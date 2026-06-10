package com.six2dez.burp.aiagent.config

import burp.api.montoya.persistence.Preferences
import java.security.SecureRandom
import java.util.Base64
import java.util.logging.Logger
import javax.crypto.Cipher
import javax.crypto.SecretKey
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.PBEKeySpec
import javax.crypto.spec.SecretKeySpec

/**
 * Authenticated symmetric encryption for secret preferences (SEC-01).
 *
 * Cipher: AES-256-GCM via [javax.crypto] (JDK 21 built-in) — no new runtime dependency.
 * Master key: a per-install random 256-bit key stored Base64-encoded in a dedicated Burp
 * Preferences entry ([MASTER_KEY_PREF_KEY]); generated on first use. No passphrase prompt
 * (zero user friction; works headless).
 *
 * Envelope (then Base64-encoded, then prefixed with "ENC1:"):
 *   [1-byte version=0x01][12-byte random IV][ciphertext + 128-bit GCM tag]
 *
 * The "ENC1:" prefix lets migration code distinguish encrypted from plaintext values
 * idempotently. [decrypt] returns non-prefixed input unchanged (plaintext migration-compat
 * path) and fails soft (returns "") on a prefixed value whose GCM tag does not authenticate.
 *
 * Headless-safe: touches only Preferences, SecureRandom, Base64, and javax.crypto — no AWT.
 *
 * Logging contract: catch blocks log only the preference KEY NAME (a caller-supplied String),
 * never the plaintext or ciphertext value.
 *
 * @param prefs the Burp Montoya Preferences instance used to persist the master key. The same
 *   instance must back the repository so the key is shared across encrypt/decrypt calls.
 */
class SecretCipher(
    private val prefs: Preferences,
) {
    private val secureRandom = SecureRandom()

    /** Lazily-resolved per-install AES key; bootstrapped from prefs on first access. */
    private val masterKey: SecretKey by lazy { loadOrCreateMasterKey() }

    /**
     * Encrypts [plaintext] into an "ENC1:"-prefixed, Base64-encoded GCM envelope.
     *
     * @param prefKeyName preference key name used only for safe logging on failure; never emitted
     *   into the returned value.
     * @throws SecretCipherException if encryption fails (the message never contains key material).
     */
    fun encrypt(
        plaintext: String,
        prefKeyName: String = "",
    ): String {
        try {
            val iv = ByteArray(IV_LENGTH_BYTES)
            secureRandom.nextBytes(iv)
            val cipher = Cipher.getInstance(TRANSFORMATION)
            cipher.init(Cipher.ENCRYPT_MODE, masterKey, GCMParameterSpec(GCM_TAG_BITS, iv))
            val ciphertext = cipher.doFinal(plaintext.toByteArray(Charsets.UTF_8))

            val envelope = ByteArray(1 + IV_LENGTH_BYTES + ciphertext.size)
            envelope[0] = ENVELOPE_VERSION
            System.arraycopy(iv, 0, envelope, 1, IV_LENGTH_BYTES)
            System.arraycopy(ciphertext, 0, envelope, 1 + IV_LENGTH_BYTES, ciphertext.size)

            return ENC_PREFIX + Base64.getEncoder().encodeToString(envelope)
        } catch (e: Exception) {
            LOGGER.warning("SecretCipher.encrypt failed for key: $prefKeyName")
            throw SecretCipherException("SecretCipher.encrypt failed for key: $prefKeyName", e)
        }
    }

    /**
     * Decrypts an "ENC1:"-prefixed value back to plaintext.
     *
     * - A value that does NOT start with "ENC1:" is returned UNCHANGED (plaintext
     *   migration-compat path — this is correct behavior, not an error).
     * - A value that starts with "ENC1:" but fails GCM authentication (bad tag, corruption, or
     *   wrong key) fails soft: it logs only [prefKeyName] and returns "" — never throws to the
     *   caller, never returns garbage.
     */
    fun decrypt(
        ciphertext: String,
        prefKeyName: String = "",
    ): String {
        if (!ciphertext.startsWith(ENC_PREFIX)) {
            // Plaintext (pre-encryption) value — pass through unchanged.
            return ciphertext
        }
        return try {
            val envelope = Base64.getDecoder().decode(ciphertext.substring(ENC_PREFIX.length))
            // WR-02: validate the version byte before parsing the IV; fail-soft on mismatch so a
            // future format change produces a clear diagnostic rather than a misleading GCM failure.
            if (envelope.isEmpty() || envelope[0] != ENVELOPE_VERSION) {
                LOGGER.warning("SecretCipher.decrypt: unrecognised envelope version for key: $prefKeyName")
                return ""
            }
            val iv = envelope.copyOfRange(1, 1 + IV_LENGTH_BYTES)
            val body = envelope.copyOfRange(1 + IV_LENGTH_BYTES, envelope.size)
            val cipher = Cipher.getInstance(TRANSFORMATION)
            cipher.init(Cipher.DECRYPT_MODE, masterKey, GCMParameterSpec(GCM_TAG_BITS, iv))
            String(cipher.doFinal(body), Charsets.UTF_8)
        } catch (e: Exception) {
            // Fail-soft per D-01: undecryptable ciphertext is treated as empty. Never log the value.
            LOGGER.warning("SecretCipher.decrypt failed for key: $prefKeyName — treating as empty")
            ""
        }
    }

    private fun loadOrCreateMasterKey(): SecretKey {
        // WR-01: double-checked locking on a companion-object lock guards across all SecretCipher
        // instances that share the same Preferences namespace. On a fresh install, only one instance
        // generates and writes the key; all others re-read the persisted value inside the lock so
        // they converge on the same key rather than each keeping an independent in-memory key.
        synchronized(BOOTSTRAP_LOCK) {
            val existing = prefs.getString(MASTER_KEY_PREF_KEY)
            if (!existing.isNullOrBlank()) {
                val bytes = Base64.getDecoder().decode(existing)
                return SecretKeySpec(bytes, "AES")
            }
            val keyBytes = ByteArray(KEY_LENGTH_BYTES)
            secureRandom.nextBytes(keyBytes)
            prefs.setString(MASTER_KEY_PREF_KEY, Base64.getEncoder().encodeToString(keyBytes))
            // Re-read after write so all instances converge on the stored (authoritative) value.
            val written = prefs.getString(MASTER_KEY_PREF_KEY)
            val finalBytes = if (!written.isNullOrBlank()) Base64.getDecoder().decode(written) else keyBytes
            return SecretKeySpec(finalBytes, "AES")
        }
    }

    /**
     * PBKDF2WithHmacSHA256 key derivation. Present for a future optional-passphrase upgrade
     * (per D-01); NOT called by the current encrypt/decrypt path which uses the per-install key.
     */
    @Suppress("unused")
    private fun deriveKey(
        passphrase: CharArray,
        salt: ByteArray,
    ): SecretKey {
        val factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
        val spec = PBEKeySpec(passphrase, salt, PBKDF2_ITERATIONS, KEY_LENGTH_BYTES * 8)
        val derived = factory.generateSecret(spec).encoded
        return SecretKeySpec(derived, "AES")
    }

    companion object {
        /** Burp Preferences key holding the Base64 per-install master key. Referenced by migration. */
        const val MASTER_KEY_PREF_KEY = "secret.master.key.v1"

        /**
         * WR-01: cross-instance lock protecting the master-key bootstrap. A single JVM may host
         * multiple [SecretCipher] instances over the same Preferences namespace; this lock ensures
         * only one instance generates a fresh key on a new install, while all others adopt the
         * persisted key.
         */
        private val BOOTSTRAP_LOCK = Any()

        private const val ENC_PREFIX = "ENC1:"
        private const val TRANSFORMATION = "AES/GCM/NoPadding"
        private const val GCM_TAG_BITS = 128
        private const val IV_LENGTH_BYTES = 12
        private const val KEY_LENGTH_BYTES = 32
        private const val ENVELOPE_VERSION: Byte = 0x01
        private const val PBKDF2_ITERATIONS = 600_000

        private val LOGGER: Logger = Logger.getLogger(SecretCipher::class.java.name)
    }
}

/** Thrown when encryption fails. The message must never include raw key material. */
class SecretCipherException(
    message: String,
    cause: Throwable,
) : RuntimeException(message, cause)
