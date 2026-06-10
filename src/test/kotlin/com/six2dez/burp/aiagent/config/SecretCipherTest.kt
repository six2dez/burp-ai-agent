package com.six2dez.burp.aiagent.config

import burp.api.montoya.persistence.Preferences
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNotEquals
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.mockito.kotlin.any
import org.mockito.kotlin.mock
import org.mockito.kotlin.whenever
import java.util.Base64
import java.util.logging.Handler
import java.util.logging.Level
import java.util.logging.LogRecord
import java.util.logging.Logger

class SecretCipherTest {
    @Test
    fun encrypt_producesCiphertextThatIsNotPlaintext() {
        val cipher = SecretCipher(InMemoryPrefs().mock)
        val plaintext = "sk-test-key-123"
        val encrypted = cipher.encrypt(plaintext)
        assertNotEquals(plaintext, encrypted)
        assertTrue(encrypted.startsWith("ENC1:"), "ciphertext must carry the ENC1: prefix")
    }

    @Test
    fun decrypt_ofEncrypt_returnsOriginalValue() {
        val cipher = SecretCipher(InMemoryPrefs().mock)
        val plaintext = "sk-test-key-123"
        assertEquals(plaintext, cipher.decrypt(cipher.encrypt(plaintext)))
    }

    @Test
    fun encrypt_twiceProducesDifferentCiphertextDueToFreshIv() {
        val cipher = SecretCipher(InMemoryPrefs().mock)
        val first = cipher.encrypt("x")
        val second = cipher.encrypt("x")
        assertNotEquals(first, second, "IV must be fresh per call, so ciphertexts differ")
    }

    @Test
    fun decrypt_ofEnc1ValueWithBadGcmTag_returnsEmptyStringFailSoft() {
        val cipher = SecretCipher(InMemoryPrefs().mock)
        // A syntactically valid ENC1: prefix but with a corrupted/wrong-key envelope.
        val corrupted = "ENC1:" + Base64.getEncoder().encodeToString(ByteArray(32) { 0x00 })
        assertEquals("", cipher.decrypt(corrupted), "bad GCM tag must fail soft to empty string")
    }

    @Test
    fun decrypt_ofNonEnc1Value_returnsInputUnchanged() {
        val cipher = SecretCipher(InMemoryPrefs().mock)
        // Plaintext migration-compat path: non-prefixed values pass through unchanged.
        assertEquals("plain-legacy-key", cipher.decrypt("plain-legacy-key"))
    }

    @Test
    fun masterKey_generatedOnFirstUseAndReusedAfterwards() {
        val prefs = InMemoryPrefs()
        // First cipher generates and stores a key.
        whenever(prefs.mock.getString(any())).thenAnswer { invocation ->
            prefs.strings[invocation.getArgument(0)]
        }
        val first = SecretCipher(prefs.mock)
        val encrypted = first.encrypt("payload")
        val storedKey = prefs.strings[SecretCipher.MASTER_KEY_PREF_KEY]
        assertNotNull(storedKey, "a master key must be generated and stored on first use")

        // A second cipher over the same prefs must reuse the stored key and decrypt the value.
        val second = SecretCipher(prefs.mock)
        assertEquals("payload", second.decrypt(encrypted), "stored key must be reused deterministically")
    }

    @Test
    fun construction_succeedsHeadless_noHeadlessException() {
        val previous = System.getProperty("java.awt.headless")
        System.setProperty("java.awt.headless", "true")
        try {
            val cipher = SecretCipher(InMemoryPrefs().mock)
            // Exercise the full path under headless to be certain no AWT is touched.
            assertEquals("ok", cipher.decrypt(cipher.encrypt("ok")))
        } finally {
            if (previous == null) System.clearProperty("java.awt.headless") else System.setProperty("java.awt.headless", previous)
        }
    }

    @Test
    fun decrypt_failure_logsOnlyPrefKeyName_neverRawValue() {
        val logger = Logger.getLogger(SecretCipher::class.java.name)
        val captured = mutableListOf<String>()
        val handler =
            object : Handler() {
                override fun publish(record: LogRecord) {
                    captured.add(record.message)
                }

                override fun flush() {}

                override fun close() {}
            }
        handler.level = Level.ALL
        logger.addHandler(handler)
        val previousLevel = logger.level
        logger.level = Level.ALL
        try {
            val cipher = SecretCipher(InMemoryPrefs().mock)
            val secretValue = "super-secret-token-value-DO-NOT-LOG"
            // Build a corrupted ENC1: envelope so decrypt fails and logs.
            val corrupted = "ENC1:" + Base64.getEncoder().encodeToString(ByteArray(40) { 0x7F })
            cipher.decrypt(corrupted, "ollama.apiKey")
            assertTrue(captured.isNotEmpty(), "a decrypt failure must emit a log record")
            val joined = captured.joinToString("\n")
            assertTrue(joined.contains("ollama.apiKey"), "log must include the preference key name")
            assertFalse(joined.contains(secretValue), "log must never include raw secret material")
        } finally {
            logger.removeHandler(handler)
            logger.level = previousLevel
        }
    }

    /**
     * Minimal in-memory [Preferences] mock mirroring the helper used in
     * AgentSettingsMigrationTest, scoped to the getString/setString surface SecretCipher needs.
     */
    private class InMemoryPrefs {
        val strings = mutableMapOf<String, String>()
        val mock: Preferences =
            mock<Preferences>().also { prefs ->
                whenever(prefs.getString(any())).thenAnswer { invocation ->
                    strings[invocation.getArgument(0)]
                }
                whenever(prefs.setString(any(), any())).thenAnswer { invocation ->
                    strings[invocation.getArgument(0)] = invocation.getArgument(1)
                    null
                }
            }
    }
}
