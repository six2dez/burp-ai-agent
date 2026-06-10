---
phase: 12-secrets-at-rest-transport-security
reviewed: 2026-06-10T14:00:00Z
depth: deep
files_reviewed: 9
files_reviewed_list:
  - src/main/kotlin/com/six2dez/burp/aiagent/config/SecretCipher.kt
  - src/main/kotlin/com/six2dez/burp/aiagent/config/AgentSettings.kt
  - src/main/kotlin/com/six2dez/burp/aiagent/mcp/McpTls.kt
  - src/main/kotlin/com/six2dez/burp/aiagent/util/SsrfGuard.kt
  - src/main/kotlin/com/six2dez/burp/aiagent/ui/panels/BackendConfigPanel.kt
  - src/test/kotlin/com/six2dez/burp/aiagent/config/SecretCipherTest.kt
  - src/test/kotlin/com/six2dez/burp/aiagent/config/AgentSettingsMigrationTest.kt
  - src/test/kotlin/com/six2dez/burp/aiagent/config/AgentSettingsSecretEncryptionTest.kt
  - src/test/kotlin/com/six2dez/burp/aiagent/util/SsrfGuardTest.kt
findings:
  critical: 0
  warning: 4
  info: 3
  total: 7
status: clean
fixed_at: 2026-06-10T16:00:00Z
fixed_by: Claude (gsd-code-fixer)
fix_commit: 1f93a7f
---

# Phase 12: Code Review Report

**Reviewed:** 2026-06-10T14:00:00Z
**Depth:** deep
**Files Reviewed:** 9
**Status:** clean — WR-01..04 and IN-01, IN-03 fixed (commit 1f93a7f); IN-02 deferred (see note below)

## Summary

Phase 12 adds AES-256-GCM encryption for 7 secret preferences (5 backend API keys + `mcp.token` + `mcp.tls.keystore.password`), a schema v3→v4 migration, keytool password delivery via env-var instead of argv, and a non-blocking SSRF advisory for private-range backend URLs.

The core cryptographic implementation in `SecretCipher` is correct: fresh 12-byte SecureRandom IV per encrypt, 128-bit GCM tag enforced, fail-soft decrypt, ENC1: idempotency guard, and no key material in logs. The keytool fix (`-storepass:env KS_PASS`) correctly removes the password from the process argument vector. The migration round-trip verification before overwrite prevents data loss.

Four warnings and three info items were found — none are catastrophic, but two of the warnings have operational consequences in adversarial or concurrent environments.

---

## Warnings

### WR-01: TOCTOU race on master key bootstrap across multiple `AgentSettingsRepository` instances

**File:** `src/main/kotlin/com/six2dez/burp/aiagent/config/SecretCipher.kt:107-116`
**Also affects:** `src/main/kotlin/com/six2dez/burp/aiagent/config/AgentSettings.kt:155`, `src/main/kotlin/com/six2dez/burp/aiagent/ui/SettingsPanel.kt:69`, `src/main/kotlin/com/six2dez/burp/aiagent/ui/MainTab.kt:62`

**Issue:** Three separate `AgentSettingsRepository` instances are constructed in the codebase, each with its own `SecretCipher`. Kotlin's `by lazy {}` uses `LazyThreadSafetyMode.SYNCHRONIZED` per-instance, so within a single `SecretCipher` only one thread calls `loadOrCreateMasterKey()`. However, this offers no cross-instance synchronization. On a fresh install (no `secret.master.key.v1` stored yet), if two `SecretCipher` instances race to call `loadOrCreateMasterKey()` concurrently:

1. Both read `null` from `prefs.getString(MASTER_KEY_PREF_KEY)`.
2. Both generate independent random keys (`key_A`, `key_B`).
3. Both call `prefs.setString()` — last writer wins with, say, `key_B` stored.
4. Instance A retains `key_A` in its `lazy` field; prefs now stores `key_B`.
5. Any ciphertext produced by instance A (which uses `key_A`) cannot be decrypted by a new instance that loads `key_B` from prefs — every secret read back as `""` (fail-soft).

In the current initialization sequence all three repositories are created on the EDT in order (App.kt:65 → line 82 triggers lazy → MainTab at line 130), making the race unlikely in practice. However the absence of a guard makes this a structural reliability risk for any future refactor that introduces concurrent initialization.

**Fix:** Extract master key bootstrap into a shared singleton that is synchronized across all `SecretCipher` instances sharing the same `Preferences` object:

```kotlin
// In AgentSettingsRepository, pass the same SecretCipher instance to SettingsPanel/MainTab
// rather than constructing a new repository (and thus new SecretCipher) per UI component.
// Alternatively, add a cross-instance lock in loadOrCreateMasterKey():
private fun loadOrCreateMasterKey(): SecretKey {
    // Double-checked locking on a companion-object lock to guard across instances
    // sharing the same prefs namespace.
    synchronized(BOOTSTRAP_LOCK) {
        val existing = prefs.getString(MASTER_KEY_PREF_KEY)
        if (!existing.isNullOrBlank()) {
            return SecretKeySpec(Base64.getDecoder().decode(existing), "AES")
        }
        val keyBytes = ByteArray(KEY_LENGTH_BYTES)
        secureRandom.nextBytes(keyBytes)
        prefs.setString(MASTER_KEY_PREF_KEY, Base64.getEncoder().encodeToString(keyBytes))
        return SecretKeySpec(keyBytes, "AES")
    }
}
// companion object addition:
private val BOOTSTRAP_LOCK = Any()
```

Or, the cleaner fix: pass a single `AgentSettingsRepository` (and its `SecretCipher`) through to all consumers instead of constructing separate instances per UI component.

---

### WR-02: Envelope version byte written but never validated on decrypt — silent format mismatch

**File:** `src/main/kotlin/com/six2dez/burp/aiagent/config/SecretCipher.kt:94-99`

**Issue:** The envelope format reserves byte `[0]` as a version discriminator (`ENVELOPE_VERSION = 0x01`), and `encrypt()` writes it at line 64. However `decrypt()` reads past it (comment at line 94: "envelope[0] is the version byte") without checking it:

```kotlin
val iv = envelope.copyOfRange(1, 1 + IV_LENGTH_BYTES)   // version byte silently consumed
val body = envelope.copyOfRange(1 + IV_LENGTH_BYTES, envelope.size)
```

If a future version changes the IV length or envelope layout and bumps the version byte to `0x02`, a v1 `SecretCipher` will silently misparse a v2 ciphertext: it will extract the wrong bytes as the IV and attempt GCM decryption, which will fail with a bad-tag exception and return `""` (fail-soft). This is correct fail-safe behavior, but the fail-soft path gives no indication of the root cause (wrong version), making future debugging needlessly difficult. The version byte's purpose is defeated if it is never read.

**Fix:**

```kotlin
// In decrypt(), after decoding the envelope:
val envelope = Base64.getDecoder().decode(ciphertext.substring(ENC_PREFIX.length))
if (envelope.isEmpty() || envelope[0] != ENVELOPE_VERSION) {
    LOGGER.warning("SecretCipher.decrypt: unrecognised envelope version for key: $prefKeyName")
    return ""
}
val iv = envelope.copyOfRange(1, 1 + IV_LENGTH_BYTES)
```

---

### WR-03: `save()` updates the in-memory cache before any preference is written — partial-write window leaves cache inconsistent

**File:** `src/main/kotlin/com/six2dez/burp/aiagent/config/AgentSettings.kt:491`

**Issue:** `save()` sets the in-memory `cachedSettings` to the new `AgentSettings` value at line 491, before any `prefs.setString()` / `prefs.setInteger()` call. If any subsequent preference write fails (for example, `cipher.encrypt()` throws `SecretCipherException` for one of the 7 secret keys), the cache holds the new settings while the preferences store holds a mix of new and old values. The next `load()` call returns the cached (new) value without re-reading preferences, masking the partial-write failure. On extension reload the old persisted values are read back, creating an invisible inconsistency.

**Fix:** Move the cache update to after all preference writes complete, or clear the cache on exception:

```kotlin
fun save(settings: AgentSettings) {
    try {
        prefs.setString(KEY_CODEX_CMD, settings.codexCmd)
        // ... all writes ...
        prefs.setInteger(KEY_SETTINGS_SCHEMA_VERSION, CURRENT_SETTINGS_SCHEMA_VERSION)
        cachedSettings.set(settings)   // update only on full success
    } catch (e: Exception) {
        cachedSettings.set(null)       // force re-read on next load()
        throw e
    }
}
```

---

### WR-04: IPv6 Unique-Local Addresses (ULA, `fc00::/7`) are not flagged by `SsrfGuard`

**File:** `src/main/kotlin/com/six2dez/burp/aiagent/util/SsrfGuard.kt:53-59`

**Issue:** `SsrfGuard.isPrivateOrLinkLocal()` relies on `InetAddress.isSiteLocalAddress()` for RFC-1918 and `isLinkLocalAddress()` for `169.254.x.x` / `fe80::/10`. Java's `Inet6Address.isSiteLocalAddress()` covers only the deprecated `fec0::/10` site-local range, not the modern IPv6 Unique Local Address range `fc00::/7` (prefixes `fc00::` through `fdff::`). An attacker-controlled backend URL like `http://[fc00::192.168.1.1]` or `http://[fd12:3456::1]` passes through unwarned. The `IPV6_REGEX` (`[0-9a-fA-F:]+`) correctly matches these addresses, and `InetAddress.getByName()` resolves them without DNS, so the only gap is the missing classification logic.

There is no test for IPv6 ULA in `SsrfGuardTest`.

**Fix:** Add explicit ULA detection after the `isLinkLocalAddress` check:

```kotlin
return when {
    addr.isLoopbackAddress -> false
    addr.isSiteLocalAddress -> true
    addr.isLinkLocalAddress -> true
    addr.hostAddress == "169.254.169.254" -> true
    // IPv6 ULA: fc00::/7 — Java's isSiteLocalAddress does not cover this range
    addr is java.net.Inet6Address && isIpv6Ula(addr) -> true
    else -> false
}

private fun isIpv6Ula(addr: java.net.Inet6Address): Boolean {
    val firstByte = addr.address[0].toInt() and 0xFF
    return firstByte and 0xFE == 0xFC  // matches fc00::/7 (fc and fd prefixes)
}
```

Add a test:
```kotlin
@Test
fun ipv6Ula_fc00_isFlagged() {
    assertTrue(SsrfGuard.isPrivateOrLinkLocal("http://[fc00::1]"))
}

@Test
fun ipv6Ula_fd_isFlagged() {
    assertTrue(SsrfGuard.isPrivateOrLinkLocal("http://[fd12:3456::1]"))
}
```

---

## Info

### IN-01: `passStr` (String copy of the keystore password) is never zeroed after use in `McpTls`

**File:** `src/main/kotlin/com/six2dez/burp/aiagent/mcp/McpTls.kt:40`

**Issue:** `val passStr = String(password)` materialises the keystore password as an immutable Java `String`, which cannot be zeroed. The `CharArray password` parameter comes from `settings.tlsKeystorePassword.toCharArray()` (also not zeroed at line 18). Immutable `String` objects stay on the heap until GC'd and may appear in heap dumps. This is a defense-in-depth gap, not an exploitable bug given the same password is already persisted in `Preferences`. The env-var delivery via `ProcessBuilder.environment()` is correct and means the password does not appear in `ps aux`.

**Fix (defense-in-depth):** Zero `password` after `process.waitFor()` and avoid materialising `passStr` if `ProcessBuilder.environment()` accepts it directly (it does — put directly):

```kotlin
val passStr = String(password)
try {
    val process = ProcessBuilder(...).also { it.environment()["KS_PASS"] = passStr }.start()
    // ...
    process.waitFor()
} finally {
    passStr.toCharArray().fill(' ')  // limited value since passStr is immutable,
    password.fill(' ')               // but zeroing the CharArray is meaningful
}
```

---

### IN-02: `hostAnonymizationSalt` is stored in cleartext (`privacy.host_salt`) — DEFERRED

> **Deferred:** encrypting `privacy.host_salt` is out of scope for Phase 12; left as a future hardening item.



**File:** `src/main/kotlin/com/six2dez/burp/aiagent/config/AgentSettings.kt:294-298`, `538`

**Issue:** The host-anonymization salt is used with HKDF in STRICT privacy mode to pseudonymize hostnames in outbound AI traffic. If the salt is recovered from the preferences file, an adversary can reverse-engineer which anonymized hostnames correspond to which real targets by brute-forcing against a known hostname set. The salt is not included in the `migrateToSchemaV4` list and is stored in cleartext as `privacy.host_salt`.

The operational impact is bounded: the salt does not grant API access and the STRICT mode use-case implies the threat model already includes a partially-trusted backend. However, given that the same encryption infrastructure now exists, encrypting this preference would be consistent with the SEC-01 goal of protecting all operationally sensitive values.

**Fix:** Add `KEY_HOST_SALT` to the `secretKeys` list in `migrateToSchemaV4()` and apply `cipher.encrypt()` / `cipher.decrypt()` at lines 294-298 and 538 in `AgentSettings.kt`.

---

### IN-03: `applyState()` does not trigger the SSRF advisory — warning never shown on initial load

**File:** `src/main/kotlin/com/six2dez/burp/aiagent/ui/panels/BackendConfigPanel.kt:281-317`

**Issue:** `checkAndShowSsrfWarning()` is only called from `currentBackendSettings()`, which runs when the user presses Save. When the panel is first populated via `applyState()` with a previously-saved private-range URL, the warning label is invisible. The user must Save (without changing anything) to see the warning. This is a minor UX gap: someone reviewing their settings visually gets no advisory for a known-private URL until they interact.

**Fix:** Call `checkAndShowSsrfWarning()` at the end of `applyState()`:

```kotlin
fun applyState(state: BackendConfigState) {
    // ... field assignments ...
    checkAndShowSsrfWarning(
        listOf(state.ollamaUrl, state.lmStudioUrl, state.openAiCompatUrl,
               state.nvidiaNimUrl, state.perplexityUrl)
    )
}
```

---

## Checklist Verdict (per prompt)

| # | Requirement | Result |
|---|-------------|--------|
| 1 | Fresh 12-byte SecureRandom IV per encrypt, stored in envelope, read back on decrypt | PASS |
| 2 | 256-bit SecureRandom master key, persisted once at `secret.master.key.v1`, 128-bit GCM tag | PASS |
| 3 | ENC1: idempotency guard; plaintext overwritten only after verified round-trip | PASS |
| 4 | Fail-soft: bad GCM tag → `""`; non-ENC1: returned unchanged; no key material in logs | PASS |
| 5 | keytool password via `-storepass:env`/`-keypass:env` + `ProcessBuilder.environment()`, never on argv; no `sun.security.*` | PASS |
| 6 | RFC-1918, link-local, loopback, cloud-metadata classified correctly; IPv6 ULA **not covered** | WR-04 |
| 7 | Per-instance `by lazy{}` is `SYNCHRONIZED`; cross-instance TOCTOU possible on fresh install | WR-01 |
| 8 | No regression to AI/HTTP routing; English-only code | PASS |

---

_Reviewed: 2026-06-10T14:00:00Z_
_Reviewer: Claude (gsd-code-reviewer)_
_Depth: deep_
