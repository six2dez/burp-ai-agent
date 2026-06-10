---
phase: 12-secrets-at-rest-transport-security
status: complete
plans_completed: 4
plans_total: 4
requirements: [SEC-01, SEC-02, SEC-03]
tests_added: 29
tests_total: 337
tests_failing: 0
completed: 2026-06-10
---

# Phase 12: Secrets at Rest & Transport Security — Phase Summary

All stored credentials are now encrypted at rest (AES-256-GCM, javax.crypto only), existing
plaintext secrets migrate non-destructively on upgrade, and two transport-security gaps
(keytool argv password exposure, SSRF-blind backend URLs) are closed. No new runtime dependency.

## What was built — per plan

### 12-01 — SecretCipher (SEC-01 foundation) — commit `ad3e714`
- `SecretCipher` (class taking `Preferences`): AES-256-GCM via `javax.crypto`; per-install
  random 256-bit master key stored at `secret.master.key.v1`, generated on first use.
- Envelope `[0x01 version][12-byte SecureRandom IV][ciphertext+128-bit GCM tag]`, Base64,
  `ENC1:` prefix for idempotent migration detection.
- `decrypt`: non-`ENC1:` values pass through unchanged (plaintext migration-compat); `ENC1:`
  values with a failed GCM tag fail soft to `""` (never throws). Catch blocks log only the
  pref key name. PBKDF2WithHmacSHA256 `deriveKey()` scaffolded (unused) for a future passphrase.
- 8 unit tests (round-trip, IV freshness, fail-soft, passthrough, headless, no-log-material,
  master-key reuse).

### 12-02 — Encrypt secret prefs at rest + schema v4 migration (SEC-01) — commit `5899e27`
- Injected `SecretCipher(prefs)` into `AgentSettingsRepository` (reuses existing prefs field).
- The 7 secret prefs (5 backend API keys + `mcp.token` + `mcp.tls.keystore.password`) are
  decrypted on `load()`/`loadMcpSettings()` and encrypted on `save()`/`saveMcpSettings()`.
- `migrateToSchemaV4()`: idempotent (skips `ENC1:`), overwrites plaintext only after a
  round-trip decrypt verifies (no data loss). `CURRENT_SETTINGS_SCHEMA_VERSION` → 4; wired into
  `migrateIfNeeded()`. All four `assertEquals(3, …)` schema assertions updated to 4.
- 5 unit tests (round-trip, migration idempotency, all-7-keys, fail-soft, headless).

### 12-03 — keytool env-var password (SEC-02) — commit `8c1ae43`
- Replaced `-storepass passStr` / `-keypass passStr` argv pairs with `-storepass:env KS_PASS` /
  `-keypass:env KS_PASS`; password supplied via `ProcessBuilder.environment()["KS_PASS"]`.
- No `sun.security.*`, no `--add-exports` (both fail at runtime inside Burp's JVM). `findKeytool()`,
  `resolve()`, `McpTlsMaterial` unchanged. This is exactly the `:env` form sanctioned by SEC-02.
- 7 unit tests (keystore round-trip, cert subject/algorithm/validity, source argv assertions).

### 12-04 — SsrfGuard + inline backend URL warning (SEC-03) — commit `5b3b4b2`
- `SsrfGuard.isPrivateOrLinkLocal(url)`: pure, network-free; flags literal-IP RFC-1918,
  link-local (169.254.x.x, fe80::/10), and 169.254.169.254 cloud-metadata; excludes loopback;
  no DNS for hostnames; never throws. Manual authority fallback classifies unbracketed IPv6.
- Shared non-blocking warning label (`statusWarning`) in BackendConfigPanel SOUTH bar, hidden
  by default; `checkAndShowSsrfWarning()` runs on Save via `currentBackendSettings()`.
- 9 unit tests covering all classification cases.

## Cross-cutting verification
- `./gradlew test -x ktlintCheck`: 337 tests, 0 failures/errors/skips (29 new).
- `./gradlew ktlintCheck`: BUILD SUCCESSFUL; no phase-12 file flagged.
- No new runtime dependency (`runtimeClasspath` has no BouncyCastle/Tink/keyring/jna).
- `MontoyaHttpTransport` untouched; English-only (only U+2014 em-dashes in English comments).

## Human UAT (visual, cannot be automated headless)
- Type `http://192.168.1.10` in a backend URL field + Save → inline SSRF warning shows; setting
  still saves. `http://127.0.0.1:11434` → no warning.

## Deviations
- `SecretCipher` is a `class` taking `Preferences`, not a Kotlin `object` (the plan prose said
  "object" but its binding contract `SecretCipher(prefs)` requires a constructor). Behavior
  identical; this is what plan 02's wiring requires.
- `cipher.encrypt`/`cipher.decrypt` grep counts are 10/8 rather than literally 7/7: the 7
  boundary calls are present in save/load; the extras are the migration round-trip-verify and
  encrypting auto-generated MCP token/password on first write-back. Intent (7 secret fields
  encrypted at the boundary) is met exactly.
