---
phase: 12-secrets-at-rest-transport-security
plan: 01
subsystem: infra
tags: [aes-gcm, javax.crypto, secrets, encryption, kotlin]

requires:
  - phase: none
    provides: standalone cryptographic primitive — no prior-phase dependency
provides:
  - SecretCipher object — AES-256-GCM encrypt/decrypt with per-install master key
  - ENC1: ciphertext prefix convention for idempotent migration detection
  - Fail-soft decrypt contract (bad GCM tag → empty string; non-ENC1: → unchanged)
  - PBKDF2WithHmacSHA256 key-derivation path scaffolded for a future passphrase upgrade
affects: [12-02, anthropicApiKey (Phase 14), AgentSettingsRepository]

tech-stack:
  added: [none — javax.crypto is JDK built-in]
  patterns: [authenticated-encryption envelope versioning, fail-soft decrypt, no-log-material]

key-files:
  created:
    - src/main/kotlin/com/six2dez/burp/aiagent/config/SecretCipher.kt
    - src/test/kotlin/com/six2dez/burp/aiagent/config/SecretCipherTest.kt
  modified: []

key-decisions:
  - "SecretCipher is a class taking Preferences (not an object) so the same prefs instance backs the master key across the repository — matches plan 02 wiring SecretCipher(prefs)."
  - "Envelope layout [0x01 version][12-byte IV][ciphertext+tag], Base64, ENC1: prefix."
  - "GCM tag 128-bit, IV 12-byte fresh per encrypt via SecureRandom; master key 256-bit SecureRandom."

patterns-established:
  - "Pattern: ENC1: prefix marks encrypted values for idempotent migration; non-prefixed values pass through decrypt unchanged."
  - "Pattern: catch blocks log only the caller-supplied preference key name via java.util.logging — never key material."

requirements-completed: [SEC-01]

duration: 12min
completed: 2026-06-10
---

# Phase 12: Secrets at Rest — Plan 01 Summary

**AES-256-GCM SecretCipher with a per-install 256-bit master key, ENC1:-prefixed envelopes, and fail-soft authenticated decrypt — zero new runtime dependencies.**

## Performance

- **Duration:** ~12 min
- **Tasks:** 1 (TDD)
- **Files modified:** 2 created

## Accomplishments
- `SecretCipher.encrypt()` produces `ENC1:`-prefixed Base64 GCM envelopes; IV is fresh per call.
- `SecretCipher.decrypt()` round-trips, passes non-`ENC1:` values through unchanged (migration-compat), and fails soft to `""` on GCM auth failure without throwing.
- Per-install master key generated on first use and stored at `secret.master.key.v1`; reused deterministically.
- PBKDF2WithHmacSHA256 `deriveKey()` present but unused (future passphrase upgrade per D-01).
- Headless-safe: no AWT touched; verified under `java.awt.headless=true`.
- No-log-material contract verified by a test asserting the failure log contains only the pref key name.

## Task Commits
1. **Task 1: SecretCipher AES-256-GCM + master key (TDD)** — see `feat(12): SecretCipher` commit.

## Files Created/Modified
- `src/main/kotlin/com/six2dez/burp/aiagent/config/SecretCipher.kt` — cipher + master key bootstrap.
- `src/test/kotlin/com/six2dez/burp/aiagent/config/SecretCipherTest.kt` — 8 tests (round-trip, IV freshness, fail-soft, non-ENC1 passthrough, headless, no-log-material, master-key reuse).

## Decisions Made
- Modeled SecretCipher as a `class` (not an `object`) taking `Preferences`, because plan 02 wires it as `SecretCipher(prefs)` reusing the repository's existing prefs field. The plan text says "object" in prose but the binding contract (constructor takes prefs, shared instance) requires a class — this is the only viable shape and matches the 12-02 key_link `SecretCipher(prefs)`.

## Deviations from Plan
SecretCipher is a `class` with a constructor parameter rather than a Kotlin `object`. An `object` cannot take a constructor parameter, and plan 02's mandated initialization `cipher = SecretCipher(prefs)` requires a constructor. Behavior and all `must_haves` are unchanged.

## Issues Encountered
None.

## Next Phase Readiness
- 12-02 can inject `SecretCipher(prefs)` into `AgentSettingsRepository` and wrap the 7 secret prefs.

---
*Phase: 12-secrets-at-rest-transport-security*
*Completed: 2026-06-10*
