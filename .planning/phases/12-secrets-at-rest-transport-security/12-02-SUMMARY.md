---
phase: 12-secrets-at-rest-transport-security
plan: 02
subsystem: infra
tags: [secrets, encryption, migration, schema-v4, agentsettings, kotlin]

requires:
  - phase: 12-01
    provides: SecretCipher (AES-256-GCM encrypt/decrypt, ENC1: prefix, fail-soft)
provides:
  - AgentSettingsRepository encrypts the 7 secret prefs at the persistence I/O boundary
  - Idempotent schema v3 -> v4 migration (migrateToSchemaV4) with round-trip verify
  - CURRENT_SETTINGS_SCHEMA_VERSION bumped 3 -> 4
  - Fail-soft load: a corrupted secret returns "" without failing other keys
affects: [anthropicApiKey (Phase 14), MCP token/TLS password persistence]

tech-stack:
  added: [none]
  patterns: [encrypt/decrypt confined to repository I/O layer; plaintext stays in memory]

key-files:
  created:
    - src/test/kotlin/com/six2dez/burp/aiagent/config/AgentSettingsSecretEncryptionTest.kt
  modified:
    - src/main/kotlin/com/six2dez/burp/aiagent/config/AgentSettings.kt
    - src/test/kotlin/com/six2dez/burp/aiagent/config/AgentSettingsMigrationTest.kt

key-decisions:
  - "cipher initialized as SecretCipher(prefs) reusing the existing prefs field — no second api.persistence().preferences() call."
  - "Migration overwrites plaintext only after a round-trip decrypt verifies (verified == raw); skips ENC1: values (idempotent) and blanks."
  - "Auto-generated MCP token/TLS password are stored encrypted on first write-back so a fresh install is also encrypted at rest."

patterns-established:
  - "Pattern: secret prefs are decrypted on load() and encrypted on save(); the AgentSettings data class stays plaintext in memory."
  - "Pattern: per-version migration step (migrateToSchemaV4) is idempotent via the ENC1: prefix guard; the caller stamps the version."

requirements-completed: [SEC-01]

duration: 18min
completed: 2026-06-10
---

# Phase 12: Secrets at Rest — Plan 02 Summary

**AgentSettingsRepository now encrypts all 7 secret preferences at the I/O boundary with an idempotent, data-loss-safe v3→v4 migration; settings stay plaintext in memory.**

## Performance

- **Duration:** ~18 min
- **Tasks:** 1 (TDD)
- **Files modified:** 1 modified (AgentSettings.kt) + 1 test modified + 1 test created

## Accomplishments
- Injected `SecretCipher(prefs)` into `AgentSettingsRepository` (reuses the existing prefs field).
- Wrapped the 5 backend API keys in `load()`/`save()` and the MCP token + TLS password in `loadMcpSettings()`/`saveMcpSettings()` with decrypt/encrypt.
- Added `migrateToSchemaV4()`: encrypts each plaintext secret in place, idempotent via the `ENC1:` guard, overwrites plaintext only after a round-trip decrypt verifies (no data loss).
- Bumped `CURRENT_SETTINGS_SCHEMA_VERSION` to 4; wired `if (effectiveVersion < 4) migrateToSchemaV4()` into `migrateIfNeeded()`.
- Updated all four `assertEquals(3, …)` schema-version assertions in `AgentSettingsMigrationTest.kt` to `assertEquals(4, …)`.
- Fail-soft verified: a corrupted `ENC1:` value loads as `""` and does not break other keys.

## Task Commits
1. **Task 1: encrypt/decrypt at I/O boundary + v3→v4 migration (TDD)** — see `feat(12): AgentSettings secret encryption` commit.

## Files Created/Modified
- `src/main/kotlin/com/six2dez/burp/aiagent/config/AgentSettings.kt` — cipher field, 7 encrypt + 7 decrypt at boundary, migrateToSchemaV4, schema = 4.
- `src/test/kotlin/.../AgentSettingsSecretEncryptionTest.kt` — 5 tests (round-trip, migration idempotency, all-7 keys, fail-soft, headless).
- `src/test/kotlin/.../AgentSettingsMigrationTest.kt` — four schema-version assertions updated to 4.

## Decisions Made
- The MCP token / TLS password auto-generation paths in `loadMcpSettings()` now store the freshly-generated value encrypted (`cipher.encrypt(generated, …)`), so a brand-new install persists those secrets as `ENC1:` immediately. This keeps the "all 7 raw pref strings start with ENC1:" invariant true even before the first explicit save.

## Deviations from Plan
- **cipher.encrypt grep count is 10, not exactly 7.** The 7 mandated boundary writes are present in `save()` (5) + `saveMcpSettings()` (2). The 3 additional occurrences are: 1 inside `migrateToSchemaV4()` (migration encrypt) and 2 in the `loadMcpSettings()` auto-gen write-backs (to persist freshly-generated MCP token/password encrypted). `cipher.decrypt` count is 8: the 7 boundary reads plus 1 round-trip-verify call inside `migrateToSchemaV4()`. These extras are required for the migration round-trip-verify contract and for fresh-install encryption; the literal grep count differs but the success criterion's intent (7 secret fields encrypted/decrypted at the boundary) is met exactly.

## Issues Encountered
None. Full `./gradlew test -x ktlintCheck` suite passes with no regressions.

## Next Phase Readiness
- The encryption mechanism is ready for `anthropicApiKey` (Phase 14) to be born encrypted.

---
*Phase: 12-secrets-at-rest-transport-security*
*Completed: 2026-06-10*
