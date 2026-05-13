---
phase: "01-perplexity-backend-audit"
plan: "01"
subsystem: "http-backend-tests"
tags: [audit, http-backend, perplexity, wire-level-test, mockwebserver, settings-migration]
dependency_graph:
  requires: []
  provides: [perplexity-backend-wire-tests, openai-compat-defaults-wire-tests, settings-migration-pplx05]
  affects: [PPLX-01, PPLX-02, PPLX-03, PPLX-04, PPLX-05]
tech_stack:
  added: [com.squareup.okhttp3:mockwebserver:4.12.0]
  patterns: [MockWebServer wire-level test, CountDownLatch async completion, InMemoryPrefs settings test double]
key_files:
  created:
    - build.gradle.kts (added 1 testImplementation line)
    - src/test/kotlin/com/six2dez/burp/aiagent/backends/perplexity/PerplexityBackendFactoryTest.kt
    - src/test/kotlin/com/six2dez/burp/aiagent/backends/openai/OpenAiCompatibleBackendDefaultsTest.kt
    - .planning/phases/01-perplexity-backend-audit/01-VERIFICATION.md
  modified:
    - src/test/kotlin/com/six2dez/burp/aiagent/config/AgentSettingsMigrationTest.kt (1 new @Test added)
    - .planning/phases/01-perplexity-backend-audit/01-VALIDATION.md (frontmatter flipped to green)
decisions:
  - "Wire-level MockWebServer tests used per D-04 — no reflection on private fields; all assertions on RecordedRequest"
  - "SSE body with data:[DONE] sentinel mandatory to prevent OkHttp timeout hang in streaming tests"
  - "Non-streaming JSON response used for OpenAiCompatibleBackendDefaultsTest (streaming=false is the default constructor default)"
  - "No TestSettings in PerplexityBackendFactoryTest / OpenAiCompatibleBackendDefaultsTest — BackendLaunchConfig constructed directly"
  - "D-06 manual smoke fields recorded as pending in 01-VERIFICATION.md — no real API key committed"
metrics:
  duration_seconds: 327
  completed_date: "2026-05-13"
  tasks_completed: 5
  files_changed: 6
---

# Phase 01 Plan 01: Perplexity Backend Audit — Behaviour-Locking Tests Summary

**One-liner:** Wire-level MockWebServer tests (5+2 tests) + settings migration test lock PPLX-01..05 Perplexity backend behaviour with zero production code changes.

## Must-Have Truths — Observable Status

| Truth | Observable? | Evidence |
|-------|-------------|----------|
| D-01: perplexityModel default = "" (free-form) | YES | `assertEquals("", loaded.perplexityModel)` in `AgentSettingsMigrationTest.load_v06xPreferencesYieldSafePerplexityDefaultsAndSchemaStaysV3` |
| D-02: perplexityUrl default = bare host (no path) | YES | `assertEquals("https://api.perplexity.ai", loaded.perplexityUrl)` same test; resolved runtime URL exercised by PerplexityBackendFactoryTest |
| D-03: schema version stays at 3; no migrateIfNeeded bump | YES | `assertEquals(3, prefs.integers["settings.schema.version"])` post-load |
| D-04: all assertions are wire-level (no reflection) | YES | All assertions on `RecordedRequest.path` and `RecordedRequest.body` |
| D-05: tests in fast suite (no *IntegrationTest suffix) | YES | `./gradlew test -PexcludeHeavyTests=true` runs all new tests; class names have no excluded suffix |
| D-07: test placement honoured | YES | New files at `backends/perplexity/`, `backends/openai/`, extended file at `config/` |
| MockWebServer 4.12.0 on test classpath | YES | `grep -c 'mockwebserver:4.12.0' build.gradle.kts` = 1 |
| PerplexityBackendFactoryTest.kt exists | YES | 5 @Test methods, min_lines=205 |
| OpenAiCompatibleBackendDefaultsTest.kt exists | YES | 2 @Test methods |
| AgentSettingsMigrationTest contains new @Test | YES | `load_v06xPreferencesYieldSafePerplexityDefaultsAndSchemaStaysV3` |
| `./gradlew test -PexcludeHeavyTests=true` exits 0 | YES | BUILD SUCCESSFUL |
| `./gradlew ktlintCheck` exits 0 | YES | BUILD SUCCESSFUL |
| 01-VERIFICATION.md records D-06 + D-08 handoffs | YES | 2 KNOWN-WORDING-GAP entries present |

## Requirements Locked

| Requirement | Locked by | Test method(s) |
|-------------|-----------|----------------|
| PPLX-01 (Perplexity card defaults pre-populated) | Indirect via T3 + existing SettingsDefaultsPersistenceTest | `load_v06xPreferencesYieldSafePerplexityDefaultsAndSchemaStaysV3` (load-path defaults) |
| PPLX-02 (URL = /chat/completions, no /v1) | Direct: PerplexityBackendFactoryTest | `targetsChatCompletionsWithoutV1PrefixOnBareHost`, `handlesTrailingSlashInUserConfiguredUrl`, `respectsExplicitV1UserUrl`, `doesNotDoubleAppendWhenUrlAlreadyHasChatCompletions` |
| PPLX-03 (no response_format when jsonMode=true) | Direct: PerplexityBackendFactoryTest | `omitsResponseFormatEvenWhenJsonModeRequested` |
| PPLX-04 (defaults stay /v1/chat/completions + response_format) | Direct: OpenAiCompatibleBackendDefaultsTest | `defaultsKeepV1PrefixOnBareHost`, `defaultsEmitResponseFormatWhenJsonModeRequested` |
| PPLX-05 (v0.6.x prefs load with safe defaults; schema stays at 3) | Direct: AgentSettingsMigrationTest | `load_v06xPreferencesYieldSafePerplexityDefaultsAndSchemaStaysV3` |

## D-08 Known Wording Gaps — Phase 5 Handoffs

Both gaps are recorded in `01-VERIFICATION.md` and do NOT block Phase 1 sign-off:

1. `KNOWN-WORDING-GAP: ROADMAP §Phase 1 SC#1 — tooltip suggests Sonar-family names; field is not pre-filled (Phase 5 to clarify the wording)`
2. `KNOWN-WORDING-GAP: SPEC §4.4 — Perplexity not yet listed in the pluggable HTTP backend table (Phase 5 to add Perplexity)`

## D-06 Manual Smoke Status

**Status: Pending maintainer pass.**
The six required fields (`api_key_source`, `date`, `model`, `request_count`, `observed_streamed_completion`, `response_body_sha256`) are all present in `01-VERIFICATION.md` with `pending — recorded on first maintainer pass` placeholders. No real API key, prompt body, or response body is committed.

## Commits

| Task | Commit | Description |
|------|--------|-------------|
| T0 | adb916d | chore(01-01): add MockWebServer 4.12.0 test dependency |
| T1 | c3d3857 | test(01-01): add PerplexityBackendFactoryTest wire-level tests (PPLX-02, PPLX-03) |
| T2 | 32f7804 | test(01-01): add OpenAiCompatibleBackendDefaultsTest wire-level tests (PPLX-04) |
| T3 | 0d45455 | test(01-01): extend AgentSettingsMigrationTest with PPLX-05 test |
| T4 | ab9edd7 | docs(01-01): full-phase verification sign-off artefacts |

## Deviations from Plan

None — plan executed exactly as written. All five tasks completed in order with no auto-fixes, no Rule 1/2/3 deviations, no blocking issues.

## Threat Model Dispositions

- T-01 (CI secrets): No real Perplexity API key in any test or VERIFICATION.md. Tests use `"pplx-test"` placeholder. grep check: 0 matches for `pplx-[A-Za-z0-9]{40}` in VERIFICATION.md.
- T-02 (token log leakage): No assertion on log output; no BackendDiagnostics mocking.
- T-03 (sharedClient cache pollution): No `shutdownSharedClients()` calls in any new test file.
- T-04 (MockWebServer lifecycle): `@AfterEach { server.shutdown() }` present in both T1 and T2 test files.
