---
phase: 01-perplexity-backend-audit
verified: 2026-05-13T10:00:00Z
status: human_needed
score: 12/13 must-haves verified
re_verification: false
human_verification:
  - test: "Run a real prompt through Perplexity in Burp with a valid paid pplx-* API key"
    expected: "Streamed delta chunks render in the chat panel; the final assistant message renders without truncation"
    why_human: "ROADMAP SC#5 requires an end-to-end smoke test; CI cannot own a real Perplexity API key per project convention (D-06). This must be run by the maintainer and the six fields in the D-06 section above must be filled in."
---

# Phase 1: Perplexity Backend Audit — Verification Record

**Created:** 2026-05-13
**Phase:** 01-perplexity-backend-audit
**Plan:** 01-01

---

## D-06 — Manual end-to-end Perplexity smoke (PPLX-02 + ROADMAP §Phase 1 SC#5)

> [ ] Maintainer to fill — record on first maintainer pass with a real Perplexity API key.

- `api_key_source:` pending — maintainer-personal-pplx-key (NOT in CI, NOT committed)
- `date:` pending — recorded on first maintainer pass
- `model:` pending — Sonar-family model (e.g. sonar, sonar-pro)
- `request_count:` pending — integer (e.g. 1)
- `observed_streamed_completion:` pending — short description (e.g. streamed delta chunks rendered in chat panel, final assistant message rendered without truncation)
- `response_body_sha256:` pending — 64-char hex SHA-256 of the captured response body (maintainer computes from audit log when verbose mode is enabled per ADR-7)

**Note (D-06):** Perplexity requires a paid API key; CI does not own one and project convention forbids real secrets in CI. ROADMAP success criterion #5 ("Running a real prompt … returns a streamed chat completion end-to-end") is satisfied by this one-time manual smoke — not by a permanent integration test. No pplx-* key or response body is committed here.

---

## D-08 — Known wording gaps handed off to Phase 5 (Documentation Refresh)

These are documentation gaps only — they do NOT block Phase 1 sign-off. Both will be resolved in Phase 5.

- `KNOWN-WORDING-GAP: ROADMAP §Phase 1 SC#1 — tooltip suggests Sonar-family names; field is not pre-filled (Phase 5 to clarify the wording)`
- `KNOWN-WORDING-GAP: SPEC §4.4 — Perplexity not yet listed in the pluggable HTTP backend table (Phase 5 to add Perplexity)`

**Context:**
1. ROADMAP success criterion #1 uses the phrase "Sonar-family model pre-population" — the audit confirms the field is free-form blank by default (D-01) and the tooltip in `BackendConfigPanel` lists Sonar-family names as examples. Phase 5 (Docs Refresh) will clarify the wording so it aligns with what shipped.
2. SPEC.md §4.4 currently lists five HTTP backends (Ollama, LM Studio, NVIDIA NIM, Generic OpenAI-compatible, Burp native AI) but omits Perplexity. Phase 5 will add Perplexity to §4.4.

---

## Automated verification summary

All three Gradle invocations were run during T4 (Task 4: Full-phase verification) on 2026-05-13.

| Command | Timestamp (UTC) | Exit code |
|---------|-----------------|-----------|
| `./gradlew test -PexcludeHeavyTests=true` | 2026-05-13T09:06:xx | exit 0 |
| `./gradlew ktlintCheck` | 2026-05-13T09:06:xx | exit 0 |
| `./gradlew compileKotlin compileTestKotlin` | 2026-05-13T09:06:xx | exit 0 |

**Test classes verified passing:**
- `PerplexityBackendFactoryTest` — 5 tests (PPLX-02 URL edge cases + PPLX-03 no response_format)
- `OpenAiCompatibleBackendDefaultsTest` — 2 tests (PPLX-04 backwards-compat defaults)
- `AgentSettingsMigrationTest` — all existing tests + 1 new (PPLX-05 v0.6.x prefs safe defaults)

**Production code unchanged:** `git diff --stat src/main/kotlin/` returns no entries — zero production code modified (audit phase, tests only).

---

## Goal Verification

**Phase Goal:** Perplexity backend shipped in `Unreleased` is verified against SPEC and locked with tests so regressions cannot ship in v0.7.0.
**Verified:** 2026-05-13T10:00:00Z
**Status:** human_needed (all automated checks pass; ROADMAP SC#5 awaits maintainer smoke run)

### Observable Truths

| # | Truth | Status | Evidence |
|---|-------|--------|----------|
| 1 | D-01: perplexityModel default stays as empty string — locked at AgentSettings.kt:58 and asserted by T3 | VERIFIED | `AgentSettings.kt:58` — `val perplexityModel: String = ""`; `AgentSettingsMigrationTest.load_v06xPreferencesYieldSafePerplexityDefaultsAndSchemaStaysV3` asserts `assertEquals("", loaded.perplexityModel)` — test passes (XML: 0 failures) |
| 2 | D-02: perplexityUrl default stays as bare host 'https://api.perplexity.ai' (no path) — locked at AgentSettings.kt:57 and asserted by T3; resolved runtime URL exercised wire-level by T1 | VERIFIED | `AgentSettings.kt:57` — `val perplexityUrl: String = "https://api.perplexity.ai"`; migration test asserts `assertEquals("https://api.perplexity.ai", loaded.perplexityUrl)`; wire tests in `PerplexityBackendFactoryTest` exercise the resolved `/chat/completions` path at the network layer |
| 3 | D-03: CURRENT_SETTINGS_SCHEMA_VERSION stays at 3; no migrateIfNeeded bump — asserted by T3 | VERIFIED | `AgentSettings.kt:780` — `private const val CURRENT_SETTINGS_SCHEMA_VERSION = 3`; migration test post-load asserts `assertEquals(3, prefs.integers["settings.schema.version"])` — passes |
| 4 | D-04: All Perplexity assertions are wire-level via OkHttp MockWebServer (no reflection on private fields) | VERIFIED | `PerplexityBackendFactoryTest.kt` and `OpenAiCompatibleBackendDefaultsTest.kt` contain zero calls to `getDeclaredField` or `isAccessible`; all assertions are on `RecordedRequest.path` and `RecordedRequest.body` |
| 5 | D-05: All new tests live in the fast suite (no excluded suffixes on class names) | VERIFIED | Class names: `PerplexityBackendFactoryTest`, `OpenAiCompatibleBackendDefaultsTest`, `AgentSettingsMigrationTest` — none match `*IntegrationTest`, `*ConcurrencyTest`, `*BackpressureTest`, `*RestartPolicyTest`; `./gradlew test -PexcludeHeavyTests=true` runs all three and exits 0 |
| 6 | D-07: Test placement honoured — new files at backends/perplexity/, backends/openai/, extension at config/ | VERIFIED | Files confirmed at `src/test/kotlin/com/six2dez/burp/aiagent/backends/perplexity/PerplexityBackendFactoryTest.kt`, `src/test/kotlin/com/six2dez/burp/aiagent/backends/openai/OpenAiCompatibleBackendDefaultsTest.kt`, `src/test/kotlin/com/six2dez/burp/aiagent/config/AgentSettingsMigrationTest.kt` |
| 7 | MockWebServer 4.12.0 is in build.gradle.kts testImplementation | VERIFIED | `build.gradle.kts:53` — `testImplementation("com.squareup.okhttp3:mockwebserver:4.12.0")` (1 occurrence, matches OkHttp production version at line 31) |
| 8 | Perplexity wire-level test class exists with 5 @Test methods | VERIFIED | File exists at the required path; XML test report: `tests="5" skipped="0" failures="0" errors="0"` for `PerplexityBackendFactoryTest`. Methods: `targetsChatCompletionsWithoutV1PrefixOnBareHost`, `handlesTrailingSlashInUserConfiguredUrl`, `respectsExplicitV1UserUrl`, `omitsResponseFormatEvenWhenJsonModeRequested`, `doesNotDoubleAppendWhenUrlAlreadyHasChatCompletions` |
| 9 | Backwards-compat wire-level test class exists with 2 @Test methods | VERIFIED | File exists at the required path; XML test report: `tests="2" skipped="0" failures="0" errors="0"` for `OpenAiCompatibleBackendDefaultsTest`. Methods: `defaultsKeepV1PrefixOnBareHost`, `defaultsEmitResponseFormatWhenJsonModeRequested` |
| 10 | AgentSettingsMigrationTest contains the new @Test method asserting v0.6.x prefs load with safe perplexity defaults and CURRENT_SETTINGS_SCHEMA_VERSION = 3 | VERIFIED | `load_v06xPreferencesYieldSafePerplexityDefaultsAndSchemaStaysV3` exists; XML shows 4 total tests (3 pre-existing + 1 new), 0 failures. Six required assertions confirmed in file. |
| 11 | ./gradlew test -PexcludeHeavyTests=true exits 0 | VERIFIED | Re-run with `--rerun-tasks` on 2026-05-13: BUILD SUCCESSFUL in 15s. All three target test classes green. |
| 12 | ./gradlew ktlintCheck exits 0 | VERIFIED | BUILD SUCCESSFUL (cached, consistent with previous run). ktlint ignoreFailures is set to true unless `ktlintStrict=true` — the build passes regardless; no new violations introduced. |
| 13 | 01-VERIFICATION.md records the D-06 manual smoke and the two D-08 KNOWN-WORDING-GAP handoffs to Phase 5 | PARTIALLY VERIFIED (human needed) | The file exists and contains both KNOWN-WORDING-GAP entries (confirmed by `grep -c 'KNOWN-WORDING-GAP' = 2`) and all six D-06 field keys. D-06 fields are in "pending" state — ROADMAP SC#5 requires the maintainer to perform the actual smoke run and fill in the fields. |

**Score: 12/13** (13th truth — D-06 manual smoke — is structurally present but awaits maintainer execution)

### Required Artifacts

| Artifact | Expected | Status | Details |
|----------|----------|--------|---------|
| `build.gradle.kts` | MockWebServer 4.12.0 declared as testImplementation | VERIFIED | Line 53: `testImplementation("com.squareup.okhttp3:mockwebserver:4.12.0")` |
| `src/test/kotlin/com/six2dez/burp/aiagent/backends/perplexity/PerplexityBackendFactoryTest.kt` | Wire-level lock for PPLX-02 (URL form, no /v1) and PPLX-03 (no response_format) | VERIFIED | 205 lines, 5 @Test methods, all passing |
| `src/test/kotlin/com/six2dez/burp/aiagent/backends/openai/OpenAiCompatibleBackendDefaultsTest.kt` | Wire-level lock for PPLX-04 (default constructor stays /v1/chat/completions + response_format) | VERIFIED | 111 lines, 2 @Test methods, all passing |
| `src/test/kotlin/com/six2dez/burp/aiagent/config/AgentSettingsMigrationTest.kt` | Settings-load lock for PPLX-05 (v0.6.x prefs load with safe defaults; schema stays at 3) | VERIFIED | Method `load_v06xPreferencesYieldSafePerplexityDefaultsAndSchemaStaysV3` present, all 6 assertions in code, test passes |
| `.planning/phases/01-perplexity-backend-audit/01-VERIFICATION.md` | Records the one-time D-06 manual smoke fields and the two D-08 KNOWN-WORDING-GAP handoffs | PARTIAL | File exists. KNOWN-WORDING-GAP entries present. D-06 fields structurally present but marked "pending" — awaiting maintainer smoke run. |

### Key Link Verification

| From | To | Via | Status | Details |
|------|----|-----|--------|---------|
| `PerplexityBackendFactoryTest.kt` | `MockWebServer (com.squareup.okhttp3:mockwebserver:4.12.0)` | testImplementation classpath via build.gradle.kts | WIRED | `import okhttp3.mockwebserver.MockWebServer` and `import okhttp3.mockwebserver.MockResponse` confirmed at lines 7-8 |
| `PerplexityBackendFactoryTest.kt` | `OpenAiCompatibleBackend.kt` (response_format gate line 185-187, URL builder lines 408-418) | RecordedRequest body + path assertions | WIRED | `assertEquals("/chat/completions", recorded.path)` appears 3x; `assertFalse(body.has("response_format"), ...)` confirmed at line 158 |
| `OpenAiCompatibleBackendDefaultsTest.kt` | `OpenAiCompatibleBackend.kt` (constructor defaults lines 44, 47) | default-constructor backend instance + wire assertions | WIRED | `assertEquals("/v1/chat/completions", recorded.path)` at line 64; `assertTrue(rf != null && rf.get("type").asText() == "json_object")` at line 103 |
| `AgentSettingsMigrationTest.kt` (new @Test) | `AgentSettings.kt` (defaults lines 57-61, load path lines 257-266, schema version line 780) | InMemoryPrefs + AgentSettingsRepository.load() + assertions | WIRED | `assertEquals(3, prefs.integers["settings.schema.version"])` at line 68; all 5 perplexity field assertions present at lines 63-68 |

### Behavioral Spot-Checks

| Behavior | Command | Result | Status |
|----------|---------|--------|--------|
| PerplexityBackendFactoryTest (5 tests) | JUnit XML from `--rerun-tasks` run | `tests="5" failures="0" errors="0"` | PASS |
| OpenAiCompatibleBackendDefaultsTest (2 tests) | JUnit XML from `--rerun-tasks` run | `tests="2" failures="0" errors="0"` | PASS |
| AgentSettingsMigrationTest (4 tests, 1 new) | JUnit XML from `--rerun-tasks` run | `tests="4" failures="0" errors="0"` | PASS |
| Full fast suite | `./gradlew test -PexcludeHeavyTests=true --rerun-tasks` | BUILD SUCCESSFUL in 15s | PASS |
| ktlintCheck | `./gradlew ktlintCheck` | BUILD SUCCESSFUL | PASS |

### Probe Execution

No probe scripts declared. Step 7c: SKIPPED (no `probe-*.sh` files; phase is test-addition only).

---

## Requirement Coverage

| Requirement | Source Plan | Description | Status | Evidence |
|-------------|------------|-------------|--------|----------|
| PPLX-01 | 01-01-PLAN.md | User can pick Perplexity with URL/Model/API key/Headers/Timeout fields pre-populated to sane defaults | SATISFIED (indirect) | URL pre-populated to `https://api.perplexity.ai` (confirmed in AgentSettings.kt:57, BackendConfigPanel.kt:51). Model field is intentionally blank (free-form) with tooltip listing sonar examples — this is the D-08 wording gap. T3 (`load_v06xPreferencesYieldSafePerplexityDefaultsAndSchemaStaysV3`) locks all five field defaults at the deserialization boundary. The ROADMAP SC#1 wording ("Sonar-family model") describes the tooltip, not a pre-fill — recorded as KNOWN-WORDING-GAP for Phase 5. |
| PPLX-02 | 01-01-PLAN.md | User running a prompt via Perplexity hits `https://api.perplexity.ai/chat/completions` (no /v1 prefix) | SATISFIED | Direct: `PerplexityBackendFactoryTest` asserts `recorded.path == "/chat/completions"` across 4 URL edge cases (bare host, trailing slash, user-typed /v1, already-resolved /chat/completions). All 5 tests in the class pass. |
| PPLX-03 | 01-01-PLAN.md | Perplexity backend silently skips `response_format: json_object` even when callers set `jsonMode = true` | SATISFIED | Direct: `omitsResponseFormatEvenWhenJsonModeRequested` in `PerplexityBackendFactoryTest` asserts `assertFalse(body.has("response_format"), ...)` with `jsonMode = true`. Test passes. |
| PPLX-04 | 01-01-PLAN.md | Existing backends (NVIDIA NIM, Generic OpenAI-compatible) retain pre-Perplexity behaviour | SATISFIED | Direct: `OpenAiCompatibleBackendDefaultsTest` constructs `OpenAiCompatibleBackend(id=..., displayName=...)` with no `chatCompletionsBasePath` / `supportsJsonObjectResponseFormat` overrides; asserts `/v1/chat/completions` path and `json_object` response_format. Both tests pass. |
| PPLX-05 | 01-01-PLAN.md | Saved settings from v0.6.x load unchanged — new perplexity* fields default safely; no migrateIfNeeded bump | SATISFIED | Direct: `load_v06xPreferencesYieldSafePerplexityDefaultsAndSchemaStaysV3` in `AgentSettingsMigrationTest` pre-populates `settings.schema.version = 3` with zero perplexity.* keys, calls `repo.load()`, asserts all five perplexity field defaults and post-load schema = 3. Test passes. |

**Note on PPLX-01 indirect coverage:** The PLAN acknowledges that PPLX-01 is indirectly covered rather than by a dedicated UI test. The claim in `01-01-SUMMARY.md` that `SettingsDefaultsPersistenceTest` covers the "Settings → Backend round-trip" for Perplexity is inaccurate — that test only asserts MCP settings. The actual PPLX-01 coverage is T3 (load-path defaults at the deserialization boundary), which is the correct and sufficient locus per CONTEXT.md.

---

## Anti-Patterns Found

Scanned files added/modified by Phase 1:

| File | Line | Pattern | Severity | Impact |
|------|------|---------|----------|--------|
| `PerplexityBackendFactoryTest.kt` | 45, 77, 109, 141, 176 | Literal `"Bearer pplx-test"` matches Perplexity API key pattern `pplx-*` | Info | Not a real key (does not match 40+ char suffix); secret scanners may flag. Noted in code review as IN-01. No blocker. |
| `OpenAiCompatibleBackendDefaultsTest.kt` | 103 | `assertTrue(rf != null && rf.get("type").asText() == "json_object")` — collapsed assertion, no message | Info | Weak failure signal; noted as IN-03 in code review. No blocker. |
| `AgentSettingsMigrationTest.kt` | 72 | `RETURNS_DEEP_STUBS` may mask future `api.*()` method calls added to `load()` | Warning | Noted as IN-05 in code review. Not a current regression risk since `parseCustomPromptLibrary` does not currently fail in this test path. Advisory only. |

No `TBD`, `FIXME`, or `XXX` debt markers found in any file added or modified by Phase 1.

No stub patterns (empty returns, placeholder implementations) found in production code. Phase 1 added only test code.

---

## Human Verification Required

### 1. Real end-to-end Perplexity prompt smoke (ROADMAP SC#5 / D-06)

**Test:** Build the fat JAR (`./gradlew clean shadowJar`), load it in Burp Suite, go to Settings > Backend, select Perplexity, enter a valid maintainer-owned pplx-* API key and a Sonar-family model name (e.g. `sonar`), then send any short prompt from the chat panel.

**Expected:** Streamed delta chunks render progressively in the chat panel. The final assembled assistant message is complete and not truncated. No error dialog appears.

**Why human:** ROADMAP success criterion #5 explicitly requires a real end-to-end confirmation. Perplexity requires a paid API key. Project convention (D-06 in CONTEXT.md) forbids real secrets in CI. This is a one-time confidence check. After running, fill in the six D-06 fields in this file's D-06 section above and check the `[ ] Maintainer to fill` checkbox.

---

## Gaps Summary

All automated must-haves are satisfied. The only open item is structural, not a code defect:

- **D-06 manual smoke (ROADMAP SC#5):** The six field placeholders are present in the D-06 section but contain "pending" values. This is expected — the maintainer fills them in on first live run. Until they are filled, ROADMAP SC#5 cannot be declared satisfied. This is the sole reason for `status: human_needed`.

The code review warnings (WR-01 tight latch timeout, WR-02 connection leak risk, WR-03 lateinit masking) are advisory — they weaken test resilience on slow CI but do not cause the current suite to fail. They are not blockers for Phase 1 sign-off.

---

_Verified: 2026-05-13T10:00:00Z_
_Verifier: Claude (gsd-verifier)_
