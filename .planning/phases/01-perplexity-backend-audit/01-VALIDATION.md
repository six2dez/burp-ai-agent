---
phase: 1
slug: perplexity-backend-audit
status: green
nyquist_compliant: true
wave_0_complete: true
created: 2026-05-13
---

# Phase 1 — Validation Strategy

> Per-phase validation contract for feedback sampling during execution.

---

## Test Infrastructure

| Property | Value |
|----------|-------|
| **Framework** | JUnit Jupiter 6.0.3 (JUnit 5 platform via `useJUnitPlatform()`) |
| **Config file** | `build.gradle.kts:86-100` (test task + `excludeHeavyTests` filter) |
| **Quick run command** | `./gradlew test -PexcludeHeavyTests=true` |
| **Full suite command** | `./gradlew test` (fast suite + JaCoCo) |
| **Estimated runtime** | ~30–60 seconds for the full fast suite; <10s for a single new test class |

Fast-suite filter excludes class-name suffixes `*IntegrationTest`, `*ConcurrencyTest`, `*BackpressureTest`, `*RestartPolicyTest`. All Phase 1 tests live in the fast suite per **D-05**.

---

## Sampling Rate

- **After every task commit:** Run `./gradlew test -PexcludeHeavyTests=true --tests "<test class added/extended in this task>"` — runs in <10s for fresh test files.
- **After every plan wave:** Run `./gradlew test -PexcludeHeavyTests=true` — full fast suite (~30–60s).
- **Before `/gsd-verify-work`:** Full fast suite green PLUS `./gradlew ktlintCheck` green PLUS the **D-06** one-time manual Perplexity smoke recorded in `01-VERIFICATION.md`.
- **Max feedback latency:** 60 seconds (full fast suite).

---

## Per-Task Verification Map

| Task ID | Plan | Wave | Requirement | Threat Ref | Secure Behavior | Test Type | Automated Command | File Exists | Status |
|---------|------|------|-------------|------------|-----------------|-----------|-------------------|-------------|--------|
| 01-01-00 | 01 | 0 | Wave-0 dep (PPLX-02/03/04 compile prerequisite) | — | N/A — additive test dep | build wiring | `./gradlew dependencies --configuration testRuntimeClasspath \| grep -i mockwebserver` | ✅ added | ✅ green |
| 01-01-01 | 01 | 1 | PPLX-02, PPLX-03 | — | Outbound prompt is redacted upstream (ADR-5); tests use `TestSettings.baselineSettings()` so STRICT mode is default — token contract is implicit, not bypassed | unit (wire-level via MockWebServer) | `./gradlew test -PexcludeHeavyTests=true --tests "*PerplexityBackendFactoryTest"` | ✅ new file | ✅ green |
| 01-01-02 | 01 | 1 | PPLX-04 | — | Existing NVIDIA NIM / Generic OpenAI-compatible defaults remain backwards-compatible (no silent regression in non-Perplexity flows) | unit (wire-level via MockWebServer) | `./gradlew test -PexcludeHeavyTests=true --tests "*OpenAiCompatibleBackendDefaultsTest"` | ✅ new file | ✅ green |
| 01-01-03 | 01 | 1 | PPLX-05 | — | v0.6.x saved preferences load with safe defaults; no `migrateIfNeeded` schema bump | unit (settings deserialisation, `InMemoryPrefs` pattern) | `./gradlew test -PexcludeHeavyTests=true --tests "*AgentSettingsMigrationTest"` | ✅ EXTEND existing | ✅ green |
| 01-01-04 | 01 | 2 | PPLX-01 (indirect coverage via PPLX-05 defaults + existing `SettingsDefaultsPersistenceTest`) and full-phase verification | — | Full fast suite green; ktlintCheck green; manual smoke recorded | gate | `./gradlew test -PexcludeHeavyTests=true && ./gradlew ktlintCheck` | ✅ existing | ✅ green |

*Status: ⬜ pending · ✅ green · ❌ red · ⚠️ flaky*

PPLX-01's UI plumbing has indirect coverage: defaults flow through `AgentSettings` (locked by 01-01-03) and the existing `SettingsDefaultsPersistenceTest` already exercises the Settings → Backend round-trip. No new test for the UI card is required (CONTEXT.md confirms; D-08 records the SPEC §4.4 wording gap as a Phase 5 handoff).

---

## Wave 0 Requirements

- [ ] `build.gradle.kts` — add `testImplementation("com.squareup.okhttp3:mockwebserver:4.12.0")` to the `dependencies { }` block (next to lines 49–53). Version pinned to match production OkHttp 4.12.0 to avoid transitive-dep divergence.
- [ ] `src/test/kotlin/com/six2dez/burp/aiagent/backends/perplexity/` — directory does not exist; created by the new test file in 01-01-01.
- [ ] `src/test/kotlin/com/six2dez/burp/aiagent/backends/perplexity/PerplexityBackendFactoryTest.kt` — new file covering PPLX-02 (URL form, no `/v1`) and PPLX-03 (`response_format` skipped when `jsonMode = true`).
- [ ] `src/test/kotlin/com/six2dez/burp/aiagent/backends/openai/OpenAiCompatibleBackendDefaultsTest.kt` — new file covering PPLX-04 (default constructor still emits `/v1/chat/completions` and `response_format`).
- [ ] `src/test/kotlin/com/six2dez/burp/aiagent/config/AgentSettingsMigrationTest.kt` — extend with one new `@Test` covering PPLX-05 (v0.6.x prefs load with safe defaults; schema marker stays at 3).

No new shared fixtures: `TestSettings.baselineSettings()` and the existing private `InMemoryPrefs` test double inside `AgentSettingsMigrationTest` cover the surface.

---

## Manual-Only Verifications

| Behavior | Requirement | Why Manual | Test Instructions |
|----------|-------------|------------|-------------------|
| Real end-to-end Perplexity prompt round-trip | ROADMAP success criterion #5 (covers PPLX-02 at the production-API boundary) | **D-06** locks this as manual: Perplexity requires a paid API key; project policy forbids real secrets in CI; one-time confidence check is enough | (a) Build `./gradlew clean shadowJar`. (b) Load JAR in Burp. (c) Settings → Backend → Perplexity → enter maintainer's `pplx-*` key, model `sonar`. (d) Send any short prompt from the chat panel. (e) Confirm streamed response renders. (f) Record in `01-VERIFICATION.md`: API key source (maintainer's own), date, model, request count, observed streamed completion, SHA-256 of the response body. |
| Known wording gap #1 (ROADMAP success criterion #1 "Sonar-family model pre-population") | D-08 | Wording-only, not behavioural | Record `KNOWN-WORDING-GAP: ROADMAP §Phase 1 SC#1 — tooltip suggests Sonar-family names; field is not pre-filled` in `01-VERIFICATION.md`. Handoff: Phase 5 (Documentation Refresh). Does not block Phase 1 sign-off. |
| Known wording gap #2 (SPEC §4.4 lists 5 HTTP backends, omits Perplexity) | D-08 | Wording-only, not behavioural | Record `KNOWN-WORDING-GAP: SPEC §4.4 — Perplexity not yet listed` in `01-VERIFICATION.md`. Handoff: Phase 5. Does not block Phase 1 sign-off. |

---

## Validation Sign-Off

- [ ] All tasks have an `<automated>` verify or a Wave 0 dependency
- [ ] Sampling continuity: no 3 consecutive tasks without automated verify (longest gap here = 1 task, well within budget)
- [ ] Wave 0 covers all MISSING references (MockWebServer dep + new test files + new sub-directory)
- [ ] No watch-mode flags (Gradle invocations are one-shot)
- [ ] Feedback latency < 60 s (full fast suite; per-task command <10 s)
- [ ] `nyquist_compliant: true` set in frontmatter — flipped by `/gsd-validate-phase` after Wave 2 closes

**Approval:** green
