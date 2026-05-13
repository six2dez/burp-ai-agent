# Phase 1: Perplexity Backend Audit - Context

**Gathered:** 2026-05-13
**Status:** Ready for planning

<domain>
## Phase Boundary

Audit the Perplexity backend that already shipped in `[Unreleased]` (CHANGELOG `#59`) and lock its behaviour with tests so regressions cannot land in v0.7.0. The five new `perplexity*` fields in `AgentSettings`, the `PerplexityBackendFactory`, the two new constructor knobs added to `OpenAiCompatibleBackend` (`chatCompletionsBasePath`, `supportsJsonObjectResponseFormat`), and the additive (no-bump) settings schema are the audit surface.

**This phase is a behaviour-locking audit, not a feature build.** The code is shipped — the work is verifying it matches PPLX-01..05, filling test gaps identified in `.planning/codebase/TESTING.md` ("Known Coverage Gaps → PerplexityBackend HTTP path"), and reconciling two minor wording gaps between ROADMAP success criteria and the actual code.

**In scope:** unit tests for the Perplexity request/response wire shape, the URL builder (`buildChatCompletionsUrl`), the JSON-mode skip, backwards-compat assertions for non-Perplexity backends, settings deserialisation with v0.6.x preferences, manual end-to-end smoke confirmation.

**Out of scope (deferred):** changing the default model from blank to `"sonar"`, fetching Perplexity's `/models` endpoint, citation/source field handling, rate-limit-aware retries, any UI redesign of the Perplexity card.

</domain>

<decisions>
## Implementation Decisions

### Defaults policy (model + URL)

- **D-01:** Keep `perplexityModel: String = ""` (free-form, blank default). The `BackendConfigPanel` tooltip already lists `sonar`, `sonar-pro`, `sonar-reasoning` as examples; the CHANGELOG calls the field free-form deliberately so future Perplexity model names work without an extension update. The audit verifies this behaviour — it does not introduce a hard-coded default. ROADMAP success criterion #1 wording ("Sonar-family model") is reconciled by clarifying in Phase 5 (Docs Refresh) that the **tooltip lists Sonar-family names**, not that the field is pre-filled.
- **D-02:** Keep `perplexityUrl: String = "https://api.perplexity.ai"` (bare host, no path). `OpenAiCompatibleBackend.buildChatCompletionsUrl` + `PerplexityBackendFactory.buildChatCompletionsUrl` already resolve the bare host to `https://api.perplexity.ai/chat/completions` at request time, with no `/v1` prefix. The ROADMAP's `(https://api.perplexity.ai/chat/completions, ...)` describes the resolved runtime URL, not the field value. Phase 5 (Docs Refresh) clarifies this in SPEC.md if needed.
- **D-03:** No `migrateIfNeeded` schema bump. `CURRENT_SETTINGS_SCHEMA_VERSION` stays at `3`. The five new fields are additive with safe defaults; existing v0.6.x preferences load unchanged.

### Test scope and depth

- **D-04:** Wire-level capture via OkHttp `MockWebServer`. Tests assert URL form, payload shape, and presence/absence of `response_format` directly on the HTTP request that `OpenAiCompatibleConnection` produces — not via reflection on private fields. Behavioural tests are durable across internal refactors.
- **D-05:** All Perplexity tests live in the **fast suite** (`./gradlew test -PexcludeHeavyTests=true` runs them). No `*IntegrationTest` / `*ConcurrencyTest` / `*BackpressureTest` / `*RestartPolicyTest` suffix — these tests must not need a real Ktor server, real PTY, or real network.
- **D-06:** No env-gated real-API integration test in CI. Perplexity requires a paid API key; CI does not own one and project convention is no external secrets in CI. PPLX-05 / ROADMAP success criterion #5 ("Running a real prompt … returns a streamed chat completion end-to-end") is satisfied by a **one-time manual smoke** recorded in the phase verification notes when planning closes — not by a permanent integration test.
- **D-07:** Test placement:
  - New file `src/test/kotlin/com/six2dez/burp/aiagent/backends/perplexity/PerplexityBackendFactoryTest.kt` — covers PPLX-02 (URL form + no `response_format`), PPLX-03 (JSON mode skip), and the URL-builder edge cases (`/v1` user URL, trailing slash, already-resolved `/chat/completions`).
  - New file `src/test/kotlin/com/six2dez/burp/aiagent/backends/openai/OpenAiCompatibleBackendDefaultsTest.kt` — covers PPLX-04 (backwards-compat defaults for NVIDIA NIM and Generic OpenAI-compatible): same `MockWebServer` harness, asserts URL ends in `/v1/chat/completions` and `response_format: {"type":"json_object"}` is emitted when `jsonMode = true`.
  - Extend existing `src/test/kotlin/com/six2dez/burp/aiagent/config/AgentSettingsMigrationTest.kt` — new `@Test` method covers PPLX-05 (v0.6.x preferences with no `perplexity.*` keys load with safe defaults; schema version stays at 3).

### Documentation reconciliation

- **D-08:** Two ROADMAP / SPEC wording gaps that the audit surfaces but **does not fix here** — they belong to Phase 5 (Documentation Refresh):
  1. ROADMAP success criterion #1 phrasing about "Sonar-family model" pre-population (clarify: tooltip-suggested, not pre-filled).
  2. SPEC.md §4.4 currently lists only 5 HTTP backends, not Perplexity. Phase 5 adds Perplexity to §4.4.
- The audit's verification step records both as `KNOWN-WORDING-GAP` items handed to Phase 5; it does not block Phase 1 sign-off.

### Claude's Discretion

- Choice of MockWebServer vs. capturing via a custom `Interceptor` — both are acceptable; planner picks based on existing helpers in `src/test/kotlin/com/six2dez/burp/aiagent/backends/http/` (a `http/` subdir exists there — researcher should inspect what it provides).
- Whether to add a private `internal` visibility modifier to `OpenAiCompatibleConnection.chatCompletionsBasePath` to avoid reflection — only if behavioural tests cannot reach the assertion via wire capture.
- Exact test method names — follow either CamelCase (`buildsChatCompletionsUrlWithoutV1Prefix`) or backtick-quoted style; both used in this codebase per CONVENTIONS.md.

</decisions>

<canonical_refs>
## Canonical References

**Downstream agents MUST read these before planning or implementing.**

### Authoritative behavioural spec
- `.planning/REQUIREMENTS.md` § "Perplexity Backend" — PPLX-01..05 are the requirements this phase locks.
- `.planning/ROADMAP.md` § "Phase 1: Perplexity Backend Audit" — five success criteria, two of which (#1 wording, #5 manual confirmation) are flagged in D-08 / D-06.
- `SPEC.md` §4.4 (Pluggable AI backends) — the contract Perplexity must fit; lists Ollama / LM Studio / NVIDIA NIM / Generic OpenAI-compatible / Burp native AI. Phase 5 adds Perplexity here; Phase 1 only verifies the in-code contract is consistent with §4.4.
- `CHANGELOG.md` `[Unreleased]` § "Added → Perplexity backend (#59)" and § "Changed → `OpenAiCompatibleBackend` is more configurable" — declarative description of what shipped. Treat as authoritative for what behaviour the audit must lock.

### Architecture decisions
- `DECISIONS.md` ADR-3 (Pluggable backends via ServiceLoader) — new backends register one line in `META-INF/services/`; Perplexity already does.
- `DECISIONS.md` ADR-4 (HTTP vs CLI hierarchies) — Perplexity is an HTTP backend extending `OpenAiCompatibleBackend`; tests must not depend on `CliBackend` plumbing.
- `DECISIONS.md` ADR-5 (Privacy redaction pre-flight) — Perplexity backend sees redacted prompts only; tests must use `TestSettings.baselineSettings()` defaults so this contract is implicit, not bypassed.

### Codebase intel
- `.planning/codebase/STACK.md` § "Testing" — JUnit Jupiter 6.0.3, Mockito-Kotlin 5.4.0, OkHttp's MockWebServer is the standard wire-capture harness.
- `.planning/codebase/TESTING.md` § "Known Coverage Gaps → PerplexityBackend HTTP path" — explicitly names this audit as a scheduled coverage gap; the new test files in D-07 close it.
- `.planning/codebase/CONVENTIONS.md` § "HTTP Backend (subclass of `OpenAiCompatibleBackend`)" — documents the factory pattern Perplexity uses; § "Settings Persistence (`AgentSettings`)" documents schema versioning.
- `.planning/codebase/STRUCTURE.md` § "backends/" — directory + naming conventions for the new test files.

### Source files under audit
- `src/main/kotlin/com/six2dez/burp/aiagent/backends/perplexity/PerplexityBackendFactory.kt` — factory, `DEFAULT_BASE_URL`, `perplexityHealthCheck`, `buildChatCompletionsUrl`.
- `src/main/kotlin/com/six2dez/burp/aiagent/backends/openai/OpenAiCompatibleBackend.kt` lines 42–47 (constructor `chatCompletionsBasePath`, `supportsJsonObjectResponseFormat`), lines 183–187 (`jsonMode && supportsJsonObjectResponseFormat` gate), lines 411–423 (URL builder), line 429 (models URL builder).
- `src/main/kotlin/com/six2dez/burp/aiagent/config/AgentSettings.kt` lines 57–61 (data-class fields), lines 257–267 (load), lines 410–414 (defaults), lines 508–512 (save), lines 691–695 (preference keys), line 780 (`CURRENT_SETTINGS_SCHEMA_VERSION = 3`), line 822 (`defaultPerplexityUrl()`).
- `src/main/kotlin/com/six2dez/burp/aiagent/ui/panels/BackendConfigPanel.kt` lines 96–100, 170–174, 186, 227–231, 423–432 — Perplexity card and bindings.
- `src/main/resources/META-INF/services/com.six2dez.burp.aiagent.backends.AiBackendFactory` — Perplexity factory already registered.

### Test scaffolding to lean on
- `src/test/kotlin/com/six2dez/burp/aiagent/TestSettings.kt` — `baselineSettings()` factory; tests use this, not hand-rolled `AgentSettings(...)`.
- `src/test/kotlin/com/six2dez/burp/aiagent/backends/http/` — existing HTTP test helpers (researcher: inventory this directory before planning).
- `src/test/kotlin/com/six2dez/burp/aiagent/config/AgentSettingsMigrationTest.kt` — extends here for PPLX-05; uses `InMemoryPrefs` pattern.
- `src/test/kotlin/com/six2dez/burp/aiagent/mcp/McpServerIntegrationTest.kt` — example of MockWebServer-style server harness (heavy suite; reference for shape, not for copy-paste, since Perplexity tests stay fast-suite).

</canonical_refs>

<code_context>
## Existing Code Insights

### Reusable Assets
- **`OpenAiCompatibleBackend`** — `PerplexityBackendFactory` already delegates to it via the new constructor knobs. Tests construct an `OpenAiCompatibleBackend(...)` directly for both Perplexity (`chatCompletionsBasePath = "/chat/completions"`, `supportsJsonObjectResponseFormat = false`) and the default shape (no overrides) — one test class can cover both with parametrisation or with two `@Test` methods.
- **`TestSettings.baselineSettings()`** — supply the canonical settings fixture; override only the `perplexity*` fields under test.
- **`HttpBackendSupport.sharedClient(baseUrl, timeout)`** — used by the production factory's health check; tests should NOT call this directly. Instead, tests inject a `MockWebServer.url(...)` as the `baseUrl` so the connection picks up the OkHttp client transparently.
- **`HeaderParser.parse(...)` / `HeaderParser.withBearerToken(...)`** — already covered by other tests; do not retest them in this phase.
- **`PerplexityBackendFactory.buildChatCompletionsUrl(...)` and `OpenAiCompatibleBackend.buildChatCompletionsUrl(...)`** — two URL-builder copies (one private in factory, one private in the connection). Tests exercise both via behaviour: hit the factory's health check path and the connection's chat path, assert the resolved URL. Do not refactor them in this phase (scope creep).
- **`InMemoryPrefs` test double** — from `AgentSettingsMigrationTest`; reuse pattern for PPLX-05.

### Established Patterns
- **Test method naming**: both CamelCase (`strictModeStripsCookiesTokensAndHosts`) and backticked (`` `test circular buffer enforcement` ``) accepted. Prefer CamelCase for ktlint friendliness (CONVENTIONS.md).
- **Wire-level test pattern**: spin a `MockWebServer`, configure `MockResponse` for both success and 401/403/429, capture the recorded `RecordedRequest` and assert path + body JSON.
- **JSON inspection in tests**: use `ObjectMapper().registerKotlinModule()` to parse captured request bodies; assert key presence/absence rather than full payload equality (so optional fields like `temperature` don't make the test brittle).
- **Settings migration tests**: build `InMemoryPrefs`, pre-populate with v3 keys only (no `perplexity.*`), construct `AgentSettingsRepository`, call `repo.load()`, assert defaults and post-load schema version.

### Integration Points
- **SPI**: `PerplexityBackendFactory` already registered in `META-INF/services/com.six2dez.burp.aiagent.backends.AiBackendFactory` line 7. `BackendRegistryTest` already covers discovery; this phase does not retest registration.
- **UI**: `BackendConfigPanel.buildPerplexityPanel()` is plumbed; the audit verifies but does not retest UI wiring (covered indirectly by `SettingsDefaultsPersistenceTest`).
- **Audit log**: Perplexity prompts flow through `AiRequestLogger` and `AuditLogger` via the standard `BackendDiagnostics` hook — covered by existing tests for those subsystems; not in audit scope.
- **`migrateIfNeeded`**: untouched. PPLX-05 explicitly verifies no bump.

</code_context>

<specifics>
## Specific Ideas

- **Wire assertions for PPLX-02 must be precise**: the audit's main lock is that the path the backend POSTs to is exactly `/chat/completions` — no leading `/v1`, no trailing slash, regardless of whether the user-configured URL was `https://api.perplexity.ai`, `https://api.perplexity.ai/`, `https://api.perplexity.ai/chat/completions`, or `https://api.perplexity.ai/v1`. Each of these should be a separate parametrised case or method.
- **Wire assertion for PPLX-03**: the captured `RecordedRequest` body must NOT contain the JSON key `response_format`, even when the test calls into the connection with `jsonMode = true`. The corresponding NVIDIA-NIM / Generic-OpenAI-compatible test in `OpenAiCompatibleBackendDefaultsTest` asserts the opposite: `response_format` IS present and equals `{"type":"json_object"}` under the same `jsonMode = true` call.
- **PPLX-04 backwards-compat assertion**: don't test the private fields directly. Test by constructing `OpenAiCompatibleBackend(...)` with the bare minimum required args (no `chatCompletionsBasePath` or `supportsJsonObjectResponseFormat` overrides) and asserting the wire request still has `/v1/chat/completions` and `response_format`. This locks the defaults via behaviour.
- **Manual smoke (D-06)** is recorded as a short paragraph in the phase's verification artefact (probably `01-VERIFICATION.md` after `/gsd-execute-phase`) listing: API key source (maintainer's own, not in CI), date of run, model used, request count, observed streamed completion, and a SHA-256 of the response body. Not a test; just an audit trail.

</specifics>

<deferred>
## Deferred Ideas

- **Model dropdown / `/models` fetch** — UI improvement that would let users pick a Sonar variant from a list rather than typing. Out of scope; future phase.
- **Citation / source field handling** — Perplexity Sonar models return a `citations` array. Today the agent treats them as opaque text. A future enhancement could surface them in the chat UI. Out of scope.
- **Perplexity-specific rate limit handling** — Sonar API returns 429 with `Retry-After`. The shared circuit breaker handles failures but does not honour `Retry-After` headers. Out of scope; future enhancement on `OpenAiCompatibleBackend` or `HttpBackendSupport`.
- **Real-API integration test** — env-var-gated, nightly-only. Deferred until project policy on CI-side API keys is reviewed; for v0.7.0 the manual smoke is sufficient.
- **Refactoring the duplicate `buildChatCompletionsUrl` implementations** (one in `OpenAiCompatibleBackend`, one in `PerplexityBackendFactory`) — visible during audit but not scope. Capture as a follow-up grooming task post-v0.7.0.

</deferred>

---

*Phase: 1-Perplexity Backend Audit*
*Context gathered: 2026-05-13*
