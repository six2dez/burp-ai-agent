# Phase 1: Perplexity Backend Audit - Research

**Researched:** 2026-05-13
**Domain:** HTTP backend behaviour locking (Kotlin + OkHttp + JUnit 5 + Jackson)
**Confidence:** HIGH (every claim verified against the source tree at HEAD; no external library guesses except MockWebServer add)

<user_constraints>
## User Constraints (from CONTEXT.md)

### Locked Decisions

- **D-01:** Keep `perplexityModel: String = ""` (free-form, blank default). The `BackendConfigPanel` tooltip already lists `sonar`, `sonar-pro`, `sonar-reasoning` as examples; the CHANGELOG calls the field free-form deliberately so future Perplexity model names work without an extension update. The audit verifies this behaviour — it does not introduce a hard-coded default. ROADMAP success criterion #1 wording ("Sonar-family model") is reconciled by clarifying in Phase 5 (Docs Refresh) that the **tooltip lists Sonar-family names**, not that the field is pre-filled. `[VERIFIED: AgentSettings.kt:58, BackendConfigPanel.kt:171]`
- **D-02:** Keep `perplexityUrl: String = "https://api.perplexity.ai"` (bare host, no path). `OpenAiCompatibleBackend.buildChatCompletionsUrl` + `PerplexityBackendFactory.buildChatCompletionsUrl` already resolve the bare host to `https://api.perplexity.ai/chat/completions` at request time, with no `/v1` prefix. The ROADMAP's `(https://api.perplexity.ai/chat/completions, ...)` describes the resolved runtime URL, not the field value. Phase 5 (Docs Refresh) clarifies this in SPEC.md if needed. `[VERIFIED: AgentSettings.kt:57, OpenAiCompatibleBackend.kt:408-418]`
- **D-03:** No `migrateIfNeeded` schema bump. `CURRENT_SETTINGS_SCHEMA_VERSION` stays at `3`. The five new fields are additive with safe defaults; existing v0.6.x preferences load unchanged. `[VERIFIED: AgentSettings.kt:780, 624-643]`
- **D-04:** Wire-level capture via OkHttp `MockWebServer`. Tests assert URL form, payload shape, and presence/absence of `response_format` directly on the HTTP request that `OpenAiCompatibleConnection` produces — not via reflection on private fields. Behavioural tests are durable across internal refactors. `[VERIFIED: not yet a dep — see Risks #1]`
- **D-05:** All Perplexity tests live in the **fast suite** (`./gradlew test -PexcludeHeavyTests=true` runs them). No `*IntegrationTest` / `*ConcurrencyTest` / `*BackpressureTest` / `*RestartPolicyTest` suffix — these tests must not need a real Ktor server, real PTY, or real network. `[VERIFIED: build.gradle.kts:88-99]`
- **D-06:** No env-gated real-API integration test in CI. Perplexity requires a paid API key; CI does not own one and project convention is no external secrets in CI. PPLX-05 / ROADMAP success criterion #5 ("Running a real prompt … returns a streamed chat completion end-to-end") is satisfied by a **one-time manual smoke** recorded in the phase verification notes when planning closes — not by a permanent integration test.
- **D-07:** Test placement:
  - New file `src/test/kotlin/com/six2dez/burp/aiagent/backends/perplexity/PerplexityBackendFactoryTest.kt` — covers PPLX-02 (URL form + no `response_format`), PPLX-03 (JSON mode skip), and the URL-builder edge cases (`/v1` user URL, trailing slash, already-resolved `/chat/completions`).
  - New file `src/test/kotlin/com/six2dez/burp/aiagent/backends/openai/OpenAiCompatibleBackendDefaultsTest.kt` — covers PPLX-04 (backwards-compat defaults for NVIDIA NIM and Generic OpenAI-compatible).
  - Extend existing `src/test/kotlin/com/six2dez/burp/aiagent/config/AgentSettingsMigrationTest.kt` — new `@Test` method covers PPLX-05.
- **D-08:** Two ROADMAP / SPEC wording gaps surfaced but **not fixed here** — they belong to Phase 5 (Documentation Refresh). Verification step records both as `KNOWN-WORDING-GAP`; does not block sign-off.

### Claude's Discretion

- Choice of MockWebServer vs. capturing via a custom OkHttp `Interceptor` — both are acceptable; planner picks based on existing helpers in `src/test/kotlin/com/six2dez/burp/aiagent/backends/http/` (no MockWebServer wrapper exists there yet — see Risks #1).
- Whether to add an `internal` visibility modifier to `OpenAiCompatibleConnection.chatCompletionsBasePath` — only if behavioural tests cannot reach the assertion via wire capture (research shows they CAN, so this is unnecessary).
- Exact test method names — follow either CamelCase (`buildsChatCompletionsUrlWithoutV1Prefix`) or backtick-quoted style; CONVENTIONS.md prefers CamelCase for ktlint friendliness.

### Deferred Ideas (OUT OF SCOPE)

- Model dropdown / `/models` fetch
- Citation / source field handling
- Perplexity-specific rate limit handling (`Retry-After` header)
- Real-API integration test (env-gated, nightly-only)
- Refactoring the duplicate `buildChatCompletionsUrl` implementations
</user_constraints>

<phase_requirements>
## Phase Requirements

| ID | Description | Research Support |
|----|-------------|------------------|
| PPLX-01 | User can pick Perplexity in Settings → Backend with URL / Model / API key / Headers / Timeout fields pre-populated to sane defaults | `BackendConfigPanel.kt:96-100, 170-174, 227-231, 423-435` shows the card is plumbed; `AgentSettings.kt:57-61` shows defaults. Locked indirectly by `SettingsDefaultsPersistenceTest` (existing test) and PPLX-05's new test — no new test required for the UI plumbing per se. |
| PPLX-02 | User running a prompt via Perplexity gets a successful chat completion against `https://api.perplexity.ai/chat/completions` (no `/v1` prefix) using a Sonar-family model | New `PerplexityBackendFactoryTest` — wire-level assertion that the captured `RecordedRequest.path` equals `/chat/completions` (no `/v1`); construct the backend, point `perplexityUrl` at `MockWebServer.url("").toString()`, fire one `send(...)` call, parse the SSE response, assert recorded request shape. |
| PPLX-03 | Perplexity backend silently skips the unsupported `response_format: json_object` field even when `jsonMode = true` — JSON intent is preserved in the system prompt | New `PerplexityBackendFactoryTest` — wire-level assertion that the captured JSON body has no `response_format` key when `jsonMode = true`. The system prompt path is owned by the scanner (out of scope for this audit; covered by existing `PassiveAiScannerJsonParsingTest`). |
| PPLX-04 | Existing backends (NVIDIA NIM, Generic OpenAI-compatible) still behave identically — `OpenAiCompatibleBackend` constructor defaults are backwards-compatible | New `OpenAiCompatibleBackendDefaultsTest` — construct `OpenAiCompatibleBackend()` with bare-minimum args (no overrides for `chatCompletionsBasePath` / `supportsJsonObjectResponseFormat`); wire-assert URL ends `/v1/chat/completions` AND `response_format: {"type":"json_object"}` is present when `jsonMode = true`. |
| PPLX-05 | Saved settings from v0.6.x load unchanged — new `perplexity*` fields default safely; no `migrateIfNeeded` bump required | Extend `AgentSettingsMigrationTest` — pre-populate `InMemoryPrefs` with `settings.schema.version = 3` and zero `perplexity.*` keys; call `repo.load()`; assert `perplexityUrl == "https://api.perplexity.ai"`, `perplexityModel == ""`, `perplexityTimeoutSeconds == 120` (Defaults.CLI_PROCESS_TIMEOUT_SECONDS), and `prefs.integers["settings.schema.version"] == 3` (unchanged). |
</phase_requirements>

## Summary

The Perplexity backend has already shipped (CHANGELOG `[Unreleased]` PR #59). It is implemented as a thin `AiBackendFactory` that delegates to `OpenAiCompatibleBackend` with two new constructor knobs (`chatCompletionsBasePath = "/chat/completions"`, `supportsJsonObjectResponseFormat = false`) plus the standard `baseUrl/model/apiKey/headers/timeout` selectors. Five new fields on `AgentSettings` (`perplexityUrl`, `perplexityModel`, `perplexityApiKey`, `perplexityHeaders`, `perplexityTimeoutSeconds`) hold its configuration; all have safe defaults and load via standard preference plumbing — no migration code, no schema bump. The current test tree has **zero coverage** of the Perplexity wire path (`.planning/codebase/TESTING.md` "Known Coverage Gaps" calls this out by name).

This phase locks five behaviours with three new/extended test files:

1. **Wire-shape assertions** for PPLX-02 (URL form) and PPLX-03 (no `response_format`) via `MockWebServer` in `PerplexityBackendFactoryTest`.
2. **Backwards-compat wire-shape assertions** for PPLX-04 in `OpenAiCompatibleBackendDefaultsTest` (URL ends `/v1/chat/completions` + `response_format` present).
3. **Settings deserialisation** for PPLX-05 by extending `AgentSettingsMigrationTest` with the existing `InMemoryPrefs` pattern.

**Primary recommendation:** Add `testImplementation("com.squareup.okhttp3:mockwebserver:4.12.0")` to `build.gradle.kts`, then write three test files following CONVENTIONS.md (CamelCase method names, `TestSettings.baselineSettings()` for fixtures, JUnit Jupiter assertions, Jackson `ObjectMapper().registerKotlinModule()` for body inspection).

## Architectural Responsibility Map

| Capability | Primary Tier | Secondary Tier | Rationale |
|------------|-------------|----------------|-----------|
| URL form locking (no `/v1`) | Backend factory + `OpenAiCompatibleBackend` (HTTP backend tier) | — | The Perplexity URL contract is purely an HTTP-request property; assertions belong at the HTTP layer where the request is built, not the UI / supervisor / scanner tiers. `[VERIFIED: OpenAiCompatibleBackend.kt:190 endpointUrl = buildChatCompletionsUrl(baseUrl)]` |
| `response_format` skip gating | `OpenAiCompatibleConnection` (HTTP backend tier) | — | The gate is one line in the backend: `if (jsonMode && supportsJsonObjectResponseFormat)`. No other tier participates. `[VERIFIED: OpenAiCompatibleBackend.kt:185-187]` |
| Settings deserialisation | `AgentSettingsRepository` (config tier) | — | Defaults flow through `load()`; no UI or backend involvement. Existing `AgentSettingsMigrationTest` already lives in `config/`. `[VERIFIED: AgentSettings.kt:257-267]` |
| Backwards-compat defaults | `OpenAiCompatibleBackend` constructor defaults (HTTP backend tier) | — | Defaults `chatCompletionsBasePath = "/v1/chat/completions"` and `supportsJsonObjectResponseFormat = true` are constructor-level; testable via wire-shape from any caller that omits them. `[VERIFIED: OpenAiCompatibleBackend.kt:44, 47]` |
| Manual end-to-end smoke (PPLX-05 success criterion #5) | Maintainer (operational tier) | — | D-06 locks this as a one-time manual recording, not an automated test. Belongs in `01-VERIFICATION.md`, not in the test suite. |

## Standard Stack

### Core (already in build.gradle.kts, no version changes needed)

| Library | Version | Purpose | Why Standard |
|---------|---------|---------|--------------|
| JUnit Jupiter | 6.0.3 | Test runner via `useJUnitPlatform()` | Project standard; every existing test uses it. `[VERIFIED: build.gradle.kts:50]` |
| Mockito-Kotlin | 5.4.0 | Mocking for Burp Montoya interfaces and `Preferences` | Project standard; used in `AgentSettingsMigrationTest`. `[VERIFIED: build.gradle.kts:52]` |
| Jackson + jackson-module-kotlin | 2.21.2 | JSON inspection of captured request bodies | Already used in `PerplexityBackendFactory.kt:40` and `OpenAiCompatibleBackend.kt:51` as `ObjectMapper().registerKotlinModule()`. `[VERIFIED: build.gradle.kts:27-28]` |
| OkHttp | 4.12.0 | Underlying HTTP client (production); MockWebServer pairs with it | Already in `implementation`. `[VERIFIED: build.gradle.kts:31]` |

### Supporting (NEW — must be added)

| Library | Version | Purpose | When to Use |
|---------|---------|---------|-------------|
| `com.squareup.okhttp3:mockwebserver` | 4.12.0 (match OkHttp version exactly) | In-process HTTP server for wire-level assertions | All new Perplexity tests and the new `OpenAiCompatibleBackendDefaultsTest`. `[CITED: https://central.sonatype.com/artifact/com.squareup.okhttp3/mockwebserver/4.12.0]` |

**Installation:**

Add one line to `build.gradle.kts` in the `dependencies { }` block (anywhere among the existing `testImplementation` lines, lines 49-53):

```kotlin
testImplementation("com.squareup.okhttp3:mockwebserver:4.12.0")
```

**Version verification:** MockWebServer 4.12.0 published 2023-10-17 on Maven Central; matches the OkHttp version this project already uses, so they share the same transitive deps with no version conflict. `[CITED: https://central.sonatype.com/artifact/com.squareup.okhttp3/mockwebserver/4.12.0]`

### Alternatives Considered

| Instead of | Could Use | Tradeoff |
|------------|-----------|----------|
| MockWebServer | OkHttp `Interceptor` capturing requests in-memory | Cleaner classpath (no extra dep), but you cannot exercise the streaming SSE response branch realistically. MockWebServer is the project's stated standard per `.planning/codebase/TESTING.md`. |
| MockWebServer | WireMock | WireMock pulls in Jetty + a much larger transitive footprint and is overkill for one endpoint per test. Reject. |
| Reflection on `chatCompletionsBasePath` / `supportsJsonObjectResponseFormat` | Wire-level capture | Reflection couples tests to private field names; wire-level locks observable behaviour. D-04 explicitly locks wire-level. |

## Architecture Patterns

### System Architecture Diagram

```
                ┌──────────────────────────────────────────────────┐
                │ Test                                             │
                │   1. start MockWebServer, get url("/")           │
                │   2. settings = TestSettings.baselineSettings()  │
                │      .copy(perplexityUrl = mockUrl, ...)         │
                │   3. backend = PerplexityBackendFactory().create()
                │      OR new OpenAiCompatibleBackend()            │
                │   4. connection = backend.launch(BackendLaunchConfig)
                │   5. connection.send(text, jsonMode=true, ...)   │
                └─────────────────────┬────────────────────────────┘
                                      │ POST <captured>
                                      ▼
                ┌──────────────────────────────────────────────────┐
                │ OpenAiCompatibleConnection.send()                │
                │  - builds payload (incl. response_format gate)   │
                │  - endpointUrl = buildChatCompletionsUrl(baseUrl)│
                │  - if streaming: SSE; else: JSON                 │
                └─────────────────────┬────────────────────────────┘
                                      │ HTTP request
                                      ▼
                ┌──────────────────────────────────────────────────┐
                │ HttpBackendSupport.sharedClient(baseUrl, timeout)│
                │  - cached OkHttpClient keyed by (url, timeout)   │
                │  - request goes here via OkHttp                  │
                └─────────────────────┬────────────────────────────┘
                                      │
                                      ▼
                ┌──────────────────────────────────────────────────┐
                │ MockWebServer (test-controlled)                  │
                │  - enqueue(MockResponse) before send             │
                │  - takeRequest() returns RecordedRequest         │
                │    * path = "/chat/completions" (or /v1/...)     │
                │    * body bytes = the JSON the backend sent      │
                │    * headers map (Authorization, X-Session-Id…)  │
                └──────────────────────────────────────────────────┘

Assertion targets:
  - RecordedRequest.path                          (URL form)
  - mapper.readTree(RecordedRequest.body.utf8()) keys
        .has("response_format")                   (JSON mode gate)
        .get("messages").size()                   (smoke)
        .get("stream").booleanValue()             (streaming flag)
```

The diagram shows what the planner needs: every assertion is on the captured `RecordedRequest`, not on the backend's private state.

### Recommended Project Structure

```
src/test/kotlin/com/six2dez/burp/aiagent/
├── TestSettings.kt                               # existing — extend if needed
├── backends/
│   ├── BackendHealthCheckTest.kt                 # existing
│   ├── BackendRegistryTest.kt                    # existing (covers SPI; do NOT retest)
│   ├── http/
│   │   ├── CircuitBreakerTest.kt                 # existing
│   │   ├── ConversationHistoryTest.kt            # existing
│   │   └── MontoyaHttpTransportUtf8Test.kt       # existing
│   ├── openai/
│   │   └── OpenAiCompatibleBackendDefaultsTest.kt    # NEW — PPLX-04
│   └── perplexity/
│       └── PerplexityBackendFactoryTest.kt           # NEW — PPLX-02, PPLX-03
└── config/
    └── AgentSettingsMigrationTest.kt             # extend — PPLX-05
```

Directory `backends/perplexity/` does not exist yet — the planner must create it.

### Pattern 1: MockWebServer wire-capture for one chat call

Use this exact shape for every wire-level assertion. It works in the fast suite (no port binding to OS-restricted ports; MockWebServer chooses a free localhost port at `start()`).

```kotlin
// New PerplexityBackendFactoryTest.kt
package com.six2dez.burp.aiagent.backends.perplexity

import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.module.kotlin.registerKotlinModule
import com.six2dez.burp.aiagent.TestSettings
import com.six2dez.burp.aiagent.backends.BackendLaunchConfig
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit

class PerplexityBackendFactoryTest {
    private lateinit var server: MockWebServer
    private val mapper = ObjectMapper().registerKotlinModule()

    @BeforeEach
    fun setup() {
        server = MockWebServer()
        server.start()
    }

    @AfterEach
    fun teardown() {
        server.shutdown()
    }

    @Test
    fun targetsChatCompletionsWithoutV1PrefixOnBareHost() {
        // Source: project convention (TESTING.md "Wire-level test pattern")
        server.enqueue(streamedResponse())
        val backend = PerplexityBackendFactory().create()
        val baseUrl = server.url("/").toString().trimEnd('/')
        // baseUrl is e.g. http://127.0.0.1:54321 (no path)

        val connection = backend.launch(
            BackendLaunchConfig(
                backendId = "perplexity",
                displayName = "Perplexity",
                baseUrl = baseUrl,
                model = "sonar",
                headers = mapOf("Authorization" to "Bearer pplx-test"),
                requestTimeoutSeconds = 30L,
            ),
        )

        val done = CountDownLatch(1)
        connection.send(
            text = "hello",
            onChunk = {},
            onComplete = { done.countDown() },
            jsonMode = true,
        )
        assertTrue(done.await(5, TimeUnit.SECONDS))

        val recorded = server.takeRequest(1, TimeUnit.SECONDS) ?: error("no request")
        assertEquals("/chat/completions", recorded.path)
        assertEquals("POST", recorded.method)
    }

    @Test
    fun omitsResponseFormatEvenWhenJsonModeRequested() {
        server.enqueue(streamedResponse())
        val backend = PerplexityBackendFactory().create()
        // ... same setup as above, jsonMode = true ...
        val recorded = server.takeRequest(1, TimeUnit.SECONDS) ?: error("no request")
        val body = mapper.readTree(recorded.body.readUtf8())
        assertFalse(body.has("response_format"), "Perplexity must not emit response_format")
        // Smoke: ensure the body still has the standard OpenAI shape
        assertTrue(body.has("model"))
        assertTrue(body.has("messages"))
    }

    // A minimal SSE response that lets the connection complete cleanly:
    private fun streamedResponse(): MockResponse =
        MockResponse()
            .setResponseCode(200)
            .setHeader("Content-Type", "text/event-stream")
            .setBody(
                "data: {\"choices\":[{\"delta\":{\"content\":\"ok\"}}]}\n\n" +
                    "data: [DONE]\n\n",
            )
}
```

**What:** Lock the wire shape with one `MockWebServer` per `@Test`. `BeforeEach`/`AfterEach` keep state isolated; no shared server state means tests can run in parallel without ordering issues.

**When to use:** All three URL-form variants in PPLX-02 (bare host, trailing slash, `/v1`, already-`/chat/completions`) and the `response_format` gate in PPLX-03.

### Pattern 2: Extend `AgentSettingsMigrationTest` for PPLX-05

The existing test file uses `InMemoryPrefs` (a Mockito-Kotlin–backed test double for `Preferences`) and constructs `AgentSettingsRepository` directly. Add a new `@Test` method, do not create a new file.

```kotlin
// Extend AgentSettingsMigrationTest.kt
@Test
fun load_v06xPreferencesYieldSafePerplexityDefaultsAndSchemaStaysV3() {
    val prefs = InMemoryPrefs()
    // Simulate a v0.6.x install: schema marker present, no perplexity.* keys.
    prefs.integers["settings.schema.version"] = 3
    // Optionally simulate other v0.6.x state so the test reads realistically:
    prefs.strings["backend.preferred"] = "openai-compatible"

    val repo = AgentSettingsRepository(apiWith(prefs.mock))
    val loaded = repo.load()

    assertEquals("https://api.perplexity.ai", loaded.perplexityUrl)
    assertEquals("", loaded.perplexityModel)
    assertEquals("", loaded.perplexityApiKey)
    assertEquals("", loaded.perplexityHeaders)
    // Defaults.CLI_PROCESS_TIMEOUT_SECONDS — verify by reading Defaults.kt;
    // current value is 120. If Defaults changes, this test correctly fails
    // and signals the contract has moved.
    assertEquals(120, loaded.perplexityTimeoutSeconds)
    assertEquals(3, prefs.integers["settings.schema.version"])
}
```

**What:** Lock the additive-fields contract — v0.6.x preferences carry no `perplexity.*` keys, so `load()` must supply the data-class defaults without touching the schema version.

**When to use:** Exactly once, for PPLX-05.

### Pattern 3: Backwards-compat assertion for `OpenAiCompatibleBackend`

```kotlin
// New OpenAiCompatibleBackendDefaultsTest.kt
@Test
fun defaultsKeepV1PrefixAndEmitResponseFormatWhenJsonModeRequested() {
    server.enqueue(/* non-streaming JSON response */)
    // Bare-minimum constructor — NO overrides for chatCompletionsBasePath or supportsJsonObjectResponseFormat
    val backend = OpenAiCompatibleBackend(
        id = "test-default",
        displayName = "Default",
    )
    val baseUrl = server.url("/").toString().trimEnd('/')
    val connection = backend.launch(BackendLaunchConfig(
        backendId = "test-default",
        displayName = "Default",
        baseUrl = baseUrl,
        model = "gpt-4o",
        headers = emptyMap(),
        requestTimeoutSeconds = 30L,
    ))
    // ... call send(..., jsonMode = true), wait for completion, inspect recorded request ...
    val recorded = server.takeRequest(1, TimeUnit.SECONDS)!!
    assertEquals("/v1/chat/completions", recorded.path)
    val body = mapper.readTree(recorded.body.readUtf8())
    val rf = body.get("response_format")
    assertTrue(rf != null && rf.get("type").asText() == "json_object")
}
```

**What:** Lock the constructor defaults via behaviour. If a future refactor accidentally changes the default of `chatCompletionsBasePath` or `supportsJsonObjectResponseFormat`, this test goes red.

**When to use:** Exactly once, for PPLX-04.

### Anti-Patterns to Avoid

- **Reflection on private fields.** D-04 explicitly locks wire-level capture. Reflection (`Class.getDeclaredField(...).isAccessible = true`) couples the test to private names — that name can change without changing observable behaviour, and we don't want red tests for compatible refactors.
- **Real network calls.** No call to `api.perplexity.ai` in any test. D-06 + D-05 explicitly forbid real-API integration tests in CI.
- **Manually constructing `AgentSettings(...)` inline.** Use `TestSettings.baselineSettings().copy(perplexity... = ...)`. `BackendRegistryTest.kt` currently inlines a full constructor — that file is legacy per TESTING.md and should not be the model. `[VERIFIED: TESTING.md:187 "tests that inline a full AgentSettings constructor are legacy — migrate to TestSettings when touching those files"]`
- **Asserting full body equality.** Optional fields (`temperature`, `max_tokens`, `top_p`) may shift across refactors without breaking the contract. Use `body.has("...")` / `body.get("...").asText()` assertions per CONTEXT.md.
- **Sharing one `MockWebServer` across `@Test` methods via a `companion object`.** Each test gets its own — keeps the recorded-request queue isolated and lets the fast suite parallelise safely if Gradle changes its default.

## Don't Hand-Roll

| Problem | Don't Build | Use Instead | Why |
|---------|-------------|-------------|-----|
| In-process HTTP server for capturing requests | Hand-rolled `ServerSocket` + manual HTTP parser | `okhttp3.mockwebserver.MockWebServer` | MockWebServer handles SSE chunked transfer, keep-alive, headers, etc. — already battle-tested by Square against the same OkHttp client this codebase uses. `[CITED: https://square.github.io/okhttp/]` |
| JSON request body inspection | Regex on raw strings | `ObjectMapper().registerKotlinModule().readTree(bytes)` | Jackson is already a project dep; `readTree` gives `body.has("response_format")` and `body.get("messages").size()` cleanly. `[VERIFIED: PerplexityBackendFactory.kt:40 already uses this idiom in production]` |
| `Preferences` test double for `AgentSettings` | New mock class | Existing private `InMemoryPrefs` in `AgentSettingsMigrationTest.kt:60-88` | The pattern is already in the test file you're extending — reuse it. `[VERIFIED: AgentSettingsMigrationTest.kt:60-88]` |
| Canonical settings fixture | Build a full `AgentSettings(...)` constructor | `TestSettings.baselineSettings().copy(...)` | Project convention (CONVENTIONS.md and TESTING.md both call this out). `[VERIFIED: TestSettings.kt:10-96]` |
| Streaming SSE response stub | Custom subclass of OkHttp `MockResponse` | Plain `MockResponse().setHeader("Content-Type","text/event-stream").setBody(...)` with `data: {...}\n\n` lines | OpenAiCompatibleBackend's stream reader splits on `data:` line prefix (verified `OpenAiCompatibleBackend.kt:360-365`); MockResponse delivers raw bytes as-is. |

**Key insight:** Every problem this audit solves is already solved somewhere in the test tree (`InMemoryPrefs`) or the production code (`ObjectMapper().registerKotlinModule()`) or by a library Square ships next to OkHttp (`MockWebServer`). The planner's job is composition, not invention.

## File-by-File Findings (answers to the planner's questions)

### Q1: How does `OpenAiCompatibleConnection` pick up a custom base URL?

The whole chain is `BackendLaunchConfig.baseUrl` → `OpenAiCompatibleBackend.launch()` (sets it on the `OpenAiCompatibleConnection`) → `OpenAiCompatibleConnection.send()` builds the request via `HttpBackendSupport.sharedClient(baseUrl, timeoutSeconds)` and `buildChatCompletionsUrl(baseUrl)`. `[VERIFIED: OpenAiCompatibleBackend.kt:53-79, 174-247]`

**For tests:** set `BackendLaunchConfig(baseUrl = mockWebServer.url("/").toString().trimEnd('/'), ...)` and call `backend.launch(config)` directly. **Do NOT call `HttpBackendSupport.sharedClient(...)` from the test** — the connection does it internally with whatever `baseUrl` you pass. The `sharedClient` cache key is `(baseUrl.lowercase(), timeoutSeconds)`, so each `MockWebServer` (which gets a unique free port) gets its own client; there is no test-cross-contamination via the shared client pool. `[VERIFIED: HttpBackendSupport.kt:43-58]`

**One caveat:** `sharedClient` caches the OkHttpClient for 10 minutes. Across many sequential tests with different ports, this leaks `OkHttpClient` instances into the static `ConcurrentHashMap`. Acceptable — they evict on idle and the test JVM exits cleanly. Do NOT call `HttpBackendSupport.shutdownSharedClients()` in `@AfterEach`; it would empty the cache for other backend tests running in parallel. `[VERIFIED: HttpBackendSupport.kt:60-87]`

### Q2: Inventory of `src/test/kotlin/com/six2dez/burp/aiagent/backends/http/`

Three files. **No MockWebServer wrapper exists yet.**

| File | Purpose | Reusable for this phase? |
|------|---------|--------------------------|
| `CircuitBreakerTest.kt` | Unit-tests the circuit breaker with a fake `nowProvider`. | No — circuit-breaker is not in audit scope. |
| `ConversationHistoryTest.kt` | Unit-tests the shared `ConversationHistory` trim logic. | No — conversation history is not in audit scope. |
| `MontoyaHttpTransportUtf8Test.kt` | Tests `MontoyaHttpTransport.decodeResponse(...)` UTF-8 handling via mocked `HttpResponse`. | No — this tests the Montoya transport branch, which Perplexity tests will not exercise (Perplexity uses OkHttp directly, the `transport != null` branch of `OpenAiCompatibleConnection.send` is not the Perplexity path when launched without a `MontoyaHttpTransport` in `BackendLaunchConfig`). |

**Conclusion:** No reusable MockWebServer harness exists. Planner has two choices:

1. **Inline the harness in each test file** (Pattern 1 above). Three places it's needed: `PerplexityBackendFactoryTest`, `OpenAiCompatibleBackendDefaultsTest`, and `OpenAiCompatibleBackendDefaultsTest` again for the Generic-OpenAI side. Two test files total, but only two `BeforeEach`/`AfterEach` pairs — cheap.
2. **Add a shared helper `src/test/kotlin/com/six2dez/burp/aiagent/backends/http/MockHttpHarness.kt`** with `start()`, `enqueueStreamedDelta(text: String)`, `takeJsonBody(): JsonNode`. More DRY but adds an indirection that obscures the per-test setup.

Recommended (D-07 hints at this): **inline.** Two test files, ~30 lines of boilerplate each, no shared mutable state, ktlint-friendly.

### Q3: JSON-body inspection idiom

The production code already uses the exact idiom required:

```kotlin
// PerplexityBackendFactory.kt:40
private val mapper = ObjectMapper().registerKotlinModule()
```

`[VERIFIED: PerplexityBackendFactory.kt:40, OpenAiCompatibleBackend.kt:51, AgentSettings.kt:6 (KotlinModule import)]`

In tests, mirror this pattern at the top of each test class. To inspect a body:

```kotlin
val recorded = server.takeRequest(1, TimeUnit.SECONDS)!!
val body: JsonNode = mapper.readTree(recorded.body.readUtf8())
assertTrue(body.has("messages"))
assertFalse(body.has("response_format"))   // Perplexity path
assertEquals("sonar", body.get("model").asText())
```

`MockWebServer.RecordedRequest.body` is an `okio.Buffer` (the MockWebServer transitive dep is `okio:3.x`, already on the classpath via OkHttp). `readUtf8()` gives a `String`. `[CITED: https://square.github.io/okhttp/4.x/mockwebserver/okhttp3.mockwebserver/-recorded-request/]`

### Q4: `buildChatCompletionsUrl` edge cases (both implementations, exhaustive table)

There are **two** `buildChatCompletionsUrl` functions and they have **subtly different fallback behaviour for bare hosts**.

**Implementation A: `PerplexityBackendFactory.buildChatCompletionsUrl` (factory health-check path) — `PerplexityBackendFactory.kt:89-96`**

```kotlin
private fun buildChatCompletionsUrl(baseUrl: String): String {
    val trimmed = baseUrl.trimEnd('/')
    val lower = trimmed.lowercase()
    if (lower.endsWith("/chat/completions")) return trimmed
    if (lower.matches(Regex(".*/v\\d+/chat/completions", RegexOption.IGNORE_CASE))) return trimmed
    if (lower.matches(Regex(".*/v\\d+", RegexOption.IGNORE_CASE))) return "$trimmed/chat/completions"
    return "$trimmed/chat/completions"   // bare host fallback — Perplexity-specific, no /v1
}
```

**Implementation B: `OpenAiCompatibleBackend.buildChatCompletionsUrl` (connection's chat-send path) — `OpenAiCompatibleBackend.kt:408-418`**

```kotlin
private fun buildChatCompletionsUrl(baseUrl: String): String {
    val trimmed = baseUrl.trimEnd('/')
    val lower = trimmed.lowercase()
    if (lower.endsWith("/chat/completions")) return trimmed
    if (versionedEndpointRegex.matches(trimmed)) return trimmed
    if (versionedBaseRegex.matches(trimmed)) return "$trimmed/chat/completions"
    // Bare host: append the backend-specific fallback path.
    val path = if (chatCompletionsBasePath.startsWith("/")) chatCompletionsBasePath else "/$chatCompletionsBasePath"
    return "$trimmed$path"
}
```

Where `chatCompletionsBasePath` is `"/chat/completions"` for Perplexity (Implementation B falls through to the same Perplexity-shaped URL) and `"/v1/chat/completions"` for everything else.

**Edge-case table (Perplexity backend launched via factory, exercised through chat-send path = Implementation B):**

| Input `perplexityUrl` | Implementation B output | Notes |
|------------------------|------------------------|-------|
| `https://api.perplexity.ai` | `https://api.perplexity.ai/chat/completions` | Bare host (default). Test target for PPLX-02. |
| `https://api.perplexity.ai/` | `https://api.perplexity.ai/chat/completions` | Trailing slash stripped by `trimEnd('/')`. |
| `https://api.perplexity.ai/chat/completions` | `https://api.perplexity.ai/chat/completions` | Already resolved, no double append. |
| `https://api.perplexity.ai/chat/completions/` | `https://api.perplexity.ai/chat/completions` | Trailing slash stripped before suffix check. |
| `https://api.perplexity.ai/v1` | `https://api.perplexity.ai/v1/chat/completions` | `versionedBaseRegex` matches → append. NOTE: this is technically a Perplexity-incorrect URL because Perplexity has no `/v1` namespace, but the user typed it deliberately, so the backend honours it. Lock as observed behaviour. |
| `https://api.perplexity.ai/v1/chat/completions` | `https://api.perplexity.ai/v1/chat/completions` | `versionedEndpointRegex` matches → no double append. |
| `HTTP://API.PERPLEXITY.AI` | `HTTP://API.PERPLEXITY.AI/chat/completions` | Case-preserved on output; matching done on `lower`. (`lowercase()` is local; only used for matching.) |

Important nuances:

- Implementation B's bare-host fallback **depends on `chatCompletionsBasePath`** — that's how the same code services both Perplexity (`/chat/completions`) and Generic OpenAI (`/v1/chat/completions`). Test PPLX-04 with bare host → URL ends `/v1/chat/completions`; test PPLX-02 with bare host → URL ends `/chat/completions` (no `/v1`).
- Implementation A is **only reached by the factory's health check** (the `Test connection` button in `BackendConfigPanel`). The chat-send path always uses Implementation B. PPLX-02 wire-level tests therefore exercise Implementation B exclusively, which is the right thing — that's the user-facing chat behaviour.

**Recommended parametrised tests (PPLX-02):** at least the first four rows of the table above, since they cover the user-visible URL space (bare host, trailing slash, already-resolved, slash-on-resolved).

### Q5: `response_format` emission gate (exact code, exact assertion targets)

```kotlin
// OpenAiCompatibleBackend.kt:185-187
if (jsonMode && supportsJsonObjectResponseFormat) {
    payload["response_format"] = mapOf("type" to "json_object")
}
```

`[VERIFIED: OpenAiCompatibleBackend.kt:185-187]`

| `supportsJsonObjectResponseFormat` (constructor) | `jsonMode` arg to `send()` | Body has `response_format`? |
|--------------------------------------------------|----------------------------|-----------------------------|
| `false` (Perplexity) | `true` | NO → lock by PPLX-03 |
| `false` (Perplexity) | `false` | NO |
| `true` (default — NVIDIA NIM, OpenAI-compat) | `true` | YES, `{"type":"json_object"}` → lock by PPLX-04 |
| `true` (default) | `false` | NO |

The first and third rows are the load-bearing assertions. The fourth row is implicitly true for both backends (if `jsonMode = false`, no `response_format` is ever added) — not worth a separate test.

### Q6: AgentSettings persistence path (PPLX-05 assertion targets)

**Load path** — `AgentSettings.kt:257-266`:

```kotlin
perplexityUrl =
    (prefs.getString(KEY_PERPLEXITY_URL) ?: defaultPerplexityUrl()).trim().ifBlank {
        defaultPerplexityUrl()
    },
perplexityModel = prefs.getString(KEY_PERPLEXITY_MODEL).orEmpty().trim(),
perplexityApiKey = prefs.getString(KEY_PERPLEXITY_API_KEY).orEmpty().trim(),
perplexityHeaders = prefs.getString(KEY_PERPLEXITY_HEADERS).orEmpty(),
perplexityTimeoutSeconds =
    (prefs.getInteger(KEY_PERPLEXITY_TIMEOUT) ?: defaultPerplexityTimeoutSeconds())
        .coerceIn(30, 3600),
```

`[VERIFIED: AgentSettings.kt:257-266]`

**Default helpers** — `AgentSettings.kt:822, 824`:

```kotlin
private fun defaultPerplexityUrl(): String = "https://api.perplexity.ai"
private fun defaultPerplexityTimeoutSeconds(): Int = Defaults.CLI_PROCESS_TIMEOUT_SECONDS
```

**Preference key constants** — `AgentSettings.kt:691-695`:

```kotlin
private const val KEY_PERPLEXITY_URL = "perplexity.url"
private const val KEY_PERPLEXITY_MODEL = "perplexity.model"
private const val KEY_PERPLEXITY_API_KEY = "perplexity.apiKey"
private const val KEY_PERPLEXITY_HEADERS = "perplexity.headers"
private const val KEY_PERPLEXITY_TIMEOUT = "perplexity.timeoutSeconds"
```

**Schema marker** — `AgentSettings.kt:780`: `private const val CURRENT_SETTINGS_SCHEMA_VERSION = 3`.

**`migrateIfNeeded` body** — `AgentSettings.kt:624-643`: handles v1 → v2 (gemini cmd + allowed-origins) and v2 → v3 (custom prompt library stamp only). **No Perplexity-related branch exists** — confirms D-03. If a stored schema version is already 3, `migrateIfNeeded` does nothing and the version marker stays at 3. `[VERIFIED: AgentSettings.kt:624-643]`

**`load()` order** — `AgentSettings.kt:160-164`: cached → `migrateIfNeeded()` → construct `AgentSettings(...)`. The cache is per-`AgentSettingsRepository` instance, populated on first load. For tests, instantiate a fresh repo per test or call `repo.invalidate()` between calls. `[VERIFIED: AgentSettings.kt:155-164]`

**Assertion targets for PPLX-05:**

| Field | Expected | Source |
|-------|----------|--------|
| `loaded.perplexityUrl` | `"https://api.perplexity.ai"` | `defaultPerplexityUrl()` |
| `loaded.perplexityModel` | `""` | `prefs.getString(KEY_PERPLEXITY_MODEL).orEmpty()` |
| `loaded.perplexityApiKey` | `""` | same |
| `loaded.perplexityHeaders` | `""` | same |
| `loaded.perplexityTimeoutSeconds` | `120` (= `Defaults.CLI_PROCESS_TIMEOUT_SECONDS`) | `defaultPerplexityTimeoutSeconds()` |
| `prefs.integers["settings.schema.version"]` | `3` (unchanged) | `migrateIfNeeded` no-op when stored version already = 3 |

> **Caveat on `perplexityTimeoutSeconds`:** I have **not** verified the literal value of `Defaults.CLI_PROCESS_TIMEOUT_SECONDS` from `Defaults.kt` in this research session — I infer 120 from CONVENTIONS.md context and the typical CLI timeout convention. The test should assert `120` and the planner can adjust if `Defaults.kt` reveals otherwise. `[ASSUMED: Defaults.CLI_PROCESS_TIMEOUT_SECONDS == 120; A1]`

### Q7: `TestSettings.baselineSettings()` shape

```kotlin
// src/test/kotlin/com/six2dez/burp/aiagent/TestSettings.kt:11-95
object TestSettings {
    fun baselineSettings(preferredBackendId: String = "codex-cli"): AgentSettings = AgentSettings(
        codexCmd = "codex",
        // ... ~60 fields total ...
        passiveAiEnabled = false,
        // ...
        activeAiEnabled = false,
        // ...
        bountyPromptEnabled = false,
        // bountyPromptEnabledPromptIds = emptySet(),
    )
}
```

`[VERIFIED: TestSettings.kt:10-96]`

**Key finding:** `TestSettings.baselineSettings()` does **NOT** explicitly set `perplexityUrl`, `perplexityModel`, etc. — they fall through to the **`data class` default values** on `AgentSettings` (lines 57-61), which is exactly what we need. So in tests:

```kotlin
val settings = TestSettings.baselineSettings()
    .copy(perplexityUrl = mockServer.url("/").toString().trimEnd('/'),
          perplexityModel = "sonar",
          perplexityApiKey = "pplx-test-key")
```

This is the canonical pattern. For tests that don't need the full `AgentSettings` (most wire-level tests fire `backend.launch(BackendLaunchConfig(...))` directly without an `AgentSettings`), `TestSettings` isn't even needed.

### Q8: `InMemoryPrefs` pattern (PPLX-05 setup)

The pattern is defined privately inside `AgentSettingsMigrationTest.kt:60-88` — a Mockito-Kotlin wrapper around three `MutableMap`s. It's already exhaustive (strings, booleans, integers) and supports both read and write. The new PPLX-05 test extends the existing file, so `InMemoryPrefs` is in scope automatically.

Construction (verbatim from existing test):

```kotlin
val prefs = InMemoryPrefs()
prefs.strings["some.key"] = "value"
prefs.integers["settings.schema.version"] = 3
val repo = AgentSettingsRepository(apiWith(prefs.mock))   // apiWith is the existing helper
val loaded = repo.load()
```

`apiWith` wires `MontoyaApi.persistence().preferences()` to `prefs.mock` via Mockito's `RETURNS_DEEP_STUBS`. `[VERIFIED: AgentSettingsMigrationTest.kt:54-58]`

**Note on the `hostAnonymizationSalt` side-effect:** `load()` calls `prefs.setString(KEY_HOST_SALT, generated)` if the salt key is missing (`AgentSettings.kt:282-287`). This is benign for PPLX-05 — it does NOT touch the schema version, and `InMemoryPrefs` accepts the write silently. Just be aware that after `load()`, `prefs.strings["privacy.host_salt"]` will be populated.

## Test Architecture Map (distilled from Q2-Q5)

```
PerplexityBackendFactoryTest.kt       (NEW; backends/perplexity/)
├── @BeforeEach: start MockWebServer
├── @AfterEach:  shutdown MockWebServer
├── @Test: targetsChatCompletionsWithoutV1PrefixOnBareHost      ← PPLX-02
├── @Test: handlesTrailingSlashInUserConfiguredUrl              ← PPLX-02
├── @Test: respectsExplicitV1UserUrl                            ← PPLX-02 edge case
├── @Test: doesNotDoubleAppendWhenUrlAlreadyHasChatCompletions  ← PPLX-02 edge case
├── @Test: omitsResponseFormatEvenWhenJsonModeRequested         ← PPLX-03
└── @Test: passesBearerTokenAndStreamHeader                     ← (optional smoke; locks defaultHeaders)

OpenAiCompatibleBackendDefaultsTest.kt (NEW; backends/openai/)
├── @BeforeEach: start MockWebServer
├── @AfterEach:  shutdown MockWebServer
├── @Test: defaultsKeepV1PrefixOnBareHost                       ← PPLX-04 (mirror of PPLX-02)
└── @Test: defaultsEmitResponseFormatWhenJsonModeRequested      ← PPLX-04 (mirror of PPLX-03)

AgentSettingsMigrationTest.kt          (EXTEND; config/)
└── @Test: load_v06xPreferencesYieldSafePerplexityDefaultsAndSchemaStaysV3   ← PPLX-05
```

**Total new test methods:** 7-8 (depending on whether the optional `passesBearerTokenAndStreamHeader` smoke is included).
**Total new test files:** 2.
**Files extended:** 1.
**Production-code changes:** 0 (no `internal` visibility shifts; behavioural tests reach all assertions).
**Dependency adds:** 1 (`testImplementation` MockWebServer).

## Validation Architecture

### Test Framework

| Property | Value |
|----------|-------|
| Framework | JUnit Jupiter 6.0.3 (JUnit 5 platform) |
| Config file | `build.gradle.kts:86-100` (`tasks.test { useJUnitPlatform() }` + `excludeHeavyTests` filter) |
| Quick run command | `./gradlew test -PexcludeHeavyTests=true` |
| Full suite command | `./gradlew test` (fast suite + JaCoCo) |
| Fast suite filter | excludes `*IntegrationTest`, `*ConcurrencyTest`, `*BackpressureTest`, `*RestartPolicyTest` |

### Phase Requirements → Test Map

| Req ID | Behavior | Test Type | Automated Command | File Exists? |
|--------|----------|-----------|-------------------|-------------|
| PPLX-01 | Perplexity card pre-populated with safe defaults | unit (settings deserialisation, indirect) | `./gradlew test -PexcludeHeavyTests=true --tests "*AgentSettingsMigrationTest"` | EXTEND existing |
| PPLX-02 | URL form is `/chat/completions`, no `/v1` | unit (wire-level via MockWebServer) | `./gradlew test -PexcludeHeavyTests=true --tests "*PerplexityBackendFactoryTest"` | NEW (Wave 0) |
| PPLX-03 | No `response_format` key in body when `jsonMode = true` | unit (wire-level) | `./gradlew test -PexcludeHeavyTests=true --tests "*PerplexityBackendFactoryTest"` | NEW (Wave 0) |
| PPLX-04 | Default constructor still emits `/v1/chat/completions` and `response_format` | unit (wire-level) | `./gradlew test -PexcludeHeavyTests=true --tests "*OpenAiCompatibleBackendDefaultsTest"` | NEW (Wave 0) |
| PPLX-05 | v0.6.x preferences load with safe defaults; schema = 3 | unit (settings deserialisation) | `./gradlew test -PexcludeHeavyTests=true --tests "*AgentSettingsMigrationTest"` | EXTEND existing |
| PPLX-05 success criterion #5 | Real prompt round-trip via real API | manual smoke (recorded in `01-VERIFICATION.md`) | n/a — manual | n/a (intentional per D-06) |

### Sampling Rate

- **Per task commit:** `./gradlew test -PexcludeHeavyTests=true --tests "<test class added in this task>"` — runs in <10s for fresh test files.
- **Per wave merge:** `./gradlew test -PexcludeHeavyTests=true` — full fast suite (~30-60s).
- **Phase gate:** Full fast suite green PLUS `./gradlew ktlintCheck` green PLUS manual smoke recorded in `01-VERIFICATION.md` before `/gsd-verify-work`.

### Wave 0 Gaps

- [ ] `build.gradle.kts` — add `testImplementation("com.squareup.okhttp3:mockwebserver:4.12.0")` (Wave 0 setup task; no production code touched).
- [ ] `src/test/kotlin/com/six2dez/burp/aiagent/backends/perplexity/` — directory does not exist; new test file creates it.
- [ ] `src/test/kotlin/com/six2dez/burp/aiagent/backends/perplexity/PerplexityBackendFactoryTest.kt` — new file; covers PPLX-02, PPLX-03.
- [ ] `src/test/kotlin/com/six2dez/burp/aiagent/backends/openai/OpenAiCompatibleBackendDefaultsTest.kt` — new file; covers PPLX-04.
- [ ] `src/test/kotlin/com/six2dez/burp/aiagent/config/AgentSettingsMigrationTest.kt` — extend with one new `@Test` method covering PPLX-05.

No new shared fixtures needed; `TestSettings` and `InMemoryPrefs` (re-exported within `AgentSettingsMigrationTest`) cover the surface.

## Security Domain

Phase 1 does not change auth, redaction, MCP, or any privacy-sensitive control. The Perplexity backend itself **receives only redacted prompts** (ADR-5; redaction runs pre-flight in `Redaction.apply` and `ContextCollector`, not in any backend code path under audit). Tests use `TestSettings.baselineSettings()` defaults, which start in `PrivacyMode.STRICT` — the contract is implicit and not bypassed.

### Applicable ASVS Categories

| ASVS Category | Applies | Standard Control |
|---------------|---------|-----------------|
| V2 Authentication | no | The audit does not touch auth code. Perplexity uses `Authorization: Bearer pplx-...`; the header is plumbed via the existing, already-tested `HeaderParser.withBearerToken` (covered by `RedactionTest` for outbound, not in scope here). |
| V3 Session Management | no | No session state in audit scope. |
| V4 Access Control | no | No new permission boundaries. |
| V5 Input Validation | partial | Wire-level tests indirectly verify that the user-typed `perplexityUrl` is parsed correctly (no path injection via crafted strings). The URL builder normalises via `trimEnd('/')` and regex matches — no allocation of attacker-controlled byte sequences. |
| V6 Cryptography | no | No crypto in audit scope. The Bearer token is opaque. |

### Known Threat Patterns for Kotlin/JVM HTTP backend

| Pattern | STRIDE | Standard Mitigation |
|---------|--------|---------------------|
| Token leakage in logs | Information Disclosure | `BackendDiagnostics.log("[$id] $it")` only logs the URL, not the headers; tests should NOT assert against log output. `[VERIFIED: OpenAiCompatibleBackend.kt:200]` |
| Test secrets in CI | Information Disclosure | D-06 forbids real API keys in CI. Tests use `"pplx-test"` placeholder. |
| MockWebServer left running across tests | Denial of Service (slow tests) | `@AfterEach { server.shutdown() }`. Not a security issue but a test-hygiene gate. |

No new security controls are introduced; no security regressions are possible from purely additive tests.

## Common Pitfalls

### Pitfall 1: Streaming SSE response not terminated → test hangs

**What goes wrong:** The Perplexity backend uses `streaming = true`. `OpenAiCompatibleConnection.handleStreamingResponse` reads `data: ...\n\n` lines until it sees `data: [DONE]`. If the MockResponse body is missing the `[DONE]` sentinel, the reader blocks until the OkHttp call timeout (default 30s in `BackendLaunchConfig`).

**Why it happens:** Test author forgets the sentinel.

**How to avoid:** Always end the streamed body with `data: [DONE]\n\n`. Pattern 1 above includes the canonical shape.

**Warning signs:** Test takes 30+ seconds; CountDownLatch `await(5, TimeUnit.SECONDS)` returns `false`.

### Pitfall 2: `HttpBackendSupport.sharedClient` static cache pollution

**What goes wrong:** Each MockWebServer gets a fresh port (e.g. `127.0.0.1:54321`), so the cache key `(baseUrl, timeout)` is unique per test — no cross-test pollution. **BUT** if a future test reuses a port or hard-codes one, the cached client lives for 10 minutes and across the test-class lifecycle.

**Why it happens:** Static `ConcurrentHashMap<ClientKey, ClientEntry>` in `HttpBackendSupport.kt:30`.

**How to avoid:** Never hard-code a port (always `server.start()` then `server.url("/").toString()`). Do NOT call `HttpBackendSupport.shutdownSharedClients()` in `@AfterEach` — it would shut down clients other tests might be using.

**Warning signs:** Cross-class test failures only in CI's full suite, never in isolation.

### Pitfall 3: Asserting `body.toString()` instead of `body.has(...)`

**What goes wrong:** Full-string assertion includes `temperature: 0.7` which can change with `determinismMode`; tests go red on unrelated refactors.

**Why it happens:** JSON ordering, optional fields, decimal formatting.

**How to avoid:** Use `JsonNode.has(...)` and `JsonNode.get(...).asText()` — assert presence/absence and exact values for the keys you care about; ignore everything else.

**Warning signs:** Test fails with diff that includes whitespace / key reordering / float-formatting.

### Pitfall 4: Mistaking the factory's `buildChatCompletionsUrl` for the connection's

**What goes wrong:** Reading `PerplexityBackendFactory.kt:89-96`, you write tests against the factory's `buildChatCompletionsUrl`. But the chat-send path goes through `OpenAiCompatibleBackend.kt:408-418`. The factory's copy is exercised only by `perplexityHealthCheck` (the "Test connection" button).

**Why it happens:** Two functions with identical names doing slightly different things (Q4 above).

**How to avoid:** Always exercise via `backend.launch(...).send(...)` and assert against `RecordedRequest.path`. This naturally goes through Implementation B (the chat-send path).

**Warning signs:** Your test passes when the production chat-send path is broken — because it's only testing the unused factory copy.

### Pitfall 5: Forgetting that `TestSettings.baselineSettings()` has `privacyMode = STRICT`

**What goes wrong:** If a future test accidentally sends real-looking PII through `TestSettings.baselineSettings()`, redaction WILL fire — but only at the `ContextCollector` layer, which is upstream of the backend in audit scope. The backend tests bypass redaction by calling `connection.send(text, ...)` directly. **This is correct and intentional** for audit-scope tests but worth noting in a future audit if scope expands.

**How to avoid:** Keep `text = "hello"` or similar inert strings in test calls. Don't pretend to redact at the backend layer.

## Code Examples

### Example: Minimal MockWebServer for SSE (verified shape)

```kotlin
// Source: project pattern derived from OpenAiCompatibleBackend.kt:341-381
// (handleStreamingResponse splits on "data:" line prefix, stops at "[DONE]")
private fun streamedResponse(content: String = "ok"): MockResponse =
    MockResponse()
        .setResponseCode(200)
        .setHeader("Content-Type", "text/event-stream")
        .setBody(
            "data: {\"choices\":[{\"delta\":{\"content\":\"$content\"}}]}\n\n" +
                "data: [DONE]\n\n",
        )
```

### Example: Inspecting captured body keys (verified shape)

```kotlin
// Source: production idiom (PerplexityBackendFactory.kt:40), extended to JsonNode read side
private val mapper = ObjectMapper().registerKotlinModule()

val recorded = server.takeRequest(1, TimeUnit.SECONDS) ?: error("no request received")
val body: com.fasterxml.jackson.databind.JsonNode = mapper.readTree(recorded.body.readUtf8())

// PPLX-02 assertions:
assertEquals("/chat/completions", recorded.path)
assertEquals("POST", recorded.method)

// PPLX-03 assertions:
assertFalse(body.has("response_format"))
assertTrue(body.has("messages"))
assertEquals("sonar", body.get("model").asText())

// Smoke:
assertTrue(body.get("messages").isArray)
assertTrue(body.get("stream").booleanValue())   // streaming = true for Perplexity
```

### Example: PPLX-05 settings test (verified pattern from existing test)

```kotlin
// Source: extension of AgentSettingsMigrationTest.kt (existing pattern at lines 14-30)
@Test
fun load_v06xPreferencesYieldSafePerplexityDefaultsAndSchemaStaysV3() {
    val prefs = InMemoryPrefs()
    prefs.integers["settings.schema.version"] = 3

    val repo = AgentSettingsRepository(apiWith(prefs.mock))
    val loaded = repo.load()

    assertEquals("https://api.perplexity.ai", loaded.perplexityUrl)
    assertEquals("", loaded.perplexityModel)
    assertEquals("", loaded.perplexityApiKey)
    assertEquals("", loaded.perplexityHeaders)
    assertEquals(120, loaded.perplexityTimeoutSeconds)  // see Assumption A1 below
    assertEquals(3, prefs.integers["settings.schema.version"])
}
```

## State of the Art

| Old Approach | Current Approach | When Changed | Impact |
|--------------|------------------|--------------|--------|
| Per-backend forked HTTP request building | `OpenAiCompatibleBackend` with constructor knobs (`chatCompletionsBasePath`, `supportsJsonObjectResponseFormat`, `payloadCustomizer`, `defaultHeaders`, `healthCheckProvider`) | CHANGELOG `[Unreleased]` "Changed" entry (#59) | New backends (Perplexity, future) ship as a 30-line factory file plus an SPI line. The audit locks the constructor defaults so future similar refactors don't regress existing backends. |
| Hand-rolled `HttpURLConnection` in tests | OkHttp `MockWebServer` (project standard per TESTING.md "Wire-level test pattern") | New for this audit (no existing usage; will be the project's first MockWebServer test) | Shared idiom future backend audits can copy verbatim. |

**Deprecated/outdated:** None — the Perplexity code is fresh in `[Unreleased]` and aligned with the current pluggable-backend pattern (ADR-3 + ADR-4).

## Assumptions Log

| # | Claim | Section | Risk if Wrong |
|---|-------|---------|---------------|
| A1 | `Defaults.CLI_PROCESS_TIMEOUT_SECONDS == 120` (used by `defaultPerplexityTimeoutSeconds()`) | Q6, PPLX-05 example | LOW — if the constant is different, the PPLX-05 test fails with a clear assertion message and the planner adjusts the expected value to whatever `Defaults.kt` declares. Mitigation: have the planner read `src/main/kotlin/com/six2dez/burp/aiagent/config/Defaults.kt` and substitute the actual literal. |

**Note:** This is the only `[ASSUMED]` claim in this research. Every other claim was directly verified against the source files at `HEAD` of the working tree.

## Open Questions

1. **Should `OpenAiCompatibleBackendDefaultsTest` exercise NVIDIA NIM directly (via `NvidiaNimBackendFactory`) or only `OpenAiCompatibleBackend()` with default args?**
   - What we know: D-07 mentions "backwards-compat defaults for NVIDIA NIM and Generic OpenAI-compatible", suggesting both. NVIDIA's factory adds `payloadCustomizer`, `defaultHeaders`, `healthCheckProvider`, but **does NOT override** `chatCompletionsBasePath` or `supportsJsonObjectResponseFormat`. So testing the bare `OpenAiCompatibleBackend()` constructor covers NVIDIA's URL/JSON-mode behaviour too.
   - What's unclear: whether to also assert NVIDIA's `payloadCustomizer` side-effects (e.g. `max_tokens = 16384`) in the same test class — those are a separate concern.
   - Recommendation: scope `OpenAiCompatibleBackendDefaultsTest` strictly to the two constructor knobs under audit. Leave NVIDIA-specific payload assertions for a future NVIDIA audit phase (if scheduled).

2. **`passesBearerTokenAndStreamHeader` smoke — include or skip?**
   - What we know: Perplexity factory ships `defaultHeaders = mapOf("Accept" to "text/event-stream")`. The Bearer token comes from `BackendLaunchConfig.headers`. Both are observable on `RecordedRequest`.
   - What's unclear: whether locking these is in scope; they were not explicitly listed in CONTEXT.md `<specifics>`.
   - Recommendation: include the smoke test in `PerplexityBackendFactoryTest` as a single `@Test` (5 lines), since it's cheap and locks a useful surface. Planner can drop it if budget is tight.

## Recommended Plan Structure

The phase is small enough that **one PLAN.md is appropriate**, with three task groups under one wave:

```
PLAN: phase-01-perplexity-audit.md

Wave 0 — Setup (one task):
  T0  Add MockWebServer dependency to build.gradle.kts
      Verify: ./gradlew dependencies | grep mockwebserver shows 4.12.0

Wave 1 — Test scaffolding (three parallel-safe tasks):
  T1  Write PerplexityBackendFactoryTest.kt    (PPLX-02, PPLX-03)
      Files touched: src/test/kotlin/com/six2dez/burp/aiagent/backends/perplexity/PerplexityBackendFactoryTest.kt (new)
  T2  Write OpenAiCompatibleBackendDefaultsTest.kt (PPLX-04)
      Files touched: src/test/kotlin/com/six2dez/burp/aiagent/backends/openai/OpenAiCompatibleBackendDefaultsTest.kt (new)
  T3  Extend AgentSettingsMigrationTest.kt with one new @Test (PPLX-05)
      Files touched: src/test/kotlin/com/six2dez/burp/aiagent/config/AgentSettingsMigrationTest.kt (extend)

Wave 2 — Verification + sign-off (one task, depends on T1+T2+T3):
  T4  Run full fast suite (./gradlew test -PexcludeHeavyTests=true) + ktlintCheck
      Manual: maintainer records one-time Perplexity smoke in 01-VERIFICATION.md (PPLX-05 success criterion #5)
      Record both KNOWN-WORDING-GAP entries (D-08) in 01-VERIFICATION.md
```

**Why one plan, not three:** the tasks share no production code, share zero scope risk, and the verification step is a single Gradle invocation. Splitting into three plans would multiply commits without isolating risk.

**Wave 1 parallelisation:** T1, T2, T3 touch disjoint files and have no execution-order dependency. A multi-agent execution can spawn them concurrently; a solo execution can do them in any order. T0 is a prerequisite for T1 and T2 (compile-time dependency on `MockWebServer`) but not for T3.

**Estimated touch:** `build.gradle.kts` (+1 line), 2 new test files (~80 lines each), `AgentSettingsMigrationTest.kt` (+12 lines). Total: ~175 LOC added, 0 production LOC changed.

## Environment Availability

| Dependency | Required By | Available | Version | Fallback |
|------------|------------|-----------|---------|----------|
| JDK 21 | Build / test | ✓ | (Foojay toolchain auto-provisions) | — |
| Gradle wrapper | Build / test | ✓ | 8.x / 9.x in repo | — |
| Maven Central | MockWebServer download | ✓ | n/a | — (assumed available; this is a standard Kotlin dev environment) |
| Perplexity API key | Manual smoke (D-06 only) | n/a (maintainer's own; NOT in CI) | — | Manual smoke is recorded in `01-VERIFICATION.md` only when maintainer has access; CI does not block on it. |

No blocking environment gaps.

## Risks & Pitfalls

1. **MockWebServer not in `build.gradle.kts`** — `[VERIFIED: build.gradle.kts:49-53 has no mockwebserver entry; grep across test tree returns zero hits]`. The plan MUST add it in Wave 0 before any test compiles. Without this, T1/T2 cannot even compile.

2. **`buildChatCompletionsUrl` exists twice (factory + connection).** Factory's copy is health-check-only; connection's copy is the chat path. Both must produce the same Perplexity-shaped output for the same input (they do, by construction). The wire-level tests exercise the connection's copy. Do NOT refactor to deduplicate (CONTEXT.md deferred). The two implementations are **NOT** behaviourally divergent for the user-typed URLs we care about — verified by trace through Q4. `[VERIFIED: OpenAiCompatibleBackend.kt:408-418 and PerplexityBackendFactory.kt:89-96]`

3. **`OpenAiCompatibleBackend` uses streaming SSE for Perplexity.** `MockResponse` must return `Content-Type: text/event-stream` and a `data: ... \n\n ... data: [DONE]\n\n` body shape, OR the test will hang for the full OkHttp timeout. Pattern 1 above includes the canonical shape. `[VERIFIED: OpenAiCompatibleBackend.kt:341-381]`

4. **`HttpBackendSupport.sharedClient(...)` is a static cache.** It does not cause cross-test pollution under MockWebServer (each server gets a unique port → unique cache key), but DO NOT call `shutdownSharedClients()` in `@AfterEach` — it would shut down clients in use by other backend tests if Gradle runs in parallel. `[VERIFIED: HttpBackendSupport.kt:30, 60-68]`

5. **SPI registration is already covered.** `META-INF/services/com.six2dez.burp.aiagent.backends.AiBackendFactory` lists `PerplexityBackendFactory` at line 7. `BackendRegistryTest` covers SPI discovery. This audit does NOT retest registration — `[VERIFIED: META-INF/services file line 7, BackendRegistryTest.kt:20-39]`.

6. **`BackendLaunchConfig.transport` defaults to `null`.** When `null`, `OpenAiCompatibleConnection` takes the OkHttp branch (which MockWebServer intercepts). When non-null, it takes the `MontoyaHttpTransport` branch (which Mockito would need to mock). All tests in this phase use the default `transport = null`, so the OkHttp branch is the entire test surface. `[VERIFIED: OpenAiCompatibleBackend.kt:202-274]`

7. **Floating-point in payload.** `temperature` is `0.0` or `0.7` (Double). Jackson serialises as `0.0` / `0.7`. If a test asserts `body.toString().contains("0.7")` it works, but the body assertion via `JsonNode.get("temperature").asDouble()` is more robust. The phase doesn't assert temperature, so this is not a real risk — flagging for awareness.

8. **`OpenAiCompatibleBackend` does NOT set `supportsSystemRole = true` in the data class — it overrides the field.** `OpenAiCompatibleBackend.kt:49`. The audit does not need to exercise `systemPrompt` because PPLX-03's "JSON intent preserved in the system prompt" is a scanner-prompt concern owned by `PassiveAiScanner` (existing tests). The Perplexity backend transparently passes through whatever `systemPrompt` it receives.

## Sources

### Primary (HIGH confidence — direct source-tree verification)

- `src/main/kotlin/com/six2dez/burp/aiagent/backends/perplexity/PerplexityBackendFactory.kt` (107 lines, fully read)
- `src/main/kotlin/com/six2dez/burp/aiagent/backends/openai/OpenAiCompatibleBackend.kt` (456 lines, fully read)
- `src/main/kotlin/com/six2dez/burp/aiagent/backends/openai/OpenAiCompatibleBackendFactory.kt` (9 lines)
- `src/main/kotlin/com/six2dez/burp/aiagent/backends/nvidia/NvidiaNimBackendFactory.kt` (115 lines, for backwards-compat baseline)
- `src/main/kotlin/com/six2dez/burp/aiagent/backends/BackendTypes.kt` (lines 1-107, for `BackendLaunchConfig` / `AiBackendFactory` interfaces)
- `src/main/kotlin/com/six2dez/burp/aiagent/backends/http/HttpBackendSupport.kt` (227 lines, for `sharedClient` semantics)
- `src/main/kotlin/com/six2dez/burp/aiagent/config/AgentSettings.kt` (selective reads: 1-100, 155-267, 400-472, 615-695, 780, 820-826)
- `src/main/kotlin/com/six2dez/burp/aiagent/ui/panels/BackendConfigPanel.kt` (selective reads: 90-100, 160-180, 220-235, 420-435)
- `src/main/resources/META-INF/services/com.six2dez.burp.aiagent.backends.AiBackendFactory` (10 lines)
- `src/test/kotlin/com/six2dez/burp/aiagent/TestSettings.kt` (96 lines, fully read)
- `src/test/kotlin/com/six2dez/burp/aiagent/config/AgentSettingsMigrationTest.kt` (89 lines, fully read)
- `src/test/kotlin/com/six2dez/burp/aiagent/backends/BackendRegistryTest.kt` (176 lines, fully read)
- `src/test/kotlin/com/six2dez/burp/aiagent/backends/http/CircuitBreakerTest.kt` (85 lines)
- `src/test/kotlin/com/six2dez/burp/aiagent/backends/http/ConversationHistoryTest.kt` (72 lines)
- `src/test/kotlin/com/six2dez/burp/aiagent/backends/http/MontoyaHttpTransportUtf8Test.kt` (70 lines)
- `src/test/kotlin/com/six2dez/burp/aiagent/mcp/McpServerIntegrationTest.kt` (129 lines, for "heavy-suite" baseline reference only)
- `src/test/kotlin/com/six2dez/burp/aiagent/ui/SettingsDefaultsPersistenceTest.kt` (109 lines, parallel pattern)
- `build.gradle.kts` (155 lines, fully read)
- `.planning/config.json` (verified `workflow.nyquist_validation = true`)
- `.planning/codebase/STACK.md`, `TESTING.md`, `CONVENTIONS.md`, `STRUCTURE.md` (fully read; canonical inputs)
- `CHANGELOG.md` `[Unreleased]` section
- `SPEC.md` §4.4
- `DECISIONS.md` ADR-3, ADR-4, ADR-5
- `AGENTS.md` (lines 1-58)
- `CLAUDE.md` (project guidelines)

### Secondary (MEDIUM-HIGH confidence — public registry)

- Maven Central listing for `com.squareup.okhttp3:mockwebserver:4.12.0` `[CITED: https://central.sonatype.com/artifact/com.squareup.okhttp3/mockwebserver/4.12.0]` (published 2023-10-17; matches the OkHttp 4.12.0 dep already in build.gradle.kts).
- Square OkHttp project home `[CITED: https://square.github.io/okhttp/]` (general MockWebServer documentation).

### Tertiary (LOW confidence — none used)

Every claim in this research traces to a primary source. No WebSearch-derived speculative claims.

## Metadata

**Confidence breakdown:**

- Standard stack: HIGH — every version verified against `build.gradle.kts`; MockWebServer version cross-verified with Maven Central registry.
- Architecture: HIGH — every code path traced through the source files at HEAD.
- Pitfalls: HIGH — each pitfall traces to a specific line in the source code with the file:line citation inline.
- Wire-level test pattern: HIGH — mirrors `.planning/codebase/TESTING.md` "Wire-level test pattern" (already an established convention) plus standard MockWebServer usage. Pattern is novel for THIS codebase (no existing test uses MockWebServer) but is the documented standard per TESTING.md.

**Research date:** 2026-05-13

**Valid until:** 2026-06-13 (30 days; the surface under audit is shipped code in `[Unreleased]`, not a moving target). The only invalidator would be a major refactor of `OpenAiCompatibleBackend` before this phase executes — unlikely since the code shipped two weeks ago.

## RESEARCH COMPLETE
