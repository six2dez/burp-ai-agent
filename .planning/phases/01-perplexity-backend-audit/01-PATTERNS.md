# Phase 01: Perplexity Backend Audit - Pattern Map

**Mapped:** 2026-05-13
**Files analyzed:** 4 (1 modify + 2 new + 1 extend)
**Analogs found:** 4 / 4 (all have at-least-partial codebase analogs)
**Scope:** TEST FILES ONLY — zero production code changes
**Test placement (locked by D-07):**
- NEW `src/test/kotlin/com/six2dez/burp/aiagent/backends/perplexity/PerplexityBackendFactoryTest.kt`
- NEW `src/test/kotlin/com/six2dez/burp/aiagent/backends/openai/OpenAiCompatibleBackendDefaultsTest.kt`
- EXTEND `src/test/kotlin/com/six2dez/burp/aiagent/config/AgentSettingsMigrationTest.kt`
- MODIFY `build.gradle.kts` (one dependency line)

## File Classification

| File | Role | Data Flow | Mode | Closest Analog | Match Quality |
|------|------|-----------|------|----------------|---------------|
| `build.gradle.kts` | build config | dependency declaration | MODIFY | self (existing `testImplementation` lines 49-52) | exact (one-line append to existing block) |
| `src/test/kotlin/.../backends/perplexity/PerplexityBackendFactoryTest.kt` | unit test (HTTP wire) | request-response + SSE streaming | NEW | NONE for wire-capture; structural analog `src/test/kotlin/.../backends/http/CircuitBreakerTest.kt` for shape; production analog `src/main/kotlin/.../backends/perplexity/PerplexityBackendFactory.kt` for the under-test code path | role-match (no MockWebServer test exists yet — this file establishes the project's first such pattern) |
| `src/test/kotlin/.../backends/openai/OpenAiCompatibleBackendDefaultsTest.kt` | unit test (HTTP wire) | request-response + non-streaming JSON | NEW | mirror of file #1 above with default constructor args; `src/main/kotlin/.../backends/nvidia/NvidiaNimBackendFactory.kt` confirms NIM does NOT override `chatCompletionsBasePath` or `supportsJsonObjectResponseFormat` (so default-constructor test covers NIM behaviour too) | role-match (sibling of file #1) |
| `src/test/kotlin/.../config/AgentSettingsMigrationTest.kt` | unit test (settings deserialisation) | preferences-load | EXTEND | THIS FILE (lines 14-30 for schema-stability pattern; lines 60-88 for `InMemoryPrefs` test double) | exact (one new `@Test` reusing the file's private helpers) |

## Pattern Assignments

### 1. `build.gradle.kts` (build config, dependency declaration)

**Mode:** MODIFY (one line added)
**Analog:** itself — the existing `testImplementation` block.

**Where to add (the existing test-dependencies block, `build.gradle.kts:49-52`):**

```kotlin
testImplementation(kotlin("test"))
testImplementation("org.junit.jupiter:junit-jupiter:6.0.3")
testImplementation("net.portswigger.burp.extensions:montoya-api:2026.2")
testImplementation("org.mockito.kotlin:mockito-kotlin:5.4.0")
```

**Line to add (anywhere in that block, prefer adjacent to the OkHttp version pin which is at line 31):**

```kotlin
testImplementation("com.squareup.okhttp3:mockwebserver:4.12.0")
```

**Why this version exactly:** Match the OkHttp version (`build.gradle.kts:31` pins `com.squareup.okhttp3:okhttp:4.12.0`). MockWebServer and OkHttp share transitive deps (okio); version drift between the two causes silent classpath clashes.

**Convention to respect:** No version-catalogs (`libs.versions.toml`) are used in this build — all versions are inlined as literals in the `dependencies { }` block. Follow that pattern.

**Verification:** `./gradlew dependencies | grep mockwebserver` should show `com.squareup.okhttp3:mockwebserver:4.12.0`.

**Do NOT:**
- Add to `implementation` (test-only dep).
- Add to a new test-source-set (project uses a single `src/test/kotlin` source set; no `testIntegration` or similar).
- Reformat the surrounding block; ktlint will catch reorderings that aren't actually required.

---

### 2. `src/test/kotlin/com/six2dez/burp/aiagent/backends/perplexity/PerplexityBackendFactoryTest.kt` (NEW)

**Role:** wire-level test of the Perplexity-configured `OpenAiCompatibleBackend`
**Covers:** PPLX-02 (URL = `/chat/completions`, no `/v1`), PPLX-03 (no `response_format` even when `jsonMode = true`)
**Data flow:** test → `MockWebServer.url()` → `backend.launch(BackendLaunchConfig).send(...)` → SSE → captured `RecordedRequest`
**Directory:** `src/test/kotlin/com/six2dez/burp/aiagent/backends/perplexity/` — **does not yet exist**, the planner must create it as part of writing this file.

**Analog (structural shape — `@Test` naming and assertion style):** `src/test/kotlin/com/six2dez/burp/aiagent/backends/http/CircuitBreakerTest.kt` lines 1-30

```kotlin
package com.six2dez.burp.aiagent.backends.http

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import java.util.concurrent.atomic.AtomicLong

class CircuitBreakerTest {
    @Test
    fun opensAfterFailureThresholdAndBlocksRequests() {
        val now = AtomicLong(0)
        val breaker =
            CircuitBreaker(...)
        ...
        assertEquals(CircuitBreaker.State.OPEN, blocked.state)
    }
}
```

**Why this is the analog:** CamelCase method names (no backticks), JUnit Jupiter imports, `Assertions.*` static imports — these are the conventions every new test in `backends/` must follow. Do NOT copy `MontoyaHttpTransportUtf8Test.kt`'s backtick-quoted method-name style — research D-04/CONVENTIONS.md prefers CamelCase for ktlint friendliness.

**Production code under test (read for understanding, do NOT modify):**

`src/main/kotlin/com/six2dez/burp/aiagent/backends/perplexity/PerplexityBackendFactory.kt:16-35` — the factory delegates to `OpenAiCompatibleBackend` with two distinguishing overrides:

```kotlin
class PerplexityBackendFactory : AiBackendFactory {
    override fun create(): AiBackend =
        OpenAiCompatibleBackend(
            id = "perplexity",
            displayName = "Perplexity",
            defaultBaseUrl = DEFAULT_BASE_URL,
            baseUrlSelector = { it.perplexityUrl.trim() },
            modelSelector = { it.perplexityModel.trim() },
            apiKeySelector = { it.perplexityApiKey },
            headersSelector = { it.perplexityHeaders },
            timeoutSelector = { it.perplexityTimeoutSeconds },
            streaming = true,
            defaultHeaders = mapOf("Accept" to "text/event-stream"),
            healthCheckProvider = ::perplexityHealthCheck,
            chatCompletionsBasePath = "/chat/completions",
            supportsJsonObjectResponseFormat = false,
        )
```

`src/main/kotlin/com/six2dez/burp/aiagent/backends/openai/OpenAiCompatibleBackend.kt:185-187` — the `response_format` gate the test must observe (absence-of):

```kotlin
if (jsonMode && supportsJsonObjectResponseFormat) {
    payload["response_format"] = mapOf("type" to "json_object")
}
```

`src/main/kotlin/com/six2dez/burp/aiagent/backends/openai/OpenAiCompatibleBackend.kt:408-418` — `buildChatCompletionsUrl` (the chat-send path; the path the test exercises):

```kotlin
private fun buildChatCompletionsUrl(baseUrl: String): String {
    val trimmed = baseUrl.trimEnd('/')
    val lower = trimmed.lowercase()
    if (lower.endsWith("/chat/completions")) return trimmed
    if (versionedEndpointRegex.matches(trimmed)) return trimmed
    if (versionedBaseRegex.matches(trimmed)) return "$trimmed/chat/completions"
    val path = if (chatCompletionsBasePath.startsWith("/")) chatCompletionsBasePath else "/$chatCompletionsBasePath"
    return "$trimmed$path"
}
```

`src/main/kotlin/com/six2dez/burp/aiagent/backends/openai/OpenAiCompatibleBackend.kt:357-362` — the SSE reader (this is why the MockResponse body MUST end with `data: [DONE]\n\n`, otherwise the connection blocks until the OkHttp call timeout):

```kotlin
while (isAlive()) {
    line = streamReader.readLine() ?: break
    val trimmed = line.trim()
    if (trimmed.isEmpty() || !trimmed.startsWith("data:")) continue
    val data = trimmed.removePrefix("data:").trim()
    if (data == "[DONE]") break
```

**Canonical class scaffold (RESEARCH.md Pattern 1):**

```kotlin
package com.six2dez.burp.aiagent.backends.perplexity

import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.module.kotlin.registerKotlinModule
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
        server.enqueue(streamedResponse())
        val backend = PerplexityBackendFactory().create()
        val baseUrl = server.url("/").toString().trimEnd('/')

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
        // ... same harness, then:
        val body = mapper.readTree(recorded.body.readUtf8())
        assertFalse(body.has("response_format"), "Perplexity must not emit response_format")
        assertTrue(body.has("model"))
        assertTrue(body.has("messages"))
    }

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

**URL edge-case parametrisation (the four test methods PPLX-02 needs — research Q4 Edge-case table):**

| Test method | Input `baseUrl` (after `trimEnd('/')`) | Expected `recorded.path` |
|-------------|----------------------------------------|--------------------------|
| `targetsChatCompletionsWithoutV1PrefixOnBareHost` | `http://127.0.0.1:PORT` | `/chat/completions` |
| `handlesTrailingSlashInUserConfiguredUrl` | `http://127.0.0.1:PORT/` → trimmed to `/` host | `/chat/completions` |
| `respectsExplicitV1UserUrl` | `http://127.0.0.1:PORT/v1` | `/v1/chat/completions` (the user typed it, we honour it) |
| `doesNotDoubleAppendWhenUrlAlreadyHasChatCompletions` | `http://127.0.0.1:PORT/chat/completions` | `/chat/completions` (no double append) |

**Why no `TestSettings` here:** This test fires `backend.launch(BackendLaunchConfig(...))` directly — it does NOT need an `AgentSettings`. `TestSettings.baselineSettings()` would be **dead code** in this file. (Reserve `TestSettings` for tests that exercise an `AgentSettings`-consuming path, like file #4 / `AgentSettingsMigrationTest`.)

**Cross-cutting items the planner should re-state in this file's `<read_first>`:**
- `OpenAiCompatibleBackend.kt:185-187` (the `response_format` gate — what the test must observe absent)
- `OpenAiCompatibleBackend.kt:357-362` (the SSE `[DONE]` sentinel — why MockResponse body needs it)
- `OpenAiCompatibleBackend.kt:408-418` (the URL builder — the four edge cases)
- `BackendTypes.kt:5-20` (the `BackendLaunchConfig` data class — for constructor-argument shape)
- `PerplexityBackendFactory.kt:16-35` (under-test code, for understanding only)

---

### 3. `src/test/kotlin/com/six2dez/burp/aiagent/backends/openai/OpenAiCompatibleBackendDefaultsTest.kt` (NEW)

**Role:** wire-level test of the DEFAULT-constructor `OpenAiCompatibleBackend` (no `chatCompletionsBasePath` or `supportsJsonObjectResponseFormat` overrides)
**Covers:** PPLX-04 (backwards-compat for NVIDIA NIM and Generic OpenAI-compatible — URL ends `/v1/chat/completions`; `response_format: {"type":"json_object"}` IS present when `jsonMode = true`)
**Data flow:** identical to file #2; this test mirrors file #2 with default constructor args
**Directory:** `src/test/kotlin/com/six2dez/burp/aiagent/backends/openai/` — **does not yet exist**, the planner must create it.

**Analog (sibling pattern):** copy the harness verbatim from file #2 (MockWebServer setup/teardown, mapper, `streamedResponse()` helper). Only the assertion expectations flip and the backend construction differs.

**Production-code analog for the "no overrides" claim:** `src/main/kotlin/com/six2dez/burp/aiagent/backends/nvidia/NvidiaNimBackendFactory.kt:17-39`

```kotlin
class NvidiaNimBackendFactory : AiBackendFactory {
    override fun create(): AiBackend =
        OpenAiCompatibleBackend(
            id = "nvidia-nim",
            displayName = "NVIDIA NIM",
            defaultBaseUrl = DEFAULT_BASE_URL,
            // ... selectors ...
            streaming = true,
            defaultHeaders = mapOf("Accept" to "text/event-stream"),
            payloadCustomizer = { payload -> ... },
            healthCheckProvider = ::nimHealthCheck,
            // NOTE: no chatCompletionsBasePath, no supportsJsonObjectResponseFormat
            //       → both fall through to the constructor defaults at OpenAiCompatibleBackend.kt:44, 47
        )
```

This is why testing `OpenAiCompatibleBackend()` with bare constructor args is sufficient — NVIDIA's factory does NOT override those two knobs, so the default path IS NVIDIA's path. (Same for `OpenAiCompatibleBackendFactory` / Generic OpenAI-compat.)

**Constructor defaults under test:** `src/main/kotlin/com/six2dez/burp/aiagent/backends/openai/OpenAiCompatibleBackend.kt:42-47`

```kotlin
// Path appended to a bare-host base URL (no /v\d+ and no /chat/completions). Defaults to the
// OpenAI shape; Perplexity overrides to "/chat/completions" because its API has no /v1 prefix.
private val chatCompletionsBasePath: String = "/v1/chat/completions",
// OpenAI-style {"type":"json_object"} response_format. Perplexity's Sonar API rejects this
// field, so set false there; the scanner prompts still ask the model for JSON in plain text.
private val supportsJsonObjectResponseFormat: Boolean = true,
```

**Two `@Test` methods PPLX-04 needs (RESEARCH.md Pattern 3):**

```kotlin
@Test
fun defaultsKeepV1PrefixOnBareHost() {
    server.enqueue(nonStreamingJsonResponse())   // see below — DEFAULT backend uses non-streaming
    val backend = OpenAiCompatibleBackend(
        id = "test-default",
        displayName = "Default",
    )   // NO chatCompletionsBasePath / supportsJsonObjectResponseFormat overrides
    val baseUrl = server.url("/").toString().trimEnd('/')
    val connection = backend.launch(
        BackendLaunchConfig(
            backendId = "test-default",
            displayName = "Default",
            baseUrl = baseUrl,
            model = "gpt-4o",
            headers = emptyMap(),
            requestTimeoutSeconds = 30L,
        ),
    )
    // ... send + latch + takeRequest ...
    val recorded = server.takeRequest(1, TimeUnit.SECONDS) ?: error("no request")
    assertEquals("/v1/chat/completions", recorded.path)
}

@Test
fun defaultsEmitResponseFormatWhenJsonModeRequested() {
    // ... same setup, jsonMode = true ...
    val body = mapper.readTree(recorded.body.readUtf8())
    val rf = body.get("response_format")
    assertTrue(rf != null && rf.get("type").asText() == "json_object")
}
```

**CAUTION — streaming flag differs from file #2:** `OpenAiCompatibleBackend.kt:38` defaults `streaming = false`. When you construct the backend with bare args (`OpenAiCompatibleBackend(id = ..., displayName = ...)`), streaming is FALSE. The mock response must therefore be a **non-streaming JSON** body — NOT an SSE event stream:

```kotlin
private fun nonStreamingJsonResponse(): MockResponse =
    MockResponse()
        .setResponseCode(200)
        .setHeader("Content-Type", "application/json")
        .setBody("""{"choices":[{"message":{"role":"assistant","content":"ok"}}]}""")
```

This is verified at `OpenAiCompatibleBackend.kt:311-339` (`handleNonStreamingResponse`): the connection parses `choices[0].message.content` from a plain JSON body. If you reuse file #2's SSE `streamedResponse()` helper here, the test will read SSE bytes via the non-streaming JSON parser, see no `choices`, and complete with `IllegalStateException("response content was empty")` — confusing and slow to diagnose.

**Cross-cutting items the planner should re-state in this file's `<read_first>`:**
- `OpenAiCompatibleBackend.kt:29-48` (constructor defaults — the contract under audit)
- `OpenAiCompatibleBackend.kt:311-339` (non-streaming JSON parser — why MockResponse body is JSON not SSE)
- `OpenAiCompatibleBackend.kt:185-187` (`response_format` gate — what the test must observe present)
- `NvidiaNimBackendFactory.kt:17-39` (proof that NIM has no overrides on the two knobs under audit)
- `BackendTypes.kt:5-20` (`BackendLaunchConfig`)

---

### 4. `src/test/kotlin/com/six2dez/burp/aiagent/config/AgentSettingsMigrationTest.kt` (EXTEND)

**Role:** add ONE new `@Test` method covering PPLX-05 (v0.6.x prefs load with safe defaults; `CURRENT_SETTINGS_SCHEMA_VERSION` stays at 3; no `migrateIfNeeded` bump)
**Data flow:** `InMemoryPrefs` (pre-populated) → `AgentSettingsRepository.load()` → assertions on the returned `AgentSettings` + assertions on the post-load `prefs.integers["settings.schema.version"]`
**Mode:** EXTEND — do not create a new file; do not extract `InMemoryPrefs` into a shared fixture in this phase.

**Analog (this file itself, two excerpts):**

**Excerpt A — the schema-stability pattern (file lines 42-52, the closest existing analog to the new test):**

```kotlin
// AgentSettingsMigrationTest.kt:42-52
@Test
fun load_v2InstallLoadsEmptyCustomPromptLibraryAndStampsV3() {
    val prefs = InMemoryPrefs()
    prefs.integers["settings.schema.version"] = 2
    val repo = AgentSettingsRepository(apiWith(prefs.mock))

    val loaded = repo.load()

    assertEquals(emptyList<CustomPromptDefinition>(), loaded.customPromptLibrary)
    assertEquals(3, prefs.integers["settings.schema.version"])
}
```

**Excerpt B — the `InMemoryPrefs` private nested class (file lines 60-88) — REUSE in-file, do NOT extract:**

```kotlin
// AgentSettingsMigrationTest.kt:60-88
private class InMemoryPrefs {
    val strings = mutableMapOf<String, String>()
    val booleans = mutableMapOf<String, Boolean>()
    val integers = mutableMapOf<String, Int>()
    val mock: Preferences =
        mock<Preferences>().also { prefs ->
            whenever(prefs.getString(any())).thenAnswer { invocation ->
                strings[invocation.getArgument(0)]
            }
            whenever(prefs.setString(any(), any())).thenAnswer { invocation ->
                strings[invocation.getArgument(0)] = invocation.getArgument(1)
                null
            }
            // ... booleans + integers wired symmetrically ...
        }
}
```

**Excerpt C — the `apiWith` helper (file lines 54-58) — REUSE in-file:**

```kotlin
// AgentSettingsMigrationTest.kt:54-58
private fun apiWith(preferences: Preferences): MontoyaApi {
    val api = mock<MontoyaApi>(defaultAnswer = Answers.RETURNS_DEEP_STUBS)
    whenever(api.persistence().preferences()).thenReturn(preferences)
    return api
}
```

**New `@Test` to insert (after the existing `load_v2InstallLoadsEmptyCustomPromptLibraryAndStampsV3` at line 52, before the `private fun apiWith` at line 54):**

```kotlin
@Test
fun load_v06xPreferencesYieldSafePerplexityDefaultsAndSchemaStaysV3() {
    val prefs = InMemoryPrefs()
    // Simulate v0.6.x install: schema marker at the version that shipped before this phase, no perplexity.* keys.
    prefs.integers["settings.schema.version"] = 3

    val repo = AgentSettingsRepository(apiWith(prefs.mock))
    val loaded = repo.load()

    assertEquals("https://api.perplexity.ai", loaded.perplexityUrl)
    assertEquals("", loaded.perplexityModel)
    assertEquals("", loaded.perplexityApiKey)
    assertEquals("", loaded.perplexityHeaders)
    assertEquals(120, loaded.perplexityTimeoutSeconds)
    assertEquals(3, prefs.integers["settings.schema.version"])
}
```

**Production code under test (read for understanding, do NOT modify):**

`src/main/kotlin/com/six2dez/burp/aiagent/config/AgentSettings.kt:57-61` — the five additive fields:

```kotlin
val perplexityUrl: String = "https://api.perplexity.ai",
val perplexityModel: String = "",
val perplexityApiKey: String = "",
val perplexityHeaders: String = "",
val perplexityTimeoutSeconds: Int = 60,
```

`src/main/kotlin/com/six2dez/burp/aiagent/config/AgentSettings.kt:257-266` — the load path:

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

`src/main/kotlin/com/six2dez/burp/aiagent/config/AgentSettings.kt:780` — `CURRENT_SETTINGS_SCHEMA_VERSION = 3` (must stay at 3 post-load).

`src/main/kotlin/com/six2dez/burp/aiagent/config/AgentSettings.kt:822-824` — default helpers:

```kotlin
private fun defaultPerplexityUrl(): String = "https://api.perplexity.ai"
private fun defaultPerplexityTimeoutSeconds(): Int = Defaults.CLI_PROCESS_TIMEOUT_SECONDS
```

`src/main/kotlin/com/six2dez/burp/aiagent/config/Defaults.kt:41` — `CLI_PROCESS_TIMEOUT_SECONDS = 120` (verified — the assertion `assertEquals(120, loaded.perplexityTimeoutSeconds)` is correct, A1 in RESEARCH.md is **confirmed**). Note: `load()` applies `.coerceIn(30, 3600)` to the loaded value, and 120 is within range, so passes through unchanged.

**Convention notes specific to this file:**

- **Naming style:** existing tests in this file use a **mixed naming style** — `load_migratesLegacySchemaAndUpdatesVersionMarker` (snake_case prefix + CamelCase suffix) and `save_persistsCurrentSchemaVersion`. The new method follows the same `load_…` prefix convention. (This is NOT in tension with CONVENTIONS.md's "CamelCase preferred" — the snake_case prefix names the under-test method and is a recognised in-file convention.)
- **`@Test` annotation:** use `org.junit.jupiter.api.Test` (already imported at line 7). Do NOT add `kotlin.test.Test` even though some files in the repo use it (it works only because Kotlin's `kotlin-test` is a multi-runner shim; consistency-with-this-file is the rule).
- **Assertions:** use `org.junit.jupiter.api.Assertions.assertEquals` (already imported at line 5). Do NOT use `kotlin.test.assertEquals` in this file.
- **No `@BeforeEach`/`@AfterEach`:** the existing tests construct `InMemoryPrefs` inside each `@Test` (no shared state). Follow that pattern.

**Cross-cutting items the planner should re-state in this file's `<read_first>`:**
- `AgentSettings.kt:57-61` (data-class defaults — the contract)
- `AgentSettings.kt:257-266` (load path)
- `AgentSettings.kt:780` (schema version constant)
- `AgentSettings.kt:822-824` (default helpers)
- `Defaults.kt:41` (the literal 120 the test asserts against)
- `AgentSettingsMigrationTest.kt:42-52` (the closest in-file analog `@Test`)

---

## Shared Patterns (apply across all three test files)

### Authentication / Authorization

**Not applicable.** No backend tests in this phase exercise auth boundaries. The `Authorization: Bearer pplx-test` header in file #2 is plumbing (so `OpenAiCompatibleConnection` accepts the launch config) — not an assertion target unless the optional `passesBearerTokenAndStreamHeader` smoke from RESEARCH.md Q7 is included. CONTEXT.md `<specifics>` does not list it; planner can drop it.

### Error Handling

**Not applicable** at file #2 / #3 level. The MockWebServer happy-path response means `onComplete(null)` fires. The tests assert on the captured `RecordedRequest`, NOT on the `onComplete`'s throwable. Asserting error paths (401, 429) is out of scope for this audit (the existing `CircuitBreakerTest` covers the circuit-breaker side; the existing `BackendHealthCheckTest` covers health-check error mapping). Do NOT add 401/429 tests in this phase.

### JSON Inspection (applies to files #2 and #3)

**Source pattern (production):** `src/main/kotlin/com/six2dez/burp/aiagent/backends/perplexity/PerplexityBackendFactory.kt:40`

```kotlin
private val mapper = ObjectMapper().registerKotlinModule()
```

**Apply in tests as:**

```kotlin
private val mapper = ObjectMapper().registerKotlinModule()
// ...
val body: com.fasterxml.jackson.databind.JsonNode = mapper.readTree(recorded.body.readUtf8())
assertTrue(body.has("messages"))
assertFalse(body.has("response_format"))   // Perplexity
assertEquals("sonar", body.get("model").asText())
```

**Rule:** assert key presence/absence and exact values for the keys you care about — never `assertEquals(expectedJsonString, body.toString())`. Optional fields (`temperature`, `top_p`, `max_tokens`) shift under refactor without breaking the contract. This is RESEARCH.md anti-pattern #4.

### MockWebServer Lifecycle (applies to files #2 and #3)

**Per-test instances, never shared via `companion object`:**

```kotlin
private lateinit var server: MockWebServer

@BeforeEach
fun setup() {
    server = MockWebServer()
    server.start()
}

@AfterEach
fun teardown() {
    server.shutdown()
}
```

**`enqueue` once per `@Test`** before calling `connection.send(...)`. Each `MockWebServer` gets a unique localhost port (e.g. `127.0.0.1:54321`), so `HttpBackendSupport.sharedClient`'s cache key `(baseUrl.lowercase(), timeoutSeconds)` is unique per test — no cross-test pollution. Do NOT call `HttpBackendSupport.shutdownSharedClients()` in `@AfterEach`; it would empty the static cache for other concurrently-running backend tests.

### `MockResponse` body shape (applies to files #2 and #3)

**Streaming (Perplexity, file #2 — `streaming = true`):**

```kotlin
private fun streamedResponse(): MockResponse =
    MockResponse()
        .setResponseCode(200)
        .setHeader("Content-Type", "text/event-stream")
        .setBody(
            "data: {\"choices\":[{\"delta\":{\"content\":\"ok\"}}]}\n\n" +
                "data: [DONE]\n\n",
        )
```

Termination via `data: [DONE]\n\n` is **mandatory**; the SSE reader at `OpenAiCompatibleBackend.kt:362` (`if (data == "[DONE]") break`) is the only loop exit besides EOF. Missing the sentinel → test hangs until OkHttp timeout (~30s).

**Non-streaming (Default OpenAI-compat, file #3 — `streaming = false`):**

```kotlin
private fun nonStreamingJsonResponse(): MockResponse =
    MockResponse()
        .setResponseCode(200)
        .setHeader("Content-Type", "application/json")
        .setBody("""{"choices":[{"message":{"role":"assistant","content":"ok"}}]}""")
```

`OpenAiCompatibleBackend.kt:311-339` (`handleNonStreamingResponse`) parses `choices[0].message.content`. If `content` is blank, the connection completes with `IllegalStateException("response content was empty")` — your latch still trips, but tests will look strangely flaky if the body is malformed.

### Test method naming (applies to files #2, #3 — NEW; file #4 follows existing in-file style)

**Convention (CONVENTIONS.md, ktlint-friendly):** CamelCase, no backticks. Examples:
- `targetsChatCompletionsWithoutV1PrefixOnBareHost` (file #2)
- `omitsResponseFormatEvenWhenJsonModeRequested` (file #2)
- `defaultsKeepV1PrefixOnBareHost` (file #3)
- `defaultsEmitResponseFormatWhenJsonModeRequested` (file #3)

**For the in-file extension (file #4):** match the existing `load_…` snake_case-prefix convention:
- `load_v06xPreferencesYieldSafePerplexityDefaultsAndSchemaStaysV3`

Don't mix conventions inside one file. Don't use the backtick-quoted style (`` `decodes multibyte body as UTF-8` ``) — that's a legacy style in `MontoyaHttpTransportUtf8Test.kt`; not the model for new files.

---

## Do NOT Modify / Do NOT Reach Into

These are intentionally excluded from the audit (scope creep guards):

| Asset | Why it must stay untouched |
|-------|---------------------------|
| `src/main/kotlin/com/six2dez/burp/aiagent/backends/http/HttpBackendSupport.kt` `sharedClient(...)`, `shutdownSharedClients()` | The shared OkHttpClient cache is statically scoped; calling `shutdownSharedClients()` from `@AfterEach` would empty the cache for ALL concurrently-running backend tests in a parallel test JVM. Tests must NOT touch this — let the cache live for the JVM lifetime. |
| `src/main/kotlin/com/six2dez/burp/aiagent/backends/openai/OpenAiCompatibleBackend.kt` private fields (`chatCompletionsBasePath`, `supportsJsonObjectResponseFormat`) | D-04 locks wire-level assertions. Do NOT add reflection (`getDeclaredField(...).isAccessible = true`) — couples tests to private names; behavioural tests already reach all assertions via `RecordedRequest`. Do NOT add `internal` visibility to either field "to make testing easier" — the wire-level path already works. |
| The duplicate `buildChatCompletionsUrl` in `PerplexityBackendFactory.kt:89-96` | This copy is exercised ONLY by the factory's health-check (the "Test connection" button in `BackendConfigPanel`). The chat-send path goes through `OpenAiCompatibleBackend.kt:408-418`. DO NOT refactor the duplication out in this phase — Deferred Idea in CONTEXT.md, future grooming task. |
| `src/main/kotlin/com/six2dez/burp/aiagent/config/AgentSettings.kt` `migrateIfNeeded` (lines 624-643) | PPLX-05 explicitly verifies NO bump. Do NOT add a new `case 3 ->` branch; the additive fields work without one. The test asserts `prefs.integers["settings.schema.version"] == 3` post-load to prove this. |
| `META-INF/services/com.six2dez.burp.aiagent.backends.AiBackendFactory` | Perplexity is already registered at line 7. `BackendRegistryTest` already covers SPI discovery (research D-08). Do NOT add a new test for registration — duplicate coverage. |
| `src/test/kotlin/com/six2dez/burp/aiagent/backends/http/` (existing 3 test files) | Not the right home for new wire-level tests. D-07 places new tests in `backends/perplexity/` and `backends/openai/`, not `backends/http/`. Do NOT touch `CircuitBreakerTest.kt`, `ConversationHistoryTest.kt`, `MontoyaHttpTransportUtf8Test.kt`. |
| `BackendHealthCheckTest.kt`'s inline `baselineSettings()` (lines 84-168) | Per RESEARCH.md anti-patterns: that file is **legacy** per TESTING.md ("tests that inline a full AgentSettings constructor are legacy"). Do NOT copy its inline constructor pattern. Use `TestSettings.baselineSettings().copy(...)` if `AgentSettings` is needed (it isn't for files #2 / #3). |
| `InMemoryPrefs` (private nested class in `AgentSettingsMigrationTest.kt:60-88`) | **REUSE in-file**, but do NOT extract into a shared fixture (`src/test/kotlin/.../config/InMemoryPrefs.kt` or similar) in this phase. The extraction is a future refactor; locking the in-file convention now keeps the scope at one new `@Test`. |

---

## Reusable Assets Summary (planner reference)

| Asset | Location | How to use |
|-------|----------|------------|
| `TestSettings.baselineSettings()` | `src/test/kotlin/com/six2dez/burp/aiagent/TestSettings.kt:11` | Returns a complete `AgentSettings` with `data class` defaults for the 5 `perplexity*` fields (Sleeve does NOT explicitly set them; they fall through to the defaults at `AgentSettings.kt:57-61`). Use as `TestSettings.baselineSettings().copy(perplexityUrl = ..., perplexityModel = ...)` if an `AgentSettings` is needed. **Not needed by files #2 or #3** (they construct `BackendLaunchConfig` directly). |
| `InMemoryPrefs` | `src/test/kotlin/com/six2dez/burp/aiagent/config/AgentSettingsMigrationTest.kt:60-88` | Mockito-Kotlin–backed `Preferences` test double; three `MutableMap`s (strings, booleans, integers). Construct via `val prefs = InMemoryPrefs()`, pre-populate via `prefs.integers["settings.schema.version"] = 3`, wire into a repo via `AgentSettingsRepository(apiWith(prefs.mock))`. **Used only by file #4** (private nested in that file — in-scope automatically). |
| `apiWith(preferences)` helper | `src/test/kotlin/com/six2dez/burp/aiagent/config/AgentSettingsMigrationTest.kt:54-58` | Builds a `MontoyaApi` mock whose `persistence().preferences()` chain returns the supplied `Preferences`. Uses Mockito `RETURNS_DEEP_STUBS`. **Used only by file #4.** |
| Canonical SSE response body | RESEARCH.md "Pattern 1" + this PATTERNS.md "Shared Patterns → MockResponse body shape" | `data: {"choices":[{"delta":{"content":"ok"}}]}\n\ndata: [DONE]\n\n` — exact string; `[DONE]` sentinel mandatory. **Used by file #2** (Perplexity, `streaming = true`). |
| Canonical non-streaming JSON response | This PATTERNS.md "Shared Patterns → MockResponse body shape" | `{"choices":[{"message":{"role":"assistant","content":"ok"}}]}` — exact string. **Used by file #3** (default constructor, `streaming = false`). |
| `BackendLaunchConfig` data class | `src/main/kotlin/com/six2dez/burp/aiagent/backends/BackendTypes.kt:5-20` | Constructor args: `backendId`, `displayName`, `baseUrl`, `model`, `headers`, `requestTimeoutSeconds` (others default). Tests construct directly — do NOT route through `AgentSupervisor` or `BackendRegistry`. |
| `ObjectMapper().registerKotlinModule()` | production idiom at `PerplexityBackendFactory.kt:40` and `OpenAiCompatibleBackend.kt:51` | Tests mirror at top of class as `private val mapper = ObjectMapper().registerKotlinModule()`. Use `mapper.readTree(recorded.body.readUtf8())` to parse captured request bodies. |
| Existing test that uses the closest naming convention | `src/test/kotlin/com/six2dez/burp/aiagent/backends/http/CircuitBreakerTest.kt:1-30` | CamelCase method names, JUnit Jupiter imports, `Assertions.*` static imports. Files #2 and #3 follow this style. |

---

## No Analog Found

None. Every new test file has at least a partial codebase analog:
- File #1 (`build.gradle.kts` line): exact in-file analog (the existing `testImplementation` lines).
- File #2 (`PerplexityBackendFactoryTest`): no MockWebServer test exists yet — **this file establishes the project's first MockWebServer convention**. But the structural shape (class scaffold, naming, imports) is fully covered by `CircuitBreakerTest.kt`. The MockWebServer harness shape comes from RESEARCH.md Pattern 1 (verified against OkHttp's documented API at https://square.github.io/okhttp/4.x/mockwebserver/).
- File #3 (`OpenAiCompatibleBackendDefaultsTest`): sibling of file #2 — copy the harness verbatim with non-streaming MockResponse and default-constructor backend.
- File #4 (`AgentSettingsMigrationTest` extension): exact in-file analog (`load_v2InstallLoadsEmptyCustomPromptLibraryAndStampsV3`).

---

## Metadata

**Analog search scope:**
- `src/test/kotlin/com/six2dez/burp/aiagent/backends/` (recursive)
- `src/test/kotlin/com/six2dez/burp/aiagent/config/AgentSettingsMigrationTest.kt`
- `src/test/kotlin/com/six2dez/burp/aiagent/TestSettings.kt`
- `src/test/kotlin/com/six2dez/burp/aiagent/mcp/McpServerIntegrationTest.kt` (referenced; rejected as shape model — Ktor server harness is heavy-suite, Perplexity tests are fast-suite)
- `src/main/kotlin/com/six2dez/burp/aiagent/backends/perplexity/PerplexityBackendFactory.kt`
- `src/main/kotlin/com/six2dez/burp/aiagent/backends/openai/OpenAiCompatibleBackend.kt`
- `src/main/kotlin/com/six2dez/burp/aiagent/backends/nvidia/NvidiaNimBackendFactory.kt`
- `src/main/kotlin/com/six2dez/burp/aiagent/backends/BackendTypes.kt`
- `src/main/kotlin/com/six2dez/burp/aiagent/config/AgentSettings.kt` (selected line ranges 50-90, 250-280, 770-830)
- `src/main/kotlin/com/six2dez/burp/aiagent/config/Defaults.kt` (line 41 — `CLI_PROCESS_TIMEOUT_SECONDS = 120`)
- `build.gradle.kts` (entire file)

**Files scanned:** 12 (8 production + 4 test, plus build script)
**Closest-analog ranking applied:** prefer same-role (test → test) + same-data-flow (HTTP wire) + recency (all test files touched in 2026). `BackendHealthCheckTest.kt` (heavy inline constructor pattern, legacy per TESTING.md) explicitly rejected as a model for new test files.

**Pattern extraction date:** 2026-05-13

---

## PATTERN MAPPING COMPLETE
