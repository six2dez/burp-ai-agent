---
phase: 01-perplexity-backend-audit
reviewed: 2026-05-13T11:30:00Z
depth: standard
files_reviewed: 4
files_reviewed_list:
  - build.gradle.kts
  - src/test/kotlin/com/six2dez/burp/aiagent/backends/perplexity/PerplexityBackendFactoryTest.kt
  - src/test/kotlin/com/six2dez/burp/aiagent/backends/openai/OpenAiCompatibleBackendDefaultsTest.kt
  - src/test/kotlin/com/six2dez/burp/aiagent/config/AgentSettingsMigrationTest.kt
findings:
  critical: 0
  warning: 3
  info: 5
  total: 8
status: issues_found
---

# Phase 1: Code Review Report

**Reviewed:** 2026-05-13T11:30:00Z
**Depth:** standard
**Files Reviewed:** 4
**Status:** issues_found

## Summary

Phase 1 adds five MockWebServer-based wire-level tests covering the Perplexity backend (PPLX-01..05), two regression tests pinning OpenAI-compatible defaults, and four settings-migration tests, plus the one Gradle dependency (`mockwebserver:4.12.0`) required to run them. Zero production code was touched, matching the phase's stated "behaviour-locking" intent.

Cross-referencing each assertion against the production code confirms the assertions are semantically correct: the Perplexity URL-rewrite cases match `OpenAiCompatibleBackend.buildChatCompletionsUrl()` and the migration assertions match the actual schema-v3 logic in `AgentSettingsRepository.migrateIfNeeded()`. Defaults asserted in `load_v06xPreferencesYieldSafePerplexityDefaultsAndSchemaStaysV3` (URL `https://api.perplexity.ai`, timeout 120s) match `defaultPerplexityUrl()` / `Defaults.CLI_PROCESS_TIMEOUT_SECONDS`. The schema-version assertions match `CURRENT_SETTINGS_SCHEMA_VERSION = 3`.

The defects found are flakiness, leak, and clarity issues — none would block landing the suite, but they leave footguns for the next contributor and weaken the regression value of the tests once retries or slow hardware are involved.

## Warnings

### WR-01: Test timeout is too tight under retry-on-failure path

**File:** `src/test/kotlin/com/six2dez/burp/aiagent/backends/perplexity/PerplexityBackendFactoryTest.kt:57,90,122,154,189` (all five tests) and `src/test/kotlin/com/six2dez/burp/aiagent/backends/openai/OpenAiCompatibleBackendDefaultsTest.kt:61,98`

**Issue:** Every `done.await(5, TimeUnit.SECONDS)` budget assumes a first-attempt-success. `OpenAiCompatibleBackend.send()` runs up to 6 attempts on retryable connection errors with exponential backoff via `HttpBackendSupport.retryDelayMs(attempt)` (`OpenAiCompatibleBackend.kt:159,278-295`). If the MockWebServer briefly stalls on a slow CI runner or a port-bind race, the latch may not fire within 5 seconds and the test fails spuriously — without any signal that a retry was the cause. The tests also do not enqueue extra `MockResponse`s, so a single retry would deadlock on `streamReader.readLine()` waiting for body content that `takeRequest()` consumes only after the await returns.

**Fix:** Either (a) raise the deterministic budget to a value that comfortably covers a single retry (e.g. 15s) and document why, or (b) assert that retries did not happen by checking `server.requestCount == 1` alongside the latch. Concretely:

```kotlin
assertTrue(done.await(15, TimeUnit.SECONDS), "send() never completed")
assertEquals(1, server.requestCount, "unexpected retry attempt")
```

### WR-02: Connections are never stopped — daemon executor and OkHttp dispatcher leak across tests

**File:** all three test files (after every `connection.send {...}` invocation)

**Issue:** `OpenAiCompatibleBackend.launch()` constructs an `OpenAiCompatibleConnection` that owns a single-thread `Executors.newSingleThreadExecutor` (`OpenAiCompatibleBackend.kt:124-127`). The tests never call `connection.stop()`, so the executor thread and its blocking `BufferedReader` stay alive past `@AfterEach`. `HttpBackendSupport.sharedClient()` additionally caches an `OkHttpClient` (with its own dispatcher + connection pool) keyed by base URL across tests (`HttpBackendSupport.kt:43-58`). Together, every test leaves at least one connection and one shared client live for the rest of the JVM. They are daemon threads, so the JVM still exits, but inside a single Gradle test JVM they accumulate (7 tests × 1 executor + N shared clients) and increase the risk of cross-test interference (notably: stream reader still blocked on a socket the next test reuses).

**Fix:** Hold the `AgentConnection` in a field and call `connection.stop()` from `@AfterEach`:

```kotlin
private var connection: AgentConnection? = null

@AfterEach
fun teardown() {
    connection?.stop()
    server.shutdown()
}
```
Even better, also call `HttpBackendSupport.shutdownSharedClients()` (already exists at `HttpBackendSupport.kt:60-69`) once after the suite via `@AfterAll`.

### WR-03: `@AfterEach` will mask the original failure if `@BeforeEach` aborts before `server.start()`

**File:** `src/test/kotlin/com/six2dez/burp/aiagent/backends/perplexity/PerplexityBackendFactoryTest.kt:27-30` and `src/test/kotlin/com/six2dez/burp/aiagent/backends/openai/OpenAiCompatibleBackendDefaultsTest.kt:26-29`

**Issue:** `server` is `lateinit var`. JUnit Jupiter still runs `@AfterEach` even when `@BeforeEach` throws. If `MockWebServer.start()` fails (port exhaustion is the realistic case on heavily loaded CI), `server` is uninitialised; `server.shutdown()` then throws `UninitializedPropertyAccessException`, which is the exception reported to the reporter — hiding the real "could not bind socket" cause.

**Fix:**

```kotlin
private var server: MockWebServer? = null

@BeforeEach
fun setup() {
    server = MockWebServer().also { it.start() }
}

@AfterEach
fun teardown() {
    server?.shutdown()
}
```
Then reference `server!!` in each test (or use a `requireNotNull` helper).

## Info

### IN-01: Hard-coded "Bearer pplx-test" looks like a credential to secret scanners

**File:** `src/test/kotlin/com/six2dez/burp/aiagent/backends/perplexity/PerplexityBackendFactoryTest.kt:45,77,109,141,176`

**Issue:** The literal `"Bearer pplx-test"` matches the Perplexity API-key naming convention (`pplx-*`). It is not a real key, but generic regex scanners (gitleaks, trufflehog defaults) and the project's own `CLAUDE.md` privacy stance flag this shape. The test never reads the value back, so it is dead weight in the assertion budget too.

**Fix:** Use an obviously-fake token that does not match Perplexity's prefix, e.g. `"Bearer test-token-not-real"`, or extract to `private const val FAKE_AUTH = "Bearer test-token"` once and reference it from each test. This also collapses five identical literals into one.

### IN-02: Five copy-pasted launch-and-send blocks; factor a helper

**File:** `src/test/kotlin/com/six2dez/burp/aiagent/backends/perplexity/PerplexityBackendFactoryTest.kt:33-94` (and same shape in OpenAi defaults file)

**Issue:** Each of the five Perplexity tests repeats the same 20-line `BackendLaunchConfig(...).launch(...).send(...)` block. Difference is limited to `baseUrl` and `jsonMode`. The duplication means a future signature change (e.g., `BackendLaunchConfig` adding a required field) will need five edits, and it inflates review surface for what's really a parameter table.

**Fix:** Extract:

```kotlin
private fun sendOneAndAwait(baseUrl: String, jsonMode: Boolean = false): RecordedRequest {
    val backend = PerplexityBackendFactory().create()
    val connection = backend.launch(
        BackendLaunchConfig(
            backendId = "perplexity",
            displayName = "Perplexity",
            baseUrl = baseUrl,
            model = "sonar",
            headers = mapOf("Authorization" to FAKE_AUTH),
            requestTimeoutSeconds = 30L,
        ),
    )
    val done = CountDownLatch(1)
    connection.send(text = "hello", onChunk = {}, onComplete = { done.countDown() }, jsonMode = jsonMode)
    assertTrue(done.await(15, TimeUnit.SECONDS))
    return server.takeRequest(1, TimeUnit.SECONDS) ?: error("no request")
}
```

### IN-03: Assertion missing a message — failure will be `expected: true was: false`

**File:** `src/test/kotlin/com/six2dez/burp/aiagent/backends/openai/OpenAiCompatibleBackendDefaultsTest.kt:103`

**Issue:** `assertTrue(rf != null && rf.get("type").asText() == "json_object")` collapses two distinct failure modes (`response_format` missing vs. wrong type) into one boolean. When this regression fires, the report says only "expected true". The companion Perplexity test (`PerplexityBackendFactoryTest.kt:158`) already uses an assertion message; align the style.

**Fix:**

```kotlin
assertEquals("json_object", body.path("response_format").path("type").asText(),
    "default OpenAI-compatible payload must request json_object response_format")
```

### IN-04: Mocking `Preferences` with Mockito-Kotlin instead of a hand-written fake

**File:** `src/test/kotlin/com/six2dez/burp/aiagent/config/AgentSettingsMigrationTest.kt:77-105`

**Issue:** The `InMemoryPrefs` class wires Mockito mocks just to delegate to plain `MutableMap`s. The `@Test`s don't actually verify any Mockito interactions (no `verify(...)` calls), so using Mockito here adds runtime cost (and an `any()` import) without adding test value. It also makes the intent ("a Preferences-backed memory store") harder to read.

**Fix:** Implement `Preferences` directly via a Kotlin `object : Preferences { ... }` anonymous class, or extract a tiny `class InMemoryPreferences : Preferences { ... }` that overrides only the six accessors the tests use. Drop the mockito-kotlin dependency from this file.

### IN-05: `Answers.RETURNS_DEEP_STUBS` masks the next refactor of `api.persistence()`

**File:** `src/test/kotlin/com/six2dez/burp/aiagent/config/AgentSettingsMigrationTest.kt:72`

**Issue:** `mock<MontoyaApi>(defaultAnswer = Answers.RETURNS_DEEP_STUBS)` auto-creates stub chains for any method called on the API, then is immediately overridden with `whenever(api.persistence().preferences()).thenReturn(preferences)`. If `AgentSettingsRepository` ever starts calling another `api.*()` method in `load()` (e.g. `api.logging().logToError(...)` is *already* called from `parseCustomPromptLibrary` — see `AgentSettings.kt:372`), the test silently returns a deep-stub `Logging` instead of `null`, hiding a real NPE in production code paths.

The current test passes only because `parseCustomPromptLibrary` is never invoked from a failing path. The risk: a future migration adds logging that today returns a no-op stub instead of throwing, and we lose the regression signal.

**Fix:** Drop deep stubs; explicitly stub each API surface the repo touches:

```kotlin
private fun apiWith(preferences: Preferences): MontoyaApi {
    val api = mock<MontoyaApi>()
    val persistence = mock<burp.api.montoya.persistence.Persistence>()
    val logging = mock<burp.api.montoya.logging.Logging>()
    whenever(api.persistence()).thenReturn(persistence)
    whenever(persistence.preferences()).thenReturn(preferences)
    whenever(api.logging()).thenReturn(logging)
    return api
}
```

---

_Reviewed: 2026-05-13T11:30:00Z_
_Reviewer: Claude (gsd-code-reviewer)_
_Depth: standard_
