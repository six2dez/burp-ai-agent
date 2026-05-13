# Testing Patterns

**Analysis Date:** 2026-05-13

## Test Framework

**Runner:**
- JUnit Jupiter (JUnit 5) `6.0.3` — `org.junit.jupiter:junit-jupiter`
- Config: `build.gradle.kts` — `tasks.test { useJUnitPlatform() }`
- Kotlin test assertions also available: `kotlin("test")` dependency (mixed usage — see below)

**Mocking:**
- Mockito-Kotlin `5.4.0` — `org.mockito.kotlin:mockito-kotlin`
- `mock<Type>()`, `whenever(...).thenReturn(...)`, `Answers.RETURNS_DEEP_STUBS` for chained Montoya API calls

**Assertion Libraries:**
- JUnit5 `Assertions.*` (primary): `assertEquals`, `assertTrue`, `assertNotNull`
- Kotlin `kotlin.test.*` (secondary, some files): `assertEquals`, `assertNull`, `assertTrue`
- Do not mix both import styles in the same test file

**Run Commands:**
```bash
./gradlew test                              # Full fast suite + JaCoCo report
./gradlew test -PexcludeHeavyTests=true     # PR gate (excludes Integration/Concurrency/Backpressure/RestartPolicy)
./gradlew nightlyRegressionTest             # Heavy suites only
./gradlew test nightlyRegressionTest        # Everything (release gate)
```

## Test File Organization

**Location:** `src/test/kotlin/com/six2dez/burp/aiagent/`

**Naming:** `{TestedClass}Test.kt` — mirrors the production package structure exactly:

```
src/test/kotlin/com/six2dez/burp/aiagent/
├── TestSettings.kt                          # shared fixture factory (object)
├── agents/
│   └── AgentProfileLoaderTest.kt
├── audit/
│   ├── AiRequestLoggerTest.kt
│   └── HashingTest.kt
├── backends/
│   ├── BackendHealthCheckTest.kt
│   └── BackendRegistryTest.kt
├── config/
│   ├── AgentSettingsMigrationTest.kt
│   ├── CustomPromptFilterTest.kt
│   ├── CustomPromptLibraryTest.kt
│   └── McpSettingsTest.kt
├── context/
│   └── ContextPreviewConsistencyTest.kt
├── integration/
│   └── CompatibilitySmokeTest.kt
├── mcp/
│   ├── KtorMcpCorsPolicyTest.kt
│   ├── KtorMcpServerManagerSecurityTest.kt
│   ├── McpRequestLimiterConcurrencyTest.kt    # heavy
│   ├── McpRuntimeContextFactoryTest.kt
│   ├── McpServerIntegrationTest.kt            # heavy
│   ├── McpStdioBridgeCompatibilityTest.kt
│   ├── McpSupervisorConnectionTest.kt
│   ├── McpSupervisorRestartPolicyTest.kt      # heavy
│   └── McpUnsafeGatingTest.kt
├── redact/
│   └── RedactionTest.kt
├── scanner/
│   ├── ActiveScannerQueueModelTest.kt
│   ├── InjectionPointExtractorTest.kt
│   ├── PassiveAiScannerConfidenceTest.kt
│   ├── PassiveAiScannerJsonParsingTest.kt
│   ├── PayloadGeneratorTest.kt
│   ├── ResponseAnalyzerTest.kt
│   ├── ScannerQueueBackpressureTest.kt        # heavy
│   └── VulnClassInventoryTest.kt
├── supervisor/
│   ├── AgentSupervisorRestartPolicyTest.kt    # heavy
│   └── BurpAiGateScopingTest.kt
└── ui/
    ├── ChatPanelConcurrencyTest.kt            # heavy
    ├── MarkdownRendererPerformanceTest.kt
    ├── SettingsDefaultsPersistenceTest.kt
    └── ToolCallParserTest.kt
```

Total: 41 test files (as of 2026-05-13).

## Test Suite Classification

**Fast suite** (default `./gradlew test`): all tests not matching heavy suffixes.

**Heavy suite** (excluded on PR gate with `-PexcludeHeavyTests=true`):
- `*IntegrationTest` — spins up real Ktor server, binds a real port
- `*ConcurrencyTest` — multi-threaded race condition checks
- `*BackpressureTest` — queue saturation under load
- `*RestartPolicyTest` — supervisor restart with timing-sensitive waits

Heavy tests run in `./gradlew nightlyRegressionTest` and in the release gate.

## Test Structure

**Suite organization:**
```kotlin
// Pattern A: Direct assertions (pure-function tests)
class RedactionTest {
    @Test
    fun strictModeStripsCookiesTokensAndHosts() {
        val policy = RedactionPolicy.fromMode(PrivacyMode.STRICT)
        val output = Redaction.apply(input, policy, stableHostSalt = "salt")
        assertTrue(output.contains("Cookie: [STRIPPED]"))
    }
}

// Pattern B: @BeforeEach setup
class AiRequestLoggerTest {
    private lateinit var logger: AiRequestLogger

    @BeforeEach
    fun setup() {
        logger = AiRequestLogger(maxEntries = 100)
    }

    @Test
    fun `test circular buffer enforcement`() { ... }
}

// Pattern C: Companion constant for contract locking
class VulnClassInventoryTest {
    companion object {
        private const val EXPECTED_COUNT = 62  // update README together when this changes
    }
    @Test
    fun enumCountMatchesPublicClaim() {
        assertEquals(EXPECTED_COUNT, VulnClass.entries.size, "...")
    }
}
```

**Test method naming:**
- JUnit 5 allows backtick names (`` `test circular buffer enforcement` ``) — used in `AiRequestLoggerTest`
- CamelCase names without underscores also common: `strictModeStripsCookiesTokensAndHosts`
- Both styles are accepted; prefer camelCase for new tests for ktlint compatibility

## Mocking

**Framework:** Mockito-Kotlin 5.4.0

**Montoya API mocking pattern** — always use `RETURNS_DEEP_STUBS` for chained API calls:
```kotlin
val api = mock<MontoyaApi>(defaultAnswer = Answers.RETURNS_DEEP_STUBS)
whenever(api.burpSuite().version().edition()).thenReturn(BurpSuiteEdition.PROFESSIONAL)
```

**Simple mock with stubbing:**
```kotlin
val api = mock<MontoyaApi>()
val logging = mock<Logging>()
whenever(api.logging()).thenReturn(logging)
```

**What to mock:**
- `MontoyaApi` and any Burp interface (`Preferences`, `Logging`, `HttpRequestResponse`, `HttpRequest`, `ParsedHttpParameter`, `AuditLogger`, `AgentSupervisor`)
- External HTTP responses (via `OkHttp MockWebServer` where needed — see `McpServerIntegrationTest`)

**What NOT to mock:**
- `AgentSettings` — use `TestSettings.baselineSettings()` or the inline builder pattern instead
- Pure-function objects (`Redaction`, `ScannerIssueSupport`, `InjectionPointExtractor`, `PayloadGenerator`) — test them directly
- `AgentSettingsRepository` internals — use `InMemoryPrefs` test double instead (see below)

## Fixtures and Factories

**`TestSettings.baselineSettings()`** — canonical `AgentSettings` fixture:
```kotlin
// src/test/kotlin/com/six2dez/burp/aiagent/TestSettings.kt
object TestSettings {
    fun baselineSettings(preferredBackendId: String = "codex-cli"): AgentSettings = AgentSettings(
        codexCmd = "codex",
        geminiCmd = "gemini",
        // ... all required fields ...
        passiveAiEnabled = false,
        activeAiEnabled = false,
        bountyPromptEnabled = false,
    )
}
```

Always use `TestSettings.baselineSettings()` in tests that need a fully-constructed `AgentSettings`. Individual test files that inline a full `AgentSettings` constructor are legacy — migrate to `TestSettings` when touching those files.

**`InMemoryPrefs` test double** — used in `AgentSettingsMigrationTest` and `SettingsDefaultsPersistenceTest`:
```kotlin
private class InMemoryPrefs {
    val strings = mutableMapOf<String, String>()
    val booleans = mutableMapOf<String, Boolean>()
    val integers = mutableMapOf<String, Int>()
    val mock: Preferences = mock<Preferences>().also { prefs ->
        whenever(prefs.getString(any())).thenAnswer { strings[it.getArgument(0)] }
        whenever(prefs.setString(any(), any())).thenAnswer { strings[...] = ...; null }
        // booleans and integers similarly
    }
}
```

## Coverage

**JaCoCo configuration (`build.gradle.kts`):**
- Every `Test` task is `finalizedBy(jacocoTestReport)`
- XML report: `build/reports/jacoco/test/jacocoTestReport.xml`
- HTML report: `build/reports/jacoco/test/html/index.html`
- Both `xml.required = true` and `html.required = true`

**CI artifact:** Coverage XML+HTML uploaded as `coverage-{sha}` on `ubuntu-latest` runs only (see `build.yml`).

**Threshold:** No minimum threshold is enforced by the build (no `jacocoTestCoverageVerification` task configured). Coverage is audited manually.

## Test Types

**Unit Tests (majority):**
- Pure functions: `RedactionTest`, `VulnClassInventoryTest`, `InjectionPointExtractorTest`, `PayloadGeneratorTest`, `ResponseAnalyzerTest`, `HashingTest`, `ToolCallParserTest`
- Settings persistence: `AgentSettingsMigrationTest`, `SettingsDefaultsPersistenceTest`, `McpSettingsTest`
- Contract lock tests: `VulnClassInventoryTest` (enum count), `BackendRegistryTest` (availability cache)

**Reflection-based unit tests:**
Used when a private method needs direct testing without refactoring for visibility:
```kotlin
// PassiveAiScannerConfidenceTest.kt
val method: Method = scanner.javaClass.getDeclaredMethod("handleFinding", ...)
method.isAccessible = true
method.invoke(scanner, ...)
```
Acceptable only for well-isolated internal logic. Prefer package-private or `internal` visibility over reflection where feasible.

**Integration Tests (heavy, nightly):**
- `McpServerIntegrationTest` — binds a real Ktor server on a free port, issues HTTP requests via `HttpURLConnection`
- `McpSupervisorRestartPolicyTest` — exercises supervisor restart with `ScriptedServerManager` fake
- `AgentSupervisorRestartPolicyTest` — concurrency + restart with real executor

**Pattern for port-binding integration tests:**
```kotlin
private fun freePort(): Int = ServerSocket(0).use { it.localPort }
val settings = McpSettings(enabled = true, host = "127.0.0.1", port = freePort(), ...)
```

## Common Patterns

**Async testing with `CountDownLatch`:**
```kotlin
val latch = CountDownLatch(1)
val result = AtomicReference<SomeType?>()
asyncOperation { value ->
    result.set(value)
    latch.countDown()
}
assertTrue(latch.await(5, TimeUnit.SECONDS))
assertEquals(expected, result.get())
```

**Concurrency stress tests:**
```kotlin
val executor = Executors.newFixedThreadPool(4)
val latch = CountDownLatch(N)
repeat(N) {
    executor.submit {
        // exercise shared state
        latch.countDown()
    }
}
assertTrue(latch.await(10, TimeUnit.SECONDS))
executor.shutdown()
```

**Error path testing:**
```kotlin
// Test that below-threshold findings are NOT recorded
val scanner = PassiveAiScanner(api = mock(), supervisor = mock(), audit = mock()) { baselineSettings() }
invokeHandleFinding(scanner, ..., confidence = 84, ...)
assertTrue(scanner.getLastFindings(10).isEmpty())
```

## Known Coverage Gaps (Next Audit Targets)

Per project roadmap, the following areas are explicitly scheduled for test coverage expansion:

**`PerplexityBackend` HTTP path:**
- `src/main/kotlin/com/six2dez/burp/aiagent/backends/perplexity/PerplexityBackendFactory.kt`
- No test covers the actual chat completions request/response flow, URL normalization logic, or `perplexityHealthCheck`

**Insertion-point integration (`AiScanCheck`):**
- `src/main/kotlin/com/six2dez/burp/aiagent/scanner/AiScanCheck.kt`
- `src/main/kotlin/com/six2dez/burp/aiagent/scanner/InjectionPointExtractor.kt` — has `InjectionPointExtractorTest` but scanner integration with `AiScanCheck` is untested
- Active scan loop (payload iteration, break-on-first-hit, rate limiting) has no test

**Custom prompt library interactions:**
- `src/test/kotlin/com/six2dez/burp/aiagent/config/CustomPromptLibraryTest.kt` exists but MCP tool invocation of custom prompts is not covered

**Backend failure → scanner fallback:**
- Passive scanner fallback from batch analysis to single-request mode when a backend fails is not directly tested

---

*Testing analysis: 2026-05-13*
