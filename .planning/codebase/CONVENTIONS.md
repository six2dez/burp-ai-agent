# Coding Conventions

**Analysis Date:** 2026-05-13

## Language Rules (Non-Negotiable)

- All code, comments, identifiers, and KDoc must be in English (AGENTS.md, line 4-5)
- Kotlin + Gradle Kotlin DSL only — no Java files in `src/`
- Target: JVM 21 (`java.toolchain.languageVersion = 21`, compiler option `JVM_21`)
- JSR-305 strict null checking: `-Xjsr305=strict` in `compilerOptions`

## Build Tooling

The Gradle wrapper is pinned to `8.12.1` (see `gradle/wrapper/gradle-wrapper.properties`), which only supports JDKs 8-23 as the launcher. Foojay toolchain auto-provisioning covers compile/test (JDK 21) but not the launcher itself, so `./gradlew` fails when the shell's default `java` is JDK ≥24 (e.g. Homebrew's `openjdk` is now 25).

Invoke gradle with JDK 21 as the launcher:

```bash
JAVA_HOME=$(/usr/libexec/java_home -v 21) ./gradlew <task>
```

Or rely on `.tool-versions` (`java temurin-21.0.10`) via mise/asdf if its shell hook is active. Claude Code's Bash sessions get `JAVA_HOME` pre-set via `.claude/settings.local.json`'s `env` block (gitignored, per-machine).

## Naming Patterns

**Files:**
- One top-level class or object per file, filename matches class name: `AgentSettings.kt`, `PassiveAiScanner.kt`
- Test files: `{SubjectClass}Test.kt` — co-located under `src/test/kotlin/` mirroring the production package

**Classes / Objects:**
- PascalCase for classes, objects, and interfaces: `BackendRegistry`, `HttpBackendSupport`, `AiBackend`
- `object` for stateless singletons / utility namespaces: `Redaction`, `ScannerIssueSupport`, `HttpBackendSupport`, `TestSettings`
- `companion object` for constants and factory members: `RedactionPolicy.fromMode()`, `HealthCheckResult.Healthy`

**Functions:**
- camelCase: `migrateIfNeeded()`, `buildCliHistory()`, `sharedClient()`
- Boolean predicates: `is` prefix — `isAlive()`, `isAvailable()`, `isWindows()`, `isRetryableConnectionError()`
- Factory functions named after return type or `create()`: `PerplexityBackendFactory.create()`, `buildClient()`

**Constants:**
- `SCREAMING_SNAKE_CASE` inside `companion object` or top-level: `CIRCUIT_FAILURE_THRESHOLD`, `CURRENT_SETTINGS_SCHEMA_VERSION`, `DEFAULT_BASE_URL`
- Numeric literals: underscore grouping for readability — `5_000`, `262_144`, `10 * 60 * 1000`

**Variables / Properties:**
- camelCase throughout: `lastUsedAt`, `availabilityLogged`, `cachedSettings`
- `@Volatile` on fields read across threads without synchronized blocks: `systemPromptEntry`, `endpointDedupMinutes`
- `AtomicBoolean` / `AtomicInteger` / `AtomicReference` / `AtomicLong` for lock-free shared state — do not use `synchronized` on primitives

## Kotlin Idioms in Use

**Data classes** — all value objects use `data class` (immutability via `val`, structural equality, free `copy()`):
- `AgentSettings` (`src/main/kotlin/com/six2dez/burp/aiagent/config/AgentSettings.kt`)
- `BackendLaunchConfig`, `ChatMessage`, `TokenUsage` (`src/main/kotlin/com/six2dez/burp/aiagent/backends/BackendTypes.kt`)
- `PassiveAiFinding`, `PassiveAiScannerStatus` (`src/main/kotlin/com/six2dez/burp/aiagent/scanner/PassiveAiScanner.kt`)
- `RedactionPolicy` (`src/main/kotlin/com/six2dez/burp/aiagent/redact/Redaction.kt`)

**Sealed classes** — use for exhaustive sum types where `when` must cover all cases:
```kotlin
// src/main/kotlin/com/six2dez/burp/aiagent/backends/BackendTypes.kt
sealed class HealthCheckResult {
    data object Healthy : HealthCheckResult()
    data class Degraded(val message: String) : HealthCheckResult()
    data class Unavailable(val message: String) : HealthCheckResult()
    data object Unknown : HealthCheckResult()
}
```
- Exhaustive `when` is enforced by the compiler — no `else` branch needed or desired.

**Enums with companion factory** — use `fromString` pattern with `ignoreCase = true` fallback:
```kotlin
enum class PrivacyMode {
    STRICT, BALANCED, OFF;
    companion object {
        fun fromString(raw: String?): PrivacyMode =
            entries.firstOrNull { it.name.equals(raw, ignoreCase = true) } ?: BALANCED
    }
}
```
All enums follow this pattern: `PrivacyMode`, `SeverityLevel`, `PayloadRisk`, `ScanMode`.

**Null safety** — ADR-1 explicitly calls this out:
- Prefer `?: ""` and `?: emptyList()` over `!!` — never use `!!` in production code
- Use `orEmpty()`, `?.trim()`, `.ifBlank { default }` chains: `prefs.getString(KEY).orEmpty().trim().ifBlank { defaultValue() }`
- Montoya API methods that return nullable: always chain safe call + Elvis

**Extension functions** — used for cohesion:
```kotlin
// AgentSettings.kt
fun AgentSettings.toPreprocessorSettings() = ResponsePreprocessorSettings(...)
```

**Coroutines** — used only in the MCP layer:
- `src/main/kotlin/com/six2dez/burp/aiagent/mcp/McpStdioBridge.kt`: `CoroutineScope(Dispatchers.IO + SupervisorJob())`, `runBlocking`
- Ktor server internals (SSE, routing) are inherently coroutine-based via `KtorMcpServerManager`
- Everywhere else concurrency is handled with `java.util.concurrent` primitives (`Executors`, `AtomicBoolean`, `ConcurrentHashMap`, `LinkedBlockingQueue`) — do NOT introduce coroutines outside the MCP package without discussion

## Code Style (ktlint)

**Plugin:** `org.jlleitschuh.gradle.ktlint` version `12.1.1`, ktlint version `1.5.0`
**Config:** `.editorconfig` (root)

Key `.editorconfig` settings:
- `charset = utf-8`
- `end_of_line = lf` (all platforms)
- `indent_style = space`, `indent_size = 4`
- `insert_final_newline = true`
- `trim_trailing_whitespace = true`
- YAML/JSON files: `indent_size = 2`

**Formatting commands:**
```bash
./gradlew ktlintCheck   # report violations (non-blocking until baseline clean)
./gradlew ktlintFormat  # auto-fix most violations
```

ktlint is currently `ignoreFailures = true` in non-strict mode (see `build.gradle.kts` line 119). Set `-PktlintStrict=true` to make it blocking. Release CI runs with failures blocking (`release.yml` runs `ktlintCheck` without `continue-on-error`).

**Trailing commas:** ktlint 1.5.0 enforces trailing commas in multi-line parameter lists — always add them:
```kotlin
SeverityLevel.LOW,  // <-- trailing comma required
```

**Suppression:** Use `@Suppress("UNCHECKED_CAST")` for reflection-heavy test helper casts only. Never suppress warnings in production code without a comment.

## Import Organization

ktlint enforces import ordering automatically. Manual rule: no wildcard imports (`import foo.bar.*`). Always use explicit imports.

**Path aliases:** none configured — use full package names.

## Backend Implementation Patterns

### HTTP Backend (subclass of `OpenAiCompatibleBackend`)
New HTTP backends implement `AiBackendFactory`, return a configured `OpenAiCompatibleBackend`, and register in the SPI file. Example — Perplexity:

```kotlin
// src/main/kotlin/com/six2dez/burp/aiagent/backends/perplexity/PerplexityBackendFactory.kt
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
            healthCheckProvider = ::perplexityHealthCheck,
        )
}
```

The shared HTTP layer lives in `src/main/kotlin/com/six2dez/burp/aiagent/backends/http/HttpBackendSupport.kt`:
- Cached `OkHttpClient` per `(baseUrl, timeout)` key via `sharedClient()`
- Built-in circuit breaker via `newCircuitBreaker()` / `CircuitBreaker`
- Retry delay table: `retryDelayMs(attempt)` returns 500ms → 4000ms steps
- Health check helpers: `healthCheckGet()` maps HTTP 401/403 to `Degraded`, other errors to `Unavailable`

### CLI Backend
`CliBackend` in `src/main/kotlin/com/six2dez/burp/aiagent/backends/cli/CliBackend.kt` handles:
- Embedded mode (`NonInteractiveCliConnection`): one shot per prompt, process spawned and killed per call
- Interactive mode (`CliConnection`): long-running process, `outputQueue` polling, PTY wrapping on Unix
- Errors reported as `IllegalStateException` with exit code and tail of stderr: `"CLI command failed (exit=1): <tail>"`
- Long prompts (> `Defaults.LARGE_PROMPT_THRESHOLD`) for claude-cli/copilot-cli written to a temp file with POSIX-restricted permissions (`OWNER_READ | OWNER_WRITE`)

**Error reporting pattern for CLI backends:** non-zero exit → `onComplete(IllegalStateException("CLI command failed (exit=${process.exitValue()}): $tail"))`. Zero exit with blank output → `onChunk("")` then `onComplete(null)` (not an error). Timeout → `destroyForcibly()` then `onComplete(IllegalStateException("CLI command timed out"))`.

### SPI Registration
Every new backend factory must be listed in:
`src/main/resources/META-INF/services/com.six2dez.burp.aiagent.backends.AiBackendFactory`

Format: one fully qualified class name per line. `mergeServiceFiles()` in `shadowJar` task merges multiple entries correctly.

## Settings Persistence (`AgentSettings`)

- `AgentSettings` is an immutable `data class` in `src/main/kotlin/com/six2dez/burp/aiagent/config/AgentSettings.kt`
- Persistence via `AgentSettingsRepository` which wraps Burp's `Preferences` API (key-value string store)
- Schema migrations: `migrateIfNeeded()` runs on every `load()` call before deserializing; current schema = **v3**
  - `CURRENT_SETTINGS_SCHEMA_VERSION = 3` (line 780 of AgentSettings.kt)
  - Migrations are additive; never remove a migration step — just add a new `else if (storedVersion < N)` block
- Thread-safe cached snapshot: `AtomicReference<AgentSettings?>` in `AgentSettingsRepository.cachedSettings`; call `invalidate()` to force re-read when another repo instance may have written newer values
- New optional fields must have default values in the `data class` constructor: `val newField: Type = Defaults.VALUE`

## Error Handling

**Strategy:** fail loudly to the caller via exceptions; never swallow silently without at least a log.

**Patterns:**
- `IllegalStateException` for logical precondition failures: `"CLI executable not found for $backendId"`, `"Backend connection has been stopped"`
- `require(condition) { message }` for parameter validation at entry points: `require(config.command.isNotEmpty()) { ... }`
- `try/catch(e: Exception)` at process and network boundaries; log with `api.logging().logToError("[Component] ${e.message}")`
- Suppressed exceptions from cleanup code: `catch (_: Exception) {}` (anonymous `_`) is intentional and accepted for `destroy()` / `close()` calls in `finally` blocks
- Scanner failure isolation: `AiScanCheck` wraps each payload test in `try/catch`, logs to `api.logging().logToError`, and continues to the next payload — does not fail the entire scan

**Logging:**
- Use Burp's logging API: `api.logging().logToError(...)` and `api.logging().logToOutput(...)`
- `BackendDiagnostics.log(...)` for backend-specific diagnostic messages
- SLF4J (`slf4j-simple`) is bundled but only used by Ktor/MCP internals; do not use it in extension code

## Swing UI Patterns (ADR-2)

UI components are thin shells over pure-Kotlin logic. All Swing mutations go through `SwingUtilities.invokeLater { ... }` when called from a non-EDT thread (background worker threads in `ChatPanel`, `AiLoggerPanel`).

**Reusable helpers in `src/main/kotlin/com/six2dez/burp/aiagent/ui/components/`:**
- `ToggleSwitch` — animated `JToggleButton` replacement (44×22 track, 18px thumb, 150ms transition). Usage: `ToggleSwitch(initialState)` then `toggle.isSelected` / `toggle.addActionListener { ... }`
- `AccordionPanel(title, subtitle, content, initiallyExpanded)` — collapsible card with header and content `JComponent`
- `ActionCard(actionName, source, target, privacySummary, payloadPreview, initiallyExpanded)` — expandable read-only prompt preview card used in `ChatPanel`
- `ContextPreviewDialog.confirm(...)` — modal dialog shown before sending captured traffic to an AI; blocks until user confirms or cancels

**Rule:** all new UI panels MUST use `UiTheme.Colors.*` and `UiTheme.Typography.*` constants (defined in `src/main/kotlin/com/six2dez/burp/aiagent/ui/UiTheme.kt`) for colors and fonts. Do not hardcode `Color(...)` or `Font(...)` inline.

## Comments

**When to comment:**
- KDoc (`/** ... */`) on public API classes and methods only
- Inline comments for non-obvious logic, concurrency contracts (`// Thread-safe: ...`), and intentional suppressions
- Example of meaningful inline comment: `// Opportunistic eviction of stale clients` in `HttpBackendSupport.sharedClient()`
- No commented-out code in commits; use a TODO with issue reference instead

**No temporal language:** comments describe current behavior, not history or intentions without action.

---

*Convention analysis: 2026-05-13*
