# Phase 18: Quality Tooling & Build Hardening - Pattern Map

**Mapped:** 2026-06-11
**Files analyzed:** 9 (new/modified)
**Analogs found:** 7 / 9

---

## File Classification

| New/Modified File | Role | Data Flow | Closest Analog | Match Quality |
|---|---|---|---|---|
| `build.gradle.kts` | config | batch (build) | `build.gradle.kts` itself (lines 90-113, 166-182) | exact (self-analog) |
| `detekt.yml` | config | batch (build) | none in-repo | no analog |
| `detekt-baseline.xml` | config | batch (build) | none in-repo (generated artifact) | no analog |
| `src/test/.../cache/PersistentPromptCacheTest.kt` | test | file-I/O | `CliBackendTempFileTest.kt` (temp-dir seam pattern) | role-match |
| `src/test/.../scanner/ActiveScannerDedupTest.kt` | test | CRUD | `ActiveScannerQueueModelTest.kt` | exact |
| `src/test/.../backends/cli/CliSupervisionTest.kt` | test | event-driven | `AgentSupervisorRestartPolicyTest.kt` + `CliTimeoutMessageTest.kt` | role-match |
| Logging helper (SC5) | utility | request-response | `BackendDiagnostics.kt` (object + logError) | exact |
| `.github/workflows/build.yml` | config | batch (CI) | `build.yml` itself (lines 21-23) | exact (self-analog) |
| `.planning/notes/exception-audit.md` | docs | n/a | none | no analog |

---

## Pattern Assignments

### `build.gradle.kts` (config, build system)

**Analog:** `build.gradle.kts` itself — the four active change sites are SC1 (lines 97-113), SC2 (plugin block + detekt config), SC3 (lines 171-173), and the CI-workflow companion change.

**SC1 — Structural srcDir wiring fix (lines 90-113):**

Current broken wiring (lines 97-99 and 111-113 — REMOVE both blocks):
```kotlin
// REMOVE: plain Provider<Directory> — no task-origin metadata, Gradle cannot infer dependency
sourceSets.main {
    kotlin.srcDir(generatedSrcDir)       // generatedSrcDir = layout.buildDirectory.dir(...)
}

// REMOVE: fragile name-match hack (lines 111-113)
tasks.matching { it.name.startsWith("runKtlint") }.configureEach {
    dependsOn(generateBuildFlags)
}
```

Replacement (structural wiring — ADD in place of the two removed blocks above):
```kotlin
// ADD: pass the task's own outputDir through the TaskProvider
// Gradle registers generateBuildFlags as the structural producer; dependency is inferred automatically.
sourceSets.main {
    kotlin.srcDir(generateBuildFlags.flatMap { it.outputDir })
}
// The tasks.withType<KotlinCompile> { dependsOn(generateBuildFlags) } block at lines 101-107 stays untouched.
```

Fallback (if flatMap form does not register the inferred dependency in Gradle 8.12.1):
```kotlin
sourceSets.main {
    kotlin.srcDir(
        project.files(generateBuildFlags.flatMap { it.outputDir }).builtBy(generateBuildFlags)
    )
}
```

**SC2 — detekt plugin block (add to `plugins {}` block, lines 4-11):**
```kotlin
plugins {
    kotlin("jvm") version "2.1.21"
    // ... existing plugins unchanged ...
    id("io.gitlab.arturbosch.detekt") version "1.23.8"    // ADD
}
```

**SC2 — detekt configuration block (add after the `ktlint {}` block at line 166):**
```kotlin
detekt {
    buildUponDefaultConfig = true           // extend defaults, not replace
    allRules = false                         // only default ruleset rules
    baseline = file("detekt-baseline.xml")  // committed baseline; generate with: ./gradlew detektBaseline
    parallel = true
    config.setFrom(files("detekt.yml"))     // optional custom overrides
}
```

Note: detekt 1.23.8 auto-wires `detekt` as a dependency of `check`. No explicit `tasks.check.dependsOn(tasks.detekt)` is needed.

**SC3 — ktlint strict flip (line 171-173, REPLACE the existing `ignoreFailures.set(...)` call):**

Current (lenient by default, lines 171-173):
```kotlin
ignoreFailures.set(
    (project.findProperty("ktlintStrict") as? String)?.equals("true", ignoreCase = true) != true,
)
```

Replacement (strict by default — escape hatch via `-PktlintLenient=true`):
```kotlin
ignoreFailures.set(
    (project.findProperty("ktlintLenient") as? String)?.equals("true", ignoreCase = true) == true,
)
```

The `filter { exclude("**/build/**"); exclude("**/generated/**") }` block at lines 178-181 stays in place — it already protects `BuildFlags.kt`.

---

### `detekt.yml` (config, no in-repo analog)

No analog exists. Use the RESEARCH.md minimal config as the template:

```yaml
# detekt.yml — project-specific overrides on top of detekt defaults
complexity:
  LongMethod:
    threshold: 80      # PassiveAiScanner/McpTools have long methods by design
  LongParameterList:
    threshold: 10      # AgentSettings constructor has many fields
naming:
  FunctionNaming:
    excludes: [ '**/test/**' ]
```

Commit this file before running `./gradlew detektBaseline`.

---

### `detekt-baseline.xml` (generated artifact, no in-repo analog)

Generate with:
```bash
./gradlew detektBaseline
git add detekt-baseline.xml
git commit -m "chore(sc2): generate detekt baseline capturing pre-existing violations"
```

The file is placed in the project root (not in `build/`). It must be committed before the detekt blocking gate goes live in CI.

---

### `src/test/kotlin/com/six2dez/burp/aiagent/cache/PersistentPromptCacheTest.kt` (test, file-I/O)

**Analog:** `src/test/kotlin/com/six2dez/burp/aiagent/backends/cli/CliBackendTempFileTest.kt`

The closest match is `CliBackendTempFileTest` because it exercises a real filesystem seam using a temp directory, uses no Montoya mocks (the class-under-test has no Burp API dependency), and cleans up in `finally` / `@AfterEach`.

**Source under test:** `src/main/kotlin/com/six2dez/burp/aiagent/cache/PersistentPromptCache.kt`

Real constructor signature (lines 24-28):
```kotlin
class PersistentPromptCache(
    private val cacheDir: File = File(System.getProperty("user.home"), ".burp-ai-agent/cache"),
    val maxDiskBytes: Long = DEFAULT_MAX_DISK_BYTES,    // default: 50 MB
    val ttlMs: Long = DEFAULT_TTL_MS,                    // default: 24 hours in ms
)
```

Public API to exercise (from PersistentPromptCache.kt):
- `get(promptHash: String): CachedEntry?` — returns null if TTL expired or file corrupt
- `put(promptHash: String, entry: CachedEntry)` — writes JSON to `cacheDir/<hash>.json`; silently swallows disk errors
- `clear()` — deletes all `.json` files in cacheDir
- `diskSizeBytes(): Long` — sum of all `.json` file sizes under read lock
- `entryCount(): Int` — count of `.json` files

Data classes needed in tests (declared at top of PersistentPromptCache.kt, same package):
```kotlin
data class CachedEntry(val createdAtMs: Long, val issues: List<CachedIssue>)
data class CachedIssue(
    val reasoning: String? = null,
    val title: String? = null,
    val severity: String? = null,
    val detail: String? = null,
    val confidence: Int? = null,
    val requestIndex: Int? = null,
)
```

**Imports pattern** (mirror CliBackendTempFileTest lines 1-8, adapt for cache):
```kotlin
package com.six2dez.burp.aiagent.cache

import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import java.io.File
import java.nio.file.Files
```

**Setup/teardown seam pattern** (from CliBackendTempFileTest + RESEARCH.md pitfall 6):
```kotlin
class PersistentPromptCacheTest {
    private lateinit var tmpDir: File

    @BeforeEach
    fun setUp() {
        // Always use a temp directory — never the production ~/.burp-ai-agent/cache/
        tmpDir = Files.createTempDirectory("cache-test").toFile()
    }

    @AfterEach
    fun tearDown() {
        tmpDir.deleteRecursively()
    }
}
```

**Core test pattern — three critical paths to cover:**

1. Put/get round-trip (basic correctness):
```kotlin
@Test
fun putAndGetRoundTrip() {
    val cache = PersistentPromptCache(cacheDir = tmpDir)
    val entry = CachedEntry(System.currentTimeMillis(), listOf(CachedIssue(title = "SQLI", severity = "HIGH")))
    cache.put("abc123", entry)
    val retrieved = cache.get("abc123")
    assertNotNull(retrieved)
    assertEquals("SQLI", retrieved!!.issues.first().title)
}
```

2. TTL eviction (get returns null for expired entry):
```kotlin
@Test
fun getReturnsNullForExpiredEntry() {
    val cache = PersistentPromptCache(cacheDir = tmpDir, ttlMs = 1L)
    val entry = CachedEntry(System.currentTimeMillis() - 1000L, listOf())
    cache.put("hash1", entry)
    Thread.sleep(5)
    assertNull(cache.get("hash1"))
}
```

3. Disk-size eviction (evictsOldestFilesWhenLimitExceeded):
```kotlin
@Test
fun evictsOldestWhenDiskLimitExceeded() {
    // maxDiskBytes = 200 forces eviction after a few entries
    val cache = PersistentPromptCache(cacheDir = tmpDir, maxDiskBytes = 200L)
    repeat(20) { i ->
        cache.put("hash$i", CachedEntry(System.currentTimeMillis(), listOf(CachedIssue(title = "T$i"))))
    }
    assertTrue(cache.diskSizeBytes() <= 200L, "disk size must be within the limit after eviction")
}
```

Note on SC5 / pitfall 5: `PersistentPromptCache.put()` silently swallows disk write errors (line 63: `catch (_: Exception) { // Silently fail on disk write errors }`). This is intentional. The SC5 audit should annotate it `// INTENTIONAL:` — do NOT add a log call here.

---

### `src/test/kotlin/com/six2dez/burp/aiagent/scanner/ActiveScannerDedupTest.kt` (test, CRUD)

**Analog:** `src/test/kotlin/com/six2dez/burp/aiagent/scanner/ActiveScannerQueueModelTest.kt`

This is an exact-role match. `ActiveScannerDedupTest` adds coverage of `queueTarget()`'s `processedTargets` dedup path, which `ActiveScannerQueueModelTest` leaves uncovered (that file only exercises `manualScan` / `manualScanInsertionPoint` which bypass dedup).

**Source under test:** `src/main/kotlin/com/six2dez/burp/aiagent/scanner/ActiveAiScanner.kt`

Dedup logic (lines 137-145):
```kotlin
val existing = processedTargets.putIfAbsent(target.id, now)
if (existing != null && (now - existing) < Defaults.DEDUP_WINDOW_MS) {   // DEDUP_WINDOW_MS = 3_600_000L
    return
}
if (existing != null) {
    processedTargets[target.id] = now   // expired — update timestamp
}
```

`target.id` is computed by `ActiveScanTarget` (ActiveScanModels.kt:300):
```kotlin
val id: String = "${originalRequest.request().url()}_${injectionPoint.name}_${vulnHint.vulnClass}"
```

**Imports pattern** (copy exactly from ActiveScannerQueueModelTest.kt lines 1-22):
```kotlin
package com.six2dez.burp.aiagent.scanner

import burp.api.montoya.MontoyaApi
import burp.api.montoya.http.message.HttpRequestResponse
import burp.api.montoya.http.message.params.HttpParameterType
import burp.api.montoya.http.message.params.ParsedHttpParameter
import burp.api.montoya.http.message.requests.HttpRequest
import com.six2dez.burp.aiagent.audit.AuditLogger
import com.six2dez.burp.aiagent.supervisor.AgentSupervisor
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.mockito.Answers
import org.mockito.kotlin.any
import org.mockito.kotlin.mock
import org.mockito.kotlin.whenever
```

**Scanner factory pattern** (copy `newScannerForQueueTests()` from ActiveScannerQueueModelTest.kt lines 163-175 — use `TestSettings.baselineSettings()` from `ScannerQueueBackpressureTest` instead of the inline `baselineSettings()` to avoid duplicating the large settings block):
```kotlin
private fun newScanner(): ActiveAiScanner {
    val api = mock<MontoyaApi>(defaultAnswer = Answers.RETURNS_DEEP_STUBS)
    return ActiveAiScanner(
        api = api,
        supervisor = mock<AgentSupervisor>(),
        audit = mock<AuditLogger>(),
        getSettings = { TestSettings.baselineSettings() },
    ).apply {
        scopeOnly = false
        maxQueueSize = 64
        scanMode = ScanMode.FULL
    }
}
```

**requestResponse helper** (copy verbatim from ActiveScannerQueueModelTest.kt lines 177-196):
```kotlin
private fun requestResponse(url: String, name: String, value: String): HttpRequestResponse {
    val param = mock<ParsedHttpParameter>()
    whenever(param.type()).thenReturn(HttpParameterType.URL)
    whenever(param.name()).thenReturn(name)
    whenever(param.value()).thenReturn(value)
    val request = mock<HttpRequest>()
    whenever(request.url()).thenReturn(url)
    whenever(request.parameters()).thenReturn(listOf(param))
    whenever(request.headers()).thenReturn(emptyList())
    whenever(request.headerValue("Content-Type")).thenReturn(null)
    whenever(request.bodyToString()).thenReturn("")
    val rr = mock<HttpRequestResponse>()
    whenever(rr.request()).thenReturn(request)
    return rr
}
```

**Core dedup test pattern — the critical path to cover:**

`queueTarget()` uses `processedTargets.putIfAbsent` keyed on `target.id`. To test dedup, call `queueTarget()` twice with the same target id and assert the second call does not grow the queue beyond 1. To call `queueTarget()` you must `setEnabled(true)` first (line 95-102 of ActiveAiScanner.kt: `enabled.set(value)`; without `enabled == true`, `queueTarget()` returns immediately at line 128).

```kotlin
@Test
fun queueTargetDedupPreventsRequeueWithinWindow() {
    val scanner = newScanner()
    scanner.setEnabled(true)
    val rr = requestResponse("http://example.com/?id=1", "id", "1")
    val point = InjectionPoint(InjectionType.URL_PARAM, "id", "1")
    val target = ActiveScanTarget(
        originalRequest = rr,
        injectionPoint = point,
        vulnHint = VulnHint(VulnClass.SQLI, 50, "test"),
        priority = 50,
    )
    // First enqueue
    scanner.queueTarget(target)
    val after1 = scanner.getQueueItems(limit = 10).size
    // Second enqueue — same target.id, within the dedup window
    scanner.queueTarget(target)
    val after2 = scanner.getQueueItems(limit = 10).size
    assertEquals(after1, after2, "dedup must prevent re-queuing the same target within DEDUP_WINDOW_MS")
    assertTrue(after1 <= 1)
}

@Test
fun queueTargetAllowsRequeueAfterWindowExpires() {
    val scanner = newScanner()
    scanner.setEnabled(true)
    val rr = requestResponse("http://example.com/?id=2", "id", "2")
    val point = InjectionPoint(InjectionType.URL_PARAM, "id", "2")
    val target = ActiveScanTarget(
        originalRequest = rr,
        injectionPoint = point,
        vulnHint = VulnHint(VulnClass.SQLI, 50, "test"),
        priority = 50,
    )
    scanner.queueTarget(target)
    // Manually expire the processedTargets entry via resetStats() — which calls processedTargets.clear()
    scanner.resetStats()
    scanner.queueTarget(target)
    assertTrue(scanner.getQueueItems(limit = 10).size >= 1, "re-queue must succeed after dedup window cleared")
}
```

Note: `ActiveScanTarget` has the `id` field as a computed `val` at `ActiveScanModels.kt:300`. Do NOT pass `id` as a constructor argument unless you need to override it; rely on the default computation.

---

### `src/test/kotlin/com/six2dez/burp/aiagent/backends/cli/CliSupervisionTest.kt` (test, event-driven)

**Primary analog:** `AgentSupervisorRestartPolicyTest.kt` (for AgentSupervisor seam + reflection pattern)
**Secondary analog:** `CliTimeoutMessageTest.kt` (for direct `internal fun` call pattern without reflection)

The supervision timeout path lives in `NonInteractiveCliConnection.send()` (CliBackend.kt lines 241-252):
```kotlin
if (!process.waitFor(cliTimeoutSeconds.toLong(), TimeUnit.SECONDS)) {
    process.destroyForcibly()
    readerThread.join(2000)
    val tail = rawOutput.toString().trim().take(2000)
    onComplete(IllegalStateException(buildTimeoutMessage(tail, cliTimeoutSeconds)))
    return@submit
}
```

`NonInteractiveCliConnection` is a `private class` inside `CliBackend`. It is NOT accessible from tests without reflection. The RESEARCH.md points to testing `AgentSupervisor` or `NonInteractiveCliConnection` — since `NonInteractiveCliConnection` is private, the recommended approach is:

1. Test `buildTimeoutMessage()` (already done in `CliTimeoutMessageTest`). That file is the direct analog.
2. For CliSupervisionTest, cover the `CliBackend.launch()` path (public) and the timeout propagation at the supervision level via `AgentSupervisorRestartPolicyTest`'s pattern of using a `FailingBackend` + reflection.

**Imports pattern** (from AgentSupervisorRestartPolicyTest.kt lines 1-21):
```kotlin
package com.six2dez.burp.aiagent.backends.cli

import com.six2dez.burp.aiagent.backends.AgentConnection
import com.six2dez.burp.aiagent.backends.BackendLaunchConfig
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
```

**Core pattern — test NonInteractiveCliConnection timeout via its public AgentConnection interface:**

`CliBackend.launch()` with `embeddedMode = true` returns a `NonInteractiveCliConnection` cast to `AgentConnection`. Call `send()` with a command that will time out, then assert the `onComplete` callback receives an `IllegalStateException` whose message contains "timed out":

```kotlin
@Test
fun sendTimesOutAndReportsViaOnComplete() {
    val backend = CliBackend("codex-cli", "Codex CLI")
    val config = BackendLaunchConfig(
        command = listOf("sleep", "60"),   // will be killed by the timeout
        env = emptyMap(),
        embeddedMode = true,
        cliTimeoutSeconds = 1,             // 1-second timeout so test runs fast
        cliSessionId = null,
    )
    val connection = backend.launch(config)
    var completionError: Throwable? = null
    val latch = java.util.concurrent.CountDownLatch(1)
    connection.send(
        text = "test",
        history = null,
        onChunk = {},
        onComplete = { err ->
            completionError = err
            latch.countDown()
        },
    )
    assertTrue(latch.await(5, java.util.concurrent.TimeUnit.SECONDS), "send must complete within 5s")
    assertNotNull(completionError, "onComplete must receive an error on timeout")
    assertTrue(
        completionError!!.message?.contains("timed out", ignoreCase = true) == true,
        "error message must mention timeout: ${completionError!!.message}",
    )
    connection.stop()
}
```

Note on platform safety: `sleep 60` works on Linux/macOS. On Windows CI the command is `timeout /t 60`. Guard with:
```kotlin
val sleepCmd = if (System.getProperty("os.name").lowercase().contains("win")) {
    listOf("cmd", "/c", "timeout", "/t", "60")
} else {
    listOf("sleep", "60")
}
```

**BackendLaunchConfig constructor** — verify the field names from the class. The key fields for this test:
- `command: List<String>` — argv to execute
- `env: Map<String, String>` — environment variables
- `embeddedMode: Boolean` — true routes to NonInteractiveCliConnection
- `cliTimeoutSeconds: Int?` — the timeout value under test (coerced to 30-3600 in CliBackend.kt line 38)

---

### Logging helper for SC5 exception audit (utility, request-response)

**Analog:** `src/main/kotlin/com/six2dez/burp/aiagent/backends/BackendDiagnostics.kt`

`BackendDiagnostics` is the existing shared logging facility for non-Montoya contexts (cache, config, backends). Full source (lines 1-57):

```kotlin
object BackendDiagnostics {
    @Volatile var output: ((String) -> Unit)? = null
    @Volatile var error: ((String) -> Unit)? = null
    @Volatile var retry: ((RetryEvent) -> Unit)? = null

    fun log(message: String) {
        try { output?.invoke(message) } catch (_: Exception) { System.err.println(message) }
        if (output == null) System.err.println(message)
    }

    fun logError(message: String) {
        try { error?.invoke(message) } catch (_: Exception) { System.err.println(message) }
        if (error == null) System.err.println(message)
    }
}
```

The two call conventions in production code:

1. Modules with `MontoyaApi` reference (scanner, ui, supervisor):
```kotlin
api.logging().logToError("[ModuleName] operation failed: ${e.message}")
api.logging().logToOutput("[ModuleName] info: ${e.message}")
```

2. Modules without `MontoyaApi` (cache, config, backends/cli, util):
```kotlin
BackendDiagnostics.logError("[ModuleName] operation failed: ${e.message}")
BackendDiagnostics.log("[ModuleName] info: ${e.message}")
```

The RESEARCH.md recommends a shared Kotlin extension function as the SC5 helper. The closest existing pattern is just calling `BackendDiagnostics.logError()` directly — no new wrapper class is needed. If a helper extension is desired, model it on the `BackendDiagnostics.log()` delegation pattern:

```kotlin
// Candidate extension (new file: src/main/kotlin/com/six2dez/burp/aiagent/util/ExceptionLogging.kt)
// Only create if multiple modules benefit from the same signature; otherwise use inline calls.
package com.six2dez.burp.aiagent.util

import com.six2dez.burp.aiagent.backends.BackendDiagnostics

fun logCaughtException(module: String, context: String, e: Exception) {
    BackendDiagnostics.logError("[$module] $context: ${e.message}")
}
```

For the SC5 audit: the annotation convention for intentional swallows mirrors the existing cache module comment at PersistentPromptCache.kt line 64:
```kotlin
// Current (implicit intent):
} catch (_: Exception) {
    // Silently fail on disk write errors
}

// SC5 target annotation (make the intent explicit):
} catch (_: Exception) {
    // INTENTIONAL: cache write failures are best-effort; must not crash scanner pipeline
}
```

---

### `.github/workflows/build.yml` (config, CI)

**Analog:** `build.yml` itself — the two active change sites.

**SC2 — Add detekt step to `lint` job (add after line 23):**
```yaml
- name: detekt (blocking)
  run: ./gradlew detekt --no-daemon
```

**SC3 — Remove `continue-on-error` from ktlintCheck step (lines 21-23):**

Current:
```yaml
- name: ktlint check (non-blocking until baseline is clean)
  run: ./gradlew ktlintCheck --no-daemon
  continue-on-error: true
```

After SC3 gate-flip commit:
```yaml
- name: ktlint check
  run: ./gradlew ktlintCheck --no-daemon
```

Important: the `continue-on-error: true` removal is the SECOND commit in the SC3 sequence. Commit A (`ktlintFormat` mass-format) must precede commit B (gate flip + this CI change) in git history.

---

### `.planning/notes/exception-audit.md` (docs, no code analog)

No code pattern. This is a Markdown tracking document. Content shape (from RESEARCH.md):

- Header: audit date, scope (183 sites, 52 files), method
- Table columns: file, line, catch type, current behavior, classification (INTENTIONAL / NEEDS-LOG / ALREADY-LOGGED), disposition
- Sections: audited modules (cache, scanner, supervisor, cli — ~30-50 sites), remaining sites with `// TODO-AUDIT:` marker count

---

## Shared Patterns

### Deep-stub Montoya mock (all scanner tests)

**Source:** `ActiveScannerQueueModelTest.kt` lines 164-165, `AgentSupervisorRestartPolicyTest.kt` lines 26-27

```kotlin
val api = mock<MontoyaApi>(defaultAnswer = Answers.RETURNS_DEEP_STUBS)
```

Apply to: `ActiveScannerDedupTest.kt` — needed because `queueTarget()` calls `api.scope().isInScope()` (line 133) and `api.logging().logToOutput()` (line 157). Deep stubs return a mock for every chained call without extra `whenever()` setup.

When scope filtering is under test, override the specific stub:
```kotlin
whenever(api.scope().isInScope(any<String>())).thenReturn(true)  // in-scope path
whenever(api.scope().isInScope(any<String>())).thenReturn(false) // out-of-scope path
```

### TestSettings.baselineSettings() shared fixture

**Source:** `src/test/kotlin/com/six2dez/burp/aiagent/TestSettings.kt`

All scanner tests that need `AgentSettings` should use `TestSettings.baselineSettings()` rather than an inline copy. The `ScannerQueueBackpressureTest` already does this (line 26); `ActiveScannerQueueModelTest` duplicates the block instead. New tests must use `TestSettings`.

```kotlin
import com.six2dez.burp.aiagent.TestSettings
// ...
getSettings = { TestSettings.baselineSettings() }
```

### Reflection for private-field access (supervisor tests)

**Source:** `AgentSupervisorRestartPolicyTest.kt` lines 70-93

Pattern for accessing private fields when testing supervisor internals:
```kotlin
private fun someField(supervisor: AgentSupervisor): AtomicReference<String?> {
    val field = supervisor.javaClass.getDeclaredField("fieldName")
    field.isAccessible = true
    @Suppress("UNCHECKED_CAST")
    return field.get(supervisor) as AtomicReference<String?>
}
```

Apply to: `CliSupervisionTest.kt` if testing `NonInteractiveCliConnection` internals via the supervisor state. Prefer the public `AgentConnection.send()` interface over reflection where possible.

### Exception swallow comment convention (SC5)

Two forms, depending on context:

1. Intentional swallow (no log needed):
```kotlin
} catch (_: Exception) {
    // INTENTIONAL: <reason why swallowing is correct>
}
```

2. Operational failure that should surface:
```kotlin
} catch (e: Exception) {
    api.logging().logToError("[ModuleName] <context>: ${e.message}")
}
// or for non-Montoya modules:
} catch (e: Exception) {
    BackendDiagnostics.logError("[ModuleName] <context>: ${e.message}")
}
```

Convention: never interpolate request body, API key, or bearer token in log messages — only `e.message` and structural context (module name, operation name) are safe.

---

## No Analog Found

| File | Role | Data Flow | Reason |
|---|---|---|---|
| `detekt.yml` | config | build | No detekt config exists in-repo; use RESEARCH.md minimal template |
| `detekt-baseline.xml` | generated artifact | build | Generated by `./gradlew detektBaseline`; no hand-authored template |
| `.planning/notes/exception-audit.md` | docs | n/a | First exception-audit tracking document in this project |

---

## Metadata

**Analog search scope:** `src/test/kotlin/`, `src/main/kotlin/`, `build.gradle.kts`, `.github/workflows/`
**Files scanned:** 12 (build.gradle.kts, PersistentPromptCache.kt, ActiveAiScanner.kt, AgentSupervisor.kt, CliBackend.kt, BackendDiagnostics.kt, CliBackendTempFileTest.kt, CliTimeoutMessageTest.kt, CopilotCommandBuilderTest.kt, ActiveScannerQueueModelTest.kt, ScannerQueueBackpressureTest.kt, AgentSupervisorRestartPolicyTest.kt, TestSettings.kt, build.yml)
**Pattern extraction date:** 2026-06-11
