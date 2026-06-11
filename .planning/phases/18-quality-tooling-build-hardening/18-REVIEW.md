---
phase: 18-quality-tooling-build-hardening
reviewed: 2026-06-11T00:00:00Z
depth: standard
files_reviewed: 11
files_reviewed_list:
  - build.gradle.kts
  - detekt.yml
  - .github/workflows/build.yml
  - src/main/kotlin/com/six2dez/burp/aiagent/cache/PersistentPromptCache.kt
  - src/main/kotlin/com/six2dez/burp/aiagent/scanner/ActiveAiScanner.kt
  - src/main/kotlin/com/six2dez/burp/aiagent/supervisor/AgentSupervisor.kt
  - src/main/kotlin/com/six2dez/burp/aiagent/supervisor/ChatSessionManager.kt
  - src/main/kotlin/com/six2dez/burp/aiagent/backends/cli/CliBackend.kt
  - src/test/kotlin/com/six2dez/burp/aiagent/cache/PersistentPromptCacheTest.kt
  - src/test/kotlin/com/six2dez/burp/aiagent/scanner/ActiveScannerDedupTest.kt
  - src/test/kotlin/com/six2dez/burp/aiagent/backends/cli/CliSupervisionTest.kt
findings:
  critical: 2
  warning: 4
  info: 2
  total: 8
status: issues_found
---

# Phase 18: Code Review Report

**Reviewed:** 2026-06-11
**Depth:** standard
**Files Reviewed:** 11
**Status:** issues_found

## Summary

This phase introduced quality tooling (detekt 1.23.8, ktlint strict gate) and build hardening
(`generateBuildFlags` lazy provider wiring). Five source files received exception-site
`// INTENTIONAL:` annotations and five edited source files gained or cleaned up logging calls.
Three new test files provide coverage for the cache, dedup, and CLI supervision paths.

The build infrastructure changes are structurally correct: the lazy provider wiring is sound,
the ktlint boolean-inversion logic is correct, and the detekt baseline is committed. The CI
workflow action versions are all valid (checkout@v6, setup-java@v5, etc.).

Two critical findings require fixes before shipping: (1) the `BackendLaunchConfig` data class is
interpolated into a `logToOutput()` call and an `audit.logEvent()` call with its full `headers`
map in scope — this leaks API keys and bearer tokens into the Burp output tab and the audit
JSONL file, and (2) the `agent_chunk` audit log event writes verbatim AI response chunks
unconditionally (not guarded by `audit.isEnabled()`), meaning every AI response token is
flushed to disk even when the user has not opted into verbose auditing.

---

## Critical Issues

### CR-01: API Keys and Bearer Tokens Leaked via BackendLaunchConfig.toString()

**File:** `src/main/kotlin/com/six2dez/burp/aiagent/supervisor/AgentSupervisor.kt:203`
**Issue:** `api.logging().logToOutput("Launching backend $backendId with config: $launchConfig")`
interpolates the full `BackendLaunchConfig` data class, whose generated `toString()` includes
the `headers` map. For Anthropic the map contains `"x-api-key" -> <actual_key>` (line 872). For
all HTTP backends (Ollama, LM Studio, OpenAI-compatible, NVIDIA NIM, Perplexity) the map
contains `"authorization" -> "Bearer <token>"` (built by `HeaderParser.withBearerToken`). The
output tab in Burp is visible to any user of the Burp instance and its content may be captured
in screen-shares, bug reports, or log files. Additionally, line 219 sends the same object to
`audit.logEvent("session_start", ..., "config" to launchConfig)`, writing all headers to
`~/.burp-ai-agent/audit.jsonl` in plaintext.

This is a **privacy and security violation** directly against the project's core constraint
("privacy controls ... are non-negotiable"). API keys must never appear in log output.

**Fix:**
```kotlin
// Option A — redact headers before logging (preferred, avoids data class surgery)
private fun redactedConfigSummary(config: BackendLaunchConfig): String =
    "BackendLaunchConfig(backendId=${config.backendId}, model=${config.model}, " +
    "baseUrl=${config.baseUrl}, embeddedMode=${config.embeddedMode}, " +
    "headers=[${config.headers.keys.joinToString()}])"  // keys only, no values

// Line 203 becomes:
api.logging().logToOutput("Launching backend $backendId with config: ${redactedConfigSummary(launchConfig)}")

// Line 219 becomes (pass only safe fields):
audit.logEvent("session_start", mapOf(
    "backendId" to backendId,
    "sessionId" to sessionId,
    "model" to launchConfig.model,
    "displayName" to launchConfig.displayName,
))
```

---

### CR-02: agent_chunk Audit Event Fires Outside the audit.isEnabled() Guard

**File:** `src/main/kotlin/com/six2dez/burp/aiagent/supervisor/AgentSupervisor.kt:363-366` and `513-516`
**Issue:** The `onChunk` callback is registered inside `current.connection.send(...)`, which is
**outside** both `if (audit.isEnabled())` blocks (lines 325 and 472). As a result,
`audit.logEvent("agent_chunk", mapOf("backendId" to backendId, "chunk" to chunk))` is called for
every streaming token from the AI backend regardless of whether the user has enabled auditing.
`AuditLogger.logEvent()` itself checks `if (!enabled) return` (line 58 of AuditLogger.kt), so
the log entry is silently discarded when audit is off — but the call still allocates a map and
calls `mapper.writeValueAsString()` on every chunk (hot path). More critically, the design
violates the project's stated audit default ("disabled by default, opt-in verbose mode") because
the chunk content (AI response tokens) is wired through audit infrastructure that runs regardless
of the enabled flag at call-site construction time. A future change that adds pre-processing in
`onChunk` before the `if (!enabled)` check in `logEvent` would silently log response content.

**Fix:** Move the `audit.logEvent("agent_chunk", ...)` call inside an explicit enabled check:
```kotlin
onChunk = { chunk ->
    responseAccumulator.append(chunk)
    if (audit.isEnabled()) {
        audit.logEvent("agent_chunk", mapOf("backendId" to backendId, "chunk" to chunk))
    }
    onChunk(chunk)
},
```
Apply identically at line 513-516 in `sendChat()`.

---

## Warnings

### WR-01: file.delete() Called Under Read Lock in PersistentPromptCache.get()

**File:** `src/main/kotlin/com/six2dez/burp/aiagent/cache/PersistentPromptCache.kt:43-49`
**Issue:** When a cache entry is expired or corrupt, `file.delete()` is called while holding
only the `readLock`. A `ReentrantReadWriteLock` allows multiple concurrent readers, so two
threads can simultaneously enter `get()` for the same expired file, both observe `age > ttlMs`,
and both call `file.delete()`. The second delete silently returns `false`. More structurally,
mutating filesystem state (deletion) inside a read lock is semantically incorrect: the read lock
is supposed to guarantee no mutations occur, making concurrent readers unsafe to reason about.
A write lock should be acquired before deletion.

**Fix:** Upgrade to a write lock before deleting the file:
```kotlin
fun get(promptHash: String): CachedEntry? {
    val file = fileFor(promptHash)
    // Read phase — shared lock is fine for deserialisation
    val entry = lock.read {
        try {
            mapper.readValue(file, CachedEntry::class.java)
        } catch (_: Exception) {
            null
        }
    } ?: run {
        // Corrupt file: delete under write lock
        lock.write { if (file.exists()) file.delete() }
        return null
    }
    val age = System.currentTimeMillis() - entry.createdAtMs
    if (age > ttlMs) {
        lock.write { file.delete() }
        return null
    }
    return entry
}
```

---

### WR-02: Vacuous Eviction Assertion in PersistentPromptCacheTest Is Fragile

**File:** `src/test/kotlin/com/six2dez/burp/aiagent/cache/PersistentPromptCacheTest.kt:65-78`
**Issue:** `evictsOldestWhenDiskLimitExceeded()` asserts `cache.diskSizeBytes() <= 200L` after
writing 20 entries with `maxDiskBytes = 200`. The eviction loop in `evictIfNeeded()` targets
80% capacity (160 bytes) — if the last written entry alone exceeds 200 bytes, the post-eviction
disk size will exceed the limit and the assertion fails. With Jackson's default serialization
(all null fields included), each `CachedIssue` entry is approximately 140 bytes. Currently this
passes, but increasing title length or adding fields to `CachedIssue` could silently break the
test. The assertion should be relaxed to account for the last-written entry's size.

**Fix:** Assert that the disk size is at most `maxDiskBytes + maxSingleEntrySize`:
```kotlin
// More robust: eviction guarantees at most one over-sized entry can remain
val lastEntryMaxSize = 300L // generous upper bound for a serialized CachedEntry
assertTrue(
    cache.diskSizeBytes() <= 200L + lastEntryMaxSize,
    "disk size must be within the limit after eviction (allow for last entry)"
)
```
Or use `cache.entryCount() <= 2` to verify that eviction actually removed files.

---

### WR-03: CliSupervisionTest Waits 30+ Seconds and Can Hang CI for 65 Seconds

**File:** `src/test/kotlin/com/six2dez/burp/aiagent/backends/cli/CliSupervisionTest.kt:23-82`
**Issue:** The test intentionally exercises the 30-second coerced timeout, making CI wait at
least 30 seconds per run on every platform. The `@Timeout(70, unit = TimeUnit.SECONDS)` prevents
infinite hangs, but 30-65 seconds per test invocation is expensive for a gate that runs on
ubuntu-latest, macos-latest, and windows-latest simultaneously. The `build.yml` `pr-gate` job
uses `-PexcludeHeavyTests=true` which only excludes `*IntegrationTest`, `*ConcurrencyTest`,
`*BackpressureTest`, and `*RestartPolicyTest` — `CliSupervisionTest` is not excluded and will
run in every PR gate, adding 30+ seconds to every CI run on every platform.

**Fix:** Either:
1. Name the class `CliSupervisionIntegrationTest` so the existing `excludeHeavyTests` filter
   catches it, or
2. Expose the minimum timeout floor as an overridable constant so the test can inject a very
   short timeout for faster validation, with a note that the floor coercion itself is tested.

---

### WR-04: Dead Private Function buildMetadataSection in ActiveAiScanner

**File:** `src/main/kotlin/com/six2dez/burp/aiagent/scanner/ActiveAiScanner.kt:1174-1204`
**Issue:** The `private fun buildMetadataSection(backendInfo, scanType, confidence)` function
(Markdown-formatted output) is defined but never called within `ActiveAiScanner.kt`. The
corresponding plain-text variant `buildMetadataSectionPlain()` at line 1206 is the one actually
used (called at line 1082). The unused function is dead code that will silently evade detekt
because it is `private` (detekt's `UnusedPrivateMember` rule applies, but this function's
signature does not match anything in the baseline). If detekt's `allRules = false` causes this
rule to be off by default, the dead code will not be flagged by the tooling introduced in this
phase.

**Fix:** Delete `buildMetadataSection()` (lines 1174-1204). If Markdown-format metadata is
needed in future, it can be restored from git history.

---

## Info

### IN-01: detekt buildUponDefaultConfig=true Does Not Include UnusedPrivateMember by Default

**File:** `build.gradle.kts:185-190` and `detekt.yml`
**Issue:** `allRules = false` and `buildUponDefaultConfig = true` means detekt uses its default
ruleset, which includes `UnusedPrivateMember` only if it is active in detekt's shipped defaults.
In detekt 1.23.x the `UnusedPrivateMember` rule is active by default but it uses type resolution
which requires the full classpath. Without type resolution enabled in the Gradle detekt config,
it may silently skip reporting the dead function noted in WR-04. The current `detekt {}` block
does not set `tasks.detekt { jvmTarget = ... }` or enable type resolution via `classpath`. This
means some rules that require type resolution are silently inactive.

**Fix:** Consider adding type resolution to the detekt task for complete coverage:
```kotlin
tasks.withType<io.gitlab.arturbosch.detekt.Detekt>().configureEach {
    jvmTarget = "21"
    classpath.setFrom(configurations.runtimeClasspath, configurations.compileClasspath)
}
```

---

### IN-02: The ActiveScannerDedupTest dedup assertion is conditionally vacuous

**File:** `src/test/kotlin/com/six2dez/burp/aiagent/scanner/ActiveScannerDedupTest.kt:43-55`
**Issue:** `queueTargetDedupPreventsRequeueWithinWindow()` calls `scanner.setEnabled(true)` which
starts a scheduler that drains the queue every 500ms. If the scheduler processes the first
`queueTarget()` call before `getQueueItems()` is called (i.e., within the 500ms window), both
`after1` and `after2` could be 0. The `assertEquals(after1, after2)` assertion would then pass
vacuously — the dedup was never actually exercised, but the test still passes green. The comment
at line 54 acknowledges this but the mitigation (that dedup uses `processedTargets.putIfAbsent`
before queue insertion) means dedup truly would still work — the test logic is sound in practice.
The concern is that future refactors that move the `processedTargets` update could silently break
the test's coverage while still making it pass.

**Fix:** To eliminate the scheduling race entirely, consider pausing the scheduler before calling
`queueTarget()` by using `scanner.setEnabled(false)` (stops the scheduler) and calling
`queueTarget()` directly (it checks `enabled.get()` first — so call `setEnabled(true)` once to
populate `enabled`, then immediately switch to `false` to freeze the scheduler, then make
assertions on the queue size). Alternatively test the underlying `processedTargets` map via
`resetStats()` explicitly rather than depending on queue size.

---

_Reviewed: 2026-06-11_
_Reviewer: Claude (gsd-code-reviewer)_
_Depth: standard_
