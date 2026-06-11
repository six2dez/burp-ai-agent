---
phase: 18-quality-tooling-build-hardening
plan: "03"
subsystem: test-coverage
tags:
  - test
  - coverage
  - cache
  - scanner
  - cli
  - sc4
  - qual-02
dependency_graph:
  requires:
    - 18-02
  provides:
    - PersistentPromptCacheTest (3 tests: put/get round-trip, TTL eviction, disk-size eviction)
    - ActiveScannerDedupTest (2 tests: dedup within window, re-queue after resetStats)
    - CliSupervisionTest (1 test: NonInteractiveCliConnection timeout path)
  affects: []
tech_stack:
  added: []
  patterns:
    - Pure-JVM temp-dir injection for PersistentPromptCache tests (no Montoya dependency)
    - Deep-stub Mockito mock for MontoyaApi in scanner tests (api.scope().isInScope chain)
    - CountDownLatch + @Timeout for async CLI watchdog timeout assertion
key_files:
  created:
    - src/test/kotlin/com/six2dez/burp/aiagent/cache/PersistentPromptCacheTest.kt
    - src/test/kotlin/com/six2dez/burp/aiagent/scanner/ActiveScannerDedupTest.kt
    - src/test/kotlin/com/six2dez/burp/aiagent/backends/cli/CliSupervisionTest.kt
  modified: []
decisions:
  - "CliSupervisionTest uses backendId='ollama' (generic) instead of 'codex-cli' to avoid NonInteractiveCliConnection.buildCommand() prepending Codex-specific argv ('codex exec ...') which would fail to find the codex binary during timeout testing"
  - "CliSupervisionTest latch.await(65s) + @Timeout(70s): CliBackend.launch() coerces cliTimeoutSeconds to coerceIn(30,3600) regardless of config value; floor 30 s dictates the minimum test duration"
  - "ActiveScannerDedupTest asserts after1==after2 (not after2==0) because startProcessing() may consume the first enqueue before getQueueItems() reads it — queue size 0 or 1 are both valid post-first-enqueue states"
metrics:
  duration: 6m
  completed_date: "2026-06-11"
  tasks_completed: 2
  files_created: 3
---

# Phase 18 Plan 03: Test Coverage (SC4/QUAL-02) Summary

Three new test files raising coverage for the three zero/near-zero coverage modules: cache,
scanner dedup, and CLI supervision timeout.

## What Was Built

**PersistentPromptCacheTest** — 3 tests verifying the cache module's critical paths:
- `putAndGetRoundTrip`: JSON serialization round-trip via tmpDir constructor injection
- `getReturnsNullForExpiredEntry`: TTL eviction path (`ttlMs=1L`, entry with past `createdAtMs`)
- `evictsOldestWhenDiskLimitExceeded`: LRU eviction after 20 entries at `maxDiskBytes=200L`

**ActiveScannerDedupTest** — 2 tests verifying the `processedTargets` ConcurrentHashMap dedup:
- `queueTargetDedupPreventsRequeueWithinWindow`: same target queued twice, second is silently dropped within DEDUP_WINDOW_MS (1 hour); requires `setEnabled(true)` before `queueTarget()`
- `queueTargetAllowsRequeueAfterWindowExpires`: `resetStats()` clears `processedTargets`; re-queue succeeds

**CliSupervisionTest** — 1 test verifying the REL-04 watchdog timeout path (issue #71):
- `sendTimesOutAndReportsViaOnComplete`: `CliBackend.launch()` with `sleep 60` command; `onComplete` receives `IllegalStateException` whose message contains "timed out" after the process watchdog fires

## Verification Results

| Command | Result |
|---------|--------|
| `./gradlew test --tests "*.PersistentPromptCacheTest" --no-daemon` | BUILD SUCCESSFUL — 3 tests pass |
| `./gradlew test --tests "*.ActiveScannerDedupTest" --no-daemon` | BUILD SUCCESSFUL — 2 tests pass |
| `./gradlew test --tests "*.CliSupervisionTest" --no-daemon` | BUILD SUCCESSFUL — 1 test passes (33s) |
| `./gradlew test -PexcludeHeavyTests=true --no-daemon` | BUILD SUCCESSFUL — full fast suite green |
| `./gradlew ktlintCheck --no-daemon` | BUILD SUCCESSFUL — no new violations |
| `./gradlew detekt --no-daemon` | BUILD SUCCESSFUL — no new violations |
| `./gradlew check --no-daemon` | BUILD SUCCESSFUL — exits 0 |

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] CliSupervisionTest used wrong backendId for timeout test**
- **Found during:** Task 2 — first test run returned "Stream closed" instead of "timed out"
- **Issue:** PATTERNS.md suggested `CliBackend("codex-cli", "Codex CLI")` but `NonInteractiveCliConnection.buildCommand()` routes `backendId == "codex-cli"` through `buildCodexExecCommand()` which prepends `codex exec --color never --skip-git-repo-check --output-last-message <path> -` to the command argv. The `resolveCommand()` then tries to find `codex` in PATH, which does not exist on CI; the command resolution fails and `onComplete` is called with "Stream closed" from the executor shutdown rather than the intended timeout.
- **Fix:** Changed backendId from `"codex-cli"` to `"ollama"` — this routes through the `else` branch in `buildCommand()` returning the raw `sleepCmd` unchanged, which correctly executes `sleep 60` and triggers the 30-second watchdog timeout.
- **Files modified:** `src/test/kotlin/com/six2dez/burp/aiagent/backends/cli/CliSupervisionTest.kt`
- **Commit:** fdffac6

**2. [Rule 3 - Formatting] ktlintFormat auto-fixed ActiveScannerDedupTest.kt**
- **Found during:** Task 2 — `./gradlew ktlintCheck` reported "Expected newline before '.'" for chained `org.mockito.kotlin.whenever(...)` calls
- **Fix:** Ran `./gradlew ktlintFormat --no-daemon` which reformatted the mock setup to place each `.thenReturn()` on a new line
- **Files modified:** `src/test/kotlin/com/six2dez/burp/aiagent/scanner/ActiveScannerDedupTest.kt`

## Known Stubs

None — all three test files exercise real production code paths; no stubs.

## Real Bugs Discovered (not fixed — tests-only scope)

None identified. The production code under test behaves as specified. The "Stream closed"
behavior for the wrong backendId was a test design issue, not a production bug.

## Threat Surface Scan

No new network endpoints, auth paths, file access patterns, or schema changes introduced.
All three files are `src/test/**` — test-only scope with no runtime exposure.

T-18-04 mitigated: PersistentPromptCacheTest uses `Files.createTempDirectory("cache-test")`
injected via constructor; no reference to `user.home` in code (only comments).

T-18-05 mitigated: CliSupervisionTest bounded by `@Timeout(70, unit = TimeUnit.SECONDS)`;
actual execution time ~33s (30s floor + overhead); latch.await(65s) matches.

## Self-Check: PASSED

- [x] `src/test/kotlin/com/six2dez/burp/aiagent/cache/PersistentPromptCacheTest.kt` — FOUND
- [x] `src/test/kotlin/com/six2dez/burp/aiagent/scanner/ActiveScannerDedupTest.kt` — FOUND
- [x] `src/test/kotlin/com/six2dez/burp/aiagent/backends/cli/CliSupervisionTest.kt` — FOUND
- [x] commit 3b570dc exists — FOUND
- [x] commit fdffac6 exists — FOUND
