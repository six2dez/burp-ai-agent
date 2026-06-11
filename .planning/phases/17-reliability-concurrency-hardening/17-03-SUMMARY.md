---
phase: 17-reliability-concurrency-hardening
plan: "03"
subsystem: cli-backend, mcp-server, redaction, config
tags: [REL-02, REL-04, resource-hardening, bounded-shutdown, lru-cache, cli-timeout]
dependency_graph:
  requires: [17-01, 17-02]
  provides: [SC2, SC4, SC5a, SC5b]
  affects:
    - CliBackend.kt (deleteOnExit + configurable timeout + buildTimeoutMessage)
    - AgentSettings.kt (cliTimeoutSeconds field)
    - KtorMcpServerManager.kt (bounded restart-safe stop())
    - Redaction.kt (LRU inner host maps)
tech_stack:
  added: []
  patterns:
    - "JDK LinkedHashMap(accessOrder=true).removeEldestEntry for LRU eviction (zero new deps)"
    - "Future.get(bound) for restart-safe bounded executor submission"
    - "deleteOnExit() + finally as belt-and-suspenders temp-file cleanup"
    - "Defaulted AgentSettings field with coerceIn(30, 3600) — five-touchpoint idiom"
key_files:
  created:
    - src/test/kotlin/com/six2dez/burp/aiagent/backends/cli/CliTimeoutMessageTest.kt
    - src/test/kotlin/com/six2dez/burp/aiagent/backends/cli/CliBackendTempFileTest.kt
    - src/test/kotlin/com/six2dez/burp/aiagent/mcp/McpShutdownBoundTest.kt
    - src/test/kotlin/com/six2dez/burp/aiagent/redact/RedactionHostMapBoundTest.kt
  modified:
    - src/main/kotlin/com/six2dez/burp/aiagent/config/AgentSettings.kt
    - src/main/kotlin/com/six2dez/burp/aiagent/backends/BackendTypes.kt
    - src/main/kotlin/com/six2dez/burp/aiagent/backends/cli/CliBackend.kt
    - src/main/kotlin/com/six2dez/burp/aiagent/mcp/KtorMcpServerManager.kt
    - src/main/kotlin/com/six2dez/burp/aiagent/redact/Redaction.kt
    - src/main/kotlin/com/six2dez/burp/aiagent/supervisor/AgentSupervisor.kt
decisions:
  - "stop() uses future.get(10s) NOT awaitTermination+shutdownNow (which would terminate the shared
     executor and break MCP restart with RejectedExecutionException)"
  - "HOST_MAP_CAP = 4096 per salt (LRU inner maps only; outer ConcurrentHashMap unchanged)"
  - "cliTimeoutSeconds threaded through BackendLaunchConfig from AgentSettings to NonInteractiveCliConnection
     (null means use Defaults.CLI_PROCESS_TIMEOUT_SECONDS — safe default)"
  - "deleteOnExit() is belt-and-suspenders (crash net); finally is primary — both kept per plan"
  - "CliBackendTempFileTest uses behavioral simulation + JDK reflection on DeleteOnExitHook (best-effort)"
metrics:
  duration_seconds: 389
  completed_date: "2026-06-11"
  tasks_completed: 3
  files_modified: 10
---

# Phase 17 Plan 03: REL-02 + REL-04 Resource Hardening Summary

**One-liner:** Crash-safe CLI temp files (deleteOnExit), configurable CLI timeout with actionable #71 message, restart-safe bounded MCP stop(), and LRU-capped host-anonymization maps.

## Tasks Completed

| Task | Description | Commit | SC |
|------|-------------|--------|----|
| 1 | REL-04: cliTimeoutSeconds setting + buildTimeoutMessage + CliTimeoutMessageTest | 8f9fe02 | SC4 |
| 2 | REL-02: deleteOnExit() at both CLI temp-file sites + CliBackendTempFileTest | 6f2a721 | SC2 |
| 3 | REL-02/SC5: bounded MCP stop() + LRU host maps + McpShutdownBoundTest + RedactionHostMapBoundTest | 5125764 | SC5a+SC5b |

## What Was Built

### SC4 — REL-04: Configurable CLI timeout + actionable timeout message (issue #71)

- `AgentSettings.cliTimeoutSeconds: Int = Defaults.CLI_PROCESS_TIMEOUT_SECONDS` — all five
  touch-points: field (defaulted), load (`coerceIn(30, 3600)`), baseline, persist, `KEY_CLI_TIMEOUT`.
  Plaintext pref (`getInteger`/`setInteger`), NOT SecretCipher.
- `Defaults.CLI_PROCESS_TIMEOUT_SECONDS = 120` unchanged — HTTP backends unaffected.
- `BackendLaunchConfig.cliTimeoutSeconds: Int?` added (null = use default); threaded through
  `AgentSupervisor.buildLaunchConfig` for all 5 CLI backends.
- `internal fun buildTimeoutMessage(tail, timeoutSeconds)` extracted (mirrors `buildCopilotCommand`
  pattern) — states "timed out after Xs", names the limit, and suggests
  "increase the cliTimeoutSeconds setting, or pre-install the CLI tool."
- Standard-path `waitFor` (`:225`) and opencode wall-clock (`:222`) both use `cliTimeoutSeconds`.

### SC2 — REL-02: Crash-safe CLI temp-file cleanup

- `deleteOnExit()` added at both `createTempFile` sites: codex output (`~:109`, `.also { it.deleteOnExit() }`)
  and uv prompt file (`~:121`, `tFile.deleteOnExit()`).
- Existing `finally` deletes (`:274-288`), inline delete (`:138`), and owner-only POSIX perms
  are all preserved — `deleteOnExit()` is crash-safety net only.

### SC5a — REL-02: Restart-safe bounded MCP stop()

`KtorMcpServerManager.stop()` now captures `executor.submit{...}` as a `Future` and calls
`future.get(10, TimeUnit.SECONDS)` with a `TimeoutException` handler that:
- Cancels the future + force-stops the server (port released)
- Still fires `callback(McpServerState.Stopped)` so the UI never waits forever

Critical constraint met: does NOT call `executor.shutdown()`/`awaitTermination()`/`shutdownNow()`.
The shared single-thread executor remains alive across `stop()`/`start()` cycles; only terminal
`shutdown()` (`:245-252`) is allowed to terminate it.

`McpShutdownBoundTest` includes a stop→start→stop restart assertion (would fail with
`RejectedExecutionException` if the executor were terminated).

### SC5b — REL-02: LRU-bounded inner host-anonymization maps

`Redaction.kt` additions:
- `private const val HOST_MAP_CAP = 4096`
- `private fun <K,V> boundedLru(maxEntries)` — `Collections.synchronizedMap(LinkedHashMap(accessOrder=true)
  { removeEldestEntry = size > maxEntries })`
- Both `computeIfAbsent` sites updated: `{ boundedLru(HOST_MAP_CAP) }` instead of `{ ConcurrentHashMap() }`

Outer `ConcurrentHashMap<String, MutableMap<String, String>>` and `computeIfAbsent`/`remove` unchanged.
`clearMappings()` continues to work. Format `host-<12hex>.local` and round-trip preserved (`RedactionTest` green).

## Deviations from Plan

None — plan executed exactly as written, including the RESTART-SAFE constraint on stop().

The one structural addition (`BackendLaunchConfig.cliTimeoutSeconds`) was the natural minimal wiring
path since `NonInteractiveCliConnection` is a private inner class that has no other access to settings.
This follows the existing `requestTimeoutSeconds` precedent in the same config.

## Verification

```
./gradlew test --tests "com.six2dez.burp.aiagent.backends.cli.CliTimeoutMessageTest"  # SC4 GREEN
./gradlew test --tests "com.six2dez.burp.aiagent.backends.cli.CliBackendTempFileTest" # SC2 GREEN
./gradlew test --tests "com.six2dez.burp.aiagent.mcp.McpShutdownBoundTest"            # SC5a GREEN
./gradlew test --tests "com.six2dez.burp.aiagent.redact.RedactionHostMapBoundTest"    # SC5b GREEN
./gradlew test --tests "com.six2dez.burp.aiagent.redact.RedactionTest"               # regression GREEN
./gradlew test                                                                         # full suite GREEN
```

Guards:
- `grep "CLI_PROCESS_TIMEOUT_SECONDS = 120" Defaults.kt` — present (unchanged)
- `grep "computeIfAbsent(salt)" Redaction.kt` — present (outer map untouched)
- `grep "removeEldestEntry" Redaction.kt` — present (inner LRU bound)

## Known Stubs

None.

## Threat Flags

None. No new network endpoints, auth paths, file access patterns, or schema changes.

## Self-Check: PASSED
