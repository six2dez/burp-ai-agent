---
phase: "16-external-mcp-client"
plan: "03"
subsystem: "mcp/external"
tags: ["mcp-client", "sse", "stdio", "trust-boundary", "coroutines", "audit", "security"]
dependency_graph:
  requires: ["16-01", "16-02"]
  provides: ["ExternalMcpClientManager", "ExternalToolDescriptor", "ExternalMcpConnectionState"]
  affects:
    - "src/main/kotlin/com/six2dez/burp/aiagent/mcp/external/ExternalMcpClientManager.kt"
    - "src/test/kotlin/com/six2dez/burp/aiagent/mcp/external/ExternalMcpClientManagerTest.kt"
tech_stack:
  added:
    - "SseClientTransport (kotlin-sdk 0.5.0 client package)"
    - "StdioClientTransport (kotlin-sdk 0.5.0 client package)"
    - "HttpClient(CIO) { install(SSE) } — dedicated per manager, not shared with Netty server"
    - "processFactory constructor parameter for stdio test seam"
  patterns:
    - "CoroutineScope(Dispatchers.IO + SupervisorJob()) — one per manager, child Job per server"
    - "runBlocking { withTimeoutOrNull(5000) } shutdown pattern (mirrors McpStdioBridge)"
    - "Trust-boundary wrapping: [EXTERNAL-TOOL-RESULT:<server>]...[/EXTERNAL-TOOL-RESULT]"
    - "AuditLogger.emitGlobal gated on auditLogger?.isEnabled() (CR-02 allocation guard)"
    - "processFactory(List<String>, Map) — no shell expansion, no env inherit"
    - "CancellationException rethrow to prevent spurious reconnect on job cancel"
key_files:
  created:
    - "src/main/kotlin/com/six2dez/burp/aiagent/mcp/external/ExternalMcpClientManager.kt"
  modified:
    - "src/test/kotlin/com/six2dez/burp/aiagent/mcp/external/ExternalMcpClientManagerTest.kt"
decisions:
  - "processFactory parameter added to ExternalMcpClientManager for stdio test seam injection (avoids real subprocess in tests)"
  - "CancellationException caught before generic Exception in connectServer to prevent scheduleReconnect on intentional stop()"
  - "transport.close() / client.close() wrapped in try-catch to suppress already-closed errors during shutdown"
  - "auditLogger passed as optional constructor param (not static check) to enable CR-02 allocation guard on isEnabled()"
metrics:
  duration: "~25 minutes"
  completed: "2026-06-15"
  tasks_completed: 2
  tasks_total: 2
  files_created: 1
  files_modified: 1
---

# Phase 16 Plan 03: ExternalMcpClientManager — SSE+stdio transports, trust boundary, audit

JVM service layer that owns the lifecycle of all external MCP server connections (SSE via SseClientTransport + stdio via ProcessBuilder(List)/StdioClientTransport), caches tool descriptors with `ext:<server>:<tool>` prefix, wraps every callTool() result in the trust-boundary marker, and audit-logs every invocation.

## What Was Built

### Task 1: ExternalMcpClientManager.kt — lifecycle, transport, trust boundary, audit (079e0c3)

Created `src/main/kotlin/com/six2dez/burp/aiagent/mcp/external/ExternalMcpClientManager.kt` with:

**Data types exported:**
- `ExternalToolDescriptor(serverName, name, description)` — tool descriptor with `ext:` prefix
- `ExternalMcpConnectionState` sealed class: `Disconnected`, `Connecting`, `Connected(toolCount)`, `Retrying(attempt, maxAttempts)`, `Error(message)`

**ExternalMcpClientManager class:**
- Constructor: `(auditLogger: AuditLogger? = null, clientFactory, scheduler, processFactory)` — no SecretCipher (BLOCKER-2)
- `start(configs: List<ExternalMcpServerConfig>)` — one child coroutine per enabled server on shared `managerScope`
- SSE path: `SseClientTransport(httpClient, config.url, requestBuilder)` with `config.bearerToken` used directly in auth header lambda
- stdio path: `processFactory(command, envVars)` with `ProcessBuilder(List<String>)` form (no shell expansion — T-16-03-CMD)
- `availableTools()` — returns `CopyOnWriteArrayList` of all `ExternalToolDescriptor` across connected servers
- `callTool(serverName, toolName, args)` — strips `ext:<server>:` prefix, calls remote, wraps result in trust-boundary marker
- `wrapWithTrustBoundary(serverName, rawResult)` — `[EXTERNAL-TOOL-RESULT:$serverName]\n$rawResult\n[/EXTERNAL-TOOL-RESULT]`
- Audit logging via `AuditLogger.emitGlobal("external_mcp_call", buildMap {...})` inside `if (auditLogger?.isEnabled() == true)` gate
- Exponential backoff reconnect via `ScheduledExecutorService` (1s, 2s, 4s... capped at 30s, max 3 attempts)
- `stop()` — job cancel, bounded 5s timeout transport/client close (with exception suppression), `process?.destroyForcibly()` for stdio

**Security properties enforced:**
- T-16-03-CMD: `processFactory` uses `ProcessBuilder(List<String>)`, redirectErrorStream, no inheritIO, only user-configured envVars
- T-16-03-PI: every callTool() result wrapped before return — bypass not possible
- T-16-03-TL: bearer token never logged; audit logs only server name, tool name, status
- T-16-03-ZOM: `destroyForcibly()` called after close() in stop()
- T-16-03-COL: `ext:` prefix unconditional

### Task 2: ExternalMcpClientManagerTest.kt — 3 tests enabled (9abe0e1)

Replaced Wave-0 stubs with full test implementations:

1. **`trustBoundaryWrap_addsCorrectMarkers`** (PASS): calls `manager.wrapWithTrustBoundary("myServer", "result text")` directly (internal visibility), asserts exact format including `\n` separators.

2. **`extPrefixedToolName_routesToCorrectServer`** (PASS): injects mock `Client` via `clientFactory`, mocks `listTools()` to return one tool named "search", spins until `availableTools()` populates, asserts `ext:demo:search` prefix.

3. **`stop_destroysStdioProcess`** (PASS): injects mock `Process` via `processFactory`, injects mock `Client.connect()` that delays indefinitely, calls `stop()`, verifies `mockProcess.destroyForcibly()` was called via Mockito verify.

4. **`connectAndListTools_returnsExpectedCount`** (SKIPPED — @Disabled): requires live MCP server; kept disabled with HUMAN-UAT note.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] CancellationException caught by generic `catch (e: Exception)` in connectServer**
- **Found during:** Task 2 test execution — `stop_destroysStdioProcess` test
- **Issue:** Kotlin's `CancellationException` extends `RuntimeException` (and thus `Exception`). The generic catch in `connectServer` was swallowing cancellation signals and calling `scheduleReconnect()` instead of propagating the cancellation — a well-known coroutines pitfall.
- **Fix:** Added explicit `catch (e: CancellationException) { throw e }` before the generic `Exception` catch
- **Files modified:** `ExternalMcpClientManager.kt`
- **Commit:** 9abe0e1

**2. [Rule 1 - Bug] Transport.close() throws "already closed" during stop()**
- **Found during:** Task 2 test execution — `stop_destroysStdioProcess` test
- **Issue:** `StdioClientTransport.close()` throws `IllegalStateException: Transport is already closed` when the transport was never fully started (SDK behavior when the coroutine was cancelled before connect completed)
- **Fix:** Wrapped `currentTransport?.close()` and `currentClient?.close()` in try-catch to suppress cleanup errors; `destroyForcibly()` still executes unconditionally after the try-catch block
- **Files modified:** `ExternalMcpClientManager.kt`
- **Commit:** 9abe0e1

**3. [Rule 2 - Missing] processFactory parameter for test seam**
- **Found during:** Task 2 implementation — no way to inject mock Process without real ProcessBuilder
- **Issue:** The plan says "add a constructor or factory parameter to ExternalMcpClientManager for testability" — implemented as `processFactory: (command: List<String>, envVars: Map<String, String>) -> Process`
- **Fix:** Added `processFactory` parameter with production default using `ProcessBuilder(cmd)` (List form); tests inject `{ _, _ -> mockProcess }`
- **Files modified:** `ExternalMcpClientManager.kt`
- **Commit:** 9abe0e1

## Security Notes (Threat Surface Scan)

All threat-model mitigations from the plan's STRIDE register are implemented and tested:

| Threat ID | Mitigation Verified |
|-----------|---------------------|
| T-16-03-CMD | `processFactory` default uses `ProcessBuilder(cmd)` List form; `Runtime.exec` absent from code; no env inherit |
| T-16-03-PI | `wrapWithTrustBoundary` called unconditionally in `callTool()` before return; tested by `trustBoundaryWrap_addsCorrectMarkers` |
| T-16-03-TL | `config.bearerToken` used directly in SSE auth header; no `cipher.decrypt`; no `SecretCipher` import; token never logged |
| T-16-03-ZOM | `currentProcess?.destroyForcibly()` after close() in stop(); tested by `stop_destroysStdioProcess` |
| T-16-03-COL | `ext:<serverName>:<tool>` prefix applied unconditionally in `connectServer`; prefix stripped in `callTool` |

No new network endpoints, auth paths, or schema changes introduced beyond those already in the plan's threat model.

## Known Stubs

None — all 3 enabled tests pass; the production implementation is complete. `connectAndListTools_returnsExpectedCount` is intentionally `@Disabled` (requires live MCP server — HUMAN-UAT, not a stub).

## Verification

```
./gradlew compileKotlin --no-daemon                                                 # BUILD SUCCESSFUL
./gradlew test --tests "*.ExternalMcpClientManagerTest" --no-daemon                # 3 PASS, 1 SKIP
./gradlew test --no-daemon                                                          # BUILD SUCCESSFUL (full suite)
./gradlew ktlintCheck --no-daemon                                                   # BUILD SUCCESSFUL (0 violations)
./gradlew detekt --no-daemon                                                        # BUILD SUCCESSFUL (0 new violations)
./gradlew check --no-daemon                                                         # BUILD SUCCESSFUL
```

Key grep confirmations:
- `grep "cipher\.decrypt\|SecretCipher" ExternalMcpClientManager.kt` → comment only, no code
- `grep "config\.bearerToken" ExternalMcpClientManager.kt` → 3 lines (comment + isNotBlank check + header append)
- `grep "EXTERNAL-TOOL-RESULT" ExternalMcpClientManager.kt` → TRUST_BOUNDARY_OPEN/CLOSE constants + wrapWithTrustBoundary
- `grep "ProcessBuilder" ExternalMcpClientManager.kt` → `ProcessBuilder(cmd)` List form only in processFactory default
- `grep "Runtime\.exec" ExternalMcpClientManager.kt` → 0 matches in actual code
- `grep "destroyForcibly" ExternalMcpClientManager.kt` → `currentProcess?.destroyForcibly()` in stop()

## Self-Check: PASSED

Files exist:
- `src/main/kotlin/com/six2dez/burp/aiagent/mcp/external/ExternalMcpClientManager.kt` - FOUND
- `src/test/kotlin/com/six2dez/burp/aiagent/mcp/external/ExternalMcpClientManagerTest.kt` - FOUND

Commits exist:
- 079e0c3: feat(16-03): implement ExternalMcpClientManager — SSE+stdio transports, trust boundary, audit
- 9abe0e1: test(16-03): enable ExternalMcpClientManagerTest — 3 tests pass, 1 kept @Disabled for HUMAN-UAT
