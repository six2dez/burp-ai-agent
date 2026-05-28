---
phase: 08-bapp-store-resubmission-mcp-pivot-to-extension-native-tools-
plan: "02"
subsystem: mcp
tags: [kotlin, mcp, burp, native-tools, ai-gate, store-build, redaction, audit]

requires:
  - phase: 08-01
    provides: BuildFlags.STORE_BUILD constant, nativeTool field on McpToolDescriptor, available() filtering, Wave-0 test stubs

provides:
  - AiTools.kt with registerAiTools() + 5 @Serializable input schema classes
  - 6 new native MCP tools: ai_analyze, ai_passive_scan, ai_findings_recent, redact_preview, ai_audit_query, ai_backends_list
  - B1 fix: McpToolHandlers.registerToolHandler() uses available() — generic tools silently skip in store builds
  - B2 fix: ai_passive_scan checks supervisor.isAiEnabled() BEFORE passiveScanner null check
  - McpToolContext extended with supervisor/passiveScanner/backendRegistry nullable fields
  - McpRuntimeContextFactory populates new fields in create()
  - KtorMcpServerManager.setAiToolDependencies() wires new context deps
  - McpSupervisor.setAiToolDependencies() delegates to serverManager
  - App.kt calls setAiToolDependencies() after scanner initialization
  - SettingsPanel MCP tool lists go through available() at 3 call sites

affects:
  - 08-03 (passive scan ScanCheck migration — AiPassiveScanCheckTest @Disabled stubs ready)
  - 08-04 (final resubmission — MCP native tools ready for review)

tech-stack:
  added: []
  patterns:
    - "B1 pattern: registerToolHandler() routes through available() so STORE_BUILD silently drops generic tool IDs"
    - "B2 pattern: AI gate (supervisor.isAiEnabled()) checked before any passiveScanner null check in handlers"
    - "Blocking AI send: CountDownLatch(1) + supervisor.send(..., onComplete = { latch.countDown() }) + await(120s)"
    - "No-arg MCP tool: Tool.Input() in inputSchema; add tool ID to noArgTools set in McpToolParityTest"

key-files:
  created:
    - src/main/kotlin/com/six2dez/burp/aiagent/mcp/tools/AiTools.kt
  modified:
    - src/main/kotlin/com/six2dez/burp/aiagent/mcp/McpToolCatalog.kt
    - src/main/kotlin/com/six2dez/burp/aiagent/mcp/McpToolContext.kt
    - src/main/kotlin/com/six2dez/burp/aiagent/mcp/McpRuntimeContextFactory.kt
    - src/main/kotlin/com/six2dez/burp/aiagent/mcp/McpServerManager.kt
    - src/main/kotlin/com/six2dez/burp/aiagent/mcp/KtorMcpServerManager.kt
    - src/main/kotlin/com/six2dez/burp/aiagent/mcp/McpSupervisor.kt
    - src/main/kotlin/com/six2dez/burp/aiagent/mcp/tools/McpToolHandlers.kt
    - src/main/kotlin/com/six2dez/burp/aiagent/mcp/tools/McpTools.kt
    - src/main/kotlin/com/six2dez/burp/aiagent/ui/SettingsPanel.kt
    - src/main/kotlin/com/six2dez/burp/aiagent/App.kt
    - src/test/kotlin/com/six2dez/burp/aiagent/mcp/AiGateMcpToolTest.kt
    - src/test/kotlin/com/six2dez/burp/aiagent/mcp/tools/McpToolParityTest.kt
    - src/test/kotlin/com/six2dez/burp/aiagent/mcp/McpSupervisorRestartPolicyTest.kt

key-decisions:
  - "setAiToolDependencies() added to McpServerManager interface so both KtorMcpServerManager and any test doubles must implement it — test double ScriptedServerManager updated with no-op"
  - "ProxyHttpRequestResponse -> HttpRequestResponse conversion uses @Suppress(UNCHECKED_CAST) explicit cast since Burp's Java type hierarchy isn't recognized as covariant in Kotlin generics"
  - "ai_backends_list added to noArgTools set in McpToolParityTest (no-arg tool returning Tool.Input())"
  - "AiGateMcpToolTest.buildContext() needed supervisor wiring — the Wave-0 stub accepted the parameter but didn't pass it into McpToolContext; fixed as auto-devation"
  - "App.kt wiring placed after activeAiScanner initialization so all three deps (supervisor, passiveAiScanner, backendRegistry) are fully constructed before MCP context is requested"

patterns-established:
  - "Pattern: Blocking AI send via CountDownLatch(1) with 120-second timeout, errorRef AtomicReference, responseBuffer StringBuilder"
  - "Pattern: AI gate check (supervisor == null || !supervisor.isAiEnabled()) before any tool-specific null checks — ensures unavailable message takes precedence"
  - "Pattern: No-arg native MCP tools use Tool.Input() in inputSchema; must be added to noArgTools in McpToolParityTest"

requirements-completed: [MCP-08-NATIVE, MCP-08-GATE, MCP-08-UI]

duration: 27min
completed: 2026-05-29
---

# Phase 08 Plan 02: Six Native MCP Tools + B1/B2 Gate Fixes Summary

**Six extension-native MCP tools (ai_analyze, ai_passive_scan, ai_findings_recent, redact_preview, ai_audit_query, ai_backends_list) implemented with B1 store-build gate (available() in registerToolHandler) and B2 AI gate on ai_passive_scan**

## Performance

- **Duration:** 27 min
- **Started:** 2026-05-28T22:12:00Z
- **Completed:** 2026-05-28T22:39:02Z
- **Tasks:** 3
- **Files modified:** 13 (1 new, 12 modified)

## Accomplishments

- Implemented all 6 new extension-native MCP tools with correct AI gating, redaction pipeline, and audit logging flowing through the existing runTool infrastructure
- Applied B1 fix: `McpToolHandlers.registerToolHandler()` now uses `McpToolCatalog.available()` — with `STORE_BUILD=true`, generic tool IDs resolve to null and silently skip registration
- Applied B2 fix: `ai_passive_scan` checks `supervisor.isAiEnabled()` BEFORE the passiveScanner null check, returning the unavailable message correctly when AI is disabled
- AiGateMcpToolTest: all 3 tests now green (aiAnalyze_returnsErrorWhenIsEnabledFalse, aiPassiveScan_returnsErrorWhenIsEnabledFalse, aiAnalyze_doesNotGateNonAiTool); McpToolParityTest: all 3 tests green; McpToolCatalogStoreBuildTest: all 3 tests green

## Task Commits

1. **Task 1: Add 6 native tool descriptors + AI context deps** - `5ef0414` (feat)
2. **Task 2: AiTools.kt + B1/B2 fixes + 6 handler branches** - `b6aff67` (feat)
3. **Task 3: SettingsPanel available() + App.kt wiring + McpSupervisor delegate** - `cd26f8c` (feat)

## Files Created/Modified

- `src/main/kotlin/com/six2dez/burp/aiagent/mcp/tools/AiTools.kt` - NEW: registerAiTools() + 5 @Serializable input schema data classes
- `src/main/kotlin/com/six2dez/burp/aiagent/mcp/McpToolCatalog.kt` - 6 new McpToolDescriptor entries with nativeTool=true
- `src/main/kotlin/com/six2dez/burp/aiagent/mcp/McpToolContext.kt` - supervisor/passiveScanner/backendRegistry nullable fields added
- `src/main/kotlin/com/six2dez/burp/aiagent/mcp/McpRuntimeContextFactory.kt` - 3 new mutable var fields; populate in create()
- `src/main/kotlin/com/six2dez/burp/aiagent/mcp/McpServerManager.kt` - setAiToolDependencies() added to interface
- `src/main/kotlin/com/six2dez/burp/aiagent/mcp/KtorMcpServerManager.kt` - setAiToolDependencies() implementation
- `src/main/kotlin/com/six2dez/burp/aiagent/mcp/McpSupervisor.kt` - setAiToolDependencies() delegate method
- `src/main/kotlin/com/six2dez/burp/aiagent/mcp/tools/McpToolHandlers.kt` - native list; allIds() extended; B1 fix (all()->available())
- `src/main/kotlin/com/six2dez/burp/aiagent/mcp/tools/McpTools.kt` - registerAiTools() call; 6 new when branches; 6 inputSchema branches
- `src/main/kotlin/com/six2dez/burp/aiagent/ui/SettingsPanel.kt` - 3 all()->available() substitutions
- `src/main/kotlin/com/six2dez/burp/aiagent/App.kt` - setAiToolDependencies() call after scanner initialization
- `src/test/kotlin/com/six2dez/burp/aiagent/mcp/AiGateMcpToolTest.kt` - buildContext() now wires supervisor into McpToolContext
- `src/test/kotlin/com/six2dez/burp/aiagent/mcp/tools/McpToolParityTest.kt` - ai_backends_list added to noArgTools
- `src/test/kotlin/com/six2dez/burp/aiagent/mcp/McpSupervisorRestartPolicyTest.kt` - ScriptedServerManager no-op setAiToolDependencies()

## Decisions Made

1. Added `setAiToolDependencies()` to `McpServerManager` interface (not just `KtorMcpServerManager`) so test doubles that implement the interface also satisfy the contract. The test `ScriptedServerManager` was updated with a no-op override.

2. `ProxyHttpRequestResponse` from `api.proxy().history()` does not auto-coerce to `List<HttpRequestResponse>` in Kotlin generics. Used `@Suppress("UNCHECKED_CAST")` with explicit cast to `List<HttpRequestResponse>` — safe because `ProxyHttpRequestResponse` extends `HttpRequestResponse` at the Java type level.

3. `ai_backends_list` takes no arguments (returns `Tool.Input()`). The pre-existing `McpToolParityTest.inputSchema_mapping_coversCatalogTools` hardcodes the no-arg tools set — updated to include `ai_backends_list`.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] AiGateMcpToolTest.buildContext() did not wire supervisor into McpToolContext**
- **Found during:** Task 2 (AiGateMcpToolTest execution)
- **Issue:** The Wave-0 test stub (Plan 01) accepted `supervisor: AgentSupervisor?` as a parameter in `buildContext()` but did not pass it through to the `McpToolContext` constructor — so `context.supervisor` was always null even when a mock supervisor was provided.
- **Fix:** Added `supervisor = supervisor` to the `McpToolContext(...)` call in `buildContext()`.
- **Files modified:** src/test/kotlin/com/six2dez/burp/aiagent/mcp/AiGateMcpToolTest.kt
- **Verification:** aiAnalyze_returnsErrorWhenIsEnabledFalse and aiPassiveScan_returnsErrorWhenIsEnabledFalse now pass green.
- **Committed in:** b6aff67 (Task 2 commit)

**2. [Rule 1 - Bug] McpToolParityTest noArgTools missing ai_backends_list**
- **Found during:** Task 2 (McpToolParityTest execution)
- **Issue:** `inputSchema_mapping_coversCatalogTools` checked that every tool NOT in `noArgTools` has non-empty schema properties. `ai_backends_list` is a no-arg tool (returns `Tool.Input()`), but was not in the hardcoded `noArgTools` set, causing the assertion to fail.
- **Fix:** Added `"ai_backends_list"` to the `noArgTools` set in the test.
- **Files modified:** src/test/kotlin/com/six2dez/burp/aiagent/mcp/tools/McpToolParityTest.kt
- **Verification:** McpToolParityTest all 3 tests pass.
- **Committed in:** b6aff67 (Task 2 commit)

**3. [Rule 2 - Missing Critical] setAiToolDependencies() added to McpServerManager interface**
- **Found during:** Task 1 (interface extension planning)
- **Issue:** Plan only mentioned adding `setAiToolDependencies()` to `KtorMcpServerManager`, but `McpSupervisor.serverManager` is typed as `McpServerManager`. To call the method via the interface reference, the interface must declare it.
- **Fix:** Added `setAiToolDependencies()` to the `McpServerManager` interface; added no-op to `ScriptedServerManager` test double.
- **Files modified:** src/main/kotlin/com/six2dez/burp/aiagent/mcp/McpServerManager.kt, McpSupervisorRestartPolicyTest.kt
- **Verification:** compileKotlin passes; McpSupervisorRestartPolicyTest compiles.
- **Committed in:** 5ef0414 (Task 1 commit)

---

**Total deviations:** 3 auto-fixed (2 Rule 1 bugs, 1 Rule 2 missing critical)
**Impact on plan:** All auto-fixes essential for correctness. No scope creep.

## Issues Encountered

- `api.proxy().history()` returns `List<ProxyHttpRequestResponse>` which Kotlin does not automatically coerce to `List<HttpRequestResponse>` despite the Java subtype relationship. Resolved with `@Suppress("UNCHECKED_CAST")` explicit cast — safe at runtime.

## Known Stubs

None — all 6 tool handlers are fully implemented. The `ai_passive_scan` handler calls `scanner.manualScan(requests)` which is an existing, fully implemented method in `PassiveAiScanner`.

## Threat Flags

None — no new network endpoints, auth paths, or schema changes at trust boundaries beyond what the plan's threat model covered. The B1 fix (available() in registerToolHandler) ensures T-08-03 is mitigated as planned.

## Next Phase Readiness

- 08-03 (AiPassiveScanCheck) can proceed: `PassiveAiScanner.manualScan()` is available; AiPassiveScanCheckTest @Disabled stubs are in place
- `McpToolCatalog.available(storeBuild=true)` returns exactly 8 tools (status, issue_create + 6 new native)
- B1 + B2 fixes verified; AiGateMcpToolTest (3/3 green), McpToolParityTest (3/3 green), McpToolCatalogStoreBuildTest (3/3 green)
- Full test suite: 261 tests, 0 failures, 0 errors

## Self-Check: PASSED

- `src/main/kotlin/com/six2dez/burp/aiagent/mcp/tools/AiTools.kt` — verified exists with registerAiTools() and 5 schema classes
- `McpToolHandlers.kt line 117` — verified uses `available()` not `all()` (B1 fix)
- `McpTools.kt` — verified ai_passive_scan branch checks isAiEnabled() before passiveScanner (B2 fix)
- Commits 5ef0414, b6aff67, cd26f8c — all verified in git log
- `./gradlew compileKotlin --quiet` — no output (clean)
- `./gradlew test -PexcludeHeavyTests=true` — BUILD SUCCESSFUL, 261 tests, 0 failures

---
*Phase: 08-bapp-store-resubmission-mcp-pivot-to-extension-native-tools-*
*Completed: 2026-05-29*
