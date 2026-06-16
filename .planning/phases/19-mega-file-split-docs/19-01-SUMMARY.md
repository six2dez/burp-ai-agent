---
phase: 19-mega-file-split-docs
plan: "01"
subsystem: mcp-tools
tags: [refactor, split, no-behaviour-change, kotlin]
dependency_graph:
  requires: []
  provides:
    - McpToolModels.kt — @Serializable parameter data classes for all MCP tools
    - McpToolHelpers.kt — pure transform helper functions for MCP tool execution
    - McpToolExecutorImpl.kt — object McpToolExecutor runtime dispatcher
  affects:
    - src/main/kotlin/com/six2dez/burp/aiagent/mcp/tools/McpTools.kt
tech_stack:
  added: []
  patterns:
    - Same-package top-level extraction (private→internal visibility widening)
    - Multi-type models file (ContextModels.kt analog)
    - AWT-free contract comment on helper files
key_files:
  created:
    - src/main/kotlin/com/six2dez/burp/aiagent/mcp/tools/McpToolModels.kt
    - src/main/kotlin/com/six2dez/burp/aiagent/mcp/tools/McpToolHelpers.kt
    - src/main/kotlin/com/six2dez/burp/aiagent/mcp/tools/McpToolExecutorImpl.kt
  modified:
    - src/main/kotlin/com/six2dez/burp/aiagent/mcp/tools/McpTools.kt
decisions:
  - "toolJson moved to McpToolHelpers.kt as internal val — accessible from McpToolExecutorImpl.kt in same package"
  - "All helper functions changed private→internal to allow cross-file same-package access"
  - "McpToolExecutorImpl.kt needs PAUSED/RUNNING imports despite being in tools package (not inherited)"
  - "registerToolsLegacy extracted to McpToolLegacy.kt (follow-up extraction) — McpTools.kt now 22 lines (SC1 satisfied)"
metrics:
  duration: "~25 minutes"
  completed: "2026-06-16T09:29:49Z"
  tasks_completed: 2
  files_created: 4
  files_modified: 1
---

# Phase 19 Plan 01: McpTools.kt Split Summary

Split McpTools.kt (2925 lines) into 3 focused same-package files using 3 atomic commits, with test suite green after every extraction.

## What Was Built

Three new files in `src/main/kotlin/com/six2dez/burp/aiagent/mcp/tools/`:

- **McpToolModels.kt** (~430 lines): `HttpServiceParams` interface, `ToolSpec` data class, and all 40+ `@Serializable data class` parameter types for MCP tools.
- **McpToolHelpers.kt** (~300 lines): `internal val toolJson`, plus all 19 private top-level helper functions (changed to `internal`) — `executeIssueCreate`, `findProxyHistoryMatch`, `withAiIssuePrefix`, `hasEquivalentIssue`, `normalizeHttpRequest`, `truncateIfNeeded`, `ensureAllowedProxyHistoryCount`, `orderedProxyHistory`, `decodeJwt`, `normalizeHashAlgorithm`, `diffLines`, `countOccurrences`, `parseHighlightColor`, `sanitizeHeaders`, `maybeAnonymizeUrl`, `resolveReportPath`, `applyReplacements`, `resolveAuditConfig`, `getActiveEditor`.
- **McpToolExecutorImpl.kt** (~1250 lines): Complete `object McpToolExecutor` block with `describeTools`, `executeToolResult`, `executeTool`, `inputSchema`, and all private routing functions.

McpTools.kt reduced from 2925 lines to 22 lines (contains only `registerTools()` dispatcher + package/imports).

## Commits

| Extraction | Hash | Files |
|-----------|------|-------|
| A — McpToolModels.kt | eb976c6 | McpToolModels.kt (new), McpTools.kt (removed data classes, ToolSpec, HttpServiceParams) |
| B — McpToolHelpers.kt | 2bb2d39 | McpToolHelpers.kt (new), McpTools.kt (removed toolJson + helper functions) |
| C — McpToolExecutorImpl.kt | 0a2e229 | McpToolExecutorImpl.kt (new), McpTools.kt (removed McpToolExecutor, pruned 13 unused imports) |
| D — McpToolLegacy.kt | c2f008e | McpToolLegacy.kt (new), McpTools.kt (removed registerToolsLegacy, pruned all unused imports — 22 lines remain) |

## Verification Results

- `./gradlew test` — GREEN after each of the 4 extraction commits
- `BackendRegistryTest` — PASSES (anthropic factory present in registry)
- `./gradlew shadowJar` — SUCCESS, produces `build/libs/Custom-AI-Agent-full-0.8.0.jar`
- `grep -c 'data class|@Serializable' McpTools.kt` — returns 0 (no data class declarations remain)
- No call-site changes outside the moved code — confirmed by grep on external imports

## Deviations from Plan

### Planning Inconsistency — McpTools.kt Line Count (RESOLVED)

**Rule: Follow-up extraction performed**

**Found during:** Task 2 final verification (original deviation)
**Issue:** The plan's must_haves require McpTools.kt to be under 500 lines. However, `registerToolsLegacy` (the private legacy function kept for historical reference, marked `@Suppress("unused")`) spanned ~810 lines. The RESEARCH.md simultaneously said this function "stays in McpTools.kt" (Pitfall 5) and estimated the result as "~90 lines" — a direct contradiction.

**Resolution:** Follow-up extraction (`c2f008e`) created `McpToolLegacy.kt` in the same package with `registerToolsLegacy` moved verbatim. Visibility changed from `private` to `internal` so the (unused) function remains reachable. McpTools.kt is now **22 lines** — SC1 fully satisfied.

**Scope:** Research estimation error resolved. All 4 extractions complete, tests green, BackendRegistryTest passes, fat JAR builds.

### Auto-fix: Missing PAUSED/RUNNING imports in McpToolExecutorImpl.kt

**Rule 3 — Blocking compile error**
**Found during:** Task 2 compileKotlin check
**Issue:** The `task_engine_state` handler in `McpToolExecutor.executeToolResult` references `RUNNING` and `PAUSED` (static enum imports). These were inherited from McpTools.kt's imports but needed to be explicitly added to McpToolExecutorImpl.kt.
**Fix:** Added `import burp.api.montoya.burpsuite.TaskExecutionEngine.TaskExecutionEngineState.PAUSED` and `RUNNING` to McpToolExecutorImpl.kt.
**Files modified:** `McpToolExecutorImpl.kt`
**Commit:** 0a2e229 (included in Extraction C commit)

## Known Stubs

None — no placeholder values, hardcoded empty data flows, or TODO-stubbed content introduced.

## Threat Flags

None — no new network endpoints, auth paths, file access patterns, or schema changes introduced. Mechanical refactor only; the trust-boundary marker in McpToolExecutor (the `ext:` routing and external tool result wrapping) moved unchanged to McpToolExecutorImpl.kt.

## Self-Check

### Files Created

- [x] `src/main/kotlin/com/six2dez/burp/aiagent/mcp/tools/McpToolModels.kt` — EXISTS
- [x] `src/main/kotlin/com/six2dez/burp/aiagent/mcp/tools/McpToolHelpers.kt` — EXISTS
- [x] `src/main/kotlin/com/six2dez/burp/aiagent/mcp/tools/McpToolExecutorImpl.kt` — EXISTS
- [x] `src/main/kotlin/com/six2dez/burp/aiagent/mcp/tools/McpToolLegacy.kt` — EXISTS

### Commits Verified

- [x] eb976c6 — refactor(19-01): extract McpToolModels.kt from McpTools.kt
- [x] 2bb2d39 — refactor(19-01): extract McpToolHelpers.kt from McpTools.kt
- [x] 0a2e229 — refactor(19-01): extract McpToolExecutorImpl.kt from McpTools.kt
- [x] c2f008e — refactor(19-01): extract McpToolLegacy.kt from McpTools.kt (SC1 <500)

### Test Results

- [x] `./gradlew test` green after each extraction (including follow-up D)
- [x] `BackendRegistryTest` passes
- [x] `./gradlew shadowJar` builds successfully
- [x] `wc -l McpTools.kt` — 22 lines (SC1 satisfied)

## Self-Check: PASSED
