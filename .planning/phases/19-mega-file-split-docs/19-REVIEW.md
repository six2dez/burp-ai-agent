---
phase: 19-mega-file-split-docs
reviewed: 2026-06-26T08:18:19Z
depth: deep
files_reviewed: 25
files_reviewed_list:
  - src/main/kotlin/com/six2dez/burp/aiagent/App.kt
  - src/main/kotlin/com/six2dez/burp/aiagent/mcp/tools/McpToolExecutorImpl.kt
  - src/main/kotlin/com/six2dez/burp/aiagent/mcp/tools/McpToolHelpers.kt
  - src/main/kotlin/com/six2dez/burp/aiagent/mcp/tools/McpToolLegacy.kt
  - src/main/kotlin/com/six2dez/burp/aiagent/mcp/tools/McpToolModels.kt
  - src/main/kotlin/com/six2dez/burp/aiagent/mcp/tools/McpTools.kt
  - src/main/kotlin/com/six2dez/burp/aiagent/scanner/PassiveAiScanner.kt
  - src/main/kotlin/com/six2dez/burp/aiagent/scanner/PassiveAiScannerAnalysis.kt
  - src/main/kotlin/com/six2dez/burp/aiagent/scanner/PassiveAiScannerFilters.kt
  - src/main/kotlin/com/six2dez/burp/aiagent/scanner/PassiveAiScannerFinding.kt
  - src/main/kotlin/com/six2dez/burp/aiagent/scanner/PassiveAiScannerHeuristics.kt
  - src/main/kotlin/com/six2dez/burp/aiagent/scanner/PassiveAiScannerModels.kt
  - src/main/kotlin/com/six2dez/burp/aiagent/scanner/PassiveAiScannerParsing.kt
  - src/main/kotlin/com/six2dez/burp/aiagent/scanner/PassiveAiScannerPrompts.kt
  - src/main/kotlin/com/six2dez/burp/aiagent/ui/SettingsPanel.kt
  - src/main/kotlin/com/six2dez/burp/aiagent/ui/SettingsPanelActions.kt
  - src/main/kotlin/com/six2dez/burp/aiagent/ui/SettingsPanelInit.kt
  - src/main/kotlin/com/six2dez/burp/aiagent/ui/SettingsPanelMcpTabs.kt
  - src/main/kotlin/com/six2dez/burp/aiagent/ui/SettingsPanelScannerTabs.kt
  - src/main/kotlin/com/six2dez/burp/aiagent/ui/SettingsPanelSettingsIO.kt
  - src/test/kotlin/com/six2dez/burp/aiagent/scanner/PassiveAiScannerConfidenceTest.kt
  - src/test/kotlin/com/six2dez/burp/aiagent/scanner/PassiveAiScannerJsonParsingTest.kt
  - docs/anthropic-backend.md
  - docs/external-mcp-servers.md
  - README.md
findings:
  critical: 0
  warning: 0
  info: 1
  total: 1
status: clean
---

# Phase 19: Code Review Report

**Reviewed:** 2026-06-26T08:18:19Z
**Depth:** deep
**Files Reviewed:** 25
**Status:** clean

## Summary

Phase 19 extracted three mega-files (`McpTools.kt` 2925 lines, `SettingsPanel.kt` 2782 lines,
`PassiveAiScanner.kt` 2566 lines) into focused same-package files, and updated user-facing docs. The
review checked extraction fidelity, visibility correctness, registration integrity, and Phase 15 tripwire
hook continuity across the full commit range `eb976c6^..e91af26`.

**Extraction fidelity:** All function signatures, data-class structures, `@Serializable` annotations,
constant values, and behavioral logic match the originals. The `private` → `internal` visibility
widening is confined to members genuinely needed across files and does not expose anything publicly
that was not public before.

**Registration integrity:** The `McpToolLegacy.registerToolsLegacy` function that appears in
`McpToolLegacy.kt` was already marked `@Suppress("unused")` in the original `McpTools.kt` — it was
dead code before the split and remains so after. Live tool registration runs through the
`McpToolRegistrations` → `registerToolHandler` → `McpToolExecutor.executeToolResult` pipeline, which
predates Phase 19 and is unaffected.

**Phase 15 tripwire hooks:** All three `SecretTripwire.detectAndBuild(...)` call sites moved intact
into `PassiveAiScannerAnalysis.kt` (lines 461-463, 629-631, 723-725). Audit logging paths
(`AuditLogger.emitGlobal`) are also preserved.

**Test updates:** Both scanner tests are correctly updated — `PassiveAiScannerConfidenceTest.kt` drops
the reflection wrapper in favour of a direct internal-extension call, and
`PassiveAiScannerJsonParsingTest.kt` calls the new package-level `cleanJsonResponse` / `parseIssuesJson`
functions directly. No mocking boilerplate was lost.

**App.kt:** A single needed import (`applyOptimizationSettings`) was added after the function moved
from a class method to a top-level package extension. The call site is unchanged.

One INFO observation follows; it is not a behavioral regression.

## Info

### IN-01: Three unused private constants in PassiveAiScannerHeuristics.kt

**File:** `src/main/kotlin/com/six2dez/burp/aiagent/scanner/PassiveAiScannerHeuristics.kt:8-10`
**Issue:** `LOCAL_FINDING_SKIP_CONFIDENCE`, `REQUEST_BODY_LOCAL_CHECK_MAX_CHARS`, and
`RESPONSE_BODY_LOCAL_CHECK_MAX_CHARS` are declared at the top of the file but never referenced within
it. They were copied from the original `PassiveAiScanner` companion block when the heuristics
functions were extracted. The constants that are actually used live in `PassiveAiScannerFilters.kt`
(line 22 for `LOCAL_FINDING_SKIP_CONFIDENCE`) and `PassiveAiScannerAnalysis.kt` (lines 28-29 for the
body-size pair), where they are separately redeclared as private. The `PassiveAiScanner` companion
itself retains the authoritative copies used by the class-body `localChecks()` method (lines 420-421).
**Fix:** Remove the three unreferenced `private const val` declarations from
`PassiveAiScannerHeuristics.kt`. The values are correct and match all other redeclarations, so removal
is safe with no functional change.

---

_Reviewed: 2026-06-26T08:18:19Z_
_Reviewer: Claude (gsd-code-reviewer)_
_Depth: deep_
