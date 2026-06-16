---
phase: 19-mega-file-split-docs
plan: "02"
subsystem: scanner
tags: [kotlin, refactor, extension-functions, passive-scanner, mega-file-split]

requires:
  - phase: 19-mega-file-split-docs/19-01
    provides: established same-package extension-function split pattern for Kotlin mega-files

provides:
  - PassiveAiScannerModels.kt — data classes (PassiveAiFinding, PassiveAiScannerStatus, LocalFinding, AiIssueItem, CachedAiIssues)
  - PassiveAiScannerHeuristics.kt — runLocalChecks + 4 detect* helpers
  - PassiveAiScannerParsing.kt — JSON parsing, sha256Hex, jsonMapper
  - PassiveAiScannerPrompts.kt — prompt builders (buildAnalysisPrompt, buildBatchAnalysisPrompt, etc.)
  - PassiveAiScannerFilters.kt — cache helpers, skip decisions, sanitizeHeadersForPrompt, applyOptimizationSettings
  - PassiveAiScannerFinding.kt — handleFinding, handleAiResponse, mapTitleToVulnClass, extractInjectionPoints
  - PassiveAiScannerAnalysis.kt — doAnalysis, flushBatch, sendSingleAnalysis, ensureBackendRunning, redactUrlForPrompt, extractAndLogJsEndpoints, etc.
  - PassiveAiScanner.kt reduced from 2566 to 445 lines (SC1 met)

affects:
  - 19-03 through 19-05 (remaining mega-file plans)
  - Any future feature work touching passive scanner

tech-stack:
  added: []
  patterns:
    - "Same-package internal extension functions for splitting Kotlin mega-files (no import changes needed for same-package callers)"
    - "Public extension functions for cross-package callers: add one import at call site"
    - "Companion object constants that move with extracted methods are redeclared as private const val in the target file"
    - "Internal val promotion for class fields accessed by extension functions in sibling files"

key-files:
  created:
    - src/main/kotlin/com/six2dez/burp/aiagent/scanner/PassiveAiScannerModels.kt
    - src/main/kotlin/com/six2dez/burp/aiagent/scanner/PassiveAiScannerHeuristics.kt
    - src/main/kotlin/com/six2dez/burp/aiagent/scanner/PassiveAiScannerParsing.kt
    - src/main/kotlin/com/six2dez/burp/aiagent/scanner/PassiveAiScannerPrompts.kt
    - src/main/kotlin/com/six2dez/burp/aiagent/scanner/PassiveAiScannerFilters.kt
    - src/main/kotlin/com/six2dez/burp/aiagent/scanner/PassiveAiScannerFinding.kt
    - src/main/kotlin/com/six2dez/burp/aiagent/scanner/PassiveAiScannerAnalysis.kt
  modified:
    - src/main/kotlin/com/six2dez/burp/aiagent/scanner/PassiveAiScanner.kt (2566 → 445 lines)
    - src/main/kotlin/com/six2dez/burp/aiagent/App.kt (add applyOptimizationSettings import)
    - src/main/kotlin/com/six2dez/burp/aiagent/ui/SettingsPanel.kt (add applyOptimizationSettings import)
    - src/test/kotlin/com/six2dez/burp/aiagent/scanner/PassiveAiScannerConfidenceTest.kt (fix reflection → direct extension call)

key-decisions:
  - "Extension functions in same-package files resolve without imports — caller code is unchanged for same-package callers"
  - "applyOptimizationSettings moved to Filters.kt as public extension (not internal) to avoid import at external callers; App.kt and SettingsPanel.kt each need one import line added"
  - "Companion constants moved to extension file as private const val — avoids companion access restriction and keeps constants close to usage"
  - "discoveredJsEndpoints renamed to discoveredJsEndpointsMap as internal val — extension functions in Analysis.kt access it by property name"
  - "requestsAnalyzed, lastAnalysisTime, aiBackoffUntilMs, lastBackoffLogTime, executor promoted to internal val — required for extension function access from Analysis.kt"
  - "SecretTripwire hook points move with doAnalysis/flushBatch/sendSingleAnalysis to Analysis.kt — correct since hooks fire on the outbound prompt, not on class construction"
  - "PassiveAiScannerConfidenceTest.kt: replaced getDeclaredMethod reflection with direct extension function call (same package, so internal access works)"

patterns-established:
  - "Rule: When moving a method that callers in OTHER packages call, make it a public extension function and add import at each call site"
  - "Rule: When moving a method called only from same-package code, internal extension function with no import changes needed"
  - "Rule: private companion object constants used only by extracted methods can be redeclared as private const val at file level in the target file"

requirements-completed: []

duration: ~2 sessions (context-window split)
completed: 2026-06-16
---

# Phase 19 Plan 02: PassiveAiScanner.kt Split Summary

**PassiveAiScanner.kt split from 2566 lines into 7 focused same-package Kotlin files, achieving SC1 (445 lines remaining) while preserving all SecretTripwire Phase 15 hook points and keeping tests green throughout**

## Performance

- **Duration:** ~2 sessions (context window boundary mid-execution)
- **Started:** 2026-06-15 (prior session)
- **Completed:** 2026-06-16
- **Tasks:** 7 extraction commits (E1-Models through E7-Analysis)
- **Files modified:** 10 (7 new, 3 modified with callers)

## Accomplishments

- Split PassiveAiScanner.kt (2566 original, 1316 after prior extractions) down to 445 lines — SC1 hard requirement of under 500 met
- Created 7 focused files: Models, Heuristics, Parsing, Prompts, Filters (with applyOptimizationSettings), Finding, Analysis
- All 3 Phase 15 SecretTripwire hook points preserved verbatim in Analysis.kt (doAnalysis, flushBatch, sendSingleAnalysis)
- Fixed PassiveAiScannerConfidenceTest.kt: reflection-based handleFinding call replaced with direct extension function call (same-package internal access)
- `JAVA_HOME=$(/usr/libexec/java_home -v 21) ./gradlew test` green after each extraction commit
- `./gradlew shadowJar` green

## Task Commits

1. **E1: Models** - `a9c346c` (refactor)
2. **E2: Heuristics** - `df99d1b` (refactor)
3. **E3: Parsing** - `37039f1` (refactor)
4. **E4: Prompts** - `b8601fe` (refactor)
5. **E5: Filters** - `20ad8b4` (refactor)
6. **E6: Finding + test fix** - `dfb9a17` (refactor)
7. **E7: Analysis + applyOptimizationSettings + SC1** - `88b88ad` (refactor)

## Files Created/Modified

- `PassiveAiScannerModels.kt` — data classes: PassiveAiFinding, PassiveAiScannerStatus, LocalFinding (internal), AiIssueItem (internal), CachedAiIssues (internal)
- `PassiveAiScannerHeuristics.kt` — runLocalChecks + 4 detect* helpers, authCookieHint (internal val)
- `PassiveAiScannerParsing.kt` — jsonMapper (internal val), parseIssuesJson, parseIssuesFromAiResponse, sha256Hex
- `PassiveAiScannerPrompts.kt` — truncateWithEllipsis, buildCompactRequestBody, buildCompactResponseBody, buildAnalysisPrompt, buildBatchAnalysisPrompt
- `PassiveAiScannerFilters.kt` — cache helpers, skip decisions, sanitizeHeadersForPrompt, applyOptimizationSettings (public extension), prompt result cache I/O
- `PassiveAiScannerFinding.kt` — handleFinding, handleAiResponse, handleParsedAiIssues, mapTitleToVulnClass (100-line when block), extractInjectionPoints, recordFinding, queueToActiveScanner
- `PassiveAiScannerAnalysis.kt` — doAnalysis (~290 lines), analyzeManually, analyzeInBackground, flushBatch, fallbackToIndividualAnalysis, sendSingleAnalysis, ensureBackendRunning, waitForBackendSession, reconcileBudgetAndLog, redactUrlForPrompt, redactSensitiveQuery, hasExcludedExtension, isGeminiCapacityError, maybeLogBackoff, extractAndLogJsEndpoints
- `PassiveAiScanner.kt` — class body reduced to: constructor, fields (promoted to internal where needed), enqueueForScanCheck, localChecks, isEnabled, getStatus, getLastFindings, shutdown, resetStats, manualScan, reconcileBudget, setBudgetPaused, isBudgetPaused, discoveredJsEndpointsMap, companion object (trimmed)
- `App.kt` — added `import com.six2dez.burp.aiagent.scanner.applyOptimizationSettings`
- `SettingsPanel.kt` — added `import com.six2dez.burp.aiagent.scanner.applyOptimizationSettings`
- `PassiveAiScannerConfidenceTest.kt` — reflection-based handleFinding replaced with direct call

## Decisions Made

- Same-package internal extension functions need no import at call site — existing method calls work unchanged
- Public extension functions used for applyOptimizationSettings because callers are in different packages; explicit import at each call site is the Kotlin-idiomatic approach
- `private companion object` constants migrated via `private const val` redeclarations at file level — they can't be accessed from extension functions in other files
- `discoveredJsEndpoints` renamed to `discoveredJsEndpointsMap` and made `internal val` so Analysis.kt extension functions can reference it by name
- `reconcileBudgetAndLog` private method removed from class and replaced by `internal fun PassiveAiScanner.reconcileBudgetAndLog` extension — same behavior, accessible from Analysis.kt
- `applyOptimizationSettings` is public (not internal) since it is called from `com.six2dez.burp.aiagent` and `com.six2dez.burp.aiagent.ui` packages

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] PassiveAiScannerConfidenceTest failing with NoSuchMethodException**
- **Found during:** E6 (Finding extraction)
- **Issue:** Test used `getDeclaredMethod("handleFinding", ...)` on the class. After handleFinding became an extension function, the method no longer exists on the class, causing `NoSuchMethodException` at runtime
- **Fix:** Replaced reflection-based call with direct extension function call — test is in `com.six2dez.burp.aiagent.scanner` (same package), so `internal` access works
- **Files modified:** `PassiveAiScannerConfidenceTest.kt`
- **Verification:** `./gradlew test` green
- **Committed in:** dfb9a17

**2. [Rule 2 - Missing critical] applyOptimizationSettings moved to Filters.kt with cross-package import addition**
- **Found during:** E7 (Analysis extraction) — line count still over 500 without moving this method
- **Issue:** After all private methods were extracted, file was at 513 lines. `applyOptimizationSettings` (68 lines) was the remaining extractable block
- **Fix:** Moved to Filters.kt as `public fun PassiveAiScanner.applyOptimizationSettings`; added one import line to App.kt and SettingsPanel.kt
- **Files modified:** PassiveAiScannerFilters.kt, PassiveAiScanner.kt, App.kt, SettingsPanel.kt
- **Verification:** Compile clean, tests green
- **Committed in:** 88b88ad

---

**Total deviations:** 2 auto-fixed (1 Rule 1 bug, 1 Rule 2 necessary-for-SC1 extraction)
**Impact on plan:** Both auto-fixes necessary for test correctness and SC1 compliance. No scope creep.

## Issues Encountered

None beyond the documented deviations.

## Next Phase Readiness

- PassiveAiScanner.kt at 445 lines (SC1 met). Future plan 19-03 can continue splitting other mega-files.
- The extension-function pattern is proven: same-package methods require no import changes, cross-package callers need one import line per file.
- SecretTripwire hooks confirmed present in Analysis.kt.

---
*Phase: 19-mega-file-split-docs*
*Completed: 2026-06-16*
