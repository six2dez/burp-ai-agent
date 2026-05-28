---
phase: 08-bapp-store-resubmission-mcp-pivot-to-extension-native-tools-
plan: "03"
subsystem: scanner
tags: [kotlin, scanner, passive-scan, burp, bapp-store, scan-check]

requires:
  - phase: 08-01
    provides: BuildFlags.STORE_BUILD constant, Wave-0 AiPassiveScanCheckTest @Disabled stubs
  - phase: 08-02
    provides: App.kt setAiToolDependencies wiring (must coexist)

provides:
  - AiPassiveScanCheck implementing PassiveScanCheck.doCheck() (BApp Store requirement)
  - PassiveAiScanner.enqueueForScanCheck() — async AI enqueue without blocking scanner thread
  - PassiveAiScanner.localChecks() — internal wrapper over private runLocalChecks()
  - PassiveAiScanner.LocalFinding promoted from private to internal (same-package visibility)
  - ProxyResponseHandler removed from PassiveAiScanner (grep registerResponseHandler = 0)
  - App.kt registerPassiveScanCheck(check, ScanCheckType.PER_REQUEST) in try/catch (Community-safe)
  - AiPassiveScanCheckTest 2 tests green (no @Disabled)

affects:
  - 08-04 (final resubmission — passive scan migration complete, both scan checks registered)

tech-stack:
  added: []
  patterns:
    - "PassiveScanCheck.doCheck() returns AuditResult synchronously (local heuristics only)"
    - "enqueueForScanCheck() submits analyzeManually() to executor — returns immediately"
    - "Async AI findings surface via api.siteMap().add() inside PassiveAiScanner (line 1724)"
    - "App.kt try/catch for Pro-only registration (Community-safe degradation pattern)"
    - "Burp factory NPE pattern: AuditResult.auditResult() requires Burp runtime; caught in unit tests"

key-files:
  created:
    - src/main/kotlin/com/six2dez/burp/aiagent/scanner/AiPassiveScanCheck.kt
  modified:
    - src/main/kotlin/com/six2dez/burp/aiagent/scanner/PassiveAiScanner.kt
    - src/main/kotlin/com/six2dez/burp/aiagent/App.kt
    - src/test/kotlin/com/six2dez/burp/aiagent/scanner/AiPassiveScanCheckTest.kt

key-decisions:
  - "Used internal visibility for localChecks() and LocalFinding (not public) because a public fun cannot expose an internal return type in Kotlin — compiler enforces this boundary"
  - "AuditResult.auditResult() requires Burp's ObjectFactoryLocator.FACTORY at runtime; unit tests catch the NPE and verify the method calls via Mockito verify() instead of asserting the return value"
  - "isStreamingOrRealtimeEndpoint(InterceptedResponse) removed as dead code after ProxyResponseHandler removal — it was only called from within the handler block"
  - "registered AtomicBoolean field removed after ProxyResponseHandler removal — its only use was guarding registerResponseHandler(handler)"
  - "enqueueForScanCheck() places no scope/size checks: those checks are the responsibility of AiPassiveScanCheck.doCheck() (scope) and Burp Scanner (size/MIME filtering); this keeps the method simple"

patterns-established:
  - "Pattern: doCheck() synchronous + async split: local heuristics inline, AI analysis via executor.submit()"
  - "Pattern: Burp factory NPE in unit tests — catch NullPointerException from ObjectFactoryLocator.FACTORY; verify Mockito interactions for behavioral correctness"
  - "Pattern: Pro-only scanner registration try/catch in App.kt — same block pattern as AiScanCheck"

requirements-completed: [SCAN-08-PASSIVE]

duration: 20min
completed: 2026-05-29
---

# Phase 08 Plan 03: AiPassiveScanCheck + ProxyResponseHandler Removal Summary

**PassiveScanCheck migration complete: AiPassiveScanCheck.doCheck() implements BApp Store requirement; ProxyResponseHandler removed from PassiveAiScanner; grep registerResponseHandler = 0**

## Performance

- **Duration:** ~20 min
- **Started:** 2026-05-28T22:30:00Z
- **Completed:** 2026-05-28T22:50:00Z
- **Tasks:** 2
- **Files modified:** 4 (1 new, 3 modified)

## Accomplishments

- Removed the `ProxyResponseHandler` private val handler block (lines 298-357) and its registration call from `PassiveAiScanner.setEnabled()`. `grep -c registerResponseHandler PassiveAiScanner.kt` = 0.
- Added `enqueueForScanCheck(HttpRequestResponse)` — guards via `enabled.get()` + `supervisor.isBlockedByBurpAiGate()`, submits `analyzeManually(requestResponse)` to the existing single-thread executor.
- Added `internal localChecks(request, response)` — thin wrapper over private `runLocalChecks()` for same-package access by `AiPassiveScanCheck`.
- Promoted `LocalFinding` data class from `private` to `internal`.
- Removed dead code: `isStreamingOrRealtimeEndpoint(InterceptedResponse)` (only called from the removed handler) and `registered AtomicBoolean` field.
- Created `AiPassiveScanCheck.kt` implementing `PassiveScanCheck` interface with `doCheck()` (synchronous local heuristics + async AI enqueue) and `consolidateIssues()` (copied verbatim from `AiScanCheck.kt:94-105`).
- Added `registerPassiveScanCheck(aiPassiveScanCheck, ScanCheckType.PER_REQUEST)` block to `App.kt` in try/catch immediately after the `AiScanCheck` active registration block.
- App.kt retains 08-02's `setAiToolDependencies` wiring and `registerScanCheck(aiScanCheck)` active registration — no regression.
- Replaced `@Disabled` stubs in `AiPassiveScanCheckTest` with two green tests. Both verify Mockito interactions rather than `AuditResult` return value (Burp factory unavailable in unit tests).
- Full quick suite: 263 tests, 0 failures (261 pre-existing + 2 new from AiPassiveScanCheckTest).

## Task Commits

1. **Task 1: expose enqueueForScanCheck/localChecks; remove ProxyResponseHandler** — `9febcff` (feat)
2. **Task 2: AiPassiveScanCheck + App.kt registration + green tests** — `50f32a3` (feat)

## Files Created/Modified

- `src/main/kotlin/com/six2dez/burp/aiagent/scanner/AiPassiveScanCheck.kt` — NEW: PassiveScanCheck implementation; doCheck(); consolidateIssues(); mapSeverity()
- `src/main/kotlin/com/six2dez/burp/aiagent/scanner/PassiveAiScanner.kt` — removed ProxyResponseHandler + imports + dead code; added enqueueForScanCheck(), internal localChecks(), LocalFinding promoted to internal
- `src/main/kotlin/com/six2dez/burp/aiagent/App.kt` — added ScanCheckType + AiPassiveScanCheck imports; added registerPassiveScanCheck try/catch block
- `src/test/kotlin/com/six2dez/burp/aiagent/scanner/AiPassiveScanCheckTest.kt` — replaced @Disabled stubs with green tests

## Decisions Made

1. Used `internal` visibility for `localChecks()` and `LocalFinding` rather than `public`. Kotlin's compiler enforces that a `public` function cannot expose an `internal` return type — so `localChecks(): List<LocalFinding>` must also be `internal`. Both `AiPassiveScanCheck` and `PassiveAiScanner` are in the `scanner` package, so `internal` gives the required access.

2. Unit tests catch `NullPointerException` from `AuditResult.auditResult()` (Burp's `ObjectFactoryLocator.FACTORY` is null outside the Burp runtime). The tests use `verify(passiveScanner).localChecks(any(), any())` and `verify(passiveScanner).enqueueForScanCheck(reqResp)` to prove behavioral correctness. This pattern is consistent with how other scanner tests handle Burp factory unavailability.

3. `enqueueForScanCheck()` has no scope/size filtering. Scope filtering is the responsibility of `AiPassiveScanCheck.doCheck()` (via `passiveAiScopeOnly` check before calling enqueue). Burp Scanner handles size/MIME filtering before calling `doCheck()`. Keeping `enqueueForScanCheck()` simple avoids double-filtering.

4. Removed `isStreamingOrRealtimeEndpoint(InterceptedResponse)` as dead code. After removing the `ProxyResponseHandler` handler block, this private method was only callable from the now-deleted handler. Removing it also eliminates the need to keep the `InterceptedResponse` import.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] isStreamingOrRealtimeEndpoint dead code retained unused import**
- **Found during:** Task 1 (compilation after removing ProxyResponseHandler)
- **Issue:** After removing the `ProxyResponseHandler` handler block, `isStreamingOrRealtimeEndpoint(InterceptedResponse)` remained as dead code. It referenced `InterceptedResponse` (now removed from imports), causing a compilation error.
- **Fix:** Removed `isStreamingOrRealtimeEndpoint()` method and its `InterceptedResponse` / `ProxyResponseReceivedAction` / `ProxyResponseToBeSentAction` imports.
- **Files modified:** src/main/kotlin/com/six2dez/burp/aiagent/scanner/PassiveAiScanner.kt
- **Verification:** `./gradlew compileKotlin --quiet` produced no errors.
- **Committed in:** 9febcff (Task 1 commit)

**2. [Rule 1 - Bug] registered AtomicBoolean field became unused**
- **Found during:** Task 1 (after removing ProxyResponseHandler)
- **Issue:** The `registered` AtomicBoolean field was only used in `setEnabled()` to guard `registerResponseHandler(handler)`. After removing the handler and its registration call, `registered` was declared but never read.
- **Fix:** Removed the `registered = AtomicBoolean(false)` field declaration.
- **Files modified:** src/main/kotlin/com/six2dez/burp/aiagent/scanner/PassiveAiScanner.kt
- **Verification:** Compile clean.
- **Committed in:** 9febcff (Task 1 commit)

**3. [Rule 1 - Bug] localChecks() must be internal (public fun exposing internal type)**
- **Found during:** Task 1 (compilation error)
- **Issue:** Plan called for `localChecks()` to be `public`, but Kotlin's visibility rules prohibit a `public` function from exposing an `internal` return type (`List<LocalFinding>`).
- **Fix:** Changed `localChecks()` from `public` to `internal` (still accessible to `AiPassiveScanCheck` in the same package).
- **Files modified:** src/main/kotlin/com/six2dez/burp/aiagent/scanner/PassiveAiScanner.kt
- **Verification:** Compile clean.
- **Committed in:** 9febcff (Task 1 commit)

**4. [Rule 1 - Bug] AuditResult.auditResult() NPE in unit tests**
- **Found during:** Task 2 (AiPassiveScanCheckTest execution)
- **Issue:** `AuditResult.auditResult()` requires `burp.api.montoya.internal.ObjectFactoryLocator.FACTORY` which is null outside the Burp runtime. Unit tests calling `check.doCheck(reqResp)` threw NPE.
- **Fix:** Tests wrap `check.doCheck(reqResp)` in `try { ... } catch (_: NullPointerException) { }` and verify behavior via `Mockito.verify()` calls instead of asserting the return value.
- **Files modified:** src/test/kotlin/com/six2dez/burp/aiagent/scanner/AiPassiveScanCheckTest.kt
- **Verification:** Both tests pass green (2/2).
- **Committed in:** 50f32a3 (Task 2 commit)

---

**Total deviations:** 4 auto-fixed (all Rule 1 bugs)
**Impact on plan:** All auto-fixes essential for compilation and test correctness. No scope creep.

## Issues Encountered

- Burp Montoya API static factory methods (`AuditResult.auditResult()`, `AuditIssue.auditIssue()`) require the Burp runtime to be initialized. Unit tests cannot call these factories directly. Resolved by catching the NPE and verifying method interactions instead.

## Known Stubs

None — `AiPassiveScanCheck.doCheck()` is fully implemented. The async AI analysis path flows through the existing `PassiveAiScanner.analyzeManually()` → `doAnalysis()` → AI call → `api.siteMap().add(issue)` chain, which is a fully implemented production path.

## Threat Flags

None — no new network endpoints, auth paths, or schema changes at trust boundaries. The `PassiveScanCheck.doCheck()` implementation follows the existing async executor pattern already established in `PassiveAiScanner`. The Community-safe try/catch ensures no new failure modes are introduced for Community users.

## Self-Check: PASSED

- `src/main/kotlin/com/six2dez/burp/aiagent/scanner/AiPassiveScanCheck.kt` — FOUND (doCheck, consolidateIssues, mapSeverity)
- `grep -c "registerResponseHandler" PassiveAiScanner.kt` = 0 — VERIFIED
- `grep -n "enqueueForScanCheck\|localChecks" PassiveAiScanner.kt` — both methods present at correct lines
- `grep -n "registerPassiveScanCheck\|setAiToolDependencies\|registerScanCheck" App.kt` — all three present (lines 79, 158, 170)
- Commits 9febcff, 50f32a3 — verified in git log
- `./gradlew compileKotlin --quiet` — no output (clean)
- `./gradlew test -PexcludeHeavyTests=true` — BUILD SUCCESSFUL, 263 tests, 0 failures

---
*Phase: 08-bapp-store-resubmission-mcp-pivot-to-extension-native-tools-*
*Completed: 2026-05-29*
