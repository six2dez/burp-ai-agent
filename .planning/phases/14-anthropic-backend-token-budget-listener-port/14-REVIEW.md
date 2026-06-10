---
phase: 14-anthropic-backend-token-budget-listener-port
reviewed: 2026-06-10T21:00:00Z
depth: standard
iteration: 3
files_reviewed: 3
files_reviewed_list:
  - src/main/kotlin/com/six2dez/burp/aiagent/scanner/PassiveAiScanner.kt
  - src/main/kotlin/com/six2dez/burp/aiagent/ui/ChatPanel.kt
  - src/test/kotlin/com/six2dez/burp/aiagent/scanner/PassiveAiScannerBudgetPauseTest.kt
findings:
  critical: 0
  warning: 0
  info: 0
  total: 0
status: clean
---

> Iteration-3 residual (overclaiming WR-02 comment in ChatPanel.kt) resolved by the orchestrator with a zero-behavior comment fix; the cosmetic `used`-display staleness is documented and accepted (gate decision is authoritative). WR-03/WR-05 accepted/deferred (WR-05 → Phase 17 REL-03). Status: clean.

# Phase 14: Code Review Report (Iteration 3, final)

**Reviewed:** 2026-06-10T21:00:00Z
**Depth:** standard
**Files Reviewed:** 3
**Status:** issues_found

## Summary

Final iteration of the fix→review loop. Confirms the two iteration-2 fixes (WR-01 commit `57d16dd`,
WR-02 commit `7f82f74`) and runs a fresh defect scan of the 3 in-scope files. The targeted
`PassiveAiScannerBudgetPauseTest` class was executed during this review and passes (BUILD SUCCESSFUL).
The deferred WR-03/WR-05 and the 3 Info items from iteration 2 are accepted/out-of-scope and are NOT
re-raised as blockers.

**Fix (a) — WR-01, `manualScan` budget gate (commit 57d16dd): CONFIRMED CORRECT, no regression.**

- The new guard at `PassiveAiScanner.kt:557-560` returns 0 **before** any state mutation:
  `manualScanTotal` / `manualScanCompleted` / `manualScanInProgress` are set only afterward
  (lines 562-565), so a paused call leaves manual-scan progress untouched and submits nothing to the
  executor.
- It does **not** call `ScanKnowledgeBase.clear()` and does **not** flip the `enabled` AtomicBoolean —
  only `setEnabled(false)` does either (lines 343-345), and it is not invoked on this path. Chat stays
  usable. This matches the intended Pitfall-3 contract.
- The gate mirrors the `enqueueForScanCheck` analog (line 356).
- Both real callers tolerate the 0 return without error: `UiActions.kt:111-117` shows
  "Queued 0 request(s)…"; `McpTools.kt:2125-2126` returns "Queued 0 requests…". No NPE, no
  divide-by-count path on 0.
- Tests are adequate and pass: `manualScan_whenBudgetPaused_isNoOpAndReturnsZero` (return==0, no
  executor submit, `isEnabled()` still true) and `manualScan_whenNotPaused_queuesRequests` (return==2).

**Fix (b) — WR-02, ChatPanel banner single snapshot (commit 7f82f74): correct for its target, but the
new in-code comment overclaims.** `warn`/`cap` now come from one unified `s = getSettings()` instance
(`ChatPanel.kt:584-586`) fed to both the banner text and `passiveScanner.reconcileBudget(s)`,
eliminating the prior split-`getSettings()` read that could show a `cap` different from the decision
input. That is a genuine, correct improvement. The residual `used` double-read (WR-01 below) is the
already-deferred cosmetic WR-03 staleness window — not a new correctness defect; the gate's
pause/resume decision is unaffected.

**Fresh defect scan (all 3 files):** No new bugs, security issues (injection / path traversal /
secrets / unsafe deserialization), null-deref, off-by-one, or data-loss paths in the changed regions.
The `manualScan` `forEachIndexed` worker (try/finally completion accounting, lines 569-596), the
`reconcileBudget` / `reconcileBudgetAndLog` resume→pause edge logging (lines 85-106), and the EDT
banner block were each re-traced. Thread-safety is unchanged from iteration 2 (`AtomicBoolean` gate,
single-threaded scanner executor, ConcurrentHashMap-backed `TokenTracker`). The accepted WR-05
(429/5xx not via `recordFailure`, consistent with the OpenAiCompatible analog → Phase 17 REL-03) is
not re-raised.

## Warnings

### WR-01: WR-02 fix comment claims a single `currentSessionTokens()` read, but `used` is still read twice on the wired-scanner path

**File:** `src/main/kotlin/com/six2dez/burp/aiagent/ui/ChatPanel.kt:580-592`
**Issue:** The comment added by commit `7f82f74` states: *"capture warn/cap/used from a SINGLE
snapshot … no second getSettings()/currentSessionTokens() read that could skew the displayed cap/used
away from the decision input."* The `getSettings()` half of that claim is now true and correctly fixed.
The `currentSessionTokens()` half is **not**: the banner's displayed `used` is read at line 587
(`val used = BudgetGuard.currentSessionTokens()`), while the value that actually drives the gate state
is read a **second** time inside `passiveScanner.reconcileBudget(s)` →
`BudgetGuard.currentSessionTokens()` at `PassiveAiScanner.kt:88`. `currentSessionTokens()`
re-aggregates `TokenTracker.snapshot()` on each call (`BudgetGuard.kt:54-56`), so under a concurrent
`TokenTracker.record(...)` the printed `used` and the decision's `used` can differ by one record.

Severity is WARNING, not BLOCKER: this only affects the number rendered inside an already-correct
banner — the CAP/WARN/OFF gate decision is authoritative and unaffected — and it is exactly the
cosmetic staleness window triaged as the deferred WR-03. It is reported solely because the new comment
now asserts the opposite of what the code does, which is a maintenance trap for the next reader (and
because the fallback branch `?: BudgetGuard.evaluate(used, warn, cap)` at line 592 genuinely *does* use
the single `used`, the inconsistency exists only on the wired path — an easy detail to misread).

**Fix:** Preferred, zero behavior change — tighten the comment to match reality:
```kotlin
// WR-02: warn/cap come from ONE settings snapshot (s) fed to both the banner and the gate, so the
// displayed thresholds match the decision input. NOTE: `used` for display is read separately from the
// gate's internal read (reconcileBudget re-reads currentSessionTokens), so the printed token count may
// lag the gate by one concurrent record — cosmetic only (WR-03); the CAP/WARN/OFF decision is authoritative.
```
Or, for exact display/decision agreement, add a `used`-accepting overload so one read feeds both, e.g.
`passiveScanner.reconcileBudget(s, used)` evaluating against the passed `used`, keeping a single
`currentSessionTokens()` call.

---

_Reviewed: 2026-06-10T21:00:00Z_
_Reviewer: Claude (gsd-code-reviewer)_
_Depth: standard (iteration 3, final)_
