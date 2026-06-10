---
phase: 14-anthropic-backend-token-budget-listener-port
fixed_at: 2026-06-10T18:30:00Z
review_path: .planning/phases/14-anthropic-backend-token-budget-listener-port/14-REVIEW.md
iteration: 2
findings_in_scope: 2
fixed: 2
skipped: 0
status: all_fixed
---

# Phase 14: Code Review Fix Report

**Fixed at:** 2026-06-10T18:30:00Z
**Source review:** .planning/phases/14-anthropic-backend-token-budget-listener-port/14-REVIEW.md
**Iteration:** 2

**Summary (iteration 2):**
- Findings in scope: 2 (both Warning tier — 0 Critical present)
- Fixed: 2 (WR-01, WR-02)
- Skipped: 0
- Info findings (IN-01, IN-02, IN-03): out of scope (`critical_warning`) — acknowledged, no change.

All 399 tests pass (`./gradlew test` → BUILD SUCCESSFUL, 0 failures, 0 errors), up from the
iteration-1 397-green baseline — the 2 new tests cover the manual-scan budget gate (no-op when
paused, queues when not paused). `BudgetGuard` remains AWT-free; the pause path still does NOT
clear `ScanKnowledgeBase` and does NOT flip the user's enabled toggle. SC2 (no OkHttp on the
Anthropic path) and SC3 (exact model-rejection string) are untouched, and the iteration-1
WR-01/WR-02 self-pause + reversible-unpause behavior is unchanged (still covered by its tests).

## Fixed Issues (Iteration 2)

### WR-01: Manual scan path bypasses the budget pause gate

**Files modified:** `src/main/kotlin/com/six2dez/burp/aiagent/scanner/PassiveAiScanner.kt`, `src/test/kotlin/com/six2dez/burp/aiagent/scanner/PassiveAiScannerBudgetPauseTest.kt`
**Commit:** 57d16dd
**Applied fix:** Mirrored the `enqueueForScanCheck` pause gate (`if (budgetPaused.get()) return`,
line ~356) at the top of `PassiveAiScanner.manualScan(requests, onProgress)`. When the hard cap is
paused, `manualScan` now logs `"[PassiveAiScanner] Manual scan skipped — token hard cap reached"`
and returns `0` without submitting any work to the executor — so a context-menu manual scan no
longer pushes session usage past the cap once the banner advertises "Passive scanning paused". This
matches the CAP-04 design intent (the hard cap pauses the passive scanner — manualScan is a
passive-scanner enqueue path) and is consistent with how the enqueue gate reports paused state. The
gate does NOT clear the KB or flip `isEnabled()` (verified). Returning `0` is the existing
zero-queue contract: both production callers handle a 0 count gracefully (`UiActions.kt:111` shows
"Queued 0 request(s)"; `McpTools.kt:2125` returns "Queued 0 requests"). Chat remains usable — only
scanner work (which manual SCAN is) pauses with the scanner. The `manualScan(requests, vulnClasses)`
overload on `ActiveAiScanner` is a different method on a different class and was intentionally not
touched. Two new tests prove the behavior: `manualScan_whenBudgetPaused_isNoOpAndReturnsZero`
(returns 0, no executor task submitted, `isEnabled()` stays true) and
`manualScan_whenNotPaused_queuesRequests` (queues all supplied requests when not paused).

### WR-02: ChatPanel banner numbers read separately from the state that drives the decision

**Files modified:** `src/main/kotlin/com/six2dez/burp/aiagent/ui/ChatPanel.kt`
**Commit:** 7f82f74
**Applied fix:** Captured a single settings snapshot (`val s = getSettings()`) inside the
`SwingUtilities.invokeLater` block and derived `warn`/`cap`/`used` from it, then fed that SAME `s`
instance to the decision call `passiveScanner?.reconcileBudget(s)`. Previously the block called
`getSettings()` twice (lines 580-581) plus a third `getSettings()` for the decision (line 586), so
the banner could interpolate a `cap`/`warn` from a different read than the one the gate evaluated
(e.g. a mid-flight settings edit landing between the reads). The displayed numbers now come from one
snapshot taken immediately adjacent to the decision call, eliminating the display-skew the review
flagged. This also resolves the cosmetic IN-02 (the duplicated/extra local reads in the
scanner-present branch are collapsed into the single snapshot). The test-only `BudgetGuard.evaluate`
elvis fallback (IN-03) is preserved for the no-scanner embedding path and now evaluates the same
captured `used`/`warn`/`cap`. The gate decision logic is unchanged — this is a display-input
consolidation, so it is a `fixed` (not a logic change requiring human re-verification). Note (per the
review's own caveat): `reconcileBudget` still re-reads `currentSessionTokens()` internally, so a
fully single-read guarantee would require a `reconcileBudget` overload accepting the pre-read totals;
the practical display-only skew — the concern WR-02 raised — is fixed. The remaining internal re-read
is the IN-01-adjacent territory and was not in scope. Verified by the full suite staying green (the
no-scanner ChatPanel banner path is exercised by existing tests; no behavioral change to the gate).

## Info Findings (acknowledged, out of scope)

The fix scope is `critical_warning`, so the three Info findings were not modified. Noting them for
the record:

- **IN-01** (`PassiveAiScanner.kt:100-106`): `reconcileBudgetAndLog` resume→pause edge detection is
  a non-atomic read-modify-read. Cannot occur today (single-threaded scanner executor; chat/settings
  call `reconcileBudget`, not `...AndLog`). Acknowledged, no change.
- **IN-02** (`ChatPanel.kt:580-587`): dead/duplicated local reads in the scanner-present branch.
  Effectively resolved as a side effect of the WR-02 fix (single snapshot reused for decision +
  display). Acknowledged.
- **IN-03** (`ChatPanel.kt:586-587`): the `?: BudgetGuard.evaluate(...)` fallback is
  production-dead (scanner is always injected at `MainTab.kt:110`); it is the documented tests /
  chat-only path. Acknowledged, no change.

---

## Iteration 1 history (summary)

Iteration 1 (`14-REVIEW.md` iteration 1, fixed 2026-06-10T18:02:51Z) addressed 5 in-scope Warnings:
**3 fixed, 2 skipped** (status: partial).

- **WR-01 (iter 1) — hard cap never enforced on the scanner-only path** — FIXED (commit 47d3dcc):
  added the shared budget-consultation point `PassiveAiScanner.reconcileBudget(settings)` +
  scanner-thread wrapper `reconcileBudgetAndLog` run after every scanner `TokenTracker.record` site
  (cache-hit, single-analysis, batch-flush), so a scanner-only run self-pauses at CAP. Chat routes
  through the SAME `reconcileBudget`. `BudgetGuard` left AWT-free.
- **WR-02 (iter 1) — pause was a one-way latch** — FIXED (commit 47d3dcc): `reconcileBudget` sets the
  gate on CAP and clears it on WARN/OFF (reversible); settings-apply (`applyAndSaveSettings`) calls
  `reconcileBudget(updated)` so raising/clearing the cap (cap=0 = unlimited) releases the pause
  without a Burp restart.
- **WR-04 (iter 1) — Anthropic accepted a blank API key** — FIXED (commit 4c40977):
  `AnthropicBackend.isAvailable() = anthropicApiKey.isNotBlank()` + new `"anthropic"` branch in
  `MainTab.validateBackendCommand` returning the empty-key / empty-model strings, removing the
  "Unsupported backend" fall-through.
- **WR-03 (iter 1) — banner only refreshes on a chat turn** — SKIPPED (known limitation): the
  *enforcement* gap it compounded is closed by the WR-01 fix; residual issue is purely cosmetic
  banner freshness during a chat-idle, scanner-heavy session. A timer/change-hook refresh was judged
  more than low-risk and out of scope.
- **WR-05 (iter 1) — 429/5xx not routed through circuit-breaker `recordFailure`** — SKIPPED: the
  `OpenAiCompatibleBackend` analog behaves identically (non-2xx → `onComplete(...)` + `return@submit`
  without `recordFailure`/retry); fixing Anthropic alone would diverge from the established pattern.
  Robustness gap, not a correctness bug. Better handled as a dedicated cross-backend task.

The iteration-2 re-review confirmed the three iteration-1 fixes are correct and introduced no
regressions; it then surfaced the two pre-existing gaps fixed above (manual-scan gate, banner
display-skew) that weaken the "Passive scanning paused" guarantee the banner advertises.

---

_Fixed: 2026-06-10T18:30:00Z_
_Fixer: Claude (gsd-code-fixer)_
_Iteration: 2_
