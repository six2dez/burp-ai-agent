---
phase: 14-anthropic-backend-token-budget-listener-port
plan: 02
subsystem: util, scanner, ui
tags: [token-budget, budget-guard, passive-scanner, chat-banner, settings-ui]
dependency_graph:
  requires: [14-01 AgentSettings.tokenBudgetWarnThreshold/tokenBudgetHardCap, TokenTracker, PassiveAiScanner, SubtleNotice]
  provides: [BudgetGuard, budgetPaused gate, ChatPanel budget banner, Settings token-budget section]
  affects: [PassiveAiScanner, ChatPanel, MainTab, SettingsPanel, PassiveScanConfigPanel]
tech_stack:
  added: []
  patterns: [AWT-free pure decision object (SecretShapes analog), AtomicBoolean per-process gate, SubtleNotice banner reuse, TDD RED/GREEN cycle]
key_files:
  created:
    - src/main/kotlin/com/six2dez/burp/aiagent/util/BudgetGuard.kt
    - src/test/kotlin/com/six2dez/burp/aiagent/util/BudgetGuardTest.kt
    - src/test/kotlin/com/six2dez/burp/aiagent/scanner/PassiveAiScannerBudgetPauseTest.kt
  modified:
    - src/main/kotlin/com/six2dez/burp/aiagent/scanner/PassiveAiScanner.kt
    - src/main/kotlin/com/six2dez/burp/aiagent/ui/ChatPanel.kt
    - src/main/kotlin/com/six2dez/burp/aiagent/ui/MainTab.kt
    - src/main/kotlin/com/six2dez/burp/aiagent/ui/SettingsPanel.kt
    - src/main/kotlin/com/six2dez/burp/aiagent/ui/panels/PassiveScanConfigPanel.kt
decisions:
  - BudgetGuard is a Kotlin object (AWT-free) mirroring SecretShapes; ChatPanel renders enum, never encodes policy
  - budgetPaused uses a SEPARATE AtomicBoolean from enabled — setEnabled(false) clears ScanKnowledgeBase and flips the user toggle; setBudgetPaused(true) does neither (Pitfall 3)
  - passiveScanner injected into ChatPanel as nullable param with default null so all existing ChatPanel construction sites keep compiling without modification
  - Token budget Section F placed in PassiveScanConfigPanel as an AccordionPanel (collapsed by default) — cause/effect locality with the scanner it governs (FLAG-14-01)
metrics:
  duration: ~15 minutes
  completed: 2026-06-10T17:38:00Z
  tasks_completed: 3
  files_changed: 8
---

# Phase 14 Plan 02: Token Budget Guardrails Summary

Per-session token-budget guardrails: pure AWT-free `BudgetGuard` object returning `{OFF, WARN, CAP}` from combined session tokens vs two thresholds, a reversible `budgetPaused` gate on `PassiveAiScanner.enqueueForScanCheck`, a `SubtleNotice` WARN/RISK banner in `ChatPanel`, and a Token Budget section in Settings (inside PassiveScanConfigPanel).

## What Was Built

### BudgetGuard.kt (CREATE)

A Kotlin singleton object in `com.six2dez.burp.aiagent.util`, mirroring `SecretShapes.kt`:
- `enum class State { OFF, WARN, CAP }` — typed output, no side effects
- `evaluate(usedTokens, warnThreshold, hardCap): State` — pure decision: CAP takes precedence over WARN; threshold=0 → never fires (SC4c)
- `currentSessionTokens(): Long` — sums `inputTokensEstimated + outputTokensEstimated` across all `TokenTracker.snapshot()` entries
- AWT-free contract documented in KDoc; verified by test at compile time (no `java.awt`/`javax.swing` imports)

### PassiveAiScanner.kt (MODIFY)

`budgetPaused = AtomicBoolean(false)` declared adjacent to the existing `enabled` field (per-process, starts false — reversible by Burp restart or future UI action).

`setBudgetPaused(on: Boolean)` and `isBudgetPaused(): Boolean` public accessors added.

Gate in `enqueueForScanCheck`: `if (budgetPaused.get()) return` added as the second guard (after `enabled`, before `isBlockedByBurpAiGate`). Does NOT call `setEnabled(false)`, does NOT call `ScanKnowledgeBase.clear()` — Pitfall 3 fully avoided.

### ChatPanel.kt (MODIFY)

- `passiveScanner: PassiveAiScanner? = null` constructor parameter (nullable with default — FLAG-14-04 minimal diff; all existing construction sites continue to compile)
- `private val budgetNotice = SubtleNotice()` member (single instance, starts hidden)
- `chatContainer.add(budgetNotice, BorderLayout.NORTH)` above `CENTER`/`SOUTH`
- After `TokenTracker.record()` in `onComplete`: `SwingUtilities.invokeLater { ... }` evaluates `BudgetGuard.evaluate(used, warn, cap)` and dispatches:
  - `State.CAP`: `budgetNotice.setMessage(RISK, ...)` + `passiveScanner?.setBudgetPaused(true)`
  - `State.WARN`: `budgetNotice.setMessage(WARN, ...)`
  - `State.OFF`: `budgetNotice.hideNotice()`
- Uses `formatChars()` (the existing token formatter in the same file) for consistent display

### PassiveScanConfigPanel.kt (MODIFY)

Two new constructor params: `tokenBudgetWarnField: JTextField`, `tokenBudgetHardCapField: JTextField`.

Section F "Token budget" as a collapsed `AccordionPanel` at the bottom of the panel:
- "Warn threshold (tokens)" row
- "Hard cap (tokens)" row
- Help text row (caption-font label: "Warn shows a chat banner. The hard cap pauses passive scanning; chat stays usable.")
- `applyFieldStyle()` applied to both fields for consistent styling

### SettingsPanel.kt (MODIFY)

Two new field members initialized from loaded `AgentSettings`:
```kotlin
private val tokenBudgetWarnField = JTextField(if (settings.tokenBudgetWarnThreshold > 0) ... else "", 10)
private val tokenBudgetHardCapField = JTextField(if (settings.tokenBudgetHardCap > 0) ... else "", 10)
```

`currentSettings()`: `tokenBudgetWarnThreshold = tokenBudgetWarnField.text.trim().toIntOrNull()?.coerceAtLeast(0) ?: 0` (non-numeric → 0 = off; T-14-10 input validation).

`applySettingsToUi()`: both fields' text synced from `updated.*`.

Both fields passed to `PassiveScanConfigPanel` via the `passiveAiScannerSection()` call.

### MainTab.kt (MODIFY)

`passiveScanner = passiveAiScanner` threaded into `ChatPanel(...)` constructor.

### Tests (CREATE)

`BudgetGuardTest`: 9 tests covering SC4a (WARN/CAP/CAP-over-WARN precedence), SC4c (zero-threshold OFF, used=0 OFF, cap=0/warn-only), and `currentSessionTokens()` delegation.

`PassiveAiScannerBudgetPauseTest`: 5 tests covering SC4b (enqueue no-op when paused, executor task count unchanged; ScanKnowledgeBase not cleared; `isEnabled()` unchanged); plus `isBudgetPaused()` initial state false and enqueue-proceeds-when-not-paused.

## Deviations from Plan

None — plan executed exactly as written. The plan's "Open Question 2" (optional scanner-side budget flip) was intentionally skipped per the plan's "minimal viable per RESEARCH" guidance; the scanner-side check would require the settings in scope without widening the diff, and the primary flip is cleanly handled by ChatPanel.

## TDD Gate Compliance

| Gate | Commit | Status |
|------|--------|--------|
| RED — test files compile-fail on unresolved BudgetGuard / setBudgetPaused | 97b19fa | PASS |
| GREEN — BudgetGuard + gate implemented, all SC4 tests pass | 38d5727 | PASS |
| Task 3 — Settings + banner + MainTab wiring, full suite green | 9205832 | PASS |

## Verification Results

- `./gradlew test --tests "com.six2dez.burp.aiagent.util.BudgetGuardTest" --tests "com.six2dez.burp.aiagent.scanner.PassiveAiScannerBudgetPauseTest"` — SC4a/SC4b/SC4c: GREEN
- `./gradlew test` full suite — 376 tests, all GREEN
- `grep -nE "import (java\.awt|javax\.swing)" BudgetGuard.kt` — no output (AWT-free)
- `grep -n "if (budgetPaused.get()) return" PassiveAiScanner.kt` — line 318 (after enabled gate)
- Banner at NORTH confirmed; CAP path calls `setBudgetPaused(true)`; Section F "Token budget" in PassiveScanConfigPanel
- SC4 banner rendering (WARN/RISK visual) is a HUMAN-UAT step per 14-VALIDATION.md

## Known Stubs

None — all threshold fields persist and load correctly (declared and wired in 14-01's AgentSettings; consumed here). The budget guardrail is fully functional for interactive chat. The optional scanner-side flip (Open Question 2) deferred by design.

## Threat Flags

All T-14-07 through T-14-SC mitigations applied:
- T-14-07: `budgetPaused` gate at `enqueueForScanCheck` choke point — verified by test
- T-14-08: Separate `budgetPaused` AtomicBoolean, NOT `setEnabled(false)` — test asserts KB not cleared and `isEnabled()` unchanged
- T-14-09: Banner interpolates token counts only (`formatChars(used)`) — no request content
- T-14-10: `toIntOrNull()?.coerceAtLeast(0) ?: 0` in SettingsPanel; non-numeric/negative/empty → 0 (= off)
- T-14-11: Per-process session total, per design

## Self-Check: PASSED

Files verified:
- `src/main/kotlin/com/six2dez/burp/aiagent/util/BudgetGuard.kt` — FOUND
- `src/test/kotlin/com/six2dez/burp/aiagent/util/BudgetGuardTest.kt` — FOUND
- `src/test/kotlin/com/six2dez/burp/aiagent/scanner/PassiveAiScannerBudgetPauseTest.kt` — FOUND

Commits verified:
- 97b19fa (RED tests) — FOUND
- 38d5727 (GREEN implementation) — FOUND
- 9205832 (Settings + banner + MainTab) — FOUND
