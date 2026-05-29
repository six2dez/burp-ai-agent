---
phase: 09-design-system-foundation
plan: 02
subsystem: ui
tags: [swing, design-components, component-builders, headless-tests, badge, form-grid]

# Dependency graph
requires:
  - phase: 09-01
    provides: "DesignTokens.kt — Spacing/Typography/Colors token contract"
provides:
  - "Components.kt — 11 public builder functions + BadgeStyle enum + applyFieldStyle/applyAreaStyle (13 public symbols)"
  - "DesignComponentsTest.kt — 16 headless JUnit 5 tests (T1-T16 all green, T1 satisfies UI-SPEC SC5)"
affects: [10-mcp-tools-tab-redesign, 11-settings-tabs-theme-rollout]

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "Top-level Kotlin functions as public API: all 11 builders are package-level (not inside object) for import-as-static ergonomics in Phase 10/11"
    - "Anonymous JLabel subclass for toolBadge: paintComponent overrides fillRoundRect with antialias — no extra class file name exposed"
    - "isSmallComponent predicate: JSpinner/JComboBox/JCheckBox/ToggleSwitch/JTextField<=20col -> anchor=WEST, fill=NONE; else fill=HORIZONTAL"
    - "nextRow helper: file-private fun using JPanel.getClientProperty(row) counter — same pattern as SettingsPanel private helper"
    - "helpText optional param: non-null adds a third help-label row to formGrid spanning columns 1-3, insets(0,0,Spacing.xs,0)"
    - "No Color/Font literals in builder bodies: all tokens from DesignTokens.Colors.*/Typography.*/Spacing.* — verified by grep check"

key-files:
  created:
    - src/main/kotlin/com/six2dez/burp/aiagent/ui/design/Components.kt
    - src/test/kotlin/com/six2dez/burp/aiagent/ui/design/DesignComponentsTest.kt
  modified: []

key-decisions:
  - "16 tests (not 15): added T5 (addRowFull_withoutHelpText_doesNotAddExtraComponent) to explicitly cover the null-helpText path from the behavior spec; all 16 pass"
  - "Task 2 (full-suite regression) required no code changes — Components.kt is additive; existing panels untouched"
  - "toolBadge uses anonymous JLabel subclass (not a named inner class) to keep the API surface minimal; isOpaque=false prevents Swing default rect fill behind the pill"
  - "buildTabPanel sections gap is Spacing.sm (8px) — matches SettingsPanel private helper rigid-area value"
  - "sectionPanel NORTH component retrieved via BorderLayout.getLayoutComponent(NORTH) in test T8 — more reliable than getComponent(0) under varying add order"

patterns-established:
  - "Public component builder module: top-level Kotlin funs in ui/design/Components.kt; importable from Phase 10/11 without object qualification"
  - "Token-driven headless test pattern: assertEquals(DesignTokens.Colors.X, component.property) — tests verify both component behavior and token delegation simultaneously"

requirements-completed: [UI-01]

# Metrics
duration: 3min
completed: 2026-05-29
---

# Phase 09 Plan 02: Design System Foundation — Components Summary

**Created ui/design/Components.kt with 11 builder functions + BadgeStyle enum + applyFieldStyle/applyAreaStyle (13 public symbols), all token-driven from DesignTokens; 16 headless tests green (T1 satisfies UI-SPEC SC5); full 284-test suite green with 0 regressions.**

## Performance

- **Duration:** ~3 min
- **Started:** 2026-05-29T11:40:17Z
- **Completed:** 2026-05-29T11:43:16Z
- **Tasks:** 2
- **Files modified:** 2

## Accomplishments

- Created `ui/design/Components.kt` with all 13 public symbols required by UI-SPEC:
  `formGrid`, `addRowFull` (+ optional helpText), `addRowPair`, `addSpacerRow`, `sectionPanel`,
  `helpLabel`, `primaryButton`, `secondaryButton`, `buildTabPanel`, `toolBadge`, `BadgeStyle`,
  `applyFieldStyle`, `applyAreaStyle`. Zero inline Color() or Font() literals.
- `toolBadge` renders as a rounded-rect pill via anonymous JLabel subclass overriding
  `paintComponent` with `fillRoundRect(0,0,w,h,6,6)` + antialias hint; `isOpaque=false`
  prevents the default rectangular background from leaking through.
- Created `DesignComponentsTest.kt` with 16 headless JUnit 5 tests (T1-T16) all green:
  formGrid non-null SC5 (T1), expand/no-expand field detection (T2-T3), helpText row (T4-T5),
  addRowPair 4-component count (T6), spacer count (T7), sectionPanel BorderLayout (T8),
  helpLabel tokens (T9), primaryButton/secondaryButton color (T10-T11), buildTabPanel (T12),
  toolBadge NATIVE/FULL foreground (T13-T14), applyFieldStyle (T15), applyAreaStyle (T16).
- Full-suite regression (Task 2): 284 tests, 0 failures — all pre-existing tests pass alongside
  DesignTokensTest (7) and DesignComponentsTest (16). UI-07 no-regression criterion satisfied.
- Phase 9 deliverable complete: DesignTokens + Components module ready for Phases 10 and 11.

## Task Commits

1. **Task 1: Create Components.kt + DesignComponentsTest.kt together** — `82ff0ac` (feat)
2. **Task 2: Full-suite regression check (UI-07)** — no new commit (verification-only; `82ff0ac` caused all 284 tests to pass)

## Files Created/Modified

- `src/main/kotlin/com/six2dez/burp/aiagent/ui/design/Components.kt` — 13 public builder symbols; token-driven from DesignTokens
- `src/test/kotlin/com/six2dez/burp/aiagent/ui/design/DesignComponentsTest.kt` — 16 headless JUnit 5 tests (T1-T16 all green)

## Decisions Made

- 16 tests written (plan specified 15 as minimum; T5 added for explicit null-helpText coverage).
- toolBadge uses anonymous JLabel subclass for minimal API surface.
- Task 2 required zero code changes — Components.kt is purely additive; SettingsPanel private helpers untouched.
- sectionPanel header retrieved via `BorderLayout.getLayoutComponent(NORTH)` (more robust than `getComponent(0)` index).

## Deviations from Plan

### Auto-added coverage

**1. [Rule 2 - Coverage] Added T5: addRowFull_withoutHelpText_doesNotAddExtraComponent**
- **Found during:** Task 1 (DesignComponentsTest authoring)
- **Issue:** Plan behavior spec lists "addRowFull with helpText=null: no extra help row added" — plan T list had 15 entries but this specific negative case had no corresponding test
- **Fix:** Added T5 to explicitly assert componentCount==2 when helpText is null; plan's 15-test list becomes 16; all pass
- **Files modified:** DesignComponentsTest.kt

## Known Stubs

None — all builder functions are fully wired to DesignTokens; no placeholder or hardcoded values.

## Threat Flags

None — pure UI factory functions; no network, no IO, no user input, no PII. Threat register T-09-02 disposition: accept.

## Verification Results

- `./gradlew test --tests "*.DesignComponentsTest" -PexcludeHeavyTests=true` — 16/16 PASS
- `./gradlew test -PexcludeHeavyTests=true` — 284 total tests, 0 failures (UI-07 satisfied)
- Color literal check: `grep -v "0x..." Components.kt | grep "Color("` — only KDoc comments (CLEAN)
- Font literal check: `grep "Font(" Components.kt` — only KDoc comments (CLEAN)

## Self-Check: PASSED

- `src/main/kotlin/com/six2dez/burp/aiagent/ui/design/Components.kt` — FOUND
- `src/test/kotlin/com/six2dez/burp/aiagent/ui/design/DesignComponentsTest.kt` — FOUND
- Commit `82ff0ac` — FOUND (Task 1: feat)
