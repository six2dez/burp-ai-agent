---
phase: 09-design-system-foundation
plan: 01
subsystem: ui
tags: [swing, design-tokens, uimanager, typography, colors, spacing, headless-tests]

# Dependency graph
requires:
  - phase: none
    provides: "UiTheme.kt (existing) — UIManager-based color and typography patterns"
provides:
  - "DesignTokens.kt — canonical Spacing (7 constants), Typography (5 roles), Colors (15 tokens), isDarkTheme"
  - "DesignTokensTest.kt — 7 headless JUnit 5 tests (spacing, dark/light flip, re-resolution, typography, no-throw)"
  - "UiTheme.kt — unchanged behavior; KDoc shim comments added for Phase 11 migration guidance"
affects: [10-mcp-tools-tab-redesign, 11-settings-tabs-theme-rollout, 09-02]

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "Computed-get UIManager resolution: all color/font tokens are `get` properties — never cached — so they track L&F switches automatically"
    - "Headless fallback font size 14 (SansSerif): matches UiTheme.kt to prevent cross-object font-size drift in CI"
    - "cardSurface FLAG-02 strategy: UIManager(Table.background) with surface-derived (-10 RGB) fallback"
    - "badgeNative FLAG-01 pattern: isDarkTheme branching (no UIManager key exists); solid alpha-blended approximation"
    - "No Color() literals in primary resolution paths; fallbacks only after ?: operators (except documented FLAG-01/02)"

key-files:
  created:
    - src/main/kotlin/com/six2dez/burp/aiagent/ui/design/DesignTokens.kt
    - src/test/kotlin/com/six2dez/burp/aiagent/ui/design/DesignTokensTest.kt
  modified:
    - src/main/kotlin/com/six2dez/burp/aiagent/ui/UiTheme.kt

key-decisions:
  - "UiTheme.kt retained as legacy shim (KDoc-only change): Phase 11 will align naming (outline→border, statusRunning→statusSuccess, etc.) once all call sites are migrated"
  - "SC5 (formGrid non-null check) deferred to DesignComponentsTest in Plan 02 — formGrid() lives in Components.kt, not DesignTokens.kt"
  - "Spacing.md = 12 kept as intentional multiple-of-4 step per UI-SPEC note (label→field horizontal gaps); not forced to 8 or 16"
  - "badgeNative uses Color(0x1E3A2C)/Color(0xE8F5EE) solid approximation (FLAG-01); Swing cannot compose CSS opacity"

patterns-established:
  - "UIManager computed-get pattern: use `val foo: Color get() = UIManager.getColor(key) ?: fallback` — never cache L&F-dependent values"
  - "Headless-safe test pattern: save/restore UIManager.put in try/finally or @AfterEach; no @Suppress needed"
  - "Token naming split: DesignTokens uses canonical UI-SPEC names; UiTheme keeps legacy names until Phase 11 alignment"

requirements-completed: [UI-01]

# Metrics
duration: 3min
completed: 2026-05-29
---

# Phase 09 Plan 01: Design System Foundation — DesignTokens Summary

**Established the immutable token contract for Phase 9: DesignTokens.kt with 7 spacing constants, 5 typography roles, 15 UIManager-backed color tokens, and 7 headless passing tests; UiTheme.kt preserved unchanged as a legacy shim.**

## Performance

- **Duration:** 3 min
- **Started:** 2026-05-29T11:32:19Z
- **Completed:** 2026-05-29T11:35:20Z
- **Tasks:** 2
- **Files modified:** 3

## Accomplishments

- Created `ui/design/DesignTokens.kt` with full UI-SPEC contract: `Spacing` (7 constants + 4 Insets),
  `Typography` (5 computed-get roles from UIManager base font), `Colors` (15 computed-get tokens from
  UIManager keys with documented fallbacks), and `isDarkTheme` (luminance < 0.5 identical to UiTheme)
- Created `DesignTokensTest.kt` with 7 headless JUnit 5 tests (T1-T7) all green: spacing multiples-of-4,
  color-role non-null, isDarkTheme light/dark flip, computed-get re-resolution after UIManager change,
  typography derivation (bold/size assertions), headless no-throw
- Updated `UiTheme.kt` with KDoc shim comments mapping legacy names to canonical DesignTokens names;
  zero behavior change; all 268 tests pass (261 pre-existing + 7 new); no regressions

## Task Commits

1. **Task 1: Create DesignTokens.kt + DesignTokensTest.kt together** - `9d7a8da` (feat)
2. **Task 2: Update UiTheme.kt shim + full-suite regression check** - `314f6a3` (chore)

## Files Created/Modified

- `src/main/kotlin/com/six2dez/burp/aiagent/ui/design/DesignTokens.kt` — New design token contract: Spacing, Typography, Colors, isDarkTheme
- `src/test/kotlin/com/six2dez/burp/aiagent/ui/design/DesignTokensTest.kt` — 7 headless JUnit 5 tests (T1-T7 all green)
- `src/main/kotlin/com/six2dez/burp/aiagent/ui/UiTheme.kt` — KDoc shim comments added (no behavior change)

## Decisions Made

- UiTheme.kt retained as legacy shim with KDoc-only change: Phase 11 will align naming
  (outline→border, statusRunning→statusSuccess, etc.) once all call sites are migrated. Changing
  now would require updating 7+ consumer files atomically — too much scope for Plan 01.
- SC5 (formGrid non-null check) intentionally deferred to DesignComponentsTest in Plan 02.
  `formGrid()` lives in Components.kt (to be created in Plan 02), not DesignTokens.kt.
- Spacing.md = 12 kept as intentional multiple-of-4 step per UI-SPEC note (Tailwind spacing-3 / Material 12dp).
- `badgeNative` uses solid color approximation (FLAG-01): Swing has no CSS opacity on solid panels.

## Deviations from Plan

None — plan executed exactly as written.

## Known Stubs

None — DesignTokens.kt is fully wired to UIManager; no placeholder values exist in the implementation.

## Threat Flags

None — pure Kotlin/Swing module; reads only JVM-internal UIManager defaults; no network, no user input, no PII.

## Verification Results

- `./gradlew test --tests "*.DesignTokensTest" -PexcludeHeavyTests=true` — 7/7 PASS
- `./gradlew test -PexcludeHeavyTests=true` — 268 total tests, 0 failures
- Color literal check: `grep -v "?:" DesignTokens.kt | grep "Color(0x"` — only FLAG-01 `badgeNative` (documented exception; no UIManager key exists); CLEAN on primary resolution paths

## Self-Check: PASSED

- `src/main/kotlin/com/six2dez/burp/aiagent/ui/design/DesignTokens.kt` — FOUND
- `src/test/kotlin/com/six2dez/burp/aiagent/ui/design/DesignTokensTest.kt` — FOUND
- `src/main/kotlin/com/six2dez/burp/aiagent/ui/UiTheme.kt` — FOUND (modified)
- Commit `9d7a8da` — FOUND (Task 1)
- Commit `314f6a3` — FOUND (Task 2)
