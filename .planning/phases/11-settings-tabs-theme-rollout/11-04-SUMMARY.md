---
phase: 11-settings-tabs-theme-rollout
plan: 04
subsystem: ui
tags: [swing, design-tokens, DesignTokens, SettingsPanel, theme, light-dark]

# Dependency graph
requires:
  - phase: 11-settings-tabs-theme-rollout
    provides: "Plans 01–03 migrated all panel files (BackendConfigPanel, PrivacyConfigPanel, PassiveScanConfigPanel, ActiveScanConfigPanel, PromptConfigPanel, CustomPromptsConfigPanel, HelpConfigPanel, McpConfigPanel) to the Phase 9 design system"
  - phase: 09-design-system-foundation
    provides: "DesignTokens (Spacing/Typography/Colors) + Components builders"
provides:
  - "SettingsPanel.kt fully migrated to DesignTokens — zero UiTheme.Colors/Typography references"
  - "All private builder helpers (sectionPanel, formGrid, addRowFull, addRowPair, addSpacerRow, buildTabPanel, nextRow) removed or replaced with shared design-module calls"
  - "No raw EmptyBorder int literals, Color(), or Font() constructors remain in SettingsPanel.kt"
  - "Human visual approval obtained: all tabs render correctly in both light and dark Burp themes"
  - "Two UI regressions identified during smoke-check and fixed in the same plan wave"
affects:
  - ui
  - settings
  - theme-rollout

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "Disabled field styling: keep background = inputBackground always; dim only the foreground on disable — consistent with password fields, theme-aware in both light and dark"
    - "Non-scrolling tab container: when a tab's content already provides its own JScrollPane (e.g. McpConfigPanel), wrap it in a plain BorderLayout JPanel (not buildTabPanel) to avoid double-scroll and wheel-event swallowing"

key-files:
  created: []
  modified:
    - src/main/kotlin/com/six2dez/burp/aiagent/ui/SettingsPanel.kt

key-decisions:
  - "Disabled field background: drop .darker() from inputBackground for disabled TLS keystore path — background stays full-brightness inputBackground, foreground dims; matches sibling password field and is theme-safe"
  - "Burp Integration tab scroll: replaced buildTabPanel() wrapping (which produced a double JScrollPane) with a plain BorderLayout container so McpConfigPanel's own JScrollPane is the sole scroll surface"

patterns-established:
  - "Disabled Swing field visual: background = inputBackground (not darker), foreground = onSurfaceVariant (dimmed) — Rule: match the disabled password-field pattern"
  - "Tab with embedded JScrollPane: use BorderLayout container, not buildTabPanel(), to avoid double-scroll conflict"

requirements-completed:
  - UI-02
  - UI-06
  - UI-07
  - UI-08

# Metrics
duration: ~35min
completed: 2026-06-02
---

# Phase 11 Plan 04: Settings Tabs + Theme Rollout — Final Cleanup Summary

**SettingsPanel.kt fully migrated to DesignTokens with zero UiTheme.Colors/Typography references, private helpers removed, and two UI regressions found and fixed during human smoke-check (disabled field dark background + double-scroll Burp Integration tab)**

## Performance

- **Duration:** ~35 min
- **Started:** 2026-06-02 (continuation from plans 01–03)
- **Completed:** 2026-06-02
- **Tasks:** 2 (1 auto + 1 human-verify checkpoint, approved after gap-fix commit)
- **Files modified:** 1

## Accomplishments

- SettingsPanel.kt cleaned to zero UiTheme.Colors/Typography references (~96 DesignTokens usages confirmed)
- All private builder helpers removed (sectionPanel, formGrid, addRowFull, addRowPair, addSpacerRow, buildTabPanel, nextRow)
- Last raw EmptyBorder int literal replaced with DesignTokens.Spacing constants
- Two visual regressions caught and fixed during the human smoke-check before sign-off (see Deviations)
- ./gradlew test green after both commits; shadowJar produced Custom-AI-Agent-full-0.7.0.jar

## Task Commits

Each task was committed atomically:

1. **Task 1: Remove private helpers and complete DesignTokens migration** - `ccad8c0` (fix)
2. **Task 2: Human-verify checkpoint — gap fixes committed before approval** - `2e5ac5a` (fix)

**Plan metadata:** _(docs commit — see final_commit below)_

## Files Created/Modified

- `src/main/kotlin/com/six2dez/burp/aiagent/ui/SettingsPanel.kt` — final design-system migration: private helpers removed, UiTheme refs eliminated, last raw Spacing literal replaced, two regressions fixed (disabled field background + Burp Integration double-scroll)

## Decisions Made

- Disabled field background: keep `inputBackground` as-is (not `.darker()`), dim only the foreground — matches the sibling `mcpKeystorePassword` JPasswordField pattern and is theme-aware in both light and dark Burp themes.
- Burp Integration tab scroll container: replaced `buildTabPanel()` wrapping with a plain `JPanel(BorderLayout())` so `McpConfigPanel`'s own `JScrollPane` (added in Phase 10) is the sole scroll surface; wheel events now work anywhere over the content.

## Deviations from Plan

### Auto-fixed Issues (found during human smoke-check, fixed before checkpoint approval)

**1. [Rule 1 - Bug] Disabled MCP TLS keystore path field rendered with dark background in light mode**
- **Found during:** Task 2 (human-verify checkpoint — smoke-check in light mode)
- **Issue:** `updateFieldStyle()` in SettingsPanel.kt called `DesignTokens.Colors.inputBackground.darker()` for the disabled field background. In light mode this produced a visually dark background that was jarring and inconsistent with the sibling `mcpKeystorePassword` JPasswordField (which keeps its background unchanged when disabled).
- **Fix:** Changed disabled branch to keep `background = DesignTokens.Colors.inputBackground`; only the foreground is dimmed to `DesignTokens.Colors.onSurfaceVariant`. Works correctly in both light and dark Burp themes.
- **Files modified:** `src/main/kotlin/com/six2dez/burp/aiagent/ui/SettingsPanel.kt`
- **Verification:** Human re-confirmed field renders light background in light mode when TLS is disabled
- **Committed in:** `2e5ac5a`

**2. [Rule 1 - Bug] "Burp Integration" tab mouse-wheel only scrolled near the scrollbar (double JScrollPane)**
- **Found during:** Task 2 (human-verify checkpoint — scroll interaction test)
- **Issue:** Plan 11-03 had wrapped `buildMcpToolsPanel()` (which already returns a `JScrollPane` from the Phase 10 redesign) inside `buildTabPanel()`. `buildTabPanel()` adds an outer `JScrollPane`, creating a nested double-scroll situation. Mouse-wheel events were consumed by the outer container and only worked near its scrollbar, not over the inner content.
- **Fix:** Changed `burpIntegrationTab` from `buildTabPanel(...)` to a plain `JPanel(BorderLayout())` with `background = DesignTokens.Colors.surface` and `Spacing.lg` inset, holding the section header in `NORTH` and `buildMcpToolsPanel()` filling `CENTER`. The inner `JScrollPane` is now the sole scroll surface; wheel scrolls anywhere — consistent with all sibling tabs.
- **Files modified:** `src/main/kotlin/com/six2dez/burp/aiagent/ui/SettingsPanel.kt`
- **Verification:** Human re-confirmed wheel scrolls anywhere over the Burp Integration tab content after fix
- **Committed in:** `2e5ac5a`

---

**Total deviations:** 2 auto-fixed ([Rule 1 - Bug] x2)
**Impact on plan:** Both fixes required for correct light-mode rendering and usable scroll UX. No scope creep; both fixes confined to SettingsPanel.kt.

## Issues Encountered

Human smoke-check surfaced two visual regressions not caught by automated tests (Swing rendering and mouse-event routing cannot be exercised headlessly). Both were fixed and re-verified before the human issued approval. No blockers remain.

## User Setup Required

None — no external service configuration required.

## Next Phase Readiness

- Phase 11 design-system rollout is complete across all settings tabs and the main SettingsPanel
- All 8 UI-* requirements (UI-01 through UI-08) are addressed across Phases 9, 10, and 11
- v0.8.0 UI/UX milestone work is ready for phase-level verification by the orchestrator
- No open regressions; ./gradlew test green; JAR builds cleanly

---
*Phase: 11-settings-tabs-theme-rollout*
*Completed: 2026-06-02*

## Self-Check: PASSED

- `ccad8c0` exists: confirmed via `git log --oneline --grep="11-04"`
- `2e5ac5a` exists: confirmed via `git show --stat 2e5ac5a` (SettingsPanel.kt, 19 insertions / 3 deletions)
- `11-04-SUMMARY.md` created at `.planning/phases/11-settings-tabs-theme-rollout/11-04-SUMMARY.md`
- Both commits reference only `SettingsPanel.kt` — no unintended file deletions
