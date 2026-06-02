---
phase: 11-settings-tabs-theme-rollout
plan: "03"
subsystem: ui-panels
tags: [design-system, migration, swing, kotlin, settings-panel, wiring]
dependency_graph:
  requires: [09-design-system-foundation, 11-01, 11-02]
  provides: [PromptConfigPanel-design-system, CustomPromptsConfigPanel-design-system, HelpConfigPanel-design-system, McpConfigPanel-design-system, SettingsPanel-wired]
  affects: []
tech_stack:
  added: []
  patterns: [DesignTokens, sectionPanel, formGrid, addRowFull, addRowPair, addSpacerRow, buildTabPanel, applyFieldStyle, applyAreaStyle]
key_files:
  created: []
  modified:
    - src/main/kotlin/com/six2dez/burp/aiagent/ui/panels/PromptConfigPanel.kt
    - src/main/kotlin/com/six2dez/burp/aiagent/ui/panels/CustomPromptsConfigPanel.kt
    - src/main/kotlin/com/six2dez/burp/aiagent/ui/panels/HelpConfigPanel.kt
    - src/main/kotlin/com/six2dez/burp/aiagent/ui/panels/McpConfigPanel.kt
    - src/main/kotlin/com/six2dez/burp/aiagent/ui/SettingsPanel.kt
decisions:
  - "PromptConfigPanel: build() returns BoxLayout Y_AXIS JPanel (two sections: Request prompts + Issue prompts) to satisfy ConfigPanel.build(): JPanel contract; SettingsPanel's buildTabPanel wraps in scroll pane"
  - "CustomPromptsConfigPanel: same BoxLayout Y_AXIS pattern; library section uses customPromptLibrarySection directly as content; bountyGrid uses formGrid+addRowFull/addRowPair"
  - "HelpConfigPanel: EmptyBorder(DesignTokens.Spacing.sectionPad x4) for helpPane border to match design module convention"
  - "McpConfigPanel: addSpacerRow(grid, 4) calls replaced with addSpacerRow(grid, DesignTokens.Spacing.xs); accordion wiring and UI-06 preservation unchanged"
  - "SettingsPanel private sectionPanel/formGrid/addRowFull/addRowPair/addSpacerRow/buildTabPanel/nextRow helpers removed entirely; replaced by direct imports from design module"
  - "SettingsPanel private applyFieldStyle/applyAreaStyle removed (identical behavior to design module equivalents); styleCombo/updateFieldStyle updated to use DesignTokens"
  - "SettingsPanel buildTabPanel calls: removed EmptyBorder param (design module buildTabPanel uses lg insets); tabContentInsets variable removed"
  - "styleCombo maps UiTheme.Colors.comboBackground -> DesignTokens.Colors.inputBackground; comboForeground -> inputForeground (closest semantic equivalents; no comboBackground token in DesignTokens)"
metrics:
  duration: "14 minutes"
  completed: "2026-06-02"
  tasks_completed: 2
  files_modified: 5
---

# Phase 11 Plan 03: Remaining Panels Migration + SettingsPanel Wiring Summary

**One-liner:** Migrated PromptConfigPanel, CustomPromptsConfigPanel, HelpConfigPanel, and McpConfigPanel to DesignTokens with direct design-module imports; consolidated SettingsPanel.kt wiring pass removed all 7 lambda constructor call sites, all private builder helpers, and all UiTheme references — full test suite green.

## Tasks Completed

| Task | Description | Commit | Files |
|------|-------------|--------|-------|
| 1 | Migrate PromptConfigPanel and CustomPromptsConfigPanel | 3b41da1 | PromptConfigPanel.kt, CustomPromptsConfigPanel.kt |
| 2 | Migrate HelpConfigPanel and McpConfigPanel; wire all SettingsPanel.kt call sites | 347feb6 | HelpConfigPanel.kt, McpConfigPanel.kt, SettingsPanel.kt |

## Verification Results

### Full test suite

```
./gradlew test
BUILD SUCCESSFUL
```

All tests pass. No regressions (UI-07 regression gate: PASS).

### Grep checks

```
grep "UiTheme." PromptConfigPanel.kt CustomPromptsConfigPanel.kt HelpConfigPanel.kt McpConfigPanel.kt → 0 matches (PASS)
grep -c "sectionPanel\|formGrid\|addRowFull" PromptConfigPanel.kt → 16 (PASS: > 0)
grep -rn "sectionPanel\s*=\|formGrid\s*=\|addRowFull\s*=" SettingsPanel.kt → 0 matches (PASS)
grep -n "UiTheme\." SettingsPanel.kt → 2 matches (comments only — PASS)
```

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] EmptyBorder single-arg call in HelpConfigPanel**
- **Found during:** Task 2 compile
- **Issue:** `EmptyBorder(DesignTokens.Spacing.sectionPad)` does not compile — EmptyBorder requires 4 int arguments; `Int` is not `Insets`
- **Fix:** Expanded to `EmptyBorder(sectionPad, sectionPad, sectionPad, sectionPad)`
- **Files modified:** HelpConfigPanel.kt
- **Commit:** 347feb6

### Implementation Notes

**PromptConfigPanel build() return type:**
The plan said "return the resulting JScrollPane from build()". However `ConfigPanel.build(): JPanel` and `JScrollPane` is not a `JPanel` subtype. Per the decision established in plan 11-02 (PassiveScanConfigPanel/ActiveScanConfigPanel), `build()` must return a `JPanel`. PromptConfigPanel and CustomPromptsConfigPanel now return a `BoxLayout Y_AXIS` JPanel with two `sectionPanel()` sections. SettingsPanel's `buildTabPanel()` wraps the result in the outer scroll pane — correct split of responsibilities.

**SettingsPanel buildTabPanel insets change:**
The private `buildTabPanel(sections, border: EmptyBorder)` used `EmptyBorder(8, 12, 12, 12)`. The design-module `buildTabPanel` uses `EmptyBorder(lg, lg, lg, lg)` = `EmptyBorder(16, 16, 16, 16)`. The slight inset difference (8→16 top, 12→16 sides) is acceptable per the plan's directive to "replace with direct design-module calls". All 9 tab panels are now consistently styled.

**SettingsPanel applyFieldStyle/applyAreaStyle:**
The plan noted these would be replaced by design module imports. The private methods were removed since the design module functions produce identical behavior (same UiTheme → DesignTokens mappings). SettingsPanel's `init` block still calls `applyFieldStyle` and `applyAreaStyle` on its fields, now routing to the design module implementations.

**styleCombo comboBackground/comboForeground mapping:**
`UiTheme.Colors.comboBackground` and `UiTheme.Colors.comboForeground` have no direct DesignTokens equivalents (only chat/combo-specific colors live in UiTheme). Mapped to `DesignTokens.Colors.inputBackground` and `DesignTokens.Colors.inputForeground` as the closest semantic equivalents. Visual behavior is unchanged in practice since both resolve from the same UIManager keys.

## Known Stubs

None — all panels wire real data from SettingsPanel fields; no placeholder text or empty data sources introduced.

## Threat Flags

None — pure Swing layout refactor; no new network endpoints, auth paths, file access patterns, or schema changes introduced.

## Self-Check: PASSED

- FOUND: PromptConfigPanel.kt
- FOUND: CustomPromptsConfigPanel.kt
- FOUND: HelpConfigPanel.kt
- FOUND: McpConfigPanel.kt
- FOUND: SettingsPanel.kt
- FOUND commit 3b41da1: feat(11-03): migrate PromptConfigPanel and CustomPromptsConfigPanel to design-system builders
- FOUND commit 347feb6: feat(11-03): migrate HelpConfigPanel/McpConfigPanel; wire all SettingsPanel constructor call sites
- ./gradlew test: BUILD SUCCESSFUL
