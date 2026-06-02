---
phase: 11-settings-tabs-theme-rollout
plan: "01"
subsystem: ui-panels
tags: [design-system, migration, swing, kotlin]
dependency_graph:
  requires: [09-design-system-foundation]
  provides: [BackendConfigPanel-design-system, PrivacyConfigPanel-design-system]
  affects: [SettingsPanel.kt (call-site fix deferred to 11-03)]
tech_stack:
  added: []
  patterns: [design-system-builders, DesignTokens, formGrid+addRowFull]
key_files:
  created: []
  modified:
    - src/main/kotlin/com/six2dez/burp/aiagent/ui/panels/BackendConfigPanel.kt
    - src/main/kotlin/com/six2dez/burp/aiagent/ui/panels/PrivacyConfigPanel.kt
decisions:
  - "BackendConfigPanel: private addRow/addButtonRow/addToggleRow/addVerticalFiller helpers replaced entirely with design-system addRowFull/addSpacerRow; no local layout logic remains"
  - "PrivacyConfigPanel: builder lambda constructor params removed; design-system builders imported directly; SettingsPanel.kt call-site fix is plan 11-03's responsibility"
  - "buildBurpAiPanel uses manual GridBagConstraints for the info JTextArea because it spans all 4 columns and addRowFull uses a 2-column label+field pattern; the row counter client property is incremented manually to stay compatible with subsequent addSpacerRow calls"
metrics:
  duration: "2 minutes"
  completed: "2026-06-02"
  tasks_completed: 2
  files_modified: 2
---

# Phase 11 Plan 01: BackendConfigPanel + PrivacyConfigPanel Design System Migration Summary

**One-liner:** Replaced all private layout helpers and UiTheme references in BackendConfigPanel with design-system formGrid/addRowFull builders; removed PrivacyConfigPanel's builder-lambda constructor params in favour of direct imports from the design module.

## Tasks Completed

| Task | Description | Commit | Files |
|------|-------------|--------|-------|
| 1 | Migrate BackendConfigPanel to design-system builders | 4c8bc2a | BackendConfigPanel.kt |
| 2 | Migrate PrivacyConfigPanel to design-system builders | 092019c | PrivacyConfigPanel.kt |

## Verification Results

### Compile check

Expected outcome per cross-plan compile note: `./gradlew :compileKotlin` fails only inside `SettingsPanel.kt` at lines 1613–1616 (the `PrivacyConfigPanel(...)` constructor call site still passes the now-removed named arguments `sectionPanel`, `formGrid`, `addRowFull`, `addSpacerRow`). This failure is intentional and owned by plan 11-03.

```
e: SettingsPanel.kt:1613:13 No parameter with name 'sectionPanel' found.
e: SettingsPanel.kt:1614:13 No parameter with name 'formGrid' found.
e: SettingsPanel.kt:1615:13 No parameter with name 'addRowFull' found.
e: SettingsPanel.kt:1616:13 No parameter with name 'addSpacerRow' found.
```

Zero errors in BackendConfigPanel.kt or PrivacyConfigPanel.kt.

### Grep checks

```
grep UiTheme.Colors|UiTheme.Typography|Color(0x|Font( in both files → 0 matches (PASS)
grep -c DesignTokens BackendConfigPanel.kt → 24 (PASS)
grep -c DesignTokens PrivacyConfigPanel.kt → 2 (PASS)
```

## Deviations from Plan

### Auto-fixed Issues

None — plan executed exactly as written.

### Implementation Notes

**buildBurpAiPanel special case:** The Burp AI info JTextArea spans all 4 grid columns (`gridwidth = 4`) which is incompatible with `addRowFull`'s 2-column label+field pattern. The panel uses manual GridBagConstraints for this one component and increments the `row` client property directly. All subsequent rows use `addSpacerRow` normally. This is consistent with the design-system contract (the `row` client property is the authoritative counter).

**PrivacyConfigPanel addSpacerRow(grid, 4):** The spacer height literal `4` equals `DesignTokens.Spacing.xs`. The original code used numeric `4` and the plan did not mandate changing these to symbolic constants — they are preserved as-is to match the original behavior exactly.

## Known Stubs

None — both panels wire real data; no placeholders introduced.

## Threat Flags

None — pure Swing layout refactor; no new network endpoints, auth paths, or file access patterns introduced.

## Expected Deferred Work

- **SettingsPanel.kt compile errors** — 4 named-argument errors at line 1613–1616 are expected and will be resolved by plan 11-03 (single owner of SettingsPanel.kt).
- **Full test run** — deferred to plan 11-03 after SettingsPanel wiring is complete (per plan success criteria: "full test run deferred to 11-03").

## Self-Check: PASSED

- FOUND: BackendConfigPanel.kt
- FOUND: PrivacyConfigPanel.kt
- FOUND: 11-01-SUMMARY.md
- FOUND commit 4c8bc2a: feat(11-01): migrate BackendConfigPanel to design-system builders
- FOUND commit 092019c: feat(11-01): migrate PrivacyConfigPanel to design-system builders
