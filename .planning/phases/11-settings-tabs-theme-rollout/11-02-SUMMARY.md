---
phase: 11-settings-tabs-theme-rollout
plan: "02"
subsystem: ui-panels
tags: [design-system, migration, swing, kotlin, accordion, collapsible]
dependency_graph:
  requires: [09-design-system-foundation, 11-01]
  provides: [PassiveScanConfigPanel-design-system, ActiveScanConfigPanel-design-system, ActiveScanQueuePanel-design-system]
  affects: [SettingsPanel.kt (call-site fix deferred to 11-03)]
tech_stack:
  added: []
  patterns: [AccordionPanel-collapsible-sections, DesignTokens, formGrid+addRowFull+addRowPair]
key_files:
  created: []
  modified:
    - src/main/kotlin/com/six2dez/burp/aiagent/ui/panels/PassiveScanConfigPanel.kt
    - src/main/kotlin/com/six2dez/burp/aiagent/ui/panels/ActiveScanConfigPanel.kt
    - src/main/kotlin/com/six2dez/burp/aiagent/ui/panels/ActiveScanQueuePanel.kt
decisions:
  - "PassiveScanConfigPanel: 5 builder-lambda constructor params removed; 5 AccordionPanel sections added (A: Scanner control, B: Rate limiting & body caps, C: Dedup & prompt cache, D: Persistent cache, E: Context builder); A+B expanded by default, C/D/E collapsed"
  - "ActiveScanConfigPanel: 5 builder-lambda constructor params removed; 2 AccordionPanel sections added (A: Scanner control, B: Scan parameters); both expanded by default"
  - "ActiveScanConfigPanel: actionsPanel added as standalone addRowFull row rather than embedded in a statusBar BorderLayout to avoid Swing double-parent issues"
  - "ActiveScanQueuePanel: UiTheme.Colors.outlineVariant mapped to DesignTokens.Colors.borderSubtle (table grid color); UiTheme.Colors.outline mapped to DesignTokens.Colors.border"
  - "build() returns JPanel (BoxLayout Y_AXIS with AccordionPanel sections) rather than JScrollPane from buildTabPanel() — preserves ConfigPanel.build(): JPanel contract; SettingsPanel's outer buildTabPanel wraps the scroll pane"
  - "SettingsPanel.kt call-site cleanup for all 3 panels deferred to plan 11-03 (single owner of SettingsPanel.kt)"
metrics:
  duration: "8 minutes"
  completed: "2026-06-02"
  tasks_completed: 2
  files_modified: 3
---

# Phase 11 Plan 02: Scanner Panels Design-System Migration + Collapsible Sections Summary

**One-liner:** Migrated PassiveScanConfigPanel (~25 fields), ActiveScanConfigPanel, and ActiveScanQueuePanel to DesignTokens exclusively; restructured the two scanner config panels into AccordionPanel-wrapped collapsible sections (UI-06) for improved scannability.

## Tasks Completed

| Task | Description | Commit | Files |
|------|-------------|--------|-------|
| 1 | Migrate PassiveScanConfigPanel with 5 collapsible AccordionPanel sections | 1d6e53b | PassiveScanConfigPanel.kt |
| 2 | Migrate ActiveScanConfigPanel (2 sections) and ActiveScanQueuePanel (token swap) | 276c103 | ActiveScanConfigPanel.kt, ActiveScanQueuePanel.kt |

## Verification Results

### Compile check

Expected outcome per cross-plan compile note: `./gradlew :compileKotlin` fails only inside `SettingsPanel.kt`. Errors present are all named-argument/arity errors for constructor call sites that have not yet been updated (plan 11-03's responsibility):

```
e: SettingsPanel.kt:1613:13 No parameter with name 'sectionPanel' found.  [PrivacyConfigPanel — plan 11-01]
e: SettingsPanel.kt:1614:13 No parameter with name 'formGrid' found.       [PrivacyConfigPanel — plan 11-01]
e: SettingsPanel.kt:1615:13 No parameter with name 'addRowFull' found.     [PrivacyConfigPanel — plan 11-01]
e: SettingsPanel.kt:1616:13 No parameter with name 'addSpacerRow' found.   [PrivacyConfigPanel — plan 11-01]
e: SettingsPanel.kt:1630:13 No parameter with name 'sectionPanel' found.   [PassiveScanConfigPanel — this plan]
e: SettingsPanel.kt:1631:13 No parameter with name 'formGrid' found.       [PassiveScanConfigPanel — this plan]
e: SettingsPanel.kt:1632:13 No parameter with name 'addRowFull' found.     [PassiveScanConfigPanel — this plan]
e: SettingsPanel.kt:1633:13 No parameter with name 'addRowPair' found.     [PassiveScanConfigPanel — this plan]
e: SettingsPanel.kt:1634:13 No parameter with name 'addSpacerRow' found.   [PassiveScanConfigPanel — this plan]
e: SettingsPanel.kt:1960:13 No parameter with name 'sectionPanel' found.   [ActiveScanConfigPanel — this plan]
e: SettingsPanel.kt:1961:13 No parameter with name 'formGrid' found.       [ActiveScanConfigPanel — this plan]
e: SettingsPanel.kt:1962:13 No parameter with name 'addRowFull' found.     [ActiveScanConfigPanel — this plan]
e: SettingsPanel.kt:1963:13 No parameter with name 'addRowPair' found.     [ActiveScanConfigPanel — this plan]
e: SettingsPanel.kt:1964:13 No parameter with name 'addSpacerRow' found.   [ActiveScanConfigPanel — this plan]
```

Zero errors in PassiveScanConfigPanel.kt, ActiveScanConfigPanel.kt, or ActiveScanQueuePanel.kt.

### Grep checks

```
grep "UiTheme." in all 3 files → 0 matches (PASS)
grep -c "AccordionPanel" PassiveScanConfigPanel.kt → 6 (PASS: >= 5)
grep -c "AccordionPanel" ActiveScanConfigPanel.kt → 3 (PASS: >= 2)
grep -c "DesignTokens" PassiveScanConfigPanel.kt → 69 (PASS)
grep -c "DesignTokens" ActiveScanConfigPanel.kt → 59 (PASS)
grep -c "DesignTokens" ActiveScanQueuePanel.kt → 26 (PASS)
```

## Deviations from Plan

### Implementation Notes

**ConfigPanel.build() return type constraint:** The plan's instruction to "return that JScrollPane from build()" could not be followed literally because `ConfigPanel.build(): JPanel` and `JScrollPane` is not a subtype of `JPanel`. Instead, `build()` returns a `JPanel` with `BoxLayout.Y_AXIS` containing the AccordionPanel sections. SettingsPanel's own `buildTabPanel()` wraps the result in the outer scroll pane — this is the correct split of responsibilities.

**ActiveScanConfigPanel actionsPanel:** The original code had both a `statusLabel` row and a separate `actionsPanel` row in the flat grid. The plan's Section A spec listed `activeAiViewFindings, activeAiViewQueue, activeAiClearQueue, activeAiResetStats` as plain fields alongside the status label. The implementation keeps them as separate `addRowFull` entries in the grid rather than combining them in a `BorderLayout` statusBar (which would have caused a Swing double-parent issue if actionsPanel were also referenced independently).

**ActiveScanQueuePanel `outlineVariant` mapping:** The original used `UiTheme.Colors.outlineVariant` for the table grid color. DesignTokens does not have `outlineVariant` by that name — it maps to `DesignTokens.Colors.borderSubtle` (the accordion divider / section divider role). This is the correct semantic equivalent.

**EmptyBorder close button inset:** The original used `BorderFactory.createEmptyBorder(6, 12, 6, 12)`. Mapped to `EmptyBorder(Spacing.sm - 2, Spacing.md, Spacing.sm - 2, Spacing.md)` = `EmptyBorder(6, 12, 6, 12)` — arithmetic-identical to preserve button sizing.

## SettingsPanel.kt Compile Errors (Expected, Deferred to 11-03)

The following compile errors in SettingsPanel.kt are **expected and intentional**. They pre-existed from plan 11-01 and are extended by this plan. All will be resolved by plan 11-03 (sole owner of SettingsPanel.kt):

- Lines 1613-1616: `PrivacyConfigPanel(...)` call site — 4 removed lambda params (plan 11-01)
- Lines 1630-1634: `PassiveScanConfigPanel(...)` call site — 5 removed lambda params (this plan, Task 1)
- Lines 1960-1964: `ActiveScanConfigPanel(...)` call site — 5 removed lambda params (this plan, Task 2)

## Known Stubs

None — all panels wire real data; no placeholder text or empty data sources introduced.

## Threat Flags

None — pure Swing layout refactor; no new network endpoints, auth paths, file access patterns, or schema changes introduced.

## Self-Check: PASSED

- FOUND: PassiveScanConfigPanel.kt
- FOUND: ActiveScanConfigPanel.kt
- FOUND: ActiveScanQueuePanel.kt
- FOUND commit 1d6e53b: feat(11-02): migrate PassiveScanConfigPanel with collapsible AccordionPanel sections
- FOUND commit 276c103: feat(11-02): migrate ActiveScanConfigPanel and ActiveScanQueuePanel to design-system
