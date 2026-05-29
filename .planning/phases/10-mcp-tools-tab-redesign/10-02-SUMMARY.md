---
phase: 10-mcp-tools-tab-redesign
plan: "02"
subsystem: ui

tags: [kotlin, swing, mcp, tools-tab, redesign, design-system, phase9, flag-10-01]

requires:
  - phase: 10-mcp-tools-tab-redesign
    plan: "01"
    provides: McpToolTabModel (groupTools/badgeStyle/filterPredicate/bulkToggleTargets/categoryGroups)
  - phase: 09-design-system-foundation
    provides: Components.kt (sectionPanel/toolBadge/helpLabel/secondaryButton/buildTabPanel/applyFieldStyle/BadgeStyle)

provides:
  - Redesigned buildMcpToolsPanel() in SettingsPanel.kt returning JScrollPane
  - Two labelled sectionPanel sections: AI Tools and Montoya Tools
  - Per-row toolBadge pills, live-search JTextField, per-group bulk toggles
  - FLAG-10-01 updateUI() override on toolBadge JLabel for theme-switch correctness

affects:
  - 10-02 human visual-verify checkpoint (Task 2)

tech-stack:
  added: []
  patterns:
    - "Thin Swing shell over pure model: buildMcpToolsPanel() delegates all grouping/filter/badge logic to McpToolTabModel; zero raw Color/Font literals in the new function"
    - "Option B show/hide filter: DocumentListener calls applyFilter() which sets row.isVisible — no panel rebuild, no flicker"
    - "FLAG-10-01 updateUI() closure pattern: anonymous JLabel subclass in toolBadge() overrides updateUI() to reassign foreground from current DesignTokens on L&F change; paintComponent already re-reads background at paint time"

key-files:
  created: []
  modified:
    - src/main/kotlin/com/six2dez/burp/aiagent/ui/SettingsPanel.kt
    - src/main/kotlin/com/six2dez/burp/aiagent/ui/design/Components.kt

key-decisions:
  - "Used import alias `buildDesignTabPanel` for Phase 9's buildTabPanel to avoid shadowing SettingsPanel's private buildTabPanel(sections, border)"
  - "Unsafe checkbox gating (unsafeOnly + unsafe OFF + not allowlisted -> isEnabled=false) deferred to Phase 11; only proOnly tools are disabled at construction time per UI-07"
  - "Section separator implemented as an opaque=false JPanel with fixed preferredSize/maximumSize rather than Box.createRigidArea (which returns Component, not JComponent, incompatible with buildDesignTabPanel signature)"
  - "toolBadge updateUI() override resolves foreground from current DesignTokens; background is resolved at paintComponent time (reads current theme on every repaint)"

requirements-completed:
  - UI-03
  - UI-04
  - UI-05
  - UI-07

duration: 5min
completed: 2026-05-29
---

# Phase 10 Plan 02: buildMcpToolsPanel() Redesign (Swing Rebuild) Summary

**Rebuilt buildMcpToolsPanel() as a thin Swing shell over McpToolTabModel with two sectionPanel sections (AI Tools / Montoya Tools), per-row toolBadge pills, live search, per-group bulk toggles, AccordionPanel unsafe allowlist, and FLAG-10-01 updateUI() theme fix in Components.kt.**

## Performance

- **Duration:** ~5 min
- **Started:** 2026-05-29T13:11:07Z
- **Completed:** 2026-05-29T13:16:07Z
- **Tasks:** 2 (Task 1 complete; Task 2 = human visual-verify checkpoint — reached)
- **Files modified:** 2

## Accomplishments

- Replaced the flat 4-column GridLayout category-grid in `buildMcpToolsPanel()` with:
  - Two `sectionPanel` sections: "AI Tools (extension-native)" and "Montoya Tools (generic)"
  - Per-row `toolBadge` pills: native tools "Store + Full" (NATIVE, green tint), generic "Full only" (FULL, neutral)
  - Full-width `JTextField` with `DocumentListener` live search (Option B show/hide — no flicker)
  - Per-group "Enable all" / "Disable all" `secondaryButton` bars using `McpToolTabModel.bulkToggleTargets()`
  - Category sub-headers in Montoya section via `McpToolTabModel.categoryGroups()`; hidden when all tools filtered out
  - Empty-state labels for filter and store-build scenarios
  - `AccordionPanel("Unsafe tool allowlist", ...)` at bottom of Montoya section (initiallyExpanded=false)
- Preserved persistence maps (`mcpToolCheckboxes`, `mcpUnsafeApprovalCheckboxes`), `collectMcpToolToggles()`, `applyMcpToolToggles()`, and `updateUnsafeToolStates()` verbatim (UI-07)
- Removed old global `selectAll` / `deselectAll` JButton pair
- Zero `Color()` or `Font()` literals in new `buildMcpToolsPanel()`; all styling from `DesignTokens`/`Components`
- Changed return type from `JPanel` to `JScrollPane` (via `buildDesignTabPanel`; compatible with `BorderLayout.CENTER`)
- Added `FLAG-10-01` `updateUI()` override to `toolBadge()` anonymous JLabel in `Components.kt` so foreground re-resolves from current DesignTokens on Burp theme switch; background re-read in `paintComponent` already
- Full `./gradlew test` suite passes: 0 regressions (262 prior tests + 15 McpToolTabModelTest = all green)

## Task Commits

1. **Task 1: Rebuild buildMcpToolsPanel() on McpToolTabModel + Phase 9 design system** - `8ed9381` (feat)

## Files Created/Modified

- `src/main/kotlin/com/six2dez/burp/aiagent/ui/SettingsPanel.kt` — `buildMcpToolsPanel()` fully redesigned (lines 2175–2463); return type `JPanel` -> `JScrollPane`; new imports for `McpToolTabModel`, `AccordionPanel`, `BadgeStyle`, `DesignTokens`, `helpLabel`, `secondaryButton`, `toolBadge`, and `buildDesignTabPanel` alias
- `src/main/kotlin/com/six2dez/burp/aiagent/ui/design/Components.kt` — `toolBadge()` anonymous JLabel class: `paintComponent` reads bg color from current `DesignTokens` at paint time; new `updateUI()` override reapplies foreground (FLAG-10-01)

## Decisions Made

- Import alias `buildDesignTabPanel` for Phase 9's `buildTabPanel` to avoid shadowing SettingsPanel's private `buildTabPanel(sections, border)` overload.
- Section separator implemented as an opaque=false `JPanel` with fixed `preferredSize`/`maximumSize` — `Box.createRigidArea` returns `Component` which is incompatible with `buildDesignTabPanel`'s `List<JComponent>` parameter.
- Unsafe checkbox gating (UI-SPEC Checkbox Enable/Disable Rules: `unsafeOnly + unsafe OFF + not allowlisted -> isEnabled=false`) deferred to Phase 11 per plan instruction; only `proOnly` tools are disabled at construction time.
- `toolBadge` `updateUI()` override reads from `style` variable captured in the anonymous class closure — no field promotion needed; pattern matches the plan's prose description.

## Deviations from Plan

### Auto-fixed Issues

None — plan executed exactly as written.

### Deferred Items (Out of Scope)

**1. [Deferred — Phase 11] Unsafe checkbox gating (UI-SPEC Checkbox Enable/Disable Rules)**
- **Deferred per plan:** The UI-SPEC "Checkbox Enable/Disable Rules" (`unsafeOnly=true AND unsafe OFF AND NOT allowlisted -> isEnabled=false`) is intentionally NOT applied in this phase because it changes observable behavior. Checkboxes for unsafe-only tools start enabled per UI-07; gating belongs in Phase 11 or a dedicated follow-up.
- **Visual indicator rendered:** The "unsafe" label is still shown (visual only) for unsafe tools when unsafe mode is OFF and not allowlisted.

## Known Stubs

None — all tool rows are fully wired to the live `McpToolCatalog.available()` data, `mcpToolCheckboxes` registration, and `McpToolTabModel` helpers.

## Threat Flags

No new network endpoints, auth paths, file access patterns, or schema changes introduced. The redesign is display-layer only per threat model assessment in the plan.

## Issues Encountered

None.

## Next Phase Readiness

- Task 2 (human visual smoke-check) is the next required step — see checkpoint details below.
- After human approval, Phase 11 can proceed with further MCP settings enhancements.

---

## Self-Check

- [x] `src/main/kotlin/com/six2dez/burp/aiagent/ui/SettingsPanel.kt` modified and committed (8ed9381)
- [x] `src/main/kotlin/com/six2dez/burp/aiagent/ui/design/Components.kt` modified and committed (8ed9381)
- [x] `./gradlew test` exits 0
- [x] No `Color()` literals in `buildMcpToolsPanel()` (verified with grep)
- [x] `selectAll`/`deselectAll` buttons removed (verified with grep)
- [x] `buildMcpToolsPanel` definition + call site both present (lines 2175 and 646)
- [x] `mcpToolCheckboxes` populated at line 2222; `mcpUnsafeApprovalCheckboxes` at line 2394
- [x] `updateUnsafeToolStates()` intact at lines 2466–2509 (unchanged)

## Self-Check: PASSED

*Phase: 10-mcp-tools-tab-redesign*
*Plan: 02*
*Completed: 2026-05-29*
