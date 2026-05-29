---
phase: 10-mcp-tools-tab-redesign
plan: "01"
subsystem: ui

tags: [kotlin, swing-free, mcp, tools-tab, model, junit5]

requires:
  - phase: 09-design-system-foundation
    provides: BadgeStyle enum in Components.kt — used directly by McpToolTabModel.badgeStyle()
  - phase: 08-bapp-store-resubmission
    provides: nativeTool field on McpToolDescriptor and McpToolCatalog.available() — the data model McpToolTabModel partitions

provides:
  - McpToolTabModel object (groupTools, badgeStyle, filterPredicate, bulkToggleTargets, categoryGroups)
  - ToolGrouping data class
  - McpToolTabModelTest (15 tests, all green)

affects:
  - 10-02-PLAN (Swing rebuild consumes McpToolTabModel directly)

tech-stack:
  added: []
  patterns:
    - "Pure-model extraction: UI logic separated from Swing layer into a zero-dependency object, mirroring Phase 3's CustomPromptDefinition.Companion pattern"

key-files:
  created:
    - src/main/kotlin/com/six2dez/burp/aiagent/ui/McpToolTabModel.kt
    - src/test/kotlin/com/six2dez/burp/aiagent/ui/McpToolTabModelTest.kt
  modified: []

key-decisions:
  - "McpToolTabModel is an object (not a class) — all helpers are stateless functions; no constructor injection needed"
  - "categoryGroups returns LinkedHashMap preserving sorted-by-key insertion order so caller iterates alphabetical categories without re-sorting"
  - "bulkToggleTargets receives disabledIds as Set<String> (not JCheckBox references) so Swing state never leaks into the model"
  - "filterPredicate trims query before isEmpty check — whitespace-only query is treated as blank (matches all)"

requirements-completed:
  - UI-03
  - UI-04
  - UI-05
  - UI-07

duration: 8min
completed: 2026-05-29
---

# Phase 10 Plan 01: McpToolTabModel (pure model extraction) Summary

**Swing-free McpToolTabModel object with five pure helpers (groupTools/badgeStyle/filterPredicate/bulkToggleTargets/categoryGroups) and 15 JUnit 5 tests, locking UI-03/04/05 semantics before the Swing rebuild in Plan 02.**

## Performance

- **Duration:** ~8 min
- **Started:** 2026-05-29T13:05:33Z
- **Completed:** 2026-05-29T13:13:00Z
- **Tasks:** 2
- **Files modified:** 2

## Accomplishments

- Created `McpToolTabModel.kt` with five pure computation helpers and zero Swing imports
- Created `McpToolTabModelTest.kt` with 15 `@Test` methods covering all helpers (exceeds plan requirement of >= 14)
- Full `./gradlew test` suite passes with no regressions (262 prior tests + 15 new = all green)

## Task Commits

Each task was committed atomically:

1. **Task 1: Create McpToolTabModel with pure grouping/badge/filter/bulk-toggle helpers** - `68a735c` (feat)
2. **Task 2: Write McpToolTabModelTest — >= 14 tests covering all helpers** - `7b3a91a` (test)

**Plan metadata:** (docs commit below)

## Files Created/Modified

- `src/main/kotlin/com/six2dez/burp/aiagent/ui/McpToolTabModel.kt` — pure model: ToolGrouping data class + McpToolTabModel object with groupTools/badgeStyle/filterPredicate/bulkToggleTargets/categoryGroups
- `src/test/kotlin/com/six2dez/burp/aiagent/ui/McpToolTabModelTest.kt` — 15 JUnit 5 tests; no Swing dependency

## Decisions Made

- `McpToolTabModel` declared as `object` (singleton) — all five helpers are stateless; no constructor needed.
- `categoryGroups` returns `LinkedHashMap` to preserve sorted-key insertion order without requiring callers to re-sort.
- `bulkToggleTargets` receives `disabledIds: Set<String>` rather than Swing checkbox references — keeps the model Swing-free and easily testable.
- `filterPredicate` trims the query before the `isEmpty()` check so whitespace-only input matches all tools (consistent with blank-query behaviour).

## Deviations from Plan

None — plan executed exactly as written. One extra test (`bulkToggleTargets_allVisibleWhenQueryBlankAndNoDisabledIds`) added beyond the 14 prescribed to cover the "all tools visible, no restrictions" happy path explicitly; it does not conflict with any plan requirement.

## Issues Encountered

None.

## User Setup Required

None — no external service configuration required.

## Next Phase Readiness

- Plan 02 (Swing rebuild of `buildMcpToolsPanel()`) can import `McpToolTabModel` directly with no further changes to the model layer.
- All five helpers are tested and locked; the Swing layer is a thin shell over them.
- No blockers.

---
*Phase: 10-mcp-tools-tab-redesign*
*Completed: 2026-05-29*
