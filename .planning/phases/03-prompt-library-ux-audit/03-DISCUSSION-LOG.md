# Phase 3 Discussion Log — Prompt Library UX Audit

**Session:** 2026-05-13
**Mode:** Default (interactive)
**Prior context loaded:** PROJECT.md, REQUIREMENTS.md (PROM-01..06), STATE.md, 02-CONTEXT.md, .planning/codebase/{CONVENTIONS,TESTING,STRUCTURE}.md
**Codebase scout:** CustomPromptDefinition.kt + companion, CustomPromptLibraryEditor.kt (private handlers), existing tests (CustomPromptFilterTest, CustomPromptLibraryTest)

---

## Gray Areas Surfaced

After loading prior decisions from Phase 1 (D-08 audit pattern) and Phase 2 (D-08 pure-function-extract decision), four gray areas remained:

1. PROM-03/04 export/import test strategy (handleImport/Export are private editor methods)
2. PROM-05 Move Up/Down boundary test (handleMove + hasNeighborOfSameStatus private)
3. Manual-smoke artefact scope (which UI wirings need maintainer eyeballs)
4. Plan split structure

User selected ALL FOUR for discussion.

---

## Area 1: PROM-03/04 Export/Import Test Strategy

**Q1.1: Test strategy for handleImport/Export merge + dedup logic**
- Options: (a) Extract pure helpers in CustomPromptDefinition companion (Recommended) | (b) Extract into new CustomPromptLibraryJson object | (c) Reflection on private methods | (d) Skip — weaken SC3 to round-trip via repo
- **User selected:** (a) Extract pure helpers in CustomPromptDefinition companion
- **Rationale:** Smallest production change; relocates logic to an already-existing companion holding filterForMenu/searchFilter/sortFavoritesFirst. Reflection ruled out as inconsistent with the Mockito-Kotlin-only test pattern in this codebase.
- **Decision captured as D-01.**

**Q1.2: Merge semantics for duplicate ids in incoming JSON**
- Options: (a) Last occurrence wins (Recommended) | (b) First occurrence wins | (c) Reject the import with an error
- **User selected:** (a) Last occurrence wins
- **Rationale:** Matches `incoming.associateBy { it.id }.values.toList()` — the standard Kotlin idiom. Aligns with how JSON parsers typically dedupe.
- **Decision captured as D-02.**

**Q1.3: File layout for extracted helpers + new tests**
- Options: (a) Helpers in companion; tests in new CustomPromptLibraryJsonTest.kt (Recommended) | (b) Helpers in companion; tests append to CustomPromptFilterTest.kt | (c) New CustomPromptLibraryJson object
- **User selected:** (a) New test file
- **Rationale:** Mirrors Phase 2 per-concern split between InjectionPointExtractorTest and ActiveScannerQueueModelTest. Keeps CustomPromptFilterTest.kt focused on filterForMenu.
- **Decision captured as D-03.**

---

## Area 2: PROM-05 Move Up/Down Boundary Test

**Q2.1: Testable API shape for handleMove + boundary clamp**
- Options: (a) Pure applyMove(library, index, delta): List<CustomPromptDefinition> in companion (Recommended) | (b) Split into canMove + performMove | (c) Reflection on handleMove and hasNeighborOfSameStatus
- **User selected:** (a) Pure applyMove
- **Rationale:** Single function carries both the move logic and the boundary clamp. Test by feeding library + index + delta, asserting the result. Consistent with GA1's extracted-helper choice.
- **Decision captured as D-04.**

**Q2.2: Boundary clamp semantics**
- Options: (a) Reject — return original library unchanged (Recommended) | (b) Clamp — swap to the last valid position within the same group
- **User selected:** (a) Reject
- **Rationale:** Simplest. Matches existing handleMove() short-circuit behaviour. The UI button is already disabled at boundaries by hasNeighborOfSameStatus(), so the only way to land here is programmatic / test invocation — pure rejection is sufficient and predictable.
- **Decision captured as D-05.**

---

## Area 3: Manual-Smoke Artefact (03-HUMAN-UAT.md)

**Q3.1: Which UI wirings need maintainer eyeballs?**
- Options (multi-select): (a) Search field live-filter (PROM-01) | (b) Favorite toggle pin + visual star (PROM-02) | (c) Move Up/Down button enable-disable at boundary (PROM-05) | (d) Export + Import JFileChooser round-trip (PROM-03/04)
- **User selected:** ALL FOUR
- **Rationale:** Each scenario exercises a Swing wiring (DocumentListener, ListCellRenderer, button-state binding, JFileChooser) that pure-function unit tests cannot reach. Mirrors Phase 2's six-scenario shape, scaled to Phase 3's UI surface.
- **Decision captured as D-09, D-10.**

---

## Area 4: Plan Split Structure

**Q4.1: How to split the audit work**
- Options: (a) 3 plans / 2 waves (Recommended) | (b) 4 plans / 3 waves | (c) 2 plans / 2 waves
- **User selected:** (a) 3 plans / 2 waves
- **Rationale:** Mirrors Phase 2 exactly (which executed cleanly). Plan 01 (pure-function tests, NO production change) and Plan 02 (extract+wire+test) are parallel-safe because they touch zero overlapping files. Plan 03 (HUMAN-UAT) depends on Plan 02's refactor being merged.
- **Decision captured as D-11, D-12.**

---

## Wrap-Up Check

After all four areas, the user agreed the decision set was complete. No additional gray areas surfaced.

---

## Deferred Ideas Captured

(Routed to `<deferred>` section of CONTEXT.md.)

- MCP tool invocation of custom prompts (already flagged in TESTING.md:293).
- `CustomPromptDialog` add/edit field validation tests.
- Per-tag visibility logic beyond `filterForMenu`.
- Drag-to-reorder via mouse.
- Bulk import of multiple JSON files.
- Conflict-resolution UI for merge.
- Stability of `sortFavoritesFirst` under stdlib changes (the new sort test guards this).

---

## Next Steps

1. `/gsd-plan-phase 3` — produces Plan 01 (PROM-01/02/06 pure tests), Plan 02 (extract+wire+test PROM-03/04/05), Plan 03 (HUMAN-UAT scaffold).
2. `/gsd-execute-phase 3` — 2 waves: Wave 1 parallel (01 + 02), Wave 2 serial (03 after 02).
