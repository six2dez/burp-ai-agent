---
phase: 03-prompt-library-ux-audit
verified: 2026-05-13T15:00:00Z
status: human_needed
score: 4/5
overrides_applied: 0
human_verification:
  - test: "Search field live-filter — PROM-01"
    expected: "Type a substring into Settings > Prompt Templates search field; row set updates on every keystroke without lag. Clear the field; all rows return."
    why_human: "DocumentListener wiring to Swing table model cannot be exercised from JUnit without a running EDT; the pure filter logic (searchFilter) is unit-tested but the Swing callback chain requires manual confirmation."
  - test: "Favorite toggle + visual star — PROM-02"
    expected: "Select a non-favorite entry; click Star Favorite; entry jumps to top of table with visible star rendered by ListCellRenderer. Toggle off; entry returns to prior non-favorites position."
    why_human: "Swing ListCellRenderer visual output and JList row reorder are not exercisable from JUnit. isFavorite serialisation round-trip via Jackson is confirmed by unit test; the Swing rendering layer requires manual confirmation."
  - test: "Move Up/Down button enable/disable at boundary — PROM-05 (Swing layer)"
    expected: "Select last favorite; Move Down button disabled. Select first non-favorite; Move Up button disabled. Boundary is wired through hasNeighborOfSameStatus() in refreshButtons()."
    why_human: "Button enablement state is managed by Swing component wiring in refreshButtons(); the boundary-reject logic itself is covered by applyMoveReturnsOriginalWhenLastFavoriteMovesDown / applyMoveReturnsOriginalWhenFirstNonFavoriteMovesUp unit tests, but visual button state requires manual confirmation."
  - test: "Export + Import JFileChooser round-trip — PROM-03 + PROM-04 (Swing layer)"
    expected: "Click Export; save to .json; file is pretty-printed with favorites first. Click Import on same file; library unchanged. Inject duplicate ids into JSON; re-import; library deduplicates with last-occurring entry winning."
    why_human: "JFileChooser dialogs cannot be driven from JUnit. The underlying parseLibraryJson / mergeById / sortFavoritesFirst logic is fully unit-tested; the end-to-end JFileChooser dialog path requires manual confirmation."
---

# Phase 3: Prompt Library UX Audit — Verification Report

**Phase Goal:** The Settings -> Prompt Templates editor and right-click submenus correctly implement search, favorites, JSON import/export, and ordering invariants so users cannot get into a corrupted or surprising state.
**Verified:** 2026-05-13T15:00:00Z
**Status:** human_needed
**Re-verification:** No — initial verification

---

## Goal Achievement

### Observable Truths (Success Criteria)

| # | Truth | Status | Evidence |
|---|-------|--------|----------|
| 1 | Live, case-insensitive search across title and prompt text — unit-tested | VERIFIED | `searchFilter` in `CustomPromptDefinition.Companion` (lines 30-39); 4 test methods in `CustomPromptFilterTest.kt` (lines 92-124): empty-query passthrough, title case-insensitive match, prompt-text substring match, no-match empty list |
| 2 | Favorite toggles pin to top + isFavorite round-trips — unit-tested | VERIFIED (partial: unit-tested portion) | `sortFavoritesFirst` in Companion (lines 45-49); `isFavorite` is a first-class Jackson-serialized field (line 16 with `@JsonIgnoreProperties`); `parseLibraryJsonParsesPrettyPrintedExport` (line 68) round-trips entries including `isFavorite = true` through Jackson; 3 sort tests in `CustomPromptFilterTest.kt` (lines 127-147). Swing visual toggle path requires human confirmation (SC-2 human item). |
| 3 | Export pretty-printed favorites-first + import merges by id + defensive dedup on duplicate input — hand-crafted JSON unit test | VERIFIED | `handleExport` calls `sortFavoritesFirst` then `JSON_MAPPER.writerWithDefaultPrettyPrinter()` (editor lines 335, 337); `handleImport` calls `parseLibraryJson` then `mergeById` (editor lines 301, 311); `mergeByIdDeduplicatesInputUsingLastOccurrenceWins` (test line 95) feeds duplicate-id input and asserts last-wins dedup — exactly the hand-crafted JSON test the SC specifies |
| 4 | Move Up/Down respects favorites/non-favorites boundary — unit-tested | VERIFIED | `applyMove` in Companion (lines 100-113): boundary check `library[index].isFavorite != library[target].isFavorite` returns original list; 5 test methods in `CustomPromptLibraryJsonTest.kt` (lines 120-155): within-favorites swap, within-non-favorites swap, last-favorite-moves-down rejected, first-non-favorite-moves-up rejected, out-of-bounds rejected |
| 5 | Right-click submenu order matches editor order (favorites first), no re-sort at menu-build time — unit-tested | VERIFIED | `filterForMenu` in Companion (line 24): pure filter with no sort; `filterForMenuPreservesExternalFavoritesFirstOrder` in `CustomPromptFilterTest.kt` (line 150): library with favorites-first input order; asserts output order unchanged by filterForMenu |

**Score:** 4/5 truths fully verified by automated checks. SC-2's Swing rendering path (visual star, position jump on toggle-off) is UNCERTAIN pending human; the underlying unit-tested logic is verified.

Note: The SC breakdown above distinguishes the unit-tested logic layer (VERIFIED for all 5) from the Swing rendering layer (human-needed for SC-1, SC-2, SC-4 Swing button state, SC-3 JFileChooser path). This matches the phase contract: "behaviour-locking with minimal production refactor" — Swing-layer verification is deferred to maintainer UAT via `03-HUMAN-UAT.md`.

### Required Artifacts

| Artifact | Expected | Status | Details |
|----------|----------|--------|---------|
| `src/test/kotlin/com/six2dez/burp/aiagent/config/CustomPromptFilterTest.kt` | PROM-06 test `filterForMenuPreservesExternalFavoritesFirstOrder` | VERIFIED | File exists; test method at line 150; tests that `filterForMenu` is a pure filter that preserves caller-imposed favorites-first order; 15 total `@Test` methods (4 pre-existing filter + 4 isValid/preservesOrder + 4 searchFilter + 3 sortFavoritesFirst + 1 new PROM-06) |
| `src/test/kotlin/com/six2dez/burp/aiagent/config/CustomPromptLibraryJsonTest.kt` | New file with 10 `@Test` methods | VERIFIED | File exists; exactly 10 `@Test` annotations confirmed by `grep -c`; 2 parseLibraryJson tests (PROM-03) + 3 mergeById tests (PROM-04) + 5 applyMove tests (PROM-05) |
| `src/main/kotlin/com/six2dez/burp/aiagent/config/CustomPromptDefinition.kt` | `parseLibraryJson`, `mergeById`, `applyMove` as Companion members | VERIFIED | All three methods present in `companion object` (lines 56, 78, 100); no `ui.components` imports (layering preserved); `associateBy` used in `mergeById` (no `distinctBy`) |
| `src/main/kotlin/com/six2dez/burp/aiagent/ui/components/CustomPromptLibraryEditor.kt` | `distinctBy` removed; thin-shell rewire to Companion | VERIFIED | `grep -n "distinctBy" CustomPromptLibraryEditor.kt` exits 1 (not found); `handleMove` at line 274 calls `applyMove`; `handleImport` at lines 301, 311 calls `parseLibraryJson` + `mergeById`; `handleExport` at line 335 calls `sortFavoritesFirst` |
| `.planning/phases/03-prompt-library-ux-audit/03-HUMAN-UAT.md` | 4 scenarios + correct frontmatter | VERIFIED | File exists; `status: partial`; `source: [03-VERIFICATION.md]`; 4 `### N.` scenario headings covering PROM-01, PROM-02, PROM-05, PROM-03+04; 4 `result: [pending]` lines; `total: 4 / pending: 4`; empty `## Gaps` section |

### Key Link Verification

| From | To | Via | Status | Details |
|------|-----|-----|--------|---------|
| `CustomPromptLibraryEditor.handleMove` | `CustomPromptDefinition.applyMove` | direct companion call | WIRED | Editor line 274: `CustomPromptDefinition.applyMove(master.toList(), idx, delta)` |
| `CustomPromptLibraryEditor.handleImport` | `CustomPromptDefinition.parseLibraryJson` | direct companion call | WIRED | Editor line 301: `CustomPromptDefinition.parseLibraryJson(text)` |
| `CustomPromptLibraryEditor.handleImport` | `CustomPromptDefinition.mergeById` | direct companion call | WIRED | Editor line 311: `CustomPromptDefinition.mergeById(master.toList(), parsed)` |
| `CustomPromptLibraryEditor.handleExport` | `CustomPromptDefinition.sortFavoritesFirst` | direct companion call | WIRED | Editor line 335: `CustomPromptDefinition.sortFavoritesFirst(master.toList())` |
| `CustomPromptFilterTest.filterForMenuPreservesExternalFavoritesFirstOrder` | `CustomPromptDefinition.filterForMenu` | JUnit test invocation | WIRED | Test line 155: `CustomPromptDefinition.filterForMenu(library, CustomPromptTag.HTTP_SELECTION)` |

### Data-Flow Trace (Level 4)

Not applicable. This is a behaviour-locking audit phase; no new data rendering components were introduced. The three new pure functions are utility/domain methods. Wiring from editor handlers to companion functions verified in Key Link table above.

### Behavioral Spot-Checks

Gradle test re-run explicitly prohibited by the task instruction ("Do NOT re-run gradle"). All three test classes were confirmed BUILD SUCCESSFUL post-merge:
- `CustomPromptFilterTest` — 15 tests (per SUMMARY-01)
- `CustomPromptLibraryJsonTest` — 10 tests (per SUMMARY-02, confirmed by file reading)
- `ktlintCheck` — BUILD SUCCESSFUL (per SUMMARY-02)

Functional verification of Swing-layer behaviors routed to human verification section.

### Probe Execution

No `probe-*.sh` scripts declared or present for this phase. Step 7c: SKIPPED (no probes defined for audit phase).

### Requirements Coverage

| Requirement | Source Plan | Description | Status | Evidence |
|------------|------------|-------------|--------|----------|
| PROM-01 | 03-01, 03-03 | Live, case-insensitive search across title and prompt text | VERIFIED (unit) + NEEDS HUMAN (Swing) | `searchFilter` Companion method; 4 unit tests; Swing DocumentListener path in UAT scenario 1 |
| PROM-02 | 03-03 | Favorite toggle pins to top; isFavorite round-trips | VERIFIED (unit: sortFavoritesFirst + Jackson) + NEEDS HUMAN (Swing rendering) | `sortFavoritesFirst` + Jackson data class; UAT scenario 2 |
| PROM-03 | 03-02 | Export pretty-printed favorites-first | VERIFIED (unit: parseLibraryJson, sortFavoritesFirst) + NEEDS HUMAN (JFileChooser) | `handleExport` thin shell; `parseLibraryJsonParsesPrettyPrintedExport` test; UAT scenario 4 |
| PROM-04 | 03-02 | Import merges by id; defensive dedup | VERIFIED (unit: mergeById, 3 tests) + NEEDS HUMAN (JFileChooser) | `mergeByIdDeduplicatesInputUsingLastOccurrenceWins` test; UAT scenario 4 |
| PROM-05 | 03-02, 03-03 | Move Up/Down respects favorites boundary | VERIFIED (unit: applyMove, 5 tests) + NEEDS HUMAN (button state) | `applyMoveReturnsOriginalWhenLastFavoriteMovesDown` etc.; UAT scenario 3 |
| PROM-06 | 03-01 | Right-click submenu order matches editor order; no re-sort | VERIFIED | `filterForMenuPreservesExternalFavoritesFirstOrder` test; `filterForMenu` is a pure filter |

All 6 requirements claimed by Phase 3 in ROADMAP.md are addressed. The unit-tested portions are VERIFIED. The Swing rendering / JFileChooser paths for PROM-01, 02, 03, 04, 05 require maintainer UAT.

### Anti-Patterns Found

No `TBD`, `FIXME`, or `XXX` markers found in any phase-modified file (`grep` exit code 1 — not found). No `TODO` or `PLACEHOLDER` markers found. No stub patterns identified: all three companion methods contain production logic (no `return emptyList()` as terminal stub — `parseLibraryJson` returns empty only on blank/malformed input as a documented defensive behaviour, not a stub).

| File | Pattern | Severity | Impact |
|------|---------|----------|--------|
| None | — | — | — |

### Human Verification Required

The following items require manual testing by a maintainer running Burp Suite with the extension loaded. All are covered by `03-HUMAN-UAT.md` scenarios.

#### 1. Search field live-filter (PROM-01)

**Test:** Open Settings -> Prompt Templates. Type a substring (e.g., "HTTP") into the search field. Verify the visible row set updates on every keystroke without lag. Clear the field; verify all rows return.
**Expected:** Real-time filtering with no perceptible lag; full library restored on clear.
**Why human:** DocumentListener -> Swing table model callback chain cannot be driven from JUnit without a live EDT. The pure filter logic (`searchFilter`) is unit-tested.

#### 2. Favorite toggle + visual star (PROM-02)

**Test:** Select a non-favorite entry; click "Favorite" checkbox or star button; verify the entry jumps to the top of the table and a star ("★") appears in the ListCellRenderer. Toggle off; verify entry returns to a position within the non-favorites group.
**Expected:** Instant visual reorder; star glyph appears/disappears; position-in-group preserved on toggle-off.
**Why human:** Swing ListCellRenderer rendering and JList reorder are not testable without a running Swing event loop.

#### 3. Move Up/Down button enable/disable at boundary (PROM-05 Swing layer)

**Test:** Select the last favorite entry; verify Move Down button is disabled. Select the first non-favorite entry; verify Move Up button is disabled. Select a middle entry in either group; verify both buttons enabled.
**Expected:** Buttons reflect boundary via `hasNeighborOfSameStatus()` wired in `refreshButtons()`.
**Why human:** Swing JButton enablement state requires a running EDT. The boundary-reject logic is fully unit-tested via `applyMove`.

#### 4. Export + Import JFileChooser round-trip (PROM-03 + PROM-04)

**Test:** Click Export; save to a `.json` file. Open the file in a text editor; confirm favorites-first ordering and pretty-printed indentation. Click Import on the same file; confirm library is unchanged (idempotent). Hand-edit the JSON to add a duplicate id entry with a different title; re-import; confirm the library contains the last-occurring entry for that id.
**Expected:** Export file is readable, pretty-printed, favorites first. Import is idempotent. Duplicate-id dedup uses last-occurrence-wins.
**Why human:** JFileChooser dialogs cannot be driven from JUnit. The underlying `parseLibraryJson` / `mergeById` / `sortFavoritesFirst` logic is fully unit-tested.

---

## Executor Recovery Events (Orchestrator-Managed)

Two executor recoveries occurred during this phase. Neither affected the final codebase state. They are documented here for audit continuity.

### Recovery 1 — Plan 03-01 Executor (Wave 1)

The first 03-01 executor (worktree `worktree-agent-a36a634eb65008403`) went out of scope. It misread `CustomPromptDefinition.kt`, declared `isFavorite` "missing" (the field exists at line 16), and as a side effect attempted to "add" it — deleting `searchFilter`, `sortFavoritesFirst`, and 6 existing tests from `CustomPromptFilterTest.kt` in the process. Its self-check passed only because the deleted tests no longer existed to fail.

Containment: Damage was isolated to the worktree branch (never merged to main). Two stale SUMMARY.md commits the agent pushed to `main` via `gsd-sdk query commit` were rolled back with `git reset --hard 7373441` (local-only, no remote push). The legitimate slice of the agent's diff (the new test method only) was applied manually by the orchestrator. Recovery committed as `ba2fa2c`. No production code was affected.

### Recovery 2 — Plan 03-03 Executor (Wave 2)

The first 03-03 executor (worktree `worktree-agent-acb9dab8ac7ae0dcf`) hit an API stream idle timeout (~5 min) without producing any commits or file writes. Spot-check confirmed no files were written. The corrupted worktree was force-removed. The single-file artifact (`03-HUMAN-UAT.md`) was applied inline by the orchestrator, mirroring `02-HUMAN-UAT.md` shape with scenario substitutions per `03-03-PLAN.md` and CONTEXT.md D-09. Committed as `0385f9f`. No retry loop was necessary — single-file scaffolds are deterministic.

---

## Gaps Summary

No automated-check gaps. All five success criteria are satisfied at the unit-test layer. The `human_needed` status is driven entirely by the Swing rendering and JFileChooser interactive layers that are architecturally untestable from JUnit — this is expected for a Swing extension phase and matches the Phase 2 precedent. The 03-HUMAN-UAT.md scaffold provides the maintainer with a fillable checklist covering all four Swing-layer verification paths.

---

_Verified: 2026-05-13T15:00:00Z_
_Verifier: Claude (gsd-verifier)_
