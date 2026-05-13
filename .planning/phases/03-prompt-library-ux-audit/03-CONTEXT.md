# Phase 3: Prompt Library UX Audit - Context

**Gathered:** 2026-05-13
**Status:** Ready for planning

<domain>
## Phase Boundary

Audit the **Custom Prompt Templates** library UX that already shipped in `[Unreleased]` and lock its behaviour with tests before v0.7.0. The audit surface is three production files plus their companion object:

- `src/main/kotlin/com/six2dez/burp/aiagent/config/CustomPromptDefinition.kt` — data class + `companion object` holding the existing pure functions `filterForMenu()`, `searchFilter()`, `sortFavoritesFirst()`.
- `src/main/kotlin/com/six2dez/burp/aiagent/ui/components/CustomPromptLibraryEditor.kt` (485 LOC) — the Settings → Prompt Templates editor with private `handleImport()`, `handleExport()`, `handleMove(delta)`, `hasNeighborOfSameStatus()`. Buttons wire into these handlers; `refreshButtons()` enables/disables Move Up/Down based on the neighbor predicate.
- `src/main/kotlin/com/six2dez/burp/aiagent/ui/components/CustomPromptDialog.kt` (131 LOC) — add/edit dialog. **Not in audit scope** — out-of-scope for PROM-01..06.

**This phase is a behaviour-locking audit, not a feature build,** with one **minimal production refactor**: extract the private merge / parse / move logic out of the editor and into the existing `CustomPromptDefinition` companion so PROM-03..05's success criteria can be locked with unit tests. The refactor relocates logic — it does not change behaviour.

**In scope:**
- Unit tests for **PROM-01** (`searchFilter`: case-insensitive title + text, empty-query passthrough, whitespace handling) — pure function already exists.
- Unit tests for **PROM-02** sort half (`sortFavoritesFirst`: stable order within each group, favorites-empty / non-favorites-empty edge cases) — pure function already exists.
- Unit tests for **PROM-06** favorites variant of `filterForMenu` — pure function already exists; existing tests do not cover favorites-first ordering.
- New companion methods + unit tests for **PROM-03** (`parseLibraryJson(text): List<CustomPromptDefinition>` — pretty-printed JSON shape) and **PROM-04** (`mergeById(existing, incoming): List<CustomPromptDefinition>` — id-keyed merge with input-side dedup, last-occurrence-wins).
- New companion method + unit tests for **PROM-05** (`applyMove(library, index, delta): List<CustomPromptDefinition>` — reorder with favorites/non-favorites boundary clamp; reject = return original list unchanged).
- Wire `handleImport`/`handleExport`/`handleMove` to call the new companion methods (production refactor: thin handler shells, file I/O + JFileChooser plumbing stays put).
- Four-scenario manual smoke recorded in `03-HUMAN-UAT.md` covering the Swing wirings that pure-function tests don't reach (search field live-filter, favorite pin + star renderer, Move button enable/disable, Import/Export JFileChooser round-trip).

**Out of scope (deferred):** Refactoring `CustomPromptDialog` for testability, integration test of the full Settings → Prompt Templates panel (`CustomPromptsConfigPanel.kt`), context-menu invocation of custom prompts (`UiActions.kt` integration), per-tag visibility logic beyond what `filterForMenu` already locks, MCP tool invocation of custom prompts (called out as a known gap in `.planning/codebase/TESTING.md:292`), changes to the JSON schema or `isFavorite` semantics, any production-code change beyond the three companion-method extractions and their handler wirings.

</domain>

<decisions>
## Implementation Decisions

### Extract-pure-helper test strategy (GA1 + GA2)

- **D-01:** Extract two new methods into `CustomPromptDefinition.Companion` (the same companion that already holds `filterForMenu`, `searchFilter`, `sortFavoritesFirst`):
  - `fun parseLibraryJson(text: String): List<CustomPromptDefinition>` — parses pretty-printed JSON produced by `handleExport()`. Returns an empty list on parse error (matches the existing `AgentSettingsRepository.load()` "malformed → empty + log" behaviour locked by `CustomPromptLibraryTest.malformedJsonReturnsEmptyAndLogs`).
  - `fun mergeById(existing: List<CustomPromptDefinition>, incoming: List<CustomPromptDefinition>): List<CustomPromptDefinition>` — merges by id. Matching ids replace; new ids append. Defensively de-duplicates the **input** side via `incoming.associateBy { it.id }.values.toList()` BEFORE merging.
- **D-02:** Merge semantics for duplicate ids in the input JSON: **last occurrence wins** (per `associateBy` semantics — the standard Kotlin idiom). The test feeds a 3-entry JSON with the same id at positions 1 and 3 and asserts the post-import library contains the position-3 definition.
- **D-03:** New companion methods get a new test file: `src/test/kotlin/com/six2dez/burp/aiagent/config/CustomPromptLibraryJsonTest.kt`. Existing `CustomPromptFilterTest.kt` stays focused on `filterForMenu` (PROM-06); `CustomPromptLibraryTest.kt` stays focused on `AgentSettingsRepository` round-trip. Mirrors Phase 2's per-concern split between `InjectionPointExtractorTest` (resolver) and `ActiveScannerQueueModelTest` (queue).
- **D-04:** Extract a third new companion method for PROM-05:
  - `fun applyMove(library: List<CustomPromptDefinition>, index: Int, delta: Int): List<CustomPromptDefinition>` — returns the reordered library, or the original list unchanged if the move would cross the favorites / non-favorites boundary (or if `index + delta` is out of bounds). Single function carries both the move logic and the boundary clamp. Tested in the same new file `CustomPromptLibraryJsonTest.kt` (single audit-target test file for all PROM-03/04/05 extractions — easier for a maintainer to find).
- **D-05:** Boundary-clamp semantics for `applyMove`: **reject** — return the original library unchanged when a move would cross from favorites to non-favorites or vice versa. Matches the existing button-disable behaviour at `CustomPromptLibraryEditor.kt:196-197` (`refreshButtons` uses `hasNeighborOfSameStatus` to grey out the button at boundaries). The UI never reaches `handleMove` at a boundary today, but the function must be safe under programmatic / test invocation. Out-of-bounds index returns the original list unchanged (same "reject" shape, different cause).

### Handler wiring (D-06..D-08)

- **D-06:** Rewrite the three private handlers to call the new companion methods:
  - `handleMove(delta)` (was `CustomPromptLibraryEditor.kt:270-284`) reads the selected index, calls `applyMove(master.toList(), selectedIndex, delta)`, replaces `master` contents with the result, calls `refreshList()`. The boundary check at line 196-197 stays (it drives button state).
  - `handleImport()` (was `CustomPromptLibraryEditor.kt:286-324`) reads the JSON via `JFileChooser`, calls `parseLibraryJson(text)` then `mergeById(master.toList(), parsed)`, replaces `master` with the result, calls `refreshList()`.
  - `handleExport()` (was `CustomPromptLibraryEditor.kt:333-364`) sorts via `sortFavoritesFirst`, serializes to pretty-printed JSON via the existing Jackson `ObjectMapper`-with-`SerializationFeature.INDENT_OUTPUT` pattern already in the file, writes via `JFileChooser`.
  - All three handlers stay private. The companion methods are public. File I/O and `JFileChooser` plumbing do not move.
- **D-07:** No new dependencies. Jackson + Kotlin module are already on the classpath. No MockWebServer, no reflection, no `Answers.RETURNS_DEEP_STUBS` in the new test file (matches Phase 2 D-08 anti-pattern policy).
- **D-08:** No production change to `CustomPromptDefinition.kt`'s constructor or data shape. The four existing fields (`id`, `title`, `promptText`, `tags`, `showInContextMenu`, `isFavorite`) and `isValid()` stay byte-for-byte identical.

### Manual smoke test strategy (GA3)

- **D-09:** Create `.planning/phases/03-prompt-library-ux-audit/03-HUMAN-UAT.md` with four scenarios (mirrors Phase 1 / Phase 2 `*-HUMAN-UAT.md` shape exactly — YAML frontmatter + `## Tests` with `### N.` blocks + `## Summary` counters + `## Gaps`). Maintainer fills `result:` fields in real Burp; scaffolding is part of this phase, runs are deferred.

  1. **Search field live-filter (PROM-01)** — open Settings → Prompt Templates with ≥3 entries; type a substring into the search field; the visible row set updates on every keystroke without lag; clear the field → all rows return.
  2. **Favorite toggle + visual star (PROM-02)** — select a non-favorite entry; click `★ Favorite`; entry jumps to the top of the table with a visible star (the `ListCellRenderer` at `CustomPromptLibraryEditor.kt:377-410` shows the star); toggle off → entry returns to its prior position within the non-favorites group.
  3. **Move Up/Down button enable/disable at boundary (PROM-05)** — select the last favorite; observe Move Down disabled; select the first non-favorite; observe Move Up disabled; click anyway via keyboard accelerator if available (typically no-op).
  4. **Export + Import JFileChooser round-trip (PROM-03/04)** — click Export; pick a target `.json`; open the file in a text editor → favorites-first, pretty-printed; click Import on the same file → library unchanged; hand-edit the JSON to inject a duplicate id; re-import → library deduplicates defensively, no JOptionPane error.

- **D-10:** Mirror Phase 2 / Phase 1 frontmatter: `status: partial`, `phase: 03-prompt-library-ux-audit`, `source: [03-VERIFICATION.md]`, ISO-8601 `started:` / `updated:` set at execution time. Initial counters reflect "all four pending": `total: 4`, `passed: 0`, `issues: 0`, `pending: 4`, `skipped: 0`, `blocked: 0`. Trailing `## Gaps` section empty.

### Plan split + wave structure (GA4)

- **D-11:** 3 plans / 2 waves — mirrors Phase 2 exactly.
  - **Plan 01 (Wave 1)** — Pure-function tests for the three EXISTING companion methods. Modifies only `src/test/kotlin/com/six2dez/burp/aiagent/config/CustomPromptFilterTest.kt`. NO production change. Locks PROM-01 (`searchFilter` cases), PROM-02 sort half (`sortFavoritesFirst` cases), PROM-06 favorites variant (`filterForMenu` against a favorites-mixed library). Parallel-safe with Plan 02 (different files).
  - **Plan 02 (Wave 1)** — Extract `mergeById` + `parseLibraryJson` + `applyMove` into `CustomPromptDefinition.Companion`, wire handlers in `CustomPromptLibraryEditor.kt` to call them, add unit tests in new `CustomPromptLibraryJsonTest.kt`. Modifies `CustomPromptDefinition.kt`, `CustomPromptLibraryEditor.kt`, creates `CustomPromptLibraryJsonTest.kt`. Locks PROM-03, PROM-04, PROM-05.
  - **Plan 03 (Wave 2)** — Create `03-HUMAN-UAT.md` scaffolding. `depends_on: ["03-02"]` because the maintainer's smoke runs against the wired-up editor (handlers calling companion methods), not the pre-refactor shape.
- **D-12:** Wave-1 file overlap check passes. Plan 01 touches `CustomPromptFilterTest.kt` only; Plan 02 touches `CustomPromptDefinition.kt` + `CustomPromptLibraryEditor.kt` + new test file. Zero overlap → parallel-safe in /gsd-execute-phase.

### Claude's Discretion

- Exact test method names — both CamelCase and backticked styles are accepted in this repo (per `.planning/codebase/CONVENTIONS.md` and Phase 1 D-07). Prefer CamelCase for ktlint friendliness; planner picks final names.
- Choice of `kotlin.test.*` vs JUnit 5 `Assertions.*` imports in the new methods — match whichever style already lives in the test file being extended (`CustomPromptFilterTest` uses JUnit `Assertions.assertEquals`; `CustomPromptLibraryTest` mixes JUnit Assertions with mockito-kotlin). Do not introduce a third style. For the new file `CustomPromptLibraryJsonTest.kt`, match `CustomPromptFilterTest`'s style for consistency.
- Choice of fixture data — small (≤5 entries) hand-built `CustomPromptDefinition` instances, mirroring the existing `CustomPromptFilterTest.kt` private val pattern (lines 7-35: `http`, `issue`, `dual`, `hiddenHttp`).
- Whether to add a tiny helper `factories` private function inside the new test file if the same 4 `CustomPromptDefinition(...)` blocks repeat 3+ times. Inline literals preferred when ≤3 instances.

</decisions>

<canonical_refs>
## Canonical References

**Downstream agents MUST read these before planning or implementing.**

### Authoritative behavioural spec
- `.planning/REQUIREMENTS.md` § "Custom prompt library" — PROM-01..06 are the requirements this phase locks. Numbered list at lines 27-32.
- `.planning/ROADMAP.md` § "Phase 3: Prompt Library UX Audit" — five success criteria. SC1 → Plan 01 (PROM-01); SC2 → Plan 01 + existing repo round-trip (PROM-02); SC3 → Plan 02 (PROM-03 + PROM-04); SC4 → Plan 02 (PROM-05); SC5 → Plan 01 favorites-variant test (PROM-06).
- `SPEC.md` §4.1 (Burp tab UI) — lists the Custom AI Agent tab and Settings panel. Prompt Templates editor lives inside the Settings panel; SPEC §4.2 (Context menu actions) names "quick prompts" which are the right-click submenus that consume `filterForMenu`'s output (PROM-06).
- `SPEC.md` §5.3 (Stable prompt templates) line 123 — declares prompt templates as a stable persisted resource. Phase 3 verifies the editor side; the consumer side (Burp Pro vs Community submenu rendering) is exercised in D-09 scenario 2.
- `CHANGELOG.md` `[Unreleased]` § "Added" — declarative description of "Custom Prompt Templates: search, favorites, JSON import/export, drag-to-reorder" must be treated as authoritative for what behaviour the audit locks.

### Architecture decisions
- `DECISIONS.md` ADR-1 (Kotlin on the JVM), ADR-2 (Swing for UI) — the editor is Swing; tests are Kotlin + JUnit 5 + Mockito-Kotlin. Standard stack.
- `DECISIONS.md` ADR-5 (Privacy redaction pre-flight) — custom prompts go through the same redaction pipeline at dispatch time. Audit scope does NOT touch redaction; the prompt-library editor is purely a storage / ordering / filter layer.

### Codebase intel
- `.planning/codebase/STRUCTURE.md` lines 36-37 (`prompts/bountyprompt/`) and 118-121 (`config/CustomPromptDefinition.kt`, `AgentSettings.kt`) — file layout. Note: `bountyprompt/` is a separate, file-driven prompt definition system; it is NOT in this audit's scope.
- `.planning/codebase/TESTING.md` line 292-293 — explicitly names the `CustomPromptLibraryTest.kt` coverage status: round-trip + serialization covered; MCP tool invocation NOT covered. The MCP invocation gap is out of scope for this phase (deferred).
- `.planning/codebase/CONVENTIONS.md` § "Language Rules" + § "Build Tooling" — JVM 21 toolchain; `JAVA_HOME=$(/usr/libexec/java_home -v 21) ./gradlew test -PexcludeHeavyTests=true` for the PR gate (Build Tooling section added during Phase 2 closeout).
- `.planning/codebase/CONVENTIONS.md` § "Code Style (ktlint)" lines 87-111 — trailing commas in multi-line params, ktlint 1.5.0, `org.jlleitschuh.gradle.ktlint` plugin.

### Source files under audit
- `src/main/kotlin/com/six2dez/burp/aiagent/config/CustomPromptDefinition.kt` lines 8-49 — data class + companion. Companion methods to extend: `filterForMenu` (line 19-22), `searchFilter` (line 28-38), `sortFavoritesFirst` (line 43-47). New methods land in this companion.
- `src/main/kotlin/com/six2dez/burp/aiagent/ui/components/CustomPromptLibraryEditor.kt` lines 196-197 (`refreshButtons` boundary check), 201 (`hasNeighborOfSameStatus`), 270 (`handleMove`), 286 (`handleImport`), 333 (`handleExport`), 377-410 (`ListCellRenderer` with favorite star). Handlers wire through the new companion methods.
- `src/main/kotlin/com/six2dez/burp/aiagent/ui/panels/CustomPromptsConfigPanel.kt` — read-only context; not modified this phase.
- `src/main/kotlin/com/six2dez/burp/aiagent/ui/components/CustomPromptDialog.kt` — out of audit scope.

### Test scaffolding to lean on
- `src/test/kotlin/com/six2dez/burp/aiagent/config/CustomPromptFilterTest.kt` lines 6-35 (fixture pattern: 4 private val `CustomPromptDefinition` instances), 37-55 (test pattern: build library list, call companion method, assert). Plan 01 extends this file with PROM-01 / PROM-02 / PROM-06 tests.
- `src/test/kotlin/com/six2dez/burp/aiagent/config/CustomPromptLibraryTest.kt` lines 16-41 (`serialize_roundtripsUnicodeAndSpecials` — PROM-02 round-trip half is here; do not duplicate in Plan 01). Tests `AgentSettingsRepository`, not the companion methods.

### Cross-phase reference
- `.planning/phases/02-insertion-point-scan-audit/02-CONTEXT.md` — Phase 2 sets the audit-style precedent for D-01..D-13 numbering, gray-area surfacing, fast-suite placement, manual-smoke artefact. This phase mirrors that pattern.
- `.planning/phases/02-insertion-point-scan-audit/02-HUMAN-UAT.md` — Phase 2's manual-smoke shape (6 scenarios). Phase 3 mirrors at 4 scenarios.

</canonical_refs>

<code_context>
## Existing Code Insights

### Reusable Assets
- **`CustomPromptDefinition.Companion`** — already holds three pure functions; perfect target for `mergeById`, `parseLibraryJson`, `applyMove`. No new file needed.
- **`CustomPromptDefinition.sortFavoritesFirst`** — already implements favorites-first ordering. Reuse inside `handleExport` (already does) and inside `applyMove`'s boundary-detection logic (a position is "favorite" iff `library[index].isFavorite == true`).
- **`AgentSettingsRepository` Jackson configuration** — Pretty-printed JSON with Kotlin module + `INDENT_OUTPUT` is already configured for `customPromptLibrary` persistence. `parseLibraryJson` uses the same `ObjectMapper().registerKotlinModule()` pattern.
- **`CustomPromptFilterTest.kt` fixtures** — private val instances of `CustomPromptDefinition` for testing. Plan 01 + Plan 02 can copy the pattern.
- **`refreshButtons()` in editor (line 196-197)** — already enforces the boundary at button level. `applyMove`'s "reject" semantics make this redundant-but-safe: the UI can never trigger a boundary-crossing call, but a programmatic / test call is protected.

### Established Patterns
- **Companion-method pure functions:** `filterForMenu`, `searchFilter`, `sortFavoritesFirst` follow the shape `fun X(library: List<CustomPromptDefinition>, ...): List<CustomPromptDefinition>`. New methods MUST follow this shape (input list + params, return list — never mutate). Tests assert structural equality of the returned list.
- **Test method naming:** CamelCase preferred (Phase 1 D-07; CONVENTIONS.md). Existing tests in `CustomPromptFilterTest` use `snake_case_with_underscores` — that's a third style outside the repo norm. **Plan 01 should not adopt that style** — use CamelCase to align with Phase 1 / Phase 2.
- **Assertion library policy:** `CustomPromptFilterTest` uses `org.junit.jupiter.api.Assertions.assertEquals` (matches JUnit 5). `CustomPromptLibraryTest` uses both JUnit Assertions and mockito-kotlin. New file `CustomPromptLibraryJsonTest.kt` matches `CustomPromptFilterTest` style.
- **Fast-suite placement:** No `*IntegrationTest`/`*ConcurrencyTest`/`*BackpressureTest`/`*RestartPolicyTest` suffix on any new file. All tests in this phase run on `./gradlew test -PexcludeHeavyTests=true`.
- **Manual smoke pattern:** one-paragraph entries in `${padded_phase}-HUMAN-UAT.md` listing scenario, request used, expected vs. observed, date, Burp edition. Mirrors Phase 2's `02-HUMAN-UAT.md` shape exactly.

### Integration Points
- **Right-click submenus** (`UiActions.kt`): consume `CustomPromptDefinition.filterForMenu(library, tag)` for HTTP_SELECTION / SCANNER_ISSUE menus. The favorites-first ordering propagates because the editor stores entries already sorted (`snapshot()` calls `sortFavoritesFirst`). PROM-06's "no re-sort at menu-build time" is the assertion that `filterForMenu` is a pure filter, not a sorter.
- **Settings persistence** (`AgentSettingsRepository`): the library is stored under preference key `custom.prompt.library.v1` as Jackson-serialized JSON. Existing `CustomPromptLibraryTest` covers round-trip including unicode and order preservation.
- **Add/Edit dialog** (`CustomPromptDialog.kt`): out of audit scope; produces / edits `CustomPromptDefinition` instances that flow into the library list.

</code_context>

<specifics>
## Specific Ideas

- **Test method names (provisional):**
  - `searchFilterMatchesTitleCaseInsensitive`
  - `searchFilterMatchesPromptTextCaseInsensitive`
  - `searchFilterReturnsLibraryUnchangedForEmptyQuery`
  - `searchFilterTrimsWhitespaceBeforeFiltering`
  - `sortFavoritesFirstPreservesRelativeOrderWithinGroups`
  - `sortFavoritesFirstReturnsAllNonFavoritesWhenNoFavorites`
  - `filterForMenuRespectsFavoritesFirstOrderWhenLibrarySortedExternally`
  - `parseLibraryJsonParsesPrettyPrintedExport`
  - `parseLibraryJsonReturnsEmptyOnMalformedInput`
  - `mergeByIdReplacesMatchingIdsAndAppendsNewIds`
  - `mergeByIdDeduplicatesInputUsingLastOccurrenceWins`
  - `applyMoveSwapsAdjacentEntriesWithinFavoritesGroup`
  - `applyMoveSwapsAdjacentEntriesWithinNonFavoritesGroup`
  - `applyMoveReturnsOriginalWhenMoveWouldCrossFavoritesBoundary`
  - `applyMoveReturnsOriginalWhenIndexOutOfBounds`
- **PROM-01 search detail:** `searchFilter` already trims whitespace and lowercases. Test cases: title-only match, prompt-text-only match, both, mixed-case query against mixed-case content, empty string → unchanged, whitespace-only → unchanged, no match → empty list.
- **PROM-02 sort detail:** `sortFavoritesFirst` partitions and concatenates. Test: input `[A, B*, C, D*, E]` (asterisk = favorite) → `[B*, D*, A, C, E]` (favorites preserve their relative order; non-favorites preserve theirs).
- **PROM-03 export detail:** `parseLibraryJson` must round-trip the exact Jackson output of `handleExport`. The export path uses `ObjectMapper().registerKotlinModule().enable(SerializationFeature.INDENT_OUTPUT)`. The parse path uses the same mapper without `INDENT_OUTPUT`. Test feeds the pretty-printed string and asserts deep equality with the original list.
- **PROM-04 merge detail:** Test inputs:
  - `existing = [A, B, C]`, `incoming = [B', D]` → `[A, B', C, D]` (B replaces, D appends, A and C preserved).
  - `existing = [A, B]`, `incoming = [A', A''", C]` → `[A'', B, C]` (input dedup picks last A; A'' replaces existing A; C appends).
  - `existing = []`, `incoming = [A, A', B]` → `[A', B]` (input dedup picks last A; nothing existing to replace).
- **PROM-05 move detail:** Library laid out as `[F1, F2, F3, N1, N2, N3]` (F = favorite, N = non-favorite). Test cases:
  - `applyMove(library, 0, 1)` → `[F2, F1, F3, N1, N2, N3]` (swap within favorites).
  - `applyMove(library, 2, 1)` → unchanged (would cross boundary: F3 → N1 across the group).
  - `applyMove(library, 3, -1)` → unchanged (would cross boundary: N1 → F3).
  - `applyMove(library, 3, 1)` → `[F1, F2, F3, N2, N1, N3]` (swap within non-favorites).
  - `applyMove(library, 5, 1)` → unchanged (out of bounds: `5 + 1 = 6` ≥ size).
- **HUMAN-UAT artefact (D-09):** lives at `.planning/phases/03-prompt-library-ux-audit/03-HUMAN-UAT.md`. The planner generates the structure; the executor / maintainer records the smoke results during execution. Phases 1 and 2 used `01-HUMAN-UAT.md` / `02-HUMAN-UAT.md` for the same purpose.
- **No production change to `CustomPromptDialog.kt`** — the add/edit dialog produces `CustomPromptDefinition` instances that flow into the library list. It is consumer-facing for the editor but is out of audit scope per PROM-01..06.

</specifics>

<deferred>
## Deferred Ideas

- **MCP tool invocation of custom prompts** — `.planning/codebase/TESTING.md:293` explicitly names this as uncovered. The MCP layer can resolve a custom prompt by id and dispatch it via the agent supervisor; that integration is a separate audit surface from the editor UX. Out of PROM-01..06 scope; capture as a follow-up audit phase or post-v0.7.0 milestone item.
- **`CustomPromptDialog` add/edit field validation tests** — the dialog's input validation (`isValid()` already covered by data-class behaviour; cross-field validation in the dialog is not). Not part of PROM-01..06; future polish phase.
- **Per-tag visibility logic beyond `filterForMenu`** — the `showInContextMenu` boolean is locked by `filterForMenu`'s tests (existing + new favorites variant). Per-tag custom rendering (e.g., different icons per tag) is not in scope.
- **Drag-to-reorder via mouse** — Move Up / Move Down buttons are the only reorder UI; drag-and-drop is not implemented and not in PROM-01..06.
- **Bulk import of multiple JSON files** — current import handles a single file. Multi-file batch import is a future v2 idea.
- **Conflict-resolution UI for merge** — current merge is silent (last-occurrence-wins, defensive dedup). Surfacing a "X entries replaced, Y appended, Z duplicates collapsed" dialog after import is a future UX enhancement; PROM-04's success criteria are satisfied by the silent behaviour.
- **`CustomPromptDefinition.companion.sortFavoritesFirst` stability under equal `isFavorite` values** — current implementation uses `filter` + `filterNot` + concat, which is stable by Kotlin spec. If the stdlib semantics ever change, the new `sortFavoritesFirstPreservesRelativeOrderWithinGroups` test will catch it.

</deferred>

---

*Phase: 3-Prompt Library UX Audit*
*Context gathered: 2026-05-13*
