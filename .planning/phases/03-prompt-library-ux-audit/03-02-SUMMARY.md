---
phase: 03-prompt-library-ux-audit
plan: 02
subsystem: config/prompt-library
tags: [prompt-library, json, merge, move, refactor, companion, unit-test, behaviour-lock]
requirements: [PROM-03, PROM-04, PROM-05]

dependency_graph:
  requires: []
  provides:
    - "CustomPromptDefinition.parseLibraryJson — pure JSON parse + validity filter"
    - "CustomPromptDefinition.mergeById — last-occurrence-wins dedup + in-place replace + append"
    - "CustomPromptDefinition.applyMove — adjacent-swap with boundary-reject semantics"
  affects:
    - "CustomPromptLibraryEditor.handleImport — semantic change: first-wins distinctBy replaced by last-wins mergeById"
    - "CustomPromptLibraryEditor.handleMove — skip-over while loop replaced by applyMove adjacent-swap"

tech_stack:
  added: []
  patterns:
    - "Companion object pure functions: no Swing, no Jackson types in signatures"
    - "Thin shell handlers: all business logic in companion, I/O stays in editor"
    - "last-occurrence-wins dedup via associateBy (D-02)"
    - "reject-not-clamp boundary semantics for applyMove (D-05)"

key_files:
  created:
    - src/test/kotlin/com/six2dez/burp/aiagent/config/CustomPromptLibraryJsonTest.kt
  modified:
    - src/main/kotlin/com/six2dez/burp/aiagent/config/CustomPromptDefinition.kt
    - src/main/kotlin/com/six2dez/burp/aiagent/ui/components/CustomPromptLibraryEditor.kt

decisions:
  - "mergeById uses associateBy last-occurrence-wins (D-02) — intentional semantic correction from prior distinctBy first-wins in handleImport"
  - "applyMove uses reject semantics on boundary-cross (D-05), not the skip-over while loop previously in handleMove"
  - "parseLibraryJson creates own ObjectMapper per call — does NOT reference CustomPromptLibraryEditor.JSON_MAPPER (config-to-ui layering preserved)"
  - "handleExport unchanged — already structurally correct; no functional change required"

metrics:
  duration_seconds: 210
  completed_date: "2026-05-13"
  tasks_completed: 4
  files_modified: 3
---

# Phase 03 Plan 02: Companion Method Extraction + Behaviour Lock Summary

Three pure functions extracted to `CustomPromptDefinition.Companion`, three editor handlers rewired as thin shells, and 10 unit tests added to lock PROM-03/04/05 — with an intentional last-occurrence-wins semantic correction replacing a broken first-wins `distinctBy` call.

## Tasks Completed

| Task | Name | Commit | Files |
|------|------|--------|-------|
| 1 | Extract parseLibraryJson, mergeById, applyMove into Companion | 539e0db | CustomPromptDefinition.kt |
| 2 | Create CustomPromptLibraryJsonTest.kt with 10 @Test methods | 5a037bd | CustomPromptLibraryJsonTest.kt (new) |
| 3 | Rewrite handleMove, handleImport as thin shells | 4e794f8 | CustomPromptLibraryEditor.kt |
| 4 | Full test suite + ktlint verification | (no code change) | — |

## Companion Methods Added

### `parseLibraryJson(text: String): List<CustomPromptDefinition>`

Located in `CustomPromptDefinition.Companion`. Parses Jackson pretty-printed JSON arrays produced by `handleExport`. Returns empty list on blank input or parse error. Filters entries by `isValid()` (matching `AgentSettings.parseCustomPromptLibrary` pattern). Uses a per-call `ObjectMapper` — does NOT reference `CustomPromptLibraryEditor.JSON_MAPPER` to preserve the config-from-ui layering boundary.

### `mergeById(existing, incoming): List<CustomPromptDefinition>`

Located in `CustomPromptDefinition.Companion`. Input-side dedup via `associateBy { it.id }.values.toList()` (last-occurrence-wins per D-02). Replaces matching ids in-place preserving existing order; appends new ids in incoming order. No `isValid()` check — expects validity-filtered input from `parseLibraryJson`.

### `applyMove(library, index, delta): List<CustomPromptDefinition>`

Located in `CustomPromptDefinition.Companion`. Adjacent-swap only. Returns original list unchanged on: (a) `index` out of bounds, (b) `index + delta` out of bounds, (c) favorites/non-favorites boundary cross. Per D-05: reject semantics, not clamp.

## Handlers Rewired

### `handleMove(delta: Int)` — Task 3

Replaced skip-over while loop (`while (... && master[target].isFavorite != entry.isFavorite) { target += delta }`) with a single call to `CustomPromptDefinition.applyMove(master.toList(), idx, delta)`. The list is replaced via `master.clear(); master.addAll(result)`. `refreshList()` + `selectById()` called unconditionally to match prior always-refresh behavior.

### `handleImport()` — Task 3 (INTENTIONAL BEHAVIOUR CHANGE)

**Before:** `imported.filter { it.isValid() }.distinctBy { it.id }` — `distinctBy` retains the FIRST occurrence (LinkedHashSet semantics). The comment on line 305 said "Last occurrence wins via the LinkedHashMap of distinctBy" — this was WRONG.

**After:** `CustomPromptDefinition.parseLibraryJson(text)` then `CustomPromptDefinition.mergeById(master.toList(), parsed)` — `associateBy` retains the LAST occurrence (D-02). The misleading comment is gone. File read moved to `file.readText()` (replaces `JSON_MAPPER.readValue(file, ...)`).

### `handleExport()` — No functional change

Already calls `CustomPromptDefinition.sortFavoritesFirst(master.toList())` and `JSON_MAPPER.writerWithDefaultPrettyPrinter().writeValue(target, payload)`. No modification required.

## Tests Created — CustomPromptLibraryJsonTest.kt (10 tests)

| Method | Group | Requirement |
|--------|-------|-------------|
| `parseLibraryJsonParsesPrettyPrintedExport` | parseLibraryJson | PROM-03 |
| `parseLibraryJsonReturnsEmptyOnMalformedInput` | parseLibraryJson | PROM-03 |
| `mergeByIdReplacesMatchingIdsAndAppendsNewIds` | mergeById | PROM-04 |
| `mergeByIdDeduplicatesInputUsingLastOccurrenceWins` | mergeById | PROM-04 |
| `mergeByIdWithEmptyExistingAppendsDedupedIncoming` | mergeById | PROM-04 |
| `applyMoveSwapsAdjacentEntriesWithinFavoritesGroup` | applyMove | PROM-05 |
| `applyMoveSwapsAdjacentEntriesWithinNonFavoritesGroup` | applyMove | PROM-05 |
| `applyMoveReturnsOriginalWhenLastFavoriteMovesDown` | applyMove | PROM-05 |
| `applyMoveReturnsOriginalWhenFirstNonFavoriteMovesUp` | applyMove | PROM-05 |
| `applyMoveReturnsOriginalWhenIndexOutOfBounds` | applyMove | PROM-05 |

All 10 tests pass. No Mockito. No reflection. JUnit Jupiter only.

## Test Run Results

```
./gradlew test --tests "*CustomPromptLibraryJsonTest" -PexcludeHeavyTests=true  → BUILD SUCCESSFUL (10/10)
./gradlew test --tests "*CustomPromptLibraryTest" -PexcludeHeavyTests=true       → BUILD SUCCESSFUL
./gradlew test --tests "*CustomPromptFilterTest" -PexcludeHeavyTests=true        → BUILD SUCCESSFUL
./gradlew test -PexcludeHeavyTests=true                                          → BUILD SUCCESSFUL
./gradlew ktlintCheck                                                             → BUILD SUCCESSFUL
```

## Structural Verification

```
grep -c 'fun parseLibraryJson\|fun mergeById\|fun applyMove' CustomPromptDefinition.kt   → 3
grep -c 'distinctBy' CustomPromptLibraryEditor.kt                                        → 0
grep -c 'CustomPromptDefinition\.(parseLibraryJson|mergeById|applyMove)' editor          → 3
grep -c '@Test' CustomPromptLibraryJsonTest.kt                                           → 10
grep -c 'com.six2dez.burp.aiagent.ui' CustomPromptDefinition.kt                         → 0
```

## Deviations from Plan

None — plan executed exactly as written.

The pre-existing ktlint import-ordering violation in `CustomPromptLibraryEditor.kt` (line 3, `java.*` interspersed with `javax.*`) predates this plan's changes. It was already present in the original file. `ktlintCheck` builds successfully (violation listed as output but does not fail the build).

## Known Stubs

None. All three companion methods are fully implemented with production logic.

## Threat Surface Scan

No new network endpoints, auth paths, file access patterns, or schema changes introduced by this plan. The trust boundary at `handleImport` / `file.readText()` was pre-existing; `parseLibraryJson` adds a defence-in-depth validation layer (`@JsonIgnoreProperties(ignoreUnknown = true)` + `isValid()` filter) as documented in the plan's threat register (T-3-PROM03-01, T-3-PROM04-01, T-3-PROM05-01 — all mitigated).

## Self-Check: PASSED

- [x] `src/main/kotlin/com/six2dez/burp/aiagent/config/CustomPromptDefinition.kt` — FOUND
- [x] `src/main/kotlin/com/six2dez/burp/aiagent/ui/components/CustomPromptLibraryEditor.kt` — FOUND
- [x] `src/test/kotlin/com/six2dez/burp/aiagent/config/CustomPromptLibraryJsonTest.kt` — FOUND
- [x] Commit 539e0db (Task 1) — FOUND
- [x] Commit 5a037bd (Task 2) — FOUND
- [x] Commit 4e794f8 (Task 3) — FOUND
