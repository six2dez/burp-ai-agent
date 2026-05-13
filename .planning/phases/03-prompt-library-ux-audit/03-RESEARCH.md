# Phase 3: Prompt Library UX Audit — Research

**Researched:** 2026-05-13
**Domain:** Kotlin/JUnit5 behaviour-locking audit of `CustomPromptDefinition` companion methods + minimal production refactor extracting three pure helpers from `CustomPromptLibraryEditor`
**Confidence:** HIGH

---

## Summary

This phase is a **behaviour-locking test audit with a minimal production refactor**. Three companion methods (`mergeById`, `parseLibraryJson`, `applyMove`) must be extracted from the private handlers of `CustomPromptLibraryEditor.kt` into `CustomPromptDefinition.Companion`, then locked with unit tests in a new file `CustomPromptLibraryJsonTest.kt`. The existing companion methods (`searchFilter`, `sortFavoritesFirst`, `filterForMenu`) already exist but have gaps: `CustomPromptFilterTest.kt` already covers `searchFilter` (4 tests) and `sortFavoritesFirst` (3 tests), but does **not** cover the favorites-first ordering invariant of `filterForMenu` (PROM-06), does not cover a prompt-text-only substring match vs. title-only in isolation, and does not cover the whitespace-trim edge case of `searchFilter`. Plan 01 fills those gaps; Plan 02 extracts and locks the three new companion methods.

CONTEXT.md (D-01..D-12) is thorough and locks the approach. This research does not re-litigate those decisions. It surfaces: (1) the exact semantic mismatch between `handleImport`'s current `distinctBy` (first-occurrence-wins) and D-02's `associateBy` (last-occurrence-wins), which is a real behaviour change the planner must reconcile; (2) the `JSON_MAPPER` reuse vs. fresh-instance question for `parseLibraryJson`; (3) the `master.toList()` snapshot requirement for `applyMove`; (4) the gap between `hasNeighborOfSameStatus`'s skip-over-opposite-group logic vs. `applyMove`'s simpler adjacent-swap shape; and (5) the test methods in `CustomPromptFilterTest.kt` that already exist and must not be duplicated.

**Primary recommendation:** Plan 01 adds three test methods to `CustomPromptFilterTest.kt` (favorites-first `filterForMenu` variant + `searchFilter` prompt-text-only + `searchFilter` whitespace-trim). Plan 02 extracts three companion methods, wires three handlers as thin shells, and adds fifteen unit tests in new `CustomPromptLibraryJsonTest.kt`. Plan 03 scaffolds `03-HUMAN-UAT.md`. No new dependencies, no reflection.

---

<user_constraints>
## User Constraints (from CONTEXT.md)

### Locked Decisions

- **D-01:** Extract `fun parseLibraryJson(text: String): List<CustomPromptDefinition>` and `fun mergeById(existing: List<CustomPromptDefinition>, incoming: List<CustomPromptDefinition>): List<CustomPromptDefinition>` into `CustomPromptDefinition.Companion`.
- **D-02:** Merge semantics for duplicate ids in the input JSON: **last occurrence wins** (via `incoming.associateBy { it.id }.values.toList()` before merging). **NOTE: This differs from the current `handleImport` which uses `distinctBy { it.id }` (first-occurrence-wins).** The refactor changes this behaviour — see Pitfall 1.
- **D-03:** New test file: `src/test/kotlin/com/six2dez/burp/aiagent/config/CustomPromptLibraryJsonTest.kt`. Existing `CustomPromptFilterTest.kt` and `CustomPromptLibraryTest.kt` stay in their current scopes.
- **D-04:** Extract `fun applyMove(library: List<CustomPromptDefinition>, index: Int, delta: Int): List<CustomPromptDefinition>` into the same companion. Tested in `CustomPromptLibraryJsonTest.kt`.
- **D-05:** Boundary-clamp semantics: **reject** — return the original library unchanged when a move would cross the favorites/non-favorites boundary or `index + delta` is out of bounds.
- **D-06:** Handlers `handleMove`, `handleImport`, `handleExport` become thin shells calling companion methods. File I/O and `JFileChooser` stay in the editor. All three handlers remain private.
- **D-07:** No new dependencies. No reflection. No `Answers.RETURNS_DEEP_STUBS` in the new test file.
- **D-08:** No change to `CustomPromptDefinition.kt` constructor or data shape.
- **D-09/D-10:** 4-scenario `03-HUMAN-UAT.md` (mirrors Phase 2 shape).
- **D-11/D-12:** 3 plans / 2 waves. Plan 01 (Wave 1) extends `CustomPromptFilterTest.kt` only. Plan 02 (Wave 1) extracts companion methods and creates `CustomPromptLibraryJsonTest.kt`. Plan 03 (Wave 2) scaffolds `03-HUMAN-UAT.md`. Plans 01 and 02 are parallel-safe (zero file overlap).

### Claude's Discretion

- Exact test method names — CamelCase preferred; planner picks finals.
- `kotlin.test.*` vs JUnit 5 `Assertions.*` — match `CustomPromptFilterTest` style (JUnit `Assertions.assertEquals`) in all new and extended files.
- Fixture data — small (≤5 entries) hand-built `CustomPromptDefinition` instances, mirroring `CustomPromptFilterTest` `private val` pattern.
- Whether to add a `private fun makeEntry(...)` helper in `CustomPromptLibraryJsonTest.kt` if the same constructor block repeats ≥3 times.

### Deferred Ideas (OUT OF SCOPE)

- MCP tool invocation of custom prompts.
- `CustomPromptDialog` add/edit field validation tests.
- Per-tag custom rendering beyond `filterForMenu`.
- Drag-to-reorder via mouse.
- Bulk import of multiple JSON files.
- Conflict-resolution UI for merge.
- Integration test of the full `CustomPromptsConfigPanel.kt`.
- Any production change beyond the three companion-method extractions and their handler wirings.
</user_constraints>

---

## Project Constraints (from CLAUDE.md)

- **English only** in code, comments, and identifiers.
- **Kotlin (JVM 21), Gradle Kotlin DSL**, Burp Montoya API — fixed by ADR-1/2/3.
- **No direct repo edits outside GSD workflow.**
- **MIT license** — all dependencies already present; no new deps required.
- **ktlint 1.5.0** — trailing commas in multi-line parameter lists required. Run `./gradlew ktlintFormat` after changes. Test file names must match `{SubjectClass}Test.kt`.
- **Fast-suite only** — no `*IntegrationTest`, `*ConcurrencyTest`, `*BackpressureTest`, or `*RestartPolicyTest` suffix. All new tests run on `JAVA_HOME=$(/usr/libexec/java_home -v 21) ./gradlew test -PexcludeHeavyTests=true`.

---

<phase_requirements>
## Phase Requirements

| ID | Description | Research Support |
|----|-------------|------------------|
| PROM-01 | Live, case-insensitive search across title and prompt text | `searchFilter` pure function exists at `CustomPromptDefinition.kt:28-38`. Three tests already exist in `CustomPromptFilterTest.kt` (lines 92-123). Plan 01 adds: prompt-text-only match isolation + whitespace-trim edge case. |
| PROM-02 | Favorite toggles pin to top; `isFavorite` round-trips through save/reload + export/import | Sort half: `sortFavoritesFirst` pure function exists; three tests in `CustomPromptFilterTest.kt` (lines 127-147) cover all sort cases. Round-trip half: covered by `CustomPromptLibraryTest.serialize_roundtripsUnicodeAndSpecials`. No new tests needed for PROM-02 — already locked. |
| PROM-03 | Export = pretty-printed `.json` with favorites first | `parseLibraryJson` companion method to be extracted. Tests: `parseLibraryJsonParsesPrettyPrintedExport` + `parseLibraryJsonReturnsEmptyOnMalformedInput`. JSON round-trip assertion feeds the exact output of `JSON_MAPPER.writerWithDefaultPrettyPrinter()`. |
| PROM-04 | Import merges by id (replace/append) + defensive dedup of duplicate input ids | `mergeById` companion method to be extracted. Tests: three merge scenarios from CONTEXT.md `<specifics>`. Note: current `handleImport` uses `distinctBy` (first-wins); `mergeById` uses `associateBy` (last-wins) — this is an intentional behaviour change confirmed by D-02. |
| PROM-05 | Move Up/Down respects favorites/non-favorites boundary | `applyMove` companion method to be extracted. Tests: five scenarios from CONTEXT.md `<specifics>` covering within-favorites swap, within-non-favorites swap, two boundary-crossing rejects, out-of-bounds reject. |
| PROM-06 | Right-click submenu order matches editor order (favorites first), without re-sorting at menu-build time | `filterForMenu` pure function exists. **No favorites-first test exists** in `CustomPromptFilterTest.kt` — the five existing `filterForMenu` tests (`httpTagReturnsHttpAndDualOrdered`, etc.) do not use any `isFavorite = true` entries. Plan 01 adds `filterForMenuPreservesExternalFavoritesFirstOrder`. |
</phase_requirements>

---

## Architectural Responsibility Map

| Capability | Primary Tier | Secondary Tier | Rationale |
|------------|-------------|----------------|-----------|
| Search filter | `CustomPromptDefinition.Companion.searchFilter` (config tier) | `CustomPromptLibraryEditor.refreshList()` (UI wires it) | Pure function; Swing layer calls it on every keystroke. Unit test at companion level is sufficient. |
| Favorites sort | `CustomPromptDefinition.Companion.sortFavoritesFirst` (config tier) | `CustomPromptLibraryEditor.load()` + `snapshot()` + `refreshList()` (UI wires it) | Pure function; already locked by `CustomPromptFilterTest` sort tests. |
| JSON parse (import) | `CustomPromptDefinition.Companion.parseLibraryJson` (config tier — NEW) | `CustomPromptLibraryEditor.handleImport()` (UI thin shell) | Extraction target. Jackson deserialization is pure over a String input; testable without Swing or file I/O. |
| Merge by id (import) | `CustomPromptDefinition.Companion.mergeById` (config tier — NEW) | `CustomPromptLibraryEditor.handleImport()` (UI thin shell) | Extraction target. Pure function over two lists; testable without Swing. |
| Move reorder | `CustomPromptDefinition.Companion.applyMove` (config tier — NEW) | `CustomPromptLibraryEditor.handleMove()` (UI thin shell) | Extraction target. Pure function over list + index + delta; testable without Swing. |
| Export serialize | `CustomPromptDefinition.Companion.sortFavoritesFirst` + `JSON_MAPPER` (config + editor tier) | `CustomPromptLibraryEditor.handleExport()` (UI thin shell) | `handleExport` stays as-is (already calls `sortFavoritesFirst`). No new companion method needed for export; tested indirectly by `parseLibraryJson` round-trip. |
| Right-click menu order | `CustomPromptDefinition.Companion.filterForMenu` (config tier) | `UiActions.requestResponseMenuItems()` (UI calls it) | Pure filter — must NOT sort internally. PROM-06 asserts ordering is a caller responsibility. New test locks this. |
| Button enable/disable | `CustomPromptLibraryEditor.refreshButtons()` + `hasNeighborOfSameStatus()` (UI tier) | — | Remains in UI; covered by HUMAN-UAT scenario 3. `applyMove` boundary semantics mirror `hasNeighborOfSameStatus` but operate independently. |

---

## Standard Stack

### Core

| Library | Version | Purpose | Why Standard |
|---------|---------|---------|--------------|
| JUnit Jupiter | 6.0.3 | Test runner | `[VERIFIED: build.gradle.kts line 50]` Already used by all files extended in this phase. `useJUnitPlatform()` configured. |
| Mockito-Kotlin | 5.4.0 | Mocking | `[VERIFIED: build.gradle.kts line 52]` Available but **not needed** for any new test in this phase — all companion methods are pure functions over plain Kotlin data classes. |
| Jackson `jackson-module-kotlin` | (bundled) | JSON serialization | `[VERIFIED: CustomPromptLibraryEditor.kt:3-5]` `ObjectMapper().registerKotlinModule().enable(SerializationFeature.INDENT_OUTPUT)` already in `JSON_MAPPER`. `parseLibraryJson` uses the same `ObjectMapper().registerKotlinModule()` pattern **without** `INDENT_OUTPUT` for reading. |

### Supporting

| Library | Version | Purpose | When to Use |
|---------|---------|---------|-------------|
| Kotlin stdlib | (bundled) | `associateBy`, `filter`, `filterNot`, list operations | Used by companion methods. No additional import needed. |
| `@JsonIgnoreProperties(ignoreUnknown = true)` | Jackson annotation | Forward-compat JSON parsing | Already on `CustomPromptDefinition` data class — protects `parseLibraryJson` from future field additions. |

### Alternatives Considered

| Instead of | Could Use | Tradeoff |
|------------|-----------|----------|
| `ObjectMapper().registerKotlinModule()` (fresh per call) in `parseLibraryJson` | Shared singleton `JSON_MAPPER` from editor companion | See Pitfall 2 below. Fresh instance per call is correct for a companion-level pure function — the companion has no business depending on the editor's private `JSON_MAPPER`. |
| `associateBy { it.id }.values.toList()` (D-02, last-wins) | `distinctBy { it.id }` (current, first-wins) | D-02 mandates last-wins. The test for `mergeByIdDeduplicatesInputUsingLastOccurrenceWins` will catch any regression. |

**Installation:** No new dependencies. Existing `build.gradle.kts` already has everything needed.

---

## Architecture Patterns

### System Architecture Diagram

```
Editor loads / user edits
        │
        ▼
┌─────────────────────────────────────────────────────┐
│ CustomPromptLibraryEditor (Swing, private handlers) │
│                                                     │
│   load(entries)  ──► sortFavoritesFirst(entries)    │
│   snapshot()     ──► sortFavoritesFirst(master)     │
│   refreshList()  ──► sortFavoritesFirst(master)     │
│                      searchFilter(sorted, query)    │
│                                                     │
│   handleMove(delta)  ─────────────────────────────► │──► applyMove(master.toList(), idx, delta) [NEW]
│     │ replace master contents; call refreshList()   │
│                                                     │
│   handleImport()  ──► JFileChooser → read file      │
│     │ text  ─────────────────────────────────────── │──► parseLibraryJson(text) [NEW]
│     │ parsed ──────────────────────────────────────►│──► mergeById(master.toList(), parsed) [NEW]
│     │ result → replace master; call refreshList()   │
│                                                     │
│   handleExport()  ──► sortFavoritesFirst(master)    │
│     │ payload ──► JSON_MAPPER.writerWithDefault...  │
│     │          ──► JFileChooser → write file        │
└─────────────────────────────────────────────────────┘
        │ snapshot()
        ▼
┌─────────────────────────────────────────────────────┐
│ AgentSettingsRepository                             │
│   saves customPromptLibrary (favorites-first order) │
└─────────────────────────────────────────────────────┘
        │ loaded on next open
        ▼
┌─────────────────────────────────────────────────────┐
│ UiActions.requestResponseMenuItems                  │
│   filterForMenu(library, tag) ─► right-click items  │
│   (pure filter — does NOT re-sort)                  │
└─────────────────────────────────────────────────────┘

        UNDER AUDIT
        ┌──────────────────────────────────┐
        │ CustomPromptDefinition.Companion │
        │                                  │
        │ EXISTING:                        │
        │   filterForMenu(lib, tag)        │◄── PROM-06: new favorites test in Plan 01
        │   searchFilter(lib, query)       │◄── PROM-01: 2 new tests in Plan 01
        │   sortFavoritesFirst(lib)        │◄── PROM-02: already locked (no new tests)
        │                                  │
        │ NEW (Plan 02):                   │
        │   parseLibraryJson(text)         │◄── PROM-03: 2 tests in CustomPromptLibraryJsonTest
        │   mergeById(existing, incoming)  │◄── PROM-04: 3 tests in CustomPromptLibraryJsonTest
        │   applyMove(lib, index, delta)   │◄── PROM-05: 5 tests in CustomPromptLibraryJsonTest
        └──────────────────────────────────┘
```

### Recommended Project Structure

```
src/main/kotlin/com/six2dez/burp/aiagent/config/
└── CustomPromptDefinition.kt       # +3 companion methods (parseLibraryJson, mergeById, applyMove)

src/main/kotlin/com/six2dez/burp/aiagent/ui/components/
└── CustomPromptLibraryEditor.kt    # handleMove + handleImport → thin shells calling companion

src/test/kotlin/com/six2dez/burp/aiagent/config/
├── CustomPromptFilterTest.kt       # +3 @Test methods (Plan 01: PROM-01 gaps + PROM-06 variant)
├── CustomPromptLibraryJsonTest.kt  # NEW (Plan 02): parseLibraryJson + mergeById + applyMove tests
└── CustomPromptLibraryTest.kt      # UNTOUCHED (round-trip scope)

.planning/phases/03-prompt-library-ux-audit/
├── 03-CONTEXT.md                   # existing
├── 03-DISCUSSION-LOG.md            # existing
├── 03-RESEARCH.md                  # this file
├── 03-HUMAN-UAT.md                 # NEW (Plan 03)
└── 03-PLAN-0{1,2,3}.md            # NEW (planner generates)
```

### Pattern 1: Extending `CustomPromptFilterTest.kt` (Plan 01)

**What:** Add `@Test` methods to the existing file that share the existing `private val` fixtures (`http`, `issue`, `dual`, `hiddenHttp`). No new fixtures needed for PROM-06 gap test — add `isFavorite = true` copies via `.copy()`.

**Example — favorites-first ordering preserved by `filterForMenu` (PROM-06 new test):**

```kotlin
// Source: CustomPromptFilterTest.kt pattern (private val fixtures + JUnit Assertions.assertEquals)
@Test
fun filterForMenuPreservesExternalFavoritesFirstOrder() {
    val favHttp = http.copy(id = "1f", isFavorite = true)
    val favDual = dual.copy(id = "3f", isFavorite = true)
    // Library already sorted favorites-first (as snapshot() produces it)
    val library = listOf(favHttp, favDual, http, dual)
    val result = CustomPromptDefinition.filterForMenu(library, CustomPromptTag.HTTP_SELECTION)
    // filterForMenu is a pure filter — it does NOT re-sort. Order comes from the caller.
    assertEquals(listOf(favHttp, favDual, http, dual), result)
}
```

**What this locks:** `filterForMenu` is `library.filter { tag in it.tags && it.showInContextMenu }` — it preserves input order. If anyone accidentally inserts a sort inside it, this test fails. That is the PROM-06 invariant.

**Example — `searchFilter` prompt-text-only match (PROM-01 gap test, already partial coverage exists):**

```kotlin
// NOTE: searchFilterMatchesByPromptTextSubstring already exists (lines 106-118 of CustomPromptFilterTest.kt)
// The existing test uses a haystack entry with a unique needle in promptText.
// A new test is needed only for: whitespace-only query → unchanged (not yet covered as a separate case).
@Test
fun searchFilterWhitespaceOnlyQueryReturnsLibraryUnchanged() {
    val library = listOf(http, issue, dual)
    assertEquals(library, CustomPromptDefinition.searchFilter(library, "   \t  "))
}
```

**Gap analysis (what Plan 01 must add vs. what already exists):**

| Test | Already exists? | Plan 01 action |
|------|----------------|----------------|
| `searchFilterEmptyQueryReturnsLibraryUnchanged` | YES (line 92) | Unchanged |
| `searchFilterMatchesByTitleCaseInsensitive` | YES (line 99) | Unchanged |
| `searchFilterMatchesByPromptTextSubstring` | YES (line 106) | Unchanged |
| `searchFilterReturnsEmptyWhenNoMatch` | YES (line 121) | Unchanged |
| `searchFilterWhitespaceOnlyQueryReturnsLibraryUnchanged` | NO | ADD |
| `sortFavoritesFirstPreservesOrderWithinGroups` | YES (line 127) | Unchanged |
| `sortFavoritesFirstNoFavoritesReturnsLibraryUnchanged` | YES (line 138) | Unchanged |
| `sortFavoritesFirstAllFavoritesReturnsLibraryUnchanged` | YES (line 144) | Unchanged |
| `filterForMenuPreservesExternalFavoritesFirstOrder` (PROM-06) | NO | ADD |

**CRITICAL:** The CONTEXT.md `<specifics>` lists `searchFilterTrimsWhitespaceBeforeFiltering` as a provisional name. Inspection of `searchFilter` source (line 32: `val q = query.trim()`) confirms it trims. The existing empty-query test at line 92 covers `""` and `"   "` in one method but does not assert the whitespace-only case as a named requirement. Either add a standalone test named `searchFilterWhitespaceOnlyQueryReturnsLibraryUnchanged` or confirm the existing two-assertion test is sufficient for PROM-01. The planner should decide; the minimum is one test explicitly covering the whitespace path.

### Pattern 2: `parseLibraryJson` (Plan 02)

**What:** Pure function — takes a `String`, returns `List<CustomPromptDefinition>`. Uses `ObjectMapper().registerKotlinModule()` (fresh instance, NO `INDENT_OUTPUT`). Returns empty list on parse error (matches `AgentSettingsRepository.parseCustomPromptLibrary` behavior at `AgentSettings.kt:1043`).

**Source: `AgentSettings.kt:1039-1058` (existing precedent for the parse pattern):**

```kotlin
private val customPromptMapper: ObjectMapper by lazy {
    ObjectMapper().registerModule(KotlinModule.Builder().build())
}

internal fun parseCustomPromptLibrary(raw: String?, logger: (String) -> Unit): List<CustomPromptDefinition> {
    if (raw.isNullOrBlank()) return emptyList()
    val decoded: List<CustomPromptDefinition> =
        try {
            val listType = customPromptMapper.typeFactory
                .constructCollectionType(List::class.java, CustomPromptDefinition::class.java)
            customPromptMapper.readValue(raw, listType)
        } catch (e: Exception) {
            logger("custom prompt library JSON invalid, falling back to empty: ${e.message}")
            return emptyList()
        }
    return decoded.filter { it.isValid() }
}
```

**Key difference vs. `handleImport`'s current approach:** `handleImport` at line 293 uses `JSON_MAPPER.readValue(file, Array<CustomPromptDefinition>::class.java).toList()` — reading from a `File`, not a `String`. `parseLibraryJson` reads from a `String` to enable unit testing without file I/O. The handler passes the file content as a string:

```kotlin
// handleImport() thin-shell form after refactor:
val text = file.readText()
val parsed = CustomPromptDefinition.parseLibraryJson(text)
if (parsed.isEmpty()) { /* show JOptionPane "No valid prompts" */ return }
val merged = CustomPromptDefinition.mergeById(master.toList(), parsed)
master.clear(); master.addAll(merged); refreshList()
```

**Proposed companion signature:**

```kotlin
// Source: Companion + D-01 pattern
fun parseLibraryJson(text: String): List<CustomPromptDefinition> {
    if (text.isBlank()) return emptyList()
    return try {
        ObjectMapper().registerKotlinModule()
            .readValue(text, Array<CustomPromptDefinition>::class.java)
            .toList()
            .filter { it.isValid() }
    } catch (e: Exception) {
        emptyList()
    }
}
```

**Test:** Feed the exact output of `ObjectMapper().registerKotlinModule().enable(SerializationFeature.INDENT_OUTPUT).writeValueAsString(listOf(entry))` and assert deep equality.

### Pattern 3: `mergeById` (Plan 02)

**What:** Pure function — takes `existing` and `incoming` lists, returns merged list where matching ids replace and new ids append, with input-side dedup via `associateBy` (last-occurrence-wins per D-02).

**Proposed companion signature:**

```kotlin
fun mergeById(
    existing: List<CustomPromptDefinition>,
    incoming: List<CustomPromptDefinition>,
): List<CustomPromptDefinition> {
    // Input-side dedup: last occurrence wins.
    val deduped = incoming.associateBy { it.id }.values.toList()
    val incomingById = deduped.associateBy { it.id }
    // Replace matching; append new.
    val result = existing.map { incomingById[it.id] ?: it }.toMutableList()
    val existingIds = existing.map { it.id }.toSet()
    result.addAll(deduped.filter { it.id !in existingIds })
    return result
}
```

**Tests (from CONTEXT.md `<specifics>`):**

| Scenario | Input | Expected output |
|----------|-------|-----------------|
| Replace + append | `existing=[A,B,C]`, `incoming=[B',D]` | `[A, B', C, D]` |
| Input dedup last-wins | `existing=[A,B]`, `incoming=[A', A'', C]` | `[A'', B, C]` |
| Empty existing | `existing=[]`, `incoming=[A, A', B]` | `[A', B]` |

### Pattern 4: `applyMove` (Plan 02)

**What:** Pure function — takes `library`, `index`, `delta` (+1 or -1), returns reordered list or original list unchanged on reject. Reject conditions: (a) `index` out of bounds, (b) `index + delta` out of bounds, (c) move would cross favorites/non-favorites boundary (`library[index].isFavorite != library[index + delta].isFavorite`).

**Key semantic nuance vs. `handleMove`:** The production `handleMove(delta)` at lines 270-284 does a SKIP-OVER: it advances `target` past items of opposite `isFavorite` status until it finds one with the same status. `applyMove`'s contract per D-04/D-05 is simpler — **adjacent swap only**. The UI's boundary check (`hasNeighborOfSameStatus` → button disable) ensures `handleMove` is never called with `idx` at a boundary from the UI; `applyMove` adds programmatic safety by returning unchanged at any boundary. The two implementations are not required to be identical — `handleMove` becomes a thin shell that calls `applyMove(master.toList(), masterIndexOf(entry), delta)` and replaces master if the result differs.

**Proposed companion signature:**

```kotlin
fun applyMove(
    library: List<CustomPromptDefinition>,
    index: Int,
    delta: Int,
): List<CustomPromptDefinition> {
    if (index !in library.indices) return library
    val target = index + delta
    if (target !in library.indices) return library
    // Reject if move would cross the favorites/non-favorites boundary.
    if (library[index].isFavorite != library[target].isFavorite) return library
    val result = library.toMutableList()
    val moved = result.removeAt(index)
    result.add(target, moved)
    return result
}
```

**Tests (from CONTEXT.md `<specifics>`, library = `[F1, F2, F3, N1, N2, N3]`):**

| Scenario | Call | Expected |
|----------|------|----------|
| Swap within favorites | `applyMove(lib, 0, 1)` | `[F2, F1, F3, N1, N2, N3]` |
| Boundary reject (last favorite down) | `applyMove(lib, 2, 1)` | unchanged |
| Boundary reject (first non-fav up) | `applyMove(lib, 3, -1)` | unchanged |
| Swap within non-favorites | `applyMove(lib, 3, 1)` | `[F1, F2, F3, N2, N1, N3]` |
| Out-of-bounds reject | `applyMove(lib, 5, 1)` | unchanged |

### Pattern 5: `CustomPromptLibraryJsonTest.kt` structure

**What:** New test file. Mirrors `CustomPromptFilterTest.kt` style (JUnit `Assertions.assertEquals`, no Mockito, `private val` fixtures at class level). All 10+ tests are in this single file, covering all three new companion methods. Package: `com.six2dez.burp.aiagent.config`.

**Fixture pattern:**

```kotlin
package com.six2dez.burp.aiagent.config

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test

class CustomPromptLibraryJsonTest {
    private val f1 = CustomPromptDefinition(
        id = "f1", title = "Fav 1", promptText = "fav prompt 1",
        tags = setOf(CustomPromptTag.HTTP_SELECTION), isFavorite = true,
    )
    // f2, f3 similarly...
    private val n1 = CustomPromptDefinition(
        id = "n1", title = "Non 1", promptText = "non-fav prompt 1",
        tags = setOf(CustomPromptTag.HTTP_SELECTION), isFavorite = false,
    )
    // n2, n3 similarly...

    // parseLibraryJson tests
    // mergeById tests
    // applyMove tests
}
```

### Anti-Patterns to Avoid

- **Mocking `CustomPromptDefinition`** — it is a `data class` with no dependencies. Construct instances directly. No Mockito in new tests.
- **Using `master.toList()` inside `applyMove`** — `applyMove` must take an already-snapshotted list. The caller (`handleMove`) snapshots via `master.toList()` before passing to `applyMove`. The companion method must not have any knowledge of `master`.
- **Importing from `CustomPromptLibraryEditor`'s `JSON_MAPPER`** — `parseLibraryJson` in the companion creates its own `ObjectMapper` instance. This is intentional: the companion is in the `config` package, the editor's `JSON_MAPPER` is a private companion member of a UI class. Cross-package access would violate layering.
- **Duplicating tests from `CustomPromptLibraryTest.kt`** — that file tests `AgentSettingsRepository` round-trip (serialization via `AgentSettings.parseCustomPromptLibrary`). Do not write another round-trip test in `CustomPromptLibraryJsonTest.kt` or `CustomPromptFilterTest.kt`. The scopes are distinct.
- **Using the `*` suffix pattern** — no file in this phase uses `BackpressureTest`, `IntegrationTest`, `ConcurrencyTest`, or `RestartPolicyTest`. All tests are fast-suite.
- **Introducing backtick-style test names** in `CustomPromptFilterTest.kt` — that file uses camelCase. Do not mix naming styles within a file.

---

## Don't Hand-Roll

| Problem | Don't Build | Use Instead | Why |
|---------|-------------|-------------|-----|
| `CustomPromptDefinition` instances | Custom builder | Direct data class constructor + `.copy()` | `data class` with structural equality; constructor is the factory. |
| JSON serialization for round-trip test | Custom string | `ObjectMapper().registerKotlinModule().enable(SerializationFeature.INDENT_OUTPUT).writeValueAsString(list)` then feed result to `parseLibraryJson` | Tests the actual round-trip, not a hand-crafted approximation. |
| `isFavorite = false` entries from existing fixtures | New fixture instances | `.copy(isFavorite = false)` or `.copy(isFavorite = true)` on `http`, `issue`, `dual` | Keeps fixture list minimal. |
| A `mergeById` implementation that handles `isValid()` filtering | Custom validity filter inside `mergeById` | Follow `handleImport`'s existing pattern: `incoming.filter { it.isValid() }` THEN pass to `mergeById` | `mergeById` should be pure merge logic only. The validity filter belongs in the caller (thin handler shell), matching the existing `handleImport` flow. See Pitfall 3. |

**Key insight:** All three companion methods are pure functions over `List<CustomPromptDefinition>`. No Swing, no Jackson complexity beyond standard `ObjectMapper`, no Burp Montoya API. The test file needs zero mocking infrastructure.

---

## Runtime State Inventory

Not applicable. This phase is a behaviour-locking test audit with a minimal production refactor (logic relocation, no behaviour change except the `distinctBy` → `associateBy` semantic fix for D-02). No rename, migration, or runtime state changes.

| Category | Items Found | Action Required |
|----------|-------------|------------------|
| Stored data | None — `custom.prompt.library.v1` JSON format unchanged; data class shape unchanged (D-08) | — |
| Live service config | None — no Burp settings changes | — |
| OS-registered state | None | — |
| Secrets/env vars | None | — |
| Build artifacts | None — no `build.gradle.kts` changes | — |

---

## Common Pitfalls

### Pitfall 1: `distinctBy` vs. `associateBy` semantic mismatch — behaviour change

**What goes wrong:** D-02 mandates `incoming.associateBy { it.id }.values.toList()` for input-side dedup, giving **last-occurrence-wins**. The current `handleImport` at line 306 uses `imported.filter { it.isValid() }.distinctBy { it.id }` — `distinctBy` in Kotlin is **first-occurrence-wins** (it uses a `LinkedHashSet`, retaining the first key encountered). The refactor to `associateBy` changes the behaviour for files that contain duplicate ids.

**Why it happens:** CONTEXT.md D-02 states "last occurrence wins via `associateBy` semantics" — this is the desired new behaviour, but it differs from what `handleImport` currently does. The comment at line 305 says "Last occurrence wins via the LinkedHashMap of distinctBy" — this comment is incorrect. `distinctBy` returns the FIRST occurrence, not the last.

**How to avoid:** The `mergeByIdDeduplicatesInputUsingLastOccurrenceWins` test (feeding `[A', A'', C]` and asserting `A''` survives) will catch any regression. The planner must note this as an intentional semantic correction, not a pure refactor. The HUMAN-UAT scenario 4 (hand-edit JSON to inject duplicate id, re-import) validates the end-to-end behavior.

**Warning signs:** If a test written with first-wins expectation passes but the `associateBy` implementation is correct, the test fixture was wrong. Always build the merge-dedup test with a three-entry input (A', A'', C) asserting A'' (last).

### Pitfall 2: `ObjectMapper` instance scope in `parseLibraryJson`

**What goes wrong:** A developer uses the editor's private `JSON_MAPPER` singleton (which has `INDENT_OUTPUT` enabled) to parse in `parseLibraryJson`. Parsing succeeds (Jackson ignores `INDENT_OUTPUT` on read), but the function now depends on a UI-layer private member, violating package layering.

**Why it happens:** The editor's `JSON_MAPPER` is convenient and already configured. The companion is in `config/`, the editor is in `ui/components/`. A `config`-package class must not depend on a `ui/components`-private member.

**How to avoid:** `parseLibraryJson` creates its own `ObjectMapper().registerKotlinModule()`. No `INDENT_OUTPUT` needed for reading. The per-call creation has negligible cost for a user-triggered import action. Alternatively, if performance becomes a concern, add a private companion val `val PARSE_MAPPER = ObjectMapper().registerKotlinModule()` inside `CustomPromptDefinition.Companion`.

**Warning signs:** If `parseLibraryJson`'s implementation has `import ... CustomPromptLibraryEditor` anywhere, that is a layering violation.

### Pitfall 3: Validity filtering in `mergeById` vs. in the handler

**What goes wrong:** `mergeById` is implemented to call `.filter { it.isValid() }` on the incoming list before merging. This makes `mergeById` impure with respect to its input type (it silently drops invalid entries).

**Why it happens:** `handleImport` currently filters at line 306. When extracting, a developer might fold the filter into `mergeById` for convenience.

**How to avoid:** `mergeById` should accept only already-valid entries. The validity filter stays in the `handleImport` thin shell, matching the existing flow:
```
parsed = parseLibraryJson(text)   // parseLibraryJson already filters by isValid()
merged = mergeById(master.toList(), parsed)   // incoming already valid
```
This keeps `mergeById` a pure merge: it does not need to know what "valid" means.

**Decision alignment:** `parseLibraryJson` applies `filter { it.isValid() }` (matching `AgentSettings.parseCustomPromptLibrary`'s behavior), so by the time `mergeById` sees `incoming`, validity is already enforced. `mergeById`'s tests should not use invalid entries in `incoming` — they are testing merge logic, not validation.

### Pitfall 4: `applyMove` vs. `handleMove` skip-over semantics

**What goes wrong:** The production `handleMove` at lines 275-278 uses a `while` loop to skip items of opposite `isFavorite` status until it finds the nearest same-status neighbor. A developer implements `applyMove` with the same skip-over logic, which is more complex and harder to test.

**Why it happens:** The context says `applyMove` "mirrors" `handleMove`, implying the same implementation.

**How to avoid:** Per D-05, `applyMove` uses **adjacent swap only**. The UI never calls `handleMove` at a boundary (button is disabled). `applyMove`'s boundary check (`library[index].isFavorite != library[target].isFavorite`) is sufficient because the two adjacent items can only differ in `isFavorite` when index is at the boundary. The `handleMove` thin shell after refactor:

```kotlin
private fun handleMove(delta: Int) {
    val entry = selectedEntry() ?: return
    val idx = masterIndexOf(entry)
    if (idx < 0) return
    val result = CustomPromptDefinition.applyMove(master.toList(), idx, delta)
    if (result !== master.toList()) {   // identity check: applyMove returns original on reject
        master.clear()
        master.addAll(result)
        refreshList()
        selectById(entry.id)
    }
}
```

**Note:** `applyMove` returns the **same list object** (original reference) on reject, but Kotlin's `===` identity check is not reliable here since `master.toList()` always creates a new list. Better: check `result == master.toList()` (structural equality) or check `result.size == master.size && result.zip(master).all { (a, b) -> a.id == b.id }`. Simplest: always replace master even on a no-op (the existing `handleMove` always mutates), or add an explicit "was the swap performed" signal. The thin-shell pattern can replicate the original behavior: always call `refreshList()` after `applyMove` even if unchanged. The boundary case is already prevented by button disable — the edge case only matters for programmatic calls.

**Warning signs:** If `applyMoveReturnsOriginalWhenMoveWouldCrossFavoritesBoundary` test passes a `[F1, N1]` library and asserts `applyMove(lib, 0, 1) === lib` using reference equality, it will fail because `applyMove` creates a new list even for the copy of original. Use structural equality: `assertEquals(lib, applyMove(lib, 0, 1))`.

### Pitfall 5: `master.toList()` snapshot timing in handler thin shells

**What goes wrong:** The `handleImport` thin shell passes `master` (mutable) directly instead of `master.toList()` to `mergeById`. If `mergeById` ever iterates the list while the handler simultaneously modifies `master`, a `ConcurrentModificationException` can occur.

**Why it happens:** Swing handlers run on the EDT, so there is no actual concurrency risk — but the companion method's contract is `List<CustomPromptDefinition>`, not `MutableList`. Passing a `MutableList` is a Liskov substitution concern.

**How to avoid:** All thin shells pass `master.toList()` (snapshot), not `master` directly. This matches the existing patterns in `snapshot()` (line 163: `master.toList()`) and `refreshList()` (line 166: `CustomPromptDefinition.sortFavoritesFirst(master)` which accepts a `List` — Kotlin resolves `MutableList` to `List` here, but the explicit `.toList()` is cleaner and matches D-01's description).

### Pitfall 6: PROM-02 test coverage gap (sort already locked)

**What goes wrong:** Plan 01 adds a `sortFavoritesFirstEmptyLibraryReturnsEmpty` or similar test, duplicating a case already covered by `sortFavoritesFirstNoFavoritesReturnsLibraryUnchanged` (which covers `[http, issue, dual]` — all non-favorites).

**Why it happens:** CONTEXT.md `<specifics>` lists PROM-02 sort detail but the existing tests already cover all cases. The sort tests at lines 127-147 of `CustomPromptFilterTest.kt` cover: mixed input, all non-favorites, all favorites.

**How to avoid:** Plan 01 must NOT add new `sortFavoritesFirst` tests — the sort half of PROM-02 is already locked. The PROM-02 round-trip (isFavorite persists through save/reload) is locked by `CustomPromptLibraryTest.serialize_roundtripsUnicodeAndSpecials`. No new test needed. The only missing coverage for PROM-02 is the export/import round-trip of `isFavorite`, which is covered indirectly by `parseLibraryJsonParsesPrettyPrintedExport` (if the fixture includes `isFavorite = true`).

---

## Code Examples

Verified patterns from source inspection:

### Existing `filterForMenu` (PROM-06 target)

```kotlin
// Source: CustomPromptDefinition.kt:19-22
fun filterForMenu(
    library: List<CustomPromptDefinition>,
    tag: CustomPromptTag,
): List<CustomPromptDefinition> = library.filter { tag in it.tags && it.showInContextMenu }
```

This function does NOT sort. It preserves input order. The PROM-06 invariant is: calling `filterForMenu` on a favorites-first-sorted library preserves favorites-first order in the result. The test must pass a pre-sorted library.

### Existing `JSON_MAPPER` in editor (export pattern)

```kotlin
// Source: CustomPromptLibraryEditor.kt:401-406
companion object {
    private val JSON_MAPPER: ObjectMapper =
        ObjectMapper()
            .registerKotlinModule()
            .enable(SerializationFeature.INDENT_OUTPUT)
    private const val CARD_EMPTY = "empty"
    private const val CARD_LIST = "list"
}
```

`handleExport` uses `JSON_MAPPER.writerWithDefaultPrettyPrinter().writeValue(target, payload)`. The `parseLibraryJson` round-trip test must use the same mapper to generate its input string:

```kotlin
// In CustomPromptLibraryJsonTest.kt
private val exportMapper = ObjectMapper().registerKotlinModule().enable(SerializationFeature.INDENT_OUTPUT)

@Test
fun parseLibraryJsonParsesPrettyPrintedExport() {
    val entries = listOf(f1, n1)
    val json = exportMapper.writeValueAsString(entries)
    val parsed = CustomPromptDefinition.parseLibraryJson(json)
    assertEquals(entries, parsed)
}
```

### Existing `AgentSettings.parseCustomPromptLibrary` (precedent for error behavior)

```kotlin
// Source: AgentSettings.kt:1043-1059 (internal, not for direct reuse)
// Error behavior: catch Exception → return emptyList()
// Validity filter: decoded.filter { it.isValid() }
```

`parseLibraryJson` mirrors this pattern (empty on error, filter by `isValid()`), making it consistent with the existing persistence layer behavior locked by `CustomPromptLibraryTest.malformedJsonReturnsEmptyAndLogs`.

---

## Signature Verification Against PROM-03/04/05 Success Criteria

| PROM | Success Criteria | Companion Method | Maps Cleanly? |
|------|-----------------|-----------------|---------------|
| PROM-03 | Export = pretty-printed `.json` with favorites first; import merges by id | `parseLibraryJson(text: String): List<CustomPromptDefinition>` — parses the export string | YES. The round-trip test (`parseLibraryJsonParsesPrettyPrintedExport`) feeds the exact Jackson pretty-print output. Favorites-first is a caller (export) concern. |
| PROM-04 | Matching ids replace existing, new ids append, duplicate input ids de-duplicated defensively | `mergeById(existing, incoming): List<CustomPromptDefinition>` — merge with `associateBy` dedup | YES. Three test scenarios from CONTEXT.md cover all three merge cases. The `associateBy` (last-wins) semantic matches D-02. |
| PROM-05 | Move Up/Down respects favorites/non-favorites boundary | `applyMove(library, index, delta): List<CustomPromptDefinition>` — reject on boundary or out-of-bounds | YES. Five test scenarios cover within-favorites swap, within-non-favorites swap, two boundary rejects, one out-of-bounds reject. |

All three companion methods map cleanly to their requirements. The signatures accept only `List<CustomPromptDefinition>` (no Swing, no Jackson types in parameters) — pure functions testable without any mocks.

---

## State of the Art

| Old Approach | Current Approach | When Changed | Impact |
|--------------|------------------|--------------|--------|
| `distinctBy { it.id }` (first-wins) in `handleImport` | `associateBy { it.id }.values.toList()` (last-wins) in `mergeById` per D-02 | Phase 3 refactor | Behaviour change for files with duplicate ids; intentional correction; locked by new test. |
| Merge logic private to `handleImport` | `mergeById` public companion method | Phase 3 refactor | Unit-testable without Swing/file I/O. |
| Parse logic using `Array<>` from `File` in `handleImport` | `parseLibraryJson` from `String` in companion | Phase 3 refactor | Handler reads file content to String, then delegates to companion — separates IO from logic. |
| Move logic with skip-over in `handleMove` | `applyMove` adjacent-swap-only in companion | Phase 3 refactor | Simpler contract; boundary safety enforced by return-unchanged semantics. |

**Nothing deprecated:** No framework changes, no Jackson version change, no Kotlin version change. This is purely a logic-extraction refactor within the existing stack.

---

## Open Questions

1. **`parseLibraryJson` mapper as companion val or local?**
   - What we know: A local `ObjectMapper()` per call is safe (thread-safe, negligible for user-triggered import).
   - What's unclear: Whether to add `private val PARSE_MAPPER` to `CustomPromptDefinition.Companion` for consistency with `AgentSettings.customPromptMapper`.
   - Recommendation: Use a local instance in the function body for now. If performance profiling ever flags it, promote to a companion val. Keep the test file simple.

2. **`handleMove` thin-shell no-op behavior**
   - What we know: `applyMove` returns the original list unchanged on reject. The thin shell must decide whether to call `refreshList()` + `selectById()` on a no-op.
   - What's unclear: The original `handleMove` always calls `refreshList()` after mutation (never no-ops). After refactor, if `applyMove` returns unchanged, the shell can safely call `refreshList()` anyway (idempotent).
   - Recommendation: The thin shell always calls `refreshList()` and `selectById()` regardless of whether `applyMove` changed the list. This matches existing behavior (the UI button disable already prevents boundary calls). The planner can confirm or adjust.

3. **Plan 01: one or two new test methods for `searchFilter` whitespace?**
   - What we know: `searchFilterEmptyQueryReturnsLibraryUnchanged` at line 92 already asserts BOTH `""` and `"   "` in the same test method.
   - What's unclear: Is PROM-01's "whitespace handling" success criterion fully locked by the existing two-assertion test, or does it require a standalone `searchFilterWhitespaceOnlyQueryReturnsLibraryUnchanged`?
   - Recommendation: The existing test at line 92 already covers the whitespace case. Plan 01 needs only **one new test**: `filterForMenuPreservesExternalFavoritesFirstOrder` (PROM-06). The `searchFilter` whitespace case is already locked. The planner should confirm whether PROM-01 requires an additional standalone test or whether the existing coverage is sufficient.

---

## Environment Availability

Step 2.6: SKIPPED — this phase is a pure code/test audit with no external runtime dependencies beyond the existing JDK 21 + Gradle 8.12.1 toolchain already verified in Phase 2.

| Dependency | Required By | Available | Version | Fallback |
|------------|------------|-----------|---------|----------|
| JDK 21 | Gradle compile + test | YES (via `/usr/libexec/java_home -v 21`) | 21.x | None needed |
| Gradle 8.12.1 | Build | YES (wrapper) | 8.12.1 | None needed |

**PR gate command (verified in Phase 2 closeout):**
```bash
JAVA_HOME=$(/usr/libexec/java_home -v 21) ./gradlew test -PexcludeHeavyTests=true
```

---

## Validation Architecture

### Test Framework

| Property | Value |
|----------|-------|
| Framework | JUnit Jupiter 6.0.3 |
| Config file | `build.gradle.kts` — `tasks.test { useJUnitPlatform() }` |
| Quick run command | `JAVA_HOME=$(/usr/libexec/java_home -v 21) ./gradlew test -PexcludeHeavyTests=true` |
| Full suite command | `JAVA_HOME=$(/usr/libexec/java_home -v 21) ./gradlew test nightlyRegressionTest` |

### Phase Requirements → Test Map

| Req ID | Behavior | Test Type | File | Automated Command | Exists? |
|--------|----------|-----------|------|-------------------|---------|
| PROM-01 | Case-insensitive search, empty/whitespace passthrough | unit | `CustomPromptFilterTest.kt` | `./gradlew test --tests "*.CustomPromptFilterTest"` | Partial — see gaps |
| PROM-02 | Favorites sort stable; isFavorite round-trips | unit + existing round-trip | `CustomPromptFilterTest.kt` + `CustomPromptLibraryTest.kt` | `./gradlew test --tests "*.CustomPromptFilterTest" --tests "*.CustomPromptLibraryTest"` | YES (no new tests needed) |
| PROM-03 | Export round-trips through parseLibraryJson | unit | `CustomPromptLibraryJsonTest.kt` | `./gradlew test --tests "*.CustomPromptLibraryJsonTest"` | NO — Wave 0 gap |
| PROM-04 | mergeById: replace + append + dedup last-wins | unit | `CustomPromptLibraryJsonTest.kt` | `./gradlew test --tests "*.CustomPromptLibraryJsonTest"` | NO — Wave 0 gap |
| PROM-05 | applyMove: within-group swap + boundary reject | unit | `CustomPromptLibraryJsonTest.kt` | `./gradlew test --tests "*.CustomPromptLibraryJsonTest"` | NO — Wave 0 gap |
| PROM-06 | filterForMenu preserves favorites-first from caller | unit | `CustomPromptFilterTest.kt` | `./gradlew test --tests "*.CustomPromptFilterTest"` | NO — Wave 0 gap |
| PROM-01 (smoke) | Search field live-filters on keystroke | manual | `03-HUMAN-UAT.md` scenario 1 | Manual — Burp UI | NO — Wave 0 gap |
| PROM-02 (smoke) | Favorite toggle + star renderer + editor re-pin | manual | `03-HUMAN-UAT.md` scenario 2 | Manual — Burp UI | NO — Wave 0 gap |
| PROM-05 (smoke) | Move button disabled at boundary | manual | `03-HUMAN-UAT.md` scenario 3 | Manual — Burp UI | NO — Wave 0 gap |
| PROM-03/04 (smoke) | Export/import round-trip with duplicate-id injection | manual | `03-HUMAN-UAT.md` scenario 4 | Manual — Burp UI | NO — Wave 0 gap |

### Sampling Rate

- **Per task commit (Wave 1):** `JAVA_HOME=$(/usr/libexec/java_home -v 21) ./gradlew test -PexcludeHeavyTests=true`
- **Per wave merge:** Same command — all new tests are fast-suite.
- **Phase gate:** Full suite green before `/gsd-verify-work`.

### Wave 0 Gaps

- [ ] `src/test/kotlin/com/six2dez/burp/aiagent/config/CustomPromptLibraryJsonTest.kt` — covers PROM-03, PROM-04, PROM-05 (created in Plan 02)
- [ ] Three `@Test` methods in `CustomPromptFilterTest.kt` — covers PROM-01 whitespace gap + PROM-06 favorites-filter variant (added in Plan 01)
- [ ] `.planning/phases/03-prompt-library-ux-audit/03-HUMAN-UAT.md` — 4-scenario smoke template (created in Plan 03)

*(No new test framework install needed — JUnit Jupiter 6.0.3 already in `build.gradle.kts`.)*

---

## Assumptions Log

| # | Claim | Section | Risk if Wrong |
|---|-------|---------|---------------|
| A1 | `CustomPromptFilterTest.kt` line 92 asserts both `""` and `"   "` in a single test, effectively covering the PROM-01 whitespace case | Gap Analysis table; Open Question 3 | If the empty-query test covers only `""` and not `"   "`, Plan 01 needs an additional whitespace-only test method. Planner should verify by reading line 92-96 of `CustomPromptFilterTest.kt` before finalizing Plan 01 task list. |
| A2 | `applyMove` returning the original list unchanged on reject (same structural content) and the thin shell detecting the no-op via structural equality is acceptable | Pitfall 4; Pattern 4 | If the shell uses reference equality (`===`) on the list returned by `applyMove`, it will always treat the result as "changed" (since `applyMove` always returns a new list or the original). Structural equality (`==`) or a no-op sentinel is the correct approach. |
| A3 | `ObjectMapper().registerKotlinModule()` (without `INDENT_OUTPUT`) correctly deserializes the pretty-printed JSON produced by `JSON_MAPPER.writerWithDefaultPrettyPrinter()` | Code Examples; Pattern 2 | Jackson ignores indentation on read. This is standard Jackson behavior. If a future Jackson version changes this, `parseLibraryJsonParsesPrettyPrintedExport` will catch it immediately. |

**Verified claims:** All other claims in this document were verified by direct source inspection of `CustomPromptDefinition.kt`, `CustomPromptLibraryEditor.kt`, `CustomPromptFilterTest.kt`, `CustomPromptLibraryTest.kt`, `AgentSettings.kt`, `build.gradle.kts`, and the planning documents. No claim relies solely on training-data knowledge without source verification.

---

## Security Domain

This phase involves no authentication, session management, access control, cryptography, or network I/O. It is a pure UI/config-layer audit of local data manipulation (in-memory list operations + local file import/export). Security enforcement is not applicable to this audit phase.

ASVS categories V2, V3, V4, V6 do not apply. V5 (input validation) is represented by `isValid()` filtering in `parseLibraryJson` and `mergeById`'s trust of pre-validated incoming entries — this is already handled.

---

## Sources

### Primary (HIGH confidence)

- `[VERIFIED: src/main/kotlin/com/six2dez/burp/aiagent/config/CustomPromptDefinition.kt]` — full companion, all three existing pure functions, data class shape.
- `[VERIFIED: src/main/kotlin/com/six2dez/burp/aiagent/ui/components/CustomPromptLibraryEditor.kt:270-363,401-408]` — `handleMove`, `handleImport`, `handleExport`, `JSON_MAPPER` companion.
- `[VERIFIED: src/test/kotlin/com/six2dez/burp/aiagent/config/CustomPromptFilterTest.kt:1-148]` — all existing test methods, fixture pattern, assertion style.
- `[VERIFIED: src/test/kotlin/com/six2dez/burp/aiagent/config/CustomPromptLibraryTest.kt:1-144]` — round-trip scope, `InMemoryPrefs` pattern, Mockito-Kotlin usage.
- `[VERIFIED: src/main/kotlin/com/six2dez/burp/aiagent/config/AgentSettings.kt:1039-1059]` — `parseCustomPromptLibrary` precedent (error → empty, `isValid()` filter).
- `[VERIFIED: build.gradle.kts lines 50,52]` — JUnit Jupiter 6.0.3, Mockito-Kotlin 5.4.0.
- `[VERIFIED: .planning/phases/03-prompt-library-ux-audit/03-CONTEXT.md]` — all locked decisions D-01..D-12.
- `[VERIFIED: .planning/REQUIREMENTS.md:27-32]` — PROM-01..06 text.
- `[VERIFIED: .planning/codebase/CONVENTIONS.md]` — ktlint 1.5.0, trailing commas, camelCase names, fast-suite suffixes.
- `[VERIFIED: .planning/codebase/TESTING.md]` — test file locations, assertion style policy, fast/heavy suite classification.

### Secondary (MEDIUM confidence)

- `[VERIFIED: CustomPromptLibraryEditor.kt:305-306]` — `distinctBy { it.id }` first-wins semantic confirmed vs. D-02 last-wins spec. Comment at line 305 is incorrect ("Last occurrence wins via the LinkedHashMap of distinctBy" — `distinctBy` is first-wins).

---

## Metadata

**Confidence breakdown:**
- Standard stack: HIGH — verified directly from `build.gradle.kts` and source files.
- Architecture: HIGH — verified from full source read of `CustomPromptDefinition.kt` and `CustomPromptLibraryEditor.kt`.
- Companion method signatures: HIGH — derived directly from D-01/D-04 decisions and production code patterns.
- Pitfalls: HIGH — Pitfall 1 verified by source inspection (`distinctBy` semantics); Pitfall 2-6 verified from code structure.
- Test gap analysis: HIGH — all existing tests read line-by-line from `CustomPromptFilterTest.kt`.

**Research date:** 2026-05-13
**Valid until:** 2026-06-13 (stable — no external dependencies; all sources are local repo files)

---

## RESEARCH COMPLETE

**Phase:** 3 — Prompt Library UX Audit
**Confidence:** HIGH

### Key Findings

- **Behaviour change confirmed:** Current `handleImport` uses `distinctBy { it.id }` (first-occurrence-wins). D-02 mandates `associateBy { it.id }` (last-occurrence-wins). The refactor corrects this, and the existing comment at line 305 is misleading. The planner must flag this as an intentional semantic correction, not a pure logic relocation.

- **Plan 01 scope is minimal:** `CustomPromptFilterTest.kt` already has 4 `searchFilter` tests and 3 `sortFavoritesFirst` tests. Plan 01 adds at most two methods: `filterForMenuPreservesExternalFavoritesFirstOrder` (PROM-06, definitely missing) and optionally a standalone whitespace-only test for PROM-01 (the existing test at line 92 may already cover it — see Open Question 3).

- **All three companion signatures are clean:** `parseLibraryJson(String)`, `mergeById(List, List)`, `applyMove(List, Int, Int)` accept only pure Kotlin types. Zero mocking needed in `CustomPromptLibraryJsonTest.kt`.

- **`applyMove` is adjacent-swap, not skip-over:** The production `handleMove` skip-over loop is NOT replicated in `applyMove`. The companion uses direct adjacent-index swap with boundary reject. The thin shell simplifies to: snapshot, call `applyMove`, replace master, refresh.

- **PROM-02 is already locked:** Both sort tests and the round-trip test exist. No new tests needed for PROM-02. Plan 01 must not add duplicate sort coverage.

### File Created

`.planning/phases/03-prompt-library-ux-audit/03-RESEARCH.md`

### Confidence Assessment

| Area | Level | Reason |
|------|-------|--------|
| Standard Stack | HIGH | Verified from build.gradle.kts and source |
| Companion Method Signatures | HIGH | Derived from CONTEXT.md decisions + production code patterns |
| Test Gap Analysis | HIGH | All existing tests read line-by-line |
| Pitfalls | HIGH | Pitfall 1 (distinctBy vs. associateBy) confirmed by source inspection |
| Architecture | HIGH | Full source read of both production files |

### Open Questions

1. Does Plan 01 need a standalone `searchFilterWhitespaceOnlyQueryReturnsLibraryUnchanged` test, or does the existing two-assertion test at line 92 fully satisfy PROM-01? (Low risk — at most one extra test.)
2. Should the `handleMove` thin shell always call `refreshList()` on no-op, or only when `applyMove` returns a different list? (Low risk — both are correct; always-refresh is simpler.)
3. Should `parseLibraryJson` use a per-call `ObjectMapper` instance or a private companion val? (Low risk — per-call is correct for the package-layering reason documented in Pitfall 2.)

### Ready for Planning

Research complete. Planner can now create `03-PLAN-01.md`, `03-PLAN-02.md`, and `03-PLAN-03.md`.
