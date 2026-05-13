---
phase: 3
slug: prompt-library-ux-audit
status: draft
nyquist_compliant: false
wave_0_complete: false
created: 2026-05-13
---

# Phase 3 — Validation Strategy

> Per-phase validation contract for feedback sampling during execution.

---

## Test Infrastructure

| Property | Value |
|----------|-------|
| **Framework** | JUnit Jupiter 6.0.3 (JUnit Platform via `useJUnitPlatform()`) |
| **Config file** | `build.gradle.kts` (lines 50, 52 declare deps; no separate test config) |
| **Quick run command** | `JAVA_HOME=$(/usr/libexec/java_home -v 21) ./gradlew test --tests "*CustomPromptFilterTest" --tests "*CustomPromptLibraryJsonTest" -PexcludeHeavyTests=true` |
| **Full suite command** | `JAVA_HOME=$(/usr/libexec/java_home -v 21) ./gradlew test -PexcludeHeavyTests=true` |
| **Estimated runtime** | ~3 s quick, ~30–60 s full |

Gradle wrapper 8.12.1 requires JDK ≤23 as launcher (see `.planning/codebase/CONVENTIONS.md` § "Build Tooling"). Claude Code's Bash gets `JAVA_HOME` pre-set via `.claude/settings.local.json`.

---

## Sampling Rate

- **After every task commit:** Run the quick command above (only the two test files this phase touches).
- **After every plan wave:** Run the full suite command.
- **Before `/gsd-verify-work`:** Full suite must be green AND all 4 manual-smoke scenarios in `03-HUMAN-UAT.md` marked `result: passed`.
- **Max feedback latency:** ~3 s on warm JVM.

---

## Per-Task Verification Map

| Task ID | Plan | Wave | Requirement | Threat Ref | Secure Behavior | Test Type | Automated Command | File Exists | Status |
|---------|------|------|-------------|------------|-----------------|-----------|-------------------|-------------|--------|
| 03-01-01 | 01 | 1 | PROM-06 | — | `filterForMenu` preserves favorites-first ordering when caller pre-sorts | unit | `./gradlew test --tests "*CustomPromptFilterTest.filterForMenuPreservesExternalFavoritesFirstOrder" -PexcludeHeavyTests=true` | ❌ W0 (new method) | ⬜ pending |
| 03-01-02 | 01 | 1 | PROM-01 | — | `searchFilter` trims whitespace before lowercasing (if RESEARCH Open Q3 confirms gap; else folded into existing test) | unit | `./gradlew test --tests "*CustomPromptFilterTest.searchFilterTrimsWhitespaceBeforeFiltering" -PexcludeHeavyTests=true` | ❌ W0 (new method, optional) | ⬜ pending |
| 03-02-01 | 02 | 1 | PROM-03 (D-01) | — | `parseLibraryJson(text)` round-trips Jackson pretty-printed export with `isValid()` filter | unit | `./gradlew test --tests "*CustomPromptLibraryJsonTest.parseLibraryJson*" -PexcludeHeavyTests=true` | ❌ W0 (new file + methods) | ⬜ pending |
| 03-02-02 | 02 | 1 | PROM-04 (D-01, D-02) | — | `mergeById(existing, incoming)` replaces matching ids, appends new ids, dedups input with last-occurrence-wins (intentional semantic correction from `distinctBy` first-wins per RESEARCH Pitfall 1) | unit | `./gradlew test --tests "*CustomPromptLibraryJsonTest.mergeById*" -PexcludeHeavyTests=true` | ❌ W0 (new file + methods) | ⬜ pending |
| 03-02-03 | 02 | 1 | PROM-05 (D-04, D-05) | — | `applyMove(library, index, delta)` swaps within group; returns original on boundary cross OR out-of-bounds (adjacent-swap, NOT skip-over — see RESEARCH Pitfall 4) | unit | `./gradlew test --tests "*CustomPromptLibraryJsonTest.applyMove*" -PexcludeHeavyTests=true` | ❌ W0 (new file + methods) | ⬜ pending |
| 03-02-04 | 02 | 1 | PROM-03, PROM-04, PROM-05 (D-06) | — | Editor `handleImport`/`handleExport`/`handleMove` rewired to call companion methods; file I/O + JFileChooser stay; no behaviour change in handlers except the intentional `distinctBy` → `associateBy` correction | static + manual smoke | `./gradlew compileTestKotlin -PexcludeHeavyTests=true` + 03-HUMAN-UAT.md scenarios | ❌ W0 (production refactor) | ⬜ pending |
| 03-03-01 | 03 | 2 | PROM-01, PROM-02, PROM-03, PROM-04, PROM-05 (D-09) | — | Four-scenario manual-smoke artefact created | manual | n/a (recorded in `03-HUMAN-UAT.md`) | ❌ W0 (new file) | ⬜ pending |

*Status: ⬜ pending · ✅ green · ❌ red · ⚠️ flaky*

**Pre-existing coverage (NOT re-tested in Plan 01):**
- PROM-01 case-insensitive title/text match — `CustomPromptFilterTest.kt:92` (verified by RESEARCH).
- PROM-02 favorites pin + isFavorite round-trip — `CustomPromptFilterTest.sortFavoritesFirst*` + `CustomPromptLibraryTest.serialize_roundtripsUnicodeAndSpecials` (verified by RESEARCH; no new tests needed).
- PROM-06 filter-by-tag with hidden-entries — `CustomPromptFilterTest.kt:37-78` (4 existing tests). Plan 01 adds ONE new test for the favorites-first ordering invariant.

---

## Wave 0 Requirements

- [ ] 1–2 new `@Test` methods added to `src/test/kotlin/com/six2dez/burp/aiagent/config/CustomPromptFilterTest.kt` (file exists — PROM-06 favorites-first variant + optional PROM-01 whitespace).
- [ ] 3 new companion methods added to `src/main/kotlin/com/six2dez/burp/aiagent/config/CustomPromptDefinition.kt`: `parseLibraryJson`, `mergeById`, `applyMove`.
- [ ] Handlers `handleImport`/`handleExport`/`handleMove` in `src/main/kotlin/com/six2dez/burp/aiagent/ui/components/CustomPromptLibraryEditor.kt` rewired to call companion methods.
- [ ] New test file `src/test/kotlin/com/six2dez/burp/aiagent/config/CustomPromptLibraryJsonTest.kt` with N `@Test` methods covering PROM-03, PROM-04, PROM-05 (planner picks final method count and names).
- [ ] `.planning/phases/03-prompt-library-ux-audit/03-HUMAN-UAT.md` created with 4 scenario blocks ready for the maintainer to fill `result:` after running in real Burp (D-09).

*Framework install: not needed — JUnit Jupiter 6.0.3 already in `build.gradle.kts`.*

---

## Manual-Only Verifications

| Behavior | Requirement | Why Manual | Test Instructions |
|----------|-------------|------------|-------------------|
| Search field live-filters on every keystroke | PROM-01 | DocumentListener wiring on `searchField`; pure `searchFilter` already unit-tested | `03-HUMAN-UAT.md` scenario 1: type substring, watch row set update without lag, clear → all return. |
| Favorite toggle pins + visual star renders | PROM-02 | `JList` + `ListCellRenderer` + `handleToggleFavorite` wiring; Swing repaint flow | Scenario 2: click ★ Favorite, observe entry jumps to top with star visible; toggle off, observe return to original group position. |
| Move Up/Down disabled at boundary | PROM-05 | `refreshButtons()` button-state binding tied to `hasNeighborOfSameStatus`; pure `applyMove` already unit-tested for the reject case | Scenario 3: select last favorite → Move Down disabled; select first non-favorite → Move Up disabled. |
| Import/Export JFileChooser round-trip | PROM-03 + PROM-04 | `JFileChooser` file I/O + Jackson serialization at the integration boundary; pure helpers already unit-tested | Scenario 4: Export to .json, inspect file (pretty + favorites first); Import same file (library unchanged); hand-edit JSON adding duplicate id; re-import (deduplicates silently per last-wins). |

---

## Validation Sign-Off

- [ ] All tasks have `<automated>` verify command or are mapped to a Wave 0 manual-smoke entry
- [ ] Sampling continuity: no 3 consecutive tasks without automated verify (03-02-04 production refactor is verified by compile + downstream tests)
- [ ] Wave 0 covers all MISSING references (1–2 + 3 new methods + handler rewires + 1 manual-smoke artefact)
- [ ] No watch-mode flags
- [ ] Feedback latency < 5 s on quick command
- [ ] `nyquist_compliant: true` set in frontmatter after planner verifies coverage

**Approval:** pending
