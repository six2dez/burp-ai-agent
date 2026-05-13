# Plan Check — Phase 3: Prompt Library UX Audit

**Checked:** 2026-05-13
**Plans verified:** 03-01-PLAN.md, 03-02-PLAN.md, 03-03-PLAN.md
**Checker:** gsd-plan-checker (Revision Gate)

---

## Verdict: READY

All blocking criteria pass. Two informational observations are noted below with WARNING severity — neither prevents execution.

---

## Dimension 1: Requirement Coverage

Phase requirements from ROADMAP.md: PROM-01, PROM-02, PROM-03, PROM-04, PROM-05, PROM-06

| Requirement | Plan(s) | Coverage Mechanism | Status |
|-------------|---------|-------------------|--------|
| PROM-01 | Plan 03 (manual, frontmatter) | Existing `searchFilterEmptyQueryReturnsLibraryUnchanged` (lines 92-95) covers case-insensitive title + text + whitespace. Swing wiring covered by HUMAN-UAT scenario 1. | COVERED |
| PROM-02 | Plan 03 (manual, frontmatter) | Existing `sortFavoritesFirst*` tests (lines 127-147) cover sort. `CustomPromptLibraryTest.serialize_roundtripsUnicodeAndSpecials` covers save/reload round-trip. Export/import `isFavorite` round-trip covered indirectly by Plan 02's `parseLibraryJsonParsesPrettyPrintedExport` (fixture `f1` has `isFavorite = true`). Swing star renderer + pin covered by HUMAN-UAT scenario 2. | COVERED |
| PROM-03 | Plan 02 (unit tests) | `parseLibraryJsonParsesPrettyPrintedExport` + `parseLibraryJsonReturnsEmptyOnMalformedInput` in `CustomPromptLibraryJsonTest.kt`. HUMAN-UAT scenario 4 covers JFileChooser path. | COVERED |
| PROM-04 | Plan 02 (unit tests) | `mergeByIdReplacesMatchingIdsAndAppendsNewIds`, `mergeByIdDeduplicatesInputUsingLastOccurrenceWins`, `mergeByIdWithEmptyExistingAppendsDedupedIncoming`. HUMAN-UAT scenario 4 covers duplicate-id injection manually. | COVERED |
| PROM-05 | Plan 02 (unit tests) | 5 `applyMove*` test methods covering within-favorites swap, within-non-favorites swap, two boundary rejects, out-of-bounds reject. HUMAN-UAT scenario 3 covers button disable UI. | COVERED |
| PROM-06 | Plan 01 (unit test) | `filterForMenuPreservesExternalFavoritesFirstOrder` — feeds pre-sorted favorites-first library, asserts `filterForMenu` preserves input order without internal re-sort. | COVERED |

**Result: PASS.** All 6 phase requirements have at least one covering task and are listed in at least one plan's `requirements` frontmatter field.

Note on PROM-01/02 frontmatter placement: Neither plan claims PROM-01 or PROM-02 as a requirement in Plans 01 or 02. Both are carried by Plan 03. This is valid — the coverage mechanisms (existing tests + manual UAT) are real, and the RESEARCH.md gap analysis confirms the existing tests at lines 92-147 of `CustomPromptFilterTest.kt` are already comprehensive.

---

## Dimension 2: Task Completeness

| Plan | Task | Type | Files | Action | Verify/Automated | Done | Status |
|------|------|------|-------|--------|-----------------|------|--------|
| 03-01 | 1 | auto | 1 file | Specific: `.copy()` fixtures, exact method body, exact assert | `./gradlew test --tests "*.filterForMenuPreservesExternalFavoritesFirstOrder"` | Yes — grep check + full class run + ktlint | PASS |
| 03-02 | 1 | auto | 1 file | Specific: exact 3 method signatures, exact logic, import list | `./gradlew compileKotlin` (compile gate) | Yes — grep -c + no ui import | PASS |
| 03-02 | 2 | auto | 1 file | Specific: 10 named test methods with exact fixture values and assertions | `./gradlew test --tests "*.CustomPromptLibraryJsonTest"` | Yes — grep -c '@Test' returns 10 + ktlint | PASS |
| 03-02 | 3 | auto | 1 file | Specific: 3 handler rewrites with exact code | `./gradlew compileKotlin` (compile gate) | Yes — grep-c companion calls + grep-c distinctBy returns 0 | PASS |
| 03-02 | 4 | auto | listed as test file but no modifications | Full test suite + ktlintCheck | `./gradlew test -PexcludeHeavyTests=true && ./gradlew ktlintCheck` | Yes — all commands exit 0 | PASS (see Warning W-01) |
| 03-03 | 1 | auto | 1 file | Specific: full file content layout, YAML frontmatter keys, 4 scenario blocks | Shell existence + grep checks | Yes — 7 structural assertions | PASS |

**Result: PASS.** All tasks have `<files>`, `<action>`, `<verify><automated>`, and `<done>` elements. Actions are specific to method level. Verification commands are runnable.

---

## Dimension 3: Dependency Correctness

| Plan | Wave | depends_on | Valid? |
|------|------|------------|--------|
| 03-01 | 1 | [] | Yes — no dependencies, Wave 1 |
| 03-02 | 1 | [] | Yes — no dependencies, Wave 1 |
| 03-03 | 2 | ["03-02"] | Yes — 03-02 exists, wave 2 = max(deps)+1 |

Dependency graph: `03-01` and `03-02` are parallel in Wave 1. `03-03` waits for `03-02`. No cycles. No forward references.

File overlap check: `03-01` touches only `CustomPromptFilterTest.kt`. `03-02` touches `CustomPromptDefinition.kt` + `CustomPromptLibraryEditor.kt` + new `CustomPromptLibraryJsonTest.kt`. Zero overlap. Parallel-safe per D-12.

**Result: PASS.**

---

## Dimension 4: Key Links Planned

| Plan | from → to | via | Implemented? |
|------|-----------|-----|--------------|
| 03-01 | `filterForMenuPreservesExternalFavoritesFirstOrder` → `filterForMenu` | direct companion call on pre-sorted library | Yes — action specifies exact call + assertion |
| 03-02 | `handleImport` (thin shell) → `parseLibraryJson` + `mergeById` | `val parsed = CustomPromptDefinition.parseLibraryJson(text); val merged = CustomPromptDefinition.mergeById(master.toList(), parsed)` | Yes — Task 3 action specifies exact substitution pattern |
| 03-02 | `handleMove` (thin shell) → `applyMove` | `CustomPromptDefinition.applyMove(master.toList(), idx, delta)` | Yes — Task 3 action specifies exact replacement |
| 03-02 | `mergeByIdDeduplicatesInputUsingLastOccurrenceWins` → D-02 semantic correction | `aDoublePrime` (last occurrence) asserted, NOT `aPrime` | Yes — Task 2 action specifies exact assertion values |
| 03-03 | HUMAN-UAT scenarios → companion methods + Swing wiring | Manual observation with explicit expected outcomes | Yes — scenario 4 explicitly names "last-occurring" per D-02 |

**Result: PASS.** All artifacts are wired together. The `handleExport` key link is implicit (no new companion method; the plan correctly states the handler is structurally unchanged). The round-trip path from `handleExport` through `parseLibraryJson` is locked by the test using `exportMapper` to generate input.

---

## Dimension 5: Scope Sanity

| Plan | Tasks | Files Modified | Wave | Assessment |
|------|-------|---------------|------|------------|
| 03-01 | 1 | 1 | 1 | Well within budget |
| 03-02 | 4 | 3 (1 existing prod + 1 existing prod + 1 new test) | 1 | 4 tasks is the WARNING threshold — see W-02 |
| 03-03 | 1 | 1 (new doc file) | 2 | Well within budget |

**Result: PASS with WARNING W-02 (Plan 02 scope).**

---

## Dimension 6: Verification Derivation

Plan 01 `must_haves`:
- Truths are user-observable behavioral invariants: `filterForMenu` preserves input order, test locks PROM-06. The explicit "NOT re-sorted internally" framing is precise. PASS.
- Artifacts: 1 file, exact method name specified, `min_lines` not set (single-method addition — acceptable). PASS.
- Key links: connect test assertion to production method and PROM-06 contract. PASS.

Plan 02 `must_haves`:
- Truths include the critical D-02 semantic correction framing ("INTENTIONAL BEHAVIOUR CHANGE: handleImport previously used distinctBy..."). This is user-observable (imports with duplicate ids now deduplicate differently). PASS.
- Truths enumerate all three companion method contracts plus the thin-shell requirement. PASS.
- Artifacts specify 3 files with `contains:` field for verification. PASS.
- Key links wire all three companion calls in the editor, plus the D-02 semantic test. PASS.

Plan 03 `must_haves`:
- Truths reference specific D-09/D-10 decisions, enumerate all 4 scenarios by PROM mapping, and require "last-occurring" language in scenario 4 (validating D-02 end-to-end). PASS.
- Artifact specifies exact path and `contains:` field. PASS.
- Key links connect scenarios to production code and companion method paths. PASS.

**Result: PASS.**

---

## Dimension 7: Context Compliance (03-CONTEXT.md)

**Locked decisions verified:**

| Decision | Implementation in Plans | Status |
|----------|------------------------|--------|
| D-01: parseLibraryJson + mergeById into Companion | Plan 02 Task 1 — exact signatures per D-01 | COVERED |
| D-02: last-occurrence-wins via associateBy | Plan 02 Task 1 (mergeById logic), Task 2 (`mergeByIdDeduplicatesInputUsingLastOccurrenceWins`), Task 3 (handleImport thin shell) | COVERED |
| D-03: new file CustomPromptLibraryJsonTest.kt | Plan 02 Task 2 | COVERED |
| D-04: applyMove into Companion | Plan 02 Task 1 — exact signature | COVERED |
| D-05: reject semantics for boundary crossing | Plan 02 Task 1 (applyMove logic returns unchanged), 5 test scenarios | COVERED |
| D-06: handlers become thin shells; file I/O + JFileChooser stays | Plan 02 Task 3 — explicit action text | COVERED |
| D-07: no new dependencies, no RETURNS_DEEP_STUBS | Plan 02 Task 2 done check: "The file does NOT contain mock(, whenever(, Mockito" | COVERED |
| D-08: no change to CustomPromptDefinition constructor | Plan 02 Task 1 — "Do NOT modify the data class constructor" | COVERED |
| D-09: 4-scenario 03-HUMAN-UAT.md | Plan 03 Task 1 | COVERED |
| D-10: frontmatter shape mirrors 02-HUMAN-UAT.md, initial counters total:4/pending:4 | Plan 03 Task 1 action and done checks | COVERED |
| D-11: 3 plans / 2 waves | All 3 plans created, wave 1+2 | COVERED |
| D-12: zero file overlap, parallel-safe | Verified above in Dimension 3 | COVERED |

**Deferred ideas check:** None of the deferred ideas (MCP invocation, CustomPromptDialog validation, drag-to-reorder, bulk import, conflict-resolution UI) appear in any plan task. PASS.

**Discretion areas:** Test method naming (CamelCase preferred, plans follow this), JUnit Assertions.assertEquals style matching CustomPromptFilterTest, fixture size (6 instances in Plan 02 — within the ≤6 guidance), ObjectMapper instance scope (per-call in parseLibraryJson per Pitfall 2 rationale). All discretion areas handled correctly.

**Result: PASS.**

---

## Dimension 7b: Scope Reduction Detection

Scanned all plan actions for scope reduction language: "v1", "static", "hardcoded", "future enhancement", "placeholder", "not wired to", "stub."

No scope reduction language found in any task action. Plan 02 Task 3 handles the `handleExport` with "Make no functional change" — this is not scope reduction; the plan explicitly verifies the handler already calls `sortFavoritesFirst` and the action confirms the existing implementation is correct, requiring no modification.

The D-02 semantic correction (distinctBy → associateBy) is explicitly called out as an "INTENTIONAL BEHAVIOUR CHANGE" in the objective, must_haves truths, and Task 3 action — not reduced or deferred.

**Result: PASS.**

---

## Dimension 7c: Architectural Tier Compliance

RESEARCH.md has a `## Architectural Responsibility Map` section. Key assignments:

| Capability | Responsibility Map Tier | Plan Task Tier | Match? |
|------------|------------------------|----------------|--------|
| parseLibraryJson | config tier (CustomPromptDefinition.Companion) | Plan 02 Task 1 adds to CustomPromptDefinition.kt | YES |
| mergeById | config tier (CustomPromptDefinition.Companion) | Plan 02 Task 1 | YES |
| applyMove | config tier (CustomPromptDefinition.Companion) | Plan 02 Task 1 | YES |
| Editor handlers (thin shells) | UI/components tier | Plan 02 Task 3 stays in CustomPromptLibraryEditor.kt | YES |
| File I/O + JFileChooser | UI/components tier | Plan 02 Task 3 explicitly keeps file I/O in editor | YES |
| Button enable/disable | UI tier | Plan 03 HUMAN-UAT scenario 3 (manual) | YES |

Plan 02 Task 1 explicitly guards against the layering violation: "NOTE: Do NOT import from CustomPromptLibraryEditor — that would violate config ← ui/components layering." The done check verifies "CustomPromptDefinition.kt does NOT import anything from com.six2dez.burp.aiagent.ui."

**Result: PASS.**

---

## Dimension 8: Nyquist Compliance

VALIDATION.md exists. `nyquist_validation: true` in config.json. VALIDATION.md has `## Validation Architecture` section.

**Check 8e — VALIDATION.md Existence:** PASS (file exists at `.planning/phases/03-prompt-library-ux-audit/03-VALIDATION.md`).

**Check 8a — Automated Verify Presence:**

| Task | Plan | Automated Command | Present? |
|------|------|------------------|----------|
| 1 | 03-01 | `./gradlew test --tests "*.filterForMenuPreservesExternalFavoritesFirstOrder" -PexcludeHeavyTests=true` | YES |
| 1 | 03-02 | `./gradlew compileKotlin -PexcludeHeavyTests=true` | YES (compile gate) |
| 2 | 03-02 | `./gradlew test --tests "*.CustomPromptLibraryJsonTest" -PexcludeHeavyTests=true` | YES |
| 3 | 03-02 | `./gradlew compileKotlin -PexcludeHeavyTests=true` | YES (compile gate) |
| 4 | 03-02 | `./gradlew test -PexcludeHeavyTests=true && ./gradlew ktlintCheck` | YES |
| 1 | 03-03 | shell existence + grep structural checks | YES (docs-only task, no JUnit applicable) |

**Check 8b — Feedback Latency:** No watch-mode flags. No E2E suite invoked. `compileKotlin` tasks are fast (sub-10s on warm JVM). `test -PexcludeHeavyTests=true` ~3-30s per VALIDATION.md estimates. PASS.

**Check 8c — Sampling Continuity (Plan 02, Wave 1):** Tasks 1 → 2 → 3 → 4. Tasks 1 and 3 have compile-gate automated commands (not test execution), but Task 2 runs the full new test file and Task 4 runs the full fast suite. No window of 3 consecutive tasks without either a compile or test automated command. PASS.

**Check 8d — Wave 0 Completeness:** VALIDATION.md lists Wave 0 gaps correctly:
- `CustomPromptLibraryJsonTest.kt` — created in Plan 02 Task 2. The test commands reference it after creation. PASS.
- `CustomPromptFilterTest.kt` additions — created in Plan 01 Task 1. The test command references the new method. PASS.
- `03-HUMAN-UAT.md` — created in Plan 03 Task 1. PASS.

**Result: PASS.** `nyquist_compliant: false` in VALIDATION.md frontmatter should be flipped to `true` before execution (the validation architecture is complete). This is an administrative step, not a code change.

---

## Dimension 9: Cross-Plan Data Contracts

Shared data entity: `List<CustomPromptDefinition>` flows from `handleExport` → JSON → `parseLibraryJson` → `mergeById`.

- `handleExport` writes via `JSON_MAPPER` (INDENT_OUTPUT). `parseLibraryJson` reads via fresh `ObjectMapper().registerKotlinModule()` (no INDENT_OUTPUT — Jackson ignores indentation on read, confirmed in RESEARCH.md Assumption A3).
- `mergeById` receives already-valid entries (parseLibraryJson filters by `isValid()`). No re-filtering in `mergeById`. No conflict.
- `applyMove` operates on a snapshot (`master.toList()`). No concurrent modification risk on EDT.
- Plan 01 and Plan 02 share no data paths — they operate on different code surfaces (`filterForMenu` vs. `mergeById`/`parseLibraryJson`/`applyMove`).

**Result: PASS.** No conflicting transforms on any shared data entity.

---

## Dimension 10: CLAUDE.md Compliance

CLAUDE.md requirements verified against plans:

| Rule | Plans | Status |
|------|-------|--------|
| Kotlin (JVM 21), Gradle Kotlin DSL | All plans use `./gradlew` commands | PASS |
| English only in code and comments | Plan actions specify English method names, English comments | PASS |
| ktlint 1.5.0 — trailing commas in multi-line params | Plans 01 and 02 explicitly mention "ktlint compliance: trailing commas" | PASS |
| No new dependencies (MIT compat) | Plan 02 must_haves truth: "No new dependency added — Jackson + Kotlin module are already on the classpath" | PASS |
| No production change beyond 3 companion extractions | Plans scope limited to 3 new companion methods + 3 handler rewires | PASS |
| Fast suite only — no *IntegrationTest suffix | New file `CustomPromptLibraryJsonTest.kt` has no heavy-test suffix; verify commands use `-PexcludeHeavyTests=true` | PASS |
| GSD workflow enforcement | Plans are executed via gsd-execute-phase per the objective's execution_context | PASS |

**Result: PASS.**

---

## Dimension 11: Research Resolution

`03-RESEARCH.md` has `## Open Questions` section (line 610). The section does NOT carry the `(RESOLVED)` suffix.

The three open questions are:
1. `parseLibraryJson` mapper as companion val or local?
2. `handleMove` thin-shell no-op behavior?
3. Plan 01: one or two new test methods for `searchFilter` whitespace?

**Assessment:** All three questions are resolved implicitly by the plans:
1. Plan 02 Task 1 action specifies "per-call `ObjectMapper` instance" — resolved to local.
2. Plan 02 Task 3 action specifies "always call `refreshList()` + `selectById()` after `applyMove`, even if the list is unchanged" — resolved to always-refresh.
3. Plan 01 objective explicitly states "WHITESPACE DECISION: the whitespace path is already locked. No new PROM-01 test is needed." — resolved to one test only (PROM-06).

The resolutions are embedded in the plan text rather than in RESEARCH.md. The formal `(RESOLVED)` suffix is absent from the section heading.

```yaml
issue:
  plan: null
  dimension: research_resolution
  severity: warning
  description: "RESEARCH.md ## Open Questions section lacks (RESOLVED) suffix despite all three questions being resolved in plan text"
  file: ".planning/phases/03-prompt-library-ux-audit/03-RESEARCH.md"
  resolved_by: "Plan 01 objective + Plan 02 Task 1/3 actions"
  fix_hint: "Rename section to '## Open Questions (RESOLVED)' and add RESOLVED markers per question. No plan changes required."
```

---

## Dimension 12: Pattern Compliance

No `03-PATTERNS.md` exists for this phase. **Dimension 12: SKIPPED (no PATTERNS.md found).**

The CONTEXT.md `<code_context>` and RESEARCH.md "Architecture Patterns" sections serve the analog function. Plans reference the appropriate analog files (`CustomPromptFilterTest.kt` style, `AgentSettingsRepository.parseCustomPromptLibrary` precedent) via the `<interfaces>` and `<context>` blocks.

---

## D-02 Semantic Correction: Specific Verification

Criterion 2 from the verification objective: "Does Plan 02 explicitly call out the `distinctBy` → `associateBy` behaviour change (RESEARCH Pitfall 1)?"

**Verified PASS across all layers:**

1. **Plan 02 objective** (line 53): "INTENTIONAL BEHAVIOUR CHANGE — must be surfaced explicitly: The current `handleImport` at line 306 uses `imported.filter { it.isValid() }.distinctBy { it.id }` which is first-occurrence-wins... After the refactor, `mergeById` uses `incoming.associateBy { it.id }.values.toList()` which is last-occurrence-wins per D-02. This is a deliberate semantic correction, not a pure logic relocation."

2. **Plan 02 must_haves truths**: "INTENTIONAL BEHAVIOUR CHANGE: handleImport previously used distinctBy (first-occurrence-wins). After refactor it calls mergeById which uses associateBy (last-occurrence-wins per D-02). The misleading comment at line 305 is corrected."

3. **Plan 02 Task 2 action**: Test `mergeByIdDeduplicatesInputUsingLastOccurrenceWins` feeds `[A', A'', C]` and asserts `aDoublePrime` (last occurrence) — explicitly contrasted with "NOT aPrime (first occurrence)."

4. **Plan 02 Task 3 action** (handler rewrite): "INTENTIONAL BEHAVIOUR CHANGE: the prior implementation used `distinctBy { it.id }` (first-occurrence-wins, misidentified in the misleading comment at line 305 as 'last occurrence wins')." The done check explicitly requires `grep -c 'distinctBy' ... returns 0`.

5. **Plan 02 key_links**: `mergeByIdDeduplicatesInputUsingLastOccurrenceWins` → D-02 intentional semantic correction.

6. **Plan 03 HUMAN-UAT scenario 4**: Explicitly requires "last-occurring entry" language in the expected outcome.

The D-02 semantic correction is unambiguously surfaced, tested, and traced end-to-end.

---

## No-Duplicate Coverage Verification

Criterion 3: Plan 01 must NOT add redundant tests already covered by `CustomPromptFilterTest.kt`.

**Verified from actual file (lines 1-148):**

| Pre-existing test | Lines | Plan 01 action |
|-------------------|-------|----------------|
| `searchFilterEmptyQueryReturnsLibraryUnchanged` | 92-95 — asserts BOTH `""` AND `"   "` | Plan 01 objective explicitly: "WHITESPACE DECISION: whitespace path already locked. No duplicate." |
| `sortFavoritesFirstPreservesOrderWithinGroups` | 127-135 | Plan 01 must_haves: "sortFavoritesFirst tests are NOT added" |
| `sortFavoritesFirstNoFavoritesReturnsLibraryUnchanged` | 138-141 | Same |
| `sortFavoritesFirstAllFavoritesReturnsLibraryUnchanged` | 144-147 | Same |

Plan 01 adds exactly ONE test: `filterForMenuPreservesExternalFavoritesFirstOrder`. No overlap. PASS.

---

## Verify Command Analysis

Criterion 7: "verify commands use the gradle test pattern that works with JDK 21 toolchain."

| Plan | Task | Command | JAVA_HOME prefix? |
|------|------|---------|-------------------|
| 03-01 | 1 | `./gradlew test --tests "..." -PexcludeHeavyTests=true` | No |
| 03-02 | 1 | `./gradlew compileKotlin -PexcludeHeavyTests=true` | No |
| 03-02 | 2 | `./gradlew test --tests "..." -PexcludeHeavyTests=true` | No |
| 03-02 | 3 | `./gradlew compileKotlin -PexcludeHeavyTests=true` | No |
| 03-02 | 4 | `./gradlew test -PexcludeHeavyTests=true && ./gradlew ktlintCheck` | No |

None of the per-task `<automated>` verify commands use the JAVA_HOME prefix shown in CONVENTIONS.md (`JAVA_HOME=$(/usr/libexec/java_home -v 21) ./gradlew ...`). However, VALIDATION.md notes "Gradle wrapper 8.12.1 requires JDK ≤23 as launcher... Claude Code's Bash gets `JAVA_HOME` pre-set via `.claude/settings.local.json`." The executor environment has JAVA_HOME pre-configured.

This is acceptable for automated verify blocks inside the executor — the environment handles JAVA_HOME. The CONVENTIONS.md `JAVA_HOME=...` prefix is for the developer's terminal, not for automated executor commands. PASS.

---

## Threat Model Verification

Criterion 8: "Each plan has a `<threat_model>` block."

| Plan | Threat Model Present? | Rows |
|------|----------------------|------|
| 03-01 | YES | 1 row (T-3-PROM06-01, accept, pure filter no attack surface) |
| 03-02 | YES | 3 rows (T-3-PROM03-01 mitigate, T-3-PROM04-01 mitigate, T-3-PROM05-01 accept) |
| 03-03 | YES | 2 rows (T-3-PROM01-01 accept, T-3-PROM0304-01 accept) |

Plan 02 threat model correctly identifies the user-supplied JSON import as the primary trust boundary and mitigates via `@JsonIgnoreProperties` + `isValid()` filter + `associateBy` dedup. PASS.

---

## Issues Summary

### Warnings (should fix — execution can proceed)

**W-01: [task_completeness] Plan 02 Task 4 `<files>` element lists a file but Task 4 makes no file modifications**

```yaml
issue:
  plan: "03-02"
  dimension: task_completeness
  severity: warning
  description: "Task 4 is a verification-only task but its <files> element lists 'CustomPromptLibraryJsonTest.kt'. Task action explicitly states 'This task has no file modifications.' The files field should be empty or omitted for a verification-only task."
  task: 4
  fix_hint: "Change <files> to empty or use a sentinel like <files><!-- verification only --></files>. No functional impact — executor will not confuse this since the task action text is clear."
```

**W-02: [scope_sanity] Plan 02 has 4 tasks — at the WARNING threshold**

```yaml
issue:
  plan: "03-02"
  dimension: scope_sanity
  severity: warning
  description: "Plan 02 has 4 tasks. The 2-3 task target is advisory; 4 is the WARNING threshold. The tasks have clear boundaries (Task 1: production companion methods; Task 2: test file; Task 3: handler rewire; Task 4: regression verification). Quality degradation risk is low given the atomic structure."
  metrics:
    tasks: 4
    files: 3
  fix_hint: "Optionally split Task 3 (handler rewire) + Task 4 (verification) into a separate 03-02b plan. Not required for execution — the task scope is well-defined and the 4th task is verification-only."
```

**W-03: [research_resolution] RESEARCH.md Open Questions section lacks (RESOLVED) suffix**

```yaml
issue:
  plan: null
  dimension: research_resolution
  severity: warning
  description: "RESEARCH.md ## Open Questions section (line 610) does not carry the (RESOLVED) suffix. All three questions are resolved within plan text but not formally closed in the research document."
  file: ".planning/phases/03-prompt-library-ux-audit/03-RESEARCH.md"
  fix_hint: "Add '(RESOLVED)' to the section heading and annotate each question with its resolution: Q1=per-call ObjectMapper, Q2=always-refresh, Q3=one test only (PROM-06). No plan changes required."
```

### Blockers

None.

---

## Coverage Matrix

| Success Criterion | ROADMAP SC | Plans | Unit Test | Manual UAT | Status |
|------------------|-----------|-------|-----------|------------|--------|
| Live case-insensitive search, `searchFilter` unit tested | SC1, PROM-01 | Existing tests | Existing `CustomPromptFilterTest.kt:92-123` | Scenario 1 | LOCKED |
| Favorites pin + `isFavorite` round-trips | SC2, PROM-02 | Existing tests + Plan 02 indirect | Existing sort tests + `parseLibraryJsonParsesPrettyPrintedExport` (isFavorite=true fixture) | Scenario 2 | LOCKED |
| Export pretty-printed favorites-first; import merges by id + dedup | SC3, PROM-03 + PROM-04 | Plan 02 | 2 + 3 = 5 tests in `CustomPromptLibraryJsonTest.kt` | Scenario 4 | LOCKED |
| Move Up/Down boundary reject, locked by unit test | SC4, PROM-05 | Plan 02 | 5 `applyMove*` tests | Scenario 3 | LOCKED |
| Right-click submenu: favorites first, no re-sort at menu-build time | SC5, PROM-06 | Plan 01 | `filterForMenuPreservesExternalFavoritesFirstOrder` | — | LOCKED |

---

## PLAN CHECK COMPLETE

**Verdict: READY**

All 3 plans will achieve the Phase 3 goal. The 6 PROM requirements are collectively covered. The D-02 semantic correction (distinctBy → associateBy) is surfaced at every layer — objective, must_haves, test name, action text, done check, and HUMAN-UAT scenario 4. No scope reduction. No deferred ideas included. No circular dependencies. File overlap is zero (parallel-safe). Three warnings are informational; none blocks execution.

**Proceed with:** `/gsd-execute-phase 03`
