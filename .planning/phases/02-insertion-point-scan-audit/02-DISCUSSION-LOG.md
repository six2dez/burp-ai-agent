# Phase 2: Insertion-Point Scan Audit - Discussion Log

> **Audit trail only.** Do not use as input to planning, research, or execution agents.
> Decisions are captured in CONTEXT.md — this log preserves the alternatives considered.

**Date:** 2026-05-13
**Phase:** 02-insertion-point-scan-audit
**Areas discussed:** Resolver sub-case coverage (INSP-04), Queue assertion strategy (INSP-03), Menu visibility test (INSP-01 + INSP-02), Audit scope boundary

---

## Gray Area Selection

| Option | Description | Selected |
|--------|-------------|----------|
| Resolver sub-case coverage (INSP-04) | matchInsertionPoint is missing tests for BODY_PARAM, COOKIE, XML_ELEMENT, and PATH_SEGMENT. Decide: add all four, or only the ones flagged in ROADMAP success criterion #4? Carries forward Phase 1's behavioural-test stance. | ✓ |
| Queue assertion strategy (INSP-03) | How do we lock priority=60 + one-target-per-class? Existing ActiveScannerQueueModelTest uses scanner.getQueueItems() snapshots — reuse, reflection peek into private scanQueue, or refactor to expose for testing? | ✓ |
| Menu visibility test (INSP-01 + INSP-02) | The UI builder hides the menu when the resolver returns null. Test only the resolver (lean, current pattern) or also exercise buildAiScanInsertionPointItem with mocked editor/event? Adjacent: is a manual smoke OK (like Phase 1 D-06)? | ✓ |
| Audit scope boundary | Strict INSP-01..04 only, or also lock adjacent invariants surfaced during the audit: dedup-bypass on re-invoke, return-0 when out-of-scope, return-0 when queue full, ScanPolicy.PASSIVE_ONLY filtering? | ✓ |

**User's choice:** All four areas selected for discussion.

---

## Resolver sub-case coverage (INSP-04)

### Sub-cases to add

| Option | Description | Selected |
|--------|-------------|----------|
| BODY_PARAM (form-encoded body) | Application/x-www-form-urlencoded body with a parameter; Montoya parses these as ParsedHttpParameter with type=BODY. Tested via valueOffsets() like URL params. Listed in INSP-04 explicitly. | ✓ |
| COOKIE | Cookie header parsed as ParsedHttpParameter with type=COOKIE. Tested via valueOffsets(). Listed in INSP-04 explicitly. | ✓ |
| XML_ELEMENT | XML body with <field>value</field>; resolver falls through to substring-match. Listed in INSP-04 explicitly under "JSON/XML body field substrings". | ✓ |
| PATH_SEGMENT | Numeric or UUID-shaped path id; resolver falls through to pathIdPattern regex. NOT listed in INSP-04 (lives outside the five sub-cases) — audit-discretion add. | ✓ |

**User's choice:** All four sub-cases — full coverage of `matchInsertionPoint` branches, including the discretionary PATH_SEGMENT branch.

### Test layout

| Option | Description | Selected |
|--------|-------------|----------|
| One @Test per sub-case (Recommended) | Four new methods: matchInsertionPointPicksBodyParam / Cookie / XmlElement / PathSegment. Mirrors the existing matchInsertionPointPicksOverlappingUrlParam style. Reads cleanly, fails atomically. | ✓ |
| Parameterized @ParameterizedTest | Single method with a CSV/MethodSource feeding all sub-cases. Tighter, but mixes Mockito-Kotlin mock construction with parameterization — not currently a pattern in this repo. | |
| One combined @Test asserting all sub-cases | Faster to write but a single failure obscures which sub-case broke. Not consistent with existing test granularity. | |

**User's choice:** One @Test per sub-case (mirror existing style; atomic failures).

### Header allowlist branch

| Option | Description | Selected |
|--------|-------------|----------|
| Default empty allowlist (Recommended) | matchInsertionPoint defaults headerAllowlist = emptySet() and skips the allowlist gate when empty. Existing UI call site uses the default. Keep tests aligned: empty allowlist, any header matches. | |
| Test both empty and non-empty allowlists | Lock both branches. Adds a second header sub-case test asserting non-allowlisted header returns null. More thorough but the UI never actually passes a non-empty allowlist today. | ✓ |

**User's choice:** Lock both branches. The non-empty allowlist branch is supported in the resolver code; without a test it can drift silently even though no caller exercises it today.

---

## Queue assertion strategy (INSP-03)

### How to assert priority=60 and one-target-per-class

| Option | Description | Selected |
|--------|-------------|----------|
| scanner.getQueueItems() snapshot (Recommended) | Reuse the pattern from ActiveScannerQueueModelTest. Call manualScanInsertionPoint with N vuln classes, assert getQueueItems(limit=N+1).size == N and every item's priority == 60. Behavioural — same shape as the existing queue-model tests. | ✓ |
| Reflection peek into private scanQueue | Use javaClass.getDeclaredField("scanQueue").isAccessible = true. Pattern exists for PassiveAiScannerConfidenceTest. Brittle to refactors; getQueueItems already exposes what we need. | |
| Refactor manualScanInsertionPoint to return List<ActiveScanTarget> | Change the production signature so the test asserts on the return value. Cleanest test but changes public API for a test-only need — scope creep risk in a behavioural audit. | |

**User's choice:** `scanner.getQueueItems()` snapshot pattern — behavioural and consistent with the existing queue tests.

### Coverage in one test vs. several

| Option | Description | Selected |
|--------|-------------|----------|
| Multi-class + priority + dedup-bypass in one test (Recommended) | Single @Test: queue with 3 vuln classes, getQueueItems().size == 3, every priority == 60, vulnHint.vulnClass set covers all 3, then re-invoke and assert size == 6 (no dedup like queueTarget). Matches the existing ActiveScannerQueueModelTest density. | ✓ |
| Separate @Test per invariant | Three small tests: priority-is-60, one-per-class-no-duplicates, dedup-bypass-on-reinvoke. Easier to read; more boilerplate around scanner builder. | |
| Skip dedup-bypass assertion here | Cover dedup-bypass in Area 4 (audit scope boundary) instead. This test focuses solely on INSP-03's exact wording. | |

**User's choice:** Multi-class + priority + dedup-bypass in one dense test. Matches existing `ActiveScannerQueueModelTest` density.

### Test file placement

| Option | Description | Selected |
|--------|-------------|----------|
| Extend ActiveScannerQueueModelTest.kt (Recommended) | Existing file already has newScannerForQueueTests() builder + requestResponse() helper. Add @Test methods alongside manualScanPopulatesQueueSnapshotAndRespectsLimit / cancelQueuedTargetRemovesOnlyMatchingId. Reuses fixtures, fast suite. | ✓ |
| New file ActiveAiScannerInsertionPointTest.kt | Separate concerns by feature; copies the scanner builder. More files, slight duplication of helpers. | |

**User's choice:** Extend the existing `ActiveScannerQueueModelTest.kt`; reuse the builders.

### HTTP harness

| Option | Description | Selected |
|--------|-------------|----------|
| No HTTP harness needed (Recommended) | manualScanInsertionPoint operates purely on in-memory ActiveScanTarget queueing — no outbound HTTP until the executor pulls from the queue. We're locking the queueing contract, not the execution path. Plain mocks suffice. | ✓ |
| Include AiBackend mock to verify scanner doesn't auto-execute | Add a mock supervisor.sendChat to assert it was NOT called — locks that manualScanInsertionPoint just queues, doesn't run. Belt-and-suspenders; the assertion is implicit in the snapshot containing QUEUED status. | |

**User's choice:** No HTTP harness. The `QUEUED` status in the snapshot already proves the executor wasn't invoked.

---

## Menu visibility test (INSP-01 + INSP-02)

### Test strategy

| Option | Description | Selected |
|--------|-------------|----------|
| Resolver-only + manual smoke (Recommended) | INSP-02 is provable via matchInsertionPointReturnsNullWhenSelectionMissesEverything (already exists). INSP-01 + UI-builder branches (no editor / wrong selection context / empty range / no request) are covered by a one-paragraph manual smoke in the HUMAN-UAT artefact — mirror Phase 1 D-06 pattern. UiActions is heavy Swing/Montoya code; a unit test gives weak signal vs. the smoke. | ✓ |
| Add a Mockito UiActions test | Mock ContextMenuEvent + MessageEditorHttpRequestResponse + Selection + Range + HttpRequest. Assert buildAiScanInsertionPointItem returns null for: wrong selectionContext, no offsets, selectionEnd <= selectionStart, no request, resolver returns null. Returns non-null when resolver matches. Heavy mock setup; locks UI branches. | |
| Refactor menu-visibility into a pure policy function | Extract a fun shouldShowAiScanInsertionPointItem(editor): InjectionPoint? from buildAiScanInsertionPointItem and unit-test that. Cleanest isolation; refactor touches production code purely for testability — scope creep risk in a behavioural audit. | |

**User's choice:** Resolver-only test + manual smoke. Mirrors the Phase 1 D-06 pattern (`01-HUMAN-UAT.md`).

### Manual smoke depth

| Option | Description | Selected |
|--------|-------------|----------|
| Six positive + negative scenarios in real Burp (Recommended) | Maintainer right-clicks in Repeater/Proxy: (1) selection in URL param value — menu shows, (2) selection in body param value — menu shows, (3) selection in cookie value — menu shows, (4) selection in header line — menu shows, (5) selection in JSON value — menu shows, (6) empty selection or whitespace-only selection — menu hidden. Record screenshots or a short paragraph per scenario in 02-HUMAN-UAT.md. | ✓ |
| Three scenarios (one positive per surface + one negative) | Lean smoke: positive URL param, positive header, negative empty selection. Faster to run, less audit-trail coverage. | |
| No smoke — trust the resolver tests | Treat the resolver's null path as proof of menu-hiding. Trade-off: an UiActions regression (e.g., bug in selectionContext().name guard) ships untested. | |

**User's choice:** Six scenarios (five positives + one negative) recorded in `02-HUMAN-UAT.md`.

---

## Audit scope boundary

### Adjacent invariants to lock

| Option | Description | Selected |
|--------|-------------|----------|
| Out-of-scope returns 0 + doesn't queue | When scopeOnly && !api.scope().isInScope(url), method returns 0 and queues nothing. Quick test (scopeOnly = true, scope mock returns false), one assertion. Strong audit-trail signal. | ✓ |
| ScanPolicy.PASSIVE_ONLY filtering | Vuln classes in PASSIVE_ONLY_VULN_CLASSES are filtered out before queueing. Tests that passing a PASSIVE_ONLY class results in fewer queued targets. Locks the existing private filter — a regression here is silent today. | ✓ |
| Dedup-bypass on re-invoke | Already folded into the Area 2 multi-class queue test per the user's earlier selection — NOT a separate test, but call out in CONTEXT.md as locked behavior. | ✓ |
| Queue-full path returns short count | When the queue is at maxQueueSize, manualScanInsertionPoint returns fewer than requested (offerIfQueueNotFull rejects). Test: set maxQueueSize = 2, request 5 classes, assert return = 2. UI surfaces this via JOptionPane warning. | ✓ |

**User's choice:** All four. Dedup-bypass remains folded into the dense Area 2 queue test; the other three become individual `@Test` methods in `ActiveScannerQueueModelTest`.

---

## Claude's Discretion

- Exact wording of new test method names — CamelCase preferred for ktlint friendliness; planner picks final names.
- Choice of `kotlin.test.*` vs JUnit 5 `Assertions.*` imports — match whichever style already lives in the file being extended.
- Whether to factor out a tiny `parsedParam(...)` helper for the four new resolver sub-case tests, only if boilerplate repeats more than three times.
- Whether to reuse existing `rangeMock(...)` / `byteArrayMock(...)` helpers (yes, reuse) or add new variants.

## Deferred Ideas

- `buildAiScanInsertionPointItem` unit test — covered by manual smoke; revisit if a regression slips through.
- Refactor of `buildAiScanInsertionPointItem` to a pure `shouldShow(...)` policy function — production change driven solely by testability; not justified by INSP-01..04.
- `AiScanCheck.kt` integration tests — the other half of the "Insertion-point integration" coverage gap in `TESTING.md`; separate audit surface, post-v0.7.0 candidate.
- Active-scan executor path (`executeScan`, payload running, response analysis) — different audit.
- `valueOffsets()` null-handling — Montoya internals; the resolver gracefully continues.
- Nested JSON object / array field extraction — current `extractJsonFields` is shallow-only.
- Body substring match collisions when multiple body fields share the same value — first-occurrence priority is documented in `matchInsertionPoint`'s kdoc.
- Real-Burp UI smoke automation (headless Burp + AWT robot) — well beyond this audit's scope.
