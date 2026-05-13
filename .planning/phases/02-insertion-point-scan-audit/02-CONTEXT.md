# Phase 2: Insertion-Point Scan Audit - Context

**Gathered:** 2026-05-13
**Status:** Ready for planning

<domain>
## Phase Boundary

Audit the "AI Scan on Selected Insertion Point" feature that already shipped in `[Unreleased]` and lock its behaviour with tests so regressions cannot land in v0.7.0. The right-click menu hook (`UiActions.buildAiScanInsertionPointItem`), the selection-to-insertion-point resolver (`InjectionPointExtractor.matchInsertionPoint`), and the active-scan queueing entry point (`ActiveAiScanner.manualScanInsertionPoint`) are the audit surface.

**This phase is a behaviour-locking audit, not a feature build.** The code is shipped — the work is verifying it matches INSP-01..04, filling test gaps explicitly named in `.planning/codebase/TESTING.md` ("Known Coverage Gaps → Insertion-point integration"), and recording a one-time manual UI smoke for the menu-visibility branches that don't reduce to a unit test.

**In scope:**
- Unit tests for the four `matchInsertionPoint` sub-cases currently uncovered (BODY_PARAM, COOKIE, XML_ELEMENT, PATH_SEGMENT) plus a non-empty `headerAllowlist` branch.
- Unit tests for `manualScanInsertionPoint`'s queueing contract: priority=60, one target per filtered vuln class, dedup-bypass on re-invoke, out-of-scope returns 0, `ScanPolicy.PASSIVE_ONLY_VULN_CLASSES` filtering, queue-full returns short count.
- A six-scenario manual smoke in real Burp recorded in `02-HUMAN-UAT.md` covering the UI builder branches (selection in URL param / body param / cookie / header / JSON value → menu shows; empty selection → menu hidden).

**Out of scope (deferred):** refactoring `buildAiScanInsertionPointItem` to extract a pure policy function, unit-mocking the UI builder against `ContextMenuEvent`/`MessageEditorHttpRequestResponse`/`Range`, tests for the executor path (`executeScan`, payload running), nested JSON object/array field extraction (current extractor is shallow only), Montoya `valueOffsets()` null-handling edge cases, and any production-code change beyond test scaffolding.

</domain>

<decisions>
## Implementation Decisions

### Resolver sub-case coverage (INSP-04)

- **D-01:** Add four new `@Test` methods in `src/test/kotlin/com/six2dez/burp/aiagent/scanner/InjectionPointExtractorTest.kt`, mirroring the existing `matchInsertionPointPicksOverlappingUrlParam` style:
  1. `matchInsertionPointPicksBodyParam` — POST with `application/x-www-form-urlencoded` body; mock `ParsedHttpParameter(type=BODY)` with `valueOffsets()` returning a `Range` over the body byte span; selection inside the value resolves to `InjectionType.BODY_PARAM`.
  2. `matchInsertionPointPicksCookie` — request with `Cookie: session=abc` header; mock `ParsedHttpParameter(type=COOKIE)` with `valueOffsets()` over `abc`; selection inside `abc` resolves to `InjectionType.COOKIE`.
  3. `matchInsertionPointPicksXmlElement` — POST with `Content-Type: application/xml` body `<order><id>42</id></order>`; selection inside `42` resolves to `InjectionType.XML_ELEMENT` with `name = "id"`. Falls through to substring branch (3) of the resolver.
  4. `matchInsertionPointPicksPathSegment` — URL `http://example.com/api/users/12345`; selection inside `12345` resolves to `InjectionType.PATH_SEGMENT` with `originalValue = "12345"`. Falls through to branch (4) — `pathIdPattern` regex.
- **D-02:** One `@Test` per sub-case (matches the existing test granularity in this file; failures are atomic). No `@ParameterizedTest` — that pattern is not used in this repo for Mockito-Kotlin-heavy fixtures.
- **D-03:** Lock both empty and non-empty `headerAllowlist` branches in `matchInsertionPoint`:
  - The existing `matchInsertionPointFallsBackToHeaderWhenSelectionHitsHeaderLine` already covers the empty-allowlist branch (default `headerAllowlist = emptySet()` → no filtering).
  - Add a new `matchInsertionPointRespectsNonEmptyHeaderAllowlist` — pass `headerAllowlist = setOf("x-foo-only")`, request has `X-Forwarded-Host: attacker.com`, selection hits that header line, assert `null` is returned (the line is not in the allowlist). The UI never actually passes a non-empty allowlist today, but the resolver supports it — lock the branch so it doesn't drift silently.

### Queue assertion strategy (INSP-03)

- **D-04:** Use the `scanner.getQueueItems(limit)` snapshot pattern established in `ActiveScannerQueueModelTest` for all queueing assertions. Behavioural — no reflection into the private `ConcurrentLinkedQueue<ActiveScanTarget>` and no production-API change to expose internals.
- **D-05:** Single dense `@Test` `manualScanInsertionPointQueuesOnePerClassAtPriority60WithoutDedup` that exercises three invariants in one method:
  1. Queue three vuln classes, assert `getQueueItems(limit = 10).size == 3`.
  2. Assert every snapshot item has `priority == 60` and the `vulnHint.vulnClass` set equals the requested set.
  3. Re-invoke `manualScanInsertionPoint` with the same insertion point and the same vuln classes; assert `getQueueItems(limit = 10).size == 6` (dedup-bypass — `manualScanInsertionPoint` deliberately skips the `processedTargets` window used by `queueTarget`, per its kdoc).
- **D-06:** All new queue tests live in `src/test/kotlin/com/six2dez/burp/aiagent/scanner/ActiveScannerQueueModelTest.kt` — reuses the existing `newScannerForQueueTests()` builder and `requestResponse()` helper. No new test file.
- **D-07:** No HTTP harness (no `MockWebServer`). `manualScanInsertionPoint` operates purely on the in-memory queue; the scanner does not auto-execute targets in these tests. The `QUEUED` status visible in the snapshot is the proof.

### Menu visibility test strategy (INSP-01 + INSP-02)

- **D-08:** Skip a Mockito-Kotlin unit test of `UiActions.buildAiScanInsertionPointItem`. Reasons:
  - `ContextMenuEvent` + `MessageEditorHttpRequestResponse` + `Selection` + `Range` + `HttpRequest` would all need to be mocked together for each of five UI-only branches (no editor / wrong selectionContext / no offsets / empty range / no request / resolver null). The setup-to-signal ratio is poor.
  - INSP-02 (menu hidden when no candidate) is provable via `matchInsertionPointReturnsNullWhenSelectionMissesEverything` (already exists in `InjectionPointExtractorTest`). The UI builder hides the menu by returning `null` when the resolver returns `null` — that contract is one line.
  - The UI guards above the resolver (selectionContext, offsets, request presence) are caught by the manual smoke described in D-09; a unit test gives weak signal vs. an actual right-click in Burp.
- **D-09:** Record a six-scenario manual smoke in `02-HUMAN-UAT.md` (mirrors Phase 1 D-06 / `01-HUMAN-UAT.md` pattern). Maintainer right-clicks in Repeater and Proxy on a request with a text selection and confirms the expected menu state:
  1. Selection inside a URL parameter value → **menu shows** with label `AI Scan on Selected Insertion Point (url param: <name>)`.
  2. Selection inside a body parameter value (form-encoded body) → menu shows with `body param: <name>` label.
  3. Selection inside a cookie value → menu shows with `cookie: <name>` label.
  4. Selection inside a header line (e.g. `User-Agent`) → menu shows with `header: <name>` label.
  5. Selection inside a JSON value (e.g. `"email":"alice@example.com"` → select `alice@example.com`) → menu shows with `json field: <name>` label.
  6. Empty selection or whitespace-only selection inside the editor → **menu does not appear**.
  Each scenario gets one paragraph (Burp edition, request used, observed label or absence, date). Not a test; an audit trail.

### Audit scope boundary — adjacent invariants

- **D-10:** Lock out-of-scope short-circuit: add `manualScanInsertionPointReturnsZeroAndDoesNotQueueWhenOutOfScope` in `ActiveScannerQueueModelTest`. Construct scanner with `scopeOnly = true`, mock `api.scope().isInScope(...)` to return `false`, invoke `manualScanInsertionPoint`, assert return value is `0` and `getQueueItems(limit = 10).isEmpty()`. The same scope predicate gates `manualScan` and `queueTarget`; this test locks it on the new path.
- **D-11:** Lock `ScanPolicy.PASSIVE_ONLY_VULN_CLASSES` filtering on the manual-insertion-point path: add `manualScanInsertionPointFiltersPassiveOnlyVulnClasses`. Pass a mix of passive-only and active-eligible classes; assert only the active-eligible ones are queued. `ScanPolicy.PASSIVE_ONLY_VULN_CLASSES` is defined in `src/main/kotlin/com/six2dez/burp/aiagent/scanner/ActiveScanModels.kt` line 110.
- **D-12:** Dedup-bypass is **folded into D-05** (the dense queue test). Do not write a separate test — the third invariant in `manualScanInsertionPointQueuesOnePerClassAtPriority60WithoutDedup` already locks it. Documented here as a captured behaviour, not a separate task.
- **D-13:** Lock queue-full short-count return: add `manualScanInsertionPointReturnsShortCountWhenQueueFull`. Set `maxQueueSize = 2`, request 5 vuln classes, assert return value is `2` (or less than 5) and `getQueueItems(limit = 10).size == 2`. The UI surfaces this via a `JOptionPane` "queue full" warning; the test locks the underlying return contract.

### Claude's Discretion

- Exact wording of new test method names — both CamelCase and backtick styles are accepted in this repo (per `.planning/codebase/CONVENTIONS.md` and Phase 1 D-07). Prefer CamelCase for ktlint friendliness; planner picks final names.
- Choice of `kotlin.test.*` vs JUnit 5 `Assertions.*` imports in the new methods — match whichever style already lives in the file being extended (`InjectionPointExtractorTest` uses `kotlin.test.*`, `ActiveScannerQueueModelTest` mixes JUnit Assertions with `kotlin.test.assertEquals`). Do not introduce a third style.
- Whether to factor out a tiny helper `parsedParam(type, name, value, valueOffsets)` for the four new resolver sub-case tests if the boilerplate gets long — only if the same six `whenever(...)` lines repeat three or more times.
- Whether to use the `rangeMock(...)` and `byteArrayMock(...)` helpers already in `InjectionPointExtractorTest.kt` (yes, reuse) or add new variants. Use what's there.

</decisions>

<canonical_refs>
## Canonical References

**Downstream agents MUST read these before planning or implementing.**

### Authoritative behavioural spec
- `.planning/REQUIREMENTS.md` § "AI Scan on Insertion Point" — INSP-01..04 are the requirements this phase locks.
- `.planning/ROADMAP.md` § "Phase 2: Insertion-Point Scan Audit" — four success criteria; criteria #1 and #2 are satisfied by the resolver tests + manual smoke (D-09), #3 by D-05, #4 by D-01.
- `SPEC.md` §4.2 (Context menu actions) — the right-click menu surface this feature lives on. Phase 5 (Documentation Refresh) updates §4.2 or §5.2 to document the entry; Phase 2 only verifies the in-code contract is consistent with §4.2's listed actions.
- `SPEC.md` §5.2 (Active AI scanner) — declares the active scan queue this feature feeds into; "integrated with Burp's native active scanner via `ScanCheck` registration".
- `CHANGELOG.md` `[Unreleased]` § "Added" — the declarative description of "AI Scan on Selected Insertion Point" must be treated as authoritative for what behaviour the audit locks.

### Architecture decisions
- `DECISIONS.md` ADR-4 (HTTP vs CLI backend hierarchies) — `ActiveAiScanner` is part of the active-scan path; tests must not depend on `CliBackend` plumbing.
- `DECISIONS.md` ADR-5 (Privacy redaction pre-flight) — active-scan targets carry the unredacted `HttpRequestResponse` because the executor applies redaction at dispatch time; the queueing tests do not exercise dispatch and therefore do not need to assert redaction. Calling this out so downstream agents don't add redaction assertions to queue tests.

### Codebase intel
- `.planning/codebase/STACK.md` § "Testing" — JUnit Jupiter 6.0.3, Mockito-Kotlin 5.4.0; both already used by the two test files this phase extends.
- `.planning/codebase/TESTING.md` § "Known Coverage Gaps → Insertion-point integration (`AiScanCheck`)" — explicitly names this audit as scheduled coverage. The new tests in D-01..D-13 close this gap. Note: `AiScanCheck.kt` itself is **not** in scope this phase — that file bridges Burp's `ScanCheck` SPI into our scanner; the manual-insertion-point path bypasses it.
- `.planning/codebase/CONVENTIONS.md` § "Scanner" / § "Tests" — documents the `getQueueItems(limit)` snapshot pattern reused in D-04 and the manual-vs-passive scan separation.
- `.planning/codebase/STRUCTURE.md` § "scanner/" and § "ui/" — file layout for the source under audit and the test files being extended.

### Source files under audit
- `src/main/kotlin/com/six2dez/burp/aiagent/scanner/InjectionPointExtractor.kt` lines 152–256 (`matchInsertionPoint`) — the resolver. Four-tier fallback: parsed parameters via `valueOffsets()` → headers via raw-byte scan → JSON/XML body via substring → path segment IDs.
- `src/main/kotlin/com/six2dez/burp/aiagent/scanner/ActiveAiScanner.kt` lines 204–256 (`manualScanInsertionPoint`) — queue entry point with `priority = 60` hardcoded at line 235; filters via `ScanPolicy.PASSIVE_ONLY_VULN_CLASSES` (line 222) and `ScanPolicy.isAllowedForMode` (line 223); short-circuits on out-of-scope at line 225; defers queue-full handling to `offerIfQueueNotFull` (line 237).
- `src/main/kotlin/com/six2dez/burp/aiagent/scanner/ActiveScanModels.kt` lines 109–177 — `object ScanPolicy` defines `PASSIVE_ONLY_VULN_CLASSES` (line 110) and `pentestClasses()` (line 177); also defines `ActiveScanTarget` data class with the `priority: Int` field that D-05 asserts.
- `src/main/kotlin/com/six2dez/burp/aiagent/ui/UiActions.kt` lines 316–417 (`buildAiScanInsertionPointItem`) — UI hook. **Read but do not extend with tests this phase** (D-08); manual smoke (D-09) is the proof-of-behaviour.

### Test scaffolding to lean on
- `src/test/kotlin/com/six2dez/burp/aiagent/scanner/InjectionPointExtractorTest.kt` — 7 existing tests including `matchInsertionPointPicksOverlappingUrlParam`, `matchInsertionPointFallsBackToHeaderWhenSelectionHitsHeaderLine`, `matchInsertionPointReturnsNullWhenSelectionMissesEverything`, `matchInsertionPointPicksJsonFieldWhenSelectionInBody`. New methods in D-01 + D-03 extend this file. Reuse `byteArrayMock(text)` and `rangeMock(start, end)` helpers (lines 189–203).
- `src/test/kotlin/com/six2dez/burp/aiagent/scanner/ActiveScannerQueueModelTest.kt` — `newScannerForQueueTests()` builder (returns an `ActiveAiScanner` with `scopeOnly = false`, `maxQueueSize = 64`, `scanMode = ScanMode.FULL`) and `requestResponse(url, name, value)` helper. New methods in D-05, D-10, D-11, D-13 extend this file. D-10 will need to flip `scopeOnly = true` after construction; D-13 will need to lower `maxQueueSize`.
- `src/test/kotlin/com/six2dez/burp/aiagent/TestSettings.kt` — `baselineSettings()` factory. Used inside `newScannerForQueueTests()` via `getSettings = { baselineSettings() }`. Do not hand-roll an `AgentSettings(...)` here.

### Cross-phase reference
- `.planning/phases/01-perplexity-backend-audit/01-CONTEXT.md` — Phase 1 set the precedent for behavioural test scope, fast-suite placement, and a one-time manual smoke (D-06 in that phase) recorded in the verification artefact. This phase reuses that pattern for D-09.

</canonical_refs>

<code_context>
## Existing Code Insights

### Reusable Assets
- **`InjectionPointExtractor.matchInsertionPoint`** — already implements all four sub-cases the audit verifies (URL/BODY/COOKIE via `valueOffsets()`, header line scan, JSON/XML body substring, path segment regex). The audit only writes tests against existing behaviour; no production change.
- **`ActiveAiScanner.manualScanInsertionPoint`** — already enforces `priority = 60`, scope predicate, `ScanPolicy` filtering, and queue-full short-count via `offerIfQueueNotFull`. The audit locks each contract.
- **`UiActions.buildAiScanInsertionPointItem`** — already returns `null` (hiding the menu) when any of the five guards fail or the resolver returns `null`. The audit proves this via the manual smoke (D-09).
- **`ActiveScannerQueueModelTest.newScannerForQueueTests()` + `requestResponse(...)`** — scanner builder and request-response factory already in place; new tests just call them.
- **`InjectionPointExtractorTest.byteArrayMock(text)` + `rangeMock(start, end)`** — helpers for mocking Montoya `ByteArray` and `Range` — reuse in all four new resolver sub-case tests.
- **`TestSettings.baselineSettings()`** — canonical `AgentSettings` fixture; do not hand-roll.

### Established Patterns
- **Test method naming:** CamelCase preferred for ktlint friendliness (Phase 1 D-07; `.planning/codebase/CONVENTIONS.md`). Backticked names are accepted but not preferred.
- **Resolver test pattern:** mock `HttpRequest` + `ParsedHttpParameter`/`HttpHeader` with Mockito-Kotlin's `mock<>()` + `whenever(...).thenReturn(...)`; never use `Answers.RETURNS_DEEP_STUBS` here (the resolver-side tests do not need chained Montoya calls).
- **Queue test pattern:** construct scanner via `newScannerForQueueTests()`, exercise the public method, snapshot via `scanner.getQueueItems(limit)`, assert size + per-item invariants. Fast-suite.
- **Fast-suite only:** no `*IntegrationTest` / `*ConcurrencyTest` / `*BackpressureTest` / `*RestartPolicyTest` suffix on any new file. All tests in this phase run on `./gradlew test -PexcludeHeavyTests=true`.
- **Manual smoke pattern:** one-paragraph entries in `${padded_phase}-HUMAN-UAT.md` listing scenario, request used, expected vs. observed, date, Burp edition. Mirrors Phase 1's `01-HUMAN-UAT.md`.

### Integration Points
- **Burp Montoya context menu:** `UiActions.requestResponseMenuItems` is the entry point that surfaces every right-click action including AI Scan on Selected Insertion Point. Existing integration via `App.kt` wiring — no new wiring this phase.
- **Active scanner queue:** `ActiveAiScanner.scanQueue` is fed by `queueTarget` (passive→active escalation), `manualScan` (bulk request menu), `manualScanInsertionPoint` (this phase's path), and `AiScanCheck` (Burp's `ScanCheck` SPI). The four entry points are independent; testing one doesn't touch the others.
- **Privacy redaction:** applied at dispatch time on the executor, not at queue time. Queue tests do not need privacy mocks.
- **Vuln class picker dialog:** `UiActions.showVulnClassSelectionDialog(tab)` is reused (it's the same dialog as the bulk request menu). Not extended this phase.

</code_context>

<specifics>
## Specific Ideas

- **Test method names (provisional):**
  - `matchInsertionPointPicksBodyParam`
  - `matchInsertionPointPicksCookie`
  - `matchInsertionPointPicksXmlElement`
  - `matchInsertionPointPicksPathSegment`
  - `matchInsertionPointRespectsNonEmptyHeaderAllowlist`
  - `manualScanInsertionPointQueuesOnePerClassAtPriority60WithoutDedup`
  - `manualScanInsertionPointReturnsZeroAndDoesNotQueueWhenOutOfScope`
  - `manualScanInsertionPointFiltersPassiveOnlyVulnClasses`
  - `manualScanInsertionPointReturnsShortCountWhenQueueFull`
- **Body-param sub-case detail (D-01.1):** mock `HttpParameterType.BODY` and `valueOffsets()` returning a `Range` over the body byte span. Selection inside that range must resolve via branch 1 of the resolver (parsed parameters), not via the substring fallback. Trigger an assertion that distinguishes the two branches: assert `match.position == value.startIndexInclusive()` (only branch 1 sets `position` from `valueOffsets`).
- **Cookie sub-case detail (D-01.2):** same shape as body param but `type=COOKIE`. The cookie header value (`session=abc`) is parsed by Montoya into a `ParsedHttpParameter` whose `valueOffsets()` points at `abc` inside the raw cookie line.
- **XML sub-case detail (D-01.3):** branch 3 substring match — request has no parsed parameters, `Content-Type: application/xml`, body `<order><id>42</id></order>`. Resolver runs `extractXmlElements(body, ...)` and returns the first `InjectionPoint` whose value substring overlaps the selection.
- **Path-segment sub-case detail (D-01.4):** URL is `http://example.com/api/users/12345`; selection is inside the absolute byte offset of `12345` in the raw request bytes. The resolver translates path-relative offsets to absolute via `pathStart + match.range.first`; the test must replicate that translation in its selection setup.
- **Non-empty allowlist detail (D-03):** the test asserts `null` is returned, not a different `InjectionPoint`. The header line still exists; the filter just causes the `firstOrNull` to skip it.
- **Dedup-bypass assertion (D-05.3):** when re-invoking with the same `InjectionPoint` (same `name`/`originalValue`), `queueTarget`'s `processedTargets` window would dedup; `manualScanInsertionPoint` deliberately bypasses that map (it never calls `queueTarget`; it calls `offerIfQueueNotFull` directly at line 237). The test proves this by asserting `size == 2 * N` after two invocations.
- **Out-of-scope detail (D-10):** the scope check is at line 225 of `ActiveAiScanner.kt`, BEFORE the per-class loop. So a scope miss returns 0 with **no** loop iterations and **no** `offerIfQueueNotFull` calls. The assertion: `count == 0` and `getQueueItems(limit = 10).isEmpty()`.
- **Passive-only filter detail (D-11):** `ScanPolicy.PASSIVE_ONLY_VULN_CLASSES` (defined in `ActiveScanModels.kt` line 110) lists classes that the active scanner refuses to take. Pick at least one class from that set and one not in the set; assert only the non-set class ends up queued. Specific class choice belongs to the planner — they should grep the set to pick stable members.
- **Queue-full detail (D-13):** set `maxQueueSize = 2` in the test, request 5 distinct vuln classes (all active-eligible). `offerIfQueueNotFull` rejects items 3, 4, 5. Assert `count <= 2`. Slight ordering variability is acceptable as long as the inequality holds — `ConcurrentLinkedQueue.size()` is O(n) but the test holds the lock implicitly via single-threaded invocation.
- **Manual smoke artefact (D-09):** lives at `.planning/phases/02-insertion-point-scan-audit/02-HUMAN-UAT.md`. The planner generates the structure; the executor records the maintainer's smoke after the test code is in. Phase 1 used `01-HUMAN-UAT.md` for the same purpose.

</specifics>

<deferred>
## Deferred Ideas

- **`buildAiScanInsertionPointItem` unit test** — covered by manual smoke; revisit if a regression slips through.
- **Refactor of `buildAiScanInsertionPointItem` to extract a pure `shouldShow(...)` policy function** — production-code change driven solely by testability; not justified by the four success criteria. Future phase if the smoke ever catches a regression.
- **`AiScanCheck.kt` integration tests** — the other half of the "Known Coverage Gaps → Insertion-point integration" entry in `TESTING.md`. That file bridges Burp's `ScanCheck` SPI into our scanner; it is a separate audit surface (passive→active escalation triggered by Burp Pro). Out of scope for INSP-01..04; capture as a follow-up audit phase or post-v0.7.0 milestone item.
- **Active-scan executor path (`executeScan`, payload running, response analysis)** — different surface; the queueing contract is what this phase locks.
- **`valueOffsets()` null-handling** — branch 1 of the resolver does `param.valueOffsets() ?: continue`. The graceful skip is in place but not directly asserted. Acceptable; Montoya virtually always returns offsets for parsed params.
- **Nested JSON object / array field extraction** — `extractJsonFields` is shallow only (top-level keys). The audit does not extend this; matches existing scanner behaviour.
- **Body substring match collisions** — when multiple body fields contain identical values, the resolver picks the first occurrence (documented in `matchInsertionPoint`'s kdoc). Not in INSP-04; out of audit scope.
- **Real-Burp UI smoke automation** — would require headless Burp + AWT robot; well beyond this audit. The maintainer-run smoke (D-09) is the agreed substitute.

</deferred>

---

*Phase: 2-Insertion-Point Scan Audit*
*Context gathered: 2026-05-13*
