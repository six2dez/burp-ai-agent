# Phase 2: Insertion-Point Scan Audit — Research

**Researched:** 2026-05-13
**Domain:** Kotlin/JUnit5/Mockito-Kotlin behaviour-locking test audit of an already-shipped Burp Montoya feature (selection → insertion-point resolver + active-scan queue entry point)
**Confidence:** HIGH

## Summary

This phase is a **behaviour-locking test audit** of three production surfaces that already shipped in `[Unreleased]`: `InjectionPointExtractor.matchInsertionPoint` (selection-to-insertion-point resolver), `ActiveAiScanner.manualScanInsertionPoint` (queue entry point for the right-click action), and `UiActions.buildAiScanInsertionPointItem` (the right-click menu builder itself). The phase writes **eight new unit tests** across two existing test files (no new test files) plus a **six-scenario maintainer-run manual smoke** recorded in `02-HUMAN-UAT.md`. No production code changes.

CONTEXT.md (D-01..D-13) is exceptionally thorough and locks the test approach. This research **does not re-litigate those decisions**; it surfaces the concrete Montoya API signatures, exact line numbers, exact `ScanPolicy.PASSIVE_ONLY_VULN_CLASSES` members, and three landmines the planner must address: (1) how to mock `api.scope().isInScope(...)` for D-10, (2) the byte-offset arithmetic shape for the four new resolver tests (especially path-segment), and (3) the fact that `ScannerQueueBackpressureTest.kt` (a heavy-suite test using a similar pattern) already exists — D-13's new queue-full test must NOT use the `*BackpressureTest` suffix and must live in `ActiveScannerQueueModelTest.kt`.

**Primary recommendation:** Extend `InjectionPointExtractorTest.kt` with four resolver sub-case tests + one non-empty allowlist test (5 new methods), extend `ActiveScannerQueueModelTest.kt` with four queue-contract tests (4 new methods), and create `02-HUMAN-UAT.md` from the Phase 1 template. No new files, no test framework changes, no new dependencies.

## Project Constraints (from CLAUDE.md)

- **English only** in code, comments, and identifiers (AGENTS.md non-negotiable). Test names and KDoc must be English.
- **Kotlin (JVM 21), Gradle Kotlin DSL**, Burp Montoya API `2026.2` (compileOnly — provided at runtime).
- **No direct repo edits outside GSD workflow** — this phase is a planned audit, planning happens through `gsd-plan-phase` next.
- **MIT license** — all dependencies (JUnit Jupiter 6.0.3, Mockito-Kotlin 5.4.0) already in `build.gradle.kts`; no new deps required.

## Phase Requirements

| ID | Description | Research Support |
|----|-------------|------------------|
| INSP-01 | Right-clicking a request with a text selection in the editor shows **AI Scan on Selected Insertion Point** in the context menu | Manual smoke scenarios 1–5 in `02-HUMAN-UAT.md` (D-09). Code path: `UiActions.buildAiScanInsertionPointItem` lines 342–417 — returns a `JMenuItem` when the selection overlaps a resolved insertion point, otherwise `null` (hidden by `listOfNotNull`). |
| INSP-02 | The menu item is hidden when there is no selection or the selection overlaps no candidate parameter / header / JSON field | Existing `matchInsertionPointReturnsNullWhenSelectionMissesEverything` (lines 167–187 of `InjectionPointExtractorTest.kt`) locks the resolver returning `null`. Manual smoke scenario 6 (empty selection) covers the UI-layer guard. The builder returns `null` early when (a) editor is absent, (b) selectionContext is not REQUEST, (c) selectionOffsets is empty, (d) range is empty, (e) requestResponse is null, (f) request is null, (g) resolver returns null — all seven null-returns at lines 347–363. |
| INSP-03 | Queues exactly one `ActiveScanTarget` per selected vuln class at priority 60 (ahead of background passive queue) | New test `manualScanInsertionPointQueuesOnePerClassAtPriority60WithoutDedup` in `ActiveScannerQueueModelTest.kt` (D-05). Code: `ActiveAiScanner.kt` lines 229–240 — `priority = 60` is hardcoded at line 235; `offerIfQueueNotFull` (line 257) drops on full but does NOT consult `processedTargets` dedup. |
| INSP-04 | Selection resolution covers URL params, body params, cookies, header lines, and JSON/XML body field substrings | Four new resolver tests in `InjectionPointExtractorTest.kt` (D-01) + existing `matchInsertionPointPicksOverlappingUrlParam` (URL) + `matchInsertionPointPicksJsonFieldWhenSelectionInBody` (JSON) + `matchInsertionPointFallsBackToHeaderWhenSelectionHitsHeaderLine` (HEADER, empty allowlist). New: BODY_PARAM, COOKIE, XML_ELEMENT, PATH_SEGMENT, plus non-empty `headerAllowlist` (D-03). |

<user_constraints>
## User Constraints (from CONTEXT.md)

### Locked Decisions

**Resolver sub-case coverage (INSP-04):**
- **D-01:** Add four new `@Test` methods in `src/test/kotlin/com/six2dez/burp/aiagent/scanner/InjectionPointExtractorTest.kt`:
  1. `matchInsertionPointPicksBodyParam` — POST with `application/x-www-form-urlencoded` body; mock `ParsedHttpParameter(type=BODY)` with `valueOffsets()` returning a `Range` over the body byte span; selection inside the value resolves to `InjectionType.BODY_PARAM`.
  2. `matchInsertionPointPicksCookie` — request with `Cookie: session=abc` header; mock `ParsedHttpParameter(type=COOKIE)` with `valueOffsets()` over `abc`; selection inside `abc` resolves to `InjectionType.COOKIE`.
  3. `matchInsertionPointPicksXmlElement` — POST with `Content-Type: application/xml` body `<order><id>42</id></order>`; selection inside `42` resolves to `InjectionType.XML_ELEMENT` with `name = "id"`. Falls through to branch (3) of the resolver.
  4. `matchInsertionPointPicksPathSegment` — URL `http://example.com/api/users/12345`; selection inside `12345` resolves to `InjectionType.PATH_SEGMENT` with `originalValue = "12345"`. Falls through to branch (4) — `pathIdPattern` regex.
- **D-02:** One `@Test` per sub-case (matches existing granularity). No `@ParameterizedTest`.
- **D-03:** Lock both empty and non-empty `headerAllowlist` branches. The existing `matchInsertionPointFallsBackToHeaderWhenSelectionHitsHeaderLine` covers empty. Add a new `matchInsertionPointRespectsNonEmptyHeaderAllowlist` — pass `headerAllowlist = setOf("x-foo-only")`, request has `X-Forwarded-Host: attacker.com`, selection hits that header line, assert `null` (line not in allowlist).

**Queue assertion strategy (INSP-03):**
- **D-04:** Use the `scanner.getQueueItems(limit)` snapshot pattern. Behavioural — no reflection into the private `ConcurrentLinkedQueue<ActiveScanTarget>`.
- **D-05:** Single dense `@Test` `manualScanInsertionPointQueuesOnePerClassAtPriority60WithoutDedup` that exercises three invariants in one method: (1) queue three vuln classes, assert size == 3; (2) assert per-item `priority == 60` and the requested vuln-class set; (3) re-invoke, assert size == 6 (dedup-bypass).
- **D-06:** All new queue tests live in `src/test/kotlin/com/six2dez/burp/aiagent/scanner/ActiveScannerQueueModelTest.kt` — reuse `newScannerForQueueTests()` and `requestResponse()`. No new test file.
- **D-07:** No HTTP harness (no `MockWebServer`). `manualScanInsertionPoint` operates purely on the in-memory queue.

**Menu visibility test strategy (INSP-01 + INSP-02):**
- **D-08:** Skip a Mockito-Kotlin unit test of `UiActions.buildAiScanInsertionPointItem`. The setup-to-signal ratio is poor and INSP-02 is provable via the existing resolver-returns-null test. The UI guards above the resolver are caught by the manual smoke in D-09.
- **D-09:** Record a six-scenario manual smoke in `02-HUMAN-UAT.md` (mirrors Phase 1 `01-HUMAN-UAT.md`). Scenarios 1–5: selection in URL param / body param / cookie / header / JSON value → menu shows with the correct label. Scenario 6: empty selection → menu does not appear.

**Audit scope boundary — adjacent invariants:**
- **D-10:** Add `manualScanInsertionPointReturnsZeroAndDoesNotQueueWhenOutOfScope` — `scopeOnly = true`, mock scope to return `false`, invoke, assert return 0 and queue empty.
- **D-11:** Add `manualScanInsertionPointFiltersPassiveOnlyVulnClasses` — pass a mix of passive-only and active-eligible classes; assert only the active-eligible ones queue.
- **D-12:** Dedup-bypass is FOLDED into D-05. Do not write a separate test.
- **D-13:** Add `manualScanInsertionPointReturnsShortCountWhenQueueFull` — set `maxQueueSize = 2`, request 5 vuln classes, assert return `<= 2` and queue size `== 2`.

### Claude's Discretion

- Exact wording of new test method names — CamelCase preferred for ktlint friendliness (Phase 1 D-07).
- Choice of `kotlin.test.*` vs JUnit 5 `Assertions.*` imports — match the file being extended. `InjectionPointExtractorTest` uses `kotlin.test.*`; `ActiveScannerQueueModelTest` mixes JUnit `Assertions` with `kotlin.test.assertEquals`. Do not introduce a third style.
- Whether to factor out a tiny helper `parsedParam(type, name, value, valueOffsets)` — only if six `whenever(...)` lines repeat three or more times.
- Reuse `rangeMock(...)` and `byteArrayMock(...)` from `InjectionPointExtractorTest.kt` lines 189–203. Do not add new variants.

### Deferred Ideas (OUT OF SCOPE)

- `buildAiScanInsertionPointItem` unit test (covered by manual smoke).
- Refactor of `buildAiScanInsertionPointItem` to extract a pure `shouldShow(...)` policy function.
- `AiScanCheck.kt` integration tests (separate audit surface; bridges Burp's `ScanCheck` SPI).
- Active-scan executor path (`executeScan`, payload running, response analysis).
- `valueOffsets()` null-handling — graceful skip is in place but not asserted.
- Nested JSON object / array field extraction — `extractJsonFields` is shallow only.
- Body substring match collisions on duplicate values — documented in `matchInsertionPoint`'s kdoc; out of INSP-04.
- Real-Burp UI smoke automation (headless Burp + AWT robot).

</user_constraints>

## Architectural Responsibility Map

| Capability | Primary Tier | Secondary Tier | Rationale |
|------------|-------------|----------------|-----------|
| Right-click menu visibility | UI / Swing (`UiActions.buildAiScanInsertionPointItem`) | — | Burp Montoya context menu builder owns menu lifecycle; manual smoke is the proof. |
| Selection-to-insertion-point resolution | Scanner core (`InjectionPointExtractor.matchInsertionPoint`) | — | Pure function over `HttpRequest` + byte offsets; unit-testable in isolation via Mockito-Kotlin. |
| Active-scan queueing | Scanner core (`ActiveAiScanner.manualScanInsertionPoint`) | — | In-memory queue (`ConcurrentLinkedQueue<ActiveScanTarget>`); behaviour locked via `getQueueItems(limit)` snapshot. |
| Privacy redaction | NOT in this phase | — | Applied at executor dispatch time (ADR-5); queue tests do not exercise dispatch and must not assert redaction. |
| Vuln-class picker dialog | UI (`UiActions.showVulnClassSelectionDialog`) | — | Reused from existing bulk-request menu; not extended this phase. |
| Burp scope predicate | Burp Montoya (`api.scope().isInScope(url)`) | Scanner core (call site) | The scanner consults the predicate via `RETURNS_DEEP_STUBS`-mockable chain; D-10 locks the scanner-side branch, not the predicate itself. |

## Standard Stack

### Core

| Library | Version | Purpose | Why Standard |
|---------|---------|---------|--------------|
| JUnit Jupiter | 6.0.3 | Test runner | `[VERIFIED: build.gradle.kts line 50]` Already in fast-suite; `useJUnitPlatform()` configured. Both files extended in this phase already use it. |
| Mockito-Kotlin | 5.4.0 | Mocking | `[VERIFIED: build.gradle.kts line 52]` Standard for mocking Montoya API interfaces (`HttpRequest`, `ParsedHttpParameter`, `HttpHeader`, `Range`, `ByteArray`, `MontoyaApi`, `HttpRequestResponse`). |
| Kotlin test (`kotlin.test.*`) | — | Kotlin idiomatic assertions | `[VERIFIED: InjectionPointExtractorTest.kt lines 10–13]` `assertEquals`, `assertNull`, `assertTrue` — already used in the file extended by D-01 and D-03. Match the file's style. |

### Supporting

| Library | Version | Purpose | When to Use |
|---------|---------|---------|-------------|
| Burp Montoya API | 2026.2 | Burp interfaces | `[VERIFIED: build.gradle.kts]` `compileOnly`. Mocked via Mockito-Kotlin. **No local stubs exist** for `Range`, `ByteArray`, `ParsedHttpParameter`, `HttpHeader`, `HttpRequest`, `HttpRequestResponse`, `Scope` — only `Persistence` is locally stubbed at `burp/api/montoya/persistence/`. Tests run against the real Montoya JAR. |

### Alternatives Considered

| Instead of | Could Use | Tradeoff |
|------------|-----------|----------|
| `@ParameterizedTest` for the four resolver sub-cases | Single test method per sub-case (CHOSEN, D-02) | Parameterised would compress LOC but obscure which sub-case fails; existing file uses one method per case. Do not introduce a new pattern just for this phase. |
| MockWebServer (Phase 1 pattern) | Direct in-memory `getQueueItems(limit)` snapshot (CHOSEN, D-04) | MockWebServer is for wire-level HTTP capture. `manualScanInsertionPoint` is in-memory only; an HTTP harness adds latency, brittleness, and zero signal. |
| Reflection into private `ConcurrentLinkedQueue<ActiveScanTarget>` | Public `getQueueItems(limit)` (CHOSEN, D-04) | Reflection is durable but couples the test to private internals. Snapshot API already exposes the assertion-relevant shape (`id`, `priority` is inferred via `vulnClass` + `injectionPoint.name`; see Pitfall #4 below). |

**Installation:** No new dependencies. Existing `build.gradle.kts` already has everything needed.

**Version verification:**
```
$ grep "junit\|mockito" build.gradle.kts
50:    testImplementation("org.junit.jupiter:junit-jupiter:6.0.3")
52:    testImplementation("org.mockito.kotlin:mockito-kotlin:5.4.0")
```
`[VERIFIED: build.gradle.kts grep 2026-05-13]` Versions match `.planning/codebase/STACK.md § Testing`.

## Architecture Patterns

### System Architecture Diagram

```
                    Right-click on request in editor (Proxy/Repeater)
                                         │
                                         ▼
            ┌────────────────────────────────────────────────┐
            │ UiActions.requestResponseMenuItems (line 54)   │
            │   ─ collects targets + editor selection        │
            │   ─ builds menu items, appends                 │
            │     buildAiScanInsertionPointItem (line 318)   │
            └────────────────────────────────────────────────┘
                                         │
                                         ▼
            ┌────────────────────────────────────────────────┐
            │ buildAiScanInsertionPointItem (line 342)       │
            │   ─ 5 UI guards: editor / selectionContext /   │
            │     offsets / range / requestResponse+request  │
            │   ─ calls InjectionPointExtractor              │
            │       .matchInsertionPoint(...)                │
            │   ─ returns JMenuItem or null                  │
            └────────────────────────────────────────────────┘
                                         │
                  null ◄──── resolver miss ────┘
                  (item hidden by listOfNotNull at line 325)
                                         │
                              non-null ▼  (menu shows)
            ┌────────────────────────────────────────────────┐
            │ User clicks → ActionListener (line 369)        │
            │   ─ scanner enable gate                        │
            │   ─ showVulnClassSelectionDialog               │
            │   ─ confirmation JOptionPane                   │
            │   ─ scanner.manualScanInsertionPoint(...)      │
            │   ─ post-queue JOptionPane                     │
            └────────────────────────────────────────────────┘

                              UNDER AUDIT
                                  │
            ┌─────────────────────┴────────────────────────┐
            ▼                                              ▼
┌───────────────────────────────┐         ┌─────────────────────────────────┐
│ InjectionPointExtractor       │         │ ActiveAiScanner                 │
│   .matchInsertionPoint        │         │   .manualScanInsertionPoint     │
│   (lines 152–256)             │         │   (lines 214–255)               │
│                               │         │                                 │
│ Resolver branches:            │         │ Contract:                       │
│   1. Parsed params via        │         │   1. PASSIVE_ONLY filter        │
│      valueOffsets()           │         │   2. ScanPolicy.isAllowedForMode│
│      → URL_PARAM / BODY_PARAM │         │   3. scopeOnly + isInScope gate │
│        / COOKIE               │         │      (line 225) — return 0      │
│   2. Header line via raw-byte │         │   4. Per-class: build           │
│      indexOf() + allowlist    │         │      ActiveScanTarget with      │
│   3. JSON / XML body via      │         │      priority = 60 (line 235)   │
│      extractJsonFields /      │         │   5. offerIfQueueNotFull        │
│      extractXmlElements       │         │      (line 257) — drop if full  │
│      substring match          │         │   6. Bypasses processedTargets  │
│   4. Path segment via         │         │      dedup window (no call to   │
│      pathIdPattern regex      │         │      queueTarget at line 127)   │
│      + absolute byte offset   │         │   7. Return queued count        │
│                               │         │                                 │
│ TESTS (D-01..D-03):           │         │ TESTS (D-05, D-10, D-11, D-13): │
│   InjectionPointExtractorTest │         │   ActiveScannerQueueModelTest   │
│   .kt (extend, no new file)   │         │   .kt (extend, no new file)     │
└───────────────────────────────┘         └─────────────────────────────────┘
```

### Recommended Project Structure

No structural changes. Files extended:

```
src/test/kotlin/com/six2dez/burp/aiagent/scanner/
├── InjectionPointExtractorTest.kt    # +5 @Test methods (D-01 × 4, D-03 × 1)
└── ActiveScannerQueueModelTest.kt    # +4 @Test methods (D-05, D-10, D-11, D-13)

.planning/phases/02-insertion-point-scan-audit/
├── 02-CONTEXT.md                     # existing
├── 02-DISCUSSION-LOG.md              # existing
├── 02-RESEARCH.md                    # this file
├── 02-HUMAN-UAT.md                   # NEW — created by planner from Phase 1 template
└── 02-PLAN.md                        # NEW — created by planner
```

### Pattern 1: Resolver Sub-Case Test (D-01)

**What:** Mock `HttpRequest` with one or more `ParsedHttpParameter`s (or empty params + body), call `matchInsertionPoint(...)` with absolute byte offsets that overlap a specific candidate, assert the returned `InjectionPoint` has the expected `type`, `name`, and `originalValue`.

**When to use:** Any new resolver sub-case test (BODY_PARAM, COOKIE, XML_ELEMENT, PATH_SEGMENT).

**Example (URL param — existing, lines 87–130 of `InjectionPointExtractorTest.kt`):**

```kotlin
// Source: src/test/kotlin/com/six2dez/burp/aiagent/scanner/InjectionPointExtractorTest.kt:87
@Test
fun matchInsertionPointPicksOverlappingUrlParam() {
    val raw =
        "GET /search?q=hello&page=1 HTTP/1.1\r\n" +
            "Host: example.com\r\n\r\n"
    val qStart = raw.indexOf("hello")
    val qEnd = qStart + "hello".length
    val qRange = rangeMock(qStart, qEnd)

    val qParam = mock<ParsedHttpParameter>()
    whenever(qParam.type()).thenReturn(HttpParameterType.URL)
    whenever(qParam.name()).thenReturn("q")
    whenever(qParam.value()).thenReturn("hello")
    whenever(qParam.valueOffsets()).thenReturn(qRange)

    val request = mock<HttpRequest>()
    whenever(request.parameters()).thenReturn(listOf(qParam, ...))
    whenever(request.headers()).thenReturn(emptyList())
    whenever(request.toByteArray()).thenReturn(byteArrayMock(raw))
    whenever(request.bodyOffset()).thenReturn(raw.length)
    whenever(request.bodyToString()).thenReturn("")
    whenever(request.headerValue("Content-Type")).thenReturn(null)
    whenever(request.url()).thenReturn("http://example.com/search?q=hello&page=1")

    val match = InjectionPointExtractor.matchInsertionPoint(
        request = request,
        selectionStart = qStart + 1,
        selectionEnd = qStart + 4,
    )
    assertTrue(match != null)
    assertEquals(InjectionType.URL_PARAM, match!!.type)
    assertEquals("q", match.name)
}
```

**Adaptation for BODY_PARAM (D-01.1):** identical shape, change `HttpParameterType.URL` → `HttpParameterType.BODY`. Raw string: `"POST /api HTTP/1.1\r\nHost: example.com\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\nusername=alice&role=user"`. `valueOffsets()` of the `username` param points at `alice`. Assert `InjectionType.BODY_PARAM` and `name == "username"`.

**Adaptation for COOKIE (D-01.2):** `HttpParameterType.COOKIE`. Raw string includes `Cookie: session=abc; tracker=xyz` line. `valueOffsets()` of the `session` cookie points at `abc`. Assert `InjectionType.COOKIE` and `name == "session"`.

**Adaptation for XML_ELEMENT (D-01.3):** NO `ParsedHttpParameter` (request.parameters() returns empty). Raw string: `"POST /api HTTP/1.1\r\nHost: example.com\r\nContent-Type: application/xml\r\n\r\n<order><id>42</id></order>"`. `bodyToString()` returns `"<order><id>42</id></order>"`. Selection covers `42`'s absolute byte position. Assert `InjectionType.XML_ELEMENT`, `name == "id"`, `originalValue == "42"`. Falls through resolver branches 1 (no params) → 2 (no headers match) → 3 (XML body substring match). **Note:** The resolver's body matching translates selection offsets to body-relative via `selectionStart - bodyOffset` (line 205). The test must set `bodyOffset` correctly and pass absolute offsets.

**Adaptation for PATH_SEGMENT (D-01.4):** NO `ParsedHttpParameter`. Raw string: `"GET /api/users/12345 HTTP/1.1\r\nHost: example.com\r\n\r\n"`. `bodyToString()` empty. URL: `http://example.com/api/users/12345`. Selection covers absolute byte offset of `12345` in `raw`. Resolver line 235 does `pathStart = raw.indexOf(path)`; the test must replicate that — compute `absStart = raw.indexOf("12345")` and pass it as `selectionStart`. Assert `InjectionType.PATH_SEGMENT`, `name == "path_id"`, `originalValue == "12345"`. Falls through branches 1, 2, 3 → 4 (`pathIdPattern` regex match).

### Pattern 2: Queue-Contract Test (D-05, D-10, D-11, D-13)

**What:** Construct a scanner via `newScannerForQueueTests()`, optionally tweak its public mutable fields (`scopeOnly`, `maxQueueSize`), invoke `manualScanInsertionPoint(requestResponse, insertionPoint, vulnClasses)`, assert the return value AND the queue snapshot.

**When to use:** Any new test in `ActiveScannerQueueModelTest.kt`.

**Example (existing, lines 24–42 of `ActiveScannerQueueModelTest.kt`):**

```kotlin
// Source: src/test/kotlin/com/six2dez/burp/aiagent/scanner/ActiveScannerQueueModelTest.kt:24
@Test
fun manualScanPopulatesQueueSnapshotAndRespectsLimit() {
    val scanner = newScannerForQueueTests()
    val queued = scanner.manualScan(
        requests = listOf(
            requestResponse("http://example.com/?id=1", "id", "1"),
            requestResponse("http://example.com/?id=2", "id", "2"),
        ),
        vulnClasses = listOf(VulnClass.SQLI),
    )
    assertEquals(2, queued)
    val allItems = scanner.getQueueItems(limit = 500)
    assertEquals(2, allItems.size)
    assertTrue(allItems.all { it.status == "QUEUED" })
    assertEquals(1, scanner.getQueueItems(limit = 1).size)
}
```

**Adaptation for D-05 (`manualScanInsertionPointQueuesOnePerClassAtPriority60WithoutDedup`):** Construct an `InjectionPoint` directly (it's a `data class` — `InjectionPoint(InjectionType.URL_PARAM, "id", "1")`). Construct an `HttpRequestResponse` via `requestResponse(...)`. Invoke `scanner.manualScanInsertionPoint(rr, point, listOf(VulnClass.SQLI, VulnClass.XSS_REFLECTED, VulnClass.CMDI))`. Assert return == 3 and `getQueueItems(limit = 10).size == 3`. Then per-item: assert `injectionPoint == "URL_PARAM:id"` (note the `getQueueItems` snapshot stringifies it as `"${target.injectionPoint.type}:${target.injectionPoint.name}"`, line 283) and `vulnClass` set equals `{SQLI, XSS_REFLECTED, CMDI}`. **Priority assertion landmine:** `ActiveScanQueueItem` (lines 303–310 of `ActiveScanModels.kt`) does NOT expose `priority` directly — it only has `id, url, vulnClass, injectionPoint, status, queuedAtEpochMs`. See Pitfall #4 below.

**Adaptation for D-10 (out-of-scope):** Tweak `scanner.scopeOnly = true` after construction (it's `var` at line 90 of `ActiveAiScanner.kt`). The `api` mock is constructed with `RETURNS_DEEP_STUBS` so `api.scope()` returns a deep mock; explicitly stub `whenever(api.scope().isInScope(any<String>())).thenReturn(false)` — see Pitfall #2 below. Assert return == 0 and `getQueueItems(limit = 10).isEmpty()`.

**Adaptation for D-11 (passive-only filter):** Use `listOf(VulnClass.CORS_MISCONFIGURATION /* PASSIVE-ONLY */, VulnClass.SQLI /* ACTIVE-ELIGIBLE */)`. Assert return == 1 and the single queue item has `vulnClass == "SQLI"`. See Pitfall #6 for the canonical passive-only members.

**Adaptation for D-13 (queue-full):** Tweak `scanner.maxQueueSize = 2` after construction. Invoke with `listOf(SQLI, XSS_REFLECTED, CMDI, SSTI, XXE)`. Assert return `<= 2` (some sources say exactly 2; the code at line 258 does `if (scanQueue.size >= maxQueueSize.coerceAtLeast(1)) return false`, so first two queue, next three are rejected). Assert `getQueueItems(limit = 10).size == 2`.

### Pattern 3: HTTP Request Mock Builder (reuse, do not modify)

**Source:** `ActiveScannerQueueModelTest.kt` lines 75–95 (`requestResponse(url, name, value)` helper). Constructs a one-parameter `HttpRequest` wrapped in `HttpRequestResponse`. **Reuse verbatim** for D-05, D-10, D-11, D-13 — the `InjectionPoint` passed to `manualScanInsertionPoint` is independent of the `HttpRequest` shape (the scanner does not re-resolve the insertion point from the request; it queues it as-is).

### Anti-Patterns to Avoid

- **`Answers.RETURNS_DEEP_STUBS` on `HttpRequest`** — the existing `InjectionPointExtractorTest.kt` mocks `HttpRequest` shallowly (each `whenever` is explicit). Adding `RETURNS_DEEP_STUBS` here would silently swallow stub gaps. **Use shallow mocks** in the new resolver tests; keep `RETURNS_DEEP_STUBS` only for `MontoyaApi` in the queue tests (`newScannerForQueueTests`).
- **Reflection into `scanQueue`** — the queue is `private`. Use `getQueueItems(limit)` exclusively (D-04 is explicit on this).
- **Reusing `ScannerQueueBackpressureTest` for D-13** — that file has the heavy-suite `*BackpressureTest` suffix and is excluded from PR gate. D-13's queue-full test goes in `ActiveScannerQueueModelTest.kt` (fast suite) with a `manualScanInsertionPoint*` prefix. **Do not** add a method to `ScannerQueueBackpressureTest`.
- **Mocking `api.scope().isInScope(...)` shallowly** — when `MontoyaApi` is constructed with `RETURNS_DEEP_STUBS`, the `Scope` mock is deep-stubbed and `isInScope(String)` returns the boolean default `false`. For D-10 the *implicit* default works, but **explicitly stub it** for test readability and to defend against the default ever changing.

## Don't Hand-Roll

| Problem | Don't Build | Use Instead | Why |
|---------|-------------|-------------|-----|
| `Range` mock with `startIndexInclusive()` / `endIndexExclusive()` | Custom helper | `rangeMock(start, end)` at `InjectionPointExtractorTest.kt:195` | Already exists. Reuse. |
| `ByteArray` mock with `.bytes` byte array | Custom helper | `byteArrayMock(text)` at `InjectionPointExtractorTest.kt:189` | Already exists. Reuse. |
| Scanner builder with all default knobs | Custom builder | `newScannerForQueueTests()` at `ActiveScannerQueueModelTest.kt:61` | Already exists. After construction, mutate the public `var` fields (`scopeOnly`, `maxQueueSize`) for per-test variation. |
| `HttpRequestResponse` factory for queue tests | Custom factory | `requestResponse(url, name, value)` at `ActiveScannerQueueModelTest.kt:75` | Already exists. Reuse. |
| `AgentSettings` factory | Inline constructor | `TestSettings.baselineSettings()` (already used by `newScannerForQueueTests`) | Canonical fixture per `.planning/codebase/CONVENTIONS.md`. |
| `InjectionPoint` data class | Custom builder | Direct constructor: `InjectionPoint(InjectionType.X, "name", "value")` | Pure `data class` (line 279 of `ActiveScanModels.kt`); no factory needed. |
| `ActiveScanTarget` priority field assertion | Reflection into private field | The test ASSERTS the queue **size** and per-item `vulnClass`/`injectionPoint` — priority 60 is implicit (see Pitfall #4). | The snapshot model `ActiveScanQueueItem` does not surface `priority`. To assert priority directly, the test would need to either add a public accessor (out of scope per audit-only constraint) or use reflection (D-04 forbids). The strongest assertion the audit can make from the public API is: "priority is locked in code at line 235, queue insertion succeeds → priority must have been 60." Document this in the test method's KDoc; do not add a reflection-based assertion. |

**Key insight:** All scaffolding for both files already exists. The phase adds **only** new `@Test` methods — no new helpers, no new files, no new dependencies. This is the lowest-cost behaviour-lock surface.

## Runtime State Inventory

Not applicable. This phase is a test-only audit with no rename, refactor, migration, or runtime state changes. No databases, no service configs, no OS registrations, no secrets, no build artifacts are affected.

| Category | Items Found | Action Required |
|----------|-------------|------------------|
| Stored data | None — verified by scope (test-only phase) | — |
| Live service config | None — no Burp config changes | — |
| OS-registered state | None — no task/service registration | — |
| Secrets/env vars | None — no API keys, no env vars touched | — |
| Build artifacts | None — no `build.gradle.kts` changes, no JAR rename | — |

## Common Pitfalls

### Pitfall 1: Path-segment offset translation

**What goes wrong:** Naïve test setup uses path-relative offsets for the `selectionStart` / `selectionEnd` argument, expecting the resolver to match `12345` at the URI path level. The match fails.

**Why it happens:** Branch 4 of the resolver (lines 226–245 of `InjectionPointExtractor.kt`) operates on **absolute request-byte offsets**. It computes `pathStart = raw.indexOf(path)` and then `absStart = pathStart + match.range.first`. The test must replicate this: pass `selectionStart = raw.indexOf("12345")` (absolute), not `selectionStart = path.indexOf("12345")` (relative).

**How to avoid:** In `matchInsertionPointPicksPathSegment`, compute the selection offsets the same way the resolver computes them — from the raw HTTP request string returned by `request.toByteArray()?.bytes`. Mirror the absolute-byte pattern used in the existing `matchInsertionPointPicksOverlappingUrlParam` (line 91: `val qStart = raw.indexOf("hello")`).

**Warning signs:** Test returns `null` from the resolver, or matches a different branch (e.g., header line if there's a header with `12345` in it).

### Pitfall 2: Mocking `api.scope().isInScope(url)` for D-10

**What goes wrong:** Test uses `RETURNS_DEEP_STUBS` and assumes `isInScope` defaults to a usable value, but the implicit default is `false` (boolean primitive default) — which happens to be what D-10 wants. However, if a future Mockito-Kotlin change alters the default or another test runs first and stubs the chain differently (in a static helper), the test silently flips.

**Why it happens:** With `Answers.RETURNS_DEEP_STUBS`, `api.scope()` returns a deep-stubbed `Scope` mock; calling `isInScope(any String)` on that returns `false` by default. The deep-stub chain is recreated per `mock<>` call (no shared state between tests), but stubbing it explicitly is more defensive.

**How to avoid:** In D-10 (`manualScanInsertionPointReturnsZeroAndDoesNotQueueWhenOutOfScope`), explicitly stub: after constructing the scanner, retrieve the api mock and call `whenever(api.scope().isInScope(any<String>())).thenReturn(false)`. If the api isn't exposed from `newScannerForQueueTests()`, refactor that helper to optionally take a pre-configured `MontoyaApi` mock — OR (lighter) inline-construct the scanner in D-10's test method:

```kotlin
@Test
fun manualScanInsertionPointReturnsZeroAndDoesNotQueueWhenOutOfScope() {
    val api = mock<MontoyaApi>(defaultAnswer = Answers.RETURNS_DEEP_STUBS)
    whenever(api.scope().isInScope(any<String>())).thenReturn(false)
    val scanner = ActiveAiScanner(
        api = api,
        supervisor = mock<AgentSupervisor>(),
        audit = mock<AuditLogger>(),
        getSettings = { TestSettings.baselineSettings() },
    ).apply {
        scopeOnly = true   // CRITICAL — default is true in production but newScannerForQueueTests sets false
        maxQueueSize = 64
        scanMode = ScanMode.FULL
    }
    val rr = requestResponse("http://out-of-scope.example.com/?id=1", "id", "1")
    val point = InjectionPoint(InjectionType.URL_PARAM, "id", "1")
    val count = scanner.manualScanInsertionPoint(rr, point, listOf(VulnClass.SQLI))
    assertEquals(0, count)
    assertTrue(scanner.getQueueItems(limit = 10).isEmpty())
}
```

`[VERIFIED: src/main/kotlin/com/six2dez/burp/aiagent/scanner/ActiveAiScanner.kt:225]` The scope check at line 225 is gated by both `scopeOnly` AND `!api.scope().isInScope(...)` — both must be set for the short-circuit to fire.

**Warning signs:** D-10 test passes when scope is mocked to `true` (means the short-circuit is the wrong branch); D-10 test passes without any explicit scope stub (means it's relying on a Mockito default).

### Pitfall 3: `newScannerForQueueTests()` defaults `scopeOnly` to `false`

**What goes wrong:** D-10 uses the shared builder and assumes the production default of `scopeOnly = true`. The test queues normally because the scope gate is bypassed.

**Why it happens:** `newScannerForQueueTests()` at `ActiveScannerQueueModelTest.kt:68` sets `scopeOnly = false` to make the existing happy-path queue tests deterministic. The production default is `scopeOnly = true` (line 90 of `ActiveAiScanner.kt`).

**How to avoid:** D-10 MUST either (a) inline-construct the scanner with `scopeOnly = true` (Pitfall #2 example above), or (b) call `newScannerForQueueTests()` then `scanner.scopeOnly = true`. The planner picks one; (a) is more readable, (b) is shorter.

**Warning signs:** D-10 test passes regardless of the scope mock — that proves the scope branch was never reached.

### Pitfall 4: `ActiveScanQueueItem` does not surface `priority`

**What goes wrong:** D-05 calls for asserting `every snapshot item has priority == 60`. But `ActiveScanQueueItem` (lines 303–310 of `ActiveScanModels.kt`) does NOT carry a `priority` field — it only exposes `id, url, vulnClass, injectionPoint, status, queuedAtEpochMs`.

**Why it happens:** `getQueueItems(limit)` (line 271 of `ActiveAiScanner.kt`) maps `ActiveScanTarget` (which has `priority`) onto `ActiveScanQueueItem` (which doesn't). The design assumes the UI doesn't need priority because the scanner processes the queue in FIFO order based on `queuedAtEpochMs`, not priority — `priority` is currently only used inside `queueTarget` for the knowledge-base boost at line 149.

**How to avoid:** Three options, in order of preference:
1. **Document, don't assert** (RECOMMENDED). The test method KDoc states: "priority is hardcoded at `ActiveAiScanner.kt:235`. Asserting size + per-item vuln-class set + queueing success proves the line executed; a direct priority assertion would require adding `priority` to `ActiveScanQueueItem`, which is out of scope per the audit-only constraint." Lock the line via a one-line review comment in the kdoc rather than the assertion.
2. **Add `priority` to `ActiveScanQueueItem`** — production change. Out of scope per D-08-equivalent reasoning (audit, not refactor).
3. **Reflection** — D-04 forbids it. Discard.

**The planner MUST resolve this** before writing the test. The current CONTEXT.md D-05 says "Assert every snapshot item has `priority == 60`" — but the snapshot doesn't expose priority. Option 1 is the only behaviour-locking path that matches the audit constraint. Recommend the planner replace the priority assertion in D-05.2 with a kdoc-anchored line reference and a code-comment in the test.

**Warning signs:** Compilation error `ActiveScanQueueItem.priority: unresolved reference`.

### Pitfall 5: Body-substring branch ordering after parsed params

**What goes wrong:** XML test (D-01.3) accidentally provides a parsed parameter that overlaps the selection — branch 1 fires before branch 3, the test asserts XML_ELEMENT but gets BODY_PARAM.

**Why it happens:** The resolver runs branches in priority order (lines 162, 184, 215, 237). Any parsed parameter that overlaps the selection wins, regardless of whether the body also contains an XML element with the same value.

**How to avoid:** In D-01.3 (XML) and D-01.4 (path-segment), stub `whenever(request.parameters()).thenReturn(emptyList())`. In D-01.3, also stub `whenever(request.headers()).thenReturn(emptyList())` to ensure the header branch (line 184) is not accidentally hit; OR stub headers that don't overlap the selection.

**Warning signs:** Assertion fails with `expected XML_ELEMENT but got URL_PARAM/BODY_PARAM/HEADER`.

### Pitfall 6: `ScanPolicy.PASSIVE_ONLY_VULN_CLASSES` membership

**What goes wrong:** D-11 picks a class that's actually active-eligible (or vice versa); the assertion misfires.

**Why it happens:** The set is defined in `ActiveScanModels.kt` lines 110–126. It currently contains exactly **14 classes**:

```kotlin
// [VERIFIED: src/main/kotlin/com/six2dez/burp/aiagent/scanner/ActiveScanModels.kt:110-126]
val PASSIVE_ONLY_VULN_CLASSES = setOf(
    VulnClass.CORS_MISCONFIGURATION,
    VulnClass.MISSING_SECURITY_HEADERS,
    VulnClass.VERSION_DISCLOSURE,
    VulnClass.INSECURE_COOKIE,
    VulnClass.REQUEST_SMUGGLING,
    VulnClass.CSRF,
    VulnClass.UNRESTRICTED_FILE_UPLOAD,
    VulnClass.DESERIALIZATION,
    VulnClass.SUBDOMAIN_TAKEOVER,
    VulnClass.S3_MISCONFIGURATION,
    VulnClass.SOURCEMAP_DISCLOSURE,
    VulnClass.GIT_EXPOSURE,
    VulnClass.BACKUP_DISCLOSURE,
    VulnClass.DEBUG_EXPOSURE,
)
```

**How to avoid:** D-11 (`manualScanInsertionPointFiltersPassiveOnlyVulnClasses`) should use:
- **Passive-only** (will be filtered out): `VulnClass.CORS_MISCONFIGURATION` (stable canary — listed first, unlikely to move).
- **Active-eligible** (will queue): `VulnClass.SQLI` (used by every other queue test in this codebase, stable).

Pass `listOf(VulnClass.CORS_MISCONFIGURATION, VulnClass.SQLI)`. Assert return == 1 and `getQueueItems(limit = 10).single().vulnClass == "SQLI"`.

**Defensive variant:** if the planner wants to lock against future PASSIVE_ONLY drift, use the **set itself**: `listOf(VulnClass.SQLI) + ScanPolicy.PASSIVE_ONLY_VULN_CLASSES.toList()` and assert return == 1 + queue size == 1. That's resilient to set membership changes but slightly less explicit. Either is acceptable; the planner picks.

**Warning signs:** D-11 test passes with `count == 2` (both classes queued — passive filter didn't fire) or `count == 0` (the chosen "active-eligible" class is actually passive-only).

### Pitfall 7: `ScanMode.FULL` is required for D-11 not to filter `SQLI`

**What goes wrong:** Test uses default scan mode and `VulnClass.SQLI` gets dropped by `ScanPolicy.isAllowedForMode` before the passive-only filter even runs. The assertion misfires.

**Why it happens:** `manualScanInsertionPoint` lines 220–223 filter by BOTH `PASSIVE_ONLY_VULN_CLASSES` AND `isAllowedForMode`. The latter depends on `scanMode`. `ScanMode.BUG_BOUNTY` includes SQLI; `ScanMode.PENTEST` includes SQLI; `ScanMode.FULL` includes everything (line 141 of `ActiveScanModels.kt`). All three include `SQLI`, but other choices may not be.

**How to avoid:** `newScannerForQueueTests()` already sets `scanMode = ScanMode.FULL` (line 71 of `ActiveScannerQueueModelTest.kt`). Reuse it. If D-10 inline-constructs the scanner (per Pitfall #2), the test MUST also set `scanMode = ScanMode.FULL`.

**Warning signs:** D-11 returns 0 (both classes filtered).

### Pitfall 8: Manual smoke artefact must mirror Phase 1 structure

**What goes wrong:** The maintainer runs the smoke and records prose paragraphs; later automation (verifier, plan-checker) cannot tell whether the smoke ran or just whether the file exists.

**Why it happens:** Phase 1's `01-HUMAN-UAT.md` uses a structured YAML front-matter + per-scenario fields (`expected`, `result`, with explicit `pending` markers — see source for the exact shape). Phase 2 must match for the same automation hooks.

**How to avoid:** The planner generates `02-HUMAN-UAT.md` from the Phase 1 template at `.planning/phases/01-perplexity-backend-audit/01-HUMAN-UAT.md`:

```yaml
---
status: partial
phase: 02-insertion-point-scan-audit
source: [02-VERIFICATION.md]
started: <timestamp>
updated: <timestamp>
---

## Current Test
[awaiting human testing]

## Tests

### 1. Selection inside a URL parameter value (INSP-01, INSP-04)
expected: Right-click menu shows "AI Scan on Selected Insertion Point (url param: <name>)".
result: [pending]

### 2. Selection inside a body parameter value (INSP-01, INSP-04)
expected: Right-click menu shows "AI Scan on Selected Insertion Point (body param: <name>)".
result: [pending]

### 3. Selection inside a cookie value (INSP-01, INSP-04)
expected: Right-click menu shows "AI Scan on Selected Insertion Point (cookie: <name>)".
result: [pending]

### 4. Selection inside a header line (INSP-01, INSP-04)
expected: Right-click menu shows "AI Scan on Selected Insertion Point (header: <name>)".
result: [pending]

### 5. Selection inside a JSON value (INSP-01, INSP-04)
expected: Right-click menu shows "AI Scan on Selected Insertion Point (json field: <name>)".
result: [pending]

### 6. Empty or whitespace-only selection (INSP-02)
expected: Menu item does not appear in the context menu.
result: [pending]

## Summary
total: 6
passed: 0
issues: 0
pending: 6
skipped: 0
blocked: 0

## Gaps
```

The exact `expected:` label wording must match the resolver's label-building code at `UiActions.kt:366`:

```kotlin
"AI Scan on Selected Insertion Point (${insertionPoint.type.name.lowercase().replace('_', ' ')}: ${insertionPoint.name})"
```

Which produces literally: `url param: q`, `body param: username`, `cookie: session`, `header: X-Forwarded-Host`, `json field: name`, `xml element: id`, `path segment: path_id`. The smoke scenarios must use these exact label forms to lock the UI contract.

**Warning signs:** Smoke recorded in free-form prose; downstream tooling (gsd-verify-work) cannot parse pass/fail.

## Code Examples

### Verified Mockito-Kotlin pattern for `Range` + `ParsedHttpParameter`

Source: `src/test/kotlin/com/six2dez/burp/aiagent/scanner/InjectionPointExtractorTest.kt:189-203` `[VERIFIED]`

```kotlin
private fun byteArrayMock(text: String): burp.api.montoya.core.ByteArray {
    val ba = mock<burp.api.montoya.core.ByteArray>()
    whenever(ba.bytes).thenReturn(text.toByteArray(Charsets.UTF_8))
    return ba
}

private fun rangeMock(start: Int, end: Int): Range {
    val r = mock<Range>()
    whenever(r.startIndexInclusive()).thenReturn(start)
    whenever(r.endIndexExclusive()).thenReturn(end)
    return r
}
```

### Verified deep-stub pattern for `MontoyaApi`

Source: `src/test/kotlin/com/six2dez/burp/aiagent/scanner/ActiveScannerQueueModelTest.kt:62-72` `[VERIFIED]`

```kotlin
private fun newScannerForQueueTests(): ActiveAiScanner {
    val api = mock<MontoyaApi>(defaultAnswer = Answers.RETURNS_DEEP_STUBS)
    return ActiveAiScanner(
        api = api,
        supervisor = mock<AgentSupervisor>(),
        audit = mock<AuditLogger>(),
        getSettings = { baselineSettings() },
    ).apply {
        scopeOnly = false
        maxQueueSize = 64
        scanMode = ScanMode.FULL
    }
}
```

### Verified queue snapshot assertion shape

Source: `src/main/kotlin/com/six2dez/burp/aiagent/scanner/ActiveAiScanner.kt:271-288` `[VERIFIED]`

```kotlin
fun getQueueItems(limit: Int = 500): List<ActiveScanQueueItem> {
    val max = limit.coerceIn(1, 10_000)
    val snapshot = scanQueue.toList().sortedBy { it.queuedAtEpochMs }.take(max)
    return snapshot.map { target ->
        ActiveScanQueueItem(
            id = target.id,                                          // "${url}_${injection.name}_${vulnClass}"
            url = target.originalRequest.request().url(),
            vulnClass = target.vulnHint.vulnClass.name,              // e.g., "SQLI"
            injectionPoint = "${target.injectionPoint.type}:${target.injectionPoint.name}",  // e.g., "URL_PARAM:id"
            status = "QUEUED",
            queuedAtEpochMs = target.queuedAtEpochMs,
        )
    }
}
```

Test assertions use: `item.vulnClass`, `item.injectionPoint`, `item.status`, `item.id`. **NOT** `item.priority` (see Pitfall #4).

### Verified `InjectionPoint` constructor

Source: `src/main/kotlin/com/six2dez/burp/aiagent/scanner/ActiveScanModels.kt:279-284` `[VERIFIED]`

```kotlin
data class InjectionPoint(
    val type: InjectionType,
    val name: String,
    val originalValue: String,
    val position: Int? = null,  // For body injection position
)
```

For D-05/D-10/D-11/D-13, just use `InjectionPoint(InjectionType.URL_PARAM, "id", "1")` — `position` is irrelevant for queue assertions.

### Verified `manualScanInsertionPoint` signature

Source: `src/main/kotlin/com/six2dez/burp/aiagent/scanner/ActiveAiScanner.kt:214-255` `[VERIFIED]`

```kotlin
fun manualScanInsertionPoint(
    request: HttpRequestResponse,
    insertionPoint: InjectionPoint,
    vulnClasses: List<VulnClass>,
): Int
```

Returns the count of queued targets (`Int`). Use this return value for D-05.1, D-10, D-11, D-13.

## State of the Art

This is a behaviour-locking audit on a stable test stack. No "state of the art" shifts apply — Mockito-Kotlin 5.4.0 and JUnit Jupiter 6.0.3 are current; the project uses both consistently. The only convention drift to call out:

| Old Approach | Current Approach | When Changed | Impact |
|--------------|------------------|--------------|--------|
| Mixed `kotlin.test.*` + JUnit `Assertions.*` in same file | Match the file's existing style; do not introduce a third | Established by CONVENTIONS.md (2026-05-13) | New test methods must use the same import set as the file they extend. `InjectionPointExtractorTest` → `kotlin.test.*` only. `ActiveScannerQueueModelTest` → JUnit `Assertions.assertTrue/assertFalse` + `kotlin.test.assertEquals` (existing convention in that file). |
| Backtick test names | CamelCase preferred (ktlint friendliness) | Phase 1 D-07 + CONVENTIONS.md | All new test method names in this phase use CamelCase. Existing backtick names in other files are not refactored. |

**Deprecated/outdated:** None. The audit's tools (Mockito-Kotlin `mock<>`, `whenever`, `Answers.RETURNS_DEEP_STUBS`) are the current best-practice for mocking Montoya API in this codebase.

## Assumptions Log

All factual claims in this research are verified against the code or cited from authoritative sources. No `[ASSUMED]` claims.

| # | Claim | Section | Risk if Wrong |
|---|-------|---------|---------------|
| — | (empty — no assumptions) | — | — |

**Confirmed in this session:**
- All Montoya API signatures (`Range`, `ByteArray`, `HttpRequest`, `ParsedHttpParameter`, `Scope`) confirmed via existing test usage and production code reads.
- All line numbers in CONTEXT.md confirmed against the current source files.
- All test framework versions confirmed via `build.gradle.kts` grep.
- `ScanPolicy.PASSIVE_ONLY_VULN_CLASSES` membership (14 entries) confirmed via direct read of `ActiveScanModels.kt:110-126`.
- `manualScanInsertionPoint` does NOT call `queueTarget` (line 237 calls `offerIfQueueNotFull` directly) — confirmed via direct read of `ActiveAiScanner.kt:229-240`.

## Open Questions

1. **D-05 priority assertion gap (Pitfall #4)**
   - What we know: `ActiveScanQueueItem` does not expose `priority`. CONTEXT.md D-05.2 says "Assert every snapshot item has `priority == 60`."
   - What's unclear: Whether the test method should (a) assert priority implicitly via kdoc + line reference, or (b) the planner should call out a discrepancy with CONTEXT.md.
   - Recommendation: Option (a). The test method's KDoc cites `ActiveAiScanner.kt:235` ("priority = 60 hardcoded") and the test asserts queue size + per-item `vulnClass` + `injectionPoint` (which proves the per-class loop at line 229 fired). A reflection assertion would violate D-04. A production change to expose priority on the snapshot is out of audit scope. The planner should add a one-line note in the plan explaining this minor scope adjustment to D-05.2.

2. **D-13 ordering variability**
   - What we know: `ConcurrentLinkedQueue.size()` is O(n) but the test is single-threaded.
   - What's unclear: Whether the queued count is exactly 2 or `<= 2`. CONTEXT.md says `<= 2` (acceptable slight ordering variability).
   - Recommendation: Use `assertTrue(count in 1..2)` and `assertTrue(scanner.getQueueItems(limit = 10).size in 1..2)`. The code at line 258 short-circuits exactly when `scanQueue.size >= maxQueueSize`, so the result is deterministic: first 2 queue, next 3 reject — strict `== 2` assertion is also defensible. The planner picks; I lean toward `== 2` for clarity (single-threaded, deterministic).

3. **Whether the manual smoke's scenario 6 wording catches whitespace-only**
   - What we know: `buildAiScanInsertionPointItem` at line 354 returns `null` when `selectionEnd <= selectionStart`. An empty selection has identical start/end. A whitespace-only selection has start < end, so this guard does NOT fire — the resolver receives the range and returns `null` because no candidate overlaps whitespace between tokens.
   - What's unclear: Does the maintainer's "whitespace-only selection" smoke scenario exercise the resolver-returns-null branch or the editor's selection-context branch?
   - Recommendation: Scenario 6 wording in `02-HUMAN-UAT.md` should be: "Selection is empty (no characters highlighted) OR is whitespace-only between tokens — menu does not appear." Both paths converge to "menu hidden" so the audit trail is identical from the user's perspective. The smoke does not need to discriminate which branch hid it.

## Environment Availability

Skipped — this phase has no external dependencies beyond the project's existing test stack. Tests run via `./gradlew test -PexcludeHeavyTests=true`. No CLI tools, no servers, no API keys, no databases. The only environmental concern is the maintainer-run manual smoke (D-09), which requires:

| Dependency | Required By | Available | Version | Fallback |
|------------|------------|-----------|---------|----------|
| Burp Suite Community or Pro | Manual smoke (D-09) | Maintainer's machine | 2023.12+ (per `CLAUDE.md` constraint) | — (manual smoke is the entire fallback for INSP-01) |
| Loaded plugin JAR | Manual smoke (D-09) | Built via `./gradlew shadowJar` | Custom-AI-Agent-0.7.0-SNAPSHOT (or current) | — |

**No blocking dependencies.** The plugin already loads (Phase 1 confirmed this); the maintainer reuses the same setup for Phase 2's manual smoke.

## Validation Architecture

### Test Framework

| Property | Value |
|----------|-------|
| Framework | JUnit Jupiter 6.0.3 (JUnit Platform via `useJUnitPlatform()`) |
| Config file | `build.gradle.kts` (no separate config file) |
| Quick run command | `./gradlew test --tests "com.six2dez.burp.aiagent.scanner.InjectionPointExtractorTest" --tests "com.six2dez.burp.aiagent.scanner.ActiveScannerQueueModelTest" -PexcludeHeavyTests=true` |
| Full suite command | `./gradlew test -PexcludeHeavyTests=true` |

### Phase Requirements → Test Map

| Req ID | Behavior | Test Type | Automated Command | File Exists? |
|--------|----------|-----------|-------------------|-------------|
| INSP-01 | Menu shows on selection overlapping URL param | manual smoke | (scenario 1 in `02-HUMAN-UAT.md`) | ❌ Wave 0 — create `02-HUMAN-UAT.md` |
| INSP-01 | Menu shows on selection overlapping body param | manual smoke | (scenario 2 in `02-HUMAN-UAT.md`) | ❌ Wave 0 |
| INSP-01 | Menu shows on selection overlapping cookie | manual smoke | (scenario 3 in `02-HUMAN-UAT.md`) | ❌ Wave 0 |
| INSP-01 | Menu shows on selection overlapping header | manual smoke | (scenario 4 in `02-HUMAN-UAT.md`) | ❌ Wave 0 |
| INSP-01 | Menu shows on selection overlapping JSON field | manual smoke | (scenario 5 in `02-HUMAN-UAT.md`) | ❌ Wave 0 |
| INSP-02 | Menu hidden when selection misses everything (resolver) | unit | `./gradlew test --tests "*InjectionPointExtractorTest.matchInsertionPointReturnsNullWhenSelectionMissesEverything" -PexcludeHeavyTests=true` | ✅ (existing at `InjectionPointExtractorTest.kt:167`) |
| INSP-02 | Menu hidden when selection empty (UI guard) | manual smoke | (scenario 6 in `02-HUMAN-UAT.md`) | ❌ Wave 0 |
| INSP-03 | Queues priority 60, one-per-class, dedup-bypass | unit | `./gradlew test --tests "*ActiveScannerQueueModelTest.manualScanInsertionPointQueuesOnePerClassAtPriority60WithoutDedup" -PexcludeHeavyTests=true` | ❌ Wave 0 (new method in existing file, D-05) |
| INSP-04 | Resolver picks BODY_PARAM | unit | `./gradlew test --tests "*InjectionPointExtractorTest.matchInsertionPointPicksBodyParam" -PexcludeHeavyTests=true` | ❌ Wave 0 (D-01.1) |
| INSP-04 | Resolver picks COOKIE | unit | `./gradlew test --tests "*InjectionPointExtractorTest.matchInsertionPointPicksCookie" -PexcludeHeavyTests=true` | ❌ Wave 0 (D-01.2) |
| INSP-04 | Resolver picks XML_ELEMENT | unit | `./gradlew test --tests "*InjectionPointExtractorTest.matchInsertionPointPicksXmlElement" -PexcludeHeavyTests=true` | ❌ Wave 0 (D-01.3) |
| INSP-04 | Resolver picks PATH_SEGMENT | unit | `./gradlew test --tests "*InjectionPointExtractorTest.matchInsertionPointPicksPathSegment" -PexcludeHeavyTests=true` | ❌ Wave 0 (D-01.4) |
| INSP-04 | Resolver picks URL_PARAM | unit | `./gradlew test --tests "*InjectionPointExtractorTest.matchInsertionPointPicksOverlappingUrlParam" -PexcludeHeavyTests=true` | ✅ (existing at `InjectionPointExtractorTest.kt:87`) |
| INSP-04 | Resolver picks HEADER (empty allowlist) | unit | `./gradlew test --tests "*InjectionPointExtractorTest.matchInsertionPointFallsBackToHeaderWhenSelectionHitsHeaderLine" -PexcludeHeavyTests=true` | ✅ (existing at `InjectionPointExtractorTest.kt:133`) |
| INSP-04 | Resolver picks JSON_FIELD | unit | `./gradlew test --tests "*InjectionPointExtractorTest.matchInsertionPointPicksJsonFieldWhenSelectionInBody" -PexcludeHeavyTests=true` | ✅ (existing at `InjectionPointExtractorTest.kt:206`) |
| INSP-04 (boundary) | Resolver respects non-empty headerAllowlist | unit | `./gradlew test --tests "*InjectionPointExtractorTest.matchInsertionPointRespectsNonEmptyHeaderAllowlist" -PexcludeHeavyTests=true` | ❌ Wave 0 (D-03) |
| Adjacent invariant | Out-of-scope returns 0, queue empty | unit | `./gradlew test --tests "*ActiveScannerQueueModelTest.manualScanInsertionPointReturnsZeroAndDoesNotQueueWhenOutOfScope" -PexcludeHeavyTests=true` | ❌ Wave 0 (D-10) |
| Adjacent invariant | PASSIVE_ONLY filter on the manual-insertion-point path | unit | `./gradlew test --tests "*ActiveScannerQueueModelTest.manualScanInsertionPointFiltersPassiveOnlyVulnClasses" -PexcludeHeavyTests=true` | ❌ Wave 0 (D-11) |
| Adjacent invariant | Queue-full returns short count | unit | `./gradlew test --tests "*ActiveScannerQueueModelTest.manualScanInsertionPointReturnsShortCountWhenQueueFull" -PexcludeHeavyTests=true` | ❌ Wave 0 (D-13) |

### Sampling Rate

- **Per task commit:** `./gradlew test --tests "*InjectionPointExtractorTest" --tests "*ActiveScannerQueueModelTest" -PexcludeHeavyTests=true` (runs only the two files this phase touches; < 5 s on a warm JVM)
- **Per wave merge:** `./gradlew test -PexcludeHeavyTests=true` (full fast suite; ~ 30–60 s)
- **Phase gate:** `./gradlew test -PexcludeHeavyTests=true` green + ktlint clean + manual smoke scenarios 1–6 all marked `passed` in `02-HUMAN-UAT.md` before `/gsd-verify-work`

### Wave 0 Gaps

- [ ] `02-HUMAN-UAT.md` — created by planner from Phase 1 template, populated with 6 scenarios (Pitfall #8 above gives the exact YAML shape). Maintainer fills in `result:` fields during execution.
- [ ] 5 new `@Test` methods in `InjectionPointExtractorTest.kt` (D-01 × 4 + D-03 × 1) — file exists; no new file needed.
- [ ] 4 new `@Test` methods in `ActiveScannerQueueModelTest.kt` (D-05, D-10, D-11, D-13) — file exists; no new file needed.

*(Framework install: not needed — JUnit Jupiter 6.0.3 + Mockito-Kotlin 5.4.0 already in `build.gradle.kts`)*

## Security Domain

`security_enforcement` is not enabled in `.planning/config.json` (the key is absent in the workflow object — only `nyquist_validation` is enabled). This phase is a test-only audit on already-shipped code; no new attack surface, no new auth/session/access logic. The audited code interacts with:

| ASVS Category | Applies | Standard Control |
|---------------|---------|-----------------|
| V2 Authentication | no | n/a — no auth code path |
| V3 Session Management | no | n/a — no session handling |
| V4 Access Control | yes | `api.scope().isInScope(url)` gate at `ActiveAiScanner.kt:225` — D-10 locks this branch. The audit verifies (not implements) the access-control gate. |
| V5 Input Validation | yes | Selection offsets are validated (`selectionEnd <= selectionStart` → `null` at line 159 of `InjectionPointExtractor.kt`). D-09 manual smoke covers empty/whitespace selection cases. |
| V6 Cryptography | no | n/a — no crypto |

| Pattern | STRIDE | Standard Mitigation |
|---------|--------|---------------------|
| Out-of-scope target leakage (queueing a request the user didn't authorise) | Information Disclosure | `scopeOnly` + `api.scope().isInScope()` gate — D-10 locks |
| Queue saturation DoS | Denial of Service | `maxQueueSize` short-count return — D-13 locks |
| Privacy leak via active-scan payload | Information Disclosure | Already gated by `PrivacyMode` at executor dispatch time (ADR-5); out of this phase's scope (D-07: queue tests don't exercise dispatch) |

**No new security controls are introduced by this phase.** The audit verifies existing controls fire on the new manual-insertion-point path.

## Sources

### Primary (HIGH confidence)

- `[VERIFIED]` `src/main/kotlin/com/six2dez/burp/aiagent/scanner/InjectionPointExtractor.kt` lines 152–256 — `matchInsertionPoint` resolver (read 2026-05-13)
- `[VERIFIED]` `src/main/kotlin/com/six2dez/burp/aiagent/scanner/ActiveAiScanner.kt` lines 204–256 — `manualScanInsertionPoint` queue entry point (read 2026-05-13)
- `[VERIFIED]` `src/main/kotlin/com/six2dez/burp/aiagent/scanner/ActiveAiScanner.kt` lines 257–264 — `offerIfQueueNotFull` queue-full short-circuit
- `[VERIFIED]` `src/main/kotlin/com/six2dez/burp/aiagent/scanner/ActiveAiScanner.kt` lines 271–288 — `getQueueItems(limit)` snapshot API
- `[VERIFIED]` `src/main/kotlin/com/six2dez/burp/aiagent/scanner/ActiveScanModels.kt` lines 109–177 — `ScanPolicy` + `PASSIVE_ONLY_VULN_CLASSES` membership
- `[VERIFIED]` `src/main/kotlin/com/six2dez/burp/aiagent/scanner/ActiveScanModels.kt` lines 279–301 — `InjectionPoint`, `ActiveScanTarget`, `ActiveScanQueueItem` data class definitions
- `[VERIFIED]` `src/main/kotlin/com/six2dez/burp/aiagent/ui/UiActions.kt` lines 316–417 — `buildAiScanInsertionPointItem` UI builder
- `[VERIFIED]` `src/main/kotlin/com/six2dez/burp/aiagent/scanner/ScannerUtils.kt` — `HEADER_INJECTION_ALLOWLIST` reference set
- `[VERIFIED]` `src/test/kotlin/com/six2dez/burp/aiagent/scanner/InjectionPointExtractorTest.kt` — 7 existing tests + helpers
- `[VERIFIED]` `src/test/kotlin/com/six2dez/burp/aiagent/scanner/ActiveScannerQueueModelTest.kt` — 2 existing tests + builders
- `[VERIFIED]` `src/test/kotlin/com/six2dez/burp/aiagent/scanner/ScannerQueueBackpressureTest.kt` — heavy-suite precedent for queue-saturation tests
- `[VERIFIED]` `src/test/kotlin/com/six2dez/burp/aiagent/TestSettings.kt` — canonical `AgentSettings` fixture
- `[VERIFIED]` `build.gradle.kts` lines 50, 52 — JUnit Jupiter 6.0.3 + Mockito-Kotlin 5.4.0 confirmed
- `[CITED]` `.planning/REQUIREMENTS.md` — INSP-01..04 wording
- `[CITED]` `.planning/ROADMAP.md` — Phase 2 success criteria
- `[CITED]` `.planning/phases/02-insertion-point-scan-audit/02-CONTEXT.md` — D-01..D-13 decisions
- `[CITED]` `.planning/codebase/STACK.md`, `TESTING.md`, `CONVENTIONS.md`, `STRUCTURE.md` — test conventions
- `[CITED]` `.planning/phases/01-perplexity-backend-audit/01-CONTEXT.md` + `01-HUMAN-UAT.md` — Phase 1 precedent for fast-suite scope + manual smoke pattern
- `[CITED]` `CHANGELOG.md` `[Unreleased]` § Added — declarative behaviour description
- `[CITED]` `SPEC.md` §4.2, §5.2 — context menu actions and active scanner integration
- `[CITED]` `DECISIONS.md` ADR-4, ADR-5 — HTTP/CLI backend hierarchies and privacy redaction timing

### Secondary (MEDIUM confidence)

- None. Every claim is verified against the current code or cited from authoritative project documents.

### Tertiary (LOW confidence)

- None.

## Metadata

**Confidence breakdown:**

- Standard stack: HIGH — versions verified via `build.gradle.kts` grep; existing tests demonstrate the pattern works.
- Architecture: HIGH — source files read in full; CONTEXT.md decisions cross-referenced against actual line numbers.
- Pitfalls: HIGH — every pitfall corresponds to a specific code line or established test pattern; none speculative.
- Open questions: HIGH — three identified gaps are all resolvable by the planner with no further research needed.

**Research date:** 2026-05-13
**Valid until:** 2026-06-13 (30 days — stable audit on shipped code; no fast-moving dependency surface)

---

*Phase: 2-Insertion-Point Scan Audit*
*Research completed: 2026-05-13*
