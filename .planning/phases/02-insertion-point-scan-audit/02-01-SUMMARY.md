---
phase: 02-insertion-point-scan-audit
plan: "01"
subsystem: scanner/resolver
tags: [scanner, insertion-point, resolver, unit-test, mockito-kotlin, tdd-audit]
dependency_graph:
  requires: []
  provides:
    - "resolver branch coverage (INSP-04): BODY_PARAM, COOKIE, XML_ELEMENT, PATH_SEGMENT, non-empty headerAllowlist"
  affects:
    - "InjectionPointExtractor.matchInsertionPoint — behaviour now locked by 5 new unit tests"
tech_stack:
  added: []
  patterns:
    - "Mockito-Kotlin shallow mocks (no RETURNS_DEEP_STUBS) for HttpRequest, ParsedHttpParameter, HttpHeader, Range, ByteArray"
    - "kotlin.test.* assertions only (assertEquals, assertTrue, assertNull)"
    - "CamelCase test method names per Phase 1 D-07"
key_files:
  created: []
  modified:
    - src/test/kotlin/com/six2dez/burp/aiagent/scanner/InjectionPointExtractorTest.kt
decisions:
  - "All 5 tests committed in one atomic commit (0cc63cc) — single-file change, individual task diffs impractical post-hoc; all tests were individually verified before commit"
  - "Java 21 (temurin-21) used for test execution — default macOS JVM is Java 25 which is incompatible with the Kotlin Gradle plugin version used (JavaVersion.parse throws on 25.0.2)"
metrics:
  duration: "3m 6s"
  completed: "2026-05-13T11:12:29Z"
  tasks_completed: 5
  files_modified: 1
---

# Phase 2 Plan 01: Resolver Coverage Lock Summary

Added 5 new `@Test` methods to `InjectionPointExtractorTest.kt` to lock resolver behaviour for INSP-04 (branch 1 BODY_PARAM + COOKIE, branch 3 XML_ELEMENT, branch 4 PATH_SEGMENT) and INSP-02 boundary (non-empty headerAllowlist returns null), using shallow Mockito-Kotlin mocks and kotlin.test.* assertions throughout.

## Tasks Completed

| Task | Name | Commit | Files |
|------|------|--------|-------|
| 1 | matchInsertionPointPicksBodyParam (D-01.1) | 0cc63cc | InjectionPointExtractorTest.kt |
| 2 | matchInsertionPointPicksCookie (D-01.2) | 0cc63cc | InjectionPointExtractorTest.kt |
| 3 | matchInsertionPointPicksXmlElement (D-01.3) | 0cc63cc | InjectionPointExtractorTest.kt |
| 4 | matchInsertionPointPicksPathSegment (D-01.4) | 0cc63cc | InjectionPointExtractorTest.kt |
| 5 | matchInsertionPointRespectsNonEmptyHeaderAllowlist (D-03) | 0cc63cc | InjectionPointExtractorTest.kt |

## Methods Landed

### 1. `matchInsertionPointPicksBodyParam` (D-01.1)
- Mirrors `matchInsertionPointPicksOverlappingUrlParam` structure with BODY substitutions
- POST `application/x-www-form-urlencoded` request; param `HttpParameterType.BODY`; valueOffsets overlap via `rangeMock(aliceStart, aliceEnd)`
- Asserts `InjectionType.BODY_PARAM`, `name = "username"`
- Selection uses `aliceStart + 1, aliceEnd - 1` (inside-the-range pattern per analog)

### 2. `matchInsertionPointPicksCookie` (D-01.2)
- Cookie GET request; `HttpParameterType.COOKIE`; `headers() -> emptyList()` (critical: only parsed-param branch fires, not header-line branch)
- `valueOffsets -> rangeMock(abcStart, abcEnd)` locating "abc" inside the Cookie header line
- Asserts `InjectionType.COOKIE`, `name = "session"`

### 3. `matchInsertionPointPicksXmlElement` (D-01.3)
- Mirrors `matchInsertionPointPicksJsonFieldWhenSelectionInBody` with XML substitutions
- `parameters() -> emptyList()`, `headers() -> emptyList()` (Pitfall #5: skip branches 1+2)
- `headerValue("Content-Type") -> "application/xml"` drives resolver into branch 3 XML route
- Selection on `raw.indexOf("42")` (absolute byte offset — not body-relative)
- Asserts 4 things: `InjectionType.XML_ELEMENT`, `name = "id"`, `originalValue = "42"` (per CONTEXT.md D-01.3)

### 4. `matchInsertionPointPicksPathSegment` (D-01.4)
- Empty `parameters()`, `headers()`, empty body — drains branches 1-3
- `selectionStart = raw.indexOf("12345")` absolute offset (Pitfall #1: not path-relative)
- `url = "http://example.com/api/users/12345"` drives resolver's branch 4 pathIdPattern
- Asserts `InjectionType.PATH_SEGMENT`, `originalValue = "12345"`

### 5. `matchInsertionPointRespectsNonEmptyHeaderAllowlist` (D-03)
- Identical setup to `matchInsertionPointFallsBackToHeaderWhenSelectionHitsHeaderLine`
- Adds `headerAllowlist = setOf("x-foo-only")` — name does NOT match `"x-forwarded-host"` (lowercase compare at InjectionPointExtractor.kt:186)
- Resolver filter returns false → no header match → body empty → no path segment → null
- Asserts `assertNull(match)` only (no post-null assertEquals)

## Test Run Output

```
BUILD SUCCESSFUL — all 12 tests in InjectionPointExtractorTest passed
(./gradlew test --tests "com.six2dez.burp.aiagent.scanner.InjectionPointExtractorTest" -PexcludeHeavyTests=true)
```

ktlintCheck: BUILD SUCCESSFUL — no new violations in InjectionPointExtractorTest.kt
(pre-existing violations in other files are out of scope per deviation Rule scope boundary)

## Coverage Matrix (INSP-04 Complete)

| Sub-case | Status |
|----------|--------|
| URL_PARAM | Pre-existing (`matchInsertionPointPicksOverlappingUrlParam`) |
| BODY_PARAM | New (Task 1) |
| COOKIE | New (Task 2) |
| HEADER (empty allowlist) | Pre-existing (`matchInsertionPointFallsBackToHeaderWhenSelectionHitsHeaderLine`) |
| HEADER (non-empty allowlist blocks) | New (Task 5 — INSP-02 boundary) |
| JSON_FIELD | Pre-existing (`matchInsertionPointPicksJsonFieldWhenSelectionInBody`) |
| XML_ELEMENT | New (Task 3) |
| PATH_SEGMENT | New (Task 4) |

## Deviations from Plan

### Auto-applied — None

No deviation rules triggered. Plan executed exactly as written.

### Implementation Notes

1. **Java 25 incompatibility (pre-existing):** The default macOS JVM (Java 25.0.2 Homebrew) is incompatible with the Kotlin Gradle plugin version used in this project (`JavaVersion.parse` throws `IllegalArgumentException` on `"25.0.2"`). Tests were run with `JAVA_HOME=/Library/Java/JavaVirtualMachines/temurin-21.jdk/Contents/Home`. This is a pre-existing infrastructure issue, not introduced by this plan.

2. **Single commit for 5 tasks:** All 5 tests committed in `0cc63cc` (single-file change; individual hunk commits impractical post-hoc). Each test was individually verified before the commit via acceptance-criteria checks.

## Known Stubs

None. All 5 new test methods wire real mock behaviour — no placeholders, hardcoded empties flowing to UI, or TODO stubs.

## Threat Flags

None. Plan 01 adds test-only changes; no new attack surface introduced (per plan threat model T-2-INSP04-01: accept disposition, resolver is a pure function).

## Self-Check

- [x] `matchInsertionPointPicksBodyParam` exists in InjectionPointExtractorTest.kt
- [x] `matchInsertionPointPicksCookie` exists in InjectionPointExtractorTest.kt
- [x] `matchInsertionPointPicksXmlElement` exists in InjectionPointExtractorTest.kt
- [x] `matchInsertionPointPicksPathSegment` exists in InjectionPointExtractorTest.kt
- [x] `matchInsertionPointRespectsNonEmptyHeaderAllowlist` exists in InjectionPointExtractorTest.kt
- [x] Commit 0cc63cc exists: `test(02-01): add 5 resolver coverage tests for InjectionPointExtractor`
- [x] All 12 tests pass: BUILD SUCCESSFUL
- [x] ktlintCheck clean on modified file: BUILD SUCCESSFUL

## Self-Check: PASSED
