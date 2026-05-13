---
phase: 2
slug: insertion-point-scan-audit
status: draft
nyquist_compliant: false
wave_0_complete: false
created: 2026-05-13
---

# Phase 2 — Validation Strategy

> Per-phase validation contract for feedback sampling during execution.

---

## Test Infrastructure

| Property | Value |
|----------|-------|
| **Framework** | JUnit Jupiter 6.0.3 (JUnit Platform via `useJUnitPlatform()`) + Mockito-Kotlin 5.4.0 |
| **Config file** | `build.gradle.kts` (lines 50, 52 declare deps; no separate test config) |
| **Quick run command** | `./gradlew test --tests "*InjectionPointExtractorTest" --tests "*ActiveScannerQueueModelTest" -PexcludeHeavyTests=true` |
| **Full suite command** | `./gradlew test -PexcludeHeavyTests=true` |
| **Estimated runtime** | ~5 s quick, ~30–60 s full |

---

## Sampling Rate

- **After every task commit:** Run the quick command above (only the two files this phase touches).
- **After every plan wave:** Run the full suite command.
- **Before `/gsd-verify-work`:** Full suite must be green AND all 6 manual-smoke scenarios in `02-HUMAN-UAT.md` marked `result: passed`.
- **Max feedback latency:** ~5 s on warm JVM.

---

## Per-Task Verification Map

| Task ID | Plan | Wave | Requirement | Threat Ref | Secure Behavior | Test Type | Automated Command | File Exists | Status |
|---------|------|------|-------------|------------|-----------------|-----------|-------------------|-------------|--------|
| 02-01-01 | 01 | 1 | INSP-04 (D-01.1) | — | BODY_PARAM resolved via `valueOffsets()` branch 1 | unit | `./gradlew test --tests "*InjectionPointExtractorTest.matchInsertionPointPicksBodyParam" -PexcludeHeavyTests=true` | ❌ W0 (new method) | ⬜ pending |
| 02-01-02 | 01 | 1 | INSP-04 (D-01.2) | — | COOKIE resolved via `valueOffsets()` branch 1 | unit | `./gradlew test --tests "*InjectionPointExtractorTest.matchInsertionPointPicksCookie" -PexcludeHeavyTests=true` | ❌ W0 (new method) | ⬜ pending |
| 02-01-03 | 01 | 1 | INSP-04 (D-01.3) | — | XML_ELEMENT resolved via substring branch 3 | unit | `./gradlew test --tests "*InjectionPointExtractorTest.matchInsertionPointPicksXmlElement" -PexcludeHeavyTests=true` | ❌ W0 (new method) | ⬜ pending |
| 02-01-04 | 01 | 1 | INSP-04 (D-01.4) | — | PATH_SEGMENT resolved via `pathIdPattern` branch 4 | unit | `./gradlew test --tests "*InjectionPointExtractorTest.matchInsertionPointPicksPathSegment" -PexcludeHeavyTests=true` | ❌ W0 (new method) | ⬜ pending |
| 02-01-05 | 01 | 1 | INSP-04 (D-03) | — | Non-empty `headerAllowlist` filters out non-allowed header lines | unit | `./gradlew test --tests "*InjectionPointExtractorTest.matchInsertionPointRespectsNonEmptyHeaderAllowlist" -PexcludeHeavyTests=true` | ❌ W0 (new method) | ⬜ pending |
| 02-02-01 | 02 | 1 | INSP-03 (D-05) | — | priority=60, one-per-class, dedup-bypass on re-invoke | unit | `./gradlew test --tests "*ActiveScannerQueueModelTest.manualScanInsertionPointQueuesOnePerClassAtPriority60WithoutDedup" -PexcludeHeavyTests=true` | ❌ W0 (new method) | ⬜ pending |
| 02-02-02 | 02 | 1 | INSP-03 (D-10) | T-2-01 | Out-of-scope short-circuit returns 0, queue stays empty | unit | `./gradlew test --tests "*ActiveScannerQueueModelTest.manualScanInsertionPointReturnsZeroAndDoesNotQueueWhenOutOfScope" -PexcludeHeavyTests=true` | ❌ W0 (new method) | ⬜ pending |
| 02-02-03 | 02 | 1 | INSP-03 (D-11) | — | `PASSIVE_ONLY_VULN_CLASSES` filter on manual-insertion-point path | unit | `./gradlew test --tests "*ActiveScannerQueueModelTest.manualScanInsertionPointFiltersPassiveOnlyVulnClasses" -PexcludeHeavyTests=true` | ❌ W0 (new method) | ⬜ pending |
| 02-02-04 | 02 | 1 | INSP-03 (D-13) | T-2-02 | Queue-full returns short count (≤ maxQueueSize) | unit | `./gradlew test --tests "*ActiveScannerQueueModelTest.manualScanInsertionPointReturnsShortCountWhenQueueFull" -PexcludeHeavyTests=true` | ❌ W0 (new method) | ⬜ pending |
| 02-03-01 | 03 | 2 | INSP-01, INSP-02 (D-09) | — | Six-scenario manual smoke artefact | manual | n/a (recorded in `02-HUMAN-UAT.md`) | ❌ W0 (new file) | ⬜ pending |

*Status: ⬜ pending · ✅ green · ❌ red · ⚠️ flaky*

---

## Wave 0 Requirements

- [ ] 5 new `@Test` methods added to `src/test/kotlin/com/six2dez/burp/aiagent/scanner/InjectionPointExtractorTest.kt` (file exists — D-01 × 4 + D-03 × 1; reuses existing `byteArrayMock`, `rangeMock`).
- [ ] 4 new `@Test` methods added to `src/test/kotlin/com/six2dez/burp/aiagent/scanner/ActiveScannerQueueModelTest.kt` (file exists — D-05, D-10, D-11, D-13; reuses `newScannerForQueueTests`, `requestResponse`).
- [ ] `.planning/phases/02-insertion-point-scan-audit/02-HUMAN-UAT.md` created with six scenario blocks ready for the maintainer to fill `result:` after running in real Burp (D-09).

*Framework install: not needed — JUnit Jupiter 6.0.3 + Mockito-Kotlin 5.4.0 already in `build.gradle.kts`.*

---

## Manual-Only Verifications

| Behavior | Requirement | Why Manual | Test Instructions |
|----------|-------------|------------|-------------------|
| Right-click menu shows on URL-param selection | INSP-01 | UI builder + ContextMenuEvent require Swing + Burp runtime; D-08 declines a Mockito unit test | `02-HUMAN-UAT.md` scenario 1: select inside a URL parameter value in Proxy/Repeater; confirm menu shows with `url param: <name>` label. |
| Right-click menu shows on body-param selection | INSP-01 | Same — UI builder coverage | Scenario 2: form-encoded body, select inside value, confirm `body param: <name>` label. |
| Right-click menu shows on cookie selection | INSP-01 | Same | Scenario 3: select inside cookie value, confirm `cookie: <name>` label. |
| Right-click menu shows on header selection | INSP-01 | Same | Scenario 4: select inside header value (e.g. User-Agent), confirm `header: <name>` label. |
| Right-click menu shows on JSON-field selection | INSP-01 | Same | Scenario 5: select inside a JSON string value, confirm `json field: <name>` label. |
| Right-click menu hidden on empty/whitespace selection | INSP-02 | UI guard — covered by `listOfNotNull` after resolver returns null | Scenario 6: empty or whitespace-only selection in editor, confirm menu does not appear. |

---

## Validation Sign-Off

- [ ] All tasks have `<automated>` verify command or are mapped to a Wave 0 manual-smoke entry
- [ ] Sampling continuity: no 3 consecutive tasks without automated verify
- [ ] Wave 0 covers all MISSING references (5 + 4 unit-test methods + 1 manual-smoke artefact)
- [ ] No watch-mode flags
- [ ] Feedback latency < 5 s on quick command
- [ ] `nyquist_compliant: true` set in frontmatter after planner verifies coverage

**Approval:** pending
