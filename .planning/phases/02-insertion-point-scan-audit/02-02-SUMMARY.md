---
phase: 02-insertion-point-scan-audit
plan: "02"
subsystem: scanner/queue
tags: [scanner, active-scan, queue, mockito-kotlin, scope, dos, unit-test]
dependency_graph:
  requires: []
  provides: [INSP-03]
  affects: [ActiveScannerQueueModelTest.kt]
tech_stack:
  added: []
  patterns:
    - "Inline scanner construction for scope-gate tests (Pitfall #3 avoidance)"
    - "RETURNS_DEEP_STUBS + any<String>() mock chain for api.scope().isInScope()"
    - "getQueueItems(limit) snapshot assertions instead of reflection (D-04)"
key_files:
  created: []
  modified:
    - src/test/kotlin/com/six2dez/burp/aiagent/scanner/ActiveScannerQueueModelTest.kt
decisions:
  - "KDoc anchors priority=60 to ActiveAiScanner.kt:235 in lieu of runtime priority field assertion (Pitfall #4, D-05.2 amended)"
  - "Inline scanner construction for out-of-scope test to make scopeOnly=true explicit (D-10, Pitfall #3)"
  - "CORS_MISCONFIGURATION selected as stable passive-only canary, SQLI as stable active-eligible canary (Pitfall #6)"
  - "assertEquals(2, count) strict assertion for queue-full test (Open Question #2 recommendation)"
metrics:
  duration: "~12 minutes"
  completed: "2026-05-13"
  tasks_completed: 4
  files_modified: 1
---

# Phase 02 Plan 02: Queue Contract Audit — Summary

**One-liner:** 4 behaviour-locking @Test methods for manualScanInsertionPoint queueing contract covering priority-60, out-of-scope gate, passive-only filter, and queue-saturation short-count.

## Tasks Completed

| Task | Name | Commit | Files |
|------|------|--------|-------|
| 1 | manualScanInsertionPointQueuesOnePerClassAtPriority60WithoutDedup | 3682db6 | ActiveScannerQueueModelTest.kt |
| 2 | manualScanInsertionPointReturnsZeroAndDoesNotQueueWhenOutOfScope | 9fe4466 | ActiveScannerQueueModelTest.kt |
| 3 | manualScanInsertionPointFiltersPassiveOnlyVulnClasses | c11ddd9 | ActiveScannerQueueModelTest.kt |
| 4 | manualScanInsertionPointReturnsShortCountWhenQueueFull | 5a80c0b | ActiveScannerQueueModelTest.kt |

## What Was Built

Four new `@Test` methods added to `src/test/kotlin/com/six2dez/burp/aiagent/scanner/ActiveScannerQueueModelTest.kt`:

### Task 1: manualScanInsertionPointQueuesOnePerClassAtPriority60WithoutDedup (D-05, D-12)

Proves three invariants in one dense method:
1. Queue size == 3 after first invocation with SQLI, XSS_REFLECTED, CMDI
2. Per-item vuln-class set matches request (`setOf("SQLI", "XSS_REFLECTED", "CMDI")`) and injectionPoint is `"URL_PARAM:id"`
3. Re-invocation queues 3 more (total == 6) proving dedup-bypass (D-12 folded per CONTEXT.md)

KDoc anchors priority=60 to `ActiveAiScanner.kt:235` in lieu of a direct `priority` field assertion (Pitfall #4 / D-05.2 amended — `ActiveScanQueueItem` does not expose the field, reflection is forbidden by D-04).

### Task 2: manualScanInsertionPointReturnsZeroAndDoesNotQueueWhenOutOfScope (D-10, T-2-01)

Uses inline scanner construction (not `newScannerForQueueTests()`) to make `scopeOnly = true` explicit (Pitfall #3). Stubs `api.scope().isInScope(any<String>())` to `false` (Pitfall #2 defensive explicit stub). Asserts `count == 0` and `getQueueItems(limit = 10).isEmpty()`.

Also adds `import org.mockito.kotlin.any` — the only import change across the entire plan. Placed alphabetically between the existing Mockito-Kotlin imports.

### Task 3: manualScanInsertionPointFiltersPassiveOnlyVulnClasses (D-11)

Uses `newScannerForQueueTests()` unchanged (ScanMode.FULL required for SQLI to pass `isAllowedForMode` — Pitfall #7). Passes `[CORS_MISCONFIGURATION, SQLI]`; asserts `count == 1` and `items.single().vulnClass == "SQLI"`. CORS_MISCONFIGURATION is the stable passive-only canary (listed first at `ActiveScanModels.kt:112`).

### Task 4: manualScanInsertionPointReturnsShortCountWhenQueueFull (D-13, T-2-02)

Sets `maxQueueSize = 2` via `apply` block on the shared builder. Passes 5 active-eligible classes (SQLI, XSS_REFLECTED, CMDI, SSTI, XXE — all in both `bugBountyClasses()` and `pentestClasses()`). Asserts `count == 2` and `getQueueItems(limit = 10).size == 2`. Lives in the fast-suite file per PATTERNS.md Fast-suite placement rule.

## Verification Results

```
./gradlew test --tests "com.six2dez.burp.aiagent.scanner.ActiveScannerQueueModelTest" -PexcludeHeavyTests=true
BUILD SUCCESSFUL

./gradlew test -PexcludeHeavyTests=true
BUILD SUCCESSFUL

./gradlew ktlintCheck
BUILD SUCCESSFUL (no violations in ActiveScannerQueueModelTest.kt)
```

All 6 tests in `ActiveScannerQueueModelTest.kt` pass (2 pre-existing + 4 new).

## Deviations from Plan

None — plan executed exactly as written.

## Threat Flags

None. All test-only changes; no new network endpoints, auth paths, file access, or schema changes.

## Known Stubs

None. This plan adds only test code; no data wiring or UI rendering is involved.

## Self-Check: PASSED

- `manualScanInsertionPointQueuesOnePerClassAtPriority60WithoutDedup` — FOUND (3682db6)
- `manualScanInsertionPointReturnsZeroAndDoesNotQueueWhenOutOfScope` — FOUND (9fe4466)
- `manualScanInsertionPointFiltersPassiveOnlyVulnClasses` — FOUND (c11ddd9)
- `manualScanInsertionPointReturnsShortCountWhenQueueFull` — FOUND (5a80c0b)
- `import org.mockito.kotlin.any` — FOUND (1 occurrence)
- No reflection, no new test files, no BackpressureTest/ConcurrencyTest suffix introduced
