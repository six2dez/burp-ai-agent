---
phase: 13-privacy-redaction-hardening
plan: "01"
subsystem: redact
tags: [hkdf, crypto, redos, saferegex, privacy, priv-01, priv-02]
dependency_graph:
  requires: []
  provides: [SafeRegex, HKDF-anonymizeHost]
  affects: [Redaction.kt, SafeRegex.kt]
tech_stack:
  added: []
  patterns: [RFC-5869-HKDF, interruptible-CharSequence-ReDoS-guard]
key_files:
  created:
    - src/main/kotlin/com/six2dez/burp/aiagent/redact/SafeRegex.kt
    - src/test/kotlin/com/six2dez/burp/aiagent/redact/SafeRegexTest.kt
  modified:
    - src/main/kotlin/com/six2dez/burp/aiagent/redact/Redaction.kt
    - src/test/kotlin/com/six2dez/burp/aiagent/redact/RedactionTest.kt
decisions:
  - "ADVERSARIAL_PROBE expanded to 2000 chars (JDK 21 NFA optimizations handle classic 64-char probes near-instantly)"
  - "testHkdfExtract/testHkdfExpand internal seams added to Redaction.kt for RFC 5869 vector assertion without exposing public API"
  - "ADVERSARIAL_PROBE changed from const to val (runtime-computed via String.repeat, not a compile-time literal)"
metrics:
  duration: ~30 min
  completed: "2026-06-10"
  tasks_completed: 3
  files_changed: 4
---

# Phase 13 Plan 01: Privacy Redaction Core Foundation Summary

HKDF host anonymization via RFC 5869 HMAC-SHA256 extract/expand replacing the previous SHA-256 digest, plus a new AWT-free SafeRegex interruptible-CharSequence ReDoS guard with 50ms deadline.

## What Was Built

### Task 1 — Wave 0 RED: Test scaffold (commit 2fa24c3)
- Extended `RedactionTest.kt` with `hostAnonymizationFormatIsStable` (regex format assertion) and `hkdfMatchesRfc5869Vector` (RFC 5869 Test Case 1 PRK/OKM vector)
- Created `SafeRegexTest.kt` with 4 tests: catastrophic pattern rejection, benign pattern acceptance, timeout-and-return-input, benign replace
- Suite fails RED as expected (SafeRegex class and testHkdfExtract seam not yet created)

### Task 2 — GREEN for SafeRegexTest: SafeRegex.kt (commit f4b0fd5)
- Created `SafeRegex.kt` as top-level `object SafeRegex` with `DeadlineCharSequence` and `RegexTimeoutException`
- `replaceAllSafe(input, pattern, replacement, timeoutMs=50)`: fail-open on timeout (returns original input unchanged)
- `isPatternSafe(regex, timeoutMs=50)`: compile check + adversarial probe; false on PatternSyntaxException or RegexTimeoutException
- AWT-free (no java.awt/javax.swing imports); no abandoned ExecutorService

### Task 3 — GREEN for all tests: HKDF + seams + probe fix (commit 7410ff1)
- Replaced `MessageDigest.getInstance("SHA-256")` with RFC 5869 HKDF extract-then-expand using `Mac.getInstance("HmacSHA256")`
- Private helpers: `hmacSha256` (empty-key guard per Pitfall 1), `hkdfExtract`, `hkdfExpand`
- Constants: `HKDF_INFO = "burp-ai-agent:host"`, `HKDF_OKM_LEN = 6` (preserves host-<12hex>.local format)
- Added `internal testHkdfExtract` / `testHkdfExpand` seams for the RFC 5869 vector test
- Updated imports: added `javax.crypto.Mac`, `javax.crypto.spec.SecretKeySpec`, `java.io.ByteArrayOutputStream`; removed `java.security.MessageDigest`
- `anonymizeHost` signature preserved exactly: `anonymizeHost(host, salt, recordMapping=true)` — zero caller changes

## Test Results

- `./gradlew test --tests "com.six2dez.burp.aiagent.redact.*"` — 12 tests, all GREEN
- `./gradlew test` — full suite GREEN, no regressions

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] JDK 21 NFA optimization invalidates 64-char adversarial probe**
- **Found during:** Task 2/3 GREEN phase — `catastrophicPatternIsRejectedWithinBudget` returned `true` instead of `false`
- **Issue:** JDK 21's regex engine (unlike the JDK 8-era OCPsoft reference) handles `(a+)+$` against 64-char inputs near-instantly. The classic probe length from research was calibrated for pre-JDK-21 engines.
- **Fix:** Expanded `ADVERSARIAL_PROBE` from 64 to 2000 `a`s + `!`. At 2000 chars, `(a+)+$` reliably times out within 50ms; benign `\d+` completes in microseconds. Changed from `private const val` to `private val` (runtime-computed via `String.repeat`).
- **Files modified:** `SafeRegex.kt`, `SafeRegexTest.kt`
- **Commit:** 7410ff1

**2. [Rule 2 - Missing critical] Internal test seam for RFC 5869 vector assertion**
- **Found during:** Task 1 — `RedactionTest.hkdfMatchesRfc5869Vector` needs to call `hkdfExtract`/`hkdfExpand` which are private
- **Fix:** Added `internal fun testHkdfExtract` / `testHkdfExpand` delegating to private helpers. Minimal seam, clearly documented as non-API.
- **Files modified:** `Redaction.kt`
- **Commit:** 7410ff1

## Known Stubs

None — this plan's scope (HKDF anonymization + SafeRegex primitive) is fully implemented and tested.

## Threat Flags

None — no new network endpoints, auth paths, file access patterns, or schema changes introduced. All changes are internal cryptographic algorithm swap and a new utility class. The threat model from the plan (T-13-01, T-13-02, T-13-03) is fully addressed:
- T-13-01: HKDF now matches SPEC's privacy claim (verified by RFC vector test)
- T-13-02: SafeRegex bounds matches to 50ms, tested against catastrophic pattern
- T-13-03: Fail-soft on timeout (returns input unchanged), no sensitive data logged

## Self-Check: PASSED

| Item | Status |
|------|--------|
| SafeRegex.kt exists | FOUND |
| SafeRegexTest.kt exists | FOUND |
| 13-01-SUMMARY.md exists | FOUND |
| Commit 2fa24c3 (Task 1 RED) | FOUND |
| Commit f4b0fd5 (Task 2 SafeRegex) | FOUND |
| Commit 7410ff1 (Task 3 HKDF) | FOUND |
| `./gradlew test --tests "*.redact.*"` | GREEN (12 tests) |
| `./gradlew test` (full suite) | GREEN |
