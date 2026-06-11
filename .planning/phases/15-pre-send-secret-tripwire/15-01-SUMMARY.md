---
phase: 15-pre-send-secret-tripwire
plan: "01"
subsystem: redact
tags: [security, entropy, detector, tdd, priv-03]
dependency_graph:
  requires: [13-03]
  provides: [Entropy.kt, SecretTripwire.kt]
  affects: [redact/Entropy.kt, redact/SecretTripwire.kt, redact/EntropyTest.kt, redact/SecretTripwireTest.kt]
tech_stack:
  added: []
  patterns: [AWT-free object, Shannon entropy, TDD RED/GREEN]
key_files:
  created:
    - src/main/kotlin/com/six2dez/burp/aiagent/redact/Entropy.kt
    - src/main/kotlin/com/six2dez/burp/aiagent/redact/SecretTripwire.kt
    - src/test/kotlin/com/six2dez/burp/aiagent/redact/EntropyTest.kt
    - src/test/kotlin/com/six2dez/burp/aiagent/redact/SecretTripwireTest.kt
  modified: []
decisions:
  - "Entropy thresholds ship as private const (BASE64=4.5, HEX=3.0, MIN_TOKEN_LEN=20) following SecretShapes no-user-facing-tuning precedent"
  - "truncatedScore uses Locale.ROOT to guarantee dot-decimal output regardless of JVM locale (ES locale produced comma-decimal)"
  - "tokenAtMinLenQualifies test uses the hex threshold (3.0) not base64 (4.5) because a 20-char token cannot reach 4.5 bits/char (log2(20)~4.32 < 4.5)"
metrics:
  duration_minutes: 4
  completed_date: "2026-06-11"
  tasks_completed: 3
  files_changed: 4
---

# Phase 15 Plan 01: Detector Core Foundation Summary

AWT-free Shannon entropy helper (Entropy.kt) and pure detector orchestrator (SecretTripwire.kt) reusing SecretShapes.findSurviving for known-shape detection and Entropy.maxQualifyingTokenEntropy for unprefixed high-entropy base64 detection — the single PRIV-03 pre-send tripwire reused by all three outbound paths.

## What Was Built

**Entropy.kt** (`redact` package, AWT-free):
- `shannon(s: String): Double` — Shannon H = -sum(p * log2(p)), 0.0 for empty
- `maxQualifyingTokenEntropy(text: String): Double` — splits on `[^A-Za-z0-9+/=_-]+` (linear/ReDoS-safe), skips tokens < 20 chars, classifies hex vs base64 charset, returns max entropy among qualifying tokens (hex >= 3.0 OR base64 >= 4.5), else 0.0
- `truncatedScore(bitsPerChar: Double): String` — `"%.1f".format(Locale.ROOT, bitsPerChar)` for SC3 audit log
- Private consts: `MIN_TOKEN_LEN=20`, `BASE64_THRESHOLD=4.5`, `HEX_THRESHOLD=3.0` (truffleHog/detect-secrets canonical defaults)

**SecretTripwire.kt** (`redact` package, AWT-free):
- `data class ScanResult(matched, shapeCategories, maxEntropyBitsPerChar)` — no-leak by type (no raw token field)
- `scan(payload: String): ScanResult` — delegates to `SecretShapes.findSurviving` + `Entropy.maxQualifyingTokenEntropy`; `matched = categories.isNotEmpty() || maxEntropy > 0.0`

**EntropyTest.kt** (7 tests):
- shannon correctness: constant string → 0.0, uniform 16-char hex → ~4.0, empty → 0.0
- MIN_TOKEN_LEN gate: 19-char token does not qualify; 20-char hex token qualifies via hex threshold
- Threshold coverage: 32-char hex token clears hex threshold; 48-char diverse base64 clears base64 threshold
- truncatedScore format: 4.73 → "4.7", 0.0 → "0.0", locale-independent

**SecretTripwireTest.kt** (8 tests):
- SC1: AKIAIOSFODNN7EXAMPLE matched + AWS category present
- SC1: synthetic 44-char high-entropy base64 matched via entropy, maxEntropyBitsPerChar > 0.0
- SC2: legit base64 fuzz token matched (by design — warn-with-confirm)
- SC2: "hello world this is fine" not matched (no false fire on low-entropy prose)
- SC3 no-leak x2: ScanResult.toString() and shapeCategories.joinToString() do not contain the raw input token (AKIAIOSFODNN7EXAMPLE and the synthetic token)

## Commits

| Task | Commit | Description |
|------|--------|-------------|
| 1 (RED) | 97c731f | test(15-01): add failing Entropy + SecretTripwire detector tests |
| 2 (GREEN) | dcb7066 | feat(15-01): AWT-free Shannon entropy helper (Entropy.kt) |
| 3 (GREEN) | 0e1e259 | feat(15-01): SecretTripwire detector reusing SecretShapes + Entropy |

## TDD Gate Compliance

- RED gate: `test(15-01)` commit 97c731f exists before any implementation
- GREEN gate: `feat(15-01)` commits dcb7066 and 0e1e259 follow and pass all tests
- REFACTOR: not required (implementation was clean)

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] Locale-dependent decimal separator in truncatedScore**
- **Found during:** Task 2 (first GREEN run)
- **Issue:** `"%.1f".format(4.73)` produced `"4,7"` on a JVM with Spanish locale (user's machine: `-Duser.country=ES -Duser.language=es`), failing the `assertEquals("4.7", ...)` assertion in EntropyTest.
- **Fix:** Changed to `"%.1f".format(Locale.ROOT, bitsPerChar)` in Entropy.kt + added `import java.util.Locale`. Locale.ROOT guarantees dot-decimal separator regardless of JVM locale.
- **Files modified:** `Entropy.kt`
- **Commit:** dcb7066

**2. [Rule 1 - Bug] Test token entropy below base64 threshold**
- **Found during:** Task 2 (first GREEN run)
- **Issue:** `tokenAtMinLenQualifiesWhenHighEntropy` used a 20-char base64 token (`"ABCDEFGHIJKLMNOPQRst"`) but log2(20) ≈ 4.32 < 4.5 = BASE64_THRESHOLD, so the test was impossible to pass by design. Also `longBase64TokenClearsBase64Threshold` asserted length==44 on a string that was actually 42 chars.
- **Fix:** `tokenAtMinLenQualifiesWhenHighEntropy` renamed to `tokenAtMinLenQualifiesViaHexThreshold` and uses a 20-char hex token (`"0123456789abcdef0123"`) which clears HEX_THRESHOLD=3.0. `longBase64TokenClearsBase64Threshold` updated to a 48-char token with entropy ~5.6 bits/char.
- **Files modified:** `EntropyTest.kt`
- **Commit:** dcb7066

## Known Stubs

None — all detector methods are fully implemented and tested.

## Threat Flags

No new security-relevant surfaces beyond those in the plan's threat model. `Entropy.kt` and `SecretTripwire.kt` are pure in-memory compute with no network, file, or UI access.

## Self-Check: PASSED

- [x] `src/main/kotlin/com/six2dez/burp/aiagent/redact/Entropy.kt` — exists
- [x] `src/main/kotlin/com/six2dez/burp/aiagent/redact/SecretTripwire.kt` — exists
- [x] `src/test/kotlin/com/six2dez/burp/aiagent/redact/EntropyTest.kt` — exists
- [x] `src/test/kotlin/com/six2dez/burp/aiagent/redact/SecretTripwireTest.kt` — exists
- [x] Commits 97c731f, dcb7066, 0e1e259 present in git log
- [x] `./gradlew test --tests "*EntropyTest" --tests "*SecretTripwireTest"` GREEN (15 tests pass)
- [x] `./gradlew test` GREEN (full suite)
- [x] AWT-free: no `import java.awt` or `import javax.swing` in Entropy.kt or SecretTripwire.kt
- [x] No new dependency added to build.gradle.kts
