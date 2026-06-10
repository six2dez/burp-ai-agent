---
phase: 13-privacy-redaction-hardening
reviewed: 2026-06-10T00:00:00Z
depth: standard
iteration: 2
files_reviewed: 12
files_reviewed_list:
  - src/main/kotlin/com/six2dez/burp/aiagent/App.kt
  - src/main/kotlin/com/six2dez/burp/aiagent/redact/Redaction.kt
  - src/main/kotlin/com/six2dez/burp/aiagent/redact/SafeRegex.kt
  - src/main/kotlin/com/six2dez/burp/aiagent/redact/SecretShapes.kt
  - src/main/kotlin/com/six2dez/burp/aiagent/config/AgentSettings.kt
  - src/main/kotlin/com/six2dez/burp/aiagent/config/Defaults.kt
  - src/main/kotlin/com/six2dez/burp/aiagent/ui/components/ContextPreviewDialog.kt
  - src/main/kotlin/com/six2dez/burp/aiagent/ui/panels/PrivacyConfigPanel.kt
  - src/main/kotlin/com/six2dez/burp/aiagent/ui/SettingsPanel.kt
  - src/test/kotlin/com/six2dez/burp/aiagent/redact/RedactionTest.kt
  - src/test/kotlin/com/six2dez/burp/aiagent/redact/SafeRegexTest.kt
  - src/test/kotlin/com/six2dez/burp/aiagent/redact/SecretShapesTest.kt
findings:
  critical: 0
  warning: 0
  info: 2
  total: 2
status: clean
---

# Phase 13: Code Review Report (Iteration 2 — fix verification)

**Reviewed:** 2026-06-10
**Depth:** standard
**Files Reviewed:** 12
**Status:** clean

## Summary

Iteration-2 re-review after the iteration-1 fixes were applied (CR-01 startup seeding,
WR-01 empty-match rejection, WR-03 unquoted-JSON-value redaction, WR-04 doc-only; WR-02
intentionally retained as accepted fail-safe design). All three priority fixes are correct
and introduce no regressions. The redaction test suite
(`./gradlew test --tests com.six2dez.burp.aiagent.redact.*`) builds and passes green; the
only compiler output is a pre-existing `registerScanCheck` deprecation warning at App.kt:165,
unrelated to this phase (and `ktlintCheck` is the known-broken `generateBuildFlags` defect, so
`test` is the correct gate).

The iteration-1 blocker and all four warnings are now resolved or accepted. No new BLOCKER or
WARNING findings. Two INFO observations are recorded for completeness — neither blocks ship.

### Verification of the three priority fixes

**CR-01 — startup seeding (App.kt:82-89): CORRECT.** `settings` is the local val returned by
`settingsRepo.load()` (line 82), and `Redaction.setCustomPatterns(settings.customRedactionPatterns)`
runs at line 89 — after load and before any context-collection or scanner path can fire (MainTab
registration and scan-check registration come later, lines 137+). No NPE risk:
`AgentSettings.customRedactionPatterns` defaults to `emptyList()` and `load()` never produces null
(it splits/filters into a non-null list at AgentSettings.kt:394-396). No ordering hazard:
`setCustomPatterns` mutates only the `@Volatile compiledCustomPatterns` field and reads nothing from
`App` state, so it is safe at this point in `initialize()`. The new regression test
`customPatternsFromSettingsAreActiveAfterSeeding` (RedactionTest.kt:290) locks the load→seed→apply
contract, and `@AfterEach resetCustomPatterns()` (RedactionTest.kt:48) prevents cross-test bleed.
Persisted patterns were already `isPatternSafe`-validated on save and `setCustomPatterns` silently
drops uncompilable entries, so the unconditional startup call is safe. Correct settings var, no
NPE, no ordering issue.

**WR-01 — SafeRegex empty-match guard (SafeRegex.kt:99-105): CORRECT, no over-rejection.** Verified
`compiled.matcher("").find()` against the full test corpus: it rejects every zero-width footgun
(`a*`, `\d*`, `[0-9]*`, `\s*`, `x?`, `(foo)?`, `.*`, `(abc)*`, `a|`) and accepts every legitimate
non-empty matcher (`\bSECRET-\d{4}\b`, `\d+`, `[A-Z]+`, `INTERNAL-[A-Z0-9]{6}`, `a+`). Bare anchors
and optional-quantified patterns (`^`, `$`, `\B`, `\d{0,4}`) are also rejected — the correct call,
since they would trigger the same between-every-character replacement bloat the guard exists to
prevent. The discarded `.find()` result on the adversarial probe (line 103) is intentional and
correct: the probe call exists only to trip `RegexTimeoutException` for catastrophic patterns; a
benign match/non-match within budget is "safe", so returning `true` unconditionally when no timeout
fires is right. Tests `emptyMatchingPatternsAreRejected` and `nonEmptyMatchingPatternsStillAccepted`
(SafeRegexTest.kt:52, 61) cover both directions. The SettingsPanel feedback message
(SettingsPanel.kt:1237-1239) was updated to mention "matches empty string", so the rejection is
surfaced to the user.

**WR-03 — JSON unquoted-value redaction (Redaction.kt:114-117): CORRECT, no over-redaction of
benign numerics.** The value group `("[^"]*"|true|false|null|-?\d+(?:\.\d+)?)` now covers quoted
strings plus JSON scalars, and every match is normalized to the quoted token `"[REDACTED]"`, keeping
output valid JSON. Traced against
`{"token":12345,"api_key":true,"secret":null,"sid":-42,"balance":99.5,"name":"alice","count":7}`:
sensitive numerics/booleans/nulls are redacted while benign numerics (`balance:99.5`, `count:7`) are
untouched. Key matching is fully anchored by the literal `"` on both sides, so substring keys are
NOT over-matched — confirmed `tokens`, `authentication`, `publickey`, `monkey`, `encode`,
`account_id`, `keymaster`, `user_session_count`, `status_code`, and `zipcode` all pass through
unredacted. Pass ordering (bearer → urlToken → form → json) traced end-to-end with no
double-redaction or leakage. The escaped-quote limitation is documented in-code (lines 111-113) and
acceptable. Test `bodyJsonUnquotedSecretValuesRedacted` (RedactionTest.kt:229) asserts both the
redaction of numeric/boolean/null secrets and the preservation of benign `balance:99.5`.

**WR-02 (accepted, not re-raised):** `code` in `SENSITIVE_KEYS` was re-examined and confirmed
contained — the `"` anchoring means only the exact `"code"` key matches, not `status_code`/`zipcode`,
and the form `(^|[?&])` gate means only a standalone `code=` field matches, not `country_code=`.
This is key breadth, not a substring bug. Correctly retained as accepted fail-safe design per the
fix brief; not re-raised as a blocker.

## Info

### IN-01: `formBodyParamRegex` multiline anchor redacts any `sensitive=value` line, not only form bodies

**File:** `src/main/kotlin/com/six2dez/burp/aiagent/redact/Redaction.kt:100-103`
**Issue:** With `(?im)` and the `(^|[?&])` anchor, the form-body pattern matches a sensitive key at
the start of *any* line, not only inside an `application/x-www-form-urlencoded` body. A line such as
`token=topsecret` or `key=val123` in a plaintext/log-style body is redacted. This is correct and
fail-safe for outbound privacy (it over-redacts toward secrecy, and HTTP headers use `:` not `=` so
they are untouched), but it is broader than the "form body" name implies. Recording so the breadth
is an explicit, documented decision rather than an accident. No regression — this behavior is
unchanged from iteration 1 and is the intended PRIV-02 design.
**Fix:** None required. Optionally tighten the in-code comment to note the pattern applies to any
line-leading `key=value`, so future maintainers do not narrow it by mistake.

### IN-02: `save()` try-block body is under-indented relative to the enclosing `try`

**File:** `src/main/kotlin/com/six2dez/burp/aiagent/config/AgentSettings.kt:503-655`
**Issue:** The `try {` opened at line 503 wraps the entire prefs-write block, but the body
(lines 504-653) is indented at the same level as the `try` keyword rather than one level deeper.
Purely cosmetic — the WR-03 cache-eviction-on-partial-write logic is correct (the cache is set only
after all writes succeed at line 655 and evicted in the catch at line 659). ktlint would normally
flag this, but `ktlintCheck` is known-broken standalone in this repo (generateBuildFlags wiring
defect), so it would not be auto-caught. Pre-existing; not introduced by this phase's redaction
fixes.
**Fix:** Re-indent lines 504-653 one level deeper to sit inside the `try` block when the ktlint
wiring is next repaired. No behavioral change.

---

_Reviewed: 2026-06-10_
_Reviewer: Claude (gsd-code-reviewer)_
_Depth: standard (iteration 2)_
