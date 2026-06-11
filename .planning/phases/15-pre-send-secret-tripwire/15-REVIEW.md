---
phase: 15-pre-send-secret-tripwire
reviewed: 2026-06-11T00:00:00Z
depth: standard
files_reviewed: 10
files_reviewed_list:
  - src/main/kotlin/com/six2dez/burp/aiagent/redact/Entropy.kt
  - src/main/kotlin/com/six2dez/burp/aiagent/redact/SecretTripwire.kt
  - src/main/kotlin/com/six2dez/burp/aiagent/ui/components/ContextPreviewDialog.kt
  - src/main/kotlin/com/six2dez/burp/aiagent/ui/ChatPanel.kt
  - src/main/kotlin/com/six2dez/burp/aiagent/scanner/PassiveAiScanner.kt
  - src/main/kotlin/com/six2dez/burp/aiagent/mcp/McpToolContext.kt
  - src/test/kotlin/com/six2dez/burp/aiagent/redact/EntropyTest.kt
  - src/test/kotlin/com/six2dez/burp/aiagent/redact/SecretTripwireTest.kt
  - src/test/kotlin/com/six2dez/burp/aiagent/redact/SecretTripwireGateTest.kt
  - src/test/kotlin/com/six2dez/burp/aiagent/redact/SecretTripwireHooksTest.kt
findings:
  critical: 0
  warning: 3
  info: 4
  total: 7
status: issues_found
---

# Phase 15: Code Review Report

**Reviewed:** 2026-06-11
**Depth:** standard
**Files Reviewed:** 10
**Status:** issues_found

## Summary

Phase 15 adds the PRIV-03 pre-send secret tripwire: a Shannon-entropy helper (`Entropy`),
an orchestrating detector (`SecretTripwire`) that reuses `SecretShapes` as the single source of
truth, an interactive warn-with-confirmation gate in `ContextPreviewDialog`, and audit-and-proceed
hooks on the two non-interactive outbound paths (`PassiveAiScanner` ×3 sites, `McpToolContext`).

**The load-bearing security invariant holds.** I traced the no-leak property (SC3) through all
five emit sites and the persistence path (`emitGlobal` → `AuditLogger.logEvent` → `audit.jsonl`):
every payload map carries only `path`, `sessionId`, a sorted `shapeCategories` name list, and a
one-decimal `entropyScore` string. `ScanResult` has no raw-token field; no `emitGlobal`/banner call
interpolates the input text. The RISK banner names categories only, and the banner HTML is built
from hardcoded `SecretShapes.category` literals (no HTML-injection vector). The never-hard-block
invariant (SC2) also holds: the chat gate returns a `Boolean` (Cancel = user choice), MCP returns
`finalText` regardless, and the scanner falls through to `supervisor.send` after auditing. AWT-free,
zero-new-deps, single-source-of-truth, and English-only/UTF-8 constraints are all satisfied, and the
targeted test suites build and pass green via `./gradlew test`.

The findings below are correctness/robustness gaps in the **detector**, not the no-leak or
no-block guarantees. The most important is WR-01: a tokenization gap in `Entropy` that lets a real
class of high-entropy secrets (those containing `.`, e.g. a raw JWT body or a dot-delimited key)
slip past the entropy half of the detector entirely. This weakens the advertised "catches unprefixed
high-entropy tokens" contribution but is not a leak or a block, hence WARNING.

## Warnings

### WR-01: Entropy tokenizer splits on `.` `:` `,` — high-entropy secrets containing those bytes evade the entropy detector

**File:** `src/main/kotlin/com/six2dez/burp/aiagent/redact/Entropy.kt:53` (used at `:85`)
**Issue:**
`TOKEN_SPLIT = Regex("[^A-Za-z0-9+/=_-]+")` treats `.`, `:`, `,`, and whitespace as token
delimiters. That is fine for the shape half (JWTs are caught by `SecretShapes`), but it means the
**entropy half** never sees a contiguous high-entropy run that contains any of those characters.
Two concrete consequences:

1. A base64**url** value with `.` separators (a JWT body/signature that somehow lost its `eyJ`
   header, or a dot-delimited API key like `xxxxxx.yyyyyy.zzzzzz`) is fragmented into sub-20-char
   pieces, each of which fails the `MIN_TOKEN_LEN` gate, so the entropy detector reports `0.0`.
2. A long unprefixed secret pasted inline with a trailing colon/comma in JSON
   (`"key":"<46 base64 chars>",`) still tokenizes fine because `"` and `,` are delimiters and the
   value is isolated — but a value like `Bearer.<token>` or `id:<token>` where the high-entropy
   run abuts a `.`/`:` *inside* the run gets split.

The entropy path's stated "real contribution is base64 tokens with no known prefix"
(`Entropy.kt:13`); silently dropping the dot-containing subset of exactly that class is a
correctness gap in the detector's advertised coverage. This is a missed-detection (false negative),
not a leak/block, so WARNING rather than BLOCKER.

**Fix:** Decide explicitly whether `.`/`:` are intra-token or inter-token, and document it. If the
intent is to cover dot-delimited base64url secrets, add `.` to the token character class so the
run stays contiguous; the per-segment hex/base64 charset check still gates qualification:
```kotlin
// Keep '.' as an intra-token char so dot-delimited base64url secrets stay contiguous;
// charset gate below still rejects ordinary prose sentences ("a.b.c" is < MIN_TOKEN_LEN).
private val TOKEN_SPLIT = Regex("[^A-Za-z0-9+/=_.\\-]+")
```
If instead the current split is intentional (rely on `SecretShapes` for all dot-delimited forms),
add a one-line comment at `:53` stating that and a negative test asserting the chosen behavior, so
the gap is a documented decision rather than an accident.

### WR-02: `entropyScore` is emitted even when the match is shape-only, encoding a misleading `0.0`

**File:** `src/main/kotlin/com/six2dez/burp/aiagent/redact/SecretTripwire.kt:103,126` (and the four
inline emit sites: `PassiveAiScanner.kt:923,1589,1691`, `McpToolContext.kt:71`)
**Issue:**
`buildAllowAuditPayload` / `buildDetectAuditPayload` always write
`"entropyScore" to Entropy.truncatedScore(scan.maxEntropyBitsPerChar)`. When a match is
shape-only (e.g. an AWS `AKIA…` key with no qualifying high-entropy token), `maxEntropyBitsPerChar`
is `0.0`, so the audit event records `entropyScore = "0.0"`. A reader of `audit.jsonl` cannot
distinguish "entropy detector ran and scored 0.0" from "entropy detector did not contribute to this
match." This is benign for the no-leak invariant (it is a number) but actively misleading for the
audit-trail consumer this phase exists to serve. It is a recurring data-quality defect duplicated
across five call sites, which also makes it fragile to fix later.

**Fix:** Emit `entropyScore` only when the entropy half actually contributed, or tag the source.
Centralize so all five sites stay consistent (see IN-01):
```kotlin
val map = buildMap<String, Any?> {
    put("path", path)
    put("sessionId", sessionId ?: "none")
    put("shapeCategories", scan.shapeCategories.toList().sorted())
    if (scan.maxEntropyBitsPerChar > 0.0) {
        put("entropyScore", Entropy.truncatedScore(scan.maxEntropyBitsPerChar))
    }
}
```
At minimum, document at `truncatedScore` that `"0.0"` overloads "no entropy contribution."

### WR-03: Four secret-tripwire emit sites are hand-duplicated instead of using the provided helpers

**File:** `src/main/kotlin/com/six2dez/burp/aiagent/scanner/PassiveAiScanner.kt:915-927,1581-1593,1683-1695`
and `src/main/kotlin/com/six2dez/burp/aiagent/mcp/McpToolContext.kt:63-75`
**Issue:**
`SecretTripwire` ships `detectAndBuild(payload, path, sessionId)` and `buildDetectAuditPayload(...)`
expressly as "convenience helper[s] for non-interactive hook bodies" (`SecretTripwire.kt:129-149`),
and `SecretTripwireHooksTest` covers them. Yet none of the four non-interactive hook sites use them:
each re-implements the scan + `if (matched)` + inline `mapOf("path" to …, "sessionId" to …,
"shapeCategories" to … .sorted(), "entropyScore" to Entropy.truncatedScore(…))` by hand. The
helper is therefore dead code in `main` (only tests call it), and the four copies have already
drifted in a way that matters: any fix for WR-01/WR-02 must now be applied in four places, and a
miss in one path is a silent no-leak/consistency regression. The duplication is the root cause that
makes WR-02 a five-site change.

**Fix:** Route every non-interactive hook through the existing helper so there is exactly one
payload shape:
```kotlin
// McpToolContext.redactIfNeeded:
SecretTripwire.detectAndBuild(finalText, path = "mcp", sessionId = supervisor?.currentSessionId())
    ?.let { AuditLogger.emitGlobal("secret_tripwire_detect", it) }

// PassiveAiScanner (each of the three sites):
SecretTripwire.detectAndBuild(prompt, path = "passive_scanner", sessionId = supervisor.currentSessionId())
    ?.let { AuditLogger.emitGlobal("secret_tripwire_detect", it) }
```
This deletes ~36 lines, removes the dead-code helper, and collapses WR-02 to a single edit.

## Info

### IN-01: `Entropy` import in `PassiveAiScanner` / `McpToolContext` only exists because the hooks bypass the helper

**File:** `src/main/kotlin/com/six2dez/burp/aiagent/scanner/PassiveAiScanner.kt:17`,
`src/main/kotlin/com/six2dez/burp/aiagent/mcp/McpToolContext.kt:11`
**Issue:** Both files import `com.six2dez.burp.aiagent.redact.Entropy` solely to call
`Entropy.truncatedScore(...)` inline. Adopting WR-03 makes `truncatedScore` an internal detail of
`SecretTripwire` and renders these two imports (and the direct `Entropy` coupling of these modules)
unnecessary. Encapsulating the score formatting behind the payload builder is the cleaner boundary.
**Fix:** After WR-03, drop the now-unused `Entropy` imports from both files.

### IN-02: `Short`-typed status comparisons read awkwardly and are easy to regress

**File:** `src/main/kotlin/com/six2dez/burp/aiagent/scanner/PassiveAiScanner.kt:1158`
**Issue:** `if (status == 204.toShort() || status == 304.toShort())` — `response.statusCode()`
returns a `Short`, so the `.toShort()` literals are required, but the pattern is unusual and a future
edit that drops `.toShort()` would silently always-false (Int vs Short never equal in Kotlin). Not a
Phase 15 change per se, but it sits one line below newly-touched scanner code and is a latent
foot-gun. (Out of strict Phase 15 scope — noted only because it is adjacent to the reviewed diff.)
**Fix:** Introduce a typed constant or compare against `Short` vals:
`private val SKIP_STATUSES = setOf<Short>(204, 304)` then `if (status in SKIP_STATUSES)`.

### IN-03: `truncatedScore` can emit a negative-looking `"-0.0"` and the allow-builder regex anticipates a sign that the domain forbids

**File:** `src/main/kotlin/com/six2dez/burp/aiagent/redact/Entropy.kt:103`;
test `SecretTripwireGateTest.kt:176` (`Regex("-?\\d+\\.\\d")`)
**Issue:** Shannon entropy is always ≥ 0, so a sign is never expected. `"%.1f".format(Locale.ROOT,
-0.0)` yields `"-0.0"`, and the gate-test regex tolerates a leading `-` (`-?`), implicitly admitting
an impossible value into the contract. While `shannon` cannot currently produce `-0.0` (the sum is
non-negative), formatting `-0.0` would still produce `"-0.0"`, and the `-?` in the test signals
uncertainty about the invariant. Cosmetic, no leak.
**Fix:** Normalize negative-zero and tighten the test to the real domain:
`fun truncatedScore(b: Double) = "%.1f".format(Locale.ROOT, if (b == 0.0) 0.0 else b)` and change
the test regex to `Regex("\\d+\\.\\d")` (matching the stricter `SecretTripwireHooksTest.kt:168`,
which already omits the sign — the two tests are inconsistent today).

### IN-04: ChatPanel re-scans the payload a second time after `confirm()` already scanned it

**File:** `src/main/kotlin/com/six2dez/burp/aiagent/ui/ChatPanel.kt:322`
**Issue:** `confirm()` runs `SecretTripwire.scan(contextJson)` to drive the gate, then
`startSessionFromContext` runs `SecretTripwire.scan(capture.contextJson)` again to build the allow
event (so it can carry the post-`createSession` session id). The code comments justify this ("cheap,
same bytes"), and it is correct, but it is a redundant full scan of a payload that can be large, and
it couples correctness to the two call sites passing the identical string (they do today:
`contextJson = capture.contextJson` at `:307`). Acceptable as-is; flagged for awareness.
**Fix (optional):** Have `confirm()` return the `ScanResult` (or a small result object) alongside the
`Boolean`, or hoist the single `scan` into `startSessionFromContext` and pass it down, so the gate
and the allow-audit share one scan. Preserves the "emit after createSession" ordering without the
second pass.

---

_Reviewed: 2026-06-11_
_Reviewer: Claude (gsd-code-reviewer)_
_Depth: standard_
