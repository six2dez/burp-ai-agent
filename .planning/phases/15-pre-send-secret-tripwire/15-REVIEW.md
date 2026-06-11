---
phase: 15-pre-send-secret-tripwire
reviewed: 2026-06-11T00:00:00Z
depth: standard
iteration: 2
files_reviewed: 7
files_reviewed_list:
  - src/main/kotlin/com/six2dez/burp/aiagent/redact/Entropy.kt
  - src/main/kotlin/com/six2dez/burp/aiagent/redact/SecretTripwire.kt
  - src/main/kotlin/com/six2dez/burp/aiagent/scanner/PassiveAiScanner.kt
  - src/main/kotlin/com/six2dez/burp/aiagent/mcp/McpToolContext.kt
  - src/test/kotlin/com/six2dez/burp/aiagent/redact/EntropyTest.kt
  - src/test/kotlin/com/six2dez/burp/aiagent/redact/SecretTripwireHooksTest.kt
  - src/test/kotlin/com/six2dez/burp/aiagent/redact/SecretTripwireGateTest.kt
findings:
  critical: 0
  warning: 0
  info: 2
  total: 2
status: clean
---

> Iteration-2 residual WARNING (dot-joined pass firing on MAC-like dotted-hex runs) resolved by the orchestrator: Pass 2 in `Entropy.maxQualifyingTokenEntropy` now requires the BASE64 threshold (4.5 bits/char) only — pure hex maxes at 4.0, so dotted-hex/MAC runs no longer qualify, while base64url/JWT recovery is preserved (entropy + tripwire suites green). Both security invariants (no-leak SC3, never-hard-block SC2) verified HOLD. The 2 INFO items are cosmetic (a `detectAndBuild` type-convention note; a test-regex `-?` that's moot since entropy is never negative) — accepted. Status: clean.

# Phase 15: Code Review Report (Iteration 2)

**Reviewed:** 2026-06-11T00:00:00Z
**Depth:** standard
**Files Reviewed:** 7
**Status:** issues_found

## Summary

Iteration-2 adversarial re-review of the PRIV-03 pre-send secret tripwire after the iteration-1
fixes: WR-03 (ad8167c) centralized the SC3 audit payload into one `SecretTripwire` builder and
routed the non-interactive hooks through `detectAndBuild`; WR-02 (134b716) omits `entropyScore` on
shape-only matches; WR-01 (db30533) added an additive dot-joined entropy pass with FP-guard tests.

**Both load-bearing security invariants were independently re-verified by full data-flow tracing and
both HOLD.** No blocker. The iteration-1 WR-01/02/03 are confirmed resolved. One residual WARNING
(the WR-01 dot-joined pass widens the dotted-hex false-positive surface — non-blocking, non-leaking,
matching the fixer's "warn-only, risk-acceptable" call) and two INFO items remain.

### Invariant (a) — NO path logs/audits/echoes the RAW secret value: HOLD

Verified at the type level and along every emit path:
- `SecretShapes.findSurviving` (single source of truth, SecretShapes.kt:93-94) maps each matching
  shape to `it.category` — a compile-time-constant label (e.g. "AWS access key") — and discards the
  regex match. The matched substring is never carried out.
- `SecretTripwire.ScanResult` (SecretTripwire.kt:38-42) has exactly three fields: `matched: Boolean`,
  `shapeCategories: Set<String>` (labels only), `maxEntropyBitsPerChar: Double`. There is no
  raw-token field by construction — the SC3 no-leak property is enforced structurally.
- `buildAuditPayload` (SecretTripwire.kt:96-115) `put`s only fixed keys: `path`, `sessionId`
  (or "none"), `shapeCategories` (sorted labels), and `entropyScore` (a `"%.1f"` string). grep
  confirmed the only `put(...)` values are `path`, `sessionId ?: "none"`, the sorted categories, and
  `Entropy.truncatedScore(...)` — no scanned-payload variable is ever interpolated.
- `Entropy.truncatedScore` (Entropy.kt:149) formats a `Double` to one decimal — never the token.
- All three emit call sites pass only the builder's map and never the scanned text:
  `PassiveAiScanner.kt:915-916` (`detectAndBuild(singlePrompt, ...)?.let { emitGlobal(...) }`),
  `McpToolContext.kt:63-64` (`detectAndBuild(finalText, ...)?.let { ... }`),
  `ChatPanel.kt:324-327` (`buildAllowAuditPayload(tripwireScan, session.id)`).
- Tests assert the no-leak property for both detector halves: `SecretTripwireHooksTest:146-168` and
  `SecretTripwireGateTest:201-228` confirm the raw token is absent from the payload's string form.

### Invariant (b) — never-hard-block (SC2): HOLD

- `PassiveAiScanner.doAnalysis` (PassiveAiScanner.kt:915-933): `detectAndBuild(...)?.let { emit }`
  then unconditionally calls `supervisor.send(...)`. The `?.let` gates only the emit, never the send.
- `McpToolContext.redactIfNeeded` (McpToolContext.kt:55-67): emit-on-match, then `return finalText`
  regardless — the scan result cannot suppress the return value.
- `SecretTripwire.detectAndBuild` (SecretTripwire.kt:164-171) returns `Map?` (an emit signal), never
  a block decision; its KDoc states the caller MUST proceed.
- Chat gate `ContextPreviewDialog.confirm` (ContextPreviewDialog.kt:60-115) returns `choice == 0`
  (Boolean). A tripwire match changes only the banner level + affirmative label ("Send anyway");
  Cancel stays `options[1]` as `initialValue`, so a match never auto-blocks and Enter never silently
  sends. The Boolean contract back to `ChatPanel.kt:302` is intact.

### WR-01 dot-joined pass — entropy math, ReDoS, false-positives: verified empirically

kotlinc was unavailable in-environment, so I ported the exact algorithm to a faithful Java
reimplementation and executed it directly:
- **Entropy math correct:** `shannon("0123456789abcdef") = 4.0`, constant string = 0.0, empty = 0.0
  — matches `EntropyTest`. The qualifying floor is `HEX_THRESHOLD = 3.0`; I confirmed the lowest
  entropy a qualifying token can have is exactly 3.0 (a 4-symbol token scores 2.0 and is rejected; an
  8-symbol even token scores 3.0 and qualifies). Therefore a genuine entropy match is ALWAYS `> 0.0`,
  making the WR-02 `> 0.0` guard (SecretTripwire.kt:112) mathematically exact: no real match is
  silently omitted, and no shape-only match ever falsely reports a score. The comment at
  SecretTripwire.kt:110-111 is accurate.
- **No ReDoS / perf cliff:** both splitters (`TOKEN_SPLIT`, `DOTTED_SPLIT`) are linear negated
  character classes with no backtracking. Pathological inputs — 100k `"a."`, 200k `"A"`, 270k mixed
  token chars, 300k `"ab."` — all completed in ≤ 28 ms. Two strictly-linear passes, O(n).
- **No false-positives on normal prose:** prose, version strings (`v1.2.3`, `10.15.7.20210101`), long
  dotted hostnames, dotted package paths, GPS coordinates, dotted filenames, GUIDs, and slashy URL
  paths all returned 0.0 — corroborating the four FP-guard tests (EntropyTest:111-147).
- **True positives recovered (the WR-01 goal):** a raw JWT body/signature and a dot-delimited
  base64url key now score ~4.9 bits/char where the old single pass returned 0.0.
- **One widened FP surface** (see WR-01 below): dotted hex octet runs that join to ≥ 32 hex chars now
  clear the 3.0 hex threshold. Non-blocking, non-leaking audit-only noise; consistent with the
  accepted `SecretShapes` "high-entropy hex key" disposition. WARNING, not blocker.

### AWT-free + single-source-of-truth + iteration-1 fix confirmation

- `Entropy.kt` and `SecretTripwire.kt` import no `java.awt.*` / `javax.swing.*` (grep confirmed).
- `SecretTripwire.scan` delegates the shape half to `SecretShapes.findSurviving` and the entropy half
  to `Entropy.maxQualifyingTokenEntropy`; neither is re-implemented. The interactive and
  non-interactive paths share one `scan` and one `buildAuditPayload`.
- **WR-03 confirmed resolved:** the four hand-duplicated emit blocks are gone; `PassiveAiScanner`
  (single-prompt path) and `McpToolContext` both route through `SecretTripwire.detectAndBuild`, and
  `ChatPanel` uses `buildAllowAuditPayload`. There is exactly one payload shape.
- **WR-02 confirmed resolved:** `entropyScore` is emitted only under the `> 0.0` guard; shape-only
  matches omit the key. Asserted by `SecretTripwireHooksTest:89-104` and `SecretTripwireGateTest:111-129`.
- **WR-01 confirmed resolved:** the additive dot-joined pass detects dot-delimited base64url secrets
  whose segments are individually below `MIN_TOKEN_LEN`; the four FP-guard tests pass.

## Warnings

### WR-01: Dot-joined entropy pass widens the dotted-hex false-positive surface

**File:** `src/main/kotlin/com/six2dez/burp/aiagent/redact/Entropy.kt:131-138`
**Issue:** The WR-01 second pass strips dots from a dotted candidate and gates the joined payload.
For the hex charset the threshold is only `HEX_THRESHOLD = 3.0`, evaluated after dots are removed, so
dotted runs of hex octets that individually fall below `MIN_TOKEN_LEN` but join to ≥ 32 hex chars now
qualify where the original single pass did not. Empirically (old single-pass vs. new two-pass):
- `ab.cd.ef.01.23.45.67.89.ab.cd.ef.01.23.45.67.89`  -> 4.000 (was 0.0) — NEW-only fire
- `a1b2c3d4.e5f6a7b8.c9d0e1f2.a3b4c5d6`               -> 3.906 (was 0.0) — NEW-only fire

These shapes occur in real traffic (MAC-like sequences, dot/colon-rendered fingerprints, chunked hex
digests). Each produces a spurious entropy-only `secret_tripwire_detect` audit event (empty
`shapeCategories`, a numeric score).

This is correctly NON-blocking and NON-leaking: the event carries only sessionId + an (empty)
category list + a numeric score, and every hook still proceeds with the send. It mirrors the
already-accepted noise disposition of the broad `SecretShapes` "high-entropy hex key" shape
(SecretShapes.kt:77-81). Per the iteration-2 directive, this is recorded as WARNING (not blocker)
because no leak, block, or crash results — matching the fixer's "warn-only, risk-acceptable" judgment.

**Fix (optional hardening, defer-acceptable — does NOT affect either invariant):** If dotted-hex
audit noise proves bothersome, restrict the dot-joined pass to the base64url case it was designed for
(JWT bodies / dot-delimited base64url keys), so pure-hex dotted runs do not newly qualify via this
pass — contiguous hex is already covered by the broad hex shape:
```kotlin
for (candidate in text.split(DOTTED_SPLIT)) {
    if (!candidate.contains('.')) continue
    val joined = candidate.replace(".", "")
    // Dotted recovery targets base64url secrets (JWT body/sig); a dotted run of pure
    // hex octets is benign noise the contiguous "high-entropy hex key" shape already covers.
    if (joined.all { it in HEX_CHARS }) continue
    val h = qualifyingEntropy(joined)
    if (h > max) max = h
}
```

## Info

### IN-01: `detectAndBuild` encodes the SC2 "proceed" guarantee by call-site convention, not in its type

**File:** `src/main/kotlin/com/six2dez/burp/aiagent/redact/SecretTripwire.kt:164-171`
**Issue:** `detectAndBuild` returns `Map?` where non-null means "emit." The never-block guarantee
(SC2) is enforced only by each caller writing `detectAndBuild(...)?.let { emitGlobal(...) }` and then
proceeding — it is not expressed in the signature. A future caller could misread a non-null return as
"block." The two current callers (PassiveAiScanner.kt:915, McpToolContext.kt:63) are correct and the
KDoc is explicit, so this is documentation-grade.
**Fix:** Consider renaming to `buildDetectEventOrNull` to make clear the return is an event payload,
not a decision. No behavioral change required.

### IN-02: SC3 score-format contract is inconsistent between the two test suites

**File:** `src/test/kotlin/.../SecretTripwireHooksTest.kt:118` vs `.../SecretTripwireGateTest.kt:195`
**Issue:** `truncatedScore` uses `"%.1f".format(Locale.ROOT, bitsPerChar)`, which would render a
negative as `-1.0`. Shannon entropy is non-negative and the qualifying floor is +3.0, so a negative
value is unreachable in practice — but the two suites disagree on the asserted contract:
`SecretTripwireHooksTest:118` asserts `\d+\.\d` (no sign) while `SecretTripwireGateTest:195` asserts
`-?\d+\.\d` (sign allowed). Harmless today; the divergence signals an unspecified contract.
**Fix:** Pick one. Since the domain is non-negative here, tighten both to `\d+\.\d` and (optionally)
document `truncatedScore`'s non-negative domain. No production change needed. (Carried over from
iteration-1 IN-03; the production `-0.0` normalization was applied, the test divergence remains.)

---

## Disposition of iteration-1 findings

- **WR-01** (entropy tokenizer dropped dot-delimited secrets) — RESOLVED by db30533 (additive
  dot-joined pass + 4 FP-guard tests). Residual dotted-hex FP surface re-filed as the WARNING above.
- **WR-02** (`entropyScore "0.0"` on shape-only matches) — RESOLVED by 134b716 (`> 0.0` guard;
  mathematically exact, verified).
- **WR-03** (four hand-duplicated emit sites) — RESOLVED by ad8167c (single builder + `detectAndBuild`).
- **IN-01** (stray `Entropy` imports from the bypassed helper) — RESOLVED as a consequence of WR-03.
- **IN-02** (`Short` status comparison foot-gun) — out of strict Phase 15 scope; not re-raised.
- **IN-03** (`-0.0` normalization + test regex) — production normalization applied; test divergence
  re-filed as IN-02 above.
- **IN-04** (ChatPanel re-scan after `confirm()`) — accepted as-is in iteration 1 (correct, cheap,
  same bytes); not re-raised.

---

_Reviewed: 2026-06-11T00:00:00Z_
_Reviewer: Claude (gsd-code-reviewer)_
_Depth: standard (iteration 2)_
