---
phase: 15-pre-send-secret-tripwire
fixed_at: 2026-06-11T09:20:48Z
review_path: .planning/phases/15-pre-send-secret-tripwire/15-REVIEW.md
iteration: 1
findings_in_scope: 3
fixed: 3
skipped: 0
status: all_fixed
---

# Phase 15: Code Review Fix Report

**Fixed at:** 2026-06-11T09:20:48Z
**Source review:** .planning/phases/15-pre-send-secret-tripwire/15-REVIEW.md
**Iteration:** 1

**Summary:**
- Findings in scope: 3 (Warnings; Info findings IN-01..04 out of scope under `critical_warning`)
- Fixed: 3
- Skipped: 0

All three Warnings were applied in the recommended root-cause-first order (WR-03 → WR-02 →
WR-01), each as an atomic commit. The full test suite is green after the changes: **448 tests,
0 failures, 0 errors** via `./gradlew test` (run in an isolated worktree). The load-bearing
security invariants are preserved: no path was made to block (SC2), and the audit payload still
carries only category names + sessionId + a numeric score — never the raw matched token (SC3).

## Fixed Issues

### WR-03: Four secret-tripwire emit sites hand-duplicated instead of using the helpers

**Files modified:** `src/main/kotlin/com/six2dez/burp/aiagent/redact/SecretTripwire.kt`,
`src/main/kotlin/com/six2dez/burp/aiagent/scanner/PassiveAiScanner.kt`,
`src/main/kotlin/com/six2dez/burp/aiagent/mcp/McpToolContext.kt`
**Commit:** ad8167c
**Applied fix:** Introduced a single private `SecretTripwire.buildAuditPayload(scan, path,
sessionId)` as the one source of truth for the SC3 payload shape; `buildAllowAuditPayload` and
`buildDetectAuditPayload` now delegate to it. Replaced the four hand-duplicated inline emit blocks
(`PassiveAiScanner` ×3 + `McpToolContext`) with `SecretTripwire.detectAndBuild(...) ?.let {
AuditLogger.emitGlobal("secret_tripwire_detect", it) }`, so the previously-dead helper is now the
only emit path. Dropped the now-unused `import ...redact.Entropy` from both files (this also
resolves IN-01 as a direct consequence — the direct `Entropy` coupling of those modules is gone).
This commit is behaviour-preserving: `entropyScore` was still emitted unconditionally here, so all
pre-existing tests continued to pass.

### WR-02: `entropyScore` emitted as a misleading `"0.0"` on shape-only matches

**Files modified:** `src/main/kotlin/com/six2dez/burp/aiagent/redact/SecretTripwire.kt`,
`src/test/kotlin/com/six2dez/burp/aiagent/redact/SecretTripwireHooksTest.kt`,
`src/test/kotlin/com/six2dez/burp/aiagent/redact/SecretTripwireGateTest.kt`
**Commit:** 134b716
**Applied fix:** With WR-03's single builder in place, this collapsed to one edit: `buildAuditPayload`
now emits the `entropyScore` key **only when `scan.maxEntropyBitsPerChar > 0.0`** (i.e. the entropy
half actually contributed). A shape-only match (e.g. an AWS `AKIA…` key, entropy 0.0) now **omits**
the key rather than recording a misleading `"0.0"` that a reader of `audit.jsonl` could not
distinguish from a real measurement. The no-leak invariant is unchanged (still only categories +
sessionId + a numeric score). Updated the two "contains required keys" tests (which used the
shape-only AWS token) to assert `entropyScore` is now **absent**, and added four targeted tests
pinning the new contract on both the detect and allow paths: omitted on a shape-only match, present
(and a one-decimal string) when entropy contributed.

### WR-01: Entropy tokenizer false-negative on dotted/base64url high-entropy tokens

**Files modified:** `src/main/kotlin/com/six2dez/burp/aiagent/redact/Entropy.kt`,
`src/test/kotlin/com/six2dez/burp/aiagent/redact/EntropyTest.kt`
**Commit:** db30533
**Status:** fixed — **requires human verification** (logic change to the detector's qualification path)
**Applied fix:** Adapted from the review's literal suggestion. The review proposed simply adding `.`
to the keep-set of `TOKEN_SPLIT` so dotted runs stay contiguous; on the actual code that change is
**inert**, because qualification uses a whole-token charset gate (`token.all { it in BASE64_CHARS }`)
and `.` is not a base64 char — so a contiguous `a.b.c` token would still fail the charset check and
report 0.0. Instead I added a strictly-additive **dot-joined second pass**: a new `DOTTED_SPLIT`
regex (`[^A-Za-z0-9+/=_.\-]+`, keeps `.` in-token) yields whole dotted candidates, and for any
candidate containing a `.` the dots-removed payload is run through the same length + charset +
entropy gate (refactored into a shared private `qualifyingEntropy(token)`). This recovers
dot-delimited base64url secrets (e.g. a raw JWT body/signature `aaaa.bbbb.cccc`) whose individual
segments are each below `MIN_TOKEN_LEN`. Entropy math and thresholds are unchanged (hex ≥ 3.0,
base64 ≥ 4.5, len ≥ 20). The pass can only raise the reported maximum, never suppress an existing
detection. Added six tests: the dotted-base64url true positive, an additive-regression check, and
four false-positive guards (IPv4 `192.168.100.200`, short hostname `www.example.com`, a long dotted
hostname `subdomain.example.organization.company.com` whose dots-removed length ≥ 20, and a long
dotted package path `com.example.service.controller.internal.handler`) — all four confirm natural
dotted prose stays below 4.5 bits/char and is NOT flagged.

**Why human verification is flagged:** This is a logic change to a security detector's qualification
path. Compile + tests confirm the cases enumerated above, but the false-positive judgment rests on
the base64 entropy threshold (4.5 bits/char on dots-removed payloads). A reviewer should confirm
that threshold is acceptable for their traffic corpus before the phase proceeds — the FP guards
cover the common dotted-identifier classes but cannot prove the absence of an unusual high-diversity
dotted identifier in real data.

## Verification

- Per-fix Tier 1 (re-read modified sections) + Tier 2 (compile + targeted `redact` test run) passed
  for all three commits.
- Final full-suite run after all three fixes: `./gradlew test` → **BUILD SUCCESSFUL**, 448 tests,
  0 failures, 0 errors (82 result files).
- `ktlintCheck` was intentionally NOT used per phase guidance (pre-existing standalone build defect
  in `generateBuildFlags` wiring); `./gradlew test` is the authoritative gate.
- Constraints honoured: zero new dependencies; English-only comments/code; `Entropy` and
  `SecretTripwire` remain AWT-free; no path was made to block (SC2); no-leak payload contract
  preserved (SC3); `truncatedScore` keeps `Locale.ROOT`; the chat `confirm()` Boolean +
  Cancel-default gate is untouched.

## Notes on out-of-scope Info findings

- **IN-01** (unused `Entropy` imports in `PassiveAiScanner` / `McpToolContext`) was resolved
  incidentally by WR-03, since routing through the helper removed the only `Entropy.truncatedScore`
  call sites — leaving the imports would have been dead imports.
- **IN-02, IN-03, IN-04** were not in scope (`fix_scope = critical_warning`) and were not touched.

---

_Fixed: 2026-06-11T09:20:48Z_
_Fixer: Claude (gsd-code-fixer)_
_Iteration: 1_
