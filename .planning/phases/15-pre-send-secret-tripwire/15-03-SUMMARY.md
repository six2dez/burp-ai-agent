---
phase: 15-pre-send-secret-tripwire
plan: "03"
subsystem: security
tags: [secret-detection, entropy, audit, tripwire, priv-03, passive-scanner, mcp]

requires:
  - phase: 15-pre-send-secret-tripwire/15-01
    provides: SecretTripwire.scan + Entropy helpers (AWT-free detector)
  - phase: 15-pre-send-secret-tripwire/15-02
    provides: interactive chat gate + buildAllowAuditPayload on SecretTripwire

provides:
  - "buildDetectAuditPayload(scan, path, sessionId) on SecretTripwire — SC3 no-leak payload builder"
  - "detectAndBuild(payload, path, sessionId) on SecretTripwire — convenience null-returns-on-no-match helper"
  - "Tripwire detect+audit+proceed hooks at all three PassiveAiScanner supervisor.send sites (SC4 / G7)"
  - "Tripwire detect+audit+proceed hook inside McpToolContext.redactIfNeeded (SC4)"
  - "SecretTripwireHooksTest — per-path detect-payload + no-leak + proceed assertions"

affects: [15-04-verify, phase-19-qual-01-split, mcp-egress, passive-scanner-egress]

tech-stack:
  added: []
  patterns:
    - "detect-audit-proceed: non-interactive outbound hooks scan FINAL post-redaction payload, emitGlobal on match, never block"
    - "buildDetectAuditPayload: shared SC3 payload builder (path + sessionId + shapeCategories + entropyScore, never raw token)"
    - "detectAndBuild: null-returning convenience wrapper for hook bodies (null = no emit, non-null = emit)"

key-files:
  created:
    - src/test/kotlin/com/six2dez/burp/aiagent/redact/SecretTripwireHooksTest.kt
  modified:
    - src/main/kotlin/com/six2dez/burp/aiagent/redact/SecretTripwire.kt
    - src/main/kotlin/com/six2dez/burp/aiagent/scanner/PassiveAiScanner.kt
    - src/main/kotlin/com/six2dez/burp/aiagent/mcp/McpToolContext.kt

key-decisions:
  - "TDD: wrote SecretTripwireHooksTest (RED compile-fail) before adding buildDetectAuditPayload/detectAndBuild to SecretTripwire"
  - "All three scanner hooks use named local vars (tw1/tw2/tw3) for clarity — all identical emitGlobal shape"
  - "McpToolContext.redactIfNeeded rewritten with finalText val to make the two branches explicit before scanning"
  - "detectAndBuild convenience helper returns null on no-match (hook bodies can be one-liners without if-nesting)"
  - "highEntropyB64 test token corrected: 48-distinct-char base64 token (entropy ~5.6 bpc) replaces the low-entropy base64-of-ASCII token"

patterns-established:
  - "Non-interactive tripwire hooks: scan(final_prompt); if matched { emitGlobal(...) }; supervisor.send — never block"
  - "Null-safe sessionId: supervisor?.currentSessionId() ?: 'none' on nullable supervisor (MCP), supervisor.currentSessionId() ?: 'none' on non-null (scanner)"

requirements-completed: [PRIV-03]

duration: 6min
completed: "2026-06-11"
---

# Phase 15 Plan 03: Pre-Send Tripwire — Non-Interactive Hooks Summary

**Post-redaction secret tripwire wired to all three PassiveAiScanner send sites and McpToolContext.redactIfNeeded: detect + AuditLogger.emitGlobal + proceed (never block) with SC3 no-leak payload (path, sessionId, shapeCategories, entropyScore)**

## Performance

- **Duration:** ~6 min
- **Started:** 2026-06-11T10:17:39Z
- **Completed:** 2026-06-11T10:23:42Z
- **Tasks:** 3 (TDD: RED commit + GREEN commit per task)
- **Files modified:** 4

## Accomplishments

- Added `buildDetectAuditPayload` and `detectAndBuild` helpers to `SecretTripwire` (SC3 no-leak payload; null sessionId falls back to "none")
- Hooked all three `PassiveAiScanner` `supervisor.send` sites (single L911, batch L1561, `sendSingleAnalysis` L1647): scan FINAL post-redaction `singlePrompt`/`prompt` (G1), emitGlobal on match, fall through — never block (SC2, G7)
- Rewrote `McpToolContext.redactIfNeeded` to extract a `finalText` val, scan it, emitGlobal on match with null-safe `supervisor?.currentSessionId() ?: "none"`, return `finalText` (SC2)
- `SecretTripwireHooksTest` (11 tests) covers payload shape, sessionId "none" fallback, no-leak, and emit-only-on-match for both paths — full suite GREEN

## Task Commits

1. **Task 1: SecretTripwireHooksTest (RED)** - `9466699` (test)
2. **Task 2: PassiveAiScanner 3 hooks + SecretTripwire helpers** - `f76d37d` (feat)
3. **Task 3: McpToolContext.redactIfNeeded hook** - `d9f6694` (feat)

## Files Created/Modified

- `src/test/kotlin/com/six2dez/burp/aiagent/redact/SecretTripwireHooksTest.kt` — 11 unit tests; RED→GREEN via TDD
- `src/main/kotlin/com/six2dez/burp/aiagent/redact/SecretTripwire.kt` — added `buildDetectAuditPayload` + `detectAndBuild` helpers
- `src/main/kotlin/com/six2dez/burp/aiagent/scanner/PassiveAiScanner.kt` — 3 detect+emitGlobal+proceed hooks before each supervisor.send
- `src/main/kotlin/com/six2dez/burp/aiagent/mcp/McpToolContext.kt` — `redactIfNeeded` rewritten with finalText + scan + emitGlobal + return

## Decisions Made

- Used named variables `tw1`/`tw2`/`tw3` in scanner hooks (same shape, distinguishable in a single large file).
- Used the static `AuditLogger.emitGlobal` throughout (no constructor surgery, consistent with `McpTool.kt:226` precedent, RESEARCH A3).
- `detectAndBuild` returns `null` on no-match, making hook bodies read clearly without nested if-blocks.
- Fixed the test's `highEntropyB64` token: replaced the base64-of-ASCII constant (low entropy) with 48-distinct-char base64 token (entropy ~5.6 bpc, well above 4.5 threshold).

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] Test high-entropy token had insufficient entropy**
- **Found during:** Task 2 (GREEN verification run)
- **Issue:** `"dGVzdFNlY3JldEtleVN0cmluZ0hpZ2g="` is base64 of ASCII text — low character diversity → entropy < 4.5, causing one `detectAndBuild` test to fail even after implementation was correct.
- **Fix:** Replaced with `"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuv"` (48 distinct base64 chars; same token used by the passing `EntropyTest.longBase64TokenClearsBase64Threshold`).
- **Files modified:** `SecretTripwireHooksTest.kt`
- **Verification:** `./gradlew test --tests "*SecretTripwireHooksTest"` 11/11 passed after fix.
- **Committed in:** `f76d37d` (Task 2 commit)

---

**Total deviations:** 1 auto-fixed (Rule 1 bug — test data)
**Impact on plan:** Minimal. Test intent unchanged; only the token literal was wrong. No scope creep.

## Issues Encountered

None beyond the test-token fix above.

## User Setup Required

None — no external service configuration required.

## Next Phase Readiness

- Phase 15 (PRIV-03) is complete: tripwire fires (detect + audit) on all three outbound paths; interactive path (15-02) shows the gate; non-interactive paths (15-03) log and proceed.
- `grep -c secret_tripwire_detect PassiveAiScanner.kt == 3` verified; all three hooks committed in Phase 15 for Phase 19 (QUAL-01 mega-file split) to carry along (G7).
- Phase 15 ready for `/gsd-verify-work` smoke test (manual Burp smoke: SC5 dialog render is the remaining UAT item; automated SC1–SC4 are fully covered).

## Threat Flags

None — all new surface was covered by the existing `<threat_model>` in 15-03-PLAN.md (T-15-09 through T-15-SC). No new network endpoints, auth paths, or schema changes introduced.

## Known Stubs

None — all three hook points are live (not guarded by TODO or feature flag). The `AuditLogger.emitGlobal` is registered in `App.kt:68`; events flow to `audit.jsonl` when audit is enabled.

## Self-Check

- [x] `src/test/kotlin/com/six2dez/burp/aiagent/redact/SecretTripwireHooksTest.kt` exists
- [x] `class SecretTripwireHooksTest` present in file
- [x] Commits `9466699`, `f76d37d`, `d9f6694` verified in git log
- [x] `grep -c secret_tripwire_detect PassiveAiScanner.kt` == 3
- [x] `secret_tripwire_detect` present in `McpToolContext.kt`
- [x] `supervisor?.currentSessionId` present in `McpToolContext.kt`
- [x] `./gradlew test` full suite GREEN

## Self-Check: PASSED

---
*Phase: 15-pre-send-secret-tripwire*
*Completed: 2026-06-11*
