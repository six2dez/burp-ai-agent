---
phase: 15
plan: "02"
subsystem: ui-gate + redact-helpers + audit
tags: [priv-03, secret-tripwire, confirm-gate, audit-log, risk-banner]
dependency_graph:
  requires: ["15-01"]
  provides: ["15-03-scanner-mcp-hooks"]
  affects: ["ContextPreviewDialog.confirm()", "ChatPanel.startSessionFromContext"]
tech_stack:
  added: []
  patterns: ["pure-helper on existing object", "two-state banner collapse (FLAG-15-01)", "RESEARCH Open Q1 Option b (real session id)"]
key_files:
  created:
    - src/test/kotlin/com/six2dez/burp/aiagent/redact/SecretTripwireGateTest.kt
  modified:
    - src/main/kotlin/com/six2dez/burp/aiagent/redact/SecretTripwire.kt
    - src/main/kotlin/com/six2dez/burp/aiagent/ui/components/ContextPreviewDialog.kt
    - src/main/kotlin/com/six2dez/burp/aiagent/ui/ChatPanel.kt
decisions:
  - "[15-02]: GateDecision data class + gateDecision() + buildAllowAuditPayload() added to SecretTripwire object (AWT-free, testable headless) — keeps confirm() pure-Boolean (G3 / FLAG-15-03)"
  - "[15-02]: Two-state clean/RISK banner collapse adopted (FLAG-15-01) — WARN advisory branch dropped; every SecretTripwire.scan().matched == true goes straight to Level.RISK"
  - "[15-02]: Audit emit placed in ChatPanel.startSessionFromContext after createSession (RESEARCH Open Q1 Option b) — carries real session.id; confirm() stays UI-only with no double-logging"
  - "[15-02]: options[1] (Cancel) remains showOptionDialog initialValue — default focus never the affirmative (G5 / Pitfall 5)"
metrics:
  duration: "~25 min"
  completed: "2026-06-11"
  tasks: 3
  files: 4
---

# Phase 15 Plan 02: Interactive Confirm Gate + Allowlist Audit Summary

**One-liner:** Tripwire RISK banner + "Send anyway"/Cancel gate in ContextPreviewDialog with Boolean-preserving Boolean return and post-createSession audit emit in ChatPanel carrying real session id.

## What Was Built

Three TDD-gated tasks wiring the Phase 15-01 `SecretTripwire` detector into the interactive send path:

**Task 1 (RED test):** Created `SecretTripwireGateTest.kt` — pure headless tests (no Swing) for the gate-decision contract (SC5) and the allow-payload builder (SC3). Tests failed RED pending the helpers.

**Task 2 (GREEN — helpers + dialog):** Added `GateDecision` data class, `gateDecision(scan)`, and `buildAllowAuditPayload(scan, sessionId)` to `SecretTripwire` (AWT-free, in the `redact` package, unit-testable). Updated `ContextPreviewDialog.confirm()`:
- Replaced `SecretShapes.findSurviving` self-scan with `SecretTripwire.scan(contextJson)`.
- Two-state banner: `hideNotice()` on clean; `setMessage(Level.RISK, html)` on match (named-shape or high-entropy variant per UI-SPEC Delta 1).
- Relabeled affirmative via `gate.affirmativeLabel` = "Send anyway" when matched, "Send" when clean (UI-SPEC Delta 2).
- `options[1]` (Cancel) remains the `showOptionDialog` `initialValue` — default focus never affirmative (G5).
- `confirm()` still returns `Boolean`; its single caller `ChatPanel.kt:299` is unchanged (G3 / FLAG-15-03).
- `SecretTripwireGateTest` went GREEN.

**Task 3 (GREEN — audit emit):** Added `secret_tripwire_allow` audit emit in `ChatPanel.startSessionFromContext` immediately after `createSession(title)`, so the event carries the real `session.id` (RESEARCH Open Q1 Option b / G3). Re-scans `capture.contextJson` (same final post-redaction bytes; cheap). Payload is `SecretTripwire.buildAllowAuditPayload(scan, session.id)` — `path:"chat"`, `sessionId`, sorted `shapeCategories`, `entropyScore` (one-decimal) — raw token never present (SC3 / G4). Emit happens only when `scan.matched`, only once (not in `confirm()` to avoid double-logging). Full test suite green.

## Deviations from Plan

None — plan executed exactly as written.

- Phase 13 WARN advisory branch dropped per FLAG-15-01 (two-state collapse). This is an explicitly permitted simplification in the plan, not a deviation.
- Audit emit placed at ChatPanel call site (RESEARCH Open Q1 Option b) — this was the plan's recommended option.

## TDD Gate Compliance

| Gate | Commit | Status |
|------|--------|--------|
| RED — `test(15-02)` | 19bc9b2 | Pass — compile error on `gateDecision` / `buildAllowAuditPayload` (unresolved reference) |
| GREEN — `feat(15-02)` gate | 62564a6 | Pass — SecretTripwireGateTest GREEN after helpers + dialog |
| GREEN — `feat(15-02)` audit | aa08fac | Pass — full suite green after ChatPanel emit |

## Commits

| Hash | Type | Description |
|------|------|-------------|
| 19bc9b2 | test | add failing gate-decision + allow-payload tests (RED) |
| 62564a6 | feat | tripwire RISK gate in ContextPreviewDialog (Boolean-preserving) |
| aa08fac | feat | audit-log tripwire allowlist with real session id (SC3) |

## Self-Check

### Files exist
- [x] `src/test/kotlin/com/six2dez/burp/aiagent/redact/SecretTripwireGateTest.kt`
- [x] `src/main/kotlin/com/six2dez/burp/aiagent/redact/SecretTripwire.kt` (updated)
- [x] `src/main/kotlin/com/six2dez/burp/aiagent/ui/components/ContextPreviewDialog.kt` (updated)
- [x] `src/main/kotlin/com/six2dez/burp/aiagent/ui/ChatPanel.kt` (updated)

### Commits exist
- [x] 19bc9b2 in git log
- [x] 62564a6 in git log
- [x] aa08fac in git log

### Verification criteria
- [x] `./gradlew test --tests "*SecretTripwireGateTest"` green (SC5 gate: RISK+label+Cancel-default when matched; SC3 allow-payload shape + no-leak)
- [x] `./gradlew test` full suite green
- [x] `ContextPreviewDialog.kt` contains `SecretTripwire.scan`, `Level.RISK`, `"Send anyway"`, `options[1]` as `showOptionDialog` `initialValue`
- [x] `ChatPanel.kt` emits `secret_tripwire_allow` exactly once, after `createSession`
- [x] `confirm()` returns `Boolean`; ChatPanel.kt:299 single caller signature unchanged

## Known Stubs

None — all wiring is live. The dialog gate, banner, and audit emit are fully connected.

## Threat Flags

None — no new network endpoints, auth paths, file access patterns, or schema changes introduced. The audit emit path (`AuditLogger.emitGlobal`) was pre-existing; payload carries only category names, a numeric score, and a session id (no secrets). Threat register T-15-04/05/06/07/08 mitigations confirmed implemented.

## Self-Check: PASSED
