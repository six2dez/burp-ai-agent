---
status: partial
phase: 15-pre-send-secret-tripwire
source: [15-VERIFICATION.md]
started: 2026-06-11T00:00:00Z
updated: 2026-06-11T00:00:00Z
---

## Current Test

[awaiting human testing in a running Burp instance]

## Tests

### 1. Pre-send tripwire dialog render (SC5)
expected: In live Burp, send a ChatPanel request whose post-redaction context still contains a surviving `AKIA…` (or high-entropy) value. The context-preview dialog shows a red RISK banner naming the shape category (never the raw value); the affirmative button reads "Send anyway"; Cancel has default Enter focus; Cancel aborts the send; "Send anyway" proceeds and writes a `secret_tripwire_allow` event to `audit.jsonl` with the session ID + category names + truncated entropy score (no raw key).
result: [pending]

## Summary

total: 1
passed: 0
issues: 0
pending: 1
skipped: 0
blocked: 0

## Gaps
