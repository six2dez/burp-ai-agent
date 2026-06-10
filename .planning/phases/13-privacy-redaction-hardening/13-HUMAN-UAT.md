---
status: partial
phase: 13-privacy-redaction-hardening
source: [13-VERIFICATION.md]
started: 2026-06-10T15:12:06Z
updated: 2026-06-10T15:12:06Z
---

## Current Test

[awaiting human testing in a running Burp instance]

## Tests

### 1. Privacy Settings — valid custom pattern accepted
expected: In Burp → AI Agent → Privacy settings, type `\bSECRET-\d{4}\b` in the custom-pattern text area and click Save. The feedback label shows success and the pattern persists across a settings reload.
result: [pending]

### 2. Privacy Settings — catastrophic pattern rejected (ReDoS guard)
expected: Type `(a+)+$` in the custom-pattern text area and click Save. An error feedback label appears (pattern rejected by the ReDoS guard) and the pattern is NOT persisted.
result: [pending]

### 3. ContextPreviewDialog — survived-secret WARN banner
expected: Trigger a Send whose post-redaction context still contains a surviving secret shape (e.g. an `sk-proj-…` form). The pre-send preview dialog shows a non-blocking amber WARN banner naming the shape category (never the raw value); the Send button stays enabled.
result: [pending]

## Summary

total: 3
passed: 0
issues: 0
pending: 3
skipped: 0
blocked: 0

## Gaps
