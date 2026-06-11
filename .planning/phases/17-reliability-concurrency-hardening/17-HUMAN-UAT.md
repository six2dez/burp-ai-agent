---
status: partial
phase: 17-reliability-concurrency-hardening
source: [17-VERIFICATION.md]
started: 2026-06-11T12:00:00Z
updated: 2026-06-11T12:00:00Z
---

## Current Test

[awaiting human testing on a fresh machine with a running Burp]

## Tests

### 1. Issue #71 — CLI command timeout, actionable + configurable (REL-04/SC4)
expected: On a machine where `@google/gemini-cli` is NOT cached, configure the CLI backend and run `npx @google/gemini-cli --output-format text --model gemini-2.5-flash --yolo`. If the first-run download exceeds the timeout, the error message is actionable — it names the configured limit and suggests increasing `cliTimeoutSeconds` (Settings) or pre-installing the CLI. Raising `cliTimeoutSeconds` then lets the command complete. (Automated regression: CliTimeoutMessageTest.)
result: [pending]

## Summary

total: 1
passed: 0
issues: 0
pending: 1
skipped: 0
blocked: 0

## Gaps
