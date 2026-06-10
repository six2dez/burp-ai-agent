---
status: partial
phase: 14-anthropic-backend-token-budget-listener-port
source: [14-VERIFICATION.md]
started: 2026-06-10T21:30:00Z
updated: 2026-06-10T21:30:00Z
---

## Current Test

[awaiting human testing in a running Burp instance with a live Anthropic API key]

## Tests

### 1. Anthropic streaming end-to-end (SC1)
expected: Settings > Backend > Anthropic, enter a real API key + model `claude-sonnet-4-6`, send a chat message → a reply arrives AND the request appears in Burp Proxy > HTTP history (to `api.anthropic.com/v1/messages`).
result: [pending]

### 2. Anthropic invalid-model error (SC3, live confirmation)
expected: set a bogus model ID, send a chat → the exact message "Anthropic rejected the model ID — check Settings > Anthropic > Model" appears (confirms the live 400 body contains "model").
result: [pending]

### 3. MCP listener-port filter, no-match (SC5, live)
expected: from a real MCP client, call `proxy_http_history` with a `listenerPort` that has no traffic → an empty result (not an error).
result: [pending]

### 4. Token-budget banner + scanner pause (SC4, visual + live)
expected: set a low warn threshold and hard cap; consume tokens via chat/scanner → amber WARN banner crosses to red RISK banner at the cap; the passive scanner stops enqueuing AI scans (and resumes when the cap is raised/cleared in Settings).
result: [pending]

## Summary

total: 4
passed: 0
issues: 0
pending: 4
skipped: 0
blocked: 0

## Gaps
