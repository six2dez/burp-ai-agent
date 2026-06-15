---
status: partial
phase: 16-external-mcp-client
source: [16-VERIFICATION.md, 16-06-PLAN.md]
started: 2026-06-15
updated: 2026-06-15
---

## Current Test

[awaiting human testing]

## Tests

### 1. SC1 — Connect to a real external MCP server (SSE + stdio)
expected: In the MCP settings, add a live SSE MCP server (URL + bearer token) and a live stdio MCP server (command). After save+connect, the server's tools appear in the agent's tool preamble namespaced as `ext:<server>:<tool>`, and invoking one returns a result wrapped in `[EXTERNAL-TOOL-RESULT:...]`. The audit log records the invocation. (stdio is off-by-default — enable it first; confirm the local-process warning shows.)
result: [pending]

### 2. SC5 — Load the fat JAR in a live Burp instance
expected: Build `./gradlew shadowJar` and load `build/libs/Custom-AI-Agent-full-*.jar` in a real Burp. The extension loads with no `NoClassDefFoundError`/`ClassNotFoundException` in Output/Errors (Path A — kotlin-sdk 0.5.0 client + ktor-client 3.1.3, no Kotlin runtime bump); the embedded MCP server still starts; the MCP Tools tab + new External Servers UI are responsive.
result: [pending]

### 3. SC4 (spot-check) — Bearer token never shown/leaked in UI
expected: An external server's saved bearer token is masked by default (show/hide toggle); at rest the stored value is `ENC1:`-prefixed (encrypted); the token never appears in Burp's Output/Errors logs.
result: [pending]

## Summary

total: 3
passed: 0
issues: 0
pending: 3
skipped: 0
blocked: 0

## Gaps
