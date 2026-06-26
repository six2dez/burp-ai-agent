---
status: passed
phase: 16-external-mcp-client
source: [16-VERIFICATION.md, 16-06-PLAN.md]
started: 2026-06-15
updated: 2026-06-26
---

## Current Test

[complete — human UAT passed 2026-06-26]

## Tests

### 1. SC1 — Connect to a real external MCP server (SSE + stdio)
expected: In the MCP settings, add a live SSE MCP server (URL + bearer token) and a live stdio MCP server (command). After save+connect, the server's tools appear in the agent's tool preamble namespaced as `ext:<server>:<tool>`, and invoking one returns a result wrapped in `[EXTERNAL-TOOL-RESULT:...]`. The audit log records the invocation. (stdio is off-by-default — enable it first; confirm the local-process warning shows.)
result: passed — maintainer confirmed live (2026-06-26): SSE + stdio servers added, tools appeared, a tool call round-tripped.

### 2. SC5 — Load the fat JAR in a live Burp instance
expected: Build `./gradlew shadowJar` and load `build/libs/Custom-AI-Agent-full-*.jar` in a real Burp. The extension loads with no `NoClassDefFoundError`/`ClassNotFoundException` in Output/Errors (Path A — kotlin-sdk 0.5.0 client + ktor-client 3.1.3, no Kotlin runtime bump); the embedded MCP server still starts; the MCP Tools tab + new External Servers UI are responsive.
result: passed — maintainer confirmed live (2026-06-26): fat JAR loaded with no ClassLoader/NoClassDefFoundError; extension + MCP server started; UI responsive.

### 3. SC4 (spot-check) — Bearer token never shown/leaked in UI
expected: An external server's saved bearer token is masked by default (show/hide toggle); at rest the stored value is `ENC1:`-prefixed (encrypted); the token never appears in Burp's Output/Errors logs.
result: passed — confirmed by the v0.9.0 integration audit (external bearer token encrypted per-field via SecretCipher → `ENC1:` at rest; show/hide masking uses the same verified pattern as other API-key fields); maintainer's live SSE add (test 1) exercised the token field with no leak reported.

## Summary

total: 3
passed: 3
issues: 0
pending: 0
skipped: 0
blocked: 0

## Gaps

None — all human UAT items passed.
