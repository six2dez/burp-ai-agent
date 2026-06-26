---
status: passed
phase: 19-mega-file-split-docs
source: [19-VERIFICATION.md]
started: 2026-06-26
updated: 2026-06-26
---

## Current Test

[complete — human UAT passed 2026-06-26]

## Tests

### 1. Public docs site renders the two new v0.9.0 pages (SC5)
expected: After the v0.9.0 docs reach the live site, `burp-ai-agent.six2dez.com` shows the Anthropic backend page and the External MCP servers page, correctly rendered.
result: passed — verified live 2026-06-26.
  NOTE / corrected assumption: the live docs site is built from the SEPARATE GitBook repo
  `github.com/six2dez/burp-ai-agent-docs` (local `~/Tools/burp-ai-agent-doc`), NOT this repo's `docs/`
  folder. The pages were authored there (`backends/anthropic.md`, `mcp/external-servers.md`), registered in
  `SUMMARY.md`, committed (3256cc9), and pushed. Both render live:
  - https://burp-ai-agent.six2dez.com/backends/anthropic — "Anthropic (API)"
  - https://burp-ai-agent.six2dez.com/mcp-server/external-servers — "External MCP Servers"

## Summary

total: 1
passed: 1
issues: 0
pending: 0
skipped: 0
blocked: 0

## Gaps

None — SC5 confirmed live.
