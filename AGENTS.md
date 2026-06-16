# Burp AI Agent Extension (Kotlin) — Codex Instructions

## Non-negotiables
- All explanations and comments MUST be in English.
- All code MUST be in English.
- Kotlin + Gradle Kotlin DSL.
- Burp Montoya API.
- Target: Burp Community + Pro, cross-platform (macOS/Linux/Windows).
- Production-grade: stable, defensive coding, deterministic modes, audit logging.

## Architecture constraints
- Keep a strict boundary between:
  1) UI (Swing)
  2) Context collection (Burp selections)
  3) Redaction pipeline (privacy modes)
  4) Backend adapters (pluggable)
  5) Supervisor (start/stop/restart)
  6) Audit logging (JSONL + hashes)
  7) Passive AI Scanner (background traffic analysis)
- New backends must be addable without refactoring core logic (ServiceLoader).

## Features required
- Burp tab UI
- Context menu actions for:
  - Requests/responses
  - Repeater tabs
  - Scanner findings (Pro)
- Backends at launch:
  - Codex CLI
  - Gemini CLI
  - Claude CLI
  - Copilot CLI
  - OpenCode CLI
  - Ollama (local)
  - LM Studio (local)
  - NVIDIA NIM
  - Perplexity
  - Generic OpenAI-compatible
  - Anthropic (native Messages API, not a CLI wrapper)
  - Burp native AI
- Supervision of external agents (launch/restart/stop)
- Embedded UI + optional external terminal spawning
- Privacy modes: cookie stripping, token redaction, host anonymization
- Audit/session logs + reproducible prompt bundles
- AI Passive Scanner for automatic traffic analysis

## MCP integration
- Built-in MCP server (SSE + optional stdio)
- Prefer designs that allow integration with Burp MCP tools.
- Do not leak raw traffic outside Burp when privacy mode is enabled.
- MCP tools include: issue_create for programmatic issue creation

## AI Passive Scanner
- Background analysis of proxy traffic using selected AI backend
- Automatic issue creation when confidence >= 85%
- Configurable: rate limit, in-scope only, max size
- Issues prefixed with [AI] for identification

## Quality bar
- Use small, testable components
- Favor pure functions for redaction
- Add unit tests where feasible
- No demo-only shortcuts
