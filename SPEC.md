# Burp AI Agent — Specification

This is the living specification of the plugin as of v0.9.0. Documentation for end users lives at [burp-ai-agent.six2dez.com](https://burp-ai-agent.six2dez.com); this file captures the contract the code is held to.

## 1. Goal

Ship a production-grade Burp Suite extension (Kotlin + Montoya API) that embeds an AI reasoning agent with pluggable backends, enforces privacy redaction on anything leaving the plugin, records an auditable history, and exposes Burp operations to external AI agents over MCP.

## 2. Non-goals

- No "demo-only" shortcuts that bypass privacy or audit controls.
- No data exfiltration when privacy mode is `STRICT` or `BALANCED`.
- No hot-swapping of backends at runtime (stopping and restarting the backend is acceptable).
- Not a replacement for Burp's native scanner; the AI scanner is complementary and always secondary to Burp's own evidence.

## 3. Constraints

- **Burp editions**: Community and Professional.
- **OS**: macOS, Linux, Windows.
- **Language**: Kotlin (JVM 21), Gradle Kotlin DSL.
- **License**: MIT.
- **Priority**: reasoning quality first, privacy controls mandatory, determinism optional.

## 4. Core features

### 4.1 Burp tab UI

- Primary Burp tab named `Custom AI Agent`.
- Embedded chat-like UI with streaming responses, multi-session transcripts, project-scoped session persistence, attach/detach context.
- Start/stop/restart of backend from the header controls.
- Privacy mode pill visible at all times.

### 4.2 Context menu actions

Right-click actions are registered on:

- Proxy HTTP History items.
- Repeater tabs.
- Site Map nodes (individual requests and directory/root nodes).
- Scanner Issues (Burp Pro only).

Actions include: attach to active or new session, quick prompts (request summary, issue analysis, PoC generation, impact estimation), 403 bypass test, custom targeted tests across 55+ vuln classes, "Extract JS endpoints".

Multiple selections are attached as a single structured payload. Site Map tree nodes that resolve to many requests are labelled so the operator knows the scope (e.g. `Analyze this request (site map - 17)`).

### 4.3 Context schema

A canonical JSON envelope is used for all captures:

- HTTP items (request + response, method, URL, headers, body, timing).
- Scanner issues (name, severity, confidence, evidence).
- Schema-versioned and stable-ordered in determinism mode so the same capture hashes identically.

### 4.4 Pluggable AI backends

Backends supported out of the box:

- **HTTP**: Ollama, LM Studio, NVIDIA NIM, Perplexity, generic OpenAI-compatible, Burp native AI.
- **Cloud API**: Anthropic (native Messages API via `MontoyaHttpTransport`; see [docs/anthropic-backend.md](docs/anthropic-backend.md)).
- **CLI**: Claude CLI, Gemini CLI, Codex CLI, OpenCode CLI, Copilot CLI.

Backends implement `AgentBackend` and are discovered via `ServiceLoader`. External JARs dropped into `~/.burp-ai-agent/backends/` are loaded on startup.

All stored API keys and tokens are encrypted at rest with AES-256-GCM via `javax.crypto` (per-install random master key). No secret is written to logs or exports in plaintext.

### 4.5 Agent lifecycle supervision

`AgentSupervisor` launches CLI backends, captures stdout/stderr, supervises their lifecycle, and restarts them with exponential backoff on crash. `McpSupervisor` does the equivalent for the MCP server. Both are shut down deterministically when the extension unloads.

### 4.6 Embedded + external terminal

The embedded UI is the primary surface. Users can optionally launch an external terminal process from Settings (used to start a CLI backend interactively). Both routes share session IDs and audit logs.

### 4.7 Privacy / redaction modes

Three modes, all applied pre-flight (before anything leaves the plugin) and re-applied on every MCP tool output:

| Mode       | Cookies | Auth headers / Bearer / JWT / Basic / URL tokens | Hosts | Body fields | Custom patterns |
|------------|---------|---------------------------------------------------|-------|-------------|-----------------|
| `STRICT`   | stripped | redacted                                        | anonymized (HKDF/HmacSHA256) | redacted | redacted |
| `BALANCED` | stripped | redacted                                        | kept  | redacted | redacted |
| `OFF`      | kept    | kept                                             | kept  | kept | not applied |

Default mode for new users: `BALANCED`. Every right-click capture opens a preview dialog showing the redacted JSON before it is sent.

STRICT mode host anonymization uses real HKDF (HMAC-SHA256 extract/expand per RFC 5869). Request and response bodies are redacted for leading fields in `application/x-www-form-urlencoded` payloads. Users can add custom redaction patterns (validated against ReDoS before save) in **Settings > Privacy > Custom Patterns**.

A pre-send secret tripwire (PRIV-03) scans the final redacted payload for high-entropy values before dispatch and prompts for confirmation if any are detected. Allowlist decisions are audit-logged.

### 4.8 Audit logging

- Append-only JSONL at `~/.burp-ai-agent/logs/audit.jsonl`, rotated by size.
- Entries carry trace IDs, backend ID, model, prompt hash (SHA-256), response hash, privacy mode, and timings.
- Repro bundle export (ZIP) captures transcript + hashes + settings for a chosen session.
- Disabled by default; enabled in Settings.

## 5. Scanners

### 5.1 Passive AI scanner

- Analyzes proxy traffic in background, on a configurable rate limit.
- In-scope only by default.
- Content-type filter (HTML, JSON, XML, JS, text) and configurable max response size.
- LRU deduplication on endpoint and response fingerprint.
- Batch mode groups 3–5 requests per AI call (60–70% fewer calls).
- Persistent prompt cache at `~/.burp-ai-agent/cache/` survives Burp restarts (TTL 1–168 h, disk-LRU).
- Issues are created only when confidence ≥ 85, prefixed with `[AI Passive]` and carry byte-range markers in the evidence view.
- Respects user privacy mode; prompts instruct the model to treat captured traffic as untrusted data, not instructions.

### 5.2 Active AI scanner

- Integrated with Burp's native active scanner via `ScanCheck` registration (Pro only).
- Generates payloads from a static catalogue (200+ payloads for 62 vuln classes) and adaptively via the AI (`AdaptivePayloadEngine`), with a destructive-pattern filter.
- Risk-level filter: `SAFE` / `CAUTIOUS` / `AGGRESSIVE`.
- Backpressure queue (default 2000 max).
- 403 Bypass testing: 3 techniques (IP spoofing headers, path manipulation, HTTP method switching).
- Findings link back to the passive scanner's knowledge base for cross-scanner reasoning.

## 6. MCP integration

- Built-in MCP server over SSE on `127.0.0.1:9876` by default.
- Optional stdio bridge for MCP clients that cannot speak SSE.
- 59 tools (full build), split into safe read-only (`status`, `proxy_http_history`, `site_map`, `scope_check`, `params_extract`, `find_reflected`, `scanner_issues`, `collaborator_status`, …) and unsafe mutating (`http1_request`, `http2_request`, `repeater_tab`, `intruder`, `collaborator_*`, `issue_create`), gated behind an Unsafe Mode master switch.
- External access requires an explicit opt-in, a bearer token on every request, and (optionally) TLS using a keystore whose password is stored in Burp preferences (see `docs/mcp-hardening.md`).
- **External MCP client (CAP-02)**: register external or custom MCP servers in **Settings > MCP > External Servers** over SSE or stdio transports. External server auth tokens are stored encrypted. Tool outputs from external servers are wrapped in a trust-boundary marker before entering the AI prompt to prevent prompt injection. See [docs/external-mcp-servers.md](docs/external-mcp-servers.md).

## 7. Token-budget guardrails (CAP-04)

`BudgetGuard` provides per-session token-spend limits for the passive scanner:

- **OFF**: no limit (default).
- **WARN**: advisory warning banner in the UI when the warn threshold is reached.
- **CAP**: passive scanner pauses automatically at the hard cap; resumes when the cap is raised or cleared.

Both thresholds are user-configurable in **Settings > Passive Scanner > Token Budget**. Values of `0` mean unlimited. State is per-session and does not persist across Burp restarts.

## 8. Determinism mode

When enabled:

- Stable prompt templates.
- Stable context ordering.
- Backend temperature clamped to 0 where supported.
- Prompt bundle hashes reproduce exactly given the same inputs.

## 9. Security model

- Local-only by default (`127.0.0.1`).
- No background exfiltration: the extension never sends traffic to any LLM unless a user action or an enabled scanner triggers it.
- Context preview dialog shows the exact redacted JSON before any auto-captured context leaves the plugin.
- MCP server protected by bearer token + optional TLS; unsafe tools gated by a separate master switch.
- All stored secrets (API keys, MCP bearer token, TLS keystore password) encrypted at rest with AES-256-GCM.
- Privacy defaults and enforcement documented in `SECURITY.md` and `docs/mcp-hardening.md`.

## 10. Acceptance tests

- Build produces a single fat JAR (`./gradlew shadowJar`).
- Plugin loads in Burp Community and Pro; the `Custom AI Agent` tab is visible.
- Context menu actions appear on Proxy, Repeater, Site Map, Intruder, and Scanner Issues.
- Redaction transforms are covered by unit tests (`RedactionTest`).
- Privacy preview dialog appears for auto-captured context in both `BALANCED` and `OFF` modes.
- Audit log writes JSONL without crashing Burp.
- MCP `health` endpoint returns `200` and rejects requests missing the bearer token.
- Passive scanner skips AI analysis for JS responses, extracts endpoints instead.

## 11. Historical milestones

All four delivered and shipped as of v0.5.0:

- **M1**: UI + context attach + audit logging.
- **M2**: backend plugins + supervisor.
- **M3**: redaction preview + determinism mode.
- **M4**: MCP integration path.
