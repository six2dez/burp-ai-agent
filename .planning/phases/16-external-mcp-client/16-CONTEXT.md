# Phase 16: External MCP Client - Context

**Gathered:** 2026-06-15
**Status:** Ready for planning
**Mode:** Smart discuss (autonomous) — 4 grey-area decisions captured from the user

<domain>
## Phase Boundary

Users can register external/custom MCP servers and the agent can call their tools. Scope:

- **CRUD UI** to add/edit/remove external MCP servers (name, transport, URL or command, auth token) in the MCP settings.
- **MCP client** (using the already-present `kotlin-sdk:0.5.0` client API) connecting OUT to external servers over **SSE** and **stdio** transports; list their tools; call their tools.
- External tools are **aggregated** alongside Burp's built-in tools in the agent's tool preamble, namespaced.
- **Trust boundary**: external tool RESULTS are wrapped in an explicit untrusted-output marker before entering the AI prompt context (prompt-injection defense); every external tool invocation + result summary is audit-logged.
- **Security reuse**: external server auth tokens encrypted at rest (Phase 12 `SecretCipher`); SSRF soft-warning on external SSE URLs (Phase 12 `SsrfGuard`); show/hide token toggle like other API key fields.

**Feasibility (RESOLVED — Path A):** NO Kotlin/Ktor bump. A compile spike proved `kotlin-sdk:0.5.0` (already a dependency for the embedded server) ships the full MCP client (`Client`, `SseClientTransport`, `StdioClientTransport`; Kotlin metadata `mv=[2,1,0]`) and compiles under the project's Kotlin 2.1.21. SC5's human-only Burp ClassLoader gate does NOT apply (it was only triggered by a Kotlin runtime bump).

</domain>

<decisions>
## Implementation Decisions

### Transports (user decision)
- Support **BOTH SSE and stdio** transports (ROADMAP SC1).
- **stdio is OFF by default** — gated behind the existing `McpSettings.stdioEnabled` flag plus a clear per-server warning that adding a stdio server runs a user-configured **local process** (arbitrary command execution). The user must deliberately enable it.

### SSE Connection Routing (user decision)
- Use a **direct ktor-client connection** via the SDK's `SseClientTransport` (add `ktor-client-core` + `ktor-client-cio` at 3.1.3). Do NOT route external MCP SSE through Burp's `MontoyaHttpTransport` for v1.
- Trade-off accepted: external MCP traffic will NOT appear in Burp's HTTP history; instead it is **SSRF-guarded on the URL** and **every tool call is audit-logged**. (Proxy-routing is a possible future enhancement — see Deferred.)

### Outbound Privacy (user decision)
- **Redact outbound tool-call arguments** sent to external MCP tools through the same redaction + pre-send tripwire pipeline as other outbound traffic. External MCP servers are third parties — the non-negotiable privacy core applies to data leaving Burp toward them.

### Tool Namespacing (user decision)
- **Always prefix** external tool names as `ext:<server>:<tool>` — unambiguously namespaced and visibly marked external/untrusted; no collisions with built-in Burp tools.

### Claude's Discretion
- Trust-boundary marker format for external results (e.g. an explicit `<untrusted_external_tool_output server="…">…</untrusted_external_tool_output>` wrapper) — implementer's choice, must be explicit and machine-distinguishable.
- Connection lifecycle/manager design (per-server scope vs shared `SupervisorJob`), reconnect/timeout policy — follow the research recommendation; bound timeouts consistent with other backends.
- Per-external-tool enable/disable — reuse the existing `toolToggles` pattern if low-cost.
- Connection-status surfacing in the MCP Tools tab vs log-only — implementer's choice; prefer surfacing status in the existing MCP Tools tab if cheap.
- schema migration version for the new encrypted external-token field — follow the Phase 12 migration ladder pattern.

</decisions>

<code_context>
## Existing Code Insights

### Reusable Assets
- `config/SecretCipher.kt` — AES-256-GCM encryption (Phase 12) for external-server auth tokens (SC4).
- `util/SsrfGuard.kt` — RFC-1918/link-local soft-warning (Phase 12) for external SSE URLs (SC3).
- `config/McpSettings.kt` — **already has `externalEnabled: Boolean` and `stdioEnabled: Boolean`** plus `toolToggles: Map<String,Boolean>` — prior groundwork; extend with the external-server list + encrypted tokens.
- `mcp/McpToolCatalog.kt`, `mcp/McpServerManager.kt`, `mcp/McpSupervisor.kt`, `mcp/KtorMcpServerManager.kt`, `mcp/tools/McpTools.kt` — existing embedded-server infra + tool registration seam (external tools aggregate here).
- `kotlin-sdk:0.5.0` client package `io.modelcontextprotocol.kotlin.sdk.client.*` — `Client`, `SseClientTransport`, `StdioClientTransport` (proven via compile spike).
- Redaction + tripwire pipeline (Phases 13/15) — apply to outbound tool-call args.

### Established Patterns
- Show/hide token toggle for API-key fields (used by all backend cards) — mirror for the external-server token field.
- Audit logging via `AuditLogger.logEvent(...)` gated by `audit.isEnabled()` (note Phase 18 CR-02 fix — keep allocations behind the gate).
- Backend timeout/CircuitBreaker conventions (Phase 17) — external MCP connections should carry bounded timeouts.

### Integration Points
- `build.gradle.kts`: add `io.ktor:ktor-client-core:3.1.3`, `io.ktor:ktor-client-cio:3.1.3`, and (explicit, transitive of stdio transport) `io.github.oshai:kotlin-logging-jvm:7.0.7`. NO Kotlin/Ktor bump.
- External tools join the agent tool preamble alongside built-in tools (McpToolCatalog / tool-registration seam).
- MCP settings UI (the MCP Tools tab / McpConfigPanel) gains the external-server CRUD list.

</code_context>

<specifics>
## Specific Ideas

- **Path A is mandatory** — pin `kotlin-sdk` at **0.5.0** (do NOT bump; 0.6.0+ pulls kotlin-stdlib 2.2.0+ which breaks Kotlin 2.1.21). The 3 new deps are at Ktor 3.1.3 to match the existing server pins.
- The plan's FIRST task should re-add + verify the 3 deps compile (`./gradlew compileKotlin`) — the spike already proved this, so it's a fast confirmation, not a risk.
- stdio transport = spawning a local process from user-supplied command/args/env — treat as a sensitive capability (off-by-default + warning). This is the phase's main new threat surface alongside external-tool prompt injection.

</specifics>

<deferred>
## Deferred Ideas

- Routing external MCP SSE traffic through Burp's proxy for HTTP-history visibility (chose direct ktor-client for v1; revisit if users want auditability in Burp).
- stdio command allowlist (chose off-by-default + warning instead; an allowlist could be a later hardening).
- WebSocket transport (`WebSocketClientTransport` exists in 0.5.0 but is out of scope — SSE + stdio only per SC1).

</deferred>
