# Phase 07: Proxy Transport + MCP Scope Hardening - Context

**Gathered:** 2026-05-27
**Status:** Ready for planning
**Source:** In-session triage of GitHub issue #69 (filed 2026-05-27)

<domain>
## Phase Boundary

Close GitHub issue #69. Four reporter sub-concerns, three of which are bugs (transport, body cap, scope) and one is a behavioural improvement (small-model context defaults).

In scope:
- The HTTP transport layer used by HTTP-based AI backends (OpenAI-compatible, Perplexity, NVIDIA NIM, LM Studio, Ollama HTTP) — both `healthCheck()` and `send()` paths.
- The chat-context construction in `ContextCollector` and the MCP body-cap UI in `SettingsPanel`.
- The MCP server's tool dispatch and per-tool scope handling.

Out of scope:
- The CLI backend path (Claude/Gemini/Codex/Copilot CLI) — those do not use HTTP transport at all.
- Any change to Burp's own proxy config or scope rules — we read them, we do not own them.
- New MCP tools (this is hardening of existing ones, not capability expansion).
- Re-architecting the OkHttp fallback for non-Burp environments (we still keep it for unit tests; we just stop reaching it from production).

</domain>

<decisions>
## Implementation Decisions

### BUG-69-01 — Transport unification (sub-concerns 1 + 2)

- Health checks for every HTTP-based backend MUST go through `MontoyaHttpTransport` when a `MontoyaApi` is available. Today they all go through `HttpBackendSupport.healthCheckGet()` which uses OkHttp — that bypasses Burp's upstream proxy / SOCKS / cert store, which is exactly the bug the reporter hit.
- Add `MontoyaHttpTransport.get(url, headers, timeoutMs): TransportResponse` mirroring the existing `post()` method (line 65-76 of `MontoyaHttpTransport.kt`).
- In `OpenAiCompatibleBackend.healthCheck()` (lines 81-98), branch on `transport != null`: if non-null, call `transport.get(buildModelsUrl(baseUrl), headers, timeoutMs)`. Else fall back to `HttpBackendSupport.healthCheckGet()` for non-Burp environments (unit tests).
- Same change in `LmStudioBackend.healthCheck()` (lines 54-68).
- Remove the OkHttp fallback branch from `OpenAiCompatibleBackend.send()` (lines 213-271) and `LmStudioBackend.send()` (lines 166-195) production paths. If `transport == null` in a real Burp session that is a wiring bug — fail fast with `IllegalStateException("MontoyaHttpTransport unavailable; AI HTTP backends require Burp's HTTP stack")` rather than silently bypassing Burp.
- Keep OkHttp client construction in `HttpBackendSupport.buildClient` so unit tests with `transport=null` still work, but fix the misleading comment at line 32-41 to say "OkHttp client for unit tests only; does NOT honor Burp's upstream proxy config".

### BUG-69-02 — Small-model context defaults (sub-concern 3)

- Lower the MCP "Max body size" `JSpinner` minimum in `SettingsPanel.kt:222-233` from 1 MB to 32 KB, denominated in **KB** instead of MB (range 32-102400). Migrate stored `mcpSettings.maxBodyBytes` defensively: if existing value < 32 KB, clamp to 32 KB; UI label becomes "Max body size (KB)".
- Add `chat.smallModelMode: Boolean = false` setting plus a "Small model mode" checkbox in the Chat section of `SettingsPanel`. When ON, `ContextCollector.fromRequestResponses()` uses `maxRequestBodyChars = 1500` and `maxResponseBodyChars = 750` (today: 4000 / 8000 — see `ContextCollector.kt:265-269`).
- Do NOT attempt per-backend max-context-window auto-detection in this phase — it's a separate design problem (each backend's metadata format differs). Document this as deferred.

### BUG-69-03 — MCP in-scope-only enforcement (sub-concern 4)

- Add `mcpScopeOnly: Boolean = false` field to `AgentSettings`, default OFF for backwards compatibility.
- Add a "Restrict MCP tools to in-scope hosts" checkbox in the MCP section of `SettingsPanel.kt` (around lines 186-252), positioned next to `mcpExternal` / `mcpUnsafe` since it has similar safety implications.
- Add a helper `McpScopeFilter` in `mcp/tools/` that wraps tool results:
  - For tools returning `HttpRequestResponse` collections (`site_map`, `proxy_history`, target tree, etc.), filter out items where `api.scope().isInScope(url) == false`.
  - For tools accepting a URL parameter (`send_request`, anything that triggers a request), short-circuit and return an MCP error if the URL is out of scope.
- Update every existing MCP tool that touches Burp HTTP data to consult the filter when `mcpScopeOnly == true`. Use the registry of tools currently in `McpTools.kt` (around lines 689-806) as the inventory.

### Claude's Discretion

- Whether to expose the OkHttp fallback as a test-only hook (`@VisibleForTesting`) or via dependency injection — pick whichever requires the smallest churn to existing tests.
- Whether to use a single `mcpScopeOnly` setting OR per-tool overrides — start with single global, can refine later if users ask.
- Whether the small-model defaults are 1500/750 or some other ratio — exact numbers can be calibrated; the requirement is "fits a 1278-token-class model with headroom".

</decisions>

<canonical_refs>
## Canonical References

**Downstream agents MUST read these before planning or implementing.**

### Reported issue
- GitHub issue #69 (https://github.com/six2dez/burp-ai-agent/issues/69) — the four sub-concerns with quoted symptoms.

### Production source files affected
- `src/main/kotlin/com/six2dez/burp/aiagent/backends/http/MontoyaHttpTransport.kt:65-76` — the `execute()` method that wraps `api.http().sendRequest(...)`. Add a sibling `get(url, headers, timeoutMs)`.
- `src/main/kotlin/com/six2dez/burp/aiagent/backends/http/HttpBackendSupport.kt:32-41` — the OkHttp client builder with the misleading "respects Burp/JVM proxy config" comment.
- `src/main/kotlin/com/six2dez/burp/aiagent/backends/http/HttpBackendSupport.kt:89-113` — `healthCheckGet()` used by every HTTP backend's healthCheck.
- `src/main/kotlin/com/six2dez/burp/aiagent/backends/openai/OpenAiCompatibleBackend.kt:81-98` — health check (OkHttp).
- `src/main/kotlin/com/six2dez/burp/aiagent/backends/openai/OpenAiCompatibleBackend.kt:213-271` — chat send with the OkHttp fallback branch to delete.
- `src/main/kotlin/com/six2dez/burp/aiagent/backends/lmstudio/LmStudioBackend.kt:54-68` — health check.
- `src/main/kotlin/com/six2dez/burp/aiagent/backends/lmstudio/LmStudioBackend.kt:166-195` — chat send.
- `src/main/kotlin/com/six2dez/burp/aiagent/supervisor/AgentSupervisor.kt:70, 715, 743` — where `httpTransport` is instantiated and passed to backends.
- `src/main/kotlin/com/six2dez/burp/aiagent/context/ContextCollector.kt:31-78` — `fromRequestResponses()` consumer of `options.maxRequestBodyChars` / `maxResponseBodyChars`.
- `src/main/kotlin/com/six2dez/burp/aiagent/context/ContextCollector.kt:265-269` — current defaults (4000 / 8000 chars).
- `src/main/kotlin/com/six2dez/burp/aiagent/ui/SettingsPanel.kt:222-233` — MCP body cap spinner.
- `src/main/kotlin/com/six2dez/burp/aiagent/ui/SettingsPanel.kt:186-252` — MCP section where the scope checkbox goes.
- `src/main/kotlin/com/six2dez/burp/aiagent/ui/SettingsPanel.kt:277` — example of how the scanner does its `activeAiScopeOnly` checkbox (reference pattern).
- `src/main/kotlin/com/six2dez/burp/aiagent/mcp/tools/McpTools.kt:689, 718, 766-779, 806, 747, 763, 778, 798, 1047-1056` — MCP tool dispatch sites, existing partial scope-checks, and the `truncateIfNeeded` helper.
- `src/main/kotlin/com/six2dez/burp/aiagent/scanner/ActiveAiScanner.kt:133` — reference for `api.scope().isInScope(...)` usage.

### Project rules
- `./CLAUDE.md` — tech stack locked (Kotlin/Gradle/Montoya); English only in code & comments (AGENTS.md non-negotiable); use `/gsd-execute-phase` for execution.
- `./AGENTS.md` — English-only, no version bump in feature/bugfix work.

</canonical_refs>

<specifics>
## Specific Ideas

- The OkHttp fallback comment at `HttpBackendSupport.kt:36-37` literally claims "Use system proxy settings (respects Burp/JVM proxy config)" — this is wrong. `ProxySelector.getDefault()` only reads JVM system properties. Burp's upstream proxy lives in Burp's own state and is only honored via the Montoya `api.http().sendRequest()` path. Fix the comment AND the path.
- The existing `ContextOptions` data class already accepts `maxRequestBodyChars` / `maxResponseBodyChars` as nullable overrides — the plumbing is in place, we just need to populate them based on the new setting.
- `McpTools.kt` already has partial scope support in `proxy_history` (lines 689, 718) — this can be the template for the rest.
- The current `_truncateIfNeeded(serialized, maxBodyBytes)` at `McpTools.kt:1047-1056` uses `coerceAtLeast(1)` — there is no real lower bound at the code level, only at the UI spinner. Lowering the spinner minimum is sufficient.

</specifics>

<deferred>
## Deferred Ideas

- **Per-backend max-context-window detection**: each provider's API exposes context size differently (OpenAI: `/models` returns it; Anthropic: in docs only; local models: depends). Out of scope here — we ship a manual "small model mode" toggle instead, and revisit auto-detection in a later phase.
- **Per-tool scope override**: today's design is one global `mcpScopeOnly`. Per-tool granularity (e.g. "site_map respects scope but `target_tree` does not") would be a follow-up if real users ask for it.
- **GitHub issue #41** (custom external MCP client): explicitly out of scope — that is a milestone-size architectural change tracked separately.

</deferred>

---

*Phase: 07-issue-69-proxy-transport-mcp-scope-hardening*
*Context gathered: 2026-05-27 via in-session code exploration (no separate discuss-phase run needed — analysis was performed live with the user)*
