# Phase 14: Anthropic Backend + Token Budget + Listener Port - Context

**Gathered:** 2026-06-10
**Status:** Ready for planning

<domain>
## Phase Boundary

Three independent capabilities shipping together (CAP-03 and CAP-04 are small additions that share no conflicts with CAP-01):

1. **CAP-01** — A native **Anthropic Messages API** backend selectable in Settings > Backend: encrypted API key (Phase 12 SecretCipher), editable model field, streaming chat routed through `MontoyaHttpTransport` (so traffic appears in Burp Proxy history — NO direct OkHttp on the production path), token counting via the Messages API usage fields, and a specific model-rejection error message.
2. **CAP-04** — Per-session **token-budget guardrails** layered on the existing `TokenTracker`: a warn threshold and a hard cap; at the hard cap the passive AI scanner pauses; the chat UI shows a warning banner when the warn threshold is crossed.
3. **CAP-03** — The MCP `proxy_http_history` tool gains an optional **listener-port filter** (closes #70): only requests received on the given Burp listener port are returned.

Out of scope: AI backends beyond Anthropic; Anthropic-native tool-use and prompt-caching beyond what SC1 requires (see Deferred).
</domain>

<decisions>
## Implementation Decisions

### CAP-01 — Anthropic Messages API Backend
- **Default model:** the editable model field defaults to `claude-sonnet-4-6` (current balanced Sonnet); users with different access edit it. **Planner/researcher MUST confirm the exact current public Anthropic Messages API model ID against Anthropic docs** — aliases evolve; the field is editable so a wrong default is low-risk but should be current.
- **Scope (this phase):** implement streaming + token counting + encrypted key + model selection + the model-rejection error message (SC1–SC3). Match the existing shared agent text protocol used by the other backends — do NOT add Anthropic-native tool-use or prompt-caching now (deferred).
- **Transport:** reuse OkHttp + `MontoyaHttpTransport` (the same path as `OpenAiCompatibleBackend`), routed through `CircuitBreaker`. `grep OkHttp AnthropicBackend.kt` must return empty on the production code path (SC2) — i.e. no direct OkHttp client construction; all HTTP goes through the injected transport.
- **API key:** new `anthropicApiKey` field in `AgentSettings`, encrypted at rest via the existing `SecretCipher` pattern (`cipher.encrypt`/`cipher.decrypt` with a `KEY_ANTHROPIC_API_KEY` versioned pref key) — identical to `openAiCompatibleApiKey`/`perplexityApiKey`. The Phase 12 per-install key bootstrap is inherited; no new key-management decision.
- **`anthropic-version` header:** stable `2023-06-01`.
- **System prompt:** `supportsSystemRole = true`; map the agent's `systemPrompt` to Anthropic's top-level `system` request field (NOT a system-role message).
- **Registration:** add `AnthropicBackendFactory()` to the `BackendRegistry` built-ins list, alongside `OpenAiCompatibleBackendFactory()` etc.
- **SSE streaming:** parse Anthropic's event stream (`message_start`, `content_block_delta` text deltas, `message_delta`/`message_stop`); pull token usage from `message_start.usage.input_tokens` and the final `message_delta.usage.output_tokens`.
- **Model error (SC3):** a 400 whose body contains "model" surfaces the specific message: "Anthropic rejected the model ID — check Settings > Anthropic > Model".

### CAP-04 — Token-Budget Guardrails
- **Session scope:** per Burp-run (process lifetime), aggregated across flows via `TokenTracker` (input + output tokens).
- **Defaults:** OFF by default — warn=0 and cap=0 mean unlimited; the guardrail only activates once the user sets non-zero thresholds (a security tool must not surprise-block mid-engagement).
- **Hard-cap behavior:** when the cap fires, **pause the passive AI scanner** (stop enqueuing new AI scans) and show a chat warning banner; interactive chat stays usable so the user isn't locked out mid-task.
- **Warn threshold:** crossing it shows a non-blocking warning banner in the chat UI (ChatPanel).
- **Counting basis:** use `TokenTracker`'s actual-when-available token counts, falling back to its estimate; compare combined input+output against the thresholds.

### CAP-03 — Listener-Port Filter
- Add an optional `listener_port` **integer** parameter to the MCP `proxy_http_history` tool; when set, return only requests received on that Burp listener port (via the Montoya proxy-history listener-port accessor). Empty/unset → all ports (current behavior). A port with no matches → empty list, NOT an error.

### Claude's Discretion
- Exact SSE buffering/parsing implementation, the precise ChatPanel banner placement/wording, where the token-budget threshold inputs live in Settings (a Usage/Privacy section vs alongside the backend), the proxy-history listener-port accessor specifics, and request/response JSON DTO shapes — at Claude's discretion, guided by the `OpenAiCompatibleBackend` analog and existing UI conventions.
</decisions>

<code_context>
## Existing Code Insights

### Reusable Assets
- `backends/openai/OpenAiCompatibleBackend.kt` + `OpenAiCompatibleBackendFactory.kt` — closest analog: HTTP streaming backend using the injected `MontoyaHttpTransport`. Model `AnthropicBackend`/`AnthropicBackendFactory` on this (Anthropic Messages API request/response shape + `x-api-key`/`anthropic-version` headers differ).
- `backends/BackendTypes.kt` — `AiBackend` (id, displayName, `launch(config)`), `AiBackendFactory`, `AgentConnection.send(... onChunk, onComplete ...)` streaming contract, `UsageAwareConnection.lastTokenUsage(): TokenUsage`, `BackendLaunchConfig.transport`.
- `backends/http/MontoyaHttpTransport.kt` + `CircuitBreaker.kt` — the Burp-routed HTTP path all backends must use.
- `backends/BackendRegistry.kt` — built-ins list where factories register (add `AnthropicBackendFactory()`).
- `config/AgentSettings.kt` + `config/SecretCipher.kt` — encrypted API-key fields (`openAiCompatibleApiKey`, `perplexityApiKey`, `nvidiaNimApiKey` all via `cipher.decrypt(prefs.getString(KEY_X), KEY_X)`). Add `anthropicApiKey` the same way.
- `util/TokenTracker.kt` — `object TokenTracker` with `record(...)` and `TokenUsageSnapshot`. CAP-04 budget logic layers on its recorded counts.
- `mcp/tools/McpTools.kt` + `McpToolHandlers.kt` + `McpToolCatalog.kt` — `proxy_http_history` tool definition + handler (add `listener_port` param).
- `ui/ChatPanel.kt` — chat UI (token-budget warning banner attaches here).
- `ui/SettingsPanel.kt` — backend selection + per-backend settings (Anthropic fields + token-budget thresholds).
- `scanner/PassiveAiScanner.kt` — the passive AI scanner that pauses at the hard cap.

### Established Patterns
- Backends are factories registered in `BackendRegistry`; HTTP backends receive a `MontoyaHttpTransport` via `BackendLaunchConfig.transport` and never build their own OkHttp client on the production path.
- Encrypted secrets: `SecretCipher` with versioned `KEY_*` pref keys; decrypt on load, encrypt on save; never log the value (Phase 12).
- MCP tools defined in a catalog + handler split; params validated in the handler.

### Integration Points
- `BackendRegistry` built-ins (register Anthropic).
- `AgentSettings`/`SettingsPanel` (Anthropic fields, encrypted key, token-budget thresholds).
- `TokenTracker` (budget accounting) → `PassiveAiScanner` (pause at cap) + `ChatPanel` (warn banner).
- `McpTools`/`McpToolHandlers` (`proxy_http_history` listener-port param).
</code_context>

<specifics>
## Specific Ideas

- SC2 is prescriptive: `grep OkHttp AnthropicBackend.kt` must return empty on the production path — all HTTP via `MontoyaHttpTransport`, confirmed by Anthropic traffic appearing in Burp Proxy > HTTP history.
- SC3 prescriptive error string: "Anthropic rejected the model ID — check Settings > Anthropic > Model" on a 400 whose body contains "model".
- SC1 verified by a HUMAN-UAT smoke test with a live Anthropic API key (streaming visible through the proxy).
- SC5: `proxy_http_history` filtered by listener port (e.g. `8080`) returns only requests on that port.
</specifics>

<deferred>
## Deferred Ideas

- **Anthropic-native tool-use** and **prompt-caching** headers/handling — listed in the CAP-01 requirement text but not in SC1–SC5; deferred this phase (scope decision 2026-06-10). The backend ships streaming + token counting matching the existing shared agent protocol; native tool-use can be added in a future phase if demand surfaces. Record in REQUIREMENTS.md CAP-01 annotation at plan-phase.
- Additional AI backends beyond Anthropic — explicitly out of scope for v0.9.0 (REQUIREMENTS Out of Scope).
</deferred>
