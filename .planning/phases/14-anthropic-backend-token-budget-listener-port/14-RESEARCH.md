# Phase 14: Anthropic Backend + Token Budget + Listener Port - Research

**Researched:** 2026-06-10
**Domain:** Anthropic Messages API client (Kotlin/JVM, Burp-routed HTTP), token-budget guardrails on an existing tracker, Montoya proxy-history filtering
**Confidence:** HIGH

## Summary

This phase ships three independent capabilities on the existing backend/scanner/MCP infrastructure with **zero new dependencies**. CAP-01 adds a native Anthropic Messages API backend (`AnthropicBackend` + `AnthropicBackendFactory`) modeled on the existing `OpenAiCompatibleBackend`: it reuses the supervisor-injected `MontoyaHttpTransport` for all production HTTP, the existing `SecretCipher` for the encrypted API key, `HttpBackendSupport`'s `CircuitBreaker`/retry helpers, and Jackson (already a dependency) for request/response JSON. The Anthropic wire contract differs from OpenAI in three concrete ways the planner must encode: `x-api-key` + `anthropic-version: 2023-06-01` headers (not Bearer), a top-level `system` field (not a system-role message), and a required `max_tokens`. CAP-04 layers warn/cap guardrails on `TokenTracker` — the natural hook is the `onComplete` callback in `ChatPanel` (and the scanner's own record sites) where `TokenTracker.record(...)` already fires; the hard cap flips a **new budget-pause gate** on `PassiveAiScanner` (NOT the existing `setEnabled` toggle, which clears the knowledge base and the user's choice). CAP-03 adds an optional `listener_port` integer to the MCP `proxy_http_history` tool and filters `api.proxy().history()` items by `ProxyHttpRequestResponse.listenerPort()` — verified to exist in the Montoya 2026.2 jar this project compiles against.

The critical safety property is SC2: `grep OkHttp AnthropicBackend.kt` must return empty on the production path. The analog `OpenAiCompatibleBackend` already satisfies this — its `send()` calls `transport.post()` and fails fast with `IllegalStateException("MontoyaHttpTransport unavailable...")` when the transport is null. `AnthropicBackend` mirrors this exactly. (Note: the existing `OpenAiCompatibleBackend` "streaming" flag sets `stream:true` in the payload but the connection still buffers the full response via `transport.post()`. `MontoyaHttpTransport` has **no streaming method** — `api.http().sendRequest()` returns a complete `HttpResponse`. See Pitfall 1 for the streaming-vs-buffering reality and how to satisfy SC1's "streaming visible in proxy" without a transport-level SSE reader.)

**Primary recommendation:** Build `AnthropicBackend` as a near-copy of `OpenAiCompatibleConnection` with an Anthropic request/response DTO shape; route every production call through `config.transport.post("https://api.anthropic.com/v1/messages", headers, json, timeoutMs)`; map `systemPrompt` to the top-level `system` field; extract usage from `usage.input_tokens` + `usage.output_tokens`; surface the SC3 string on a 400 whose body contains "model". Add a `budgetPaused` AtomicBoolean gate to `PassiveAiScanner` and centralize the budget check where `TokenTracker.record` is already called. Add `listenerPort: Int? = null` to `GetProxyHttpHistory` and filter both dispatch paths.

## Architectural Responsibility Map

| Capability | Primary Tier | Secondary Tier | Rationale |
|------------|-------------|----------------|-----------|
| Anthropic Messages API request/response (CAP-01) | Backend adapter (`backends/anthropic/`) | HTTP transport (`MontoyaHttpTransport`) | New backends are addable without refactoring core logic (AGENTS.md); all outbound HTTP must traverse Burp's stack |
| API key at rest (CAP-01) | Config (`AgentSettings` + `SecretCipher`) | UI (`BackendConfigPanel`) | Phase 12 established encrypted-secret pattern; UI only collects/masks |
| Streaming render to chat (CAP-01 SC1) | UI (`ChatPanel` chunk rendering) | Backend `onChunk` | Existing `onChunk`→`assistant.appendChunk` path; UI owns display |
| Token accounting + budget decision (CAP-04) | Util (`TokenTracker`) + caller (`ChatPanel` onComplete / scanner record sites) | — | `TokenTracker` is the single source of session totals; the *decision* belongs where the call completes |
| Hard-cap enforcement (CAP-04) | Scanner (`PassiveAiScanner` budget-pause gate) | — | The enforcement action is "stop enqueuing AI scans"; that state lives on the scanner |
| Budget banner (CAP-04) | UI (`ChatPanel` `SubtleNotice` at NORTH) | — | Advisory surface; reuses existing component |
| Listener-port filter (CAP-03) | MCP tool (`McpTools.kt` proxy_http_history handler) | Montoya (`ProxyHttpRequestResponse.listenerPort()`) | Pure server-side filter on history items; no UI |

<user_constraints>
## User Constraints (from CONTEXT.md)

### Locked Decisions

**CAP-01 — Anthropic Messages API Backend**
- Default model: editable Model field defaults to `claude-sonnet-4-6` (current balanced Sonnet). **Confirmed current 2026-06-10** (see Standard Stack / Model Verification).
- Scope this phase: streaming + token counting + encrypted key + model selection + the model-rejection error message (SC1–SC3). Match the existing shared agent text protocol. Do NOT add Anthropic-native tool-use or prompt-caching now (deferred).
- Transport: reuse OkHttp + `MontoyaHttpTransport` (same path as `OpenAiCompatibleBackend`), routed through `CircuitBreaker`. `grep OkHttp AnthropicBackend.kt` must return empty on the production code path (SC2) — no direct OkHttp client construction; all HTTP via the injected transport.
- API key: new `anthropicApiKey` field in `AgentSettings`, encrypted at rest via the existing `SecretCipher` (`cipher.encrypt`/`cipher.decrypt` with a `KEY_ANTHROPIC_API_KEY` versioned pref key) — identical to `openAiCompatibleApiKey`/`perplexityApiKey`. Phase 12 per-install key bootstrap inherited; no new key-management decision.
- `anthropic-version` header: stable `2023-06-01`.
- System prompt: `supportsSystemRole = true`; map the agent's `systemPrompt` to Anthropic's top-level `system` request field (NOT a system-role message).
- Registration: add `AnthropicBackendFactory()` to the `BackendRegistry` built-ins list, alongside `OpenAiCompatibleBackendFactory()` etc.
- SSE streaming: parse Anthropic's event stream (`message_start`, `content_block_delta` text deltas, `message_delta`/`message_stop`); pull token usage from `message_start.usage.input_tokens` and the final `message_delta.usage.output_tokens`.
- Model error (SC3): a 400 whose body contains "model" surfaces the specific message: **"Anthropic rejected the model ID — check Settings > Anthropic > Model"**.

**CAP-04 — Token-Budget Guardrails**
- Session scope: per Burp-run (process lifetime), aggregated across flows via `TokenTracker` (input + output tokens).
- Defaults: OFF by default — warn=0 and cap=0 mean unlimited; the guardrail only activates once the user sets non-zero thresholds (a security tool must not surprise-block mid-engagement).
- Hard-cap behavior: when the cap fires, **pause the passive AI scanner** (stop enqueuing new AI scans) and show a chat warning banner; interactive chat stays usable.
- Warn threshold: crossing it shows a non-blocking warning banner in the chat UI (ChatPanel).
- Counting basis: use `TokenTracker`'s actual-when-available token counts, falling back to its estimate; compare combined input+output against the thresholds.

**CAP-03 — Listener-Port Filter**
- Add an optional `listener_port` **integer** parameter to the MCP `proxy_http_history` tool; when set, return only requests received on that Burp listener port (via the Montoya proxy-history listener-port accessor). Empty/unset → all ports (current behavior). A port with no matches → empty list, NOT an error.

### Claude's Discretion
- Exact SSE buffering/parsing implementation, the precise ChatPanel banner placement/wording, where the token-budget threshold inputs live in Settings (a Usage/Privacy section vs alongside the backend), the proxy-history listener-port accessor specifics, and request/response JSON DTO shapes — guided by the `OpenAiCompatibleBackend` analog and existing UI conventions. (UI-SPEC resolves placement: Anthropic card in `BackendConfigPanel`, token-budget section inside the Passive AI Scanner region of `SettingsPanel`, banner at `BorderLayout.NORTH` of `chatContainer`.)

### Deferred Ideas (OUT OF SCOPE)
- **Anthropic-native tool-use** and **prompt-caching** headers/handling — not in SC1–SC5; deferred. Backend ships streaming + token counting matching the existing shared agent protocol. Record in REQUIREMENTS.md CAP-01 annotation at plan-phase.
- Additional AI backends beyond Anthropic — out of scope for v0.9.0.
</user_constraints>

<phase_requirements>
## Phase Requirements

| ID | Description | Research Support |
|----|-------------|------------------|
| CAP-01 (C1) | Native Anthropic Messages API backend with streaming + token counting — reusing OkHttp + `MontoyaHttpTransport` (no SDK that bypasses Burp), API key encrypted via SEC-01 | Authoritative Anthropic Messages API contract (Code Examples §1–4); analog `OpenAiCompatibleBackend` integration points (Code Examples §5); `SecretCipher`/`AgentSettings` key pattern (Code Examples §6). Tool-use + prompt-caching deferred per CONTEXT.md. |
| CAP-03 (C5, closes #70) | Filter MCP proxy-history tool output by Burp listener port | `ProxyHttpRequestResponse.listenerPort(): Int` verified in Montoya 2026.2 jar (Code Examples §9); two dispatch paths in `McpTools.kt` identified (Pitfall 4). |
| CAP-04 (C7) | Per-session token-budget guardrails — warn + cap (pausing passive scanner at hard cap), built on `TokenTracker` | `TokenTracker.snapshot()` sums actual+estimate per (flow,backend) (Code Examples §7); hook at `ChatPanel` onComplete (Code Examples §8); new `PassiveAiScanner` budget-pause gate (Pitfall 3). |
</phase_requirements>

## Standard Stack

### Core (all already present — ZERO new dependencies)
| Library | Version | Purpose | Why Standard |
|---------|---------|---------|--------------|
| Kotlin / JVM | 21 | Language/runtime | Fixed by ADR-1/2/3 (CLAUDE.md) |
| `montoya-api` | 2026.2 | Burp extension API + `api.http().sendRequest()` transport + `api.proxy().history()` | `compileOnly` in build.gradle.kts; the only sanctioned Burp HTTP path |
| `jackson-databind` + `jackson-module-kotlin` | 2.21.2 | Anthropic request/response JSON (mirrors `OpenAiCompatibleBackend`'s `ObjectMapper().registerKotlinModule()`) | Already used by every HTTP backend |
| `kotlinx-serialization-json` | 1.8.1 | MCP tool input/output serialization (`@Serializable` DTOs, `decode<T>`) | Already used by all MCP tools |
| `okhttp3` | 4.12.0 | Present in classpath BUT **must NOT be referenced on the Anthropic production path** (SC2). Used only by `HttpBackendSupport.buildClient` (test-only) and health-check fallbacks. | — |

### Supporting (existing infrastructure to reuse)
| Component | Path | Purpose | When to Use |
|-----------|------|---------|-------------|
| `MontoyaHttpTransport` | `backends/http/MontoyaHttpTransport.kt` | `post(url, headers, jsonBody, timeoutMs): TransportResponse` — Burp-routed | Every Anthropic HTTP call |
| `HttpBackendSupport` | `backends/http/HttpBackendSupport.kt` | `newCircuitBreaker()`, `isRetryableConnectionError(e)`, `retryDelayMs(attempt)`, `openCircuitError(name, retryAfterMs)` | Reuse the retry/circuit-breaker loop verbatim from `OpenAiCompatibleConnection` |
| `ConversationHistory` | nested in `HttpBackendSupport.kt:166` | `addUser`/`addAssistant`/`setHistory`/`snapshot()` (returns `List<Map<String,String>>`) | Build the `messages` array — but DO NOT use `setSystemPrompt` (it injects a `system`-role message; Anthropic needs top-level `system`) |
| `SecretCipher` | `config/SecretCipher.kt` | `encrypt(plaintext, KEY)` / `decrypt(ciphertext, KEY)` AES-256-GCM, "ENC1:" envelope, fail-soft | The `anthropicApiKey` field |
| `TokenTracker` | `util/TokenTracker.kt` | `record(...)`, `snapshot(): List<TokenUsageSnapshot>` (actual-when-available + estimate fallback) | CAP-04 session totals |
| `SubtleNotice` | `ui/components/SubtleNotice.kt` | `setMessage(Level, html)` / `hideNotice()`; `Level.{INFO,WARN,RISK}` | CAP-04 chat banner |
| `CircuitBreaker` | `backends/http/CircuitBreaker.kt` | `tryAcquire()` / `recordSuccess()` / `recordFailure()` | Reuse in the send loop |

### Alternatives Considered
| Instead of | Could Use | Tradeoff |
|------------|-----------|----------|
| Hand-rolled Jackson DTO via `MontoyaHttpTransport` | Official Anthropic Java SDK (`com.anthropic:anthropic-java`, which embeds `AnthropicOkHttpClient`) | **REJECTED** — explicitly out of scope (REQUIREMENTS "Vendoring an Anthropic SDK that embeds its own HTTP client" = the #69 trap); bypasses Burp's proxy and bloats the fat JAR |
| `MontoyaHttpTransport.post()` buffered call | A new transport-level SSE/streaming reader | Montoya's `sendRequest()` is request/response only (no chunked callback). A true streaming reader would require a custom OkHttp `EventSource` — forbidden by SC2. Buffer the response and chunk at the UI/connection boundary. See Pitfall 1. |

**Installation:** None. All packages already declared in `build.gradle.kts`.

**Version verification:**
- `claude-sonnet-4-6` — verified current Sonnet 4.6 API ID/alias [VERIFIED: platform.claude.com models overview, 2026-06-10].
- `montoya-api:2026.2` — resolved in `~/.gradle/caches/...montoya-api-2026.2.jar`; `ProxyHttpRequestResponse.listenerPort()` confirmed via `javap` [VERIFIED: local jar decompile].
- jackson 2.21.2 / kotlinx-serialization 1.8.1 / okhttp 4.12.0 — confirmed in `build.gradle.kts` [VERIFIED: codebase grep].

### Model Verification (CONTEXT.md mandate)
The "Latest models comparison" table at platform.claude.com confirms **`claude-sonnet-4-6`** is the current Claude API ID AND alias for Claude Sonnet 4.6, described as "The best combination of speed and intelligence" — the balanced Sonnet. The CONTEXT.md default is **correct and current; keep it.** Adjacent current IDs (for the editable field's docs/help, not the default): Opus = `claude-opus-4-8`, Haiku = `claude-haiku-4-5`. [VERIFIED: platform.claude.com/docs/en/about-claude/models/overview, 2026-06-10]

> Note: Sonnet 4.6 (and all 4.6+ models) **do not support prefilling assistant messages** — a trailing partial assistant message returns 400 `invalid_request_error`. The agent protocol sends complete user/assistant turns (not partial prefills), so this is not hit; do not add assistant-prefill behavior. [CITED: platform.claude.com/docs/en/api/errors → "Prefill not supported"]

## Package Legitimacy Audit

> No external packages are installed by this phase. All libraries are pre-existing, declared in `build.gradle.kts`, and resolved from the project's existing Gradle cache. slopcheck/registry verification is **not applicable** — there is no new npm/PyPI/crates install surface.

| Package | Registry | Disposition |
|---------|----------|-------------|
| (none — zero new dependencies) | — | N/A |

**Packages removed due to slopcheck [SLOP] verdict:** none
**Packages flagged as suspicious [SUS]:** none

## Architecture Patterns

### System Architecture Diagram

```
CAP-01 — Anthropic chat request flow
====================================

  ChatPanel.send(userText)
        │  (systemPrompt, maxOutputTokens=Defaults.CHAT_MAX_OUTPUT_TOKENS)
        ▼
  AgentSupervisor.launch(backendId="anthropic")
        │  builds BackendLaunchConfig(model, headers={x-api-key,anthropic-version}, transport=httpTransport)
        ▼
  AnthropicBackend.launch(config) ──► AnthropicConnection
        │
        │  send(text, history, onChunk, onComplete, systemPrompt, maxOutputTokens)
        ▼
  [CircuitBreaker.tryAcquire] ──► build JSON {model, max_tokens, system, messages[], stream}
        │                                   (Jackson ObjectMapper; system = top-level field)
        ▼
  config.transport.post("https://api.anthropic.com/v1/messages",      ◄── SC2: ONLY HTTP call.
                        headers, json, timeoutMs)                          NO OkHttp construction.
        │   (Burp's api.http().sendRequest → appears in Proxy > HTTP history = SC2 proof)
        ▼
  TransportResponse{statusCode, body, isSuccessful}
        │
        ├─ 200 ─► parse body: content[].text  ──► onChunk(text) ──► ChatPanel renders
        │         extract usage.input_tokens / usage.output_tokens ──► lastTokenUsage()
        │
        └─ 400 & body contains "model" ─► onComplete(IllegalStateException(
                 "Anthropic rejected the model ID — check Settings > Anthropic > Model"))   ◄── SC3
        ▼
  ChatPanel.onComplete(err):
        TokenTracker.record(flow="chat", inputTokensActual=usage.input, outputTokensActual=usage.output)
        │
        ▼   ◄────────────────────────── CAP-04 budget hook attaches HERE
  BudgetGuard.check(TokenTracker.snapshot()):
        sum(inputTokensEstimated + outputTokensEstimated) vs warn / cap
        ├─ ≥ warn & < cap ─► budgetNotice.setMessage(WARN, "...")
        ├─ ≥ cap          ─► budgetNotice.setMessage(RISK, "...scanning paused...")
        │                    + PassiveAiScanner.setBudgetPaused(true)   ◄── stops enqueue
        └─ below both     ─► budgetNotice.hideNotice()


CAP-03 — Listener-port filter
=============================

  MCP client → tool call "proxy_http_history" {count, offset, listener_port?}
        │
        ▼
  api.proxy().history() : List<ProxyHttpRequestResponse>
        │
        ▼   filter when listener_port != null
  seq.filter { it.listenerPort() == listener_port }   ◄── ProxyHttpRequestResponse.listenerPort(): Int
        │                                                  (verified, Montoya 2026.2)
        ▼
  .drop(offset).take(count).map { toSerializableForm } ──► JSON to client
  (empty result when no match = empty list, NOT an error)
```

### Recommended Project Structure
```
src/main/kotlin/com/six2dez/burp/aiagent/
├── backends/
│   ├── anthropic/                       # NEW package (mirror backends/openai/)
│   │   ├── AnthropicBackend.kt          # AiBackend; supportsSystemRole=true; launch() → AnthropicConnection
│   │   └── AnthropicBackendFactory.kt   # AiBackendFactory; create() = AnthropicBackend()
│   └── http/MontoyaHttpTransport.kt     # reuse (no change)
├── config/
│   └── AgentSettings.kt                 # +anthropicModel, +anthropicApiKey, +tokenBudgetWarnThreshold, +tokenBudgetHardCap; +KEY_ANTHROPIC_*; migration list += KEY_ANTHROPIC_API_KEY
├── scanner/PassiveAiScanner.kt          # +budgetPaused gate; enqueueForScanCheck respects it
├── ui/
│   ├── panels/BackendConfigPanel.kt     # +buildAnthropicPanel() card
│   ├── SettingsPanel.kt                 # +Token budget section (warn/cap fields)
│   └── ChatPanel.kt                     # +budgetNotice (SubtleNotice@NORTH); budget check in onComplete
└── mcp/tools/McpTools.kt                # GetProxyHttpHistory +listenerPort; filter in BOTH dispatch paths
src/main/resources/META-INF/services/com.six2dez.burp.aiagent.backends.AiBackendFactory  # += AnthropicBackendFactory line
```

### Pattern 1: Anthropic connection mirrors OpenAiCompatibleConnection
**What:** A private `AnthropicConnection : AgentConnection, UsageAwareConnection` with the same single-thread executor, `CircuitBreaker`, retry loop, and transport-null fail-fast guard as `OpenAiCompatibleConnection`. Only the request JSON shape, headers, endpoint, response parsing, and usage extraction differ.
**When to use:** The entire CAP-01 backend.
**Example:** see Code Examples §5 (analog) and the Anthropic request/response contract in §1–4.

### Pattern 2: Top-level `system`, not a system-role message
**What:** Anthropic has no `system` role in `messages`. Map `systemPrompt` to the request's top-level `system` string field. Build `messages` from user/assistant turns only.
**When to use:** Constructing every Anthropic request.
**Why it differs from OpenAI:** `ConversationHistory.snapshot()` embeds the system prompt as `{"role":"system",...}` (correct for OpenAI). For Anthropic, either (a) call `addUser`/`addAssistant` but never `setSystemPrompt`, then pass `systemPrompt` into the top-level field; or (b) filter out any `role==system` entry from the snapshot. Option (a) is cleaner.

### Pattern 3: Budget gate distinct from scanner enable
**What:** Add `private val budgetPaused = AtomicBoolean(false)` + `fun setBudgetPaused(on: Boolean)` to `PassiveAiScanner`; make `enqueueForScanCheck` early-return when `budgetPaused.get()` is true (in addition to the existing `!enabled.get()` check).
**When to use:** CAP-04 hard-cap enforcement.
**Why:** Reusing `setEnabled(false)` would (1) clear `ScanKnowledgeBase` and (2) flip the user's visible toggle — both wrong for a reversible budget pause. The pause must un-flip when the user raises the cap/threshold or on a new Burp run (per-process budget).

### Anti-Patterns to Avoid
- **Constructing an OkHttp client (or the Anthropic SDK) in `AnthropicBackend`** — breaks SC2 and the #69 privacy guarantee. All HTTP via `config.transport.post(...)`.
- **Logging the request JSON or message content** — the existing backends log only a body *shape* preview (`model=… messages=N json_bytes=…`). Mirror that exactly (privacy + Phase 12 rule). Never log the API key.
- **Putting the system prompt in the `messages` array** for Anthropic — returns wrong behavior or 400.
- **Calling `setEnabled(false)` for the budget pause** — see Pattern 3.
- **Filtering listener port in only one dispatch path** — see Pitfall 4.
- **Treating "no matches for a listener port" as an error** — CONTEXT.md says empty list, not error.

## Don't Hand-Roll

| Problem | Don't Build | Use Instead | Why |
|---------|-------------|-------------|-----|
| Outbound HTTP to Anthropic | A new OkHttp/HttpClient call | `config.transport.post(...)` (`MontoyaHttpTransport`) | SC2 + #69; Burp proxy/cert/SOCKS participation |
| API-key encryption | Any new crypto | `SecretCipher.encrypt/decrypt` | Phase 12 SEC-01; AES-256-GCM, fail-soft, migration-aware |
| Retry / backoff / circuit breaking | A custom retry loop | `HttpBackendSupport.newCircuitBreaker/isRetryableConnectionError/retryDelayMs` + `CircuitBreaker` | Identical semantics already shipped; consistency (REL-03) |
| Session token totals | A new counter | `TokenTracker.record` + `snapshot()` | Already aggregates actual+estimate per flow/backend |
| Chat advisory banner | A new Swing banner | `SubtleNotice` (`Level.WARN`/`RISK`) | Phase 13 reuse pattern; theme-correct via `updateUI()` |
| Listener-port lookup | Parsing the request line / a custom field | `ProxyHttpRequestResponse.listenerPort()` | First-class Montoya accessor (verified 2026.2) |
| Backend registration | Manual wiring everywhere | `META-INF/services` ServiceLoader line + `BackendRegistry` fallback list | Established ServiceLoader pattern |
| Request/response JSON | String concatenation | Jackson `ObjectMapper` (mirror OpenAi backend) | Escaping, UTF-8, robustness |

**Key insight:** Phase 14 is overwhelmingly an *integration/composition* exercise. The dominant risk is **diverging** from the established analogs (transport routing, secret handling, retry loop, banner reuse), not building anything novel. The only genuinely new logic is: the Anthropic JSON DTO shape, the budget comparison/pause, and the listener-port filter — all small.

## Runtime State Inventory

> Phase 14 is additive (new backend, new optional settings, new optional MCP param). It contains **no rename/refactor/migration of existing identifiers**. One new encrypted secret key is introduced, which must join the SEC-01 migration list.

| Category | Items Found | Action Required |
|----------|-------------|------------------|
| Stored data | New pref keys only: `anthropic.model`, `anthropic.apiKey` (encrypted), `tokenBudget.warnThreshold`, `tokenBudget.hardCap`. No existing key is renamed. Absent keys load as defaults (no schema break). | Code edit (add load/save); add `KEY_ANTHROPIC_API_KEY` to `migrateToSchemaV4`'s `secretKeys` list so a future plaintext value is encrypted idempotently. |
| Live service config | None — no external service stores Phase-14 state. | None — verified: the only external endpoint is the fixed `api.anthropic.com` (a backend constant). |
| OS-registered state | None. | None — verified: no OS-level registration touched. |
| Secrets/env vars | New: `anthropicApiKey` (Burp Preferences, encrypted via existing per-install master key). No new env var; no new master-key decision (Phase 12 bootstrap inherited). | Code rename only / none — reuses `secret.master.key.v1`. |
| Build artifacts | None — no Gradle coordinate or generated-source change. `BuildFlags`/`generateBuildFlags` untouched. | None. |

**The canonical question — "after every file is updated, what runtime systems still hold old state?":** Nothing. The phase adds new keys/params; it does not migrate or rename anything users already have. The single migration touch is appending `KEY_ANTHROPIC_API_KEY` to the existing idempotent secret-encryption migration (so a key saved before the encrypt path is wired would still get encrypted — though in practice the save path encrypts on write, so this is belt-and-suspenders consistent with the other backends).

## Common Pitfalls

### Pitfall 1: Expecting transport-level token streaming
**What goes wrong:** A planner assumes "streaming" means `AnthropicBackend` reads SSE chunks off the socket. `MontoyaHttpTransport.post()` calls `api.http().sendRequest(request, options)` which returns a **complete** `HttpResponse` — Montoya exposes no chunked/streaming callback. The existing `OpenAiCompatibleBackend` "streaming" flag merely sets `stream:true` in the payload but still buffers the whole response and emits it via a single `onChunk(content)`.
**Why it happens:** The Anthropic docs and SC1 emphasize SSE streaming; the transport doesn't support it.
**How to avoid:** Two valid options, both SC2-compliant (no OkHttp):
  1. **Recommended (simplest, matches analog):** Send `stream:false` (or omit), get the full JSON Message back via `transport.post`, parse `content[0].text` and `usage`, emit one `onChunk`. SC1 ("streaming visible through the proxy") is satisfied because the request **appears in Burp Proxy history** — that is the SC2/SC1 proof point per CONTEXT.md ("traffic appears in Burp Proxy > HTTP history"). The chat still renders the answer; it just arrives in one chunk like the other HTTP backends.
  2. **If true incremental rendering is desired later:** send `stream:true`, receive the full SSE body as one buffered string (Montoya returns the whole body), then parse the buffered SSE locally (split on `\n\n`, read `data:` lines, accumulate `text_delta`s) and replay them as multiple `onChunk` calls. This is cosmetic — the network call is still one buffered round-trip. Still no OkHttp.
**Warning signs:** Any design that reaches for `okhttp3.sse.EventSource`, `Response.body().source()`, or a second HTTP client — all violate SC2.
**Recommendation:** Use option 1 for this phase (matches every other HTTP backend; minimal surface). Note the SSE-parse option in the plan as a discretionary enhancement, not a requirement. The usage fields are present in the non-streaming response (`usage.input_tokens`/`usage.output_tokens`), so token counting (SC1) works without any SSE parsing.

### Pitfall 2: Wrong headers / auth scheme
**What goes wrong:** Reusing the OpenAI `Authorization: Bearer <key>` header. Anthropic uses `x-api-key: <key>` + `anthropic-version: 2023-06-01` + `content-type: application/json`.
**Why it happens:** `HeaderParser.withBearerToken(...)` is the established helper for the other backends.
**How to avoid:** Build the header map directly: `mapOf("x-api-key" to apiKey, "anthropic-version" to "2023-06-01")` (the transport adds `Content-Type: application/json` automatically — see `MontoyaHttpTransport.post`). Do NOT route the Anthropic key through `withBearerToken`. The supervisor branch for `"anthropic"` constructs these headers (analog: the perplexity/nvidia branches build their header maps).
**Warning signs:** A 401 `authentication_error`, or the key landing in an `Authorization` header.

### Pitfall 3: Budget pause clobbering the scanner toggle
**What goes wrong:** Hard cap calls `passiveScanner.setEnabled(false)`, which clears `ScanKnowledgeBase` and visibly turns off the user's scanner switch; raising the cap later doesn't restore it.
**Why it happens:** `setEnabled` looks like the obvious "stop scanning" lever.
**How to avoid:** Add a separate `budgetPaused` AtomicBoolean and gate `enqueueForScanCheck` on it (see Pattern 3). Pause = `setBudgetPaused(true)`; resume (cap raised, or thresholds cleared) = `setBudgetPaused(false)`. Per-process budget means a Burp restart naturally resets it (the AtomicBoolean starts false).
**Warning signs:** Tests that observe the knowledge base cleared, or the scanner's `enabled` flag flipped, when the cap fires.

### Pitfall 4: Listener-port filter applied to only one dispatch path
**What goes wrong:** `proxy_http_history` is handled in **two** places in `McpTools.kt`: (a) the `mcpPaginatedTool<GetProxyHttpHistory>` registration (~line 649, auto-schema via reified generic) and (b) a manual `decode<GetProxyHttpHistory>` dispatch (~line 1860). Adding the filter to only one leaves the other unfiltered.
**Why it happens:** The second path is far from the first and easy to miss.
**How to avoid:** Add `listenerPort: Int? = null` to the `GetProxyHttpHistory` data class once; then add the same `.filter { lp == null || it.listenerPort() == lp }` to the `seq` pipeline in **both** locations. The reified-generic registration auto-exposes the new field in the tool schema (no manual schema edit needed for path (a)). Verify the manual schema at `GetProxyHttpHistory::class.asInputSchema()` (~line 2322) also reflects it (it derives from the same class).
**Warning signs:** SC5 passes via one MCP entry point but not the other; a test that only exercises the paginated path.

### Pitfall 5: Token-budget thresholds encrypted as if secrets
**What goes wrong:** Routing `tokenBudgetWarnThreshold`/`tokenBudgetHardCap` through `SecretCipher`.
**Why it happens:** Adjacent secret-handling code.
**How to avoid:** These are integers, not secrets — persist via `prefs.setInteger(...)` like the other passive-scanner settings (mirrors `customRedactionPatterns` being plaintext config in Phase 13). Only `anthropicApiKey` is encrypted.

### Pitfall 6: `ktlintCheck` standalone failure
**What goes wrong:** Running `./gradlew ktlintCheck` standalone fails on a pre-existing `generateBuildFlags` wiring defect (documented in MEMORY + STATE).
**How to avoid:** Build/verify with `./gradlew test` (per CLAUDE.md). `ktlintCheck` standalone is QUAL-05's job (Phase 18), not this phase.

## Code Examples

### §1. Anthropic Messages API — endpoint, headers, required body
```
POST https://api.anthropic.com/v1/messages
Headers:
  content-type: application/json
  anthropic-version: 2023-06-01            // stable
  x-api-key: <ANTHROPIC_API_KEY>

Required body fields: model, max_tokens, messages   (max_tokens is REQUIRED)
Top-level system field (NOT a message role).
```
Source: platform.claude.com/docs/en/api/messages [CITED]

### §2. Anthropic request JSON (this phase's shape — streaming optional, see Pitfall 1)
```json
{
  "model": "claude-sonnet-4-6",
  "max_tokens": 1024,
  "system": "You are a security assistant. ...",
  "messages": [
    { "role": "user", "content": "Hello, Claude" },
    { "role": "assistant", "content": "Hi! How can I help?" },
    { "role": "user", "content": "Explain this request" }
  ],
  "stream": false
}
```
Notes: `temperature` may be set (0.0 when `determinismMode`, else a default) — optional. Do NOT send `response_format` (OpenAI-only). Do NOT add `tools`/`tool_choice`/cache headers (deferred). Source: platform.claude.com/docs/en/api/messages [CITED]

### §3. Non-streaming success response (parse `content[].text` + `usage`)
```json
{
  "id": "msg_...",
  "type": "message",
  "role": "assistant",
  "content": [ { "type": "text", "text": "The answer is ..." } ],
  "model": "claude-sonnet-4-6",
  "stop_reason": "end_turn",
  "usage": { "input_tokens": 2095, "output_tokens": 503,
             "cache_creation_input_tokens": 0, "cache_read_input_tokens": 0 }
}
```
Extract: text = `content[0].text` (iterate `content[]`, concatenate `type=="text"` blocks); usage = `usage.input_tokens` / `usage.output_tokens`. Source: platform.claude.com/docs/en/api/messages [CITED]

### §4. SSE event sequence (if option-2 streaming is ever used) + 400 error body
```
event: message_start
data: {"type":"message_start","message":{...,"usage":{"input_tokens":25,"output_tokens":1}}}

event: content_block_start
data: {"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}

event: ping
data: {"type":"ping"}

event: content_block_delta
data: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"Hello"}}

event: content_block_stop
data: {"type":"content_block_stop","index":0}

event: message_delta
data: {"type":"message_delta","delta":{"stop_reason":"end_turn"},"usage":{"output_tokens":15}}  // CUMULATIVE

event: message_stop
data: {"type":"message_stop"}
```
- Input tokens: `message_start.message.usage.input_tokens` (+ `cache_creation_input_tokens`/`cache_read_input_tokens` when present).
- Output tokens: `message_delta.usage.output_tokens` — **cumulative** (take the last one).
- Handle unknown event types gracefully; `ping` and `error` may appear anytime.

**400 invalid-model error body (SC3 trigger):**
```json
{ "type": "error",
  "error": { "type": "invalid_request_error", "message": "...model: ... not found..." },
  "request_id": "req_..." }
```
An unrecognized model ID returns HTTP **400** `invalid_request_error`; the message contains "model". SC3 logic: `if (resp.statusCode == 400 && resp.body.contains("model", ignoreCase = true)) → IllegalStateException("Anthropic rejected the model ID — check Settings > Anthropic > Model")`. Source: platform.claude.com/docs/en/api/streaming + /api/errors [CITED]

### §5. Analog production path (OpenAiCompatibleConnection — SC2-compliant; copy this skeleton)
```kotlin
// backends/openai/OpenAiCompatibleBackend.kt:190-242 — the transport-routed send loop
// BUG-69-01: AI HTTP backends MUST go through MontoyaHttpTransport in production.
if (transport == null) {
    throw IllegalStateException(
        "MontoyaHttpTransport unavailable; AI HTTP backends require Burp's HTTP stack ...")
}
conversationHistory.addUser(text)
val messages = conversationHistory.snapshot()
val payload = mutableMapOf<String, Any?>("model" to model, "messages" to messages, "stream" to streaming, ...)
if (maxOutputTokens != null) payload["max_tokens"] = maxOutputTokens
val json = mapper.writeValueAsString(payload)
val resp = transport.post(endpointUrl, allHeaders, json, timeoutSeconds * 1000)   // ◄── only HTTP call
if (!resp.isSuccessful) { /* status-specific error message */ }
val node = mapper.readTree(resp.body)
val content = node.path("choices").path(0).path("message").path("content").asText()  // ◄── Anthropic: content[].text
extractUsage(node)?.let { lastTokenUsageRef.set(it) }
onChunk(content); onComplete(null)
```
For Anthropic: change endpoint to `https://api.anthropic.com/v1/messages`, headers to x-api-key/anthropic-version, drop the system entry from `messages` and pass `system` top-level, parse `content[].text`, and extract `usage.input_tokens`/`usage.output_tokens`. Source: codebase [VERIFIED: file read]

### §6. Encrypted key + settings wiring (mirror Perplexity)
```kotlin
// AgentSettings data class: add (with safe defaults so old prefs load)
val anthropicModel: String = "claude-sonnet-4-6",
val anthropicApiKey: String = "",
val tokenBudgetWarnThreshold: Int = 0,   // 0 = off
val tokenBudgetHardCap: Int = 0,         // 0 = off

// load(): decrypt on read
anthropicModel = prefs.getString(KEY_ANTHROPIC_MODEL).orEmpty().trim().ifBlank { "claude-sonnet-4-6" },
anthropicApiKey = cipher.decrypt(prefs.getString(KEY_ANTHROPIC_API_KEY).orEmpty().trim(), KEY_ANTHROPIC_API_KEY),
tokenBudgetWarnThreshold = (prefs.getInteger(KEY_TOKEN_BUDGET_WARN) ?: 0).coerceAtLeast(0),
tokenBudgetHardCap = (prefs.getInteger(KEY_TOKEN_BUDGET_CAP) ?: 0).coerceAtLeast(0),

// save(): encrypt on write (key) / plain integer (thresholds)
prefs.setString(KEY_ANTHROPIC_MODEL, settings.anthropicModel)
prefs.setString(KEY_ANTHROPIC_API_KEY, cipher.encrypt(settings.anthropicApiKey, KEY_ANTHROPIC_API_KEY))
prefs.setInteger(KEY_TOKEN_BUDGET_WARN, settings.tokenBudgetWarnThreshold.coerceAtLeast(0))
prefs.setInteger(KEY_TOKEN_BUDGET_CAP, settings.tokenBudgetHardCap.coerceAtLeast(0))

// companion KEY_* constants
private const val KEY_ANTHROPIC_MODEL = "anthropic.model"
private const val KEY_ANTHROPIC_API_KEY = "anthropic.apiKey"
private const val KEY_TOKEN_BUDGET_WARN = "tokenBudget.warnThreshold"
private const val KEY_TOKEN_BUDGET_CAP = "tokenBudget.hardCap"

// migrateToSchemaV4().secretKeys += KEY_ANTHROPIC_API_KEY   (idempotent, consistent with other backends)
```
Source: codebase AgentSettings.kt (perplexity pattern) [VERIFIED: file read]

### §7. TokenTracker session totals for the budget comparison
```kotlin
// Sum actual-when-available + estimate across all flows/backends (combined input + output)
fun currentSessionTokens(): Long =
    TokenTracker.snapshot().sumOf { it.inputTokensEstimated + it.outputTokensEstimated }
// inputTokensEstimated/outputTokensEstimated already = actual tokens + estimate for the
// chars that had no actual count (TokenTracker.snapshot(), lines 109-110). No extra logic needed.
```
Source: codebase TokenTracker.kt:91-112 [VERIFIED: file read]

### §8. Budget hook in ChatPanel.onComplete (after the existing TokenTracker.record)
```kotlin
// ChatPanel.kt:558 already calls TokenTracker.record(flow="chat", ..., inputTokensActual=usage?.inputTokens, ...)
// Immediately after, evaluate the budget on the EDT:
SwingUtilities.invokeLater {
    val warn = getSettings().tokenBudgetWarnThreshold
    val cap  = getSettings().tokenBudgetHardCap
    val used = currentSessionTokens()
    when {
        cap > 0 && used >= cap -> {
            budgetNotice.setMessage(SubtleNotice.Level.RISK,
                "Token budget reached (${fmt(used)}/${fmt(cap)}). Passive scanning paused; chat is still available.")
            passiveScanner.setBudgetPaused(true)
        }
        warn > 0 && used >= warn -> budgetNotice.setMessage(SubtleNotice.Level.WARN,
                "Token budget warning: ${fmt(used)} of ${fmt(warn)} tokens used this session.")
        else -> budgetNotice.hideNotice()
    }
}
```
Note: the passive scanner also calls `TokenTracker.record` at its own sites (PassiveAiScanner.kt:811/959/1550). For a fully centralized cap, evaluate the same budget check there too (or have the scanner consult `currentSessionTokens()` vs cap in `enqueueForScanCheck`). Minimal viable: gate enqueue on `budgetPaused`, and let the chat onComplete + a scanner-side check both flip it. Source: codebase ChatPanel.kt:546-608, SubtleNotice.kt:69 [VERIFIED: file read]

### §9. CAP-03 listener-port accessor + filter (verified Montoya API)
```kotlin
// burp.api.montoya.proxy.ProxyHttpRequestResponse  (Montoya 2026.2, javap-verified):
//   public abstract int listenerPort();          ◄── THE accessor
//   public abstract int port();  host(); url(); request(); response(); ...

// GetProxyHttpHistory (McpTools.kt:2719) — add the optional param:
@Serializable
data class GetProxyHttpHistory(
    override val count: Int = 5,
    override val offset: Int = 0,
    val includeUnpreprocessedResponse: Boolean = false,
    val listenerPort: Int? = null,            // CAP-03 — null/unset = all ports
) : Paginated

// In BOTH dispatch paths (mcpPaginatedTool ~line 649 AND manual decode ~line 1860):
val items = api.proxy().history()
val seq = orderedProxyHistory(items, context) { it.request()?.toString().orEmpty() }
    .let { s -> if (listenerPort != null) s.filter { it.listenerPort() == listenerPort } else s }
// empty result → mcpPaginatedTool yields "Reached end of items" / manual path yields empty join (NOT an error)
```
Source: javap of montoya-api-2026.2.jar + codebase McpTools.kt [VERIFIED: local jar decompile + file read]

## State of the Art

| Old Approach | Current Approach | When Changed | Impact |
|--------------|------------------|--------------|--------|
| `claude-3-5-sonnet-*` dated IDs | Dateless pinned snapshots `claude-sonnet-4-6` / `claude-opus-4-8` | Claude 4.6 generation | Aliases are now pinned snapshots, not evergreen pointers; the editable Model field handles future bumps |
| Assistant-message prefill to constrain output | Not supported on 4.6+ (400) | Sonnet 4.5+/4.6 | Don't prefill; the agent protocol uses full turns anyway |
| (proposed) Anthropic SDK | Hand-rolled Jackson + `MontoyaHttpTransport` | This project (ADR/#69) | SDK forbidden — embeds its own OkHttp client |

**Deprecated/outdated:**
- `claude-sonnet-4-20250514` / `claude-opus-4-20250514` are deprecated (retire 2026-06-15) — do NOT use as the default. `claude-sonnet-4-6` is current. [CITED: models overview]

## Assumptions Log

| # | Claim | Section | Risk if Wrong |
|---|-------|---------|---------------|
| A1 | The Anthropic invalid-model 400 body reliably contains the substring "model" (so the SC3 `body.contains("model")` trigger fires) | Code Examples §4 | LOW — docs show `invalid_request_error` for bad requests and model errors are a 400; if the exact phrasing varies, the SC3 test should assert against a representative body and the production check may also match `invalid_request_error` + model context. Confirm with one live 400 during SC1 UAT. |
| A2 | The `claude-api` skill referenced in the task brief is not installed on this machine; Anthropic details were grounded directly via platform.claude.com (the brief's explicit fallback) | (whole CAP-01) | NONE — the official docs are authoritative; the skill would have pointed to the same source. |
| A3 | Option-1 (buffered, single `onChunk`) satisfies SC1 because CONTEXT.md defines the SC1/SC2 proof as "streaming visible **through the proxy**" (i.e. the request appears in Burp history), not per-token UI animation | Pitfall 1 | LOW — if the maintainer wants visible token-by-token rendering, use option-2 (buffer then locally replay SSE deltas); still no OkHttp, still SC2-clean. Flag for the planner. |

**If the maintainer wants token-by-token rendering in SC1:** choose Pitfall-1 option 2 (parse the buffered SSE body and replay `text_delta`s as multiple `onChunk` calls). This is a discretionary UI nicety, not an SC requirement.

## Open Questions (RESOLVED)

> RESOLVED at plan-phase (2026-06-10): Q1 → single-chunk `stream:false` (14-01, matches all existing backends; SC1 = proxy-visible request). Q2 → pure AWT-free `BudgetGuard` consulted at the chat record site + scanner gate (14-02). Q3 (invalid-model 400 contains "model") → confirmed at SC1 HUMAN-UAT.

1. **Per-token streaming vs single-chunk render for SC1**
   - What we know: `MontoyaHttpTransport` buffers the full response; SC2 forbids OkHttp SSE.
   - What's unclear: whether the maintainer expects visible incremental rendering.
   - Recommendation: ship option-1 (single chunk, matches every other HTTP backend), note option-2 as discretionary. Either passes SC1 as defined (proxy-visible streaming request).

2. **Centralization of the budget check across chat + scanner**
   - What we know: `TokenTracker.record` fires in `ChatPanel.onComplete` and at 3 scanner sites; the pause gate lives on the scanner.
   - What's unclear: whether to evaluate the cap only in chat onComplete, only in the scanner enqueue, or both.
   - Recommendation: gate `enqueueForScanCheck` on `budgetPaused`, and evaluate `currentSessionTokens()` vs thresholds in BOTH `ChatPanel.onComplete` (to drive the banner + flip the pause) and at the scanner's record sites (so a scanner-driven overflow also flips the pause even if chat is idle). Keep the comparison in one small helper (`BudgetGuard`) to avoid drift.

## Environment Availability

| Dependency | Required By | Available | Version | Fallback |
|------------|------------|-----------|---------|----------|
| JDK 21 / `./gradlew` | Build + test | ✓ | toolchain | — |
| `montoya-api` (offline cache) | Compile + tests | ✓ | 2026.2 | — |
| jackson-databind / jackson-module-kotlin | Anthropic JSON | ✓ | 2.21.2 | — |
| kotlinx-serialization-json | MCP DTOs | ✓ | 1.8.1 | — |
| Live Anthropic API key | **SC1 human-UAT only** | ✗ (not in repo) | — | SC2/SC3/SC4/SC5 are fully automated; SC1 is the only item needing a live key (maintainer-supplied at UAT) |

**Missing dependencies with no fallback:** none for automated work.
**Missing dependencies with fallback:** the live Anthropic API key is needed only for the SC1 manual smoke test (streaming visible through Burp's proxy); all other SCs verify via `./gradlew test` with a mocked transport.

## Validation Architecture

### Test Framework
| Property | Value |
|----------|-------|
| Framework | JUnit 5 (Jupiter) + Mockito-Kotlin (`org.mockito.kotlin`) [VERIFIED: existing tests use `org.junit.jupiter.api.Test`, `org.mockito.kotlin.*`] |
| Config file | Gradle `test` task (`./gradlew test`) — no separate junit config |
| Quick run command | `./gradlew test --tests "com.six2dez.burp.aiagent.backends.anthropic.*"` |
| Full suite command | `./gradlew test` (NOT `ktlintCheck` — pre-existing generateBuildFlags defect, per CLAUDE.md/MEMORY) |

### Phase Requirements → Test Map
| SC | Behavior | Test Type | Automated Command | File Exists? |
|----|----------|-----------|-------------------|-------------|
| SC1 | Streaming chat works end-to-end with a live key (proxy-visible) | manual-UAT | — (human; needs live `x-api-key`) | ❌ human-only |
| SC2a | `AnthropicBackend.send()` issues HTTP **only** via `transport.post(...)` to `api.anthropic.com/v1/messages` | unit | `./gradlew test --tests "*AnthropicBackendTransportRoutingTest*"` (spy transport, `verify(transport).post(eq("https://api.anthropic.com/v1/messages"), any(), any(), any())`) | ❌ Wave 0 |
| SC2b | `send()` with `transport == null` fails fast (no OkHttp fallback) | unit | same file (`assertTrue(err.message.contains("MontoyaHttpTransport unavailable"))`) | ❌ Wave 0 |
| SC2c | `grep OkHttp AnthropicBackend.kt` returns empty | source-string guard | a test reading the .kt file asserts `!source.contains("okhttp3")` / `!source.contains("OkHttpClient")` (mirrors `HttpBackendTransportRoutingTest.buildClient KDoc` guard) | ❌ Wave 0 |
| SC3 | 400 body containing "model" → exact SC3 string | unit | `*AnthropicModelErrorTest*` (stub `transport.post` → `TransportResponse(400, "...model...not_found...", false)`; assert `onComplete` error message equals the SC3 string) | ❌ Wave 0 |
| SC4a | Crossing warn threshold shows WARN banner; crossing cap shows RISK + pauses scanner | unit | `*TokenBudgetGuardTest*` (drive `TokenTracker.record` past warn then cap; assert banner level + `passiveScanner.isBudgetPaused()`/enqueue no-op) | ❌ Wave 0 |
| SC4b | `enqueueForScanCheck` is a no-op when `budgetPaused` | unit | `*PassiveAiScannerBudgetPauseTest*` (set paused, call enqueue, verify executor not submitted) | ❌ Wave 0 |
| SC4c | warn=0 & cap=0 → never pauses, never banners | unit | same as SC4a with zero thresholds | ❌ Wave 0 |
| SC5 | `proxy_http_history` filtered by `listener_port` returns only that port; no match → empty (not error); unset → all | unit | `*ProxyHistoryListenerPortFilterTest*` (mock `api.proxy().history()` with items whose `listenerPort()` returns 8080/8081; assert filter both dispatch paths) | ❌ Wave 0 |
| (reg) | `AnthropicBackendFactory` is registered (ServiceLoader + fallback) and key round-trips encrypted | unit | extend `BackendRegistryTest` + an `AgentSettings` encryption round-trip test for `KEY_ANTHROPIC_API_KEY` | ⚠️ extend existing |

### Sampling Rate
- **Per task commit:** `./gradlew test --tests "*Anthropic*"` (or the specific new test class)
- **Per wave merge:** `./gradlew test` (full suite — 308+ tests must stay green)
- **Phase gate:** full `./gradlew test` green before `/gsd-verify-work`; SC1 manual smoke with a live key

### Wave 0 Gaps
- [ ] `backends/anthropic/AnthropicBackendTransportRoutingTest.kt` — SC2a/SC2b/SC2c (model on `HttpBackendTransportRoutingTest`, reuse its `stubTransportPost()` spy helper)
- [ ] `backends/anthropic/AnthropicModelErrorTest.kt` — SC3 (stub a 400 "model" body)
- [ ] `util/TokenBudgetGuardTest.kt` (or `ui/.../BudgetGuardTest.kt`) — SC4a/SC4c budget thresholds → banner level + pause decision (test the pure `BudgetGuard` helper, AWT-free)
- [ ] `scanner/PassiveAiScannerBudgetPauseTest.kt` — SC4b enqueue no-op when paused
- [ ] `mcp/tools/ProxyHistoryListenerPortFilterTest.kt` — SC5 (both dispatch paths)
- [ ] Extend `backends/BackendRegistryTest.kt` (Anthropic registered) + an `AgentSettings` round-trip test for the new encrypted key
- [ ] Framework install: none — JUnit 5 + Mockito-Kotlin already present

*Design tests AWT-free where possible: put the budget comparison in a pure `BudgetGuard` object (input: used/warn/cap → output: an enum {OFF, WARN, CAP}) so SC4 logic is testable without Swing, then ChatPanel just renders the enum. Mirrors Phase 13's AWT-free `SecretShapes`.*

## Security Domain

> `security_enforcement` is not set to `false` in config — included. This is a security tool handling API keys and proxied traffic; the relevant controls are inherited from Phases 7/12/13.

### Applicable ASVS Categories
| ASVS Category | Applies | Standard Control |
|---------------|---------|-----------------|
| V2 Authentication | yes | Anthropic `x-api-key` sent only over TLS via Burp's stack; never logged (Phase 12 rule). MCP listener auth unchanged. |
| V3 Session Management | no | No new sessions introduced (chat session state is existing). |
| V4 Access Control | yes | MCP `proxy_http_history` remains scope-gated (`McpScopeFilter.filterInScope` already applied in the manual path); the new `listener_port` filter is additive and does not widen exposure. |
| V5 Input Validation | yes | `listener_port` is a typed `Int?` (kotlinx-serialization rejects non-ints); thresholds coerced `>= 0`; model field is a plain string sent to Anthropic (server validates → 400). |
| V6 Cryptography | yes | API key at rest via `SecretCipher` (AES-256-GCM, Phase 12) — never hand-rolled. No new crypto. |
| V7 Error Handling / Logging | yes | Body-shape-only logging (no request content, no key) — mirror `OpenAiCompatibleConnection`'s `safeBodyPreview`. |

### Known Threat Patterns for this stack
| Pattern | STRIDE | Standard Mitigation |
|---------|--------|---------------------|
| API key leaked to logs/proxy-bypass | Information disclosure | All HTTP via `MontoyaHttpTransport` (SC2); shape-only debug logging; `SecretCipher` at rest |
| SDK embedding its own HTTP client bypasses Burp/redaction | Information disclosure (#69) | No Anthropic SDK; hand-rolled Jackson over the injected transport |
| Outbound to a non-Anthropic host (SSRF via configurable base URL) | Tampering / SSRF | Endpoint is a **fixed backend constant** (`api.anthropic.com`), NOT a user field — no Base URL row on the Anthropic card (UI-SPEC FLAG-14-02); narrower than the OpenAI-compat card by design |
| Budget bypass leaving scanner running past cap | Denial of (budget) control | `budgetPaused` gate evaluated at the enqueue choke point; per-process reset is intentional |
| Sensitive request content interpolated into the budget banner | Information disclosure | Banner shows token **counts only** (UI-SPEC) — never request content |

## Sources

### Primary (HIGH confidence)
- platform.claude.com/docs/en/api/messages — endpoint, headers, required fields, top-level `system`, response `usage` shape [CITED]
- platform.claude.com/docs/en/api/streaming — full SSE event sequence, `text_delta`, cumulative `message_delta.usage.output_tokens`, error events, basic-streaming response sample [CITED]
- platform.claude.com/docs/en/api/errors — error body shape (`{type:"error", error:{type,message}, request_id}`), 400 `invalid_request_error`, "Prefill not supported" for 4.6+ [CITED]
- platform.claude.com/docs/en/about-claude/models/overview — `claude-sonnet-4-6` current Sonnet ID/alias; Opus `claude-opus-4-8`; deprecations [VERIFIED, 2026-06-10]
- montoya-api 2026.2 jar (`javap burp.api.montoya.proxy.ProxyHttpRequestResponse`) — `listenerPort(): Int` accessor [VERIFIED: local decompile]
- Codebase (file reads): `OpenAiCompatibleBackend.kt`, `OpenAiCompatibleBackendFactory.kt`, `PerplexityBackendFactory.kt`, `BackendTypes.kt`, `BackendRegistry.kt`, `MontoyaHttpTransport.kt`, `HttpBackendSupport.kt` (+ nested `ConversationHistory`), `SecretCipher.kt`, `AgentSettings.kt`, `TokenTracker.kt`, `PassiveAiScanner.kt`, `ChatPanel.kt`, `SubtleNotice.kt`, `McpTools.kt`, `McpToolCatalog.kt`, `mcp/schema/serialization.kt`, `AgentSupervisor.kt`, `HttpBackendTransportRoutingTest.kt`, `build.gradle.kts`, `META-INF/services/...AiBackendFactory` [VERIFIED]

### Secondary (MEDIUM confidence)
- None — all claims grounded in primary sources above.

### Tertiary (LOW confidence)
- A1 (exact 400 model-error phrasing) — inferred from the documented 400 `invalid_request_error` category; confirm via one live 400 at SC1 UAT.

## Metadata

**Confidence breakdown:**
- Anthropic API contract (CAP-01): HIGH — official docs, exact field paths and SSE sequence quoted; model ID verified current.
- Backend integration / transport routing / SC2: HIGH — analog read line-by-line; transport-null fail-fast and spy-test harness confirmed.
- Token budget (CAP-04): HIGH — `TokenTracker.snapshot()` semantics and the exact `ChatPanel.onComplete` hook read directly; pause-gate design verified against `PassiveAiScanner.enqueueForScanCheck`.
- Listener-port filter (CAP-03): HIGH — `ProxyHttpRequestResponse.listenerPort()` verified in the exact Montoya jar the project compiles against; both dispatch paths located.
- Validation: HIGH — every automated SC maps to an existing analog test pattern; only SC1 is human-UAT.

**Research date:** 2026-06-10
**Valid until:** 2026-07-10 for the codebase/Montoya facts (stable); the Anthropic model alias should be re-confirmed if planning slips >30 days (aliases evolve, but the field is editable so risk is low).
