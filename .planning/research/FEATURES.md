# Feature Research

**Domain:** Privacy-first Burp Suite AI extension — v0.9.0 new capabilities (C1–C5, C7)
**Researched:** 2026-06-10
**Confidence:** HIGH (C1 from official Anthropic docs), MEDIUM (C2, C3, C4, C7), MEDIUM (C5)

---

## Feature Landscape

### Table Stakes (Users Expect These)

Features users assume exist. Missing these = product feels incomplete.

| Feature | Why Expected | Complexity | Notes |
|---------|--------------|------------|-------|
| C1: Native Anthropic backend | Claude is the default AI for most security researchers; every other cloud backend is natively integrated | MEDIUM | Requires AiBackend impl, SSE streaming, tool_use loop, cache_control support |
| C2: Encrypted secrets at rest | No professional tool stores API keys in plaintext; expectation set by every password manager and IDE plugin | MEDIUM | Must be transparent — user should not notice unless they explicitly rotate the key or move the config |
| C4: Pre-send secret tripwire | Redaction pipeline already exists; users assume it covers AWS keys / GitHub tokens, not just HTTP headers | MEDIUM | Extends existing redaction + preview dialog; must never silently drop secrets |
| C5: Proxy-history listener port filter | Burp can bind multiple listeners on different ports; filtering MCP history by port is standard proxy-tool UX | LOW | Additive UI field in MCP proxy-history settings; filter applied inside existing proxy history handler |
| C7: Per-session token-budget guardrails | Any tool with metered API usage is expected to surface consumption and let users cap it | MEDIUM | TokenTracker already exists; needs warn threshold + hard cap + UI display |

### Differentiators (Competitive Advantage)

Features that set the product apart. Not required, but valued.

| Feature | Value Proposition | Complexity | Notes |
|---------|-------------------|------------|-------|
| C1: prompt caching via cache_control | Dramatically reduces cost for repeated scanning sessions with a fixed system prompt; no other Burp AI integration does this | LOW (additive) | cache_creation_input_tokens / cache_read_input_tokens surfaced in TokenTracker; breakpoints placed on system prompt + tools block |
| C3: External/custom MCP servers | Lets users connect any MCP-compatible tool (browser automation, custom internal APIs, Nuclei runners) to the agent loop without building a Burp extension | HIGH | New subsystem: MCP client role in addition to current MCP server role; tool discovery, registration, and forwarding to agent |
| C2: Per-profile key isolation | Different Burp projects can use different API keys without global config; supports team-shared machines | LOW (additive once encryption exists) | Scoped to project preferences, unlocked per session |
| C7: Cost-capped scanning modes | Agent stops or warns before burning through a budget in a long passive-scan run; privacy-first tools should also be cost-aware | LOW (additive once tracking exists) | Hard cap = no accidental $50 scan sessions |

### Anti-Features (Things to Deliberately NOT Do for a Privacy-First Tool)

These are patterns that seem helpful but directly violate the core value (privacy + auditability) or create more problems than they solve.

| Anti-Feature | Why Requested | Why Problematic | Alternative |
|--------------|---------------|-----------------|-------------|
| Auto-send context to Anthropic without redaction | Native backend is convenient; users may expect same "just works" behavior as CLI backends | Violates the non-negotiable: no data exfiltration without user-controlled redaction pass. Anthropic API has no SSE fallback for redaction — it must happen in-process first | Apply full redaction pipeline before every Messages API call, same as all other backends |
| Persist API keys / TLS passwords in plaintext Burp preferences | Simplest implementation path; what v0.8.0 already does for TLS keystore password | A Burp preferences file is world-readable in many setups; a compromised Burp profile = credential exfiltration | Encrypt with OS-keychain-derived key or passphrase-derived key (AES-256 + PBKDF2); store only the ciphertext in preferences |
| Store the master passphrase (C2 fallback) in memory beyond session unlock | Convenience: users hate typing passwords | If the JVM heap is dumped or attached by a debugger, the passphrase is trivially recoverable | Hold passphrase as a `CharArray`, zero it immediately after key derivation; never store as `String` (interned, GC non-deterministic) |
| Auto-register all tools from external MCP servers (C3) into Unsafe mode | Power-user appeal: "connect any server and get everything" | External MCP servers are an untrusted supply chain; auto-enabling their tools bypasses the Unsafe Mode master switch that protects against unintended HTTP mutations | Require explicit per-tool or per-server enable in settings; display server-declared tool descriptions before activation |
| Secret tripwire bypass via allowlist without confirmation (C4) | Developer workflow: test tokens that look like real secrets | Once an allowlist entry is set, the tripwire is silently skipped; a real secret could be allowlisted by mistake | Require explicit per-allowlist confirmation in UI; log allowlist use in audit log; allowlisted items show in context-preview dialog with a visual flag |
| Expose cache_creation costs without displaying total cost (C1) | Partial transparency | cache_creation_input_tokens are 1.25–2× base price; showing only output_tokens misleads users about actual spend | Show all four usage fields: input_tokens + cache_creation_input_tokens + cache_read_input_tokens + output_tokens; label clearly in TokenTracker |
| Per-session token budget implemented as soft-warn-only (C7) | Less disruptive UX | A warn-only cap still lets a runaway scan exhaust a monthly budget overnight | Offer both: a warn threshold (yellow) and a hard stop threshold (red) that blocks new requests in the session |

---

## Feature Deep-Dives

### C1: Native Anthropic Messages API Backend

**Sources:** Official Anthropic Messages API docs (platform.claude.com), prompt caching docs — HIGH confidence.

#### Request / Response Shape

The Messages API endpoint is `POST https://api.anthropic.com/v1/messages`.

Required fields:
- `model` (string) — e.g. `"claude-opus-4-6"`, `"claude-sonnet-4-6"`, `"claude-haiku-4-5"`
- `max_tokens` (integer) — hard ceiling on generated tokens; model may stop earlier at `end_turn`
- `messages` (array) — alternating `user` / `assistant` turns

Key optional fields:
- `system` — either a plain string or an array of `TextBlockParam` objects (the array form is required to attach `cache_control`)
- `stream` (boolean) — set `true` for SSE streaming
- `tools` (array) — tool definitions for client-executed tool use
- `tool_choice` — force specific tool or `{"type":"auto"}`
- `temperature` — 0.0–1.0; clamp to 0 in Determinism mode
- `stop_sequences` — array of custom stop strings
- `thinking` — extended thinking config (`{"type":"enabled","budget_tokens":N}`)

Required HTTP headers:
- `x-api-key: <key>`
- `anthropic-version: 2023-06-01`
- `content-type: application/json`

#### Streaming SSE Event Sequence (complete)

When `stream: true`, the server sends newline-delimited `data:` events. The full ordered sequence per response is:

```
1. message_start
   {"type":"message_start","message":{"id":"msg_...","type":"message","role":"assistant","content":[],"model":"claude-opus-4-6","stop_reason":null,"usage":{"input_tokens":N,"cache_creation_input_tokens":N,"cache_read_input_tokens":N,"output_tokens":0}}}

2. content_block_start  (once per content block, index=0,1,2,...)
   {"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}
   — OR for a tool_use block:
   {"type":"content_block_start","index":0,"content_block":{"type":"tool_use","id":"toolu_...","name":"tool_name","input":{}}}

3. content_block_delta  (repeated until block complete)
   Text block:    {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"chunk"}}
   Tool block:    {"type":"content_block_delta","index":0,"delta":{"type":"input_json_delta","partial_json":"{\"key\":"}}

4. content_block_stop
   {"type":"content_block_stop","index":0}

5. message_delta  (once per response, after all content blocks)
   {"type":"message_delta","delta":{"stop_reason":"end_turn","stop_sequence":null},"usage":{"output_tokens":N}}

6. message_stop
   {"type":"message_stop"}
```

For a tool_use response, `stop_reason` in `message_delta` is `"tool_use"`, not `"end_turn"`.
Partial tool inputs arrive as `input_json_delta` events; concatenate `partial_json` strings to reconstruct the full JSON object.

#### Stop Reasons

| Value | Meaning |
|-------|---------|
| `"end_turn"` | Natural stop — extract the text response |
| `"tool_use"` | Model requested one or more tools — drive the agentic loop |
| `"max_tokens"` | Hard ceiling hit — consider increasing or warning user |
| `"stop_sequence"` | Custom stop string matched |
| `"pause_turn"` | Server-executed tool hit iteration limit — re-send to continue |
| `"refusal"` | Policy violation — log and surface to user |

#### Tool Use / Agentic Loop

The canonical agentic loop for client-executed tools:

```
while stop_reason == "tool_use":
    for each tool_use block in response.content:
        result = execute(tool_use.name, tool_use.input)
        append tool_result block to next user message
    send new request with appended tool_result user message
```

The `tool_result` block structure sent back:
```json
{"type":"tool_result","tool_use_id":"toolu_...","content":"<result string or array>","is_error":false}
```

#### System Prompt and cache_control Breakpoints

To cache the system prompt (prevents re-counting tokens on every turn in a long session):

```json
{
  "system": [
    {
      "type": "text",
      "text": "<full system prompt text>",
      "cache_control": {"type": "ephemeral"}
    }
  ]
}
```

`cache_control` can also be placed on tool definitions and on user message content blocks. The marker must appear on the **last block that stays stable across requests** — changing content after a cache_control marker breaks the prefix match and causes a cache miss (cache write cost incurred instead of read).

**Cache TTL:** default 5 minutes (`{"type":"ephemeral"}`); extended 1 hour (`{"type":"ephemeral","ttl":"1h"}` — 2× write cost, 0.1× read cost).

**Minimum cacheable tokens by model:**
- claude-sonnet-4-6, claude-opus-4-6, claude-opus-4-8: 1024 tokens
- claude-haiku-4-5: 2048 tokens

If the prefix is shorter than the minimum, no cache entry is written (no error returned).

**Pre-warming:** Send a request with `max_tokens: 0` to populate the cache without generating output. Useful for loading the security-analysis system prompt before the first user turn.

#### Token Counting Fields

All four fields appear in the response `usage` object and in the `message_start` SSE event:

| Field | Meaning |
|-------|---------|
| `input_tokens` | Tokens after the last cache breakpoint (not cached) |
| `cache_creation_input_tokens` | Tokens written to cache this request (1.25–2× cost) |
| `cache_read_input_tokens` | Tokens read from cache this request (0.1× cost) |
| `output_tokens` | Tokens in the generated response |

All four must be exposed in the TokenTracker to give users an accurate cost picture.

#### Current Model IDs (as of 2026-06-10)

| Model ID | Notes |
|----------|-------|
| `claude-opus-4-6` | Frontier intelligence; 4096 min cache tokens |
| `claude-opus-4-7` | Frontier intelligence; 2048 min cache tokens |
| `claude-opus-4-8` | Frontier intelligence; 1024 min cache tokens |
| `claude-sonnet-4-6` | Best speed/intelligence balance; 1024 min cache tokens |
| `claude-haiku-4-5` | Fastest; 2048 min cache tokens |

Backend should accept a free-text model ID field so users are not limited to a hardcoded list.

**`max_tokens` semantics:** This is a ceiling, not a target. Set it conservatively for chat (e.g. 4096) and higher for scanner calls (e.g. 8192). Setting it to 0 is valid only for cache pre-warming.

#### Integration with Existing Components

- **AiBackend interface:** Implement `AnthropicBackend : AiBackend` using the HTTP backend path (not CLI). Reuse existing `HttpClient` + streaming pipeline.
- **Redaction pipeline:** Apply full STRICT/BALANCED/OFF redaction to the `messages` array contents before serializing the request body — identical to all other backends.
- **Context preview dialog:** Show redacted JSON before sending, same as auto-captured context.
- **TokenTracker:** Ingest all four usage fields from the streaming `message_start` event and the final `message_delta` event.
- **Determinism mode:** Clamp `temperature` to 0.

---

### C2: Encrypt API Keys / TLS Keystore Password at Rest

**Sources:** java-keyring (BSD), microsoft/credential-secure-storage-for-java (MIT, archived), security UX patterns — MEDIUM confidence.

#### Expected UX Patterns

**Option A — OS Keychain (transparent unlock):**

The OS (macOS Keychain, Windows Credential Manager, Linux libsecret/kwallet) holds the encryption key or the secret directly. The user is prompted by the OS on first access per session; subsequent reads in the same OS session are silent. This is what `1Password`, `IntelliJ IDEA`, and `AWS CLI` do.

- Pros: no master passphrase to remember or forget; hardware-backed on macOS (Secure Enclave); integrates with biometrics where OS supports it.
- Cons: non-portable (config cannot be copied to a new machine without re-entry); on Linux, behaviour depends on whether a keyring daemon is running (headless servers / CI = broken); JVM signing requirements on macOS/Windows for Keychain prompts to fire correctly (unsigned JARs may silently use a less-secure fallback).
- JVM library: `com.github.javakeyring:java-keyring:1.0.1` (BSD) or `com.microsoft:credential-secure-storage:1.0.0` (MIT, archived). The microsoft library is archived — prefer java-keyring.

**Option B — Master Passphrase (portable, explicit):**

User sets a master passphrase in Settings once. All secrets are AES-256-GCM encrypted with a key derived from the passphrase via PBKDF2 (or Argon2id). Ciphertext stored in Burp preferences or `~/.burp-ai-agent/`. On startup, the extension prompts once per session.

- Pros: fully portable; works headless; no OS-specific behaviour.
- Cons: user must remember yet another passphrase; passphrase loss = all secrets must be re-entered; passphrase must never be stored (only the derived key, in a zeroed `CharArray`, in memory for the session lifetime).

**Recommended approach (hybrid):**

Attempt OS keychain first; fall back to passphrase-derived encryption if the keychain is unavailable. This matches the pattern used by `git-credential-manager` and `docker credential helpers`. The key stored in the OS keychain should be an AES-256 key that encrypts the actual secrets in preferences — storing one key in the keychain avoids the multiple-prompt problem (one keychain entry vs. one per API key).

#### Unlock Timing

- Prompt at first use of a backend that requires a secret, not at startup.
- After successful unlock, hold the derived key in memory for the session (not persisted).
- "Session" = until Burp exits or the user explicitly locks in Settings.

#### What Happens With No Passphrase / No Keychain

If OS keychain is unavailable and no master passphrase has been set, secrets fall back to the current plaintext behavior (Burp preferences) **with a visible warning** in the Settings tab — never silently. The warning should say "API key is stored unencrypted" in a red label adjacent to the field.

#### Key Rotation / Migration

- Settings UI must have an explicit "Re-encrypt secrets" action that decrypts all stored secrets with the old key and re-encrypts with the new key, atomically.
- On first upgrade from v0.8.0 (plaintext), detect existing plaintext secrets and offer to migrate: decrypt from preferences (no-op), re-encrypt under the new key, replace in preferences.

#### Security Requirements (implementation)

- Never store passphrase as `String` — use `CharArray`; zero immediately after KDF call.
- Never store derived key beyond session lifetime.
- AES-256-GCM for encryption; random 96-bit nonce per encryption; store nonce alongside ciphertext.
- PBKDF2-HMAC-SHA256 with ≥ 600,000 iterations (NIST 2023 guidance) or Argon2id (memory-hard, preferred if Bouncy Castle is already on classpath).

---

### C3: External/Custom MCP Servers (Issue #41)

**Sources:** MCP specification 2025-11-25 (modelcontextprotocol.io) — HIGH confidence.

#### How MCP Client Discovery Works

The extension currently acts as an MCP **server**. For C3, it must also act as an MCP **client** — connecting outward to user-configured external servers and making their tools available to the internal agent loop.

**Registration model:**
Users add external MCP servers in Settings with:
- A display name
- Transport type: `stdio` (subprocess command + args) or `HTTP` (endpoint URL)
- For HTTP: authentication (bearer token header)
- Enable/disable toggle per server
- Per-tool enable/disable list (populated after connection)

**Connection / initialization handshake (MCP spec 2025-11-25):**

```
1. Client sends:  initialize { protocolVersion, capabilities, clientInfo }
2. Server sends:  initialize response { protocolVersion, capabilities, serverInfo, instructions }
3. Client sends:  notifications/initialized
4. Client sends:  tools/list {} 
5. Server sends:  tools/list response { tools: [{name, description, inputSchema}] }
```

The `capabilities.tools` presence in the server's initialize response confirms the server exposes tools. After `tools/list`, the client has the full tool manifest.

**Tool forwarding to agent:**
External tools are merged into the `tools` array sent to the AI backend. When the AI calls one, the extension routes the `tool_use` block to the appropriate external MCP server via `tools/call`, waits for the result, and injects the `tool_result` into the conversation — transparent to the AI.

**Transport details:**

- **stdio:** Extension spawns the subprocess (same lifecycle model as `AgentSupervisor`). JSON-RPC messages as newline-delimited UTF-8 on stdin/stdout. The existing `AgentSupervisor` pattern is directly reusable.
- **Streamable HTTP (current MCP standard):** Single endpoint supporting POST + optional SSE. Client must include `Accept: application/json, text/event-stream` on POSTs; must include `MCP-Protocol-Version: 2025-11-25` header; follow `MCP-Session-Id` from initialize response. Origin validation is the server's responsibility.
- **Legacy HTTP+SSE (deprecated, backward compat):** GET for SSE stream + POST endpoint. Detect by attempting POST to the configured URL; if 404/405, fall back to GET for the SSE `endpoint` event.

**Auth for HTTP MCP servers:**
Bearer token sent as `Authorization: Bearer <token>` header. No OAuth handshake needed unless the server declares it. The token is stored encrypted (C2).

#### What "Good" Looks Like

- Settings shows a list of configured external servers with status (connected / disconnected / error).
- On connect, tools/list is called; resulting tools appear in the MCP Tools tab with a server label and the server's declared description.
- Each external tool has an individual enable/disable toggle in the same UI as built-in tools.
- External tools are **never auto-enabled in Unsafe mode** — they require explicit activation.
- The agent's context preview dialog shows which external tools are enabled.
- If an external server disconnects mid-session, the extension surfaces an error rather than silently dropping tool results.

---

### C4: Pre-Send Secret Tripwire

**Sources:** Git secret scanning patterns (gitleaks, trufflehog), GitHub push protection UX — MEDIUM confidence.

#### Expected Behavior

The tripwire runs **after** the existing redaction pipeline and **before** sending. It is a second-pass scanner whose job is to catch high-entropy values that look like secrets but weren't covered by named redaction patterns (cookie: stripped; Authorization: stripped; but an AWS key in a JSON body might not be caught unless the body regex matches).

**What to scan:**
- The final serialized request body that would be sent to the AI backend (post-redaction)
- Scanner should check: high-entropy strings, known secret patterns (AWS AKIA*, GitHub `ghp_*`, Anthropic `sk-ant-*`, npm tokens, Stripe keys, generic 40-char hex that looks like a token)

**Severity / action model:**

| Severity | Example | Default action |
|----------|---------|----------------|
| HIGH | `AKIA[0-9A-Z]{16}` AWS key, `sk-ant-*` Anthropic key, `ghp_*` GitHub token | Block send; show warning in preview dialog; require explicit confirm or edit |
| MEDIUM | Generic high-entropy 32+ char string, `bearer [a-zA-Z0-9+/]{40,}` | Warn in preview dialog; allow send with one-click acknowledge |
| LOW | IP addresses, UUIDs, numeric tokens that might be session IDs | Optionally note; do not block |

**Integration with context-preview dialog:**
The existing preview dialog already shows redacted JSON. The tripwire findings appear as an inline list below the JSON, color-coded by severity. The Send button is disabled until HIGH findings are resolved (blocked or explicitly allowlisted).

**Allowlisting:**
- User can add a pattern or literal to an allowlist in Settings.
- Allowlisted matches are still shown in the preview dialog with a "Allowlisted" badge — they are never silently skipped.
- Every allowlist use is written to the audit log.

**False-positive UX:**
- "Mark as false positive" adds the specific match to the allowlist for the session only (not persisted) — no confirmation noise in subsequent sends during the same session.
- "Add to permanent allowlist" is a separate, more deliberate action in Settings.

#### Dependencies

- Existing redaction pipeline (tripwire runs on the post-redaction payload)
- Context preview dialog (findings displayed inline)
- Audit log (allowlist use, blocked sends)

---

### C5: Proxy-History Listener Port Filter (Issue #70)

**Sources:** Burp Montoya API proxy listener API, existing MCP proxy-history handler — MEDIUM confidence.

#### Expected Behavior

Burp can bind multiple listener ports (e.g. 8080 for general traffic, 8081 for mobile, 9090 for a specific service). The `proxy_http_history` MCP tool currently returns all history with body-size and content-type filters. Users need to restrict it to a specific listener port so the AI only sees traffic from the relevant proxy listener.

**User-facing change:**
- In MCP Settings (Proxy History section), add an optional "Listener port" text field (integer or blank for "all").
- The field accepts a single port (e.g. `8080`) or is left blank to retain current behavior.
- When set, the `proxy_http_history` tool filters items by the listener port they arrived on.

**Montoya API note:**
`ProxyHttpRequestResponse` exposes `listenerInterface()` which returns the interface+port string (e.g. `"127.0.0.1:8080"`). The filter should parse the port component and compare.

#### Complexity: LOW
Single field addition + filter in the existing proxy-history handler. No new subsystems.

---

### C7: Per-Session Token-Budget Guardrails

**Sources:** LLM cost control patterns, Claude Code token budget UX, TokenTracker existing component — MEDIUM confidence.

#### Expected Behavior

The TokenTracker already accumulates token counts per session. Guardrails add two configurable thresholds:

| Threshold | Default | Behavior |
|-----------|---------|----------|
| Warn threshold | 50,000 input tokens | Yellow warning banner in chat panel: "Session token budget at 80% (40k/50k)" |
| Hard cap | 100,000 input tokens | Blocks new requests in this session; shows red error banner; user must start a new session or raise the cap in Settings |

**Tiered warning pattern** (matches Claude Code behavior):
- 0–79%: silent
- 80–99%: yellow inline banner with current/max count
- 100%+: red banner, Send button disabled

**What counts toward the budget:**
- All four token fields: `input_tokens + cache_creation_input_tokens + cache_read_input_tokens + output_tokens`
- This prevents cache write costs from being invisible

**Settings UI:**
- "Per-session token warn threshold" (integer input, tokens)
- "Per-session token hard cap" (integer input, tokens; 0 = no cap)
- "Reset token count" action (manual reset without starting a new session)

**Interaction with passive scanner:**
The passive scanner runs in the background. If the hard cap is hit, the scanner should pause (not crash), log a message, and resume when the user resets the counter or starts a new session.

#### Dependencies

- TokenTracker (existing — needs warn/cap threshold checks and callback hooks)
- Chat panel UI (existing — needs banner component)
- Passive scanner lifecycle (existing — needs pause-on-cap hook)

---

## Feature Dependencies

```
C1 (Anthropic backend)
    └── requires ──> AiBackend interface (existing)
    └── requires ──> Redaction pipeline (existing, applied pre-send)
    └── requires ──> Context preview dialog (existing)
    └── enhances ──> C7 (TokenTracker: 4 token fields instead of 2)
    └── enhances ──> C2 (API key must be stored encrypted)

C2 (Encrypt secrets)
    └── requires ──> Burp preferences storage (existing)
    └── enhances ──> C3 (external MCP server auth tokens encrypted)
    └── enhances ──> C1 (Anthropic API key encrypted)

C3 (External MCP servers)
    └── requires ──> AgentSupervisor pattern (reuse for stdio subprocess)
    └── requires ──> MCP protocol lifecycle (initialize/tools/list/tools/call)
    └── requires ──> AiBackend tool forwarding (tool_use loop)
    └── requires ──> C2 (HTTP server bearer tokens stored encrypted)
    └── enhances ──> C4 (external tool outputs should also pass tripwire before agent sees them)

C4 (Secret tripwire)
    └── requires ──> Redaction pipeline (runs after it)
    └── requires ──> Context preview dialog (findings displayed in it)
    └── requires ──> Audit log (allowlist use logged)

C5 (Listener port filter)
    └── requires ──> MCP proxy-history handler (existing)
    └── requires ──> MCP Settings UI (additive field)

C7 (Token budget)
    └── requires ──> TokenTracker (existing)
    └── requires ──> Chat panel UI (banner component)
    └── requires ──> Passive scanner lifecycle (pause hook)
```

### Dependency Notes

- **C1 requires redaction pipeline:** The Anthropic backend must apply the full STRICT/BALANCED/OFF redaction pipeline to all message content before serializing — identical to every other HTTP backend. This is not optional.
- **C3 requires C2:** External MCP server bearer tokens must be stored encrypted; implementing C3 before C2 would mean storing new secrets in plaintext.
- **C4 runs after redaction:** The tripwire's job is to catch what redaction missed. Running it before redaction would produce false positives on Authorization headers that redaction would have stripped.
- **C1 enhances C7:** The four-field Anthropic token usage model (input / cache_creation / cache_read / output) makes the TokenTracker more informative for all backends.

---

## MVP Definition for v0.9.0

### Ship in v0.9.0 (this milestone)

- [x] C1: Native Anthropic backend — core team priority; high user demand; depends only on existing infrastructure
- [x] C2: Encrypt secrets at rest — security non-negotiable; plaintext keys is the current gap
- [x] C4: Pre-send secret tripwire — privacy pillar; extends existing preview dialog with minimal new subsystem
- [x] C5: Listener port filter — LOW complexity; closes a specific user-reported issue (#70)
- [x] C7: Per-session token budget — extends existing TokenTracker; LOW new code

### After Core Delivery (v0.9.x or v1.0.0)

- [ ] C3: External MCP servers — HIGH complexity new subsystem; requires C2 first; warrants its own phase or milestone
- [ ] C1 cache pre-warming — additive once C1 core is shipped; useful for scanner workloads

---

## Feature Prioritization Matrix

| Feature | User Value | Implementation Cost | Priority |
|---------|------------|---------------------|----------|
| C1: Anthropic native backend | HIGH | MEDIUM | P1 |
| C2: Encrypt secrets at rest | HIGH (security non-negotiable) | MEDIUM | P1 |
| C4: Secret tripwire | HIGH (privacy pillar) | MEDIUM | P1 |
| C5: Listener port filter | MEDIUM (issue #70, power user) | LOW | P1 |
| C7: Token budget guardrails | MEDIUM | MEDIUM | P1 |
| C3: External MCP servers | HIGH (differentiator) | HIGH | P2 |
| C1: cache pre-warming | LOW (optimization) | LOW | P2 |

---

## Sources

- [Anthropic Messages API](https://platform.claude.com/docs/en/api/messages) — HIGH confidence
- [Anthropic Prompt Caching](https://platform.claude.com/docs/en/docs/build-with-claude/prompt-caching) — HIGH confidence
- [Anthropic Tool Use: How Tool Use Works](https://platform.claude.com/docs/en/agents-and-tools/tool-use/how-tool-use-works) — HIGH confidence
- [MCP Specification 2025-11-25: Transports](https://modelcontextprotocol.io/specification/2025-11-25/basic/transports) — HIGH confidence
- [MCP Specification 2025-11-25: Lifecycle](https://modelcontextprotocol.io/specification/2025-11-25/basic/lifecycle) — HIGH confidence
- [java-keyring library](https://github.com/javakeyring/java-keyring) — MEDIUM confidence (BSD, cross-platform macOS/Windows/Linux)
- [microsoft/credential-secure-storage-for-java](https://github.com/microsoft/credential-secure-storage-for-java) — MEDIUM confidence (archived March 2025; MIT)
- [Cycode: Secret Scanning guide](https://cycode.com/blog/secret-scanning-guide/) — MEDIUM confidence
- [LLM Guardrails cost control patterns](https://margindash.com/llm-guardrails) — MEDIUM confidence
- [MindStudio: AI Agent Token Budget Management](https://www.mindstudio.ai/blog/ai-agent-token-budget-management-claude-code) — MEDIUM confidence

---
*Feature research for: Burp AI Agent v0.9.0 new capabilities (C1–C5, C7)*
*Researched: 2026-06-10*
