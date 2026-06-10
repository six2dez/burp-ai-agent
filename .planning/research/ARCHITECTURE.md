# Architecture Research

**Domain:** Burp Suite Extension — v0.9.0 integration points
**Researched:** 2026-06-10
**Confidence:** HIGH (all findings grounded in actual source files)

## System Overview

```
┌──────────────────────────────────────────────────────────────────────┐
│  Burp Suite JVM — Extension Host                                      │
│                                                                        │
│  ┌──────────────┐  ┌─────────────────┐  ┌───────────────────────┐    │
│  │  ChatPanel   │  │ PassiveAiScanner│  │  McpSupervisor        │    │
│  │  (UI / EDT)  │  │  (background)   │  │  (embedded server)    │    │
│  └──────┬───────┘  └────────┬────────┘  └──────────┬────────────┘    │
│         │                   │                       │                  │
│  ┌──────▼──────────────────▼───────────────────────▼────────────┐    │
│  │                    AgentSupervisor                             │    │
│  │  (backend lifecycle, sendChat, session/connection management)  │    │
│  └──────────────────────────┬──────────────────────────────────-─┘    │
│                             │ BackendRegistry (ServiceLoader)          │
│  ┌──────────────────────────▼─────────────────────────────────────┐   │
│  │  AiBackend implementations (AiBackend / AgentConnection)        │   │
│  │  HttpBackendSupport  ←  MontoyaHttpTransport  ←  CircuitBreaker │   │
│  │  [OpenAiCompatible, Perplexity, Ollama, NVIDIA, LmStudio, ...]  │   │
│  │  [NEW: AnthropicBackend]                                         │   │
│  └─────────────────────────────────────────────────────────────────┘   │
│                                                                          │
│  ┌──────────────────────────────────────────────────────────────────┐   │
│  │  Privacy layer: Redaction.apply()  ←  RedactionPolicy            │   │
│  │  ContextCollector (pre-flight)  |  McpToolContext.redactIfNeeded  │   │
│  │  [NEW: SecretTripwire check on final redacted payload]            │   │
│  └──────────────────────────────────────────────────────────────────┘   │
│                                                                          │
│  ┌──────────────────────────────────────────────────────────────────┐   │
│  │  Config: AgentSettings (data class) + AgentSettingsRepository    │   │
│  │  [NEW: encrypt/decrypt wrapper for secret preference keys]        │   │
│  └──────────────────────────────────────────────────────────────────┘   │
│                                                                          │
│  ┌──────────────────────────────────────────────────────────────────┐   │
│  │  MCP server (Ktor SSE + optional stdio bridge)                    │   │
│  │  McpTools.kt → per-category tool files (registerXxxTools)        │   │
│  │  McpToolContext.redactIfNeeded — boundary for outbound data       │   │
│  │  [NEW: McpClientManager — external MCP server connections]        │   │
│  └──────────────────────────────────────────────────────────────────┘   │
└──────────────────────────────────────────────────────────────────────────┘
```

## Component Responsibilities

| Component | File | Responsibility |
|-----------|------|----------------|
| `AgentSettings` | `config/AgentSettings.kt` | Immutable data class; all user-visible settings including every API key field |
| `AgentSettingsRepository` | `config/AgentSettings.kt` (same file) | Load/save to Burp `Preferences`; migration ladder; ALL secret encrypt/decrypt goes here |
| `BackendRegistry` | `backends/BackendRegistry.kt` | ServiceLoader discovery, external JAR loading, health-check dispatch |
| `OpenAiCompatibleBackend` | `backends/openai/OpenAiCompatibleBackend.kt` | Template HTTP backend; constructor-injected selectors; `launch()` → inner `Connection` class; `setHealthCheckTransport()` injection point |
| `HttpBackendSupport` | `backends/http/HttpBackendSupport.kt` | Shared retry policy, circuit breaker factory, OkHttp fallback for tests |
| `MontoyaHttpTransport` | `backends/http/MontoyaHttpTransport.kt` | Burp-proxy-aware HTTP execution; required for all production AI HTTP calls |
| `McpSupervisor` | `mcp/McpSupervisor.kt` | Lifecycle controller for the embedded MCP SERVER (start/stop/restart/takeover) |
| `KtorMcpServerManager` | `mcp/KtorMcpServerManager.kt` | Actual Ktor server spin-up; calls `Server.registerTools()` |
| `McpToolContext` | `mcp/McpToolContext.kt` | Data object carried into every MCP tool; owns `redactIfNeeded()` — the final outbound redaction gate |
| `McpTools.kt` | `mcp/tools/McpTools.kt` | Entry-point `registerTools()`; legacy `registerToolsLegacy()`; shared private helpers (~880–1270) |
| Per-category tool files | `mcp/tools/{History,Request,SiteMap,...}Tools.kt` | 8 files, each 8 lines — stub that delegates to `McpToolHandlers.registerToolHandler()` |
| `McpToolHandlers.kt` | `mcp/tools/McpToolHandlers.kt` | `McpToolRegistrations` name-lists; `registerToolHandler()` dispatcher; audit logging |
| `McpToolExecutor` (object) | `mcp/tools/McpTools.kt` line 1269 | Executes a tool by name string; input schema resolution |
| `ContextCollector` | `context/ContextCollector.kt` | Assembles HTTP context; calls `Redaction.apply()` for pre-flight; produces `contextJson` + `previewText` |
| `ChatPanel` | `ui/ChatPanel.kt` | Owns `sendMessage()`; builds `finalPrompt`; calls `supervisor.sendChat()` with the redacted `contextJson` |
| `PassiveAiScanner` | `scanner/PassiveAiScanner.kt` | Single 2480-line class: scan loop, dedup caches, batch analysis, prompt cache, issue creation, local heuristics |
| `SettingsPanel` | `ui/SettingsPanel.kt` | 2596-line orchestrator; already delegates tabs to `ui/panels/` but still owns wiring/save logic |

---

## C1: Anthropic Native Backend

### Integration Points

**New components:**
- `backends/anthropic/AnthropicBackend.kt` — implement `AiBackend` + inner `AnthropicConnection` implementing `AgentConnection`, `UsageAwareConnection`, `JsonModeCapable`
- `backends/anthropic/AnthropicBackendFactory.kt` — implement `AiBackendFactory`; one `create()` call
- `META-INF/services/com.six2dez.burp.aiagent.backends.AiBackendFactory` — add the factory class name

**Modified components:**
- `config/AgentSettings.kt` (data class only) — add fields: `anthropicModel: String`, `anthropicApiKey: String`, `anthropicTimeoutSeconds: Int`; use `""` defaults
- `config/AgentSettings.kt` (repository) — add load/save for the three new keys; add `anthropicApiKey` to the encrypted-field set (C2 dependency); increment `CURRENT_SETTINGS_SCHEMA_VERSION` to 4
- `backends/BackendRegistry.kt` — add `AnthropicBackendFactory()` to the hardcoded fallback list (the `if (builtIns.isEmpty())` branch)
- `ui/panels/BackendConfigPanel.kt` — add the Anthropic configuration section (URL, model, key, timeout)

### Data-flow changes

Anthropic Messages API shape differs from OpenAI: `POST /v1/messages`, body key `max_tokens` is required (not optional), response is `content[0].text`, token usage is `usage.input_tokens` / `usage.output_tokens`. The `payloadCustomizer` lambda in `OpenAiCompatibleBackend` cannot absorb these differences cleanly; implement a dedicated `AnthropicConnection.send()` that builds the Messages API payload directly. Reuse `MontoyaHttpTransport.post()` identically to how `OpenAiCompatibleConnection` uses it (line 242 of `OpenAiCompatibleBackend.kt`). Reuse `HttpBackendSupport.newCircuitBreaker()`, `HttpBackendSupport.retryDelayMs()`, and `HttpBackendSupport.isRetryableConnectionError()`.

**`healthCheck()`** follows the same `setHealthCheckTransport()` injection pattern as `OpenAiCompatibleBackend` (lines 56–62). Call `GET /v1/models` — Anthropic exposes this endpoint.

### Dependency

C2 (secret encryption) must be in place before C1 stores `anthropicApiKey`. The field inventory in C2 must include `"anthropic.apiKey"` from day one.

---

## C2: Secret Encryption at Rest

### Secret field inventory

All fields that store credentials in `AgentSettingsRepository`. Confirmed from `save()` and `saveMcpSettings()`:

| Preference key | `AgentSettings` field |
|---|---|
| `ollama.apiKey` | `ollamaApiKey` |
| `lmstudio.apiKey` | `lmStudioApiKey` |
| `openai.compat.apiKey` | `openAiCompatibleApiKey` |
| `nvidia.nim.apiKey` | `nvidiaNimApiKey` |
| `perplexity.apiKey` | `perplexityApiKey` |
| `mcp.token` | `McpSettings.token` |
| `mcp.tls.keystore.password` | `McpSettings.tlsKeystorePassword` |
| `anthropic.apiKey` (new, C1) | `anthropicApiKey` |

**Not secrets:** `hostAnonymizationSalt` (`privacy.host_salt`) is HKDF input — redact it in verbose mode but encrypting it is unnecessary and would break anonymization on migrate. Do not encrypt it.

### Integration points

**New component:**
- `config/SecretStore.kt` — thin wrapper providing `encrypt(plaintext: String): String` and `decrypt(ciphertext: String): String`; the ADR-resolved approach (passphrase-derived AES-GCM with HKDF from a per-install machine key stored in a separate `prefs` key) lives here. Keep this class under 100 lines; no dependencies on Montoya.

**Modified component:**
- `config/AgentSettings.kt` (repository) — the ONLY change site:
  - In `load()`: wrap every `prefs.getString(SECRET_KEY)` call with `SecretStore.decrypt()`
  - In `save()`: wrap every `prefs.setString(SECRET_KEY, value)` call with `SecretStore.encrypt()`
  - In `loadMcpSettings()` and `saveMcpSettings()`: same pattern for `mcp.token` and `mcp.tls.keystore.password`
  - In `migrateIfNeeded()`: add a `migrateToSchemaV4()` that reads each secret key in plaintext, re-writes it encrypted, bumps to version 4. This is the one-time migration.

**Migration contract:** `migrateToSchemaV4()` must be idempotent — if `decrypt()` of a stored value succeeds cleanly (recognizable by a version prefix or HMAC tag), skip re-encryption. If it fails (plaintext), encrypt and write. This avoids double-encryption on re-entry.

**Nothing else changes.** `AgentSettings` data class holds plaintext strings at runtime — the layer is purely at persistence I/O. The `AgentSettings` data object, `AgentSupervisor`, and all backends are not touched.

---

## C3: External MCP Client (Connecting to External Servers)

### Architecture decision

`McpSupervisor` owns the embedded MCP SERVER. The new MCP client lives alongside it as a peer, not inside it. `McpSupervisor` already has `setAiToolDependencies(supervisor, passiveScanner, backendRegistry)` — the client manager gets added to this dependency injection chain.

### New components

- `mcp/McpClientManager.kt` — manages a pool of `ExternalMcpClient` connections; lifecycle: `start(configs)` / `stop()` / `listTools()` / `callTool(serverName, toolName, args)`; each connection is a Ktor SSE or stdio child process
- `mcp/ExternalMcpServerConfig.kt` (data class) — `id: String`, `displayName: String`, `transport: McpClientTransport` (enum: `SSE` / `STDIO`), `url: String?`, `command: List<String>?`, `token: String?`, `enabled: Boolean`

### Config model

Add `externalMcpServers: List<ExternalMcpServerConfig>` to `McpSettings` (not to `AgentSettings` directly — it already nests `McpSettings`). Serialize as JSON blob under key `mcp.external.servers.v1` in `AgentSettingsRepository.saveMcpSettings()`. The existing `McpSettings.parseToolToggles()` pattern (JSON blob in a single prefs string) is the right model here.

### Surfacing external tools to chat/agent

`McpToolContext` gains an optional `externalMcpClient: McpClientManager?` field (default null). In `ChatPanel.buildToolContext()`, populate it when external MCP is configured. When an `AiTools.kt` tool handler enumerates available tools for the agent, it queries `context.externalMcpClient?.listTools()` and merges them into the preamble. Tool invocations named with a `server::tool` prefix are dispatched via `context.externalMcpClient?.callTool()`.

**Modified components:**
- `config/McpSettings.kt` — add `externalMcpServers: List<ExternalMcpServerConfig>` field
- `config/AgentSettings.kt` (repository) — serialize/deserialize in `loadMcpSettings()` / `saveMcpSettings()`
- `mcp/McpToolContext.kt` — add `externalMcpClient: McpClientManager? = null`
- `mcp/McpSupervisor.kt` — instantiate and start `McpClientManager`; add to `setAiToolDependencies()`
- `mcp/tools/AiTools.kt` — extend `registerAiTools()` to enumerate and proxy external tool calls
- `ui/panels/McpConfigPanel.kt` — add external servers CRUD UI

### What is NOT touched

`KtorMcpServerManager.kt` — the embedded server is unaffected. `McpTool.kt` / `McpToolHandlers.kt` — local tools are unaffected. `BackendRegistry` — this is not a backend; it's a tool source.

---

## C4: Pre-Send Secret Tripwire

### Exact hook point

The tripwire must run on the **final redacted payload**, after `Redaction.apply()` has run. There are two independent send paths:

**Path 1 — ChatPanel (interactive chat):**
`ChatPanel.sendMessage()` constructs `finalPrompt` at line 502–506 by joining `toolPreamble` and `prompt`. The `prompt` already incorporates `contextJson` which was redacted by `ContextCollector`. The hook belongs **after** `finalPrompt` is assembled and **before** `supervisor.sendChat()` is called (line 530). This is the earliest point where the complete, redacted payload is available as a single string.

**Path 2 — MCP tool path:**
Every MCP tool result is returned through `context.redactIfNeeded(execute())` inside `McpTool.kt` (line 45). The tripwire for this path belongs **inside `McpToolContext.redactIfNeeded()`**, after `Redaction.apply()` returns, wrapping the return value.

**Path 3 — PassiveAiScanner:**
`PassiveAiScanner.sendSingleAnalysis()` (line 1574) and `flushBatch()` (line 1473) call `supervisor.sendChat()` directly. Redaction of the HTTP context happens earlier in `doAnalysis()` via `Redaction.apply()`. The hook belongs after the prompt is assembled but before `supervisor.sendChat()` — the same structural position as Path 1.

### New component

- `redact/SecretTripwire.kt` — `check(payload: String, privacyMode: PrivacyMode): TripwireResult` where `TripwireResult` is a sealed class: `Clean` or `Violation(matches: List<String>)`. Contains the heuristic patterns: raw API key shapes (sk-..., Bearer tokens that survived redaction, base64 blobs that look like keys). Does not call `Redaction.apply()` again; only scans for post-redaction leakage.

### Modified components

- `mcp/McpToolContext.kt` — `redactIfNeeded()` calls `SecretTripwire.check(redacted, privacyMode)`; on `Violation`, logs to `api.logging().logToError()` and optionally returns a sanitized placeholder; does NOT throw (non-blocking by default; severity is configurable)
- `ui/ChatPanel.kt` — after `finalPrompt` assembly, before `supervisor.sendChat()`: call `SecretTripwire.check(finalPrompt, settings.privacyMode)` and surface any violations in the chat panel UI
- `scanner/PassiveAiScanner.kt` — in `sendSingleAnalysis()` and `flushBatch()` before each `supervisor.sendChat()` call

**Confidence check:** `McpToolContext.redactIfNeeded()` is the single gate for all MCP tool output (confirmed: every `mcpTool {}` lambda wraps its result in `context.redactIfNeeded(execute())`). The `ChatPanel` and `PassiveAiScanner` paths bypass that gate — they call `Redaction.apply()` independently — so they each need their own tripwire check.

---

## B1: Mega-file Split Seams

### McpTools.kt (2770 lines) — what remains vs what is already extracted

The 8 per-category files (`HistoryTools.kt`, `RequestTools.kt`, `SiteMapTools.kt`, etc.) currently contain only 8-line stubs that delegate to `McpToolHandlers.registerToolHandler()`. The actual tool implementations (the large `@Serializable` data classes and lambda bodies) are still in `McpTools.kt`. The existing architecture is:

```
McpTools.kt:registerTools()
    → registerHistoryTools(context)    [HistoryTools.kt, 8 lines — stub]
    → registerRequestTools(context)    [RequestTools.kt, 8 lines — stub]
    → ...
McpToolHandlers.kt:registerToolHandler()
    → McpToolExecutor.executeToolResult()  [still in McpTools.kt line 1269]
```

The pattern is already correct; it just needs the implementations moved. The split seams:

| Target file | Lines to move from McpTools.kt | Current location |
|---|---|---|
| `mcp/tools/UtilityTools.kt` | `url_encode`, `url_decode`, `base64_*`, `random_string`, `hash_compute`, `jwt_decode`, `decode_as`, `cookie_jar_get` tool data classes + handlers | Lines ~200–450 (estimate; cross-reference with `McpToolRegistrations.utility`) |
| `mcp/tools/HistoryTools.kt` | `proxy_http_history`, `proxy_history_annotate`, `response_body_search`, WebSocket history tools + handlers | Lines ~450–650 |
| `mcp/tools/SiteMapTools.kt` | `site_map`, `scope_check`, `scope_include/exclude` tools | Lines ~650–750 |
| `mcp/tools/RequestTools.kt` | `http1_request` through `comparer_send` tools (already in `registerToolsLegacy`) | Lines 75–880 (the legacy block) |
| `mcp/tools/IssueTools.kt` | `executeIssueCreate()` (line 881) and `issue_create` data class | Lines 881–962 |
| `mcp/tools/McpTools.kt` (keep) | `registerTools()` entry point; `findProxyHistoryMatch()`, `normalizeHttpRequest()`, `truncateIfNeeded()`, `ensureAllowedProxyHistoryCount()`, `orderedProxyHistory()`, `decodeJwt()`, `normalizeHashAlgorithm()`, `diffLines()`, `countOccurrences()`, `parseHighlightColor()`, `sanitizeHeaders()`, `maybeAnonymizeUrl()`, `resolveReportPath()`, `applyReplacements()`, `resolveAuditConfig()`, `getActiveEditor()`, `McpToolExecutor` object | Lines 963–2770 |

Shared private helpers (`findProxyHistoryMatch`, `normalizeHttpRequest`, etc.) remain in `McpTools.kt` until it is clear which single category owns them; do not duplicate them.

### SettingsPanel.kt (2596 lines) — split seams

The `ui/panels/` directory already contains 10 extracted panel files. What remains in `SettingsPanel.kt` is the orchestrator wiring that builds each tab, listens for save events, and calls `applySettings()`. The remaining bulk is:

- The `SettingsPanel` class itself (around line 60)
- `buildXxxTab()` factory methods that instantiate each panel — these are the seams
- The `save()` / `load()` plumbing that collects state from all sub-panels

The concrete split: extract remaining inline tab builders that have not yet been moved to `ui/panels/`. The exact targets require reading the full file to identify any `buildXxxTab()` functions beyond what is already delegated. Do not break the outer `SettingsPanel` class; keep it as the coordinator. Target size after split: under 400 lines.

### PassiveAiScanner.kt (2480 lines) — split seams

The class is a single `class PassiveAiScanner`. The natural split is by concern:

| Target file | Lines | Content |
|---|---|---|
| `scanner/PassiveScanDedup.kt` | ~300 | `shouldSkipRecentlyAnalyzedEndpoint()`, `buildEndpointCacheKey()`, `shouldSkipKnownResponseFingerprint()`, `buildResponseFingerprint()`, `stripDynamicValues()`, `endpointDedupWindowMs()`, `responseFingerprintDedupWindowMs()`, LRU cache helpers |
| `scanner/PassiveScanPromptBuilder.kt` | ~300 | `buildAnalysisPrompt()`, `buildBatchAnalysisPrompt()`, `sanitizeHeadersForPrompt()`, `buildCompactRequestBody()`, `buildCompactResponseBody()`, `looksLikeJson()`, `compactJsonBody()`, `compactHtmlBody()` |
| `scanner/PassiveScanResultHandler.kt` | ~400 | `handleAiResponse()`, `handleParsedAiIssues()`, `handleFinding()`, `recordFinding()`, `issueNameForPassive()`, `hasExistingIssue()`, `queueToActiveScanner()`, `mapTitleToVulnClass()` |
| `scanner/PassiveScanLocalChecks.kt` | ~300 | `runLocalChecks()`, `detectRequestSmuggling()`, `detectCsrf()`, `detectDeserialization()`, `detectUnrestrictedFileUpload()`, and other `detect*()` methods |
| `scanner/PassiveAiScanner.kt` (keep) | ~500 | Core class fields; `setEnabled()`, `enqueueForScanCheck()`, `analyzeInBackground()`, `doAnalysis()`, `flushBatch()`, `sendSingleAnalysis()`, `manualScan()`, `getStatus()`, `getLastFindings()`, `shutdown()`, `applyOptimizationSettings()`, prompt result cache I/O |

These are not top-level classes — they are private helper groups. The extracted files should be in the same package (`scanner`) and accessed as package-private (no `internal` boundary needed). Use Kotlin extension functions on `PassiveAiScanner` where state access is needed, or pass state explicitly. The class itself stays in `PassiveAiScanner.kt` to avoid a rename that breaks existing references.

---

## Data Flows

### Chat send path (with C4 tripwire placement)

```
User types prompt
    ↓
ContextCollector.fromRequestResponses()
    → Redaction.apply()  ← RedactionPolicy
    → produces contextJson (redacted), previewText
        ↓
ContextPreviewDialog.confirm()  [shows redacted preview to user]
        ↓
ChatPanel.sendMessage()
    → buildContextPayload() / buildContextPayloadNoAgent()
    → assembles finalPrompt (toolPreamble + contextJson + userText)
    → [C4] SecretTripwire.check(finalPrompt, privacyMode)   ← NEW HOOK
    → supervisor.sendChat(finalPrompt, ...)
        ↓
AgentSupervisor → AgentConnection.send()
    → MontoyaHttpTransport.post(endpointUrl, headers, json, timeoutMs)
        ↓
AI provider
```

### MCP tool path (with C4 tripwire placement)

```
External AI agent → Ktor SSE endpoint
    ↓
McpToolHandlers.registerToolHandler() → McpToolExecutor.executeToolResult()
    ↓
Tool lambda: execute()  [reads Burp state via MontoyaApi]
    ↓
McpTool.mcpTool() wrapper:
    context.redactIfNeeded(execute())
        → Redaction.apply(raw, policy, hostSalt)
        → [C4] SecretTripwire.check(redacted, privacyMode)  ← NEW HOOK (inside redactIfNeeded)
        → returns redacted + tripwire-checked string
    ↓
context.limitOutput()
    ↓
CallToolResult → SSE response
```

### Secret persist path (C2 encrypt/decrypt boundary)

```
UI save button
    ↓
AgentSettingsRepository.save(settings)
    → for each secret field:
        SecretStore.encrypt(plaintext)  → prefs.setString(key, ciphertext)
    ↓
Burp Preferences (on-disk JNLP store)

[on load]
Burp Preferences
    ↓
AgentSettingsRepository.load()
    → for each secret field:
        SecretStore.decrypt(prefs.getString(key))  → plaintext
    → AgentSettings(plaintext fields)  ← only ever holds plaintext at runtime
```

### External MCP client path (C3)

```
McpSupervisor.setAiToolDependencies(supervisor, passiveScanner, backendRegistry)
    → also sets McpClientManager on KtorMcpServerManager
    ↓
McpClientManager.start(externalMcpServers from McpSettings)
    → for each enabled config: connect SSE or launch stdio subprocess
    ↓
ChatPanel.buildToolContext(settings, sessionId)
    → McpToolContext(externalMcpClient = mcpClientManager)
    ↓
AiTools.registerAiTools(context)
    → ai_backends_list tool enumerates: local tools + context.externalMcpClient?.listTools()
    ↓
Tool invocation dispatch in McpToolExecutor / AiTools:
    if toolId matches "server::toolName" format:
        context.externalMcpClient?.callTool(server, tool, args)
```

---

## Build Order (Dependency-Aware)

The items are not independent. The correct order:

### Phase 1 — C2 Secret field inventory + encryption wrapper

**Must go first.** C1 stores `anthropicApiKey`; the Anthropic key must be encrypted from day one. The migration ladder (`migrateToSchemaV4`) must exist before any new secret field is added.

1. Define `SecretStore.kt` with key derivation and AES-GCM implementation.
2. Add `migrateToSchemaV4()` to `AgentSettingsRepository.migrateIfNeeded()`.
3. Wrap all 7 existing secret preference keys with `encrypt`/`decrypt` in `load()`, `save()`, `loadMcpSettings()`, `saveMcpSettings()`.
4. Increment `CURRENT_SETTINGS_SCHEMA_VERSION` to 4.
5. Write unit tests for round-trip and migration path.

### Phase 2 — C1 Anthropic backend

**Depends on Phase 1.** Add `anthropicApiKey` to `AgentSettings`, serialize with `SecretStore.encrypt()`, implement `AnthropicBackend.kt` + `AnthropicBackendFactory.kt`, register in `META-INF/services` and fallback list, add UI section in `BackendConfigPanel.kt`.

### Phase 3 — C4 Secret tripwire

**Depends on Phase 1 (needs the encryption migration to be complete so existing keys are no longer plaintext in prefs, making the tripwire's post-redaction check meaningful) and benefits from C2 being done. Does NOT depend on C1.**

1. Implement `SecretTripwire.kt` with post-redaction pattern set.
2. Hook into `McpToolContext.redactIfNeeded()`.
3. Hook into `ChatPanel.sendMessage()` after `finalPrompt` assembly.
4. Hook into `PassiveAiScanner.sendSingleAnalysis()` and `flushBatch()`.
5. Decide on blocking vs logging-only behavior (recommend: log + UI warning, non-blocking for MVP).

### Phase 4 — C3 External MCP client

**Independent of C1/C4. Depends on C2 only if the external server tokens need to be encrypted (they should — add them to the secret field set in Phase 1).**

1. `ExternalMcpServerConfig.kt` data class.
2. `McpClientManager.kt` with SSE and stdio transports.
3. `McpSettings` + `AgentSettingsRepository` changes (serialize config list).
4. `McpToolContext` extension + `AiTools.kt` proxy tool registration.
5. `McpConfigPanel.kt` CRUD UI.

### Phase 5 — B1 Mega-file split

**Independent of all C-items. Safe to do in parallel with Phase 2–4 IF on a separate branch.** Recommended order: `McpTools.kt` first (pure refactor, no behaviour change), then `PassiveAiScanner.kt` (higher regression risk, needs tests), then `SettingsPanel.kt` (lowest risk as panels already exist).

---

## Anti-Patterns

### Anti-Pattern 1: Encrypting secrets in AgentSettings data class

**What:** Storing `encryptedApiKey: String` fields in `AgentSettings`; decrypting on first access.
**Why:** `AgentSettings` is an immutable snapshot passed around freely. Mixing ciphertext into it means every consumer must know to decrypt. It also makes `copy()` unsafe (copies ciphertext).
**Do instead:** Keep `AgentSettings` plaintext at runtime. Encrypt/decrypt exclusively in `AgentSettingsRepository.save()` and `load()` — that is the only persistence boundary.

### Anti-Pattern 2: Placing the C4 tripwire before redaction

**What:** Checking for secrets in the raw, pre-redaction payload.
**Why:** This fires false positives on every API key that `Redaction.apply()` would have caught anyway. The value of the tripwire is detecting what SURVIVES redaction.
**Do instead:** Hook after `Redaction.apply()` returns — in `redactIfNeeded()` return path and after `finalPrompt` assembly in `ChatPanel`.

### Anti-Pattern 3: Putting McpClientManager inside McpSupervisor

**What:** Making `McpSupervisor` manage both the embedded server AND external client connections.
**Why:** `McpSupervisor` is already responsible for server lifecycle, restart policy, bind-conflict takeover, and stdio bridge. Adding client pooling makes it a god class.
**Do instead:** `McpClientManager` is a peer, initialized alongside `McpSupervisor` in `BurpAiAgentExtension.kt` and injected into `McpToolContext` via the existing `setAiToolDependencies()` pathway.

### Anti-Pattern 4: Putting all Anthropic tools in McpTools.kt's legacy block

**What:** Adding the Anthropic backend registration to `registerToolsLegacy()`.
**Why:** The legacy block is dead code — it exists for reference only. The Anthropic backend is a `ServiceLoader`-discovered `AiBackend`, not an MCP tool registration.
**Do instead:** Register via `META-INF/services` + the fallback list in `BackendRegistry.reload()`.

### Anti-Pattern 5: Splitting PassiveAiScanner before adding C4 tripwire hooks

**What:** Splitting `PassiveAiScanner.kt` in the same PR that adds C4 hooks inside it.
**Why:** The C4 hooks land in `sendSingleAnalysis()` and `flushBatch()` — methods that will move during the split. Doing both at once creates a large, hard-to-review diff.
**Do instead:** Land C4 hooks first (Phase 3), then execute the split (Phase 5) as a pure refactor with no behaviour change.

---

## Integration Boundaries

| Boundary | Communication | Notes |
|---|---|---|
| `AgentSettingsRepository` ↔ `SecretStore` | Direct call; no interface needed | `SecretStore` is a pure utility object; no Montoya API dependency |
| `AnthropicBackend` ↔ `MontoyaHttpTransport` | Injected via `BackendLaunchConfig.transport` (same as `OpenAiCompatibleBackend`) | `transport == null` must throw `IllegalStateException` on the production path |
| `McpClientManager` ↔ `McpToolContext` | Optional field `externalMcpClient: McpClientManager?` | Null-safe; external tools are additive, not required |
| `SecretTripwire` ↔ `McpToolContext.redactIfNeeded()` | Direct call inside the function body; no interface | Side effect: log to `api.logging().logToError()`; the context already holds `api` |
| `ChatPanel` ↔ `SecretTripwire` | Direct call before `supervisor.sendChat()` | `settings.privacyMode` is already in scope |
| `McpTools.kt` ↔ per-category files | Package-internal `internal fun Server.registerXxxTools()` — already the pattern | Move implementations into the stubs; stubs grow to full size; `McpTools.kt` shrinks |

## Sources

- Grounded analysis of actual source files; no external documentation consulted
- `OpenAiCompatibleBackend.kt` — canonical HTTP backend template (lines 24–387)
- `AgentSettings.kt` — complete secret field inventory from `save()` and `saveMcpSettings()` (lines 481–631, 1156–1186)
- `McpToolContext.kt` — `redactIfNeeded()` as the outbound redaction gate (lines 53–57)
- `McpTool.kt` — `mcpTool {}` wrappers confirm every tool result passes through `redactIfNeeded` (lines 27–48)
- `ChatPanel.kt` — `sendMessage()` pre-send path showing `finalPrompt` assembly at lines 502–506 and `supervisor.sendChat()` at line 530
- `BackendRegistry.kt` — `ServiceLoader` + fallback list pattern (lines 35–85)
- `McpSupervisor.kt` — server-only lifecycle; `setAiToolDependencies()` injection point (lines 71–77)
- `McpToolHandlers.kt` — `McpToolRegistrations` name-lists and dispatcher; confirms per-category stubs are 8-line placeholders
- `PassiveAiScanner.kt` — method index confirms `sendSingleAnalysis()` at line 1574, `flushBatch()` at line 1473

---
*Architecture research for: Burp AI Agent v0.9.0 integration points*
*Researched: 2026-06-10*
