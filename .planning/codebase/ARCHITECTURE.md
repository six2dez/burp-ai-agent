<!-- refreshed: 2026-05-13 -->
# Architecture

**Analysis Date:** 2026-05-13

## System Overview

```text
┌─────────────────────────────────────────────────────────────────────────┐
│                     Burp Suite JVM (Montoya API)                        │
│  BurpAiAgentExtension  →  App.initialize()                              │
├──────────────┬──────────────┬──────────────┬──────────────┬─────────────┤
│   Swing UI   │  Context     │  Redaction   │  MCP Server  │  Scanners   │
│  `ui/`       │  `context/`  │  `redact/`   │  `mcp/`      │  `scanner/` │
└──────┬───────┴──────┬───────┴──────┬───────┴──────┬───────┴──────┬──────┘
       │              │              │              │               │
       ▼              ▼              ▼              ▼               ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                        AgentSupervisor                                  │
│  `supervisor/AgentSupervisor.kt`  (lifecycle: Idle → Starting → Running)│
└─────────────────────────────┬───────────────────────────────────────────┘
                              │
              ┌───────────────┴───────────────┐
              ▼                               ▼
┌─────────────────────────┐   ┌──────────────────────────────┐
│  HTTP Backend hierarchy │   │  CLI Backend hierarchy       │
│  `backends/http/`       │   │  `backends/cli/`             │
│  HttpBackendSupport     │   │  CliBackend                  │
│  OkHttp + CircuitBreaker│   │  NonInteractiveCliConnection │
│  OllamaBackend          │   │  ClaudeCliBackendFactory     │
│  LmStudioBackend        │   │  CodexCliBackendFactory      │
│  OpenAiCompatible       │   │  GeminiCliBackendFactory     │
│  NvidiaNim              │   │  OpenCodeCliBackendFactory   │
│  Perplexity             │   │  CopilotCliBackendFactory    │
│  BurpAiBackend          │   └──────────────────────────────┘
└─────────────────────────┘
              │
              ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                  AuditLogger + AiRequestLogger                          │
│  `audit/AuditLogger.kt`  (`~/.burp-ai-agent/audit.jsonl`, JSONL+hashes)│
└─────────────────────────────────────────────────────────────────────────┘
```

## Component Responsibilities

| Component | Responsibility | File |
|-----------|----------------|------|
| `BurpAiAgentExtension` | Montoya entry point; delegates to `App` | `src/main/kotlin/com/six2dez/burp/aiagent/BurpAiAgentExtension.kt` |
| `App` | Singleton wiring: instantiates and connects every subsystem; owns shutdown order | `src/main/kotlin/com/six2dez/burp/aiagent/App.kt` |
| `AgentSupervisor` | Backend lifecycle (Idle/Starting/Running), health-check loop, exponential-backoff auto-restart, `send()` / `sendChat()` dispatch, CLI PATH resolution | `src/main/kotlin/com/six2dez/burp/aiagent/supervisor/AgentSupervisor.kt` |
| `BackendRegistry` | ServiceLoader discovery, external JAR loading (`~/.burp-ai-agent/backends/`), health-check delegation | `src/main/kotlin/com/six2dez/burp/aiagent/backends/BackendRegistry.kt` |
| `AiBackend` / `AiBackendFactory` | SPI contract for all backends; factories registered in `META-INF/services` | `src/main/kotlin/com/six2dez/burp/aiagent/backends/BackendTypes.kt` |
| `AgentConnection` | Per-send contract (`send`, `isAlive`, `stop`); optionally implements `SessionAwareConnection`, `DiagnosableConnection`, `UsageAwareConnection` | `src/main/kotlin/com/six2dez/burp/aiagent/backends/BackendTypes.kt` |
| `HttpBackendSupport` | Shared OkHttp client pool, circuit breaker, eviction | `src/main/kotlin/com/six2dez/burp/aiagent/backends/http/HttpBackendSupport.kt` |
| `CliBackend` | Process launch, `NonInteractiveCliConnection` for embedded mode, PTY path for external terminal | `src/main/kotlin/com/six2dez/burp/aiagent/backends/cli/CliBackend.kt` |
| `Redaction` / `RedactionPolicy` | Pure-function pre-flight redaction; regex-based cookie/token/host stripping | `src/main/kotlin/com/six2dez/burp/aiagent/redact/Redaction.kt` |
| `ContextCollector` | Captures `HttpRequestResponse` or `AuditIssue` lists into schema-versioned `BurpContextEnvelope` JSON, applies redaction, builds preview text | `src/main/kotlin/com/six2dez/burp/aiagent/context/ContextCollector.kt` |
| `AuditLogger` | Append-only JSONL at `~/.burp-ai-agent/audit.jsonl`; SHA-256 prompt/response hashes; ZIP bundle export | `src/main/kotlin/com/six2dez/burp/aiagent/audit/AuditLogger.kt` |
| `AiRequestLogger` | In-memory rotating activity log (displayed in the AI Logger panel); optional rolling file persistence | `src/main/kotlin/com/six2dez/burp/aiagent/audit/AiRequestLogger.kt` |
| `PassiveAiScanner` | Background `ProxyResponseHandler`; rate-limited single-thread executor; LRU dedup; batch mode (3–5 reqs per AI call); confidence ≥ 85 threshold for issue creation | `src/main/kotlin/com/six2dez/burp/aiagent/scanner/PassiveAiScanner.kt` |
| `ActiveAiScanner` | AI-powered confirmation of vulnerabilities via test payloads; risk-level filter; `BatchAnalysisQueue` backpressure (default 2 000 max) | `src/main/kotlin/com/six2dez/burp/aiagent/scanner/ActiveAiScanner.kt` |
| `AiScanCheck` | Burp Pro `ScanCheck` integration; bridges Burp's active scanner with `ActiveAiScanner` | `src/main/kotlin/com/six2dez/burp/aiagent/scanner/AiScanCheck.kt` |
| `McpSupervisor` | MCP server lifecycle; restart policy; takeover/shutdown of pre-existing server on same port | `src/main/kotlin/com/six2dez/burp/aiagent/mcp/McpSupervisor.kt` |
| `KtorMcpServerManager` | Ktor/Netty server hosting MCP over SSE on `127.0.0.1:9876`; bearer-token auth; optional TLS; CORS policy | `src/main/kotlin/com/six2dez/burp/aiagent/mcp/KtorMcpServerManager.kt` |
| `McpStdioBridge` | Optional stdio bridge for MCP clients that cannot speak SSE | `src/main/kotlin/com/six2dez/burp/aiagent/mcp/McpStdioBridge.kt` |
| `McpToolCatalog` | Declarative catalogue of 53+ tools with `safe/unsafe` and `proOnly` gates | `src/main/kotlin/com/six2dez/burp/aiagent/mcp/McpToolCatalog.kt` |
| `MainTab` | Root Swing component registered as the `Custom AI Agent` suite tab; owns status timers | `src/main/kotlin/com/six2dez/burp/aiagent/ui/MainTab.kt` |
| `SettingsPanel` | Settings accordion (backend config, privacy, MCP, scanner, prompts, custom library) | `src/main/kotlin/com/six2dez/burp/aiagent/ui/SettingsPanel.kt` |
| `ChatPanel` | Chat-like streaming UI; multi-session transcripts; context attach/detach | `src/main/kotlin/com/six2dez/burp/aiagent/ui/ChatPanel.kt` |
| `UiActions` | Context menu item provider: right-click actions for Proxy, Repeater, Site Map, Scanner Issues | `src/main/kotlin/com/six2dez/burp/aiagent/ui/UiActions.kt` |
| `AgentSettings` / `AgentSettingsRepository` | Typed settings data class; persisted via Burp `Preferences` API as JSON | `src/main/kotlin/com/six2dez/burp/aiagent/config/AgentSettings.kt` |
| `PersistentPromptCache` | Disk-LRU cache at `~/.burp-ai-agent/cache/`; keyed by SHA-256 of redacted prompt; TTL configurable | `src/main/kotlin/com/six2dez/burp/aiagent/cache/PersistentPromptCache.kt` |
| `AgentProfileLoader` | Loads `.md` agent profiles from `~/.burp-ai-agent/AGENTS/`; hot-reloads on file change | `src/main/kotlin/com/six2dez/burp/aiagent/agents/AgentProfileLoader.kt` |
| `BountyPromptCatalog` / `BountyPromptLoader` | Loads structured prompt definitions from `AGENTS/` resources; resolves `[HTTP_*]` tags against captured context | `src/main/kotlin/com/six2dez/burp/aiagent/prompts/bountyprompt/` |
| `Alerting` | Outbound webhook dispatcher (Slack-style JSON); uses `MontoyaHttpTransport` when available | `src/main/kotlin/com/six2dez/burp/aiagent/alerts/Alerting.kt` |

## Pattern Overview

**Overall:** Layered plugin with a strict unidirectional dependency boundary enforced by package boundaries.

**Key Characteristics:**
- Every piece of data that leaves the plugin (to an AI backend or MCP client) passes through `Redaction.apply()` first.
- Backends are discovered and loaded at runtime via Java `ServiceLoader` — no compile-time coupling to `BackendRegistry`.
- Two independent supervisor objects manage lifecycle: `AgentSupervisor` (interactive backend) and `McpSupervisor` (embedded HTTP server). Both are shut down deterministically in `App.shutdown()` in the correct order.
- Swing EDT discipline: all UI mutations go through `SwingUtilities.invokeLater`. Non-UI work runs on `workerPool` (cached thread pool in `App`) or dedicated executors per component.
- Settings flow one way: `AgentSettingsRepository.load()` → `App.initialize()` → each subsystem's `applySettings()`. Settings are never mutated in-place.

## Layers

**Layer 1 — UI (Swing):**
- Purpose: Render tab, settings, chat, context menus; all user-visible surfaces.
- Location: `src/main/kotlin/com/six2dez/burp/aiagent/ui/`
- Contains: `MainTab`, `ChatPanel`, `SettingsPanel`, `BottomTabsPanel`, `UiActions`, `AiLoggerPanel`, reusable components in `ui/components/`, settings panels in `ui/panels/`.
- Depends on: Context, Config, Supervisor, MCP, Scanner (for status display only). Never depends on Redaction directly; calls `ContextCollector`.
- Used by: Burp's `userInterface().registerSuiteTab()` and `registerContextMenuItemsProvider()`.

**Layer 2 — Context Collection:**
- Purpose: Capture Montoya `HttpRequestResponse` / `AuditIssue` objects into a canonical JSON envelope.
- Location: `src/main/kotlin/com/six2dez/burp/aiagent/context/`
- Contains: `ContextCollector`, `ContextModels` (data classes: `ContextCapture`, `BurpContextEnvelope`, `HttpItem`, `AuditIssueItem`).
- Depends on: Redaction (calls `Redaction.apply()` inline during capture).
- Used by: UI (`UiActions`), `PassiveAiScanner`, `ActiveAiScanner`.

**Layer 3 — Redaction Pipeline:**
- Purpose: Pre-flight privacy transformation. Pure functions only; no I/O.
- Location: `src/main/kotlin/com/six2dez/burp/aiagent/redact/`
- Contains: `Redaction` (object with regex set), `RedactionPolicy` (data class), `PrivacyMode` (enum: STRICT / BALANCED / OFF).
- Depends on: Nothing in this codebase (pure Kotlin/JDK).
- Used by: `ContextCollector`, `PassiveAiScanner`, MCP tool output pre-processing, `AgentSupervisor.send()`.

**Layer 4 — Backend Adapters:**
- Purpose: Implement `AiBackend` / `AgentConnection` for each AI provider.
- Location: `src/main/kotlin/com/six2dez/burp/aiagent/backends/`
- Contains: `BackendTypes.kt` (interfaces and data classes), `BackendRegistry`, `BackendDiagnostics`, subdirectories per provider.
- Depends on: Config (for settings), `http/HttpBackendSupport` (shared OkHttp pool), `http/MontoyaHttpTransport` (thin wrapper that routes HTTP calls through Burp's HTTP engine).
- Used by: `AgentSupervisor`, `KtorMcpServerManager` (indirectly via `McpSupervisor`).

**Layer 5 — Supervisor:**
- Purpose: Own the running `AgentConnection`; manage lifecycle state machine; implement exponential-backoff restart; dispatch `send()` / `sendChat()` with audit wrapping.
- Location: `src/main/kotlin/com/six2dez/burp/aiagent/supervisor/`
- Contains: `AgentSupervisor`, `ChatSessionManager`.
- Depends on: Backend (via `BackendRegistry`), Audit, Config, Redaction (receives `PrivacyMode` from caller; does not call `Redaction` directly).
- Used by: UI, PassiveAiScanner, ActiveAiScanner, MCP tools.

**Layer 6 — Audit:**
- Purpose: Record all AI interactions; emit JSONL events; build repro bundles.
- Location: `src/main/kotlin/com/six2dez/burp/aiagent/audit/`
- Contains: `AuditLogger` (JSONL file sink, ZIP export), `AiRequestLogger` (in-memory activity ring buffer + optional rolling files), `Hashing` (SHA-256 helpers), `PromptBundle` (data class).
- Depends on: Nothing in this codebase.
- Used by: `AgentSupervisor`, `PassiveAiScanner`, `ActiveAiScanner`, `KtorMcpServerManager`.

**Layer 7 — Passive Scanner:**
- Purpose: Background analysis of proxy traffic; automatic issue creation.
- Location: `src/main/kotlin/com/six2dez/burp/aiagent/scanner/`
- Contains: `PassiveAiScanner`, `ActiveAiScanner`, `AiScanCheck`, `BatchAnalysisQueue`, `PayloadGenerator`, `AdaptivePayloadEngine`, `ResponseAnalyzer`, `ScanKnowledgeBase`, `InjectionPointExtractor`, `JsEndpointExtractor`, `IssueMarkerSupport`, `ScannerIssueSupport`, `ScannerUtils`.
- Depends on: Supervisor (to send prompts), Audit, Config, Redaction.
- Used by: `App` (registered with Burp's proxy and scanner APIs).

## Data Flow

### Interactive Chat (right-click → send)

1. User right-clicks in Proxy/Repeater/Site Map → `UiActions.requestResponseMenuItems()` (`src/main/kotlin/com/six2dez/burp/aiagent/ui/UiActions.kt`)
2. `ContextCollector.fromRequestResponses()` captures and redacts context (`src/main/kotlin/com/six2dez/burp/aiagent/context/ContextCollector.kt`)
3. `ContextPreviewDialog` displays redacted JSON to user before send (`src/main/kotlin/com/six2dez/burp/aiagent/ui/components/ContextPreviewDialog.kt`)
4. On confirm: `AgentSupervisor.sendChat()` dispatches prompt + context to the running `AgentConnection` (`src/main/kotlin/com/six2dez/burp/aiagent/supervisor/AgentSupervisor.kt`)
5. `AuditLogger.logEvent("prompt", bundle)` writes hash-stamped JSONL before send (`src/main/kotlin/com/six2dez/burp/aiagent/audit/AuditLogger.kt`)
6. `AgentConnection.send()` streams chunks back; `ChatPanel.onChunk()` appends to transcript (`src/main/kotlin/com/six2dez/burp/aiagent/ui/ChatPanel.kt`)
7. `AiRequestLogger.log(RESPONSE_COMPLETE)` records timing and character counts (`src/main/kotlin/com/six2dez/burp/aiagent/audit/AiRequestLogger.kt`)

### Passive Scanner Flow

1. `PassiveAiScanner` registered as Burp `ProxyResponseHandler`; intercepts every proxied response.
2. In-scope + content-type + size checks + rate-limit gate applied on the proxy thread.
3. Work item enqueued to single-threaded executor.
4. Redaction applied (`Redaction.apply()`) before prompt assembly.
5. `AgentSupervisor.send()` dispatches to running backend.
6. Response JSON parsed; if confidence ≥ 85 and no duplicate → `api.scanner().createIssue()`.

### MCP Tool Request Flow

1. External AI agent (Claude Desktop, Codex CLI) sends HTTP request to `127.0.0.1:9876/mcp` with bearer token.
2. `KtorMcpServerManager` validates token; routes to `McpToolHandlers.dispatch()`.
3. `McpRequestLimiter` enforces concurrency cap.
4. Tool handler reads live Burp state via `MontoyaApi` (proxy history, site map, scope, issues).
5. `ResponsePreprocessor` applies redaction to tool output before returning to client.
6. Unsafe tools (e.g. `http1_request`, `issue_create`) additionally require `unsafeModeEnabled = true`.

**State Management:**
- `AgentSupervisor` state is an `AtomicReference<AgentState>` (sealed class: Idle/Starting/Running); transitions are protected by `ReentrantLock`.
- `McpSupervisor` state is an `AtomicReference<McpServerState>`; restart attempts tracked with `AtomicInteger`.
- `AgentSettings` is immutable; loaded fresh from Burp `Preferences` each time `settingsRepo.load()` is called.

## Key Abstractions

**`AiBackend` / `AiBackendFactory` (SPI):**
- Purpose: Contract every AI provider must implement; factories registered in `META-INF/services`.
- Examples: `src/main/kotlin/com/six2dez/burp/aiagent/backends/ollama/OllamaBackendFactory.kt`, `src/main/kotlin/com/six2dez/burp/aiagent/backends/cli/ClaudeCliBackendFactory.kt`
- Pattern: Factory returns a backend; backend's `launch(BackendLaunchConfig)` returns a connection; connection's `send()` streams chunks via callbacks.

**`AgentConnection` (optional mix-in interfaces):**
- `SessionAwareConnection` — exposes `cliSessionId()` for CLI resume (e.g. `claude --resume`).
- `DiagnosableConnection` — exposes `exitCode()` and `lastOutputTail()` for crash diagnostics.
- `UsageAwareConnection` — exposes `lastTokenUsage()` for token accounting.
- `JsonModeCapable` — marker enabling JSON-mode in backends that support it.

**`RedactionPolicy` (data class):**
- Purpose: Encodes the three privacy switches (stripCookies, redactTokens, anonymizeHosts) independently of `PrivacyMode`. Allows callers to override individual flags without changing the mode enum.
- Examples: `src/main/kotlin/com/six2dez/burp/aiagent/redact/Redaction.kt`

**`BurpContextEnvelope` (schema-versioned):**
- Purpose: Stable JSON envelope sent to AI backends; schema-versioned (`schemaVersion: 1`); items sorted alphabetically in determinism mode.
- Examples: `src/main/kotlin/com/six2dez/burp/aiagent/context/ContextModels.kt`

**`BountyPromptDefinition` (structured prompts):**
- Purpose: Declarative prompt templates with `[HTTP_*]` tag substitution; output type determines whether result creates a Burp issue or displays in chat.
- Examples: `src/main/kotlin/com/six2dez/burp/aiagent/prompts/bountyprompt/`

## Entry Points

**Burp Extension Entry:**
- Location: `src/main/kotlin/com/six2dez/burp/aiagent/BurpAiAgentExtension.kt`
- Triggers: Burp loads the shadow JAR; calls `initialize(MontoyaApi)`.
- Responsibilities: Delegates entirely to `App.initialize(api)` and registers `App.shutdown()` as the unload handler.

**`App.initialize()`:**
- Location: `src/main/kotlin/com/six2dez/burp/aiagent/App.kt`
- Triggers: Called by `BurpAiAgentExtension.initialize()`.
- Responsibilities: Constructs all singletons in dependency order; wires cross-cutting references (e.g. `passiveAiScanner.activeScanner = activeAiScanner`); registers suite tab and context menu provider; registers `AiScanCheck` with Burp scanner (Pro only, failures swallowed gracefully).

**ServiceLoader SPI Entry:**
- Location: `src/main/resources/META-INF/services/com.six2dez.burp.aiagent.backends.AiBackendFactory`
- Triggers: `BackendRegistry.reload()` calls `ServiceLoader.load(AiBackendFactory::class.java)`.
- Responsibilities: Registers 10 built-in backend factories.

## Architectural Constraints

- **Threading:** Swing EDT for all UI mutations. Non-UI work on `App.workerPool` (cached), dedicated `SingleThreadExecutor` per component (`PassiveAiScanner`, `McpSupervisor`, `AgentSupervisor` monitor). CLI backends use `LinkedBlockingQueue` for output streaming.
- **Global state:** `App` is a Kotlin `object` singleton (module-level). `Redaction` is also an `object` (its host-mapping tables are cleared on `App.shutdown()`). `BackendDiagnostics` is a singleton with mutable function references set by `App`. `AuditLogger.globalEmitter` is a `@Volatile` static.
- **Circular imports:** None by design — layer boundary strictly prevents Scanner from importing UI, and UI from importing Scanner internals beyond status types.
- **Burp Pro gating:** `AiScanCheck` registration is wrapped in try/catch; failure is logged and swallowed. `AgentSupervisor.isAiEnabled()` gates the `burp-ai` backend only; all other backends are unaffected.
- **ServiceLoader invariant:** Adding a new backend requires only one new `AiBackend` implementation, one `AiBackendFactory`, and one SPI entry in `META-INF/services`. No changes to `BackendRegistry` or `AgentSupervisor`.

## Anti-Patterns

### Calling `Redaction.apply()` after the context leaves the plugin

**What happens:** If redaction is deferred to after `AgentSupervisor.send()` constructs the prompt, the raw traffic string has already been assembled and may be logged or transmitted before redaction runs.

**Why it's wrong:** ADR-5 mandates redaction pre-flight. The privacy guarantee is void if redaction happens at the sink rather than at the source.

**Do this instead:** Apply redaction inside `ContextCollector.fromRequestResponses()` or `fromAuditIssues()` before the `ContextCapture` is returned. For MCP tools, apply via `ResponsePreprocessor` before tool output is serialized. See `src/main/kotlin/com/six2dez/burp/aiagent/context/ContextCollector.kt` lines 52–54.

### Adding backend-specific logic to `AgentSupervisor.buildLaunchConfig()`

**What happens:** The `when (backendId)` block in `AgentSupervisor.buildLaunchConfig()` already has 12 arms. Adding more backend-specific config logic there tightly couples the supervisor to every backend.

**Why it's wrong:** New backends should be addable without touching `AgentSupervisor` (ADR-3).

**Do this instead:** Move backend-specific config resolution into the backend's own `launch(config: BackendLaunchConfig)` method, or into a helper function co-located with that backend's factory in `backends/<provider>/`.

### Mutating UI state from a non-EDT thread

**What happens:** Any call to `JLabel.setText()`, `JPanel.repaint()`, or similar Swing methods from a worker thread or backend callback thread.

**Why it's wrong:** Swing is single-threaded; non-EDT mutations cause intermittent rendering corruption and race conditions.

**Do this instead:** Wrap all UI mutations in `SwingUtilities.invokeLater { ... }`. Backend `onChunk` callbacks arrive on executor threads; always relay to EDT before touching a Swing component.

## Error Handling

**Strategy:** Fail-fast in pure layers (Redaction, ContextCollector); catch-and-log at system boundaries (Supervisor, MCP, Scanner, `App.safeShutdownStep()`).

**Patterns:**
- `App.shutdown()` uses `safeShutdownStep(name) { action() }` to isolate each subsystem shutdown; logs but does not rethrow.
- `AgentSupervisor.send()` calls `onComplete(Throwable)` on error — callers must never assume `onComplete(null)` is the only path.
- `BackendRegistry.healthCheck()` catches all exceptions and returns `HealthCheckResult.Unavailable`.
- `AiScanCheck` registration wrapped in try/catch for graceful Community-edition degradation.
- Circuit breaker (`backends/http/CircuitBreaker.kt`) blocks HTTP backends after 5 consecutive failures; resets after 30 s.

## Cross-Cutting Concerns

**Logging:** `api.logging().logToOutput()` / `logToError()` for Burp's output tab. `java.util.logging.Logger` in `ContextCollector`. SLF4J simple backend for Ktor/MCP SDK internals.

**Validation:** Input validation at the boundary of each public method (e.g. `require(config.command.isNotEmpty())` in `CliBackend.launch()`). No validation framework used.

**Authentication:** MCP bearer token generated with `SecureRandom` at startup, stored in `McpSettings`. Unsafe MCP tools gated by a separate `unsafeModeEnabled` boolean in `McpSettings`. Burp AI backend availability gated by `api.ai().isEnabled()`.

---

*Architecture analysis: 2026-05-13*
