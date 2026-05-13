<!-- refreshed: 2026-05-13 -->
# Codebase Structure

**Analysis Date:** 2026-05-13

## Directory Layout

```
burp-ai-agent/
├── src/
│   ├── main/
│   │   ├── kotlin/com/six2dez/burp/aiagent/
│   │   │   ├── BurpAiAgentExtension.kt   # Montoya entry point
│   │   │   ├── App.kt                    # Singleton wiring + lifecycle
│   │   │   ├── agents/                   # Agent profile loader (.md profiles)
│   │   │   ├── alerts/                   # Outbound webhook dispatcher
│   │   │   ├── audit/                    # JSONL audit log + in-memory activity log
│   │   │   ├── backends/                 # AiBackend SPI + provider subdirs
│   │   │   │   ├── BackendTypes.kt       # Interfaces: AiBackend, AgentConnection, factories
│   │   │   │   ├── BackendRegistry.kt    # ServiceLoader discovery + external JAR loading
│   │   │   │   ├── BackendDiagnostics.kt # Retry/error telemetry hooks
│   │   │   │   ├── burpai/               # Burp-native AI backend
│   │   │   │   ├── cli/                  # All CLI backends + CliBackend base
│   │   │   │   ├── http/                 # HttpBackendSupport, CircuitBreaker, MontoyaHttpTransport
│   │   │   │   ├── lmstudio/             # LM Studio HTTP backend
│   │   │   │   ├── nvidia/               # NVIDIA NIM HTTP backend
│   │   │   │   ├── ollama/               # Ollama HTTP backend
│   │   │   │   ├── openai/               # Generic OpenAI-compatible HTTP backend
│   │   │   │   └── perplexity/           # Perplexity HTTP backend
│   │   │   ├── cache/                    # Disk-LRU prompt cache
│   │   │   ├── config/                   # AgentSettings data class + repo + defaults
│   │   │   ├── context/                  # Context capture: models + ContextCollector
│   │   │   ├── mcp/                      # Embedded MCP server (Ktor + MCP SDK)
│   │   │   │   ├── schema/               # JSON schema helpers + serialization
│   │   │   │   └── tools/                # Per-tool handlers (history, sitemap, scanner, etc.)
│   │   │   ├── prompts/
│   │   │   │   └── bountyprompt/         # Structured bug-bounty prompts + tag resolver
│   │   │   ├── redact/                   # Pure redaction: Redaction, RedactionPolicy, PrivacyMode
│   │   │   ├── scanner/                  # Passive + active AI scanners
│   │   │   ├── supervisor/               # AgentSupervisor + ChatSessionManager
│   │   │   ├── ui/                       # Swing UI root
│   │   │   │   ├── components/           # Reusable widgets (ToggleSwitch, AccordionPanel, etc.)
│   │   │   │   └── panels/               # Settings sub-panels (one per settings section)
│   │   │   └── util/                     # Shared utilities (HeaderParser, IssueUtils, TokenTracker)
│   │   └── resources/
│   │       ├── AGENTS/                   # Bundled agent profile .md files
│   │       └── META-INF/services/        # ServiceLoader registrations
│   └── test/
│       └── kotlin/com/six2dez/burp/aiagent/
│           ├── (mirrors main package layout)
│           ├── integration/              # Full-stack integration tests
│           └── TestSettings.kt          # Shared test fixtures
├── AGENTS/                               # Additional bundled agent profiles
├── burp/api/montoya/persistence/         # Local Montoya API stubs (for compilation)
├── docs/                                 # User-facing documentation (mcp-hardening, etc.)
├── skills/burp-scan/                     # Project skill definitions
├── build.gradle.kts                      # Gradle build (shadow JAR, ktlint, JaCoCo, CycloneDX)
├── settings.gradle.kts                   # Project name
├── gradle.properties                     # JVM args
├── DECISIONS.md                          # 7 ADRs
├── SPEC.md                               # Living specification
└── AGENTS.md                             # Codex/agent instructions
```

## Package → Role Mapping

**`com.six2dez.burp.aiagent` (root):**
- `BurpAiAgentExtension.kt` — Montoya SPI entry; 16 lines; only delegates to `App`.
- `App.kt` — Application singleton (`object`); constructs every subsystem; owns `shutdown()` with `safeShutdownStep` isolation.

**`agents/`:**
- Role: Load and hot-reload operator-supplied agent profiles from `~/.burp-ai-agent/AGENTS/*.md`.
- Key file: `AgentProfileLoader.kt` — atomic file-change detection via `CacheEntry(path, modified, profile)`.

**`alerts/`:**
- Role: Outbound webhook notifications (Slack-compatible JSON payload).
- Key file: `Alerting.kt` — singleton; uses `MontoyaHttpTransport` when available, OkHttp fallback.

**`audit/`:**
- Role: Compliance-grade event recording and in-memory activity log.
- Key files:
  - `AuditLogger.kt` — appends JSONL to `~/.burp-ai-agent/audit.jsonl`; ZIP bundle export; SHA-256 hashing.
  - `AiRequestLogger.kt` — in-memory ring buffer; optional rolling file sink; displayed in the AI Logger UI panel.
  - `Hashing.kt` — SHA-256 helper functions (pure).
  - `PromptBundle.kt` — data class capturing prompt hash + metadata per AI call.

**`backends/`:**
- Role: All AI provider implementations and their SPI contracts.
- Key files in root:
  - `BackendTypes.kt` — all interfaces: `AiBackend`, `AiBackendFactory`, `AgentConnection`, `BackendLaunchConfig`, `HealthCheckResult`.
  - `BackendRegistry.kt` — loads via `ServiceLoader`; handles external JAR `URLClassLoader`.
  - `BackendDiagnostics.kt` — static telemetry hooks used by `App` to wire retry events to `AiRequestLogger`.

**`backends/cli/`:**
- Role: CLI process-based backends.
- Key file: `CliBackend.kt` — `NonInteractiveCliConnection` (embedded mode, stdin/stdout pipes) and `CliConnection` (PTY mode for external terminal).
- Factory files: `ClaudeCliBackendFactory.kt`, `CodexCliBackendFactory.kt`, `GeminiCliBackendFactory.kt`, `OpenCodeCliBackendFactory.kt`, `CopilotCliBackendFactory.kt`.

**`backends/http/`:**
- Role: Shared HTTP plumbing for all HTTP-based backends.
- Key files:
  - `HttpBackendSupport.kt` — shared `OkHttpClient` pool keyed by `(baseUrl, timeoutSeconds)`; time-based eviction.
  - `CircuitBreaker.kt` — 5-failure threshold, 30 s reset, half-open probe.
  - `MontoyaHttpTransport.kt` — routes outbound HTTP through Burp's built-in HTTP engine (respects Burp proxy settings).

**`backends/<provider>/`:**
- Role: Provider-specific request/response shapes.
- Pattern: One `*Backend.kt` extending the HTTP pattern, one `*BackendFactory.kt` implementing `AiBackendFactory`.
- Providers: `ollama/`, `lmstudio/`, `openai/`, `nvidia/`, `perplexity/`, `burpai/`.

**`cache/`:**
- Role: Persistent prompt result cache for `PassiveAiScanner`.
- Key file: `PersistentPromptCache.kt` — disk-LRU at `~/.burp-ai-agent/cache/`; `ReentrantReadWriteLock` for concurrent access; TTL-based expiry.

**`config/`:**
- Role: All user-configurable settings.
- Key files:
  - `AgentSettings.kt` — large `data class` covering all backend URLs, CLI commands, privacy mode, scanner config, prompt templates, MCP settings.
  - `AgentSettingsRepository.kt` — serializes/deserializes `AgentSettings` via Burp `Preferences` (JSON via Jackson).
  - `Defaults.kt` — compile-time constants (rate limits, buffer sizes, timeouts).
  - `CustomPromptDefinition.kt` — user-defined prompt data class.
  - `McpSettings.kt` — MCP-specific settings (host, port, token, TLS, unsafe mode).

**`context/`:**
- Role: Capture Burp selections into a redacted JSON envelope.
- Key files:
  - `ContextCollector.kt` — two public methods: `fromRequestResponses()` and `fromAuditIssues()`; applies `Redaction.apply()` inline.
  - `ContextModels.kt` — `ContextCapture`, `ContextOptions`, `BurpContextEnvelope`, `HttpItem`, `AuditIssueItem`.

**`mcp/`:**
- Role: Embedded MCP server (Ktor + MCP Kotlin SDK).
- Key files:
  - `McpSupervisor.kt` — MCP lifecycle: start/stop/restart/takeover; `AtomicReference<McpServerState>`.
  - `KtorMcpServerManager.kt` — Ktor/Netty server binding; SSE endpoint; bearer-token middleware; CORS; optional TLS via `McpTls.kt`.
  - `McpStdioBridge.kt` — stdio bridge for clients that cannot speak SSE.
  - `McpToolCatalog.kt` — declarative catalogue of 53+ tool descriptors with `safe/unsafe` and `proOnly` flags.
  - `McpToolContext.kt` — context object passed to every tool handler (holds `MontoyaApi`, privacy mode, settings).
  - `McpRequestLimiter.kt` — semaphore-based concurrency cap.
  - `McpRuntimeContextFactory.kt` — constructs `McpToolContext` per request from current settings.

**`mcp/schema/`:**
- Role: JSON schema helpers for MCP tool definitions.
- Key files: `JsonSchema.kt`, `serialization.kt`.

**`mcp/tools/`:**
- Role: Individual MCP tool handler implementations.
- Pattern: Groups of related tools in a single file; all registered by calling `registerTools()` from `KtorMcpServerManager`.
- Key files:
  - `HistoryTools.kt` — `proxy_http_history`, `find_reflected`, `params_extract`.
  - `SiteMapTools.kt` — `site_map`, `scope_check`.
  - `ScannerTools.kt` — `scanner_issues`, `passive_scan_trigger`, `active_scan_trigger`.
  - `RequestTools.kt` — `http1_request`, `http2_request` (unsafe).
  - `IssueTools.kt` — `issue_create` (unsafe).
  - `EditorTools.kt` — `repeater_tab`, `intruder` (unsafe).
  - `CollaboratorTools.kt` — `collaborator_register`, `collaborator_status` (unsafe).
  - `UtilityTools.kt` — `url_encode`, `url_decode`, `base64_encode`, `hash_compute`, etc.
  - `ConfigTools.kt` — `status`, `privacy_mode_get`.
  - `ResponsePreprocessor.kt` — applies redaction to all tool outputs.
  - `McpToolHandlers.kt` — central dispatcher; calls `registerTools()`.
  - `McpTools.kt` — `McpTool` interface.
  - `LimitedStringBuilder.kt` — output size cap helper.
  - `ScannerTaskRegistry.kt`, `CollaboratorRegistry.kt` — per-session state registries.

**`prompts/bountyprompt/`:**
- Role: Structured, file-driven prompt definitions for bug-bounty and security testing.
- Key files:
  - `BountyPromptLoader.kt` — loads `.yaml` or `.md` prompt definitions from `AGENTS/` resource dir.
  - `BountyPromptCatalog.kt` — in-memory catalogue with category/tag filtering.
  - `BountyPromptTagResolver.kt` — substitutes `[HTTP_*]` tags with captured request/response parts.
  - `BountyPromptOutputParser.kt` — parses model output to extract structured issue data.
  - `BountyPromptModels.kt` — enums: `BountyPromptCategory`, `BountyPromptOutputType`, `BountyPromptConfidence`, `BountyPromptTag`.

**`redact/`:**
- Role: Pure, side-effect-free redaction transforms.
- Key file: `Redaction.kt` — `object Redaction` with hand-curated regex set; `RedactionPolicy` data class; `PrivacyMode` enum.
- No dependencies on any other package in this codebase.

**`scanner/`:**
- Role: Passive and active AI-powered scanning.
- Key files:
  - `PassiveAiScanner.kt` — `ProxyResponseHandler` registration; single-thread executor; LRU dedup; batch queue; confidence gate.
  - `ActiveAiScanner.kt` — parallel scan executor; `BatchAnalysisQueue` backpressure; risk-level filter.
  - `AiScanCheck.kt` — Burp `ScanCheck` implementation (Pro only); bridges active scanner.
  - `BatchAnalysisQueue.kt` — bounded queue with backpressure.
  - `PayloadGenerator.kt` — static catalogue of 200+ payloads for 62 vuln classes.
  - `AdaptivePayloadEngine.kt` — AI-generated payloads with destructive-pattern filter.
  - `ResponseAnalyzer.kt` — parses AI JSON response to extract vuln findings.
  - `ScanKnowledgeBase.kt` — cross-scanner shared knowledge (passive → active correlation).
  - `InjectionPointExtractor.kt` — extracts parameters and injection points from requests.
  - `JsEndpointExtractor.kt` — extracts JS endpoints for "Extract JS endpoints" action.
  - `IssueMarkerSupport.kt`, `ScannerIssueSupport.kt` — Burp issue creation helpers with byte-range evidence markers.
  - `ScannerUtils.kt` — shared constants (header allowlist, etc.).
  - `ActiveScanModels.kt` — data classes for active scan targets and results.

**`supervisor/`:**
- Role: Backend lifecycle management and prompt dispatch.
- Key files:
  - `AgentSupervisor.kt` — state machine (`Idle/Starting/Running`); `ReentrantLock` + `AtomicReference`; exponential backoff; `sendChat()` with per-session connection reuse.
  - `ChatSessionManager.kt` — maps chat session IDs to live `AgentConnection` instances; handles CLI session-ID persistence for resume.

**`ui/`:**
- Role: All Swing UI components.
- Key files:
  - `MainTab.kt` — root `JComponent`; owns status timers (1 s); registers with `api.userInterface().registerSuiteTab()`.
  - `ChatPanel.kt` — streaming chat area; multi-session tab management; context attachment.
  - `SettingsPanel.kt` — accordion-style settings; delegates to `ui/panels/` sub-panels.
  - `BottomTabsPanel.kt` — tabbed panel hosting scanner status, MCP help, AI logger.
  - `AiLoggerPanel.kt` — displays `AiRequestLogger` ring buffer.
  - `McpHelpPanel.kt` — MCP configuration help and tool catalogue display.
  - `MarkdownRenderer.kt` — lightweight Markdown → styled Swing text renderer.
  - `ToolCallParser.kt` — parses tool invocations from AI response text.
  - `UiActions.kt` — singleton providing `requestResponseMenuItems()` and `auditIssueMenuItems()`.
  - `UiTheme.kt` — color and font constants.
  - `PromptLaunchSpec.kt` — data class encapsulating a prompt launch (text + context + metadata).

**`ui/components/`:**
- Role: Reusable custom Swing widgets.
- Key files: `ToggleSwitch.kt`, `AccordionPanel.kt`, `ActionCard.kt`, `ContextPreviewDialog.kt`, `CustomPromptDialog.kt`, `CustomPromptLibraryEditor.kt`, `DependencyBanner.kt`, `PrivacyPill.kt`, `SafetyIndicator.kt`, `SubtleNotice.kt`, `ToolInvocationDialog.kt`.

**`ui/panels/`:**
- Role: Settings accordion sub-panels (one file per settings section).
- Key files: `BackendConfigPanel.kt`, `PrivacyConfigPanel.kt`, `McpConfigPanel.kt`, `PassiveScanConfigPanel.kt`, `ActiveScanConfigPanel.kt`, `ActiveScanQueuePanel.kt`, `PromptConfigPanel.kt`, `CustomPromptsConfigPanel.kt`, `ConfigPanel.kt`, `HelpConfigPanel.kt`.

**`util/`:**
- Role: Shared helpers with no domain coupling.
- Key files:
  - `HeaderParser.kt` — parses `key: value` header strings; adds Bearer token.
  - `IssueUtils.kt` — helper to create Burp `AuditIssue` objects with correct severity/confidence.
  - `IssueText.kt` — text formatting for issue titles and descriptions.
  - `SecurityExcerpts.kt` — extracts security-relevant substrings from truncated response bodies.
  - `TokenTracker.kt` — accumulates token usage across a session.

**`META-INF/services/`:**
- Location: `src/main/resources/META-INF/services/com.six2dez.burp.aiagent.backends.AiBackendFactory`
- Role: `ServiceLoader` registration for 10 built-in backend factories.
- New backends: Add one line here pointing to the new `*BackendFactory` class.

**`AGENTS/` (resources):**
- Location: `src/main/resources/AGENTS/`
- Role: Bundled agent profile `.md` files (`pentester.md`, `bughunter.md`, `auditor.md`).
- Installed to `~/.burp-ai-agent/AGENTS/` on first load.

## Key File Locations

**Entry Points:**
- `src/main/kotlin/com/six2dez/burp/aiagent/BurpAiAgentExtension.kt`: Montoya SPI; Burp loads this.
- `src/main/kotlin/com/six2dez/burp/aiagent/App.kt`: All wiring; only place where singletons are constructed.

**Configuration:**
- `src/main/kotlin/com/six2dez/burp/aiagent/config/AgentSettings.kt`: Master settings type.
- `src/main/kotlin/com/six2dez/burp/aiagent/config/Defaults.kt`: All numeric defaults (timeouts, buffer sizes, rate limits).
- `build.gradle.kts`: Build config, dependency versions, shadow JAR config.

**Core Logic:**
- `src/main/kotlin/com/six2dez/burp/aiagent/redact/Redaction.kt`: Privacy transform — edit to add new redaction patterns.
- `src/main/kotlin/com/six2dez/burp/aiagent/context/ContextCollector.kt`: Context capture — edit to change JSON envelope schema.
- `src/main/kotlin/com/six2dez/burp/aiagent/supervisor/AgentSupervisor.kt`: Backend lifecycle and dispatch.
- `src/main/kotlin/com/six2dez/burp/aiagent/backends/BackendRegistry.kt`: ServiceLoader + external JAR loading.

**Testing:**
- `src/test/kotlin/com/six2dez/burp/aiagent/TestSettings.kt`: Shared test fixture settings.
- `src/test/kotlin/com/six2dez/burp/aiagent/integration/CompatibilitySmokeTest.kt`: Smoke test run against a real Burp instance.

## Naming Conventions

**Files:**
- Kotlin classes: `PascalCase` matching the class name exactly (`AgentSupervisor.kt`, `KtorMcpServerManager.kt`).
- Files with multiple related declarations use a descriptor noun: `BackendTypes.kt`, `ContextModels.kt`, `ActiveScanModels.kt`.
- Factory files: `*BackendFactory.kt` — one factory per backend provider.
- Test files: `*Test.kt` suffix, mirroring the source file name (`AgentSupervisorRestartPolicyTest.kt`).

**Directories:**
- All lowercase, short, no hyphens: `backends/`, `redact/`, `scanner/`, `mcp/`, `ui/`.
- Sub-package by responsibility within a package: `backends/cli/`, `backends/http/`, `mcp/tools/`, `ui/components/`, `ui/panels/`.

**Kotlin identifiers:**
- Classes/objects/interfaces: `PascalCase`.
- Functions and properties: `camelCase`.
- Constants (in companion objects / top-level): `SCREAMING_SNAKE_CASE` (e.g. `DEFAULT_MAX_DISK_BYTES`, `CIRCUIT_FAILURE_THRESHOLD`).
- Enum entries: `SCREAMING_SNAKE_CASE`.
- Private fields with atomic types: `*Ref` suffix (`stateRef`, `settingsRef`, `privacyRef`).

## Where to Add New Code

**New AI backend (HTTP):**
1. Create `src/main/kotlin/com/six2dez/burp/aiagent/backends/<provider>/` directory.
2. Implement `AiBackend` (or extend `HttpBackendSupport`-pattern) in `<Provider>Backend.kt`.
3. Implement `AiBackendFactory` in `<Provider>BackendFactory.kt`.
4. Add one line to `src/main/resources/META-INF/services/com.six2dez.burp.aiagent.backends.AiBackendFactory`.
5. Add backend ID and settings fields to `AgentSettings.kt` (in `config/`).
6. Add launch config arm to `AgentSupervisor.buildLaunchConfig()` — or better, handle it in the backend's `launch()`.
7. Write unit test in `src/test/kotlin/com/six2dez/burp/aiagent/backends/`.

**New AI backend (CLI):**
- Same as HTTP, but extend `CliBackend` pattern from `backends/cli/CliBackend.kt`.

**New MCP tool:**
1. Add a `McpToolDescriptor` entry to `McpToolCatalog.kt` with correct `safe/unsafe` and `proOnly` flags.
2. Implement the tool handler in the relevant file under `mcp/tools/` (or a new file if it's a new category).
3. Register it in `McpToolHandlers.kt` via the `registerTools()` call.
4. Write unit test in `src/test/kotlin/com/six2dez/burp/aiagent/mcp/tools/`.

**New redaction pattern:**
- Edit the regex set in `Redaction.kt` (`authHeaderRegex`, `urlTokenParamRegex`, etc.).
- Add a test case to `src/test/kotlin/com/six2dez/burp/aiagent/redact/RedactionTest.kt`.

**New settings field:**
1. Add the field to `AgentSettings.kt` with a default value.
2. Add migration logic in `AgentSettingsRepository` (check `AgentSettingsMigrationTest` for the pattern).
3. Wire to `Defaults.kt` constant if applicable.
4. Add UI control in the appropriate panel under `ui/panels/`.

**New Swing component:**
- Reusable widget: `src/main/kotlin/com/six2dez/burp/aiagent/ui/components/`.
- Settings sub-panel: `src/main/kotlin/com/six2dez/burp/aiagent/ui/panels/`.
- Top-level panel (added to `MainTab` tabbed pane): `src/main/kotlin/com/six2dez/burp/aiagent/ui/`.

**New utility:**
- Pure helper with no domain coupling: `src/main/kotlin/com/six2dez/burp/aiagent/util/`.
- Domain-coupled helper: co-locate with the package it serves.

## Special Directories

**`.planning/codebase/`:**
- Purpose: GSD codebase map documents consumed by planning and execution agents.
- Generated: By `/gsd-map-codebase`.
- Committed: Yes (tracks architectural intent).

**`build/`:**
- Purpose: Gradle build outputs; shadow JAR at `build/libs/Custom-AI-Agent-<version>.jar`.
- Generated: Yes.
- Committed: No.

**`burp/api/montoya/persistence/`:**
- Purpose: Local Montoya API stub classes used for compilation without a real Burp JAR.
- Generated: No (hand-authored stubs).
- Committed: Yes.

**`~/.burp-ai-agent/` (runtime, not in repo):**
- `audit.jsonl` — append-only audit log (when enabled).
- `bundles/` — ZIP repro bundle exports.
- `cache/` — disk-LRU prompt result cache.
- `AGENTS/` — operator agent profiles; bundled profiles installed on first run.
- `backends/` — drop-in external backend JARs loaded at startup.
- `logs/` — rolling activity log files (when rolling persistence enabled).

---

*Structure analysis: 2026-05-13*
