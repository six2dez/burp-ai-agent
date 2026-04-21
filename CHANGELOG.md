# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/), and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.6.0] - 2026-04-21

### Changed

- **Privacy-by-default**: Default privacy mode is now `BALANCED` instead of `OFF`. New users, and users who never explicitly chose a mode, get cookie stripping and token redaction before any HTTP data is sent to an AI backend. Users with an existing explicit mode keep their choice.
- **Redaction coverage expanded**: the token redactor now also strips `X-Auth-Token`, `X-Access-Token`, `X-Session-Token`, `X-CSRF-Token`, `X-Api-Secret`, `X-Client-Secret` and their non-prefixed variants; Basic auth values are replaced with `Basic [REDACTED]`; URL query parameters named `access_token`, `api_key`, `apikey`, `auth`, `token`, `key`, `secret`, `password`, `pwd`, `session`, `sid`, `code` have their value redacted in-place.
- **Vulnerability class inventory**: removed the duplicate `RACE_CONDITION` entry; race-condition issues now use the single canonical `RACE_CONDITION_TOCTOU`. A new `VulnClassInventoryTest` locks the 62-class count plus severity and remediation coverage, so any future drift in `VulnClass` fails the build.
- **JAR artifact renamed**: build output is now `Custom-AI-Agent-<version>.jar` (was `Burp-AI-Agent-<version>.jar`). CI, release workflows, and `CONTRIBUTING.md` updated; any external script or download URL that hard-codes the old name must be updated.

### Added

- **NVIDIA NIM backend** (#new): 10th backend (`nvidia-nim`) targeting `integrate.api.nvidia.com` — configurable URL, model id, API key, extra headers, and request timeout. Participates in the standard backend registry, health check, and AI logger flows like other HTTP backends.
- **MCP proxy history preprocessing**: the MCP tools that surface Burp's proxy history now run through a preprocessor pipeline that optionally filters binary content types, caps per-response body size, limits the total items returned per request, and orders results newest-first. Adds `preprocessProxyHistory`, `preprocessMaxResponseSizeKb`, `preprocessFilterBinaryContent`, `preprocessAllowedContentTypes`, `proxyHistoryMaxItemsPerRequest`, `proxyHistoryNewestFirst`, and `allowUnpreprocessedProxyHistory` settings (surfaced in **Settings → MCP**). The unpreprocessed option is off by default; turning it on is an opt-in that lets MCP clients request raw history when they explicitly need it.
- **Context preview dialog**: right-click actions that auto-capture context from Burp (requests, issues, site map) now open a modal showing the prompt, privacy mode, and the exact redacted JSON that will be sent to the AI. The user can confirm with `Send` or abort with `Cancel`.
- **Prompt-injection hardening in scanner prompts**: passive scanner (single + batch) and adaptive payload generator now instruct the model to treat captured HTTP traffic and observed context as untrusted data, not as instructions, even if a response body tries to override the prompt.
- **Custom prompt library**: new `Custom prompts` submenu in both the HTTP request/response context menu and the scanner issue context menu. Saved prompts are tagged per applicability (`HTTP_SELECTION`, `SCANNER_ISSUE`, or both) with an `Show in context menu` toggle and ordered from Settings → Prompt Templates (Add / Edit / Duplicate / Delete / Move Up / Move Down). A `Custom…` entry at the bottom of the submenu opens a free-form editor for ad-hoc prompts, optionally seeded from a saved one. Library persists as JSON under settings schema v3.
- **Launch metadata in audit & logging**: every context-driven chat launch now carries `promptSource` (`FIXED` / `CUSTOM_SAVED` / `CUSTOM_AD_HOC`), `contextKind` (`HTTP_SELECTION` / `SCANNER_ISSUE`), and — for saved custom prompts — `promptId` and `promptTitle`. These flow into `AuditLogger` prompt bundles (`~/.burp-ai-agent/bundles/`) and the `prompt` records in `audit.jsonl`, plus the `AiRequestLogger` metadata map, making runs reproducible and filterable (e.g. `jq 'select(.type=="prompt") | .payload.promptSource'`). `PromptBundle` schema gained four optional fields; existing bundles on disk remain readable.
- **Build & CI hygiene**:
  - `ktlint` plugin (`12.1.1`) with `ktlintFormat` (auto-fix) and `ktlintCheck` (verification) Gradle tasks; ktlint gate in CI.
  - `jacoco` plugin with HTML + XML coverage reports generated on every `./gradlew test` and published as a CI artifact.
  - CycloneDX SBOM (`cyclonedxBom`) generated on release, published as `bom.json`.
  - Multi-OS test matrix on PRs: `ubuntu-latest`, `macos-latest`, `windows-latest` (JAR + coverage still only uploaded from Linux).
  - Release pipeline now uploads the release JAR, a matching SHA-256 checksum, and the SBOM, and uses release notes extracted from the matching `CHANGELOG.md` section of the tagged version.
- **Community and project hygiene files**: `CODE_OF_CONDUCT.md`, `.github/dependabot.yml` (gradle + github-actions, weekly), `.github/pull_request_template.md`, and YAML-form issue templates (`bug_report.yml`, `feature_request.yml`, `config.yml`) with links to Security Advisories, Discussions, and docs.
- **Operational docs**: `docs/mcp-hardening.md` gained a *Credential Storage* section documenting how the TLS keystore password and MCP bearer token are persisted and rotated.

### Fixed

- **Stale settings cache across UI instances**: `SettingsPanel` and `MainTab` own separate `AgentSettingsRepository` instances, each with its own in-memory cache. Before this fix, saving any setting (prompts, backends, privacy mode, scanner config) from the Settings tab could leave the right-click menu reading a stale snapshot until Burp restart. `AgentSettingsRepository.invalidate()` is now called on every save-through-Settings event so the next menu build re-reads from preferences.
- **Runtime defaults restored**: token budget and CLI idle-timeout defaults were missing from `Defaults.kt` after an earlier refactor, causing some backends to launch with zero-valued limits. Defaults are now explicit again.
- **MCP preprocess change detection**: fixed a case where changing proxy-history preprocessing settings did not invalidate the tool schema, so MCP clients kept seeing the old schema until the MCP server restarted. Also gated the proxy-history tool schema on the active preprocessor settings so clients can distinguish between `preprocessed` and `raw` shapes.

## [0.5.0] - 2026-04-02

### Added

- **JS Endpoint Discovery**:
  - New `JsEndpointExtractor` that extracts API endpoints from JavaScript responses using 8 regex patterns (fetch, axios, ajax, XMLHttpRequest, `/api/`, `/vN/`, variable assignments, and path literals).
  - Automatic extraction in the passive scanner for JS MIME responses passing through the proxy, with LRU dedup cache (2000 entries).
  - "Extract JS Endpoints" context menu entry for manual extraction with a scrollable results dialog.
- **403 Bypass Testing**:
  - New `ACCESS_CONTROL_BYPASS` vulnerability class in the active scanner with 3 bypass techniques: IP spoofing headers (9 headers), path manipulation (7 variations), and HTTP method switching.
  - "Test 403 Bypass" context menu entry that filters selected requests to 403 status and queues them for active bypass testing.
- **Keyword-Priority Response Sampling**:
  - `PassiveAiScanner` and `ContextCollector` now append a `=== SECURITY-RELEVANT EXCERPTS ===` section when response bodies are truncated, surfacing security-relevant lines (tokens, keys, errors, auth headers) from beyond the truncation point.
- **Finding Request/Response Markers**:
  - New `IssueMarkerSupport` utility that adds Montoya API byte-range markers to audit issue evidence, highlighting injected payloads in requests and evidence strings in responses.
  - Integrated in `ActiveAiScanner`, `AiScanCheck`, and `PassiveAiScanner` so findings show highlighted regions in Burp's request/response viewer.
- **Site Map Tree Node Selection**:
  - Context menu actions now work when right-clicking directory or root nodes in the site map tree (not just individual requests).
  - Falls back to `api.siteMap().requestResponses()` when `selectedRequestResponses()` returns empty in `SITE_MAP_TREE` context, with "(site map - N)" labels indicating broader scope.

- **Custom Targeted Tests** (#31):
  - New "Custom..." item in the Targeted Tests context menu that opens a multi-select dialog with all 55+ vulnerability classes.
  - Select All / Deselect All buttons for quick selection.
- **Excluded File Extensions Filter** (#33):
  - New configurable "Excluded extensions" setting in the passive scanner that skips requests to static files (CSS, JS, images, fonts, archives, etc.) by URL path extension.
  - Default exclusion list covers 30+ common static file extensions to reduce unnecessary API calls and token usage.
  - Persisted in Burp preferences and applied via `applyOptimizationSettings()`.

- **MCP `issue_create` Tool Fix**:
  - Fixed `issue_create` MCP tool returning "Unknown tool" because its execution handler was missing from the `executeToolResult()` dispatcher after the refactoring to the handler-based registration system.

- **Batch Analysis (Passive Scanner)**:
  - New `BatchAnalysisQueue` groups 3-5 proxy requests into a single AI call, reducing API calls by 60-70%.
  - Batch prompt includes cross-request analysis instructions for detecting IDOR/BAC patterns across endpoints.
  - Configurable via `Batch size (1=off)` setting (range: 1-5, default: 3).
  - Flush triggers when batch is full or timeout expires (5s, checked on next request); explicit flush on shutdown.
  - Fallback to individual single-request analysis if batch call fails (timeout, backend error, or backend unavailable).

- **Structured Output (JSON Mode)**:
  - HTTP backends (OpenAI-compatible, LM Studio, Ollama) now request structured JSON output (`response_format: json_object` / `format: json`) for scanner analysis calls.
  - New `JsonModeCapable` marker interface and `jsonMode` parameter on `AgentConnection.send()`.
  - Eliminates JSON parsing errors from markdown wrapping, code fences, or mixed text in AI responses.
  - CLI backends gracefully ignore the flag; existing text-based parsing remains as fallback.

- **Persistent Prompt Cache**:
  - New `PersistentPromptCache` stores AI analysis results to disk (`~/.burp-ai-agent/cache/`) as individual JSON files keyed by prompt hash.
  - Results survive Burp restarts — same target scanned in different sessions returns instant cached results.
  - Configurable TTL (1-168 hours, default: 24h) and max disk size (10-500 MB, default: 50 MB) with LRU eviction.
  - Two-tier lookup: in-memory cache first, disk fallback, then AI call. Disk hits are promoted to in-memory.

- **Cross-Scanner Knowledge Sharing**:
  - New `ScanKnowledgeBase` singleton shared across passive scanner, active scanner, and chat.
  - Passive scanner records tech stack hints (from `Server`, `X-Powered-By`, `X-ASPNet-Version` headers), auth patterns (session cookies, auth headers, API keys), and vulnerability signals per endpoint.
  - Active scanner records confirmed findings and database technology hints (MySQL, PostgreSQL, MSSQL, Oracle, SQLite) from error pattern evidence.
  - Knowledge base context (`=== PRIOR KNOWLEDGE ===`) is included in passive scanner AI prompts with tech stack, previous findings, and error patterns.
  - Active scanner boosts priority (+20) for targets with high-priority signals in the knowledge base.

- **Burp Scan Skill** (`skills/burp-scan/SKILL.md`):
  - Standalone skill file that lets any AI coding assistant (Claude Code, Gemini CLI, Codex, etc.) operate Burp's MCP tools as a scanner from the terminal.
  - 53+ MCP tools reorganized by scanning action (discover, analyze, send payloads, OOB, report).
  - Passive analysis protocol with 4 deterministic local checks (request smuggling, CSRF, deserialization, file upload) and full analysis checklist.
  - Active testing payload library: 200+ payloads for 62 vuln classes with detection patterns, confidence scores, and unique markers (`XSS-BURP-AI-1337`, `97601`, `evil-burp-ai-test.com`).
  - End-to-end scanning workflow: scope -> passive -> active confirmation -> OOB (Collaborator) -> issue creation.
  - Issue creation protocol with severity/confidence mapping and remediation reference for all vuln classes.
  - Installable as a Claude Code skill (`~/.claude/skills/burp-scan/`) or usable as context with any AI assistant.

- **AI Adaptive Payload Generation**:
  - New `AdaptivePayloadEngine` generates context-aware payloads using AI based on detected tech stack, error patterns, and parameter context from `ScanKnowledgeBase`.
  - Generated payloads are cached per `vulnClass:techStack` key (30-minute TTL) to avoid redundant AI calls.
  - Safety: destructive payloads (DROP, DELETE, TRUNCATE, ALTER, SHUTDOWN, rm) are rejected by regex validation.
  - Opt-in via `AI adaptive payloads` setting in Active AI Scanner tab (default: off).
  - Static payloads always included; adaptive payloads are merged and deduplicated.

- **Cache Normalization**:
  - Response fingerprint now strips dynamic values (UUIDs, MongoDB ObjectIds, Unix timestamps, ISO 8601 dates, long tokens/nonces) before hashing, improving cache hit rate by 15-30%.
  - Endpoint dedup key now includes sorted query parameter names (excluding cache-busting params like `_`, `ts`, `nonce`) for more accurate dedup across parameter ordering variations.

- **Project-Scoped Chat Sessions**:
  - Chat sessions are now stored in Burp's `extensionData()` (project-scoped) instead of global `preferences()`. Each Burp project has its own independent chat history.
  - One-time automatic migration of existing global sessions to the first project opened after update.
  - "Clear Chat" now fully resets: messages, context flag, counters, drafts, tool state, and persisted message blobs.

- **Project Change Detection**:
  - Automatic detection of Burp project switches via `api.project().id()` polling (30-second interval).
  - On project change: saves current sessions, clears in-memory state, reloads sessions from new project, clears `ScanKnowledgeBase`, and shuts down all live chat backend connections.
  - Prevents cross-project contamination of chat history, scanner knowledge, and cached results.

- **Output Token Limits (`max_tokens` / `num_predict`)**:
  - All HTTP backends (OpenAI-compatible, LM Studio, Ollama) now set explicit output token limits to prevent truncated responses.
  - Chat: 4096 tokens, Scanner (single): 2048, Scanner (batch): 4096, Adaptive payloads: 1024.
  - New `maxOutputTokens` parameter threaded through `AgentConnection.send()` -> `AgentSupervisor` -> all backends.
  - Ollama maps to `num_predict` in options; OpenAI/LM Studio map to `max_tokens` in payload. CLI backends ignore (managed by CLI tool).

- **Scanner Project Isolation**:
  - `ScanKnowledgeBase` is now cleared when the passive scanner is disabled, preventing accumulated tech stack and vulnerability data from bleeding across scopes.
  - `PersistentPromptCache` is now namespaced per Burp project (`~/.burp-ai-agent/cache/{projectId}/`), preventing cached analysis from one project from being served in another.

- **NVIDIA NIM Backend**:
  - New NVIDIA NIM backend with SSE streaming, `chat_template_kwargs.thinking` support, and POST-based health checks against the chat completions endpoint.
  - Backend configuration fields in the UI for NVIDIA NIM URL, model, API key, custom headers, and timeout.
  - `OpenAiCompatibleBackend` now supports streaming mode, payload customization hooks, default headers, and custom health check providers, enabling new OpenAI-compatible backends with minimal boilerplate.

### Changed

- **Passive Scanner Settings UI**:
  - Added `Batch size (1=off)` spinner, `Persistent cache` checkbox, `Persistent TTL (hrs)` and `Persistent max (MB)` spinners to the AI Passive Scanner settings tab.
- **Active Scanner Settings UI**:
  - Added `AI adaptive payloads` checkbox to the AI Active Scanner settings tab.
- **HTTP 429 Chat Error Handling**:
  - Improved chat error handling so HTTP 429 and other error responses no longer leave the UI stuck on "Thinking...".

### Fixed

- **Batch analysis silent request loss**:
  - `flushBatch()` now falls back to individual single-request analysis when the batch call fails (timeout, backend error, or backend unavailable), instead of silently discarding the requests.
- **403 bypass false positives on path manipulation and method switching**:
  - Added `MIN_BYPASS_BODY_DELTA` (50 bytes) body length difference check to path manipulation and HTTP method switching techniques, matching the existing check on IP spoofing headers. Prevents generic 200 pages or wildcard routes from being reported as confirmed bypasses.
- **CLI session ID race condition**:
  - Replaced unsafe `!!` assertion on `_cliSessionId.get()` after failed CAS with a safe `?:` throw, preventing potential `NullPointerException` if another thread calls `stop()` between the CAS failure and the read.
- **External backend JAR classloader leak**:
  - `URLClassLoader` in `BackendRegistry.loadExternalBackendJars()` is now explicitly closed in the catch block if `ServiceLoader` loading fails, preventing file descriptor leaks.
- **Webhook delivery crash**:
  - `Alerting.sendWebhook()` is now wrapped in try-catch, preventing network errors from propagating to callers. Webhook delivery is best-effort.
- **AI enabled check fail-open**:
  - `isAiEnabled()` fallback changed from `true` to `false` when `api.ai().isEnabled()` throws an exception. Ensures AI requests are blocked when the AI API is unavailable (BApp Store compliance: fail-closed).

- **Burp Suite shutdown hang after chat usage** (#34):
  - Added `ChatPanel.shutdown()` that cancels in-flight backend connections and stops all active Swing timers (spinner, coalescing, copy button reset) across all session panels.
  - `MainTab.shutdown()` now calls `chatPanel.shutdown()` before saving sessions.
  - Fixed anonymous copy button timer leak by tracking it in a field.
  - Fixed `McpStdioBridge.stop()` not canceling its `CoroutineScope`'s `SupervisorJob`, which kept coroutines alive after extension unload.
- **TLS certificate generation error on JDK 25** (#35):
  - Replaced Netty's `SelfSignedCertificate` (which required BouncyCastle or unsupported internal JDK APIs) with JDK's built-in `keytool` command.
  - Works on all JDK versions (8-25+) and all platforms (macOS, Linux, Windows) without additional dependencies.
- **CLI backends not visible in UI** (#38):
  - Backend dropdown now shows all registered backends regardless of CLI binary availability, using new `BackendRegistry.listAllBackendIds()`.
  - Users can now select and configure CLI backends (Claude, Gemini, Codex, OpenCode, Copilot) even when the binary is not in PATH; errors are reported at usage time via health check.
- **Codex CLI Windows integration** (#42):
  - Fixed `CreateProcess error=193` when running npm-installed CLI tools (Codex, Gemini, Copilot) on Windows.
  - `normalizeWindowsCommand()` now generically resolves `.cmd` shim siblings for all CLI backends, not just OpenCode.
  - For absolute paths to npm shell script shims without a Windows-executable extension, the resolver tries the `.cmd` sibling first, then falls back to a `cmd /c` wrapper.
- **OpenCode blank messages and unrendered responses** (#40):
  - Fixed `readOpenCodeOutput()` filtering out actual AI response content by matching short prompt lines (e.g., "SQL Injection", "Analyze the request") against output.
  - Prompt-line dedup threshold raised to 40+ characters to avoid false positives on common short strings.
  - OpenCode metadata filter generalized: all `> ` prefixed lines under 120 characters are now treated as status/metadata, replacing the previous hardcoded list of 7 specific prefixes.
  - Idle timeout before process termination increased from 10 seconds to 30 seconds (`Defaults.OPENCODE_IDLE_TIMEOUT_MS`), preventing premature kill during long model inference.
- **Burp AI backend not usable from chat**:
  - Added missing `"burp-ai"` case in `validateBackendCommand()`, which caused "Unsupported backend: burp-ai" when sending messages.
- **Backend picker change not applied to scanners**:
  - Changing the backend in the top bar now immediately persists to settings repository, so passive/active scanners use the selected backend instead of the previous one.
- **CLI path resolution log spam**:
  - Removed verbose "Resolved absolute" diagnostic log from `resolveCommand()` that fired every 5 seconds via health timer. Error-case logging ("Absolute path not found") is preserved.
- **Finding marker range calculation**:
  - Fixed `IssueMarkerSupport.markResponseEvidence()` using the wrong prefix length when a shorter evidence prefix was matched, causing incorrect byte-range highlights in Burp's response viewer.
  - Added bounds check in `markResponseFromDetail()` to prevent marker end exceeding response length.

### Changed

- **PortSwigger Compliance Rename**:
  - All user-facing strings renamed from "Burp AI Agent" to "Custom AI Agent" (UI title, help panel, log prefixes).
  - Internal identifiers (thread names, temp files, config directory) unchanged.
- **UI Emoji Cleanup**:
  - Removed all decorative emojis from context menu items, status panel labels, logger activity types, and warning dialogs across `UiActions`, `SettingsPanel`, and `AiLoggerPanel`.
  - Functional unicode symbols (arrows, toggles, spinners) are preserved.
- **MCP Settings Optimization**:
  - `McpSupervisor.applySettings()` now skips server restart when settings, privacy mode, and determinism mode are unchanged, reducing unnecessary MCP restarts during settings apply.
- **MCP Tool Call Prompt Format**:
  - Chat system prompt for MCP tools changed from inline description to JSON code block format with explicit invocation instructions.
  - Tool descriptions now include parameter schemas (`includeSchemas: true`) for better AI tool usage accuracy.


## [0.4.0] - 2026-03-06


- **Copilot CLI Backend**:
  - New GitHub Copilot CLI backend with non-interactive prompt mode (`-p`), quiet output (`--quiet`), and large prompt file-based fallback for payloads exceeding 32k chars.
  - Configurable command in AI Backend settings tab; registered via ServiceLoader for drop-in availability.
- **AI Request Logger**:
  - Real-time activity logger (`AiRequestLogger`) capturing all AI interactions: prompts, responses, MCP tool calls, retries, errors, and scanner dispatches.
  - Trace ID correlation across chat (`chat-turn-{UUID}`), scanner (`scanner-job-{UUID}`), and agent (`agent-turn-{UUID}`) flows for end-to-end observability.
  - Structured `AiActivityEntry` with timestamp, activity type, source, backend, duration, character counts, token usage, and arbitrary metadata.
  - Integration in `AgentSupervisor` (prompt/response/error), `PassiveAiScanner` (send/timeout/error/completion), `McpToolHandlers` (per-tool call with policy decisions and arg/result hashes), and `ChatPanel` (tool chain steps).
- **AI Logger UI Tab**:
  - New "AI Logger" tab in bottom settings panel with live filterable table, detail inspector pane, and JSON export.
  - Preset filters (Errors only, Slow >=3s, Tool failures), type/source dropdowns, and trace ID search for quick diagnosis.
- **Rolling JSONL Persistence**:
  - Optional file-based persistence for the AI Request Logger with configurable rotation via JVM system properties (`burp.ai.logger.rolling.enabled`, `.dir`, `.maxBytes`, `.maxFiles`).
- **Auto Tool Chaining**:
  - Chat automatically chains up to 8 sequential MCP tool calls per interaction when the AI response contains a tool call JSON payload.
  - All chained calls share the same trace ID for end-to-end correlation in the AI Logger.
- **ToolCallParser**:
  - Robust JSON tool call extraction from AI responses supporting fenced code blocks (`json`/`tool`), bare JSON objects, and nested OpenAI-style `tool_calls`/`function_call` formats.
- **System Prompt Support**:
  - `AgentConnection.send()` now accepts a `systemPrompt` parameter; HTTP backends (Ollama, LM Studio, OpenAI-compatible) receive agent profile instructions via the system role instead of inlining them in user prompts.
- **Per-Session Token Tracking**:
  - Chat sessions track cumulative input/output token counts with visual token bars showing session-level and global usage in the sidebar.
- **Context Collection Size Cap**:
  - `ContextCollector` caps total serialized size of context items to prevent oversized payloads from exceeding prompt limits.
- **Backend Retry Diagnostics**:
  - `BackendDiagnostics.RetryEvent` model with structured metadata (attempt number, delay, reason) logged to the AI Request Logger as `RETRY` activities.

## [0.3.0] - 2026-02-24

### Added

- **Security Test Coverage (MCP)**:
  - Added unit tests for bearer token authorization and constant-time comparison in `KtorMcpServerManager`.
  - Added unit tests for loopback TLS connection hardening behavior in `McpSupervisor`.
- **Backend Registry Test Coverage**:
  - Added tests for availability cache behavior and cache reset on reload/shutdown.
- **Scanner/Issue Utilities Test Coverage**:
  - Added tests for shared issue canonicalization, equivalent-issue detection, and HTML detail formatting.
  - Added passive scanner confidence-threshold test to ensure AI findings below 85% confidence are skipped.
- **Redaction Lifecycle Test Coverage**:
  - Added tests for per-salt and global host mapping cleanup.
- **Shared Issue Utilities**:
  - New `IssueUtils` helper for canonical issue naming, equivalent issue detection, and safe issue detail HTML formatting.
- **Redaction Cleanup API**:
  - Added `Redaction.clearMappings(salt: String? = null)` to support deterministic cleanup of anonymization mappings.
- **Token Optimization Controls (Passive + Context)**:
  - Added persistent passive scanner controls for endpoint dedup TTL, response-fingerprint dedup TTL, prompt-cache TTL, and cache sizes.
  - Added persistent passive scanner controls for request/response body prompt caps, maximum header count, and maximum parameter count.
  - Added persistent manual-context controls for request/response body truncation and compact JSON serialization.
- **Passive Scanner Prompt Result Cache**:
  - Added prompt-hash result caching with TTL-aware reuse and cache-hit audit events to avoid repeated backend calls for identical payloads.
- **Token Usage Telemetry**:
  - Added shared `TokenTracker` flow accounting (input/output chars + token estimate) for chat and passive scanning paths.
- **Active Scanner Queue Panel**:
  - Added a dedicated queue viewer dialog with live refresh, per-item cancellation, and full queue clearing controls.
  - Added queue snapshot APIs and selective cancellation support for queued active scan targets.
- **Backend Health Contract and Diagnostics UX**:
  - Added `HealthCheckResult` contract (`Healthy`, `Degraded`, `Unavailable`, `Unknown`) at backend level.
  - Added backend-level health check integration in registry/supervisor flows.
  - Added "Test connection" actions in backend settings panels.
- **HTTP Backend Runtime Telemetry**:
  - Added usage-aware connection support so HTTP backends can report real token usage when providers expose `usage` fields.
- **Testing Expansion (Integration + Concurrency + Resilience)**:
  - Added MCP server integration tests (`McpServerIntegrationTest`) covering health and auth/shutdown endpoints.
  - Added MCP limiter concurrency stress tests (`McpRequestLimiterConcurrencyTest`).
  - Added active scanner queue backpressure tests (`ScannerQueueBackpressureTest`).
  - Added supervisor auto-restart policy tests (`AgentSupervisorRestartPolicyTest`).
  - Added backend health contract tests (`BackendHealthCheckTest`) and settings migration tests (`AgentSettingsMigrationTest`).
- **CI Workflows for Reliability**:
  - Added `nightlyRegressionTest` Gradle task for heavy suites (integration/concurrency/resilience).
  - Added `.github/workflows/nightly-regression.yml` with scheduled/manual execution and artifact publishing.
- **Settings Schema Migration and Operator Docs**:
  - Added schema version marker `settings.schema.version` with additive/idempotent migration flow.
  - Added operator runbooks: `docs/mcp-hardening.md`, `docs/ui-safety-guide.md`, `docs/backend-troubleshooting.md`.

### Changed

- **System Proxy Support**:
  - HTTP backends now use `ProxySelector.getDefault()` instead of `Proxy.NO_PROXY`, respecting Burp/JVM proxy configuration.
- **Passive Scanner Prompt Improvements**:
  - Updated prompt with explicit severity definitions (Critical/High/Medium/Low), concrete DO NOT REPORT rules (missing headers, potential issues without evidence, generic reflection, rate limiting absence), and step-by-step evidence chain requirement in reasoning.
  - AI responses with "Critical" severity are now mapped to Burp's `HIGH` severity level.
- **Agent Profile Tool Descriptions**:
  - Agent profiles now mark `http1_request`/`http2_request` tools as "(optional when unsafe mode is enabled)".
  - Tool validation suppresses warnings for catalog-only tools that require Unsafe mode.
- **Chat Context Dedup**:
  - Follow-up messages in the same session skip re-sending context JSON, reducing prompt size on subsequent turns.
- **Issue Consolidation**:
  - `AiScanCheck` now uses canonical issue names and normalized URLs for cross-scanner dedup consistency.
  - `hasExistingIssue` renamed to `hasEquivalentIssue` for clarity across active scanner and UI actions.
- **ConversationHistory System Prompt**:
  - Added `setSystemPrompt()` method; system prompt is prepended in conversation snapshots for HTTP backends.
- **Duplicate Issue Logic Consolidation**:
  - Replaced duplicated issue matching/canonicalization code in Passive Scanner, Active Scanner, MCP tools, and UI actions with `IssueUtils`.
- **Shutdown Reliability and Consistency**:
  - Refactored `App.shutdown()` to use a unified safe shutdown step wrapper with consistent error handling.
  - Added redaction mapping cleanup to app shutdown flow.
- **Text Sanitization Performance**:
  - Cached regex patterns in `IssueText` to avoid recompilation on each call.
- **Passive Scanner Request Filtering and Deduplication**:
  - Added pre-AI traffic pruning for low-value responses (204/304, static assets, tiny bodies without interesting headers).
  - Added endpoint-path and response-fingerprint dedup windows to avoid repeated analysis of equivalent traffic.
- **Passive Scanner Prompt Compaction**:
  - Replaced full-header forwarding with security-focused header filtering (allowlist + noise denylist + custom `x-*` handling).
  - Reduced parameter verbosity and removed cache-busting parameters from AI metadata.
  - Added content-aware body compaction (JSON array sampling + HTML head/form/inline-script extraction).
  - Updated passive scanner base prompt to a compact, evidence-first schema while preserving strict JSON output constraints.
- **Context Collection Payload Size Control**:
  - `ContextCollector` now supports body truncation controls and compact JSON output to reduce manual action token usage.
  - Context menu actions now pass context size/compact settings from `AgentSettings` instead of relying on implicit defaults.
- **HTTP Backend Conversation Trimming**:
  - Conversation history trimming now enforces both message count and total character budget to prevent prompt blow-up in long sessions.
- **BountyPrompt Context Limits**:
  - Reduced default tag/chunk limits and added category-specific bounds to lower prompt size while keeping actionable context.
- **Passive Scanner Settings UX**:
  - Expanded AI Passive Scanner tab with advanced token/performance controls and live runtime application of optimization settings.
- **Backend Health Status Presentation**:
  - Main tab backend badge now supports richer status transitions (`AI: OK`, `AI: Degraded`, `AI: Offline`) with explanatory tooltips.
- **Supervisor Health Flow**:
  - Backend health resolution now routes through backend registry health contracts with compatibility fallback to availability checks.
- **HTTP Backend Client Lifecycle**:
  - HTTP backends now reuse shared `OkHttpClient` instances keyed by backend URL/timeout and close pools centrally on shutdown.
- **Token Estimation Accuracy**:
  - Token estimates now use backend-specific calibration factors and mix real usage values with estimated remainder when available.
- **CI Gate Strategy**:
  - PR pipeline now uses a fast verification gate (`test -PexcludeHeavyTests=true`) while preserving heavy suites for nightly runs.
- **Architecture and README References**:
  - Updated architecture and README docs to include schema migration behavior and operator playbook links.
- **Ollama context limit**:
  - Updated default Ollama Max Context Window to 256000.

### Fixed

- **Backend Registry Cache Lifecycle**:
  - Fixed `availabilityCache` lifecycle by clearing it on `reload()` and `shutdown()`.
  - Fixed initialization-order safety so cache is always available during startup/reload.
- **Repeated Passive AI Cost on Equivalent Traffic**:
  - Fixed repeated backend invocations for semantically identical passive traffic by combining endpoint/fingerprint dedup with prompt-result caching.
- **Unbounded Manual Context Growth**:
  - Fixed manual context actions sending oversized request/response payloads and pretty-printed JSON by introducing truncation + compact encoding.
- **Long-Session Prompt Inflation (HTTP Backends)**:
  - Fixed runaway history growth by adding total-character trimming in conversation history management.
- **HTTP Backend Client Churn**:
  - Fixed repeated per-request HTTP client construction that prevented efficient connection reuse.
- **Legacy Settings Drift**:
  - Fixed legacy preference normalization for MCP allowed origins and old Gemini default command values during migration.
- **Pre-Release Stability Hardening (Round 1)**:
  - Fixed `McpStdioBridge.stop()` potential deadlock by adding `withTimeoutOrNull(5s)` around transport/server close calls.
  - Fixed `KtorMcpServerManager.shutdown()` missing `shutdownNow()` fallback when `awaitTermination` times out.
  - Fixed `CliBackend` session ID race condition by replacing `@Volatile` with `AtomicReference` + `compareAndSet`.
  - Fixed `ChatPanel.deleteSession()` partial cleanup by wrapping in `try-finally` to guarantee map/model consistency.
  - Fixed `ChatPanel` unsafe `!!` on `coalescingTimer` with null-safe `?.let` pattern.
  - Fixed `ActiveAiScanner.startProcessing()` executor leak by calling `stopProcessing()` before creating new executors.
  - Fixed `McpSupervisor.shutdown()` ordering: scheduler now stops first with `awaitTermination` before server/bridge shutdown.
  - Fixed `AgentSupervisor.tryCapture()` missing `waitFor` timeout that could hang Burp startup on broken shell configs.
  - Fixed `McpSupervisor` HTTP connection leak in probe/shutdown methods by moving `disconnect()` to `finally` blocks.
  - Fixed `AgentSupervisor` service reader stream leak by wrapping `bufferedReader()` in `.use {}`.
  - Fixed `CliConnection` init resource leak by wrapping `readerExec.submit` in try-catch that calls `stop()` on failure.
  - Fixed `AiScanCheck` evidence showing "nullms" for time-based detection by adding null-coalescing fallback.
  - Fixed Gradle build failure on JDK 25 by pinning `org.gradle.java.home` to JDK 21.
- **Pre-Release Stability Hardening (Round 2)**:
  - Fixed `ConversationHistory.runningTotalChars` data race by replacing non-atomic `@Volatile +=` with `synchronized` block.
  - Fixed `NonInteractiveCliConnection.send()` crash after `stop()` by catching `RejectedExecutionException` and routing to `onComplete`.
  - Fixed `SettingsPanel` status refresh timer leak by promoting to class field with proper `shutdown()` lifecycle.
  - Fixed swallowed exception context in `AiScanCheck` registration log (now includes `e.message`).
  - Fixed chat session title serialization corruption when titles contain tab/control characters by adding `sanitizeTitle()`.
- **Additional Stability Hardening**:
  - Fixed agent profile cache torn reads by consolidating three `@Volatile` fields into single `AtomicReference<CacheEntry>`.
  - Fixed settings repository concurrent load performance by caching loaded settings via `AtomicReference`.
  - Fixed HTTP shared client pool accumulation by adding idle eviction after 10 minutes of inactivity.
  - Fixed active scanner issue creation race condition by protecting check-then-create with `ReentrantLock`.
  - Fixed active scanner dedup race condition by using atomic `putIfAbsent` instead of separate read-then-write.
  - Fixed CLI connection `stop()` missing executor termination wait by adding `awaitTermination` and `destroyForcibly()` fallback.
  - Fixed temporary prompt file permissions by setting POSIX owner-only read/write (600) before writing content.
  - Fixed agent supervisor concurrent lifecycle transitions by adding explicit `Starting` state and split-lock pattern.
  - Fixed cached CLI PATH initialization race by using `AtomicReference.compareAndSet` instead of `@Volatile`.
  - Fixed passive scanner regex recompilation in hot paths by promoting to pre-compiled companion object patterns.
  - Fixed CLI backend availability log spam by deduplicating with `AtomicBoolean.compareAndSet`.

## [0.2.0] - 2026-02-09

### Added

- **Chat UI Overhaul**: ChatGPT-style message bubbles with timestamps, hover-copy, and improved streaming layout.
- **Session Persistence**: Chat sessions (titles, messages, usage stats) are auto-saved and restored across Burp restarts.
- **Chat Export**: Export any session as Markdown via context menu or shortcut.
- **Keyboard Shortcuts**: New session, delete session, clear chat, export chat, and toggle settings panel.
- **Cancel In-Flight Requests**: Cancel current AI response directly from the chat UI.
- **Usage Stats Sidebar**: Total messages and per-backend usage displayed in the sessions sidebar.
- **Backend Availability Filtering**: Backend selector only shows backends that are available on this machine.
- **Cross-Platform CLI Resolution**: Robust PATH discovery (login shell capture + fallbacks) and executable resolution.
- **Markdown Rendering Enhancements**: Headings, blockquotes, horizontal rules, links, inline code, and improved code block styling.

### Changed

- **Settings Panel UX**: Collapsible settings panel with a compact toggle bar and improved focus styling.
- **Chat History Handling**: Controlled CLI history size to avoid oversized prompts while preserving context.
- **MCP Tool Errors**: Cleaner, action-oriented validation errors for missing tool arguments.

### Fixed

- **CLI Discovery Reliability**: Better detection of CLI tools when Burp is launched from a GUI environment.
- **Chat Session Backend Tracking**: Sessions now track the last backend used rather than only the creation backend.
- **UI State Safety**: Prevent stuck “sending” states when session panels are missing.
- **Chat Input Shortcuts**: Shift+Enter now reliably inserts a new line while Enter sends.
- **Chat Persistence Scope**: Chat history now persists per Burp project (with one-time migration from global storage).
- **Issue Detail Formatting**: AI Active and Passive issues now render line breaks and indented sections reliably.

## [0.1.4] - 2026-02-06

### Added

- **UI Backend Health Indicator**: Visual "AI: OK" / "AI: Offline" badge in the main tab top bar to monitor backend connectivity.
- **Active Scan Real-time Stats**: Live statistics (Queue, Processed, Confirmed) displayed in the active scanner toggle section.
- **Configurable Ollama Context Window**: Added `ollamaContextWindow` setting (default 8192) to prevent context exhaustion errors with larger inputs.
- **Shared Runtime Defaults**: New centralized defaults in `config/Defaults.kt` for scanner buffers, timeouts, dedup windows, queue limits, and other operational constants.
- **Scanner Shared Utilities**: New shared scanner helpers (`ScannerIssueSupport`, `ScannerUtils`) to remove duplicated severity/remediation/allowlist logic.
- **HTTP Backend Shared Support**: New `backends/http/HttpBackendSupport.kt` with shared HTTP client/retry utilities and reusable `ConversationHistory`.
- **Active Scanner Queue Backpressure**: Added configurable max queue capacity (`ACTIVE_SCAN_MAX_QUEUE_SIZE`, default 2000) to prevent unbounded queue growth.
- **Agent Profile Validation**: AGENTS profiles are now validated against currently enabled MCP tools, with warnings shown in Settings.
- **Architecture Documentation**: Added `docs/ARCHITECTURE.md` describing module boundaries, runtime flows, extension points, and invariants.
- **New Test Coverage**:
  - `ConversationHistory` trimming/concurrency tests.
  - `PayloadGenerator` context-aware and risk-filter tests.
  - `ResponseAnalyzer` diff/time-based tests.
  - Extended `InjectionPointExtractor` tests (escaped JSON strings, booleans, null).
  - Extended AGENTS profile loader tests for tool validation.

### Changed

- **Analysis Reasoning in Passive AI**: Added a `reasoning` field to AI passive scanner results, displaying the model's logic in Burp issue details to reduce false positives and improve transparency.
- **Structured Prompt Templates**: Upgraded all default templates to a modern, structured Markdown format (Role/Task/Scope/Output) for significantly better model performance and clarity.
- **Passive Scanner Optimization**: Significantly reduced prompt token usage (~50%) by consolidating instructions and grouping vulnerability definitions, improving performance and compatibility with smaller models.
- **Passive Scanner Concurrency/Startup Flow**:
  - Replaced one-time registration and backend startup flags with atomic control.
  - Replaced fixed startup sleep with bounded readiness polling.
  - Replaced response wait busy-loop with latch-based completion waiting.
- **Passive Scanner JSON Parsing**: Replaced fragile regex-only JSON extraction for AI results with Jackson-based parsing.
- **Injection Point Extraction**: JSON extraction now supports escaped strings, booleans and null values with Jackson-first parsing + safe regex fallback.
- **Settings Type Safety**: Migrated scanner settings from raw strings to enums (`SeverityLevel`, `PayloadRisk`, `ScanMode`) with compatibility-preserving load/save behavior.
- **HTTP Backends Refactor**: Ollama, LM Studio and OpenAI-compatible backends now use shared HTTP/retry/history support for reduced duplication and more consistent behavior.
- **Settings UI Modularization**: `SettingsPanel` now delegates section rendering to dedicated panel classes (`Backend`, `Passive`, `Active`, `MCP`, `Prompt`, `Privacy`, `Help`) for maintainability.
- **Context Menu Active Scan UX**:
  - Added explicit confirmation dialogs before active testing.
  - Added target validation and queue status visibility (current/max queue).
  - Added clearer warnings when targets are filtered or queue is full.

### Fixed

- **IDE Build Configuration**: Resolved Java 21 compatibility issues and removed unnecessary Eclipse plugins, enabling successful import and build in IDEs.
- **Context Loss Persistence**: Fixed an issue where chat context was lost for stateless CLI backends (Codex, Gemini, OpenCode).
- **History Management**: Implemented proper conversation history handling for CLI backends to simulate session continuity.
- **Claude CLI Prompt Limits**: Implemented file-based prompt passing for large inputs (>32k chars). Prompts exceeding the limit are now written to a temporary file which Claude is instructed to read, completely bypassing shell argument/STDIN size limits and preventing "Prompt is too long" errors without data loss.
- **Thread-Safety and Shutdown Reliability**:
  - Active scanner stop path now force-cancels and awaits termination.
  - Supervisor lifecycle transitions are lock-protected for safer start/stop/restart behavior.
  - Main tab timers are explicitly stopped on extension shutdown.
- **Resource Leak Prevention**:
  - External backend `URLClassLoader` lifecycle is now closed explicitly via `BackendRegistry.shutdown()`.
  - App shutdown now includes explicit backend registry shutdown.
- **Error Visibility**:
  - Reduced silent exception swallowing in operational paths (shutdown/supervisor/MCP/chat/profile loading), replacing with diagnostic logging where actionable.

## [0.1.3] - 2026-01-30

### Added

- Configurable request timeout for Ollama backend (30-3600 seconds, default 120s). Fixes timeouts with larger/slower models like `qwen3-coder:30b` in non-streaming mode.
- Bottom settings panel with native-style tabs for configuration sections.

### Changed

- Settings UI moved from right sidebar to a bottom split panel with a larger main workspace.
- Each settings category now has its own dedicated tab (AI Backend, AI Passive Scanner, AI Active Scanner, MCP Server, Burp Integration, Prompt Templates, Privacy & Logging, Help).
- Settings sections are always visible per tab (no accordion collapse).
- Burp Integration tool list uses a wider multi-column layout to better utilize horizontal space.
- Prompt templates use a full-width single-field-per-row layout.
- Bottom settings panel now collapses to a smaller minimum height when not in use.

## [0.1.2] - 2026-01-30

### Added

- Documentation notes for Windows npm shim paths (double backslashes) across CLI backends and settings reference.
- OpenAI-compatible URL behavior documentation, including `/vN` base URL handling.

### Changed

- Gemini CLI default command updated to `gemini --output-format text --model gemini-2.5-flash`.
- OpenAI-compatible backend now respects versioned base URLs by appending `/chat/completions` instead of forcing `/v1`.
- MCP environment variables expanded for wider CLI discovery (`MCP_SERVER_URL`, `MCP_SERVER`, `MCP_TOKEN`).

### Fixed

- Toggle switches now animate to the correct side when state changes programmatically.
- CLI embedded mode no longer hangs on stdout reads; timeouts return with output tail for debugging.
- OpenCode CLI sessions now return after idle output instead of timing out.

## [0.1.1] - 2026-01-29

### Added

- Targeted tests submenu in request context menu for focused active scans (SQLi, XSS, SSRF, IDOR, etc.).
- Generic OpenAI-compatible HTTP backend with configurable base URL, model, API key, extra headers, and timeout.
- Optional API key and custom headers for Ollama and LM Studio HTTP backends.
- Open CLI buttons in backend settings for CLI backends (Codex, Gemini, OpenCode, Claude, Ollama CLI).
- Each chat session now remembers the context from previous messages.
- Default prompt templates now instruct the AI to always answer in English.

### Changed

- Context menu action renamed from "Quick recon" to "Analyze this request".
- Active issues now use class-based names (e.g., `[AI Active] SQLI`) and consolidate duplicates per base URL.
- Passive issues normalize to `[AI Passive] <VULN_CLASS>` when possible and consolidate duplicates per base URL.
- Issue details are sanitized to plain text (markdown removed) across passive/active scanners and MCP `issue_create`.

### Fixed

- Windows failures when OpenCode is installed via npm and the command is set to `opencode.exe`.

## [0.1.0] - 2026-01-28

### Added

- Initial public release.
- 6 AI backends: Ollama, LM Studio, Gemini CLI, Claude CLI, Codex CLI, OpenCode CLI.
- MCP server with 53+ tools (SSE and STDIO transports).
- Passive AI Scanner with background traffic analysis.
- Active AI Scanner with 62 vulnerability classes and 3 scan modes (BUG_BOUNTY, PENTEST, FULL).
- 3 privacy modes (STRICT, BALANCED, OFF) with cookie stripping, token redaction, and host anonymization.
- Agent Profiles system (pentester, bughunter, auditor) with section-based action mapping.
- 9 customizable prompt templates for context menu actions.
- JSONL audit logging with SHA-256 integrity hashing.
- Determinism mode for reproducible prompt bundles.
- Drop-in custom backend support via ServiceLoader.
- Burp Pro integration: native ScanCheck, Collaborator OAST, scanner issue actions.
- Full GitBook documentation.
