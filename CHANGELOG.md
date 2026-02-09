# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/), and this project adheres to [Semantic Versioning](https://semver.org/).

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
