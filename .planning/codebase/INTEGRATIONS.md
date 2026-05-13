# External Integrations

**Analysis Date:** 2026-05-13

## Burp Suite Host Application

**Burp Montoya API:**
- SDK: `net.portswigger.burp.extensions:montoya-api:2026.2` (compileOnly)
- Entry point: `BurpAiAgentExtension` implements `BurpExtension`, called by Burp on load
- Key interfaces used: `MontoyaApi`, `api.http()`, `api.ai()`, `api.logging()`, `api.persistence().preferences()`, `api.userInterface()`, `api.scanner()`, `api.collaborator()`, `api.burpSuite()`
- HTTP transport wrapper: `src/main/kotlin/com/six2dez/burp/aiagent/backends/http/MontoyaHttpTransport.kt` — routes AI backend HTTP calls through Burp's own HTTP engine (respects Burp proxy settings and TLS)
- Settings storage: `burp.api.montoya.persistence.Preferences` — all `AgentSettings` fields serialized as Burp project preferences (no external config files)

## AI Backends

The backend system uses a ServiceLoader SPI (`META-INF/services/com.six2dez.burp.aiagent.backends.AiBackendFactory`). All backends implement `AiBackend` / `AgentConnection`. Settings are in `AgentSettings` fields; no API keys are stored outside Burp Preferences.

### Burp AI (Built-in)

- **What:** Burp Suite's built-in AI accessed via `api.ai().prompt().execute()`
- **Transport:** Burp internal (no HTTP; Montoya API calls only)
- **Auth:** Managed entirely by Burp Suite; extension has no access to credentials
- **Availability:** Requires "Use AI" enabled in Burp settings; `api.ai().isEnabled()` is checked
- **Implementation:** `src/main/kotlin/com/six2dez/burp/aiagent/backends/burpai/BurpAiBackend.kt`
- **Config fields:** None (no user-configurable URL or key)

### Ollama (Local HTTP)

- **What:** Local Ollama server; OpenAI-compatible chat API (`/api/chat`, `/api/show`, `/api/tags`)
- **Default URL:** `http://127.0.0.1:11434`
- **Transport:** Montoya HTTP transport when available; OkHttp3 fallback
- **Auth:** Optional Bearer token via `ollamaApiKey`; custom headers via `ollamaHeaders`
- **Config fields:** `ollamaUrl`, `ollamaModel`, `ollamaApiKey`, `ollamaHeaders`, `ollamaTimeoutSeconds`, `ollamaContextWindow`, `ollamaAutoStart`, `ollamaServeCmd`, `ollamaCliCmd`
- **Implementation:** `src/main/kotlin/com/six2dez/burp/aiagent/backends/ollama/OllamaBackend.kt`
- **Notes:** Detects model context window via `/api/show` on launch; supports circuit breaker with up to 6 retries

### LM Studio (Local HTTP)

- **What:** Local LM Studio server; OpenAI-compatible `/v1/chat/completions`
- **Default URL:** `http://127.0.0.1:1234`
- **Transport:** Montoya HTTP transport when available; OkHttp3 fallback
- **Auth:** Optional API key; custom headers
- **Config fields:** `lmStudioUrl`, `lmStudioModel`, `lmStudioApiKey`, `lmStudioHeaders`, `lmStudioTimeoutSeconds`, `lmStudioAutoStart`, `lmStudioServerCmd`
- **Implementation:** `src/main/kotlin/com/six2dez/burp/aiagent/backends/lmstudio/LmStudioBackend.kt`

### Generic OpenAI-Compatible (HTTP)

- **What:** Any endpoint conforming to the OpenAI Chat Completions API shape
- **Default URL:** User-configured
- **Transport:** Montoya HTTP / OkHttp3 fallback; supports both streaming (SSE) and non-streaming
- **Auth:** Bearer token via `openAiCompatibleApiKey`; custom headers
- **Config fields:** `openAiCompatibleUrl`, `openAiCompatibleModel`, `openAiCompatibleApiKey`, `openAiCompatibleHeaders`, `openAiCompatibleTimeoutSeconds`
- **Implementation:** `src/main/kotlin/com/six2dez/burp/aiagent/backends/openai/OpenAiCompatibleBackend.kt`
- **Notes:** URL normalization handles bare host, `/v1`, `/v1/chat/completions` variants automatically; used as the base class for Perplexity and NVIDIA NIM

### NVIDIA NIM (HTTP)

- **What:** NVIDIA NIM cloud inference API (OpenAI-compatible)
- **Default URL:** `https://integrate.api.nvidia.com`
- **Endpoint:** `/v1/chat/completions`
- **Transport:** Montoya HTTP / OkHttp3 fallback; streaming (SSE)
- **Auth:** Bearer token via `nvidiaNimApiKey`
- **Config fields:** `nvidiaNimUrl`, `nvidiaNimModel`, `nvidiaNimApiKey`, `nvidiaNimHeaders`, `nvidiaNimTimeoutSeconds`
- **Implementation:** `src/main/kotlin/com/six2dez/burp/aiagent/backends/nvidia/NvidiaNimBackendFactory.kt`
- **Notes:** Injects `chat_template_kwargs: {thinking: true}`, `top_p: 1.0`, `max_tokens: 16384` into all payloads

### Perplexity (HTTP)

- **What:** Perplexity AI Sonar API (OpenAI-compatible with differences)
- **Default URL:** `https://api.perplexity.ai`
- **Endpoint:** `/chat/completions` (no `/v1` prefix)
- **Transport:** Montoya HTTP / OkHttp3 fallback; streaming (SSE with `Accept: text/event-stream`)
- **Auth:** Bearer token via `perplexityApiKey`
- **Config fields:** `perplexityUrl`, `perplexityModel`, `perplexityApiKey`, `perplexityHeaders`, `perplexityTimeoutSeconds`
- **Implementation:** `src/main/kotlin/com/six2dez/burp/aiagent/backends/perplexity/PerplexityBackendFactory.kt`
- **Notes:** Does NOT send `response_format: {type: json_object}` (Sonar API rejects it); health check sends a live probe request

### Claude CLI (subprocess)

- **What:** Anthropic Claude Code CLI (`claude -p`)
- **Transport:** OS subprocess; prompt sent via stdin (or temp file for prompts >32 KB)
- **Auth:** CLI handles its own auth (Anthropic account / API key in CLI config)
- **Config fields:** `claudeCmd` (path/command to the `claude` binary)
- **Implementation:** `src/main/kotlin/com/six2dez/burp/aiagent/backends/cli/CliBackend.kt` + `ClaudeCliBackendFactory.kt`
- **Notes:** Supports `--resume <session-id>` for conversation continuity; temp prompt files written with POSIX owner-only permissions (600); PTY wrapping via `script` on macOS/Linux for interactive mode

### Gemini CLI (subprocess)

- **What:** Google Gemini CLI
- **Transport:** OS subprocess; prompt sent via stdin; `--output-format text`
- **Auth:** CLI handles its own auth (Google account / cached credentials)
- **Config fields:** `geminiCmd`
- **Implementation:** `src/main/kotlin/com/six2dez/burp/aiagent/backends/cli/CliBackend.kt` + `GeminiCliBackendFactory.kt`
- **Notes:** Noise-line filtering removes Gemini startup banners, MCP server discovery messages, and policy denial lines from output

### Codex CLI (subprocess)

- **What:** OpenAI Codex CLI
- **Transport:** OS subprocess; prompt via stdin; output captured via `--output-last-message <file>` temp file
- **Auth:** CLI handles its own auth
- **Config fields:** `codexCmd`
- **Implementation:** `src/main/kotlin/com/six2dez/burp/aiagent/backends/cli/CliBackend.kt` + `CodexCliBackendFactory.kt`
- **Notes:** Uses `exec --color never --skip-git-repo-check` subcommand; output captured from temp file when available, stdout otherwise

### OpenCode CLI (subprocess)

- **What:** OpenCode AI coding assistant CLI
- **Transport:** OS subprocess; `opencode run <prompt>` invocation (no stdin)
- **Auth:** CLI handles its own auth
- **Config fields:** `opencodeCmd`
- **Implementation:** `src/main/kotlin/com/six2dez/burp/aiagent/backends/cli/CliBackend.kt` + `OpenCodeCliBackendFactory.kt`
- **Notes:** Idle-timeout detection (30 s of no output after first output) triggers `destroyForcibly()`; output deduplication uses 40-char minimum line length to avoid false-positive filtering

### Copilot CLI (subprocess)

- **What:** GitHub Copilot CLI (`gh copilot` or standalone `copilot`)
- **Transport:** OS subprocess; prompt sent via stdin; `--quiet` flag suppresses banners
- **Auth:** CLI handles its own auth (GitHub account)
- **Config fields:** `copilotCmd`
- **Implementation:** `src/main/kotlin/com/six2dez/burp/aiagent/backends/cli/CliBackend.kt` + `CopilotCliBackendFactory.kt`

## MCP Protocol Server

**Embedded MCP server exposed to AI clients (Claude Desktop, Gemini CLI, Cursor, etc.):**

- **Transport 1 — SSE (HTTP):** Ktor/Netty server; default loopback (`127.0.0.1:7070`); optional TLS via PKCS12 keystore
  - Implementation: `src/main/kotlin/com/six2dez/burp/aiagent/mcp/KtorMcpServerManager.kt`
  - Endpoints: `GET /__mcp/health`, `POST /__mcp/shutdown`, MCP SSE routes
  - Auth: Bearer token (constant-time comparison via `MessageDigest.isEqual`)
  - CORS: loopback-only by default; configurable allowlist for external mode
  - Security headers: `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, `Content-Security-Policy: default-src 'none'`

- **Transport 2 — stdio:** MCP SDK `StdioServerTransport`; launched when `stdioEnabled = true`
  - Implementation: `src/main/kotlin/com/six2dez/burp/aiagent/mcp/McpStdioBridge.kt`

- **TLS:** Self-signed cert auto-generated via `keytool` if `tlsAutoGenerate = true`; PKCS12 keystore path configured by user
  - Implementation: `src/main/kotlin/com/six2dez/burp/aiagent/mcp/McpTls.kt`

- **MCP Tools registered:** history, site-map, request replay, scanner (active/passive), Collaborator, config, editor, issues, utility
  - Tool registration: `src/main/kotlin/com/six2dez/burp/aiagent/mcp/tools/McpTools.kt`

- **Rate limiting:** `src/main/kotlin/com/six2dez/burp/aiagent/mcp/McpRequestLimiter.kt` — concurrent request cap (configurable via `maxConcurrentRequests`)

- **Config fields:** `McpSettings` — `enabled`, `host`, `port`, `externalEnabled`, `stdioEnabled`, `token`, `allowedOrigins`, `tlsEnabled`, `tlsAutoGenerate`, `tlsKeystorePath`, `tlsKeystorePassword`, `scanTaskTtlMinutes`, `collaboratorClientTtlMinutes`, `maxConcurrentRequests`, `maxBodyBytes`, `toolToggles`, `enabledUnsafeTools`, `unsafeEnabled`

## Local Filesystem

**Base directory:** `~/.burp-ai-agent/` (created automatically at startup)

| Path | Purpose |
|------|---------|
| `~/.burp-ai-agent/audit.jsonl` | Append-only JSONL audit log of all AI requests (`AuditLogger`) |
| `~/.burp-ai-agent/bundles/` | Per-session prompt bundle JSON and ZIP exports (`AuditLogger.writePromptBundle`) |
| `~/.burp-ai-agent/contexts/` | Serialized context snapshots linked to audit bundles |
| `~/.burp-ai-agent/cache/` | Persistent passive-scan prompt cache (JSON files keyed by prompt SHA-256; `PersistentPromptCache`) |
| `~/.burp-ai-agent/backends/` | Drop-in external backend JARs loaded via `URLClassLoader` (`BackendRegistry.loadExternalBackendJars`) |
| `~/.burp-ai-agent/<tls-keystore>.p12` | User-configured or auto-generated PKCS12 keystore for MCP TLS |

## Outbound Webhooks (Alerting)

**What:** Optional best-effort webhook notifications (e.g., Slack-compatible JSON payload `{"text": "..."}`)
- Implementation: `src/main/kotlin/com/six2dez/burp/aiagent/alerts/Alerting.kt`
- Transport: Montoya HTTP when available; OkHttp3 fallback
- Config: Webhook URL stored in `AgentSettings` (user-provided)
- Error handling: Exceptions are silently swallowed; delivery is explicitly best-effort

## CI/CD Pipeline (GitHub Actions)

**Three workflows in `.github/workflows/`:**

| Workflow | File | Trigger |
|----------|------|---------|
| Build & PR Gate | `build.yml` | Push/PR to `main` |
| Nightly Regression | `nightly-regression.yml` | Cron `03:30 UTC` daily + manual |
| Release | `release.yml` | Push of `v*` tag |

**PR Gate steps:** ktlint check → fast test suite (heavy tests excluded) → shadow JAR build; matrix: `ubuntu-latest`, `macos-latest`, `windows-latest`

**Release pipeline steps:** ktlint → full test suite (including `nightlyRegressionTest`) → shadow JAR → CycloneDX SBOM → SHA-256 checksum → GitHub Release with CHANGELOG extract + SBOM + JAR + checksum attached

**JDK provisioning:** Eclipse Temurin 21 via `actions/setup-java@v5`

**Artifact names:**
- JAR: `Custom-AI-Agent-{version}.jar`
- SBOM: `bom.json` (CycloneDX JSON, runtime classpath only)
- Coverage: JaCoCo XML + HTML (uploaded as CI artifact on Linux runners)

## Data Storage

**Databases:** None — no external database. All persistent state uses:
1. Burp `Preferences` API (project/user settings)
2. Local filesystem under `~/.burp-ai-agent/`

**File Storage:** Local filesystem only (see Local Filesystem section above)

**Caching:** In-memory LRU caches (endpoint dedup, response fingerprint dedup, prompt cache) and on-disk `PersistentPromptCache` in `~/.burp-ai-agent/cache/`

## Authentication

**Extension auth model:** No centralized auth system. Each integration handles credentials independently:
- HTTP backends: Bearer tokens in `AgentSettings` fields (stored via Burp Preferences; shown as password fields in UI)
- CLI backends: Auth delegated entirely to the CLI tool's own credential store
- MCP server: Per-server Bearer token (`McpSettings.token`), auto-generated with `SecureRandom` if not set
- Burp AI: Managed by Burp Suite itself; extension cannot access credentials

## Monitoring & Observability

**Error Tracking:** None (no Sentry, Rollbar, etc.)

**Logs:**
- `api.logging().logToOutput()` / `api.logging().logToError()` — visible in Burp's Extensions output tab
- `BackendDiagnostics.log()` / `BackendDiagnostics.logError()` — wrapper around Burp logging for backend-layer messages
- Audit JSONL (`~/.burp-ai-agent/audit.jsonl`) — structured record of every AI prompt/response event with SHA-256 payload hash

---

*Integration audit: 2026-05-13*
