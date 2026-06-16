# Architecture Decisions

This document records the significant architectural choices in Burp AI Agent and the reasons behind them. Each section follows the ADR (Architecture Decision Record) shape: context → decision → consequences. Decisions are not frozen — they can be revisited as the plugin evolves — but changing them should be intentional, not accidental.

## ADR-1: Kotlin on the JVM, not Java, not Scala

**Context.** Burp Suite is a JVM application and exposes its extension API (Montoya) as Java interfaces. The plugin must run in the same JVM as Burp, which restricts the language to one that compiles to JVM bytecode. Burp itself already bundles a JDK at runtime, so there is no cost to targeting the JVM.

**Decision.** Write the plugin in Kotlin, not Java, and not Scala.

**Consequences.**
- Null-safety, data classes, sealed classes, and coroutines remove a large class of bugs that are easy to hit with a plugin that glues AI reasoning to HTTP traffic.
- New contributors familiar with Java can still read and edit Kotlin; the learning curve is much smaller than Scala's.
- Tooling (Gradle Kotlin DSL, IntelliJ, ktlint) is first-class. We pay nothing for it.
- Trade-off: we rely on Kotlin stdlib in the shadow JAR (~1.6 MB). Acceptable.

## ADR-2: Swing for the UI, not JavaFX or Compose

**Context.** The Burp extension tab is embedded inside Burp's own Swing UI via `api.userInterface().registerSuiteTab(…)`. Any other UI toolkit would either need to be hosted inside Swing (fragile) or rendered in a separate window (breaks the user's mental model of "my plugin lives inside Burp").

**Decision.** Use Swing directly.

**Consequences.**
- Zero friction with Burp's theme and keyboard handling.
- We inherit Swing's verbosity (GridBagLayout, BorderLayout, explicit EDT handling). We accept it and wrap repeated patterns in helpers (`ToggleSwitch`, `AccordionPanel`, `ActionCard`, `ContextPreviewDialog`).
- Testing UI components is painful. We mitigate by keeping UI components thin shells over pure-Kotlin logic that is tested directly.

## ADR-3: Pluggable backends via `ServiceLoader`

**Context.** The plugin supports many AI backends (Ollama, LM Studio, NVIDIA NIM, Claude CLI, Gemini CLI, Codex CLI, OpenCode CLI, Copilot CLI, Burp native AI). New backends appear regularly, and users sometimes need a private backend that cannot live in the open-source repo.

**Decision.** Backends implement the `AgentBackend` interface and are discovered via Java's `ServiceLoader` mechanism. Backends bundled in-tree are registered by `META-INF/services` entries. External backends are loaded from JARs the user drops into `~/.burp-ai-agent/backends/` via a dedicated `URLClassLoader` with proper close-on-fail handling.

**Consequences.**
- Adding a new backend is a one-file change (implementation + SPI entry) with no modifications to core code.
- Users can ship their own closed-source backend without forking the project.
- Trade-off: `ServiceLoader` gives us no dependency injection. Backends receive the Montoya API and settings via constructor; we do not inject fakes in tests. Backends are therefore tested with real `AgentSupervisor`-shaped wrappers.

## ADR-4: HTTP backends and CLI backends share an interface, split their implementation

**Context.** Some backends are local HTTP servers (Ollama, LM Studio, NVIDIA NIM, generic OpenAI-compatible). Others are command-line tools that manage their own authentication and state (Claude CLI, Gemini CLI, Codex CLI, OpenCode CLI, Copilot CLI). Both have to expose the same abstraction (`send prompt, stream chunks, return or error`), but the implementation diverges sharply (HTTP client with retry/backoff vs process supervisor with session resume).

**Decision.** Define a single `AgentConnection` / `AgentBackend` contract, and split the implementation in two base classes: `HttpBackendSupport` (shares OkHttp client, retry policy, conversation history, circuit breaker) and `CliBackend` (shares process supervision, session ID management, file-based prompt transfer for long inputs, Windows command normalization).

**Consequences.**
- New HTTP backends implement a thin subclass that knows only the request/response shape.
- CLI process concerns (quoting, env, cwd, kill on shutdown) live in one place.
- We accept that the two hierarchies will drift over time. When they do, we move the shared concern into a third helper, not into a shared superclass.

## ADR-5: Privacy redaction runs pre-flight and is a user-visible mode, not a silent default

**Context.** The plugin sends captured HTTP traffic to external AI backends. Cookies, `Authorization` headers, JWTs, and URL tokens are routinely in that traffic. If we send them raw, we make the user's API keys and session tokens visible to a third-party AI provider — possibly in their training data.

**Decision.** Define three privacy modes — `STRICT`, `BALANCED`, `OFF` — and run redaction (`RedactionPolicy`, `Redaction.apply`) before any captured traffic leaves the plugin. The default for new users is `BALANCED` (cookies and tokens redacted, hosts kept). `STRICT` also anonymizes hosts via HKDF. `OFF` exists for users who know what they are doing on private local models.

**Consequences.**
- The regex set that drives redaction is a hand-curated list of common header names and URL parameter names; it is not exhaustive. We accept false negatives and tighten the list when new patterns appear (last tightened for `X-Auth-Token`, `X-Access-Token`, `X-CSRF-Token`, `X-Api-Secret`, Basic auth, and query-string tokens).
- The UI shows the current mode in a pill on the main tab and on every context preview dialog, so users never send traffic without knowing which rules are active.
- Audit logs store only hashes of prompt bodies by default, not the bodies themselves.

## ADR-6: MCP server is embedded in the plugin, not a separate process

**Context.** We want to expose Burp tools (proxy history, site map, scope check, `issue_create`, `http1_request`, …) to external AI agents (Claude Desktop, Codex CLI, etc.) over the Model Context Protocol. MCP can be served over stdio or over SSE/HTTP. A separate process would let us isolate the server but would require us to replicate scope, session, and Burp API access.

**Decision.** Embed an MCP server inside the plugin's JVM using Ktor (SSE + optional stdio bridge), backed by the Montoya API directly. The server binds to `127.0.0.1` by default and is protected by a bearer token generated with `SecureRandom`. External access is an explicit opt-in and unlocks TLS.

**Consequences.**
- Tools see live Burp state without any IPC layer. No desync, no cache invalidation problem.
- The plugin's lifecycle owns the MCP server's lifecycle — shutdown is trivial.
- Trade-off: a crash in the MCP server can take the plugin down. `McpSupervisor` + restart policy mitigates this; heavy request concurrency is capped by `McpRequestLimiter`.
- Unsafe tools (anything that mutates Burp state — `http1_request`, `issue_create`, `repeater_tab`, `intruder`, `collaborator_register`) are gated by a separate master switch that is off by default.

## ADR-7: Audit logging is JSONL, hash-stamped, and disabled by default

**Context.** Compliance and incident response teams need a tamper-evident record of what prompts the plugin sent to which backend, and what responses came back. Writing full prompts to disk on every request, however, duplicates sensitive data and costs performance. Writing nothing leaves us blind in a post-mortem.

**Decision.** Use an append-only JSONL log (`~/.burp-ai-agent/logs/audit.jsonl`, rolled by size). Every entry records backend id, model, trace id, prompt hash (SHA-256), response hash, privacy mode, and timings. Full prompt bodies are written only when the operator enables verbose mode. The audit subsystem is disabled by default; the user enables it in Settings.

**Consequences.**
- Default behavior is zero disk I/O for compliance.
- When enabled, the log is grep-able and diff-able and can be rotated by standard log tools.
- Trade-off: verifying a hash from the log against a prompt the user remembers sending requires the operator to have verbose mode on at the time of capture. This is documented in the hardening runbook.

## ADR-8: AES-256-GCM encryption for secrets at rest (SEC-01)

**Context.** Seven or more secrets (all backend API keys, `mcp.token`, `mcp.tls.keystore.password`) were persisted in plaintext in Burp's Preferences store. Vendoring Bouncy Castle or Google Tink would add a heavy dependency at risk of fat-JAR class conflicts with whatever Burp itself bundles.

**Decision.** Encrypt all stored secrets with AES-256-GCM via `javax.crypto` (bundled in the JVM). A per-install random 256-bit master key is generated on first use. Encrypted values are prefixed with `ENC1:` for idempotent migration detection.

**Consequences.**
- No new runtime dependency; the JVM's built-in crypto covers the requirement.
- Existing plaintext secrets are migrated automatically on first load after upgrade.
- The `ENC1:` prefix allows safe forward/backward migration: a plaintext value without the prefix is used as-is (legacy pass-through) until it is next written.

## ADR-9: Real HKDF for STRICT-mode host anonymization (PRIV-01)

**Context.** STRICT privacy mode documented "HKDF host anonymization" but the implementation used salted `MessageDigest.getInstance("SHA-256")` — a standard hash function, not HKDF. The privacy guarantee stated in documentation was not delivered.

**Decision.** Replace `MessageDigest.getInstance("SHA-256")` with `Mac.getInstance("HmacSHA256")` extract/expand (proper HKDF per RFC 5869). `SecretShapes` becomes the single AWT-free source of truth for privacy-curated patterns and the HKDF implementation.

**Consequences.**
- Anonymized host values change on upgrade from any prior version (expected; anonymization is not required to be stable across versions — only stable within a session).
- Existing tests that asserted the salted-SHA-256 output were updated to match the HKDF output.
- `SecretShapes` is now the canonical place for any future privacy-pattern additions.

## ADR-10: Anthropic backend uses MontoyaHttpTransport, not a vendored Anthropic SDK (CAP-01)

**Context.** Direct Anthropic API access was the top user-requested backend. Vendoring the official Anthropic Java/Kotlin SDK would embed its own OkHttp client, bypassing `MontoyaHttpTransport` and repeating the silent-exfiltration regression fixed in Phase 7 (#69), where HTTP backends could send AI traffic without it appearing in Burp's proxy or upstream proxy.

**Decision.** Implement `AnthropicBackend` using the existing `HttpBackendSupport` base class and `MontoyaHttpTransport`, calling the Anthropic Messages API (`/v1/messages`) directly. No vendored Anthropic SDK is included.

**Consequences.**
- All Anthropic API traffic (requests and responses) appears in Burp's Proxy > HTTP history, where it can be inspected, replayed, and intercepted.
- The API key is encrypted at rest via ADR-8 (SEC-01).
- Native tool-use and prompt-caching features of the Anthropic API are deferred; the current implementation covers single-turn and streaming chat completions.

## ADR-11: External MCP client wraps untrusted server output in a trust-boundary marker (CAP-02)

**Context.** External MCP servers registered by the user may be attacker-controlled, compromised, or return maliciously crafted tool results. If those results are fed directly into the AI prompt without marking, they constitute an untrusted injection surface — a classic prompt-injection attack vector.

**Decision.** Wrap all external MCP server tool results in an explicit trust-boundary marker string before they are concatenated into the AI context. The kotlin-mcp-sdk 0.5.0 (already present from the built-in MCP server) provides `SseClientTransport` and `StdioClientTransport` — no SDK version bump is required (Path A confirmed).

**Consequences.**
- Prompt-injection from untrusted external server responses is bounded by the trust-boundary marker; the AI prompt structure makes the boundary explicit.
- Auth tokens for external servers are stored encrypted (ADR-8 / SEC-01).
- All external tool invocations are recorded in the audit log for traceability.
- A non-loopback SSE URL triggers a runtime SSRF warning before the connection is made.

## ADR-12: Per-session token-budget guardrails via BudgetGuard (CAP-04)

**Context.** Long passive-scan sessions could exhaust user API token budgets silently or unpredictably, especially with cloud backends like Anthropic or Perplexity that charge per token.

**Decision.** Introduce `BudgetGuard`, a pure object with three reversible states: `OFF` (no limit), `WARN` (advisory warning shown in UI), and `CAP` (passive scanner pauses automatically). Both the warn threshold and hard cap are user-configurable; `0` means unlimited (off). State is per-session and does not persist across Burp restarts.

**Consequences.**
- Users can cap per-session spend; the passive scanner pauses automatically when the hard cap fires and resumes when the cap is raised or cleared.
- No token-count state leaks between sessions.
- The `BudgetGuard` object is pure and testable independently of the scanner lifecycle.
