# Project Research Summary

**Project:** Burp AI Agent v0.9.0 — Hardening, Quality & New Capabilities
**Domain:** Privacy-first Burp Suite Extension (Kotlin/JVM) — AI agent with pluggable backends
**Researched:** 2026-06-10
**Confidence:** HIGH

## Executive Summary

Burp AI Agent v0.9.0 is a security-tool milestone that adds five new capabilities (Anthropic backend, secret encryption, secret tripwire, listener port filter, token budget) alongside a high-novelty new subsystem (external MCP client) and a pure-refactor quality pass (mega-file splits + detekt). The research converged on a disciplined "no new runtime dependencies" policy for every item except the MCP SDK version bump required by C3: C1 reuses OkHttp + MontoyaHttpTransport + Jackson/kotlinx, C2 uses only javax.crypto (AES-256-GCM + PBKDF2), and C4 uses inline Kotlin + curated regex. The sole runtime dependency change is upgrading io.modelcontextprotocol:kotlin-sdk from 0.5.0 to 0.13.0 (which carries Ktor from 3.1.3 to 3.4.3 and a kotlin-stdlib transitive bump to 2.3.21). The build-time addition of detekt 1.23.8 does not affect the fat JAR.

The canonical core-value guardrail must be enforced at every turn: AI traffic must never bypass MontoyaHttpTransport. The existing HttpBackendSupport.sharedClient is explicitly marked test-only; copying it into AnthropicBackend would recreate the exact regression closed by issue #69. Every new backend, every health check, every streaming call must be routed through the Burp-proxy-aware MontoyaHttpTransport. The redaction pipeline (STRICT/BALANCED/OFF) must run before serializing any payload to any AI backend — Anthropic is not an exception.

Build order is the central planning constraint for this milestone. C2 (encrypt secrets at rest) must land before C1 (Anthropic backend) because the new Anthropic API key must be encrypted from day one. C4 (secret tripwire) depends on C2 being complete so existing keys are no longer in plaintext before the tripwire post-redaction scan becomes meaningful. C3 (external MCP client) depends on C2 because HTTP server bearer tokens must be encrypted. B1 (mega-file split) must come last: the C4 hooks land inside PassiveAiScanner methods that will move during the split, and splitting before hooking produces large, hard-to-review diffs. The correct serialization is C2 -> C1 -> C4 -> C3 -> B1, with C5 and C7 being independent and safe to interleave with C1 or C4.

## Key Findings

### Recommended Stack

The v0.9.0 additions require minimal stack change. All five "new" features are implemented on top of the existing Kotlin 2.1.21 / JVM 21 / Montoya API / OkHttp 4.12.0 / Jackson 2.21.2 / kotlinx-serialization 1.8.1 platform. No new runtime JAR is added to the fat JAR for C1, C2, or C4. The only runtime artifact change is the MCP SDK bump required for C3 client transports. The build-time addition of detekt 1.23.8 (Apache-2.0) is a Gradle plugin only and adds zero bytes to the extension JAR.

**Core technologies for v0.9.0 additions:**
- `javax.crypto` (JDK 21 built-in): AES-256-GCM + PBKDF2WithHmacSHA256 for C2 — zero-dependency, hardware-accelerated via AES-NI, fully portable across macOS/Linux/Windows
- `io.modelcontextprotocol:kotlin-sdk:0.13.0` (Apache-2.0): replaces 0.5.0; required for documented MCP client transports (StdioClientTransport, StreamableHttpClientTransport); carries Ktor 3.4.3 — must pin ktor-bom:3.4.3 platform BOM or explicit version pins
- `io.gitlab.arturbosch.detekt:detekt-gradle-plugin:1.23.8` (Apache-2.0): build-time only; use 1.23.8 stable with Kotlin 2.1.x warning workaround (not the 2.0.0-alpha.3); generate detekt-baseline.xml before enabling blocking gate

**Explicitly rejected alternatives:**
- `com.anthropic:anthropic-java:2.40.1` — ships its own OkHttp tree; cannot route through MontoyaHttpTransport without shims; bloats fat JAR by several MB
- `com.google.crypto.tink:tink:1.21.0` — transitive protobuf-java:4.33.0 clashes with Burp internal Protobuf; pulls Gson alongside Jackson; zero capability gain over javax.crypto for AES-GCM
- `com.github.javakeyring:java-keyring:1.0.4` — maintenance-mode (last release Aug 2023); Linux path requires libsecret daemon (unreliable in headless/pentest environments)

### Expected Features

The research distinguishes features that are table stakes for a professional security tool from features that are genuine differentiators.

**Must have (table stakes for v0.9.0):**
- C1: Native Anthropic Messages API backend — Claude is the default AI for most security researchers; every other cloud backend is natively integrated; gap is conspicuous
- C2: Encrypt API keys and TLS keystore password at rest — no professional tool stores credentials in plaintext; current v0.8.0 state is a known gap
- C4: Pre-send secret tripwire — redaction pipeline already exists; users assume it covers AWS keys and GitHub tokens in request bodies, not just headers
- C5: Proxy-history listener port filter (issue #70) — standard proxy-tool UX; LOW complexity, single field addition
- C7: Per-session token-budget guardrails — any metered API tool is expected to surface consumption and enforce caps

**Should have (differentiators for v0.9.0 or v0.9.x):**
- C3: External/custom MCP servers — lets users connect any MCP-compatible tool without building a Burp extension; no other Burp AI integration does this; highest novelty and highest build risk of the milestone
- C1 prompt caching via cache_control — dramatically reduces cost for long scanning sessions; no other Burp AI integration does this; additive once C1 core ships

**Defer (v1.0.0+):**
- C1 cache pre-warming (send max_tokens:0 to populate cache before first user turn) — additive optimization; defer until C1 core is stable
- OS keychain integration via java-keyring — maintenance-mode library; Linux path unreliable; revisit when a maintained cross-platform alternative emerges

**Anti-features to avoid:**
- Auto-sending context to Anthropic without redaction pipeline — violates the non-negotiable core value
- Storing the master passphrase beyond session unlock (must use CharArray, zeroed immediately after KDF call)
- Auto-registering all external MCP tools in Unsafe mode — bypasses the Unsafe Mode master switch
- Secret tripwire hard-blocking without user override — blocks legitimate pentest payloads; users will disable the feature entirely

### Architecture Approach

The extension already has a clean layered architecture: AgentSupervisor -> AiBackend (ServiceLoader-discovered) -> HttpBackendSupport -> MontoyaHttpTransport -> OkHttp. All v0.9.0 features insert into this existing structure without restructuring it. C2 inserts a SecretStore wrapper exclusively at the AgentSettingsRepository persistence boundary — AgentSettings holds plaintext at runtime, encryption is an I/O concern only. C1 adds AnthropicBackend as a peer to the existing OpenAI-compatible backends using the identical constructor-injection pattern. C4 adds SecretTripwire as a post-redaction gate at three specific hook points. C3 adds McpClientManager as a peer to McpSupervisor (not inside it), injected via the existing setAiToolDependencies() pathway.

**New components:**
1. `config/SecretStore.kt` — AES-256-GCM + PBKDF2 utility; under 100 lines; no Montoya dependency; encrypt/decrypt at persistence I/O boundary only
2. `backends/anthropic/AnthropicBackend.kt` + `AnthropicBackendFactory.kt` — implements AiBackend; uses MontoyaHttpTransport exclusively; registered via META-INF/services + BackendRegistry fallback list
3. `redact/SecretTripwire.kt` — post-redaction pattern scanner; ~15 curated regexes + Shannon entropy check; hooks into McpToolContext.redactIfNeeded(), ChatPanel.sendMessage(), PassiveAiScanner send paths
4. `mcp/McpClientManager.kt` + `mcp/ExternalMcpServerConfig.kt` — external MCP client pool; SSE and stdio transports; peer to McpSupervisor

**Modified components (scoped changes):**
- `config/AgentSettings.kt` (repository only): wrap 8 secret preference keys with SecretStore.encrypt/decrypt; add migrateToSchemaV4(); bump CURRENT_SETTINGS_SCHEMA_VERSION to 4
- `config/AgentSettings.kt` (data class): add three Anthropic fields (anthropicModel, anthropicApiKey, anthropicTimeoutSeconds)
- `mcp/McpToolContext.kt`: add externalMcpClient field; call SecretTripwire inside redactIfNeeded()
- `ui/ChatPanel.kt`: SecretTripwire hook after finalPrompt assembly, before supervisor.sendChat()
- `scanner/PassiveAiScanner.kt`: SecretTripwire hook in sendSingleAnalysis() and flushBatch()

### Critical Pitfalls

1. **C1-1: Anthropic traffic bypassing MontoyaHttpTransport** — AnthropicBackend must have zero OkHttpClient references on the production code path. HttpBackendSupport.sharedClient is test-only and must not be copied into launch(). Add a runtime assertion: check(config.transport != null). Verify with grep OkHttp AnthropicBackend.kt returning empty. This is a privacy and architectural regression identical to the #69 bug.

2. **C2-2: Migration wiping existing plaintext API keys** — Schema V4 migration must read-encrypt-verify-then-clear, not read-clear-then-encrypt. If encryption of any key fails, abort migration for that key, log a user-visible error, and leave the plaintext value intact. Round-trip verify must pass before the plaintext entry is overwritten. A silent migration failure leaves the user with a blank settings screen.

3. **C2-1: Rolling own encryption** — Use only javax.crypto.Cipher.getInstance("AES/GCM/NoPadding") with PBKDF2WithHmacSHA256 at 600,000 iterations (NIST 2023 minimum). Never store the derived key. Never store the encryption key as another Preferences entry alongside the ciphertext. Envelope: [1-byte version][16-byte salt][12-byte IV][ciphertext+tag] in one Preferences entry per secret.

4. **C3-1: Prompt injection from external MCP tool output** — External MCP tool results must never be inserted into the AI system message block. Wrap all external results in an explicit trust boundary marker. Apply the same redaction pipeline to external tool results. Log all external tool invocations in the audit log.

5. **B1-1: Behavior-changing refactors during mega-file split** — Split only along natural seams; never change visibility modifiers (private -> internal) in a split commit; never reorder companion object constants or init blocks across the split boundary. Add C4 hooks to PassiveAiScanner before splitting it.

## Implications for Roadmap

Based on research, the dependency graph enforces a specific build order. The suggested phase structure follows that order, not feature grouping by user-visible concern.

### Phase 1: C2 — Encrypt Secrets at Rest
**Rationale:** Hard dependency for every subsequent phase that introduces a new secret. The Anthropic API key (C1) must be encrypted from day one; external MCP server bearer tokens (C3) must be encrypted before C3 ships. The migration ladder (migrateToSchemaV4) must exist before any new secret field is added. This phase also patches the pre-existing keytool argv password exposure (A3-1 in McpTls.kt).
**Delivers:** SecretStore.kt (AES-256-GCM + PBKDF2); schema V4 migration encrypting all 7 existing secret preference keys; keytool -storepassfile fix or in-JVM cert generation; plaintext-state warning in Settings UI.
**Addresses:** C2 (table stakes: no professional tool stores credentials in plaintext)
**Avoids:** C2-1 (rolling own crypto), C2-2 (migration data loss), C2-3 (headless Linux keychain failure), C2-4 (secrets in logs), A3-1 (keytool argv password)
**Research flag:** Standard patterns — javax.crypto AES-GCM + PBKDF2 is well-documented; no phase research needed. The key-bootstrap strategy (per-install random key vs user passphrase) is a UX decision that must be made during phase planning, not deferred to implementation.

### Phase 2: C1 — Native Anthropic Messages API Backend
**Rationale:** Depends on Phase 1 (anthropicApiKey must be encrypted from day one). The highest user-demand feature of the milestone. Uses only existing OkHttp + MontoyaHttpTransport + Jackson/kotlinx — no new dependency.
**Delivers:** AnthropicBackend.kt + AnthropicBackendFactory.kt; META-INF/services registration; BackendConfigPanel Anthropic section; full SSE streaming with state machine for partial_json accumulation; tool-use agentic loop with maxToolRoundtrips cap (recommended 10); cache_control on system prompt and tools block; all four token usage fields surfaced in TokenTracker. C5 and C7 can be interleaved into this phase as they share no conflicts.
**Addresses:** C1 (table stakes: Claude is the default AI for most security researchers); C5 (LOW complexity, issue #70); C7 (extends existing TokenTracker)
**Avoids:** C1-1 (Anthropic bypassing Burp proxy), C1-2 (SSE parse errors on partial chunks), C1-3 (unbounded tool-use loop), C1-4 (model-ID drift)
**Research flag:** Standard patterns — Anthropic Messages API is official-docs-documented at HIGH confidence; SSE state machine mechanics are fully specified in PITFALLS.md; no phase research needed.

### Phase 3: C4 — Pre-Send Secret Tripwire
**Rationale:** Depends on Phase 1 being complete (existing keys are no longer in plaintext before the tripwire post-redaction scan is meaningful). Independent of C1. Must land before B1 (Phase 5) because C4 hooks land inside PassiveAiScanner.sendSingleAnalysis() and flushBatch(), which move during the mega-file split.
**Delivers:** SecretTripwire.kt (~15 curated regexes from gitleaks TOML + Shannon entropy check); hooks in McpToolContext.redactIfNeeded(), ChatPanel.sendMessage(), PassiveAiScanner send paths; warn-with-confirmation UI in context preview dialog (not hard-block); configurable entropy threshold (default 5.0 bits/char); audit log entries for allowlist use.
**Addresses:** C4 (table stakes: users assume redaction covers AWS keys in request bodies)
**Avoids:** C4-1 (false positives blocking legitimate pentest traffic — warn not block), A2-1 (ReDoS — Shannon entropy and curated patterns are compile-time constants, not user-supplied)
**Research flag:** Standard patterns — Shannon entropy and regex-based secret detection are well-understood; no phase research needed.

### Phase 4: C3 — External MCP Client (Connect to External/Custom MCP Servers)
**Rationale:** Depends on Phase 1 (external MCP server bearer tokens encrypted). Independent of C1 and C4. This is the highest-novelty and highest-build-risk item: new subsystem (MCP client role), new dependency (kotlin-sdk 0.13.0 bump with Ktor 3.4.3), potential multi-subprocess concern, and significant security surface (prompt injection, SSRF).
**Delivers:** McpClientManager.kt + ExternalMcpServerConfig.kt; SSE and stdio transports; McpSettings.externalMcpServers serialization; McpConfigPanel.kt CRUD UI; external tool listing and forwarding in AiTools.kt; per-tool enable/disable; external tool results wrapped in untrusted-data marker; SSRF warning at settings-save time.
**Addresses:** C3 (differentiator: connect any MCP-compatible tool without building a Burp extension)
**Avoids:** C3-1 (prompt injection from external MCP tool output), C3-2 (SSRF via external MCP URL), A4-1 (LinkedHashMap session maps off-EDT)
**Research flag:** NEEDS DEEPER RESEARCH during phase planning. Open questions: (1) kotlin-sdk 0.13.0 transitively bumps kotlin-stdlib to 2.3.21 — requires a Burp-JVM test-run before phase begins; (2) AgentSupervisor multi-subprocess check — verify whether the existing subprocess management supports multiple concurrent external MCP server processes; (3) ProxyHttpRequestResponse.listenerInterface() codebase verification (also needed for C5).

### Phase 5: B1 + B3 — Mega-File Splits + detekt Static Analysis
**Rationale:** Pure no-behavior-change refactor. Must come last because C4 hooks land inside the files being split. Detekt must be configured with a baseline before it is wired as a blocking CI gate; ktlintFormat must be run on the full codebase before ktlintCheck is promoted to blocking.
**Delivers:** McpTools.kt split (2770 lines -> per-category tool files already stubbed); PassiveAiScanner.kt split (2480 lines -> PassiveScanDedup, PassiveScanPromptBuilder, PassiveScanResultHandler, PassiveScanLocalChecks); SettingsPanel.kt target under 400 lines; detekt 1.23.8 Gradle plugin with detekt-baseline.xml; ktlintFormat formatting commit then blocking ktlintCheck gate.
**Addresses:** B1 (code quality, maintainability), B3 (static analysis gate)
**Avoids:** B1-1 (behavior-changing refactors during split), B1-2 (ServiceLoader registration broken after rename), B3-1 (ktlint blocking CI without a format pass)
**Research flag:** Standard patterns — file split mechanics and detekt configuration are standard Kotlin/Gradle; no phase research needed.

### Phase Ordering Rationale

- C2 before C1: The Anthropic API key must be encrypted from the first commit that introduces it. Retrofitting encryption after C1 ships means a window where anthropicApiKey is plaintext in preferences.
- C2 before C3: External MCP server bearer tokens are secrets. C3 stores them in McpSettings; those writes must go through SecretStore.encrypt() from day one.
- C4 before B1: C4 hooks land in PassiveAiScanner.sendSingleAnalysis() and flushBatch(). These methods move during the B1 split. Landing C4 first means the split is a pure refactor with no conflated behavior changes.
- C3 after C1 and C4: C3 is the highest-risk phase. Placing it after the lower-risk phases means the kotlin-sdk compatibility test does not block earlier phases from shipping.
- B1 last: Splitting mega-files is a zero-behavior-change refactor. Doing it last avoids merge conflicts with every other phase.
- C5 and C7 are independent and can be interleaved with Phase 2 (natural fit: C7 alongside Anthropic four-field token usage; C5 alongside proxy-history work).

### Research Flags

Needs research during phase planning:
- **Phase 4 (C3):** kotlin-sdk 0.13.0 transitively bumps kotlin-stdlib to 2.3.21 — run Burp-JVM compatibility test before phase planning begins; confirm Ktor 3.4.3 embedded server still starts correctly inside Burp classloader
- **Phase 4 (C3):** Verify AgentSupervisor subprocess management supports multiple concurrent external MCP server stdio processes without lifecycle interference
- **Phase 4 (C3) / C5:** Verify ProxyHttpRequestResponse.listenerInterface() exists in the Montoya API version in use and returns the expected "host:port" string format

Standard patterns (skip research-phase):
- **Phase 1 (C2):** AES-256-GCM + PBKDF2 via javax.crypto is fully documented; key-bootstrap UX is a product decision
- **Phase 2 (C1):** Anthropic Messages API is official-docs-documented at HIGH confidence; SSE state machine mechanics are fully specified
- **Phase 3 (C4):** Shannon entropy + curated regex secret detection is well-understood; gitleaks TOML patterns are MIT-licensed and directly portable
- **Phase 5 (B1+B3):** File split mechanics and detekt setup are standard Kotlin/Gradle patterns

## Confidence Assessment

| Area | Confidence | Notes |
|------|------------|-------|
| Stack | HIGH | All versions verified via Maven Central, official docs, and GitHub releases on 2026-06-10. The only uncertainty is runtime behavior of kotlin-stdlib 2.3.21 inside Burp JVM classloader (requires a test-run, not research). |
| Features | HIGH (C1, C3 transport), MEDIUM (C2 UX, C5, C7) | C1 wire format verified against official Anthropic docs. C3 MCP spec verified against modelcontextprotocol.io. C2 key-bootstrap UX is a product decision with no single right answer. C5 and C7 are simple extensions of existing components. |
| Architecture | HIGH | All findings grounded in actual source files with line references. Integration points, data flows, and anti-patterns verified against the real codebase. |
| Pitfalls | HIGH | Critical pitfalls verified against actual codebase (McpTls.kt argv exposure lines 45-68, Redaction.kt SHA-256 vs HKDF lines 122-136, HttpBackendSupport.kt sharedClient test-only lines 31-51, CliBackend.kt temp file delete in catch lines 109-285). |

**Overall confidence:** HIGH

### Gaps to Address

- **C2 key-bootstrap strategy (UX decision):** The research confirms javax.crypto AES-256-GCM + PBKDF2 is correct. What is not decided: whether the default is (a) a randomly-generated per-install key stored in a separate Preferences key (transparent but non-portable), (b) a user-supplied master passphrase (portable but adds user friction), or (c) OS keychain with passphrase fallback (best UX but Linux unreliable). The phase planning session for C2 must make this decision before implementation begins.

- **kotlin-sdk 0.13.0 Burp-JVM compatibility:** The kotlin-stdlib 2.3.21 transitive dependency needs a test-run against the actual Burp Suite JVM before Phase 4 (C3) planning begins. Add the 0.13.0 dependency, build the fat JAR, load in Burp, confirm the embedded MCP server starts and the extension loads without ClassLoader conflicts.

- **ProxyHttpRequestResponse.listenerInterface() verification:** Both feature and architecture research reference this method for C5. Verify it exists and returns the expected "host:port" format before C5 implementation begins.

- **AgentSupervisor multi-subprocess capacity:** Architecture notes the existing AgentSupervisor pattern is reusable for stdio external MCP servers but does not confirm whether its lifecycle management supports multiple concurrent subprocesses. Needs codebase verification before Phase 4 planning.

- **A1 HKDF vs SHA-256 fix scope:** PITFALLS.md flags that Redaction.anonymizeHost uses salted SHA-256 but is documented as HKDF (Redaction.kt lines 122-136). The roadmapper should decide whether this lands in Phase 1 (alongside C2 as a privacy-layer fix) or is deferred to a subsequent milestone.

## Sources

### Primary (HIGH confidence)
- Anthropic Messages API docs (platform.claude.com/docs/en/api/messages) — wire format, streaming SSE event sequence, tool-use loop, cache_control, token usage fields; verified 2026-06-10
- Anthropic Prompt Caching docs (platform.claude.com/docs/en/build-with-claude/prompt-caching) — cache_control breakpoints, TTL, minimum token thresholds, cache_creation_input_tokens pricing
- Anthropic Tool Use docs (platform.claude.com/docs/en/agents-and-tools/tool-use/how-tool-use-works) — tool_use stop_reason, tool_result format, agentic loop canonical pattern
- MCP Specification 2025-11-25 (modelcontextprotocol.io) — initialize handshake, tools/list, tools/call, Streamable HTTP transport, stdio transport, session management
- io.modelcontextprotocol kotlin-sdk 0.13.0 POM (central.sonatype.com) — client artifact deps: ktor-client-core 3.4.3, kotlin-stdlib 2.3.21; verified 2026-06-10
- MCP kotlin-sdk GitHub releases 0.13.0 — Ktor 3.4.3 upgrade, client transport list
- com.google.crypto.tink:tink:1.21.0 POM (central.sonatype.com) — protobuf-java:4.33.0 transitive dep confirmed
- detekt compatibility table (detekt.dev) — 1.23.8 latest stable, built against Kotlin 2.0.21
- Codebase direct verification: McpTls.kt (argv password lines 45-68), Redaction.kt (SHA-256 not HKDF lines 122-136), HttpBackendSupport.kt (sharedClient test-only lines 31-51), CliBackend.kt (temp file delete in catch lines 109-285), ChatPanel.kt (finalPrompt assembly lines 502-506, sendChat line 530), AgentSettings.kt (secret field inventory lines 481-631)

### Secondary (MEDIUM confidence)
- MCP kotlin-sdk issue #390 — ktor-bom requirement for 0.7.5+ documented
- detekt issue #7883 — Kotlin 2.1.0 kotlin-compiler-embeddable warning in 1.23.7+
- javakeyring/java-keyring — v1.0.4 latest Aug 2023, BSD-3 license, maintenance-mode, Linux libsecret dependency
- gitleaks/config/gitleaks.toml (MIT) — Go regex engine, 100+ rules, Shannon entropy thresholds; patterns portable to Java regex with caveats
- Anthropic 529 overloaded error in streams — embedded in 200 OK SSE stream as first data event
- OWASP MCP Security Cheat Sheet — SSRF and prompt injection via external MCP servers
- PBKDF2/AES-GCM JVM best practices (Baeldung) — cipher parameters, iteration counts
- ktlint/detekt baseline strategy — ktlintFormat-before-gate pattern

### Tertiary (LOW confidence, needs validation during implementation)
- C5: ProxyHttpRequestResponse.listenerInterface() return format — referenced in feature and architecture research but not directly verified against Montoya API javadoc
- C7: Passive scanner pause-on-hard-cap behavior — described in feature research but exact hook point in PassiveAiScanner not pinpointed in architecture research

---
*Research completed: 2026-06-10*
*Ready for roadmap: yes*
