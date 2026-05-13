# Technology Stack

**Analysis Date:** 2026-05-13

## Languages

**Primary:**
- Kotlin 2.1.21 - All production and test source code (`src/main/kotlin/`, `src/test/kotlin/`)

**Secondary:**
- None (pure Kotlin/JVM project; no mixed Java sources)

## Runtime

**Environment:**
- JVM 21 (Eclipse Temurin on CI; any JDK 21 at runtime inside Burp Suite's JVM)

**Compiler flags:**
- `-Xjsr305=strict` — strict null-safety for JSR-305 annotations
- Target: `JVM_21`

**Package Manager:**
- Gradle 8.x / 9.x (wrapper present; `.gradle/8.12.1` and `.gradle/9.2.1` caches both exist)
- Lockfile: `gradle.properties` (no dependency locking file; `org.gradle.configuration-cache=true` is enabled)

## Frameworks

**Core:**
- Burp Montoya API `2026.2` (`net.portswigger.burp.extensions:montoya-api`) — compileOnly; provided at runtime by Burp Suite. Accessed via `burp.api.montoya.MontoyaApi` throughout all modules.

**MCP Server:**
- Ktor `3.1.3` (server-core, server-netty, server-cors, server-sse, server-content-negotiation, serialization-kotlinx-json) — embedded HTTP server for MCP SSE transport (`src/main/kotlin/com/six2dez/burp/aiagent/mcp/KtorMcpServerManager.kt`)
- MCP Kotlin SDK `0.5.0` (`io.modelcontextprotocol:kotlin-sdk`) — MCP protocol implementation for both SSE and stdio transports

**Serialization:**
- kotlinx-serialization-json `1.8.1` — Kotlin-native JSON (used in MCP tool schemas and Ktor serialization)
- Jackson `2.21.2` (jackson-databind + jackson-module-kotlin) — JSON for backend request/response handling, audit log, and settings persistence

**Concurrency:**
- kotlinx-coroutines-core `1.9.0` — used in MCP stdio bridge (`McpStdioBridge.kt`); HTTP backends use JVM `ExecutorService` directly
- kotlinx-io-core `0.5.4` — I/O primitives for MCP stdio (`asSource`, `asSink`, `buffered`)

**HTTP Client:**
- OkHttp3 `4.12.0` — outbound HTTP for all HTTP-based AI backends (Ollama, LM Studio, OpenAI-compatible, health checks) when Montoya transport is unavailable

**Logging:**
- SLF4J API + slf4j-simple `2.0.16` — logging facade; Burp's own `api.logging()` is also used extensively

**Testing:**
- JUnit Jupiter `6.0.3` — test runner (JUnit Platform via `useJUnitPlatform()`)
- Mockito-Kotlin `5.4.0` — mocking for Burp Montoya API interfaces
- kotlin("test") — Kotlin test assertions

**Build / Dev:**
- Shadow JAR plugin `8.1.1` (`com.github.johnrengelman.shadow`) — fat JAR output named `Custom-AI-Agent-{version}.jar`; `mergeServiceFiles()` is required for ServiceLoader SPI entries
- ktlint Gradle plugin `12.1.1` / ktlint `1.5.0` — Kotlin code style enforcement
- Jacoco (built-in Gradle plugin) — code coverage; XML + HTML reports
- CycloneDX BOM plugin `1.10.0` — SBOM generation to `build/reports/sbom/bom.json`
- Foojay Toolchains resolver `1.0.0` — JDK auto-provisioning via `settings.gradle.kts`

## Key Dependencies

**Critical:**
- `net.portswigger.burp.extensions:montoya-api:2026.2` — the entire extension surface; all Burp API calls go through this. `compileOnly` — must NOT be shaded into the fat JAR.
- `io.modelcontextprotocol:kotlin-sdk:0.5.0` — MCP server protocol implementation (SSE + stdio)
- `io.ktor:ktor-server-netty:3.1.3` — embedded Netty HTTP server for the MCP SSE endpoint

**Infrastructure:**
- `com.squareup.okhttp3:okhttp:4.12.0` — HTTP client for AI backend communication and alerting webhooks
- `com.fasterxml.jackson.core:jackson-databind:2.21.2` — serialization for backend payloads, audit JSONL, and Burp Preferences persistence
- `org.jetbrains.kotlinx:kotlinx-coroutines-core:1.9.0` — coroutine support (MCP stdio bridge)

## Configuration

**Build-time:**
- `build.gradle.kts` — all dependency versions, Gradle plugin versions, artifact name (`Custom-AI-Agent`), version (`0.6.1`), JVM toolchain, test filtering, SBOM destination
- `gradle.properties` — JVM args for Gradle daemon (`-Xmx2g`), configuration cache enabled, Kotlin code style
- `settings.gradle.kts` — root project name (`burp-ai-agent`), Foojay toolchain resolver

**Runtime (user-facing):**
- All settings are persisted via `burp.api.montoya.persistence.Preferences` (Burp project file / preferences). No external config files are read at startup.
- `AgentSettings` data class (`src/main/kotlin/com/six2dez/burp/aiagent/config/AgentSettings.kt`) is the single source of truth for all configurable values.

**Code style:**
- `.editorconfig` — UTF-8, LF line endings, 4-space indent (2 for YAML/JSON), no trailing whitespace

## Platform Requirements

**Development:**
- JDK 21 (auto-provisioned by Foojay via toolchain)
- Gradle wrapper (no system Gradle required)
- Burp Suite Professional or Community with Montoya API 2026.2 support (for runtime)

**Production:**
- Burp Suite — the extension JAR is loaded as a Burp extension; Burp provides the JVM runtime
- No external runtime dependencies (all non-Montoya deps are shaded into the fat JAR)
- Local filesystem access to `~/.burp-ai-agent/` (audit logs, cache, backend JARs, TLS keystore)
- Optional: CLI tools on PATH (`claude`, `gemini`, `codex`, `opencode`, `gh copilot`) for CLI backends
- Optional: Running Ollama or LM Studio server for local HTTP backends

---

*Stack analysis: 2026-05-13*
