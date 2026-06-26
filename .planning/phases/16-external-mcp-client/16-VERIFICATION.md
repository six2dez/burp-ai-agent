---
phase: 16-external-mcp-client
verified: 2026-06-15T14:45:00Z
status: passed
human_verified: 2026-06-26 — all 3 human-UAT items passed (see 16-HUMAN-UAT.md)
score: 5/5 automatable must-haves verified
overrides_applied: 0
human_verification:
  - test: "SC1 — Connect to a real external MCP server (SSE or stdio); tools appear as ext:<server>:<tool> in agent preamble and are callable"
    expected: "After adding a server in Settings > MCP > External MCP Servers accordion, the Status column shows 'Connected (N tools)'; a chat message asking to list tools shows ext:<serverName>:<toolName> entries in the agent's tool preamble response"
    why_human: "Requires a live external MCP server process; automated tests mock the client; real SSE/stdio handshake and ClassLoader resolution under Burp's JVM cannot be verified programmatically"
  - test: "SC5 — Fat JAR loads in live Burp Suite with no ClassLoader/NoClassDefFoundError; embedded MCP server starts; MCP Tools tab is responsive"
    expected: "Burp Extensions list shows 'Burp AI Agent' with no error icon; Output/Errors tabs show no NoClassDefFoundError or ClassNotFoundException; MCP Tools tab opens; embedded server starts"
    why_human: "Burp JVM bundles its own Kotlin runtime — ClassLoader conflicts (ktor-client-cio:3.1.3 vs Burp's bundled version) can only be confirmed by loading the fat JAR in a real Burp instance; no JVM emulation available in test suite"
---

# Phase 16: External MCP Client — Verification Report

**Phase Goal:** Users can register external/custom MCP servers and the agent can call their tools; external server auth tokens are encrypted (Phase 12 SecretCipher); untrusted tool output is wrapped before entering the AI context; SSRF warning covers external MCP URLs; no Kotlin/kotlin-sdk bump (Path A — kotlin-sdk 0.5.0 client).
**Verified:** 2026-06-15T14:45:00Z
**Status:** human_needed
**Requirement:** CAP-02
**Re-verification:** No — initial verification

---

## Goal Achievement

### Observable Truths

| # | Truth | Status | Evidence |
|---|-------|--------|----------|
| 1 | ExternalServersPanel CRUD UI exists and is wired into SettingsPanel; external tools surface as `ext:<server>:<tool>` in describeTools preamble; routing dispatches `ext:`-prefixed calls to ExternalMcpClientManager | VERIFIED | `ExternalServersPanel.kt` (884 lines); `SettingsPanel.kt` line 237–239 (field init), 1105 (`getServers()`), 1410 (`setServers()`), 2068 (accordion mount); `McpTools.kt` lines 1301–1316 (fan-out in `describeTools`), 1374–1375 (routing dispatch to `routeExternalToolCall`), 2303–2315 (impl). `extPrefixedToolName_routesToCorrectServer` test PASS |
| 2 | External tool results wrapped in `[EXTERNAL-TOOL-RESULT:...]...[/EXTERNAL-TOOL-RESULT]` trust-boundary marker; `trustBoundaryWrap_escapesEmbeddedCloseMarker` test exists and passes (WR-01); every external tool invocation is audit-logged behind `auditLogger.isEnabled()` | VERIFIED | `ExternalMcpClientManager.kt` lines 364–372 (`wrapWithTrustBoundary`), line 370 (WR-01 escape); `McpTools.kt` line 2319–2321 (trust-boundary text preserved); `ExternalMcpClientManagerTest` XML: `trustBoundaryWrap_addsCorrectMarkers` PASS, `trustBoundaryWrap_escapesEmbeddedCloseMarker` PASS; audit log lines 328–337 guarded by `auditLogger?.isEnabled() == true` |
| 3 | External SSE URL triggers SsrfGuard soft warning (RFC-1918/link-local) in ExternalServersPanel | VERIFIED | `ExternalServersPanel.kt` line 375–392 (DocumentListener on `urlField` calling `SsrfGuard.isPrivateOrLinkLocal`); `ssrfWarningLabel.isVisible` toggled on every `DocumentEvent`; `ExternalMcpClientManager.kt` line 184–186 (soft log-only SSRF check on connect — non-blocking per SC3/D-01) |
| 4 | External bearer tokens encrypted at rest with per-field SecretCipher / `ENC1:` prefix; schema v5 migration round-trips and is idempotent; token masked in UI (JPasswordField + show/hide); token never logged; ExternalMcpClientManager uses `config.bearerToken` directly with no `cipher.decrypt` | VERIFIED | `AgentSettings.kt` lines 1378–1428 (`saveExternalMcpServers`/`loadExternalMcpServers`); `CURRENT_SETTINGS_SCHEMA_VERSION = 5` (line 964); `ExternalServersPanel.kt` line 95 (`JPasswordField`), line 100 (show/hide), line 607 (raw read from `tokenField.password`); No `SecretCipher` or `cipher.decrypt` in `ExternalMcpClientManager.kt` (confirmed by grep); `ExternalMcpSettingsMigrationTest` XML: all 4 tests PASS (0 failures, 0 skipped): `externalMcpServers_roundTripsThroughSaveLoad`, `externalServerBlob_isStoredEncrypted`, `schemaVersion_bumpedToFive`, `migrationIsIdempotent_doubleLoadDoesNotDoubleEncrypt` |
| 5 | `./gradlew shadowJar` builds successfully; fat JAR bundles kotlin-sdk client classes + ktor-client-cio; kotlin-sdk stays at 0.5.0; Kotlin plugin stays at 2.1.21 | VERIFIED | `./gradlew shadowJar --no-daemon` BUILD SUCCESSFUL; `build/libs/Custom-AI-Agent-full-0.8.0.jar` confirmed; `jar tf` shows `io/ktor/client/engine/cio/CIO.class`, `META-INF/ktor-client-cio.kotlin_module`, `io/modelcontextprotocol/kotlin/sdk/client/KtorClientKt.class`; `build.gradle.kts` line 35: `kotlin-sdk:0.5.0`; lines 5–6: Kotlin plugin `2.1.21` |

**Automatable Score:** 5/5 truths verified

---

### Required Artifacts

| Artifact | Expected | Status | Details |
|----------|----------|--------|---------|
| `src/main/kotlin/com/six2dez/burp/aiagent/mcp/external/ExternalMcpClientManager.kt` | SSE+stdio lifecycle, trust-boundary wrap, audit log, ProcessBuilder(List) | VERIFIED | 454 lines; SSE + STDIO transport; `wrapWithTrustBoundary`; audit-logged; `pb.environment().clear()` (CR-01) |
| `src/main/kotlin/com/six2dez/burp/aiagent/mcp/external/ExternalMcpServerConfig.kt` | Data model with bearerToken (plaintext in memory) | VERIFIED | 42 lines; `bearerToken: String = ""`; plaintext contract documented in KDoc |
| `src/main/kotlin/com/six2dez/burp/aiagent/ui/panels/ExternalServersPanel.kt` | CRUD UI panel (min 300 lines), JTable, SSRF warning, JPasswordField, AccordionPanel | VERIFIED | 884 lines; all required elements present and imported |
| `src/main/kotlin/com/six2dez/burp/aiagent/ui/SettingsPanel.kt` | ExternalServersPanel wired into MCP section | VERIFIED | Contains `ExternalServersPanel`, `externalMcpServers = externalServersPanel.getServers()`, `externalServersPanel.setServers(` |
| `src/test/kotlin/com/six2dez/burp/aiagent/mcp/external/ExternalMcpClientManagerTest.kt` | Wave 0 test scaffold with 4 test methods | VERIFIED | 221 lines; 4 named methods; 3 PASS + 1 intentionally `@Disabled` (live server required) |
| `src/test/kotlin/com/six2dez/burp/aiagent/config/ExternalMcpSettingsMigrationTest.kt` | Schema v5 migration tests with InMemoryPrefs | VERIFIED | 207 lines; `InMemoryPrefs` inner class; 4 tests all PASS |
| `build.gradle.kts` | `ktor-client-core:3.1.3`, `ktor-client-cio:3.1.3`, `kotlin-logging-jvm:7.0.7`; `kotlin-sdk:0.5.0` unchanged | VERIFIED | Lines 43–46 confirm all 3 new deps; line 35: `kotlin-sdk:0.5.0` unchanged |

---

### Key Link Verification

| From | To | Via | Status | Details |
|------|----|-----|--------|---------|
| `ExternalServersPanel` | `SsrfGuard.isPrivateOrLinkLocal` | DocumentListener on URL field fires on every `DocumentEvent` | WIRED | Line 386: `SsrfGuard.isPrivateOrLinkLocal(urlField.text)` called on every change; ssrfWarningLabel toggled |
| `ExternalServersPanel` | `ExternalMcpServerConfig` | `getServers()` returns `List<ExternalMcpServerConfig>` with plaintext bearerToken | WIRED | Lines 251–255 (`getServers()`); line 607 raw token read from `tokenField.password` |
| `SettingsPanel` | `ExternalServersPanel.getServers()` | `mcpSettings.copy(externalMcpServers = externalServersPanel.getServers())` | WIRED | Line 1105 in `SettingsPanel.kt` |
| `SettingsPanel` | `ExternalServersPanel.setServers()` | `externalServersPanel.setServers(updated.mcpSettings.externalMcpServers)` | WIRED | Line 1410 in `SettingsPanel.kt` |
| `McpToolContext.externalClientManager` | `McpTools.describeTools` fan-out | `context.externalClientManager?.availableTools()?.map { ext -> ToolSpec(id = ext.name ...) }` | WIRED | `McpTools.kt` lines 1304–1316 |
| `McpTools.executeToolResult` | `routeExternalToolCall` | `if (resolvedName.startsWith("ext:"))` guard + dispatch | WIRED | Lines 1374–1375 |
| `routeExternalToolCall` | `context.redactIfNeeded` | `val redactedArgs = context.redactIfNeeded(argsJson.orEmpty())` | WIRED | Line 2315 (D-03 outbound privacy) |
| `ExternalMcpClientManager.callTool` | `wrapWithTrustBoundary` | Every result path calls `wrapWithTrustBoundary(serverName, rawText)` | WIRED | Lines 325, 310, 314, 354 — all return paths wrap |
| `AgentSettings.saveExternalMcpServers` | `SecretCipher.encrypt` | `cipher.encrypt(config.bearerToken, KEY_EXT_MCP_SERVERS)` per-field | WIRED | Line 1385; ENC1: prefix confirmed by `externalServerBlob_isStoredEncrypted` PASS |
| `AgentSettings.loadExternalMcpServers` | `SecretCipher.decrypt` | `cipher.decrypt(config.bearerToken, KEY_EXT_MCP_SERVERS)` per-field | WIRED | Line 1419; round-trip confirmed by `externalMcpServers_roundTripsThroughSaveLoad` PASS |

---

### Data-Flow Trace (Level 4)

| Artifact | Data Variable | Source | Produces Real Data | Status |
|----------|---------------|--------|-------------------|--------|
| `ExternalMcpClientManager.wrapWithTrustBoundary` | `rawResult` | `callTool` -> `client.callTool(toolName, args)` -> TextContent | Real MCP response (mocked in unit tests; live server in UAT) | FLOWING (automated path verified; live path is HUMAN-UAT) |
| `ExternalMcpSettingsMigrationTest` | `bearerToken` in prefs | `saveExternalMcpServers` -> `cipher.encrypt` -> prefs write | Real `ENC1:`-prefixed ciphertext (4 tests PASS) | FLOWING |
| `ExternalServersPanel` | server list (JTable rows) | `initialServers` from `AgentSettings.loadExternalMcpServers()` (decrypted plaintext) | Decrypted real config on load | FLOWING |

---

### Behavioral Spot-Checks

| Behavior | Command | Result | Status |
|----------|---------|--------|--------|
| Full check gate (detekt + ktlint + all tests) | `./gradlew check --no-daemon` | BUILD SUCCESSFUL in 50s | PASS |
| Fat JAR builds with ktor-client-cio bundled | `./gradlew shadowJar --no-daemon` | BUILD SUCCESSFUL; `Custom-AI-Agent-full-0.8.0.jar` exists; `io/ktor/client/engine/cio/CIO.class` present | PASS |
| `ExternalMcpClientManagerTest` (3 auto + 1 disabled) | `./gradlew test --tests "...ExternalMcpClientManagerTest"` | tests=5, skipped=1, failures=0, errors=0 | PASS |
| `ExternalMcpSettingsMigrationTest` (4 auto) | `./gradlew test --tests "...ExternalMcpSettingsMigrationTest"` | tests=4, skipped=0, failures=0, errors=0 | PASS |
| `trustBoundaryWrap_escapesEmbeddedCloseMarker` exists and passes | test XML | `trustBoundaryWrap_escapesEmbeddedCloseMarker()` time=0.001, no failure element | PASS |
| No `SecretCipher`/`cipher.decrypt` in `ExternalMcpClientManager.kt` | `grep "SecretCipher\|cipher.decrypt" ExternalMcpClientManager.kt` | Comment references only (no call sites); only comments: "MUST NOT call SecretCipher.decrypt" and "DO NOT call cipher.decrypt here" | PASS |
| `pb.environment().clear()` present (CR-01 fix) | `grep "pb.environment().clear" ExternalMcpClientManager.kt` | Line 136: `pb.environment().clear()` confirmed | PASS |
| `tokenizeArgs()` used for command parsing (WR-03 fix) | `grep "tokenizeArgs" ExternalServersPanel.kt` | Lines 533, 595, 596: function defined and used for both command and args fields | PASS |
| Colon rejection in server name (WR-02 fix) | `grep "contains.*\":\"" ExternalServersPanel.kt` | Line 554: `else if (name.contains(":"))` branch rejects colons | PASS |
| kotlin-sdk stays at 0.5.0; Kotlin at 2.1.21 | `grep "kotlin-sdk\|kotlin.*version" build.gradle.kts` | `kotlin-sdk:0.5.0` (line 35); `2.1.21` (lines 5–6) | PASS |
| ktor-client-cio:3.1.3 bundled in fat JAR | `jar tf ... \| grep ktor.*client.*cio` | `META-INF/ktor-client-cio.kotlin_module` and `io/ktor/client/engine/cio/CIO.class` present | PASS |

---

### Probe Execution

No conventional `scripts/*/tests/probe-*.sh` files declared for Phase 16. Build gate serves as the probe equivalent (`./gradlew check --no-daemon` — PASS).

---

### Requirements Coverage

| Requirement | Source Plan | Description | Status | Evidence |
|-------------|-------------|-------------|--------|----------|
| CAP-02 / SC1 | 16-04 + 16-05 | ExternalServersPanel CRUD UI; ext: tool preamble fan-out; routing dispatch | SATISFIED (automatable portion) | All wiring verified; live-server UAT is HUMAN-UAT |
| CAP-02 / SC2 | 16-03 | Trust-boundary wrap + WR-01 escape + audit log per invocation | SATISFIED | `wrapWithTrustBoundary` + escape tested; audit gated on `isEnabled()` |
| CAP-02 / SC3 | 16-05 | SSRF soft warning on RFC-1918/link-local external SSE URL | SATISFIED | DocumentListener fires `SsrfGuard.isPrivateOrLinkLocal` on every keystroke |
| CAP-02 / SC4 | 16-02 | Per-field `ENC1:` encryption; schema v5; idempotency; no token in logs | SATISFIED | 4 migration tests PASS; `KEY_EXT_MCP_SERVERS` logged on error, never the token value |
| CAP-02 / SC5 | 16-01 + 16-06 | Fat JAR builds with ktor-client-cio bundled; no ClassLoader conflict in live Burp | SATISFIED (build); HUMAN-UAT (live Burp load) | `shadowJar` BUILD SUCCESSFUL; CIO.class bundled; live Burp load is documented HUMAN-UAT |

---

### Security Fixes Verified (from 16-REVIEW.md)

| Finding | Severity | Fix Expected | Verified |
|---------|----------|--------------|---------|
| CR-01 — stdio subprocess inherits Burp env (ANTHROPIC_API_KEY leak) | Critical | `pb.environment().clear()` before env inject | CONFIRMED — line 136 of `ExternalMcpClientManager.kt` |
| WR-01 — trust-boundary close-marker not sanitized | Warning | Escape embedded `[/EXTERNAL-TOOL-RESULT]` before wrap; regression test | CONFIRMED — line 370 replace call; `trustBoundaryWrap_escapesEmbeddedCloseMarker` PASS |
| WR-02 — colon in server name breaks `ext:` dispatch | Warning | Colon rejected in `onSaveClicked` validation | CONFIRMED — line 554 in `ExternalServersPanel.kt` |
| WR-03 — naive space-split breaks paths with spaces | Warning | Quote-aware `tokenizeArgs()` | CONFIRMED — lines 533, 595–596 in `ExternalServersPanel.kt` |
| IN-01 — junit-jupiter:6.0.3 unconventional version | Info | Deferred — not Phase 16 change; suite green | DEFERRED — suite BUILD SUCCESSFUL |
| IN-02 — `stdioEnabled` stale snapshot | Info | Deferred — minor UX, non-blocking | DEFERRED |
| IN-03 — `scheduler.shutdown()` vs `shutdownNow()` | Info | Deferred — harmless cosmetic | DEFERRED |

---

### Anti-Patterns Found

| File | Line | Pattern | Severity | Impact |
|------|------|---------|----------|--------|
| None found | — | No `TBD`, `FIXME`, `XXX`, `return null`, or hardcoded stubs in Phase 16 production files | — | — |

---

### Human Verification Required

#### 1. SC1 — Connect to a Real External MCP Server

**Test:** Start a local SSE MCP server (e.g., `npx -y @modelcontextprotocol/server-filesystem /tmp` in SSE mode) OR configure a stdio MCP server with `stdioEnabled` on. In Burp > AI Agent > Settings > MCP tab, scroll to "External MCP Servers" accordion, click "Add Server", fill in Name/Transport/URL (or Command), click "Save Server". Observe the Status column. Send a chat message asking the agent to list its tools.
**Expected:** Status column shows "Connected (N tools)" with a green dot; the agent's tool preamble response includes `ext:<serverName>:<toolName>` entries; a tool call returns a result wrapped in `[EXTERNAL-TOOL-RESULT:...]`.
**Why human:** Requires a live external MCP server process. Automated tests mock the MCP client. Real SSE/stdio handshake, connection lifecycle, and tool preamble integration in the chat UI cannot be asserted programmatically.

#### 2. SC5 — Fat JAR Loads in Live Burp with No ClassLoader Conflict

**Test:** Run `ls build/libs/Custom-AI-Agent-*.jar`. Open Burp Suite (Community or Professional). Extensions > Add > select the JAR. Check Burp's Output tab and Errors tab immediately after load.
**Expected:** "Burp AI Agent" appears in the Extensions list with no error icon; no `NoClassDefFoundError` or `ClassNotFoundException` in Output/Errors; MCP Tools tab opens and is responsive; embedded MCP server starts.
**Why human:** Burp bundles its own Kotlin runtime. ClassLoader conflicts between `ktor-client-cio:3.1.3` and Burp's bundled Ktor version can only be confirmed by loading the fat JAR in a real Burp JVM. Path A (no Kotlin bump) makes this unlikely but it must be confirmed empirically.

---

### Gaps Summary

No automatable gaps. All 5 success criteria have been verified at the code level:

- SC1: UI + routing + fan-out wiring complete and tested (`extPrefixedToolName_routesToCorrectServer` PASS). The "live server" portion is documented HUMAN-UAT, as specified in the phase plan (16-06-PLAN.md and 16-VALIDATION.md).
- SC2: Trust-boundary wrap implemented and tested (`trustBoundaryWrap_addsCorrectMarkers` PASS, `trustBoundaryWrap_escapesEmbeddedCloseMarker` PASS). Audit logging gated on `isEnabled()` present at all call paths.
- SC3: SSRF DocumentListener wired; `SsrfGuard.isPrivateOrLinkLocal` fires on every URL keystroke.
- SC4: Per-field encryption confirmed by 4 migration tests all PASS. Token never logged. No `cipher.decrypt` in manager. JPasswordField show/hide confirmed in source.
- SC5: `shadowJar` BUILD SUCCESSFUL; `ktor-client-cio` classes bundled. Live Burp load is documented HUMAN-UAT per 16-06-PLAN.md.

All four code-review security fixes (CR-01, WR-01, WR-02, WR-03) are confirmed in the codebase.

The phase is blocked only on the two HUMAN-UAT items that were explicitly scoped as manual-only from the beginning (16-VALIDATION.md "Manual-Only Verifications" table, 16-06-PLAN.md purpose statement).

---

_Verified: 2026-06-15T14:45:00Z_
_Verifier: Claude (gsd-verifier)_
