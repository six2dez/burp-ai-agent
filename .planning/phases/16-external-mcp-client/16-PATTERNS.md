# Phase 16: External MCP Client - Pattern Map

**Mapped:** 2026-06-15
**Files analyzed:** 10 new/modified files
**Analogs found:** 10 / 10

---

## File Classification

| New/Modified File | Role | Data Flow | Closest Analog | Match Quality |
|---|---|---|---|---|
| `mcp/external/ExternalMcpServerConfig.kt` | model/data | CRUD | `config/McpSettings.kt` (data class shape) | role-match |
| `mcp/external/ExternalMcpClientManager.kt` | service | event-driven + request-response | `mcp/McpStdioBridge.kt` (coroutine scope), `mcp/McpSupervisor.kt` (lifecycle/restart policy) | exact |
| `mcp/McpToolContext.kt` | model | CRUD | self (additive field to existing data class) | exact |
| `mcp/tools/McpTools.kt` | service/util | request-response | self (additive fan-out in `registerTools` + new routing branch) | exact |
| `config/McpSettings.kt` | model | CRUD | self (additive field) | exact |
| `config/AgentSettings.kt` | config/persistence | CRUD | self (additive field + schema v5 migration branch) | exact |
| `ui/panels/ExternalServersPanel.kt` | component/UI | CRUD | `ui/panels/McpConfigPanel.kt` (accordion + stack layout), `ui/panels/BackendConfigPanel.kt` (SSRF warning + JPasswordField), `ui/AiLoggerPanel.kt` (JTable + AbstractTableModel) | exact |
| `build.gradle.kts` | config | transform | self (additive dep lines) | exact |
| `mcp/external/ExternalMcpClientManagerTest.kt` | test | request-response | `mcp/McpSupervisorRestartPolicyTest.kt` (manager lifecycle mocking pattern) | role-match |
| `config/ExternalMcpSettingsMigrationTest.kt` | test | CRUD | `config/AgentSettingsMigrationTest.kt` (InMemoryPrefs + round-trip pattern) | exact |

---

## Pattern Assignments

### `mcp/external/ExternalMcpServerConfig.kt` (model, CRUD)

**Analog:** `config/McpSettings.kt` (data class + Jackson serialization + companion parse/serialize helpers)

**Data class pattern** (`McpSettings.kt` lines 8-33):
```kotlin
data class McpSettings(
    val enabled: Boolean,
    val host: String,
    val port: Int,
    val externalEnabled: Boolean,
    val stdioEnabled: Boolean,
    val token: String,
    // ...
    val toolToggles: Map<String, Boolean>,
) {
    companion object {
        private val mapper = JsonMapper.builder().build().registerKotlinModule()
        fun generateToken(): String { ... }
        fun parseToolToggles(raw: String?): Map<String, Boolean> { ... }
    }
}
```

**New file shape** — mirror this structure exactly for `ExternalMcpServerConfig`:
```kotlin
// Target: mcp/external/ExternalMcpServerConfig.kt
enum class ExternalMcpTransport { SSE, STDIO }

data class ExternalMcpServerConfig(
    val name: String,               // display name; also used as namespace key
    val transport: ExternalMcpTransport,
    val url: String = "",           // SSE only
    val command: List<String> = emptyList(), // stdio only
    val extraArgs: List<String> = emptyList(),
    val envVars: Map<String, String> = emptyMap(),
    val encryptedToken: String = "", // SSE only; stored via SecretCipher.encrypt()
    val enabled: Boolean = true,
)
```

---

### `mcp/external/ExternalMcpClientManager.kt` (service, event-driven + request-response)

**Primary analog:** `mcp/McpStdioBridge.kt` — coroutine scope ownership, `CoroutineScope(Dispatchers.IO + SupervisorJob())`, `launch {}` for async connect, `runBlocking { withTimeoutOrNull(5000) { ... } }` for shutdown.

**Secondary analog:** `mcp/McpSupervisor.kt` — restart policy, `AtomicReference<State>`, `AtomicInteger` for retry count, `ScheduledExecutorService` for delay-and-retry.

**Imports pattern** (`McpStdioBridge.kt` lines 14-23):
```kotlin
import io.modelcontextprotocol.kotlin.sdk.Implementation
import io.modelcontextprotocol.kotlin.sdk.ServerCapabilities
import io.modelcontextprotocol.kotlin.sdk.server.Server
import io.modelcontextprotocol.kotlin.sdk.server.ServerOptions
import io.modelcontextprotocol.kotlin.sdk.server.StdioServerTransport
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeoutOrNull
import kotlinx.io.asSink
import kotlinx.io.asSource
import kotlinx.io.buffered
```

**Client imports** (SDK 0.5.0 client package — mirror from RESEARCH.md code examples):
```kotlin
import io.modelcontextprotocol.kotlin.sdk.client.Client
import io.modelcontextprotocol.kotlin.sdk.client.ClientOptions
import io.modelcontextprotocol.kotlin.sdk.client.SseClientTransport
import io.modelcontextprotocol.kotlin.sdk.client.StdioClientTransport
import io.ktor.client.HttpClient
import io.ktor.client.engine.cio.CIO
import io.ktor.client.plugins.sse.SSE
```

**Coroutine scope pattern** (`McpStdioBridge.kt` lines 29-31, 67-73):
```kotlin
// One scope per manager instance; each server connection is a child Job.
private var scope: CoroutineScope? = null
private var job: Job? = null

val newScope = CoroutineScope(Dispatchers.IO + SupervisorJob())
scope = newScope
job = newScope.launch {
    mcpClient.connect(transport)
}
```

**Shutdown / cleanup pattern** (`McpStdioBridge.kt` lines 78-93):
```kotlin
fun stop() {
    job?.cancel()
    job = null
    val currentTransport = transport
    val currentClient = client
    val currentProcess = process          // stdio only
    val currentScope = scope
    transport = null; client = null; process = null; scope = null
    runBlocking {
        withTimeoutOrNull(5000) { currentTransport?.close() }
        withTimeoutOrNull(5000) { currentClient?.close() }
    }
    currentProcess?.destroyForcibly()     // stdio: always call after close()
    currentScope?.coroutineContext?.get(kotlinx.coroutines.Job)?.cancel()
}
```

**Restart/backoff policy** (`McpSupervisor.kt` lines 50, 181-188):
```kotlin
private val restartAttempts = AtomicInteger(0)
// Exponential or fixed delay via ScheduledExecutorService:
scheduler.schedule({
    // reconnect if still enabled
    connectServer(config)
}, delayMs, TimeUnit.MILLISECONDS)
// Capped at maxRestartAttempts (default 4 in McpSupervisor)
```

**State model** (`McpSupervisor.kt` lines 45-47):
```kotlin
private val stateRef = AtomicReference<McpServerState>(McpServerState.Stopped)
private val settingsRef = AtomicReference<McpSettings?>(null)
```

**Connection state enum** (mirror `McpServerState` for external connections):
```kotlin
sealed class ExternalMcpConnectionState {
    data object Disconnected : ExternalMcpConnectionState()
    data object Connecting : ExternalMcpConnectionState()
    data class Connected(val toolCount: Int) : ExternalMcpConnectionState()
    data class Retrying(val attempt: Int, val maxAttempts: Int) : ExternalMcpConnectionState()
    data class Error(val message: String) : ExternalMcpConnectionState()
}
```

**Trust boundary wrap** — always applied in `callTool()` before returning:
```kotlin
private const val TRUST_BOUNDARY_OPEN  = "[EXTERNAL-TOOL-RESULT:"
private const val TRUST_BOUNDARY_CLOSE = "[/EXTERNAL-TOOL-RESULT]"

private fun wrapWithTrustBoundary(serverName: String, rawResult: String): String =
    "$TRUST_BOUNDARY_OPEN$serverName]\n$rawResult\n$TRUST_BOUNDARY_CLOSE"
```

**AuditLogger call pattern** (mirror existing uses of `AuditLogger.emitGlobal` in `McpToolContext.kt` lines 65-68):
```kotlin
AuditLogger.emitGlobal("external_mcp_call", mapOf(
    "server" to serverName,
    "tool" to toolName,
    "status" to "ok",   // or "error"
))
```

---

### `mcp/McpToolContext.kt` (model, CRUD — MODIFY)

**Analog:** self (`mcp/McpToolContext.kt` lines 18-44)

**Existing nullable optional field pattern** (lines 37-40) — add `externalClientManager` at the same position after the existing optional fields:
```kotlin
data class McpToolContext(
    // ... existing fields ...
    val aiRequestLogger: AiRequestLogger? = null,
    val supervisor: AgentSupervisor? = null,
    val passiveScanner: PassiveAiScanner? = null,
    val backendRegistry: BackendRegistry? = null,
    val scopeOnly: Boolean = false,
    // PHASE 16: add after scopeOnly
    val externalClientManager: ExternalMcpClientManager? = null,
)
```

---

### `mcp/tools/McpTools.kt` (service/util, request-response — MODIFY)

**Analog:** self (`mcp/tools/McpTools.kt` lines 54-69)

**`registerTools` extension function** — the fan-out pattern; add external tool description injection after existing registrations:
```kotlin
fun Server.registerTools(api: MontoyaApi, context: McpToolContext) {
    registerUtilityTools(context)
    registerHistoryTools(context)
    // ... existing registrations ...
    registerAiTools(context)
    // PHASE 16: external tools appended to the preamble description, NOT registered with the
    // embedded MCP Server (they are called via ExternalMcpClientManager.callTool, not via Server.tool())
}
```

**Tool routing branch for `ext:` prefix** — add in `mcpTool` dispatcher or whichever routing entry point dispatches tool calls:
```kotlin
// In executeTool() / the tool dispatch path:
if (toolName.startsWith("ext:")) {
    val parts = toolName.split(":", limit = 3)
    // parts[1] = serverName, parts[2] = remoteToolName
    val result = context.externalClientManager?.callTool(parts[1], parts[2], argsMap)
        ?: "External MCP client not available"
    return result
}
```

**`describeTools()` external tool injection** (RESEARCH.md lines 445-447 pattern):
```kotlin
val externalSpecs = context.externalClientManager
    ?.availableTools()
    ?.map { ext -> "ext:${ext.serverName}:${ext.name}" to ext.description }
    .orEmpty()
// Append to tool description string before building preamble
```

---

### `config/McpSettings.kt` (model, CRUD — MODIFY)

**Analog:** self (`config/McpSettings.kt` lines 8-33)

**Existing optional field pattern** — `scopeOnly: Boolean = false` (line 32) was added in Phase 7 without breaking existing serialization. Mirror this exact pattern for the new field:

Current tail of `McpSettings` data class:
```kotlin
    val scopeOnly: Boolean = false,
) {
```

Add after `scopeOnly`:
```kotlin
    val scopeOnly: Boolean = false,
    // PHASE 16: external MCP server list. JSON-serialized blob stored encrypted via SecretCipher.
    // Default empty list; schema v5 migration adds the Preferences key.
    val externalMcpServers: List<ExternalMcpServerConfig> = emptyList(),
) {
```

---

### `config/AgentSettings.kt` (config/persistence, CRUD — MODIFY)

**Analog:** self — schema migration ladder (`AgentSettings.kt` lines 712-737) and secret encrypt/decrypt pattern (lines 243, 268, 273, 554, 563, etc.)

**Current schema version** (line 942):
```kotlin
private const val CURRENT_SETTINGS_SCHEMA_VERSION = 4
```

**Migration ladder pattern** (`AgentSettings.kt` lines 712-737):
```kotlin
private fun migrateIfNeeded() {
    val storedVersion = prefs.getInteger(KEY_SETTINGS_SCHEMA_VERSION) ?: 1
    var effectiveVersion = storedVersion.coerceAtLeast(1)

    if (effectiveVersion < 2) { migrateToSchemaV2(); effectiveVersion = 2 }
    if (effectiveVersion < 3) { /* no-op comment */ effectiveVersion = 3 }
    if (effectiveVersion < 4) { migrateToSchemaV4(); effectiveVersion = 4 }
    // PHASE 16: add this block:
    if (effectiveVersion < 5) {
        // v5: adds externalMcpServers encrypted blob. New key; no existing data to migrate.
        // Existing installs get an empty list on first load — no action needed.
        effectiveVersion = 5
    }

    if (storedVersion != effectiveVersion) {
        prefs.setInteger(KEY_SETTINGS_SCHEMA_VERSION, effectiveVersion)
    }
}
```

**Secret encrypt/decrypt pattern** (lines 243, 554 — for `ollamaApiKey`):
```kotlin
// In load():
ollamaApiKey = cipher.decrypt(prefs.getString(KEY_OLLAMA_API_KEY).orEmpty().trim(), KEY_OLLAMA_API_KEY),
// In save():
prefs.setString(KEY_OLLAMA_API_KEY, cipher.encrypt(settings.ollamaApiKey, KEY_OLLAMA_API_KEY))
```

**External servers blob key** — follow the same pattern but serialize the entire list as JSON first, then encrypt:
```kotlin
// New pref key constant:
private const val KEY_EXT_MCP_SERVERS = "mcp.external.servers.v1"

// In load():
externalMcpServers = loadExternalMcpServers()  // decrypt blob + parse JSON

// In save():
prefs.setString(KEY_EXT_MCP_SERVERS, cipher.encrypt(serializeExternalServers(settings.mcpSettings.externalMcpServers), KEY_EXT_MCP_SERVERS))
```

**Versioned constant bump** (line 942):
```kotlin
// Change from:
private const val CURRENT_SETTINGS_SCHEMA_VERSION = 4
// To:
private const val CURRENT_SETTINGS_SCHEMA_VERSION = 5
```

**`migrateToSchemaV4` idempotency pattern** (lines 748-783) — each key checked for `ENC1:` prefix before re-encrypting. The v5 migration for the new key is a no-op (new key, empty default) but bump must still be gated.

---

### `ui/panels/ExternalServersPanel.kt` (component, CRUD — CREATE)

**Primary layout analog:** `ui/panels/McpConfigPanel.kt` — `sectionPanel()` wrapper, `AccordionPanel` (initially collapsed), `BoxLayout Y_AXIS` stack, `formGrid()` + `addRowFull()` / `addRowPair()`.

**Imports pattern** (`McpConfigPanel.kt` lines 1-15):
```kotlin
import com.six2dez.burp.aiagent.ui.components.AccordionPanel
import com.six2dez.burp.aiagent.ui.design.DesignTokens
import com.six2dez.burp.aiagent.ui.design.addRowFull
import com.six2dez.burp.aiagent.ui.design.addRowPair
import com.six2dez.burp.aiagent.ui.design.addSpacerRow
import com.six2dez.burp.aiagent.ui.design.formGrid
import com.six2dez.burp.aiagent.ui.design.sectionPanel
import java.awt.BorderLayout
import javax.swing.BorderFactory
import javax.swing.BoxLayout
import javax.swing.JComponent
import javax.swing.JPanel
```

**Additional imports for ExternalServersPanel** — extend the above with:
```kotlin
import com.six2dez.burp.aiagent.ui.components.SubtleNotice
import com.six2dez.burp.aiagent.ui.components.ToggleSwitch
import com.six2dez.burp.aiagent.ui.design.BadgeStyle
import com.six2dez.burp.aiagent.ui.design.applyFieldStyle
import com.six2dez.burp.aiagent.ui.design.applyAreaStyle
import com.six2dez.burp.aiagent.ui.design.helpLabel
import com.six2dez.burp.aiagent.ui.design.primaryButton
import com.six2dez.burp.aiagent.ui.design.secondaryButton
import com.six2dez.burp.aiagent.ui.design.toolBadge
import com.six2dez.burp.aiagent.util.SsrfGuard
import javax.swing.table.AbstractTableModel
import javax.swing.JTable
import javax.swing.JScrollPane
import javax.swing.JPasswordField
import javax.swing.JComboBox
import javax.swing.ListSelectionModel
```

**AccordionPanel + BoxLayout stack pattern** (`McpConfigPanel.kt` lines 113-138):
```kotlin
val preprocessingAccordion = AccordionPanel(
    title = "...",
    subtitle = "...",
    content = preprocessingGrid,
    initiallyExpanded = false,
).apply {
    border = BorderFactory.createEmptyBorder(DesignTokens.Spacing.sm, 0, 0, 0)
}
val stack = JPanel().apply {
    layout = BoxLayout(this, BoxLayout.Y_AXIS)
    background = DesignTokens.Colors.surface
    add(grid)
    add(preprocessingAccordion)
}
body.add(stack, BorderLayout.CENTER)
```

**sectionPanel wrapper** (`McpConfigPanel.kt` lines 47-54):
```kotlin
val wrapper = sectionPanel(
    "External MCP Servers",
    "Connect to external or custom MCP servers and use their tools alongside Burp's built-in tools.",
    body,
)
```

**SSRF warning pattern** (`BackendConfigPanel.kt` lines 79-83, 232-234):
```kotlin
// Field declaration:
private val ssrfWarningLabel = JLabel(
    "Warning: this URL resolves to a private/internal address — verify this is intentional"
).apply {
    foreground = DesignTokens.Colors.statusWarning
    isVisible = false
}

// Trigger on URL document change (DocumentListener):
private fun checkAndShowSsrfWarning(urls: List<String>) {
    ssrfWarningLabel.isVisible = urls.any { it.isNotBlank() && SsrfGuard.isPrivateOrLinkLocal(it) }
}
```

**JPasswordField show/hide pattern** (`BackendConfigPanel.kt` — `JPasswordField` fields at lines 94, 102, 106):
```kotlin
val tokenField = JPasswordField(20).apply { applyFieldStyle(this) }
val showButton = secondaryButton("Show").apply {
    addActionListener {
        if (tokenField.echoChar == '*') {
            tokenField.echoChar = 0.toChar()
            text = "Hide"
        } else {
            tokenField.echoChar = '*'
            text = "Show"
        }
    }
}
val tokenPanel = JPanel().apply {
    layout = BoxLayout(this, BoxLayout.X_AXIS)
    isOpaque = false
    add(tokenField)
    add(Box.createRigidArea(java.awt.Dimension(DesignTokens.Spacing.sm, 0)))
    add(showButton)
}
```

**JTable + AbstractTableModel pattern** (`AiLoggerPanel.kt` lines 43-46, 139-158):
```kotlin
// Model:
private val tableModel = AiLogTableModel()   // : AbstractTableModel
private val table = JTable(tableModel)

// Table config:
table.autoResizeMode = JTable.AUTO_RESIZE_LAST_COLUMN
table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION)
table.font = DesignTokens.Typography.body
table.rowHeight = 24                          // Phase 16: 24 px (22 in AiLoggerPanel)
table.tableHeader.font = DesignTokens.Typography.label
```

**SubtleNotice pattern** (`SubtleNotice.kt` lines 69-85):
```kotlin
val stdioNotice = SubtleNotice()
// Show when transport = stdio:
stdioNotice.setMessage(
    level = SubtleNotice.Level.RISK,
    html = "<b>Warning:</b> This server will run a local process using the command above. " +
           "Only configure commands you trust. The process is spawned with no shell expansion " +
           "and only the environment variables you provide."
)
```

**toolBadge usage** (`McpToolTabModel.kt` line 50 + `Components.kt` lines 426-465):
```kotlin
// Transport badge in table column renderer:
toolBadge("SSE", BadgeStyle.FULL)    // neutral gray for SSE
toolBadge("stdio", BadgeStyle.NATIVE) // green-tinted for stdio (higher salience)
// External tool badge in MCP Tools tab:
toolBadge("ext", BadgeStyle.FULL)
```

**primaryButton / secondaryButton** (`Components.kt` lines 347-395):
```kotlin
primaryButton("Add Server")   // Colors.primary bg
secondaryButton("Cancel")     // Colors.surface bg, Colors.primary fg, border Colors.border
secondaryButton("Edit")       // inline in table action cell
secondaryButton("Remove")     // inline in table action cell
```

**Remove confirmation dialog** (standard Swing pattern, consistent with existing uses):
```kotlin
val result = JOptionPane.showConfirmDialog(
    parent,
    "Remove '${config.name}'? The server will be disconnected and all its tools removed from the agent.",
    "Remove Server",
    JOptionPane.YES_NO_OPTION,
    JOptionPane.WARNING_MESSAGE,
)
if (result == JOptionPane.YES_OPTION) { /* remove */ }
```

---

### `build.gradle.kts` (config — MODIFY)

**Analog:** self — existing Ktor server dependency block (`build.gradle.kts` lines 35-41):
```kotlin
implementation("io.modelcontextprotocol:kotlin-sdk:0.5.0")
implementation("io.ktor:ktor-server-core:3.1.3")
implementation("io.ktor:ktor-server-netty:3.1.3")
implementation("io.ktor:ktor-server-cors:3.1.3")
implementation("io.ktor:ktor-server-sse:3.1.3")
implementation("io.ktor:ktor-server-content-negotiation:3.1.3")
implementation("io.ktor:ktor-serialization-kotlinx-json:3.1.3")
```

**Add immediately after the existing MCP/Ktor block** (three new lines only):
```kotlin
// Phase 16: Ktor CLIENT modules (pin to 3.1.3 to match server-side Ktor family)
implementation("io.ktor:ktor-client-core:3.1.3")
implementation("io.ktor:ktor-client-cio:3.1.3")
// kotlin-logging: transitive via kotlin-sdk:0.5.0 StdioClientTransport; declared explicitly to pin version
implementation("io.github.oshai:kotlin-logging-jvm:7.0.7")
```

**Constraint:** Do NOT change `io.modelcontextprotocol:kotlin-sdk` — must remain at `0.5.0`.

---

### `mcp/external/ExternalMcpClientManagerTest.kt` (test, request-response — CREATE)

**Analog:** `mcp/McpSupervisorRestartPolicyTest.kt` — manager lifecycle mock pattern, `ScriptedServerManager`, `FakeTakeoverClient`, `mock<MontoyaApi>(defaultAnswer = Answers.RETURNS_DEEP_STUBS)`, `CountDownLatch` for async assertions.

**Imports pattern** (`McpSupervisorRestartPolicyTest.kt` lines 1-18):
```kotlin
package com.six2dez.burp.aiagent.mcp

import burp.api.montoya.MontoyaApi
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.mockito.Answers
import org.mockito.kotlin.mock
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
```

**API mock setup** (line 23 + full `McpSupervisorRestartPolicyTest`):
```kotlin
val api = mock<MontoyaApi>(defaultAnswer = Answers.RETURNS_DEEP_STUBS)
```

**Async assertion pattern** (lines 62):
```kotlin
assertTrue(manager.awaitStarts(timeoutMs = 1_000))
```

**Test structure for `ExternalMcpClientManagerTest`** — each test should:
1. Create a fake `Client` (mock or stub)
2. Inject it into `ExternalMcpClientManager` via constructor override
3. Call `start(configs)` / `callTool()` / `stop()`
4. Assert state transitions and trust-boundary wrapping

---

### `config/ExternalMcpSettingsMigrationTest.kt` (test, CRUD — CREATE)

**Analog:** `config/AgentSettingsMigrationTest.kt` — `InMemoryPrefs`, `apiWith(prefs.mock)`, round-trip save/load, idempotency assertions.

**InMemoryPrefs pattern** (`AgentSettingsMigrationTest.kt` lines 205-233):
```kotlin
private class InMemoryPrefs {
    val strings = mutableMapOf<String, String>()
    val booleans = mutableMapOf<String, Boolean>()
    val integers = mutableMapOf<String, Int>()
    val mock: Preferences = mock<Preferences>().also { prefs ->
        whenever(prefs.getString(any())).thenAnswer { invocation ->
            strings[invocation.getArgument(0)]
        }
        whenever(prefs.setString(any(), any())).thenAnswer { invocation ->
            strings[invocation.getArgument(0)] = invocation.getArgument(1)
            null
        }
        // ... same for getBoolean, setBoolean, getInteger, setInteger
    }
}

private fun apiWith(preferences: Preferences): MontoyaApi {
    val api = mock<MontoyaApi>(defaultAnswer = Answers.RETURNS_DEEP_STUBS)
    whenever(api.persistence().preferences()).thenReturn(preferences)
    return api
}
```

**Round-trip test pattern** (`AgentSettingsMigrationTest.kt` lines 72-99):
```kotlin
@Test
fun externalMcpServers_roundTripsThroughSaveLoad() {
    val prefs = InMemoryPrefs()
    val writer = AgentSettingsRepository(apiWith(prefs.mock))
    val testConfig = ExternalMcpServerConfig(name = "test", transport = SSE, url = "https://example.com/sse", encryptedToken = "")
    writer.save(writer.defaultSettings().copy(mcpSettings = defaults.mcpSettings.copy(externalMcpServers = listOf(testConfig))))

    val reader = AgentSettingsRepository(apiWith(prefs.mock))
    val loaded = reader.load()

    assertEquals(1, loaded.mcpSettings.externalMcpServers.size)
    assertEquals("test", loaded.mcpSettings.externalMcpServers[0].name)
}
```

**ENC1: prefix idempotency assertion** (mirrors `AgentSettingsMigrationTest.kt` lines 140-143):
```kotlin
// Token blob must be stored encrypted:
val stored = prefs.strings["mcp.external.servers.v1"] ?: ""
assertTrue(stored.startsWith("ENC1:"), "External server blob must be encrypted")
```

**Schema version assertions** (mirrors line 29):
```kotlin
assertEquals(5, prefs.integers["settings.schema.version"])
```

---

## Shared Patterns

### SSRF Guard Wiring
**Source:** `util/SsrfGuard.kt` line 27 + `ui/panels/BackendConfigPanel.kt` lines 79-83, 232-234
**Apply to:** `ExternalServersPanel` SSE URL field DocumentListener + `ExternalMcpClientManager` pre-connect check
```kotlin
// Pure check — no network I/O, no DNS:
SsrfGuard.isPrivateOrLinkLocal(url)  // returns Boolean
```

### SecretCipher Encrypt/Decrypt
**Source:** `config/AgentSettings.kt` lines 243, 554; `config/SecretCipher.kt` lines 52-73, 84-110
**Apply to:** `AgentSettingsRepository.loadExternalMcpServers()` and `saveExternalMcpServers()`, `ExternalMcpClientManager` when decrypting token before injecting into `SseClientTransport` requestBuilder
```kotlin
// Encrypt on save:
cipher.encrypt(plaintext, KEY_EXT_MCP_SERVERS)
// Decrypt on load:
cipher.decrypt(stored, KEY_EXT_MCP_SERVERS)  // returns "" on failure (fail-soft)
// Never log the value; log only the key name.
```

### AuditLogger Emission Pattern
**Source:** `mcp/McpToolContext.kt` lines 65-68
**Apply to:** `ExternalMcpClientManager.callTool()` for every invocation
```kotlin
AuditLogger.emitGlobal("external_mcp_call", buildMap {
    put("server", serverName)
    put("tool", toolName)
    put("status", "ok")  // or "error"
    // CR-02 guard: keep allocations behind the gate
})
```

### CoroutineScope + SupervisorJob Lifecycle
**Source:** `mcp/McpStdioBridge.kt` lines 67-73, 78-93
**Apply to:** `ExternalMcpClientManager` — one `CoroutineScope(Dispatchers.IO + SupervisorJob())` per manager, one child `Job` per connected server
```kotlin
val scope = CoroutineScope(Dispatchers.IO + SupervisorJob())
val job = scope.launch { mcpClient.connect(transport) }
// On shutdown:
runBlocking { withTimeoutOrNull(5000) { client?.close() } }
scope.coroutineContext[kotlinx.coroutines.Job]?.cancel()
```

### ObjectMapper / JSON Serialization (for server list blob)
**Source:** `config/McpSettings.kt` lines 35-39 (Jackson + Kotlin module)
**Apply to:** `ExternalMcpServerConfig` list serialization in `AgentSettingsRepository`
```kotlin
private val mapper = JsonMapper.builder().build().registerKotlinModule()
// Serialize list to JSON string before encrypting:
mapper.writeValueAsString(configs)
// Deserialize after decrypting:
mapper.readValue(json, Array<ExternalMcpServerConfig>::class.java).toList()
```

### JTable AbstractTableModel Pattern
**Source:** `ui/AiLoggerPanel.kt` lines 43-46, 139-158 + the `AiLogTableModel` inner class (lines ~280+)
**Apply to:** `ExternalServersPanel.ExternalServerTableModel : AbstractTableModel`
```kotlin
// Column definitions:
table.autoResizeMode = JTable.AUTO_RESIZE_LAST_COLUMN
table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION)
table.font = DesignTokens.Typography.body
table.rowHeight = 24
table.tableHeader.font = DesignTokens.Typography.label
// Column widths set via: table.columnModel.getColumn(n).preferredWidth = N
```

---

## No Analog Found

None — all files have close analogs in the codebase.

---

## Critical Constraints (carry into PLAN.md actions)

1. **SDK stays at 0.5.0**: `io.modelcontextprotocol:kotlin-sdk` must NOT be bumped. Client classes (`Client`, `SseClientTransport`, `StdioClientTransport`) already exist in this version.
2. **Separate HttpClient**: `ExternalMcpClientManager` creates its own `HttpClient(CIO) { install(SSE) }` — NEVER reuse the Ktor Netty server's application engine.
3. **No shell expansion for stdio**: `ProcessBuilder(listOf(...))` not `Runtime.exec(String)`.
4. **Trust boundary is mandatory**: Every external tool result MUST go through `wrapWithTrustBoundary()` before returning to the tool executor.
5. **Schema v5 bump + migration are atomic**: `CURRENT_SETTINGS_SCHEMA_VERSION = 5` and the `if (effectiveVersion < 5)` block must land in the same commit.
6. **Never log token values**: Only log the Preferences key name on cipher failure (established pattern in `SecretCipher.kt` line 70).
7. **Process cleanup**: `process.destroyForcibly()` after `transport.close()` + `client.close()` for stdio servers on unload.

---

## Metadata

**Analog search scope:** `src/main/kotlin/`, `src/test/kotlin/`, `build.gradle.kts`
**Files scanned:** 15 source files read in full or targeted sections
**Pattern extraction date:** 2026-06-15
