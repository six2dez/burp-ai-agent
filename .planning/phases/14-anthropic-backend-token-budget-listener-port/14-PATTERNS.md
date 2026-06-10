# Phase 14: Anthropic Backend + Token Budget + Listener Port - Pattern Map

**Mapped:** 2026-06-10
**Files analyzed:** 13 (5 create, 8 modify) + 6 test files
**Analogs found:** 13 / 13 (every file has an in-repo analog; zero "no analog" entries)

> All line anchors below were re-verified against the current source on 2026-06-10. Where the
> RESEARCH.md cited a stale line (file drift since research), this map carries the **verified**
> number and notes the correction.

---

## File Classification

| New/Modified File | Role | Data Flow | Closest Analog | Match Quality |
|-------------------|------|-----------|----------------|---------------|
| `backends/anthropic/AnthropicBackend.kt` (CREATE) | backend (HTTP connection) | request-response (buffered) | `backends/openai/OpenAiCompatibleBackend.kt` | exact (same role + flow) |
| `backends/anthropic/AnthropicBackendFactory.kt` (CREATE) | factory | n/a | `backends/openai/OpenAiCompatibleBackendFactory.kt` | exact |
| `backends/BackendRegistry.kt` (MODIFY) | registry | n/a | existing factory list (lines 51-63) | exact (same file) |
| `supervisor/AgentSupervisor.kt` (MODIFY) | supervisor (launch dispatch) | request-response | `"perplexity"`/`"nvidia-nim"` branch (lines 793-854) | exact (same file) — **NOT called out in RESEARCH/UI-SPEC; required** |
| `META-INF/services/...AiBackendFactory` (MODIFY) | service registration | n/a | the 10 existing lines | exact |
| `config/AgentSettings.kt` (MODIFY) | config (persistence) | CRUD (prefs) | `perplexityApiKey`/`perplexityModel` + integer prefs | exact (same file) |
| `util/BudgetGuard.kt` (CREATE) | utility (pure decision) | transform (input→enum) | `redact/SecretShapes.kt` (AWT-free object) | role-match (pure AWT-free object) |
| `scanner/PassiveAiScanner.kt` (MODIFY) | scanner (enqueue gate) | event-driven | `enqueueForScanCheck` enabled gate (line 309-313) | exact (same file) |
| `ui/ChatPanel.kt` (MODIFY) | UI (chat) | event-driven | Phase-13 `ContextPreviewDialog` SubtleNotice reuse | role-match (banner reuse) |
| `ui/panels/BackendConfigPanel.kt` (MODIFY) | UI (settings card) | request-response | `buildPerplexityPanel()` / `buildOpenAiCompatPanel()` | exact (sibling card) |
| `ui/SettingsPanel.kt` (MODIFY) | UI (settings tab) | CRUD (form) | existing scanner `sectionPanel` + integer fields | exact (same file) |
| `mcp/tools/McpTools.kt` (MODIFY) | MCP tool (handler) | request-response (filter) | `proxy_http_history` two dispatch sites | exact (same file) |
| `ui/components/SubtleNotice.kt` (REUSE, no edit) | UI component | n/a | itself — consumed, not modified | n/a |

**Test files (Wave 0, per 14-VALIDATION.md):**

| Test File | Analog | Pattern Borrowed |
|-----------|--------|------------------|
| `backends/anthropic/AnthropicBackendTransportRoutingTest.kt` (CREATE) | `backends/http/HttpBackendTransportRoutingTest.kt` | `stubTransportPost()` spy + `verify(transport).post(eq(url), …)` + null-transport fail-fast |
| `backends/anthropic/AnthropicModelErrorTest.kt` (CREATE) | same file (stub a 400 body) | spy `post()` returns `TransportResponse(400, "...model...", false)`, assert `onComplete` message |
| `util/BudgetGuardTest.kt` (CREATE) | `util/TokenTrackerTest.kt` + `SecretShapes` purity | pure object input→enum; no Swing |
| `scanner/PassiveAiScannerBudgetPauseTest.kt` (CREATE) | `scanner/ScannerQueueBackpressureTest.kt` (existing scanner test style) | set paused, call enqueue, assert executor not submitted |
| `mcp/tools/ProxyHistoryListenerPortFilterTest.kt` (CREATE) | `mcp/tools/*` + `RETURNS_DEEP_STUBS` api mock | mock `api.proxy().history()` items with `listenerPort()` 8080/8081 |
| `backends/BackendRegistryTest.kt` (EXTEND) | itself | assert `"anthropic"` registered |
| `config/AgentSettingsSecretEncryptionTest.kt` (EXTEND) | `roundTrip_allSevenSecretKeys_encryptedAtRest` (lines 57-96) | add `anthropic.apiKey` to the encrypted-keys round-trip |

---

## Pattern Assignments

### `backends/anthropic/AnthropicBackend.kt` (CREATE) — backend, request-response

**Analog:** `backends/openai/OpenAiCompatibleBackend.kt` (387 lines — copy the whole skeleton).

> **The single most important file in this phase.** Build `AnthropicBackend : AiBackend` with a private
> `AnthropicConnection : AgentConnection, UsageAwareConnection` that is a near-copy of
> `OpenAiCompatibleConnection`, swapping ONLY: endpoint, headers, the `messages`/`system` shape,
> response parsing, and usage extraction. **SC2 = no OkHttp**: keep the `transport == null` fail-fast
> verbatim; the only HTTP call is `transport.post(...)`.

**Imports pattern** (`OpenAiCompatibleBackend.kt:1-22` — copy verbatim, change package to `backends.anthropic`):
```kotlin
import com.fasterxml.jackson.databind.JsonNode
import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.module.kotlin.registerKotlinModule
import com.six2dez.burp.aiagent.backends.AgentConnection
import com.six2dez.burp.aiagent.backends.AiBackend
import com.six2dez.burp.aiagent.backends.BackendDiagnostics
import com.six2dez.burp.aiagent.backends.BackendLaunchConfig
import com.six2dez.burp.aiagent.backends.TokenUsage
import com.six2dez.burp.aiagent.backends.UsageAwareConnection
import com.six2dez.burp.aiagent.backends.http.CircuitBreaker
import com.six2dez.burp.aiagent.backends.http.ConversationHistory
import com.six2dez.burp.aiagent.backends.http.HttpBackendSupport
import com.six2dez.burp.aiagent.backends.http.MontoyaHttpTransport
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicReference
```
NOTE: do **NOT** import `com.six2dez.burp.aiagent.util.HeaderParser` (no Bearer here) and do **NOT**
import `okhttp3.*` (SC2c source-string guard asserts the file contains no `okhttp3` / `OkHttpClient`).
`supportsSystemRole` is set on the backend (`OpenAiCompatibleBackend.kt:44` → `override val supportsSystemRole: Boolean = true`).

**launch() pattern** (`OpenAiCompatibleBackend.kt:64-88`): build the connection from `config`, get
`HttpBackendSupport.newCircuitBreaker()`, pass `config.transport`, coerce timeout. Anthropic needs no
`baseUrl` selector (endpoint is a constant) — drop the base-URL plumbing.

**Core send() pattern — the transport-routed loop** (`OpenAiCompatibleBackend.kt:153-322`, copy the structure). The SC2 fail-fast guard (lines 195-200) is mandatory and unchanged:
```kotlin
// BUG-69-01: AI HTTP backends MUST go through MontoyaHttpTransport in production ...
if (transport == null) {
    throw IllegalStateException(
        "MontoyaHttpTransport unavailable; AI HTTP backends require Burp's HTTP stack " +
            "(see HttpBackendSupport.buildClient KDoc for the test-only path)",
    )
}
```

**DIVERGENCE 1 — system prompt (Pattern 2 from RESEARCH).** The OpenAI path calls
`conversationHistory.setSystemPrompt(systemPrompt)` (`OpenAiCompatibleBackend.kt:173`) which
`ConversationHistory.snapshot()` (`HttpBackendSupport.kt:199-205`) prepends as a `{"role":"system",…}`
entry. Anthropic has **no system role** — do NOT call `setSystemPrompt`. Instead:
```kotlin
if (history != null) conversationHistory.setHistory(history)   // HttpBackendSupport.kt:207
conversationHistory.addUser(text)                              // HttpBackendSupport.kt:177
val messages = conversationHistory.snapshot()                  // user/assistant turns ONLY
val payload = mutableMapOf<String, Any?>(
    "model" to model,
    "max_tokens" to (maxOutputTokens ?: 1024),                 // REQUIRED by Anthropic
    "messages" to messages,
    "stream" to false,                                          // Pitfall 1: buffered single-chunk
)
if (!systemPrompt.isNullOrBlank()) payload["system"] = systemPrompt   // TOP-LEVEL field
if (determinismMode) payload["temperature"] = 0.0
```
Do NOT send `response_format` (OpenAI-only; `OpenAiCompatibleBackend.kt:214-216`). Do NOT add
`tools`/`tool_choice`/cache headers (deferred).

**DIVERGENCE 2 — headers (Pitfall 2).** The transport adds `Content-Type: application/json` itself
(`MontoyaHttpTransport.kt:29`), so DO NOT include it. Headers come from `config.headers` (built by the
supervisor branch — see AgentSupervisor below) as:
```kotlin
mapOf("x-api-key" to apiKey, "anthropic-version" to "2023-06-01")
```

**DIVERGENCE 3 — endpoint.** Replace `buildChatCompletionsUrl(baseUrl)` with a constant:
```kotlin
private const val ANTHROPIC_MESSAGES_URL = "https://api.anthropic.com/v1/messages"
val resp = transport.post(ANTHROPIC_MESSAGES_URL, allHeaders, json, timeoutSeconds * 1000)
```
(mirrors `OpenAiCompatibleBackend.kt:242` — the only HTTP call).

**DIVERGENCE 4 — SC3 model-rejection error.** Add BEFORE the generic non-2xx handler
(`OpenAiCompatibleBackend.kt:243-264`):
```kotlin
if (resp.statusCode == 400 && resp.body.contains("model", ignoreCase = true)) {
    onComplete(IllegalStateException(
        "Anthropic rejected the model ID — check Settings > Anthropic > Model"))
    return@submit
}
```
(exact string from CONTEXT.md SC3 — do not reword.)

**DIVERGENCE 5 — response parsing.** OpenAI reads `choices[0].message.content`
(`OpenAiCompatibleBackend.kt:270-278`). Anthropic reads `content[].text` (concatenate `type=="text"` blocks):
```kotlin
val node = mapper.readTree(body)
val text = buildString {
    node.path("content").forEach { block ->
        if (block.path("type").asText() == "text") append(block.path("text").asText())
    }
}
```

**DIVERGENCE 6 — usage extraction.** Replace `extractUsage` (`OpenAiCompatibleBackend.kt:324-333`,
which reads `usage.prompt_tokens`/`usage.completion_tokens`) with:
```kotlin
private fun extractUsage(node: JsonNode): TokenUsage? {
    val u = node.path("usage")
    val input = u.path("input_tokens").asInt(-1)
    val output = u.path("output_tokens").asInt(-1)
    if (input < 0 && output < 0) return null
    return TokenUsage(input.coerceAtLeast(0), output.coerceAtLeast(0))
}
```

**Privacy logging (keep verbatim, `OpenAiCompatibleBackend.kt:229-240`):** log the body **shape** only
(`model=… messages=N json_bytes=…`) — never the JSON, never message content, never the key.

**Retry / circuit-breaker loop:** reuse `circuitBreaker.tryAcquire()` /
`HttpBackendSupport.openCircuitError` / `isRetryableConnectionError` / `retryDelayMs` exactly as
`OpenAiCompatibleBackend.kt:177-308`.

---

### `backends/anthropic/AnthropicBackendFactory.kt` (CREATE) — factory

**Analog:** `backends/openai/OpenAiCompatibleBackendFactory.kt` (whole file, 8 lines):
```kotlin
package com.six2dez.burp.aiagent.backends.openai
import com.six2dez.burp.aiagent.backends.AiBackend
import com.six2dez.burp.aiagent.backends.AiBackendFactory
class OpenAiCompatibleBackendFactory : AiBackendFactory {
    override fun create(): AiBackend = OpenAiCompatibleBackend()
}
```
Anthropic version: `package backends.anthropic`, `create(): AiBackend = AnthropicBackend()`.
(Do NOT follow the Perplexity/NVIDIA factory shape — those delegate to `OpenAiCompatibleBackend` with
selectors; Anthropic has its own backend class, so the plain OpenAI **factory** is the right analog.)

---

### `backends/BackendRegistry.kt` (MODIFY) — registry

**Analog:** the existing import + fallback list in the same file.

**Import** (alongside `BackendRegistry.kt:14` `import …backends.openai.OpenAiCompatibleBackendFactory`):
add `import com.six2dez.burp.aiagent.backends.anthropic.AnthropicBackendFactory`.

**Fallback built-ins list** (`BackendRegistry.kt:53-62` — add one line):
```kotlin
listOf(
    CodexCliBackendFactory(),
    ...
    PerplexityBackendFactory(),
    AnthropicBackendFactory(),   // ← add
)
```
NOTE: the primary registration path is `META-INF/services` (ServiceLoader, `BackendRegistry.kt:42-44`);
the list above is only the fallback when ServiceLoader returns empty. Register in **both**.

---

### `META-INF/services/com.six2dez.burp.aiagent.backends.AiBackendFactory` (MODIFY) — service registration

**Analog:** the 10 existing lines (e.g. `...backends.openai.OpenAiCompatibleBackendFactory`).
Append one line:
```
com.six2dez.burp.aiagent.backends.anthropic.AnthropicBackendFactory
```

---

### `supervisor/AgentSupervisor.kt` (MODIFY) — supervisor launch dispatch  ⚠️ NOT in RESEARCH/UI-SPEC file list

**Analog:** the `"perplexity"` branch (`AgentSupervisor.kt:824-854`) and `"nvidia-nim"`
(`AgentSupervisor.kt:793-823`).

> **This file is required but was not explicitly enumerated in RESEARCH.md's "Recommended Project
> Structure" or UI-SPEC.** The supervisor's `backendLaunchConfig` `when(backendId)` is where per-backend
> headers + transport are assembled. Without an `"anthropic"` branch, `AnthropicBackend.launch()` would
> receive empty headers and the `x-api-key`/`anthropic-version` headers (Pitfall 2) would never be set.

The existing branches build headers via `HeaderParser.withBearerToken(...)` (`AgentSupervisor.kt:773-777`,
`801-805`, `832-836`). The Anthropic branch must **NOT** use `withBearerToken` (Pitfall 2). Add:
```kotlin
"anthropic" -> {
    val model = (settings?.anthropicModel ?: prefs.getString("anthropic.model") ?: "claude-sonnet-4-6").trim()
    val apiKey = settings?.anthropicApiKey ?: prefs.getString("anthropic.apiKey").orEmpty()
    val timeoutSeconds = settings?.someTimeout ?: Defaults.CLI_PROCESS_TIMEOUT_SECONDS  // reuse existing default
    BackendLaunchConfig(
        backendId = backendId,
        displayName = "Anthropic",
        model = model,
        headers = mapOf("x-api-key" to apiKey, "anthropic-version" to "2023-06-01"),  // NOT withBearerToken
        requestTimeoutSeconds = timeoutSeconds.toLong(),
        embeddedMode = embeddedMode,
        sessionId = sessionId,
        determinismMode = determinism,
        env = baseEnv,
        cliSessionId = cliSessionId,
        transport = httpTransport,   // BUG-69-01: route through Burp's stack
    )
}
```
`BackendLaunchConfig` field reference: `backends/BackendTypes.kt:5-19` (`headers`, `transport`,
`requestTimeoutSeconds`, `model` all present; `baseUrl` optional and unused here).

---

### `config/AgentSettings.kt` (MODIFY) — config persistence (CRUD)

**Analog:** the Perplexity fields (encrypted key + model) and the integer-pref pattern.

**Data class fields** (after `perplexityTimeoutSeconds`, `AgentSettings.kt:58-61`) — all defaulted so
old prefs and the positional `BackendRegistryTest.baselineSettings()` still construct:
```kotlin
val anthropicModel: String = "claude-sonnet-4-6",
val anthropicApiKey: String = "",
val tokenBudgetWarnThreshold: Int = 0,   // 0 = off
val tokenBudgetHardCap: Int = 0,         // 0 = off
```

**Load — decrypt key + integer thresholds** (mirror `AgentSettings.kt:277-281`):
```kotlin
anthropicModel = prefs.getString(KEY_ANTHROPIC_MODEL).orEmpty().trim().ifBlank { "claude-sonnet-4-6" },
anthropicApiKey = cipher.decrypt(prefs.getString(KEY_ANTHROPIC_API_KEY).orEmpty().trim(), KEY_ANTHROPIC_API_KEY),
tokenBudgetWarnThreshold = (prefs.getInteger(KEY_TOKEN_BUDGET_WARN) ?: 0).coerceAtLeast(0),
tokenBudgetHardCap = (prefs.getInteger(KEY_TOKEN_BUDGET_CAP) ?: 0).coerceAtLeast(0),
```
(`cipher.decrypt` usage anchor: `AgentSettings.kt:278`; integer-coerce anchor: `AgentSettings.kt:327`.)

**defaultSettings()** (mirror `AgentSettings.kt:434-437`): `anthropicModel = "claude-sonnet-4-6"`,
`anthropicApiKey = ""`, `tokenBudgetWarnThreshold = 0`, `tokenBudgetHardCap = 0`.

**Save — encrypt key + plain integers** (mirror `AgentSettings.kt:536-539`):
```kotlin
prefs.setString(KEY_ANTHROPIC_MODEL, settings.anthropicModel)
prefs.setString(KEY_ANTHROPIC_API_KEY, cipher.encrypt(settings.anthropicApiKey, KEY_ANTHROPIC_API_KEY))
prefs.setInteger(KEY_TOKEN_BUDGET_WARN, settings.tokenBudgetWarnThreshold.coerceAtLeast(0))
prefs.setInteger(KEY_TOKEN_BUDGET_CAP, settings.tokenBudgetHardCap.coerceAtLeast(0))
```
(Pitfall 5: thresholds are **integers, NOT secrets** — `setInteger`, never `cipher.encrypt`.)

**KEY_* constants** (companion, `AgentSettings.kt:782-786` is the Perplexity block):
```kotlin
private const val KEY_ANTHROPIC_MODEL = "anthropic.model"
private const val KEY_ANTHROPIC_API_KEY = "anthropic.apiKey"
private const val KEY_TOKEN_BUDGET_WARN = "tokenBudget.warnThreshold"
private const val KEY_TOKEN_BUDGET_CAP = "tokenBudget.hardCap"
```

**Migration secret list** (`AgentSettings.kt:701-710` — add `KEY_ANTHROPIC_API_KEY` to the `secretKeys`
`listOf(...)` so a pre-encryption plaintext value is encrypted idempotently; belt-and-suspenders since
save() already encrypts on write):
```kotlin
val secretKeys = listOf(
    KEY_OLLAMA_API_KEY, KEY_LMSTUDIO_API_KEY, KEY_OPENAI_COMPAT_API_KEY,
    KEY_NVIDIA_NIM_API_KEY, KEY_PERPLEXITY_API_KEY,
    KEY_ANTHROPIC_API_KEY,           // ← add
    KEY_MCP_TOKEN, KEY_MCP_TLS_PASSWORD,
)
```

---

### `util/BudgetGuard.kt` (CREATE) — pure AWT-free decision utility

**Analog:** `redact/SecretShapes.kt` (an `object` with a `data class` and a typed pure output;
explicitly AWT-free — `SecretShapes.kt:17-19` documents the no-`java.awt`/`javax.swing` contract).

Mirror the SecretShapes shape (`object` + nested type + a pure function). The output is an enum so
SC4 is testable without Swing and `ChatPanel` only renders the result:
```kotlin
package com.six2dez.burp.aiagent.util

/** AWT-free per-session token-budget decision. MUST NOT import java.awt / javax.swing (mirrors SecretShapes). */
object BudgetGuard {
    enum class State { OFF, WARN, CAP }   // RESEARCH §"Design tests AWT-free": {OFF, WARN, CAP}

    fun evaluate(usedTokens: Long, warnThreshold: Int, hardCap: Int): State = when {
        hardCap > 0 && usedTokens >= hardCap -> State.CAP
        warnThreshold > 0 && usedTokens >= warnThreshold -> State.WARN
        else -> State.OFF
    }

    /** Session total = combined input+output across all flows/backends (TokenTracker.kt:91-112). */
    fun currentSessionTokens(): Long =
        com.six2dez.burp.aiagent.util.TokenTracker.snapshot()
            .sumOf { it.inputTokensEstimated + it.outputTokensEstimated }
}
```
`TokenUsageSnapshot.inputTokensEstimated`/`outputTokensEstimated` already = actual-when-available +
estimate (`TokenTracker.kt:15-16`, `109-110`) — no extra logic. `TokenTracker.snapshot()` signature:
`TokenTracker.kt:91`. Reused by BOTH `ChatPanel` (Touch Point 3) and the scanner (Open Question 2).

---

### `scanner/PassiveAiScanner.kt` (MODIFY) — enqueue gate (event-driven)

**Analog:** the existing `enabled` gate in `enqueueForScanCheck` (same file).

**Pattern 3 (RESEARCH) — separate gate, NOT setEnabled.** `setEnabled(false)` clears the knowledge base
(`PassiveAiScanner.kt:293-302`, esp. `ScanKnowledgeBase.clear()` at line 299) and flips the user's
visible toggle — wrong for a reversible budget pause. Add a distinct `AtomicBoolean`:
```kotlin
// near the existing `private val enabled = AtomicBoolean(false)` at PassiveAiScanner.kt:62
private val budgetPaused = java.util.concurrent.atomic.AtomicBoolean(false)
fun setBudgetPaused(on: Boolean) { budgetPaused.set(on) }
fun isBudgetPaused(): Boolean = budgetPaused.get()
```
(`AtomicBoolean` already imported at `PassiveAiScanner.kt:30`.)

**Gate the enqueue choke point** (`PassiveAiScanner.kt:309-313` — add ONE line after the `enabled` check):
```kotlin
fun enqueueForScanCheck(requestResponse: HttpRequestResponse) {
    if (!enabled.get()) return
    if (budgetPaused.get()) return                    // ← CAP-04: no-op when paused (does NOT clear KB)
    if (supervisor.isBlockedByBurpAiGate()) return
    executor.submit { analyzeManually(requestResponse) }
}
```
Per-process reset is intentional (the `AtomicBoolean` starts `false` on each Burp run).

**Optional (Open Question 2):** the scanner records tokens at `PassiveAiScanner.kt:811`, `959`, `1550`.
For a fully centralized cap, evaluate `BudgetGuard.evaluate(BudgetGuard.currentSessionTokens(), warn, cap)`
at one of those sites and flip `setBudgetPaused(true)` on `State.CAP`, so a scanner-driven overflow
pauses even when chat is idle. Minimal viable per RESEARCH: gate enqueue on `budgetPaused` and let
ChatPanel.onComplete flip it; the scanner-side check is the recommended extension.

---

### `ui/ChatPanel.kt` (MODIFY) — chat banner (event-driven)  [FLAG-14-04: keep the diff tiny]

**Analog:** Phase-13 `ui/components/ContextPreviewDialog.kt:54-74` (the SubtleNotice reuse pattern).

**Banner member + NORTH placement** (UI-SPEC Touch Point 3). `chatContainer` is built at
`ChatPanel.kt:238-241`:
```kotlin
val chatContainer = JPanel(BorderLayout())                       // ChatPanel.kt:238 (existing)
chatContainer.background = UiTheme.Colors.surface                // 239 (existing)
chatContainer.add(budgetNotice, BorderLayout.NORTH)              // ← ADD (budgetNotice = SubtleNotice(), starts hidden)
chatContainer.add(chatCards, BorderLayout.CENTER)                // 240 (existing)
chatContainer.add(inputPanel(), BorderLayout.SOUTH)              // 241 (existing)
```
Declare `private val budgetNotice = SubtleNotice()` as a member (single instance, not per-message).

**Budget check hook** — immediately AFTER the existing `TokenTracker.record(...)` call in `onComplete`
(`ChatPanel.kt:558-565`; `onComplete` opens at line 546). Render the `BudgetGuard.State` enum:
```kotlin
SwingUtilities.invokeLater {
    val warn = getSettings().tokenBudgetWarnThreshold        // getSettings: ChatPanel.kt:73
    val cap  = getSettings().tokenBudgetHardCap
    val used = BudgetGuard.currentSessionTokens()
    when (BudgetGuard.evaluate(used, warn, cap)) {
        BudgetGuard.State.CAP -> {
            budgetNotice.setMessage(SubtleNotice.Level.RISK,
                "Token budget reached (${fmt(used)}/${fmt(cap)}). Passive scanning paused; chat is still available.")
            passiveScanner.setBudgetPaused(true)
        }
        BudgetGuard.State.WARN -> budgetNotice.setMessage(SubtleNotice.Level.WARN,
            "Token budget warning: ${fmt(used)} of ${fmt(warn)} tokens used this session.")
        BudgetGuard.State.OFF -> budgetNotice.hideNotice()
    }
}
```
SubtleNotice API: `setMessage(Level, html)` / `hideNotice()` (`SubtleNotice.kt:69`, `87`); levels
`INFO/WARN/RISK` (`SubtleNotice.kt:25`). Exact copy strings = UI-SPEC Copywriting Contract.
ChatPanel must hold a `passiveScanner` reference (verify it is already injected; if not, thread it
through the constructor like `getSettings`).

> **ContextPreviewDialog reuse pattern (the analog), `ContextPreviewDialog.kt:59-71`:**
> ```kotlin
> val survivedNotice = SubtleNotice()
> if (survivors.isNotEmpty()) survivedNotice.setMessage(SubtleNotice.Level.WARN, html)
> else survivedNotice.hideNotice()
> ```

---

### `ui/panels/BackendConfigPanel.kt` (MODIFY) — Anthropic settings card

**Analog:** `buildPerplexityPanel()` / `buildOpenAiCompatPanel()` (UI-SPEC Touch Point 1 carries the
verbatim anatomy). Field members styled via `applyFieldStyle(...)`; card built with `formGrid()` +
`EmptyBorder(sectionPad×4)` + `addRowFull` + trailing `addSpacerRow(panel, Spacing.sm)`.

```kotlin
private val anthropicModel = JTextField(initialState.anthropicModel)   // default claude-sonnet-4-6
private val anthropicApiKey = JPasswordField(initialState.anthropicApiKey)
// in init: applyFieldStyle(anthropicModel); applyFieldStyle(anthropicApiKey)

private fun buildAnthropicPanel(): JPanel {
    val panel = formGrid()
    panel.border = EmptyBorder(DesignTokens.Spacing.sectionPad, DesignTokens.Spacing.sectionPad,
                               DesignTokens.Spacing.sectionPad, DesignTokens.Spacing.sectionPad)
    addRowFull(panel, "Model", anthropicModel)
    addRowFull(panel, "API key (Bearer)", anthropicApiKey)
    addRowFull(panel, "", buildButtonRowPanel(buildTestConnectionButton("anthropic")))
    addSpacerRow(panel, DesignTokens.Spacing.sm)
    return panel
}
// register: cards.add(buildAnthropicPanel(), "anthropic")  — after the buildPerplexityPanel line
```
`BackendConfigState` gains `anthropicModel`/`anthropicApiKey` (read `String(anthropicApiKey.password).trim()`
in `currentBackendSettings()`, set `anthropicApiKey.text` in `applyState`) — mirror the Perplexity wiring.
**Row-set rule (FLAG-14-02):** NO Base URL row (endpoint is fixed → false configurability + SSRF surface).
A "Timeout (seconds)" row is the only acceptable extra.

---

### `ui/SettingsPanel.kt` (MODIFY) — Token-budget section

**Analog:** the existing Passive AI Scanner `sectionPanel` region + sibling integer fields (UI-SPEC
Touch Point 2; FLAG-14-01 placement). Use `sectionPanel(title, subtitle, content)` + `helpLabel(...)`:
```kotlin
sectionPanel(
    title = "Token budget",
    subtitle = "Optional per-session limits. 0 means unlimited (off).",
    content = run {
        val grid = formGrid()
        addRowFull(grid, "Warn threshold (tokens)", warnThresholdField)   // JTextField + applyFieldStyle
        addRowFull(grid, "Hard cap (tokens)", hardCapField)
        addRowFull(grid, "", helpLabel(
            "Warn shows a chat banner. The hard cap pauses passive scanning; chat stays usable."))
        grid
    },
)
```
Parse with `toIntOrNull()` + fallback to `0` (mirror the existing timeout-seconds fields). Collect/apply
through the existing `SettingsPanel` save flow into `AgentSettings.tokenBudgetWarnThreshold`/`…HardCap`.

---

### `mcp/tools/McpTools.kt` (MODIFY) — proxy_http_history listener-port filter  ⚠️ TWO dispatch paths (Pitfall 4)

**Analog:** the two existing `proxy_http_history` handlers + `GetProxyHttpHistory` data class (same file).

**1) Data class** (`McpTools.kt:2719-2723` — add one field; the reified-generic registration
auto-exposes it in the tool schema, no manual schema edit):
```kotlin
@Serializable
data class GetProxyHttpHistory(
    override val count: Int = 5,
    override val offset: Int = 0,
    val includeUnpreprocessedResponse: Boolean = false,
    val listenerPort: Int? = null,            // CAP-03 — null/unset = all ports
) : Paginated
```

**2) Paginated path** (`McpTools.kt:649-663` — lambda receiver is `GetProxyHttpHistory`, so
`listenerPort` is in scope directly). Filter the `seq` from line 657:
```kotlin
val items = api.proxy().history()                                              // 656 (existing)
val seq = orderedProxyHistory(items, context) { it.request()?.toString().orEmpty() }   // 657 (existing)
    .let { s -> if (listenerPort != null) s.filter { it.listenerPort() == listenerPort } else s }   // ← ADD
```

**3) Manual decode path** (`McpTools.kt:1860-1878` — `input.listenerPort`). Filter the `seq` from line 1869:
```kotlin
val seq = orderedProxyHistory(items, context) { it.request()?.toString().orEmpty() }   // 1869 (existing)
    .let { s -> if (input.listenerPort != null) s.filter { it.listenerPort() == input.listenerPort } else s }  // ← ADD
// existing McpScopeFilter.filterInScope(...) at 1871 follows unchanged
```
`ProxyHttpRequestResponse.listenerPort(): Int` is verified in montoya-api 2026.2 (RESEARCH §9).
Empty result is NOT an error: the paginated path yields "Reached end of items"; the manual path yields
an empty `limitedJoin` (`McpTools.kt:1872`). Both must filter — applying to only one leaves the other
unfiltered (Pitfall 4). `orderedProxyHistory` helper: `McpTools.kt:1074`.

---

## Shared Patterns

### Transport routing (SC2) — applies to AnthropicBackend
**Source:** `backends/openai/OpenAiCompatibleBackend.kt:195-242` + `backends/http/MontoyaHttpTransport.kt:18-34`
**Rule:** all HTTP via the injected `transport.post(...)`; `transport == null` → fail fast with
`IllegalStateException("MontoyaHttpTransport unavailable; …")`. No `okhttp3` import on the production path
(SC2c source-string guard). The transport adds `Content-Type: application/json` itself
(`MontoyaHttpTransport.kt:29`).

### Encrypted secret at rest (SEC-01) — applies to AgentSettings.anthropicApiKey
**Source:** `config/AgentSettings.kt:278` (decrypt) / `:537` (encrypt) / `:701-710` (migration list);
`config/SecretCipher.kt:52` (`encrypt`) / `:84` (`decrypt`).
**Rule:** decrypt on load, encrypt on save, add key to the migration `secretKeys` list, never log the value.
Versioned pref key `KEY_ANTHROPIC_API_KEY = "anthropic.apiKey"`. (Integers are NOT secrets — Pitfall 5.)

### AWT-free pure decision object — applies to BudgetGuard
**Source:** `redact/SecretShapes.kt` (object + nested type + pure function; AWT-free contract at lines 17-19).
**Rule:** no `java.awt`/`javax.swing` imports; output a typed value (enum `State{OFF,WARN,CAP}`) the UI renders.

### SubtleNotice banner reuse (Phase 13) — applies to ChatPanel
**Source:** `ui/components/ContextPreviewDialog.kt:59-71`; component API `ui/components/SubtleNotice.kt:69,87,25`.
**Rule:** one instance, `setMessage(Level, html)` to show / `hideNotice()` to hide; `Level.WARN` amber
advisory, `Level.RISK` red (a guardrail fired). The component re-applies its palette on theme switch
(`SubtleNotice.updateUI()`).

### Spy-transport test harness — applies to the two Anthropic backend tests
**Source:** `backends/http/HttpBackendTransportRoutingTest.kt:288-296` (`stubTransportPost()`) + the
null-transport fail-fast test at lines 82-118.
**Rule:** `spy(MontoyaHttpTransport(mock<MontoyaApi>(RETURNS_DEEP_STUBS)))`, stub `post()` to a
`TransportResponse`, then `verify(transport).post(eq("https://api.anthropic.com/v1/messages"), any(), any(), any())`.
SC3 test stubs `TransportResponse(400, "...model...not_found...", false)` and asserts the `onComplete`
message equals the SC3 string.

---

## No Analog Found

None. Every file in this phase has a direct in-repo analog (Phase 14 is an integration/composition
exercise — RESEARCH §"Don't Hand-Roll" key insight). The only genuinely new logic is the Anthropic JSON
DTO shape, the `BudgetGuard` comparison, and the listener-port filter — all small and each modeled on an
existing pattern above.

---

## Planner Notes (gotchas that change plan structure)

1. **`AgentSupervisor.kt` is a required modification absent from RESEARCH/UI-SPEC file lists.** The
   `when(backendId)` launch dispatch (lines 765-869) needs an `"anthropic"` branch building the
   `x-api-key`/`anthropic-version` headers (NOT `withBearerToken`) + `transport = httpTransport`.
   Without it the backend gets no auth headers. Assign it to the same plan as `AnthropicBackend.kt`.

2. **`McpTools.kt` has TWO dispatch paths** (paginated lambda ~L649 with `GetProxyHttpHistory` as
   receiver, manual decode ~L1860 with `input.listenerPort`). Add the data-class field once (L2719) and
   the `.filter { it.listenerPort() == … }` in BOTH `seq` pipelines. A test that exercises only one path
   will pass while the other regresses (Pitfall 4) — the SC5 test must cover both.

3. **New `AgentSettings` fields MUST be defaulted.** `BackendRegistryTest.baselineSettings()`
   (lines 79-162) constructs `AgentSettings(...)` **positionally** without the new fields; the four
   additions (`anthropicModel`, `anthropicApiKey`, `tokenBudgetWarnThreshold`, `tokenBudgetHardCap`) all
   carry defaults in RESEARCH §6, so that test keeps compiling. Do not add a non-defaulted field.

4. **Streaming is buffered (Pitfall 1).** `MontoyaHttpTransport.post()` returns a complete response
   (`MontoyaHttpTransport.kt:74`). Ship `stream:false` + single `onChunk` (matches every HTTP backend);
   SC1's "streaming visible through the proxy" = the request appearing in Burp history, which `post()`
   guarantees. SSE-replay is a discretionary enhancement, not an SC requirement.

5. **Budget pause ≠ scanner disable.** `setEnabled(false)` clears `ScanKnowledgeBase`
   (`PassiveAiScanner.kt:299`). Use the separate `budgetPaused` gate (Pattern 3). SC4b test asserts the
   KB is NOT cleared and the executor is not submitted when paused.

6. **ChatPanel needs a `passiveScanner` handle.** Verify it is injected into `ChatPanel`'s constructor;
   if not, thread it through alongside `getSettings` (ChatPanel.kt:73). FLAG-14-04: keep the ChatPanel
   diff minimal (one member + one `add` + the onComplete block) — it is slated for the Phase 19 split.

## Metadata

**Analog search scope:** `backends/{openai,perplexity,nvidia,http}`, `backends/BackendRegistry.kt` +
`BackendTypes.kt`, `supervisor/AgentSupervisor.kt`, `config/{AgentSettings,SecretCipher}.kt`,
`util/{TokenTracker}.kt`, `redact/SecretShapes.kt`, `scanner/PassiveAiScanner.kt`,
`ui/{ChatPanel}.kt` + `ui/components/{SubtleNotice,ContextPreviewDialog}.kt`,
`ui/panels/BackendConfigPanel.kt`, `mcp/tools/McpTools.kt`, `META-INF/services/...AiBackendFactory`,
and the matching `src/test/...` analogs.
**Files scanned:** ~22 source + 3 test analogs read; line anchors re-verified 2026-06-10.
**Pattern extraction date:** 2026-06-10
