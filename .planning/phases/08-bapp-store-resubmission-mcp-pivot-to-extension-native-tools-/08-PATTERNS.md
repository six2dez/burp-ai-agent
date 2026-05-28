# Phase 8: BApp Store Resubmission — Pattern Map

**Mapped:** 2026-05-28
**Files analyzed:** 15 (new/modified)
**Analogs found:** 14 / 15 (1 new file has no in-project analog — `BuildFlags.kt` is generated)

---

## File Classification

| New/Modified File | Role | Data Flow | Closest Analog | Match Quality |
|---|---|---|---|---|
| `build/generated/.../BuildFlags.kt` (generated) | config/constant | N/A (compile-time) | No in-project analog; use RESEARCH.md Pattern 1 | none |
| `build.gradle.kts` (add generate task + artifact naming) | config | batch/transform | `build.gradle.kts` itself (tasks.shadowJar block, lines 73-81 + ktlint filter line 128) | self-modify |
| `mcp/McpToolCatalog.kt` (add `nativeTool` field + `available()`) | config/registry | CRUD | `McpToolCatalog.kt` itself (`all()`, `defaults()`, `unsafeToolIds()`, lines 418-429) | self-modify |
| `mcp/tools/McpToolHandlers.kt` (add `native` list + route through `available()`) | middleware/router | request-response | `McpToolHandlers.kt` `McpToolRegistrations` itself (lines 10-101) | self-modify |
| `mcp/tools/McpTools.kt` (`registerTools()` filter + 6 new `when` branches) | controller | request-response | `McpTools.kt` `executeToolResult()` lines 1328-2067 — `status` / `issue_create` handlers | exact |
| `mcp/McpToolContext.kt` (add nullable `supervisor`, `passiveScanner`, `backendRegistry`) | model/context | N/A | `McpToolContext.kt` lines 32 (`aiRequestLogger: AiRequestLogger? = null`) | exact |
| `mcp/McpRuntimeContextFactory.kt` (populate new context fields) | factory | N/A | `McpRuntimeContextFactory.kt` lines 14-48 (existing field population pattern) | exact |
| `mcp/tools/AiTools.kt` (NEW — `registerAiTools()` + 6 handler cases) | controller | request-response | `IssueTools.kt` / `UtilityTools.kt` (registration pattern) + `McpTool.kt` `runTool` | exact |
| `ui/SettingsPanel.kt` (swap `all()` to `available()` in tool list loop) | component | request-response | `SettingsPanel.kt` line 2194 `McpToolCatalog.all().groupBy { it.category }` | self-modify |
| `supervisor/AgentSupervisor.kt` (no change to `startOrAttach` gate; review only) | service | event-driven | `AgentSupervisor.kt` lines 119-141 (isAiEnabled, requiresBurpAiAndDisabled, isBlockedByBurpAiGate) | exact |
| `scanner/AiPassiveScanCheck.kt` (NEW — implements `PassiveScanCheck`) | service | event-driven | `AiScanCheck.kt` (implements `ScanCheck`; same activeAudit + consolidateIssues pattern) | role-match |
| `scanner/PassiveAiScanner.kt` (remove ProxyResponseHandler; add `analyzeForScanCheck()`) | service | event-driven | `PassiveAiScanner.kt` `manualScan()` lines 543-586 + `analyzeManually()` 588-594 | exact |
| `App.kt` (register `AiPassiveScanCheck` via `registerPassiveScanCheck`) | config/wiring | N/A | `App.kt` lines 151-160 (existing try/catch ScanCheck registration block) | exact |
| `mcp/tools/McpToolParityTest.kt` (extend parity assertions for new tools) | test | N/A | `McpToolParityTest.kt` lines 17-22 | exact |
| `mcp/AiGateMcpToolTest.kt` (NEW test) | test | N/A | `BurpAiGateScopingTest.kt` (mock MontoyaApi + AgentSupervisor pattern) | role-match |
| `scanner/AiPassiveScanCheckTest.kt` (NEW test) | test | N/A | `PassiveAiScannerConfidenceTest.kt` (reflection-based private method access + mock api) | role-match |
| `mcp/McpToolCatalogStoreBuildTest.kt` (NEW test) | test | N/A | `McpToolParityTest.kt` (catalog-only test; no mock api needed) | role-match |

---

## Pattern Assignments

### `build.gradle.kts` (modified — generate task + artifact naming)

**Analog:** `build.gradle.kts` itself — `tasks.shadowJar` (lines 73-81), ktlint filter (lines 127-130), `tasks.withType<KotlinCompile>` (lines 62-67)

**Existing shadowJar block to extend** (lines 73-81):
```kotlin
tasks.shadowJar {
    archiveBaseName.set("Custom-AI-Agent")
    archiveClassifier.set("")
    mergeServiceFiles()
    isZip64 = true
    configurations = listOf(project.configurations.runtimeClasspath.get())
}
```

**Existing ktlint exclusion already covers generated dir** (lines 127-130):
```kotlin
filter {
    exclude("**/build/**")
    exclude("**/generated/**")
}
```

**Existing KotlinCompile task config to extend with `dependsOn`** (lines 62-67):
```kotlin
tasks.withType<KotlinCompile> {
    compilerOptions {
        jvmTarget.set(org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_21)
        freeCompilerArgs.addAll(listOf("-Xjsr305=strict"))
    }
}
```

**Pattern to add** (no in-project analog — use RESEARCH.md Pattern 1 + Pattern "Two-artifact naming"):
```kotlin
val storeBuild = providers.gradleProperty("storeBuild").orNull == "true"

val generatedSrcDir = layout.buildDirectory.dir("generated/buildflags").get().asFile

val generateBuildFlags by tasks.registering {
    group = "build"
    description = "Generates BuildFlags.kt with compile-time store-build flag"
    inputs.property("storeBuild", storeBuild)
    outputs.dir(generatedSrcDir)
    doFirst {
        val pkgPath = "com/six2dez/burp/aiagent"
        val pkgDir = generatedSrcDir.resolve(pkgPath).also { it.mkdirs() }
        pkgDir.resolve("BuildFlags.kt").writeText("""
package com.six2dez.burp.aiagent

object BuildFlags {
    const val STORE_BUILD = $storeBuild
}
""".trimIndent())
    }
}

sourceSets.main {
    kotlin.srcDir(generatedSrcDir)
}

tasks.withType<KotlinCompile> {
    dependsOn(generateBuildFlags)
}

// In tasks.shadowJar replace the fixed archiveBaseName with:
tasks.shadowJar {
    if (storeBuild) {
        archiveBaseName.set("Custom-AI-Agent")
    } else {
        archiveBaseName.set("Custom-AI-Agent-full")
    }
    archiveClassifier.set("")
    // ... rest unchanged
}
```

---

### `mcp/McpToolCatalog.kt` (modified — add `nativeTool` field + `available()`)

**Analog:** `McpToolCatalog.kt` itself — `McpToolDescriptor` data class (lines 3-11), `all()` / `defaults()` / `unsafeToolIds()` (lines 418-429)

**Existing data class** (lines 3-11):
```kotlin
data class McpToolDescriptor(
    val id: String,
    val title: String,
    val description: String,
    val category: String,
    val defaultEnabled: Boolean,
    val proOnly: Boolean = false,
    val unsafeOnly: Boolean = false,
)
```

**Add `nativeTool` field with default `false`** (after `unsafeOnly`):
```kotlin
    val nativeTool: Boolean = false,   // true = extension-native; stays in store build
```

**Existing `all()` functions** (lines 418-428):
```kotlin
fun all(): List<McpToolDescriptor> = tools

fun defaults(): Map<String, Boolean> = tools.associate { it.id to it.defaultEnabled }

fun unsafeToolIds(): Set<String> = tools.filter { it.unsafeOnly }.map { it.id }.toSet()

fun mergeWithDefaults(overrides: Map<String, Boolean>): Map<String, Boolean> { ... }
```

**Add `available()` after `all()`** — testable overload matches RESEARCH.md Q4:
```kotlin
fun available(storeBuild: Boolean = BuildFlags.STORE_BUILD): List<McpToolDescriptor> =
    if (storeBuild) tools.filter { it.nativeTool } else tools
```

**Mark existing native tools in the descriptor list** — `status` (line 16-22) and `issue_create` (lines 409-415) need `nativeTool = true`. All 57 generic wrappers stay `nativeTool = false` (default).

---

### `mcp/tools/McpToolHandlers.kt` (modified — add `native` list + route through `available()`)

**Analog:** `McpToolHandlers.kt` itself — `McpToolRegistrations` lists (lines 10-101) and `registerToolHandler` (lines 103-164)

**Existing group lists pattern** (lines 10-101):
```kotlin
internal object McpToolRegistrations {
    val utility = listOf("status", "url_encode", ...)
    val issue = listOf("issue_create")
    // ... other groups

    fun allIds(): Set<String> = (utility + history + siteMap + request + scanner + config + editor + collaborator + issue).toSet()
}
```

**Add `native` list and include in `allIds()`**:
```kotlin
    val native = listOf(
        "ai_analyze",
        "ai_passive_scan",
        "ai_findings_recent",
        "redact_preview",
        "ai_audit_query",
        "ai_backends_list",
    )

    fun allIds(): Set<String> = (utility + history + siteMap + request + scanner + config + editor + collaborator + issue + native).toSet()
```

**`registerToolHandler` already reads from `McpToolCatalog.all()` at line 107** — no change needed there. The store-build filtering is done in `McpTools.kt` `registerTools()` by calling `McpToolCatalog.available()` instead of iterating `McpToolRegistrations.allIds()` directly.

**Existing `registerToolHandler` wrapper pattern** (lines 103-164) — used verbatim by all new native tools; no per-tool audit/limiter code needed:
```kotlin
internal fun Server.registerToolHandler(toolId: String, context: McpToolContext) {
    val descriptor = McpToolCatalog.all().firstOrNull { it.id == toolId } ?: return
    if (descriptor.proOnly && context.edition != burp.api.montoya.core.BurpSuiteEdition.PROFESSIONAL) {
        return
    }
    addTool(
        name = descriptor.id,
        description = descriptor.description,
        inputSchema = McpToolExecutor.inputSchema(descriptor.id, context),
        handler = { request ->
            val argsJson = request.arguments.toString().takeIf { it != "null" }
            val startMs = System.currentTimeMillis()
            val result = McpToolExecutor.executeToolResult(descriptor.id, argsJson, context)
            val durationMs = System.currentTimeMillis() - startMs
            // ... audit logging already done here (lines 121-162)
            result
        },
    )
}
```

---

### `mcp/tools/McpTools.kt` (modified — `registerTools()` filter + new `when` branches)

**Analog:** `McpTools.kt` — `registerTools()` (lines 51-64), `executeToolResult()` `when` block (lines 1328-2067), `inputSchema()` (lines 2176-2248)

**Existing `registerTools()` dispatch** (lines 51-64):
```kotlin
fun Server.registerTools(api: MontoyaApi, context: McpToolContext) {
    registerUtilityTools(context)
    registerHistoryTools(context)
    registerSiteMapTools(context)
    registerRequestTools(context)
    registerScannerTools(context)
    registerConfigTools(context)
    registerEditorTools(context)
    registerCollaboratorTools(context)
    registerIssueTools(context)
}
```

**Change:** Add `registerAiTools(context)` call here. For store-build gating, `registerAiTools` (and all other `register*Tools`) must iterate `McpToolCatalog.available()` instead of unconditionally calling `registerToolHandler` for every ID in the group list. Simplest approach: change each `XxxTools.kt` file from `McpToolRegistrations.xxx.forEach { ... }` to `McpToolCatalog.available().filter { it.id in McpToolRegistrations.xxx }.forEach { ... }`. Alternatively, keep the current approach and gate inside `registerToolHandler` using `McpToolCatalog.available()` — but the simplest path is to filter in `registerAiTools` itself.

**Closest existing handler patterns — `status` (no args) and `issue_create` (with decode)** (lines 1328-1335, 2061-2063):
```kotlin
"status" -> {
    val version = api.burpSuite().version()
    buildString {
        appendLine("extension=burp-ai-agent")
        appendLine("burp_version=${version.name()}")
        appendLine("burp_edition=${version.edition().name}")
    }.trim()
}

"issue_create" -> {
    val input = decode<CreateAuditIssue>(normalizedArgs)
    executeIssueCreate(input, api, context)
}
```

**`decode<T>()` helper** (lines 2111-2122) — use for all new tools that take input:
```kotlin
private inline fun <reified T : Any> decode(raw: String?): T {
    val jsonText = raw?.trim().orEmpty().ifBlank { "{}" }
    val element = decodeJson.parseToJsonElement(jsonText)
    return decodeJson.decodeFromJsonElement(element)
}
```

**`context.redactIfNeeded(output)` applied automatically** (line 2067) — every `when` branch's returned `String` passes through it. Do NOT call it inside the branch.

**`runTool` wrapper applied automatically** (lines 1325-2068) — toggle check, unsafe check, limiter acquire/release, error handling, output limit all done automatically. Inside `runTool { ... }` only return the raw `String`.

**AI gate pattern to use in each AI-calling branch** — based on `AgentSupervisor.kt:119-124`:
```kotlin
"ai_analyze" -> {
    val input = decode<AiAnalyzeInput>(normalizedArgs)
    val supervisor = context.supervisor
        ?: return@runTool "AI tools not available: supervisor not initialized."
    if (!supervisor.isAiEnabled()) {
        return@runTool "AI features unavailable: check that your Burp edition supports AI " +
            "and the 'Use AI' toggle is enabled. Non-AI backends remain usable via the chat panel."
    }
    // ... blocking AI call
}
```

**Blocking `supervisor.send()` pattern** — from `PassiveAiScanner.kt:891-928`:
```kotlin
val responseBuffer = StringBuilder()
val completionLatch = CountDownLatch(1)
val errorRef = AtomicReference<String?>(null)

supervisor.send(
    text = input.text,
    history = emptyList(),
    contextJson = null,
    privacyMode = context.privacyMode,
    determinismMode = context.determinismMode,
    onChunk = { chunk -> responseBuffer.append(chunk) },
    onComplete = { err ->
        errorRef.set(err?.message)
        completionLatch.countDown()
    },
    jsonMode = input.jsonMode,
    maxOutputTokens = input.maxOutputTokens,
)

val completed = completionLatch.await(120_000L, TimeUnit.MILLISECONDS)
if (!completed) return@runTool "AI request timed out after 120 seconds."
val error = errorRef.get()
if (error != null) return@runTool "AI error: $error"
responseBuffer.toString().trim()
```

**`inputSchema()` additions** (lines 2176-2248) — add one `when` branch per new tool:
```kotlin
"ai_analyze" -> AiAnalyzeInput::class.asInputSchema()
"ai_passive_scan" -> AiPassiveScanInput::class.asInputSchema()
"ai_findings_recent" -> AiFindingsRecentInput::class.asInputSchema()
"redact_preview" -> RedactPreviewInput::class.asInputSchema()
"ai_audit_query" -> AiAuditQueryInput::class.asInputSchema()
"ai_backends_list",
"ai_active_scan" -> Tool.Input()   // no-arg tools
```

---

### `mcp/McpToolContext.kt` (modified — add nullable AI tool dependencies)

**Analog:** `McpToolContext.kt` line 32 — `aiRequestLogger: AiRequestLogger? = null`

**Existing nullable field pattern** (line 32):
```kotlin
val aiRequestLogger: AiRequestLogger? = null,
```

**Add three new nullable fields after `aiRequestLogger`** using the identical pattern:
```kotlin
val supervisor: com.six2dez.burp.aiagent.supervisor.AgentSupervisor? = null,
val passiveScanner: com.six2dez.burp.aiagent.scanner.PassiveAiScanner? = null,
val backendRegistry: com.six2dez.burp.aiagent.backends.BackendRegistry? = null,
```

All callers that construct `McpToolContext` without these fields use named-argument syntax and will not require changes (Kotlin defaults).

---

### `mcp/McpRuntimeContextFactory.kt` (modified — populate new context fields)

**Analog:** `McpRuntimeContextFactory.kt` lines 14-48 (current `create()` implementation)

**Existing population pattern** (lines 25-47):
```kotlin
return McpToolContext(
    api = api,
    privacyMode = privacyMode,
    ...
    aiRequestLogger = aiRequestLogger,
    scopeOnly = settings.scopeOnly,
)
```

**Class currently holds** `val api: MontoyaApi` and `var aiRequestLogger: AiRequestLogger?` (lines 10-12). The new fields must be injected the same way:
```kotlin
class McpRuntimeContextFactory(
    private val api: MontoyaApi,
) {
    var aiRequestLogger: AiRequestLogger? = null
    var supervisor: AgentSupervisor? = null         // add
    var passiveScanner: PassiveAiScanner? = null    // add
    var backendRegistry: BackendRegistry? = null    // add

    fun create(...): McpToolContext {
        return McpToolContext(
            ...
            aiRequestLogger = aiRequestLogger,
            supervisor = supervisor,                // add
            passiveScanner = passiveScanner,        // add
            backendRegistry = backendRegistry,      // add
            scopeOnly = settings.scopeOnly,
        )
    }
}
```

These fields are set in `McpSupervisor` (which constructs `McpRuntimeContextFactory`). Trace `McpSupervisor` init in `App.kt` lines 41-43 — `supervisor`, `passiveAiScanner`, and `backendRegistry` are all `lateinit var` on `App` object (lines 35-51), available for assignment into `McpRuntimeContextFactory` after `initialize()`.

---

### `mcp/tools/AiTools.kt` (NEW — `registerAiTools()` + tool catalog descriptors)

**Analog:** `IssueTools.kt` (registration pattern) + `McpTools.kt` executeToolResult `when` branches

**Registration file pattern** (from `IssueTools.kt`):
```kotlin
package com.six2dez.burp.aiagent.mcp.tools

import com.six2dez.burp.aiagent.mcp.McpToolContext
import io.modelcontextprotocol.kotlin.sdk.server.Server

internal fun Server.registerAiTools(context: McpToolContext) {
    McpToolRegistrations.native.forEach { registerToolHandler(it, context) }
}
```

**Input schemas for new tools** — define as `@Serializable data class` in the same file as the handler or in a dedicated `AiToolsSchemas.kt`:
```kotlin
@Serializable
data class AiAnalyzeInput(
    val text: String,
    val jsonMode: Boolean = false,
    val maxOutputTokens: Int? = null,
)

@Serializable
data class AiPassiveScanInput(
    val proxyHistoryIndices: List<Int> = emptyList(),
    val siteMapUrl: String? = null,
    val maxRequests: Int = 10,
)

@Serializable
data class AiFindingsRecentInput(
    val n: Int = 10,
)

@Serializable
data class RedactPreviewInput(
    val text: String,
    val mode: String = "STRICT",  // "STRICT" | "BALANCED" | "OFF"
)

@Serializable
data class AiAuditQueryInput(
    val n: Int = 20,
)
```

**`redact_preview` handler pattern** — from `McpToolContext.redactIfNeeded()` (lines 47-51):
```kotlin
"redact_preview" -> {
    val input = decode<RedactPreviewInput>(normalizedArgs)
    val policy = com.six2dez.burp.aiagent.redact.RedactionPolicy.fromMode(
        com.six2dez.burp.aiagent.redact.PrivacyMode.valueOf(input.mode.uppercase())
    )
    com.six2dez.burp.aiagent.redact.Redaction.apply(input.text, policy, stableHostSalt = context.hostSalt)
}
```
Note: `redact_preview` does NOT need the `isAiEnabled()` gate (no AI call).

**`ai_findings_recent` handler pattern** — from `PassiveAiScanner.getLastFindings()` (line 500-504):
```kotlin
"ai_findings_recent" -> {
    val input = decode<AiFindingsRecentInput>(normalizedArgs)
    val scanner = context.passiveScanner ?: return@runTool "Passive scanner not available."
    val findings = scanner.getLastFindings(input.n)
    if (findings.isEmpty()) return@runTool "No findings recorded yet."
    findings.joinToString("\n\n") { f ->
        "[${f.timestamp}] ${f.title} (${f.severity}) - ${f.url}: ${f.detail.take(500)}"
    }
}
```

**`ai_backends_list` handler pattern** — from `BackendRegistry.listBackendIds()` (line 89) + `AgentSupervisor.status()` (line 578):
```kotlin
"ai_backends_list" -> {
    val registry = context.backendRegistry
    val supervisor = context.supervisor
    if (registry == null || supervisor == null) return@runTool "Registry not available."
    val settings = context.api.burpSuite().version()   // settings not directly in context; need AgentSettings
    // Simplest approach: call listAllBackendIds() which needs no settings:
    val ids = registry.listAllBackendIds()
    val status = supervisor.status()
    buildString {
        appendLine("Available backends: ${ids.joinToString(", ")}")
        appendLine("Current backend: ${status.backendId ?: "none"}")
        appendLine("State: ${status.state}")
    }.trim()
}
```

---

### `scanner/AiPassiveScanCheck.kt` (NEW — implements `PassiveScanCheck`)

**Analog:** `AiScanCheck.kt` lines 1-105 (implements `ScanCheck`; same structure, different interface)

**Imports pattern from `AiScanCheck.kt`** (lines 1-13):
```kotlin
package com.six2dez.burp.aiagent.scanner

import burp.api.montoya.MontoyaApi
import burp.api.montoya.http.message.HttpRequestResponse
import burp.api.montoya.scanner.AuditResult
import burp.api.montoya.scanner.ConsolidationAction
import burp.api.montoya.scanner.audit.issues.AuditIssue
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence
import com.six2dez.burp.aiagent.config.AgentSettings
import com.six2dez.burp.aiagent.util.IssueUtils
```

**New imports required (not in AiScanCheck.kt)**:
```kotlin
import burp.api.montoya.scanner.scancheck.PassiveScanCheck   // NEW interface
import burp.api.montoya.scanner.scancheck.ScanCheckType       // for registration call
```

**Class skeleton** (adapt from `AiScanCheck.kt:21-24`):
```kotlin
class AiPassiveScanCheck(
    private val api: MontoyaApi,
    private val passiveScanner: PassiveAiScanner,
    private val getSettings: () -> AgentSettings,
) : PassiveScanCheck {
    override fun checkName(): String = "AI Passive Security Analysis"

    override fun doCheck(httpRequestResponse: HttpRequestResponse): AuditResult {
        val settings = getSettings()

        // Scope check (same as AiScanCheck.activeAudit lines 44-46)
        if (settings.passiveAiScopeOnly &&
            !api.scope().isInScope(httpRequestResponse.request().url())
        ) {
            return AuditResult.auditResult(emptyList())
        }

        // Synchronous local heuristics (from PassiveAiScanner.kt:620-632 pattern)
        val request = httpRequestResponse.request()
        val response = httpRequestResponse.response()
        // ... extract bodies, call runLocalChecks via passiveScanner (or inline)
        // ... convert LocalFinding list to AuditIssue list and return synchronously

        // Enqueue async AI analysis (executor.submit pattern from PassiveAiScanner.kt:348-350)
        passiveScanner.enqueueForScanCheck(httpRequestResponse)

        return AuditResult.auditResult(localIssues)  // only local findings returned synchronously
    }

    override fun consolidateIssues(
        newIssue: AuditIssue,
        existingIssue: AuditIssue,
    ): ConsolidationAction {
        // Copy from AiScanCheck.kt:94-105 verbatim
        val sameName = IssueUtils.canonicalIssueName(newIssue.name()) == IssueUtils.canonicalIssueName(existingIssue.name())
        val sameUrl = IssueUtils.normalizeUrl(newIssue.baseUrl()) == IssueUtils.normalizeUrl(existingIssue.baseUrl())
        if (sameName && sameUrl) return ConsolidationAction.KEEP_EXISTING
        return ConsolidationAction.KEEP_BOTH
    }
}
```

**`AuditResult.auditResult()` factory** — from `AiScanCheck.kt:79,88`:
```kotlin
return AuditResult.auditResult(issues)
return AuditResult.auditResult(emptyList())
```

**`api.siteMap().add(issue)` async findings pattern** — from `PassiveAiScanner.kt:1765`:
```kotlin
api.siteMap().add(issue)
```
Use this in the async callback after AI completes, not in `doCheck()`.

**Note:** `runLocalChecks()` is private in `PassiveAiScanner`. Two options: (a) make it `internal`, (b) add a public `doLocalChecks(req, res): List<LocalFinding>` wrapper in `PassiveAiScanner`. The planner should choose option (b) — add a thin public method to `PassiveAiScanner` that calls the private `runLocalChecks()`, and have `AiPassiveScanCheck.doCheck()` call it. `LocalFinding` is also private; similarly expose via a public type alias or data class.

---

### `scanner/PassiveAiScanner.kt` (modified — remove ProxyResponseHandler; add `enqueueForScanCheck()`)

**Analog:** `PassiveAiScanner.kt` — `manualScan()` (lines 543-586) and `analyzeManually()` (lines 588-594)

**`ProxyResponseHandler` to remove** (lines 298-357, registered at 362):
```kotlin
private val handler = object : ProxyResponseHandler { ... }
// and at line 362:
fun setEnabled(on: Boolean) {
    if (on && registered.compareAndSet(false, true)) {
        api.proxy().registerResponseHandler(handler)  // REMOVE this call
    }
}
```

**New public `enqueueForScanCheck()` method** — mirroring `manualScan()` (lines 543-586):
```kotlin
fun enqueueForScanCheck(requestResponse: HttpRequestResponse) {
    // Same guard as the ProxyResponseHandler had: scope, size, MIME type
    if (!enabled.get()) return
    if (supervisor.isBlockedByBurpAiGate()) return
    executor.submit {
        analyzeManually(requestResponse)
    }
}
```

**`runLocalChecks()` exposure** — add a public wrapper:
```kotlin
fun localChecks(
    request: burp.api.montoya.http.message.requests.HttpRequest,
    response: burp.api.montoya.http.message.responses.HttpResponse?,
): List<LocalFinding> = runLocalChecks(
    request, response,
    request.bodyToString().take(REQUEST_BODY_LOCAL_CHECK_MAX_CHARS),
    response?.bodyToString().orEmpty().take(RESPONSE_BODY_LOCAL_CHECK_MAX_CHARS),
)
```

Or make `LocalFinding` and `runLocalChecks()` `internal` (same package, both are in `scanner` package).

---

### `App.kt` (modified — register `AiPassiveScanCheck` via `registerPassiveScanCheck`)

**Analog:** `App.kt` lines 151-160 (existing ScanCheck try/catch registration block)

**Existing try/catch pattern** (lines 151-160):
```kotlin
try {
    val aiScanCheck = AiScanCheck(api) { settingsRepo.load() }
    api.scanner().registerScanCheck(aiScanCheck)
    api.logging().logToOutput("AI ScanCheck registered with Burp Scanner (Pro feature)")
} catch (e: Exception) {
    // Expected to fail on Community edition
    api.logging().logToOutput("AI ScanCheck not registered (Burp Pro required): ${e.message}")
}
```

**New block to add** (directly after, same structure):
```kotlin
try {
    val aiPassiveScanCheck = AiPassiveScanCheck(api, passiveAiScanner) { settingsRepo.load() }
    api.scanner().registerPassiveScanCheck(aiPassiveScanCheck, ScanCheckType.PER_REQUEST)
    api.logging().logToOutput("AI PassiveScanCheck registered with Burp Scanner (Pro feature)")
} catch (e: Exception) {
    // Expected to fail on Community edition
    api.logging().logToOutput("AI PassiveScanCheck not registered (Burp Pro required): ${e.message}")
}
```

**Import to add** (following `AiScanCheck.kt` import pattern):
```kotlin
import burp.api.montoya.scanner.scancheck.ScanCheckType
```

---

### `ui/SettingsPanel.kt` (modified — swap `all()` to `available()` in tool list loop)

**Analog:** `SettingsPanel.kt` lines 2194, 2234-2235, 2331-2332

**Existing `all()` call sites in the MCP tools UI section** (lines 2194, 2234-2235):
```kotlin
McpToolCatalog.all().groupBy { it.category }.forEach { (category, tools) -> ... }

McpToolCatalog
    .all()
    .filter { it.unsafeOnly }
```

**Change:** Replace `all()` with `available()` in the tool-list rendering loop (line 2194). The unsafe allowlist loop (line 2234) can stay as `all()` (the full unsafe tool list should always be shown for management purposes) or also switch to `available()` depending on reviewer expectations. The safe default for the store build: both switch to `available()`.

---

## Shared Patterns

### Authentication / AI Gate
**Source:** `AgentSupervisor.kt` lines 119-141
**Apply to:** All new MCP tool handlers that invoke AI (`ai_analyze`, `ai_passive_scan`); do NOT apply to `ai_findings_recent`, `redact_preview`, `ai_audit_query`, `ai_backends_list`

```kotlin
// Community-safe isEnabled() wrapper (AgentSupervisor.kt:119-124)
fun isAiEnabled(): Boolean =
    try {
        api.ai().isEnabled()
    } catch (_: Exception) {
        false
    }

// Gate in MCP tool handler — narrow interpretation:
val supervisor = context.supervisor
    ?: return@runTool "AI tools not initialized."
if (!supervisor.isAiEnabled()) {
    return@runTool "AI features unavailable: check that your Burp edition supports AI and " +
        "the 'Use AI' toggle is enabled. Non-AI backends remain usable via the chat panel."
}
// Non-burp-ai backends: do NOT gate startOrAttach here.
// requiresBurpAiAndDisabled() already correctly gates only burp-ai (AgentSupervisor.kt:131).
```

### Error Handling in MCP Tools
**Source:** `McpTool.kt` lines 113-218 (`runTool` function)
**Apply to:** All new MCP tool handlers — automatic via `runTool`

```kotlin
// runTool handles: toggle-disabled, unsafe-blocked, concurrency-limited, SerializationException,
// general Exception, output-truncation. Inside the lambda only throw or return@runTool a String.
// return@runTool "error message" is preferred over throw for user-visible errors.
```

### Tool Registration (audit + limiter wrapper)
**Source:** `McpToolHandlers.kt` lines 103-164 (`registerToolHandler`)
**Apply to:** All new native tools — automatic via `McpToolRegistrations.native.forEach { registerToolHandler(it, context) }`

No per-tool audit/limiter code needed. Every tool call is already logged with toolId, args SHA, result SHA, duration, and policy decision.

### Blocking AI Send
**Source:** `PassiveAiScanner.kt` lines 891-928
**Apply to:** `ai_analyze` and `ai_passive_scan` MCP tool handlers

```kotlin
val responseBuffer = StringBuilder()
val completionLatch = CountDownLatch(1)
val errorRef = AtomicReference<String?>(null)
supervisor.send(
    text = prompt,
    history = emptyList(),
    contextJson = null,
    privacyMode = context.privacyMode,
    determinismMode = context.determinismMode,
    onChunk = { chunk -> responseBuffer.append(chunk) },
    onComplete = { err -> errorRef.set(err?.message); completionLatch.countDown() },
    jsonMode = true,
    maxOutputTokens = null,
)
val completed = completionLatch.await(120_000L, TimeUnit.MILLISECONDS)
if (!completed) return@runTool "AI request timed out after 120 seconds."
errorRef.get()?.let { return@runTool "AI error: $it" }
responseBuffer.toString().trim()
```

### Passive Scan: Async Site-Map Add
**Source:** `PassiveAiScanner.kt` line 1765
**Apply to:** `AiPassiveScanCheck.doCheck()` async path; `enqueueForScanCheck()` callback

```kotlin
api.siteMap().add(issue)   // called from background thread after AI completes; do NOT call from doCheck()
```

### Passive Scan: Consolidate Issues (dedup)
**Source:** `AiScanCheck.kt` lines 94-105
**Apply to:** `AiPassiveScanCheck.consolidateIssues()` — copy verbatim

```kotlin
override fun consolidateIssues(newIssue: AuditIssue, existingIssue: AuditIssue): ConsolidationAction {
    val sameName = IssueUtils.canonicalIssueName(newIssue.name()) == IssueUtils.canonicalIssueName(existingIssue.name())
    val sameUrl = IssueUtils.normalizeUrl(newIssue.baseUrl()) == IssueUtils.normalizeUrl(existingIssue.baseUrl())
    if (sameName && sameUrl) return ConsolidationAction.KEEP_EXISTING
    return ConsolidationAction.KEEP_BOTH
}
```

### Redaction
**Source:** `McpToolContext.kt` lines 47-51 (`redactIfNeeded`)
**Apply to:** All MCP tools — automatic via `context.redactIfNeeded(output)` at `McpTools.kt:2067`

No per-tool redaction calls needed.

### Test Mock Construction
**Source:** `BurpAiGateScopingTest.kt` lines 24-26 + `McpToolParityTest.kt` lines 43-58
**Apply to:** All new test files

```kotlin
// Deep stub for MontoyaApi (covers all chained calls like api.ai().isEnabled()):
val api = mock<MontoyaApi>(defaultAnswer = Answers.RETURNS_DEEP_STUBS)
whenever(api.ai().isEnabled()).thenReturn(false)

// McpToolContext construction for tool tests:
McpToolContext(
    api = api,
    privacyMode = PrivacyMode.OFF,
    determinismMode = false,
    hostSalt = "test",
    toolToggles = McpToolCatalog.all().associate { it.id to true },
    unsafeEnabled = false,
    unsafeTools = McpToolCatalog.unsafeToolIds(),
    enabledUnsafeTools = emptySet(),
    limiter = McpRequestLimiter(4),
    edition = BurpSuiteEdition.PROFESSIONAL,
    maxBodyBytes = 1024,
    // new fields:
    supervisor = mockSupervisor,
    passiveScanner = mockScanner,
    backendRegistry = null,
)
```

---

## Test Pattern Assignments

### `mcp/McpToolCatalogStoreBuildTest.kt` (NEW)

**Analog:** `McpToolParityTest.kt` — catalog-only assertions with no MCP API or mock required

**Imports + test structure** (from `McpToolParityTest.kt` lines 1-11):
```kotlin
package com.six2dez.burp.aiagent.mcp.tools

import com.six2dez.burp.aiagent.mcp.McpToolCatalog
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class McpToolCatalogStoreBuildTest {
    @Test
    fun available_returnsOnlyNativeToolsWhenStoreBuildTrue() {
        val result = McpToolCatalog.available(storeBuild = true)
        assertTrue(result.all { it.nativeTool }, "Store build must return only native tools")
        assertTrue(result.isNotEmpty(), "At least one native tool must exist")
    }

    @Test
    fun available_returnsAllToolsWhenStoreBuildFalse() {
        val all = McpToolCatalog.all()
        val result = McpToolCatalog.available(storeBuild = false)
        assertEquals(all.size, result.size, "Full build returns all tools")
    }

    @Test
    fun available_nativeSubsetIsSubsetOfAll() {
        val allIds = McpToolCatalog.all().map { it.id }.toSet()
        val nativeIds = McpToolCatalog.available(storeBuild = true).map { it.id }.toSet()
        assertTrue(allIds.containsAll(nativeIds), "Native tools must be a subset of all tools")
    }
}
```

### `mcp/AiGateMcpToolTest.kt` (NEW)

**Analog:** `BurpAiGateScopingTest.kt` (mock MontoyaApi with `RETURNS_DEEP_STUBS`) + `McpToolParityTest.kt` (McpToolContext construction)

**Key test assertions:**
```kotlin
class AiGateMcpToolTest {
    @Test
    fun aiAnalyze_returnsErrorWhenIsEnabledFalse() {
        val api = mock<MontoyaApi>(defaultAnswer = Answers.RETURNS_DEEP_STUBS)
        whenever(api.ai().isEnabled()).thenReturn(false)
        whenever(api.burpSuite().version().edition()).thenReturn(BurpSuiteEdition.PROFESSIONAL)
        val supervisor = mock<AgentSupervisor>()
        whenever(supervisor.isAiEnabled()).thenReturn(false)

        val context = buildContext(api, supervisor)
        val result = McpToolExecutor.executeTool("ai_analyze", """{"text":"test"}""", context)

        assertTrue(result.contains("unavailable"), "Gate must return unavailable message, got: $result")
    }

    @Test
    fun aiAnalyze_doesNotGateNonAiTool() {
        // redact_preview must work even when isEnabled()=false
        val api = mock<MontoyaApi>(defaultAnswer = Answers.RETURNS_DEEP_STUBS)
        whenever(api.ai().isEnabled()).thenReturn(false)
        whenever(api.burpSuite().version().edition()).thenReturn(BurpSuiteEdition.PROFESSIONAL)

        val context = buildContext(api, supervisor = null)
        val result = McpToolExecutor.executeTool("redact_preview", """{"text":"secret@host.com","mode":"STRICT"}""", context)

        assertFalse(result.contains("unavailable"), "redact_preview must not be gated: $result")
    }
}
```

### `scanner/AiPassiveScanCheckTest.kt` (NEW)

**Analog:** `PassiveAiScannerConfidenceTest.kt` (reflection access for private methods) + `BurpAiGateScopingTest.kt` (mock api)

**Key test assertions:**
```kotlin
class AiPassiveScanCheckTest {
    @Test
    fun doCheck_returnsLocalFindingsSynchronously() {
        val api = mock<MontoyaApi>()
        val passiveScanner = mock<PassiveAiScanner>()
        val reqResp = mock<HttpRequestResponse>(defaultAnswer = Answers.RETURNS_DEEP_STUBS)
        // stub request with smuggling indicators so runLocalChecks returns findings
        // ...

        val check = AiPassiveScanCheck(api, passiveScanner) { baselineSettings() }
        val result = check.doCheck(reqResp)

        // doCheck must return immediately (test completes in < 500ms)
        assertNotNull(result)
    }

    @Test
    fun doCheck_enqueuesAsyncAnalysisOnScanner() {
        val passiveScanner = mock<PassiveAiScanner>()
        val check = AiPassiveScanCheck(mock<MontoyaApi>(), passiveScanner) { baselineSettings() }
        check.doCheck(mock<HttpRequestResponse>(defaultAnswer = Answers.RETURNS_DEEP_STUBS))

        verify(passiveScanner).enqueueForScanCheck(any())
    }
}
```

---

## No Analog Found

| File | Role | Data Flow | Reason |
|---|---|---|---|
| `build/generated/.../BuildFlags.kt` | config/constant | N/A | Generated file; no in-project generated-source precedent. Use RESEARCH.md Pattern 1 (hand-rolled Gradle task). The generate task itself is new in `build.gradle.kts`. |

---

## Metadata

**Analog search scope:** `src/main/kotlin/`, `src/test/kotlin/`, `build.gradle.kts`
**Files scanned:** 18 source files + 4 test files
**Pattern extraction date:** 2026-05-28

**Key correctness notes for planner:**
1. `AiPassiveScanCheck` implements `PassiveScanCheck` (package `burp.api.montoya.scanner.scancheck`) — NOT the deprecated `ScanCheck` (`burp.api.montoya.scanner`). Method is `doCheck()`, not `passiveAudit()`.
2. `available(storeBuild: Boolean = BuildFlags.STORE_BUILD)` — the default-argument overload makes the function testable without mocking a compile-time constant.
3. `McpToolParityTest.registeredToolIds_matchCatalog()` (line 18) must pass: update both `McpToolCatalog` (add descriptors) and `McpToolRegistrations.native` (add IDs) in the same commit.
4. `CountDownLatch` blocking for `ai_analyze` is the established pattern — already used 3x in `PassiveAiScanner.kt` (lines 891, 1539, 1625). Use 120-second timeout.
5. `BuildFlags.kt` must land in `build/generated/buildflags/` not `src/generated/` — ktlint excludes `**/build/**` (line 128) but not `src/generated/`.
