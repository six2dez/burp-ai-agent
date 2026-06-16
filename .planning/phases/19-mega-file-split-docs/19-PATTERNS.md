# Phase 19: Mega-File Split + Docs - Pattern Map

**Mapped:** 2026-06-16
**Files analyzed:** 11 (8 new Kotlin files, 2 new docs pages, 1 DECISIONS.md append)
**Analogs found:** 11 / 11

---

## File Classification

| New/Modified File | Role | Data Flow | Closest Analog | Match Quality |
|---|---|---|---|---|
| `mcp/tools/McpToolModels.kt` | model | transform | `context/ContextModels.kt` | role-match |
| `mcp/tools/McpToolHelpers.kt` | utility | transform | `scanner/ScannerUtils.kt` + `util/BudgetGuard.kt` | role-match |
| `mcp/tools/McpToolExecutorImpl.kt` | service | request-response | `mcp/tools/McpTools.kt` (self, extracted object) | exact |
| `ui/SettingsPanelScannerTabs.kt` | component | request-response | `ui/panels/PassiveScanConfigPanel.kt` | role-match |
| `ui/SettingsPanelMcpTabs.kt` | component | request-response | `ui/panels/McpConfigPanel.kt` | role-match |
| `scanner/PassiveAiScannerModels.kt` | model | transform | `scanner/ActiveScanModels.kt` + `context/ContextModels.kt` | exact |
| `scanner/PassiveAiScannerHeuristics.kt` | utility | transform | `redact/SecretShapes.kt` + `redact/Entropy.kt` | exact |
| `scanner/PassiveAiScannerParsing.kt` | utility | transform | `redact/SecretShapes.kt` + `util/BudgetGuard.kt` | exact |
| `scanner/PassiveAiScannerPrompts.kt` | utility | transform | `util/BudgetGuard.kt` | role-match |
| `docs/anthropic-backend.md` | documentation | — | `docs/mcp-hardening.md` + `docs/backend-troubleshooting.md` | exact |
| `docs/external-mcp-servers.md` | documentation | — | `docs/mcp-hardening.md` | exact |
| `DECISIONS.md` (append) | documentation | — | `DECISIONS.md` existing H2 ADR entries | exact |

---

## Pattern Assignments

### `mcp/tools/McpToolModels.kt` (model, transform)

**Full path:** `src/main/kotlin/com/six2dez/burp/aiagent/mcp/tools/McpToolModels.kt`

**Analog:** `src/main/kotlin/com/six2dez/burp/aiagent/context/ContextModels.kt`

**What moves here:** All `@Serializable data class` types from `McpTools.kt` lines 2533–2926 plus the `ToolSpec` data class at line 1263. Also includes the `Paginated` interface and `HttpServiceParams` interface if they are currently in this block. Approximately 420 lines.

**Package declaration pattern** (mirrors `McpTools.kt` line 1, same package):
```kotlin
package com.six2dez.burp.aiagent.mcp.tools

import kotlinx.serialization.Serializable
```

**Model type pattern** (`McpTools.kt` lines 2533–2578 — concrete excerpt):
```kotlin
@Serializable
data class SendHttp1Request(
    val content: String,
    override val targetHostname: String,
    override val targetPort: Int,
    override val usesHttps: Boolean,
) : HttpServiceParams

@Serializable
data class SendHttp2Request(
    val pseudoHeaders: Map<String, String>,
    val headers: Map<String, String>,
    val requestBody: String,
    override val targetHostname: String,
    override val targetPort: Int,
    override val usesHttps: Boolean,
) : HttpServiceParams
```

**`ToolSpec` type** (`McpTools.kt` lines 1263–1270):
```kotlin
data class ToolSpec(
    val id: String,
    val description: String,
    val enabled: Boolean,
    val unsafeOnly: Boolean,
    val proOnly: Boolean,
    val argsSchema: String?,
)
```

**Visibility hazards:** None — all types are package-internal (`data class` with no `private` modifier). The `@Serializable` annotation requires `kotlinx-serialization` import. No companion objects. No instance state.

**Key rule:** No `private` or `internal` qualifier on the data classes themselves; they must remain accessible from `McpToolExecutor` and from `McpTools.kt`'s `registerToolsLegacy`.

---

### `mcp/tools/McpToolHelpers.kt` (utility, transform)

**Full path:** `src/main/kotlin/com/six2dez/burp/aiagent/mcp/tools/McpToolHelpers.kt`

**Analog:** `src/main/kotlin/com/six2dez/burp/aiagent/scanner/ScannerUtils.kt` (for top-level `object` with constants) and `src/main/kotlin/com/six2dez/burp/aiagent/util/BudgetGuard.kt` (for AWT-free top-level pure functions)

**What moves here:** The 12–19 private top-level helper functions from `McpTools.kt` lines 884–1262: `executeIssueCreate`, `findProxyHistoryMatch`, `withAiIssuePrefix`, `hasEquivalentIssue`, `normalizeHttpRequest`, `truncateIfNeeded`, `ensureAllowedProxyHistoryCount`, `orderedProxyHistory`, `decodeJwt`, `normalizeHashAlgorithm`, `diffLines`, `countOccurrences`, `parseHighlightColor`, `sanitizeHeaders`, `maybeAnonymizeUrl`, `resolveReportPath`, `applyReplacements`, `resolveAuditConfig`, `getActiveEditor`. Approximately 380 lines.

Also a candidate home for the `private val toolJson = Json { encodeDefaults = true }` declaration (line 53 of `McpTools.kt`) if `McpToolExecutor` needs it — move it here and change visibility to `internal` so both `McpTools.kt` and `McpToolExecutorImpl.kt` can access it without re-importing. Alternatively keep it in `McpTools.kt` as `internal`.

**Package + imports pattern** (same package, same imports as current top of `McpTools.kt`):
```kotlin
package com.six2dez.burp.aiagent.mcp.tools

import burp.api.montoya.MontoyaApi
import com.six2dez.burp.aiagent.mcp.McpToolContext
import com.six2dez.burp.aiagent.redact.PrivacyMode
import com.six2dez.burp.aiagent.redact.Redaction
// ... other imports as needed by the specific functions
```

**Top-level helper function pattern** (`McpTools.kt` lines 884–910 — concrete excerpt):
```kotlin
private fun executeIssueCreate(
    input: CreateAuditIssue,
    api: MontoyaApi,
    context: McpToolContext,
): String {
    val severityEnum =
        try {
            burp.api.montoya.scanner.audit.issues.AuditIssueSeverity
                .valueOf(input.severity.uppercase())
        } catch (_: Exception) {
            return "Invalid severity: ${input.severity}. Use: HIGH, MEDIUM, LOW, INFORMATION"
        }
    // ...
}
```

**Visibility hazards:**
- All these functions are currently `private` (file-private to `McpTools.kt`). Moving them to a new file in the same package means the `private` keyword continues to work correctly (each function is private to ITS own file), BUT `McpToolExecutor` in `McpToolExecutorImpl.kt` calls them. Decision: change `private` to `internal` on these functions — they remain invisible outside the `mcp.tools` package (which is correct) but are accessible from other files in the same package.
- `normalizeHttpRequest` is already `internal` — move as-is.
- `getActiveEditor` is currently non-private (package-internal by default) — move as-is.

---

### `mcp/tools/McpToolExecutorImpl.kt` (service, request-response)

**Full path:** `src/main/kotlin/com/six2dez/burp/aiagent/mcp/tools/McpToolExecutorImpl.kt`

**Analog:** `mcp/tools/McpTools.kt` lines 1272–2533 (self — this is the extraction of the `object McpToolExecutor` block)

**What moves here:** The entire `object McpToolExecutor` body from `McpTools.kt` lines 1272–2533. Approximately 1260 lines. SC1 does not gate the size of this helper file.

**Object declaration pattern** (`McpTools.kt` lines 1272–1319 — concrete excerpt):
```kotlin
object McpToolExecutor {
    private val decodeJson = Json { ignoreUnknownKeys = true }

    // Phase 16 (CAP-02): expected part count for ext:<server>:<tool> tool names.
    private const val EXT_TOOL_NAME_PARTS = 3

    fun describeTools(
        context: McpToolContext,
        includeSchemas: Boolean,
        includeDisabled: Boolean = true,
    ): String {
        val specs =
            McpToolCatalog.all().mapNotNull { desc ->
                // ...
            }
        // ...
    }
}
```

**Imports pattern:** Copy the full import block from `McpTools.kt` lines 1–51 verbatim as the starting point, then prune imports that are only needed by `registerToolsLegacy` (which stays in `McpTools.kt`) and add any imports needed exclusively by the executor.

**Visibility hazards:**
- `object McpToolExecutor` references `toolJson` from `McpTools.kt` line 53. This is `private`. Before extraction, change `toolJson` to `internal` and ensure it is visible from the new file. Alternatively move `toolJson` into `McpToolHelpers.kt` as `internal` and import it from there (same package — no import statement needed).
- The `describeTools` / `executeTool` public methods remain unchanged. No call sites change.

---

### `ui/SettingsPanelScannerTabs.kt` (component, request-response)

**Full path:** `src/main/kotlin/com/six2dez/burp/aiagent/ui/SettingsPanelScannerTabs.kt`

**Analog:** `src/main/kotlin/com/six2dez/burp/aiagent/ui/panels/PassiveScanConfigPanel.kt`

**What moves here:** Scanner-related section builder methods from `SettingsPanel.kt` as `internal` extension functions on `SettingsPanel`. Approximately 450 lines.

Methods: `passiveAiScannerSection()`, `refreshPassiveAiStatus()`, `applyPassiveAiSettings()`, `showPassiveAiFindingsDialog()`, `activeAiScannerSection()`, `refreshActiveAiStatus()`, `applyActiveAiSettings()`, `updateActiveRiskDescription()`, `showActiveAiFindingsDialog()`, `showActiveScanQueueDialog()`, `showScannerTriageDialog()`, `severityRank()`.

**File header pattern** (Kotlin extension functions on a class from another file — same package):
```kotlin
package com.six2dez.burp.aiagent.ui

import com.six2dez.burp.aiagent.ui.design.DesignTokens
import com.six2dez.burp.aiagent.ui.design.addRowFull
import com.six2dez.burp.aiagent.ui.design.formGrid
import com.six2dez.burp.aiagent.ui.panels.PassiveScanConfigPanel
// ... same ui.design.* imports that SettingsPanel.kt already uses
import javax.swing.JComponent
import javax.swing.JPanel
import javax.swing.SwingUtilities
```

**Extension function pattern** (how private section builders become internal extension functions — structural pattern):
```kotlin
// Before (in SettingsPanel.kt):
//   private fun refreshPassiveAiStatus() { ... uses this.passiveAiScanner, this.passiveAiStatusLabel }

// After (in SettingsPanelScannerTabs.kt):
internal fun SettingsPanel.refreshPassiveAiStatus() {
    val status = passiveAiScanner.getStatus()
    val (manualInProgress, manualCompleted, manualTotal) = passiveAiScanner.getManualScanProgress()
    // ... same body as before; `this` is the SettingsPanel receiver
}
```

**Concrete excerpt from current `SettingsPanel.kt` lines 1637–1666 showing the method body to be extracted as an extension:**
```kotlin
private fun refreshPassiveAiStatus() {
    val status = passiveAiScanner.getStatus()
    val (manualInProgress, manualCompleted, manualTotal) = passiveAiScanner.getManualScanProgress()
    val statusText =
        buildString {
            if (manualInProgress) {
                append("Manual scan: $manualCompleted/$manualTotal | ")
            }
            if (status.enabled) {
                val lastTime = if (status.lastAnalysisTime > 0) {
                    val formatter = DateTimeFormatter.ofPattern("HH:mm:ss").withZone(ZoneId.systemDefault())
                    formatter.format(Instant.ofEpochMilli(status.lastAnalysisTime))
                } else { "Never" }
                append("Passive: ON | Analyzed: ${status.requestsAnalyzed} | Issues: ${status.issuesFound} | Last: $lastTime")
            } else {
                append("Passive: OFF")
                if (!manualInProgress) append(" | Total issues: ${status.issuesFound}")
            }
        }
    passiveAiStatusLabel.text = statusText
}
```

**Visibility hazards — CRITICAL:**
- Methods in this file reference `private val` fields of `SettingsPanel` (e.g. `passiveAiScanner`, `passiveAiStatusLabel`, `passiveAiRateSpinner`, `passiveAiScopeOnly`, etc.).
- **Required visibility change:** Change those `private val` declarations in `SettingsPanel.kt` to `internal val`. Kotlin extension functions can only access `internal` or `public` members, not `private` members.
- Scope: only the fields that are referenced from the extracted methods need widening. All fields stay inside the `ui` module — no API surface change, no binary compatibility issue.
- Design imports: `applyAreaStyle`, `applyFieldStyle`, `addRowFull`, etc. are in `com.six2dez.burp.aiagent.ui.design` (a different sub-package). They ARE needed by the extracted file — add explicit imports for them in `SettingsPanelScannerTabs.kt`. They are NOT in the `ui` package itself.

---

### `ui/SettingsPanelMcpTabs.kt` (component, request-response)

**Full path:** `src/main/kotlin/com/six2dez/burp/aiagent/ui/SettingsPanelMcpTabs.kt`

**Analog:** `src/main/kotlin/com/six2dez/burp/aiagent/ui/panels/PassiveScanConfigPanel.kt` (constructor injection style) and `src/main/kotlin/com/six2dez/burp/aiagent/ui/panels/McpConfigPanel.kt` (MCP-specific UI structure)

**What moves here:** MCP and Burp-integration section builder methods from `SettingsPanel.kt` as `internal` extension functions on `SettingsPanel`. Approximately 500 lines.

Methods: `mcpSection()`, `tokenPanel()`, `mcpQuickActions()`, `buildSseUrl()`, `buildCurlCommand()`, `copyToClipboard()`, `buildMcpToolsPanel()`, `updateUnsafeToolStates()`, `collectMcpToolToggles()`, `collectEnabledUnsafeTools()`, `applyUnsafeToolApprovals()`, `availableMcpToolsWithReasons()`, `availableMcpTools()`, `updateMcpTlsState()`, `updateMcpCorsWarning()`, `refreshMcpNotice()`.

**Extension function pattern:** same structure as `SettingsPanelScannerTabs.kt` above — `internal fun SettingsPanel.<methodName>(...)`.

**Visibility hazards:** Same `private` → `internal` field widening as scanner tabs. Fields referenced here include MCP-specific ones: `mcpEnabled`, `mcpToken`, `mcpPort`, `mcpToolToggles` map, `unsafeToolToggles`, etc.

**Assumption A3 from RESEARCH.md:** The `applyAreaStyle`, `applyFieldStyle`, and other `ui.design.*` helpers used in these methods are in the `com.six2dez.burp.aiagent.ui.design` package (NOT in `com.six2dez.burp.aiagent.ui`). Explicit imports for all `ui.design.*` symbols used must be added to this file — they are not in the same package. The existing `SettingsPanel.kt` imports at lines 27–36 show the exact set needed.

---

### `scanner/PassiveAiScannerModels.kt` (model, transform)

**Full path:** `src/main/kotlin/com/six2dez/burp/aiagent/scanner/PassiveAiScannerModels.kt`

**Analog:** `src/main/kotlin/com/six2dez/burp/aiagent/scanner/ActiveScanModels.kt` and `src/main/kotlin/com/six2dez/burp/aiagent/context/ContextModels.kt`

**What moves here:** File-level and inner data classes from `PassiveAiScanner.kt`. Approximately 60 lines.

- `data class PassiveAiFinding` (lines 37–46)
- `data class PassiveAiScannerStatus` (lines 48–54)
- `internal data class LocalFinding` (line 2057–2062, currently inside the class body)
- `internal data class AiIssueItem` (lines 2215–2222, currently inside the class body)
- Any private inner data classes used only in parsing/caching (e.g. `CachedAiIssues`, `PendingAnalysis`)

**Concrete excerpt — file-level models from `PassiveAiScanner.kt` lines 37–54:**
```kotlin
data class PassiveAiFinding(
    val timestamp: Long,
    val url: String,
    val title: String,
    val severity: String,
    val detail: String,
    val confidence: Int,
    val source: String = "ai",
    val issueCreated: Boolean = true,
)

data class PassiveAiScannerStatus(
    val enabled: Boolean,
    val requestsAnalyzed: Int,
    val issuesFound: Int,
    val lastAnalysisTime: Long,
    val queueSize: Int,
)
```

**Package declaration:**
```kotlin
package com.six2dez.burp.aiagent.scanner
```

**Visibility hazards — CRITICAL:**
- `internal data class LocalFinding` must remain `internal` — it is referenced by `AiPassiveScanCheck.kt` in the same package. Do NOT change to `private`.
- `internal data class AiIssueItem` is referenced from `parseIssuesFromAiResponse` — keep `internal`.
- These are currently nested inside `class PassiveAiScanner`. Moving them to file-level in `PassiveAiScannerModels.kt` (same package) is safe — same-package access is transparent.
- No imports are required for the data class declarations themselves; they do not depend on external types.

---

### `scanner/PassiveAiScannerHeuristics.kt` (utility, transform)

**Full path:** `src/main/kotlin/com/six2dez/burp/aiagent/scanner/PassiveAiScannerHeuristics.kt`

**Analog:** `src/main/kotlin/com/six2dez/burp/aiagent/redact/SecretShapes.kt` and `src/main/kotlin/com/six2dez/burp/aiagent/redact/Entropy.kt`

**What moves here:** Local heuristic check functions from `PassiveAiScanner.kt`. The `runLocalChecks` dispatcher and all its `detect*` / `checkFor*` private methods. Approximately 200 lines.

Methods: `runLocalChecks`, `detectRequestSmuggling`, `detectCsrf`, `detectDeserialization`, `detectUnrestrictedFileUpload` (and any other `check*`/`detect*` methods in the lines 2064–2213 range).

**AWT-free top-level function pattern** (mirrors `BudgetGuard.kt` + `SecretShapes.kt`):
```kotlin
package com.six2dez.burp.aiagent.scanner

import burp.api.montoya.http.message.requests.HttpRequest
import burp.api.montoya.http.message.responses.HttpResponse

// AWT-free contract: MUST NOT import java.awt.* or javax.swing.*

internal fun runLocalChecks(
    request: HttpRequest,
    response: HttpResponse?,
    requestBody: String,
    responseBody: String,
): List<LocalFinding> {
    val findings = mutableListOf<LocalFinding>()
    detectRequestSmuggling(request)?.let { findings.add(it) }
    detectCsrf(request, response)?.let { findings.add(it) }
    detectDeserialization(request, requestBody)?.let { findings.add(it) }
    detectUnrestrictedFileUpload(request, response, requestBody, responseBody)?.let { findings.add(it) }
    return findings
}

private fun detectRequestSmuggling(request: HttpRequest): LocalFinding? {
    // ... body unchanged
}
```

**Concrete excerpt from `PassiveAiScanner.kt` lines 2064–2104 showing structure to extract:**
```kotlin
private fun runLocalChecks(
    request: burp.api.montoya.http.message.requests.HttpRequest,
    response: burp.api.montoya.http.message.responses.HttpResponse?,
    requestBody: String,
    responseBody: String,
): List<LocalFinding> {
    val findings = mutableListOf<LocalFinding>()
    detectRequestSmuggling(request)?.let { findings.add(it) }
    detectCsrf(request, response)?.let { findings.add(it) }
    detectDeserialization(request, requestBody)?.let { findings.add(it) }
    detectUnrestrictedFileUpload(request, response, requestBody, responseBody)?.let { findings.add(it) }
    return findings
}
```

**Visibility hazards:**
- These methods are currently `private` to `PassiveAiScanner.kt`. After extraction to a new file, change to `internal` (package-visible) so `PassiveAiScanner.kt` can call them.
- `LocalFinding` is referenced here — it must be defined in `PassiveAiScannerModels.kt` (same package) before this file is compiled. Kotlin compilation order within a package is handled by the compiler.
- The methods use `companion object` constants like `LOCAL_FINDING_SKIP_CONFIDENCE`, `REQUEST_BODY_LOCAL_CHECK_MAX_CHARS`, `RESPONSE_BODY_LOCAL_CHECK_MAX_CHARS`. These are in `private companion object` in `PassiveAiScanner`. Constants needed here must be redeclared as `private const val` at the top of `PassiveAiScannerHeuristics.kt`, OR the companion object must be changed to `internal companion object`.
- **Recommended:** Redeclare the specific constants needed in heuristics as `private const val` in this file. This is the cleanest approach (matches the anti-pattern guidance in RESEARCH.md Section 3.3).

---

### `scanner/PassiveAiScannerParsing.kt` (utility, transform)

**Full path:** `src/main/kotlin/com/six2dez/burp/aiagent/scanner/PassiveAiScannerParsing.kt`

**Analog:** `src/main/kotlin/com/six2dez/burp/aiagent/util/BudgetGuard.kt` (pure top-level functions with no instance state)

**What moves here:** AI response parsing functions from `PassiveAiScanner.kt` lines approximately 2224–2400. Approximately 200 lines.

Methods: `parseIssuesJson`, `parseIssuesFromAiResponse`, `cleanJsonResponse`, `parseIssuesNode`, `parseNodeIfValid`, `stripCodeFences`, `extractBalancedJsonCandidates`, `sha256Hex`.

**Concrete excerpt from `PassiveAiScanner.kt` lines 2224–2240:**
```kotlin
internal fun parseIssuesJson(json: String): List<AiIssueItem> {
    val root = jsonMapper.readTree(json)
    return parseIssuesNode(root)
}

internal fun parseIssuesFromAiResponse(text: String): List<AiIssueItem> {
    if (text.isBlank()) return emptyList()
    val cleaned = cleanJsonResponse(text)
    if (cleaned.isBlank() || cleaned == "[]") return emptyList()
    return try {
        parseIssuesJson(cleaned)
    } catch (e: Exception) {
        val preview = text.replace(Regex("\\s+"), " ").take(160)
        api.logging().logToError("[PassiveAiScanner] Failed to parse AI response after cleanup: ${e.message} | preview=$preview")
        emptyList()
    }
}
```

**Package declaration + imports:**
```kotlin
package com.six2dez.burp.aiagent.scanner

import com.fasterxml.jackson.databind.JsonNode
import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.module.kotlin.registerKotlinModule
import com.six2dez.burp.aiagent.audit.Hashing
```

**Visibility hazards:**
- `parseIssuesFromAiResponse` currently calls `api.logging().logToError(...)`. This is the only reference to an instance field (`api: MontoyaApi`) in this group. Two options: (a) pass `api` as a parameter, or (b) return a `Result<...>` or nullable and let the caller log. Recommended: pass `api` as a parameter to keep the function pure while preserving the error log.
- `jsonMapper` (`ObjectMapper`) is referenced — it is a private field in `PassiveAiScanner`. Extract it as a `private val` at the top of this file.
- `AiIssueItem` is in `PassiveAiScannerModels.kt` — same package, no import needed.
- These methods are currently `internal` in the class — keep `internal` at file level.

---

### `scanner/PassiveAiScannerPrompts.kt` (utility, transform)

**Full path:** `src/main/kotlin/com/six2dez/burp/aiagent/scanner/PassiveAiScannerPrompts.kt`

**Analog:** `src/main/kotlin/com/six2dez/burp/aiagent/util/BudgetGuard.kt` (pure functions, no instance state beyond constants)

**What moves here:** Prompt and body builder functions from `PassiveAiScanner.kt`. Approximately 350 lines.

Methods: `buildAnalysisPrompt`, `buildBatchAnalysisPrompt`, `buildMetadataSectionPlain`, `buildCompactRequestBody`, `buildCompactResponseBody`, `isJsonBody`, `compactJsonBody`, `compactHtmlBody`, `truncateWithEllipsis`.

**Concrete excerpt from `PassiveAiScanner.kt` lines 1104–1110 and 2537–2564:**
```kotlin
private fun truncateWithEllipsis(
    text: String,
    maxChars: Int,
): String {
    if (text.length <= maxChars) return text
    return text.take(maxChars) + "..."
}

private fun buildMetadataSectionPlain(
    backendInfo: AgentSupervisor.BackendInfo?,
    scanType: String,
    confidence: Int,
    note: String,
): String {
    val lines = mutableListOf<String>()
    lines.add("AI Analysis Metadata")
    // ...
    return lines.joinToString("\r\n")
}
```

**Package declaration + key imports:**
```kotlin
package com.six2dez.burp.aiagent.scanner

import com.six2dez.burp.aiagent.supervisor.AgentSupervisor
import com.six2dez.burp.aiagent.util.SecurityExcerpts
// Note: com.fasterxml.jackson if compactJsonBody uses the ObjectMapper
```

**Visibility hazards:**
- `buildAnalysisPrompt` / `buildBatchAnalysisPrompt` reference constants from `companion object` (e.g. `DEFAULT_REQUEST_BODY_PROMPT_MAX_CHARS`, `MAX_HEADERS_MAX_COUNT`, `PARAM_VALUE_MAX_CHARS`). Redeclare the needed ones as `private const val` at the top of this file.
- `buildAnalysisPrompt` may also reference `endpointDedupMinutes` / other instance fields via indirect calls — audit the body and pass any instance values as parameters.
- `buildCompactRequestBody` / `buildCompactResponseBody` may use the `ObjectMapper` — move `private val jsonMapper` into a shared file-level val (e.g. in `PassiveAiScannerParsing.kt`) and reference it from the same package.
- Change all extracted methods from `private` to `internal`.

---

## Shared Patterns

### Pattern: AWT-free top-level object/functions

**Source files:** `src/main/kotlin/com/six2dez/burp/aiagent/redact/SecretShapes.kt` and `src/main/kotlin/com/six2dez/burp/aiagent/util/BudgetGuard.kt`

**Apply to:** `PassiveAiScannerHeuristics.kt`, `PassiveAiScannerParsing.kt`, `PassiveAiScannerPrompts.kt`, `McpToolHelpers.kt`

**Pattern structure:**
```kotlin
/**
 * AWT-free <description of purpose>.
 *
 * ### AWT-free contract
 * This file MUST NOT import `java.awt.*` or `javax.swing.*`. <Reason>.
 */
// Top-level functions (not wrapped in an object unless a namespace is needed)
internal fun functionName(param: Type): ReturnType {
    // pure transform
}

private const val CONSTANT_NAME = value  // for companion-object constants that were moved here
```

**Key rule from `BudgetGuard.kt` lines 1–18:** The AWT-free comment block is a contract-level KDoc (not a lint suppressions). Every extracted scanner helper file SHOULD carry a `// AWT-free contract: MUST NOT import java.awt.* or javax.swing.*` comment to enforce the headless-testable requirement.

---

### Pattern: Same-package extension functions on a Swing class

**Source:** `src/main/kotlin/com/six2dez/burp/aiagent/config/AgentSettings.kt` (for the extension function syntax) and `ui/panels/PassiveScanConfigPanel.kt` (for the Swing design-token usage)

**Apply to:** `SettingsPanelScannerTabs.kt`, `SettingsPanelMcpTabs.kt`

**Extension function syntax** (from `AgentSettings.kt` — the only existing extension-function-on-class-in-separate-file pattern in the project):
```kotlin
// In a different file, same package:
fun AgentSettings.toPreprocessorSettings() = ResponsePreprocessorSettings(
    // ...uses this.someField (public or internal)
)
```

**Design-token usage** (from `PassiveScanConfigPanel.kt` lines 58–60):
```kotlin
passiveAiEnabled.font = DesignTokens.Typography.body
passiveAiEnabled.background = DesignTokens.Colors.surface
passiveAiEnabled.foreground = DesignTokens.Colors.onSurface
```

**Key rule:** All UI color/font references in the extracted extension functions MUST use `DesignTokens.*` or `UiTheme.*` constants — never hardcoded `Color(...)` or `Font(...)` inline (from `CONVENTIONS.md` Swing UI Patterns section).

---

### Pattern: Multi-type models file

**Source:** `src/main/kotlin/com/six2dez/burp/aiagent/context/ContextModels.kt` and `src/main/kotlin/com/six2dez/burp/aiagent/scanner/ActiveScanModels.kt`

**Apply to:** `McpToolModels.kt`, `PassiveAiScannerModels.kt`

**Structure** (from `ContextModels.kt` lines 1–40):
```kotlin
package com.six2dez.burp.aiagent.<package>

// No class wrapper — all top-level declarations
data class TypeA(val field: Type)
data class TypeB(val field: Type)
sealed interface SomeInterface
data class TypeC(...) : SomeInterface
```

**Key rule:** No enclosing class or object. All types are top-level in the file. Use `internal` on types that must not be visible outside the module (e.g. `LocalFinding`, `AiIssueItem`). Use no modifier (package-internal) or `internal` for types shared across the package.

---

### Pattern: Error handling in utility functions

**Source:** `src/main/kotlin/com/six2dez/burp/aiagent/mcp/tools/McpTools.kt` lines 890–896 (concrete)

**Apply to:** `McpToolHelpers.kt`, `PassiveAiScannerParsing.kt`

```kotlin
try {
    burp.api.montoya.scanner.audit.issues.AuditIssueSeverity
        .valueOf(input.severity.uppercase())
} catch (_: Exception) {
    return "Invalid severity: ${input.severity}. Use: HIGH, MEDIUM, LOW, INFORMATION"
}
```

**Key rule from `CONVENTIONS.md`:** Use anonymous `_` for caught exceptions in cleanup / input validation code where the exception type is not used in the handler body. Never use `!!`. Use `try/catch(e: Exception)` at process and network boundaries.

---

### Pattern: `internal` visibility for cross-file same-package helpers

**Source:** `src/main/kotlin/com/six2dez/burp/aiagent/mcp/tools/HistoryTools.kt` lines 6–8 (all register functions are `internal`):
```kotlin
internal fun Server.registerHistoryTools(context: McpToolContext) {
    McpToolRegistrations.history.forEach { registerToolHandler(it, context) }
}
```

**Apply to:** All extracted helper functions in `McpToolHelpers.kt`, `SettingsPanelScannerTabs.kt`, `SettingsPanelMcpTabs.kt`, `PassiveAiScannerHeuristics.kt`, `PassiveAiScannerParsing.kt`, `PassiveAiScannerPrompts.kt`.

**Key rule:** Functions extracted from one file to another file in the same package must change from `private` to `internal`. Kotlin `private` is file-scoped (not class-scoped); an `internal` function is still invisible outside the module.

---

## Docs Patterns

### `docs/anthropic-backend.md` and `docs/external-mcp-servers.md`

**Analog:** `docs/mcp-hardening.md` (structure) and `docs/backend-troubleshooting.md` (tone)

**Structural pattern** (from `docs/mcp-hardening.md` lines 1–44):
```markdown
# <Noun> <Verb/Role>

<Lead paragraph — 1–2 sentences describing the page's purpose.>

## <Section Name>

1. Step one.
2. Step two.
3. Step three.

## <Another Section>

| Column A | Column B |
|----------|----------|
| value    | meaning  |

## <Setup/Verification>

1. Verification step.
```

**Key style rules** (derived from reading all three existing docs pages):
- H1 title is the feature name or runbook name — no subtitle.
- Lead paragraph is exactly 1–2 sentences.
- All H2 section headings are action-oriented nouns: "Setup", "Configuration", "Privacy Notes", "Verification", not "How to configure X".
- Numbered lists for sequential steps; bullet lists for non-sequential options.
- Code blocks (` ``` `) for commands, config values, and example responses.
- Tables for structured reference data (configuration options, environment variables).
- No prose padding — no "As you can see" or "In this section". Each H2 is self-contained.
- Target length: 40–80 lines total (mcp-hardening.md is 44 lines; backend-troubleshooting.md is 36 lines; ui-safety-guide.md is 30 lines).

**Section skeletons to use:**

For `docs/anthropic-backend.md`:
```markdown
# Anthropic Backend

<lead: what it is — native Anthropic Messages API backend, no Anthropic SDK, uses Burp's HTTP transport>

## Setup
1. Select **Anthropic** in Backend settings.
2. Enter API key (stored AES-256-GCM encrypted).
3. Choose model (claude-3-5-sonnet-... etc.).

## Configuration

| Setting | Default | Notes |
|---------|---------|-------|
| Model   | ...     | ...   |
| Timeout | ...     | ...   |

## Privacy Notes
1. ...
2. ...
```

For `docs/external-mcp-servers.md`:
```markdown
# External MCP Servers

<lead: what it is — CAP-02, connect Burp to external MCP servers so Claude/other agents can proxy through Burp>

## Setup
1. ...

## Security Notes
1. Auth tokens encrypted at rest (AES-256-GCM).
2. Trust boundary — untrusted server output is sanitized before use.
3. ...
```

---

## DECISIONS.md ADR Entries

**Analog:** All existing H2 entries in `DECISIONS.md` (lines 1–83). Each follows: `## ADR-N: Title`, `**Context.**`, `**Decision.**`, `**Consequences.**`.

**Format to match** (from `DECISIONS.md` ADR-5 lines 51–59):
```markdown
## ADR-N: <Title>

**Context.** <1–3 sentences describing what problem the decision addresses and what alternatives existed.>

**Decision.** <1 sentence stating the specific choice made.>

**Consequences.**
- <positive consequence>
- <negative consequence / trade-off>
- <any mitigating action>
```

**ADR entries to append (5 new entries for v0.9.0 decisions):**
1. AES-256-GCM secrets at rest (SEC-01) — `javax.crypto` only, no Bouncy Castle, no Tink; per-install random key.
2. Real HKDF host anonymization (PRIV-01) — HMAC-SHA256 extract/expand replaces salted SHA-256; `SecretShapes` is the single source of truth.
3. Anthropic backend via `MontoyaHttpTransport` (CAP-01) — not a vendored Anthropic SDK; uses the existing HTTP transport layer.
4. External MCP client untrusted-output trust boundary (CAP-02) — kotlin-sdk 0.5.0, `SseClientTransport`/`StdioClientTransport`; external server output sanitized before use.
5. Per-session token-budget guardrails (CAP-04) — `BudgetGuard` pure object, reversible CAP/WARN/OFF states; 0 = unlimited/off.

---

## No Analog Found

All files in scope have close analogs in the codebase. No entries.

---

## Visibility Change Summary

This table is the executor's checklist — apply these changes BEFORE moving code between files.

| Origin File | Member | Current Visibility | Required Visibility | Reason |
|---|---|---|---|---|
| `McpTools.kt` | `toolJson` (val, line 53) | `private` | `internal` | Referenced by `McpToolExecutor` moving to `McpToolExecutorImpl.kt` |
| `McpTools.kt` | helper functions (lines 884–1262) | `private` | `internal` | Called from `McpToolExecutor` in new file |
| `SettingsPanel.kt` | UI component fields (all `private val` referenced by section builders) | `private` | `internal` | Extension functions in `SettingsPanelScannerTabs.kt` and `SettingsPanelMcpTabs.kt` cannot access `private` members |
| `PassiveAiScanner.kt` | `LocalFinding` (inner class, line 2057) | `internal` (class member) | `internal` (file-level) | Stays `internal`; moves to `PassiveAiScannerModels.kt` |
| `PassiveAiScanner.kt` | `AiIssueItem` (inner class, line 2215) | `internal` (class member) | `internal` (file-level) | Stays `internal`; moves to `PassiveAiScannerModels.kt` |
| `PassiveAiScanner.kt` | heuristic methods (lines 2064–2213) | `private` | `internal` | Top-level functions in `PassiveAiScannerHeuristics.kt` |
| `PassiveAiScanner.kt` | parsing methods (lines 2224–2400) | `private`/`internal` | `internal` | Top-level functions in `PassiveAiScannerParsing.kt` |
| `PassiveAiScanner.kt` | prompt/body builder methods | `private` | `internal` | Top-level functions in `PassiveAiScannerPrompts.kt` |
| `PassiveAiScanner.kt` | `companion object` | `private companion object` | `internal companion object` OR keep `private` and redeclare needed constants in new files | Constants referenced by extracted functions |

---

## Metadata

**Analog search scope:** `src/main/kotlin/com/six2dez/burp/aiagent/` (all packages), `docs/`, `DECISIONS.md`
**Files scanned:** McpTools.kt, SettingsPanel.kt, PassiveAiScanner.kt, HistoryTools.kt, UtilityTools.kt, PassiveScanConfigPanel.kt, BudgetGuard.kt, SecretShapes.kt, Entropy.kt, ScannerUtils.kt, ContextModels.kt, ActiveScanModels.kt, mcp-hardening.md, backend-troubleshooting.md, ui-safety-guide.md, DECISIONS.md, CONVENTIONS.md, STRUCTURE.md
**Pattern extraction date:** 2026-06-16
