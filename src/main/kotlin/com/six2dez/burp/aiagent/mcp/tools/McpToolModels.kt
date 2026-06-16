package com.six2dez.burp.aiagent.mcp.tools

import burp.api.montoya.http.HttpService
import kotlinx.serialization.Serializable

// ──────────────────────────────────────────────────────────────────────────────
// Shared interfaces
// ──────────────────────────────────────────────────────────────────────────────

interface HttpServiceParams {
    val targetHostname: String
    val targetPort: Int
    val usesHttps: Boolean

    fun toMontoyaService(resolveHost: (String) -> String = { it }): HttpService = HttpService.httpService(resolveHost(targetHostname), targetPort, usesHttps)

    fun toMontoyaServiceOrNull(resolveHost: (String) -> String = { it }): HttpService? {
        if (targetHostname.isBlank() || targetPort <= 0) return null
        return HttpService.httpService(resolveHost(targetHostname), targetPort, usesHttps)
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// ToolSpec (used by McpToolExecutor.describeTools)
// ──────────────────────────────────────────────────────────────────────────────

data class ToolSpec(
    val id: String,
    val description: String,
    val enabled: Boolean,
    val unsafeOnly: Boolean,
    val proOnly: Boolean,
    val argsSchema: String?,
)

// ──────────────────────────────────────────────────────────────────────────────
// @Serializable parameter types for MCP tool inputs
// ──────────────────────────────────────────────────────────────────────────────

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

@Serializable
data class CreateRepeaterTab(
    val tabName: String?,
    val content: String,
    override val targetHostname: String,
    override val targetPort: Int,
    override val usesHttps: Boolean,
) : HttpServiceParams

@Serializable
data class RepeaterTabWithPayload(
    val tabName: String?,
    val content: String,
    val replacements: Map<String, String>,
    override val targetHostname: String,
    override val targetPort: Int,
    override val usesHttps: Boolean,
) : HttpServiceParams

@Serializable
data class SendToIntruder(
    val tabName: String?,
    val content: String,
    override val targetHostname: String,
    override val targetPort: Int,
    override val usesHttps: Boolean,
) : HttpServiceParams

@Serializable
data class IntruderPrepare(
    val tabName: String?,
    val content: String,
    val insertionPoints: List<InsertionPointRange> = emptyList(),
    val mode: String = "REPLACE_BASE_PARAMETER_VALUE_WITH_OFFSETS",
    override val targetHostname: String,
    override val targetPort: Int,
    override val usesHttps: Boolean,
) : HttpServiceParams

@Serializable
data class InsertionPointRange(
    val start: Int,
    val end: Int,
)

@Serializable
data class InsertionPoints(
    val content: String,
    val mode: String = "REPLACE_BASE_PARAMETER_VALUE_WITH_OFFSETS",
)

@Serializable
data class ExtractParams(
    val content: String,
)

@Serializable
data class DiffRequests(
    val requestA: String,
    val requestB: String,
)

@Serializable
data class RequestParse(
    val content: String,
    val includeBody: Boolean = false,
)

@Serializable
data class ResponseParse(
    val content: String,
    val includeBody: Boolean = false,
)

@Serializable
data class ParsedParam(
    val type: String,
    val name: String,
    val value: String,
)

@Serializable
data class ParsedRequest(
    val method: String,
    val path: String,
    val url: String,
    val headers: Map<String, String>,
    val parameters: List<ParsedParam>,
    val body: String? = null,
    val bodyLength: Int,
)

@Serializable
data class ParsedResponse(
    val statusCode: Int,
    val headers: Map<String, String>,
    val body: String? = null,
    val bodyLength: Int,
)

@Serializable
data class FindReflected(
    val request: String,
    val response: String,
)

@Serializable
data class ComparerSend(
    val items: List<String>,
)

@Serializable
data class ProxyHistoryAnnotate(
    val regex: String,
    val note: String,
    val highlight: String? = null,
    val scopeOnly: Boolean = true,
    val limit: Int = 20,
)

@Serializable
data class ResponseBodySearch(
    val regex: String,
    override val count: Int = 5,
    override val offset: Int = 0,
    val scopeOnly: Boolean = true,
) : Paginated

@Serializable
data class CookieJarGet(
    val domain: String? = null,
    val includeSubdomains: Boolean = true,
    val scopeOnly: Boolean = true,
    val includeValues: Boolean = false,
)

@Serializable
data class CookieEntry(
    val name: String,
    val value: String,
    val domain: String,
    val path: String,
    val expiresAt: String? = null,
)

@Serializable
data class ScopeCheck(
    val url: String = "",
) {
    init {
        require(url.isNotBlank()) { "'url' is required for scope_check. Provide the URL to check." }
    }
}

@Serializable
data class ScopeUpdate(
    val url: String = "",
) {
    init {
        require(url.isNotBlank()) { "'url' is required for scope_include/scope_exclude. Provide the URL to modify." }
    }
}

@Serializable
data class CollaboratorGenerate(
    val customData: String? = null,
    val options: List<String> = emptyList(),
)

@Serializable
data class CollaboratorPoll(
    val secretKey: String,
    val includeHttp: Boolean = false,
)

@Serializable
data class UrlEncode(
    val content: String,
)

@Serializable
data class UrlDecode(
    val content: String,
)

@Serializable
data class Base64Encode(
    val content: String,
)

@Serializable
data class Base64Decode(
    val content: String,
)

@Serializable
data class GenerateRandomString(
    val length: Int,
    val characterSet: String,
)

@Serializable
data class HashCompute(
    val content: String,
    val algorithm: String,
)

@Serializable
data class JwtDecode(
    val token: String,
)

@Serializable
data class DecodeAs(
    val base64: String,
    val encoding: String,
)

@Serializable
data class SetProjectOptions(
    val json: String,
)

@Serializable
data class SetUserOptions(
    val json: String,
)

@Serializable
data class SetTaskExecutionEngineState(
    val running: Boolean,
)

@Serializable
data class SetProxyInterceptState(
    val intercepting: Boolean,
)

@Serializable
data class SetActiveEditorContents(
    val text: String,
)

@Serializable
data class CreateAuditIssue(
    val name: String,
    val detail: String,
    val baseUrl: String,
    val severity: String,
    val confidence: String,
    val remediation: String? = null,
    val background: String? = null,
    val remediationBackground: String? = null,
    val typicalSeverity: String? = null,
    val httpRequest: String? = null,
    val httpResponseContent: String? = null,
    override val targetHostname: String = "",
    override val targetPort: Int = 443,
    override val usesHttps: Boolean = true,
) : HttpServiceParams {
    override fun toMontoyaServiceOrNull(resolveHost: (String) -> String): HttpService? =
        if (targetHostname.isNotBlank()) {
            HttpService.httpService(resolveHost(targetHostname), targetPort, usesHttps)
        } else {
            null
        }
}

@Serializable
data class GetScannerIssues(
    override val count: Int = 5,
    override val offset: Int = 0,
) : Paginated

@Serializable
data class StartAudit(
    val builtInConfiguration: String,
)

@Serializable
data class StartAuditMode(
    val mode: String,
    val requests: List<String> = emptyList(),
    override val targetHostname: String = "",
    override val targetPort: Int = 0,
    override val usesHttps: Boolean = true,
) : HttpServiceParams

@Serializable
data class StartAuditWithRequests(
    val builtInConfiguration: String,
    val requests: List<String>,
    override val targetHostname: String,
    override val targetPort: Int,
    override val usesHttps: Boolean,
) : HttpServiceParams

@Serializable
data class StartCrawl(
    val seedUrls: List<String>,
)

@Serializable
data class GetScanTaskStatus(
    val taskId: String,
)

@Serializable
data class DeleteScanTask(
    val taskId: String,
)

@Serializable
data class GenerateScannerReport(
    val taskId: String?,
    val allIssues: Boolean,
    val format: String,
    val path: String,
)

@Serializable
data class GetProxyHttpHistory(
    override val count: Int = 5,
    override val offset: Int = 0,
    val includeUnpreprocessedResponse: Boolean = false,
    val listenerPort: Int? = null, // CAP-03 — null/unset = all ports
) : Paginated

@Serializable
data class GetProxyHttpHistoryRestricted(
    override val count: Int = 5,
    override val offset: Int = 0,
    val listenerPort: Int? = null, // CAP-03 — null/unset = all ports (schema exposed under restricted branch)
) : Paginated

@Serializable
data class GetProxyHttpHistoryRegex(
    val regex: String,
    override val count: Int = 5,
    override val offset: Int = 0,
    val includeUnpreprocessedResponse: Boolean = false,
) : Paginated

@Serializable
data class GetProxyHttpHistoryRegexRestricted(
    val regex: String,
    override val count: Int = 5,
    override val offset: Int = 0,
) : Paginated

@Serializable
data class GetProxyWebsocketHistory(
    override val count: Int = 5,
    override val offset: Int = 0,
) : Paginated

@Serializable
data class GetProxyWebsocketHistoryRegex(
    val regex: String,
    override val count: Int = 5,
    override val offset: Int = 0,
) : Paginated

@Serializable
data class GetSiteMap(
    override val count: Int = 5,
    override val offset: Int = 0,
) : Paginated

@Serializable
data class GetSiteMapRegex(
    val regex: String,
    override val count: Int = 5,
    override val offset: Int = 0,
) : Paginated

