package com.six2dez.burp.aiagent.mcp.tools

import com.six2dez.burp.aiagent.mcp.McpToolContext
import io.modelcontextprotocol.kotlin.sdk.server.Server
import kotlinx.serialization.Serializable

internal fun Server.registerAiTools(context: McpToolContext) {
    McpToolRegistrations.native.forEach { registerToolHandler(it, context) }
}

@Serializable
internal data class AiAnalyzeInput(
    val text: String,
    val jsonMode: Boolean = false,
    val maxOutputTokens: Int? = null,
)

@Serializable
internal data class AiPassiveScanInput(
    val proxyHistoryIndices: List<Int> = emptyList(),
    val siteMapUrl: String? = null,
    val maxRequests: Int = 10,
)

@Serializable
internal data class AiFindingsRecentInput(
    val n: Int = 10,
)

@Serializable
internal data class RedactPreviewInput(
    val text: String,
    val mode: String = "STRICT",
)

@Serializable
internal data class AiAuditQueryInput(
    val n: Int = 20,
)
