package com.six2dez.burp.aiagent.mcp.tools

import burp.api.montoya.MontoyaApi
import com.six2dez.burp.aiagent.mcp.McpToolContext
import io.modelcontextprotocol.kotlin.sdk.server.Server

@Suppress("UNUSED_PARAMETER")
fun Server.registerTools(
    api: MontoyaApi,
    context: McpToolContext,
) {
    registerUtilityTools(context)
    registerHistoryTools(context)
    registerSiteMapTools(context)
    registerRequestTools(context)
    registerScannerTools(context)
    registerConfigTools(context)
    registerEditorTools(context)
    registerCollaboratorTools(context)
    registerIssueTools(context)
    registerAiTools(context)
}
