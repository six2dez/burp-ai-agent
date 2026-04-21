package com.six2dez.burp.aiagent.mcp.tools

import com.six2dez.burp.aiagent.audit.ActivityType
import com.six2dez.burp.aiagent.audit.Hashing
import com.six2dez.burp.aiagent.mcp.McpToolCatalog
import com.six2dez.burp.aiagent.mcp.McpToolContext
import io.modelcontextprotocol.kotlin.sdk.TextContent
import io.modelcontextprotocol.kotlin.sdk.server.Server

internal object McpToolRegistrations {
    val utility =
        listOf(
            "status",
            "url_encode",
            "url_decode",
            "base64_encode",
            "base64_decode",
            "random_string",
            "hash_compute",
            "jwt_decode",
            "decode_as",
            "cookie_jar_get",
        )

    val history =
        listOf(
            "proxy_http_history",
            "proxy_http_history_regex",
            "proxy_history_annotate",
            "response_body_search",
            "proxy_ws_history",
            "proxy_ws_history_regex",
        )

    val siteMap =
        listOf(
            "site_map",
            "site_map_regex",
            "scope_check",
            "scope_include",
            "scope_exclude",
        )

    val request =
        listOf(
            "http1_request",
            "http2_request",
            "repeater_tab",
            "repeater_tab_with_payload",
            "intruder",
            "intruder_prepare",
            "insertion_points",
            "params_extract",
            "diff_requests",
            "request_parse",
            "response_parse",
            "find_reflected",
            "comparer_send",
        )

    val scanner =
        listOf(
            "scanner_issues",
            "scan_audit_start",
            "scan_audit_start_mode",
            "scan_audit_start_requests",
            "scan_crawl_start",
            "scan_task_status",
            "scan_task_delete",
            "scan_report",
        )

    val config =
        listOf(
            "project_options_get",
            "user_options_get",
            "project_options_set",
            "user_options_set",
            "task_engine_state",
            "proxy_intercept",
        )

    val editor =
        listOf(
            "editor_get",
            "editor_set",
        )

    val collaborator =
        listOf(
            "collaborator_generate",
            "collaborator_poll",
        )

    val issue =
        listOf(
            "issue_create",
        )

    fun allIds(): Set<String> = (utility + history + siteMap + request + scanner + config + editor + collaborator + issue).toSet()
}

internal fun Server.registerToolHandler(
    toolId: String,
    context: McpToolContext,
) {
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
            val argsSummary = argsJson?.take(120) ?: "(none)"
            val resultText =
                result.content
                    .filterIsInstance<TextContent>()
                    .joinToString("\n") { it.text?.toString().orEmpty() }
            val argsHash = argsJson?.takeIf { it.isNotBlank() }?.let { Hashing.sha256Hex(it) } ?: ""
            val resultHash = resultText.takeIf { it.isNotBlank() }?.let { Hashing.sha256Hex(it) } ?: ""
            val policyDecision =
                when {
                    resultText.startsWith("Tool disabled:") -> "disabled"
                    resultText.startsWith("Unsafe mode is disabled for tool:") -> "unsafe_blocked"
                    resultText.startsWith("Tool requires Burp Suite Professional:") -> "pro_only"
                    resultText.startsWith("Too many concurrent MCP requests.") -> "concurrency_limited"
                    else -> "allowed"
                }
            val status =
                when {
                    policyDecision != "allowed" -> "blocked"
                    result.isError == true -> "error"
                    else -> "ok"
                }

            context.aiRequestLogger?.log(
                type = ActivityType.MCP_TOOL_CALL,
                source = "mcp",
                backendId = "mcp-server",
                detail = "Tool: ${descriptor.id} | Args: $argsSummary",
                durationMs = durationMs,
                metadata =
                    mapOf(
                        "toolId" to descriptor.id,
                        "status" to status,
                        "policyDecision" to policyDecision,
                        "durationMs" to durationMs.toString(),
                        "argsSha256" to argsHash,
                        "resultSha256" to resultHash,
                        "resultChars" to resultText.length.toString(),
                    ),
            )

            result
        },
    )
}
