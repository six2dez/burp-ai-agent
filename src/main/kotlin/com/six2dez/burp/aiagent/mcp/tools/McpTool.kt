package com.six2dez.burp.aiagent.mcp.tools

import com.six2dez.burp.aiagent.audit.AuditLogger
import com.six2dez.burp.aiagent.audit.Hashing
import com.six2dez.burp.aiagent.mcp.McpToolContext
import com.six2dez.burp.aiagent.mcp.schema.asInputSchema
import io.modelcontextprotocol.kotlin.sdk.CallToolResult
import io.modelcontextprotocol.kotlin.sdk.TextContent
import io.modelcontextprotocol.kotlin.sdk.Tool
import io.modelcontextprotocol.kotlin.sdk.server.Server
import kotlinx.serialization.InternalSerializationApi
import kotlinx.serialization.json.Json
import kotlinx.serialization.serializer
import kotlin.experimental.ExperimentalTypeInference

@PublishedApi
internal val json = Json { ignoreUnknownKeys = true }
private const val MAX_ERROR_MESSAGE_LENGTH = 500
private const val MCP_TOOL_EVENT_START = "mcp_tool_start"
private const val MCP_TOOL_EVENT_END = "mcp_tool_end"
private const val MCP_TOOL_EVENT_BLOCKED = "mcp_tool_blocked"
private val unixAbsPathRegex = Regex("""/(?:Users|home|var|tmp|opt|etc|private|Library|Applications)(?:/[^\s:]+)+""")
private val windowsAbsPathRegex = Regex("""[A-Za-z]:\\(?:[^\\\s:]+\\)*[^\\\s:]*""")
private val packageClassRegex = Regex("""\b(?:[a-z_][a-z0-9_]*\.){2,}[A-Za-z_][A-Za-z0-9_$]*\b""")

@OptIn(InternalSerializationApi::class)
inline fun <reified I : Any> Server.mcpTool(
    description: String,
    context: McpToolContext,
    toolName: String? = null,
    crossinline execute: I.() -> String,
) {
    val name = toolName ?: I::class.simpleName?.toLowerSnakeCase() ?: error("Missing tool name for ${I::class}")
    addTool(
        name = name,
        description = description,
        inputSchema = I::class.asInputSchema(),
        handler = { request ->
            runTool(context, name, request.arguments.toString()) {
                val input =
                    json.decodeFromJsonElement(
                        I::class.serializer(),
                        request.arguments,
                    )
                context.redactIfNeeded(execute(input))
            }
        },
    )
}

@OptIn(ExperimentalTypeInference::class)
@OverloadResolutionByLambdaReturnType
@JvmName("mcpToolUnit")
inline fun <reified I : Any> Server.mcpTool(
    description: String,
    context: McpToolContext,
    toolName: String? = null,
    crossinline execute: I.() -> Unit,
) {
    mcpTool<I>(description, context, toolName) {
        execute(this)
        "Executed tool"
    }
}

inline fun Server.mcpTool(
    name: String,
    description: String,
    context: McpToolContext,
    crossinline execute: () -> String,
) {
    addTool(
        name = name,
        description = description,
        inputSchema = Tool.Input(),
        handler = {
            runTool(context, name, null) {
                context.redactIfNeeded(execute())
            }
        },
    )
}

inline fun <reified I : Paginated> Server.mcpPaginatedTool(
    description: String,
    context: McpToolContext,
    toolName: String? = null,
    crossinline execute: I.() -> Sequence<String>,
) {
    mcpTool<I>(description, context, toolName) {
        val items = execute(this).drop(offset).take(count).toList()
        if (items.isEmpty()) {
            "Reached end of items"
        } else {
            items.joinToString(separator = "\n\n")
        }
    }
}

fun String.toLowerSnakeCase(): String =
    this
        .replace(Regex("([a-z0-9])([A-Z])"), "$1_$2")
        .replace(Regex("([A-Z])([A-Z][a-z])"), "$1_$2")
        .replace(Regex("[\\s-]+"), "_")
        .lowercase()

interface Paginated {
    val count: Int
    val offset: Int
}

@PublishedApi
internal fun runTool(
    context: McpToolContext,
    name: String,
    argsJson: String? = null,
    execute: () -> String,
): CallToolResult {
    val normalizedArgs = argsJson?.trim().orEmpty()
    val hasArgs = normalizedArgs.isNotBlank() && normalizedArgs != "{}"
    val argsSha256 = if (hasArgs) Hashing.sha256Hex(normalizedArgs) else null
    val toolType = if (context.isUnsafeTool(name)) "unsafe" else "safe"

    val baseTelemetry =
        linkedMapOf<String, Any?>(
            "tool" to name,
            "toolType" to toolType,
            "hasArgs" to hasArgs,
        ).also { payload ->
            if (argsSha256 != null) {
                payload["argsSha256"] = argsSha256
            }
        }

    if (!context.isToolEnabled(name)) {
        emitToolTelemetry(MCP_TOOL_EVENT_BLOCKED, baseTelemetry + mapOf("reason" to "disabled"))
        return CallToolResult(
            content = listOf(TextContent("Tool disabled: $name")),
            isError = true,
        )
    }
    if (context.isUnsafeTool(name) && !context.isUnsafeToolAllowed(name)) {
        emitToolTelemetry(MCP_TOOL_EVENT_BLOCKED, baseTelemetry + mapOf("reason" to "unsafe_not_allowed"))
        return CallToolResult(
            content =
                listOf(
                    TextContent("Unsafe mode is disabled for tool: $name. Enable global unsafe mode or explicitly allow this tool."),
                ),
            isError = true,
        )
    }
    if (!context.limiter.tryAcquire()) {
        emitToolTelemetry(MCP_TOOL_EVENT_BLOCKED, baseTelemetry + mapOf("reason" to "concurrency_limited"))
        return CallToolResult(
            content = listOf(TextContent("Too many concurrent MCP requests.")),
            isError = true,
        )
    }

    emitToolTelemetry(MCP_TOOL_EVENT_START, baseTelemetry)
    val startedAtNanos = System.nanoTime()

    return try {
        val output = context.limitOutput(execute())
        val result = CallToolResult(content = listOf(TextContent(output)))
        emitToolTelemetry(
            MCP_TOOL_EVENT_END,
            baseTelemetry +
                mapOf(
                    "outcome" to "success",
                    "durationMs" to elapsedMs(startedAtNanos),
                    "outputChars" to output.length,
                ),
        )
        result
    } catch (e: kotlinx.serialization.SerializationException) {
        // Extract missing field from the error message for a cleaner message
        val msg = e.message.orEmpty()
        val fieldMatch = Regex("Field '([^']+)' is required").find(msg)
        val cleanMsg =
            if (fieldMatch != null) {
                "Missing required parameter: ${fieldMatch.groupValues[1]}"
            } else {
                "Invalid tool arguments: $msg"
            }
        emitToolTelemetry(
            MCP_TOOL_EVENT_END,
            baseTelemetry +
                mapOf(
                    "outcome" to "error",
                    "errorType" to "serialization",
                    "durationMs" to elapsedMs(startedAtNanos),
                ),
        )
        CallToolResult(
            content = listOf(TextContent(cleanMsg)),
            isError = true,
        )
    } catch (e: Exception) {
        context.api.logging().logToError(e)
        val cleanMsg = sanitizeErrorMessage(e)
        emitToolTelemetry(
            MCP_TOOL_EVENT_END,
            baseTelemetry +
                mapOf(
                    "outcome" to "error",
                    "errorType" to "exception",
                    "durationMs" to elapsedMs(startedAtNanos),
                ),
        )
        CallToolResult(
            content = listOf(TextContent(cleanMsg)),
            isError = true,
        )
    } finally {
        context.limiter.release()
    }
}

private fun elapsedMs(startedAtNanos: Long): Long = ((System.nanoTime() - startedAtNanos) / 1_000_000L).coerceAtLeast(0L)

private fun emitToolTelemetry(
    type: String,
    payload: Map<String, Any?>,
) {
    AuditLogger.emitGlobal(type, payload)
}

private fun sanitizeErrorMessage(e: Exception): String {
    var message = e.message.orEmpty().ifBlank { "Unexpected MCP tool error" }
    message = unixAbsPathRegex.replace(message, "[path]")
    message = windowsAbsPathRegex.replace(message, "[path]")
    message = packageClassRegex.replace(message, "[internal]")
    message = message.replace(Regex("\\s+"), " ").trim()
    if (message.isBlank()) {
        message = "Unexpected MCP tool error"
    }
    if (message.length > MAX_ERROR_MESSAGE_LENGTH) {
        message = message.take(MAX_ERROR_MESSAGE_LENGTH).trimEnd() + "..."
    }
    return message
}
