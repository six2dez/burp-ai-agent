package com.six2dez.burp.aiagent.mcp.tools

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

@OptIn(InternalSerializationApi::class)
inline fun <reified I : Any> Server.mcpTool(
    description: String,
    context: McpToolContext,
    toolName: String? = null,
    crossinline execute: I.() -> String
) {
    val name = toolName ?: I::class.simpleName?.toLowerSnakeCase() ?: error("Missing tool name for ${I::class}")
    addTool(
        name = name,
        description = description,
        inputSchema = I::class.asInputSchema(),
        handler = { request ->
            runTool(context, name) {
                val input = json.decodeFromJsonElement(
                    I::class.serializer(),
                    request.arguments
                )
                context.redactIfNeeded(execute(input))
            }
        }
    )
}

@OptIn(ExperimentalTypeInference::class)
@OverloadResolutionByLambdaReturnType
@JvmName("mcpToolUnit")
inline fun <reified I : Any> Server.mcpTool(
    description: String,
    context: McpToolContext,
    toolName: String? = null,
    crossinline execute: I.() -> Unit
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
    crossinline execute: () -> String
) {
    addTool(
        name = name,
        description = description,
        inputSchema = Tool.Input(),
        handler = {
            runTool(context, name) {
                context.redactIfNeeded(execute())
            }
        }
    )
}

inline fun <reified I : Paginated> Server.mcpPaginatedTool(
    description: String,
    context: McpToolContext,
    toolName: String? = null,
    crossinline execute: I.() -> Sequence<String>
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

fun String.toLowerSnakeCase(): String {
    return this
        .replace(Regex("([a-z0-9])([A-Z])"), "$1_$2")
        .replace(Regex("([A-Z])([A-Z][a-z])"), "$1_$2")
        .replace(Regex("[\\s-]+"), "_")
        .lowercase()
}

interface Paginated {
    val count: Int
    val offset: Int
}

@PublishedApi
internal fun runTool(
    context: McpToolContext,
    name: String,
    execute: () -> String
): CallToolResult {
    if (!context.isToolEnabled(name)) {
        return CallToolResult(
            content = listOf(TextContent("Tool disabled: $name")),
            isError = true
        )
    }
    if (context.isUnsafeTool(name) && !context.unsafeEnabled) {
        return CallToolResult(
            content = listOf(TextContent("Unsafe mode is disabled for tool: $name")),
            isError = true
        )
    }
    if (!context.limiter.tryAcquire()) {
        return CallToolResult(
            content = listOf(TextContent("Too many concurrent MCP requests.")),
            isError = true
        )
    }
    return try {
        val output = context.limitOutput(execute())
        CallToolResult(content = listOf(TextContent(output)))
    } catch (e: kotlinx.serialization.SerializationException) {
        // Extract missing field from the error message for a cleaner message
        val msg = e.message.orEmpty()
        val fieldMatch = Regex("Field '([^']+)' is required").find(msg)
        val cleanMsg = if (fieldMatch != null) {
            "Missing required parameter: ${fieldMatch.groupValues[1]}"
        } else {
            "Invalid tool arguments: $msg"
        }
        CallToolResult(
            content = listOf(TextContent(cleanMsg)),
            isError = true
        )
    } catch (e: Exception) {
        CallToolResult(
            content = listOf(TextContent(e.message ?: "Unknown error")),
            isError = true
        )
    } finally {
        context.limiter.release()
    }
}
