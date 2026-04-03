package com.six2dez.burp.aiagent.mcp

import burp.api.montoya.MontoyaApi
import com.six2dez.burp.aiagent.audit.AiRequestLogger
import com.six2dez.burp.aiagent.config.McpSettings
import com.six2dez.burp.aiagent.mcp.tools.registerTools
import com.six2dez.burp.aiagent.redact.PrivacyMode
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

class McpStdioBridge(
    private val api: MontoyaApi,
    private val contextFactory: McpRuntimeContextFactory = McpRuntimeContextFactory(api)
) {
    private var scope: CoroutineScope? = null
    private var job: Job? = null
    private var server: Server? = null
    private var transport: StdioServerTransport? = null

    fun setAiRequestLogger(logger: AiRequestLogger) {
        contextFactory.aiRequestLogger = logger
    }

    fun start(settings: McpSettings, privacyMode: PrivacyMode, determinismMode: Boolean) {
        stop()
        val context = contextFactory.create(settings, privacyMode, determinismMode)

        val mcpServer = Server(
            serverInfo = Implementation("burp-ai-agent", "0.1.0"),
            options = ServerOptions(
                capabilities = ServerCapabilities(
                    tools = ServerCapabilities.Tools(listChanged = false)
                )
            )
        )
        mcpServer.registerTools(api, context)

        val source = System.`in`.asSource().buffered()
        val sink = System.out.asSink().buffered()
        val stdioTransport = StdioServerTransport(source, sink)

        server = mcpServer
        transport = stdioTransport

        val newScope = CoroutineScope(Dispatchers.IO + SupervisorJob())
        scope = newScope
        job = newScope.launch {
            mcpServer.connect(stdioTransport)
            stdioTransport.start()
        }

        api.logging().logToOutput("MCP stdio bridge started.")
    }

    fun stop() {
        job?.cancel()
        job = null
        val currentTransport = transport
        val currentServer = server
        val currentScope = scope
        transport = null
        server = null
        scope = null
        runBlocking {
            withTimeoutOrNull(5000) { currentTransport?.close() }
            withTimeoutOrNull(5000) { currentServer?.close() }
        }
        currentScope?.coroutineContext?.get(kotlinx.coroutines.Job)?.cancel()
    }
}
