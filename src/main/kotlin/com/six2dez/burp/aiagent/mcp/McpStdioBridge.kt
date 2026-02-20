package com.six2dez.burp.aiagent.mcp

import burp.api.montoya.MontoyaApi
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
import kotlinx.io.RawSink
import kotlinx.io.RawSource
import kotlinx.io.Sink
import kotlinx.io.Source
import kotlinx.io.asSink
import kotlinx.io.asSource

class McpStdioBridge(private val api: MontoyaApi) {
    private val scope = CoroutineScope(Dispatchers.IO + SupervisorJob())
    private var job: Job? = null
    private var server: Server? = null
    private var transport: StdioServerTransport? = null

    fun start(settings: McpSettings, privacyMode: PrivacyMode, determinismMode: Boolean) {
        stop()
        val tools = McpToolCatalog.mergeWithDefaults(settings.toolToggles)
        val unsafeTools = McpToolCatalog.unsafeToolIds()
        val limiter = McpRequestLimiter(settings.maxConcurrentRequests)
        val hostSalt = settings.hostAnonymizationSalt.ifBlank { "mcp-${settings.token.take(12)}" }
        val context = McpToolContext(
            api = api,
            privacyMode = privacyMode,
            determinismMode = determinismMode,
            hostSalt = hostSalt,
            toolToggles = tools,
            unsafeEnabled = settings.unsafeEnabled,
            unsafeTools = unsafeTools,
            limiter = limiter,
            edition = api.burpSuite().version().edition(),
            maxBodyBytes = settings.maxBodyBytes
        )

        val mcpServer = Server(
            serverInfo = Implementation("burp-ai-agent", com.six2dez.burp.aiagent.config.Defaults.MCP_VERSION),
            options = ServerOptions(
                capabilities = ServerCapabilities(
                    tools = ServerCapabilities.Tools(listChanged = false)
                )
            )
        )
        mcpServer.registerTools(api, context)

        val source = createSource(System.`in`.asSource())
        val sink = createSink(System.out.asSink())
        val stdioTransport = StdioServerTransport(source, sink)

        server = mcpServer
        transport = stdioTransport

        job = scope.launch {
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
        transport = null
        server = null
        if (currentTransport != null) {
            runBlocking { currentTransport.close() }
        }
        if (currentServer != null) {
            runBlocking { currentServer.close() }
        }
    }

    private fun createSource(raw: RawSource): Source {
        return try {
            val clazz = Class.forName("kotlinx.io.RealSource")
            val ctor = clazz.getConstructor(RawSource::class.java)
            ctor.newInstance(raw) as Source
        } catch (e: Exception) {
            throw IllegalStateException("Failed to initialize stdio Source: ${e.message}", e)
        }
    }

    private fun createSink(raw: RawSink): Sink {
        return try {
            val clazz = Class.forName("kotlinx.io.RealSink")
            val ctor = clazz.getConstructor(RawSink::class.java)
            ctor.newInstance(raw) as Sink
        } catch (e: Exception) {
            throw IllegalStateException("Failed to initialize stdio Sink: ${e.message}", e)
        }
    }
}
