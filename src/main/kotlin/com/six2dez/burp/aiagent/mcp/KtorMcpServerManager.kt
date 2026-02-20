package com.six2dez.burp.aiagent.mcp

import burp.api.montoya.MontoyaApi
import io.ktor.http.HttpMethod
import io.ktor.http.HttpStatusCode
import io.ktor.server.application.*
import io.ktor.server.engine.*
import io.ktor.server.engine.applicationEnvironment
import io.ktor.server.engine.connector
import io.ktor.server.engine.sslConnector
import io.ktor.server.netty.*
import io.ktor.server.plugins.cors.routing.*
import io.ktor.server.response.*
import io.ktor.server.routing.*
import io.modelcontextprotocol.kotlin.sdk.Implementation
import io.modelcontextprotocol.kotlin.sdk.ServerCapabilities
import io.modelcontextprotocol.kotlin.sdk.server.Server
import io.modelcontextprotocol.kotlin.sdk.server.ServerOptions
import io.modelcontextprotocol.kotlin.sdk.server.mcp
import com.six2dez.burp.aiagent.config.McpSettings
import com.six2dez.burp.aiagent.mcp.tools.registerTools
import com.six2dez.burp.aiagent.redact.PrivacyMode
import java.security.MessageDigest
import java.net.URI
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit

class KtorMcpServerManager(private val api: MontoyaApi) : McpServerManager {
    private var server: EmbeddedServer<*, *>? = null
    private val executor: ExecutorService = Executors.newSingleThreadExecutor()

    override fun start(settings: McpSettings, privacyMode: PrivacyMode, determinismMode: Boolean, callback: (McpServerState) -> Unit) {
        callback(McpServerState.Starting)
        executor.submit {
            try {
                server?.stop(1000, 5000)
                server = null

                if (settings.externalEnabled && !settings.tlsEnabled) {
                    throw IllegalStateException("External MCP access requires TLS. Enable TLS to continue.")
                }
                if (!settings.externalEnabled && !isLoopbackHost(settings.host)) {
                    throw IllegalStateException("MCP host must be loopback when external access is disabled.")
                }

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

                val environment = applicationEnvironment { }
                val serverInstance = embeddedServer(Netty, environment, configure = {
                    if (settings.tlsEnabled) {
                        val tlsMaterial = McpTls.resolve(settings)
                            ?: throw IllegalStateException("TLS enabled but keystore not available.")
                        sslConnector(
                            keyStore = tlsMaterial.keyStore,
                            keyAlias = tlsMaterial.keyAlias,
                            keyStorePassword = { tlsMaterial.password },
                            privateKeyPassword = { tlsMaterial.password }
                        ) {
                            host = settings.host
                            port = settings.port
                        }
                    } else {
                        connector {
                            host = settings.host
                            port = settings.port
                        }
                    }
                }) {
                    install(CORS) {
                        if (!settings.externalEnabled) {
                            allowHost("localhost:${settings.port}")
                            allowHost("127.0.0.1:${settings.port}")
                        } else {
                            anyHost()
                        }
                        allowMethod(HttpMethod.Get)
                        allowMethod(HttpMethod.Post)
                        allowHeader("Content-Type")
                        allowHeader("Accept")
                        allowHeader("Authorization")
                        allowHeader("Last-Event-ID")
                        allowCredentials = false
                        allowNonSimpleContentTypes = true
                        maxAgeInSeconds = 3600
                    }

                    routing {
                        get("/__mcp/health") {
                            if (settings.externalEnabled) {
                                val authHeader = call.request.headers["Authorization"].orEmpty()
                                if (!isAuthorized(authHeader, settings.token)) {
                                    call.respond(HttpStatusCode.Unauthorized)
                                    return@get
                                }
                            }
                            call.response.headers.append("X-Burp-AI-Agent", "mcp")
                            call.respondText("ok")
                        }
                        post("/__mcp/shutdown") {
                            val authHeader = call.request.headers["Authorization"].orEmpty()
                            if (!isAuthorized(authHeader, settings.token)) {
                                call.respond(HttpStatusCode.Unauthorized)
                                return@post
                            }
                            call.respondText("shutting down")
                            executor.submit {
                                try {
                                    server?.stop(1000, 5000)
                                } catch (e: Exception) {
                                    api.logging().logToError("MCP shutdown failed: ${e.message}")
                                }
                            }
                        }
                    }

                    intercept(ApplicationCallPipeline.Call) {
                        if (settings.externalEnabled) {
                            val authHeader = call.request.headers["Authorization"].orEmpty()
                            if (!isAuthorized(authHeader, settings.token)) {
                                call.respond(HttpStatusCode.Unauthorized)
                                return@intercept
                            }
                        }

                        if (!settings.externalEnabled) {
                            val origin = call.request.headers["Origin"]
                            val host = call.request.headers["Host"]
                            val referer = call.request.headers["Referer"]
                            val userAgent = call.request.headers["User-Agent"]

                            if (origin != null && !isValidOrigin(origin)) {
                                api.logging().logToOutput("Blocked MCP request from origin: $origin")
                                call.respond(HttpStatusCode.Forbidden)
                                return@intercept
                            } else if (isBrowserRequest(userAgent)) {
                                api.logging().logToOutput("Blocked browser MCP request without Origin header")
                                call.respond(HttpStatusCode.Forbidden)
                                return@intercept
                            }

                            if (host != null && !isValidHost(host, settings.port)) {
                                api.logging().logToOutput("Blocked MCP request from host: $host")
                                call.respond(HttpStatusCode.Forbidden)
                                return@intercept
                            }

                            if (referer != null && !isValidReferer(referer)) {
                                api.logging().logToOutput("Blocked MCP request from referer: $referer")
                                call.respond(HttpStatusCode.Forbidden)
                                return@intercept
                            }
                        }

                        call.response.headers.append("X-Frame-Options", "DENY")
                        call.response.headers.append("X-Content-Type-Options", "nosniff")
                        call.response.headers.append("Referrer-Policy", "same-origin")
                        call.response.headers.append("Content-Security-Policy", "default-src 'none'")
                    }

                    mcp {
                        mcpServer
                    }

                    mcpServer.registerTools(api, context)
                }

                server = serverInstance.apply { start(false) }
                api.logging().logToOutput("Started MCP server on ${settings.host}:${settings.port}")
                callback(McpServerState.Running)
            } catch (e: Exception) {
                api.logging().logToError(e)
                callback(McpServerState.Failed(e))
            }
        }
    }

    override fun stop(callback: (McpServerState) -> Unit) {
        callback(McpServerState.Stopping)
        executor.submit {
            try {
                server?.stop(1000, 5000)
                server = null
                api.logging().logToOutput("Stopped MCP server")
                callback(McpServerState.Stopped)
            } catch (e: Exception) {
                api.logging().logToError(e)
                callback(McpServerState.Failed(e))
            }
        }
    }

    override fun shutdown() {
        server?.stop(1000, 5000)
        server = null
        executor.shutdown()
        executor.awaitTermination(10, TimeUnit.SECONDS)
    }

    private fun isAuthorized(authHeader: String, token: String): Boolean {
        val expected = "Bearer $token"
        return constantTimeEquals(authHeader, expected)
    }

    private fun constantTimeEquals(left: String, right: String): Boolean {
        val leftBytes = left.toByteArray(Charsets.UTF_8)
        val rightBytes = right.toByteArray(Charsets.UTF_8)
        return MessageDigest.isEqual(leftBytes, rightBytes)
    }

    private fun isLoopbackHost(host: String): Boolean {
        val normalized = host.lowercase()
        return normalized == "localhost" || normalized == "127.0.0.1" || normalized == "::1"
    }

    private fun isValidOrigin(origin: String): Boolean {
        return try {
            val url = URI(origin).toURL()
            val hostname = url.host.lowercase()
            hostname == "localhost" || hostname == "127.0.0.1"
        } catch (_: Exception) {
            false
        }
    }

    private fun isBrowserRequest(userAgent: String?): Boolean {
        if (userAgent == null) return false
        val userAgentLower = userAgent.lowercase()
        val browserIndicators = listOf(
            "mozilla/", "chrome/", "safari/", "webkit/", "gecko/", "firefox/", "edge/", "opera/", "browser"
        )
        return browserIndicators.any { userAgentLower.contains(it) }
    }

    private fun isValidHost(host: String, expectedPort: Int): Boolean {
        return try {
            val parts = host.split(":")
            val hostname = parts[0].lowercase()
            val port = if (parts.size > 1) parts[1].toIntOrNull() else null
            if (hostname != "localhost" && hostname != "127.0.0.1") return false
            if (port != null && port != expectedPort) return false
            true
        } catch (_: Exception) {
            false
        }
    }

    private fun isValidReferer(referer: String): Boolean {
        return try {
            val url = URI(referer).toURL()
            val hostname = url.host.lowercase()
            hostname == "localhost" || hostname == "127.0.0.1"
        } catch (_: Exception) {
            false
        }
    }
}
