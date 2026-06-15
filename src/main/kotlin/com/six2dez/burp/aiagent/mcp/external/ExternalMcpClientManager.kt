package com.six2dez.burp.aiagent.mcp.external

import com.six2dez.burp.aiagent.audit.AuditLogger
import com.six2dez.burp.aiagent.util.SsrfGuard
import io.ktor.client.HttpClient
import io.ktor.client.engine.cio.CIO
import io.ktor.client.plugins.sse.SSE
import io.modelcontextprotocol.kotlin.sdk.Implementation
import io.modelcontextprotocol.kotlin.sdk.ListToolsRequest
import io.modelcontextprotocol.kotlin.sdk.TextContent
import io.modelcontextprotocol.kotlin.sdk.client.Client
import io.modelcontextprotocol.kotlin.sdk.client.ClientOptions
import io.modelcontextprotocol.kotlin.sdk.client.SseClientTransport
import io.modelcontextprotocol.kotlin.sdk.client.StdioClientTransport
import io.modelcontextprotocol.kotlin.sdk.shared.Transport
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
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.Executors
import java.util.concurrent.ScheduledExecutorService
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicReference
import kotlin.math.min
import kotlin.math.pow

// Trust-boundary constants (SC2) — every external tool result is wrapped before entering AI context.
private const val TRUST_BOUNDARY_OPEN = "[EXTERNAL-TOOL-RESULT:"
private const val TRUST_BOUNDARY_CLOSE = "[/EXTERNAL-TOOL-RESULT]"

// Reconnect policy constants (mirrored from McpSupervisor pattern).
private const val MAX_RECONNECT_ATTEMPTS = 3
private const val RECONNECT_DELAY_BASE_MS = 1000L
private const val RECONNECT_DELAY_MAX_MS = 30_000L
private const val SHUTDOWN_TIMEOUT_MS = 5000L

/**
 * Describes a single tool exposed by an external MCP server.
 *
 * The [name] field uses the fully-qualified `ext:<serverName>:<originalName>` form required by
 * the D-04 disambiguation contract. Callers must strip the `ext:<serverName>:` prefix before
 * forwarding the call to the remote server via [ExternalMcpClientManager.callTool].
 */
data class ExternalToolDescriptor(
    val serverName: String,
    val name: String,
    val description: String,
)

/**
 * Lifecycle state for a single external MCP server connection.
 * Mirrors [com.six2dez.burp.aiagent.mcp.McpServerState].
 */
sealed class ExternalMcpConnectionState {
    data object Disconnected : ExternalMcpConnectionState()

    data object Connecting : ExternalMcpConnectionState()

    data class Connected(
        val toolCount: Int,
    ) : ExternalMcpConnectionState()

    data class Retrying(
        val attempt: Int,
        val maxAttempts: Int,
    ) : ExternalMcpConnectionState()

    data class Error(
        val message: String,
    ) : ExternalMcpConnectionState()
}

/**
 * Internal holder for per-server connection state.
 */
private data class ServerConnection(
    val config: ExternalMcpServerConfig,
    var client: Client? = null,
    var transport: Transport? = null,
    var process: Process? = null,
    val scope: CoroutineScope,
    var job: Job? = null,
    val stateRef: AtomicReference<ExternalMcpConnectionState> =
        AtomicReference(ExternalMcpConnectionState.Disconnected),
    val cachedTools: CopyOnWriteArrayList<ExternalToolDescriptor> = CopyOnWriteArrayList(),
    var retryCount: Int = 0,
)

/**
 * Manages the lifecycle of all configured external MCP server connections.
 *
 * Responsibilities:
 * - SSE connections via [SseClientTransport] with a dedicated [HttpClient] (CIO engine).
 * - stdio connections via [StdioClientTransport] using [ProcessBuilder] with a List argument
 *   (no shell expansion — T-16-03-CMD mitigation).
 * - Prefixes all external tool names with `ext:<serverName>:<tool>` (D-04).
 * - Wraps every [callTool] result in the trust-boundary marker (SC2 — T-16-03-PI mitigation).
 * - Audit-logs every tool invocation behind the [auditLogger] enabled gate (CR-02 allocation
 *   guard: allocations inside the if-block only when audit is active).
 * - Reconnect with exponential backoff up to [MAX_RECONNECT_ATTEMPTS] (via
 *   [ScheduledExecutorService] — mirrors [com.six2dez.burp.aiagent.mcp.McpSupervisor]).
 * - Bounded shutdown with [SHUTDOWN_TIMEOUT_MS] and [Process.destroyForcibly] for stdio
 *   (T-16-03-ZOM mitigation).
 *
 * Crypto contract: [ExternalMcpServerConfig.bearerToken] is ALWAYS plaintext on arrival — it
 * was decrypted by [com.six2dez.burp.aiagent.config.AgentSettingsRepository.loadExternalMcpServers].
 * This class MUST NOT call SecretCipher.decrypt.
 *
 * @param auditLogger optional [AuditLogger] instance for guarding allocation (CR-02).
 * @param clientFactory override for tests to inject a mock [Client].
 * @param scheduler optional [ScheduledExecutorService] for reconnect — overridden in tests.
 */
class ExternalMcpClientManager(
    private val auditLogger: AuditLogger? = null,
    private val clientFactory: (Implementation, ClientOptions) -> Client = { impl, opts -> Client(impl, opts) },
    private val scheduler: ScheduledExecutorService = Executors.newSingleThreadScheduledExecutor(),
    /**
     * Factory for spawning stdio subprocess — overridden in tests to inject a mock [Process].
     * Default implementation uses [ProcessBuilder] with a List (no shell expansion).
     */
    private val processFactory: (command: List<String>, envVars: Map<String, String>) -> Process = { cmd, env ->
        val pb = ProcessBuilder(cmd)
        pb.redirectErrorStream(true)
        pb.redirectInput(ProcessBuilder.Redirect.PIPE)
        pb.redirectOutput(ProcessBuilder.Redirect.PIPE)
        env.forEach { (k, v) -> pb.environment()[k] = v }
        pb.start()
    },
) {
    // Shared scope with SupervisorJob: one child-job failure does not cancel siblings.
    private val managerScope = CoroutineScope(Dispatchers.IO + SupervisorJob())

    // Dedicated HttpClient for SSE transport — NEVER reuse the Ktor Netty server instance.
    private val httpClient =
        HttpClient(CIO) {
            install(SSE)
        }

    // All active server connections, thread-safe.
    private val connections = CopyOnWriteArrayList<ServerConnection>()

    /**
     * Starts connections to all enabled servers in [configs].
     * Each server gets an independent child coroutine on [managerScope].
     */
    fun start(configs: List<ExternalMcpServerConfig>) {
        configs.filter { it.enabled }.forEach { config ->
            val connection =
                ServerConnection(
                    config = config,
                    scope = managerScope,
                )
            connections.add(connection)
            connection.job =
                managerScope.launch {
                    connectServer(connection)
                }
        }
    }

    @Suppress("TooGenericExceptionCaught")
    private suspend fun connectServer(connection: ServerConnection) {
        val config = connection.config
        val serverName = config.name

        connection.stateRef.set(ExternalMcpConnectionState.Connecting)

        try {
            val transport: Transport
            when (config.transport) {
                ExternalMcpTransport.SSE -> {
                    // SSRF advisory check — soft warning only (non-blocking per SC3 / D-01).
                    if (SsrfGuard.isPrivateOrLinkLocal(config.url)) {
                        logWarning(serverName, "SSE URL resolves to a private/link-local address (SSRF risk)")
                    }
                    // Use config.bearerToken DIRECTLY — it is already plaintext (Plan 16-02 contract).
                    // DO NOT call cipher.decrypt here.
                    transport =
                        SseClientTransport(
                            client = httpClient,
                            urlString = config.url,
                            requestBuilder = {
                                if (config.bearerToken.isNotBlank()) {
                                    headers.append("Authorization", "Bearer ${config.bearerToken}")
                                }
                            },
                        )
                    connection.transport = transport
                }
                ExternalMcpTransport.STDIO -> {
                    // Security: processFactory uses ProcessBuilder(List) — prevents shell expansion (T-16-03-CMD).
                    // Do NOT call Runtime.exec(String) or ProcessBuilder(String) directly.
                    val command = config.command + config.extraArgs
                    // Inject only user-configured env vars — do NOT inherit Burp's environment
                    // (prevents secret leakage via ANTHROPIC_API_KEY etc.).
                    val process = processFactory(command, config.envVars)
                    connection.process = process

                    transport =
                        StdioClientTransport(
                            input = process.inputStream.asSource().buffered(),
                            output = process.outputStream.asSink().buffered(),
                        )
                    connection.transport = transport
                }
            }

            val client =
                clientFactory(
                    Implementation("burp-ai-agent-ext", "0.9.0"),
                    ClientOptions(),
                )
            connection.client = client

            client.connect(transport)

            val toolsResult = client.listTools(ListToolsRequest(), null)
            val descriptors =
                toolsResult
                    ?.tools
                    ?.map { tool ->
                        ExternalToolDescriptor(
                            serverName = serverName,
                            name = "ext:$serverName:${tool.name}",
                            description = tool.description.orEmpty(),
                        )
                    }.orEmpty()

            connection.cachedTools.clear()
            connection.cachedTools.addAll(descriptors)
            connection.retryCount = 0
            connection.stateRef.set(ExternalMcpConnectionState.Connected(descriptors.size))
        } catch (e: kotlinx.coroutines.CancellationException) {
            // Re-throw CancellationException — coroutine was cancelled intentionally (e.g. stop()).
            // Do NOT schedule reconnect on cancellation.
            throw e
        } catch (e: Exception) {
            scheduleReconnect(connection, e)
        }
    }

    private fun scheduleReconnect(
        connection: ServerConnection,
        cause: Exception,
    ) {
        val attempt = ++connection.retryCount
        if (attempt > MAX_RECONNECT_ATTEMPTS) {
            val msg = "Connection failed after $MAX_RECONNECT_ATTEMPTS attempts: ${cause.message}"
            connection.stateRef.set(ExternalMcpConnectionState.Error(msg))
            return
        }

        val delayMs =
            min(
                (RECONNECT_DELAY_BASE_MS * (2.0.pow(attempt - 1))).toLong(),
                RECONNECT_DELAY_MAX_MS,
            )
        connection.stateRef.set(
            ExternalMcpConnectionState.Retrying(attempt, MAX_RECONNECT_ATTEMPTS),
        )

        scheduler.schedule(
            {
                if (connection.config.enabled) {
                    connection.job =
                        managerScope.launch {
                            connectServer(connection)
                        }
                }
            },
            delayMs,
            TimeUnit.MILLISECONDS,
        )
    }

    /**
     * Returns all tool descriptors across all connected servers. Thread-safe.
     */
    fun availableTools(): List<ExternalToolDescriptor> = connections.flatMap { it.cachedTools.toList() }

    /**
     * Calls a tool on the named external server.
     *
     * The [toolName] parameter must be the RAW tool name as declared by the remote server (i.e.
     * the `ext:<serverName>:` prefix must already be stripped by the caller before passing here).
     *
     * Every result is wrapped with the trust-boundary marker (SC2 / T-16-03-PI).
     * Every invocation is audit-logged when audit is enabled (CR-02 allocation guard).
     * The bearer token is NEVER included in audit output (T-16-03-TL).
     */
    @Suppress("TooGenericExceptionCaught", "ReturnCount")
    suspend fun callTool(
        serverName: String,
        toolName: String,
        args: Map<String, Any?>,
    ): String {
        val connection =
            connections.firstOrNull { it.config.name == serverName }
                ?: return wrapWithTrustBoundary(serverName, "Error: server '$serverName' not found")

        val client =
            connection.client
                ?: return wrapWithTrustBoundary(serverName, "Error: server '$serverName' not connected")

        return try {
            val callResult = client.callTool(toolName, args, false, null)
            val rawText =
                callResult
                    ?.content
                    ?.filterIsInstance<TextContent>()
                    ?.joinToString("\n") { it.text.orEmpty() }
                    .orEmpty()

            val wrapped = wrapWithTrustBoundary(serverName, rawText)

            // CR-02 allocation guard: only allocate buildMap when audit is active.
            if (auditLogger?.isEnabled() == true) {
                AuditLogger.emitGlobal(
                    "external_mcp_call",
                    buildMap {
                        put("server", serverName)
                        put("tool", toolName)
                        put("status", "ok")
                    },
                )
            }

            wrapped
        } catch (e: Exception) {
            // CR-02 allocation guard on error path too.
            if (auditLogger?.isEnabled() == true) {
                AuditLogger.emitGlobal(
                    "external_mcp_call",
                    buildMap {
                        put("server", serverName)
                        put("tool", toolName)
                        put("status", "error")
                        put("error", e.message.orEmpty())
                        // Note: bearer token is never included in audit output (T-16-03-TL).
                    },
                )
            }
            wrapWithTrustBoundary(serverName, "Error calling tool '$toolName': ${e.message.orEmpty()}")
        }
    }

    /**
     * Wraps [rawResult] in the trust-boundary marker for prompt-injection defense (SC2).
     *
     * Format: `[EXTERNAL-TOOL-RESULT:<serverName>]\n<rawResult>\n[/EXTERNAL-TOOL-RESULT]`
     */
    @Suppress("MemberVisibilityCanBePrivate")
    internal fun wrapWithTrustBoundary(
        serverName: String,
        rawResult: String,
    ): String = "$TRUST_BOUNDARY_OPEN$serverName]\n$rawResult\n$TRUST_BOUNDARY_CLOSE"

    /**
     * Returns the current connection state for [serverName], or [ExternalMcpConnectionState.Disconnected]
     * if the server is not registered.
     */
    fun connectionState(serverName: String): ExternalMcpConnectionState =
        connections
            .firstOrNull { it.config.name == serverName }
            ?.stateRef
            ?.get()
            ?: ExternalMcpConnectionState.Disconnected

    /**
     * Stops all connections and the manager scope.
     *
     * For each server:
     * 1. Cancel the coroutine job.
     * 2. Close transport and client with [SHUTDOWN_TIMEOUT_MS] bounded timeout.
     * 3. [Process.destroyForcibly] for stdio servers after close (T-16-03-ZOM mitigation).
     *
     * Mirrors [com.six2dez.burp.aiagent.mcp.McpStdioBridge.stop] pattern.
     */
    fun stop() {
        connections.forEach { connection ->
            connection.job?.cancel()
            connection.job = null

            val currentTransport = connection.transport
            val currentClient = connection.client
            val currentProcess = connection.process

            connection.transport = null
            connection.client = null
            connection.process = null

            runBlocking {
                withTimeoutOrNull(SHUTDOWN_TIMEOUT_MS) {
                    try {
                        currentTransport?.close()
                    } catch (_: Exception) {
                        // Suppress "already closed" or similar cleanup errors — destroyForcibly follows.
                    }
                }
                withTimeoutOrNull(SHUTDOWN_TIMEOUT_MS) {
                    try {
                        currentClient?.close()
                    } catch (_: Exception) {
                        // Suppress close errors — connection is being torn down.
                    }
                }
            }

            // destroyForcibly must be called AFTER close() to prevent zombie processes.
            currentProcess?.destroyForcibly()

            connection.stateRef.set(ExternalMcpConnectionState.Disconnected)
            connection.cachedTools.clear()
        }

        connections.clear()
        managerScope.coroutineContext[kotlinx.coroutines.Job]?.cancel()

        scheduler.shutdown()
        try {
            scheduler.awaitTermination(SHUTDOWN_TIMEOUT_MS, TimeUnit.MILLISECONDS)
        } catch (_: InterruptedException) {
            Thread.currentThread().interrupt()
        }

        runBlocking {
            withTimeoutOrNull(SHUTDOWN_TIMEOUT_MS) { httpClient.close() }
        }
    }

    private fun logWarning(
        serverName: String,
        message: String,
    ) {
        // Log-only; no network call. SsrfGuard is advisory (non-blocking per SC3 / D-01).
        System.err.println("[ExternalMcpClientManager] WARNING [$serverName]: $message")
    }
}
