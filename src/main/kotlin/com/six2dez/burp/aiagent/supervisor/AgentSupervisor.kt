package com.six2dez.burp.aiagent.supervisor

import burp.api.montoya.MontoyaApi
import com.six2dez.burp.aiagent.audit.AuditLogger
import com.six2dez.burp.aiagent.backends.AgentConnection
import com.six2dez.burp.aiagent.backends.BackendLaunchConfig
import com.six2dez.burp.aiagent.backends.BackendRegistry
import com.six2dez.burp.aiagent.backends.DiagnosableConnection
import com.six2dez.burp.aiagent.config.AgentSettings
import com.six2dez.burp.aiagent.config.Defaults
import com.six2dez.burp.aiagent.redact.PrivacyMode
import com.six2dez.burp.aiagent.util.HeaderParser
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicLong
import java.util.concurrent.atomic.AtomicReference
import java.util.UUID
import java.util.concurrent.locks.ReentrantLock
import okhttp3.OkHttpClient
import okhttp3.Request
import kotlin.concurrent.withLock

class AgentSupervisor(
    private val api: MontoyaApi,
    private val registry: BackendRegistry,
    private val audit: AuditLogger,
    private val workerPool: ExecutorService
) {
    data class Status(val state: String, val backendId: String?)

    private sealed class AgentState {
        data object Idle : AgentState()
        data class Running(
            val backendId: String,
            val sessionId: String,
            val connection: AgentConnection,
            val launchConfig: BackendLaunchConfig,
            val startedAt: Long
        ) : AgentState()
    }

    private val stateRef = AtomicReference<AgentState>(AgentState.Idle)
    private val settingsRef = AtomicReference<AgentSettings?>(null)
    private val lastErrorRef = AtomicReference<String?>(null)
    private val crashCount = AtomicInteger(0)
    private val lastRestartAt = AtomicLong(0)
    private val autoRestartSuppressed = AtomicReference<String?>(null)
    private val immediateCrashCount = AtomicInteger(0)
    private val chatSessionManager = ChatSessionManager()
    private val services = java.util.concurrent.ConcurrentHashMap<String, Process>()
    private val lifecycleLock = ReentrantLock()
    private val httpClient = OkHttpClient.Builder()
        .connectTimeout(java.time.Duration.ofSeconds(3))
        .readTimeout(java.time.Duration.ofSeconds(3))
        .build()
    private val monitorExec = Executors.newSingleThreadScheduledExecutor()

    init {
        monitorExec.scheduleAtFixedRate(
            { checkHealth() },
            Defaults.HEALTH_CHECK_INTERVAL_MS,
            Defaults.HEALTH_CHECK_INTERVAL_MS,
            TimeUnit.MILLISECONDS
        )
    }

    fun applySettings(settings: AgentSettings) {
        settingsRef.set(settings)
    }

    fun currentSessionId(): String? {
        return (stateRef.get() as? AgentState.Running)?.sessionId
    }

    fun lastStartError(): String? = lastErrorRef.get()

    fun startOrAttach(backendId: String): Boolean {
        return lifecycleLock.withLock {
            lastErrorRef.set(null)
            autoRestartSuppressed.set(null)
            immediateCrashCount.set(0)

            // Check if already running the requested backend
            val current = stateRef.get()
            if (current is AgentState.Running && current.backendId == backendId && current.connection.isAlive()) {
                return@withLock true
            }

            stop()

            val backend = registry.get(backendId)
            if (backend == null) {
                val msg = "Backend not found: $backendId"
                lastErrorRef.set(msg)
                api.logging().logToError(msg)
                return@withLock false
            }

            try {
                val sessionId = "session-" + UUID.randomUUID().toString()
                val launchConfig = buildLaunchConfig(backendId, sessionId, embeddedMode = true)
                api.logging().logToOutput("Launching backend $backendId with config: $launchConfig")
                val conn = backend.launch(launchConfig)

                val newState = AgentState.Running(
                    backendId = backendId,
                    sessionId = sessionId,
                    connection = conn,
                    launchConfig = launchConfig,
                    startedAt = System.currentTimeMillis()
                )
                stateRef.set(newState)

                audit.logEvent("session_start", mapOf("backendId" to backendId, "sessionId" to sessionId, "config" to launchConfig))
                true
            } catch (e: Exception) {
                val msg = "Failed to launch backend $backendId: ${e.message}"
                lastErrorRef.set(msg)
                api.logging().logToError(msg)
                false
            }
        }
    }

    fun isOllamaHealthy(settings: AgentSettings): Boolean {
        val url = settings.ollamaUrl.trimEnd('/') + "/api/tags"
        return try {
            val headers = HeaderParser.withBearerToken(
                settings.ollamaApiKey,
                HeaderParser.parse(settings.ollamaHeaders)
            )
            val req = Request.Builder()
                .url(url)
                .apply { headers.forEach { (name, value) -> header(name, value) } }
                .get()
                .build()
            httpClient.newCall(req).execute().use { it.isSuccessful }
        } catch (_: Exception) {
            false
        }
    }

    fun startOllamaService(settings: AgentSettings): Boolean {
        val cmd = settings.ollamaServeCmd
        if (cmd.isBlank()) {
            api.logging().logToError("Ollama serve command is empty.")
            return false
        }
        return startService("ollama-serve", cmd)
    }

    fun isLmStudioHealthy(settings: AgentSettings): Boolean {
        val url = settings.lmStudioUrl.trimEnd('/') + "/v1/models"
        return try {
            val headers = HeaderParser.withBearerToken(
                settings.lmStudioApiKey,
                HeaderParser.parse(settings.lmStudioHeaders)
            )
            val req = Request.Builder()
                .url(url)
                .apply { headers.forEach { (name, value) -> header(name, value) } }
                .get()
                .build()
            httpClient.newCall(req).execute().use { it.isSuccessful }
        } catch (_: Exception) {
            false
        }
    }

    fun startLmStudioService(settings: AgentSettings): Boolean {
        val cmd = settings.lmStudioServerCmd
        if (cmd.isBlank()) {
            api.logging().logToError("LM Studio server command is empty.")
            return false
        }
        return startService("lmstudio-server", cmd)
    }

    fun isBackendHealthy(settings: AgentSettings): Boolean {
        return when (settings.preferredBackendId) {
            "ollama" -> isOllamaHealthy(settings)
            "lmstudio" -> isLmStudioHealthy(settings)
            "openai-compatible" -> {
                // Basic check for OpenAI compatible
                val url = settings.openAiCompatibleUrl.trimEnd('/') + "/models"
                try {
                    val headers = HeaderParser.withBearerToken(
                        settings.openAiCompatibleApiKey,
                        HeaderParser.parse(settings.openAiCompatibleHeaders)
                    )
                    val req = Request.Builder()
                        .url(url)
                        .apply { headers.forEach { (name, value) -> header(name, value) } }
                        .get()
                        .build()
                    httpClient.newCall(req).execute().close()
                    true
                } catch (_: Exception) {
                    false
                }
            }
            // CLI backends are considered "healthy" if configured (no easy poll)
            else -> true
        }
    }

    fun stop() {
        lifecycleLock.withLock {
            val prev = stateRef.getAndSet(AgentState.Idle)
            if (prev is AgentState.Running) {
                prev.connection.stop()
                audit.logEvent("session_stop", mapOf("backendId" to prev.backendId))
            }
            autoRestartSuppressed.set(null)
            immediateCrashCount.set(0)
        }
    }

    fun restart(): Boolean {
        return lifecycleLock.withLock {
            val current = stateRef.get()
            if (current !is AgentState.Running) return@withLock false
            val backendId = current.backendId
            stop()
            startOrAttach(backendId)
        }
    }

    fun send(
        text: String,
        contextJson: String?,
        privacyMode: PrivacyMode,
        determinismMode: Boolean,
        onChunk: (String) -> Unit,
        onComplete: (Throwable?) -> Unit
    ) {
        val current = stateRef.get()
        if (current !is AgentState.Running) {
            onComplete(IllegalStateException("No active session"))
            return
        }

        if (!current.connection.isAlive()) {
             onComplete(IllegalStateException("Session is not alive"))
             return
        }
        
        val sessionId = current.sessionId
        val backendId = current.backendId
        val launchConfig = current.launchConfig

        if (audit.isEnabled()) {
            val bundle = audit.buildPromptBundle(
                sessionId = sessionId,
                backendId = backendId,
                backendConfig = launchConfig,
                promptText = text,
                contextJson = contextJson,
                privacyMode = privacyMode,
                determinismMode = determinismMode
            )
            audit.logEvent("prompt", bundle)
            audit.writePromptBundle(bundle)
        }

        api.logging().logToOutput("AI send: backend=$backendId session=$sessionId")
        api.logging().logToOutput("AI connection: ${current.connection.javaClass.name}")
        current.connection.send(text,
            onChunk = { chunk ->
                audit.logEvent("agent_chunk", mapOf("backendId" to backendId, "chunk" to chunk))
                onChunk(chunk)
            },
            onComplete = { err ->
                audit.logEvent("prompt_complete", mapOf("backendId" to backendId, "error" to err?.message))
                if (err != null) {
                    api.logging().logToError("AI backend error ($backendId): ${err.message}")
                }
                onComplete(err)
            }
        )
    }

    fun sendChat(
        chatSessionId: String,
        backendId: String,
        text: String,
        contextJson: String?,
        privacyMode: PrivacyMode,
        determinismMode: Boolean,
        onChunk: (String) -> Unit,
        onComplete: (Throwable?) -> Unit
    ): AgentConnection? {
        lastErrorRef.set(null)
        val backend = registry.get(backendId)
        if (backend == null) {
            onComplete(IllegalStateException("Backend not found: $backendId"))
            return null
        }

        // Try to reuse an existing connection (for HTTP backends with conversation history)
        val existingConn = chatSessionManager.existingConnectionFor(chatSessionId, backendId)
        val connection: AgentConnection
        if (existingConn != null) {
            connection = existingConn
        } else {
            // Create a new connection with cliSessionId for CLI resume
            val cliSessionId = chatSessionManager.cliSessionIdFor(chatSessionId)
            val sessionId = "chat-session-" + java.util.UUID.randomUUID().toString()
            val launchConfig = buildLaunchConfig(backendId, sessionId, embeddedMode = true, cliSessionId = cliSessionId)
            try {
                connection = backend.launch(launchConfig)
            } catch (e: Exception) {
                val msg = "Failed to launch backend $backendId: ${e.message}"
                lastErrorRef.set(msg)
                api.logging().logToError(msg)
                onComplete(e)
                return null
            }
        }

        api.logging().logToOutput("AI chat send: backend=$backendId chatSession=$chatSessionId")
        connection.send(text,
            onChunk = { chunk ->
                audit.logEvent("agent_chunk", mapOf("backendId" to backendId, "chunk" to chunk))
                onChunk(chunk)
            },
            onComplete = { err ->
                audit.logEvent("prompt_complete", mapOf("backendId" to backendId, "error" to err?.message))
                if (err != null) {
                    api.logging().logToError("AI backend error ($backendId): ${err.message}")
                }
                // Update session state after completion (stores cliSessionId or connection for reuse)
                chatSessionManager.updateSession(chatSessionId, backendId, connection)
                onComplete(err)
            }
        )
        return connection
    }

    fun removeChatSession(chatSessionId: String) {
        chatSessionManager.removeSession(chatSessionId)
    }

    fun status(): Status {
        val current = stateRef.get()
        return when (current) {
            is AgentState.Idle -> Status("Idle", null)
            is AgentState.Running -> {
                if (current.connection.isAlive()) {
                    Status("Running", current.backendId)
                } else {
                    Status("Crashed", current.backendId)
                }
            }
        }
    }

    private fun buildLaunchConfig(backendId: String, sessionId: String, embeddedMode: Boolean, cliSessionId: String? = null): BackendLaunchConfig {
        val prefs = api.persistence().preferences()
        val settings = settingsRef.get()
        val determinism = settings?.determinismMode ?: (prefs.getBoolean("determinism.enabled") ?: false)
        
        val mcpSettings = settings?.mcpSettings
        val mcpEnv = if (mcpSettings != null && mcpSettings.enabled) {
            val url = "http://${mcpSettings.host}:${mcpSettings.port}/mcp"
            mapOf(
                "BURP_MCP_PORT" to mcpSettings.port.toString(),
                "BURP_MCP_HOST" to mcpSettings.host,
                "BURP_MCP_TOKEN" to mcpSettings.token,
                "BURP_MCP_API_URL" to url,
                "MCP_SERVER_URL" to url,
                "MCP_SERVER" to url,
                "MCP_TOKEN" to mcpSettings.token
            )
        } else {
            emptyMap()
        }

        val baseEnv = mapOf(
            "BURP_AI_AGENT_SESSION_ID" to sessionId,
            "BURP_AI_AGENT_DETERMINISM" to determinism.toString(),
            "PATH" to buildCliPathStatic()
        ) + mcpEnv

        return when (backendId) {
            "codex-cli" -> {
                val cmd = (settings?.codexCmd ?: prefs.getString("codex.cmd") ?: "codex").trim()
                val env = embeddedCliEnv(baseEnv, embeddedMode)
                BackendLaunchConfig(
                    backendId = backendId,
                    displayName = "Codex CLI",
                    command = tokenizeCommand(cmd),
                    embeddedMode = embeddedMode,
                    sessionId = sessionId,
                    determinismMode = determinism,
                    env = env,
                    cliSessionId = cliSessionId
                )
            }
            "gemini-cli" -> {
                val cmd = (settings?.geminiCmd ?: prefs.getString("gemini.cmd") ?: "gemini").trim()
                val env = embeddedCliEnv(baseEnv, embeddedMode)
                BackendLaunchConfig(
                    backendId = backendId,
                    displayName = "Gemini CLI",
                    command = tokenizeCommand(cmd),
                    embeddedMode = embeddedMode,
                    sessionId = sessionId,
                    determinismMode = determinism,
                    env = env,
                    cliSessionId = cliSessionId
                )
            }
            "opencode-cli" -> {
                val baseCmd = (settings?.opencodeCmd ?: prefs.getString("opencode.cmd") ?: "opencode").trim()
                val cmdParts = tokenizeCommand(baseCmd)
                val env = embeddedCliEnv(baseEnv, embeddedMode)
                BackendLaunchConfig(
                    backendId = backendId,
                    displayName = "OpenCode CLI",
                    command = cmdParts,
                    embeddedMode = embeddedMode,
                    sessionId = sessionId,
                    determinismMode = determinism,
                    env = env,
                    cliSessionId = cliSessionId
                )
            }
            "claude-cli" -> {
                val cmd = (settings?.claudeCmd ?: prefs.getString("claude.cmd") ?: "claude").trim()
                val env = embeddedCliEnv(baseEnv, embeddedMode)
                BackendLaunchConfig(
                    backendId = backendId,
                    displayName = "Claude Code",
                    command = tokenizeCommand(cmd),
                    embeddedMode = embeddedMode,
                    sessionId = sessionId,
                    determinismMode = determinism,
                    env = env,
                    cliSessionId = cliSessionId
                )
            }
            "ollama" -> {
                val url = (settings?.ollamaUrl ?: prefs.getString("ollama.url") ?: "http://127.0.0.1:11434").trim()
                val explicitModel = (settings?.ollamaModel ?: prefs.getString("ollama.model")).orEmpty().trim()
                val model = explicitModel.ifBlank { resolveOllamaModel(settings) }
                val apiKey = settings?.ollamaApiKey ?: prefs.getString("ollama.apiKey").orEmpty()
                val rawHeaders = settings?.ollamaHeaders ?: prefs.getString("ollama.headers").orEmpty()
                val headers = HeaderParser.withBearerToken(
                    apiKey,
                    HeaderParser.parse(rawHeaders)
                )
                val timeoutSeconds = settings?.ollamaTimeoutSeconds
                    ?: (prefs.getInteger("ollama.timeoutSeconds") ?: Defaults.CLI_PROCESS_TIMEOUT_SECONDS)
                BackendLaunchConfig(
                    backendId = backendId,
                    displayName = "Ollama",
                    baseUrl = url,
                    model = model,
                    headers = headers,
                    requestTimeoutSeconds = timeoutSeconds.toLong(),
                    embeddedMode = embeddedMode,
                    sessionId = sessionId,
                    determinismMode = determinism,
                    env = baseEnv,
                    cliSessionId = cliSessionId,
                    contextWindow = settings?.ollamaContextWindow
                        ?: prefs.getInteger("ollama.contextWindow")
                )
            }
            "lmstudio" -> {
                val url = (settings?.lmStudioUrl ?: prefs.getString("lmstudio.url") ?: "http://127.0.0.1:1234").trim()
                val model = (settings?.lmStudioModel ?: prefs.getString("lmstudio.model") ?: "lmstudio").trim()
                val timeoutSeconds = settings?.lmStudioTimeoutSeconds
                    ?: (prefs.getInteger("lmstudio.timeoutSeconds") ?: Defaults.CLI_PROCESS_TIMEOUT_SECONDS)
                val apiKey = settings?.lmStudioApiKey ?: prefs.getString("lmstudio.apiKey").orEmpty()
                val rawHeaders = settings?.lmStudioHeaders ?: prefs.getString("lmstudio.headers").orEmpty()
                val headers = HeaderParser.withBearerToken(
                    apiKey,
                    HeaderParser.parse(rawHeaders)
                )
                BackendLaunchConfig(
                    backendId = backendId,
                    displayName = "LM Studio",
                    baseUrl = url,
                    model = model,
                    headers = headers,
                    requestTimeoutSeconds = timeoutSeconds.toLong(),
                    embeddedMode = embeddedMode,
                    sessionId = sessionId,
                    determinismMode = determinism,
                    env = baseEnv,
                    cliSessionId = cliSessionId
                )
            }
            "openai-compatible" -> {
                val url = (settings?.openAiCompatibleUrl ?: prefs.getString("openai.compat.url") ?: "").trim()
                val model = (settings?.openAiCompatibleModel ?: prefs.getString("openai.compat.model") ?: "").trim()
                val timeoutSeconds = settings?.openAiCompatibleTimeoutSeconds
                    ?: (prefs.getInteger("openai.compat.timeoutSeconds") ?: Defaults.CLI_PROCESS_TIMEOUT_SECONDS)
                val apiKey = settings?.openAiCompatibleApiKey ?: prefs.getString("openai.compat.apiKey").orEmpty()
                val rawHeaders = settings?.openAiCompatibleHeaders ?: prefs.getString("openai.compat.headers").orEmpty()
                val headers = HeaderParser.withBearerToken(
                    apiKey,
                    HeaderParser.parse(rawHeaders)
                )
                BackendLaunchConfig(
                    backendId = backendId,
                    displayName = "Generic (OpenAI-compatible)",
                    baseUrl = url,
                    model = model,
                    headers = headers,
                    requestTimeoutSeconds = timeoutSeconds.toLong(),
                    embeddedMode = embeddedMode,
                    sessionId = sessionId,
                    determinismMode = determinism,
                    env = baseEnv,
                    cliSessionId = cliSessionId
                )
            }
            else -> BackendLaunchConfig(backendId, backendId, embeddedMode = embeddedMode, env = baseEnv, cliSessionId = cliSessionId)
        }
    }

    private fun embeddedCliEnv(baseEnv: Map<String, String>, embeddedMode: Boolean): Map<String, String> {
        if (!embeddedMode) return baseEnv
        return baseEnv + mapOf(
            "CI" to "1",
            "TERM" to "dumb",
            "NO_COLOR" to "1",
            "CLICOLOR" to "0",
            "FORCE_COLOR" to "0",
            "BURP_AI_AGENT_EMBEDDED" to "1"
        )
    }

    private fun resolveOllamaModel(settings: AgentSettings?): String {
        val cmd = settings?.ollamaCliCmd?.trim().orEmpty()
        val fromCmd = parseOllamaModelFromCli(cmd)
        if (!fromCmd.isNullOrBlank()) return fromCmd
        return "llama3.1"
    }

    private fun parseOllamaModelFromCli(cmd: String): String? {
        if (cmd.isBlank()) return null
        val parts = tokenizeCommand(cmd)
        val runIdx = parts.indexOf("run")
        if (runIdx >= 0 && runIdx + 1 < parts.size) {
            val candidate = parts[runIdx + 1]
            return if (candidate.startsWith("-")) null else candidate
        }
        if (parts.size >= 3 && parts[0] == "ollama" && parts[1] == "run") {
            return parts[2]
        }
        return null
    }

    private fun checkHealth() {
        val current = stateRef.get() as? AgentState.Running ?: return

        if (current.connection.isAlive()) {
            val startedAt = current.startedAt
            if (startedAt > 0 && System.currentTimeMillis() - startedAt > 5_000) {
                crashCount.set(0)
                autoRestartSuppressed.set(null)
                immediateCrashCount.set(0)
            }
            return
        }

        val settings = settingsRef.get() ?: return
        if (!settings.autoRestart) return
        if (autoRestartSuppressed.get() != null) return

        val startedAt = current.startedAt
        val now = System.currentTimeMillis()
        val immediateCrash = startedAt > 0 && (now - startedAt) < 5_000

        val failures = crashCount.get().coerceAtLeast(1)
        val backoffMs = (1000L * (1 shl failures.coerceAtMost(5))).coerceAtMost(30_000L)
        val last = lastRestartAt.get()
        if (now - last < backoffMs) return

        val attempt = crashCount.incrementAndGet()
        val backendId = current.backendId
        
        if (immediateCrash) {
            val immediate = immediateCrashCount.incrementAndGet()
            val detail = buildExitDetail(current.connection)
            if (detail.isNotBlank()) {
                api.logging().logToError("Agent exited immediately: $backendId.${detail}")
            }
            if (immediate >= 3) {
                val msg = "Auto-restart suppressed: $backendId exits immediately. Check CLI config/auth.${detail}"
                autoRestartSuppressed.set(msg)
                lastErrorRef.set(msg)
                api.logging().logToError(msg)
                return
            }
        } else {
            immediateCrashCount.set(0)
        }

        lastRestartAt.set(now)
        api.logging().logToError("Agent crashed. Auto-restarting in ${backoffMs}ms (attempt $attempt).")

        workerPool.submit { startOrAttach(backendId) }
    }

    private fun buildExitDetail(conn: AgentConnection): String {
        if (conn !is DiagnosableConnection) return ""
        val code = conn.exitCode()?.let { " exit=$it" }.orEmpty()
        val tail = conn.lastOutputTail()?.let { "\nOutput:\n$it" }.orEmpty()
        return if (code.isNotBlank() || tail.isNotBlank()) "$code$tail" else ""
    }

    private fun startService(name: String, cmd: String): Boolean {
        val existing = services[name]
        if (existing != null && existing.isAlive) return true
        val parts = tokenizeCommand(cmd)
        if (parts.isEmpty()) return false
        return try {
            val process = ProcessBuilder(parts)
                .redirectErrorStream(true)
                .start()
            services[name] = process
            workerPool.submit {
                try {
                    val reader = process.inputStream.bufferedReader()
                    reader.forEachLine { line ->
                        safeLogOutput("[$name] $line")
                    }
                } catch (e: Exception) {
                    safeLogOutput("[$name] output stream closed: ${e.message}")
                }
            }
            safeLogOutput("Started service: $name")
            true
        } catch (e: Exception) {
            safeLogError("Failed to start service $name: ${e.message}")
            false
        }
    }

    private fun tokenizeCommand(command: String): List<String> {
        val tokens = mutableListOf<String>()
        val currentToken = StringBuilder()
        var inQuotes = false
        var quoteChar = ' '

        var i = 0
        while (i < command.length) {
            val c = command[i]
            when {
                c == '\\' && i + 1 < command.length -> {
                    currentToken.append(command[i + 1])
                    i++
                }
                (c == '"' || c == '\'') -> {
                    if (inQuotes) {
                        if (c == quoteChar) {
                            inQuotes = false
                        } else {
                            currentToken.append(c)
                        }
                    } else {
                        inQuotes = true
                        quoteChar = c
                    }
                }
                c.isWhitespace() -> {
                    if (inQuotes) {
                        currentToken.append(c)
                    } else if (currentToken.isNotEmpty()) {
                        tokens.add(currentToken.toString())
                        currentToken.clear()
                    }
                }
                else -> {
                    currentToken.append(c)
                }
            }
            i++
        }
        if (currentToken.isNotEmpty()) {
            tokens.add(currentToken.toString())
        }
        return tokens
    }

    private fun safeLogOutput(message: String) {
        try {
            api.logging().logToOutput(message)
        } catch (_: Throwable) {
            System.err.println(message)
        }
    }

    private fun safeLogError(message: String) {
        try {
            api.logging().logToError(message)
        } catch (_: Throwable) {
            System.err.println(message)
        }
    }

    fun shutdown() {
        stop()
        chatSessionManager.shutdown()
        monitorExec.shutdown()
        try {
            if (!monitorExec.awaitTermination(3, TimeUnit.SECONDS)) {
                monitorExec.shutdownNow()
            }
        } catch (_: InterruptedException) {
            monitorExec.shutdownNow()
        }
        for ((name, process) in services) {
            try {
                process.destroyForcibly()
            } catch (e: Exception) {
                safeLogError("Failed to terminate service '$name': ${e.message}")
            }
        }
        services.clear()
        httpClient.dispatcher.executorService.shutdown()
        httpClient.connectionPool.evictAll()
    }

    companion object {
        @Volatile
        private var cachedPath: String? = null

        fun buildCliPathStatic(): String {
            cachedPath?.let { return it }

            val initialBase = System.getenv("PATH").orEmpty()
            val userHome = System.getProperty("user.home")
            val sep = java.io.File.pathSeparator
            val os = System.getProperty("os.name").lowercase(java.util.Locale.ROOT)
            val isWin = os.contains("win")

            if (isWin) {
                cachedPath = initialBase
                return initialBase
            }

            // On Unix (macOS/Linux), Burp often has a truncated PATH if not started from terminal.
            // We try multiple strategies to find the "real" user PATH.
            val capturedPath = capturePathFromShells() ?: initialBase

            // Merge everything and inject common local folders that are often missed
            val rawList = (capturedPath.split(sep) + initialBase.split(sep)).toMutableList()
            
            val commonFolders = listOf(
                "~/.local/bin",
                "~/bin",
                "/opt/homebrew/bin",
                "/usr/local/bin"
            )

            for (f in commonFolders) {
                val expanded = expandHome(f, userHome)
                if (java.io.File(expanded).exists()) {
                    rawList.add(expanded)
                }
            }

            val finalPath = rawList.filter { it.isNotBlank() }.distinct().joinToString(sep)
            
            cachedPath = finalPath
            return finalPath
        }

        private fun expandHome(path: String, home: String): String {
            return if (path.startsWith("~")) {
                home + path.substring(1)
            } else path
        }

        private fun capturePathFromShells(): String? {
            val shells = listOf(
                System.getenv("SHELL"),
                "/bin/zsh", "/usr/bin/zsh",
                "/bin/bash", "/usr/bin/bash",
                "/bin/sh"
            ).filterNotNull().distinct()

            for (shellPath in shells) {
                if (!java.io.File(shellPath).exists()) continue
                
                // Strategy A: Standard login shell
                val captured = tryCapture(shellPath, "-l", "echo ___BURP_PATH___\$PATH")
                if (captured != null && (captured.contains(".local/bin") || captured.contains("homebrew"))) {
                    return captured
                }

                // Strategy B: Explicit source (often needed for macOS GUI apps)
                if (shellPath.endsWith("zsh")) {
                    val fallback = tryCapture(shellPath, "-c", "source ~/.zshrc 2>/dev/null; echo ___BURP_PATH___\$PATH")
                    if (fallback != null) return fallback
                }
            }
            return null
        }

        private fun tryCapture(shellPath: String, flag: String, cmd: String): String? {
            try {
                val process = ProcessBuilder(shellPath, flag, "-c", cmd).start()
                val output = process.inputStream.bufferedReader().use { it.readText() }
                if (process.waitFor() == 0 && output.contains("___BURP_PATH___")) {
                    val result = output.substringAfter("___BURP_PATH___").substringBefore("\n").trim()
                    if (result.isNotBlank()) {
                        return result
                    }
                }
            } catch (_: Exception) {
            }
            return null
        }
    }
}
