package com.six2dez.burp.aiagent.backends

import burp.api.montoya.MontoyaApi
import com.six2dez.burp.aiagent.backends.cli.CodexCliBackendFactory
import com.six2dez.burp.aiagent.backends.cli.GeminiCliBackendFactory
import com.six2dez.burp.aiagent.backends.cli.OpenCodeCliBackendFactory
import com.six2dez.burp.aiagent.backends.cli.ClaudeCliBackendFactory
import com.six2dez.burp.aiagent.backends.cli.CopilotCliBackendFactory
import com.six2dez.burp.aiagent.backends.burpai.BurpAiBackend
import com.six2dez.burp.aiagent.backends.http.HttpBackendSupport
import com.six2dez.burp.aiagent.backends.lmstudio.LmStudioBackendFactory
import com.six2dez.burp.aiagent.backends.nvidia.NvidiaNimBackendFactory
import com.six2dez.burp.aiagent.backends.ollama.OllamaBackendFactory
import com.six2dez.burp.aiagent.backends.openai.OpenAiCompatibleBackendFactory
import com.six2dez.burp.aiagent.config.AgentSettings
import java.io.File
import java.net.URLClassLoader
import java.util.ServiceLoader
import java.util.concurrent.ConcurrentHashMap

class BackendRegistry(private val api: MontoyaApi) {
    private val backends = ConcurrentHashMap<String, AiBackend>()
    private val availabilityCache = ConcurrentHashMap<Pair<String, Int>, Boolean>()
    private var externalClassLoader: URLClassLoader? = null

    private val externalBackendDir = File(System.getProperty("user.home"), ".burp-ai-agent/backends").also { it.mkdirs() }

    init {
        reload()
    }

    fun reload() {
        backends.clear()
        availabilityCache.clear()
        closeExternalClassLoader()

        // Built-ins (same extension JAR)
        val builtIns = ServiceLoader.load(AiBackendFactory::class.java).toList()
        if (builtIns.isEmpty()) {
            api.logging().logToOutput("No AiBackendFactory found via ServiceLoader; falling back to built-ins.")
            listOf(
                CodexCliBackendFactory(),
                GeminiCliBackendFactory(),
                OpenCodeCliBackendFactory(),
                ClaudeCliBackendFactory(),
                LmStudioBackendFactory(),
                OllamaBackendFactory(),
                NvidiaNimBackendFactory(),
                OpenAiCompatibleBackendFactory(),
                CopilotCliBackendFactory()
            ).forEach { f ->
                val b = f.create()
                backends[b.id] = b
            }
        } else {
            builtIns.forEach { f ->
                val b = f.create()
                backends[b.id] = b
            }
        }

        // Burp AI backend (requires MontoyaApi, registered directly)
        try {
            val burpAi = BurpAiBackend(api)
            backends[burpAi.id] = burpAi
        } catch (e: Exception) {
            api.logging().logToOutput("Burp AI backend not available: ${e.message}")
        }

        // Optional drop-in backend JARs
        loadExternalBackendJars()

        api.logging().logToOutput("Total backends registered: ${backends.size}")
    }

    fun get(id: String): AiBackend? = backends[id]

    fun listBackendIds(settings: com.six2dez.burp.aiagent.config.AgentSettings): List<String> {
        val settingsHash = settings.hashCode()
        return backends.values
            .filter { backend ->
                val cacheKey = Pair(backend.id, settingsHash)
                availabilityCache.getOrPut(cacheKey) { backend.isAvailable(settings) }
            }
            .sortedBy { it.displayName }
            .map { it.id }
    }

    /** Returns all registered backend IDs regardless of availability. */
    fun listAllBackendIds(): List<String> {
        return backends.values
            .sortedBy { it.displayName }
            .map { it.id }
    }

    fun healthCheck(backendId: String, settings: AgentSettings): HealthCheckResult {
        val backend = backends[backendId]
            ?: return HealthCheckResult.Unavailable("Backend not found: $backendId")
        return try {
            val result = backend.healthCheck(settings)
            if (result is HealthCheckResult.Unknown) {
                if (backend.isAvailable(settings)) {
                    HealthCheckResult.Healthy
                } else {
                    HealthCheckResult.Unavailable("Backend is not available with current configuration.")
                }
            } else {
                result
            }
        } catch (e: Exception) {
            HealthCheckResult.Unavailable(e.message ?: "Health check failed")
        }
    }

    fun shutdown() {
        backends.clear()
        availabilityCache.clear()
        closeExternalClassLoader()
        HttpBackendSupport.shutdownSharedClients()
    }

    private fun loadExternalBackendJars() {
        val jars = externalBackendDir.listFiles { f -> f.isFile && f.extension.lowercase() == "jar" }?.toList().orEmpty()
        if (jars.isEmpty()) return

        val cl = URLClassLoader(jars.map { it.toURI().toURL() }.toTypedArray(), this::class.java.classLoader)
        try {
            ServiceLoader.load(AiBackendFactory::class.java, cl).forEach { f ->
                val b = f.create()
                backends[b.id] = b
            }
            externalClassLoader = cl
            api.logging().logToOutput("Loaded external backend JARs: ${jars.joinToString { it.name }}")
        } catch (e: Exception) {
            try { cl.close() } catch (_: Exception) {}
            api.logging().logToError("Failed loading external backend JARs: ${e.message}")
        }
    }

    private fun closeExternalClassLoader() {
        val cl = externalClassLoader ?: return
        externalClassLoader = null
        try {
            cl.close()
        } catch (e: Exception) {
            api.logging().logToError("Failed closing backend classloader: ${e.message}")
        }
    }
}
