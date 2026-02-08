package com.six2dez.burp.aiagent.backends

import burp.api.montoya.MontoyaApi
import com.six2dez.burp.aiagent.backends.cli.CodexCliBackendFactory
import com.six2dez.burp.aiagent.backends.cli.GeminiCliBackendFactory
import com.six2dez.burp.aiagent.backends.cli.OpenCodeCliBackendFactory
import com.six2dez.burp.aiagent.backends.cli.ClaudeCliBackendFactory
import com.six2dez.burp.aiagent.backends.lmstudio.LmStudioBackendFactory
import com.six2dez.burp.aiagent.backends.ollama.OllamaBackendFactory
import com.six2dez.burp.aiagent.backends.openai.OpenAiCompatibleBackendFactory
import java.io.File
import java.net.URLClassLoader
import java.util.ServiceLoader
import java.util.concurrent.ConcurrentHashMap

class BackendRegistry(private val api: MontoyaApi) {
    private val backends = ConcurrentHashMap<String, AiBackend>()
    private var externalClassLoader: URLClassLoader? = null

    private val externalBackendDir = File(System.getProperty("user.home"), ".burp-ai-agent/backends").also { it.mkdirs() }

    init {
        reload()
    }

    fun reload() {
        backends.clear()
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
                OpenAiCompatibleBackendFactory()
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

        // Optional drop-in backend JARs
        loadExternalBackendJars()

        api.logging().logToOutput("Total backends registered: ${backends.size}")
    }

    fun get(id: String): AiBackend? = backends[id]

    private val availabilityCache = ConcurrentHashMap<Pair<String, Int>, Boolean>()

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

    fun shutdown() {
        backends.clear()
        closeExternalClassLoader()
    }

    private fun loadExternalBackendJars() {
        val jars = externalBackendDir.listFiles { f -> f.isFile && f.extension.lowercase() == "jar" }?.toList().orEmpty()
        if (jars.isEmpty()) return

        try {
            val cl = URLClassLoader(jars.map { it.toURI().toURL() }.toTypedArray(), this::class.java.classLoader)
            ServiceLoader.load(AiBackendFactory::class.java, cl).forEach { f ->
                val b = f.create()
                backends[b.id] = b
            }
            externalClassLoader = cl
            api.logging().logToOutput("Loaded external backend JARs: ${jars.joinToString { it.name }}")
        } catch (e: Exception) {
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
