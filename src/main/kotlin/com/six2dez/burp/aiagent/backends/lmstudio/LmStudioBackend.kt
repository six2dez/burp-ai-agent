package com.six2dez.burp.aiagent.backends.lmstudio

import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.module.kotlin.registerKotlinModule
import com.six2dez.burp.aiagent.backends.AgentConnection
import com.six2dez.burp.aiagent.backends.AiBackend
import com.six2dez.burp.aiagent.backends.BackendDiagnostics
import com.six2dez.burp.aiagent.backends.BackendLaunchConfig
import com.six2dez.burp.aiagent.backends.HealthCheckResult
import com.six2dez.burp.aiagent.backends.TokenUsage
import com.six2dez.burp.aiagent.backends.UsageAwareConnection
import com.six2dez.burp.aiagent.backends.http.CircuitBreaker
import com.six2dez.burp.aiagent.backends.http.ConversationHistory
import com.six2dez.burp.aiagent.backends.http.HttpBackendSupport
import com.six2dez.burp.aiagent.config.AgentSettings
import com.six2dez.burp.aiagent.util.HeaderParser
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicReference

class LmStudioBackend : AiBackend {
    override val id: String = "lmstudio"
    override val displayName: String = "LM Studio (local)"
    override val supportsSystemRole: Boolean = true

    private val mapper = ObjectMapper().registerKotlinModule()

    override fun launch(config: BackendLaunchConfig): AgentConnection {
        val baseUrl = config.baseUrl?.trimEnd('/') ?: "http://127.0.0.1:1234"
        val model = config.model?.ifBlank { "lmstudio" } ?: "lmstudio"
        val timeoutSeconds = (config.requestTimeoutSeconds ?: 120L).coerceIn(30L, 3600L)
        val client = HttpBackendSupport.sharedClient(baseUrl, timeoutSeconds)
        return LmStudioConnection(
            client,
            mapper,
            baseUrl,
            model,
            config.headers,
            config.determinismMode,
            config.sessionId,
            HttpBackendSupport.newCircuitBreaker(),
            debugLog = { BackendDiagnostics.log("[lmstudio] $it") },
            errorLog = { BackendDiagnostics.logError("[lmstudio] $it") }
        )
    }

    override fun healthCheck(settings: AgentSettings): HealthCheckResult {
        val baseUrl = settings.lmStudioUrl.trim()
        if (baseUrl.isBlank()) {
            return HealthCheckResult.Unavailable("LM Studio URL is empty.")
        }
        val headers = HeaderParser.withBearerToken(
            settings.lmStudioApiKey,
            HeaderParser.parse(settings.lmStudioHeaders)
        )
        return HttpBackendSupport.healthCheckGet(
            url = "${baseUrl.trimEnd('/')}/v1/models",
            headers = headers
        )
    }

    private class LmStudioConnection(
        private val client: okhttp3.OkHttpClient,
        private val mapper: ObjectMapper,
        private val baseUrl: String,
        private val model: String,
        private val headers: Map<String, String>,
        private val determinismMode: Boolean,
        private val sessionId: String?,
        private val circuitBreaker: CircuitBreaker,
        private val debugLog: (String) -> Unit,
        private val errorLog: (String) -> Unit
    ) : AgentConnection, UsageAwareConnection {
        private val alive = AtomicBoolean(true)
        private val exec = Executors.newSingleThreadExecutor { runnable ->
            Thread(runnable, "lmstudio-connection").apply { isDaemon = true }
        }
        private val conversationHistory = ConversationHistory(20)
        private val lastTokenUsageRef = AtomicReference<TokenUsage?>(null)

        override fun isAlive(): Boolean = alive.get()

        override fun lastTokenUsage(): TokenUsage? = lastTokenUsageRef.get()

        override fun send(
            text: String,
            history: List<com.six2dez.burp.aiagent.backends.ChatMessage>?,
            onChunk: (String) -> Unit,
            onComplete: (Throwable?) -> Unit,
            systemPrompt: String?
        ) {
            if (!isAlive()) {
                onComplete(IllegalStateException("Connection closed"))
                return
            }

            exec.submit {
                try {
                    lastTokenUsageRef.set(null)
                    if (history != null) {
                        conversationHistory.setHistory(history)
                    }
                    conversationHistory.setSystemPrompt(systemPrompt)
                    val maxAttempts = 6
                    var attempt = 0
                    var lastError: Exception? = null
                    while (attempt < maxAttempts) {
                        val permission = circuitBreaker.tryAcquire()
                        if (!permission.allowed) {
                            val failFastError = HttpBackendSupport.openCircuitError("LM Studio", permission.retryAfterMs)
                            debugLog("circuit open: ${failFastError.message}")
                            onComplete(failFastError)
                            return@submit
                        }
                        if (!isAlive()) {
                            onComplete(IllegalStateException("Connection closed"))
                            return@submit
                        }
                        try {
                            // Add user message to conversation history
                            conversationHistory.addUser(text)
                            val messages = conversationHistory.snapshot()
                            val payload = mapOf(
                                "model" to model,
                                "messages" to messages,
                                "stream" to false,
                                "temperature" to if (determinismMode) 0.0 else 0.7
                            )

                            val json = mapper.writeValueAsString(payload)
                            val req = Request.Builder()
                                .url("$baseUrl/v1/chat/completions")
                                .post(json.toRequestBody("application/json".toMediaType()))
                                .apply {
                                    headers.forEach { (name, value) ->
                                        header(name, value)
                                    }
                                    if (!sessionId.isNullOrBlank()) {
                                        header("X-Session-Id", sessionId)
                                    }
                                }
                                .build()

                            debugLog("request -> ${req.url}")
                            client.newCall(req).execute().use { resp ->
                                if (!resp.isSuccessful) {
                                    val bodyText = resp.body?.string().orEmpty()
                                    errorLog("HTTP ${resp.code}: ${bodyText.take(500)}")
                                    onComplete(IllegalStateException("LM Studio HTTP ${resp.code}: $bodyText"))
                                    return@submit
                                }
                                val body = resp.body?.string().orEmpty()
                                if (body.isBlank()) {
                                    onComplete(IllegalStateException("LM Studio response body was empty"))
                                    return@submit
                                }
                                val node = mapper.readTree(body)
                                val content = node.path("choices").path(0).path("message").path("content").asText()
                                val usageNode = node.path("usage")
                                val promptTokens = usageNode.path("prompt_tokens").asInt(-1)
                                val completionTokens = usageNode.path("completion_tokens").asInt(-1)
                                if (promptTokens >= 0 || completionTokens >= 0) {
                                    lastTokenUsageRef.set(
                                        TokenUsage(
                                            inputTokens = promptTokens.coerceAtLeast(0),
                                            outputTokens = completionTokens.coerceAtLeast(0)
                                        )
                                    )
                                }
                                if (content.isBlank()) {
                                    onComplete(IllegalStateException("LM Studio response content was empty"))
                                    return@submit
                                }
                                debugLog("response <- ${content.take(200)}")
                                // Add assistant response to conversation history
                                conversationHistory.addAssistant(content)
                                circuitBreaker.recordSuccess()
                                onChunk(content)
                                onComplete(null)
                                return@submit
                            }
                        } catch (e: Exception) {
                            lastError = e
                            val retryable = HttpBackendSupport.isRetryableConnectionError(e)
                            if (retryable) {
                                circuitBreaker.recordFailure()
                            }
                            if (!retryable || attempt == maxAttempts - 1) {
                                throw e
                            }
                            val delayMs = HttpBackendSupport.retryDelayMs(attempt)
                            BackendDiagnostics.logRetry("lmstudio", attempt + 1, delayMs, e.message)
                            debugLog("retrying in ${delayMs}ms after: ${e.message}")
                            try {
                                Thread.sleep(delayMs)
                            } catch (_: InterruptedException) {
                                Thread.currentThread().interrupt()
                                throw e
                            }
                            attempt++
                        }
                    }
                    if (lastError != null) {
                        throw lastError
                    }
                } catch (e: Exception) {
                    errorLog("exception: ${e.message}")
                    onComplete(e)
                } finally {
                    if (!isAlive()) {
                        exec.shutdownNow()
                    }
                }
            }
        }

        override fun stop() {
            alive.set(false)
            exec.shutdownNow()
        }
    }
}
