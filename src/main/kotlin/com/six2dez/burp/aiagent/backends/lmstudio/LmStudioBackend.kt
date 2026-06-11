package com.six2dez.burp.aiagent.backends.lmstudio

import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.module.kotlin.registerKotlinModule
import com.six2dez.burp.aiagent.backends.AgentConnection
import com.six2dez.burp.aiagent.backends.AiBackend
import com.six2dez.burp.aiagent.backends.BackendDiagnostics
import com.six2dez.burp.aiagent.backends.BackendLaunchConfig
import com.six2dez.burp.aiagent.backends.HealthCheckResult
import com.six2dez.burp.aiagent.backends.JsonModeCapable
import com.six2dez.burp.aiagent.backends.TokenUsage
import com.six2dez.burp.aiagent.backends.UsageAwareConnection
import com.six2dez.burp.aiagent.backends.http.CircuitBreaker
import com.six2dez.burp.aiagent.backends.http.ConversationHistory
import com.six2dez.burp.aiagent.backends.http.HttpBackendSupport
import com.six2dez.burp.aiagent.backends.http.MontoyaHttpTransport
import com.six2dez.burp.aiagent.backends.http.recordHttpFailureIfRetryable
import com.six2dez.burp.aiagent.config.AgentSettings
import com.six2dez.burp.aiagent.util.HeaderParser
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicReference

class LmStudioBackend : AiBackend {
    override val id: String = "lmstudio"
    override val displayName: String = "LM Studio (local)"
    override val supportsSystemRole: Boolean = true

    private val mapper = ObjectMapper().registerKotlinModule()

    /**
     * Optional, supervisor-injected [MontoyaHttpTransport] used by [healthCheck]. Null only on the
     * unit-test path (tests construct backends directly without a supervisor); production wiring
     * lives in [com.six2dez.burp.aiagent.supervisor.AgentSupervisor]'s init block.
     */
    @Volatile
    private var healthCheckTransport: MontoyaHttpTransport? = null

    fun setHealthCheckTransport(transport: MontoyaHttpTransport) {
        healthCheckTransport = transport
    }

    fun healthCheckTransport(): MontoyaHttpTransport? = healthCheckTransport

    override fun launch(config: BackendLaunchConfig): AgentConnection {
        val baseUrl = config.baseUrl?.trimEnd('/') ?: "http://127.0.0.1:1234"
        val model = config.model?.ifBlank { "lmstudio" } ?: "lmstudio"
        val timeoutSeconds = (config.requestTimeoutSeconds ?: 120L).coerceIn(30L, 3600L)
        return LmStudioConnection(
            mapper,
            baseUrl,
            model,
            config.headers,
            config.determinismMode,
            config.sessionId,
            HttpBackendSupport.newCircuitBreaker(),
            transport = config.transport,
            timeoutSeconds = timeoutSeconds,
            debugLog = { BackendDiagnostics.log("[lmstudio] $it") },
            errorLog = { BackendDiagnostics.logError("[lmstudio] $it") },
        )
    }

    override fun healthCheck(settings: AgentSettings): HealthCheckResult {
        val baseUrl = settings.lmStudioUrl.trim()
        if (baseUrl.isBlank()) {
            return HealthCheckResult.Unavailable("LM Studio URL is empty.")
        }
        val headers =
            HeaderParser.withBearerToken(
                settings.lmStudioApiKey,
                HeaderParser.parse(settings.lmStudioHeaders),
            )
        val url = "${baseUrl.trimEnd('/')}/v1/models"
        // BUG-69-01: prefer supervisor-injected MontoyaHttpTransport so health check honors Burp's
        // upstream proxy / SOCKS / cert store. Fall through to OkHttp only on the unit-test path.
        val transport = healthCheckTransport
        return if (transport != null) {
            transport.healthCheckGet(url, headers, timeoutMs = 3_000)
        } else {
            HttpBackendSupport.healthCheckGet(
                url = url,
                headers = headers,
            )
        }
    }

    private class LmStudioConnection(
        private val mapper: ObjectMapper,
        private val baseUrl: String,
        private val model: String,
        private val headers: Map<String, String>,
        private val determinismMode: Boolean,
        private val sessionId: String?,
        private val circuitBreaker: CircuitBreaker,
        private val transport: MontoyaHttpTransport?,
        private val timeoutSeconds: Long,
        private val debugLog: (String) -> Unit,
        private val errorLog: (String) -> Unit,
    ) : AgentConnection,
        UsageAwareConnection,
        JsonModeCapable {
        private val alive = AtomicBoolean(true)
        private val exec =
            Executors.newSingleThreadExecutor { runnable ->
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
            systemPrompt: String?,
            jsonMode: Boolean,
            maxOutputTokens: Int?,
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
                            // BUG-69-01: LM Studio MUST route through MontoyaHttpTransport in
                            // production so Burp's upstream proxy / SOCKS / cert store participate.
                            // Reaching this branch with transport == null means the supervisor's
                            // wiring is broken — fail fast instead of silently bypassing Burp via
                            // OkHttp. See HttpBackendSupport.buildClient KDoc for the test-only path.
                            if (transport == null) {
                                throw IllegalStateException(
                                    "MontoyaHttpTransport unavailable; AI HTTP backends require Burp's HTTP stack " +
                                        "(see HttpBackendSupport.buildClient KDoc for the test-only path)",
                                )
                            }
                            // Add user message to conversation history
                            conversationHistory.addUser(text)
                            val messages = conversationHistory.snapshot()
                            val payload =
                                mutableMapOf<String, Any>(
                                    "model" to model,
                                    "messages" to messages,
                                    "stream" to false,
                                    "temperature" to if (determinismMode) 0.0 else 0.7,
                                )
                            if (maxOutputTokens != null) {
                                payload["max_tokens"] = maxOutputTokens
                            }
                            if (jsonMode) {
                                payload["response_format"] = mapOf("type" to "json_object")
                            }

                            val json = mapper.writeValueAsString(payload)
                            val endpointUrl = "$baseUrl/v1/chat/completions"

                            val allHeaders =
                                buildMap {
                                    putAll(headers)
                                    if (!sessionId.isNullOrBlank()) {
                                        put("X-Session-Id", sessionId)
                                    }
                                }

                            debugLog("request -> $endpointUrl")

                            val resp = transport.post(endpointUrl, allHeaders, json, timeoutSeconds * 1000)
                            if (!resp.isSuccessful) {
                                errorLog("HTTP ${resp.statusCode}: ${resp.body.take(500)}")
                                circuitBreaker.recordHttpFailureIfRetryable(resp.statusCode)
                                onComplete(IllegalStateException("LM Studio HTTP ${resp.statusCode}: ${resp.body}"))
                                return@submit
                            }
                            val body: String = resp.body

                            if (body.isBlank()) {
                                onComplete(IllegalStateException("LM Studio response body was empty"))
                                return@submit
                            }
                            val node = mapper.readTree(body)
                            val choices = node.path("choices")
                            if (!choices.isArray || choices.isEmpty) {
                                // Snippet capped at 200 chars; see Ollama backend for rationale.
                                val snippet = body.take(200).replace("\n", " ")
                                errorLog("missing or empty 'choices' array; raw body snippet: $snippet")
                                onComplete(
                                    IllegalStateException(
                                        "LM Studio response had no 'choices'. Raw body snippet: $snippet",
                                    ),
                                )
                                return@submit
                            }
                            val content =
                                choices
                                    .path(0)
                                    .path("message")
                                    .path("content")
                                    .asText()
                            val usageNode = node.path("usage")
                            val promptTokens = usageNode.path("prompt_tokens").asInt(-1)
                            val completionTokens = usageNode.path("completion_tokens").asInt(-1)
                            if (promptTokens >= 0 || completionTokens >= 0) {
                                lastTokenUsageRef.set(
                                    TokenUsage(
                                        inputTokens = promptTokens.coerceAtLeast(0),
                                        outputTokens = completionTokens.coerceAtLeast(0),
                                    ),
                                )
                            }
                            if (content.isBlank()) {
                                val snippet = body.take(200).replace("\n", " ")
                                errorLog("response content empty; raw body snippet: $snippet")
                                onComplete(
                                    IllegalStateException(
                                        "LM Studio response content was empty. Raw body snippet: $snippet",
                                    ),
                                )
                                return@submit
                            }
                            debugLog("response <- ${content.take(200)}")
                            // Add assistant response to conversation history
                            conversationHistory.addAssistant(content)
                            circuitBreaker.recordSuccess()
                            onChunk(content)
                            onComplete(null)
                            return@submit
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
