package com.six2dez.burp.aiagent.backends.openai

import com.fasterxml.jackson.databind.JsonNode
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
import com.six2dez.burp.aiagent.config.AgentSettings
import com.six2dez.burp.aiagent.util.HeaderParser
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicReference

class OpenAiCompatibleBackend(
    override val id: String = "openai-compatible",
    override val displayName: String = "Generic (OpenAI-compatible)",
    private val defaultBaseUrl: String = "",
    private val baseUrlSelector: (AgentSettings) -> String = { it.openAiCompatibleUrl.trim() },
    private val modelSelector: (AgentSettings) -> String = { it.openAiCompatibleModel.trim() },
    private val apiKeySelector: (AgentSettings) -> String = { it.openAiCompatibleApiKey },
    private val headersSelector: (AgentSettings) -> String = { it.openAiCompatibleHeaders },
    private val timeoutSelector: (AgentSettings) -> Int = { it.openAiCompatibleTimeoutSeconds },
    private val streaming: Boolean = false,
    private val defaultHeaders: Map<String, String> = emptyMap(),
    private val payloadCustomizer: ((MutableMap<String, Any?>) -> Unit)? = null,
    private val healthCheckProvider: ((AgentSettings) -> HealthCheckResult)? = null,
    // Path appended to a bare-host base URL (no /v\d+ and no /chat/completions). Defaults to the
    // OpenAI shape; Perplexity overrides to "/chat/completions" because its API has no /v1 prefix.
    private val chatCompletionsBasePath: String = "/v1/chat/completions",
    // OpenAI-style {"type":"json_object"} response_format. Perplexity's Sonar API rejects this
    // field, so set false there; the scanner prompts still ask the model for JSON in plain text.
    private val supportsJsonObjectResponseFormat: Boolean = true,
) : AiBackend {
    override val supportsSystemRole: Boolean = true

    private val mapper = ObjectMapper().registerKotlinModule()

    /**
     * Optional, supervisor-injected [MontoyaHttpTransport] used by [healthCheck] (and exposed to
     * factory-specific health-check providers such as NVIDIA NIM). The injection happens once in
     * [com.six2dez.burp.aiagent.supervisor.AgentSupervisor]'s init block so the [AiBackend.healthCheck]
     * signature stays unchanged. Null only on the unit-test path (tests construct backends directly
     * without a supervisor), where [HttpBackendSupport.healthCheckGet] is the OkHttp fallback.
     */
    @Volatile
    private var healthCheckTransport: MontoyaHttpTransport? = null

    fun setHealthCheckTransport(transport: MontoyaHttpTransport) {
        healthCheckTransport = transport
    }

    fun healthCheckTransport(): MontoyaHttpTransport? = healthCheckTransport

    override fun launch(config: BackendLaunchConfig): AgentConnection {
        val baseUrl = effectiveBaseUrl(config.baseUrl)
        val model = config.model?.ifBlank { "" } ?: ""
        val timeoutSeconds = (config.requestTimeoutSeconds ?: 120L).coerceIn(30L, 3600L)
        val mergedHeaders = mergeHeaders(defaultHeaders, config.headers)
        return OpenAiCompatibleConnection(
            mapper = mapper,
            backendId = id,
            backendDisplayName = displayName,
            baseUrl = baseUrl,
            model = model,
            headers = mergedHeaders,
            determinismMode = config.determinismMode,
            sessionId = config.sessionId,
            circuitBreaker = HttpBackendSupport.newCircuitBreaker(),
            streaming = streaming,
            payloadCustomizer = payloadCustomizer,
            transport = config.transport,
            timeoutSeconds = timeoutSeconds,
            chatCompletionsBasePath = chatCompletionsBasePath,
            supportsJsonObjectResponseFormat = supportsJsonObjectResponseFormat,
            debugLog = { BackendDiagnostics.log("[$id] $it") },
            errorLog = { BackendDiagnostics.logError("[$id] $it") },
        )
    }

    override fun healthCheck(settings: AgentSettings): HealthCheckResult {
        if (healthCheckProvider != null) {
            return healthCheckProvider.invoke(settings)
        }
        val baseUrl = effectiveBaseUrl(baseUrlSelector(settings))
        if (baseUrl.isBlank()) {
            return HealthCheckResult.Unavailable("$displayName URL is empty.")
        }
        val headers =
            HeaderParser.withBearerToken(
                apiKeySelector(settings),
                HeaderParser.parse(headersSelector(settings)),
            )
        val modelsUrl = buildModelsUrl(baseUrl)
        val timeoutSeconds = timeoutSelector(settings).coerceIn(1, 30).toLong()
        // BUG-69-01: prefer the supervisor-injected MontoyaHttpTransport so the health check
        // honors Burp's upstream proxy / SOCKS / cert store. Fall through to OkHttp only on the
        // unit-test path (no supervisor present → transport stays null).
        val transport = healthCheckTransport
        return if (transport != null) {
            transport.healthCheckGet(modelsUrl, headers, timeoutMs = timeoutSeconds * 1000)
        } else {
            HttpBackendSupport.healthCheckGet(
                url = modelsUrl,
                headers = headers,
                timeoutSeconds = timeoutSeconds,
            )
        }
    }

    private class OpenAiCompatibleConnection(
        private val mapper: ObjectMapper,
        private val backendId: String,
        private val backendDisplayName: String,
        private val baseUrl: String,
        private val model: String,
        private val headers: Map<String, String>,
        private val determinismMode: Boolean,
        private val sessionId: String?,
        private val circuitBreaker: CircuitBreaker,
        private val streaming: Boolean,
        private val payloadCustomizer: ((MutableMap<String, Any?>) -> Unit)?,
        private val transport: MontoyaHttpTransport?,
        private val timeoutSeconds: Long,
        private val chatCompletionsBasePath: String,
        private val supportsJsonObjectResponseFormat: Boolean,
        private val debugLog: (String) -> Unit,
        private val errorLog: (String) -> Unit,
    ) : AgentConnection,
        UsageAwareConnection,
        JsonModeCapable {
        private val alive = AtomicBoolean(true)
        private val exec =
            Executors.newSingleThreadExecutor { runnable ->
                Thread(runnable, "$backendId-connection").apply { isDaemon = true }
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
                            val failFastError = HttpBackendSupport.openCircuitError(backendDisplayName, permission.retryAfterMs)
                            debugLog("circuit open: ${failFastError.message}")
                            onComplete(failFastError)
                            return@submit
                        }
                        if (!isAlive()) {
                            onComplete(IllegalStateException("Connection closed"))
                            return@submit
                        }
                        try {
                            // BUG-69-01: AI HTTP backends MUST go through MontoyaHttpTransport in
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
                            conversationHistory.addUser(text)
                            val messages = conversationHistory.snapshot()
                            val payload =
                                mutableMapOf<String, Any?>(
                                    "model" to model,
                                    "messages" to messages,
                                    "stream" to streaming,
                                    "temperature" to if (determinismMode) 0.0 else 0.7,
                                )
                            payloadCustomizer?.invoke(payload)
                            if (maxOutputTokens != null) {
                                payload["max_tokens"] = maxOutputTokens
                            }
                            if (jsonMode && supportsJsonObjectResponseFormat) {
                                payload["response_format"] = mapOf("type" to "json_object")
                            }

                            val json = mapper.writeValueAsString(payload)
                            val endpointUrl = buildChatCompletionsUrl(baseUrl)

                            val allHeaders =
                                buildMap {
                                    putAll(headers)
                                    if (!sessionId.isNullOrBlank()) {
                                        put("X-Session-Id", sessionId)
                                    }
                                }

                            // Bug #66: pre-flight log shows the body SHAPE only — never the JSON itself
                            // and never the message content. This preserves the privacy guarantee
                            // (STRIDE T-quick-03) while giving operators enough to debug a 4xx.
                            val safeBodyPreview =
                                buildString {
                                    append("model=").append(model)
                                    append(" messages=").append(messages.size)
                                    append(" json_bytes=").append(json.length)
                                    if (jsonMode) append(" json_mode=true")
                                    if (maxOutputTokens != null) append(" max_tokens=").append(maxOutputTokens)
                                }
                            debugLog("request -> POST $endpointUrl ($safeBodyPreview)")

                            val resp = transport.post(endpointUrl, allHeaders, json, timeoutSeconds * 1000)
                            if (!resp.isSuccessful) {
                                errorLog("HTTP ${resp.statusCode}: ${resp.body.take(500)}")
                                val message =
                                    when (resp.statusCode) {
                                        429 -> "$backendDisplayName rate limited (HTTP 429). Check quota/capacity or retry later."
                                        // Bug #66: diagnosable 4xx — include the endpoint URL, a bounded
                                        // body excerpt (T-quick-04: accepted up to 800 chars), and the
                                        // standard remediation hint pointing at the three common causes.
                                        else ->
                                            buildString {
                                                append("$backendDisplayName HTTP ${resp.statusCode} from POST ").append(endpointUrl)
                                                append("\nResponse: ").append(resp.body.take(800))
                                                append(
                                                    "\nHints: verify the URL ends in /v1 (or /chat/completions), " +
                                                        "the model name matches the provider's catalog, " +
                                                        "and the API key is valid for this endpoint.",
                                                )
                                            }
                                    }
                                onComplete(IllegalStateException(message))
                                return@submit
                            }
                            val body = resp.body
                            if (body.isBlank()) {
                                onComplete(IllegalStateException("$backendDisplayName response body was empty"))
                                return@submit
                            }
                            val node = mapper.readTree(body)
                            val content =
                                node
                                    .path("choices")
                                    .path(0)
                                    .path("message")
                                    .path("content")
                                    .asText()
                            extractUsage(node)?.let { lastTokenUsageRef.set(it) }
                            if (content.isBlank()) {
                                onComplete(IllegalStateException("$backendDisplayName response content was empty"))
                                return@submit
                            }
                            debugLog("response <- ${content.take(200)}")
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
                            BackendDiagnostics.logRetry(backendId, attempt + 1, delayMs, e.message)
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

        private fun extractUsage(node: JsonNode): TokenUsage? {
            val usageNode = node.path("usage")
            val promptTokens = usageNode.path("prompt_tokens").asInt(-1)
            val completionTokens = usageNode.path("completion_tokens").asInt(-1)
            if (promptTokens < 0 && completionTokens < 0) return null
            return TokenUsage(
                inputTokens = promptTokens.coerceAtLeast(0),
                outputTokens = completionTokens.coerceAtLeast(0),
            )
        }

        override fun stop() {
            alive.set(false)
            exec.shutdownNow()
        }

        private fun buildChatCompletionsUrl(baseUrl: String): String {
            val trimmed = baseUrl.trimEnd('/')
            val lower = trimmed.lowercase()
            if (lower.endsWith("/chat/completions")) return trimmed
            if (versionedEndpointRegex.matches(trimmed)) return trimmed
            if (versionedBaseRegex.matches(trimmed)) return "$trimmed/chat/completions"
            // Bare host: append the backend-specific fallback path. Defaults to "/v1/chat/completions"
            // but Perplexity overrides to "/chat/completions" because its API exposes no /v1 prefix.
            val path = if (chatCompletionsBasePath.startsWith("/")) chatCompletionsBasePath else "/$chatCompletionsBasePath"
            return "$trimmed$path"
        }
    }

    private companion object {
        private val versionedBaseRegex = Regex(".*/v\\d+$", RegexOption.IGNORE_CASE)
        private val versionedEndpointRegex = Regex(".*/v\\d+/chat/completions$", RegexOption.IGNORE_CASE)

        private fun buildModelsUrl(baseUrl: String): String {
            val trimmed = baseUrl.trimEnd('/')
            val lower = trimmed.lowercase()
            if (lower.endsWith("/models")) return trimmed
            if (lower.endsWith("/chat/completions")) {
                return trimmed.substringBeforeLast("/chat/completions") + "/models"
            }
            if (versionedBaseRegex.matches(trimmed)) return "$trimmed/models"
            return "$trimmed/v1/models"
        }

        private fun mergeHeaders(
            defaults: Map<String, String>,
            overrides: Map<String, String>,
        ): Map<String, String> {
            if (defaults.isEmpty()) return overrides
            val merged = LinkedHashMap<String, String>()
            merged.putAll(defaults)
            merged.putAll(overrides)
            return merged
        }
    }

    private fun effectiveBaseUrl(candidate: String?): String {
        val trimmed = candidate?.trim()?.trimEnd('/').orEmpty()
        if (trimmed.isNotBlank()) {
            return trimmed
        }
        return defaultBaseUrl.trim().trimEnd('/')
    }
}
