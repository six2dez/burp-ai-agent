package com.six2dez.burp.aiagent.backends.openai

import com.fasterxml.jackson.databind.JsonNode
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
import java.io.BufferedReader
import java.io.InputStreamReader
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
    private val healthCheckProvider: ((AgentSettings) -> HealthCheckResult)? = null
) : AiBackend {
    override val supportsSystemRole: Boolean = true

    private val mapper = ObjectMapper().registerKotlinModule()

    override fun launch(config: BackendLaunchConfig): AgentConnection {
        val baseUrl = effectiveBaseUrl(config.baseUrl)
        val model = config.model?.ifBlank { "" } ?: ""
        val timeoutSeconds = (config.requestTimeoutSeconds ?: 120L).coerceIn(30L, 3600L)
        val client = HttpBackendSupport.sharedClient(baseUrl, timeoutSeconds)
        val mergedHeaders = mergeHeaders(defaultHeaders, config.headers)
        return OpenAiCompatibleConnection(
            client = client,
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
            debugLog = { BackendDiagnostics.log("[$id] $it") },
            errorLog = { BackendDiagnostics.logError("[$id] $it") }
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
        val headers = HeaderParser.withBearerToken(
            apiKeySelector(settings),
            HeaderParser.parse(headersSelector(settings))
        )
        return HttpBackendSupport.healthCheckGet(
            url = buildModelsUrl(baseUrl),
            headers = headers,
            timeoutSeconds = timeoutSelector(settings).coerceIn(1, 30).toLong()
        )
    }

    private class OpenAiCompatibleConnection(
        private val client: okhttp3.OkHttpClient,
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
        private val debugLog: (String) -> Unit,
        private val errorLog: (String) -> Unit
    ) : AgentConnection, UsageAwareConnection {
        private val alive = AtomicBoolean(true)
        private val exec = Executors.newSingleThreadExecutor { runnable ->
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
                            conversationHistory.addUser(text)
                            val messages = conversationHistory.snapshot()
                            val payload = mutableMapOf<String, Any?>(
                                "model" to model,
                                "messages" to messages,
                                "stream" to streaming,
                                "temperature" to if (determinismMode) 0.0 else 0.7
                            )
                            payloadCustomizer?.invoke(payload)

                            val json = mapper.writeValueAsString(payload)
                            val endpointUrl = buildChatCompletionsUrl(baseUrl)
                            val req = Request.Builder()
                                .url(endpointUrl)
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
                                    val retryAfter = resp.header("Retry-After")
                                    val message = when (resp.code) {
                                        429 -> {
                                            val retryHint = retryAfter?.takeIf { it.isNotBlank() }?.let { " Retry after: $it." }.orEmpty()
                                            "$backendDisplayName rate limited (HTTP 429). Check quota/capacity or retry later.$retryHint"
                                        }
                                        else -> "$backendDisplayName HTTP ${resp.code}: $bodyText"
                                    }
                                    onComplete(IllegalStateException(message))
                                    return@submit
                                }
                                if (streaming) {
                                    handleStreamingResponse(resp, onChunk, onComplete)
                                } else {
                                    handleNonStreamingResponse(resp, onChunk, onComplete)
                                }
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

        private fun handleNonStreamingResponse(
            resp: okhttp3.Response,
            onChunk: (String) -> Unit,
            onComplete: (Throwable?) -> Unit
        ) {
            val body = resp.body?.string().orEmpty()
            if (body.isBlank()) {
                onComplete(IllegalStateException("$backendDisplayName response body was empty"))
                return
            }
            val node = mapper.readTree(body)
            val content = node.path("choices").path(0).path("message").path("content").asText()
            extractUsage(node)?.let { lastTokenUsageRef.set(it) }
            if (content.isBlank()) {
                onComplete(IllegalStateException("$backendDisplayName response content was empty"))
                return
            }
            debugLog("response <- ${content.take(200)}")
            conversationHistory.addAssistant(content)
            circuitBreaker.recordSuccess()
            onChunk(content)
            onComplete(null)
        }

        private fun handleStreamingResponse(
            resp: okhttp3.Response,
            onChunk: (String) -> Unit,
            onComplete: (Throwable?) -> Unit
        ) {
            val body = resp.body ?: run {
                onComplete(IllegalStateException("$backendDisplayName response body was empty"))
                return
            }
            val streamReader = BufferedReader(InputStreamReader(body.byteStream()))
            val fullContent = StringBuilder()
            var emittedAny = false
            var line: String?
            while (isAlive()) {
                line = streamReader.readLine() ?: break
                val trimmed = line.trim()
                if (trimmed.isEmpty() || !trimmed.startsWith("data:")) continue
                val data = trimmed.removePrefix("data:").trim()
                if (data == "[DONE]") break
                val node = mapper.readTree(data)
                extractUsage(node)?.let { lastTokenUsageRef.set(it) }
                val chunkText = extractStreamingChunkText(node)
                if (!chunkText.isNullOrEmpty()) {
                    emittedAny = true
                    fullContent.append(chunkText)
                    onChunk(chunkText)
                }
            }

            if (!emittedAny) {
                onComplete(IllegalStateException("$backendDisplayName response content was empty"))
                return
            }
            debugLog("response <- ${fullContent.toString().take(200)}")
            conversationHistory.addAssistant(fullContent.toString())
            circuitBreaker.recordSuccess()
            onComplete(null)
        }

        private fun extractStreamingChunkText(node: JsonNode): String? {
            val choice = node.path("choices").path(0)
            val deltaContent = choice.path("delta").path("content").asText()
            if (deltaContent.isNotBlank()) return deltaContent
            val messageContent = choice.path("message").path("content").asText()
            if (messageContent.isNotBlank()) return messageContent
            return null
        }

        private fun extractUsage(node: JsonNode): TokenUsage? {
            val usageNode = node.path("usage")
            val promptTokens = usageNode.path("prompt_tokens").asInt(-1)
            val completionTokens = usageNode.path("completion_tokens").asInt(-1)
            if (promptTokens < 0 && completionTokens < 0) return null
            return TokenUsage(
                inputTokens = promptTokens.coerceAtLeast(0),
                outputTokens = completionTokens.coerceAtLeast(0)
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
            return "$trimmed/v1/chat/completions"
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

        private fun mergeHeaders(defaults: Map<String, String>, overrides: Map<String, String>): Map<String, String> {
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
