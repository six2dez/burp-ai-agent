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
        return HttpBackendSupport.healthCheckGet(
            url = buildModelsUrl(baseUrl),
            headers = headers,
            timeoutSeconds = timeoutSelector(settings).coerceIn(1, 30).toLong(),
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

                            if (transport != null) {
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
                            } else {
                                val req =
                                    Request
                                        .Builder()
                                        .url(endpointUrl)
                                        .post(json.toRequestBody("application/json".toMediaType()))
                                        .apply {
                                            allHeaders.forEach { (name, value) ->
                                                header(name, value)
                                            }
                                        }.build()
                                client.newCall(req).execute().use { resp ->
                                    if (!resp.isSuccessful) {
                                        val bodyText = resp.body?.string().orEmpty()
                                        errorLog("HTTP ${resp.code}: ${bodyText.take(500)}")
                                        val retryAfter = resp.header("Retry-After")
                                        val message =
                                            when (resp.code) {
                                                429 -> {
                                                    val retryHint =
                                                        retryAfter
                                                            ?.takeIf { it.isNotBlank() }
                                                            ?.let { " Retry after: $it." }
                                                            .orEmpty()
                                                    "$backendDisplayName rate limited (HTTP 429). Check quota/capacity or retry later.$retryHint"
                                                }
                                                // Bug #66: same diagnosable-4xx shape as the Montoya
                                                // transport branch — keep both transports identical
                                                // so the user sees consistent error messages.
                                                else ->
                                                    buildString {
                                                        append("$backendDisplayName HTTP ${resp.code} from POST ").append(endpointUrl)
                                                        append("\nResponse: ").append(bodyText.take(800))
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
                                    if (streaming) {
                                        handleStreamingResponse(resp, onChunk, onComplete)
                                    } else {
                                        handleNonStreamingResponse(resp, onChunk, onComplete)
                                    }
                                }
                            }
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

        private fun handleNonStreamingResponse(
            resp: okhttp3.Response,
            onChunk: (String) -> Unit,
            onComplete: (Throwable?) -> Unit,
        ) {
            val body = resp.body?.string().orEmpty()
            if (body.isBlank()) {
                onComplete(IllegalStateException("$backendDisplayName response body was empty"))
                return
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
            onComplete: (Throwable?) -> Unit,
        ) {
            val body =
                resp.body ?: run {
                    onComplete(IllegalStateException("$backendDisplayName response body was empty"))
                    return
                }
            // Force UTF-8 on SSE chunks: OpenAI-compatible servers send `text/event-stream` without
            // an explicit charset, so a default-charset reader can mojibake multibyte content.
            val streamReader = BufferedReader(InputStreamReader(body.byteStream(), Charsets.UTF_8))
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
