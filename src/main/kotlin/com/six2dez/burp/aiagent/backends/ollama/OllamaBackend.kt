package com.six2dez.burp.aiagent.backends.ollama

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
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicReference

class OllamaBackend : AiBackend {
    override val id: String = "ollama"
    override val displayName: String = "Ollama (local)"
    override val supportsSystemRole: Boolean = true

    private val mapper = ObjectMapper().registerKotlinModule()

    companion object {
        private const val DEFAULT_CONTEXT_WINDOW = 8192
    }

    override fun launch(config: BackendLaunchConfig): AgentConnection {
        val baseUrl = config.baseUrl?.trimEnd('/') ?: "http://127.0.0.1:11434"
        val model = config.model?.ifBlank { "llama3.1" } ?: "llama3.1"
        val timeoutSeconds = (config.requestTimeoutSeconds ?: 120L).coerceIn(30L, 3600L)
        val client = HttpBackendSupport.sharedClient(baseUrl, timeoutSeconds)

        val resolvedContextWindow = if (config.contextWindow == null || config.contextWindow == DEFAULT_CONTEXT_WINDOW) {
            detectContextWindow(baseUrl, model, config.headers, config.contextWindow, config.transport)
        } else {
            BackendDiagnostics.log("[ollama] Using user-configured context window: ${config.contextWindow}")
            config.contextWindow
        }

        return OllamaConnection(
            client = client,
            mapper = mapper,
            baseUrl = baseUrl,
            model = model,
            headers = config.headers,
            determinismMode = config.determinismMode,
            sessionId = config.sessionId,
            contextWindow = resolvedContextWindow,
            circuitBreaker = HttpBackendSupport.newCircuitBreaker(),
            transport = config.transport,
            timeoutSeconds = timeoutSeconds,
            debugLog = { BackendDiagnostics.log("[ollama] $it") },
            errorLog = { BackendDiagnostics.logError("[ollama] $it") }
        )
    }

    override fun healthCheck(settings: AgentSettings): HealthCheckResult {
        val baseUrl = settings.ollamaUrl.trim()
        if (baseUrl.isBlank()) {
            return HealthCheckResult.Unavailable("Ollama URL is empty.")
        }
        val headers = HeaderParser.withBearerToken(
            settings.ollamaApiKey,
            HeaderParser.parse(settings.ollamaHeaders)
        )
        return HttpBackendSupport.healthCheckGet(
            url = "${baseUrl.trimEnd('/')}/api/tags",
            headers = headers
        )
    }

    private fun detectContextWindow(
        baseUrl: String,
        model: String,
        headers: Map<String, String>,
        fallback: Int?,
        transport: MontoyaHttpTransport? = null
    ): Int? {
        try {
            val requestJson = mapper.writeValueAsString(mapOf("name" to model))
            val showUrl = "$baseUrl/api/show"

            val body: String
            if (transport != null) {
                val resp = transport.post(showUrl, headers, requestJson, 5_000)
                if (!resp.isSuccessful) {
                    BackendDiagnostics.log(
                        "[ollama] /api/show returned HTTP ${resp.statusCode}, using fallback: $fallback"
                    )
                    return fallback
                }
                body = resp.body
            } else {
                val client = HttpBackendSupport.sharedClient(baseUrl, 5L)
                val request = Request.Builder()
                    .url(showUrl)
                    .post(requestJson.toRequestBody("application/json".toMediaType()))
                    .apply {
                        headers.forEach { (name, value) -> header(name, value) }
                    }
                    .build()

                val okResp = client.newCall(request).execute()
                okResp.use { resp ->
                    if (!resp.isSuccessful) {
                        BackendDiagnostics.log(
                            "[ollama] /api/show returned HTTP ${resp.code}, using fallback: $fallback"
                        )
                        return fallback
                    }
                    body = resp.body?.string().orEmpty()
                }
            }

            if (body.isBlank()) return fallback

            val root = mapper.readTree(body)

            // Priority 1: explicit num_ctx in parameters (user Modelfile override)
            val parameters = root.path("parameters").asText("")
            val numCtxMatch = Regex("""num_ctx\s+(\d+)""").find(parameters)
            if (numCtxMatch != null) {
                val detected = numCtxMatch.groupValues[1].toIntOrNull()
                if (detected != null && detected > 0) {
                    BackendDiagnostics.log(
                        "[ollama] Detected context window from Modelfile parameters: $detected"
                    )
                    return detected
                }
            }

            // Priority 2: *.context_length in model_info (model default)
            val modelInfo = root.path("model_info")
            if (modelInfo.isObject) {
                val iter = modelInfo.fields()
                while (iter.hasNext()) {
                    val entry = iter.next()
                    if (entry.key.endsWith(".context_length")) {
                        val detected = entry.value.asInt(-1)
                        if (detected > 0) {
                            BackendDiagnostics.log(
                                "[ollama] Detected context window from model_info: $detected"
                            )
                            return detected
                        }
                    }
                }
            }

            BackendDiagnostics.log(
                "[ollama] No context window found in /api/show response, using fallback: $fallback"
            )
            return fallback
        } catch (e: Exception) {
            BackendDiagnostics.log(
                "[ollama] Failed to detect context window: ${e.message}, using fallback: $fallback"
            )
            return fallback
        }
    }

    private class OllamaConnection(
        private val client: okhttp3.OkHttpClient,
        private val mapper: ObjectMapper,
        private val baseUrl: String,
        private val model: String,
        private val headers: Map<String, String>,
        private val determinismMode: Boolean,
        private val sessionId: String?,
        private val contextWindow: Int?,
        private val circuitBreaker: CircuitBreaker,
        private val transport: MontoyaHttpTransport?,
        private val timeoutSeconds: Long,
        private val debugLog: (String) -> Unit,
        private val errorLog: (String) -> Unit
    ) : AgentConnection, UsageAwareConnection, JsonModeCapable {

        private val alive = AtomicBoolean(true)
        private val exec = Executors.newSingleThreadExecutor { runnable ->
            Thread(runnable, "ollama-connection").apply { isDaemon = true }
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
            maxOutputTokens: Int?
        ) {
            if (!isAlive()) {
                onComplete(IllegalStateException("Connection closed"))
                return
            }

            debugLog("send invoked (alive=${isAlive()}) textBytes=${text.toByteArray(Charsets.UTF_8).size}")
            exec.submit {
                try {
                    lastTokenUsageRef.set(null)
                    debugLog("worker started on ${Thread.currentThread().name}")
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
                            val failFastError = HttpBackendSupport.openCircuitError("Ollama", permission.retryAfterMs)
                            debugLog("circuit open: ${failFastError.message}")
                            onComplete(failFastError)
                            return@submit
                        }
                        if (!isAlive()) {
                            onComplete(IllegalStateException("Connection closed"))
                            return@submit
                        }
                        try {
                            debugLog("serialize start (model=$model, baseUrl=$baseUrl)")
                            // Add user message to conversation history
                            conversationHistory.addUser(text)
                            // Use non-streaming mode for better performance
                            val json = buildChatJson(
                                model = model,
                                stream = false,
                                temperature = if (determinismMode) 0.0 else null,
                                numCtx = contextWindow,
                                formatJson = jsonMode,
                                numPredict = maxOutputTokens
                            )
                            debugLog("serialize done bytes=${json.toByteArray(Charsets.UTF_8).size}")

                            val endpointUrl = "$baseUrl/api/chat"
                            val allHeaders = buildMap {
                                putAll(headers)
                                if (!sessionId.isNullOrBlank()) {
                                    put("X-Session-Id", sessionId)
                                }
                            }

                            debugLog("request -> $endpointUrl (stream=false)")

                            val body: String
                            if (transport != null) {
                                val resp = transport.post(endpointUrl, allHeaders, json, timeoutSeconds * 1000)
                                if (!resp.isSuccessful) {
                                    errorLog("HTTP ${resp.statusCode}: ${resp.body.take(500)}")
                                    onComplete(IllegalStateException("Ollama HTTP ${resp.statusCode}: ${resp.body}"))
                                    return@submit
                                }
                                debugLog("response <- HTTP ${resp.statusCode}")
                                body = resp.body
                            } else {
                                val req = Request.Builder()
                                    .url(endpointUrl)
                                    .post(json.toRequestBody("application/json".toMediaType()))
                                    .apply {
                                        allHeaders.forEach { (name, value) ->
                                            header(name, value)
                                        }
                                    }
                                    .build()
                                val okResp = client.newCall(req).execute()
                                okResp.use { resp ->
                                    if (!resp.isSuccessful) {
                                        val bodyText = resp.body?.string().orEmpty()
                                        errorLog("HTTP ${resp.code}: ${bodyText.take(500)}")
                                        onComplete(IllegalStateException("Ollama HTTP ${resp.code}: $bodyText"))
                                        return@submit
                                    }
                                    debugLog("response <- HTTP ${resp.code}")
                                    body = resp.body?.string().orEmpty()
                                }
                            }

                            if (body.isBlank()) {
                                onComplete(IllegalStateException("Ollama response body was empty"))
                                return@submit
                            }
                            val node = mapper.readTree(body)
                            if (node.has("error")) {
                                val errText = node.path("error").asText()
                                errorLog("error: $errText")
                                onComplete(IllegalStateException("Ollama error: $errText"))
                                return@submit
                            }

                            // Extract content from either 'content' or 'response' field
                            val content = node.path("message").path("content").asText()
                                .ifBlank { node.path("response").asText() }
                            val promptTokens = node.path("prompt_eval_count").asInt(-1)
                            val completionTokens = node.path("eval_count").asInt(-1)
                            if (promptTokens >= 0 || completionTokens >= 0) {
                                lastTokenUsageRef.set(
                                    TokenUsage(
                                        inputTokens = promptTokens.coerceAtLeast(0),
                                        outputTokens = completionTokens.coerceAtLeast(0)
                                    )
                                )
                            }

                            if (content.isBlank()) {
                                onComplete(IllegalStateException("Ollama response content was empty"))
                                return@submit
                            }

                            debugLog("received complete response (${content.length} chars)")
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
                            BackendDiagnostics.logRetry("ollama", attempt + 1, delayMs, e.message)
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

        private fun buildChatJson(
            model: String,
            stream: Boolean,
            temperature: Double?,
            numCtx: Int?,
            formatJson: Boolean = false,
            numPredict: Int? = null
        ): String {
            val messages = conversationHistory.snapshot()
            val sb = StringBuilder(256)
            sb.append("{")
            sb.append("\"model\":\"").append(escapeJson(model)).append("\",")
            sb.append("\"messages\":[")
            messages.forEachIndexed { index, msg ->
                if (index > 0) sb.append(",")
                sb.append("{\"role\":\"").append(escapeJson(msg["role"] ?: "user"))
                sb.append("\",\"content\":\"").append(escapeJson(msg["content"] ?: ""))
                sb.append("\"}")
            }
            sb.append("],")
            sb.append("\"stream\":").append(if (stream) "true" else "false")
            if (formatJson) {
                sb.append(",\"format\":\"json\"")
            }
            if (temperature != null || numCtx != null || numPredict != null) {
                sb.append(",\"options\":{")
                var firstOpt = true
                if (temperature != null) {
                    sb.append("\"temperature\":").append(temperature)
                    firstOpt = false
                }
                if (numCtx != null) {
                    if (!firstOpt) sb.append(",")
                    sb.append("\"num_ctx\":").append(numCtx)
                    firstOpt = false
                }
                if (numPredict != null) {
                    if (!firstOpt) sb.append(",")
                    sb.append("\"num_predict\":").append(numPredict)
                }
                sb.append("}")
            }
            sb.append("}")
            return sb.toString()
        }

        private fun escapeJson(value: String): String {
            val out = StringBuilder(value.length + 16)
            value.forEach { ch ->
                when (ch) {
                    '\\' -> out.append("\\\\")
                    '"' -> out.append("\\\"")
                    '\n' -> out.append("\\n")
                    '\r' -> out.append("\\r")
                    '\t' -> out.append("\\t")
                    else -> {
                        if (ch < ' ') {
                            out.append(String.format("\\u%04x", ch.code))
                        } else {
                            out.append(ch)
                        }
                    }
                }
            }
            return out.toString()
        }

        override fun stop() {
            alive.set(false)
            exec.shutdownNow()
        }
    }
}
