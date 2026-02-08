package com.six2dez.burp.aiagent.backends.ollama

import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.module.kotlin.registerKotlinModule
import com.six2dez.burp.aiagent.backends.AgentConnection
import com.six2dez.burp.aiagent.backends.AiBackend
import com.six2dez.burp.aiagent.backends.BackendDiagnostics
import com.six2dez.burp.aiagent.backends.BackendLaunchConfig
import com.six2dez.burp.aiagent.backends.http.ConversationHistory
import com.six2dez.burp.aiagent.backends.http.HttpBackendSupport
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicBoolean

class OllamaBackend : AiBackend {
    override val id: String = "ollama"
    override val displayName: String = "Ollama (local)"

    private val mapper = ObjectMapper().registerKotlinModule()

    override fun launch(config: BackendLaunchConfig): AgentConnection {
        val baseUrl = config.baseUrl?.trimEnd('/') ?: "http://127.0.0.1:11434"
        val model = config.model?.ifBlank { "llama3.1" } ?: "llama3.1"
        val timeoutSeconds = (config.requestTimeoutSeconds ?: 120L).coerceIn(30L, 3600L)
        val client = HttpBackendSupport.buildClient(timeoutSeconds)
        return OllamaConnection(
            client = client,
            mapper = mapper,
            baseUrl = baseUrl,
            model = model,
            headers = config.headers,
            determinismMode = config.determinismMode,
            sessionId = config.sessionId,
            contextWindow = config.contextWindow,
            debugLog = { BackendDiagnostics.log("[ollama] $it") },
            errorLog = { BackendDiagnostics.logError("[ollama] $it") }
        )
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
        private val debugLog: (String) -> Unit,
        private val errorLog: (String) -> Unit
    ) : AgentConnection {

        private val alive = AtomicBoolean(true)
        private val exec = Executors.newSingleThreadExecutor { runnable ->
            Thread(runnable, "ollama-connection").apply { isDaemon = true }
        }
        private val conversationHistory = ConversationHistory(20)

        override fun isAlive(): Boolean = alive.get()

        override fun send(
            text: String,
            history: List<com.six2dez.burp.aiagent.backends.ChatMessage>?,
            onChunk: (String) -> Unit,
            onComplete: (Throwable?) -> Unit
        ) {
            if (!isAlive()) {
                onComplete(IllegalStateException("Connection closed"))
                return
            }

            debugLog("send invoked (alive=${isAlive()}) textBytes=${text.toByteArray(Charsets.UTF_8).size}")
            exec.submit {
                try {
                    debugLog("worker started on ${Thread.currentThread().name}")
                    
                    // Sync history if provided
                    if (history != null) {
                        conversationHistory.setHistory(history)
                    }
                    
                    val maxAttempts = 6
                    var attempt = 0
                    var lastError: Exception? = null
                    while (attempt < maxAttempts) {
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
                                numCtx = contextWindow
                            )
                            debugLog("serialize done bytes=${json.toByteArray(Charsets.UTF_8).size}")
                            val req = Request.Builder()
                                .url("$baseUrl/api/chat")
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

                            debugLog("request -> ${req.url} (stream=false)")
                            client.newCall(req).execute().use { resp ->
                                if (!resp.isSuccessful) {
                                    val bodyText = resp.body?.string().orEmpty()
                                    errorLog("HTTP ${resp.code}: ${bodyText.take(500)}")
                                    onComplete(IllegalStateException("Ollama HTTP ${resp.code}: $bodyText"))
                                    return@submit
                                }
                                debugLog("response <- HTTP ${resp.code}")
                                val body = resp.body?.string().orEmpty()
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

                                if (content.isBlank()) {
                                    onComplete(IllegalStateException("Ollama response content was empty"))
                                    return@submit
                                }

                                debugLog("received complete response (${content.length} chars)")
                                // Add assistant response to conversation history
                                conversationHistory.addAssistant(content)
                                onChunk(content)
                                onComplete(null)
                                return@submit
                            }
                        } catch (e: Exception) {
                            lastError = e
                            if (!HttpBackendSupport.isRetryableConnectionError(e) || attempt == maxAttempts - 1) {
                                throw e
                            }
                            val delayMs = HttpBackendSupport.retryDelayMs(attempt)
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
            numCtx: Int?
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
            if (temperature != null || numCtx != null) {
                sb.append(",\"options\":{")
                var firstOpt = true
                if (temperature != null) {
                    sb.append("\"temperature\":").append(temperature)
                    firstOpt = false
                }
                if (numCtx != null) {
                    if (!firstOpt) sb.append(",")
                    sb.append("\"num_ctx\":").append(numCtx)
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
