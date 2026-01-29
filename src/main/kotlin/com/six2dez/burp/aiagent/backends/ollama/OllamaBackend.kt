package com.six2dez.burp.aiagent.backends.ollama

import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.module.kotlin.registerKotlinModule
import com.six2dez.burp.aiagent.backends.AgentConnection
import com.six2dez.burp.aiagent.backends.AiBackend
import com.six2dez.burp.aiagent.backends.BackendDiagnostics
import com.six2dez.burp.aiagent.backends.BackendLaunchConfig
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import java.net.Proxy
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicBoolean

class OllamaBackend : AiBackend {
    override val id: String = "ollama"
    override val displayName: String = "Ollama (local)"

    private val client = OkHttpClient.Builder()
        .connectTimeout(java.time.Duration.ofSeconds(10))
        .writeTimeout(java.time.Duration.ofSeconds(30))
        .readTimeout(java.time.Duration.ofSeconds(120))
        .callTimeout(java.time.Duration.ofSeconds(120))
        .proxy(Proxy.NO_PROXY)
        .build()
    private val mapper = ObjectMapper().registerKotlinModule()

    override fun launch(config: BackendLaunchConfig): AgentConnection {
        val baseUrl = config.baseUrl?.trimEnd('/') ?: "http://127.0.0.1:11434"
        val model = config.model?.ifBlank { "llama3.1" } ?: "llama3.1"
        return OllamaConnection(
            client = client,
            mapper = mapper,
            baseUrl = baseUrl,
            model = model,
            headers = config.headers,
            determinismMode = config.determinismMode,
            sessionId = config.sessionId,
            debugLog = { BackendDiagnostics.log("[ollama] $it") },
            errorLog = { BackendDiagnostics.logError("[ollama] $it") }
        )
    }

    private class OllamaConnection(
        private val client: OkHttpClient,
        private val mapper: ObjectMapper,
        private val baseUrl: String,
        private val model: String,
        private val headers: Map<String, String>,
        private val determinismMode: Boolean,
        private val sessionId: String?,
        private val debugLog: (String) -> Unit,
        private val errorLog: (String) -> Unit
    ) : AgentConnection {

        private val alive = AtomicBoolean(true)
        private val exec = Executors.newSingleThreadExecutor { runnable ->
            Thread(runnable, "ollama-connection").apply { isDaemon = true }
        }
        private val conversationHistory = mutableListOf<Map<String, String>>()
        private val maxHistoryMessages = 20

        override fun isAlive(): Boolean = alive.get()

        override fun send(text: String, onChunk: (String) -> Unit, onComplete: (Throwable?) -> Unit) {
            if (!isAlive()) {
                onComplete(IllegalStateException("Connection closed"))
                return
            }

            debugLog("send invoked (alive=${isAlive()}) textBytes=${text.toByteArray(Charsets.UTF_8).size}")
            exec.submit {
                try {
                    debugLog("worker started on ${Thread.currentThread().name}")
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
                            synchronized(conversationHistory) {
                                conversationHistory.add(mapOf("role" to "user", "content" to text))
                                trimHistory()
                            }
                            // Use non-streaming mode for better performance
                            val json = buildChatJson(
                                model = model,
                                stream = false,
                                temperature = if (determinismMode) 0.0 else null
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
                                synchronized(conversationHistory) {
                                    conversationHistory.add(mapOf("role" to "assistant", "content" to content))
                                    trimHistory()
                                }
                                onChunk(content)
                                onComplete(null)
                                return@submit
                            }
                        } catch (e: Exception) {
                            lastError = e
                            if (!isRetryableConnectionError(e) || attempt == maxAttempts - 1) {
                                throw e
                            }
                            val delayMs = retryDelayMs(attempt)
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

        private fun sendNonStreaming(
            text: String,
            temperature: Double?,
            onChunk: (String) -> Unit,
            onComplete: (Throwable?) -> Unit
        ) {
            try {
                val json = buildChatJson(
                    model = model,
                    stream = false,
                    temperature = temperature
                )
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
                        return
                    }
                    val body = resp.body?.string().orEmpty()
                    if (body.isBlank()) {
                        onComplete(IllegalStateException("Ollama response body was empty"))
                        return
                    }
                    val node = mapper.readTree(body)
                    val content = node.path("message").path("content").asText()
                        .ifBlank { node.path("response").asText() }
                    if (content.isBlank()) {
                        onComplete(IllegalStateException("Ollama response content was empty"))
                        return
                    }
                    onChunk(content)
                    onComplete(null)
                }
            } catch (e: Exception) {
                errorLog("exception (stream=false): ${e.message}")
                onComplete(e)
            }
        }

        private fun buildChatJson(
            model: String,
            stream: Boolean,
            temperature: Double?
        ): String {
            val messages = synchronized(conversationHistory) { conversationHistory.toList() }
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
            if (temperature != null) {
                sb.append(",\"options\":{\"temperature\":").append(temperature).append("}")
            }
            sb.append("}")
            return sb.toString()
        }

        private fun trimHistory() {
            while (conversationHistory.size > maxHistoryMessages) {
                conversationHistory.removeAt(0)
            }
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

        private fun isRetryableConnectionError(e: Exception): Boolean {
            if (e is java.net.ConnectException || e is java.net.SocketTimeoutException) return true
            val msg = e.message?.lowercase().orEmpty()
            return msg.contains("failed to connect") || msg.contains("connection refused") || msg.contains("timeout")
        }

        private fun retryDelayMs(attempt: Int): Long {
            return when (attempt) {
                0 -> 500
                1 -> 1000
                2 -> 1500
                3 -> 2000
                4 -> 3000
                else -> 4000
            }
        }

        override fun stop() {
            alive.set(false)
            exec.shutdownNow()
        }
    }
}
