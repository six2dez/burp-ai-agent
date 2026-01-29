package com.six2dez.burp.aiagent.backends.openai

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
import java.io.EOFException
import java.net.Proxy
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicBoolean

class OpenAiCompatibleBackend : AiBackend {
    override val id: String = "openai-compatible"
    override val displayName: String = "Generic (OpenAI-compatible)"

    private val mapper = ObjectMapper().registerKotlinModule()

    override fun launch(config: BackendLaunchConfig): AgentConnection {
        val baseUrl = config.baseUrl?.trimEnd('/') ?: ""
        val model = config.model?.ifBlank { "" } ?: ""
        val timeoutSeconds = (config.requestTimeoutSeconds ?: 120L).coerceIn(30L, 3600L)
        val client = buildClient(timeoutSeconds)
        return OpenAiCompatibleConnection(
            client = client,
            mapper = mapper,
            baseUrl = baseUrl,
            model = model,
            headers = config.headers,
            determinismMode = config.determinismMode,
            sessionId = config.sessionId,
            debugLog = { BackendDiagnostics.log("[openai-compatible] $it") },
            errorLog = { BackendDiagnostics.logError("[openai-compatible] $it") }
        )
    }

    private fun buildClient(timeoutSeconds: Long): OkHttpClient {
        return OkHttpClient.Builder()
            .connectTimeout(java.time.Duration.ofSeconds(10))
            .writeTimeout(java.time.Duration.ofSeconds(30))
            .readTimeout(java.time.Duration.ofSeconds(timeoutSeconds))
            .callTimeout(java.time.Duration.ofSeconds(timeoutSeconds))
            .proxy(Proxy.NO_PROXY)
            .build()
    }

    private class OpenAiCompatibleConnection(
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
            Thread(runnable, "openai-compatible-connection").apply { isDaemon = true }
        }
        private val conversationHistory = mutableListOf<Map<String, String>>()
        private val maxHistoryMessages = 20

        override fun isAlive(): Boolean = alive.get()

        override fun send(text: String, onChunk: (String) -> Unit, onComplete: (Throwable?) -> Unit) {
            if (!isAlive()) {
                onComplete(IllegalStateException("Connection closed"))
                return
            }

            exec.submit {
                try {
                    val maxAttempts = 6
                    var attempt = 0
                    var lastError: Exception? = null
                    while (attempt < maxAttempts) {
                        if (!isAlive()) {
                            onComplete(IllegalStateException("Connection closed"))
                            return@submit
                        }
                        try {
                            synchronized(conversationHistory) {
                                conversationHistory.add(mapOf("role" to "user", "content" to text))
                                while (conversationHistory.size > maxHistoryMessages) {
                                    conversationHistory.removeAt(0)
                                }
                            }
                            val messages = synchronized(conversationHistory) { conversationHistory.toList() }
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
                                    onComplete(IllegalStateException("OpenAI-compatible HTTP ${resp.code}: $bodyText"))
                                    return@submit
                                }
                                val body = resp.body?.string().orEmpty()
                                if (body.isBlank()) {
                                    onComplete(IllegalStateException("OpenAI-compatible response body was empty"))
                                    return@submit
                                }
                                val node = mapper.readTree(body)
                                val content = node.path("choices").path(0).path("message").path("content").asText()
                                if (content.isBlank()) {
                                    onComplete(IllegalStateException("OpenAI-compatible response content was empty"))
                                    return@submit
                                }
                                debugLog("response <- ${content.take(200)}")
                                synchronized(conversationHistory) {
                                    conversationHistory.add(mapOf("role" to "assistant", "content" to content))
                                    while (conversationHistory.size > maxHistoryMessages) {
                                        conversationHistory.removeAt(0)
                                    }
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

        override fun stop() {
            alive.set(false)
            exec.shutdownNow()
        }

        private fun isRetryableConnectionError(e: Exception): Boolean {
            if (e is EOFException) return true
            if (e is java.net.ConnectException || e is java.net.SocketTimeoutException) return true
            if (e is java.net.SocketException) return true
            val msg = e.message?.lowercase().orEmpty()
            return msg.contains("failed to connect") ||
                msg.contains("connection refused") ||
                msg.contains("timeout") ||
                msg.contains("unexpected end of stream") ||
                msg.contains("stream was reset") ||
                msg.contains("end of input")
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
    }
}
