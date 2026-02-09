package com.six2dez.burp.aiagent.backends.lmstudio

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

class LmStudioBackend : AiBackend {
    override val id: String = "lmstudio"
    override val displayName: String = "LM Studio (local)"

    private val mapper = ObjectMapper().registerKotlinModule()

    override fun launch(config: BackendLaunchConfig): AgentConnection {
        val baseUrl = config.baseUrl?.trimEnd('/') ?: "http://127.0.0.1:1234"
        val model = config.model?.ifBlank { "lmstudio" } ?: "lmstudio"
        val timeoutSeconds = (config.requestTimeoutSeconds ?: 120L).coerceIn(30L, 3600L)
        val client = HttpBackendSupport.buildClient(timeoutSeconds)
        return LmStudioConnection(
            client,
            mapper,
            baseUrl,
            model,
            config.headers,
            config.determinismMode,
            config.sessionId,
            debugLog = { BackendDiagnostics.log("[lmstudio] $it") },
            errorLog = { BackendDiagnostics.logError("[lmstudio] $it") }
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
        private val debugLog: (String) -> Unit,
        private val errorLog: (String) -> Unit
    ) : AgentConnection {
        private val alive = AtomicBoolean(true)
        private val exec = Executors.newSingleThreadExecutor { runnable ->
            Thread(runnable, "lmstudio-connection").apply { isDaemon = true }
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

            exec.submit {
                try {
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
                                if (content.isBlank()) {
                                    onComplete(IllegalStateException("LM Studio response content was empty"))
                                    return@submit
                                }
                                debugLog("response <- ${content.take(200)}")
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

        override fun stop() {
            alive.set(false)
            exec.shutdownNow()
        }
    }
}
