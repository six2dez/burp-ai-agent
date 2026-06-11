package com.six2dez.burp.aiagent.backends.anthropic

import com.fasterxml.jackson.databind.JsonNode
import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.module.kotlin.registerKotlinModule
import com.six2dez.burp.aiagent.backends.AgentConnection
import com.six2dez.burp.aiagent.backends.AiBackend
import com.six2dez.burp.aiagent.backends.BackendDiagnostics
import com.six2dez.burp.aiagent.backends.BackendLaunchConfig
import com.six2dez.burp.aiagent.backends.TokenUsage
import com.six2dez.burp.aiagent.backends.UsageAwareConnection
import com.six2dez.burp.aiagent.backends.http.CircuitBreaker
import com.six2dez.burp.aiagent.backends.http.ConversationHistory
import com.six2dez.burp.aiagent.backends.http.HttpBackendSupport
import com.six2dez.burp.aiagent.backends.http.MontoyaHttpTransport
import com.six2dez.burp.aiagent.backends.http.recordHttpFailureIfRetryable
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicReference

/**
 * Native Anthropic Messages API backend (CAP-01).
 *
 * SC2: all production HTTP routed through the injected [MontoyaHttpTransport].
 * SC2c: no direct HTTP client construction on this path (verified by AnthropicBackendTransportRoutingTest).
 * transport == null → fail fast (AnthropicBackendTransportRoutingTest SC2b).
 * SC3: a 400 whose body contains "model" surfaces the exact CONTEXT.md error string.
 */
class AnthropicBackend : AiBackend {
    override val id: String = "anthropic"
    override val displayName: String = "Anthropic"

    // supportsSystemRole = true: the supervisor sets systemPrompt on the shared AgentProtocol;
    // AnthropicConnection maps it to the top-level "system" request field (not a system-role message).
    override val supportsSystemRole: Boolean = true

    private val mapper = ObjectMapper().registerKotlinModule()

    override fun launch(config: BackendLaunchConfig): AgentConnection {
        val model = config.model?.ifBlank { "" } ?: ""
        val timeoutSeconds = (config.requestTimeoutSeconds ?: 120L).coerceIn(30L, 3600L)
        return AnthropicConnection(
            mapper = mapper,
            model = model,
            headers = config.headers,
            determinismMode = config.determinismMode,
            sessionId = config.sessionId,
            circuitBreaker = HttpBackendSupport.newCircuitBreaker(),
            transport = config.transport,
            timeoutSeconds = timeoutSeconds,
            debugLog = { BackendDiagnostics.log("[anthropic] $it") },
            errorLog = { BackendDiagnostics.logError("[anthropic] $it") },
        )
    }

    // WR-04: like the other keyed HTTP backends, Anthropic is only "available" once an API key is
    // configured. Without this, a blank key inherits the default isAvailable()=true and the registry
    // maps Unknown + available → Healthy, masking the missing credential until the first 401.
    override fun isAvailable(settings: com.six2dez.burp.aiagent.config.AgentSettings): Boolean =
        settings.anthropicApiKey.isNotBlank()

    // HealthCheckResult.Unknown = not testable without a live request; the registry calls
    // isAvailable() (now key-gated above), and surfacing a dedicated health-check endpoint would
    // require a live API key — defer to the supervisor's test-connection path.
    override fun healthCheck(settings: com.six2dez.burp.aiagent.config.AgentSettings) =
        com.six2dez.burp.aiagent.backends.HealthCheckResult.Unknown

    private class AnthropicConnection(
        private val mapper: ObjectMapper,
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
        UsageAwareConnection {
        private val alive = AtomicBoolean(true)
        private val exec =
            Executors.newSingleThreadExecutor { runnable ->
                Thread(runnable, "anthropic-connection").apply { isDaemon = true }
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
                    val maxAttempts = 6
                    var attempt = 0
                    var lastError: Exception? = null
                    while (attempt < maxAttempts) {
                        val permission = circuitBreaker.tryAcquire()
                        if (!permission.allowed) {
                            val failFastError =
                                HttpBackendSupport.openCircuitError("Anthropic", permission.retryAfterMs)
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

                            // DIVERGENCE 1 — system prompt: Anthropic has NO system role in messages[].
                            // Do NOT call conversationHistory.setSystemPrompt — that would inject a
                            // {"role":"system",…} entry which Anthropic's API rejects. Instead, pass
                            // systemPrompt as the top-level "system" field in the request payload.
                            if (history != null) conversationHistory.setHistory(history)
                            conversationHistory.addUser(text)
                            val messages = conversationHistory.snapshot()

                            val payload =
                                mutableMapOf<String, Any?>(
                                    "model" to model,
                                    "max_tokens" to (maxOutputTokens ?: 1024), // REQUIRED by Anthropic
                                    "messages" to messages,
                                    "stream" to false, // Pitfall 1: buffered single-chunk via transport.post
                                )
                            // DIVERGENCE 1 (continued): top-level "system" field, not a messages entry.
                            if (!systemPrompt.isNullOrBlank()) {
                                payload["system"] = systemPrompt
                            }
                            if (determinismMode) {
                                payload["temperature"] = 0.0
                            }

                            val json = mapper.writeValueAsString(payload)

                            // DIVERGENCE 2 — headers: x-api-key + anthropic-version (NOT Bearer).
                            // The transport adds Content-Type: application/json automatically.
                            val allHeaders =
                                buildMap {
                                    putAll(headers)
                                    if (!sessionId.isNullOrBlank()) {
                                        put("X-Session-Id", sessionId)
                                    }
                                }

                            // Bug #66: pre-flight log shows the body SHAPE only — never the JSON itself
                            // and never the message content. Privacy guarantee (STRIDE T-14-03).
                            val safeBodyPreview =
                                buildString {
                                    append("model=").append(model)
                                    append(" messages=").append(messages.size)
                                    append(" json_bytes=").append(json.length)
                                    if (maxOutputTokens != null) append(" max_tokens=").append(maxOutputTokens)
                                }
                            debugLog("request -> POST $ANTHROPIC_MESSAGES_URL ($safeBodyPreview)")

                            // DIVERGENCE 3 — endpoint: fixed constant (no base URL selector).
                            val resp = transport.post(ANTHROPIC_MESSAGES_URL, allHeaders, json, timeoutSeconds * 1000)

                            // DIVERGENCE 4 — SC3: check for model-rejection 400 BEFORE the generic handler.
                            if (resp.statusCode == 400 && resp.body.contains("model", ignoreCase = true)) {
                                onComplete(
                                    IllegalStateException(
                                        "Anthropic rejected the model ID — check Settings > Anthropic > Model",
                                    ),
                                )
                                return@submit
                            }

                            if (!resp.isSuccessful) {
                                errorLog("HTTP ${resp.statusCode}: ${resp.body.take(500)}")
                                val message =
                                    when (resp.statusCode) {
                                        429 -> "Anthropic rate limited (HTTP 429). Check quota/capacity or retry later."
                                        else ->
                                            buildString {
                                                append("Anthropic HTTP ${resp.statusCode} from POST ").append(ANTHROPIC_MESSAGES_URL)
                                                append("\nResponse: ").append(resp.body.take(800))
                                                append(
                                                    "\nHints: verify the model name is valid and the API key is correct.",
                                                )
                                            }
                                    }
                                circuitBreaker.recordHttpFailureIfRetryable(resp.statusCode)
                                onComplete(IllegalStateException(message))
                                return@submit
                            }

                            val body = resp.body
                            if (body.isBlank()) {
                                onComplete(IllegalStateException("Anthropic response body was empty"))
                                return@submit
                            }

                            val node = mapper.readTree(body)

                            // DIVERGENCE 5 — response parsing: iterate content[], concatenate text blocks.
                            val content =
                                buildString {
                                    node.path("content").forEach { block ->
                                        if (block.path("type").asText() == "text") {
                                            append(block.path("text").asText())
                                        }
                                    }
                                }

                            // DIVERGENCE 6 — usage extraction: input_tokens / output_tokens.
                            extractUsage(node)?.let { lastTokenUsageRef.set(it) }

                            if (content.isBlank()) {
                                onComplete(IllegalStateException("Anthropic response content was empty"))
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
                            BackendDiagnostics.logRetry("anthropic", attempt + 1, delayMs, e.message)
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

        /** DIVERGENCE 6: Anthropic usage fields are input_tokens / output_tokens. */
        private fun extractUsage(node: JsonNode): TokenUsage? {
            val u = node.path("usage")
            val input = u.path("input_tokens").asInt(-1)
            val output = u.path("output_tokens").asInt(-1)
            if (input < 0 && output < 0) return null
            return TokenUsage(
                inputTokens = input.coerceAtLeast(0),
                outputTokens = output.coerceAtLeast(0),
            )
        }

        override fun stop() {
            alive.set(false)
            exec.shutdownNow()
        }
    }

    private companion object {
        /** Fixed Anthropic Messages API endpoint (CONTEXT.md / RESEARCH §1). */
        private const val ANTHROPIC_MESSAGES_URL = "https://api.anthropic.com/v1/messages"
    }
}
