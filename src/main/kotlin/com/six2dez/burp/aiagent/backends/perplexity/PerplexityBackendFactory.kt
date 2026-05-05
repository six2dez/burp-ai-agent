package com.six2dez.burp.aiagent.backends.perplexity

import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.module.kotlin.registerKotlinModule
import com.six2dez.burp.aiagent.backends.AiBackend
import com.six2dez.burp.aiagent.backends.AiBackendFactory
import com.six2dez.burp.aiagent.backends.HealthCheckResult
import com.six2dez.burp.aiagent.backends.http.HttpBackendSupport
import com.six2dez.burp.aiagent.backends.openai.OpenAiCompatibleBackend
import com.six2dez.burp.aiagent.config.AgentSettings
import com.six2dez.burp.aiagent.util.HeaderParser
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody

class PerplexityBackendFactory : AiBackendFactory {
    override fun create(): AiBackend =
        OpenAiCompatibleBackend(
            id = "perplexity",
            displayName = "Perplexity",
            defaultBaseUrl = DEFAULT_BASE_URL,
            baseUrlSelector = { it.perplexityUrl.trim() },
            modelSelector = { it.perplexityModel.trim() },
            apiKeySelector = { it.perplexityApiKey },
            headersSelector = { it.perplexityHeaders },
            timeoutSelector = { it.perplexityTimeoutSeconds },
            streaming = true,
            defaultHeaders = mapOf("Accept" to "text/event-stream"),
            healthCheckProvider = ::perplexityHealthCheck,
            // Perplexity's chat-completions endpoint is at the root, no /v1 prefix.
            chatCompletionsBasePath = "/chat/completions",
            // Perplexity's Sonar API does not accept {"type":"json_object"} response_format; the
            // scanner prompts still request JSON via the system message, which Sonar honors.
            supportsJsonObjectResponseFormat = false,
        )

    companion object {
        const val DEFAULT_BASE_URL: String = "https://api.perplexity.ai"

        private val mapper = ObjectMapper().registerKotlinModule()

        private fun perplexityHealthCheck(settings: AgentSettings): HealthCheckResult {
            val baseUrl = settings.perplexityUrl.trim().ifBlank { DEFAULT_BASE_URL }
            val model = settings.perplexityModel.trim()
            if (model.isBlank()) {
                return HealthCheckResult.Unavailable("Perplexity model is empty.")
            }

            val headers =
                withDefaultAcceptHeader(
                    HeaderParser.withBearerToken(
                        settings.perplexityApiKey,
                        HeaderParser.parse(settings.perplexityHeaders),
                    ),
                )
            val payload =
                mapOf(
                    "model" to model,
                    "messages" to listOf(mapOf("role" to "user", "content" to "Hey")),
                    "max_tokens" to 16,
                    "stream" to false,
                )

            return try {
                val url = buildChatCompletionsUrl(baseUrl)
                val client = HttpBackendSupport.sharedClient(baseUrl, settings.perplexityTimeoutSeconds.toLong().coerceIn(5L, 30L))
                val request =
                    Request
                        .Builder()
                        .url(url)
                        .post(mapper.writeValueAsString(payload).toRequestBody("application/json".toMediaType()))
                        .apply { headers.forEach { (name, value) -> header(name, value) } }
                        .build()
                client.newCall(request).execute().use { response ->
                    when {
                        response.isSuccessful -> HealthCheckResult.Healthy
                        response.code == 401 || response.code == 403 ->
                            HealthCheckResult.Degraded("Endpoint reachable but authentication failed (HTTP ${response.code}).")
                        response.code == 429 ->
                            HealthCheckResult.Degraded("Endpoint reachable but rate limited (HTTP 429).")
                        else -> HealthCheckResult.Unavailable("HTTP ${response.code}.")
                    }
                }
            } catch (e: Exception) {
                HealthCheckResult.Unavailable(e.message ?: "Request failed")
            }
        }

        private fun buildChatCompletionsUrl(baseUrl: String): String {
            val trimmed = baseUrl.trimEnd('/')
            val lower = trimmed.lowercase()
            if (lower.endsWith("/chat/completions")) return trimmed
            if (lower.matches(Regex(".*/v\\d+/chat/completions", RegexOption.IGNORE_CASE))) return trimmed
            if (lower.matches(Regex(".*/v\\d+", RegexOption.IGNORE_CASE))) return "$trimmed/chat/completions"
            return "$trimmed/chat/completions"
        }

        private fun withDefaultAcceptHeader(headers: Map<String, String>): Map<String, String> {
            val merged = LinkedHashMap<String, String>()
            merged.putAll(headers)
            if (merged.keys.none { it.equals("accept", ignoreCase = true) }) {
                merged["Accept"] = "text/event-stream"
            }
            return merged
        }
    }
}
