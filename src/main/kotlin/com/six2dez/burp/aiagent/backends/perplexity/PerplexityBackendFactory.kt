package com.six2dez.burp.aiagent.backends.perplexity

import com.six2dez.burp.aiagent.backends.AiBackend
import com.six2dez.burp.aiagent.backends.AiBackendFactory
import com.six2dez.burp.aiagent.backends.HealthCheckResult
import com.six2dez.burp.aiagent.backends.http.MontoyaHttpTransport
import com.six2dez.burp.aiagent.backends.openai.OpenAiCompatibleBackend
import com.six2dez.burp.aiagent.backends.openai.OpenAiModelsUrl
import com.six2dez.burp.aiagent.config.AgentSettings
import com.six2dez.burp.aiagent.util.HeaderParser
import java.util.concurrent.TimeUnit

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
            streaming = false,
            defaultHeaders = mapOf("Accept" to "application/json"),
            healthCheckProvider = ::perplexityHealthCheck,
            // Perplexity's chat-completions endpoint is at the root, no /v1 prefix.
            chatCompletionsBasePath = "/chat/completions",
            // Perplexity's Sonar API does not accept {"type":"json_object"} response_format; the
            // scanner prompts still request JSON via the system message, which Sonar honors.
            supportsJsonObjectResponseFormat = false,
        )

    companion object {
        const val DEFAULT_BASE_URL: String = "https://api.perplexity.ai"

        private const val HEALTH_TIMEOUT_MIN_SECONDS = 5
        private const val HEALTH_TIMEOUT_MAX_SECONDS = 30

        private fun perplexityHealthCheck(
            settings: AgentSettings,
            transport: MontoyaHttpTransport?,
        ): HealthCheckResult {
            val baseUrl = settings.perplexityUrl.trim().ifBlank { DEFAULT_BASE_URL }
            return when {
                settings.perplexityModel.isBlank() -> HealthCheckResult.Unavailable("Perplexity model is empty.")
                // BUG-69-01: health traffic must use Burp's HTTP stack. Without the registry-injected
                // transport there is no safe way to probe, so report Unknown instead of opening a socket.
                transport == null -> HealthCheckResult.Unknown
                else -> {
                    val headers =
                        HeaderParser.withBearerToken(
                            settings.perplexityApiKey,
                            HeaderParser.parse(settings.perplexityHeaders),
                        )
                    val timeoutSeconds =
                        settings.perplexityTimeoutSeconds.coerceIn(HEALTH_TIMEOUT_MIN_SECONDS, HEALTH_TIMEOUT_MAX_SECONDS)
                    val timeoutMs = TimeUnit.SECONDS.toMillis(timeoutSeconds.toLong())
                    // GET /v1/models is free; the previous chat-completion probe was billed on every check.
                    transport.healthCheckGet(OpenAiModelsUrl.versioned(baseUrl), headers, timeoutMs)
                }
            }
        }
    }
}
