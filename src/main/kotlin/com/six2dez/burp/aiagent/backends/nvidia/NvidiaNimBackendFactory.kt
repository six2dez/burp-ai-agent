package com.six2dez.burp.aiagent.backends.nvidia

import com.six2dez.burp.aiagent.backends.AiBackend
import com.six2dez.burp.aiagent.backends.AiBackendFactory
import com.six2dez.burp.aiagent.backends.HealthCheckResult
import com.six2dez.burp.aiagent.backends.http.MontoyaHttpTransport
import com.six2dez.burp.aiagent.backends.openai.OpenAiCompatibleBackend
import com.six2dez.burp.aiagent.backends.openai.OpenAiModelsUrl
import com.six2dez.burp.aiagent.config.AgentSettings
import com.six2dez.burp.aiagent.util.HeaderParser
import java.util.concurrent.TimeUnit

class NvidiaNimBackendFactory : AiBackendFactory {
    override fun create(): AiBackend =
        OpenAiCompatibleBackend(
            id = "nvidia-nim",
            displayName = "NVIDIA NIM",
            defaultBaseUrl = DEFAULT_BASE_URL,
            baseUrlSelector = { it.nvidiaNimUrl.trim() },
            modelSelector = { it.nvidiaNimModel.trim() },
            apiKeySelector = { it.nvidiaNimApiKey },
            headersSelector = { it.nvidiaNimHeaders },
            timeoutSelector = { it.nvidiaNimTimeoutSeconds },
            streaming = false,
            defaultHeaders = mapOf("Accept" to "application/json"),
            payloadCustomizer = { payload ->
                payload["max_tokens"] = 16384
                payload["top_p"] = 1.0
                payload["chat_template_kwargs"] = mapOf("thinking" to true)
                val temp = payload["temperature"]
                if (temp is Number && temp.toDouble() == 0.7) {
                    payload["temperature"] = 1.0
                }
            },
            healthCheckProvider = ::nimHealthCheck,
        )

    companion object {
        const val DEFAULT_BASE_URL: String = "https://integrate.api.nvidia.com"

        private const val HEALTH_TIMEOUT_MIN_SECONDS = 5
        private const val HEALTH_TIMEOUT_MAX_SECONDS = 30

        private fun nimHealthCheck(
            settings: AgentSettings,
            transport: MontoyaHttpTransport?,
        ): HealthCheckResult {
            val baseUrl = settings.nvidiaNimUrl.trim().ifBlank { DEFAULT_BASE_URL }
            return when {
                settings.nvidiaNimModel.isBlank() -> HealthCheckResult.Unavailable("NVIDIA NIM model is empty.")
                // BUG-69-01: health traffic must use Burp's HTTP stack. Without the registry-injected
                // transport there is no safe way to probe, so report Unknown instead of opening a socket.
                transport == null -> HealthCheckResult.Unknown
                else -> {
                    val headers =
                        HeaderParser.withBearerToken(
                            settings.nvidiaNimApiKey,
                            HeaderParser.parse(settings.nvidiaNimHeaders),
                        )
                    val timeoutSeconds =
                        settings.nvidiaNimTimeoutSeconds.coerceIn(HEALTH_TIMEOUT_MIN_SECONDS, HEALTH_TIMEOUT_MAX_SECONDS)
                    val timeoutMs = TimeUnit.SECONDS.toMillis(timeoutSeconds.toLong())
                    // GET /v1/models is free; the previous chat-completion probe was billed on every check.
                    transport.healthCheckGet(OpenAiModelsUrl.versioned(baseUrl), headers, timeoutMs)
                }
            }
        }
    }
}
