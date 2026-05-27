package com.six2dez.burp.aiagent.backends.nvidia

import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.module.kotlin.registerKotlinModule
import com.six2dez.burp.aiagent.backends.AiBackend
import com.six2dez.burp.aiagent.backends.AiBackendFactory
import com.six2dez.burp.aiagent.backends.HealthCheckResult
import com.six2dez.burp.aiagent.backends.http.HttpBackendSupport
import com.six2dez.burp.aiagent.backends.http.MontoyaHttpTransport
import com.six2dez.burp.aiagent.backends.openai.OpenAiCompatibleBackend
import com.six2dez.burp.aiagent.config.AgentSettings
import com.six2dez.burp.aiagent.util.HeaderParser
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import java.util.concurrent.atomic.AtomicReference

class NvidiaNimBackendFactory : AiBackendFactory {
    override fun create(): AiBackend {
        // Capture the constructed backend so the healthCheckProvider lambda can resolve the
        // supervisor-injected MontoyaHttpTransport (set on the backend via
        // OpenAiCompatibleBackend.setHealthCheckTransport in AgentSupervisor's init block).
        // Without this indirection the lambda only sees AgentSettings and would silently fall
        // back to OkHttp, defeating BUG-69-01.
        val backendRef = AtomicReference<OpenAiCompatibleBackend?>(null)
        val backend =
            OpenAiCompatibleBackend(
                id = "nvidia-nim",
                displayName = "NVIDIA NIM",
                defaultBaseUrl = DEFAULT_BASE_URL,
                baseUrlSelector = { it.nvidiaNimUrl.trim() },
                modelSelector = { it.nvidiaNimModel.trim() },
                apiKeySelector = { it.nvidiaNimApiKey },
                headersSelector = { it.nvidiaNimHeaders },
                timeoutSelector = { it.nvidiaNimTimeoutSeconds },
                streaming = true,
                defaultHeaders = mapOf("Accept" to "text/event-stream"),
                payloadCustomizer = { payload ->
                    payload["max_tokens"] = 16384
                    payload["top_p"] = 1.0
                    payload["chat_template_kwargs"] = mapOf("thinking" to true)
                    val temp = payload["temperature"]
                    if (temp is Number && temp.toDouble() == 0.7) {
                        payload["temperature"] = 1.0
                    }
                },
                healthCheckProvider = { settings ->
                    nimHealthCheck(settings, backendRef.get()?.healthCheckTransport())
                },
            )
        backendRef.set(backend)
        return backend
    }

    companion object {
        const val DEFAULT_BASE_URL: String = "https://integrate.api.nvidia.com"

        private val mapper = ObjectMapper().registerKotlinModule()

        private fun nimHealthCheck(
            settings: AgentSettings,
            transport: MontoyaHttpTransport?,
        ): HealthCheckResult {
            val baseUrl = settings.nvidiaNimUrl.trim().ifBlank { DEFAULT_BASE_URL }
            val model = settings.nvidiaNimModel.trim()
            if (model.isBlank()) {
                return HealthCheckResult.Unavailable("NVIDIA NIM model is empty.")
            }

            val headers =
                withDefaultAcceptHeader(
                    HeaderParser.withBearerToken(
                        settings.nvidiaNimApiKey,
                        HeaderParser.parse(settings.nvidiaNimHeaders),
                    ),
                )
            val payload =
                mapOf(
                    "model" to model,
                    "messages" to listOf(mapOf("role" to "user", "content" to "Hey")),
                    "max_tokens" to 16,
                    "temperature" to 1.0,
                    "top_p" to 1.0,
                    "stream" to false,
                    "chat_template_kwargs" to mapOf("thinking" to true),
                )

            val url = buildChatCompletionsUrl(baseUrl)
            val payloadJson = mapper.writeValueAsString(payload)

            // BUG-69-01: route POST through MontoyaHttpTransport when the supervisor has injected
            // one, so the health-check tickle honors Burp's upstream proxy / SOCKS / cert store
            // (issue #69). Fall through to OkHttp only on the unit-test path.
            if (transport != null) {
                return try {
                    val resp = transport.post(url, headers, payloadJson, timeoutMs = 5_000)
                    when {
                        resp.isSuccessful -> HealthCheckResult.Healthy
                        resp.statusCode == 401 || resp.statusCode == 403 ->
                            HealthCheckResult.Degraded("Endpoint reachable but authentication failed (HTTP ${resp.statusCode}).")
                        resp.statusCode == 429 ->
                            HealthCheckResult.Degraded("Endpoint reachable but rate limited (HTTP 429).")
                        else -> HealthCheckResult.Unavailable("HTTP ${resp.statusCode}.")
                    }
                } catch (e: Exception) {
                    HealthCheckResult.Unavailable(e.message ?: "Request failed")
                }
            }

            return try {
                val client = HttpBackendSupport.sharedClient(baseUrl, settings.nvidiaNimTimeoutSeconds.toLong().coerceIn(5L, 30L))
                val request =
                    Request
                        .Builder()
                        .url(url)
                        .post(payloadJson.toRequestBody("application/json".toMediaType()))
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
            return "$trimmed/v1/chat/completions"
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
