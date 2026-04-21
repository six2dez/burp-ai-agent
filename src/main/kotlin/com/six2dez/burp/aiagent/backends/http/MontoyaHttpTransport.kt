package com.six2dez.burp.aiagent.backends.http

import burp.api.montoya.MontoyaApi
import burp.api.montoya.http.RequestOptions
import burp.api.montoya.http.message.requests.HttpRequest
import com.six2dez.burp.aiagent.backends.HealthCheckResult

data class TransportResponse(
    val statusCode: Int,
    val body: String,
    val isSuccessful: Boolean,
)

class MontoyaHttpTransport(
    private val api: MontoyaApi,
) {
    fun post(
        url: String,
        headers: Map<String, String>,
        jsonBody: String,
        timeoutMs: Long = 120_000,
    ): TransportResponse {
        var request =
            HttpRequest
                .httpRequestFromUrl(url)
                .withMethod("POST")
                .withBody(jsonBody)
                .withAddedHeader("Content-Type", "application/json")
        headers.forEach { (name, value) ->
            request = request.withAddedHeader(name, value)
        }
        return execute(request, timeoutMs)
    }

    fun get(
        url: String,
        headers: Map<String, String>,
        timeoutMs: Long = 3_000,
    ): TransportResponse {
        var request = HttpRequest.httpRequestFromUrl(url)
        headers.forEach { (name, value) ->
            request = request.withAddedHeader(name, value)
        }
        return execute(request, timeoutMs)
    }

    fun healthCheckGet(
        url: String,
        headers: Map<String, String>,
        timeoutMs: Long = 3_000,
    ): HealthCheckResult =
        try {
            val resp = get(url, headers, timeoutMs)
            when {
                resp.isSuccessful -> HealthCheckResult.Healthy
                resp.statusCode == 401 || resp.statusCode == 403 ->
                    HealthCheckResult.Degraded("Endpoint reachable but authentication failed (HTTP ${resp.statusCode}).")
                else -> HealthCheckResult.Unavailable("HTTP ${resp.statusCode}.")
            }
        } catch (e: Exception) {
            HealthCheckResult.Unavailable(e.message ?: "Request failed")
        }

    private fun execute(
        request: HttpRequest,
        timeoutMs: Long,
    ): TransportResponse {
        val options =
            RequestOptions
                .requestOptions()
                .withUpstreamTLSVerification()
                .withResponseTimeout(timeoutMs)
        val result = api.http().sendRequest(request, options)
        val response = result.response()
        val code = response?.statusCode()?.toInt() ?: 0
        val body = response?.bodyToString() ?: ""
        return TransportResponse(
            statusCode = code,
            body = body,
            isSuccessful = code in 200..299,
        )
    }
}
