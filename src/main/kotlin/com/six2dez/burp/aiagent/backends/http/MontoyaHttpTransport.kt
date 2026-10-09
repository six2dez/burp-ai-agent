package com.six2dez.burp.aiagent.backends.http

import burp.api.montoya.MontoyaApi
import burp.api.montoya.http.RequestOptions
import burp.api.montoya.http.message.requests.HttpRequest
import burp.api.montoya.http.message.responses.HttpResponse
import com.six2dez.burp.aiagent.backends.HealthCheckResult
import java.util.concurrent.ExecutionException
import java.util.concurrent.FutureTask
import java.util.concurrent.TimeUnit
import javax.swing.SwingUtilities
import burp.api.montoya.core.ByteArray as MontoyaByteArray

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
                .withBody(utf8Body(jsonBody))
                .withAddedHeader("Content-Type", "application/json; charset=utf-8")
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
                resp.statusCode == HTTP_TOO_MANY_REQUESTS ->
                    HealthCheckResult.Degraded("Endpoint reachable but rate limited (HTTP 429).")
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
        val result =
            if (SwingUtilities.isEventDispatchThread()) {
                // Burp throws "Extensions should not make HTTP requests in the Swing event dispatch
                // thread" if sendRequest runs on the EDT (#80 — reached via the pre-send LM Studio /
                // Ollama health check). Run it on a short-lived daemon worker and block for the
                // result; the request is already bounded by timeoutMs.
                val task = FutureTask { api.http().sendRequest(request, options) }
                Thread(task, "montoya-http-offedt").apply { isDaemon = true }.start()
                try {
                    task.get(timeoutMs + EDT_OFFLOAD_GRACE_MS, TimeUnit.MILLISECONDS)
                } catch (e: ExecutionException) {
                    throw e.cause ?: e
                }
            } else {
                api.http().sendRequest(request, options)
            }
        return decodeResponse(result.response())
    }

    companion object {
        // Extra grace over the request's own response timeout before the off-EDT worker join gives up.
        private const val EDT_OFFLOAD_GRACE_MS = 5_000L

        // A rate-limited provider is reachable; the health pill reports Degraded, not Offline.
        private const val HTTP_TOO_MANY_REQUESTS = 429

        /**
         * Encodes a JSON request body as explicit UTF-8 bytes for Burp.
         *
         * Burp's String-to-message-bytes conversion keeps only the low byte of each char instead of
         * encoding it as UTF-8. That corrupted every non-ASCII character sent to the HTTP backends
         * and could even turn characters such as U+2022 or U+0122 into a raw JSON `"` byte
         * (#84 #85 #86 #88). `String.toByteArray(UTF_8)` maps an unpaired surrogate (e.g. from a
         * `take(n)` that split a pair) to '?', which is intended.
         *
         * The SpreadOperator suppression is deliberate: Montoya's only byte[] entry point is the
         * Java vararg `byteArray(byte...)`, Kotlin can pass an existing array to it only with a
         * spread, and one array copy per request is negligible next to the network round trip.
         * Answered in source per ADR-17 clause 1 rather than baselined.
         */
        @Suppress("SpreadOperator")
        private fun utf8Body(json: String): MontoyaByteArray = MontoyaByteArray.byteArray(*json.toByteArray(Charsets.UTF_8))

        // Force UTF-8: Montoya's bodyToString() decodes with the JVM platform charset, which mojibakes
        // multibyte responses (e.g. Chinese, emoji) on hosts whose default charset isn't UTF-8.
        // OpenAI-compatible servers commonly return Content-Type: application/json without an explicit
        // charset parameter, so we cannot rely on the server-declared charset either.
        internal fun decodeResponse(response: HttpResponse?): TransportResponse {
            val code = response?.statusCode()?.toInt() ?: 0
            val body = response?.body()?.bytes?.toString(Charsets.UTF_8) ?: ""
            return TransportResponse(
                statusCode = code,
                body = body,
                isSuccessful = code in 200..299,
            )
        }
    }
}
