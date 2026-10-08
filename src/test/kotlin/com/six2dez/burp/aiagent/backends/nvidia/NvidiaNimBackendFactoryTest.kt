package com.six2dez.burp.aiagent.backends.nvidia

import burp.api.montoya.MontoyaApi
import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.module.kotlin.registerKotlinModule
import com.six2dez.burp.aiagent.TestSettings
import com.six2dez.burp.aiagent.backends.AiBackend
import com.six2dez.burp.aiagent.backends.BackendLaunchConfig
import com.six2dez.burp.aiagent.backends.HealthCheckResult
import com.six2dez.burp.aiagent.backends.HttpTransportAware
import com.six2dez.burp.aiagent.backends.http.MontoyaHttpTransport
import com.six2dez.burp.aiagent.backends.http.TransportResponse
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.mockito.Mockito
import org.mockito.kotlin.any
import org.mockito.kotlin.argumentCaptor
import org.mockito.kotlin.doAnswer
import org.mockito.kotlin.doReturn
import org.mockito.kotlin.eq
import org.mockito.kotlin.mock
import org.mockito.kotlin.never
import org.mockito.kotlin.spy
import org.mockito.kotlin.times
import org.mockito.kotlin.verify
import org.mockito.kotlin.whenever
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicReference

/**
 * Quick 261008-kw4: NVIDIA NIM sends used to ask for `"stream":true` with an
 * `Accept: text/event-stream` default, while the buffered Montoya transport hands the whole body to
 * a single-JSON parser — every send failed with "Unrecognized token 'data'". The factory now sends
 * non-streaming requests and the connection also aggregates an SSE body defensively.
 */
class NvidiaNimBackendFactoryTest {
    private val mapper = ObjectMapper().registerKotlinModule()

    @Test
    fun sseBodyIsAggregatedAndCompletesWithoutError() {
        val captured = CapturedPost()
        val result = sendWithCannedBody(SSE_BODY, captured)
        assertNull(result.error, "an SSE body must not fail the send")
        assertEquals("Hello", result.text)
    }

    @Test
    fun singleJsonBodyCompletesWithoutError() {
        val captured = CapturedPost()
        val result = sendWithCannedBody(JSON_BODY, captured)
        assertNull(result.error)
        assertEquals("Hello", result.text)
    }

    @Test
    fun requestAsksForNonStreamingJson() {
        val captured = CapturedPost()
        sendWithCannedBody(JSON_BODY, captured)
        val body = mapper.readTree(captured.body ?: error("no post captured"))
        assertTrue(body.has("stream"))
        assertFalse(body.get("stream").asBoolean(), "NIM must send \"stream\":false")
        val accept = captured.headers.orEmpty().filterKeys { it.equals("accept", ignoreCase = true) }
        assertEquals(mapOf("Accept" to "application/json"), accept)
    }

    @Test
    fun userSuppliedAcceptHeaderReplacesTheDefaultCaseInsensitively() {
        val captured = CapturedPost()
        sendWithCannedBody(JSON_BODY, captured, extraHeaders = mapOf("accept" to "text/plain"))
        val accept = captured.headers.orEmpty().filterKeys { it.equals("accept", ignoreCase = true) }
        assertEquals(1, accept.size, "exactly one accept header must travel: $accept")
        assertEquals("text/plain", accept.values.single())
    }

    // --- Health checks (quick 261008-kw4): one non-billable GET /v1/models via the transport ----

    @Test
    fun healthCheckIsOneGetToV1ModelsWithBearerAndCustomHeaders() {
        val (backend, transport) = backendWithStatusTransport(200)
        val result = backend.healthCheck(healthSettings())
        assertEquals(HealthCheckResult.Healthy, result)
        val headers = argumentCaptor<Map<String, String>>()
        verify(transport, times(1)).get(eq("https://integrate.api.nvidia.com/v1/models"), headers.capture(), any())
        assertEquals("Bearer nvapi-test", headers.firstValue["Authorization"])
        assertEquals("1", headers.firstValue["X-Custom"])
        verify(transport, never()).post(any(), any(), any(), any())
    }

    @Test
    fun healthCheckMapsStatusCodes() {
        assertEquals(HealthCheckResult.Healthy, backendWithStatusTransport(200).first.healthCheck(healthSettings()))
        val auth = backendWithStatusTransport(401).first.healthCheck(healthSettings())
        assertTrue(auth is HealthCheckResult.Degraded && auth.message.contains("authentication failed"), "got $auth")
        val limited = backendWithStatusTransport(429).first.healthCheck(healthSettings())
        assertTrue(limited is HealthCheckResult.Degraded && limited.message.contains("rate limited"), "got $limited")
        assertEquals(
            HealthCheckResult.Unavailable("HTTP 500."),
            backendWithStatusTransport(500).first.healthCheck(healthSettings()),
        )
    }

    @Test
    fun healthCheckWithBlankModelIsUnavailableWithoutTouchingTheTransport() {
        val (backend, transport) = backendWithStatusTransport(200)
        val result = backend.healthCheck(healthSettings().copy(nvidiaNimModel = ""))
        assertTrue(result is HealthCheckResult.Unavailable && result.message.contains("model is empty"), "got $result")
        Mockito.verifyNoInteractions(transport)
    }

    @Test
    fun healthCheckWithoutTransportIsUnknownAndDoesNoNetworkIo() {
        // A network attempt against the discard port would yield Unavailable; Unknown proves the
        // OkHttp fallback is gone (health traffic must never bypass Burp's HTTP stack).
        val backend = NvidiaNimBackendFactory().create()
        val result = backend.healthCheck(healthSettings().copy(nvidiaNimUrl = "http://127.0.0.1:9"))
        assertEquals(HealthCheckResult.Unknown, result)
    }

    private fun healthSettings() =
        TestSettings.baselineSettings().copy(
            nvidiaNimUrl = "https://integrate.api.nvidia.com",
            nvidiaNimModel = "meta/llama-3.1-8b-instruct",
            nvidiaNimApiKey = "nvapi-test",
            nvidiaNimHeaders = "X-Custom: 1",
        )

    private fun backendWithStatusTransport(status: Int): Pair<AiBackend, MontoyaHttpTransport> {
        val transport = spy(MontoyaHttpTransport(mock<MontoyaApi>(defaultAnswer = Mockito.RETURNS_DEEP_STUBS)))
        doReturn(TransportResponse(status, "{}", status in 200..299))
            .whenever(transport)
            .get(any(), any(), any())
        val backend = NvidiaNimBackendFactory().create()
        (backend as HttpTransportAware).setHealthCheckTransport(transport)
        return backend to transport
    }

    private class CapturedPost {
        var url: String? = null
        var headers: Map<String, String>? = null
        var body: String? = null
    }

    private data class SendResult(
        val text: String,
        val error: Throwable?,
    )

    private fun sendWithCannedBody(
        responseBody: String,
        captured: CapturedPost,
        extraHeaders: Map<String, String> = emptyMap(),
    ): SendResult {
        val api = mock<MontoyaApi>(defaultAnswer = Mockito.RETURNS_DEEP_STUBS)
        val transport = spy(MontoyaHttpTransport(api))
        doAnswer { invocation ->
            captured.url = invocation.getArgument(0)
            captured.headers = invocation.getArgument(1)
            captured.body = invocation.getArgument(2)
            TransportResponse(statusCode = 200, body = responseBody, isSuccessful = true)
        }.whenever(transport).post(any(), any(), any(), any())
        val connection =
            NvidiaNimBackendFactory().create().launch(
                BackendLaunchConfig(
                    backendId = "nvidia-nim",
                    displayName = "NVIDIA NIM",
                    baseUrl = NvidiaNimBackendFactory.DEFAULT_BASE_URL,
                    model = "meta/llama-3.1-8b-instruct",
                    headers = mapOf("Authorization" to "Bearer nvapi-test") + extraHeaders,
                    requestTimeoutSeconds = 30L,
                    transport = transport,
                ),
            )
        val done = CountDownLatch(1)
        val error = AtomicReference<Throwable?>(null)
        val text = StringBuilder()
        connection.send(
            text = "hello",
            onChunk = { synchronized(text) { text.append(it) } },
            onComplete = {
                error.set(it)
                done.countDown()
            },
            jsonMode = false,
        )
        assertTrue(done.await(5, TimeUnit.SECONDS))
        connection.stop()
        return SendResult(synchronized(text) { text.toString() }, error.get())
    }

    private companion object {
        const val SSE_BODY =
            "data: {\"choices\":[{\"delta\":{\"content\":\"Hel\"}}]}\n\n" +
                "data: {\"choices\":[{\"delta\":{\"content\":\"lo\"}}]}\n\n" +
                "data: [DONE]\n\n"
        const val JSON_BODY = """{"choices":[{"message":{"role":"assistant","content":"Hello"}}]}"""
    }
}
