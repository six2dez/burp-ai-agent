package com.six2dez.burp.aiagent.backends.nvidia

import burp.api.montoya.MontoyaApi
import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.module.kotlin.registerKotlinModule
import com.six2dez.burp.aiagent.backends.BackendLaunchConfig
import com.six2dez.burp.aiagent.backends.http.MontoyaHttpTransport
import com.six2dez.burp.aiagent.backends.http.TransportResponse
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.mockito.Mockito
import org.mockito.kotlin.any
import org.mockito.kotlin.doAnswer
import org.mockito.kotlin.mock
import org.mockito.kotlin.spy
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
