package com.six2dez.burp.aiagent.backends.anthropic

import burp.api.montoya.MontoyaApi
import com.six2dez.burp.aiagent.backends.BackendLaunchConfig
import com.six2dez.burp.aiagent.backends.http.MontoyaHttpTransport
import com.six2dez.burp.aiagent.backends.http.TransportResponse
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.mockito.Mockito
import org.mockito.kotlin.any
import org.mockito.kotlin.doReturn
import org.mockito.kotlin.eq
import org.mockito.kotlin.mock
import org.mockito.kotlin.spy
import org.mockito.kotlin.verify
import org.mockito.kotlin.whenever
import java.io.File
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicReference

/**
 * Verifies BUG-69-01 transport-routing wiring for AnthropicBackend (SC2a/b/c):
 *   (a) send() routes HTTP only via transport.post() to the Anthropic endpoint;
 *   (b) send() with transport == null fails fast (no OkHttp fallback);
 *   (c) AnthropicBackend.kt source contains no okhttp3 / OkHttpClient reference.
 */
class AnthropicBackendTransportRoutingTest {
    /** A representative Anthropic Messages API 200 success body (RESEARCH §3). */
    private val successBody =
        """
        {
          "id": "msg_test",
          "type": "message",
          "role": "assistant",
          "content": [ { "type": "text", "text": "Hello from Anthropic" } ],
          "model": "claude-sonnet-4-6",
          "stop_reason": "end_turn",
          "usage": { "input_tokens": 10, "output_tokens": 5 }
        }
        """.trimIndent()

    @Test
    fun `send routes through transport post to Anthropic endpoint`() {
        // SC2a: verify send() calls transport.post(ANTHROPIC_URL, …) exactly once.
        val transport = stubTransportPost(200, successBody)
        val backend = AnthropicBackend()
        val connection =
            backend.launch(
                BackendLaunchConfig(
                    backendId = "anthropic",
                    displayName = "Anthropic",
                    model = "claude-sonnet-4-6",
                    headers = mapOf("x-api-key" to "k", "anthropic-version" to "2023-06-01"),
                    requestTimeoutSeconds = 30L,
                    transport = transport,
                ),
            )

        val chunks = mutableListOf<String>()
        val errorRef = AtomicReference<Throwable?>(null)
        val done = CountDownLatch(1)
        connection.send(
            text = "Hello",
            onChunk = { chunk -> chunks.add(chunk) },
            onComplete = { err ->
                errorRef.set(err)
                done.countDown()
            },
        )
        assertTrue(done.await(10, TimeUnit.SECONDS), "send() did not complete within 10s")
        assertTrue(errorRef.get() == null, "Expected no error, got: ${errorRef.get()?.message}")
        assertTrue(chunks.isNotEmpty(), "Expected at least one chunk")
        assertTrue(chunks.any { it.contains("Hello from Anthropic") }, "Expected chunk to contain parsed text")

        verify(transport).post(
            eq("https://api.anthropic.com/v1/messages"),
            any(),
            any(),
            any(),
        )
    }

    @Test
    fun `send fails fast when transport is null`() {
        // SC2b: null transport must fail fast with the shared message — NO OkHttp fallback.
        val backend = AnthropicBackend()
        val connection =
            backend.launch(
                BackendLaunchConfig(
                    backendId = "anthropic",
                    displayName = "Anthropic",
                    model = "claude-sonnet-4-6",
                    headers = emptyMap(),
                    requestTimeoutSeconds = 30L,
                    transport = null,
                ),
            )

        val errorRef = AtomicReference<Throwable?>(null)
        val done = CountDownLatch(1)
        connection.send(
            text = "Hello",
            onChunk = { _: String -> },
            onComplete = { err ->
                errorRef.set(err)
                done.countDown()
            },
        )
        assertTrue(done.await(5, TimeUnit.SECONDS), "send() did not complete within 5s")
        val err = errorRef.get()
        assertNotNull(err, "Expected IllegalStateException, got null")
        assertTrue(err is IllegalStateException, "Expected IllegalStateException, got ${err?.javaClass?.name}")
        assertTrue(
            err!!.message!!.contains("MontoyaHttpTransport unavailable"),
            "Expected message to contain 'MontoyaHttpTransport unavailable', got: ${err.message}",
        )
    }

    @Test
    fun `AnthropicBackend source file contains no okhttp3 or OkHttpClient reference`() {
        // SC2c: source-string guard — read the production .kt file from disk and assert it
        // contains neither "okhttp3" nor "OkHttpClient". Mirrors HttpBackendTransportRoutingTest.
        val candidates =
            listOf(
                "src/main/kotlin/com/six2dez/burp/aiagent/backends/anthropic/AnthropicBackend.kt",
                "../src/main/kotlin/com/six2dez/burp/aiagent/backends/anthropic/AnthropicBackend.kt",
                "../../src/main/kotlin/com/six2dez/burp/aiagent/backends/anthropic/AnthropicBackend.kt",
            )
        val source =
            candidates
                .map { File(it) }
                .firstOrNull { it.exists() && it.canRead() }
                ?.readText()
                ?: error("AnthropicBackend.kt not readable from CWD ${File(".").absolutePath}")

        assertTrue(
            !source.contains("okhttp3"),
            "AnthropicBackend.kt must NOT reference okhttp3 on the production path (SC2c)",
        )
        assertTrue(
            !source.contains("OkHttpClient"),
            "AnthropicBackend.kt must NOT construct an OkHttpClient on the production path (SC2c)",
        )
    }

    // --- Helpers ----------------------------------------------------------------------------------

    /** Builds a spy MontoyaHttpTransport whose post() returns the given status + body. */
    private fun stubTransportPost(
        statusCode: Int,
        body: String,
    ): MontoyaHttpTransport {
        val api = mock<MontoyaApi>(defaultAnswer = Mockito.RETURNS_DEEP_STUBS)
        val real = MontoyaHttpTransport(api)
        val spy = spy(real)
        doReturn(TransportResponse(statusCode, body, statusCode in 200..299))
            .whenever(spy)
            .post(any(), any(), any(), any())
        return spy
    }
}
