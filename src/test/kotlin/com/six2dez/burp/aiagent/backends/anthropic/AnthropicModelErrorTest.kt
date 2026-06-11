package com.six2dez.burp.aiagent.backends.anthropic

import burp.api.montoya.MontoyaApi
import com.six2dez.burp.aiagent.backends.BackendLaunchConfig
import com.six2dez.burp.aiagent.backends.http.MontoyaHttpTransport
import com.six2dez.burp.aiagent.backends.http.TransportResponse
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Test
import org.mockito.Mockito
import org.mockito.kotlin.any
import org.mockito.kotlin.doReturn
import org.mockito.kotlin.mock
import org.mockito.kotlin.spy
import org.mockito.kotlin.whenever
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicReference

/**
 * Verifies SC3: a 400 whose body contains "model" surfaces the exact user-visible error string.
 */
class AnthropicModelErrorTest {
    /** Exact SC3 error string from CONTEXT.md — must not be reworded. */
    private val sc3ErrorMessage = "Anthropic rejected the model ID — check Settings > Anthropic > Model"

    /** A representative 400 invalid-model error body (RESEARCH §4). */
    private val invalidModelBody =
        """
        {
          "type": "error",
          "error": {
            "type": "invalid_request_error",
            "message": "model: bogus-model-id not found. Please check our models page for available models."
          },
          "request_id": "req_test"
        }
        """.trimIndent()

    @Test
    fun `send returns exact SC3 string when 400 body contains model`() {
        val transport = stubTransportPost(400, invalidModelBody)
        val backend = AnthropicBackend()
        val connection =
            backend.launch(
                BackendLaunchConfig(
                    backendId = "anthropic",
                    displayName = "Anthropic",
                    model = "bogus-model-id",
                    headers = mapOf("x-api-key" to "k", "anthropic-version" to "2023-06-01"),
                    requestTimeoutSeconds = 30L,
                    transport = transport,
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
        assertNotNull(err, "Expected an error for a 400 response, got null")
        assertEquals(
            sc3ErrorMessage,
            err!!.message,
            "SC3 error message must match exactly — do not reword",
        )
    }

    // --- Helpers ----------------------------------------------------------------------------------

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

    private fun assertTrue(
        condition: Boolean,
        message: String,
    ) {
        if (!condition) throw AssertionError(message)
    }
}
