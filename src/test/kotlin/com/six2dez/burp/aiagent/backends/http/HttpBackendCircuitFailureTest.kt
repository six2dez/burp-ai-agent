package com.six2dez.burp.aiagent.backends.http

import burp.api.montoya.MontoyaApi
import com.six2dez.burp.aiagent.backends.BackendLaunchConfig
import com.six2dez.burp.aiagent.backends.anthropic.AnthropicBackend
import com.six2dez.burp.aiagent.backends.lmstudio.LmStudioBackend
import com.six2dez.burp.aiagent.backends.ollama.OllamaBackend
import com.six2dez.burp.aiagent.backends.openai.OpenAiCompatibleBackend
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
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
 * REL-03 behavioral test: repeated 429 or 5xx responses from a spied transport open the
 * circuit breaker after the threshold (5), causing the next send to fail fast with the
 * "circuit open" message from HttpBackendSupport.openCircuitError.
 *
 * The breaker field is private to each connection — state is observed purely via the
 * user-visible error message (Open Question 3: no widened visibility).
 *
 * Also includes direct unit coverage for isRetryableHttpStatus.
 */
class HttpBackendCircuitFailureTest {
    // --- isRetryableHttpStatus unit tests --------------------------------------------------------

    @Test
    fun `isRetryableHttpStatus returns true for 429`() {
        assertTrue(HttpBackendSupport.isRetryableHttpStatus(429))
    }

    @Test
    fun `isRetryableHttpStatus returns true for 500`() {
        assertTrue(HttpBackendSupport.isRetryableHttpStatus(500))
    }

    @Test
    fun `isRetryableHttpStatus returns true for 503`() {
        assertTrue(HttpBackendSupport.isRetryableHttpStatus(503))
    }

    @Test
    fun `isRetryableHttpStatus returns true for 599`() {
        assertTrue(HttpBackendSupport.isRetryableHttpStatus(599))
    }

    @Test
    fun `isRetryableHttpStatus returns false for 200`() {
        assertFalse(HttpBackendSupport.isRetryableHttpStatus(200))
    }

    @Test
    fun `isRetryableHttpStatus returns false for 400`() {
        assertFalse(HttpBackendSupport.isRetryableHttpStatus(400))
    }

    @Test
    fun `isRetryableHttpStatus returns false for 401`() {
        assertFalse(HttpBackendSupport.isRetryableHttpStatus(401))
    }

    @Test
    fun `isRetryableHttpStatus returns false for 403`() {
        assertFalse(HttpBackendSupport.isRetryableHttpStatus(403))
    }

    @Test
    fun `isRetryableHttpStatus returns false for 404`() {
        assertFalse(HttpBackendSupport.isRetryableHttpStatus(404))
    }

    // --- Behavioral breaker-open tests (one per backend) ----------------------------------------

    /**
     * Drives 6 consecutive 429 responses through OpenAiCompatibleBackend and asserts that at
     * least one send fails fast with the "circuit open" message (threshold is 5).
     * NVIDIA and Perplexity delegate to OpenAiCompatibleBackend and are covered automatically.
     */
    @Test
    fun `OpenAiCompatible 429 responses open the circuit breaker after threshold`() {
        val transport = stub429Transport()
        val backend = OpenAiCompatibleBackend(id = "openai-compatible", displayName = "OpenAI-compatible")
        val conn =
            backend.launch(
                BackendLaunchConfig(
                    backendId = "openai-compatible",
                    displayName = "OpenAI-compatible",
                    baseUrl = "https://example.test/v1",
                    model = "gpt-4o",
                    headers = emptyMap(),
                    requestTimeoutSeconds = 30L,
                    transport = transport,
                ),
            )
        val errors = (1..6).map { sendAndAwait(conn) }
        assertTrue(
            errors.any { it?.message?.contains("circuit open") == true },
            "Expected the breaker to open after 5 consecutive 429s; errors: ${errors.map { it?.message }}",
        )
    }

    @Test
    fun `AnthropicBackend 429 responses open the circuit breaker after threshold`() {
        val transport = stub429Transport()
        val backend = AnthropicBackend()
        val conn =
            backend.launch(
                BackendLaunchConfig(
                    backendId = "anthropic",
                    displayName = "Anthropic",
                    model = "claude-3-5-sonnet-20241022",
                    headers = emptyMap(),
                    requestTimeoutSeconds = 30L,
                    transport = transport,
                ),
            )
        val errors = (1..6).map { sendAndAwait(conn) }
        assertTrue(
            errors.any { it?.message?.contains("circuit open") == true },
            "Expected the breaker to open after 5 consecutive 429s; errors: ${errors.map { it?.message }}",
        )
    }

    @Test
    fun `OllamaBackend 429 responses open the circuit breaker after threshold`() {
        val transport = stub429Transport()
        val backend = OllamaBackend()
        val conn =
            backend.launch(
                BackendLaunchConfig(
                    backendId = "ollama",
                    displayName = "Ollama",
                    baseUrl = "http://127.0.0.1:11434",
                    model = "llama3",
                    headers = emptyMap(),
                    requestTimeoutSeconds = 30L,
                    transport = transport,
                ),
            )
        val errors = (1..6).map { sendAndAwait(conn) }
        assertTrue(
            errors.any { it?.message?.contains("circuit open") == true },
            "Expected the breaker to open after 5 consecutive 429s; errors: ${errors.map { it?.message }}",
        )
    }

    @Test
    fun `LmStudioBackend 429 responses open the circuit breaker after threshold`() {
        val transport = stub429Transport()
        val backend = LmStudioBackend()
        val conn =
            backend.launch(
                BackendLaunchConfig(
                    backendId = "lmstudio",
                    displayName = "LM Studio",
                    baseUrl = "http://127.0.0.1:1234",
                    model = "local-model",
                    headers = emptyMap(),
                    requestTimeoutSeconds = 30L,
                    transport = transport,
                ),
            )
        val errors = (1..6).map { sendAndAwait(conn) }
        assertTrue(
            errors.any { it?.message?.contains("circuit open") == true },
            "Expected the breaker to open after 5 consecutive 429s; errors: ${errors.map { it?.message }}",
        )
    }

    @Test
    fun `400 response does NOT open the circuit breaker`() {
        val transport = stub4xxTransport(400)
        val backend = OpenAiCompatibleBackend(id = "openai-compatible", displayName = "OpenAI-compatible")
        val conn =
            backend.launch(
                BackendLaunchConfig(
                    backendId = "openai-compatible",
                    displayName = "OpenAI-compatible",
                    baseUrl = "https://example.test/v1",
                    model = "gpt-4o",
                    headers = emptyMap(),
                    requestTimeoutSeconds = 30L,
                    transport = transport,
                ),
            )
        val errors = (1..6).map { sendAndAwait(conn) }
        // None of the errors should be a "circuit open" message — 400 is non-transient
        assertFalse(
            errors.any { it?.message?.contains("circuit open") == true },
            "400 is a non-transient config error; breaker must NOT open. errors: ${errors.map { it?.message }}",
        )
    }

    // --- Helpers ---------------------------------------------------------------------------------

    /**
     * Builds a spy MontoyaHttpTransport whose post() always returns 429 rate-limited.
     * Mirrors stubTransportPost() in HttpBackendTransportRoutingTest.
     */
    private fun stub429Transport(): MontoyaHttpTransport {
        val api = mock<MontoyaApi>(defaultAnswer = Mockito.RETURNS_DEEP_STUBS)
        val transport = spy(MontoyaHttpTransport(api))
        doReturn(TransportResponse(statusCode = 429, body = "rate limited", isSuccessful = false))
            .whenever(transport)
            .post(any(), any(), any(), any())
        return transport
    }

    /** Builds a spy transport returning the given 4xx status. */
    private fun stub4xxTransport(status: Int): MontoyaHttpTransport {
        val api = mock<MontoyaApi>(defaultAnswer = Mockito.RETURNS_DEEP_STUBS)
        val transport = spy(MontoyaHttpTransport(api))
        doReturn(TransportResponse(statusCode = status, body = "bad request", isSuccessful = false))
            .whenever(transport)
            .post(any(), any(), any(), any())
        return transport
    }

    /**
     * Sends one message on the connection and awaits completion (5s timeout).
     * Returns the error from onComplete, or null if the send succeeded.
     * Mirrors the await pattern in HttpBackendTransportRoutingTest.
     */
    private fun sendAndAwait(conn: com.six2dez.burp.aiagent.backends.AgentConnection): Throwable? {
        val errorRef = AtomicReference<Throwable?>(null)
        val done = CountDownLatch(1)
        conn.send(
            text = "test",
            onChunk = {},
            onComplete = { err ->
                errorRef.set(err)
                done.countDown()
            },
            jsonMode = false,
        )
        assertTrue(done.await(5, TimeUnit.SECONDS), "send() did not complete within 5s")
        return errorRef.get()
    }
}
