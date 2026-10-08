package com.six2dez.burp.aiagent.backends.perplexity

import burp.api.montoya.MontoyaApi
import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.module.kotlin.registerKotlinModule
import com.six2dez.burp.aiagent.backends.BackendLaunchConfig
import com.six2dez.burp.aiagent.backends.http.MontoyaHttpTransport
import com.six2dez.burp.aiagent.backends.http.TransportResponse
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.BeforeEach
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
 * BUG-69-01: OpenAiCompatibleBackend.send() now fails fast when transport == null. These tests
 * wire a spy MontoyaHttpTransport that forwards the post() to MockWebServer via OkHttp so the
 * original MockWebServer-based path/body assertions stay intact. Perplexity now sends
 * `"stream":false`, and the production parser (OpenAiResponseParser) accepts both a single JSON
 * document and an SSE body, so the canned-transport tests below cover both shapes.
 */
class PerplexityBackendFactoryTest {
    private lateinit var server: MockWebServer
    private val mapper = ObjectMapper().registerKotlinModule()
    private val httpClient = OkHttpClient()

    @BeforeEach
    fun setup() {
        server = MockWebServer()
        server.start()
    }

    @AfterEach
    fun teardown() {
        server.shutdown()
    }

    @Test
    fun targetsChatCompletionsWithoutV1PrefixOnBareHost() {
        server.enqueue(nonStreamingJsonResponse())
        val backend = PerplexityBackendFactory().create()
        val baseUrl = server.url("/").toString().trimEnd('/')

        val connection =
            backend.launch(
                BackendLaunchConfig(
                    backendId = "perplexity",
                    displayName = "Perplexity",
                    baseUrl = baseUrl,
                    model = "sonar",
                    headers = mapOf("Authorization" to "Bearer pplx-test"),
                    requestTimeoutSeconds = 30L,
                    transport = mockWebServerProxyTransport(),
                ),
            )

        val done = CountDownLatch(1)
        val error = AtomicReference<Throwable?>(null)
        connection.send(
            text = "hello",
            onChunk = {},
            onComplete = {
                error.set(it)
                done.countDown()
            },
            jsonMode = false,
        )
        assertTrue(done.await(5, TimeUnit.SECONDS))
        assertNull(error.get(), "send must complete without an error")

        val recorded = server.takeRequest(1, TimeUnit.SECONDS) ?: error("no request")
        assertEquals("/chat/completions", recorded.path)
        assertEquals("POST", recorded.method)
    }

    @Test
    fun handlesTrailingSlashInUserConfiguredUrl() {
        server.enqueue(nonStreamingJsonResponse())
        val backend = PerplexityBackendFactory().create()
        // NOT trimmed — trailing slash present
        val baseUrl = server.url("/").toString()

        val connection =
            backend.launch(
                BackendLaunchConfig(
                    backendId = "perplexity",
                    displayName = "Perplexity",
                    baseUrl = baseUrl,
                    model = "sonar",
                    headers = mapOf("Authorization" to "Bearer pplx-test"),
                    requestTimeoutSeconds = 30L,
                    transport = mockWebServerProxyTransport(),
                ),
            )

        val done = CountDownLatch(1)
        val error = AtomicReference<Throwable?>(null)
        connection.send(
            text = "hello",
            onChunk = {},
            onComplete = {
                error.set(it)
                done.countDown()
            },
            jsonMode = false,
        )
        assertTrue(done.await(5, TimeUnit.SECONDS))
        assertNull(error.get(), "send must complete without an error")

        val recorded = server.takeRequest(1, TimeUnit.SECONDS) ?: error("no request")
        assertEquals("/chat/completions", recorded.path)
        assertEquals("POST", recorded.method)
    }

    @Test
    fun respectsExplicitV1UserUrl() {
        server.enqueue(nonStreamingJsonResponse())
        val backend = PerplexityBackendFactory().create()
        val baseUrl = server.url("/v1").toString().trimEnd('/')

        val connection =
            backend.launch(
                BackendLaunchConfig(
                    backendId = "perplexity",
                    displayName = "Perplexity",
                    baseUrl = baseUrl,
                    model = "sonar",
                    headers = mapOf("Authorization" to "Bearer pplx-test"),
                    requestTimeoutSeconds = 30L,
                    transport = mockWebServerProxyTransport(),
                ),
            )

        val done = CountDownLatch(1)
        val error = AtomicReference<Throwable?>(null)
        connection.send(
            text = "hello",
            onChunk = {},
            onComplete = {
                error.set(it)
                done.countDown()
            },
            jsonMode = false,
        )
        assertTrue(done.await(5, TimeUnit.SECONDS))
        assertNull(error.get(), "send must complete without an error")

        val recorded = server.takeRequest(1, TimeUnit.SECONDS) ?: error("no request")
        assertEquals("/v1/chat/completions", recorded.path)
        assertEquals("POST", recorded.method)
    }

    @Test
    fun omitsResponseFormatEvenWhenJsonModeRequested() {
        server.enqueue(nonStreamingJsonResponse())
        val backend = PerplexityBackendFactory().create()
        val baseUrl = server.url("/").toString().trimEnd('/')

        val connection =
            backend.launch(
                BackendLaunchConfig(
                    backendId = "perplexity",
                    displayName = "Perplexity",
                    baseUrl = baseUrl,
                    model = "sonar",
                    headers = mapOf("Authorization" to "Bearer pplx-test"),
                    requestTimeoutSeconds = 30L,
                    transport = mockWebServerProxyTransport(),
                ),
            )

        val done = CountDownLatch(1)
        val error = AtomicReference<Throwable?>(null)
        connection.send(
            text = "hello",
            onChunk = {},
            onComplete = {
                error.set(it)
                done.countDown()
            },
            jsonMode = true,
        )
        assertTrue(done.await(5, TimeUnit.SECONDS))
        assertNull(error.get(), "send must complete without an error")

        val recorded = server.takeRequest(1, TimeUnit.SECONDS) ?: error("no request")
        val body = mapper.readTree(recorded.body.readUtf8())
        assertFalse(body.has("response_format"), "Perplexity must not emit response_format")
        assertTrue(body.has("model"))
        assertTrue(body.has("messages"))
    }

    @Test
    fun doesNotDoubleAppendWhenUrlAlreadyHasChatCompletions() {
        server.enqueue(nonStreamingJsonResponse())
        val backend = PerplexityBackendFactory().create()
        // Simulates a user who already typed the full chat-completions path
        val baseUrl = server.url("/chat/completions").toString().trimEnd('/')

        val connection =
            backend.launch(
                BackendLaunchConfig(
                    backendId = "perplexity",
                    displayName = "Perplexity",
                    baseUrl = baseUrl,
                    model = "sonar",
                    headers = mapOf("Authorization" to "Bearer pplx-test"),
                    requestTimeoutSeconds = 30L,
                    transport = mockWebServerProxyTransport(),
                ),
            )

        val done = CountDownLatch(1)
        val error = AtomicReference<Throwable?>(null)
        connection.send(
            text = "hello",
            onChunk = {},
            onComplete = {
                error.set(it)
                done.countDown()
            },
            jsonMode = false,
        )
        assertTrue(done.await(5, TimeUnit.SECONDS))
        assertNull(error.get(), "send must complete without an error")

        val recorded = server.takeRequest(1, TimeUnit.SECONDS) ?: error("no request")
        // Must NOT be "/chat/completions/chat/completions"
        assertEquals("/chat/completions", recorded.path)
        assertEquals("POST", recorded.method)
    }

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
    fun requestBodyAsksForNonStreamingJson() {
        val captured = CapturedPost()
        sendWithCannedBody(JSON_BODY, captured)
        val body = mapper.readTree(captured.body ?: error("no post captured"))
        assertTrue(body.has("stream"))
        assertFalse(body.get("stream").asBoolean(), "Perplexity must send \"stream\":false")
        val accept = captured.headers.orEmpty().filterKeys { it.equals("accept", ignoreCase = true) }
        assertEquals(mapOf("Accept" to "application/json"), accept)
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
            PerplexityBackendFactory().create().launch(
                BackendLaunchConfig(
                    backendId = "perplexity",
                    displayName = "Perplexity",
                    baseUrl = "https://api.perplexity.ai",
                    model = "sonar",
                    headers = mapOf("Authorization" to "Bearer pplx-test"),
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

    /**
     * Non-streaming JSON response — the shape Perplexity returns for a `"stream":false` request.
     * SSE bodies are covered separately by [sseBodyIsAggregatedAndCompletesWithoutError].
     */
    private fun nonStreamingJsonResponse(): MockResponse =
        MockResponse()
            .setResponseCode(200)
            .setHeader("Content-Type", "application/json")
            .setBody("""{"choices":[{"message":{"role":"assistant","content":"ok"}}]}""")

    /**
     * Builds a spy [MontoyaHttpTransport] whose `post()` forwards the request to MockWebServer
     * via OkHttp. Preserves the MockWebServer-based path/body assertions while satisfying the
     * new fail-fast guard introduced by BUG-69-01.
     */
    private fun mockWebServerProxyTransport(): MontoyaHttpTransport {
        val api = mock<MontoyaApi>(defaultAnswer = Mockito.RETURNS_DEEP_STUBS)
        val real = MontoyaHttpTransport(api)
        val spy = spy(real)
        doAnswer { invocation ->
            val url = invocation.getArgument<String>(0)
            val headers = invocation.getArgument<Map<String, String>>(1)
            val body = invocation.getArgument<String>(2)
            val req =
                Request
                    .Builder()
                    .url(url)
                    .post(body.toRequestBody("application/json".toMediaType()))
                    .apply {
                        headers.forEach { (name, value) -> header(name, value) }
                    }.build()
            httpClient.newCall(req).execute().use { resp ->
                TransportResponse(
                    statusCode = resp.code,
                    body = resp.body?.string().orEmpty(),
                    isSuccessful = resp.isSuccessful,
                )
            }
        }.whenever(spy).post(any(), any(), any(), any())
        return spy
    }
}
