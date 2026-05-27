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

/**
 * BUG-69-01: OpenAiCompatibleBackend.send() now fails fast when transport == null. These tests
 * wire a spy MontoyaHttpTransport that forwards the post() to MockWebServer via OkHttp so the
 * original MockWebServer-based path/body assertions stay intact. Production already takes the
 * non-streaming JSON parsing path (transport-bearing branch parses `resp.body` as one JSON
 * document), so the mock responses use non-streaming JSON instead of SSE chunks.
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
        connection.send(
            text = "hello",
            onChunk = {},
            onComplete = { done.countDown() },
            jsonMode = false,
        )
        assertTrue(done.await(5, TimeUnit.SECONDS))

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
        connection.send(
            text = "hello",
            onChunk = {},
            onComplete = { done.countDown() },
            jsonMode = false,
        )
        assertTrue(done.await(5, TimeUnit.SECONDS))

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
        connection.send(
            text = "hello",
            onChunk = {},
            onComplete = { done.countDown() },
            jsonMode = false,
        )
        assertTrue(done.await(5, TimeUnit.SECONDS))

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
        connection.send(
            text = "hello",
            onChunk = {},
            onComplete = { done.countDown() },
            jsonMode = true,
        )
        assertTrue(done.await(5, TimeUnit.SECONDS))

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
        connection.send(
            text = "hello",
            onChunk = {},
            onComplete = { done.countDown() },
            jsonMode = false,
        )
        assertTrue(done.await(5, TimeUnit.SECONDS))

        val recorded = server.takeRequest(1, TimeUnit.SECONDS) ?: error("no request")
        // Must NOT be "/chat/completions/chat/completions"
        assertEquals("/chat/completions", recorded.path)
        assertEquals("POST", recorded.method)
    }

    /**
     * Non-streaming JSON response — production code (transport != null) parses the body as a
     * single JSON document. The pre-BUG-69-01 OkHttp branch handled SSE; that branch is now
     * deleted, so MockWebServer must return non-streaming JSON to match the production path.
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
