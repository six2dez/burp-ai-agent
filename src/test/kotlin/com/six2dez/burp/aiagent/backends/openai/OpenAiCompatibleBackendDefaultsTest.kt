package com.six2dez.burp.aiagent.backends.openai

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
 * BUG-69-01: send() no longer falls back to OkHttp when transport == null — it fails fast.
 * To keep MockWebServer-based assertions working, these tests inject a spy MontoyaHttpTransport
 * whose post() forwards the call to MockWebServer via a lightweight OkHttp client (test-only).
 * MockWebServer still records the actual HTTP request, so the original path/body assertions stay
 * intact while satisfying the new fail-fast guard.
 */
class OpenAiCompatibleBackendDefaultsTest {
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
    fun defaultsKeepV1PrefixOnBareHost() {
        server.enqueue(nonStreamingJsonResponse())
        // Construct with NO chatCompletionsBasePath / supportsJsonObjectResponseFormat overrides
        val backend =
            OpenAiCompatibleBackend(
                id = "test-default",
                displayName = "Default",
            )
        val baseUrl = server.url("/").toString().trimEnd('/')

        val connection =
            backend.launch(
                BackendLaunchConfig(
                    backendId = "test-default",
                    displayName = "Default",
                    baseUrl = baseUrl,
                    model = "gpt-4o",
                    headers = emptyMap(),
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
    fun defaultsEmitResponseFormatWhenJsonModeRequested() {
        server.enqueue(nonStreamingJsonResponse())
        // Construct with NO chatCompletionsBasePath / supportsJsonObjectResponseFormat overrides
        val backend =
            OpenAiCompatibleBackend(
                id = "test-default",
                displayName = "Default",
            )
        val baseUrl = server.url("/").toString().trimEnd('/')

        val connection =
            backend.launch(
                BackendLaunchConfig(
                    backendId = "test-default",
                    displayName = "Default",
                    baseUrl = baseUrl,
                    model = "gpt-4o",
                    headers = emptyMap(),
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
        val rf = body.get("response_format")
        assertTrue(rf != null && rf.get("type").asText() == "json_object")
    }

    private fun nonStreamingJsonResponse(): MockResponse =
        MockResponse()
            .setResponseCode(200)
            .setHeader("Content-Type", "application/json")
            .setBody("""{"choices":[{"message":{"role":"assistant","content":"ok"}}]}""")

    /**
     * Builds a spy [MontoyaHttpTransport] whose `post()` is rewired to forward the request to
     * MockWebServer via OkHttp. Preserves the original test's MockWebServer-based path/body
     * assertions while satisfying the new fail-fast guard introduced by BUG-69-01.
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
