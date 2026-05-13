package com.six2dez.burp.aiagent.backends.openai

import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.module.kotlin.registerKotlinModule
import com.six2dez.burp.aiagent.backends.BackendLaunchConfig
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit

class OpenAiCompatibleBackendDefaultsTest {
    private lateinit var server: MockWebServer
    private val mapper = ObjectMapper().registerKotlinModule()

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
}
