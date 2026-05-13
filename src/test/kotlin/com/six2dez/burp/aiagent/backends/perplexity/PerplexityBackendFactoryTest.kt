package com.six2dez.burp.aiagent.backends.perplexity

import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.module.kotlin.registerKotlinModule
import com.six2dez.burp.aiagent.backends.BackendLaunchConfig
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit

class PerplexityBackendFactoryTest {
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
    fun targetsChatCompletionsWithoutV1PrefixOnBareHost() {
        server.enqueue(streamedResponse())
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
        server.enqueue(streamedResponse())
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
        server.enqueue(streamedResponse())
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
        server.enqueue(streamedResponse())
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
        server.enqueue(streamedResponse())
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

    private fun streamedResponse(): MockResponse =
        MockResponse()
            .setResponseCode(200)
            .setHeader("Content-Type", "text/event-stream")
            .setBody(
                "data: {\"choices\":[{\"delta\":{\"content\":\"ok\"}}]}\n\n" +
                    "data: [DONE]\n\n",
            )
}
