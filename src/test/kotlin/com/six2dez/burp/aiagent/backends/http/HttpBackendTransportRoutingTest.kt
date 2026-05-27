package com.six2dez.burp.aiagent.backends.http

import burp.api.montoya.MontoyaApi
import com.six2dez.burp.aiagent.TestSettings
import com.six2dez.burp.aiagent.backends.BackendLaunchConfig
import com.six2dez.burp.aiagent.backends.HealthCheckResult
import com.six2dez.burp.aiagent.backends.lmstudio.LmStudioBackend
import com.six2dez.burp.aiagent.backends.nvidia.NvidiaNimBackendFactory
import com.six2dez.burp.aiagent.backends.ollama.OllamaBackend
import com.six2dez.burp.aiagent.backends.openai.OpenAiCompatibleBackend
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertSame
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.mockito.Mockito
import org.mockito.kotlin.any
import org.mockito.kotlin.doAnswer
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
 * Verifies BUG-69-01 transport-routing wiring:
 *   (a) healthCheck() for OpenAi-compatible, LmStudio, Ollama backends invokes transport.get();
 *   (b) healthCheck() for NVIDIA NIM invokes transport.post();
 *   (c) send() with transport == null in OpenAi-compatible / LmStudio fails fast with
 *       IllegalStateException containing "MontoyaHttpTransport unavailable";
 *   (d) HttpBackendSupport.buildClient KDoc declares the unit-test-only fact and removes the
 *       misleading "respects Burp/JVM proxy config" claim — source-string guard.
 */
class HttpBackendTransportRoutingTest {
    @Test
    fun `healthCheck routes OpenAiCompatible through transport`() {
        val backend = OpenAiCompatibleBackend(id = "openai-compatible", displayName = "OpenAI-compatible")
        val transport = stubTransportGet()
        backend.setHealthCheckTransport(transport)

        val settings =
            TestSettings.baselineSettings().copy(
                openAiCompatibleUrl = "https://example.test/v1",
                openAiCompatibleApiKey = "sk-test",
            )

        val result = backend.healthCheck(settings)
        assertEquals(HealthCheckResult.Healthy, result)
        verify(transport).get(
            eq("https://example.test/v1/models"),
            any(),
            any(),
        )
    }

    @Test
    fun `healthCheck routes LmStudio through transport`() {
        val backend = LmStudioBackend()
        val transport = stubTransportGet()
        backend.setHealthCheckTransport(transport)

        val settings =
            TestSettings.baselineSettings().copy(
                lmStudioUrl = "http://127.0.0.1:1234",
            )

        val result = backend.healthCheck(settings)
        assertEquals(HealthCheckResult.Healthy, result)
        verify(transport).get(
            eq("http://127.0.0.1:1234/v1/models"),
            any(),
            any(),
        )
    }

    @Test
    fun `send fails fast when transport is null on OpenAi-compatible`() {
        val backend = OpenAiCompatibleBackend(id = "openai-compatible", displayName = "OpenAI-compatible")
        val connection =
            backend.launch(
                BackendLaunchConfig(
                    backendId = "openai-compatible",
                    displayName = "OpenAI-compatible",
                    baseUrl = "https://example.test/v1",
                    model = "gpt-4o",
                    headers = emptyMap(),
                    requestTimeoutSeconds = 30L,
                    // transport explicitly null — production code MUST reach the fail-fast guard.
                    transport = null,
                ),
            )

        val errorRef = AtomicReference<Throwable?>(null)
        val done = CountDownLatch(1)
        connection.send(
            text = "hello",
            onChunk = {},
            onComplete = { err ->
                errorRef.set(err)
                done.countDown()
            },
            jsonMode = false,
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
    fun `send fails fast when transport is null on LmStudio`() {
        val backend = LmStudioBackend()
        val connection =
            backend.launch(
                BackendLaunchConfig(
                    backendId = "lmstudio",
                    displayName = "LM Studio",
                    baseUrl = "http://127.0.0.1:1234",
                    model = "lmstudio",
                    headers = emptyMap(),
                    requestTimeoutSeconds = 30L,
                    transport = null,
                ),
            )

        val errorRef = AtomicReference<Throwable?>(null)
        val done = CountDownLatch(1)
        connection.send(
            text = "hello",
            onChunk = {},
            onComplete = { err ->
                errorRef.set(err)
                done.countDown()
            },
            jsonMode = false,
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
    fun `buildClient KDoc declares test-only and does not claim proxy honoring`() {
        // Source-string guard: read the .kt file directly from the project tree. This is the
        // simplest, most direct way to enforce the comment fix per the plan's behavior block.
        val candidates =
            listOf(
                "src/main/kotlin/com/six2dez/burp/aiagent/backends/http/HttpBackendSupport.kt",
                "../src/main/kotlin/com/six2dez/burp/aiagent/backends/http/HttpBackendSupport.kt",
                "../../src/main/kotlin/com/six2dez/burp/aiagent/backends/http/HttpBackendSupport.kt",
            )
        val source =
            candidates
                .map { File(it) }
                .firstOrNull { it.exists() && it.canRead() }
                ?.readText()
                ?: error("HttpBackendSupport.kt not readable from CWD ${File(".").absolutePath}")
        assertTrue(
            source.contains("OkHttp client for unit tests only"),
            "Expected truthful KDoc 'OkHttp client for unit tests only' in HttpBackendSupport.kt",
        )
        assertFalse(
            source.contains("respects Burp/JVM proxy config"),
            "Expected misleading KDoc 'respects Burp/JVM proxy config' to be removed",
        )
    }

    @Test
    fun `healthCheck routes Ollama through transport`() {
        val backend = OllamaBackend()
        val transport = stubTransportGet()
        backend.setHealthCheckTransport(transport)

        val settings =
            TestSettings.baselineSettings().copy(
                ollamaUrl = "http://127.0.0.1:11434",
            )

        val result = backend.healthCheck(settings)
        assertEquals(HealthCheckResult.Healthy, result)
        verify(transport).get(
            eq("http://127.0.0.1:11434/api/tags"),
            any(),
            any(),
        )
    }

    @Test
    fun `healthCheck routes NvidiaNim through transport via POST`() {
        val factory = NvidiaNimBackendFactory()
        val backend = factory.create() as OpenAiCompatibleBackend
        val transport = stubTransportPost()
        backend.setHealthCheckTransport(transport)

        val settings =
            TestSettings.baselineSettings().copy(
                nvidiaNimUrl = "https://integrate.api.nvidia.com",
                nvidiaNimModel = "meta/llama-3.1-8b-instruct",
                nvidiaNimApiKey = "nvapi-test",
            )

        val result = backend.healthCheck(settings)
        assertEquals(HealthCheckResult.Healthy, result)
        verify(transport).post(
            eq("https://integrate.api.nvidia.com/v1/chat/completions"),
            any(),
            any(),
            any(),
        )
    }

    @Test
    fun `healthCheck NvidiaNim returns Unavailable when model blank without touching transport`() {
        val factory = NvidiaNimBackendFactory()
        val backend = factory.create() as OpenAiCompatibleBackend
        val transport = stubTransportPost()
        backend.setHealthCheckTransport(transport)

        val settings =
            TestSettings.baselineSettings().copy(
                nvidiaNimUrl = "https://integrate.api.nvidia.com",
                nvidiaNimModel = "",
                nvidiaNimApiKey = "nvapi-test",
            )

        val result = backend.healthCheck(settings)
        assertTrue(result is HealthCheckResult.Unavailable, "Expected Unavailable, got $result")
        // Verify transport was NOT invoked.
        Mockito.verifyNoInteractions(transport)
    }

    @Test
    fun `getter returns null before injection and the same instance after setHealthCheckTransport`() {
        // Sanity contract for the supervisor-injection regression: the getter must return null
        // before injection and the injected reference after setHealthCheckTransport.
        val backend = OpenAiCompatibleBackend(id = "openai-compatible", displayName = "OpenAI-compatible")
        assertEquals(null, backend.healthCheckTransport())
        val transport = stubTransportGet()
        backend.setHealthCheckTransport(transport)
        assertSame(transport, backend.healthCheckTransport())
    }

    // --- Helpers ---------------------------------------------------------------------------------

    /** Builds a spy MontoyaHttpTransport whose `get()` and `healthCheckGet()` return Healthy. */
    private fun stubTransportGet(): MontoyaHttpTransport {
        val api = mock<MontoyaApi>(defaultAnswer = Mockito.RETURNS_DEEP_STUBS)
        val real = MontoyaHttpTransport(api)
        val spy = spy(real)
        // Stub the low-level get() so any caller observes a 200 response and tests can verify the URL.
        doReturn(TransportResponse(200, "{}", true))
            .whenever(spy)
            .get(any(), any(), any())
        // Stub healthCheckGet() so the production code path (which calls healthCheckGet → get) gets
        // Healthy directly AND the underlying get() is observed by `verify()`.
        doAnswer { invocation ->
            val url = invocation.getArgument<String>(0)
            val headers = invocation.getArgument<Map<String, String>>(1)
            val timeoutMs = invocation.getArgument<Long>(2)
            // Re-invoke the spy's stubbed get() so the verify() in the test observes the call.
            val resp = spy.get(url, headers, timeoutMs)
            when {
                resp.isSuccessful -> HealthCheckResult.Healthy
                resp.statusCode == 401 || resp.statusCode == 403 ->
                    HealthCheckResult.Degraded("Endpoint reachable but authentication failed (HTTP ${resp.statusCode}).")
                else -> HealthCheckResult.Unavailable("HTTP ${resp.statusCode}.")
            }
        }.whenever(spy).healthCheckGet(any(), any(), any())
        return spy
    }

    /** Variant whose `post()` returns 200 — needed for NVIDIA NIM. */
    private fun stubTransportPost(): MontoyaHttpTransport {
        val api = mock<MontoyaApi>(defaultAnswer = Mockito.RETURNS_DEEP_STUBS)
        val real = MontoyaHttpTransport(api)
        val spy = spy(real)
        doReturn(TransportResponse(200, "{}", true))
            .whenever(spy)
            .post(any(), any(), any(), any())
        return spy
    }
}
