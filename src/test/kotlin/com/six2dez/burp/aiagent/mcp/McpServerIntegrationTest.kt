package com.six2dez.burp.aiagent.mcp

import burp.api.montoya.MontoyaApi
import burp.api.montoya.core.BurpSuiteEdition
import com.six2dez.burp.aiagent.config.McpSettings
import com.six2dez.burp.aiagent.redact.PrivacyMode
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.mockito.Answers
import org.mockito.kotlin.mock
import org.mockito.kotlin.whenever
import java.net.HttpURLConnection
import java.net.ServerSocket
import java.net.URI
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicReference

class McpServerIntegrationTest {

    @Test
    fun startsServerAndServesHealthAndShutdownEndpoints() {
        val api = mock<MontoyaApi>(defaultAnswer = Answers.RETURNS_DEEP_STUBS)
        whenever(api.burpSuite().version().edition()).thenReturn(BurpSuiteEdition.PROFESSIONAL)
        val manager = KtorMcpServerManager(api)
        val port = freePort()
        val settings = McpSettings(
            enabled = true,
            host = "127.0.0.1",
            port = port,
            externalEnabled = false,
            stdioEnabled = false,
            token = "integration-token",
            allowedOrigins = emptyList(),
            tlsEnabled = false,
            tlsAutoGenerate = true,
            tlsKeystorePath = "",
            tlsKeystorePassword = "",
            scanTaskTtlMinutes = 120,
            collaboratorClientTtlMinutes = 60,
            maxConcurrentRequests = 4,
            maxBodyBytes = 262_144,
            toolToggles = emptyMap(),
            enabledUnsafeTools = emptySet(),
            unsafeEnabled = false
        )

        val terminalState = AtomicReference<McpServerState?>()
        val started = CountDownLatch(1)
        manager.start(settings, PrivacyMode.STRICT, determinismMode = false) { state ->
            if (state is McpServerState.Running || state is McpServerState.Failed) {
                terminalState.set(state)
                started.countDown()
            }
        }

        try {
            assertTrue(started.await(10, TimeUnit.SECONDS), "MCP server did not start in time.")
            val state = terminalState.get()
            assertTrue(state is McpServerState.Running, "MCP failed to start: $state")

            val health = httpRequest(
                method = "GET",
                url = "http://127.0.0.1:$port/__mcp/health"
            )
            assertEquals(200, health.code)
            assertEquals("ok", health.body.trim())

            val unauthorizedShutdown = httpRequest(
                method = "POST",
                url = "http://127.0.0.1:$port/__mcp/shutdown"
            )
            assertEquals(401, unauthorizedShutdown.code)

            val authorizedShutdown = httpRequest(
                method = "POST",
                url = "http://127.0.0.1:$port/__mcp/shutdown",
                headers = mapOf("Authorization" to "Bearer integration-token")
            )
            assertEquals(200, authorizedShutdown.code)
        } finally {
            manager.shutdown()
        }
    }

    private fun freePort(): Int {
        ServerSocket(0).use { socket ->
            return socket.localPort
        }
    }

    private fun httpRequest(
        method: String,
        url: String,
        headers: Map<String, String> = emptyMap()
    ): HttpResponse {
        val connection = URI(url).toURL().openConnection() as HttpURLConnection
        connection.requestMethod = method
        connection.connectTimeout = 3_000
        connection.readTimeout = 3_000
        connection.instanceFollowRedirects = false
        headers.forEach { (name, value) ->
            connection.setRequestProperty(name, value)
        }
        if (method == "POST") {
            connection.doOutput = true
            connection.outputStream.use { }
        }
        val code = connection.responseCode
        val bodyStream = if (code >= 400) connection.errorStream else connection.inputStream
        val body = bodyStream?.bufferedReader()?.use { it.readText() }.orEmpty()
        return HttpResponse(code = code, body = body)
    }

    private data class HttpResponse(
        val code: Int,
        val body: String
    )
}
