package com.six2dez.burp.aiagent.mcp

import burp.api.montoya.MontoyaApi
import com.six2dez.burp.aiagent.config.McpSettings
import com.six2dez.burp.aiagent.mcp.tools.ResponsePreprocessorSettings
import com.six2dez.burp.aiagent.redact.PrivacyMode
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.mockito.Answers
import org.mockito.kotlin.mock
import java.net.ServerSocket
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicReference

/**
 * SC5a — verifies that KtorMcpServerManager.stop() is bounded (never hangs forever)
 * and that a stop→start→stop restart cycle works correctly.
 *
 * The stop() method must:
 *  1. Complete within a bounded timeout (well under 30 s in tests).
 *  2. Fire the lifecycle callback (Stopped or Failed) so the UI does not wait forever.
 *  3. NOT terminate the shared single-thread executor — start() must be usable after stop().
 *
 * Naming note: McpShutdownBoundTest is NOT matched by the *IntegrationTest / *RestartPolicyTest
 * / *ConcurrencyTest exclusion globs under -PexcludeHeavyTests=true, so it runs in the
 * standard suite.
 */
class McpShutdownBoundTest {

    // Allow up to 15 s for stop to complete in CI (actual bound in production is ~10 s)
    private val stopTimeoutSeconds = 15L

    private fun freePort(): Int =
        ServerSocket(0).use { it.localPort }

    private fun defaultSettings(port: Int): McpSettings =
        McpSettings(
            enabled = true,
            host = "127.0.0.1",
            port = port,
            externalEnabled = false,
            stdioEnabled = false,
            token = "test-token",
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
            unsafeEnabled = false,
        )

    @Test
    fun stopCallbackFiresWithinBound() {
        val api = mock<MontoyaApi>(defaultAnswer = Answers.RETURNS_DEEP_STUBS)
        val manager = KtorMcpServerManager(api)
        val port = freePort()

        // Start the server and wait for it to be Running
        val startedLatch = CountDownLatch(1)
        val startState = AtomicReference<McpServerState?>()
        manager.start(
            defaultSettings(port),
            PrivacyMode.STRICT,
            determinismMode = false,
            preprocessSettings = ResponsePreprocessorSettings(),
        ) { state ->
            if (state is McpServerState.Running || state is McpServerState.Failed) {
                startState.set(state)
                startedLatch.countDown()
            }
        }

        assertTrue(startedLatch.await(10, TimeUnit.SECONDS), "MCP server did not start in time")
        assertTrue(startState.get() is McpServerState.Running, "MCP server failed to start: ${startState.get()}")

        // Now call stop and assert the callback fires within the bound
        val stopLatch = CountDownLatch(1)
        val stopState = AtomicReference<McpServerState?>()
        manager.stop { state ->
            if (state is McpServerState.Stopped || state is McpServerState.Failed) {
                stopState.set(state)
                stopLatch.countDown()
            }
        }

        assertTrue(
            stopLatch.await(stopTimeoutSeconds, TimeUnit.SECONDS),
            "stop() did not complete within ${stopTimeoutSeconds}s — it may be hanging",
        )
        assertTrue(
            stopState.get() is McpServerState.Stopped || stopState.get() is McpServerState.Failed,
            "stop callback must reach Stopped or Failed, got: ${stopState.get()}",
        )

        manager.shutdown()
    }

    @Test
    fun stopDoesNotTerminateExecutorAllowingRestart() {
        val api = mock<MontoyaApi>(defaultAnswer = Answers.RETURNS_DEEP_STUBS)
        val manager = KtorMcpServerManager(api)

        // Cycle 1: start → stop
        val port1 = freePort()
        val started1 = CountDownLatch(1)
        manager.start(
            defaultSettings(port1),
            PrivacyMode.STRICT,
            determinismMode = false,
            preprocessSettings = ResponsePreprocessorSettings(),
        ) { state ->
            if (state is McpServerState.Running || state is McpServerState.Failed) started1.countDown()
        }
        assertTrue(started1.await(10, TimeUnit.SECONDS), "first start did not complete")

        val stopped1 = CountDownLatch(1)
        manager.stop { state ->
            if (state is McpServerState.Stopped || state is McpServerState.Failed) stopped1.countDown()
        }
        assertTrue(stopped1.await(stopTimeoutSeconds, TimeUnit.SECONDS), "first stop did not complete in time")

        // Cycle 2: start again on a NEW port (executor must NOT have been shut down)
        val port2 = freePort()
        val started2 = CountDownLatch(1)
        val state2 = AtomicReference<McpServerState?>()
        manager.start(
            defaultSettings(port2),
            PrivacyMode.STRICT,
            determinismMode = false,
            preprocessSettings = ResponsePreprocessorSettings(),
        ) { state ->
            if (state is McpServerState.Running || state is McpServerState.Failed) {
                state2.set(state)
                started2.countDown()
            }
        }
        assertTrue(started2.await(10, TimeUnit.SECONDS), "restart after stop did not complete")
        assertTrue(
            state2.get() is McpServerState.Running,
            "restart after stop should reach Running, got: ${state2.get()}. " +
                "If RejectedExecutionException — stop() terminated the executor (regression).",
        )

        // Cycle 3: stop again
        val stopped2 = CountDownLatch(1)
        manager.stop { state ->
            if (state is McpServerState.Stopped || state is McpServerState.Failed) stopped2.countDown()
        }
        assertTrue(stopped2.await(stopTimeoutSeconds, TimeUnit.SECONDS), "second stop did not complete in time")

        manager.shutdown()
    }
}
