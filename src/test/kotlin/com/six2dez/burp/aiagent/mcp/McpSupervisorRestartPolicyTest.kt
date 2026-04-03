package com.six2dez.burp.aiagent.mcp

import burp.api.montoya.MontoyaApi
import com.six2dez.burp.aiagent.audit.AiRequestLogger
import com.six2dez.burp.aiagent.config.McpSettings
import com.six2dez.burp.aiagent.mcp.tools.ResponsePreprocessorSettings
import com.six2dez.burp.aiagent.redact.PrivacyMode
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.mockito.Answers
import org.mockito.kotlin.mock
import java.net.BindException
import java.util.ArrayDeque
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger

class McpSupervisorRestartPolicyTest {

    @Test
    fun bindConflict_requestsTakeoverAndRetriesWithBoundedPolicy() {
        val api = mock<MontoyaApi>(defaultAnswer = Answers.RETURNS_DEEP_STUBS)
        val manager = ScriptedServerManager(
            scriptedStates = ArrayDeque(
                listOf(
                    McpServerState.Failed(BindException("Address already in use")),
                    McpServerState.Running
                )
            ),
            fallbackState = McpServerState.Running,
            expectedStarts = 2
        )
        val takeoverClient = FakeTakeoverClient(
            probeResult = true,
            shutdownResult = true
        )
        val scheduler = Executors.newSingleThreadScheduledExecutor()
        val supervisor = McpSupervisor(
            api = api,
            serverManager = manager,
            stdioBridge = McpStdioBridge(api),
            scheduler = scheduler,
            takeoverClientOverride = takeoverClient,
            maxRestartAttempts = 2,
            maxTakeoverAttempts = 2,
            restartDelayMs = 10,
            takeoverRetryDelayMs = 10
        )

        supervisor.applySettings(
            settings(enabled = true),
            PrivacyMode.STRICT,
            determinismMode = false,
            preprocessSettings = ResponsePreprocessorSettings()
        )

        assertTrue(manager.awaitStarts(timeoutMs = 1_000))
        assertEquals(2, manager.startCalls.get())
        assertEquals(1, takeoverClient.probeCalls.get())
        assertEquals(1, takeoverClient.shutdownCalls.get())
        assertTrue(supervisor.status() is McpServerState.Running)

        supervisor.shutdown()
    }

    @Test
    fun nonBindFailures_stopAfterRetryBudgetExhaustion() {
        val api = mock<MontoyaApi>(defaultAnswer = Answers.RETURNS_DEEP_STUBS)
        val manager = ScriptedServerManager(
            scriptedStates = ArrayDeque(),
            fallbackState = McpServerState.Failed(IllegalStateException("boom")),
            expectedStarts = 3
        )
        val takeoverClient = FakeTakeoverClient(
            probeResult = false,
            shutdownResult = false
        )
        val scheduler = Executors.newSingleThreadScheduledExecutor()
        val supervisor = McpSupervisor(
            api = api,
            serverManager = manager,
            stdioBridge = McpStdioBridge(api),
            scheduler = scheduler,
            takeoverClientOverride = takeoverClient,
            maxRestartAttempts = 2,
            maxTakeoverAttempts = 1,
            restartDelayMs = 10,
            takeoverRetryDelayMs = 10
        )

        supervisor.applySettings(
            settings(enabled = true),
            PrivacyMode.STRICT,
            determinismMode = false,
            preprocessSettings = ResponsePreprocessorSettings()
        )

        assertTrue(manager.awaitStarts(timeoutMs = 1_000))
        Thread.sleep(50)
        assertEquals(3, manager.startCalls.get())
        assertEquals(0, takeoverClient.probeCalls.get())
        assertTrue(supervisor.status() is McpServerState.Failed)

        supervisor.shutdown()
    }

    private fun settings(enabled: Boolean): McpSettings {
        return McpSettings(
            enabled = enabled,
            host = "127.0.0.1",
            port = 8765,
            externalEnabled = false,
            stdioEnabled = false,
            token = "token",
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
    }

    private class FakeTakeoverClient(
        private val probeResult: Boolean,
        private val shutdownResult: Boolean
    ) : McpTakeoverClient {
        val probeCalls = AtomicInteger(0)
        val shutdownCalls = AtomicInteger(0)

        override fun probe(settings: McpSettings): Boolean {
            probeCalls.incrementAndGet()
            return probeResult
        }

        override fun requestShutdown(settings: McpSettings): Boolean {
            shutdownCalls.incrementAndGet()
            return shutdownResult
        }
    }

    private class ScriptedServerManager(
        private val scriptedStates: ArrayDeque<McpServerState>,
        private val fallbackState: McpServerState,
        expectedStarts: Int
    ) : McpServerManager {
        val startCalls = AtomicInteger(0)
        private val startLatch = CountDownLatch(expectedStarts)

        override fun setAiRequestLogger(logger: AiRequestLogger) = Unit

        override fun start(
            settings: McpSettings,
            privacyMode: PrivacyMode,
            determinismMode: Boolean,
            preprocessSettings: ResponsePreprocessorSettings,
            callback: (McpServerState) -> Unit
        ) {
            startCalls.incrementAndGet()
            startLatch.countDown()
            val state = if (scriptedStates.isEmpty()) fallbackState else scriptedStates.removeFirst()
            callback(state)
        }

        override fun stop(callback: (McpServerState) -> Unit) {
            callback(McpServerState.Stopped)
        }

        override fun shutdown() = Unit

        fun awaitStarts(timeoutMs: Long): Boolean {
            return startLatch.await(timeoutMs, TimeUnit.MILLISECONDS)
        }
    }
}
