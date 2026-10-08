package com.six2dez.burp.aiagent.ui

import com.six2dez.burp.aiagent.TestSettings
import com.six2dez.burp.aiagent.config.AgentSettings
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import java.time.LocalTime
import java.util.ArrayDeque
import java.util.concurrent.Executor
import java.util.concurrent.RejectedExecutionException
import java.util.concurrent.atomic.AtomicInteger

/** Headless pure-logic tests for the status-pill scheduling (quick 261008-kw4). */
class BackendHealthSchedulingTest {
    private fun settings(
        backendId: String,
        transform: (AgentSettings) -> AgentSettings = { it },
    ): AgentSettings = transform(TestSettings.baselineSettings(preferredBackendId = backendId))

    @Test
    fun periodicRunsOnlyForLocalBackends() {
        val local =
            listOf(
                settings("codex-cli"),
                settings("gemini-cli"),
                settings("opencode-cli"),
                settings("claude-cli"),
                settings("copilot-cli"),
                settings("burp-ai"),
                settings("ollama") { it.copy(ollamaUrl = "http://127.0.0.1:11434") },
                settings("ollama") { it.copy(ollamaUrl = "") },
                settings("lmstudio") { it.copy(lmStudioUrl = "http://localhost:1234") },
                settings("openai-compatible") { it.copy(openAiCompatibleUrl = "http://127.0.0.1:8080/v1") },
                settings("nvidia-nim") { it.copy(nvidiaNimUrl = "http://[::1]:8000") },
            )
        local.forEach {
            assertTrue(
                BackendHealthPolicy.shouldRun(HealthCheckTrigger.PERIODIC, it),
                "expected periodic poll for ${it.preferredBackendId}",
            )
        }
    }

    @Test
    fun periodicNeverRunsForRemoteOrUnknownBackends() {
        val remote =
            listOf(
                settings("nvidia-nim") { it.copy(nvidiaNimUrl = "https://integrate.api.nvidia.com") },
                settings("nvidia-nim") { it.copy(nvidiaNimUrl = "") },
                settings("perplexity") { it.copy(perplexityUrl = "https://api.perplexity.ai") },
                settings("perplexity") { it.copy(perplexityUrl = "") },
                settings("openai-compatible") { it.copy(openAiCompatibleUrl = "https://api.openai.com/v1") },
                settings("openai-compatible") { it.copy(openAiCompatibleUrl = "http://192.168.1.50:8000") },
                settings("openai-compatible") { it.copy(openAiCompatibleUrl = "") },
                settings("anthropic"),
                settings("some-external-backend"),
            )
        remote.forEach {
            assertFalse(
                BackendHealthPolicy.shouldRun(HealthCheckTrigger.PERIODIC, it),
                "a timer must never poll ${it.preferredBackendId}",
            )
        }
    }

    @Test
    fun onDemandTriggersAlwaysRun() {
        val remote = settings("perplexity") { it.copy(perplexityUrl = "https://api.perplexity.ai") }
        val unknown = settings("some-external-backend")
        listOf(HealthCheckTrigger.STARTUP, HealthCheckTrigger.SETTINGS_CHANGED, HealthCheckTrigger.USER_CLICK).forEach { trigger ->
            assertTrue(BackendHealthPolicy.shouldRun(trigger, remote))
            assertTrue(BackendHealthPolicy.shouldRun(trigger, unknown))
        }
    }

    @Test
    fun tooltipShowsTheLastCheckTime() {
        assertEquals(
            "Backend health check passed. Last checked 09:05:07. Click to re-check.",
            BackendHealthPolicy.tooltip("Backend health check passed.", LocalTime.of(9, 5, 7)),
        )
    }

    /** Executor that queues runnables until the test drains them. */
    private class ManualExecutor : Executor {
        val queue = ArrayDeque<Runnable>()

        override fun execute(command: Runnable) {
            queue.add(command)
        }

        fun runNext() = queue.removeFirst().run()
    }

    @Test
    fun singleFlightRejectsASecondSubmitWhileBusy() {
        val exec = ManualExecutor()
        val gate = SingleFlightGate(exec) {}
        assertTrue(gate.submit(coalesce = false) {})
        assertEquals(1, exec.queue.size)
        assertFalse(gate.submit(coalesce = false) {})
        assertEquals(1, exec.queue.size, "a busy gate must not enqueue")
        exec.runNext()
        assertTrue(gate.submit(coalesce = false) {}, "the gate must reopen after the flight")
        assertEquals(1, exec.queue.size)
    }

    @Test
    fun coalescingSubmitsDuringAFlightTriggerExactlyOneRerun() {
        val exec = ManualExecutor()
        val reruns = AtomicInteger(0)
        val gate = SingleFlightGate(exec) { reruns.incrementAndGet() }
        assertTrue(gate.submit(coalesce = true) {})
        assertFalse(gate.submit(coalesce = true) {})
        assertFalse(gate.submit(coalesce = true) {})
        assertEquals(0, reruns.get())
        exec.runNext()
        assertEquals(1, reruns.get())
    }

    @Test
    fun nonCoalescingSubmitDuringAFlightTriggersNoRerun() {
        val exec = ManualExecutor()
        val reruns = AtomicInteger(0)
        val gate = SingleFlightGate(exec) { reruns.incrementAndGet() }
        assertTrue(gate.submit(coalesce = false) {})
        assertFalse(gate.submit(coalesce = false) {})
        exec.runNext()
        assertEquals(0, reruns.get())
    }

    @Test
    fun aThrowingTaskStillReleasesTheGate() {
        val exec = ManualExecutor()
        val gate = SingleFlightGate(exec) {}
        assertTrue(gate.submit(coalesce = false) { error("boom") })
        runCatching { exec.runNext() }
        assertTrue(gate.submit(coalesce = false) {}, "a failed check must not wedge the pill")
    }

    @Test
    fun rejectedExecutionLeavesTheGateReleased() {
        // A second submit must reach the executor again (and be rejected again) instead of being
        // refused as "busy" without trying: the rejection released the gate.
        val attempts = AtomicInteger(0)
        val gate =
            SingleFlightGate(
                Executor {
                    attempts.incrementAndGet()
                    throw RejectedExecutionException("shut down")
                },
            ) {}
        assertFalse(gate.submit(coalesce = false) {})
        assertFalse(gate.submit(coalesce = false) {})
        assertEquals(2, attempts.get(), "a rejected submit must leave the gate released")
    }
}
