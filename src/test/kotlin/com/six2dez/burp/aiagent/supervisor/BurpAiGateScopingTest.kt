package com.six2dez.burp.aiagent.supervisor

import burp.api.montoya.MontoyaApi
import com.six2dez.burp.aiagent.audit.AuditLogger
import com.six2dez.burp.aiagent.backends.BackendRegistry
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.mockito.Answers
import org.mockito.kotlin.mock
import org.mockito.kotlin.whenever
import java.util.concurrent.Executors

/**
 * Regression tests for the v0.6.0 → v0.6.x bug where Burp Pro's "Use AI" toggle was incorrectly
 * gating ALL backends — including CLI agents (claude-cli, codex-cli, gemini-cli, …) and HTTP
 * backends (ollama, lmstudio, openai-compatible, nvidia-nim, perplexity) that have nothing to do
 * with Burp's bundled AI. The toggle must only affect the `burp-ai` backend.
 */
class BurpAiGateScopingTest {
    @Test
    fun requiresBurpAiAndDisabledIsTrueOnlyForBurpAiBackendWhenToggleOff() {
        val api = mock<MontoyaApi>(defaultAnswer = Answers.RETURNS_DEEP_STUBS)
        whenever(api.ai().isEnabled()).thenReturn(false)
        val supervisor = newSupervisor(api)

        // The Burp-AI backend must surface the gate when the toggle is off.
        assertTrue(supervisor.requiresBurpAiAndDisabled("burp-ai"))

        // Every other backend must be unaffected: the gate is irrelevant for them.
        listOf(
            "claude-cli",
            "codex-cli",
            "gemini-cli",
            "opencode-cli",
            "copilot-cli",
            "ollama",
            "lmstudio",
            "openai-compatible",
            "nvidia-nim",
            "perplexity",
        ).forEach { backendId ->
            assertFalse(
                supervisor.requiresBurpAiAndDisabled(backendId),
                "$backendId must not be gated by Burp's Use AI toggle",
            )
        }
    }

    @Test
    fun requiresBurpAiAndDisabledIsFalseForBurpAiWhenToggleOn() {
        val api = mock<MontoyaApi>(defaultAnswer = Answers.RETURNS_DEEP_STUBS)
        whenever(api.ai().isEnabled()).thenReturn(true)
        val supervisor = newSupervisor(api)

        assertFalse(supervisor.requiresBurpAiAndDisabled("burp-ai"))
        assertFalse(supervisor.requiresBurpAiAndDisabled("claude-cli"))
    }

    @Test
    fun isBlockedByBurpAiGateReturnsFalseWhenNoBackendIsRunning() {
        val api = mock<MontoyaApi>(defaultAnswer = Answers.RETURNS_DEEP_STUBS)
        whenever(api.ai().isEnabled()).thenReturn(false)
        val supervisor = newSupervisor(api)

        // No active session yet → the scanner gate must not short-circuit. The send() path will
        // surface the precise error if/when the user actually starts a burp-ai session.
        assertFalse(supervisor.isBlockedByBurpAiGate())
    }

    @Test
    fun isAiEnabledStillReportsRawBurpPreference() {
        val api = mock<MontoyaApi>(defaultAnswer = Answers.RETURNS_DEEP_STUBS)
        whenever(api.ai().isEnabled()).thenReturn(true)
        val supervisorOn = newSupervisor(api)
        assertEquals(true, supervisorOn.isAiEnabled())

        val apiOff = mock<MontoyaApi>(defaultAnswer = Answers.RETURNS_DEEP_STUBS)
        whenever(apiOff.ai().isEnabled()).thenReturn(false)
        val supervisorOff = newSupervisor(apiOff)
        assertEquals(false, supervisorOff.isAiEnabled())
    }

    private fun newSupervisor(api: MontoyaApi): AgentSupervisor =
        AgentSupervisor(
            api = api,
            registry = BackendRegistry(api),
            audit = mock<AuditLogger>(),
            workerPool = Executors.newSingleThreadExecutor { r -> Thread(r, "test-worker").apply { isDaemon = true } },
        )
}
