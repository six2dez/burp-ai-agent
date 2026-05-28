package com.six2dez.burp.aiagent.scanner

import burp.api.montoya.MontoyaApi
import burp.api.montoya.http.message.HttpRequestResponse
import com.six2dez.burp.aiagent.config.AgentSettings
import com.six2dez.burp.aiagent.config.McpSettings
import com.six2dez.burp.aiagent.config.SeverityLevel
import com.six2dez.burp.aiagent.redact.PrivacyMode
import com.six2dez.burp.aiagent.scanner.PayloadRisk
import com.six2dez.burp.aiagent.scanner.ScanMode
import org.junit.jupiter.api.Test
import org.mockito.Answers
import org.mockito.kotlin.any
import org.mockito.kotlin.mock
import org.mockito.kotlin.verify
import org.mockito.kotlin.whenever

class AiPassiveScanCheckTest {

    /**
     * Verifies that doCheck() returns synchronously (without blocking on AI).
     *
     * Note: AuditResult.auditResult() requires the Burp runtime factory which is unavailable
     * in unit tests. We catch the resulting NullPointerException (from ObjectFactoryLocator.FACTORY)
     * and verify that localChecks() was called synchronously — proving the scan check ran its
     * local heuristics path without blocking on AI. The test completes within milliseconds.
     */
    @Test
    fun doCheck_returnsLocalFindingsSynchronously() {
        val api = mock<MontoyaApi>(defaultAnswer = Answers.RETURNS_DEEP_STUBS)
        val passiveScanner = mock<PassiveAiScanner>()
        val reqResp = mock<HttpRequestResponse>(defaultAnswer = Answers.RETURNS_DEEP_STUBS)

        // localChecks() returns an empty list so the AuditResult factory is called with empty list
        whenever(passiveScanner.localChecks(any(), any())).thenReturn(emptyList())

        val check = AiPassiveScanCheck(api, passiveScanner) { testSettings() }

        // doCheck() completes without blocking on AI.
        // AuditResult.auditResult() throws NPE without Burp runtime — expected in unit tests.
        try {
            check.doCheck(reqResp)
        } catch (_: NullPointerException) {
            // Expected: Burp ObjectFactoryLocator.FACTORY is null outside the Burp runtime.
            // The important proof is that localChecks() was called synchronously below.
        }

        // Verify localChecks() was invoked — proves the synchronous heuristic path ran
        verify(passiveScanner).localChecks(any(), any())
    }

    /**
     * Verifies that doCheck() enqueues async AI analysis on the passive scanner.
     */
    @Test
    fun doCheck_enqueuesAsyncAnalysisOnScanner() {
        val api = mock<MontoyaApi>(defaultAnswer = Answers.RETURNS_DEEP_STUBS)
        val passiveScanner = mock<PassiveAiScanner>()
        val reqResp = mock<HttpRequestResponse>(defaultAnswer = Answers.RETURNS_DEEP_STUBS)

        whenever(passiveScanner.localChecks(any(), any())).thenReturn(emptyList())

        val check = AiPassiveScanCheck(api, passiveScanner) { testSettings() }

        // AuditResult.auditResult() throws NPE without Burp runtime — expected in unit tests.
        try {
            check.doCheck(reqResp)
        } catch (_: NullPointerException) {
            // Expected: Burp ObjectFactoryLocator.FACTORY is null outside the Burp runtime.
        }

        // After doCheck(), the async AI analysis must have been enqueued
        verify(passiveScanner).enqueueForScanCheck(reqResp)
    }

    private fun testSettings(): AgentSettings =
        AgentSettings(
            codexCmd = "codex",
            geminiCmd = "gemini",
            opencodeCmd = "opencode",
            claudeCmd = "claude",
            agentProfile = "pentester",
            ollamaCliCmd = "ollama",
            ollamaModel = "llama3.1:8b",
            ollamaUrl = "http://127.0.0.1:11434",
            ollamaServeCmd = "ollama serve",
            ollamaAutoStart = false,
            ollamaApiKey = "",
            ollamaHeaders = "",
            ollamaTimeoutSeconds = 60,
            ollamaContextWindow = 8192,
            lmStudioUrl = "http://127.0.0.1:1234",
            lmStudioModel = "model",
            lmStudioTimeoutSeconds = 60,
            lmStudioServerCmd = "",
            lmStudioAutoStart = false,
            lmStudioApiKey = "",
            lmStudioHeaders = "",
            openAiCompatibleUrl = "",
            openAiCompatibleModel = "",
            openAiCompatibleApiKey = "",
            openAiCompatibleHeaders = "",
            openAiCompatibleTimeoutSeconds = 60,
            requestPromptTemplate = "req",
            issuePromptTemplate = "issue",
            issueAnalyzePrompt = "analyze",
            issuePocPrompt = "poc",
            issueImpactPrompt = "impact",
            requestSummaryPrompt = "summary",
            explainJsPrompt = "js",
            accessControlPrompt = "access",
            loginSequencePrompt = "login",
            hostAnonymizationSalt = "salt",
            preferredBackendId = "codex-cli",
            privacyMode = PrivacyMode.STRICT,
            determinismMode = false,
            autoRestart = true,
            auditEnabled = true,
            mcpSettings =
                McpSettings(
                    enabled = false,
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
                    unsafeEnabled = false,
                ),
            // passiveAiScopeOnly = false so scope check does not short-circuit doCheck()
            passiveAiEnabled = false,
            passiveAiRateSeconds = 5,
            passiveAiScopeOnly = false,
            passiveAiMaxSizeKb = 96,
            passiveAiMinSeverity = SeverityLevel.LOW,
            activeAiEnabled = false,
            activeAiMaxConcurrent = 2,
            activeAiMaxPayloadsPerPoint = 8,
            activeAiTimeoutSeconds = 30,
            activeAiRequestDelayMs = 100,
            activeAiMaxRiskLevel = PayloadRisk.SAFE,
            activeAiScopeOnly = true,
            activeAiAutoFromPassive = true,
            activeAiScanMode = ScanMode.FULL,
            activeAiUseCollaborator = false,
            bountyPromptEnabled = false,
            bountyPromptDir = "",
            bountyPromptAutoCreateIssues = true,
            bountyPromptIssueConfidenceThreshold = 90,
            bountyPromptEnabledPromptIds = emptySet(),
        )
}
