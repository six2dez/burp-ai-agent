package com.six2dez.burp.aiagent.scanner

import burp.api.montoya.MontoyaApi
import burp.api.montoya.http.message.HttpRequestResponse
import burp.api.montoya.http.message.params.HttpParameterType
import burp.api.montoya.http.message.params.ParsedHttpParameter
import burp.api.montoya.http.message.requests.HttpRequest
import com.six2dez.burp.aiagent.audit.AuditLogger
import com.six2dez.burp.aiagent.config.AgentSettings
import com.six2dez.burp.aiagent.config.McpSettings
import com.six2dez.burp.aiagent.config.SeverityLevel
import com.six2dez.burp.aiagent.redact.PrivacyMode
import com.six2dez.burp.aiagent.supervisor.AgentSupervisor
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.mockito.Answers
import org.mockito.kotlin.mock
import org.mockito.kotlin.whenever
import kotlin.test.assertEquals

class ActiveScannerQueueModelTest {
    @Test
    fun manualScanPopulatesQueueSnapshotAndRespectsLimit() {
        val scanner = newScannerForQueueTests()

        val queued =
            scanner.manualScan(
                requests =
                    listOf(
                        requestResponse("http://example.com/?id=1", "id", "1"),
                        requestResponse("http://example.com/?id=2", "id", "2"),
                    ),
                vulnClasses = listOf(VulnClass.SQLI),
            )

        assertEquals(2, queued)
        val allItems = scanner.getQueueItems(limit = 500)
        assertEquals(2, allItems.size)
        assertTrue(allItems.all { it.status == "QUEUED" })
        assertEquals(1, scanner.getQueueItems(limit = 1).size)
    }

    @Test
    fun cancelQueuedTargetRemovesOnlyMatchingId() {
        val scanner = newScannerForQueueTests()

        val queued =
            scanner.manualScan(
                requests = listOf(requestResponse("http://example.com/?id=9", "id", "9")),
                vulnClasses = listOf(VulnClass.SQLI),
            )
        assertEquals(1, queued)

        val targetId = scanner.getQueueItems(limit = 10).first().id
        assertTrue(scanner.cancelQueuedTarget(targetId))
        assertFalse(scanner.cancelQueuedTarget(targetId))
        assertTrue(scanner.getQueueItems(limit = 10).isEmpty())
    }

    private fun newScannerForQueueTests(): ActiveAiScanner {
        val api = mock<MontoyaApi>(defaultAnswer = Answers.RETURNS_DEEP_STUBS)
        return ActiveAiScanner(
            api = api,
            supervisor = mock<AgentSupervisor>(),
            audit = mock<AuditLogger>(),
            getSettings = { baselineSettings() },
        ).apply {
            scopeOnly = false
            maxQueueSize = 64
            scanMode = ScanMode.FULL
        }
    }

    private fun requestResponse(
        url: String,
        name: String,
        value: String,
    ): HttpRequestResponse {
        val param = mock<ParsedHttpParameter>()
        whenever(param.type()).thenReturn(HttpParameterType.URL)
        whenever(param.name()).thenReturn(name)
        whenever(param.value()).thenReturn(value)

        val request = mock<HttpRequest>()
        whenever(request.url()).thenReturn(url)
        whenever(request.parameters()).thenReturn(listOf(param))
        whenever(request.headers()).thenReturn(emptyList())
        whenever(request.headerValue("Content-Type")).thenReturn(null)
        whenever(request.bodyToString()).thenReturn("")

        val requestResponse = mock<HttpRequestResponse>()
        whenever(requestResponse.request()).thenReturn(request)
        return requestResponse
    }

    private fun baselineSettings(): AgentSettings =
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
            passiveAiEnabled = false,
            passiveAiRateSeconds = 5,
            passiveAiScopeOnly = true,
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
