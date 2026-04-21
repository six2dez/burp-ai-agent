package com.six2dez.burp.aiagent.scanner

import burp.api.montoya.MontoyaApi
import burp.api.montoya.http.message.HttpRequestResponse
import com.six2dez.burp.aiagent.audit.AuditLogger
import com.six2dez.burp.aiagent.config.AgentSettings
import com.six2dez.burp.aiagent.config.McpSettings
import com.six2dez.burp.aiagent.config.SeverityLevel
import com.six2dez.burp.aiagent.redact.PrivacyMode
import com.six2dez.burp.aiagent.scanner.PayloadRisk
import com.six2dez.burp.aiagent.scanner.ScanMode
import com.six2dez.burp.aiagent.supervisor.AgentSupervisor
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.mockito.kotlin.mock
import java.lang.reflect.Method

class PassiveAiScannerConfidenceTest {
    @Test
    fun aiFindingBelowThreshold_isSkippedAndNotRecorded() {
        val scanner =
            PassiveAiScanner(
                api = mock<MontoyaApi>(),
                supervisor = mock<AgentSupervisor>(),
                audit = mock<AuditLogger>(),
            ) { baselineSettings() }

        invokeHandleFinding(
            scanner = scanner,
            requestResponse = mock<HttpRequestResponse>(),
            title = "Potential issue",
            rawSeverity = "High",
            detail = "detail",
            confidence = 84,
            minSeverity = "LOW",
            settings = baselineSettings(),
            source = "ai",
        )

        assertTrue(scanner.getLastFindings(10).isEmpty())
    }

    private fun invokeHandleFinding(
        scanner: PassiveAiScanner,
        requestResponse: HttpRequestResponse,
        title: String,
        rawSeverity: String,
        detail: String,
        confidence: Int,
        minSeverity: String,
        settings: AgentSettings,
        source: String,
    ) {
        val method: Method =
            scanner.javaClass.getDeclaredMethod(
                "handleFinding",
                HttpRequestResponse::class.java,
                String::class.java,
                String::class.java,
                String::class.java,
                Int::class.javaPrimitiveType,
                String::class.java,
                AgentSettings::class.java,
                String::class.java,
            )
        method.isAccessible = true
        method.invoke(scanner, requestResponse, title, rawSeverity, detail, confidence, minSeverity, settings, source)
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
