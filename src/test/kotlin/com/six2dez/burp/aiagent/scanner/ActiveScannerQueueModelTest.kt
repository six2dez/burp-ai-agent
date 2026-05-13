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
import org.mockito.kotlin.any
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

    /**
     * Priority 60 is hardcoded at ActiveAiScanner.kt:235; ActiveScanQueueItem does not surface
     * priority, so the queueing-success assertions below prove the per-class loop fired.
     * Reflection into the private scanQueue is forbidden by D-04; adding a priority field to
     * ActiveScanQueueItem is out of audit scope.
     */
    @Test
    fun manualScanInsertionPointQueuesOnePerClassAtPriority60WithoutDedup() {
        val scanner = newScannerForQueueTests()
        val rr = requestResponse("http://example.com/?id=1", "id", "1")
        val point = InjectionPoint(InjectionType.URL_PARAM, "id", "1")
        val vulnClasses = listOf(VulnClass.SQLI, VulnClass.XSS_REFLECTED, VulnClass.CMDI)

        // Invariant 1: queue size after first invocation
        val firstCount = scanner.manualScanInsertionPoint(rr, point, vulnClasses)
        assertEquals(3, firstCount)
        val firstItems = scanner.getQueueItems(limit = 10)
        assertEquals(3, firstItems.size)

        // Invariant 2: per-item vuln-class set + injectionPoint stringification
        assertEquals(setOf("SQLI", "XSS_REFLECTED", "CMDI"), firstItems.map { it.vulnClass }.toSet())
        assertTrue(firstItems.all { it.injectionPoint == "URL_PARAM:id" })
        assertTrue(firstItems.all { it.status == "QUEUED" })

        // Invariant 3: dedup-bypass on re-invoke (D-12 folded per CONTEXT.md)
        val secondCount = scanner.manualScanInsertionPoint(rr, point, vulnClasses)
        assertEquals(3, secondCount)
        val totalItems = scanner.getQueueItems(limit = 10)
        assertEquals(6, totalItems.size)
    }

    /**
     * Locks the out-of-scope short-circuit at ActiveAiScanner.kt:225. Threat model T-2-01
     * (out-of-scope target leakage / information disclosure) — mitigated by scopeOnly +
     * api.scope().isInScope() gate.
     */
    @Test
    fun manualScanInsertionPointReturnsZeroAndDoesNotQueueWhenOutOfScope() {
        val api = mock<MontoyaApi>(defaultAnswer = Answers.RETURNS_DEEP_STUBS)
        whenever(api.scope().isInScope(any<String>())).thenReturn(false)
        val scanner =
            ActiveAiScanner(
                api = api,
                supervisor = mock<AgentSupervisor>(),
                audit = mock<AuditLogger>(),
                getSettings = { baselineSettings() },
            ).apply {
                scopeOnly = true
                maxQueueSize = 64
                scanMode = ScanMode.FULL
            }
        val rr = requestResponse("http://out-of-scope.example.com/?id=1", "id", "1")
        val point = InjectionPoint(InjectionType.URL_PARAM, "id", "1")

        val count = scanner.manualScanInsertionPoint(rr, point, listOf(VulnClass.SQLI))

        assertEquals(0, count)
        assertTrue(scanner.getQueueItems(limit = 10).isEmpty())
    }

    /**
     * Locks the PASSIVE_ONLY_VULN_CLASSES filter on the manual-insertion-point path. Per
     * RESEARCH.md Pitfall #6: CORS_MISCONFIGURATION is the stable passive-only canary
     * (ActiveScanModels.kt:112) and SQLI is the stable active-eligible canary (used by every
     * other queue test). Filter chain: ActiveAiScanner.kt:220-223.
     */
    @Test
    fun manualScanInsertionPointFiltersPassiveOnlyVulnClasses() {
        val scanner = newScannerForQueueTests()
        val rr = requestResponse("http://example.com/?id=1", "id", "1")
        val point = InjectionPoint(InjectionType.URL_PARAM, "id", "1")
        val vulnClasses = listOf(VulnClass.CORS_MISCONFIGURATION, VulnClass.SQLI)

        val count = scanner.manualScanInsertionPoint(rr, point, vulnClasses)

        assertEquals(1, count)
        val items = scanner.getQueueItems(limit = 10)
        assertEquals(1, items.size)
        assertEquals("SQLI", items.single().vulnClass)
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
