package com.six2dez.burp.aiagent.backends

import burp.api.montoya.MontoyaApi
import burp.api.montoya.logging.Logging
import com.six2dez.burp.aiagent.config.AgentSettings
import com.six2dez.burp.aiagent.config.McpSettings
import com.six2dez.burp.aiagent.config.SeverityLevel
import com.six2dez.burp.aiagent.redact.PrivacyMode
import com.six2dez.burp.aiagent.scanner.PayloadRisk
import com.six2dez.burp.aiagent.scanner.ScanMode
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.mockito.kotlin.mock
import org.mockito.kotlin.whenever
import java.util.concurrent.atomic.AtomicInteger

class BackendRegistryTest {
    @Test
    fun listBackendIds_usesAvailabilityCachePerSettings() {
        val registry = createRegistry()
        val backends = backendsField(registry)
        val cache = availabilityCacheField(registry)
        backends.clear()
        cache.clear()

        val firstCalls = AtomicInteger(0)
        val secondCalls = AtomicInteger(0)
        backends["first"] = CountingBackend("first", "B", firstCalls)
        backends["second"] = CountingBackend("second", "A", secondCalls)

        val settings = baselineSettings()
        val idsFirst = registry.listBackendIds(settings)
        val idsSecond = registry.listBackendIds(settings)

        assertEquals(listOf("second", "first"), idsFirst)
        assertEquals(idsFirst, idsSecond)
        assertEquals(1, firstCalls.get())
        assertEquals(1, secondCalls.get())
    }

    @Test
    fun reloadAndShutdown_clearAvailabilityCache() {
        val registry = createRegistry()
        val cache = availabilityCacheField(registry)
        cache[Pair("backend", 7)] = true
        assertTrue(cache.isNotEmpty())

        registry.reload()
        assertTrue(cache.isEmpty())

        cache[Pair("backend", 9)] = true
        registry.shutdown()
        assertTrue(cache.isEmpty())
    }

    private fun createRegistry(): BackendRegistry {
        val api = mock<MontoyaApi>()
        val logging = mock<Logging>()
        whenever(api.logging()).thenReturn(logging)
        return BackendRegistry(api)
    }

    @Suppress("UNCHECKED_CAST")
    private fun backendsField(registry: BackendRegistry): java.util.concurrent.ConcurrentHashMap<String, AiBackend> {
        val field = registry.javaClass.getDeclaredField("backends")
        field.isAccessible = true
        return field.get(registry) as java.util.concurrent.ConcurrentHashMap<String, AiBackend>
    }

    @Suppress("UNCHECKED_CAST")
    private fun availabilityCacheField(registry: BackendRegistry): java.util.concurrent.ConcurrentHashMap<Pair<String, Int>, Boolean> {
        val field = registry.javaClass.getDeclaredField("availabilityCache")
        field.isAccessible = true
        return field.get(registry) as java.util.concurrent.ConcurrentHashMap<Pair<String, Int>, Boolean>
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

    private class CountingBackend(
        override val id: String,
        override val displayName: String,
        private val calls: AtomicInteger,
    ) : AiBackend {
        override fun launch(config: BackendLaunchConfig): AgentConnection = throw UnsupportedOperationException("Not needed in this test")

        override fun isAvailable(settings: AgentSettings): Boolean {
            calls.incrementAndGet()
            return true
        }
    }
}
