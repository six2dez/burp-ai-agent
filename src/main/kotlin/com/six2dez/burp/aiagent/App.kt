package com.six2dez.burp.aiagent

import burp.api.montoya.MontoyaApi
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider
import burp.api.montoya.ui.contextmenu.ContextMenuEvent
import burp.api.montoya.ui.contextmenu.AuditIssueContextMenuEvent
import com.six2dez.burp.aiagent.audit.ActivityType
import com.six2dez.burp.aiagent.audit.AiRequestLogger
import com.six2dez.burp.aiagent.audit.AuditLogger
import com.six2dez.burp.aiagent.audit.RollingLogConfig
import com.six2dez.burp.aiagent.backends.BackendDiagnostics
import com.six2dez.burp.aiagent.backends.BackendRegistry
import com.six2dez.burp.aiagent.agents.AgentProfileLoader
import com.six2dez.burp.aiagent.config.AgentSettingsRepository
import com.six2dez.burp.aiagent.context.ContextCollector
import com.six2dez.burp.aiagent.mcp.McpSupervisor
import com.six2dez.burp.aiagent.redact.Redaction
import com.six2dez.burp.aiagent.scanner.ActiveAiScanner
import com.six2dez.burp.aiagent.scanner.AiScanCheck
import com.six2dez.burp.aiagent.scanner.PassiveAiScanner
import com.six2dez.burp.aiagent.scanner.PayloadRisk
import com.six2dez.burp.aiagent.supervisor.AgentSupervisor
import com.six2dez.burp.aiagent.ui.MainTab
import com.six2dez.burp.aiagent.ui.UiActions
import com.six2dez.burp.aiagent.alerts.Alerting
import java.nio.file.Paths
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit

object App {
    lateinit var api: MontoyaApi
        private set

    private val workerPool = Executors.newCachedThreadPool()
    lateinit var backendRegistry: BackendRegistry
        private set
    lateinit var auditLogger: AuditLogger
        private set
    lateinit var supervisor: AgentSupervisor
        private set
    lateinit var mcpSupervisor: McpSupervisor
        private set
    lateinit var contextCollector: ContextCollector
        private set
    lateinit var passiveAiScanner: PassiveAiScanner
        private set
    lateinit var activeAiScanner: ActiveAiScanner
        private set
    private var mainTab: MainTab? = null
    lateinit var aiRequestLogger: AiRequestLogger
        private set

    private lateinit var settingsRepo: AgentSettingsRepository

    fun initialize(montoyaApi: MontoyaApi) {
        api = montoyaApi
        api.extension().setName("Custom AI Agent")

        BackendDiagnostics.output = { api.logging().logToOutput(it) }
        BackendDiagnostics.error = { api.logging().logToError(it) }
        api.logging().logToOutput("Backend diagnostics enabled.")

        settingsRepo = AgentSettingsRepository(api)
        backendRegistry = BackendRegistry(api)
        auditLogger = AuditLogger(api)
        AuditLogger.registerGlobalEmitter { type, payload -> auditLogger.logEvent(type, payload) }
        supervisor = AgentSupervisor(api, backendRegistry, auditLogger, workerPool)
        aiRequestLogger = AiRequestLogger()
        supervisor.aiRequestLogger = aiRequestLogger
        mcpSupervisor = McpSupervisor(api)
        mcpSupervisor.setAiRequestLogger(aiRequestLogger)
        contextCollector = ContextCollector(api)
        passiveAiScanner = PassiveAiScanner(api, supervisor, auditLogger) { settingsRepo.load() }
        passiveAiScanner.aiRequestLogger = aiRequestLogger
        activeAiScanner = ActiveAiScanner(api, supervisor, auditLogger) { settingsRepo.load() }
        
        AgentProfileLoader.ensureBundledProfilesInstalled()
        val settings = settingsRepo.load()
        AgentProfileLoader.setActiveProfile(settings.agentProfile)
        aiRequestLogger.enabled = settings.aiRequestLoggerEnabled
        aiRequestLogger.maxEntries = settings.aiRequestLoggerMaxEntries
        configureRollingLoggerFromProperties()
        BackendDiagnostics.retry = { event ->
            aiRequestLogger.log(
                type = ActivityType.RETRY,
                source = "backend",
                backendId = event.backendId,
                detail = "Retry attempt ${event.attempt} in ${event.delayMs}ms: ${event.reason ?: "unknown"}",
                durationMs = event.delayMs,
                metadata = mapOf(
                    "attempt" to event.attempt.toString(),
                    "delayMs" to event.delayMs.toString(),
                    "reason" to (event.reason ?: "")
                )
            )
        }
        auditLogger.setEnabled(settings.auditEnabled)
        supervisor.applySettings(settings)
        mcpSupervisor.applySettings(settings.mcpSettings, settings.privacyMode, settings.determinismMode)
        
        // Initialize passive AI scanner
        passiveAiScanner.rateLimitSeconds = settings.passiveAiRateSeconds
        passiveAiScanner.scopeOnly = settings.passiveAiScopeOnly
        passiveAiScanner.maxSizeKb = settings.passiveAiMaxSizeKb
        passiveAiScanner.applyOptimizationSettings(settings)
        passiveAiScanner.activeScanner = activeAiScanner  // Wire passive -> active
        passiveAiScanner.setEnabled(settings.passiveAiEnabled)
        
        // Initialize active AI scanner
        activeAiScanner.maxConcurrent = settings.activeAiMaxConcurrent
        activeAiScanner.maxPayloadsPerPoint = settings.activeAiMaxPayloadsPerPoint
        activeAiScanner.timeoutSeconds = settings.activeAiTimeoutSeconds
        activeAiScanner.requestDelayMs = settings.activeAiRequestDelayMs.toLong()
        activeAiScanner.maxRiskLevel = settings.activeAiMaxRiskLevel
        activeAiScanner.scopeOnly = settings.activeAiScopeOnly
        activeAiScanner.scanMode = settings.activeAiScanMode
        activeAiScanner.useCollaborator = settings.activeAiUseCollaborator
        activeAiScanner.setEnabled(settings.activeAiEnabled)

        val ui = MainTab(api, backendRegistry, supervisor, auditLogger, mcpSupervisor, passiveAiScanner, activeAiScanner, aiRequestLogger)
        mainTab = ui
        api.userInterface().registerSuiteTab("AI Agent", ui.root) //  [oai_citation:4‡PortSwigger](https://portswigger.net/burp/documentation/desktop/extend-burp/extensions/creating/first-extension?utm_source=chatgpt.com)

        // Context menu: requests/responses (all editions)
        api.userInterface().registerContextMenuItemsProvider(object : ContextMenuItemsProvider {
            override fun provideMenuItems(event: ContextMenuEvent) =
                UiActions.requestResponseMenuItems(
                    api,
                    event,
                    ui,
                    mcpSupervisor,
                    passiveAiScanner,
                    activeAiScanner,
                    auditLogger
                )

            // Scanner findings (Pro): use the dedicated event type
            override fun provideMenuItems(event: AuditIssueContextMenuEvent) =
                UiActions.auditIssueMenuItems(api, event, ui, mcpSupervisor)
        })
        
        // Register AI ScanCheck with Burp Scanner (Burp Pro only - Option A)
        // This integrates with Burp's native active scanner
        try {
            val aiScanCheck = AiScanCheck(api) { settingsRepo.load() }
            api.scanner().registerScanCheck(aiScanCheck)
            api.logging().logToOutput("AI ScanCheck registered with Burp Scanner (Pro feature)")
        } catch (e: Exception) {
            // Expected to fail on Community edition
            api.logging().logToOutput("AI ScanCheck not registered (Burp Pro required): ${e.message}")
        }

        api.logging().logToOutput("AI Agent extension loaded. Backends discovered: ${backendRegistry.listBackendIds(settingsRepo.load()).joinToString(", ")}")
    }

    fun shutdown() {
        safeShutdownStep("MainTab") { mainTab?.shutdown() }
        mainTab = null
        safeShutdownStep("AI Request Logger") { aiRequestLogger.shutdown() }
        safeShutdownStep("Passive scanner") {
            passiveAiScanner.setEnabled(false)
            passiveAiScanner.shutdown()
        }
        safeShutdownStep("Active scanner") {
            activeAiScanner.setEnabled(false)
            activeAiScanner.shutdown()
        }
        safeShutdownStep("Supervisor") { supervisor.shutdown() }
        safeShutdownStep("MCP supervisor") { mcpSupervisor.shutdown() }
        safeShutdownStep("Backend registry") { backendRegistry.shutdown() }
        BackendDiagnostics.retry = null
        safeShutdownStep("Worker pool") {
            workerPool.shutdown()
            try {
                if (!workerPool.awaitTermination(5, TimeUnit.SECONDS)) {
                    workerPool.shutdownNow()
                }
            } catch (e: InterruptedException) {
                workerPool.shutdownNow()
                throw e
            }
        }
        safeShutdownStep("Alerting client") { Alerting.shutdownClient() }
        safeShutdownStep("Redaction mappings") { Redaction.clearMappings() }
        AuditLogger.registerGlobalEmitter(null)
    }

    private fun configureRollingLoggerFromProperties() {
        val enabled = System.getProperty("burp.ai.logger.rolling.enabled")?.toBooleanStrictOrNull() ?: false
        if (!enabled) {
            aiRequestLogger.configureRollingPersistence(null)
            return
        }

        val directory = System.getProperty("burp.ai.logger.rolling.dir")
            ?.takeIf { it.isNotBlank() }
            ?: Paths.get(System.getProperty("user.home"), ".burp-ai-agent", "logs").toString()
        val maxBytes = System.getProperty("burp.ai.logger.rolling.maxBytes")?.toLongOrNull()
            ?: AiRequestLogger.DEFAULT_ROLLING_MAX_FILE_BYTES
        val maxFiles = System.getProperty("burp.ai.logger.rolling.maxFiles")?.toIntOrNull()
            ?: AiRequestLogger.DEFAULT_ROLLING_MAX_FILES

        aiRequestLogger.configureRollingPersistence(
            RollingLogConfig(
                directory = Paths.get(directory),
                maxFileBytes = maxBytes,
                maxFiles = maxFiles
            )
        )
        api.logging().logToOutput("AI logger rolling persistence enabled at $directory")
    }

    private fun safeShutdownStep(component: String, action: () -> Unit) {
        try {
            action()
        } catch (_: InterruptedException) {
            Thread.currentThread().interrupt()
            api.logging().logToError("$component shutdown interrupted")
        } catch (e: Exception) {
            api.logging().logToError("$component shutdown failed: ${e.message}")
        }
    }
}
