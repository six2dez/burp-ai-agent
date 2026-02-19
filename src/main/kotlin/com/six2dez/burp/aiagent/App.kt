package com.six2dez.burp.aiagent

import burp.api.montoya.MontoyaApi
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider
import burp.api.montoya.ui.contextmenu.ContextMenuEvent
import burp.api.montoya.ui.contextmenu.AuditIssueContextMenuEvent
import com.six2dez.burp.aiagent.audit.AuditLogger
import com.six2dez.burp.aiagent.backends.BackendDiagnostics
import com.six2dez.burp.aiagent.backends.BackendRegistry
import com.six2dez.burp.aiagent.agents.AgentProfileLoader
import com.six2dez.burp.aiagent.config.AgentSettingsRepository
import com.six2dez.burp.aiagent.context.ContextCollector
import com.six2dez.burp.aiagent.mcp.McpSupervisor
import com.six2dez.burp.aiagent.scanner.ActiveAiScanner
import com.six2dez.burp.aiagent.scanner.AiScanCheck
import com.six2dez.burp.aiagent.scanner.PassiveAiScanner
import com.six2dez.burp.aiagent.scanner.PayloadRisk
import com.six2dez.burp.aiagent.supervisor.AgentSupervisor
import com.six2dez.burp.aiagent.ui.MainTab
import com.six2dez.burp.aiagent.ui.UiActions
import com.six2dez.burp.aiagent.alerts.Alerting
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
        supervisor = AgentSupervisor(api, backendRegistry, auditLogger, workerPool)
        mcpSupervisor = McpSupervisor(api)
        contextCollector = ContextCollector(api)
        passiveAiScanner = PassiveAiScanner(api, supervisor, auditLogger) { settingsRepo.load() }
        activeAiScanner = ActiveAiScanner(api, supervisor, auditLogger) { settingsRepo.load() }
        
        AgentProfileLoader.ensureBundledProfilesInstalled()
        val settings = settingsRepo.load()
        AgentProfileLoader.setActiveProfile(settings.agentProfile)
        auditLogger.setEnabled(settings.auditEnabled)
        supervisor.applySettings(settings)
        mcpSupervisor.applySettings(settings.mcpSettings, settings.privacyMode, settings.determinismMode)
        
        // Initialize passive AI scanner
        passiveAiScanner.rateLimitSeconds = settings.passiveAiRateSeconds
        passiveAiScanner.scopeOnly = settings.passiveAiScopeOnly
        passiveAiScanner.maxSizeKb = settings.passiveAiMaxSizeKb
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

        val ui = MainTab(api, backendRegistry, supervisor, auditLogger, mcpSupervisor, passiveAiScanner, activeAiScanner)
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
            api.logging().logToOutput("AI ScanCheck not registered (Burp Pro required for Scanner API)")
        }

        api.logging().logToOutput("AI Agent extension loaded. Backends discovered: ${backendRegistry.listBackendIds(settingsRepo.load()).joinToString(", ")}")
    }

    fun shutdown() {
        try {
            mainTab?.shutdown()
        } catch (e: Exception) {
            api.logging().logToError("MainTab shutdown failed: ${e.message}")
        }
        mainTab = null
        try {
            passiveAiScanner.setEnabled(false)
            passiveAiScanner.shutdown()
        } catch (e: Exception) {
            api.logging().logToError("Passive scanner shutdown failed: ${e.message}")
        }
        try {
            activeAiScanner.setEnabled(false)
            activeAiScanner.shutdown()
        } catch (e: Exception) {
            api.logging().logToError("Active scanner shutdown failed: ${e.message}")
        }
        try {
            supervisor.shutdown()
        } catch (e: Exception) {
            api.logging().logToError("Supervisor shutdown failed: ${e.message}")
        }
        try {
            mcpSupervisor.shutdown()
        } catch (e: Exception) {
            api.logging().logToError("MCP supervisor shutdown failed: ${e.message}")
        }
        try {
            backendRegistry.shutdown()
        } catch (e: Exception) {
            api.logging().logToError("Backend registry shutdown failed: ${e.message}")
        }
        try {
            workerPool.shutdown()
            if (!workerPool.awaitTermination(5, TimeUnit.SECONDS)) {
                workerPool.shutdownNow()
            }
        } catch (_: InterruptedException) {
            workerPool.shutdownNow()
        } catch (e: Exception) {
            api.logging().logToError("Worker pool shutdown failed: ${e.message}")
        }
        try {
            Alerting.shutdownClient()
        } catch (e: Exception) {
            api.logging().logToError("Alerting client shutdown failed: ${e.message}")
        }
    }
}
