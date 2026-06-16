package com.six2dez.burp.aiagent.ui

import burp.api.montoya.MontoyaApi
import com.six2dez.burp.aiagent.agents.AgentProfileLoader
import com.six2dez.burp.aiagent.audit.AuditLogger
import com.six2dez.burp.aiagent.backends.BackendRegistry
import com.six2dez.burp.aiagent.backends.HealthCheckResult
import com.six2dez.burp.aiagent.config.AgentSettings
import com.six2dez.burp.aiagent.config.AgentSettingsRepository
import com.six2dez.burp.aiagent.mcp.McpSupervisor
import com.six2dez.burp.aiagent.mcp.McpToolCatalog
import com.six2dez.burp.aiagent.redact.PrivacyMode
import com.six2dez.burp.aiagent.supervisor.AgentSupervisor
import com.six2dez.burp.aiagent.ui.McpToolTabModel
import com.six2dez.burp.aiagent.ui.components.CustomPromptLibraryEditor
import com.six2dez.burp.aiagent.ui.components.ToggleSwitch
import com.six2dez.burp.aiagent.ui.design.DesignTokens
import com.six2dez.burp.aiagent.ui.design.applyAreaStyle
import com.six2dez.burp.aiagent.ui.panels.BackendConfigPanel
import com.six2dez.burp.aiagent.ui.panels.BackendConfigState
import com.six2dez.burp.aiagent.ui.panels.CustomPromptsConfigPanel
import com.six2dez.burp.aiagent.ui.panels.ExternalServersPanel
import com.six2dez.burp.aiagent.ui.panels.HelpConfigPanel
import com.six2dez.burp.aiagent.ui.panels.PrivacyConfigPanel
import com.six2dez.burp.aiagent.ui.panels.PromptConfigPanel
import javax.swing.DefaultComboBoxModel
import javax.swing.JButton
import javax.swing.JCheckBox
import javax.swing.JComboBox
import javax.swing.JComponent
import javax.swing.JLabel
import javax.swing.JOptionPane
import javax.swing.JPanel
import javax.swing.JPasswordField
import javax.swing.JSpinner
import javax.swing.JTextArea
import javax.swing.JTextField
import javax.swing.SpinnerNumberModel
import javax.swing.SwingUtilities
import javax.swing.Timer
import javax.swing.border.LineBorder

class SettingsPanel(
    internal val api: MontoyaApi,
    internal val backends: BackendRegistry,
    internal val supervisor: AgentSupervisor,
    internal val audit: AuditLogger,
    internal val mcpSupervisor: McpSupervisor,
    internal val passiveAiScanner: com.six2dez.burp.aiagent.scanner.PassiveAiScanner,
    internal val activeAiScanner: com.six2dez.burp.aiagent.scanner.ActiveAiScanner,
) {
    internal val settingsRepo = AgentSettingsRepository(api)
    internal var settings: AgentSettings = settingsRepo.load()
    internal val customPromptLibraryEditor =
        CustomPromptLibraryEditor().apply {
            load(settings.customPromptLibrary)
        }
    var onMcpEnabledChanged: ((Boolean) -> Unit)? = null
    var onPassiveAiEnabledChanged: ((Boolean) -> Unit)? = null
    var onActiveAiEnabledChanged: ((Boolean) -> Unit)? = null
    var onSettingsChanged: ((AgentSettings) -> Unit)? = null
    internal var dialogParent: JComponent? = null
    internal var saveFeedbackResetTimer: javax.swing.Timer? = null
    internal var statusRefreshTimer: javax.swing.Timer? = null
    internal lateinit var generalTab: JComponent
    internal lateinit var passiveScannerTab: JComponent
    internal lateinit var activeScannerTab: JComponent
    internal lateinit var mcpTab: JComponent
    internal lateinit var burpIntegrationTab: JComponent
    internal lateinit var promptsTab: JComponent
    internal lateinit var customPromptsTab: JComponent
    internal lateinit var privacyTab: JComponent
    internal lateinit var helpTab: JComponent

    internal val backendConfigPanel =
        BackendConfigPanel(
            BackendConfigState(
                codexCmd = settings.codexCmd,
                geminiCmd = settings.geminiCmd,
                opencodeCmd = settings.opencodeCmd,
                claudeCmd = settings.claudeCmd,
                ollamaCliCmd = settings.ollamaCliCmd,
                ollamaModel = settings.ollamaModel,
                ollamaUrl = settings.ollamaUrl,
                ollamaServeCmd = settings.ollamaServeCmd,
                ollamaAutoStart = settings.ollamaAutoStart,
                ollamaApiKey = settings.ollamaApiKey,
                ollamaHeaders = settings.ollamaHeaders,
                ollamaTimeoutSeconds = settings.ollamaTimeoutSeconds.toString(),
                lmStudioUrl = settings.lmStudioUrl,
                lmStudioModel = settings.lmStudioModel,
                lmStudioTimeoutSeconds = settings.lmStudioTimeoutSeconds.toString(),
                lmStudioServerCmd = settings.lmStudioServerCmd,
                lmStudioAutoStart = settings.lmStudioAutoStart,
                lmStudioApiKey = settings.lmStudioApiKey,
                lmStudioHeaders = settings.lmStudioHeaders,
                openAiCompatUrl = settings.openAiCompatibleUrl,
                openAiCompatModel = settings.openAiCompatibleModel,
                openAiCompatApiKey = settings.openAiCompatibleApiKey,
                openAiCompatHeaders = settings.openAiCompatibleHeaders,
                openAiCompatTimeoutSeconds = settings.openAiCompatibleTimeoutSeconds.toString(),
                nvidiaNimUrl = settings.nvidiaNimUrl,
                nvidiaNimModel = settings.nvidiaNimModel,
                nvidiaNimApiKey = settings.nvidiaNimApiKey,
                nvidiaNimHeaders = settings.nvidiaNimHeaders,
                nvidiaNimTimeoutSeconds = settings.nvidiaNimTimeoutSeconds.toString(),
                perplexityUrl = settings.perplexityUrl,
                perplexityModel = settings.perplexityModel,
                perplexityApiKey = settings.perplexityApiKey,
                perplexityHeaders = settings.perplexityHeaders,
                perplexityTimeoutSeconds = settings.perplexityTimeoutSeconds.toString(),
                anthropicModel = settings.anthropicModel,
                anthropicApiKey = settings.anthropicApiKey,
                copilotCmd = settings.copilotCmd,
            ),
        )
    internal val profilePicker =
        JComboBox<String>().apply {
            preferredSize = java.awt.Dimension(140, preferredSize.height)
            maximumSize = java.awt.Dimension(140, preferredSize.height)
        }
    internal val profileWarningLabel =
        JLabel().apply {
            isVisible = false
        }
    internal val refreshProfilesBtn = JButton("Refresh")
    internal val preferredBackend =
        JComboBox(backends.listAllBackendIds().toTypedArray()).apply {
            selectedItem = settings.preferredBackendId
            preferredSize = java.awt.Dimension(140, preferredSize.height)
            maximumSize = java.awt.Dimension(140, preferredSize.height)
        }

    internal val privacyMode =
        JComboBox(PrivacyMode.entries.toTypedArray()).apply {
            selectedItem = settings.privacyMode
            preferredSize = java.awt.Dimension(120, preferredSize.height)
            maximumSize = java.awt.Dimension(120, preferredSize.height)
        }
    internal val determinism = ToggleSwitch(settings.determinismMode)
    internal val autoRestart = ToggleSwitch(settings.autoRestart)
    internal val auditEnabled = ToggleSwitch(settings.auditEnabled)

    // 07-02 D-02: caps chat context to 1500/750 chars when ON (BUG-69-02 / issue #69).
    internal val chatSmallModelMode = ToggleSwitch(settings.smallModelMode)
    internal val rotateSaltBtn = JButton("Rotate anonymization salt")
    internal val promptRequest = JTextArea(settings.requestPromptTemplate, 3, 20)
    internal val promptSummary = JTextArea(settings.requestSummaryPrompt, 2, 20)
    internal val promptJs = JTextArea(settings.explainJsPrompt, 2, 20)
    internal val promptAccessControl = JTextArea(settings.accessControlPrompt, 2, 20)
    internal val promptLoginSequence = JTextArea(settings.loginSequencePrompt, 2, 20)
    internal val promptIssueAnalyze = JTextArea(settings.issueAnalyzePrompt, 3, 20)
    internal val promptIssuePoc = JTextArea(settings.issuePocPrompt, 3, 20)
    internal val promptIssueImpact = JTextArea(settings.issueImpactPrompt, 3, 20)
    internal val promptIssueFull = JTextArea(settings.issuePromptTemplate, 3, 20)
    internal val bountyPromptEnabled = ToggleSwitch(settings.bountyPromptEnabled)
    internal val bountyPromptDir =
        JTextField(settings.bountyPromptDir, 24).apply {
            preferredSize = java.awt.Dimension(320, preferredSize.height)
        }
    internal val bountyPromptAutoCreateIssues = ToggleSwitch(settings.bountyPromptAutoCreateIssues)
    internal val bountyPromptIssueThreshold =
        JSpinner(
            SpinnerNumberModel(settings.bountyPromptIssueConfidenceThreshold, 0, 100, 1),
        ).apply {
            preferredSize = java.awt.Dimension(80, preferredSize.height)
            maximumSize = java.awt.Dimension(80, preferredSize.height)
        }
    internal val bountyPromptEnabledIds =
        JTextArea(
            settings.bountyPromptEnabledPromptIds.joinToString(","),
            2,
            20,
        )
    internal val aiLoggerEnabled = ToggleSwitch(settings.aiRequestLoggerEnabled)
    internal val aiLoggerMaxEntries =
        JSpinner(
            SpinnerNumberModel(settings.aiRequestLoggerMaxEntries, 10, 5000, 50),
        ).apply {
            preferredSize = java.awt.Dimension(80, preferredSize.height)
            maximumSize = java.awt.Dimension(80, preferredSize.height)
        }
    internal val privacyNotice =
        com.six2dez.burp.aiagent.ui.components
            .SubtleNotice()
    internal val saveFeedbackLabel = JLabel("No recent save activity.")

    // PRIV-02: custom-pattern text area (one regex per line) + inline validation-feedback label.
    // Both are injected into PrivacyConfigPanel; validation runs on Save via SafeRegex.isPatternSafe.
    internal val customPatternsArea =
        JTextArea(settings.customRedactionPatterns.joinToString("\n"), 4, 20).also {
            com.six2dez.burp.aiagent.ui.design
                .applyAreaStyle(it)
        }
    internal val patternsFeedbackLabel =
        JLabel("").also {
            it.font = DesignTokens.Typography.caption
            it.isVisible = false
        }

    // Phase 16-05: External MCP server CRUD panel. Receives plaintext bearerToken values from
    // AgentSettings.loadExternalMcpServers(); returns plaintext on getServers() for persistence.
    internal val externalServersPanel =
        ExternalServersPanel(
            initialServers = settings.mcpSettings.externalMcpServers,
            stdioEnabled = settings.mcpSettings.stdioEnabled,
        )
    internal val mcpEnabled = ToggleSwitch(settings.mcpSettings.enabled)
    internal val mcpHost =
        JTextField(settings.mcpSettings.host, 15).apply {
            preferredSize = java.awt.Dimension(140, preferredSize.height)
            maximumSize = java.awt.Dimension(140, preferredSize.height)
        }
    internal val mcpPort =
        JSpinner(SpinnerNumberModel(settings.mcpSettings.port, 1, 65535, 1)).apply {
            preferredSize = java.awt.Dimension(80, preferredSize.height)
            maximumSize = java.awt.Dimension(80, preferredSize.height)
        }
    internal val mcpExternal = JCheckBox("Allow external access (requires TLS)", settings.mcpSettings.externalEnabled)
    internal val mcpStdio = JCheckBox("Enable stdio bridge", settings.mcpSettings.stdioEnabled)
    internal val mcpTlsEnabled = JCheckBox("Enable TLS", settings.mcpSettings.tlsEnabled)
    internal val mcpTlsAuto = JCheckBox("Auto-generate TLS certificate", settings.mcpSettings.tlsAutoGenerate)
    internal val mcpKeystorePath = JTextField(settings.mcpSettings.tlsKeystorePath)
    internal val mcpKeystorePassword =
        JPasswordField(settings.mcpSettings.tlsKeystorePassword).apply {
            preferredSize = java.awt.Dimension(200, preferredSize.height)
        }
    internal val mcpToken = JTextField(settings.mcpSettings.token)
    internal val mcpAllowedOrigins =
        JTextArea(
            settings.mcpSettings.allowedOrigins.joinToString("\n"),
            3,
            20,
        )
    internal val mcpNotice =
        com.six2dez.burp.aiagent.ui.components
            .SubtleNotice()
    internal val mcpTokenRegenerate = JButton("Regenerate token")
    internal val mcpMaxConcurrent =
        JSpinner(
            SpinnerNumberModel(settings.mcpSettings.maxConcurrentRequests, 1, 64, 1),
        ).apply {
            preferredSize = java.awt.Dimension(70, preferredSize.height)
            maximumSize = java.awt.Dimension(70, preferredSize.height)
        }

    // 07-02 D-02: spinner is denominated in KB so users with 1278-token-class local models
    // can configure tight MCP body caps below the previous 1 MB minimum. Range 32 KB – 100 MB,
    // step 32 KB. Legacy stored values below 32 KB are clamped up by AgentSettings.loadMcpSettings.
    internal val mcpMaxBodyKb =
        JSpinner(
            SpinnerNumberModel(
                (settings.mcpSettings.maxBodyBytes / 1024).coerceAtLeast(32),
                32,
                102_400,
                32,
            ),
        ).apply {
            preferredSize = java.awt.Dimension(90, preferredSize.height)
            maximumSize = java.awt.Dimension(90, preferredSize.height)
        }
    internal val mcpProxyHistoryMaxItems =
        JSpinner(
            SpinnerNumberModel(settings.mcpSettings.proxyHistoryMaxItemsPerRequest, 1, 500, 1),
        ).apply {
            preferredSize = java.awt.Dimension(70, preferredSize.height)
            maximumSize = java.awt.Dimension(70, preferredSize.height)
        }
    internal val mcpProxyHistorySortOrder =
        JComboBox(arrayOf("Newest first", "Oldest first")).apply {
            selectedItem = if (settings.mcpSettings.proxyHistoryNewestFirst) "Newest first" else "Oldest first"
            preferredSize = java.awt.Dimension(120, preferredSize.height)
            maximumSize = java.awt.Dimension(120, preferredSize.height)
        }
    internal val mcpAllowUnpreprocessedProxyHistory =
        JCheckBox(
            "Allow AI to request unpreprocessed proxy responses",
            settings.mcpSettings.allowUnpreprocessedProxyHistory,
        )
    internal val mcpUnsafe = JCheckBox("Unsafe mode (allow write/mutation tools)", settings.mcpSettings.unsafeEnabled)

    // 07-03 D-03: global "Restrict MCP tools to in-scope hosts" toggle. Mirrors the JCheckBox
    // pattern used by mcpExternal / mcpUnsafe / passiveAiScopeOnly / activeAiScopeOnly so it stays
    // consistent with the rest of the MCP section. Closes GitHub issue #69 sub-concern 4.
    internal val mcpScopeOnly =
        JCheckBox(
            "Restrict MCP tools to in-scope hosts",
            settings.mcpSettings.scopeOnly,
        )
    internal val preprocessProxyHistory = ToggleSwitch(settings.preprocessProxyHistory)
    internal val preprocessMaxResponseSizeKb =
        JSpinner(
            SpinnerNumberModel(settings.preprocessMaxResponseSizeKb, 1, 10_240, 1),
        ).apply {
            preferredSize = java.awt.Dimension(80, preferredSize.height)
            maximumSize = java.awt.Dimension(80, preferredSize.height)
        }
    internal val preprocessFilterBinaryContent =
        JCheckBox(
            "Filter binary content (images, video, audio)",
            settings.preprocessFilterBinaryContent,
        )
    internal val preprocessAllowedContentTypes =
        JTextArea(
            settings.preprocessAllowedContentTypes.joinToString(","),
            3,
            20,
        )
    internal val mcpToolCheckboxes = mutableMapOf<String, JCheckBox>()
    internal val mcpUnsafeApprovalCheckboxes = mutableMapOf<String, JCheckBox>()

    // Passive AI Scanner UI components
    internal val passiveAiEnabled = ToggleSwitch(settings.passiveAiEnabled)
    internal val passiveAiScopeOnly = JCheckBox("In-scope only", settings.passiveAiScopeOnly)
    internal val passiveAiRateSpinner =
        JSpinner(SpinnerNumberModel(settings.passiveAiRateSeconds, 1, 60, 1)).apply {
            preferredSize = java.awt.Dimension(70, preferredSize.height)
            maximumSize = java.awt.Dimension(70, preferredSize.height)
        }
    internal val passiveAiMaxSizeSpinner =
        JSpinner(SpinnerNumberModel(settings.passiveAiMaxSizeKb, 16, 1024, 1)).apply {
            preferredSize = java.awt.Dimension(80, preferredSize.height)
            maximumSize = java.awt.Dimension(80, preferredSize.height)
        }
    internal val passiveAiExcludedExtensionsField =
        JTextField(settings.passiveAiExcludedExtensions, 30).apply {
            toolTipText = "Comma-separated file extensions to skip (e.g. css,js,png,woff). Leave empty to disable."
        }
    internal val passiveAiBatchSizeSpinner =
        JSpinner(
            SpinnerNumberModel(settings.passiveAiBatchSize, 1, 5, 1),
        ).apply {
            preferredSize = java.awt.Dimension(60, preferredSize.height)
            maximumSize = java.awt.Dimension(60, preferredSize.height)
        }
    internal val passiveAiPersistentCacheEnabled = JCheckBox("Enable persistent cache", settings.passiveAiPersistentCacheEnabled)
    internal val passiveAiPersistentCacheTtlSpinner =
        JSpinner(
            SpinnerNumberModel(settings.passiveAiPersistentCacheTtlHours, 1, 168, 1),
        ).apply {
            preferredSize = java.awt.Dimension(80, preferredSize.height)
            maximumSize = java.awt.Dimension(80, preferredSize.height)
        }
    internal val passiveAiPersistentCacheMaxMbSpinner =
        JSpinner(
            SpinnerNumberModel(settings.passiveAiPersistentCacheMaxMb, 10, 500, 10),
        ).apply {
            preferredSize = java.awt.Dimension(80, preferredSize.height)
            maximumSize = java.awt.Dimension(80, preferredSize.height)
        }
    internal val passiveAiMinSeverityCombo =
        JComboBox(arrayOf("LOW", "MEDIUM", "HIGH", "CRITICAL")).apply {
            selectedItem = settings.passiveAiMinSeverity.name
            preferredSize = java.awt.Dimension(100, preferredSize.height)
            maximumSize = java.awt.Dimension(100, preferredSize.height)
        }
    internal val passiveAiEndpointDedupSpinner =
        JSpinner(
            SpinnerNumberModel(settings.passiveAiEndpointDedupMinutes, 1, 240, 1),
        ).apply {
            preferredSize = java.awt.Dimension(80, preferredSize.height)
            maximumSize = java.awt.Dimension(80, preferredSize.height)
        }
    internal val passiveAiFingerprintDedupSpinner =
        JSpinner(
            SpinnerNumberModel(settings.passiveAiResponseFingerprintDedupMinutes, 1, 240, 1),
        ).apply {
            preferredSize = java.awt.Dimension(80, preferredSize.height)
            maximumSize = java.awt.Dimension(80, preferredSize.height)
        }
    internal val passiveAiPromptCacheTtlSpinner =
        JSpinner(
            SpinnerNumberModel(settings.passiveAiPromptCacheTtlMinutes, 1, 240, 1),
        ).apply {
            preferredSize = java.awt.Dimension(80, preferredSize.height)
            maximumSize = java.awt.Dimension(80, preferredSize.height)
        }
    internal val passiveAiEndpointCacheEntriesSpinner =
        JSpinner(
            SpinnerNumberModel(settings.passiveAiEndpointCacheEntries, 100, 50_000, 100),
        ).apply {
            preferredSize = java.awt.Dimension(95, preferredSize.height)
            maximumSize = java.awt.Dimension(95, preferredSize.height)
        }
    internal val passiveAiFingerprintCacheEntriesSpinner =
        JSpinner(
            SpinnerNumberModel(settings.passiveAiResponseFingerprintCacheEntries, 100, 50_000, 100),
        ).apply {
            preferredSize = java.awt.Dimension(95, preferredSize.height)
            maximumSize = java.awt.Dimension(95, preferredSize.height)
        }
    internal val passiveAiPromptCacheEntriesSpinner =
        JSpinner(
            SpinnerNumberModel(settings.passiveAiPromptCacheEntries, 50, 5_000, 50),
        ).apply {
            preferredSize = java.awt.Dimension(95, preferredSize.height)
            maximumSize = java.awt.Dimension(95, preferredSize.height)
        }
    internal val passiveAiRequestBodyMaxCharsSpinner =
        JSpinner(
            SpinnerNumberModel(settings.passiveAiRequestBodyMaxChars, 256, 20_000, 256),
        ).apply {
            preferredSize = java.awt.Dimension(95, preferredSize.height)
            maximumSize = java.awt.Dimension(95, preferredSize.height)
        }
    internal val passiveAiResponseBodyMaxCharsSpinner =
        JSpinner(
            SpinnerNumberModel(settings.passiveAiResponseBodyMaxChars, 512, 40_000, 256),
        ).apply {
            preferredSize = java.awt.Dimension(95, preferredSize.height)
            maximumSize = java.awt.Dimension(95, preferredSize.height)
        }
    internal val passiveAiHeaderMaxCountSpinner =
        JSpinner(
            SpinnerNumberModel(settings.passiveAiHeaderMaxCount, 5, 120, 1),
        ).apply {
            preferredSize = java.awt.Dimension(80, preferredSize.height)
            maximumSize = java.awt.Dimension(80, preferredSize.height)
        }
    internal val passiveAiParamMaxCountSpinner =
        JSpinner(
            SpinnerNumberModel(settings.passiveAiParamMaxCount, 5, 100, 1),
        ).apply {
            preferredSize = java.awt.Dimension(80, preferredSize.height)
            maximumSize = java.awt.Dimension(80, preferredSize.height)
        }
    internal val contextRequestBodyMaxCharsSpinner =
        JSpinner(
            SpinnerNumberModel(settings.contextRequestBodyMaxChars, 256, 40_000, 256),
        ).apply {
            preferredSize = java.awt.Dimension(95, preferredSize.height)
            maximumSize = java.awt.Dimension(95, preferredSize.height)
        }
    internal val contextResponseBodyMaxCharsSpinner =
        JSpinner(
            SpinnerNumberModel(settings.contextResponseBodyMaxChars, 512, 80_000, 256),
        ).apply {
            preferredSize = java.awt.Dimension(95, preferredSize.height)
            maximumSize = java.awt.Dimension(95, preferredSize.height)
        }
    internal val contextCompactJson = JCheckBox("Compact context JSON (manual actions)", settings.contextCompactJson)
    internal val passiveAiStatusLabel = JLabel()
    internal val passiveAiViewFindings = JButton("View findings")
    internal val passiveAiResetStats = JButton("Reset stats")

    // Active AI Scanner UI components
    internal val activeAiEnabled = ToggleSwitch(settings.activeAiEnabled)
    internal val activeAiScopeOnly = JCheckBox("In-scope only", settings.activeAiScopeOnly)
    internal val activeAiAutoFromPassive = JCheckBox("Auto-queue passive findings", settings.activeAiAutoFromPassive)
    internal val activeAiMaxConcurrentSpinner =
        JSpinner(SpinnerNumberModel(settings.activeAiMaxConcurrent, 1, 10, 1)).apply {
            preferredSize = java.awt.Dimension(70, preferredSize.height)
            maximumSize = java.awt.Dimension(70, preferredSize.height)
        }
    internal val activeAiMaxPayloadsSpinner =
        JSpinner(SpinnerNumberModel(settings.activeAiMaxPayloadsPerPoint, 1, 50, 5)).apply {
            preferredSize = java.awt.Dimension(70, preferredSize.height)
            maximumSize = java.awt.Dimension(70, preferredSize.height)
        }
    internal val activeAiTimeoutSpinner =
        JSpinner(SpinnerNumberModel(settings.activeAiTimeoutSeconds, 5, 120, 5)).apply {
            preferredSize = java.awt.Dimension(70, preferredSize.height)
            maximumSize = java.awt.Dimension(70, preferredSize.height)
        }
    internal val activeAiDelaySpinner =
        JSpinner(SpinnerNumberModel(settings.activeAiRequestDelayMs, 0, 5000, 100)).apply {
            preferredSize = java.awt.Dimension(80, preferredSize.height)
            maximumSize = java.awt.Dimension(80, preferredSize.height)
        }
    internal val activeAiRiskLevelCombo =
        JComboBox(arrayOf("SAFE", "MODERATE", "DANGEROUS")).apply {
            selectedItem = settings.activeAiMaxRiskLevel.name
            preferredSize = java.awt.Dimension(110, preferredSize.height)
            maximumSize = java.awt.Dimension(110, preferredSize.height)
        }
    internal val activeAiScanModeCombo =
        JComboBox(arrayOf("BUG_BOUNTY", "PENTEST", "FULL")).apply {
            selectedItem = settings.activeAiScanMode.name
            preferredSize = java.awt.Dimension(120, preferredSize.height)
            maximumSize = java.awt.Dimension(120, preferredSize.height)
        }
    internal val activeAiUseCollaborator = JCheckBox("Use Collaborator for SSRF OAST", settings.activeAiUseCollaborator)
    internal val activeAiAdaptivePayloads = JCheckBox("AI adaptive payloads", settings.activeAiAdaptivePayloads)
    internal val activeAiRiskDescription = JLabel()
    internal val activeAiStatusLabel = JLabel()
    internal val activeAiViewFindings = JButton("View findings")
    internal val activeAiViewQueue = JButton("View queue")
    internal val activeAiClearQueue = JButton("Clear queue")
    internal val activeAiResetStats = JButton("Reset stats")

    internal val scannerTriageButton = JButton("Open triage")

    // CAP-04: token-budget threshold fields; displayed in PassiveScanConfigPanel Section F
    internal val tokenBudgetWarnField =
        JTextField(
            if (settings.tokenBudgetWarnThreshold > 0) settings.tokenBudgetWarnThreshold.toString() else "",
            10,
        )
    internal val tokenBudgetHardCapField =
        JTextField(
            if (settings.tokenBudgetHardCap > 0) settings.tokenBudgetHardCap.toString() else "",
            10,
        )

    init {
        initUiWiring()
    }

    internal fun refreshProfileOptions() {
        val available = AgentProfileLoader.listAvailableProfiles()
        val fallback = listOf("pentester", "bughunter", "auditor")
        val options = if (available.isEmpty()) fallback else available
        val model = DefaultComboBoxModel(options.toTypedArray())
        val current = (profilePicker.selectedItem as? String ?: settings.agentProfile).trim()
        if (current.isNotBlank() && options.none { it.equals(current, ignoreCase = true) }) {
            model.addElement(current)
        }
        profilePicker.model = model
        profilePicker.selectedItem = if (current.isNotBlank()) current else options.firstOrNull()
    }

    fun setDialogParent(component: JComponent) {
        dialogParent = component
    }

    fun generalTabComponent(): JComponent = generalTab

    fun passiveScannerTabComponent(): JComponent = passiveScannerTab

    fun activeScannerTabComponent(): JComponent = activeScannerTab

    fun mcpTabComponent(): JComponent = mcpTab

    fun burpIntegrationTabComponent(): JComponent = burpIntegrationTab

    fun promptsTabComponent(): JComponent = promptsTab

    fun customPromptsTabComponent(): JComponent = customPromptsTab

    fun privacyTabComponent(): JComponent = privacyTab

    fun helpTabComponent(): JComponent = helpTab

    fun updateUsageSummary(stats: ChatPanel.UsageStats) {
        // Usage is displayed in sidebar only
    }

    fun saveSettings() {
        updateSaveFeedback("Saving settings...", DesignTokens.Colors.statusWarning)
        try {
            applyAndSaveSettings(currentSettings())
            updateSaveFeedback("Saved and applied.", DesignTokens.Colors.statusSuccess, resetMs = 3000)
        } catch (e: Exception) {
            updateSaveFeedback("Save failed: ${e.message ?: "unknown error"}", DesignTokens.Colors.statusError, resetMs = 5000)
            api.logging().logToError("AI Agent settings save failed: ${e.message}")
            JOptionPane.showMessageDialog(
                dialogParentComponent(),
                "Failed to save settings: ${e.message ?: "unknown error"}",
                "Custom AI Agent",
                JOptionPane.ERROR_MESSAGE,
            )
        }
    }

    fun restoreDefaultsWithConfirmation() {
        val confirmed =
            JOptionPane.showConfirmDialog(
                dialogParent,
                "Restore default settings? This will overwrite current values.",
                "Restore defaults",
                JOptionPane.YES_NO_OPTION,
            )
        if (confirmed != JOptionPane.YES_OPTION) return
        val defaults = settingsRepo.defaultSettings()
        applySettingsToUi(defaults)
        applyAndSaveSettings(defaults)
        updateSaveFeedback("Defaults restored and applied.", DesignTokens.Colors.statusSuccess, resetMs = 3000)
    }

    fun setPreferredBackend(value: String) {
        preferredBackend.selectedItem = value
        backendConfigPanel.setBackend(preferredBackendId())
    }

    fun preferredBackendId(): String = preferredBackend.selectedItem as? String ?: "codex-cli"

    fun setMcpEnabled(enabled: Boolean) {
        mcpEnabled.isSelected = enabled
    }

    fun setPassiveAiEnabled(enabled: Boolean) {
        passiveAiEnabled.isSelected = enabled
        applyPassiveAiSettings()
    }

    fun setActiveAiEnabled(enabled: Boolean) {
        activeAiEnabled.isSelected = enabled
        applyActiveAiSettings()
        updatePrivacyWarnings()
    }

    fun shutdown() {
        statusRefreshTimer?.stop()
        statusRefreshTimer = null
        saveFeedbackResetTimer?.stop()
        saveFeedbackResetTimer = null
    }

    internal fun applyMcpToolToggles(toggles: Map<String, Boolean>) {
        val effective = McpToolCatalog.mergeWithDefaults(toggles)
        mcpToolCheckboxes.forEach { (id, checkbox) ->
            checkbox.isSelected = effective[id] ?: false
        }
    }

    internal fun dialogParentComponent(): JComponent? = dialogParent

    internal fun helpSection(): JPanel =
        HelpConfigPanel(
            dialogParentProvider = ::dialogParentComponent,
        ).build()

    internal fun privacySection(): JPanel =
        PrivacyConfigPanel(
            privacyMode = privacyMode,
            auditEnabled = auditEnabled,
            autoRestart = autoRestart,
            determinism = determinism,
            rotateSaltBtn = rotateSaltBtn,
            privacyNotice = privacyNotice,
            saveFeedback = saveFeedbackLabel,
            aiLoggerEnabled = aiLoggerEnabled,
            aiLoggerMaxEntries = aiLoggerMaxEntries,
            customPatternsArea = customPatternsArea,
            patternsFeedback = patternsFeedbackLabel,
        ).build()

    internal fun testBackendConnection(backendId: String) {
        val settingsSnapshot = currentSettings()
        Thread {
            val result = backends.healthCheck(backendId, settingsSnapshot)
            SwingUtilities.invokeLater {
                val title = "Backend health: $backendId"
                when (result) {
                    is HealthCheckResult.Healthy ->
                        JOptionPane.showMessageDialog(
                            dialogParentComponent(),
                            "Connection OK.",
                            title,
                            JOptionPane.INFORMATION_MESSAGE,
                        )
                    is HealthCheckResult.Degraded ->
                        JOptionPane.showMessageDialog(
                            dialogParentComponent(),
                            result.message,
                            title,
                            JOptionPane.WARNING_MESSAGE,
                        )
                    is HealthCheckResult.Unavailable ->
                        JOptionPane.showMessageDialog(
                            dialogParentComponent(),
                            result.message,
                            title,
                            JOptionPane.ERROR_MESSAGE,
                        )
                    HealthCheckResult.Unknown ->
                        JOptionPane.showMessageDialog(
                            dialogParentComponent(),
                            "No health signal available for this backend.",
                            title,
                            JOptionPane.INFORMATION_MESSAGE,
                        )
                }
            }
        }.start()
    }

    internal fun promptSection(): JPanel =
        PromptConfigPanel(
            promptRequest = promptRequest,
            promptSummary = promptSummary,
            promptJs = promptJs,
            promptAccessControl = promptAccessControl,
            promptLoginSequence = promptLoginSequence,
            promptIssueAnalyze = promptIssueAnalyze,
            promptIssuePoc = promptIssuePoc,
            promptIssueImpact = promptIssueImpact,
            promptIssueFull = promptIssueFull,
        ).build()

    internal fun customPromptsSection(): JPanel =
        CustomPromptsConfigPanel(
            customPromptLibrarySection = customPromptLibraryEditor.component(),
            bountyPromptEnabled = bountyPromptEnabled,
            bountyPromptDir = bountyPromptDir,
            bountyPromptAutoCreateIssues = bountyPromptAutoCreateIssues,
            bountyPromptIssueThreshold = bountyPromptIssueThreshold,
            bountyPromptEnabledIds = bountyPromptEnabledIds,
        ).build()

    internal fun updatePrivacyWarnings() {
        refreshPrivacyNotice()
    }

    internal fun updateRiskWarnings() {
        refreshPrivacyNotice()
        refreshMcpNotice()
    }

    /**
     * Compose a single advisory for the Privacy & Logging tab. Replaces the previous trio of
     * stacked red `JLabel` banners (`privacyWarning` + `privacyActiveWarning` + `privacyRiskWarning`)
     * with one [SubtleNotice] whose level + message reflect the active risk combination.
     */
    internal fun refreshPrivacyNotice() {
        val selectedPrivacy = privacyMode.selectedItem as? PrivacyMode ?: PrivacyMode.STRICT
        val auditOff = !auditEnabled.isSelected
        val activeOn = activeAiEnabled.isSelected

        val (level, htmlMessage) =
            when {
                selectedPrivacy == PrivacyMode.OFF && auditOff && activeOn ->
                    com.six2dez.burp.aiagent.ui.components.SubtleNotice.Level.RISK to
                        "<b>Privacy OFF + Audit logging OFF + Active Scanner ON.</b> " +
                        "Raw traffic may reach MCP and prompts, with no audit trail and live payloads going to targets."
                selectedPrivacy == PrivacyMode.OFF && auditOff ->
                    com.six2dez.burp.aiagent.ui.components.SubtleNotice.Level.RISK to
                        "<b>Privacy OFF + Audit logging OFF.</b> Raw traffic may reach MCP and prompts; " +
                        "without audit logs, traceability and data-protection guarantees are reduced."
                selectedPrivacy == PrivacyMode.OFF && activeOn ->
                    com.six2dez.burp.aiagent.ui.components.SubtleNotice.Level.RISK to
                        "<b>Privacy OFF + Active Scanner ON.</b> Raw traffic may reach MCP and prompts " +
                        "while the active scanner sends payloads to real targets."
                selectedPrivacy == PrivacyMode.OFF ->
                    com.six2dez.burp.aiagent.ui.components.SubtleNotice.Level.WARN to
                        "<b>Privacy mode is OFF.</b> Raw traffic may reach MCP and prompts."
                selectedPrivacy == PrivacyMode.STRICT && activeOn ->
                    com.six2dez.burp.aiagent.ui.components.SubtleNotice.Level.INFO to
                        "STRICT anonymizes hosts in AI prompts but does not prevent the active scanner " +
                        "from sending real requests to targets."
                else -> null to null
            }
        if (level != null && htmlMessage != null) {
            privacyNotice.setMessage(level, htmlMessage)
        } else {
            privacyNotice.hideNotice()
        }
    }

    internal fun updateSaveFeedback(
        message: String,
        backgroundColor: java.awt.Color,
        resetMs: Int? = null,
    ) {
        saveFeedbackResetTimer?.stop()
        saveFeedbackResetTimer = null
        saveFeedbackLabel.text = message
        saveFeedbackLabel.background = backgroundColor
        saveFeedbackLabel.foreground = DesignTokens.Colors.onPrimary
        if (resetMs != null && resetMs > 0) {
            saveFeedbackResetTimer =
                javax.swing
                    .Timer(resetMs) {
                        saveFeedbackLabel.text = "No recent save activity."
                        saveFeedbackLabel.background = DesignTokens.Colors.borderSubtle
                    }.also { timer ->
                        timer.isRepeats = false
                        timer.start()
                    }
        }
    }

    internal fun updateProfileWarnings() {
        val profile = (profilePicker.selectedItem as? String)?.trim().orEmpty()
        if (profile.isBlank()) {
            profileWarningLabel.text = ""
            profileWarningLabel.isVisible = false
            return
        }
        val (available, reasons) = availableMcpToolsWithReasons()
        val warnings = AgentProfileLoader.validateProfile(profile, available, reasons)
        if (warnings.isEmpty()) {
            profileWarningLabel.text = "No profile tool conflicts detected."
            profileWarningLabel.foreground = DesignTokens.Colors.statusSuccess
            profileWarningLabel.isVisible = true
            return
        }
        profileWarningLabel.text = warnings.first()
        profileWarningLabel.foreground = DesignTokens.Colors.statusError
        profileWarningLabel.isVisible = true
    }

    internal fun updateFieldStyle(field: JTextField) {
        field.background = DesignTokens.Colors.inputBackground
        field.foreground = if (field.isEnabled) DesignTokens.Colors.inputForeground else DesignTokens.Colors.onSurfaceVariant
    }

    internal fun styleCombo(combo: JComboBox<*>) {
        combo.font = DesignTokens.Typography.body
        combo.background = DesignTokens.Colors.inputBackground
        combo.foreground = DesignTokens.Colors.inputForeground
        combo.border = LineBorder(DesignTokens.Colors.border, 1, true)
    }

    internal fun openExternalCli(
        backendId: String,
        command: String,
    ) {
        if (command.isBlank()) {
            JOptionPane.showMessageDialog(
                dialogParentComponent(),
                "Command is empty for $backendId.",
                "Custom AI Agent",
                JOptionPane.WARNING_MESSAGE,
            )
            return
        }
        try {
            val os = System.getProperty("os.name").lowercase()
            val process =
                when {
                    os.contains("win") -> {
                        ProcessBuilder("cmd.exe", "/c", "start", "\"AI Agent CLI\"", "cmd.exe", "/k", command)
                    }
                    os.contains("mac") -> {
                        val escaped = command.replace("\\", "\\\\").replace("\"", "\\\"")
                        ProcessBuilder("osascript", "-e", "tell application \"Terminal\" to do script \"$escaped\"")
                    }
                    else -> {
                        val shellCmd =
                            "x-terminal-emulator -e bash -lc ${shellQuote("$command; exec bash")} " +
                                "|| gnome-terminal -- bash -lc ${shellQuote("$command; exec bash")} " +
                                "|| konsole -e bash -lc ${shellQuote("$command; exec bash")} " +
                                "|| xterm -e bash -lc ${shellQuote("$command; exec bash")}"
                        ProcessBuilder("sh", "-c", shellCmd)
                    }
                }
            process.start()
        } catch (e: Exception) {
            api.logging().logToError("Failed to open CLI for $backendId: ${e.message}")
            JOptionPane.showMessageDialog(
                dialogParentComponent(),
                "Failed to open CLI: ${e.message}",
                "Custom AI Agent",
                JOptionPane.ERROR_MESSAGE,
            )
        }
    }

    internal fun shellQuote(value: String): String {
        if (value.isEmpty()) return "''"
        if (value.none { it.isWhitespace() || it == '"' || it == '\'' }) return value
        return "'" + value.replace("'", "'\"'\"'") + "'"
    }
}
