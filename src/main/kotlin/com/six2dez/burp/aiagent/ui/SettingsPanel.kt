package com.six2dez.burp.aiagent.ui

import burp.api.montoya.MontoyaApi
import burp.api.montoya.core.BurpSuiteEdition
import com.six2dez.burp.aiagent.agents.AgentProfileLoader
import com.six2dez.burp.aiagent.audit.AuditLogger
import com.six2dez.burp.aiagent.backends.BackendRegistry
import com.six2dez.burp.aiagent.backends.HealthCheckResult
import com.six2dez.burp.aiagent.config.AgentSettings
import com.six2dez.burp.aiagent.config.AgentSettingsRepository
import com.six2dez.burp.aiagent.config.Defaults
import com.six2dez.burp.aiagent.config.McpSettings
import com.six2dez.burp.aiagent.config.SeverityLevel
import com.six2dez.burp.aiagent.config.toPreprocessorSettings
import com.six2dez.burp.aiagent.mcp.McpSupervisor
import com.six2dez.burp.aiagent.mcp.McpToolCatalog
import com.six2dez.burp.aiagent.prompts.bountyprompt.BountyPromptCatalog
import com.six2dez.burp.aiagent.redact.PrivacyMode
import com.six2dez.burp.aiagent.scanner.PayloadRisk
import com.six2dez.burp.aiagent.scanner.ScanMode
import com.six2dez.burp.aiagent.supervisor.AgentSupervisor
import com.six2dez.burp.aiagent.ui.McpToolTabModel
import com.six2dez.burp.aiagent.ui.components.AccordionPanel
import com.six2dez.burp.aiagent.ui.components.CustomPromptLibraryEditor
import com.six2dez.burp.aiagent.ui.components.ToggleSwitch
import com.six2dez.burp.aiagent.ui.design.BadgeStyle
import com.six2dez.burp.aiagent.ui.design.DesignTokens
import com.six2dez.burp.aiagent.ui.design.addRowFull
import com.six2dez.burp.aiagent.ui.design.addSpacerRow
import com.six2dez.burp.aiagent.ui.design.applyFieldStyle
import com.six2dez.burp.aiagent.ui.design.applyAreaStyle
import com.six2dez.burp.aiagent.ui.design.buildTabPanel
import com.six2dez.burp.aiagent.ui.design.formGrid
import com.six2dez.burp.aiagent.ui.design.helpLabel
import com.six2dez.burp.aiagent.ui.design.sectionPanel
import com.six2dez.burp.aiagent.ui.design.secondaryButton
import com.six2dez.burp.aiagent.ui.design.toolBadge
import com.six2dez.burp.aiagent.ui.panels.ActiveScanConfigPanel
import com.six2dez.burp.aiagent.ui.panels.ActiveScanQueuePanel
import com.six2dez.burp.aiagent.ui.panels.BackendConfigPanel
import com.six2dez.burp.aiagent.ui.panels.BackendConfigState
import com.six2dez.burp.aiagent.ui.panels.HelpConfigPanel
import com.six2dez.burp.aiagent.ui.panels.McpConfigPanel
import com.six2dez.burp.aiagent.ui.panels.PassiveScanConfigPanel
import com.six2dez.burp.aiagent.ui.panels.PrivacyConfigPanel
import com.six2dez.burp.aiagent.ui.panels.CustomPromptsConfigPanel
import com.six2dez.burp.aiagent.ui.panels.PromptConfigPanel
import java.awt.BorderLayout
import java.awt.Toolkit
import java.awt.datatransfer.StringSelection
import java.time.Instant
import java.time.ZoneId
import java.time.format.DateTimeFormatter
import javax.swing.*
import javax.swing.border.EmptyBorder
import javax.swing.border.LineBorder
import javax.swing.event.DocumentEvent
import javax.swing.event.DocumentListener

class SettingsPanel(
    private val api: MontoyaApi,
    private val backends: BackendRegistry,
    private val supervisor: AgentSupervisor,
    private val audit: AuditLogger,
    private val mcpSupervisor: McpSupervisor,
    private val passiveAiScanner: com.six2dez.burp.aiagent.scanner.PassiveAiScanner,
    private val activeAiScanner: com.six2dez.burp.aiagent.scanner.ActiveAiScanner,
) {
    private val settingsRepo = AgentSettingsRepository(api)
    private var settings: AgentSettings = settingsRepo.load()
    private val customPromptLibraryEditor =
        CustomPromptLibraryEditor().apply {
            load(settings.customPromptLibrary)
        }
    var onMcpEnabledChanged: ((Boolean) -> Unit)? = null
    var onPassiveAiEnabledChanged: ((Boolean) -> Unit)? = null
    var onActiveAiEnabledChanged: ((Boolean) -> Unit)? = null
    var onSettingsChanged: ((AgentSettings) -> Unit)? = null
    private var dialogParent: JComponent? = null
    private var saveFeedbackResetTimer: javax.swing.Timer? = null
    private var statusRefreshTimer: javax.swing.Timer? = null
    private lateinit var generalTab: JComponent
    private lateinit var passiveScannerTab: JComponent
    private lateinit var activeScannerTab: JComponent
    private lateinit var mcpTab: JComponent
    private lateinit var burpIntegrationTab: JComponent
    private lateinit var promptsTab: JComponent
    private lateinit var customPromptsTab: JComponent
    private lateinit var privacyTab: JComponent
    private lateinit var helpTab: JComponent

    private val backendConfigPanel =
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
                copilotCmd = settings.copilotCmd,
            ),
        )
    private val profilePicker =
        JComboBox<String>().apply {
            preferredSize = java.awt.Dimension(140, preferredSize.height)
            maximumSize = java.awt.Dimension(140, preferredSize.height)
        }
    private val profileWarningLabel =
        JLabel().apply {
            isVisible = false
        }
    private val refreshProfilesBtn = JButton("Refresh")
    private val preferredBackend =
        JComboBox(backends.listAllBackendIds().toTypedArray()).apply {
            selectedItem = settings.preferredBackendId
            preferredSize = java.awt.Dimension(140, preferredSize.height)
            maximumSize = java.awt.Dimension(140, preferredSize.height)
        }

    private val privacyMode =
        JComboBox(PrivacyMode.entries.toTypedArray()).apply {
            selectedItem = settings.privacyMode
            preferredSize = java.awt.Dimension(120, preferredSize.height)
            maximumSize = java.awt.Dimension(120, preferredSize.height)
        }
    private val determinism = ToggleSwitch(settings.determinismMode)
    private val autoRestart = ToggleSwitch(settings.autoRestart)
    private val auditEnabled = ToggleSwitch(settings.auditEnabled)

    // 07-02 D-02: caps chat context to 1500/750 chars when ON (BUG-69-02 / issue #69).
    private val chatSmallModelMode = ToggleSwitch(settings.smallModelMode)
    private val rotateSaltBtn = JButton("Rotate anonymization salt")
    private val promptRequest = JTextArea(settings.requestPromptTemplate, 3, 20)
    private val promptSummary = JTextArea(settings.requestSummaryPrompt, 2, 20)
    private val promptJs = JTextArea(settings.explainJsPrompt, 2, 20)
    private val promptAccessControl = JTextArea(settings.accessControlPrompt, 2, 20)
    private val promptLoginSequence = JTextArea(settings.loginSequencePrompt, 2, 20)
    private val promptIssueAnalyze = JTextArea(settings.issueAnalyzePrompt, 3, 20)
    private val promptIssuePoc = JTextArea(settings.issuePocPrompt, 3, 20)
    private val promptIssueImpact = JTextArea(settings.issueImpactPrompt, 3, 20)
    private val promptIssueFull = JTextArea(settings.issuePromptTemplate, 3, 20)
    private val bountyPromptEnabled = ToggleSwitch(settings.bountyPromptEnabled)
    private val bountyPromptDir =
        JTextField(settings.bountyPromptDir, 24).apply {
            preferredSize = java.awt.Dimension(320, preferredSize.height)
        }
    private val bountyPromptAutoCreateIssues = ToggleSwitch(settings.bountyPromptAutoCreateIssues)
    private val bountyPromptIssueThreshold =
        JSpinner(
            SpinnerNumberModel(settings.bountyPromptIssueConfidenceThreshold, 0, 100, 1),
        ).apply {
            preferredSize = java.awt.Dimension(80, preferredSize.height)
            maximumSize = java.awt.Dimension(80, preferredSize.height)
        }
    private val bountyPromptEnabledIds =
        JTextArea(
            settings.bountyPromptEnabledPromptIds.joinToString(","),
            2,
            20,
        )
    private val aiLoggerEnabled = ToggleSwitch(settings.aiRequestLoggerEnabled)
    private val aiLoggerMaxEntries =
        JSpinner(
            SpinnerNumberModel(settings.aiRequestLoggerMaxEntries, 10, 5000, 50),
        ).apply {
            preferredSize = java.awt.Dimension(80, preferredSize.height)
            maximumSize = java.awt.Dimension(80, preferredSize.height)
        }
    private val privacyNotice = com.six2dez.burp.aiagent.ui.components.SubtleNotice()
    private val saveFeedbackLabel = JLabel("No recent save activity.")
    private val mcpEnabled = ToggleSwitch(settings.mcpSettings.enabled)
    private val mcpHost =
        JTextField(settings.mcpSettings.host, 15).apply {
            preferredSize = java.awt.Dimension(140, preferredSize.height)
            maximumSize = java.awt.Dimension(140, preferredSize.height)
        }
    private val mcpPort =
        JSpinner(SpinnerNumberModel(settings.mcpSettings.port, 1, 65535, 1)).apply {
            preferredSize = java.awt.Dimension(80, preferredSize.height)
            maximumSize = java.awt.Dimension(80, preferredSize.height)
        }
    private val mcpExternal = JCheckBox("Allow external access (requires TLS)", settings.mcpSettings.externalEnabled)
    private val mcpStdio = JCheckBox("Enable stdio bridge", settings.mcpSettings.stdioEnabled)
    private val mcpTlsEnabled = JCheckBox("Enable TLS", settings.mcpSettings.tlsEnabled)
    private val mcpTlsAuto = JCheckBox("Auto-generate TLS certificate", settings.mcpSettings.tlsAutoGenerate)
    private val mcpKeystorePath = JTextField(settings.mcpSettings.tlsKeystorePath)
    private val mcpKeystorePassword =
        JPasswordField(settings.mcpSettings.tlsKeystorePassword).apply {
            preferredSize = java.awt.Dimension(200, preferredSize.height)
        }
    private val mcpToken = JTextField(settings.mcpSettings.token)
    private val mcpAllowedOrigins =
        JTextArea(
            settings.mcpSettings.allowedOrigins.joinToString("\n"),
            3,
            20,
        )
    private val mcpNotice = com.six2dez.burp.aiagent.ui.components.SubtleNotice()
    private val mcpTokenRegenerate = JButton("Regenerate token")
    private val mcpMaxConcurrent =
        JSpinner(
            SpinnerNumberModel(settings.mcpSettings.maxConcurrentRequests, 1, 64, 1),
        ).apply {
            preferredSize = java.awt.Dimension(70, preferredSize.height)
            maximumSize = java.awt.Dimension(70, preferredSize.height)
        }

    // 07-02 D-02: spinner is denominated in KB so users with 1278-token-class local models
    // can configure tight MCP body caps below the previous 1 MB minimum. Range 32 KB – 100 MB,
    // step 32 KB. Legacy stored values below 32 KB are clamped up by AgentSettings.loadMcpSettings.
    private val mcpMaxBodyKb =
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
    private val mcpProxyHistoryMaxItems =
        JSpinner(
            SpinnerNumberModel(settings.mcpSettings.proxyHistoryMaxItemsPerRequest, 1, 500, 1),
        ).apply {
            preferredSize = java.awt.Dimension(70, preferredSize.height)
            maximumSize = java.awt.Dimension(70, preferredSize.height)
        }
    private val mcpProxyHistorySortOrder =
        JComboBox(arrayOf("Newest first", "Oldest first")).apply {
            selectedItem = if (settings.mcpSettings.proxyHistoryNewestFirst) "Newest first" else "Oldest first"
            preferredSize = java.awt.Dimension(120, preferredSize.height)
            maximumSize = java.awt.Dimension(120, preferredSize.height)
        }
    private val mcpAllowUnpreprocessedProxyHistory =
        JCheckBox(
            "Allow AI to request unpreprocessed proxy responses",
            settings.mcpSettings.allowUnpreprocessedProxyHistory,
        )
    private val mcpUnsafe = JCheckBox("Unsafe mode (allow write/mutation tools)", settings.mcpSettings.unsafeEnabled)

    // 07-03 D-03: global "Restrict MCP tools to in-scope hosts" toggle. Mirrors the JCheckBox
    // pattern used by mcpExternal / mcpUnsafe / passiveAiScopeOnly / activeAiScopeOnly so it stays
    // consistent with the rest of the MCP section. Closes GitHub issue #69 sub-concern 4.
    private val mcpScopeOnly =
        JCheckBox(
            "Restrict MCP tools to in-scope hosts",
            settings.mcpSettings.scopeOnly,
        )
    private val preprocessProxyHistory = ToggleSwitch(settings.preprocessProxyHistory)
    private val preprocessMaxResponseSizeKb =
        JSpinner(
            SpinnerNumberModel(settings.preprocessMaxResponseSizeKb, 1, 10_240, 1),
        ).apply {
            preferredSize = java.awt.Dimension(80, preferredSize.height)
            maximumSize = java.awt.Dimension(80, preferredSize.height)
        }
    private val preprocessFilterBinaryContent =
        JCheckBox(
            "Filter binary content (images, video, audio)",
            settings.preprocessFilterBinaryContent,
        )
    private val preprocessAllowedContentTypes =
        JTextArea(
            settings.preprocessAllowedContentTypes.joinToString(","),
            3,
            20,
        )
    private val mcpToolCheckboxes = mutableMapOf<String, JCheckBox>()
    private val mcpUnsafeApprovalCheckboxes = mutableMapOf<String, JCheckBox>()

    // Passive AI Scanner UI components
    private val passiveAiEnabled = ToggleSwitch(settings.passiveAiEnabled)
    private val passiveAiScopeOnly = JCheckBox("In-scope only", settings.passiveAiScopeOnly)
    private val passiveAiRateSpinner =
        JSpinner(SpinnerNumberModel(settings.passiveAiRateSeconds, 1, 60, 1)).apply {
            preferredSize = java.awt.Dimension(70, preferredSize.height)
            maximumSize = java.awt.Dimension(70, preferredSize.height)
        }
    private val passiveAiMaxSizeSpinner =
        JSpinner(SpinnerNumberModel(settings.passiveAiMaxSizeKb, 16, 1024, 1)).apply {
            preferredSize = java.awt.Dimension(80, preferredSize.height)
            maximumSize = java.awt.Dimension(80, preferredSize.height)
        }
    private val passiveAiExcludedExtensionsField =
        JTextField(settings.passiveAiExcludedExtensions, 30).apply {
            toolTipText = "Comma-separated file extensions to skip (e.g. css,js,png,woff). Leave empty to disable."
        }
    private val passiveAiBatchSizeSpinner =
        JSpinner(
            SpinnerNumberModel(settings.passiveAiBatchSize, 1, 5, 1),
        ).apply {
            preferredSize = java.awt.Dimension(60, preferredSize.height)
            maximumSize = java.awt.Dimension(60, preferredSize.height)
        }
    private val passiveAiPersistentCacheEnabled = JCheckBox("Enable persistent cache", settings.passiveAiPersistentCacheEnabled)
    private val passiveAiPersistentCacheTtlSpinner =
        JSpinner(
            SpinnerNumberModel(settings.passiveAiPersistentCacheTtlHours, 1, 168, 1),
        ).apply {
            preferredSize = java.awt.Dimension(80, preferredSize.height)
            maximumSize = java.awt.Dimension(80, preferredSize.height)
        }
    private val passiveAiPersistentCacheMaxMbSpinner =
        JSpinner(
            SpinnerNumberModel(settings.passiveAiPersistentCacheMaxMb, 10, 500, 10),
        ).apply {
            preferredSize = java.awt.Dimension(80, preferredSize.height)
            maximumSize = java.awt.Dimension(80, preferredSize.height)
        }
    private val passiveAiMinSeverityCombo =
        JComboBox(arrayOf("LOW", "MEDIUM", "HIGH", "CRITICAL")).apply {
            selectedItem = settings.passiveAiMinSeverity.name
            preferredSize = java.awt.Dimension(100, preferredSize.height)
            maximumSize = java.awt.Dimension(100, preferredSize.height)
        }
    private val passiveAiEndpointDedupSpinner =
        JSpinner(
            SpinnerNumberModel(settings.passiveAiEndpointDedupMinutes, 1, 240, 1),
        ).apply {
            preferredSize = java.awt.Dimension(80, preferredSize.height)
            maximumSize = java.awt.Dimension(80, preferredSize.height)
        }
    private val passiveAiFingerprintDedupSpinner =
        JSpinner(
            SpinnerNumberModel(settings.passiveAiResponseFingerprintDedupMinutes, 1, 240, 1),
        ).apply {
            preferredSize = java.awt.Dimension(80, preferredSize.height)
            maximumSize = java.awt.Dimension(80, preferredSize.height)
        }
    private val passiveAiPromptCacheTtlSpinner =
        JSpinner(
            SpinnerNumberModel(settings.passiveAiPromptCacheTtlMinutes, 1, 240, 1),
        ).apply {
            preferredSize = java.awt.Dimension(80, preferredSize.height)
            maximumSize = java.awt.Dimension(80, preferredSize.height)
        }
    private val passiveAiEndpointCacheEntriesSpinner =
        JSpinner(
            SpinnerNumberModel(settings.passiveAiEndpointCacheEntries, 100, 50_000, 100),
        ).apply {
            preferredSize = java.awt.Dimension(95, preferredSize.height)
            maximumSize = java.awt.Dimension(95, preferredSize.height)
        }
    private val passiveAiFingerprintCacheEntriesSpinner =
        JSpinner(
            SpinnerNumberModel(settings.passiveAiResponseFingerprintCacheEntries, 100, 50_000, 100),
        ).apply {
            preferredSize = java.awt.Dimension(95, preferredSize.height)
            maximumSize = java.awt.Dimension(95, preferredSize.height)
        }
    private val passiveAiPromptCacheEntriesSpinner =
        JSpinner(
            SpinnerNumberModel(settings.passiveAiPromptCacheEntries, 50, 5_000, 50),
        ).apply {
            preferredSize = java.awt.Dimension(95, preferredSize.height)
            maximumSize = java.awt.Dimension(95, preferredSize.height)
        }
    private val passiveAiRequestBodyMaxCharsSpinner =
        JSpinner(
            SpinnerNumberModel(settings.passiveAiRequestBodyMaxChars, 256, 20_000, 256),
        ).apply {
            preferredSize = java.awt.Dimension(95, preferredSize.height)
            maximumSize = java.awt.Dimension(95, preferredSize.height)
        }
    private val passiveAiResponseBodyMaxCharsSpinner =
        JSpinner(
            SpinnerNumberModel(settings.passiveAiResponseBodyMaxChars, 512, 40_000, 256),
        ).apply {
            preferredSize = java.awt.Dimension(95, preferredSize.height)
            maximumSize = java.awt.Dimension(95, preferredSize.height)
        }
    private val passiveAiHeaderMaxCountSpinner =
        JSpinner(
            SpinnerNumberModel(settings.passiveAiHeaderMaxCount, 5, 120, 1),
        ).apply {
            preferredSize = java.awt.Dimension(80, preferredSize.height)
            maximumSize = java.awt.Dimension(80, preferredSize.height)
        }
    private val passiveAiParamMaxCountSpinner =
        JSpinner(
            SpinnerNumberModel(settings.passiveAiParamMaxCount, 5, 100, 1),
        ).apply {
            preferredSize = java.awt.Dimension(80, preferredSize.height)
            maximumSize = java.awt.Dimension(80, preferredSize.height)
        }
    private val contextRequestBodyMaxCharsSpinner =
        JSpinner(
            SpinnerNumberModel(settings.contextRequestBodyMaxChars, 256, 40_000, 256),
        ).apply {
            preferredSize = java.awt.Dimension(95, preferredSize.height)
            maximumSize = java.awt.Dimension(95, preferredSize.height)
        }
    private val contextResponseBodyMaxCharsSpinner =
        JSpinner(
            SpinnerNumberModel(settings.contextResponseBodyMaxChars, 512, 80_000, 256),
        ).apply {
            preferredSize = java.awt.Dimension(95, preferredSize.height)
            maximumSize = java.awt.Dimension(95, preferredSize.height)
        }
    private val contextCompactJson = JCheckBox("Compact context JSON (manual actions)", settings.contextCompactJson)
    private val passiveAiStatusLabel = JLabel()
    private val passiveAiViewFindings = JButton("View findings")
    private val passiveAiResetStats = JButton("Reset stats")

    // Active AI Scanner UI components
    private val activeAiEnabled = ToggleSwitch(settings.activeAiEnabled)
    private val activeAiScopeOnly = JCheckBox("In-scope only", settings.activeAiScopeOnly)
    private val activeAiAutoFromPassive = JCheckBox("Auto-queue passive findings", settings.activeAiAutoFromPassive)
    private val activeAiMaxConcurrentSpinner =
        JSpinner(SpinnerNumberModel(settings.activeAiMaxConcurrent, 1, 10, 1)).apply {
            preferredSize = java.awt.Dimension(70, preferredSize.height)
            maximumSize = java.awt.Dimension(70, preferredSize.height)
        }
    private val activeAiMaxPayloadsSpinner =
        JSpinner(SpinnerNumberModel(settings.activeAiMaxPayloadsPerPoint, 1, 50, 5)).apply {
            preferredSize = java.awt.Dimension(70, preferredSize.height)
            maximumSize = java.awt.Dimension(70, preferredSize.height)
        }
    private val activeAiTimeoutSpinner =
        JSpinner(SpinnerNumberModel(settings.activeAiTimeoutSeconds, 5, 120, 5)).apply {
            preferredSize = java.awt.Dimension(70, preferredSize.height)
            maximumSize = java.awt.Dimension(70, preferredSize.height)
        }
    private val activeAiDelaySpinner =
        JSpinner(SpinnerNumberModel(settings.activeAiRequestDelayMs, 0, 5000, 100)).apply {
            preferredSize = java.awt.Dimension(80, preferredSize.height)
            maximumSize = java.awt.Dimension(80, preferredSize.height)
        }
    private val activeAiRiskLevelCombo =
        JComboBox(arrayOf("SAFE", "MODERATE", "DANGEROUS")).apply {
            selectedItem = settings.activeAiMaxRiskLevel.name
            preferredSize = java.awt.Dimension(110, preferredSize.height)
            maximumSize = java.awt.Dimension(110, preferredSize.height)
        }
    private val activeAiScanModeCombo =
        JComboBox(arrayOf("BUG_BOUNTY", "PENTEST", "FULL")).apply {
            selectedItem = settings.activeAiScanMode.name
            preferredSize = java.awt.Dimension(120, preferredSize.height)
            maximumSize = java.awt.Dimension(120, preferredSize.height)
        }
    private val activeAiUseCollaborator = JCheckBox("Use Collaborator for SSRF OAST", settings.activeAiUseCollaborator)
    private val activeAiAdaptivePayloads = JCheckBox("AI adaptive payloads", settings.activeAiAdaptivePayloads)
    private val activeAiRiskDescription = JLabel()
    private val activeAiStatusLabel = JLabel()
    private val activeAiViewFindings = JButton("View findings")
    private val activeAiViewQueue = JButton("View queue")
    private val activeAiClearQueue = JButton("Clear queue")
    private val activeAiResetStats = JButton("Reset stats")

    private val scannerTriageButton = JButton("Open triage")

    init {
        refreshProfileOptions()

        applyFieldStyle(mcpHost)
        applyFieldStyle(mcpKeystorePath)
        applyFieldStyle(mcpToken)
        applyAreaStyle(mcpAllowedOrigins)
        applyAreaStyle(preprocessAllowedContentTypes)
        applyAreaStyle(promptRequest)
        applyAreaStyle(promptSummary)
        applyAreaStyle(promptJs)
        applyAreaStyle(promptAccessControl)
        applyAreaStyle(promptLoginSequence)
        applyAreaStyle(promptIssueAnalyze)
        applyAreaStyle(promptIssuePoc)
        applyAreaStyle(promptIssueImpact)
        applyAreaStyle(promptIssueFull)
        applyFieldStyle(bountyPromptDir)
        applyAreaStyle(bountyPromptEnabledIds)

        styleCombo(privacyMode)
        styleCombo(profilePicker)
        styleCombo(mcpProxyHistorySortOrder)
        preferredBackend.toolTipText = "Default backend used for new sessions and context actions."
        profilePicker.toolTipText = "Select the AGENTS profile used for system instructions."
        refreshProfilesBtn.toolTipText = "Reload AGENTS profiles from disk."
        profileWarningLabel.font = DesignTokens.Typography.body
        profileWarningLabel.foreground = DesignTokens.Colors.statusError
        privacyMode.toolTipText = "Controls how traffic is redacted before sending to a model."
        determinism.font = DesignTokens.Typography.body
        determinism.background = DesignTokens.Colors.surface
        determinism.foreground = DesignTokens.Colors.onSurface
        determinism.toolTipText = "Stable ordering for reproducible prompts. Advanced use only."
        autoRestart.font = DesignTokens.Typography.body
        autoRestart.background = DesignTokens.Colors.surface
        autoRestart.foreground = DesignTokens.Colors.onSurface
        autoRestart.toolTipText = "Automatically restart a crashed agent session."
        auditEnabled.font = DesignTokens.Typography.body
        auditEnabled.background = DesignTokens.Colors.surface
        auditEnabled.foreground = DesignTokens.Colors.onSurface
        auditEnabled.toolTipText = "Tamper-evident logs (JSONL + SHA-256 hashes). Logs saved to ~/.burp-ai-agent/audit.jsonl"
        chatSmallModelMode.font = DesignTokens.Typography.body
        chatSmallModelMode.background = DesignTokens.Colors.surface
        chatSmallModelMode.foreground = DesignTokens.Colors.onSurface
        chatSmallModelMode.toolTipText =
            "Caps chat context to 1500/750 chars per request/response for 1278-token-class local models (issue #69)."
        rotateSaltBtn.font = DesignTokens.Typography.label
        rotateSaltBtn.background = DesignTokens.Colors.surface
        rotateSaltBtn.foreground = DesignTokens.Colors.primary
        rotateSaltBtn.border = LineBorder(DesignTokens.Colors.border, 1, true)
        rotateSaltBtn.isFocusPainted = false
        rotateSaltBtn.toolTipText =
            "Rotates the salt used for host anonymization (e.g. host-xxxxxx.local). Current: ${settings.hostAnonymizationSalt.take(8)}..."
        mcpToken.isEditable = true
        mcpToken.font = DesignTokens.Typography.mono
        mcpToken.toolTipText = "Required for external access. Use as: Authorization: Bearer <token>"
        mcpAllowedOrigins.toolTipText =
            "Allowed web origins for external mode (one per line, example: https://app.example.com). Leave empty to allow any origin."
        mcpEnabled.toolTipText = "Enable the built-in MCP server."
        mcpHost.toolTipText = "Host/interface for MCP server binding."
        mcpPort.toolTipText = "Port for the MCP server."
        (mcpPort.editor as? JSpinner.NumberEditor)?.format?.isGroupingUsed = false
        mcpExternal.toolTipText = "Allow external access (requires TLS and token)."
        mcpStdio.toolTipText = "Enable stdio bridge for MCP."
        mcpTlsEnabled.toolTipText = "Enable TLS for MCP server."
        mcpTlsAuto.toolTipText = "Auto-generate a TLS certificate if missing."
        mcpKeystorePath.toolTipText = "Path to the TLS keystore (PKCS12)."
        mcpKeystorePassword.toolTipText = "Password for the TLS keystore."
        mcpMaxConcurrent.toolTipText = "Maximum number of concurrent MCP tool requests."
        mcpMaxBodyKb.toolTipText = "Max tool output size in KB. Range 32 KB – 102400 KB (100 MB)."
        mcpProxyHistoryMaxItems.toolTipText =
            "Maximum number of proxy HTTP history items AI can request in one call."
        mcpProxyHistorySortOrder.toolTipText =
            "Default order for proxy HTTP history listings."
        mcpAllowUnpreprocessedProxyHistory.toolTipText =
            "Allow or block AI access to unpreprocessed proxy history responses."
        mcpUnsafe.toolTipText = "Allow tools that modify Burp state or send active requests."
        mcpTokenRegenerate.font = DesignTokens.Typography.label
        mcpTokenRegenerate.isFocusPainted = false
        mcpKeystorePassword.font = DesignTokens.Typography.mono
        mcpKeystorePassword.border = LineBorder(DesignTokens.Colors.border, 1, true)
        mcpKeystorePassword.background = DesignTokens.Colors.inputBackground
        mcpKeystorePassword.foreground = DesignTokens.Colors.inputForeground

        promptRequest.toolTipText = "Find vulnerabilities in the selected request/response."
        promptSummary.toolTipText = "Endpoint summary for analysis."
        promptJs.toolTipText = "Explain JavaScript behavior and risk."
        promptAccessControl.toolTipText = "Access control test plan."
        promptLoginSequence.toolTipText = "Login sequence draft."
        promptIssueAnalyze.toolTipText = "Analyze the issue and explain evidence and risk."
        promptIssuePoc.toolTipText = "Generate PoC steps and validation guidance."
        promptIssueImpact.toolTipText = "Assess impact and severity."
        promptIssueFull.toolTipText = "Full vulnerability report for an issue."
        bountyPromptEnabled.toolTipText = "Enable curated BountyPrompt actions in the request/response context menu."
        bountyPromptDir.toolTipText = "Directory containing BountyPrompt JSON files."
        bountyPromptAutoCreateIssues.toolTipText = "Auto-create Burp issues when parsed confidence meets threshold."
        bountyPromptIssueThreshold.toolTipText = "Confidence threshold (0-100) required for auto-creating issues."
        bountyPromptEnabledIds.toolTipText =
            "Comma-separated prompt IDs to expose. Leave empty to use curated defaults."
        aiLoggerEnabled.toolTipText = "Enable the AI request logger to record all AI interactions for observability."
        aiLoggerMaxEntries.toolTipText = "Maximum number of log entries to keep in memory (10-5000)."
        mcpMaxConcurrent.font = DesignTokens.Typography.body
        mcpMaxBodyKb.font = DesignTokens.Typography.body
        mcpMaxBodyKb.toolTipText = "Maximum MCP response body size per item (KB)."
        mcpTlsEnabled.font = DesignTokens.Typography.body
        mcpTlsAuto.font = DesignTokens.Typography.body
        mcpExternal.font = DesignTokens.Typography.body
        mcpEnabled.font = DesignTokens.Typography.body
        mcpStdio.font = DesignTokens.Typography.body
        mcpUnsafe.font = DesignTokens.Typography.body
        mcpUnsafe.toolTipText = "Allows tools that modify Burp state, write files, or send active requests."
        // 07-03 D-03: mirror the styling of mcpUnsafe so the new toggle blends into the section.
        mcpScopeOnly.font = DesignTokens.Typography.body
        mcpScopeOnly.toolTipText =
            "When enabled, MCP tools that return Burp HTTP data only include in-scope items, " +
                "and send_request-style tools refuse out-of-scope URLs. Issue #69."
        preprocessProxyHistory.toolTipText =
            "Preprocess proxy history before MCP returns it, reducing context-window overflow from large or binary responses."
        preprocessMaxResponseSizeKb.toolTipText =
            "Maximum response body size in KB before truncating with [SNIP - ...]."
        preprocessFilterBinaryContent.toolTipText =
            "Replace unreadable binary response bodies with a content-type placeholder."
        preprocessAllowedContentTypes.toolTipText =
            "Comma-separated allowed readable content-type prefixes (e.g. text/,application/json)."
        // mcpNotice styles itself via UiTheme; refreshMcpNotice() decides level + visibility.
        // privacyNotice styles itself via UiTheme; just seed the message with the current settings.
        saveFeedbackLabel.font = DesignTokens.Typography.body
        saveFeedbackLabel.foreground = DesignTokens.Colors.onPrimary
        saveFeedbackLabel.background = DesignTokens.Colors.borderSubtle
        saveFeedbackLabel.border = EmptyBorder(DesignTokens.Spacing.xs, DesignTokens.Spacing.sm, DesignTokens.Spacing.xs, DesignTokens.Spacing.sm)
        saveFeedbackLabel.isOpaque = true

        val backendBody =
            JPanel(BorderLayout()).apply {
                background = DesignTokens.Colors.surface
            }
        val backendSection =
            sectionPanel(
                title = "AI Backend",
                subtitle = "Select the default backend and configure its connection.",
                content = backendBody,
            ).apply {
                backendBody.add(backendConfigPanel, BorderLayout.CENTER)
                val profileGrid = formGrid()
                val profileRow =
                    JPanel().apply {
                        layout = BoxLayout(this, BoxLayout.X_AXIS)
                        background = DesignTokens.Colors.surface
                        add(profilePicker)
                        add(Box.createRigidArea(java.awt.Dimension(6, 0)))
                        add(refreshProfilesBtn)
                    }
                addRowFull(profileGrid, "Agent profile", profileRow)
                addSpacerRow(profileGrid, DesignTokens.Spacing.xs)
                addRowFull(profileGrid, "Profile warnings", profileWarningLabel)
                addSpacerRow(profileGrid, DesignTokens.Spacing.xs)
                // 07-02 D-02: small-model-mode toggle (BUG-69-02 / issue #69).
                addRowFull(profileGrid, "Small model mode", chatSmallModelMode)
                backendBody.add(profileGrid, BorderLayout.NORTH)
            }
        val privacySection = privacySection()
        val burpIntegrationBody =
            JPanel(BorderLayout()).apply {
                background = DesignTokens.Colors.surface
            }
        burpIntegrationBody.add(buildMcpToolsPanel(), BorderLayout.CENTER)
        val burpIntegrationSection =
            sectionPanel(
                title = "Burp Integration",
                subtitle = "Controls how Burp MCP tools are exposed.",
                content = burpIntegrationBody,
            )
        generalTab = buildTabPanel(listOf(backendSection))
        passiveScannerTab = buildTabPanel(listOf(passiveAiScannerSection()))
        mcpTab = buildTabPanel(listOf(mcpSection()))
        promptsTab = buildTabPanel(listOf(promptSection()))
        customPromptsTab = buildTabPanel(listOf(customPromptsSection()))
        privacyTab = buildTabPanel(listOf(privacySection))
        activeScannerTab = buildTabPanel(listOf(activeAiScannerSection()))
        burpIntegrationTab = buildTabPanel(listOf(burpIntegrationSection))
        helpTab = buildTabPanel(listOf(helpSection()))

        preferredBackend.addActionListener {
            backendConfigPanel.setBackend(preferredBackendId())
        }
        profilePicker.addActionListener {
            updateProfileWarnings()
        }
        refreshProfilesBtn.addActionListener {
            refreshProfileOptions()
            updateProfileWarnings()
        }
        privacyMode.addActionListener {
            // updateRiskWarnings already routes through refreshPrivacyNotice; no need to call
            // updatePrivacyWarnings separately (would re-compose the same advisory twice).
            updateRiskWarnings()
        }
        mcpExternal.addActionListener {
            updateMcpTlsState()
            // updateRiskWarnings() routes through refreshMcpNotice() which already covers the
            // CORS-open advisory; calling updateMcpCorsWarning() here as well would refresh twice.
            updateRiskWarnings()
        }
        mcpTlsEnabled.addActionListener {
            updateMcpTlsState()
        }
        mcpTlsAuto.addActionListener {
            updateMcpTlsState()
        }
        mcpEnabled.addActionListener {
            onMcpEnabledChanged?.invoke(mcpEnabled.isSelected)
            updateRiskWarnings()
        }
        mcpUnsafe.addActionListener {
            updateUnsafeToolStates()
            updateRiskWarnings()
        }
        auditEnabled.addActionListener {
            updateRiskWarnings()
        }
        mcpTokenRegenerate.addActionListener {
            mcpToken.text = McpSettings.generateToken()
            updateRiskWarnings()
        }
        mcpAllowedOrigins.document.addDocumentListener(
            object : DocumentListener {
                // updateRiskWarnings() already routes through refreshMcpNotice() which covers the
                // CORS-open advisory; calling updateMcpCorsWarning() in addition would refresh twice.
                override fun insertUpdate(e: DocumentEvent?) {
                    updateRiskWarnings()
                }

                override fun removeUpdate(e: DocumentEvent?) {
                    updateRiskWarnings()
                }

                override fun changedUpdate(e: DocumentEvent?) {
                    updateRiskWarnings()
                }
            },
        )
        mcpToken.document.addDocumentListener(
            object : DocumentListener {
                override fun insertUpdate(e: DocumentEvent?) {
                    updateRiskWarnings()
                }

                override fun removeUpdate(e: DocumentEvent?) {
                    updateRiskWarnings()
                }

                override fun changedUpdate(e: DocumentEvent?) {
                    updateRiskWarnings()
                }
            },
        )
        rotateSaltBtn.addActionListener {
            val newSalt = McpSettings.generateToken()
            settings = settings.copy(hostAnonymizationSalt = newSalt)
            rotateSaltBtn.toolTipText =
                "Rotates the salt used for host anonymization (e.g. host-xxxxxx.local). Current: ${newSalt.take(8)}..."
            JOptionPane.showMessageDialog(
                dialogParentComponent(),
                "Salt rotated. New anonymized hosts will be different.",
                "Privacy",
                JOptionPane.INFORMATION_MESSAGE,
            )
        }
        backendConfigPanel.onOpenCli = { backendId, command ->
            openExternalCli(backendId, command)
        }
        backendConfigPanel.onTestConnection = { backendId ->
            testBackendConnection(backendId)
        }
        backendConfigPanel.setBackend(preferredBackendId())
        updateMcpTlsState()
        updateMcpCorsWarning()
        updatePrivacyWarnings()
        updateRiskWarnings()
        refreshPassiveAiStatus()
        updateActiveRiskDescription()
        refreshActiveAiStatus()

        // Passive AI Scanner event listeners
        passiveAiEnabled.addActionListener {
            applyPassiveAiSettings()
            onPassiveAiEnabledChanged?.invoke(passiveAiEnabled.isSelected)
        }
        passiveAiScopeOnly.addActionListener {
            applyPassiveAiSettings()
        }
        passiveAiRateSpinner.addChangeListener {
            applyPassiveAiSettings()
        }
        passiveAiMaxSizeSpinner.addChangeListener {
            applyPassiveAiSettings()
        }
        passiveAiEndpointDedupSpinner.addChangeListener {
            applyPassiveAiSettings()
        }
        passiveAiFingerprintDedupSpinner.addChangeListener {
            applyPassiveAiSettings()
        }
        passiveAiPromptCacheTtlSpinner.addChangeListener {
            applyPassiveAiSettings()
        }
        passiveAiEndpointCacheEntriesSpinner.addChangeListener {
            applyPassiveAiSettings()
        }
        passiveAiFingerprintCacheEntriesSpinner.addChangeListener {
            applyPassiveAiSettings()
        }
        passiveAiPromptCacheEntriesSpinner.addChangeListener {
            applyPassiveAiSettings()
        }
        passiveAiRequestBodyMaxCharsSpinner.addChangeListener {
            applyPassiveAiSettings()
        }
        passiveAiResponseBodyMaxCharsSpinner.addChangeListener {
            applyPassiveAiSettings()
        }
        passiveAiHeaderMaxCountSpinner.addChangeListener {
            applyPassiveAiSettings()
        }
        passiveAiParamMaxCountSpinner.addChangeListener {
            applyPassiveAiSettings()
        }
        passiveAiBatchSizeSpinner.addChangeListener {
            applyPassiveAiSettings()
        }
        passiveAiPersistentCacheEnabled.addActionListener {
            applyPassiveAiSettings()
        }
        passiveAiPersistentCacheTtlSpinner.addChangeListener {
            applyPassiveAiSettings()
        }
        passiveAiPersistentCacheMaxMbSpinner.addChangeListener {
            applyPassiveAiSettings()
        }
        passiveAiViewFindings.addActionListener {
            showPassiveAiFindingsDialog()
        }
        scannerTriageButton.addActionListener {
            showScannerTriageDialog()
        }
        passiveAiResetStats.addActionListener {
            passiveAiScanner.resetStats()
            refreshPassiveAiStatus()
        }

        // Active AI Scanner event listeners
        activeAiEnabled.addActionListener {
            applyActiveAiSettings()
            updatePrivacyWarnings()
            updateRiskWarnings()
            onActiveAiEnabledChanged?.invoke(activeAiEnabled.isSelected)
        }
        activeAiScopeOnly.addActionListener {
            applyActiveAiSettings()
        }
        activeAiAutoFromPassive.addActionListener {
            applyActiveAiSettings()
        }
        activeAiMaxConcurrentSpinner.addChangeListener {
            applyActiveAiSettings()
        }
        activeAiMaxPayloadsSpinner.addChangeListener {
            applyActiveAiSettings()
        }
        activeAiTimeoutSpinner.addChangeListener {
            applyActiveAiSettings()
        }
        activeAiDelaySpinner.addChangeListener {
            applyActiveAiSettings()
        }
        activeAiRiskLevelCombo.addActionListener {
            applyActiveAiSettings()
            val level = activeAiRiskLevelCombo.selectedItem as? String
            if (level == "DANGEROUS") {
                JOptionPane.showMessageDialog(
                    dialogParentComponent(),
                    "DANGEROUS mode may modify or delete data. Only use in authorized test environments.",
                    "Active Scanner Warning",
                    JOptionPane.WARNING_MESSAGE,
                )
            }
        }
        activeAiScanModeCombo.addActionListener {
            applyActiveAiSettings()
        }
        activeAiUseCollaborator.addActionListener {
            applyActiveAiSettings()
        }
        activeAiAdaptivePayloads.addActionListener {
            applyActiveAiSettings()
        }
        activeAiViewFindings.addActionListener {
            showActiveAiFindingsDialog()
        }
        activeAiViewQueue.addActionListener {
            showActiveScanQueueDialog()
        }
        activeAiClearQueue.addActionListener {
            activeAiScanner.clearQueue()
            refreshActiveAiStatus()
        }
        activeAiResetStats.addActionListener {
            activeAiScanner.resetStats()
            refreshActiveAiStatus()
        }

        // Timer to refresh scanner status periodically
        statusRefreshTimer =
            javax.swing.Timer(2000) {
                refreshPassiveAiStatus()
                refreshActiveAiStatus()
            }
        statusRefreshTimer?.start()
        updateProfileWarnings()
    }

    private fun refreshProfileOptions() {
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

    fun currentSettings(): AgentSettings {
        val mcpSettings =
            McpSettings(
                enabled = mcpEnabled.isSelected,
                host = mcpHost.text.trim().ifBlank { "127.0.0.1" },
                port = (mcpPort.value as? Int) ?: 9876,
                externalEnabled = mcpExternal.isSelected,
                stdioEnabled = mcpStdio.isSelected,
                token = mcpToken.text.trim(),
                allowedOrigins = parseAllowedOriginsInput(mcpAllowedOrigins.text),
                tlsEnabled = mcpTlsEnabled.isSelected,
                tlsAutoGenerate = mcpTlsAuto.isSelected,
                tlsKeystorePath = mcpKeystorePath.text.trim(),
                tlsKeystorePassword = String(mcpKeystorePassword.password),
                scanTaskTtlMinutes = settings.mcpSettings.scanTaskTtlMinutes,
                collaboratorClientTtlMinutes = settings.mcpSettings.collaboratorClientTtlMinutes,
                maxConcurrentRequests = (mcpMaxConcurrent.value as? Int) ?: 4,
                // 07-02 D-02: spinner is denominated in KB; convert to bytes for persistence.
                // Floor of 32 KB matches AgentSettings.loadMcpSettings coerceIn lower bound.
                maxBodyBytes = ((mcpMaxBodyKb.value as? Int) ?: 2048).coerceAtLeast(32) * 1024,
                proxyHistoryMaxItemsPerRequest =
                    (mcpProxyHistoryMaxItems.value as? Int)
                        ?.coerceIn(1, 500)
                        ?: Defaults.MCP_PROXY_HISTORY_MAX_ITEMS_PER_REQUEST,
                proxyHistoryNewestFirst =
                    (mcpProxyHistorySortOrder.selectedItem as? String) != "Oldest first",
                allowUnpreprocessedProxyHistory = mcpAllowUnpreprocessedProxyHistory.isSelected,
                toolToggles = collectMcpToolToggles(),
                enabledUnsafeTools = collectEnabledUnsafeTools(),
                unsafeEnabled = mcpUnsafe.isSelected,
                // 07-03 D-03: persist the global MCP scope toggle on the McpSettings sub-object.
                scopeOnly = mcpScopeOnly.isSelected,
            )
        val backendState = backendConfigPanel.currentBackendSettings()
        val ollamaTimeoutSeconds =
            parseTimeoutSeconds(
                backendState.ollamaTimeoutSeconds,
                settings.ollamaTimeoutSeconds,
            )
        val lmStudioTimeoutSeconds =
            parseTimeoutSeconds(
                backendState.lmStudioTimeoutSeconds,
                settings.lmStudioTimeoutSeconds,
            )
        val openAiCompatTimeoutSeconds =
            parseTimeoutSeconds(
                backendState.openAiCompatTimeoutSeconds,
                settings.openAiCompatibleTimeoutSeconds,
            )
        val nvidiaNimTimeoutSeconds =
            parseTimeoutSeconds(
                backendState.nvidiaNimTimeoutSeconds,
                settings.nvidiaNimTimeoutSeconds,
            )
        val perplexityTimeoutSeconds =
            parseTimeoutSeconds(
                backendState.perplexityTimeoutSeconds,
                settings.perplexityTimeoutSeconds,
            )
        return AgentSettings(
            codexCmd = backendState.codexCmd,
            geminiCmd = backendState.geminiCmd,
            opencodeCmd = backendState.opencodeCmd,
            claudeCmd = backendState.claudeCmd,
            agentProfile = profilePicker.selectedItem as? String ?: "pentester",
            ollamaCliCmd = backendState.ollamaCliCmd,
            ollamaModel = backendState.ollamaModel,
            ollamaUrl = backendState.ollamaUrl,
            ollamaServeCmd = backendState.ollamaServeCmd,
            ollamaAutoStart = backendState.ollamaAutoStart,
            ollamaApiKey = backendState.ollamaApiKey,
            ollamaHeaders = backendState.ollamaHeaders,
            ollamaTimeoutSeconds = ollamaTimeoutSeconds,
            ollamaContextWindow = settings.ollamaContextWindow,
            lmStudioUrl = backendState.lmStudioUrl,
            lmStudioModel = backendState.lmStudioModel,
            lmStudioTimeoutSeconds = lmStudioTimeoutSeconds,
            lmStudioServerCmd = backendState.lmStudioServerCmd,
            lmStudioAutoStart = backendState.lmStudioAutoStart,
            lmStudioApiKey = backendState.lmStudioApiKey,
            lmStudioHeaders = backendState.lmStudioHeaders,
            openAiCompatibleUrl = backendState.openAiCompatUrl,
            openAiCompatibleModel = backendState.openAiCompatModel,
            openAiCompatibleApiKey = backendState.openAiCompatApiKey,
            openAiCompatibleHeaders = backendState.openAiCompatHeaders,
            openAiCompatibleTimeoutSeconds = openAiCompatTimeoutSeconds,
            nvidiaNimUrl = backendState.nvidiaNimUrl,
            nvidiaNimModel = backendState.nvidiaNimModel,
            nvidiaNimApiKey = backendState.nvidiaNimApiKey,
            nvidiaNimHeaders = backendState.nvidiaNimHeaders,
            nvidiaNimTimeoutSeconds = nvidiaNimTimeoutSeconds,
            perplexityUrl = backendState.perplexityUrl,
            perplexityModel = backendState.perplexityModel,
            perplexityApiKey = backendState.perplexityApiKey,
            perplexityHeaders = backendState.perplexityHeaders,
            perplexityTimeoutSeconds = perplexityTimeoutSeconds,
            copilotCmd = backendState.copilotCmd,
            requestPromptTemplate = promptRequest.text.trim(),
            issuePromptTemplate = promptIssueFull.text.trim(),
            issueAnalyzePrompt = promptIssueAnalyze.text.trim(),
            issuePocPrompt = promptIssuePoc.text.trim(),
            issueImpactPrompt = promptIssueImpact.text.trim(),
            requestSummaryPrompt = promptSummary.text.trim(),
            explainJsPrompt = promptJs.text.trim(),
            accessControlPrompt = promptAccessControl.text.trim(),
            loginSequencePrompt = promptLoginSequence.text.trim(),
            hostAnonymizationSalt = settings.hostAnonymizationSalt,
            preferredBackendId = preferredBackendId(),
            privacyMode = privacyMode.selectedItem as? PrivacyMode ?: PrivacyMode.STRICT,
            determinismMode = determinism.isSelected,
            autoRestart = autoRestart.isSelected,
            auditEnabled = auditEnabled.isSelected,
            mcpSettings = mcpSettings,
            preprocessProxyHistory = preprocessProxyHistory.isSelected,
            preprocessMaxResponseSizeKb =
                (preprocessMaxResponseSizeKb.value as? Int)
                    ?: Defaults.PREPROCESS_MAX_RESPONSE_SIZE_KB,
            preprocessFilterBinaryContent = preprocessFilterBinaryContent.isSelected,
            preprocessAllowedContentTypes =
                parseContentTypePrefixesInput(
                    preprocessAllowedContentTypes.text,
                    Defaults.PREPROCESS_ALLOWED_CONTENT_TYPES,
                ),
            passiveAiEnabled = passiveAiEnabled.isSelected,
            passiveAiRateSeconds = (passiveAiRateSpinner.value as? Int) ?: 5,
            passiveAiScopeOnly = passiveAiScopeOnly.isSelected,
            passiveAiMaxSizeKb = (passiveAiMaxSizeSpinner.value as? Int) ?: 96,
            passiveAiMinSeverity = SeverityLevel.fromString(passiveAiMinSeverityCombo.selectedItem as? String),
            passiveAiEndpointDedupMinutes = (passiveAiEndpointDedupSpinner.value as? Int) ?: 30,
            passiveAiResponseFingerprintDedupMinutes = (passiveAiFingerprintDedupSpinner.value as? Int) ?: 30,
            passiveAiPromptCacheTtlMinutes = (passiveAiPromptCacheTtlSpinner.value as? Int) ?: 30,
            passiveAiEndpointCacheEntries = (passiveAiEndpointCacheEntriesSpinner.value as? Int) ?: 5_000,
            passiveAiResponseFingerprintCacheEntries = (passiveAiFingerprintCacheEntriesSpinner.value as? Int) ?: 5_000,
            passiveAiPromptCacheEntries = (passiveAiPromptCacheEntriesSpinner.value as? Int) ?: 500,
            passiveAiRequestBodyMaxChars = (passiveAiRequestBodyMaxCharsSpinner.value as? Int) ?: 2_000,
            passiveAiResponseBodyMaxChars = (passiveAiResponseBodyMaxCharsSpinner.value as? Int) ?: 4_000,
            passiveAiHeaderMaxCount = (passiveAiHeaderMaxCountSpinner.value as? Int) ?: 40,
            passiveAiParamMaxCount = (passiveAiParamMaxCountSpinner.value as? Int) ?: 15,
            passiveAiExcludedExtensions = passiveAiExcludedExtensionsField.text.trim(),
            passiveAiBatchSize = (passiveAiBatchSizeSpinner.value as? Int) ?: 3,
            passiveAiPersistentCacheEnabled = passiveAiPersistentCacheEnabled.isSelected,
            passiveAiPersistentCacheTtlHours = (passiveAiPersistentCacheTtlSpinner.value as? Int) ?: 24,
            passiveAiPersistentCacheMaxMb = (passiveAiPersistentCacheMaxMbSpinner.value as? Int) ?: 50,
            contextRequestBodyMaxChars = (contextRequestBodyMaxCharsSpinner.value as? Int) ?: 4_000,
            contextResponseBodyMaxChars = (contextResponseBodyMaxCharsSpinner.value as? Int) ?: 8_000,
            contextCompactJson = contextCompactJson.isSelected,
            activeAiEnabled = activeAiEnabled.isSelected,
            activeAiMaxConcurrent = (activeAiMaxConcurrentSpinner.value as? Int) ?: 3,
            activeAiMaxPayloadsPerPoint = (activeAiMaxPayloadsSpinner.value as? Int) ?: 10,
            activeAiTimeoutSeconds = (activeAiTimeoutSpinner.value as? Int) ?: 30,
            activeAiRequestDelayMs = (activeAiDelaySpinner.value as? Int) ?: 100,
            activeAiMaxRiskLevel = PayloadRisk.fromString(activeAiRiskLevelCombo.selectedItem as? String),
            activeAiScopeOnly = activeAiScopeOnly.isSelected,
            activeAiAutoFromPassive = activeAiAutoFromPassive.isSelected,
            activeAiScanMode = ScanMode.fromString(activeAiScanModeCombo.selectedItem as? String),
            activeAiUseCollaborator = activeAiUseCollaborator.isSelected,
            activeAiAdaptivePayloads = activeAiAdaptivePayloads.isSelected,
            bountyPromptEnabled = bountyPromptEnabled.isSelected,
            bountyPromptDir = bountyPromptDir.text.trim(),
            bountyPromptAutoCreateIssues = bountyPromptAutoCreateIssues.isSelected,
            bountyPromptIssueConfidenceThreshold = (bountyPromptIssueThreshold.value as? Int) ?: 90,
            bountyPromptEnabledPromptIds =
                parseIdSetInput(
                    bountyPromptEnabledIds.text,
                    BountyPromptCatalog.defaultEnabledPromptIds(),
                ),
            aiRequestLoggerEnabled = aiLoggerEnabled.isSelected,
            aiRequestLoggerMaxEntries = (aiLoggerMaxEntries.value as? Int) ?: 500,
            customPromptLibrary = customPromptLibraryEditor.snapshot(),
            // 07-02 D-02: ToggleSwitch.isSelected is inherited from JToggleButton and returns
            // kotlin.Boolean — verified at compile time by this AgentSettings constructor call.
            smallModelMode = chatSmallModelMode.isSelected,
        )
    }

    private fun applySettingsToUi(updated: AgentSettings) {
        preferredBackend.selectedItem = updated.preferredBackendId
        backendConfigPanel.applyState(
            BackendConfigState(
                codexCmd = updated.codexCmd,
                geminiCmd = updated.geminiCmd,
                opencodeCmd = updated.opencodeCmd,
                claudeCmd = updated.claudeCmd,
                ollamaCliCmd = updated.ollamaCliCmd,
                ollamaModel = updated.ollamaModel,
                ollamaUrl = updated.ollamaUrl,
                ollamaServeCmd = updated.ollamaServeCmd,
                ollamaAutoStart = updated.ollamaAutoStart,
                ollamaApiKey = updated.ollamaApiKey,
                ollamaHeaders = updated.ollamaHeaders,
                ollamaTimeoutSeconds = updated.ollamaTimeoutSeconds.toString(),
                lmStudioUrl = updated.lmStudioUrl,
                lmStudioModel = updated.lmStudioModel,
                lmStudioTimeoutSeconds = updated.lmStudioTimeoutSeconds.toString(),
                lmStudioServerCmd = updated.lmStudioServerCmd,
                lmStudioAutoStart = updated.lmStudioAutoStart,
                lmStudioApiKey = updated.lmStudioApiKey,
                lmStudioHeaders = updated.lmStudioHeaders,
                openAiCompatUrl = updated.openAiCompatibleUrl,
                openAiCompatModel = updated.openAiCompatibleModel,
                openAiCompatApiKey = updated.openAiCompatibleApiKey,
                openAiCompatHeaders = updated.openAiCompatibleHeaders,
                openAiCompatTimeoutSeconds = updated.openAiCompatibleTimeoutSeconds.toString(),
                nvidiaNimUrl = updated.nvidiaNimUrl,
                nvidiaNimModel = updated.nvidiaNimModel,
                nvidiaNimApiKey = updated.nvidiaNimApiKey,
                nvidiaNimHeaders = updated.nvidiaNimHeaders,
                nvidiaNimTimeoutSeconds = updated.nvidiaNimTimeoutSeconds.toString(),
                perplexityUrl = updated.perplexityUrl,
                perplexityModel = updated.perplexityModel,
                perplexityApiKey = updated.perplexityApiKey,
                perplexityHeaders = updated.perplexityHeaders,
                perplexityTimeoutSeconds = updated.perplexityTimeoutSeconds.toString(),
                copilotCmd = updated.copilotCmd,
            ),
        )
        profilePicker.selectedItem = updated.agentProfile
        privacyMode.selectedItem = updated.privacyMode
        determinism.isSelected = updated.determinismMode
        autoRestart.isSelected = updated.autoRestart
        auditEnabled.isSelected = updated.auditEnabled
        // 07-02 D-02: keep the small-model-mode toggle in sync with persisted state.
        chatSmallModelMode.isSelected = updated.smallModelMode
        promptRequest.text = updated.requestPromptTemplate
        promptIssueFull.text = updated.issuePromptTemplate
        promptIssueAnalyze.text = updated.issueAnalyzePrompt
        promptIssuePoc.text = updated.issuePocPrompt
        promptIssueImpact.text = updated.issueImpactPrompt
        promptSummary.text = updated.requestSummaryPrompt
        promptJs.text = updated.explainJsPrompt
        promptAccessControl.text = updated.accessControlPrompt
        promptLoginSequence.text = updated.loginSequencePrompt
        bountyPromptEnabled.isSelected = updated.bountyPromptEnabled
        bountyPromptDir.text = updated.bountyPromptDir
        bountyPromptAutoCreateIssues.isSelected = updated.bountyPromptAutoCreateIssues
        customPromptLibraryEditor.load(updated.customPromptLibrary)
        bountyPromptIssueThreshold.value = updated.bountyPromptIssueConfidenceThreshold
        bountyPromptEnabledIds.text = updated.bountyPromptEnabledPromptIds.joinToString(",")
        aiLoggerEnabled.isSelected = updated.aiRequestLoggerEnabled
        aiLoggerMaxEntries.value = updated.aiRequestLoggerMaxEntries

        mcpEnabled.isSelected = updated.mcpSettings.enabled
        mcpHost.text = updated.mcpSettings.host
        mcpPort.value = updated.mcpSettings.port
        mcpExternal.isSelected = updated.mcpSettings.externalEnabled
        mcpStdio.isSelected = updated.mcpSettings.stdioEnabled
        mcpToken.text = updated.mcpSettings.token
        mcpAllowedOrigins.text = updated.mcpSettings.allowedOrigins.joinToString("\n")
        mcpTlsEnabled.isSelected = updated.mcpSettings.tlsEnabled
        mcpTlsAuto.isSelected = updated.mcpSettings.tlsAutoGenerate
        mcpKeystorePath.text = updated.mcpSettings.tlsKeystorePath
        mcpKeystorePassword.text = updated.mcpSettings.tlsKeystorePassword
        mcpMaxConcurrent.value = updated.mcpSettings.maxConcurrentRequests
        // 07-02 D-02: spinner is denominated in KB; clamp to the 32 KB floor on refresh too.
        mcpMaxBodyKb.value = (updated.mcpSettings.maxBodyBytes / 1024).coerceAtLeast(32)
        mcpProxyHistoryMaxItems.value = updated.mcpSettings.proxyHistoryMaxItemsPerRequest
        mcpProxyHistorySortOrder.selectedItem =
            if (updated.mcpSettings.proxyHistoryNewestFirst) "Newest first" else "Oldest first"
        mcpAllowUnpreprocessedProxyHistory.isSelected = updated.mcpSettings.allowUnpreprocessedProxyHistory
        mcpUnsafe.isSelected = updated.mcpSettings.unsafeEnabled
        // 07-03 D-03: keep the scope-only toggle in sync with persisted state.
        mcpScopeOnly.isSelected = updated.mcpSettings.scopeOnly
        preprocessProxyHistory.isSelected = updated.preprocessProxyHistory
        preprocessMaxResponseSizeKb.value = updated.preprocessMaxResponseSizeKb
        preprocessFilterBinaryContent.isSelected = updated.preprocessFilterBinaryContent
        preprocessAllowedContentTypes.text = updated.preprocessAllowedContentTypes.joinToString(",")
        applyMcpToolToggles(updated.mcpSettings.toolToggles)
        applyUnsafeToolApprovals(updated.mcpSettings.enabledUnsafeTools)

        // Privacy advisory now lives in `privacyNotice` (SubtleNotice); the next call routes
        // through `refreshPrivacyNotice()` which decides level + visibility from current state.
        updatePrivacyWarnings()
        backendConfigPanel.setBackend(preferredBackendId())
        updateMcpTlsState()
        updateMcpCorsWarning()
        updateUnsafeToolStates()
        updateRiskWarnings()

        // Passive AI Scanner settings
        passiveAiEnabled.isSelected = updated.passiveAiEnabled
        passiveAiScopeOnly.isSelected = updated.passiveAiScopeOnly
        passiveAiRateSpinner.value = updated.passiveAiRateSeconds
        passiveAiMaxSizeSpinner.value = updated.passiveAiMaxSizeKb
        passiveAiMinSeverityCombo.selectedItem = updated.passiveAiMinSeverity.name
        passiveAiEndpointDedupSpinner.value = updated.passiveAiEndpointDedupMinutes
        passiveAiFingerprintDedupSpinner.value = updated.passiveAiResponseFingerprintDedupMinutes
        passiveAiPromptCacheTtlSpinner.value = updated.passiveAiPromptCacheTtlMinutes
        passiveAiEndpointCacheEntriesSpinner.value = updated.passiveAiEndpointCacheEntries
        passiveAiFingerprintCacheEntriesSpinner.value = updated.passiveAiResponseFingerprintCacheEntries
        passiveAiPromptCacheEntriesSpinner.value = updated.passiveAiPromptCacheEntries
        passiveAiRequestBodyMaxCharsSpinner.value = updated.passiveAiRequestBodyMaxChars
        passiveAiResponseBodyMaxCharsSpinner.value = updated.passiveAiResponseBodyMaxChars
        passiveAiHeaderMaxCountSpinner.value = updated.passiveAiHeaderMaxCount
        passiveAiParamMaxCountSpinner.value = updated.passiveAiParamMaxCount
        passiveAiExcludedExtensionsField.text = updated.passiveAiExcludedExtensions
        passiveAiBatchSizeSpinner.value = updated.passiveAiBatchSize
        passiveAiPersistentCacheEnabled.isSelected = updated.passiveAiPersistentCacheEnabled
        passiveAiPersistentCacheTtlSpinner.value = updated.passiveAiPersistentCacheTtlHours
        passiveAiPersistentCacheMaxMbSpinner.value = updated.passiveAiPersistentCacheMaxMb
        contextRequestBodyMaxCharsSpinner.value = updated.contextRequestBodyMaxChars
        contextResponseBodyMaxCharsSpinner.value = updated.contextResponseBodyMaxChars
        contextCompactJson.isSelected = updated.contextCompactJson
        refreshPassiveAiStatus()

        // Active AI Scanner settings
        activeAiEnabled.isSelected = updated.activeAiEnabled
        activeAiScopeOnly.isSelected = updated.activeAiScopeOnly
        activeAiAutoFromPassive.isSelected = updated.activeAiAutoFromPassive
        activeAiMaxConcurrentSpinner.value = updated.activeAiMaxConcurrent
        activeAiMaxPayloadsSpinner.value = updated.activeAiMaxPayloadsPerPoint
        activeAiTimeoutSpinner.value = updated.activeAiTimeoutSeconds
        activeAiDelaySpinner.value = updated.activeAiRequestDelayMs
        activeAiRiskLevelCombo.selectedItem = updated.activeAiMaxRiskLevel.name
        activeAiScanModeCombo.selectedItem = updated.activeAiScanMode.name
        activeAiUseCollaborator.isSelected = updated.activeAiUseCollaborator
        activeAiAdaptivePayloads.isSelected = updated.activeAiAdaptivePayloads
        updateActiveRiskDescription()
        refreshActiveAiStatus()
        onMcpEnabledChanged?.invoke(updated.mcpSettings.enabled)
        onPassiveAiEnabledChanged?.invoke(updated.passiveAiEnabled)
        onActiveAiEnabledChanged?.invoke(updated.activeAiEnabled)
    }

    private fun parseTimeoutSeconds(
        raw: String,
        fallback: Int,
    ): Int {
        val parsed = raw.trim().toIntOrNull() ?: return fallback.coerceIn(30, 3600)
        return parsed.coerceIn(30, 3600)
    }

    private fun parseIdSetInput(
        raw: String,
        fallback: Set<String>,
    ): Set<String> {
        val parsed =
            raw
                .split(',')
                .map { it.trim() }
                .filter { it.isNotBlank() }
                .toSet()
        return if (parsed.isEmpty()) fallback else parsed
    }

    fun shutdown() {
        statusRefreshTimer?.stop()
        statusRefreshTimer = null
        saveFeedbackResetTimer?.stop()
        saveFeedbackResetTimer = null
    }

    private fun parseAllowedOriginsInput(raw: String): List<String> =
        raw
            .split('\n', ',', ';')
            .asSequence()
            .map { it.trim() }
            .filter { it.isNotBlank() }
            .distinct()
            .toList()

    private fun parseContentTypePrefixesInput(
        raw: String,
        fallback: Set<String>,
    ): Set<String> {
        val parsed =
            raw
                .split('\n', ',', ';')
                .asSequence()
                .map { it.trim().lowercase() }
                .filter { it.isNotBlank() }
                .toSet()
        return if (parsed.isEmpty()) fallback else parsed
    }

    private fun applyAndSaveSettings(updated: AgentSettings) {
        settings = updated
        settingsRepo.save(updated)
        AgentProfileLoader.setActiveProfile(updated.agentProfile)
        backends.reload()
        supervisor.applySettings(updated)
        audit.setEnabled(updated.auditEnabled)
        mcpSupervisor.applySettings(
            updated.mcpSettings,
            updated.privacyMode,
            updated.determinismMode,
            updated.toPreprocessorSettings(),
        )

        // Apply passive AI scanner settings
        passiveAiScanner.rateLimitSeconds = updated.passiveAiRateSeconds
        passiveAiScanner.scopeOnly = updated.passiveAiScopeOnly
        passiveAiScanner.maxSizeKb = updated.passiveAiMaxSizeKb
        passiveAiScanner.applyOptimizationSettings(updated)
        passiveAiScanner.setEnabled(updated.passiveAiEnabled)

        // Apply active AI scanner settings
        activeAiScanner.maxConcurrent = updated.activeAiMaxConcurrent
        activeAiScanner.maxPayloadsPerPoint = updated.activeAiMaxPayloadsPerPoint
        activeAiScanner.timeoutSeconds = updated.activeAiTimeoutSeconds
        activeAiScanner.requestDelayMs = updated.activeAiRequestDelayMs.toLong()
        activeAiScanner.maxRiskLevel = updated.activeAiMaxRiskLevel
        activeAiScanner.scopeOnly = updated.activeAiScopeOnly
        activeAiScanner.scanMode = updated.activeAiScanMode
        activeAiScanner.useCollaborator = updated.activeAiUseCollaborator
        activeAiScanner.setEnabled(updated.activeAiEnabled)

        api.logging().logToOutput("AI Agent settings saved.")
        onSettingsChanged?.invoke(updated)
        refreshPassiveAiStatus()
        refreshActiveAiStatus()
        updateProfileWarnings()
        updateRiskWarnings()
    }

    private fun applyMcpToolToggles(toggles: Map<String, Boolean>) {
        val effective = McpToolCatalog.mergeWithDefaults(toggles)
        mcpToolCheckboxes.forEach { (id, checkbox) ->
            checkbox.isSelected = effective[id] ?: false
        }
    }

    private fun dialogParentComponent(): JComponent? = dialogParent

    private fun helpSection(): JPanel =
        HelpConfigPanel(
            dialogParentProvider = ::dialogParentComponent,
        ).build()

    private fun privacySection(): JPanel =
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
        ).build()

    private fun passiveAiScannerSection(): JPanel =
        PassiveScanConfigPanel(
            passiveAiEnabled = passiveAiEnabled,
            passiveAiScopeOnly = passiveAiScopeOnly,
            passiveAiRateSpinner = passiveAiRateSpinner,
            passiveAiMaxSizeSpinner = passiveAiMaxSizeSpinner,
            passiveAiMinSeverityCombo = passiveAiMinSeverityCombo,
            passiveAiEndpointDedupSpinner = passiveAiEndpointDedupSpinner,
            passiveAiFingerprintDedupSpinner = passiveAiFingerprintDedupSpinner,
            passiveAiPromptCacheTtlSpinner = passiveAiPromptCacheTtlSpinner,
            passiveAiEndpointCacheEntriesSpinner = passiveAiEndpointCacheEntriesSpinner,
            passiveAiFingerprintCacheEntriesSpinner = passiveAiFingerprintCacheEntriesSpinner,
            passiveAiPromptCacheEntriesSpinner = passiveAiPromptCacheEntriesSpinner,
            passiveAiRequestBodyMaxCharsSpinner = passiveAiRequestBodyMaxCharsSpinner,
            passiveAiResponseBodyMaxCharsSpinner = passiveAiResponseBodyMaxCharsSpinner,
            passiveAiHeaderMaxCountSpinner = passiveAiHeaderMaxCountSpinner,
            passiveAiParamMaxCountSpinner = passiveAiParamMaxCountSpinner,
            passiveAiExcludedExtensionsField = passiveAiExcludedExtensionsField,
            passiveAiBatchSizeSpinner = passiveAiBatchSizeSpinner,
            passiveAiPersistentCacheEnabled = passiveAiPersistentCacheEnabled,
            passiveAiPersistentCacheTtlSpinner = passiveAiPersistentCacheTtlSpinner,
            passiveAiPersistentCacheMaxMbSpinner = passiveAiPersistentCacheMaxMbSpinner,
            contextRequestBodyMaxCharsSpinner = contextRequestBodyMaxCharsSpinner,
            contextResponseBodyMaxCharsSpinner = contextResponseBodyMaxCharsSpinner,
            contextCompactJson = contextCompactJson,
            passiveAiStatusLabel = passiveAiStatusLabel,
            passiveAiViewFindings = passiveAiViewFindings,
            scannerTriageButton = scannerTriageButton,
            passiveAiResetStats = passiveAiResetStats,
        ).build()

    private fun refreshPassiveAiStatus() {
        val status = passiveAiScanner.getStatus()
        val (manualInProgress, manualCompleted, manualTotal) = passiveAiScanner.getManualScanProgress()

        val statusText =
            buildString {
                if (manualInProgress) {
                    append("Manual scan: $manualCompleted/$manualTotal | ")
                }
                if (status.enabled) {
                    val lastTime =
                        if (status.lastAnalysisTime > 0) {
                            val formatter =
                                DateTimeFormatter
                                    .ofPattern("HH:mm:ss")
                                    .withZone(ZoneId.systemDefault())
                            formatter.format(Instant.ofEpochMilli(status.lastAnalysisTime))
                        } else {
                            "Never"
                        }
                    append("Passive: ON | Analyzed: ${status.requestsAnalyzed} | Issues: ${status.issuesFound} | Last: $lastTime")
                } else {
                    append("Passive: OFF")
                    if (!manualInProgress) {
                        append(" | Total issues: ${status.issuesFound}")
                    }
                }
            }
        passiveAiStatusLabel.text = statusText
    }

    private fun applyPassiveAiSettings() {
        passiveAiScanner.rateLimitSeconds = (passiveAiRateSpinner.value as? Int) ?: 5
        passiveAiScanner.scopeOnly = passiveAiScopeOnly.isSelected
        passiveAiScanner.maxSizeKb = (passiveAiMaxSizeSpinner.value as? Int) ?: 96
        passiveAiScanner.endpointDedupMinutes = (passiveAiEndpointDedupSpinner.value as? Int) ?: 30
        passiveAiScanner.responseFingerprintDedupMinutes =
            (passiveAiFingerprintDedupSpinner.value as? Int) ?: 30
        passiveAiScanner.promptCacheTtlMinutes = (passiveAiPromptCacheTtlSpinner.value as? Int) ?: 30
        passiveAiScanner.endpointCacheEntries = (passiveAiEndpointCacheEntriesSpinner.value as? Int) ?: 5_000
        passiveAiScanner.responseFingerprintCacheEntries =
            (passiveAiFingerprintCacheEntriesSpinner.value as? Int) ?: 5_000
        passiveAiScanner.promptCacheEntries = (passiveAiPromptCacheEntriesSpinner.value as? Int) ?: 500
        passiveAiScanner.requestBodyPromptMaxChars =
            (passiveAiRequestBodyMaxCharsSpinner.value as? Int) ?: 2_000
        passiveAiScanner.responseBodyPromptMaxChars =
            (passiveAiResponseBodyMaxCharsSpinner.value as? Int) ?: 4_000
        passiveAiScanner.headerMaxCount = (passiveAiHeaderMaxCountSpinner.value as? Int) ?: 40
        passiveAiScanner.paramMaxCount = (passiveAiParamMaxCountSpinner.value as? Int) ?: 15
        // Propagate excluded extensions, batch size, and persistent cache via optimization settings
        passiveAiScanner.applyOptimizationSettings(currentSettings())
        passiveAiScanner.setEnabled(passiveAiEnabled.isSelected)
        refreshPassiveAiStatus()
    }

    private fun showPassiveAiFindingsDialog() {
        val findings = passiveAiScanner.getLastFindings(20)
        if (findings.isEmpty()) {
            JOptionPane.showMessageDialog(
                dialogParentComponent(),
                "No findings yet. Enable the scanner and browse the target to generate findings.",
                "AI Passive Scanner Findings",
                JOptionPane.INFORMATION_MESSAGE,
            )
            return
        }

        val sb = StringBuilder()
        sb.append("Recent AI Passive Scanner Findings:\n\n")
        findings.reversed().forEach { finding ->
            val time =
                java.time.Instant
                    .ofEpochMilli(finding.timestamp)
                    .atZone(java.time.ZoneId.systemDefault())
                    .format(
                        java.time.format.DateTimeFormatter
                            .ofPattern("HH:mm:ss"),
                    )
            sb.append("[$time] ${finding.severity} - ${finding.title}\n")
            sb.append("  URL: ${finding.url}\n")
            sb.append("  Detail: ${finding.detail.take(100)}${if (finding.detail.length > 100) "..." else ""}\n")
            sb.append("  Confidence: ${finding.confidence}% | Source: ${finding.source}")
            if (!finding.issueCreated) sb.append(" | Not created as issue")
            sb.append("\n\n")
        }

        val textArea = JTextArea(sb.toString())
        textArea.isEditable = false
        textArea.font = DesignTokens.Typography.mono
        textArea.rows = 20
        textArea.columns = 60

        JOptionPane.showMessageDialog(
            dialogParentComponent(),
            JScrollPane(textArea),
            "AI Passive Scanner Findings (${findings.size} recent)",
            JOptionPane.PLAIN_MESSAGE,
        )
    }

    private fun showActiveAiFindingsDialog() {
        val findings = activeAiScanner.getRecentConfirmations(20)
        if (findings.isEmpty()) {
            JOptionPane.showMessageDialog(
                dialogParentComponent(),
                "No active confirmations yet. Run active scans to generate findings.",
                "AI Active Scanner Findings",
                JOptionPane.INFORMATION_MESSAGE,
            )
            return
        }

        val sb = StringBuilder()
        sb.append("Recent AI Active Scanner Confirmations:\n\n")
        findings.reversed().forEach { finding ->
            val time =
                java.time.Instant
                    .ofEpochMilli(finding.timestamp)
                    .atZone(java.time.ZoneId.systemDefault())
                    .format(
                        java.time.format.DateTimeFormatter
                            .ofPattern("HH:mm:ss"),
                    )
            sb.append("[$time] ${finding.severity} - ${finding.title}\n")
            sb.append("  URL: ${finding.url}\n")
            sb.append("  Confidence: ${finding.confidence}%\n")
            sb.append("  Detail: ${finding.detail.take(120)}${if (finding.detail.length > 120) "..." else ""}\n\n")
        }

        val textArea = JTextArea(sb.toString())
        textArea.isEditable = false
        textArea.font = DesignTokens.Typography.mono
        textArea.rows = 20
        textArea.columns = 60

        JOptionPane.showMessageDialog(
            dialogParentComponent(),
            JScrollPane(textArea),
            "AI Active Scanner Findings (${findings.size} recent)",
            JOptionPane.PLAIN_MESSAGE,
        )
    }

    private fun testBackendConnection(backendId: String) {
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

    private fun showActiveScanQueueDialog() {
        ActiveScanQueuePanel.showDialog(dialogParentComponent(), activeAiScanner)
    }

    private fun showScannerTriageDialog() {
        val passiveFindings = passiveAiScanner.getLastFindings(50)
        val activeFindings = activeAiScanner.getRecentConfirmations(50)
        if (passiveFindings.isEmpty() && activeFindings.isEmpty()) {
            JOptionPane.showMessageDialog(
                dialogParentComponent(),
                "No findings yet. Run passive or active scans to populate triage.",
                "Scanner Triage",
                JOptionPane.INFORMATION_MESSAGE,
            )
            return
        }

        data class TriageEntry(
            val title: String,
            val url: String,
            val severity: String,
            val confidence: Int,
            val source: String,
            val count: Int,
            val lastSeen: Long,
            val detail: String,
        )

        val entries = mutableListOf<TriageEntry>()

        val passiveGrouped = passiveFindings.groupBy { "${it.title}::${it.url}" }
        passiveGrouped.values.forEach { group ->
            val first = group.first()
            entries.add(
                TriageEntry(
                    title = first.title,
                    url = first.url,
                    severity = first.severity,
                    confidence = group.maxOf { it.confidence },
                    source = "passive",
                    count = group.size,
                    lastSeen = group.maxOf { it.timestamp },
                    detail = first.detail,
                ),
            )
        }

        val activeGrouped = activeFindings.groupBy { "${it.title}::${it.url}" }
        activeGrouped.values.forEach { group ->
            val first = group.first()
            entries.add(
                TriageEntry(
                    title = first.title,
                    url = first.url,
                    severity = first.severity,
                    confidence = group.maxOf { it.confidence },
                    source = "active",
                    count = group.size,
                    lastSeen = group.maxOf { it.timestamp },
                    detail = first.detail,
                ),
            )
        }

        val sorted =
            entries.sortedWith(
                compareByDescending<TriageEntry> { severityRank(it.severity) }
                    .thenByDescending { it.confidence }
                    .thenByDescending { it.lastSeen },
            )

        val sb = StringBuilder()
        sb.append("Scanner Triage Summary:\n\n")
        sorted.forEach { entry ->
            val time =
                java.time.Instant
                    .ofEpochMilli(entry.lastSeen)
                    .atZone(java.time.ZoneId.systemDefault())
                    .format(
                        java.time.format.DateTimeFormatter
                            .ofPattern("HH:mm:ss"),
                    )
            sb.append("[${entry.severity}] ${entry.title} (${entry.source}) x${entry.count}\n")
            sb.append("  URL: ${entry.url}\n")
            sb.append("  Confidence: ${entry.confidence}% | Last seen: $time\n")
            sb.append("  Detail: ${entry.detail.take(120)}${if (entry.detail.length > 120) "..." else ""}\n\n")
        }

        val textArea = JTextArea(sb.toString())
        textArea.isEditable = false
        textArea.font = DesignTokens.Typography.mono
        textArea.rows = 24
        textArea.columns = 70

        JOptionPane.showMessageDialog(
            dialogParentComponent(),
            JScrollPane(textArea),
            "Scanner Triage (${sorted.size} grouped findings)",
            JOptionPane.PLAIN_MESSAGE,
        )
    }

    private fun severityRank(severity: String): Int =
        when (severity.uppercase()) {
            "CRITICAL" -> 4
            "HIGH" -> 3
            "MEDIUM" -> 2
            "LOW" -> 1
            else -> 0
        }

    private fun activeAiScannerSection(): JPanel =
        ActiveScanConfigPanel(
            activeAiEnabled = activeAiEnabled,
            activeAiScopeOnly = activeAiScopeOnly,
            activeAiAutoFromPassive = activeAiAutoFromPassive,
            activeAiMaxConcurrentSpinner = activeAiMaxConcurrentSpinner,
            activeAiMaxPayloadsSpinner = activeAiMaxPayloadsSpinner,
            activeAiTimeoutSpinner = activeAiTimeoutSpinner,
            activeAiDelaySpinner = activeAiDelaySpinner,
            activeAiRiskLevelCombo = activeAiRiskLevelCombo,
            activeAiScanModeCombo = activeAiScanModeCombo,
            activeAiUseCollaborator = activeAiUseCollaborator,
            activeAiAdaptivePayloads = activeAiAdaptivePayloads,
            activeAiRiskDescription = activeAiRiskDescription,
            activeAiStatusLabel = activeAiStatusLabel,
            activeAiViewFindings = activeAiViewFindings,
            activeAiViewQueue = activeAiViewQueue,
            activeAiClearQueue = activeAiClearQueue,
            activeAiResetStats = activeAiResetStats,
        ).build()

    private fun updateActiveRiskDescription() {
        val level = (activeAiRiskLevelCombo.selectedItem as? String ?: "SAFE").uppercase()
        activeAiRiskDescription.text =
            when (level) {
                "SAFE" -> "Read-only payloads. No data modified. Safe for bug bounty."
                "MODERATE" -> "May read sensitive data. Could trigger IDS/WAF."
                "DANGEROUS" -> "May modify or delete data. Only for authorized pentests."
                else -> "Risk level not recognized."
            }
    }

    private fun refreshActiveAiStatus() {
        val status = activeAiScanner.getStatus()
        val statusText =
            buildString {
                if (status.enabled) {
                    append("Active: ON")
                    if (status.scanning) {
                        append(" | Scanning")
                        status.currentTarget?.let { target ->
                            append(" (${target.take(40)}...)")
                        }
                    }
                    append(" | Queue: ${status.queueSize}")
                    append(" | Scans: ${status.scansCompleted}")
                    append(" | Confirmed: ${status.vulnsConfirmed}")
                } else {
                    append("Active: OFF")
                    if (status.vulnsConfirmed > 0) {
                        append(" | Confirmed: ${status.vulnsConfirmed}")
                    }
                }
            }
        activeAiStatusLabel.text = statusText
    }

    private fun applyActiveAiSettings() {
        updateActiveRiskDescription()
        activeAiScanner.maxConcurrent = (activeAiMaxConcurrentSpinner.value as? Int) ?: 3
        activeAiScanner.maxPayloadsPerPoint = (activeAiMaxPayloadsSpinner.value as? Int) ?: 10
        activeAiScanner.timeoutSeconds = (activeAiTimeoutSpinner.value as? Int) ?: 30
        activeAiScanner.requestDelayMs = ((activeAiDelaySpinner.value as? Int) ?: 100).toLong()
        activeAiScanner.maxRiskLevel = PayloadRisk.fromString(activeAiRiskLevelCombo.selectedItem as? String)
        activeAiScanner.scopeOnly = activeAiScopeOnly.isSelected
        activeAiScanner.scanMode = ScanMode.fromString(activeAiScanModeCombo.selectedItem as? String)
        activeAiScanner.useCollaborator = activeAiUseCollaborator.isSelected
        activeAiScanner.setEnabled(activeAiEnabled.isSelected)
        refreshActiveAiStatus()
    }

    private fun promptSection(): JPanel =
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

    private fun customPromptsSection(): JPanel =
        CustomPromptsConfigPanel(
            customPromptLibrarySection = customPromptLibraryEditor.component(),
            bountyPromptEnabled = bountyPromptEnabled,
            bountyPromptDir = bountyPromptDir,
            bountyPromptAutoCreateIssues = bountyPromptAutoCreateIssues,
            bountyPromptIssueThreshold = bountyPromptIssueThreshold,
            bountyPromptEnabledIds = bountyPromptEnabledIds,
        ).build()

    private fun mcpSection(): JPanel =
        McpConfigPanel(
            mcpEnabled = mcpEnabled,
            mcpHost = mcpHost,
            mcpPort = mcpPort,
            mcpExternal = mcpExternal,
            mcpStdio = mcpStdio,
            // 07-03 D-03: pass the new scope-only checkbox into McpConfigPanel.
            mcpScopeOnlyCheckbox = mcpScopeOnly,
            mcpTlsEnabled = mcpTlsEnabled,
            mcpTlsAuto = mcpTlsAuto,
            mcpKeystorePath = mcpKeystorePath,
            mcpKeystorePassword = mcpKeystorePassword,
            mcpAllowedOrigins =
                JScrollPane(mcpAllowedOrigins).apply {
                    border = LineBorder(DesignTokens.Colors.border, 1, true)
                    verticalScrollBarPolicy = JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED
                    horizontalScrollBarPolicy = JScrollPane.HORIZONTAL_SCROLLBAR_NEVER
                },
            mcpNotice = mcpNotice,
            mcpMaxConcurrent = mcpMaxConcurrent,
            // 07-02 D-02: McpConfigPanel constructor param name is preserved to minimise the
            // refactor; only the bound variable changes to the KB-denominated spinner.
            mcpMaxBodyMb = mcpMaxBodyKb,
            mcpProxyHistoryMaxItems = mcpProxyHistoryMaxItems,
            mcpProxyHistorySortOrder = mcpProxyHistorySortOrder,
            mcpAllowUnpreprocessedProxyHistory = mcpAllowUnpreprocessedProxyHistory,
            mcpUnsafe = mcpUnsafe,
            preprocessProxyHistory = preprocessProxyHistory,
            preprocessMaxResponseSizeKb = preprocessMaxResponseSizeKb,
            preprocessFilterBinaryContent = preprocessFilterBinaryContent,
            preprocessAllowedContentTypes =
                JScrollPane(preprocessAllowedContentTypes).apply {
                    border = LineBorder(DesignTokens.Colors.border, 1, true)
                    verticalScrollBarPolicy = JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED
                    horizontalScrollBarPolicy = JScrollPane.HORIZONTAL_SCROLLBAR_NEVER
                },
            tokenPanelFactory = ::tokenPanel,
            quickActionsFactory = ::mcpQuickActions,
        ).build()

    private fun tokenPanel(): JPanel {
        val panel = JPanel()
        panel.layout = BoxLayout(panel, BoxLayout.X_AXIS)
        panel.background = DesignTokens.Colors.surface
        panel.add(mcpToken)
        panel.add(Box.createRigidArea(java.awt.Dimension(8, 0)))
        panel.add(mcpTokenRegenerate)
        return panel
    }

    private fun mcpQuickActions(): JPanel {
        val panel = JPanel()
        panel.layout = BoxLayout(panel, BoxLayout.X_AXIS)
        panel.background = DesignTokens.Colors.surface

        val copyUrl = JButton("Copy SSE URL")
        val copyToken = JButton("Copy Token")
        val copyCurl = JButton("Copy curl")

        listOf(copyUrl, copyToken, copyCurl).forEach { btn ->
            btn.font = DesignTokens.Typography.label
            btn.isFocusPainted = false
            btn.background = DesignTokens.Colors.surface
            btn.foreground = DesignTokens.Colors.primary
            btn.border = LineBorder(DesignTokens.Colors.border, 1, true)
        }

        copyUrl.addActionListener { copyToClipboard(buildSseUrl()) }
        copyToken.addActionListener { copyToClipboard(mcpToken.text.trim()) }
        copyCurl.addActionListener { copyToClipboard(buildCurlCommand()) }

        panel.add(copyUrl)
        panel.add(Box.createRigidArea(java.awt.Dimension(8, 0)))
        panel.add(copyToken)
        panel.add(Box.createRigidArea(java.awt.Dimension(8, 0)))
        panel.add(copyCurl)
        return panel
    }

    private fun buildSseUrl(): String {
        val scheme = if (mcpTlsEnabled.isSelected) "https" else "http"
        val host = mcpHost.text.trim().ifBlank { "127.0.0.1" }
        val port = (mcpPort.value as? Int) ?: 9876
        return "$scheme://$host:$port/sse"
    }

    private fun buildCurlCommand(): String {
        val url = buildSseUrl()
        val token = mcpToken.text.trim()
        val header =
            if (mcpExternal.isSelected && token.isNotBlank()) {
                "-H \"Authorization: Bearer $token\" "
            } else {
                ""
            }
        return "curl -v ${header}$url"
    }

    private fun copyToClipboard(text: String) {
        if (text.isBlank()) return
        val clipboard = Toolkit.getDefaultToolkit().systemClipboard
        clipboard.setContents(StringSelection(text), null)
    }

    @Suppress("LongMethod")
    private fun buildMcpToolsPanel(): JScrollPane {
        // STEP 1 — Shared state (UI-07: unchanged from original)
        val effectiveToggles = McpToolCatalog.mergeWithDefaults(settings.mcpSettings.toolToggles)
        val edition = api.burpSuite().version().edition()
        val unsafeEnabled = mcpUnsafe.isSelected
        val unsafeAllowlist = settings.mcpSettings.enabledUnsafeTools
        val grouping = McpToolTabModel.groupTools(McpToolCatalog.available())

        // STEP 2 — Search bar panel (full-width, above both sections)
        val searchField = JTextField()
        applyFieldStyle(searchField)
        searchField.toolTipText = "Search tools by name or description…"
        searchField.maximumSize = java.awt.Dimension(Int.MAX_VALUE, searchField.preferredSize.height)
        val totalTools = McpToolCatalog.available().size
        val resultCountLabel = helpLabel("$totalTools tools")
        val searchBarPanel = JPanel().apply {
            layout = BoxLayout(this, BoxLayout.X_AXIS)
            background = DesignTokens.Colors.surface
            border = EmptyBorder(0, 0, DesignTokens.Spacing.lg, 0)
            add(searchField)
            add(Box.createRigidArea(java.awt.Dimension(DesignTokens.Spacing.sm, 0)))
            add(resultCountLabel)
        }

        // STEP 3 — Tool-row builder (local helper)
        fun buildToolRow(tool: com.six2dez.burp.aiagent.mcp.McpToolDescriptor): JPanel {
            val checkbox = JCheckBox(tool.title, effectiveToggles[tool.id] ?: false)
            checkbox.putClientProperty("unsafeOnly", tool.unsafeOnly)
            checkbox.putClientProperty("description", tool.description)
            // Tooltip logic: preserved verbatim from original (UI-07)
            checkbox.toolTipText =
                when {
                    !tool.unsafeOnly -> tool.description
                    unsafeEnabled -> "${tool.description} Allowed by global unsafe mode."
                    unsafeAllowlist.contains(tool.id) -> "${tool.description} Allowed by per-tool unsafe approval."
                    else -> "${tool.description} Blocked until unsafe mode is enabled globally or approved in allowlist."
                }
            // isEnabled logic: preserved verbatim (UI-07 — only proOnly tools disabled at build time)
            if (tool.proOnly && edition != BurpSuiteEdition.PROFESSIONAL) {
                checkbox.isEnabled = false
                checkbox.putClientProperty("proDisabled", true)
                checkbox.toolTipText = "${tool.description} (Pro only)"
            } else {
                checkbox.putClientProperty("proDisabled", false)
                // NOTE: unsafe checkbox gating (unsafeOnly + unsafe OFF + not allowlisted → disabled)
                // is intentionally DEFERRED to Phase 11. Checkboxes start enabled here per UI-07.
            }
            mcpToolCheckboxes[tool.id] = checkbox

            // North sub-row: checkbox + gap + badge + glue + optional indicator
            val badge = toolBadge(
                if (tool.nativeTool) "Store + Full" else "Full only",
                McpToolTabModel.badgeStyle(tool),
            )
            val northRow = JPanel().apply {
                layout = BoxLayout(this, BoxLayout.X_AXIS)
                isOpaque = false
                add(checkbox)
                add(Box.createRigidArea(java.awt.Dimension(DesignTokens.Spacing.sm, 0)))
                add(badge)
                add(Box.createHorizontalGlue())
            }
            // Optional indicator label (right-aligned, visual only — does NOT affect isEnabled)
            val indicator: JLabel? = when {
                tool.proOnly && edition != BurpSuiteEdition.PROFESSIONAL ->
                    JLabel("Pro only").apply {
                        font = DesignTokens.Typography.caption
                        foreground = DesignTokens.Colors.onSurfaceVariant
                    }
                tool.unsafeOnly && !unsafeEnabled && unsafeAllowlist.contains(tool.id) ->
                    JLabel("allowlisted").apply {
                        font = DesignTokens.Typography.caption
                        foreground = DesignTokens.Colors.statusWarning
                    }
                tool.unsafeOnly && !unsafeEnabled ->
                    JLabel("unsafe").apply {
                        font = DesignTokens.Typography.caption
                        foreground = DesignTokens.Colors.statusError
                    }
                else -> null
            }
            if (indicator != null) northRow.add(indicator)

            // South sub-row: description help label
            val descLabel = helpLabel(tool.description)
            descLabel.border = EmptyBorder(0, DesignTokens.Spacing.md, 0, 0)

            return JPanel(BorderLayout()).apply {
                isOpaque = false
                border = EmptyBorder(
                    DesignTokens.Spacing.xs,
                    DesignTokens.Spacing.md,
                    DesignTokens.Spacing.xs,
                    DesignTokens.Spacing.md,
                )
                add(northRow, BorderLayout.NORTH)
                add(descLabel, BorderLayout.SOUTH)
            }
        }

        // Helper: compute set of disabled checkbox tool IDs at call time
        val disabledCheckboxIds: () -> Set<String> = {
            mcpToolCheckboxes.entries.filter { !it.value.isEnabled }.map { it.key }.toSet()
        }

        // STEP 4 — AI Tools section
        val aiToolRows = mutableListOf<Pair<com.six2dez.burp.aiagent.mcp.McpToolDescriptor, JPanel>>()
        val aiEnableAll = secondaryButton("Enable all")
        val aiDisableAll = secondaryButton("Disable all")
        val aiBulkBar = JPanel().apply {
            layout = BoxLayout(this, BoxLayout.X_AXIS)
            isOpaque = false
            border = EmptyBorder(0, 0, DesignTokens.Spacing.sm, 0)
            add(aiEnableAll)
            add(Box.createRigidArea(java.awt.Dimension(DesignTokens.Spacing.sm, 0)))
            add(aiDisableAll)
            add(Box.createHorizontalGlue())
        }
        val aiEmptyLabel = helpLabel("No tools match your search.").also { it.isVisible = false }
        val aiListPanel = JPanel().apply {
            layout = BoxLayout(this, BoxLayout.Y_AXIS)
            isOpaque = false
            add(aiBulkBar)
        }
        for (tool in grouping.native) {
            val row = buildToolRow(tool)
            aiToolRows.add(tool to row)
            aiListPanel.add(row)
        }
        aiListPanel.add(aiEmptyLabel)

        aiEnableAll.addActionListener {
            val targets = McpToolTabModel.bulkToggleTargets(grouping.native, searchField.text, disabledCheckboxIds())
            for (target in targets) mcpToolCheckboxes[target.id]?.isSelected = true
        }
        aiDisableAll.addActionListener {
            val targets = McpToolTabModel.bulkToggleTargets(grouping.native, searchField.text, disabledCheckboxIds())
            for (target in targets) mcpToolCheckboxes[target.id]?.isSelected = false
        }

        val aiSection = sectionPanel(
            title = "AI Tools (extension-native)",
            subtitle = "Extension-native tools — available in both the BApp Store and the full build.",
            content = aiListPanel,
        )

        // STEP 5 — Montoya Tools section
        val montoyaToolRows = mutableListOf<Pair<com.six2dez.burp.aiagent.mcp.McpToolDescriptor, JPanel>>()
        val montoyaCategoryHeaders = mutableListOf<Pair<String, JLabel>>()
        val montoyaEnableAll = secondaryButton("Enable all")
        val montoyaDisableAll = secondaryButton("Disable all")
        val montoyaBulkBar = JPanel().apply {
            layout = BoxLayout(this, BoxLayout.X_AXIS)
            isOpaque = false
            border = EmptyBorder(0, 0, DesignTokens.Spacing.sm, 0)
            add(montoyaEnableAll)
            add(Box.createRigidArea(java.awt.Dimension(DesignTokens.Spacing.sm, 0)))
            add(montoyaDisableAll)
            add(Box.createHorizontalGlue())
        }
        val montoyaEmptyLabel = helpLabel("No tools match your search.").also { it.isVisible = false }
        val montoyaListPanel = JPanel().apply {
            layout = BoxLayout(this, BoxLayout.Y_AXIS)
            isOpaque = false
        }

        val categoryMap = McpToolTabModel.categoryGroups(grouping.generic)
        if (grouping.generic.isEmpty()) {
            montoyaBulkBar.isVisible = false
            montoyaListPanel.add(helpLabel("No Montoya tools available in this build."))
        } else {
            montoyaListPanel.add(montoyaBulkBar)
            for ((category, tools) in categoryMap) {
                val catHeader = JLabel(category).apply {
                    font = DesignTokens.Typography.label
                    foreground = DesignTokens.Colors.onSurfaceVariant
                    border = EmptyBorder(DesignTokens.Spacing.sm, 0, DesignTokens.Spacing.xs, 0)
                }
                montoyaCategoryHeaders.add(category to catHeader)
                montoyaListPanel.add(catHeader)
                for (tool in tools) {
                    val row = buildToolRow(tool)
                    montoyaToolRows.add(tool to row)
                    montoyaListPanel.add(row)
                }
            }
        }
        montoyaListPanel.add(montoyaEmptyLabel)

        montoyaEnableAll.addActionListener {
            val targets = McpToolTabModel.bulkToggleTargets(grouping.generic, searchField.text, disabledCheckboxIds())
            for (target in targets) mcpToolCheckboxes[target.id]?.isSelected = true
        }
        montoyaDisableAll.addActionListener {
            val targets = McpToolTabModel.bulkToggleTargets(grouping.generic, searchField.text, disabledCheckboxIds())
            for (target in targets) mcpToolCheckboxes[target.id]?.isSelected = false
        }

        // STEP 6 — Unsafe Allowlist AccordionPanel (bottom of Montoya section)
        val allowlistContentPanel = JPanel().apply {
            layout = BoxLayout(this, BoxLayout.Y_AXIS)
            isOpaque = false
        }
        val unsafeTools = McpToolCatalog.available().filter { it.unsafeOnly }.sortedBy { it.title }
        for (tool in unsafeTools) {
            val approved = unsafeAllowlist.contains(tool.id)
            val approval = JCheckBox(tool.title, approved).apply {
                toolTipText = tool.description
                putClientProperty("proOnly", tool.proOnly)
                putClientProperty("toolId", tool.id)
            }
            val proDisabled = tool.proOnly && edition != BurpSuiteEdition.PROFESSIONAL
            if (proDisabled) {
                approval.isEnabled = false
                approval.toolTipText = "${tool.description} (Pro only)"
            } else {
                approval.isEnabled = !unsafeEnabled
            }
            approval.addActionListener { updateUnsafeToolStates() }
            mcpUnsafeApprovalCheckboxes[tool.id] = approval
            val row = JPanel().apply {
                layout = BoxLayout(this, BoxLayout.X_AXIS)
                isOpaque = false
                border = EmptyBorder(DesignTokens.Spacing.xs, DesignTokens.Spacing.md, DesignTokens.Spacing.xs, DesignTokens.Spacing.md)
                add(approval)
                add(Box.createHorizontalGlue())
            }
            allowlistContentPanel.add(row)
        }
        val allowlistAccordion = AccordionPanel(
            "Unsafe tool allowlist",
            "Approve individual unsafe tools without enabling global unsafe mode.",
            allowlistContentPanel,
            initiallyExpanded = false,
        )
        montoyaListPanel.add(Box.createRigidArea(java.awt.Dimension(0, DesignTokens.Spacing.sm)))
        montoyaListPanel.add(allowlistAccordion)

        val montoyaSection = sectionPanel(
            title = "Montoya Tools (generic)",
            subtitle = "Generic Montoya API wrappers — available in the full build only.",
            content = montoyaListPanel,
        )

        // STEP 7 — Section separator (Spacing.xl gap between AI and Montoya sections)
        val sectionSeparator = JPanel().apply {
            isOpaque = false
            preferredSize = java.awt.Dimension(0, DesignTokens.Spacing.xl)
            maximumSize = java.awt.Dimension(Int.MAX_VALUE, DesignTokens.Spacing.xl)
        }

        // STEP 8 — DocumentListener for live filter (Option B — show/hide rows)
        fun applyFilter(query: String) {
            var visibleAiCount = 0
            for ((tool, row) in aiToolRows) {
                val visible = McpToolTabModel.filterPredicate(query, tool)
                row.isVisible = visible
                if (visible) visibleAiCount++
            }
            var visibleMontoyaCount = 0
            for ((tool, row) in montoyaToolRows) {
                val visible = McpToolTabModel.filterPredicate(query, tool)
                row.isVisible = visible
                if (visible) visibleMontoyaCount++
            }
            for ((category, header) in montoyaCategoryHeaders) {
                val hasVisible = categoryMap[category]?.any { McpToolTabModel.filterPredicate(query, it) } == true
                header.isVisible = hasVisible
            }
            aiEmptyLabel.isVisible = visibleAiCount == 0 && query.isNotBlank()
            aiBulkBar.isVisible = visibleAiCount > 0
            montoyaEmptyLabel.isVisible = visibleMontoyaCount == 0 && query.isNotBlank() && grouping.generic.isNotEmpty()
            montoyaBulkBar.isVisible = visibleMontoyaCount > 0 && grouping.generic.isNotEmpty()
            val totalVisible = visibleAiCount + visibleMontoyaCount
            resultCountLabel.text = if (query.isBlank()) "$totalTools tools" else "$totalVisible of $totalTools tools"
            aiListPanel.revalidate()
            aiListPanel.repaint()
            montoyaListPanel.revalidate()
            montoyaListPanel.repaint()
        }

        searchField.document.addDocumentListener(object : DocumentListener {
            override fun insertUpdate(e: DocumentEvent) = applyFilter(searchField.text)
            override fun removeUpdate(e: DocumentEvent) = applyFilter(searchField.text)
            override fun changedUpdate(e: DocumentEvent) = applyFilter(searchField.text)
        })

        // STEP 9 — Return via buildTabPanel from design module
        return buildTabPanel(listOf(searchBarPanel, aiSection, sectionSeparator, montoyaSection))
    }

    private fun updateUnsafeToolStates() {
        val unsafeEnabled = mcpUnsafe.isSelected
        mcpToolCheckboxes.values.forEach { checkbox ->
            val proDisabled = checkbox.getClientProperty("proDisabled") as? Boolean ?: false
            if (proDisabled) {
                checkbox.isEnabled = false
                return@forEach
            }
            val unsafeOnly = checkbox.getClientProperty("unsafeOnly") as? Boolean ?: false
            val description = checkbox.getClientProperty("description") as? String ?: ""
            val toolId = mcpToolCheckboxes.entries.firstOrNull { it.value === checkbox }?.key
            val allowlisted = toolId != null && mcpUnsafeApprovalCheckboxes[toolId]?.isSelected == true
            checkbox.isEnabled = true
            checkbox.toolTipText =
                if (unsafeOnly) {
                    when {
                        unsafeEnabled -> "$description Allowed by global unsafe mode."
                        allowlisted -> "$description Allowed by per-tool unsafe approval."
                        else -> "$description Blocked until unsafe mode is enabled globally or approved in allowlist."
                    }
                } else {
                    description
                }
        }
        mcpUnsafeApprovalCheckboxes.forEach { (id, checkbox) ->
            val proOnly = checkbox.getClientProperty("proOnly") as? Boolean ?: false
            val proDisabled = proOnly && api.burpSuite().version().edition() != BurpSuiteEdition.PROFESSIONAL
            checkbox.isEnabled = !unsafeEnabled && !proDisabled
            val description =
                McpToolCatalog
                    .all()
                    .firstOrNull { it.id == id }
                    ?.description
                    .orEmpty()
            checkbox.toolTipText =
                when {
                    proDisabled -> "$description (Pro only)"
                    unsafeEnabled -> "$description Ignored while global unsafe mode is ON."
                    else -> description
                }
        }
        updateProfileWarnings()
        updateRiskWarnings()
    }

    private fun updatePrivacyWarnings() {
        refreshPrivacyNotice()
    }

    private fun updateRiskWarnings() {
        refreshPrivacyNotice()
        refreshMcpNotice()
    }

    /**
     * Compose a single advisory for the Privacy & Logging tab. Replaces the previous trio of
     * stacked red `JLabel` banners (`privacyWarning` + `privacyActiveWarning` + `privacyRiskWarning`)
     * with one [SubtleNotice] whose level + message reflect the active risk combination.
     */
    private fun refreshPrivacyNotice() {
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

    /**
     * Compose a single advisory for the MCP Server tab. Replaces the previous pair of stacked
     * banners (`mcpCorsWarning` + `mcpRiskWarning`) with one [SubtleNotice] that surfaces
     * **every** applicable misconfiguration as a bulleted list — accent color follows the
     * highest-severity entry. Earlier draft used a `when` chain that returned only the first
     * matching branch, dropping the CORS-open warning in combined-risk states; the accumulator
     * below preserves all caveats simultaneously.
     */
    private fun refreshMcpNotice() {
        val selectedPrivacy = privacyMode.selectedItem as? PrivacyMode ?: PrivacyMode.STRICT
        val mcpOn = mcpEnabled.isSelected
        val external = mcpExternal.isSelected
        val unsafeEnabled = mcpUnsafe.isSelected
        val tokenBlank = mcpToken.text.trim().isBlank()
        val hasAllowedOrigins = parseAllowedOriginsInput(mcpAllowedOrigins.text).isNotEmpty()

        if (!mcpOn) {
            mcpNotice.hideNotice()
            return
        }

        data class Item(
            val level: com.six2dez.burp.aiagent.ui.components.SubtleNotice.Level,
            val html: String,
        )
        val items = mutableListOf<Item>()
        if (external && unsafeEnabled) {
            items +=
                Item(
                    com.six2dez.burp.aiagent.ui.components.SubtleNotice.Level.RISK,
                    "<b>External MCP + Unsafe mode.</b> Remote callers can invoke state-changing tools.",
                )
        }
        if (external && tokenBlank) {
            items +=
                Item(
                    com.six2dez.burp.aiagent.ui.components.SubtleNotice.Level.RISK,
                    "<b>External MCP with empty token.</b> The endpoint is reachable without authentication.",
                )
        }
        if (external && selectedPrivacy == PrivacyMode.OFF) {
            items +=
                Item(
                    com.six2dez.burp.aiagent.ui.components.SubtleNotice.Level.WARN,
                    "<b>External MCP with Privacy OFF.</b> Raw traffic may leave the host.",
                )
        }
        if (external && !hasAllowedOrigins) {
            items +=
                Item(
                    com.six2dez.burp.aiagent.ui.components.SubtleNotice.Level.WARN,
                    "<b>External MCP with no allowed origins.</b> CORS will accept requests from any origin.",
                )
        }
        if (items.isEmpty()) {
            mcpNotice.hideNotice()
            return
        }
        val highest =
            if (items.any { it.level == com.six2dez.burp.aiagent.ui.components.SubtleNotice.Level.RISK }) {
                com.six2dez.burp.aiagent.ui.components.SubtleNotice.Level.RISK
            } else {
                com.six2dez.burp.aiagent.ui.components.SubtleNotice.Level.WARN
            }
        val body = items.joinToString("<br>") { "• ${it.html}" }
        mcpNotice.setMessage(highest, body)
    }

    private fun updateSaveFeedback(
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

    private fun updateMcpTlsState() {
        val external = mcpExternal.isSelected
        val tlsEnabled = if (external) true else mcpTlsEnabled.isSelected
        mcpTlsEnabled.isSelected = tlsEnabled
        mcpTlsEnabled.isEnabled = !external
        mcpTlsAuto.isEnabled = tlsEnabled
        mcpKeystorePath.isEnabled = tlsEnabled
        mcpKeystorePassword.isEnabled = tlsEnabled
        updateFieldStyle(mcpKeystorePath)
        mcpKeystorePassword.foreground =
            if (mcpKeystorePassword.isEnabled) DesignTokens.Colors.inputForeground else DesignTokens.Colors.onSurfaceVariant
    }

    /**
     * Legacy entry point — kept so existing listeners (Allowed Origins document changes) still
     * compile. Routes into the consolidated MCP notice.
     */
    private fun updateMcpCorsWarning() {
        refreshMcpNotice()
    }

    private fun collectMcpToolToggles(): Map<String, Boolean> = mcpToolCheckboxes.mapValues { it.value.isSelected }

    private fun collectEnabledUnsafeTools(): Set<String> =
        mcpUnsafeApprovalCheckboxes
            .filterValues { it.isSelected }
            .keys

    private fun applyUnsafeToolApprovals(enabledUnsafeTools: Set<String>) {
        mcpUnsafeApprovalCheckboxes.forEach { (id, checkbox) ->
            checkbox.isSelected = enabledUnsafeTools.contains(id)
        }
    }

    private fun updateProfileWarnings() {
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

    private fun availableMcpToolsWithReasons(): Pair<Set<String>, Map<String, String>> {
        val edition = api.burpSuite().version().edition()
        val unsafeEnabled = mcpUnsafe.isSelected
        val enabledUnsafeTools = collectEnabledUnsafeTools()
        val effectiveToggles = McpToolCatalog.mergeWithDefaults(collectMcpToolToggles())
        val available = mutableSetOf<String>()
        val reasons = mutableMapOf<String, String>()
        for (tool in McpToolCatalog.available()) {
            val id = tool.id.lowercase()
            when {
                tool.proOnly && edition != BurpSuiteEdition.PROFESSIONAL ->
                    reasons[id] = "requires Burp Professional."
                tool.unsafeOnly && !unsafeEnabled && !enabledUnsafeTools.contains(tool.id) ->
                    reasons[id] = "requires Unsafe mode or explicit per-tool unsafe approval."
                effectiveToggles[tool.id] != true ->
                    reasons[id] = "disabled in MCP Tools settings."
                else -> available.add(id)
            }
        }
        return available to reasons
    }

    private fun availableMcpTools(): Set<String> = availableMcpToolsWithReasons().first

    private fun updateFieldStyle(field: JTextField) {
        val disabled = DesignTokens.Colors.inputBackground.darker()
        field.background = if (field.isEnabled) DesignTokens.Colors.inputBackground else disabled
        field.foreground = if (field.isEnabled) DesignTokens.Colors.inputForeground else DesignTokens.Colors.onSurfaceVariant
    }

    private fun styleCombo(combo: JComboBox<*>) {
        combo.font = DesignTokens.Typography.body
        combo.background = DesignTokens.Colors.inputBackground
        combo.foreground = DesignTokens.Colors.inputForeground
        combo.border = LineBorder(DesignTokens.Colors.border, 1, true)
    }

    private fun openExternalCli(
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

    private fun shellQuote(value: String): String {
        if (value.isEmpty()) return "''"
        if (value.none { it.isWhitespace() || it == '"' || it == '\'' }) return value
        return "'" + value.replace("'", "'\"'\"'") + "'"
    }
}
