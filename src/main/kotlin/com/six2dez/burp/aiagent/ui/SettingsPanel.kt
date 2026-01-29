package com.six2dez.burp.aiagent.ui

import burp.api.montoya.MontoyaApi
import com.six2dez.burp.aiagent.audit.AuditLogger
import com.six2dez.burp.aiagent.backends.BackendRegistry
import com.six2dez.burp.aiagent.config.AgentSettings
import com.six2dez.burp.aiagent.config.AgentSettingsRepository
import com.six2dez.burp.aiagent.config.McpSettings
import com.six2dez.burp.aiagent.mcp.McpSupervisor
import com.six2dez.burp.aiagent.mcp.McpToolCatalog
import com.six2dez.burp.aiagent.agents.AgentProfileLoader
import com.six2dez.burp.aiagent.ui.components.AccordionPanel
import com.six2dez.burp.aiagent.ui.components.ToggleSwitch
import com.six2dez.burp.aiagent.ui.panels.BackendConfigPanel
import com.six2dez.burp.aiagent.ui.panels.BackendConfigState
import com.six2dez.burp.aiagent.redact.PrivacyMode
import com.six2dez.burp.aiagent.supervisor.AgentSupervisor
import burp.api.montoya.core.BurpSuiteEdition
import java.awt.BorderLayout
import java.awt.GridBagConstraints
import java.awt.GridBagLayout
import java.awt.Insets
import java.awt.Toolkit
import java.awt.datatransfer.StringSelection
import java.time.Instant
import java.time.ZoneId
import java.time.format.DateTimeFormatter
import javax.swing.*
import javax.swing.border.EmptyBorder
import javax.swing.border.LineBorder

class SettingsPanel(
    private val api: MontoyaApi,
    private val backends: BackendRegistry,
    private val supervisor: AgentSupervisor,
    private val audit: AuditLogger,
    private val mcpSupervisor: McpSupervisor,
    private val passiveAiScanner: com.six2dez.burp.aiagent.scanner.PassiveAiScanner,
    private val activeAiScanner: com.six2dez.burp.aiagent.scanner.ActiveAiScanner
) {
    private val settingsRepo = AgentSettingsRepository(api)
    private var settings: AgentSettings = settingsRepo.load()
    var onMcpEnabledChanged: ((Boolean) -> Unit)? = null
    var onPassiveAiEnabledChanged: ((Boolean) -> Unit)? = null
    var onActiveAiEnabledChanged: ((Boolean) -> Unit)? = null

    private val panel = JPanel(BorderLayout())
    private val content = JPanel()

    private val backendConfigPanel = BackendConfigPanel(
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
            openAiCompatTimeoutSeconds = settings.openAiCompatibleTimeoutSeconds.toString()
        )
    )
    private val profilePicker = JComboBox(arrayOf("pentester", "bughunter", "auditor")).apply {
        selectedItem = settings.agentProfile
        preferredSize = java.awt.Dimension(140, preferredSize.height)
        maximumSize = java.awt.Dimension(140, preferredSize.height)
    }
    private val preferredBackend = JComboBox(backends.listBackendIds().toTypedArray()).apply {
        selectedItem = settings.preferredBackendId
        preferredSize = java.awt.Dimension(140, preferredSize.height)
        maximumSize = java.awt.Dimension(140, preferredSize.height)
    }

    private val privacyMode = JComboBox(PrivacyMode.entries.toTypedArray()).apply {
        selectedItem = settings.privacyMode
        preferredSize = java.awt.Dimension(120, preferredSize.height)
        maximumSize = java.awt.Dimension(120, preferredSize.height)
    }
    private val determinism = ToggleSwitch(settings.determinismMode)
    private val autoRestart = ToggleSwitch(settings.autoRestart)
    private val auditEnabled = ToggleSwitch(settings.auditEnabled)
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
    private val privacyWarning = JLabel("Privacy mode is OFF. Raw traffic may be exposed via MCP and prompts.")
    private val privacyActiveWarning = JLabel(
        "STRICT anonymizes hosts in AI prompts but does not prevent active scanner from sending real requests to targets."
    )
    private val mcpEnabled = ToggleSwitch(settings.mcpSettings.enabled)
    private val mcpHost = JTextField(settings.mcpSettings.host, 15).apply {
        preferredSize = java.awt.Dimension(140, preferredSize.height)
        maximumSize = java.awt.Dimension(140, preferredSize.height)
    }
    private val mcpPort = JSpinner(SpinnerNumberModel(settings.mcpSettings.port, 1, 65535, 1)).apply {
        preferredSize = java.awt.Dimension(80, preferredSize.height)
        maximumSize = java.awt.Dimension(80, preferredSize.height)
    }
    private val mcpExternal = JCheckBox("Allow external access (requires TLS)", settings.mcpSettings.externalEnabled)
    private val mcpStdio = JCheckBox("Enable stdio bridge", settings.mcpSettings.stdioEnabled)
    private val mcpTlsEnabled = JCheckBox("Enable TLS", settings.mcpSettings.tlsEnabled)
    private val mcpTlsAuto = JCheckBox("Auto-generate TLS certificate", settings.mcpSettings.tlsAutoGenerate)
    private val mcpKeystorePath = JTextField(settings.mcpSettings.tlsKeystorePath)
    private val mcpKeystorePassword = JPasswordField(settings.mcpSettings.tlsKeystorePassword).apply {
        preferredSize = java.awt.Dimension(200, preferredSize.height)
    }
    private val mcpToken = JTextField(settings.mcpSettings.token)
    private val mcpTokenRegenerate = JButton("Regenerate token")
    private val mcpMaxConcurrent = JSpinner(
        SpinnerNumberModel(settings.mcpSettings.maxConcurrentRequests, 1, 64, 1)
    ).apply {
        preferredSize = java.awt.Dimension(70, preferredSize.height)
        maximumSize = java.awt.Dimension(70, preferredSize.height)
    }
    private val mcpMaxBodyMb = JSpinner(
        SpinnerNumberModel(
            (settings.mcpSettings.maxBodyBytes / (1024 * 1024)).coerceAtLeast(1),
            1,
            100,
            1
        )
    ).apply {
        preferredSize = java.awt.Dimension(70, preferredSize.height)
        maximumSize = java.awt.Dimension(70, preferredSize.height)
    }
    private val mcpUnsafe = JCheckBox("Unsafe mode (allow write/mutation tools)", settings.mcpSettings.unsafeEnabled)
    private val mcpToolCheckboxes = mutableMapOf<String, JCheckBox>()
    
    // Passive AI Scanner UI components
    private val passiveAiEnabled = ToggleSwitch(settings.passiveAiEnabled)
    private val passiveAiScopeOnly = JCheckBox("In-scope only", settings.passiveAiScopeOnly)
    private val passiveAiRateSpinner = JSpinner(SpinnerNumberModel(settings.passiveAiRateSeconds, 1, 60, 1)).apply {
        preferredSize = java.awt.Dimension(70, preferredSize.height)
        maximumSize = java.awt.Dimension(70, preferredSize.height)
    }
    private val passiveAiMaxSizeSpinner = JSpinner(SpinnerNumberModel(settings.passiveAiMaxSizeKb, 16, 1024, 1)).apply {
        preferredSize = java.awt.Dimension(80, preferredSize.height)
        maximumSize = java.awt.Dimension(80, preferredSize.height)
    }
    private val passiveAiMinSeverityCombo = JComboBox(arrayOf("LOW", "MEDIUM", "HIGH", "CRITICAL")).apply {
        selectedItem = settings.passiveAiMinSeverity
        preferredSize = java.awt.Dimension(100, preferredSize.height)
        maximumSize = java.awt.Dimension(100, preferredSize.height)
    }
    private val passiveAiStatusLabel = JLabel()
    private val passiveAiViewFindings = JButton("View findings")
    private val passiveAiResetStats = JButton("Reset stats")
    
    // Active AI Scanner UI components
    private val activeAiEnabled = ToggleSwitch(settings.activeAiEnabled)
    private val activeAiScopeOnly = JCheckBox("In-scope only", settings.activeAiScopeOnly)
    private val activeAiAutoFromPassive = JCheckBox("Auto-queue passive findings", settings.activeAiAutoFromPassive)
    private val activeAiMaxConcurrentSpinner = JSpinner(SpinnerNumberModel(settings.activeAiMaxConcurrent, 1, 10, 1)).apply {
        preferredSize = java.awt.Dimension(70, preferredSize.height)
        maximumSize = java.awt.Dimension(70, preferredSize.height)
    }
    private val activeAiMaxPayloadsSpinner = JSpinner(SpinnerNumberModel(settings.activeAiMaxPayloadsPerPoint, 1, 50, 5)).apply {
        preferredSize = java.awt.Dimension(70, preferredSize.height)
        maximumSize = java.awt.Dimension(70, preferredSize.height)
    }
    private val activeAiTimeoutSpinner = JSpinner(SpinnerNumberModel(settings.activeAiTimeoutSeconds, 5, 120, 5)).apply {
        preferredSize = java.awt.Dimension(70, preferredSize.height)
        maximumSize = java.awt.Dimension(70, preferredSize.height)
    }
    private val activeAiDelaySpinner = JSpinner(SpinnerNumberModel(settings.activeAiRequestDelayMs, 0, 5000, 100)).apply {
        preferredSize = java.awt.Dimension(80, preferredSize.height)
        maximumSize = java.awt.Dimension(80, preferredSize.height)
    }
    private val activeAiRiskLevelCombo = JComboBox(arrayOf("SAFE", "MODERATE", "DANGEROUS")).apply {
        selectedItem = settings.activeAiMaxRiskLevel
        preferredSize = java.awt.Dimension(110, preferredSize.height)
        maximumSize = java.awt.Dimension(110, preferredSize.height)
    }
    private val activeAiScanModeCombo = JComboBox(arrayOf("BUG_BOUNTY", "PENTEST", "FULL")).apply {
        selectedItem = settings.activeAiScanMode
        preferredSize = java.awt.Dimension(120, preferredSize.height)
        maximumSize = java.awt.Dimension(120, preferredSize.height)
    }
    private val activeAiUseCollaborator = JCheckBox("Use Collaborator for SSRF OAST", settings.activeAiUseCollaborator)
    private val activeAiRiskDescription = JLabel()
    private val activeAiStatusLabel = JLabel()
    private val activeAiViewFindings = JButton("View findings")
    private val activeAiClearQueue = JButton("Clear queue")
    private val activeAiResetStats = JButton("Reset stats")

    private val scannerTriageButton = JButton("Open triage")

    init {
        panel.background = UiTheme.Colors.surface
        content.layout = BoxLayout(content, BoxLayout.Y_AXIS)
        content.border = EmptyBorder(8, 12, 12, 12)
        content.background = UiTheme.Colors.surface

        applyFieldStyle(mcpHost)
        applyFieldStyle(mcpKeystorePath)
        applyFieldStyle(mcpToken)
        applyAreaStyle(promptRequest)
        applyAreaStyle(promptSummary)
        applyAreaStyle(promptJs)
        applyAreaStyle(promptAccessControl)
        applyAreaStyle(promptLoginSequence)
        applyAreaStyle(promptIssueAnalyze)
        applyAreaStyle(promptIssuePoc)
        applyAreaStyle(promptIssueImpact)
        applyAreaStyle(promptIssueFull)

        styleCombo(privacyMode)
        styleCombo(profilePicker)
        preferredBackend.toolTipText = "Default backend used for new sessions and context actions."
        profilePicker.toolTipText = "Select the AGENTS profile used for system instructions."
        privacyMode.toolTipText = "Controls how traffic is redacted before sending to a model."
        determinism.font = UiTheme.Typography.body
        determinism.background = UiTheme.Colors.surface
        determinism.foreground = UiTheme.Colors.onSurface
        determinism.toolTipText = "Stable ordering for reproducible prompts. Advanced use only."
        autoRestart.font = UiTheme.Typography.body
        autoRestart.background = UiTheme.Colors.surface
        autoRestart.foreground = UiTheme.Colors.onSurface
        autoRestart.toolTipText = "Automatically restart a crashed agent session."
        auditEnabled.font = UiTheme.Typography.body
        auditEnabled.background = UiTheme.Colors.surface
        auditEnabled.foreground = UiTheme.Colors.onSurface
        auditEnabled.toolTipText = "Tamper-evident logs (JSONL + SHA-256 hashes). Logs saved to ~/.burp-ai-agent/audit.jsonl"
        rotateSaltBtn.font = UiTheme.Typography.label
        rotateSaltBtn.background = UiTheme.Colors.surface
        rotateSaltBtn.foreground = UiTheme.Colors.primary
        rotateSaltBtn.border = LineBorder(UiTheme.Colors.outline, 1, true)
        rotateSaltBtn.isFocusPainted = false
        rotateSaltBtn.toolTipText = "Rotates the salt used for host anonymization (e.g. host-xxxxxx.local). Current: ${settings.hostAnonymizationSalt.take(8)}..."
        mcpToken.isEditable = true
        mcpToken.font = UiTheme.Typography.mono
        mcpToken.toolTipText = "Required for external access. Use as: Authorization: Bearer <token>"
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
        mcpMaxBodyMb.toolTipText = "Max tool output size in MB."
        mcpUnsafe.toolTipText = "Allow tools that modify Burp state or send active requests."
        mcpTokenRegenerate.font = UiTheme.Typography.label
        mcpTokenRegenerate.isFocusPainted = false
        mcpKeystorePassword.font = UiTheme.Typography.mono
        mcpKeystorePassword.border = LineBorder(UiTheme.Colors.outline, 1, true)
        mcpKeystorePassword.background = UiTheme.Colors.inputBackground
        mcpKeystorePassword.foreground = UiTheme.Colors.inputForeground

        promptRequest.toolTipText = "Find vulnerabilities in the selected request/response."
        promptSummary.toolTipText = "Endpoint summary for analysis."
        promptJs.toolTipText = "Explain JavaScript behavior and risk."
        promptAccessControl.toolTipText = "Access control test plan."
        promptLoginSequence.toolTipText = "Login sequence draft."
        promptIssueAnalyze.toolTipText = "Analyze the issue and explain evidence and risk."
        promptIssuePoc.toolTipText = "Generate PoC steps and validation guidance."
        promptIssueImpact.toolTipText = "Assess impact and severity."
        promptIssueFull.toolTipText = "Full vulnerability report for an issue."
        mcpMaxConcurrent.font = UiTheme.Typography.body
        mcpMaxBodyMb.font = UiTheme.Typography.body
        mcpMaxBodyMb.toolTipText = "Maximum MCP response body size per item (MB)."
        mcpTlsEnabled.font = UiTheme.Typography.body
        mcpTlsAuto.font = UiTheme.Typography.body
        mcpExternal.font = UiTheme.Typography.body
        mcpEnabled.font = UiTheme.Typography.body
        mcpStdio.font = UiTheme.Typography.body
        mcpUnsafe.font = UiTheme.Typography.body
        mcpUnsafe.toolTipText = "Allows tools that modify Burp state, write files, or send active requests."
        privacyWarning.font = UiTheme.Typography.body
        privacyWarning.foreground = UiTheme.Colors.onPrimary
        privacyWarning.background = UiTheme.Colors.statusCrashed
        privacyWarning.border = EmptyBorder(6, 8, 6, 8)
        privacyWarning.isOpaque = true
        privacyWarning.isVisible = settings.privacyMode == PrivacyMode.OFF
        privacyActiveWarning.font = UiTheme.Typography.body
        privacyActiveWarning.foreground = UiTheme.Colors.onPrimary
        privacyActiveWarning.background = UiTheme.Colors.statusTerminal
        privacyActiveWarning.border = EmptyBorder(6, 8, 6, 8)
        privacyActiveWarning.isOpaque = true
        privacyActiveWarning.isVisible = settings.privacyMode == PrivacyMode.STRICT && settings.activeAiEnabled

        val backendBody = JPanel(BorderLayout()).apply {
            background = UiTheme.Colors.surface
        }
        val backendSection = AccordionPanel(
            title = "🤖 AI Backend",
            subtitle = "Select the default backend and configure its connection.",
            content = backendBody,
            initiallyExpanded = false
        ).apply {
            backendBody.add(backendConfigPanel, BorderLayout.CENTER)
            val profileGrid = formGrid()
            addRowFull(profileGrid, "Agent profile", profilePicker)
            backendBody.add(profileGrid, BorderLayout.NORTH)
        }
        val privacyBody = JPanel(BorderLayout()).apply {
            background = UiTheme.Colors.surface
        }
        val privacySection = AccordionPanel(
            title = "🔒 Privacy & Logging",
            subtitle = "Controls redaction and stable ordering of context.",
            content = privacyBody,
            initiallyExpanded = false
        ).apply {
            val grid = formGrid()
            addRowFull(grid, "Privacy mode", privacyMode)
            addSpacerRow(grid, 4)
            addRowFull(grid, "Audit logging", auditEnabled)
            addSpacerRow(grid, 4)
            addRowFull(grid, "Auto-restart", autoRestart)
            addSpacerRow(grid, 4)
            addRowFull(grid, "Determinism mode", determinism)
            addSpacerRow(grid, 4)
            addRowFull(grid, "Anonymization", rotateSaltBtn)
            addSpacerRow(grid, 8)
            addRowFull(grid, "Privacy warning", privacyWarning)
            addSpacerRow(grid, 4)
            addRowFull(grid, "Active scan warning", privacyActiveWarning)
            privacyBody.add(grid, BorderLayout.CENTER)
        }
        val burpIntegrationBody = JPanel(BorderLayout()).apply {
            background = UiTheme.Colors.surface
        }
        burpIntegrationBody.add(buildMcpToolsPanel(), BorderLayout.CENTER)
        val burpIntegrationSection = AccordionPanel(
            title = "🔌 Burp Integration",
            subtitle = "Controls how Burp MCP tools are exposed.",
            content = burpIntegrationBody,
            initiallyExpanded = false
        )
        content.add(backendSection)
        content.add(Box.createRigidArea(java.awt.Dimension(0, 8)))
        content.add(passiveAiScannerSection())  // AI Scanner as main feature after backend
        content.add(Box.createRigidArea(java.awt.Dimension(0, 8)))
        content.add(activeAiScannerSection())   // Active Scanner after passive
        content.add(Box.createRigidArea(java.awt.Dimension(0, 8)))
        content.add(mcpSection())
        content.add(Box.createRigidArea(java.awt.Dimension(0, 8)))
        content.add(privacySection)
        content.add(Box.createRigidArea(java.awt.Dimension(0, 8)))
        content.add(burpIntegrationSection)
        content.add(Box.createRigidArea(java.awt.Dimension(0, 8)))
        content.add(promptSection())
        content.add(Box.createRigidArea(java.awt.Dimension(0, 6)))
        content.add(helpSection())

        preferredBackend.addActionListener {
            backendConfigPanel.setBackend(preferredBackendId())
        }
        privacyMode.addActionListener {
            updatePrivacyWarnings()
        }
        mcpExternal.addActionListener {
            updateMcpTlsState()
        }
        mcpTlsEnabled.addActionListener {
            updateMcpTlsState()
        }
        mcpTlsAuto.addActionListener {
            updateMcpTlsState()
        }
        mcpEnabled.addActionListener {
            onMcpEnabledChanged?.invoke(mcpEnabled.isSelected)
        }
        mcpUnsafe.addActionListener {
            updateUnsafeToolStates()
        }
        mcpTokenRegenerate.addActionListener {
            mcpToken.text = McpSettings.generateToken()
        }
        rotateSaltBtn.addActionListener {
            val newSalt = McpSettings.generateToken()
            settings = settings.copy(hostAnonymizationSalt = newSalt)
            rotateSaltBtn.toolTipText = "Rotates the salt used for host anonymization (e.g. host-xxxxxx.local). Current: ${newSalt.take(8)}..."
            JOptionPane.showMessageDialog(panel, "Salt rotated. New anonymized hosts will be different.", "Privacy", JOptionPane.INFORMATION_MESSAGE)
        }
        backendConfigPanel.onOpenCli = { backendId, command ->
            openExternalCli(backendId, command)
        }
        backendConfigPanel.setBackend(preferredBackendId())
        updateMcpTlsState()
        updatePrivacyWarnings()
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
                    panel,
                    "⚠️ DANGEROUS mode may modify or delete data. Only use in authorized test environments.",
                    "Active Scanner Warning",
                    JOptionPane.WARNING_MESSAGE
                )
            }
        }
        activeAiScanModeCombo.addActionListener {
            applyActiveAiSettings()
        }
        activeAiUseCollaborator.addActionListener {
            applyActiveAiSettings()
        }
        activeAiViewFindings.addActionListener {
            showActiveAiFindingsDialog()
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
        val statusRefreshTimer = javax.swing.Timer(2000) {
            refreshPassiveAiStatus()
            refreshActiveAiStatus()
        }
        statusRefreshTimer.start()

        val save = JButton("Save settings")
        save.font = UiTheme.Typography.label
        save.background = UiTheme.Colors.primary
        save.foreground = UiTheme.Colors.onPrimary
        save.isOpaque = true
        save.border = EmptyBorder(8, 14, 8, 14)
        save.isFocusPainted = false
        save.addActionListener {
            applyAndSaveSettings(currentSettings())
        }

        val restoreDefaults = JButton("Restore defaults")
        restoreDefaults.font = UiTheme.Typography.label
        restoreDefaults.background = UiTheme.Colors.surface
        restoreDefaults.foreground = UiTheme.Colors.primary
        restoreDefaults.isOpaque = true
        restoreDefaults.border = LineBorder(UiTheme.Colors.outline, 1, true)
        restoreDefaults.isFocusPainted = false
        restoreDefaults.addActionListener {
            val confirmed = JOptionPane.showConfirmDialog(
                panel,
                "Restore default settings? This will overwrite current values.",
                "Restore defaults",
                JOptionPane.YES_NO_OPTION
            )
            if (confirmed != JOptionPane.YES_OPTION) return@addActionListener
            val defaults = settingsRepo.defaultSettings()
            applySettingsToUi(defaults)
            applyAndSaveSettings(defaults)
        }

        val scroll = JScrollPane(content)
        scroll.border = EmptyBorder(0, 0, 0, 0)
        scroll.viewport.background = UiTheme.Colors.surface
        panel.add(scroll, BorderLayout.CENTER)

        val footer = JPanel(java.awt.FlowLayout(java.awt.FlowLayout.CENTER, 12, 0))
        footer.border = EmptyBorder(6, 12, 10, 12)
        footer.background = UiTheme.Colors.surface
        footer.add(save)
        footer.add(restoreDefaults)
        panel.add(footer, BorderLayout.SOUTH)
    }

    fun panelComponent() = panel

    fun setPreferredBackend(value: String) {
        preferredBackend.selectedItem = value
        backendConfigPanel.setBackend(preferredBackendId())
    }

    fun preferredBackendId(): String {
        return preferredBackend.selectedItem as? String ?: "codex-cli"
    }

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
        val mcpSettings = McpSettings(
            enabled = mcpEnabled.isSelected,
            host = mcpHost.text.trim().ifBlank { "127.0.0.1" },
            port = (mcpPort.value as? Int) ?: 9876,
            externalEnabled = mcpExternal.isSelected,
            stdioEnabled = mcpStdio.isSelected,
            token = mcpToken.text.trim(),
            tlsEnabled = mcpTlsEnabled.isSelected,
            tlsAutoGenerate = mcpTlsAuto.isSelected,
            tlsKeystorePath = mcpKeystorePath.text.trim(),
            tlsKeystorePassword = String(mcpKeystorePassword.password),
            maxConcurrentRequests = (mcpMaxConcurrent.value as? Int) ?: 4,
            maxBodyBytes = ((mcpMaxBodyMb.value as? Int) ?: 2).coerceAtLeast(1) * 1024 * 1024,
            toolToggles = collectMcpToolToggles(),
            unsafeEnabled = mcpUnsafe.isSelected
        )
        val backendState = backendConfigPanel.currentBackendSettings()
        val lmStudioTimeoutSeconds = parseTimeoutSeconds(
            backendState.lmStudioTimeoutSeconds,
            settings.lmStudioTimeoutSeconds
        )
        val openAiCompatTimeoutSeconds = parseTimeoutSeconds(
            backendState.openAiCompatTimeoutSeconds,
            settings.openAiCompatibleTimeoutSeconds
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
            passiveAiEnabled = passiveAiEnabled.isSelected,
            passiveAiRateSeconds = (passiveAiRateSpinner.value as? Int) ?: 5,
            passiveAiScopeOnly = passiveAiScopeOnly.isSelected,
            passiveAiMaxSizeKb = (passiveAiMaxSizeSpinner.value as? Int) ?: 96,
            passiveAiMinSeverity = passiveAiMinSeverityCombo.selectedItem as? String ?: "LOW",
            activeAiEnabled = activeAiEnabled.isSelected,
            activeAiMaxConcurrent = (activeAiMaxConcurrentSpinner.value as? Int) ?: 3,
            activeAiMaxPayloadsPerPoint = (activeAiMaxPayloadsSpinner.value as? Int) ?: 10,
            activeAiTimeoutSeconds = (activeAiTimeoutSpinner.value as? Int) ?: 30,
            activeAiRequestDelayMs = (activeAiDelaySpinner.value as? Int) ?: 100,
            activeAiMaxRiskLevel = activeAiRiskLevelCombo.selectedItem as? String ?: "SAFE",
            activeAiScopeOnly = activeAiScopeOnly.isSelected,
            activeAiAutoFromPassive = activeAiAutoFromPassive.isSelected,
            activeAiScanMode = activeAiScanModeCombo.selectedItem as? String ?: "FULL",
            activeAiUseCollaborator = activeAiUseCollaborator.isSelected
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
                openAiCompatTimeoutSeconds = updated.openAiCompatibleTimeoutSeconds.toString()
            )
        )
        profilePicker.selectedItem = updated.agentProfile
        privacyMode.selectedItem = updated.privacyMode
        determinism.isSelected = updated.determinismMode
        autoRestart.isSelected = updated.autoRestart
        auditEnabled.isSelected = updated.auditEnabled
        promptRequest.text = updated.requestPromptTemplate
        promptIssueFull.text = updated.issuePromptTemplate
        promptIssueAnalyze.text = updated.issueAnalyzePrompt
        promptIssuePoc.text = updated.issuePocPrompt
        promptIssueImpact.text = updated.issueImpactPrompt
        promptSummary.text = updated.requestSummaryPrompt
        promptJs.text = updated.explainJsPrompt
        promptAccessControl.text = updated.accessControlPrompt
        promptLoginSequence.text = updated.loginSequencePrompt

        mcpEnabled.isSelected = updated.mcpSettings.enabled
        mcpHost.text = updated.mcpSettings.host
        mcpPort.value = updated.mcpSettings.port
        mcpExternal.isSelected = updated.mcpSettings.externalEnabled
        mcpStdio.isSelected = updated.mcpSettings.stdioEnabled
        mcpToken.text = updated.mcpSettings.token
        mcpTlsEnabled.isSelected = updated.mcpSettings.tlsEnabled
        mcpTlsAuto.isSelected = updated.mcpSettings.tlsAutoGenerate
        mcpKeystorePath.text = updated.mcpSettings.tlsKeystorePath
        mcpKeystorePassword.text = updated.mcpSettings.tlsKeystorePassword
        mcpMaxConcurrent.value = updated.mcpSettings.maxConcurrentRequests
        mcpMaxBodyMb.value = (updated.mcpSettings.maxBodyBytes / (1024 * 1024)).coerceAtLeast(1)
        mcpUnsafe.isSelected = updated.mcpSettings.unsafeEnabled
        applyMcpToolToggles(updated.mcpSettings.toolToggles)

        privacyWarning.isVisible = updated.privacyMode == PrivacyMode.OFF
        updatePrivacyWarnings()
        backendConfigPanel.setBackend(preferredBackendId())
        updateMcpTlsState()
        updateUnsafeToolStates()
        
        // Passive AI Scanner settings
        passiveAiEnabled.isSelected = updated.passiveAiEnabled
        passiveAiScopeOnly.isSelected = updated.passiveAiScopeOnly
        passiveAiRateSpinner.value = updated.passiveAiRateSeconds
        passiveAiMaxSizeSpinner.value = updated.passiveAiMaxSizeKb
        passiveAiMinSeverityCombo.selectedItem = updated.passiveAiMinSeverity
        refreshPassiveAiStatus()
        
        // Active AI Scanner settings
        activeAiEnabled.isSelected = updated.activeAiEnabled
        activeAiScopeOnly.isSelected = updated.activeAiScopeOnly
        activeAiAutoFromPassive.isSelected = updated.activeAiAutoFromPassive
        activeAiMaxConcurrentSpinner.value = updated.activeAiMaxConcurrent
        activeAiMaxPayloadsSpinner.value = updated.activeAiMaxPayloadsPerPoint
        activeAiTimeoutSpinner.value = updated.activeAiTimeoutSeconds
        activeAiDelaySpinner.value = updated.activeAiRequestDelayMs
        activeAiRiskLevelCombo.selectedItem = updated.activeAiMaxRiskLevel
        activeAiScanModeCombo.selectedItem = updated.activeAiScanMode
        activeAiUseCollaborator.isSelected = updated.activeAiUseCollaborator
        updateActiveRiskDescription()
        refreshActiveAiStatus()
        onMcpEnabledChanged?.invoke(updated.mcpSettings.enabled)
        onPassiveAiEnabledChanged?.invoke(updated.passiveAiEnabled)
        onActiveAiEnabledChanged?.invoke(updated.activeAiEnabled)
    }

    private fun parseTimeoutSeconds(raw: String, fallback: Int): Int {
        val parsed = raw.trim().toIntOrNull() ?: return fallback.coerceIn(30, 3600)
        return parsed.coerceIn(30, 3600)
    }

    private fun applyAndSaveSettings(updated: AgentSettings) {
        settings = updated
        settingsRepo.save(updated)
        AgentProfileLoader.setActiveProfile(updated.agentProfile)
        backends.reload()
        supervisor.applySettings(updated)
        audit.setEnabled(updated.auditEnabled)
        mcpSupervisor.applySettings(updated.mcpSettings, updated.privacyMode, updated.determinismMode)
        
        // Apply passive AI scanner settings
        passiveAiScanner.rateLimitSeconds = updated.passiveAiRateSeconds
        passiveAiScanner.scopeOnly = updated.passiveAiScopeOnly
        passiveAiScanner.maxSizeKb = updated.passiveAiMaxSizeKb
        passiveAiScanner.setEnabled(updated.passiveAiEnabled)
        
        // Apply active AI scanner settings
        activeAiScanner.maxConcurrent = updated.activeAiMaxConcurrent
        activeAiScanner.maxPayloadsPerPoint = updated.activeAiMaxPayloadsPerPoint
        activeAiScanner.timeoutSeconds = updated.activeAiTimeoutSeconds
        activeAiScanner.requestDelayMs = updated.activeAiRequestDelayMs.toLong()
        activeAiScanner.maxRiskLevel = com.six2dez.burp.aiagent.scanner.PayloadRisk.fromString(updated.activeAiMaxRiskLevel)
        activeAiScanner.scopeOnly = updated.activeAiScopeOnly
        activeAiScanner.scanMode = com.six2dez.burp.aiagent.scanner.ScanMode.fromString(updated.activeAiScanMode)
        activeAiScanner.useCollaborator = updated.activeAiUseCollaborator
        activeAiScanner.setEnabled(updated.activeAiEnabled)
        
        api.logging().logToOutput("AI Agent settings saved.")
        refreshPassiveAiStatus()
        refreshActiveAiStatus()
    }

    private fun applyMcpToolToggles(toggles: Map<String, Boolean>) {
        val effective = McpToolCatalog.mergeWithDefaults(toggles)
        mcpToolCheckboxes.forEach { (id, checkbox) ->
            checkbox.isSelected = effective[id] ?: false
        }
    }

    private fun formGrid(): JPanel {
        val grid = JPanel(GridBagLayout())
        grid.background = UiTheme.Colors.surface
        grid.border = EmptyBorder(2, 0, 6, 0)
        return grid
    }

    private fun addRowFull(grid: JPanel, labelText: String, field: JComponent) {
        val row = nextRow(grid)
        val c = GridBagConstraints()
        c.gridx = 0
        c.gridy = row
        c.anchor = GridBagConstraints.WEST
        c.insets = Insets(3, 8, 3, 8)
        val label = JLabel(labelText)
        label.font = UiTheme.Typography.body
        label.foreground = UiTheme.Colors.onSurface
        grid.add(label, c)

        val c2 = GridBagConstraints()
        c2.gridx = 1
        c2.gridy = row
        c2.gridwidth = 3
        c2.weightx = 1.0
        c2.insets = Insets(3, 0, 3, 8)
        
        // Don't expand small components (spinners, combos, small text fields)
        val isSmallComponent = field is JSpinner || field is JComboBox<*> || field is JCheckBox || field is ToggleSwitch ||
            (field is JTextField && field.columns <= 20)
        
        if (isSmallComponent) {
            c2.anchor = GridBagConstraints.WEST
            c2.fill = GridBagConstraints.NONE
        } else {
            c2.fill = GridBagConstraints.HORIZONTAL
        }
        grid.add(field, c2)
    }

    private fun addRowPair(
        grid: JPanel,
        leftLabel: String,
        leftField: JComponent,
        rightLabel: String,
        rightField: JComponent
    ) {
        val row = nextRow(grid)

        val c1 = GridBagConstraints()
        c1.gridx = 0
        c1.gridy = row
        c1.anchor = GridBagConstraints.WEST
        c1.insets = Insets(3, 8, 3, 8)
        val left = JLabel(leftLabel)
        left.font = UiTheme.Typography.body
        left.foreground = UiTheme.Colors.onSurface
        grid.add(left, c1)

        val c2 = GridBagConstraints()
        c2.gridx = 1
        c2.gridy = row
        c2.weightx = 0.5
        c2.insets = Insets(3, 0, 3, 12)
        
        val isLeftSmall = leftField is JSpinner || leftField is JComboBox<*> || leftField is JCheckBox || leftField is ToggleSwitch ||
            (leftField is JTextField && leftField.columns <= 20)
        if (isLeftSmall) {
            c2.anchor = GridBagConstraints.WEST
            c2.fill = GridBagConstraints.NONE
        } else {
            c2.fill = GridBagConstraints.HORIZONTAL
        }
        grid.add(leftField, c2)

        val c3 = GridBagConstraints()
        c3.gridx = 2
        c3.gridy = row
        c3.anchor = GridBagConstraints.WEST
        c3.insets = Insets(3, 8, 3, 8)
        val right = JLabel(rightLabel)
        right.font = UiTheme.Typography.body
        right.foreground = UiTheme.Colors.onSurface
        grid.add(right, c3)

        val c4 = GridBagConstraints()
        c4.gridx = 3
        c4.gridy = row
        c4.weightx = 0.5
        c4.insets = Insets(3, 0, 3, 8)
        
        val isRightSmall = rightField is JSpinner || rightField is JComboBox<*> || rightField is JCheckBox || rightField is ToggleSwitch ||
            (rightField is JTextField && rightField.columns <= 20)
        if (isRightSmall) {
            c4.anchor = GridBagConstraints.WEST
            c4.fill = GridBagConstraints.NONE
        } else {
            c4.fill = GridBagConstraints.HORIZONTAL
        }
        grid.add(rightField, c4)
    }

    private fun nextRow(grid: JPanel): Int {
        val row = (grid.getClientProperty("row") as? Int) ?: 0
        grid.putClientProperty("row", row + 1)
        return row
    }

    private fun addSpacerRow(grid: JPanel, height: Int) {
        val row = nextRow(grid)
        val c = GridBagConstraints()
        c.gridx = 0
        c.gridy = row
        c.gridwidth = 4
        c.weightx = 1.0
        c.fill = GridBagConstraints.HORIZONTAL
        c.insets = Insets(0, 0, 0, 0)
        grid.add(Box.createRigidArea(java.awt.Dimension(0, height)), c)
    }

    private fun helpSection(): JPanel {
        val body = JPanel(BorderLayout())
        body.background = UiTheme.Colors.surface
        body.border = EmptyBorder(6, 8, 8, 8)
        val helpHtml = """
            <html>
              <body style="font-family: sans-serif; font-size: 12px;">
                <b>Burp AI Agent - Quick Start</b><br/>
                1. Toggle MCP on in the top bar.<br/>
                2. Select your AI backend.<br/>
                3. Right-click requests/issues for AI analysis.<br/>
                4. Enable passive/active scanners for automated testing.<br/><br/>
                <b>Full documentation:</b>
                <a href="https://burp-ai-agent.six2dez.com/">Plugin Documentation</a><br/><br/>
                <b>Privacy:</b> STRICT (hosts anonymized) | BALANCED (hosts visible) | OFF (raw data)
              </body>
            </html>
        """.trimIndent()
        val helpPane = JEditorPane("text/html", helpHtml)
        helpPane.isEditable = false
        helpPane.isOpaque = false
        helpPane.border = EmptyBorder(6, 8, 8, 8)
        helpPane.addHyperlinkListener { event ->
            if (event.eventType == javax.swing.event.HyperlinkEvent.EventType.ACTIVATED) {
                try {
                    if (java.awt.Desktop.isDesktopSupported()) {
                        java.awt.Desktop.getDesktop().browse(event.url.toURI())
                    } else {
                        JOptionPane.showMessageDialog(panel, "Open this URL in your browser: ${event.url}", "Help", JOptionPane.INFORMATION_MESSAGE)
                    }
                } catch (_: Exception) {
                    JOptionPane.showMessageDialog(panel, "Open this URL in your browser: ${event.url}", "Help", JOptionPane.INFORMATION_MESSAGE)
                }
            }
        }
        body.add(helpPane, BorderLayout.CENTER)

        return AccordionPanel(
            title = "❓ Help",
            subtitle = "Quick start and documentation links.",
            content = body,
            initiallyExpanded = false
        )
    }

    private fun passiveAiScannerSection(): JPanel {
        val body = JPanel(BorderLayout())
        body.background = UiTheme.Colors.surface
        body.border = EmptyBorder(6, 8, 8, 8)

        // Style components
        passiveAiEnabled.font = UiTheme.Typography.body
        passiveAiEnabled.background = UiTheme.Colors.surface
        passiveAiEnabled.foreground = UiTheme.Colors.onSurface
        passiveAiEnabled.toolTipText = "Automatically analyze proxy traffic using AI and create Burp issues for findings."

        passiveAiScopeOnly.font = UiTheme.Typography.body
        passiveAiScopeOnly.background = UiTheme.Colors.surface
        passiveAiScopeOnly.foreground = UiTheme.Colors.onSurface
        passiveAiScopeOnly.toolTipText = "Only analyze requests that are in the defined target scope."

        passiveAiRateSpinner.font = UiTheme.Typography.body
        passiveAiRateSpinner.toolTipText = "Minimum seconds between AI analyses (rate limiting)."

        passiveAiMaxSizeSpinner.font = UiTheme.Typography.body
        passiveAiMaxSizeSpinner.toolTipText = "Maximum response size in KB to analyze."

        passiveAiMinSeverityCombo.font = UiTheme.Typography.body
        passiveAiMinSeverityCombo.background = UiTheme.Colors.surface
        passiveAiMinSeverityCombo.toolTipText = "Only report findings at or above this severity level."

        passiveAiStatusLabel.font = UiTheme.Typography.body
        passiveAiStatusLabel.foreground = UiTheme.Colors.onSurfaceVariant

        passiveAiViewFindings.font = UiTheme.Typography.label
        passiveAiViewFindings.background = UiTheme.Colors.surface
        passiveAiViewFindings.foreground = UiTheme.Colors.primary
        passiveAiViewFindings.border = EmptyBorder(6, 10, 6, 10)
        passiveAiViewFindings.isFocusPainted = false

        scannerTriageButton.font = UiTheme.Typography.label
        scannerTriageButton.background = UiTheme.Colors.surface
        scannerTriageButton.foreground = UiTheme.Colors.primary
        scannerTriageButton.border = EmptyBorder(6, 10, 6, 10)
        scannerTriageButton.isFocusPainted = false

        passiveAiResetStats.font = UiTheme.Typography.label
        passiveAiResetStats.background = UiTheme.Colors.surface
        passiveAiResetStats.foreground = UiTheme.Colors.primary
        passiveAiResetStats.border = LineBorder(UiTheme.Colors.outline, 1, true)
        passiveAiResetStats.isFocusPainted = false

        val grid = formGrid()
        addRowFull(grid, "Enable scanner", passiveAiEnabled)
        addSpacerRow(grid, 4)
        addRowFull(grid, "In-scope only", passiveAiScopeOnly)
        addSpacerRow(grid, 4)
        addRowPair(grid, "Rate limit (sec)", passiveAiRateSpinner, "Max size (KB)", passiveAiMaxSizeSpinner)
        addSpacerRow(grid, 4)
        addRowFull(grid, "Min severity", passiveAiMinSeverityCombo)
        addSpacerRow(grid, 8)
        addRowFull(grid, "Status", passiveAiStatusLabel)
        addSpacerRow(grid, 4)
        
        val actionsPanel = JPanel()
        actionsPanel.layout = javax.swing.BoxLayout(actionsPanel, javax.swing.BoxLayout.X_AXIS)
        actionsPanel.background = UiTheme.Colors.surface
        actionsPanel.add(passiveAiViewFindings)
        actionsPanel.add(Box.createRigidArea(java.awt.Dimension(8, 0)))
        actionsPanel.add(scannerTriageButton)
        actionsPanel.add(Box.createRigidArea(java.awt.Dimension(8, 0)))
        actionsPanel.add(passiveAiResetStats)
        addRowFull(grid, "Actions", actionsPanel)

        body.add(grid, BorderLayout.CENTER)

        return AccordionPanel(
            title = "🔍 AI Passive Scanner",
            subtitle = "Automatically analyze proxy traffic for vulnerabilities (XSS, SQLi, IDOR, BOLA, BAC, etc.)",
            content = body,
            initiallyExpanded = false
        )
    }

    private fun refreshPassiveAiStatus() {
        val status = passiveAiScanner.getStatus()
        val (manualInProgress, manualCompleted, manualTotal) = passiveAiScanner.getManualScanProgress()
        
        val statusText = buildString {
            if (manualInProgress) {
                append("🔄 Manual scan: $manualCompleted/$manualTotal | ")
            }
            if (status.enabled) {
                val lastTime = if (status.lastAnalysisTime > 0) {
                    val formatter = DateTimeFormatter.ofPattern("HH:mm:ss")
                        .withZone(ZoneId.systemDefault())
                    formatter.format(Instant.ofEpochMilli(status.lastAnalysisTime))
                } else "Never"
                append("✅ Passive: ON | Analyzed: ${status.requestsAnalyzed} | Issues: ${status.issuesFound} | Last: $lastTime")
            } else {
                append("⏸️ Passive: OFF")
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
        passiveAiScanner.setEnabled(passiveAiEnabled.isSelected)
        refreshPassiveAiStatus()
    }

    private fun showPassiveAiFindingsDialog() {
        val findings = passiveAiScanner.getLastFindings(20)
        if (findings.isEmpty()) {
            JOptionPane.showMessageDialog(
                panel,
                "No findings yet. Enable the scanner and browse the target to generate findings.",
                "AI Passive Scanner Findings",
                JOptionPane.INFORMATION_MESSAGE
            )
            return
        }

        val sb = StringBuilder()
        sb.append("Recent AI Passive Scanner Findings:\n\n")
        findings.reversed().forEach { finding ->
            val time = java.time.Instant.ofEpochMilli(finding.timestamp)
                .atZone(java.time.ZoneId.systemDefault())
                .format(java.time.format.DateTimeFormatter.ofPattern("HH:mm:ss"))
            sb.append("[$time] ${finding.severity} - ${finding.title}\n")
            sb.append("  URL: ${finding.url}\n")
            sb.append("  Detail: ${finding.detail.take(100)}${if (finding.detail.length > 100) "..." else ""}\n")
            sb.append("  Confidence: ${finding.confidence}% | Source: ${finding.source}")
            if (!finding.issueCreated) sb.append(" | Not created as issue")
            sb.append("\n\n")
        }

        val textArea = JTextArea(sb.toString())
        textArea.isEditable = false
        textArea.font = UiTheme.Typography.mono
        textArea.rows = 20
        textArea.columns = 60

        JOptionPane.showMessageDialog(
            panel,
            JScrollPane(textArea),
            "AI Passive Scanner Findings (${findings.size} recent)",
            JOptionPane.PLAIN_MESSAGE
        )
    }

    private fun showActiveAiFindingsDialog() {
        val findings = activeAiScanner.getRecentConfirmations(20)
        if (findings.isEmpty()) {
            JOptionPane.showMessageDialog(
                panel,
                "No active confirmations yet. Run active scans to generate findings.",
                "AI Active Scanner Findings",
                JOptionPane.INFORMATION_MESSAGE
            )
            return
        }

        val sb = StringBuilder()
        sb.append("Recent AI Active Scanner Confirmations:\n\n")
        findings.reversed().forEach { finding ->
            val time = java.time.Instant.ofEpochMilli(finding.timestamp)
                .atZone(java.time.ZoneId.systemDefault())
                .format(java.time.format.DateTimeFormatter.ofPattern("HH:mm:ss"))
            sb.append("[$time] ${finding.severity} - ${finding.title}\n")
            sb.append("  URL: ${finding.url}\n")
            sb.append("  Confidence: ${finding.confidence}%\n")
            sb.append("  Detail: ${finding.detail.take(120)}${if (finding.detail.length > 120) "..." else ""}\n\n")
        }

        val textArea = JTextArea(sb.toString())
        textArea.isEditable = false
        textArea.font = UiTheme.Typography.mono
        textArea.rows = 20
        textArea.columns = 60

        JOptionPane.showMessageDialog(
            panel,
            JScrollPane(textArea),
            "AI Active Scanner Findings (${findings.size} recent)",
            JOptionPane.PLAIN_MESSAGE
        )
    }

    private fun showScannerTriageDialog() {
        val passiveFindings = passiveAiScanner.getLastFindings(50)
        val activeFindings = activeAiScanner.getRecentConfirmations(50)
        if (passiveFindings.isEmpty() && activeFindings.isEmpty()) {
            JOptionPane.showMessageDialog(
                panel,
                "No findings yet. Run passive or active scans to populate triage.",
                "Scanner Triage",
                JOptionPane.INFORMATION_MESSAGE
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
            val detail: String
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
                    detail = first.detail
                )
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
                    detail = first.detail
                )
            )
        }

        val sorted = entries.sortedWith(
            compareByDescending<TriageEntry> { severityRank(it.severity) }
                .thenByDescending { it.confidence }
                .thenByDescending { it.lastSeen }
        )

        val sb = StringBuilder()
        sb.append("Scanner Triage Summary:\n\n")
        sorted.forEach { entry ->
            val time = java.time.Instant.ofEpochMilli(entry.lastSeen)
                .atZone(java.time.ZoneId.systemDefault())
                .format(java.time.format.DateTimeFormatter.ofPattern("HH:mm:ss"))
            sb.append("[${entry.severity}] ${entry.title} (${entry.source}) x${entry.count}\n")
            sb.append("  URL: ${entry.url}\n")
            sb.append("  Confidence: ${entry.confidence}% | Last seen: $time\n")
            sb.append("  Detail: ${entry.detail.take(120)}${if (entry.detail.length > 120) "..." else ""}\n\n")
        }

        val textArea = JTextArea(sb.toString())
        textArea.isEditable = false
        textArea.font = UiTheme.Typography.mono
        textArea.rows = 24
        textArea.columns = 70

        JOptionPane.showMessageDialog(
            panel,
            JScrollPane(textArea),
            "Scanner Triage (${sorted.size} grouped findings)",
            JOptionPane.PLAIN_MESSAGE
        )
    }

    private fun severityRank(severity: String): Int {
        return when (severity.uppercase()) {
            "CRITICAL" -> 4
            "HIGH" -> 3
            "MEDIUM" -> 2
            "LOW" -> 1
            else -> 0
        }
    }

    private fun activeAiScannerSection(): JPanel {
        val body = JPanel(BorderLayout())
        body.background = UiTheme.Colors.surface
        body.border = EmptyBorder(6, 8, 8, 8)

        // Style components
        activeAiEnabled.font = UiTheme.Typography.body
        activeAiEnabled.background = UiTheme.Colors.surface
        activeAiEnabled.foreground = UiTheme.Colors.onSurface
        activeAiEnabled.toolTipText = "Enable active testing to confirm vulnerabilities detected by passive scanning."

        activeAiScopeOnly.font = UiTheme.Typography.body
        activeAiScopeOnly.background = UiTheme.Colors.surface
        activeAiScopeOnly.foreground = UiTheme.Colors.onSurface
        activeAiScopeOnly.toolTipText = "Only test requests that are in the defined target scope."

        activeAiAutoFromPassive.font = UiTheme.Typography.body
        activeAiAutoFromPassive.background = UiTheme.Colors.surface
        activeAiAutoFromPassive.foreground = UiTheme.Colors.onSurface
        activeAiAutoFromPassive.toolTipText = "Automatically queue passive scanner findings for active testing."

        activeAiMaxConcurrentSpinner.font = UiTheme.Typography.body
        activeAiMaxConcurrentSpinner.toolTipText = "Maximum number of concurrent active scans."

        activeAiMaxPayloadsSpinner.font = UiTheme.Typography.body
        activeAiMaxPayloadsSpinner.toolTipText = "Maximum payloads to test per injection point."

        activeAiTimeoutSpinner.font = UiTheme.Typography.body
        activeAiTimeoutSpinner.toolTipText = "Request timeout in seconds."

        activeAiDelaySpinner.font = UiTheme.Typography.body
        activeAiDelaySpinner.toolTipText = "Delay between requests in milliseconds (rate limiting)."

        activeAiRiskLevelCombo.font = UiTheme.Typography.body
        activeAiRiskLevelCombo.background = UiTheme.Colors.surface
        activeAiRiskLevelCombo.toolTipText = "SAFE: read-only tests. MODERATE: may read data. DANGEROUS: may modify data."

        activeAiRiskDescription.font = UiTheme.Typography.body
        activeAiRiskDescription.foreground = UiTheme.Colors.onSurfaceVariant

        activeAiScanModeCombo.font = UiTheme.Typography.body
        activeAiScanModeCombo.background = UiTheme.Colors.surface
        activeAiScanModeCombo.toolTipText = "BUG_BOUNTY: high-impact only. PENTEST: broad coverage. FULL: all classes."

        activeAiUseCollaborator.font = UiTheme.Typography.body
        activeAiUseCollaborator.background = UiTheme.Colors.surface
        activeAiUseCollaborator.foreground = UiTheme.Colors.onSurface
        activeAiUseCollaborator.toolTipText = "Use Burp Collaborator for SSRF confirmation (out-of-band)."

        activeAiStatusLabel.font = UiTheme.Typography.body
        activeAiStatusLabel.foreground = UiTheme.Colors.onSurfaceVariant

        activeAiViewFindings.font = UiTheme.Typography.label
        activeAiViewFindings.background = UiTheme.Colors.surface
        activeAiViewFindings.foreground = UiTheme.Colors.primary
        activeAiViewFindings.border = EmptyBorder(6, 10, 6, 10)
        activeAiViewFindings.isFocusPainted = false

        activeAiClearQueue.font = UiTheme.Typography.label
        activeAiClearQueue.background = UiTheme.Colors.surface
        activeAiClearQueue.foreground = UiTheme.Colors.primary
        activeAiClearQueue.border = LineBorder(UiTheme.Colors.outline, 1, true)
        activeAiClearQueue.isFocusPainted = false

        activeAiResetStats.font = UiTheme.Typography.label
        activeAiResetStats.background = UiTheme.Colors.surface
        activeAiResetStats.foreground = UiTheme.Colors.primary
        activeAiResetStats.border = LineBorder(UiTheme.Colors.outline, 1, true)
        activeAiResetStats.isFocusPainted = false

        val grid = formGrid()
        addRowFull(grid, "Enable scanner", activeAiEnabled)
        addSpacerRow(grid, 4)
        addRowFull(grid, "In-scope only", activeAiScopeOnly)
        addSpacerRow(grid, 4)
        addRowFull(grid, "Auto-queue findings", activeAiAutoFromPassive)
        addSpacerRow(grid, 4)
        addRowPair(grid, "Concurrent scans", activeAiMaxConcurrentSpinner, "Max payloads", activeAiMaxPayloadsSpinner)
        addSpacerRow(grid, 4)
        addRowPair(grid, "Timeout (sec)", activeAiTimeoutSpinner, "Delay (ms)", activeAiDelaySpinner)
        addSpacerRow(grid, 4)
        addRowPair(grid, "Max risk level", activeAiRiskLevelCombo, "Scan mode", activeAiScanModeCombo)
        addSpacerRow(grid, 4)
        addRowFull(grid, "Risk level details", activeAiRiskDescription)
        addSpacerRow(grid, 4)
        addRowFull(grid, "SSRF OAST", activeAiUseCollaborator)
        addSpacerRow(grid, 8)
        addRowFull(grid, "Status", activeAiStatusLabel)
        addSpacerRow(grid, 4)

        val actionsPanel = JPanel()
        actionsPanel.layout = javax.swing.BoxLayout(actionsPanel, javax.swing.BoxLayout.X_AXIS)
        actionsPanel.background = UiTheme.Colors.surface
        actionsPanel.add(activeAiViewFindings)
        actionsPanel.add(Box.createRigidArea(java.awt.Dimension(8, 0)))
        actionsPanel.add(activeAiClearQueue)
        actionsPanel.add(Box.createRigidArea(java.awt.Dimension(8, 0)))
        actionsPanel.add(activeAiResetStats)
        addRowFull(grid, "Actions", actionsPanel)

        body.add(grid, BorderLayout.CENTER)

        return AccordionPanel(
            title = "⚡ AI Active Scanner",
            subtitle = "Confirm vulnerabilities by sending test payloads (SQLi, XSS, LFI, CMDI, SSRF, etc.)",
            content = body,
            initiallyExpanded = false
        )
    }

    private fun updateActiveRiskDescription() {
        val level = (activeAiRiskLevelCombo.selectedItem as? String ?: "SAFE").uppercase()
        activeAiRiskDescription.text = when (level) {
            "SAFE" -> "Read-only payloads. No data modified. Safe for bug bounty."
            "MODERATE" -> "May read sensitive data. Could trigger IDS/WAF."
            "DANGEROUS" -> "May modify or delete data. Only for authorized pentests."
            else -> "Risk level not recognized."
        }
    }

    private fun refreshActiveAiStatus() {
        val status = activeAiScanner.getStatus()
        val statusText = buildString {
            if (status.enabled) {
                append("✅ Active: ON")
                if (status.scanning) {
                    append(" | 🔄 Scanning")
                    status.currentTarget?.let { target ->
                        append(" (${target.take(40)}...)")
                    }
                }
                append(" | Queue: ${status.queueSize}")
                append(" | Scans: ${status.scansCompleted}")
                append(" | Confirmed: ${status.vulnsConfirmed}")
            } else {
                append("⏸️ Active: OFF")
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
        activeAiScanner.maxRiskLevel = com.six2dez.burp.aiagent.scanner.PayloadRisk.fromString(
            activeAiRiskLevelCombo.selectedItem as? String ?: "SAFE"
        )
        activeAiScanner.scopeOnly = activeAiScopeOnly.isSelected
        activeAiScanner.scanMode = com.six2dez.burp.aiagent.scanner.ScanMode.fromString(
            activeAiScanModeCombo.selectedItem as? String ?: "FULL"
        )
        activeAiScanner.useCollaborator = activeAiUseCollaborator.isSelected
        activeAiScanner.setEnabled(activeAiEnabled.isSelected)
        refreshActiveAiStatus()
    }

    private fun promptSection(): JPanel {
        val body = JPanel(BorderLayout())
        body.background = UiTheme.Colors.surface
        body.border = EmptyBorder(6, 8, 8, 8)

        val content = JPanel()
        content.layout = BoxLayout(content, BoxLayout.Y_AXIS)
        content.background = UiTheme.Colors.surface

        val requestTitle = JLabel("Request prompts")
        requestTitle.font = UiTheme.Typography.label
        requestTitle.foreground = UiTheme.Colors.onSurfaceVariant
        requestTitle.border = EmptyBorder(0, 0, 6, 0)
        content.add(requestTitle)

        val requestGrid = formGrid()
        addRowPair(requestGrid, "Find vulnerabilities", JScrollPane(promptRequest), "Analyze this request", JScrollPane(promptSummary))
        addRowPair(requestGrid, "Explain JS", JScrollPane(promptJs), "Access control", JScrollPane(promptAccessControl))
        addRowFull(requestGrid, "Login sequence", JScrollPane(promptLoginSequence))
        content.add(requestGrid)

        val issueTitle = JLabel("Issue prompts")
        issueTitle.font = UiTheme.Typography.label
        issueTitle.foreground = UiTheme.Colors.onSurfaceVariant
        issueTitle.border = EmptyBorder(12, 0, 6, 0)
        content.add(issueTitle)

        val issueGrid = formGrid()
        addRowPair(issueGrid, "Analyze this issue", JScrollPane(promptIssueAnalyze), "Generate PoC & validate", JScrollPane(promptIssuePoc))
        addRowPair(issueGrid, "Impact & severity", JScrollPane(promptIssueImpact), "Full report", JScrollPane(promptIssueFull))
        content.add(issueGrid)

        body.add(content, BorderLayout.CENTER)
        return AccordionPanel(
            title = "📝 Prompt Templates",
            subtitle = "Edit the default prompts used by context actions.",
            content = body,
            initiallyExpanded = false
        )
    }

    private fun mcpSection(): JPanel {
        val body = JPanel(BorderLayout())
        body.background = UiTheme.Colors.surface
        val wrapper = AccordionPanel(
            title = "🌐 MCP Server",
            subtitle = "Built-in MCP server (SSE + optional stdio bridge).",
            content = body,
            initiallyExpanded = false
        )

        val grid = formGrid()
        addRowFull(grid, "Enabled", mcpEnabled)
        addSpacerRow(grid, 4)
        addRowPair(grid, "Host", mcpHost, "Port", mcpPort)
        addSpacerRow(grid, 4)
        addRowPair(grid, "External access", mcpExternal, "Stdio bridge", mcpStdio)
        addSpacerRow(grid, 4)
        addRowPair(grid, "TLS enabled", mcpTlsEnabled, "Auto-generate TLS", mcpTlsAuto)
        addSpacerRow(grid, 4)
        addRowFull(grid, "TLS keystore path", mcpKeystorePath)
        addSpacerRow(grid, 4)
        addRowFull(grid, "TLS keystore password", mcpKeystorePassword)
        addSpacerRow(grid, 4)
        addRowFull(grid, "Token", tokenPanel())
        addSpacerRow(grid, 4)
        addRowFull(grid, "Quick actions", mcpQuickActions())
        addSpacerRow(grid, 4)
        addRowFull(grid, "Max concurrent requests", mcpMaxConcurrent)
        addSpacerRow(grid, 4)
        addRowFull(grid, "Max body size (MB)", mcpMaxBodyMb)
        addSpacerRow(grid, 4)
        addRowFull(grid, "Unsafe mode", mcpUnsafe)
        addSpacerRow(grid, 6)

        val container = JPanel(BorderLayout())
        container.background = UiTheme.Colors.surface
        container.add(grid, BorderLayout.NORTH)
        body.add(container, BorderLayout.CENTER)
        return wrapper
    }

    private fun tokenPanel(): JPanel {
        val panel = JPanel()
        panel.layout = BoxLayout(panel, BoxLayout.X_AXIS)
        panel.background = UiTheme.Colors.surface
        panel.add(mcpToken)
        panel.add(Box.createRigidArea(java.awt.Dimension(8, 0)))
        panel.add(mcpTokenRegenerate)
        return panel
    }

    private fun mcpQuickActions(): JPanel {
        val panel = JPanel()
        panel.layout = BoxLayout(panel, BoxLayout.X_AXIS)
        panel.background = UiTheme.Colors.surface

        val copyUrl = JButton("Copy SSE URL")
        val copyToken = JButton("Copy Token")
        val copyCurl = JButton("Copy curl")

        listOf(copyUrl, copyToken, copyCurl).forEach { btn ->
            btn.font = UiTheme.Typography.label
            btn.isFocusPainted = false
            btn.background = UiTheme.Colors.surface
            btn.foreground = UiTheme.Colors.primary
            btn.border = LineBorder(UiTheme.Colors.outline, 1, true)
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
        val header = if (mcpExternal.isSelected && token.isNotBlank()) {
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

    private fun buildMcpToolsPanel(): JPanel {
        val toolsPanel = JPanel()
        toolsPanel.layout = BoxLayout(toolsPanel, BoxLayout.Y_AXIS)
        toolsPanel.background = UiTheme.Colors.surface
        toolsPanel.border = EmptyBorder(6, 8, 8, 8)

        val selectAll = JButton("Select all").apply {
            font = UiTheme.Typography.label
            background = UiTheme.Colors.surface
            foreground = UiTheme.Colors.primary
            border = LineBorder(UiTheme.Colors.outline, 1, true)
            isFocusPainted = false
        }
        val deselectAll = JButton("Deselect all").apply {
            font = UiTheme.Typography.label
            background = UiTheme.Colors.surface
            foreground = UiTheme.Colors.primary
            border = LineBorder(UiTheme.Colors.outline, 1, true)
            isFocusPainted = false
        }

        val effectiveToggles = McpToolCatalog.mergeWithDefaults(settings.mcpSettings.toolToggles)
        val edition = api.burpSuite().version().edition()
        val unsafeEnabled = mcpUnsafe.isSelected

        McpToolCatalog.all().groupBy { it.category }.forEach { (category, tools) ->
            val label = JLabel(category)
            label.font = UiTheme.Typography.label
            label.foreground = UiTheme.Colors.onSurface
            toolsPanel.add(label)

            val grid = JPanel(java.awt.GridLayout(0, 2, 12, 4))
            grid.background = UiTheme.Colors.surface
            tools.sortedBy { it.title }.forEach { tool ->
                val title = if (tool.unsafeOnly) "${tool.title} (unsafe)" else tool.title
                val checkbox = JCheckBox(title, effectiveToggles[tool.id] ?: false)
                checkbox.font = UiTheme.Typography.body
                checkbox.background = UiTheme.Colors.surface
                checkbox.foreground = UiTheme.Colors.onSurface
                checkbox.putClientProperty("unsafeOnly", tool.unsafeOnly)
                checkbox.putClientProperty("description", tool.description)
                checkbox.toolTipText = if (tool.unsafeOnly) {
                    "${tool.description} Requires unsafe mode."
                } else {
                    tool.description
                }
                if (tool.proOnly && edition != BurpSuiteEdition.PROFESSIONAL) {
                    checkbox.isEnabled = false
                    checkbox.putClientProperty("proDisabled", true)
                    checkbox.toolTipText = "${tool.description} (Pro only)"
                } else {
                    checkbox.putClientProperty("proDisabled", false)
                    checkbox.isEnabled = !tool.unsafeOnly || unsafeEnabled
                }
                mcpToolCheckboxes[tool.id] = checkbox
                grid.add(checkbox)
            }

            toolsPanel.add(grid)
            toolsPanel.add(Box.createRigidArea(java.awt.Dimension(0, 8)))
        }

        selectAll.addActionListener {
            mcpToolCheckboxes.values.forEach { checkbox ->
                if (checkbox.isEnabled) checkbox.isSelected = true
            }
        }
        deselectAll.addActionListener {
            mcpToolCheckboxes.values.forEach { checkbox ->
                if (checkbox.isEnabled) checkbox.isSelected = false
            }
        }

        val scroll = JScrollPane(toolsPanel)
        scroll.border = LineBorder(UiTheme.Colors.outline, 1, true)
        scroll.maximumSize = java.awt.Dimension(Int.MAX_VALUE, 220)
        scroll.preferredSize = java.awt.Dimension(1, 220)
        return JPanel(BorderLayout()).apply {
            background = UiTheme.Colors.surface
            val actions = JPanel()
            actions.layout = BoxLayout(actions, BoxLayout.X_AXIS)
            actions.background = UiTheme.Colors.surface
            actions.add(selectAll)
            actions.add(Box.createRigidArea(java.awt.Dimension(8, 0)))
            actions.add(deselectAll)
            add(actions, BorderLayout.NORTH)
            add(scroll, BorderLayout.CENTER)
        }
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
            checkbox.isEnabled = !unsafeOnly || unsafeEnabled
            val description = checkbox.getClientProperty("description") as? String ?: ""
            checkbox.toolTipText = if (unsafeOnly) {
                if (unsafeEnabled) description else "$description Requires unsafe mode."
            } else {
                description
            }
        }
    }

    private fun updatePrivacyWarnings() {
        val selected = privacyMode.selectedItem as? PrivacyMode ?: PrivacyMode.STRICT
        privacyWarning.isVisible = selected == PrivacyMode.OFF
        privacyActiveWarning.isVisible = selected == PrivacyMode.STRICT && activeAiEnabled.isSelected
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
            if (mcpKeystorePassword.isEnabled) UiTheme.Colors.inputForeground else UiTheme.Colors.onSurfaceVariant
    }

    private fun collectMcpToolToggles(): Map<String, Boolean> {
        return mcpToolCheckboxes.mapValues { it.value.isSelected }
    }

    private fun applyFieldStyle(field: JTextField) {
        field.font = UiTheme.Typography.mono
        field.border = LineBorder(UiTheme.Colors.outline, 1, true)
        field.background = UiTheme.Colors.inputBackground
        field.foreground = UiTheme.Colors.inputForeground
    }

    private fun updateFieldStyle(field: JTextField) {
        val disabled = UiTheme.Colors.inputBackground.darker()
        field.background = if (field.isEnabled) UiTheme.Colors.inputBackground else disabled
        field.foreground = if (field.isEnabled) UiTheme.Colors.inputForeground else UiTheme.Colors.onSurfaceVariant
    }

    private fun applyAreaStyle(area: JTextArea) {
        area.font = UiTheme.Typography.mono
        area.foreground = UiTheme.Colors.inputForeground
        area.background = UiTheme.Colors.inputBackground
        area.border = LineBorder(UiTheme.Colors.outline, 1, true)
        area.lineWrap = true
        area.wrapStyleWord = true
    }

    private fun styleCombo(combo: JComboBox<*>) {
        combo.font = UiTheme.Typography.body
        combo.background = UiTheme.Colors.comboBackground
        combo.foreground = UiTheme.Colors.comboForeground
        combo.border = LineBorder(UiTheme.Colors.outline, 1, true)
    }

    private fun openExternalCli(backendId: String, command: String) {
        if (command.isBlank()) {
            JOptionPane.showMessageDialog(panel, "Command is empty for $backendId.", "AI Agent", JOptionPane.WARNING_MESSAGE)
            return
        }
        try {
            val os = System.getProperty("os.name").lowercase()
            val process = when {
                os.contains("win") -> {
                    ProcessBuilder("cmd.exe", "/c", "start", "\"AI Agent CLI\"", "cmd.exe", "/k", command)
                }
                os.contains("mac") -> {
                    val escaped = command.replace("\\", "\\\\").replace("\"", "\\\"")
                    ProcessBuilder("osascript", "-e", "tell application \"Terminal\" to do script \"$escaped\"")
                }
                else -> {
                    val shellCmd = "x-terminal-emulator -e bash -lc ${shellQuote("$command; exec bash")} " +
                        "|| gnome-terminal -- bash -lc ${shellQuote("$command; exec bash")} " +
                        "|| konsole -e bash -lc ${shellQuote("$command; exec bash")} " +
                        "|| xterm -e bash -lc ${shellQuote("$command; exec bash")}"
                    ProcessBuilder("sh", "-c", shellCmd)
                }
            }
            process.start()
        } catch (e: Exception) {
            api.logging().logToError("Failed to open CLI for $backendId: ${e.message}")
            JOptionPane.showMessageDialog(panel, "Failed to open CLI: ${e.message}", "AI Agent", JOptionPane.ERROR_MESSAGE)
        }
    }

    private fun shellQuote(value: String): String {
        if (value.isEmpty()) return "''"
        if (value.none { it.isWhitespace() || it == '"' || it == '\'' }) return value
        return "'" + value.replace("'", "'\"'\"'") + "'"
    }

}
