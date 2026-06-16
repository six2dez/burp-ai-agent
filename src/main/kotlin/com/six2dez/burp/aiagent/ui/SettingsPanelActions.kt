package com.six2dez.burp.aiagent.ui

import com.six2dez.burp.aiagent.agents.AgentProfileLoader
import com.six2dez.burp.aiagent.backends.HealthCheckResult
import com.six2dez.burp.aiagent.mcp.McpToolCatalog
import com.six2dez.burp.aiagent.redact.PrivacyMode
import com.six2dez.burp.aiagent.ui.components.SubtleNotice
import com.six2dez.burp.aiagent.ui.design.DesignTokens
import com.six2dez.burp.aiagent.ui.panels.CustomPromptsConfigPanel
import com.six2dez.burp.aiagent.ui.panels.HelpConfigPanel
import com.six2dez.burp.aiagent.ui.panels.PrivacyConfigPanel
import com.six2dez.burp.aiagent.ui.panels.PromptConfigPanel
import javax.swing.DefaultComboBoxModel
import javax.swing.JComboBox
import javax.swing.JComponent
import javax.swing.JOptionPane
import javax.swing.JPanel
import javax.swing.JTextField
import javax.swing.SwingUtilities
import javax.swing.border.LineBorder

internal fun SettingsPanel.refreshProfileOptions() {
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

fun SettingsPanel.setDialogParent(component: JComponent) {
    dialogParent = component
}

fun SettingsPanel.generalTabComponent(): JComponent = generalTab

fun SettingsPanel.passiveScannerTabComponent(): JComponent = passiveScannerTab

fun SettingsPanel.activeScannerTabComponent(): JComponent = activeScannerTab

fun SettingsPanel.mcpTabComponent(): JComponent = mcpTab

fun SettingsPanel.burpIntegrationTabComponent(): JComponent = burpIntegrationTab

fun SettingsPanel.promptsTabComponent(): JComponent = promptsTab

fun SettingsPanel.customPromptsTabComponent(): JComponent = customPromptsTab

fun SettingsPanel.privacyTabComponent(): JComponent = privacyTab

fun SettingsPanel.helpTabComponent(): JComponent = helpTab

fun SettingsPanel.updateUsageSummary(
    @Suppress("UNUSED_PARAMETER") stats: ChatPanel.UsageStats,
) {
    // Usage is displayed in sidebar only
}

fun SettingsPanel.saveSettings() {
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

fun SettingsPanel.restoreDefaultsWithConfirmation() {
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

fun SettingsPanel.setPreferredBackend(value: String) {
    preferredBackend.selectedItem = value
    backendConfigPanel.setBackend(preferredBackendId())
}

fun SettingsPanel.preferredBackendId(): String = preferredBackend.selectedItem as? String ?: "codex-cli"

fun SettingsPanel.setMcpEnabled(enabled: Boolean) {
    mcpEnabled.isSelected = enabled
}

fun SettingsPanel.setPassiveAiEnabled(enabled: Boolean) {
    passiveAiEnabled.isSelected = enabled
    applyPassiveAiSettings()
}

fun SettingsPanel.setActiveAiEnabled(enabled: Boolean) {
    activeAiEnabled.isSelected = enabled
    applyActiveAiSettings()
    updatePrivacyWarnings()
}

fun SettingsPanel.shutdown() {
    statusRefreshTimer?.stop()
    statusRefreshTimer = null
    saveFeedbackResetTimer?.stop()
    saveFeedbackResetTimer = null
}

internal fun SettingsPanel.applyMcpToolToggles(toggles: Map<String, Boolean>) {
    val effective = McpToolCatalog.mergeWithDefaults(toggles)
    mcpToolCheckboxes.forEach { (id, checkbox) ->
        checkbox.isSelected = effective[id] ?: false
    }
}

internal fun SettingsPanel.dialogParentComponent(): JComponent? = dialogParent

internal fun SettingsPanel.helpSection(): JPanel =
    HelpConfigPanel(
        dialogParentProvider = ::dialogParentComponent,
    ).build()

internal fun SettingsPanel.privacySection(): JPanel =
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

internal fun SettingsPanel.testBackendConnection(backendId: String) {
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

internal fun SettingsPanel.promptSection(): JPanel =
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

internal fun SettingsPanel.customPromptsSection(): JPanel =
    CustomPromptsConfigPanel(
        customPromptLibrarySection = customPromptLibraryEditor.component(),
        bountyPromptEnabled = bountyPromptEnabled,
        bountyPromptDir = bountyPromptDir,
        bountyPromptAutoCreateIssues = bountyPromptAutoCreateIssues,
        bountyPromptIssueThreshold = bountyPromptIssueThreshold,
        bountyPromptEnabledIds = bountyPromptEnabledIds,
    ).build()

internal fun SettingsPanel.updatePrivacyWarnings() {
    refreshPrivacyNotice()
}

internal fun SettingsPanel.updateRiskWarnings() {
    refreshPrivacyNotice()
    refreshMcpNotice()
}

/**
 * Compose a single advisory for the Privacy & Logging tab. Replaces the previous trio of
 * stacked red `JLabel` banners (`privacyWarning` + `privacyActiveWarning` + `privacyRiskWarning`)
 * with one [SubtleNotice] whose level + message reflect the active risk combination.
 */
internal fun SettingsPanel.refreshPrivacyNotice() {
    val selectedPrivacy = privacyMode.selectedItem as? PrivacyMode ?: PrivacyMode.STRICT
    val auditOff = !auditEnabled.isSelected
    val activeOn = activeAiEnabled.isSelected

    val (level, htmlMessage) =
        when {
            selectedPrivacy == PrivacyMode.OFF && auditOff && activeOn ->
                SubtleNotice.Level.RISK to
                    "<b>Privacy OFF + Audit logging OFF + Active Scanner ON.</b> " +
                    "Raw traffic may reach MCP and prompts, with no audit trail and live payloads going to targets."
            selectedPrivacy == PrivacyMode.OFF && auditOff ->
                SubtleNotice.Level.RISK to
                    "<b>Privacy OFF + Audit logging OFF.</b> Raw traffic may reach MCP and prompts; " +
                    "without audit logs, traceability and data-protection guarantees are reduced."
            selectedPrivacy == PrivacyMode.OFF && activeOn ->
                SubtleNotice.Level.RISK to
                    "<b>Privacy OFF + Active Scanner ON.</b> Raw traffic may reach MCP and prompts " +
                    "while the active scanner sends payloads to real targets."
            selectedPrivacy == PrivacyMode.OFF ->
                SubtleNotice.Level.WARN to
                    "<b>Privacy mode is OFF.</b> Raw traffic may reach MCP and prompts."
            selectedPrivacy == PrivacyMode.STRICT && activeOn ->
                SubtleNotice.Level.INFO to
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

internal fun SettingsPanel.updateSaveFeedback(
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

internal fun SettingsPanel.updateProfileWarnings() {
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

internal fun SettingsPanel.updateFieldStyle(field: JTextField) {
    field.background = DesignTokens.Colors.inputBackground
    field.foreground = if (field.isEnabled) DesignTokens.Colors.inputForeground else DesignTokens.Colors.onSurfaceVariant
}

internal fun SettingsPanel.styleCombo(combo: JComboBox<*>) {
    combo.font = DesignTokens.Typography.body
    combo.background = DesignTokens.Colors.inputBackground
    combo.foreground = DesignTokens.Colors.inputForeground
    combo.border = LineBorder(DesignTokens.Colors.border, 1, true)
}

internal fun SettingsPanel.openExternalCli(
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

internal fun SettingsPanel.shellQuote(value: String): String {
    if (value.isEmpty()) return "''"
    if (value.none { it.isWhitespace() || it == '"' || it == '\'' }) return value
    return "'" + value.replace("'", "'\"'\"'") + "'"
}
