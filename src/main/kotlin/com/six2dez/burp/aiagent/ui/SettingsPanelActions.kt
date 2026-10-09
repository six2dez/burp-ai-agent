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
import java.awt.FlowLayout
import javax.swing.Box
import javax.swing.DefaultComboBoxModel
import javax.swing.JComboBox
import javax.swing.JComponent
import javax.swing.JLabel
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

/** Installs the busy seam the async save path raises and lowers. See [SettingsPanel.busyListener]. */
fun SettingsPanel.setBusyListener(listener: (Boolean) -> Unit) {
    busyListener = listener
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
    // currentSettings() reads the Swing components, so it stays on the EDT before dispatch.
    val updated = currentSettings()
    updateSaveFeedback("Saving settings...", DesignTokens.Colors.statusWarning)
    applyAndSaveSettingsAsync(updated) { result ->
        result
            .onSuccess {
                updateSaveFeedback("Saved and applied.", DesignTokens.Colors.statusSuccess, resetMs = 3000)
            }.onFailure { e ->
                updateSaveFeedback(
                    "Save failed: ${e.message ?: "unknown error"}",
                    DesignTokens.Colors.statusError,
                    resetMs = 5000,
                )
                api.logging().logToError("AI Agent settings save failed: ${e.message}")
                JOptionPane.showMessageDialog(
                    dialogParentComponent(),
                    "Failed to save settings: ${e.message ?: "unknown error"}",
                    "Custom AI Agent",
                    JOptionPane.ERROR_MESSAGE,
                )
            }
    }
}

fun SettingsPanel.restoreDefaultsWithConfirmation() {
    // Rule T-3: the confirmation stays on the EDT and ahead of everything restoreDefaultsConfirmed()
    // does. A confirmation that runs after the work has started is not a confirmation.
    val confirmed =
        JOptionPane.showConfirmDialog(
            dialogParent,
            "Restore default settings? This will overwrite current values.",
            "Restore defaults",
            JOptionPane.YES_NO_OPTION,
        )
    if (confirmed != JOptionPane.YES_OPTION) return
    restoreDefaultsConfirmed()
}

/**
 * Everything `restoreDefaultsWithConfirmation` does once the user has said yes.
 *
 * Split out so the path is headlessly drivable: `JOptionPane.getRootFrame()` throws
 * `HeadlessException`, so every line below used to sit under a statement no test could get past. The
 * modal was NOT deleted to make this testable — UI-SPEC forbids that, and Rule T-3 keeps the
 * confirmation ahead of the work, because a confirmation that runs after the work has started is not a
 * confirmation.
 */
internal fun SettingsPanel.restoreDefaultsConfirmed() {
    val defaults = settingsRepo.defaultSettings()
    applySettingsToUi(defaults, notifyHosts = false)
    updateSaveFeedback("Restoring defaults...", DesignTokens.Colors.statusWarning)
    applyAndSaveSettingsAsync(defaults) { result ->
        result
            .onSuccess {
                updateSaveFeedback("Defaults restored and applied.", DesignTokens.Colors.statusSuccess, resetMs = 3000)
            }.onFailure { e ->
                updateSaveFeedback(
                    "Restore failed: ${e.message ?: "unknown error"}",
                    DesignTokens.Colors.statusError,
                    resetMs = 5000,
                )
                api.logging().logToError("AI Agent settings restore failed: ${e.message}")
                JOptionPane.showMessageDialog(
                    dialogParentComponent(),
                    "Failed to restore defaults: ${e.message ?: "unknown error"}",
                    "Custom AI Agent",
                    JOptionPane.ERROR_MESSAGE,
                )
            }
    }
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

/**
 * Teardown hook for the Settings panel, reached from `MainTab.shutdown()` — which `App.shutdown()`
 * calls FIRST, before `passiveAiScanner.shutdown()`, `activeAiScanner.shutdown()` and
 * `mcpSupervisor.shutdown()`.
 *
 * The first two statements supersede any `burp-ai-settings-save` worker still in flight (CR-01), so it
 * cannot restart the MCP server or re-enable a scanner after `App.shutdown()` has torn them down. See
 * [SettingsPanel.saveGeneration] for the guarantee stated at its true strength.
 *
 * **Neither statement takes a lock and neither waits on anything, on purpose (D-08).** Joining or
 * awaiting the save worker here would put a bounded blocking wait back on the EDT — the exact shape of
 * `future.get(10, TimeUnit.SECONDS)` this phase exists to remove, and the alternative D-08 already
 * rejected for `ChatPanel`'s teardown for the same reason. A `@Volatile` write plus an `AtomicLong`
 * increment costs unload nothing.
 */
fun SettingsPanel.shutdown() {
    disposed = true
    saveGeneration.incrementAndGet()
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
        // Quick 261008-sqa (PD-12): PrivacyConfigPanel's constructor is baselined by its exact text, so
        // the Verbose switch is composed INTO the Audit logging row here rather than added as a parameter.
        auditEnabled =
            JPanel(FlowLayout(FlowLayout.LEADING, 0, 0)).apply {
                isOpaque = false
                add(auditEnabled)
                add(Box.createHorizontalStrut(DesignTokens.Spacing.md))
                add(
                    JLabel("Verbose").apply {
                        font = DesignTokens.Typography.body
                        foreground = DesignTokens.Colors.onSurface
                        toolTipText = AUDIT_VERBOSE_TOOLTIP
                        labelFor = auditVerbose
                    },
                )
                add(Box.createHorizontalStrut(DesignTokens.Spacing.xs))
                add(auditVerbose)
            },
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
 * Pure composer for the Privacy & Logging advisory: maps a risk combination to a [SubtleNotice]
 * level and message, or `null to null` when no notice should be shown.
 *
 * WR-02: deliberately **top-level**, not a `SettingsPanel` extension. An extension would have the
 * Privacy tab's pattern editor in lexical scope and could silently regress to reading its unsaved
 * text; a top-level function cannot reach any Swing component at all, so the defective source is
 * unrepresentable here rather than merely unused.
 *
 * @param persistedCustomPatterns the saved, `isPatternSafe`-validated list from `AgentSettings` —
 *   the very list handed to `Redaction.setCustomPatterns`. Never pass unsaved editor text: the OFF
 *   clause claims the engine is applying these patterns, so that claim must be true when shown.
 */
internal fun privacyNoticeFor(
    selectedPrivacy: PrivacyMode,
    auditOff: Boolean,
    activeOn: Boolean,
    persistedCustomPatterns: List<String>,
): Pair<SubtleNotice.Level?, String?> {
    // D-07: OFF disables the built-in rules only — custom patterns are the user's "never send this,
    // ever" list and apply in every mode (D-05), which is what makes this clause load-bearing: under
    // OFF the persisted patterns are the only redaction there is.
    val customPatternsConfigured = persistedCustomPatterns.isNotEmpty()
    // D-07: one shared clause for every OFF arm below. All four are reworded as a single unit —
    // rewording one and leaving the others would let the panel contradict itself.
    val offClause =
        if (customPatternsConfigured) {
            "Built-in redaction is disabled; only your custom patterns are applied to MCP and prompts."
        } else {
            "Built-in redaction is disabled; raw traffic may reach MCP and prompts."
        }

    return when {
        selectedPrivacy == PrivacyMode.OFF && auditOff && activeOn ->
            SubtleNotice.Level.RISK to
                "<b>Privacy OFF + Audit logging OFF + Active Scanner ON.</b> " +
                offClause +
                " There is no audit trail, and live payloads go to targets."
        selectedPrivacy == PrivacyMode.OFF && auditOff ->
            SubtleNotice.Level.RISK to
                "<b>Privacy OFF + Audit logging OFF.</b> " +
                offClause +
                " Without audit logs, traceability and data-protection guarantees are reduced."
        selectedPrivacy == PrivacyMode.OFF && activeOn ->
            SubtleNotice.Level.RISK to
                "<b>Privacy OFF + Active Scanner ON.</b> " +
                offClause +
                " The active scanner sends payloads to real targets."
        selectedPrivacy == PrivacyMode.OFF ->
            SubtleNotice.Level.WARN to
                "<b>Privacy mode is OFF.</b> " +
                offClause
        selectedPrivacy == PrivacyMode.STRICT && activeOn ->
            SubtleNotice.Level.INFO to
                "STRICT anonymizes hosts in AI prompts but does not prevent the active scanner " +
                "from sending real requests to targets."
        else -> null to null
    }
}

/**
 * Compose a single advisory for the Privacy & Logging tab. Replaces the previous trio of
 * stacked red `JLabel` banners (`privacyWarning` + `privacyActiveWarning` + `privacyRiskWarning`)
 * with one [SubtleNotice] whose level + message reflect the active risk combination.
 *
 * Adapter only: it reads live component state and delegates every wording decision to
 * [privacyNoticeFor].
 */
internal fun SettingsPanel.refreshPrivacyNotice() {
    val selectedPrivacy = privacyMode.selectedItem as? PrivacyMode ?: PrivacyMode.STRICT
    val auditOff = !auditEnabled.isSelected
    val activeOn = activeAiEnabled.isSelected

    // WR-02: the first three arguments are genuinely live UI state — a user can flip them without
    // saving and the banner must follow immediately. The pattern list is not. It is *engine* state
    // that only applyAndSaveSettingsBody can change, and validateAndCollectCustomPatterns drops every
    // line failing SafeRegex.isPatternSafe before it is stored, so unsaved or invalid text is not
    // merely stale — it may never become active at all. Inferring "your custom patterns are applied"
    // from the editor's text therefore downgrades a real risk warning on the strength of text that
    // has no effect on anything. Passing the persisted list makes this banner agree with the two
    // sibling claims that already read it: `ChatPanel.privacySummary` and the
    // customPatternsConfigured parameter of ContextPreviewDialog.privacyModeHint.
    // D-07: this deliberately does NOT call validateAndCollectCustomPatterns(), whose ReDoS probes
    // (six, each bounded by SafeRegex.PROBE_ACCESS_BUDGET) must never run on the EDT during a notice
    // refresh. No probe is needed here - the persisted list was already validated on the way in.
    val (level, htmlMessage) =
        privacyNoticeFor(selectedPrivacy, auditOff, activeOn, settings.customRedactionPatterns)
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
