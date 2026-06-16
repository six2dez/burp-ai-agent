package com.six2dez.burp.aiagent.ui

import com.six2dez.burp.aiagent.config.McpSettings
import com.six2dez.burp.aiagent.ui.design.DesignTokens
import com.six2dez.burp.aiagent.ui.design.addRowFull
import com.six2dez.burp.aiagent.ui.design.addSpacerRow
import com.six2dez.burp.aiagent.ui.design.applyAreaStyle
import com.six2dez.burp.aiagent.ui.design.applyFieldStyle
import com.six2dez.burp.aiagent.ui.design.buildTabPanel
import com.six2dez.burp.aiagent.ui.design.formGrid
import com.six2dez.burp.aiagent.ui.design.sectionPanel
import java.awt.BorderLayout
import javax.swing.Box
import javax.swing.BoxLayout
import javax.swing.JOptionPane
import javax.swing.JPanel
import javax.swing.JSpinner
import javax.swing.Timer
import javax.swing.border.EmptyBorder
import javax.swing.border.LineBorder
import javax.swing.event.DocumentEvent
import javax.swing.event.DocumentListener

/**
 * Wires all UI component styling, tooltips, tab panels, and event listeners for SettingsPanel.
 * Extracted from the SettingsPanel init block to keep SettingsPanel.kt under the module size target.
 * Called exclusively from the SettingsPanel init { } block.
 */
@Suppress("LongMethod")
internal fun SettingsPanel.initUiWiring() {
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
    saveFeedbackLabel.border =
        EmptyBorder(DesignTokens.Spacing.xs, DesignTokens.Spacing.sm, DesignTokens.Spacing.xs, DesignTokens.Spacing.sm)
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
    // Burp Integration: the embedded MCP tools panel (buildMcpToolsPanel) already provides its
    // own JScrollPane. Wrapping it again in buildTabPanel produced a nested scroll pane that
    // swallowed wheel events, so the wheel only scrolled near the outer scrollbar (regression
    // from 11-03). Use a non-scrolling BorderLayout container instead: the section header sits
    // in NORTH and the inner JScrollPane fills CENTER, becoming the single scroll surface so
    // the wheel scrolls anywhere over the content — consistent with the sibling tabs.
    burpIntegrationTab =
        JPanel(BorderLayout()).apply {
            background = DesignTokens.Colors.surface
            border =
                EmptyBorder(
                    DesignTokens.Spacing.lg,
                    DesignTokens.Spacing.lg,
                    DesignTokens.Spacing.lg,
                    DesignTokens.Spacing.lg,
                )
            add(burpIntegrationSection, BorderLayout.CENTER)
        }
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
        Timer(2000) {
            refreshPassiveAiStatus()
            refreshActiveAiStatus()
        }
    statusRefreshTimer?.start()
    updateProfileWarnings()
}
