package com.six2dez.burp.aiagent.ui.panels

import com.six2dez.burp.aiagent.ui.UiTheme
import java.awt.BorderLayout
import javax.swing.Box
import javax.swing.BoxLayout
import javax.swing.JButton
import javax.swing.JCheckBox
import javax.swing.JComboBox
import javax.swing.JComponent
import javax.swing.JLabel
import javax.swing.JPanel
import javax.swing.JSpinner
import javax.swing.JTextField
import javax.swing.border.EmptyBorder
import javax.swing.border.LineBorder

class PassiveScanConfigPanel(
    private val sectionPanel: (String, String, JComponent) -> JPanel,
    private val formGrid: () -> JPanel,
    private val addRowFull: (JPanel, String, JComponent) -> Unit,
    private val addRowPair: (JPanel, String, JComponent, String, JComponent) -> Unit,
    private val addSpacerRow: (JPanel, Int) -> Unit,
    private val passiveAiEnabled: JComponent,
    private val passiveAiScopeOnly: JCheckBox,
    private val passiveAiRateSpinner: JSpinner,
    private val passiveAiMaxSizeSpinner: JSpinner,
    private val passiveAiMinSeverityCombo: JComboBox<*>,
    private val passiveAiEndpointDedupSpinner: JSpinner,
    private val passiveAiFingerprintDedupSpinner: JSpinner,
    private val passiveAiPromptCacheTtlSpinner: JSpinner,
    private val passiveAiEndpointCacheEntriesSpinner: JSpinner,
    private val passiveAiFingerprintCacheEntriesSpinner: JSpinner,
    private val passiveAiPromptCacheEntriesSpinner: JSpinner,
    private val passiveAiRequestBodyMaxCharsSpinner: JSpinner,
    private val passiveAiResponseBodyMaxCharsSpinner: JSpinner,
    private val passiveAiHeaderMaxCountSpinner: JSpinner,
    private val passiveAiParamMaxCountSpinner: JSpinner,
    private val passiveAiExcludedExtensionsField: JTextField,
    private val passiveAiBatchSizeSpinner: JSpinner,
    private val passiveAiPersistentCacheEnabled: JCheckBox,
    private val passiveAiPersistentCacheTtlSpinner: JSpinner,
    private val passiveAiPersistentCacheMaxMbSpinner: JSpinner,
    private val contextRequestBodyMaxCharsSpinner: JSpinner,
    private val contextResponseBodyMaxCharsSpinner: JSpinner,
    private val contextCompactJson: JCheckBox,
    private val passiveAiStatusLabel: JLabel,
    private val passiveAiViewFindings: JButton,
    private val scannerTriageButton: JButton,
    private val passiveAiResetStats: JButton,
) : ConfigPanel {
    override fun build(): JPanel {
        val body = JPanel(BorderLayout())
        body.background = UiTheme.Colors.surface
        body.border = EmptyBorder(6, 8, 8, 8)

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

        passiveAiEndpointDedupSpinner.font = UiTheme.Typography.body
        passiveAiEndpointDedupSpinner.toolTipText = "Skip repeated endpoint analysis within this number of minutes."

        passiveAiFingerprintDedupSpinner.font = UiTheme.Typography.body
        passiveAiFingerprintDedupSpinner.toolTipText = "Skip repeated response fingerprints within this number of minutes."

        passiveAiPromptCacheTtlSpinner.font = UiTheme.Typography.body
        passiveAiPromptCacheTtlSpinner.toolTipText = "Reuse previous AI results for identical prompts within this time window."

        passiveAiEndpointCacheEntriesSpinner.font = UiTheme.Typography.body
        passiveAiEndpointCacheEntriesSpinner.toolTipText = "Maximum endpoint dedup cache entries."

        passiveAiFingerprintCacheEntriesSpinner.font = UiTheme.Typography.body
        passiveAiFingerprintCacheEntriesSpinner.toolTipText = "Maximum response fingerprint cache entries."

        passiveAiPromptCacheEntriesSpinner.font = UiTheme.Typography.body
        passiveAiPromptCacheEntriesSpinner.toolTipText = "Maximum prompt-result cache entries."

        passiveAiRequestBodyMaxCharsSpinner.font = UiTheme.Typography.body
        passiveAiRequestBodyMaxCharsSpinner.toolTipText = "Max request body characters sent to AI."

        passiveAiResponseBodyMaxCharsSpinner.font = UiTheme.Typography.body
        passiveAiResponseBodyMaxCharsSpinner.toolTipText = "Max response body characters sent to AI."

        passiveAiHeaderMaxCountSpinner.font = UiTheme.Typography.body
        passiveAiHeaderMaxCountSpinner.toolTipText = "Max filtered headers included in prompt metadata."

        passiveAiParamMaxCountSpinner.font = UiTheme.Typography.body
        passiveAiParamMaxCountSpinner.toolTipText = "Max parameters included in prompt metadata."

        passiveAiExcludedExtensionsField.font = UiTheme.Typography.body
        passiveAiExcludedExtensionsField.toolTipText =
            "Comma-separated file extensions to skip (e.g. css,js,png,woff,ico). Leave empty to disable."

        passiveAiBatchSizeSpinner.font = UiTheme.Typography.body
        passiveAiBatchSizeSpinner.toolTipText = "Group N requests per AI call (1 = disabled). Reduces API calls by 60-70%."

        passiveAiPersistentCacheEnabled.font = UiTheme.Typography.body
        passiveAiPersistentCacheEnabled.background = UiTheme.Colors.surface
        passiveAiPersistentCacheEnabled.foreground = UiTheme.Colors.onSurface
        passiveAiPersistentCacheEnabled.toolTipText = "Cache AI results to disk for reuse across Burp sessions."

        passiveAiPersistentCacheTtlSpinner.font = UiTheme.Typography.body
        passiveAiPersistentCacheTtlSpinner.toolTipText = "Hours before persistent cache entries expire (1-168)."

        passiveAiPersistentCacheMaxMbSpinner.font = UiTheme.Typography.body
        passiveAiPersistentCacheMaxMbSpinner.toolTipText = "Maximum disk space for persistent cache in MB."

        contextRequestBodyMaxCharsSpinner.font = UiTheme.Typography.body
        contextRequestBodyMaxCharsSpinner.toolTipText = "Max request body characters in manual context actions."

        contextResponseBodyMaxCharsSpinner.font = UiTheme.Typography.body
        contextResponseBodyMaxCharsSpinner.toolTipText = "Max response body characters in manual context actions."

        contextCompactJson.font = UiTheme.Typography.body
        contextCompactJson.background = UiTheme.Colors.surface
        contextCompactJson.foreground = UiTheme.Colors.onSurface
        contextCompactJson.toolTipText = "Serialize manual context payloads as compact JSON to reduce tokens."

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
        addSpacerRow(grid, 4)
        addRowPair(
            grid,
            "Endpoint dedup (min)",
            passiveAiEndpointDedupSpinner,
            "Response dedup (min)",
            passiveAiFingerprintDedupSpinner,
        )
        addSpacerRow(grid, 4)
        addRowPair(
            grid,
            "Prompt cache TTL (min)",
            passiveAiPromptCacheTtlSpinner,
            "Prompt cache entries",
            passiveAiPromptCacheEntriesSpinner,
        )
        addSpacerRow(grid, 4)
        addRowPair(
            grid,
            "Endpoint cache entries",
            passiveAiEndpointCacheEntriesSpinner,
            "Fingerprint cache entries",
            passiveAiFingerprintCacheEntriesSpinner,
        )
        addSpacerRow(grid, 4)
        addRowPair(
            grid,
            "Req body chars (AI)",
            passiveAiRequestBodyMaxCharsSpinner,
            "Resp body chars (AI)",
            passiveAiResponseBodyMaxCharsSpinner,
        )
        addSpacerRow(grid, 4)
        addRowPair(
            grid,
            "Max headers",
            passiveAiHeaderMaxCountSpinner,
            "Max params",
            passiveAiParamMaxCountSpinner,
        )
        addSpacerRow(grid, 4)
        addRowFull(grid, "Excluded extensions", passiveAiExcludedExtensionsField)
        addSpacerRow(grid, 4)
        addRowFull(grid, "Batch size (1=off)", passiveAiBatchSizeSpinner)
        addSpacerRow(grid, 4)
        addRowFull(grid, "Persistent cache", passiveAiPersistentCacheEnabled)
        addSpacerRow(grid, 4)
        addRowPair(
            grid,
            "Persistent TTL (hrs)",
            passiveAiPersistentCacheTtlSpinner,
            "Persistent max (MB)",
            passiveAiPersistentCacheMaxMbSpinner,
        )
        addSpacerRow(grid, 4)
        addRowPair(
            grid,
            "Req body chars (manual)",
            contextRequestBodyMaxCharsSpinner,
            "Resp body chars (manual)",
            contextResponseBodyMaxCharsSpinner,
        )
        addSpacerRow(grid, 4)
        addRowFull(grid, "Manual context JSON", contextCompactJson)
        addSpacerRow(grid, 8)
        addRowFull(grid, "Status", passiveAiStatusLabel)
        addSpacerRow(grid, 4)

        val actionsPanel = JPanel()
        actionsPanel.layout = BoxLayout(actionsPanel, BoxLayout.X_AXIS)
        actionsPanel.background = UiTheme.Colors.surface
        actionsPanel.add(passiveAiViewFindings)
        actionsPanel.add(Box.createRigidArea(java.awt.Dimension(8, 0)))
        actionsPanel.add(scannerTriageButton)
        actionsPanel.add(Box.createRigidArea(java.awt.Dimension(8, 0)))
        actionsPanel.add(passiveAiResetStats)
        addRowFull(grid, "Actions", actionsPanel)

        body.add(grid, BorderLayout.CENTER)
        return sectionPanel(
            "AI Passive Scanner",
            "Automatically analyze proxy traffic for vulnerabilities (XSS, SQLi, IDOR, BOLA, BAC, etc.)",
            body,
        )
    }
}
