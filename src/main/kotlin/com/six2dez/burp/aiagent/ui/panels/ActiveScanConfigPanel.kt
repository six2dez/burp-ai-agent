package com.six2dez.burp.aiagent.ui.panels

import com.six2dez.burp.aiagent.ui.UiTheme
import java.awt.BorderLayout
import javax.swing.Box
import javax.swing.BoxLayout
import javax.swing.JButton
import javax.swing.JCheckBox
import javax.swing.JComponent
import javax.swing.JComboBox
import javax.swing.JLabel
import javax.swing.JPanel
import javax.swing.JSpinner
import javax.swing.border.EmptyBorder
import javax.swing.border.LineBorder

class ActiveScanConfigPanel(
    private val sectionPanel: (String, String, JComponent) -> JPanel,
    private val formGrid: () -> JPanel,
    private val addRowFull: (JPanel, String, JComponent) -> Unit,
    private val addRowPair: (JPanel, String, JComponent, String, JComponent) -> Unit,
    private val addSpacerRow: (JPanel, Int) -> Unit,
    private val activeAiEnabled: JComponent,
    private val activeAiScopeOnly: JCheckBox,
    private val activeAiAutoFromPassive: JCheckBox,
    private val activeAiMaxConcurrentSpinner: JSpinner,
    private val activeAiMaxPayloadsSpinner: JSpinner,
    private val activeAiTimeoutSpinner: JSpinner,
    private val activeAiDelaySpinner: JSpinner,
    private val activeAiRiskLevelCombo: JComboBox<*>,
    private val activeAiScanModeCombo: JComboBox<*>,
    private val activeAiUseCollaborator: JCheckBox,
    private val activeAiAdaptivePayloads: JCheckBox,
    private val activeAiRiskDescription: JLabel,
    private val activeAiStatusLabel: JLabel,
    private val activeAiViewFindings: JButton,
    private val activeAiViewQueue: JButton,
    private val activeAiClearQueue: JButton,
    private val activeAiResetStats: JButton
) : ConfigPanel {
    override fun build(): JPanel {
        val body = JPanel(BorderLayout())
        body.background = UiTheme.Colors.surface
        body.border = EmptyBorder(6, 8, 8, 8)

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

        activeAiAdaptivePayloads.font = UiTheme.Typography.body
        activeAiAdaptivePayloads.background = UiTheme.Colors.surface
        activeAiAdaptivePayloads.foreground = UiTheme.Colors.onSurface
        activeAiAdaptivePayloads.toolTipText = "Use AI to generate context-aware payloads based on detected tech stack and error patterns."

        activeAiStatusLabel.font = UiTheme.Typography.body
        activeAiStatusLabel.foreground = UiTheme.Colors.onSurfaceVariant

        activeAiViewFindings.font = UiTheme.Typography.label
        activeAiViewFindings.background = UiTheme.Colors.surface
        activeAiViewFindings.foreground = UiTheme.Colors.primary
        activeAiViewFindings.border = EmptyBorder(6, 10, 6, 10)
        activeAiViewFindings.isFocusPainted = false

        activeAiViewQueue.font = UiTheme.Typography.label
        activeAiViewQueue.background = UiTheme.Colors.surface
        activeAiViewQueue.foreground = UiTheme.Colors.primary
        activeAiViewQueue.border = EmptyBorder(6, 10, 6, 10)
        activeAiViewQueue.isFocusPainted = false

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
        addSpacerRow(grid, 4)
        addRowFull(grid, "Adaptive payloads", activeAiAdaptivePayloads)
        addSpacerRow(grid, 8)
        addRowFull(grid, "Status", activeAiStatusLabel)
        addSpacerRow(grid, 4)

        val actionsPanel = JPanel()
        actionsPanel.layout = BoxLayout(actionsPanel, BoxLayout.X_AXIS)
        actionsPanel.background = UiTheme.Colors.surface
        actionsPanel.add(activeAiViewFindings)
        actionsPanel.add(Box.createRigidArea(java.awt.Dimension(8, 0)))
        actionsPanel.add(activeAiViewQueue)
        actionsPanel.add(Box.createRigidArea(java.awt.Dimension(8, 0)))
        actionsPanel.add(activeAiClearQueue)
        actionsPanel.add(Box.createRigidArea(java.awt.Dimension(8, 0)))
        actionsPanel.add(activeAiResetStats)
        addRowFull(grid, "Actions", actionsPanel)

        body.add(grid, BorderLayout.CENTER)
        return sectionPanel(
            "AI Active Scanner",
            "Confirm vulnerabilities by sending test payloads (SQLi, XSS, LFI, CMDI, SSRF, etc.)",
            body
        )
    }
}
