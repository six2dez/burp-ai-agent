package com.six2dez.burp.aiagent.ui.panels

import com.six2dez.burp.aiagent.ui.components.AccordionPanel
import com.six2dez.burp.aiagent.ui.design.DesignTokens
import com.six2dez.burp.aiagent.ui.design.addRowFull
import com.six2dez.burp.aiagent.ui.design.addRowPair
import com.six2dez.burp.aiagent.ui.design.addSpacerRow
import com.six2dez.burp.aiagent.ui.design.formGrid
import java.awt.Dimension
import javax.swing.Box
import javax.swing.BoxLayout
import javax.swing.JButton
import javax.swing.JCheckBox
import javax.swing.JComboBox
import javax.swing.JComponent
import javax.swing.JLabel
import javax.swing.JPanel
import javax.swing.JSpinner
import javax.swing.border.EmptyBorder
import javax.swing.border.LineBorder

class ActiveScanConfigPanel(
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
    private val activeAiResetStats: JButton,
) : ConfigPanel {
    override fun build(): JPanel {
        activeAiEnabled.font = DesignTokens.Typography.body
        activeAiEnabled.background = DesignTokens.Colors.surface
        activeAiEnabled.foreground = DesignTokens.Colors.onSurface
        activeAiEnabled.toolTipText = "Enable active testing to confirm vulnerabilities detected by passive scanning."

        activeAiScopeOnly.font = DesignTokens.Typography.body
        activeAiScopeOnly.background = DesignTokens.Colors.surface
        activeAiScopeOnly.foreground = DesignTokens.Colors.onSurface
        activeAiScopeOnly.toolTipText = "Only test requests that are in the defined target scope."

        activeAiAutoFromPassive.font = DesignTokens.Typography.body
        activeAiAutoFromPassive.background = DesignTokens.Colors.surface
        activeAiAutoFromPassive.foreground = DesignTokens.Colors.onSurface
        activeAiAutoFromPassive.toolTipText = "Automatically queue passive scanner findings for active testing."

        activeAiStatusLabel.font = DesignTokens.Typography.body
        activeAiStatusLabel.foreground = DesignTokens.Colors.onSurfaceVariant

        activeAiRiskDescription.font = DesignTokens.Typography.body
        activeAiRiskDescription.foreground = DesignTokens.Colors.onSurfaceVariant

        activeAiViewFindings.font = DesignTokens.Typography.label
        activeAiViewFindings.background = DesignTokens.Colors.surface
        activeAiViewFindings.foreground = DesignTokens.Colors.primary
        activeAiViewFindings.isFocusPainted = false

        activeAiViewQueue.font = DesignTokens.Typography.label
        activeAiViewQueue.background = DesignTokens.Colors.surface
        activeAiViewQueue.foreground = DesignTokens.Colors.primary
        activeAiViewQueue.isFocusPainted = false

        activeAiClearQueue.font = DesignTokens.Typography.label
        activeAiClearQueue.background = DesignTokens.Colors.surface
        activeAiClearQueue.foreground = DesignTokens.Colors.primary
        activeAiClearQueue.border = LineBorder(DesignTokens.Colors.border, 1, true)
        activeAiClearQueue.isFocusPainted = false

        activeAiResetStats.font = DesignTokens.Typography.label
        activeAiResetStats.background = DesignTokens.Colors.surface
        activeAiResetStats.foreground = DesignTokens.Colors.primary
        activeAiResetStats.border = LineBorder(DesignTokens.Colors.border, 1, true)
        activeAiResetStats.isFocusPainted = false

        activeAiMaxConcurrentSpinner.font = DesignTokens.Typography.body
        activeAiMaxConcurrentSpinner.toolTipText = "Maximum number of concurrent active scans."

        activeAiMaxPayloadsSpinner.font = DesignTokens.Typography.body
        activeAiMaxPayloadsSpinner.toolTipText = "Maximum payloads to test per injection point."

        activeAiTimeoutSpinner.font = DesignTokens.Typography.body
        activeAiTimeoutSpinner.toolTipText = "Request timeout in seconds."

        activeAiDelaySpinner.font = DesignTokens.Typography.body
        activeAiDelaySpinner.toolTipText = "Delay between requests in milliseconds (rate limiting)."

        activeAiRiskLevelCombo.font = DesignTokens.Typography.body
        activeAiRiskLevelCombo.background = DesignTokens.Colors.surface
        activeAiRiskLevelCombo.toolTipText = "SAFE: read-only tests. MODERATE: may read data. DANGEROUS: may modify data."

        activeAiScanModeCombo.font = DesignTokens.Typography.body
        activeAiScanModeCombo.background = DesignTokens.Colors.surface
        activeAiScanModeCombo.toolTipText = "BUG_BOUNTY: high-impact only. PENTEST: broad coverage. FULL: all classes."

        activeAiUseCollaborator.font = DesignTokens.Typography.body
        activeAiUseCollaborator.background = DesignTokens.Colors.surface
        activeAiUseCollaborator.foreground = DesignTokens.Colors.onSurface
        activeAiUseCollaborator.toolTipText = "Use Burp Collaborator for SSRF confirmation (out-of-band)."

        activeAiAdaptivePayloads.font = DesignTokens.Typography.body
        activeAiAdaptivePayloads.background = DesignTokens.Colors.surface
        activeAiAdaptivePayloads.foreground = DesignTokens.Colors.onSurface
        activeAiAdaptivePayloads.toolTipText = "Use AI to generate context-aware payloads based on detected tech stack and error patterns."

        // --- Section A: Scanner control ---
        val actionsPanel =
            JPanel().apply {
                layout = BoxLayout(this, BoxLayout.X_AXIS)
                background = DesignTokens.Colors.surface
                add(activeAiViewFindings)
                add(Box.createRigidArea(Dimension(DesignTokens.Spacing.sm, 0)))
                add(activeAiViewQueue)
                add(Box.createRigidArea(Dimension(DesignTokens.Spacing.sm, 0)))
                add(activeAiClearQueue)
                add(Box.createRigidArea(Dimension(DesignTokens.Spacing.sm, 0)))
                add(activeAiResetStats)
            }

        val gridA = formGrid()
        addRowFull(gridA, "Enable scanner", activeAiEnabled)
        addSpacerRow(gridA, DesignTokens.Spacing.xs)
        addRowFull(gridA, "In-scope only", activeAiScopeOnly)
        addSpacerRow(gridA, DesignTokens.Spacing.xs)
        addRowFull(gridA, "Auto-queue findings", activeAiAutoFromPassive)
        addSpacerRow(gridA, DesignTokens.Spacing.xs)
        addRowFull(gridA, "Status", activeAiStatusLabel)
        addSpacerRow(gridA, DesignTokens.Spacing.xs)
        addRowFull(gridA, "Actions", actionsPanel)
        val sectionA =
            AccordionPanel(
                "Scanner control",
                "Enable active testing and define scope constraints",
                gridA,
                initiallyExpanded = true,
            )

        // --- Section B: Scan parameters ---
        val gridB = formGrid()
        addRowPair(gridB, "Max concurrent", activeAiMaxConcurrentSpinner, "Max payloads", activeAiMaxPayloadsSpinner)
        addSpacerRow(gridB, DesignTokens.Spacing.xs)
        addRowPair(gridB, "Timeout (s)", activeAiTimeoutSpinner, "Delay (ms)", activeAiDelaySpinner)
        addSpacerRow(gridB, DesignTokens.Spacing.xs)
        addRowFull(gridB, "Risk level", activeAiRiskLevelCombo)
        addSpacerRow(gridB, DesignTokens.Spacing.xs)
        addRowFull(gridB, "Risk level details", activeAiRiskDescription)
        addSpacerRow(gridB, DesignTokens.Spacing.xs)
        addRowFull(gridB, "Scan mode", activeAiScanModeCombo)
        addSpacerRow(gridB, DesignTokens.Spacing.xs)
        addRowFull(gridB, "Use Collaborator", activeAiUseCollaborator)
        addSpacerRow(gridB, DesignTokens.Spacing.xs)
        addRowFull(gridB, "Adaptive payloads", activeAiAdaptivePayloads)
        val sectionB =
            AccordionPanel(
                "Scan parameters",
                "Concurrency, payloads, timing, risk level and mode",
                gridB,
                initiallyExpanded = true,
            )

        val body =
            JPanel().apply {
                layout = BoxLayout(this, BoxLayout.Y_AXIS)
                background = DesignTokens.Colors.surface
                border =
                    EmptyBorder(
                        DesignTokens.Spacing.sectionPad,
                        DesignTokens.Spacing.sectionPad,
                        DesignTokens.Spacing.sectionPad,
                        DesignTokens.Spacing.sectionPad,
                    )
                add(sectionA)
                add(Box.createRigidArea(Dimension(0, DesignTokens.Spacing.sm)))
                add(sectionB)
            }
        return body
    }
}
