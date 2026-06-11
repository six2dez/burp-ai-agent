package com.six2dez.burp.aiagent.ui.panels

import com.six2dez.burp.aiagent.ui.components.ToggleSwitch
import com.six2dez.burp.aiagent.ui.design.DesignTokens
import com.six2dez.burp.aiagent.ui.design.addRowFull
import com.six2dez.burp.aiagent.ui.design.addRowPair
import com.six2dez.burp.aiagent.ui.design.applyAreaStyle
import com.six2dez.burp.aiagent.ui.design.applyFieldStyle
import com.six2dez.burp.aiagent.ui.design.formGrid
import com.six2dez.burp.aiagent.ui.design.sectionPanel
import java.awt.Dimension
import javax.swing.Box
import javax.swing.BoxLayout
import javax.swing.JComponent
import javax.swing.JPanel
import javax.swing.JScrollPane
import javax.swing.JSpinner
import javax.swing.JTextArea
import javax.swing.JTextField

/**
 * Dedicated settings tab that consolidates the custom prompt library editor and the BountyPrompt
 * integration. Previously these lived as nested sections inside `Prompt Templates`, which made
 * that tab feel crowded; v0.7.0 splits them out so each tab has a single, focused purpose.
 */
class CustomPromptsConfigPanel(
    private val customPromptLibrarySection: JComponent,
    private val bountyPromptEnabled: ToggleSwitch,
    private val bountyPromptDir: JTextField,
    private val bountyPromptAutoCreateIssues: ToggleSwitch,
    private val bountyPromptIssueThreshold: JSpinner,
    private val bountyPromptEnabledIds: JTextArea,
) : ConfigPanel {
    override fun build(): JPanel {
        applyFieldStyle(bountyPromptDir)
        applyAreaStyle(bountyPromptEnabledIds)

        // ── Library section: editor + the empty-state hint that the editor renders internally
        // when its master list is empty.
        val librarySection =
            sectionPanel(
                "Custom prompt library",
                "Manage, search, reorder and export your saved prompts",
                customPromptLibrarySection,
            )

        // ── BountyPrompt integration: toggle + auto-create + threshold paired where it makes
        // sense, prompt directory + enabled IDs full-width because they need horizontal room.
        val bountyGrid = formGrid()
        addRowFull(bountyGrid, "Enabled", bountyPromptEnabled)
        addRowFull(bountyGrid, "Prompts directory", bountyPromptDir)
        addRowPair(
            bountyGrid,
            "Auto-create issues",
            bountyPromptAutoCreateIssues,
            "Issue threshold",
            bountyPromptIssueThreshold,
        )
        val idsScroll =
            JScrollPane(bountyPromptEnabledIds).apply {
                preferredSize = Dimension(preferredSize.width, 60)
            }
        addRowFull(bountyGrid, "Enabled prompt IDs", idsScroll)

        val bountySection =
            sectionPanel(
                "BountyPrompt integration",
                "Auto-create issues from BountyPrompt directory results",
                bountyGrid,
            )

        return JPanel().apply {
            layout = BoxLayout(this, BoxLayout.Y_AXIS)
            background = DesignTokens.Colors.surface
            add(librarySection)
            add(Box.createRigidArea(java.awt.Dimension(0, DesignTokens.Spacing.sm)))
            add(bountySection)
        }
    }
}
