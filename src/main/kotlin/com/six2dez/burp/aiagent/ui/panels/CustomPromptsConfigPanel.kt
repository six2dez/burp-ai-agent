package com.six2dez.burp.aiagent.ui.panels

import com.six2dez.burp.aiagent.ui.UiTheme
import com.six2dez.burp.aiagent.ui.components.ToggleSwitch
import java.awt.BorderLayout
import java.awt.Dimension
import javax.swing.BoxLayout
import javax.swing.JComponent
import javax.swing.JLabel
import javax.swing.JPanel
import javax.swing.JScrollPane
import javax.swing.JSpinner
import javax.swing.JTextArea
import javax.swing.JTextField
import javax.swing.border.EmptyBorder

/**
 * Dedicated settings tab that consolidates the custom prompt library editor and the BountyPrompt
 * integration. Previously these lived as nested sections inside `Prompt Templates`, which made
 * that tab feel crowded; v0.7.0 splits them out so each tab has a single, focused purpose.
 */
class CustomPromptsConfigPanel(
    private val sectionPanel: (String, String, JComponent) -> JPanel,
    private val formGrid: () -> JPanel,
    private val addRowFull: (JPanel, String, JComponent) -> Unit,
    private val addRowPair: (JPanel, String, JComponent, String, JComponent) -> Unit,
    private val customPromptLibrarySection: JComponent,
    private val bountyPromptEnabled: ToggleSwitch,
    private val bountyPromptDir: JTextField,
    private val bountyPromptAutoCreateIssues: ToggleSwitch,
    private val bountyPromptIssueThreshold: JSpinner,
    private val bountyPromptEnabledIds: JTextArea,
) : ConfigPanel {
    override fun build(): JPanel {
        val body = JPanel(BorderLayout())
        body.background = UiTheme.Colors.surface
        body.border = EmptyBorder(6, 8, 8, 8)

        val content = JPanel()
        content.layout = BoxLayout(content, BoxLayout.Y_AXIS)
        content.background = UiTheme.Colors.surface

        // ── Library section: editor + the empty-state hint that the editor renders internally
        // when its master list is empty.
        val libraryTitle = JLabel("Library")
        libraryTitle.font = UiTheme.Typography.label
        libraryTitle.foreground = UiTheme.Colors.onSurfaceVariant
        libraryTitle.border = EmptyBorder(0, 0, 6, 0)
        content.add(libraryTitle)
        content.add(customPromptLibrarySection)

        // ── BountyPrompt integration: toggle + auto-create + threshold paired where it makes
        // sense, prompt directory + enabled IDs full-width because they need horizontal room.
        val bountyTitle = JLabel("BountyPrompt integration")
        bountyTitle.font = UiTheme.Typography.label
        bountyTitle.foreground = UiTheme.Colors.onSurfaceVariant
        bountyTitle.border = EmptyBorder(16, 0, 6, 0)
        content.add(bountyTitle)

        val bountyGrid = formGrid()
        addRowPair(
            bountyGrid,
            "Enable BountyPrompt actions",
            bountyPromptEnabled,
            "Auto-create issues",
            bountyPromptAutoCreateIssues,
        )
        addRowFull(bountyGrid, "Issue confidence threshold", bountyPromptIssueThreshold)
        addRowFull(bountyGrid, "Prompt directory", bountyPromptDir)
        val idsScroll =
            JScrollPane(bountyPromptEnabledIds).apply {
                preferredSize = Dimension(preferredSize.width, 60)
            }
        addRowFull(bountyGrid, "Enabled prompt IDs", idsScroll)
        content.add(bountyGrid)

        body.add(content, BorderLayout.CENTER)
        return sectionPanel(
            "Custom Prompts",
            "Manage your prompt library and BountyPrompt context actions.",
            body,
        )
    }
}
