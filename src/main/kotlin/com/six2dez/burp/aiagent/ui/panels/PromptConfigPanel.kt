package com.six2dez.burp.aiagent.ui.panels

import com.six2dez.burp.aiagent.ui.UiTheme
import java.awt.BorderLayout
import javax.swing.BoxLayout
import javax.swing.JComponent
import javax.swing.JLabel
import javax.swing.JPanel
import javax.swing.JScrollPane
import javax.swing.JTextArea
import javax.swing.border.EmptyBorder

/**
 * Settings tab for the built-in prompt templates used by the request and issue context-menu
 * actions. The custom prompt library and BountyPrompt integration moved to a dedicated
 * "Custom Prompts" tab in v0.7.0 so this panel can focus on the request/issue prompts.
 */
class PromptConfigPanel(
    private val sectionPanel: (String, String, JComponent) -> JPanel,
    private val formGrid: () -> JPanel,
    private val addRowFull: (JPanel, String, JComponent) -> Unit,
    private val promptRequest: JTextArea,
    private val promptSummary: JTextArea,
    private val promptJs: JTextArea,
    private val promptAccessControl: JTextArea,
    private val promptLoginSequence: JTextArea,
    private val promptIssueAnalyze: JTextArea,
    private val promptIssuePoc: JTextArea,
    private val promptIssueImpact: JTextArea,
    private val promptIssueFull: JTextArea,
) : ConfigPanel {
    override fun build(): JPanel {
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
        addRowFull(requestGrid, "Find vulnerabilities", JScrollPane(promptRequest))
        addRowFull(requestGrid, "Analyze this request", JScrollPane(promptSummary))
        addRowFull(requestGrid, "Explain JS", JScrollPane(promptJs))
        addRowFull(requestGrid, "Access control", JScrollPane(promptAccessControl))
        addRowFull(requestGrid, "Login sequence", JScrollPane(promptLoginSequence))
        content.add(requestGrid)

        val issueTitle = JLabel("Issue prompts")
        issueTitle.font = UiTheme.Typography.label
        issueTitle.foreground = UiTheme.Colors.onSurfaceVariant
        issueTitle.border = EmptyBorder(12, 0, 6, 0)
        content.add(issueTitle)

        val issueGrid = formGrid()
        addRowFull(issueGrid, "Analyze this issue", JScrollPane(promptIssueAnalyze))
        addRowFull(issueGrid, "Generate PoC & validate", JScrollPane(promptIssuePoc))
        addRowFull(issueGrid, "Impact & severity", JScrollPane(promptIssueImpact))
        addRowFull(issueGrid, "Full report", JScrollPane(promptIssueFull))
        content.add(issueGrid)

        body.add(content, BorderLayout.CENTER)
        return sectionPanel(
            "Prompt Templates",
            "Edit built-in prompts used by request and issue context actions.",
            body,
        )
    }
}
