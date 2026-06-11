package com.six2dez.burp.aiagent.ui.panels

import com.six2dez.burp.aiagent.ui.design.DesignTokens
import com.six2dez.burp.aiagent.ui.design.addRowFull
import com.six2dez.burp.aiagent.ui.design.applyAreaStyle
import com.six2dez.burp.aiagent.ui.design.formGrid
import com.six2dez.burp.aiagent.ui.design.sectionPanel
import javax.swing.Box
import javax.swing.BoxLayout
import javax.swing.JPanel
import javax.swing.JScrollPane
import javax.swing.JTextArea

/**
 * Settings tab for the built-in prompt templates used by the request and issue context-menu
 * actions. The custom prompt library and BountyPrompt integration moved to a dedicated
 * "Custom Prompts" tab in v0.7.0 so this panel can focus on the request/issue prompts.
 */
class PromptConfigPanel(
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
        applyAreaStyle(promptRequest)
        applyAreaStyle(promptSummary)
        applyAreaStyle(promptJs)
        applyAreaStyle(promptAccessControl)
        applyAreaStyle(promptLoginSequence)
        applyAreaStyle(promptIssueAnalyze)
        applyAreaStyle(promptIssuePoc)
        applyAreaStyle(promptIssueImpact)
        applyAreaStyle(promptIssueFull)

        val requestGrid = formGrid()
        addRowFull(requestGrid, "Find vulnerabilities", JScrollPane(promptRequest))
        addRowFull(requestGrid, "Analyze this request", JScrollPane(promptSummary))
        addRowFull(requestGrid, "Explain JS", JScrollPane(promptJs))
        addRowFull(requestGrid, "Access control", JScrollPane(promptAccessControl))
        addRowFull(requestGrid, "Login sequence", JScrollPane(promptLoginSequence))

        val issueGrid = formGrid()
        addRowFull(issueGrid, "Analyze this issue", JScrollPane(promptIssueAnalyze))
        addRowFull(issueGrid, "Generate PoC & validate", JScrollPane(promptIssuePoc))
        addRowFull(issueGrid, "Impact & severity", JScrollPane(promptIssueImpact))
        addRowFull(issueGrid, "Full report", JScrollPane(promptIssueFull))

        val requestSection =
            sectionPanel(
                "Request prompts",
                "Built-in prompts for request context-menu actions",
                requestGrid,
            )
        val issueSection =
            sectionPanel(
                "Issue prompts",
                "Built-in prompts for Burp issue analysis actions",
                issueGrid,
            )

        return JPanel().apply {
            layout = BoxLayout(this, BoxLayout.Y_AXIS)
            background = DesignTokens.Colors.surface
            add(requestSection)
            add(Box.createRigidArea(java.awt.Dimension(0, DesignTokens.Spacing.sm)))
            add(issueSection)
        }
    }
}
