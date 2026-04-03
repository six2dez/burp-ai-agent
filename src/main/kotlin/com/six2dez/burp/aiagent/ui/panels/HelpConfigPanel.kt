package com.six2dez.burp.aiagent.ui.panels

import java.awt.Desktop
import javax.swing.JEditorPane
import javax.swing.JOptionPane
import javax.swing.JPanel
import javax.swing.border.EmptyBorder

class HelpConfigPanel(
    private val sectionPanel: (String, String, javax.swing.JComponent) -> JPanel,
    private val dialogParentProvider: () -> javax.swing.JComponent?
) : ConfigPanel {
    override fun build(): JPanel {
        val helpHtml = """
            <html>
              <body style="font-family: sans-serif; font-size: 12px;">
                <b>Custom AI Agent - Quick Start</b><br/>
                1. Toggle MCP on in the top bar.<br/>
                2. Select your AI backend.<br/>
                3. Right-click requests/issues for AI analysis.<br/>
                4. Enable passive/active scanners for automated testing.<br/><br/>
                <b>Full documentation:</b>
                <a href="https://burp-ai-agent.six2dez.com/">Plugin Documentation</a><br/><br/>
                <b>Privacy:</b> STRICT (hosts anonymized) | BALANCED (hosts visible) | OFF (raw data)
              </body>
            </html>
        """.trimIndent()
        val helpPane = JEditorPane("text/html", helpHtml)
        helpPane.isEditable = false
        helpPane.isOpaque = false
        helpPane.border = EmptyBorder(6, 8, 8, 8)
        helpPane.addHyperlinkListener { event ->
            if (event.eventType != javax.swing.event.HyperlinkEvent.EventType.ACTIVATED) return@addHyperlinkListener
            val urlText = event.url?.toString().orEmpty()
            try {
                if (Desktop.isDesktopSupported()) {
                    Desktop.getDesktop().browse(event.url.toURI())
                } else {
                    JOptionPane.showMessageDialog(
                        dialogParentProvider(),
                        "Open this URL in your browser: $urlText",
                        "Help",
                        JOptionPane.INFORMATION_MESSAGE
                    )
                }
            } catch (_: Exception) {
                JOptionPane.showMessageDialog(
                    dialogParentProvider(),
                    "Open this URL in your browser: $urlText",
                    "Help",
                    JOptionPane.INFORMATION_MESSAGE
                )
            }
        }
        return sectionPanel(
            "Help",
            "Quick start and documentation links.",
            helpPane
        )
    }
}
