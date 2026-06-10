package com.six2dez.burp.aiagent.ui.components

import com.six2dez.burp.aiagent.redact.PrivacyMode
import com.six2dez.burp.aiagent.redact.SecretShapes
import java.awt.BorderLayout
import java.awt.Component
import java.awt.Dimension
import javax.swing.Box
import javax.swing.BoxLayout
import javax.swing.JLabel
import javax.swing.JOptionPane
import javax.swing.JPanel
import javax.swing.JScrollPane
import javax.swing.JTextArea

object ContextPreviewDialog {
    fun confirm(
        parent: Component?,
        privacyMode: PrivacyMode,
        actionName: String,
        prompt: String,
        contextJson: String,
    ): Boolean {
        val panel = JPanel(BorderLayout(8, 8))
        panel.preferredSize = Dimension(780, 560)

        val header = JPanel()
        header.layout = BoxLayout(header, BoxLayout.Y_AXIS)

        val modeLabel = JLabel("Privacy mode: ${privacyMode.name}${privacyModeHint(privacyMode)}")
        val actionLabel = JLabel("Action: $actionName")

        header.add(actionLabel)
        header.add(modeLabel)
        header.add(Box.createVerticalStrut(6))
        header.add(JLabel("Prompt that will be sent:"))

        val promptArea =
            JTextArea(prompt).apply {
                lineWrap = true
                wrapStyleWord = true
                isEditable = false
                rows = 4
            }
        val promptScroll =
            JScrollPane(promptArea).apply {
                preferredSize = Dimension(740, 90)
            }
        header.add(promptScroll)
        header.add(Box.createVerticalStrut(6))
        header.add(JLabel("Context (as will be sent, after redaction):"))

        // PRIV-04: scan the post-redaction contextJson for surviving known secret shapes.
        // The banner is informational only — Send/Cancel semantics are unchanged (no hard stop).
        // UI-SPEC Touch Point 2: Level.WARN (amber, advisory); names categories only, never the raw value.
        // FLAG-13-02: only the SubtleNotice banner is added; the surrounding un-migrated dialog
        // literals (BorderLayout(8,8), Dimension, Box.createVerticalStrut) are left as-is.
        val survivedNotice = SubtleNotice()
        val survivors = SecretShapes.findSurviving(contextJson)
        if (survivors.isNotEmpty()) {
            val shapes = survivors.joinToString(", ")
            val html =
                if (survivors.size == 1) {
                    "A value matching a known secret shape ($shapes) survived redaction. Review before sending."
                } else {
                    "${survivors.size} values matching known secret shapes ($shapes) survived redaction. Review before sending."
                }
            survivedNotice.setMessage(SubtleNotice.Level.WARN, html)
        } else {
            survivedNotice.hideNotice()
        }
        header.add(Box.createVerticalStrut(6))
        header.add(survivedNotice)

        val body =
            JTextArea(contextJson).apply {
                lineWrap = true
                wrapStyleWord = true
                isEditable = false
                caretPosition = 0
            }
        val bodyScroll =
            JScrollPane(body).apply {
                preferredSize = Dimension(740, 340)
            }

        panel.add(header, BorderLayout.NORTH)
        panel.add(bodyScroll, BorderLayout.CENTER)

        val options = arrayOf("Send", "Cancel")
        val choice =
            JOptionPane.showOptionDialog(
                parent,
                panel,
                "Review context before sending to AI",
                JOptionPane.YES_NO_OPTION,
                JOptionPane.PLAIN_MESSAGE,
                null,
                options,
                options[1],
            )
        return choice == 0
    }

    private fun privacyModeHint(mode: PrivacyMode): String =
        when (mode) {
            PrivacyMode.STRICT -> "  (cookies, tokens, and hosts redacted)"
            PrivacyMode.BALANCED -> "  (cookies and tokens redacted, hosts kept)"
            PrivacyMode.OFF -> "  (no redaction; raw traffic will be sent)"
        }
}
