package com.six2dez.burp.aiagent.ui.components

import com.six2dez.burp.aiagent.redact.PrivacyMode
import com.six2dez.burp.aiagent.redact.SecretTripwire
import com.six2dez.burp.aiagent.ui.design.DesignTokens
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

        // PRIV-03 / Phase 15: tripwire scan — replaces the Phase 13 SecretShapes.findSurviving
        // advisory banner with a two-state clean/RISK gate (FLAG-15-01 two-state collapse).
        // The contextJson arg is the FINAL post-redaction payload (redacted in ContextCollector
        // L52-53, G2). Do NOT re-redact — scan it as-is (G8).
        // FLAG-13-02: only the SubtleNotice banner level + button label are changed; the surrounding
        // un-migrated dialog literals (BorderLayout(8,8), Dimension, Box.createVerticalStrut) stay.
        val scan = SecretTripwire.scan(contextJson)
        val gate = SecretTripwire.gateDecision(scan)
        val survivedNotice = SubtleNotice()
        if (scan.matched) {
            // UI-SPEC Delta 1 / SC5: escalate to RISK (red) and name categories only, never the raw value.
            val shapes = scan.shapeCategories.joinToString(", ")
            val html =
                if (scan.shapeCategories.isEmpty()) {
                    // Entropy-only match — no named shape to display.
                    "A high-entropy value that may be a secret survived redaction. Review before sending."
                } else {
                    // Named-shape match (may also have entropy component).
                    "A value matching a known secret shape ($shapes) survived redaction. Review before sending."
                }
            survivedNotice.setMessage(SubtleNotice.Level.RISK, html)
        } else {
            survivedNotice.hideNotice()
        }
        header.add(Box.createVerticalStrut(DesignTokens.Spacing.sm))
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

        // UI-SPEC Delta 2 / SC5: relabel the affirmative to "Send anyway" only when a tripwire
        // match is present. Cancel (options[1]) stays the initialValue — the default focus is
        // NEVER the affirmative (G5 / Pitfall 5 / FLAG-15-02).
        val options = arrayOf(gate.affirmativeLabel, "Cancel")
        val choice =
            JOptionPane.showOptionDialog(
                parent,
                panel,
                "Review context before sending to AI",
                JOptionPane.YES_NO_OPTION,
                JOptionPane.PLAIN_MESSAGE,
                null,
                options,
                options[1], // Cancel = default focus, regardless of tripwire state
            )
        // Boolean return contract preserved (G3 / FLAG-15-03): false routes ChatPanel.kt:299 to
        // the "cancelled by user" path. The secret_tripwire_allow audit event is emitted by the
        // ChatPanel call site AFTER createSession (RESEARCH Open Q1 Option b) — not here,
        // to avoid double-logging and to carry a real session id.
        return choice == 0
    }

    private fun privacyModeHint(mode: PrivacyMode): String =
        when (mode) {
            PrivacyMode.STRICT -> "  (cookies, tokens, and hosts redacted)"
            PrivacyMode.BALANCED -> "  (cookies and tokens redacted, hosts kept)"
            PrivacyMode.OFF -> "  (no redaction; raw traffic will be sent)"
        }
}
