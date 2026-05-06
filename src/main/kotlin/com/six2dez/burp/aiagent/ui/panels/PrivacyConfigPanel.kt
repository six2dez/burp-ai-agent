package com.six2dez.burp.aiagent.ui.panels

import java.awt.BorderLayout
import javax.swing.BorderFactory
import javax.swing.JComponent
import javax.swing.JPanel

class PrivacyConfigPanel(
    private val sectionPanel: (String, String, JComponent) -> JPanel,
    private val formGrid: () -> JPanel,
    private val addRowFull: (JPanel, String, JComponent) -> Unit,
    private val addSpacerRow: (JPanel, Int) -> Unit,
    private val privacyMode: JComponent,
    private val auditEnabled: JComponent,
    private val autoRestart: JComponent,
    private val determinism: JComponent,
    private val rotateSaltBtn: JComponent,
    // Single advisory replaces the previous trio of stacked red labels. Caller manages level
    // + visibility via `SubtleNotice.setMessage` / `hideNotice` from `refreshPrivacyNotice()`.
    private val privacyNotice: JComponent,
    private val saveFeedback: JComponent,
    private val aiLoggerEnabled: JComponent? = null,
    private val aiLoggerMaxEntries: JComponent? = null,
) : ConfigPanel {
    override fun build(): JPanel {
        val grid = formGrid()
        addRowFull(grid, "Privacy mode", privacyMode)
        addSpacerRow(grid, 4)
        addRowFull(grid, "Audit logging", auditEnabled)
        addSpacerRow(grid, 4)
        if (aiLoggerEnabled != null) {
            addRowFull(grid, "AI request logger", aiLoggerEnabled)
            addSpacerRow(grid, 4)
        }
        if (aiLoggerMaxEntries != null) {
            addRowFull(grid, "Logger max entries", aiLoggerMaxEntries)
            addSpacerRow(grid, 4)
        }
        addRowFull(grid, "Auto-restart", autoRestart)
        addSpacerRow(grid, 4)
        addRowFull(grid, "Determinism mode", determinism)
        addSpacerRow(grid, 4)
        addRowFull(grid, "Anonymization", rotateSaltBtn)
        addSpacerRow(grid, 4)
        addRowFull(grid, "Save feedback", saveFeedback)

        // The privacy advisory lives outside the form grid so it can collapse cleanly when there
        // is nothing to report (no dangling "Advisory:" label remains visible). Padded above so
        // it visually separates from the form rows.
        val noticeWrapper =
            JPanel(BorderLayout()).apply {
                isOpaque = false
                border = BorderFactory.createEmptyBorder(8, 0, 0, 0)
                add(privacyNotice, BorderLayout.CENTER)
            }
        val body =
            JPanel(BorderLayout()).apply {
                isOpaque = false
                add(grid, BorderLayout.NORTH)
                add(noticeWrapper, BorderLayout.CENTER)
            }
        return sectionPanel(
            "Privacy & Logging",
            "Controls redaction, logging and stable ordering of context.",
            body,
        )
    }
}
