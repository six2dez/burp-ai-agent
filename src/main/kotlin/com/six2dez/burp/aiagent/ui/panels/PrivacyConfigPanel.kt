package com.six2dez.burp.aiagent.ui.panels

import com.six2dez.burp.aiagent.ui.design.DesignTokens
import com.six2dez.burp.aiagent.ui.design.addRowFull
import com.six2dez.burp.aiagent.ui.design.addSpacerRow
import com.six2dez.burp.aiagent.ui.design.formGrid
import com.six2dez.burp.aiagent.ui.design.sectionPanel
import java.awt.BorderLayout
import javax.swing.BoxLayout
import javax.swing.JComponent
import javax.swing.JPanel
import javax.swing.border.EmptyBorder

class PrivacyConfigPanel(
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
    // PRIV-02: custom-pattern text area + inline validation-feedback label (injected by SettingsPanel).
    private val customPatternsArea: JComponent? = null,
    private val patternsFeedback: JComponent? = null,
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
        // PRIV-02: custom-pattern row (inserted after Anonymization, before Save feedback).
        // addRowFull with helpText auto-adds the help line — do NOT add a separate helpLabel row.
        if (customPatternsArea != null) {
            addRowFull(
                grid,
                "Custom redaction patterns",
                customPatternsArea,
                helpText = "One regex per line. Applied in STRICT and BALANCED. Validated on Save.",
            )
            if (patternsFeedback != null) {
                addRowFull(grid, "", patternsFeedback)
            }
            addSpacerRow(grid, DesignTokens.Spacing.xs)
        }
        addRowFull(grid, "Save feedback", saveFeedback)

        // Stack the form grid + advisory vertically and pin everything to the top of the panel.
        // The advisory lives outside the grid so it collapses cleanly when there is nothing to
        // report (no dangling "Advisory:" label). It must NOT be placed in BorderLayout.CENTER
        // because CENTER stretches its child to fill leftover space, which makes the advisory
        // banner balloon to half the panel height — instead, both children sit in NORTH via a
        // BoxLayout Y_AXIS stack so each takes its preferred height only.
        val noticeWrapper =
            JPanel(BorderLayout()).apply {
                isOpaque = false
                border = EmptyBorder(DesignTokens.Spacing.sm, 0, 0, 0)
                add(privacyNotice, BorderLayout.NORTH)
            }
        val northStack =
            JPanel().apply {
                isOpaque = false
                layout = BoxLayout(this, BoxLayout.Y_AXIS)
                add(grid)
                add(noticeWrapper)
            }
        val body =
            JPanel(BorderLayout()).apply {
                isOpaque = false
                add(northStack, BorderLayout.NORTH)
            }
        return sectionPanel(
            "Privacy & Logging",
            "Controls redaction, logging and stable ordering of context.",
            body,
        )
    }
}
