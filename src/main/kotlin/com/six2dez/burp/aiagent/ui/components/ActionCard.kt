package com.six2dez.burp.aiagent.ui.components

import com.six2dez.burp.aiagent.ui.UiTheme
import java.awt.GridBagConstraints
import java.awt.GridBagLayout
import java.awt.Insets
import javax.swing.JButton
import javax.swing.JLabel
import javax.swing.JPanel
import javax.swing.JScrollPane
import javax.swing.JTextArea
import javax.swing.SwingConstants
import javax.swing.border.EmptyBorder
import javax.swing.border.LineBorder

class ActionCard(
    actionName: String,
    source: String,
    target: String,
    privacySummary: String,
    payloadPreview: String,
    initiallyExpanded: Boolean = false,
) : JPanel(GridBagLayout()) {
    private val actionLabel = JLabel(actionName)
    private val sourceLabel = JLabel(source)
    private val targetLabel = JLabel(target)
    private val privacyLabel = JLabel(privacySummary)
    private val toggleButton = JButton()
    private val previewArea = JTextArea()
    private val previewScroll = JScrollPane(previewArea)
    private var expanded = initiallyExpanded

    init {
        background = UiTheme.Colors.surface
        border = LineBorder(UiTheme.Colors.outlineVariant, 1, true)

        actionLabel.font = UiTheme.Typography.title
        actionLabel.foreground = UiTheme.Colors.onSurface
        sourceLabel.font = UiTheme.Typography.body
        sourceLabel.foreground = UiTheme.Colors.onSurfaceVariant
        targetLabel.font = UiTheme.Typography.body
        targetLabel.foreground = UiTheme.Colors.onSurfaceVariant
        privacyLabel.font = UiTheme.Typography.body
        privacyLabel.foreground = UiTheme.Colors.onSurfaceVariant

        previewArea.font = UiTheme.Typography.mono
        previewArea.foreground = UiTheme.Colors.inputForeground
        previewArea.background = UiTheme.Colors.inputBackground
        previewArea.isEditable = false
        previewArea.lineWrap = true
        previewArea.wrapStyleWord = true
        previewArea.border = EmptyBorder(8, 8, 8, 8)

        previewScroll.border = LineBorder(UiTheme.Colors.outline, 1, true)
        previewScroll.isVisible = expanded

        toggleButton.horizontalAlignment = SwingConstants.LEFT
        toggleButton.isFocusPainted = false
        toggleButton.font = UiTheme.Typography.body
        toggleButton.addActionListener { setExpanded(!expanded) }

        setPayloadPreview(payloadPreview)
        updateExpandedState()

        val constraints =
            GridBagConstraints().apply {
                gridx = 0
                gridy = 0
                anchor = GridBagConstraints.WEST
                fill = GridBagConstraints.HORIZONTAL
                weightx = 1.0
                insets = Insets(8, 10, 0, 10)
            }
        add(actionLabel, constraints)

        constraints.gridy++
        constraints.insets = Insets(4, 10, 0, 10)
        add(sourceLabel, constraints)

        constraints.gridy++
        add(targetLabel, constraints)

        constraints.gridy++
        add(privacyLabel, constraints)

        constraints.gridy++
        constraints.insets = Insets(6, 10, 0, 10)
        add(toggleButton, constraints)

        constraints.gridy++
        constraints.insets = Insets(6, 10, 10, 10)
        constraints.weighty = 1.0
        constraints.fill = GridBagConstraints.BOTH
        add(previewScroll, constraints)
    }

    fun setExpanded(value: Boolean) {
        if (expanded == value) {
            return
        }
        expanded = value
        updateExpandedState()
    }

    fun setPayloadPreview(raw: String) {
        val trimmed = limitLines(raw, 50)
        previewArea.text = trimmed
        previewArea.caretPosition = 0
    }

    private fun updateExpandedState() {
        previewScroll.isVisible = expanded
        toggleButton.text = if (expanded) "Hide payload preview" else "Show payload preview"
        revalidate()
        repaint()
    }

    private fun limitLines(
        raw: String,
        maxLines: Int,
    ): String {
        if (raw.isBlank()) {
            return raw
        }
        val lines = raw.split('\n')
        if (lines.size <= maxLines) {
            return raw
        }
        return lines.take(maxLines).joinToString("\n")
    }
}
