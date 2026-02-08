package com.six2dez.burp.aiagent.ui.components

import com.six2dez.burp.aiagent.ui.UiTheme
import java.awt.BorderLayout
import java.awt.Cursor
import java.awt.event.MouseAdapter
import java.awt.event.MouseEvent
import javax.swing.JComponent
import javax.swing.JLabel
import javax.swing.JPanel
import javax.swing.SwingConstants
import javax.swing.BoxLayout
import javax.swing.border.EmptyBorder
import javax.swing.border.MatteBorder

class AccordionPanel(
    title: String,
    subtitle: String,
    content: JComponent,
    initiallyExpanded: Boolean = false
) : JPanel(BorderLayout()) {
    private val header = JPanel(BorderLayout())
    private val titleLabel = JLabel(title)
    private val subtitleLabel = JLabel(subtitle)
    private val toggleLabel = JLabel("", SwingConstants.CENTER)
    private val contentPanel = JPanel(BorderLayout())
    private var expanded = initiallyExpanded

    init {
        background = UiTheme.Colors.surface
        header.background = UiTheme.Colors.surface
        header.border = EmptyBorder(8, 8, 8, 8)
        header.cursor = Cursor.getPredefinedCursor(Cursor.HAND_CURSOR)

        titleLabel.font = UiTheme.Typography.title
        titleLabel.foreground = UiTheme.Colors.onSurface
        subtitleLabel.font = UiTheme.Typography.body
        subtitleLabel.foreground = UiTheme.Colors.onSurfaceVariant

        val textPanel = JPanel()
        textPanel.layout = BoxLayout(textPanel, BoxLayout.Y_AXIS)
        textPanel.background = UiTheme.Colors.surface
        textPanel.add(titleLabel)
        textPanel.add(subtitleLabel)
        subtitleLabel.border = EmptyBorder(2, 0, 0, 0)

        toggleLabel.font = UiTheme.Typography.label
        toggleLabel.foreground = UiTheme.Colors.onSurfaceVariant
        toggleLabel.border = EmptyBorder(0, 8, 0, 0)

        header.add(textPanel, BorderLayout.CENTER)
        header.add(toggleLabel, BorderLayout.EAST)
        header.border = MatteBorder(0, 0, 1, 0, UiTheme.Colors.outlineVariant)

        contentPanel.background = UiTheme.Colors.surface
        contentPanel.add(content, BorderLayout.CENTER)

        add(header, BorderLayout.NORTH)
        add(contentPanel, BorderLayout.CENTER)

        updateExpandedState()

        val toggleListener = object : MouseAdapter() {
            override fun mouseClicked(e: MouseEvent) {
                setExpanded(!expanded)
            }
        }
        header.addMouseListener(toggleListener)
        textPanel.addMouseListener(toggleListener)
        toggleLabel.addMouseListener(toggleListener)
    }

    fun setExpanded(value: Boolean) {
        if (expanded == value) {
            return
        }
        expanded = value
        updateExpandedState()
    }

    fun isExpanded(): Boolean = expanded

    private fun updateExpandedState() {
        contentPanel.isVisible = expanded
        toggleLabel.text = if (expanded) "\u25BC" else "\u25B6"
        revalidate()
        repaint()
    }
}
