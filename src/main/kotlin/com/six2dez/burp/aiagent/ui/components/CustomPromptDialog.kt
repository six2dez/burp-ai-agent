package com.six2dez.burp.aiagent.ui.components

import com.six2dez.burp.aiagent.config.CustomPromptDefinition
import com.six2dez.burp.aiagent.ui.UiTheme
import java.awt.BorderLayout
import java.awt.Component
import java.awt.Dimension
import javax.swing.Box
import javax.swing.BoxLayout
import javax.swing.DefaultComboBoxModel
import javax.swing.JComboBox
import javax.swing.JLabel
import javax.swing.JOptionPane
import javax.swing.JPanel
import javax.swing.JScrollPane
import javax.swing.JTextArea

object CustomPromptDialog {
    private const val START_FROM_SCRATCH_LABEL = "— Start from scratch —"

    fun ask(
        parent: Component?,
        targetLabel: String,
        relevantSaved: List<CustomPromptDefinition>,
    ): String? {
        val panel = JPanel(BorderLayout(8, 8))
        panel.preferredSize = Dimension(740, 360)

        val header = JPanel()
        header.layout = BoxLayout(header, BoxLayout.Y_AXIS)

        val title =
            JLabel("Custom prompt for $targetLabel").apply {
                font = UiTheme.Typography.title
            }
        header.add(title)
        header.add(Box.createVerticalStrut(4))

        val textArea =
            JTextArea().apply {
                lineWrap = true
                wrapStyleWord = true
                rows = 10
                columns = 72
                font = UiTheme.Typography.body
            }

        if (relevantSaved.isNotEmpty()) {
            val entries: Array<Any> =
                buildList<Any> {
                    add(START_FROM_SCRATCH_LABEL)
                    addAll(relevantSaved)
                }.toTypedArray()
            val combo = JComboBox<Any>(DefaultComboBoxModel(entries))
            val baseRenderer = javax.swing.DefaultListCellRenderer()
            combo.renderer =
                javax.swing.ListCellRenderer<Any> { list, value, index, isSelected, cellHasFocus ->
                    val label =
                        when (value) {
                            is CustomPromptDefinition -> truncate(value.title, 60)
                            else -> value?.toString() ?: ""
                        }
                    baseRenderer.getListCellRendererComponent(list, label, index, isSelected, cellHasFocus)
                }
            combo.addActionListener {
                val selected = combo.selectedItem
                if (selected is CustomPromptDefinition) {
                    val proceed =
                        textArea.text.isBlank() ||
                            JOptionPane.showConfirmDialog(
                                panel,
                                "Replace the current prompt text with the saved one?",
                                "Replace prompt?",
                                JOptionPane.YES_NO_OPTION,
                                JOptionPane.QUESTION_MESSAGE,
                            ) == JOptionPane.YES_OPTION
                    if (proceed) {
                        textArea.text = selected.promptText
                        textArea.caretPosition = 0
                    }
                    combo.selectedIndex = 0
                }
            }
            val comboLabel =
                JLabel("Start from a saved prompt:").apply {
                    font = UiTheme.Typography.label
                }
            header.add(comboLabel)
            header.add(combo)
            header.add(Box.createVerticalStrut(6))
        }

        header.add(JLabel("Prompt:").apply { font = UiTheme.Typography.label })

        val scroll =
            JScrollPane(textArea).apply {
                preferredSize = Dimension(720, 260)
            }

        val footer =
            JLabel("Manage saved prompts under Settings → Prompt Templates.").apply {
                font = UiTheme.Typography.label
                foreground = UiTheme.Colors.onSurfaceVariant
            }

        panel.add(header, BorderLayout.NORTH)
        panel.add(scroll, BorderLayout.CENTER)
        panel.add(footer, BorderLayout.SOUTH)

        val options = arrayOf("Next: preview & send", "Cancel")
        val choice =
            JOptionPane.showOptionDialog(
                parent,
                panel,
                "Custom prompt",
                JOptionPane.YES_NO_OPTION,
                JOptionPane.PLAIN_MESSAGE,
                null,
                options,
                options[1],
            )
        if (choice != 0) return null
        val prompt = textArea.text.trim()
        return prompt.ifBlank { null }
    }

    private fun truncate(
        value: String,
        max: Int,
    ): String = if (value.length <= max) value else value.take(max - 1) + "…"
}
