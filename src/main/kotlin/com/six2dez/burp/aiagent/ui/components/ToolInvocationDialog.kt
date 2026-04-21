package com.six2dez.burp.aiagent.ui.components

import com.six2dez.burp.aiagent.mcp.McpToolDescriptor
import com.six2dez.burp.aiagent.ui.UiTheme
import io.modelcontextprotocol.kotlin.sdk.Tool
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import java.awt.BorderLayout
import java.awt.Dimension
import java.awt.FlowLayout
import java.awt.GridBagConstraints
import java.awt.GridBagLayout
import java.awt.Insets
import java.awt.Window
import javax.swing.BorderFactory
import javax.swing.JButton
import javax.swing.JComboBox
import javax.swing.JComponent
import javax.swing.JDialog
import javax.swing.JLabel
import javax.swing.JOptionPane
import javax.swing.JPanel
import javax.swing.JScrollPane
import javax.swing.JTextArea
import javax.swing.JTextField
import javax.swing.ListCellRenderer
import javax.swing.SwingConstants
import javax.swing.border.EmptyBorder

class ToolInvocationDialog(
    owner: Window?,
    tools: List<McpToolDescriptor>,
    private val schemaProvider: (String) -> Tool.Input,
) : JDialog(owner, "Invoke MCP Tool", ModalityType.APPLICATION_MODAL) {
    data class Invocation(
        val toolId: String,
        val argsJson: String?,
    )

    private data class ToolOption(
        val id: String,
        val title: String,
        val description: String,
    )

    private sealed interface FieldEditor {
        val component: JComponent

        fun isEmpty(): Boolean

        fun readJsonValue(): JsonElement?
    }

    private class TextEditor(
        private val field: JTextField,
    ) : FieldEditor {
        override val component: JComponent = field

        override fun isEmpty(): Boolean = field.text.trim().isEmpty()

        override fun readJsonValue(): JsonElement = JsonPrimitive(field.text.trim())
    }

    private class IntegerEditor(
        private val field: JTextField,
    ) : FieldEditor {
        override val component: JComponent = field

        override fun isEmpty(): Boolean = field.text.trim().isEmpty()

        override fun readJsonValue(): JsonElement {
            val raw = field.text.trim()
            val value = raw.toIntOrNull() ?: throw IllegalArgumentException("Expected integer, got '$raw'")
            return JsonPrimitive(value)
        }
    }

    private class NumberEditor(
        private val field: JTextField,
    ) : FieldEditor {
        override val component: JComponent = field

        override fun isEmpty(): Boolean = field.text.trim().isEmpty()

        override fun readJsonValue(): JsonElement {
            val raw = field.text.trim()
            val value = raw.toDoubleOrNull() ?: throw IllegalArgumentException("Expected number, got '$raw'")
            return JsonPrimitive(value)
        }
    }

    private class BooleanEditor(
        private val combo: JComboBox<String>,
    ) : FieldEditor {
        override val component: JComponent = combo

        override fun isEmpty(): Boolean = (combo.selectedItem as? String).orEmpty().isBlank()

        override fun readJsonValue(): JsonElement {
            val raw = (combo.selectedItem as? String).orEmpty()
            val value = raw.toBooleanStrictOrNull() ?: throw IllegalArgumentException("Expected true or false")
            return JsonPrimitive(value)
        }
    }

    private class JsonEditor(
        private val area: JTextArea,
        private val expectedType: String,
    ) : FieldEditor {
        override val component: JComponent =
            JScrollPane(area).apply {
                border = BorderFactory.createLineBorder(UiTheme.Colors.outline, 1, true)
                preferredSize = Dimension(380, 80)
            }

        override fun isEmpty(): Boolean = area.text.trim().isEmpty()

        override fun readJsonValue(): JsonElement {
            val parsed = Json.parseToJsonElement(area.text.trim())
            if (expectedType == "array" && parsed !is kotlinx.serialization.json.JsonArray) {
                throw IllegalArgumentException("Expected JSON array")
            }
            if (expectedType == "object" && parsed !is JsonObject) {
                throw IllegalArgumentException("Expected JSON object")
            }
            return parsed
        }
    }

    private val toolOptions =
        tools
            .sortedBy { it.title.lowercase() }
            .map { ToolOption(id = it.id, title = it.title, description = it.description) }

    private val toolCombo = JComboBox(toolOptions.toTypedArray())
    private val descriptionLabel = JLabel(" ")
    private val fieldsPanel = JPanel(GridBagLayout())
    private val fieldEditors = linkedMapOf<String, FieldEditor>()
    private var selectedSchema: Tool.Input = Tool.Input()
    private var invocation: Invocation? = null

    init {
        title = "Invoke MCP Tool"
        minimumSize = Dimension(640, 520)
        preferredSize = Dimension(720, 560)
        layout = BorderLayout(10, 10)

        val content =
            JPanel(BorderLayout(8, 8)).apply {
                border = EmptyBorder(12, 12, 8, 12)
                background = UiTheme.Colors.surface
            }

        val top =
            JPanel(GridBagLayout()).apply {
                isOpaque = false
            }
        val c0 =
            GridBagConstraints().apply {
                gridx = 0
                gridy = 0
                anchor = GridBagConstraints.WEST
                insets = Insets(0, 0, 6, 8)
            }
        val toolLabel =
            JLabel("Tool").apply {
                font = UiTheme.Typography.label
                foreground = UiTheme.Colors.onSurface
            }
        top.add(toolLabel, c0)

        val c1 =
            GridBagConstraints().apply {
                gridx = 1
                gridy = 0
                weightx = 1.0
                fill = GridBagConstraints.HORIZONTAL
                insets = Insets(0, 0, 6, 0)
            }
        styleCombo(toolCombo)
        toolCombo.renderer =
            ListCellRenderer { list, value, index, isSelected, cellHasFocus ->
                val label = JLabel()
                val option = value as? ToolOption
                label.text = if (option == null) "" else "${option.title} (${option.id})"
                label.font = UiTheme.Typography.body
                label.horizontalAlignment = SwingConstants.LEFT
                if (isSelected) {
                    label.background = list.selectionBackground
                    label.foreground = list.selectionForeground
                    label.isOpaque = true
                } else {
                    label.background = UiTheme.Colors.comboBackground
                    label.foreground = UiTheme.Colors.comboForeground
                    label.isOpaque = true
                }
                label.border = EmptyBorder(3, 4, 3, 4)
                label
            }
        top.add(toolCombo, c1)

        val c2 =
            GridBagConstraints().apply {
                gridx = 0
                gridy = 1
                gridwidth = 2
                weightx = 1.0
                fill = GridBagConstraints.HORIZONTAL
                insets = Insets(0, 0, 0, 0)
            }
        descriptionLabel.font = UiTheme.Typography.body
        descriptionLabel.foreground = UiTheme.Colors.onSurfaceVariant
        top.add(descriptionLabel, c2)

        fieldsPanel.background = UiTheme.Colors.surface
        val fieldsScroll =
            JScrollPane(fieldsPanel).apply {
                border = BorderFactory.createLineBorder(UiTheme.Colors.outline, 1, true)
                viewport.background = UiTheme.Colors.surface
                verticalScrollBarPolicy = JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED
                horizontalScrollBarPolicy = JScrollPane.HORIZONTAL_SCROLLBAR_NEVER
            }

        val buttons =
            JPanel(FlowLayout(FlowLayout.RIGHT, 8, 0)).apply {
                isOpaque = false
            }
        val cancel = JButton("Cancel")
        val execute = JButton("Execute")
        styleButton(cancel)
        stylePrimaryButton(execute)
        buttons.add(cancel)
        buttons.add(execute)

        content.add(top, BorderLayout.NORTH)
        content.add(fieldsScroll, BorderLayout.CENTER)

        add(content, BorderLayout.CENTER)
        add(buttons, BorderLayout.SOUTH)

        toolCombo.addActionListener {
            rebuildFields()
        }
        cancel.addActionListener {
            invocation = null
            dispose()
        }
        execute.addActionListener {
            val selected = toolCombo.selectedItem as? ToolOption ?: return@addActionListener
            val args = collectArgsOrShowError() ?: return@addActionListener
            invocation = Invocation(selected.id, args)
            dispose()
        }

        if (toolOptions.isEmpty()) {
            descriptionLabel.text = "No enabled tools are currently available."
            toolCombo.isEnabled = false
            execute.isEnabled = false
        } else {
            toolCombo.selectedIndex = 0
            rebuildFields()
        }

        pack()
        setLocationRelativeTo(owner)
    }

    fun showDialog(): Invocation? {
        isVisible = true
        return invocation
    }

    private fun rebuildFields() {
        fieldsPanel.removeAll()
        fieldEditors.clear()

        val selected = toolCombo.selectedItem as? ToolOption
        if (selected == null) {
            fieldsPanel.revalidate()
            fieldsPanel.repaint()
            return
        }

        descriptionLabel.text = selected.description
        selectedSchema = schemaProvider(selected.id)
        val required = selectedSchema.required?.toSet().orEmpty()
        val properties =
            selectedSchema.properties
                .entries
                .sortedBy { it.key }

        if (properties.isEmpty()) {
            val empty =
                JLabel("This tool does not require arguments.").apply {
                    font = UiTheme.Typography.body
                    foreground = UiTheme.Colors.onSurfaceVariant
                    border = EmptyBorder(10, 10, 10, 10)
                }
            val c =
                GridBagConstraints().apply {
                    gridx = 0
                    gridy = 0
                    weightx = 1.0
                    anchor = GridBagConstraints.WEST
                    fill = GridBagConstraints.HORIZONTAL
                    insets = Insets(6, 6, 6, 6)
                }
            fieldsPanel.add(empty, c)
            fieldsPanel.revalidate()
            fieldsPanel.repaint()
            return
        }

        var row = 0
        for ((name, schema) in properties) {
            val type = schemaType(schema)
            val labelText = if (required.contains(name)) "$name *" else name
            val label =
                JLabel(labelText).apply {
                    font = UiTheme.Typography.label
                    foreground = UiTheme.Colors.onSurface
                }
            val editor = createEditor(type)
            fieldEditors[name] = editor

            val c1 =
                GridBagConstraints().apply {
                    gridx = 0
                    gridy = row
                    anchor = GridBagConstraints.NORTHWEST
                    insets = Insets(8, 8, 2, 8)
                }
            val c2 =
                GridBagConstraints().apply {
                    gridx = 0
                    gridy = row + 1
                    weightx = 1.0
                    fill = GridBagConstraints.HORIZONTAL
                    insets = Insets(0, 8, 8, 8)
                }
            fieldsPanel.add(label, c1)
            fieldsPanel.add(editor.component, c2)
            row += 2
        }

        val filler =
            GridBagConstraints().apply {
                gridx = 0
                gridy = row
                weighty = 1.0
                fill = GridBagConstraints.BOTH
            }
        fieldsPanel.add(JPanel().apply { isOpaque = false }, filler)

        fieldsPanel.revalidate()
        fieldsPanel.repaint()
    }

    private fun collectArgsOrShowError(): String? {
        val required = selectedSchema.required?.toSet().orEmpty()
        val payload = linkedMapOf<String, JsonElement>()

        for ((name, editor) in fieldEditors) {
            if (editor.isEmpty()) {
                if (required.contains(name)) {
                    JOptionPane.showMessageDialog(
                        this,
                        "Missing required field: $name",
                        "Tool Invocation",
                        JOptionPane.WARNING_MESSAGE,
                    )
                    return null
                }
                continue
            }
            try {
                val value = editor.readJsonValue() ?: continue
                payload[name] = value
            } catch (e: Exception) {
                JOptionPane.showMessageDialog(
                    this,
                    "Invalid value for '$name': ${e.message}",
                    "Tool Invocation",
                    JOptionPane.WARNING_MESSAGE,
                )
                return null
            }
        }

        if (payload.isEmpty()) return null
        return JsonObject(payload).toString()
    }

    private fun createEditor(type: String): FieldEditor =
        when (type) {
            "integer" -> IntegerEditor(styledField())
            "number" -> NumberEditor(styledField())
            "boolean" ->
                BooleanEditor(
                    JComboBox(arrayOf("", "true", "false")).apply {
                        font = UiTheme.Typography.body
                        background = UiTheme.Colors.comboBackground
                        foreground = UiTheme.Colors.comboForeground
                        border = BorderFactory.createLineBorder(UiTheme.Colors.outline, 1, true)
                    },
                )
            "object" -> JsonEditor(styledArea("{}"), "object")
            "array" -> JsonEditor(styledArea("[]"), "array")
            else -> TextEditor(styledField())
        }

    private fun schemaType(schema: JsonElement): String =
        runCatching {
            schema.jsonObject["type"]?.jsonPrimitive?.contentOrNull
        }.getOrNull().orEmpty().ifBlank { "string" }

    private fun styledField(): JTextField =
        JTextField().apply {
            font = UiTheme.Typography.mono
            background = UiTheme.Colors.inputBackground
            foreground = UiTheme.Colors.inputForeground
            border = BorderFactory.createLineBorder(UiTheme.Colors.outline, 1, true)
        }

    private fun styledArea(initialText: String): JTextArea =
        JTextArea(initialText, 4, 20).apply {
            font = UiTheme.Typography.mono
            background = UiTheme.Colors.inputBackground
            foreground = UiTheme.Colors.inputForeground
            lineWrap = true
            wrapStyleWord = true
        }

    private fun styleCombo(combo: JComboBox<*>) {
        combo.font = UiTheme.Typography.body
        combo.background = UiTheme.Colors.comboBackground
        combo.foreground = UiTheme.Colors.comboForeground
        combo.border = BorderFactory.createLineBorder(UiTheme.Colors.outline, 1, true)
    }

    private fun styleButton(button: JButton) {
        button.font = UiTheme.Typography.label
        button.background = UiTheme.Colors.surface
        button.foreground = UiTheme.Colors.primary
        button.border = BorderFactory.createLineBorder(UiTheme.Colors.outline, 1, true)
        button.isFocusPainted = false
    }

    private fun stylePrimaryButton(button: JButton) {
        button.font = UiTheme.Typography.label
        button.background = UiTheme.Colors.primary
        button.foreground = UiTheme.Colors.onPrimary
        button.border = BorderFactory.createEmptyBorder(6, 12, 6, 12)
        button.isFocusPainted = false
    }
}
