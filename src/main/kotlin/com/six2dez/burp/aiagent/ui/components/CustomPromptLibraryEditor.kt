package com.six2dez.burp.aiagent.ui.components

import com.six2dez.burp.aiagent.config.CustomPromptDefinition
import com.six2dez.burp.aiagent.config.CustomPromptTag
import com.six2dez.burp.aiagent.ui.UiTheme
import java.awt.BorderLayout
import java.awt.Dimension
import java.awt.GridLayout
import java.util.UUID
import javax.swing.Box
import javax.swing.BoxLayout
import javax.swing.DefaultListModel
import javax.swing.JButton
import javax.swing.JCheckBox
import javax.swing.JComponent
import javax.swing.JLabel
import javax.swing.JList
import javax.swing.JOptionPane
import javax.swing.JPanel
import javax.swing.JScrollPane
import javax.swing.JTextArea
import javax.swing.JTextField
import javax.swing.ListCellRenderer
import javax.swing.ListSelectionModel

/**
 * Settings panel widget for managing the persistent custom prompt library.
 *
 * Owns a mutable [DefaultListModel]. [snapshot] returns the current ordered list
 * and is pulled into `AgentSettings.copy(customPromptLibrary = ...)` when
 * `SettingsPanel.applyAndSaveSettings` fires.
 */
class CustomPromptLibraryEditor {
    private val listModel: DefaultListModel<CustomPromptDefinition> = DefaultListModel()
    private val list: JList<CustomPromptDefinition> = JList(listModel)
    private val addBtn = JButton("Add")
    private val editBtn = JButton("Edit")
    private val dupBtn = JButton("Duplicate")
    private val delBtn = JButton("Delete")
    private val upBtn = JButton("Move Up")
    private val downBtn = JButton("Move Down")

    init {
        list.selectionMode = ListSelectionModel.SINGLE_SELECTION
        list.cellRenderer = EntryRenderer()
        list.addListSelectionListener { refreshButtons() }

        addBtn.addActionListener { handleAdd() }
        editBtn.addActionListener { handleEdit() }
        dupBtn.addActionListener { handleDuplicate() }
        delBtn.addActionListener { handleDelete() }
        upBtn.addActionListener { handleMove(-1) }
        downBtn.addActionListener { handleMove(1) }

        refreshButtons()
    }

    fun component(): JComponent {
        val root = JPanel(BorderLayout(8, 4))
        val scroll = JScrollPane(list)
        scroll.preferredSize = Dimension(520, 180)
        root.add(scroll, BorderLayout.CENTER)

        val buttons = JPanel()
        buttons.layout = BoxLayout(buttons, BoxLayout.Y_AXIS)
        listOf(addBtn, editBtn, dupBtn, delBtn, Box.createVerticalStrut(8), upBtn, downBtn).forEach {
            buttons.add(it)
            buttons.add(Box.createVerticalStrut(4))
        }
        root.add(buttons, BorderLayout.EAST)
        return root
    }

    fun load(entries: List<CustomPromptDefinition>) {
        listModel.clear()
        entries.forEach { listModel.addElement(it) }
        refreshButtons()
    }

    fun snapshot(): List<CustomPromptDefinition> = (0 until listModel.size()).map { listModel.get(it) }

    private fun refreshButtons() {
        val idx = list.selectedIndex
        val hasSelection = idx >= 0
        editBtn.isEnabled = hasSelection
        dupBtn.isEnabled = hasSelection
        delBtn.isEnabled = hasSelection
        upBtn.isEnabled = hasSelection && idx > 0
        downBtn.isEnabled = hasSelection && idx < listModel.size() - 1
    }

    private fun handleAdd() {
        val created = CustomPromptEditDialog.show(list, null) ?: return
        listModel.addElement(created)
        list.selectedIndex = listModel.size() - 1
    }

    private fun handleEdit() {
        val idx = list.selectedIndex
        if (idx < 0) return
        val updated = CustomPromptEditDialog.show(list, listModel.get(idx)) ?: return
        listModel.set(idx, updated)
    }

    private fun handleDuplicate() {
        val idx = list.selectedIndex
        if (idx < 0) return
        val source = listModel.get(idx)
        val copy =
            source.copy(
                id = UUID.randomUUID().toString(),
                title = source.title + " (copy)",
            )
        listModel.add(idx + 1, copy)
        list.selectedIndex = idx + 1
    }

    private fun handleDelete() {
        val idx = list.selectedIndex
        if (idx < 0) return
        val entry = listModel.get(idx)
        val confirm =
            JOptionPane.showConfirmDialog(
                list,
                "Delete '${entry.title}'?",
                "Delete custom prompt",
                JOptionPane.YES_NO_OPTION,
                JOptionPane.WARNING_MESSAGE,
            )
        if (confirm == JOptionPane.YES_OPTION) {
            listModel.remove(idx)
            refreshButtons()
        }
    }

    private fun handleMove(delta: Int) {
        val idx = list.selectedIndex
        val target = idx + delta
        if (idx < 0 || target < 0 || target >= listModel.size()) return
        val entry = listModel.get(idx)
        listModel.remove(idx)
        listModel.add(target, entry)
        list.selectedIndex = target
    }

    private class EntryRenderer : ListCellRenderer<CustomPromptDefinition> {
        private val base = javax.swing.DefaultListCellRenderer()

        override fun getListCellRendererComponent(
            list: JList<out CustomPromptDefinition>,
            value: CustomPromptDefinition?,
            index: Int,
            isSelected: Boolean,
            cellHasFocus: Boolean,
        ): java.awt.Component {
            val label =
                if (value == null) {
                    ""
                } else {
                    val tags =
                        buildList {
                            if (CustomPromptTag.HTTP_SELECTION in value.tags) add("H")
                            if (CustomPromptTag.SCANNER_ISSUE in value.tags) add("I")
                        }.joinToString("·")
                    val hidden = if (!value.showInContextMenu) " (hidden)" else ""
                    "${value.title}  [$tags]$hidden"
                }
            return base.getListCellRendererComponent(list, label, index, isSelected, cellHasFocus)
        }
    }
}

private object CustomPromptEditDialog {
    fun show(
        parent: JComponent,
        existing: CustomPromptDefinition?,
    ): CustomPromptDefinition? {
        val titleField = JTextField(existing?.title.orEmpty(), 40)
        val textArea =
            JTextArea(existing?.promptText.orEmpty(), 8, 60).apply {
                lineWrap = true
                wrapStyleWord = true
                font = UiTheme.Typography.body
            }
        val httpTag = JCheckBox("HTTP request/response menu", existing?.let { CustomPromptTag.HTTP_SELECTION in it.tags } ?: true)
        val issueTag = JCheckBox("Scanner issue menu", existing?.let { CustomPromptTag.SCANNER_ISSUE in it.tags } ?: false)
        val showInMenu = JCheckBox("Show in context menu", existing?.showInContextMenu ?: true)

        val panel = JPanel(BorderLayout(8, 8))
        panel.preferredSize = Dimension(720, 420)

        val form = JPanel(GridLayout(0, 1, 4, 4))
        form.add(JLabel("Title"))
        form.add(titleField)
        form.add(JLabel("Prompt text"))
        panel.add(form, BorderLayout.NORTH)
        panel.add(JScrollPane(textArea), BorderLayout.CENTER)

        val south = JPanel()
        south.layout = BoxLayout(south, BoxLayout.Y_AXIS)
        south.add(JLabel("Show in:").apply { font = UiTheme.Typography.label })
        south.add(httpTag)
        south.add(issueTag)
        south.add(Box.createVerticalStrut(6))
        south.add(showInMenu)
        panel.add(south, BorderLayout.SOUTH)

        while (true) {
            val result =
                JOptionPane.showConfirmDialog(
                    parent,
                    panel,
                    if (existing == null) "New custom prompt" else "Edit custom prompt",
                    JOptionPane.OK_CANCEL_OPTION,
                    JOptionPane.PLAIN_MESSAGE,
                )
            if (result != JOptionPane.OK_OPTION) return null
            val title = titleField.text.trim()
            val text = textArea.text.trim()
            val tags =
                buildSet {
                    if (httpTag.isSelected) add(CustomPromptTag.HTTP_SELECTION)
                    if (issueTag.isSelected) add(CustomPromptTag.SCANNER_ISSUE)
                }
            if (title.isBlank() || text.isBlank() || tags.isEmpty()) {
                JOptionPane.showMessageDialog(
                    parent,
                    "Title, prompt text, and at least one tag are required.",
                    "Missing fields",
                    JOptionPane.WARNING_MESSAGE,
                )
                continue
            }
            val id = existing?.id ?: UUID.randomUUID().toString()
            return CustomPromptDefinition(
                id = id,
                title = title,
                promptText = text,
                tags = tags,
                showInContextMenu = showInMenu.isSelected,
            )
        }
    }
}
