package com.six2dez.burp.aiagent.ui.components

import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.databind.SerializationFeature
import com.fasterxml.jackson.module.kotlin.registerKotlinModule
import com.six2dez.burp.aiagent.config.CustomPromptDefinition
import com.six2dez.burp.aiagent.config.CustomPromptTag
import com.six2dez.burp.aiagent.ui.UiTheme
import java.awt.BorderLayout
import java.awt.Dimension
import java.awt.GridLayout
import java.io.File
import java.util.UUID
import javax.swing.Box
import javax.swing.BoxLayout
import javax.swing.DefaultListModel
import javax.swing.JButton
import javax.swing.JCheckBox
import javax.swing.JComponent
import javax.swing.JFileChooser
import javax.swing.JLabel
import javax.swing.JList
import javax.swing.JOptionPane
import javax.swing.JPanel
import javax.swing.JScrollPane
import javax.swing.JTextArea
import javax.swing.JTextField
import javax.swing.ListCellRenderer
import javax.swing.ListSelectionModel
import javax.swing.event.DocumentEvent
import javax.swing.event.DocumentListener
import javax.swing.filechooser.FileNameExtensionFilter

/**
 * Settings panel widget for managing the persistent custom prompt library.
 *
 * Holds a [master] list as the source of truth and renders a filtered + sorted view into a Swing
 * [DefaultListModel]. [snapshot] returns the master list (with favorites moved to the top, since
 * the rest of the application shows them in that order via [CustomPromptDefinition.sortFavoritesFirst]).
 *
 * Features:
 * - Free-form search filter across title + prompt text.
 * - Favorite toggle that bubbles entries to the top of the master list.
 * - JSON import/export so users can share their prompt library across machines.
 */
class CustomPromptLibraryEditor {
    private val master: MutableList<CustomPromptDefinition> = mutableListOf()
    private val listModel: DefaultListModel<CustomPromptDefinition> = DefaultListModel()
    private val list: JList<CustomPromptDefinition> = JList(listModel)
    private val searchField = JTextField()
    private val addBtn = JButton("Add")
    private val editBtn = JButton("Edit")
    private val dupBtn = JButton("Duplicate")
    private val delBtn = JButton("Delete")
    private val favBtn = JButton("Toggle Favorite")
    private val upBtn = JButton("Move Up")
    private val downBtn = JButton("Move Down")
    private val importBtn = JButton("Import…")
    private val exportBtn = JButton("Export…")

    init {
        list.selectionMode = ListSelectionModel.SINGLE_SELECTION
        list.cellRenderer = EntryRenderer()
        list.addListSelectionListener { refreshButtons() }

        addBtn.addActionListener { handleAdd() }
        editBtn.addActionListener { handleEdit() }
        dupBtn.addActionListener { handleDuplicate() }
        delBtn.addActionListener { handleDelete() }
        favBtn.addActionListener { handleToggleFavorite() }
        upBtn.addActionListener { handleMove(-1) }
        downBtn.addActionListener { handleMove(1) }
        importBtn.addActionListener { handleImport() }
        exportBtn.addActionListener { handleExport() }

        searchField.toolTipText = "Filter prompts by title or text (case-insensitive)."
        searchField.document.addDocumentListener(
            object : DocumentListener {
                override fun insertUpdate(e: DocumentEvent?) = refreshList()

                override fun removeUpdate(e: DocumentEvent?) = refreshList()

                override fun changedUpdate(e: DocumentEvent?) = refreshList()
            },
        )

        refreshButtons()
    }

    fun component(): JComponent {
        val root = JPanel(BorderLayout(8, 4))

        val searchRow = JPanel(BorderLayout(8, 0))
        searchRow.add(JLabel("Search"), BorderLayout.WEST)
        searchRow.add(searchField, BorderLayout.CENTER)
        root.add(searchRow, BorderLayout.NORTH)

        val scroll = JScrollPane(list)
        scroll.preferredSize = Dimension(520, 180)
        root.add(scroll, BorderLayout.CENTER)

        val buttons = JPanel()
        buttons.layout = BoxLayout(buttons, BoxLayout.Y_AXIS)
        listOf(
            addBtn,
            editBtn,
            dupBtn,
            delBtn,
            Box.createVerticalStrut(8),
            favBtn,
            Box.createVerticalStrut(8),
            upBtn,
            downBtn,
            Box.createVerticalStrut(8),
            importBtn,
            exportBtn,
        ).forEach {
            buttons.add(it)
            buttons.add(Box.createVerticalStrut(4))
        }
        root.add(buttons, BorderLayout.EAST)
        return root
    }

    fun load(entries: List<CustomPromptDefinition>) {
        master.clear()
        master.addAll(CustomPromptDefinition.sortFavoritesFirst(entries))
        refreshList()
    }

    /**
     * Returns the current library with favorites moved to the top, matching what the user sees in
     * the editor. Saved as-is into [com.six2dez.burp.aiagent.config.AgentSettings.customPromptLibrary].
     */
    fun snapshot(): List<CustomPromptDefinition> = CustomPromptDefinition.sortFavoritesFirst(master.toList())

    private fun refreshList() {
        val sorted = CustomPromptDefinition.sortFavoritesFirst(master)
        val filtered = CustomPromptDefinition.searchFilter(sorted, searchField.text)
        listModel.clear()
        filtered.forEach { listModel.addElement(it) }
        refreshButtons()
    }

    private fun selectedEntry(): CustomPromptDefinition? {
        val idx = list.selectedIndex
        if (idx < 0) return null
        return listModel.get(idx)
    }

    private fun masterIndexOf(entry: CustomPromptDefinition): Int = master.indexOfFirst { it.id == entry.id }

    private fun refreshButtons() {
        val hasSelection = list.selectedIndex >= 0
        editBtn.isEnabled = hasSelection
        dupBtn.isEnabled = hasSelection
        delBtn.isEnabled = hasSelection
        favBtn.isEnabled = hasSelection
        // Move up/down operate on the master list. They are enabled iff the selected entry has a
        // neighbour of the same favorite-status to swap with — preserves the favorites-first
        // grouping users see in the rendered list.
        val selected = selectedEntry()
        upBtn.isEnabled = selected != null && hasNeighborOfSameStatus(selected, -1)
        downBtn.isEnabled = selected != null && hasNeighborOfSameStatus(selected, 1)
        exportBtn.isEnabled = master.isNotEmpty()
    }

    private fun hasNeighborOfSameStatus(
        entry: CustomPromptDefinition,
        direction: Int,
    ): Boolean {
        val idx = masterIndexOf(entry)
        if (idx < 0) return false
        var probe = idx + direction
        while (probe in master.indices) {
            if (master[probe].isFavorite == entry.isFavorite) return true
            probe += direction
        }
        return false
    }

    private fun handleAdd() {
        val created = CustomPromptEditDialog.show(list, null) ?: return
        master.add(created)
        refreshList()
        // Select the newly created entry by id.
        selectById(created.id)
    }

    private fun handleEdit() {
        val current = selectedEntry() ?: return
        val updated = CustomPromptEditDialog.show(list, current) ?: return
        val idx = masterIndexOf(current)
        if (idx >= 0) master[idx] = updated
        refreshList()
        selectById(updated.id)
    }

    private fun handleDuplicate() {
        val source = selectedEntry() ?: return
        val copy =
            source.copy(
                id = UUID.randomUUID().toString(),
                title = source.title + " (copy)",
            )
        val idx = masterIndexOf(source)
        if (idx >= 0) master.add(idx + 1, copy) else master.add(copy)
        refreshList()
        selectById(copy.id)
    }

    private fun handleDelete() {
        val entry = selectedEntry() ?: return
        val confirm =
            JOptionPane.showConfirmDialog(
                list,
                "Delete '${entry.title}'?",
                "Delete custom prompt",
                JOptionPane.YES_NO_OPTION,
                JOptionPane.WARNING_MESSAGE,
            )
        if (confirm == JOptionPane.YES_OPTION) {
            master.removeAll { it.id == entry.id }
            refreshList()
        }
    }

    private fun handleToggleFavorite() {
        val entry = selectedEntry() ?: return
        val idx = masterIndexOf(entry)
        if (idx < 0) return
        master[idx] = entry.copy(isFavorite = !entry.isFavorite)
        refreshList()
        selectById(entry.id)
    }

    private fun handleMove(delta: Int) {
        val entry = selectedEntry() ?: return
        val idx = masterIndexOf(entry)
        if (idx < 0) return
        // Find the next neighbour with the same favorite status — preserves grouping after move.
        var target = idx + delta
        while (target in master.indices && master[target].isFavorite != entry.isFavorite) {
            target += delta
        }
        if (target !in master.indices) return
        val moved = master.removeAt(idx)
        master.add(target, moved)
        refreshList()
        selectById(entry.id)
    }

    private fun handleImport() {
        val chooser = JFileChooser()
        chooser.fileFilter = FileNameExtensionFilter("JSON files", "json")
        if (chooser.showOpenDialog(list) != JFileChooser.APPROVE_OPTION) return
        val file = chooser.selectedFile ?: return
        val imported =
            try {
                JSON_MAPPER.readValue(file, Array<CustomPromptDefinition>::class.java).toList()
            } catch (e: Exception) {
                JOptionPane.showMessageDialog(
                    list,
                    "Failed to parse JSON: ${e.message}",
                    "Import failed",
                    JOptionPane.ERROR_MESSAGE,
                )
                return
            }
        // Drop invalid entries, then de-dup by id so a malformed import file with internal
        // duplicates can't introduce ambiguous ids into `master` (later id-based lookups would
        // become non-deterministic). Last occurrence wins via the LinkedHashMap of distinctBy.
        val valid = imported.filter { it.isValid() }.distinctBy { it.id }
        if (valid.isEmpty()) {
            JOptionPane.showMessageDialog(
                list,
                "No valid prompts found in the file.",
                "Nothing to import",
                JOptionPane.WARNING_MESSAGE,
            )
            return
        }
        // Merge by id: incoming entries replace existing ones, new entries are appended.
        val existingIds = master.map { it.id }.toSet()
        val (replacements, additions) = valid.partition { it.id in existingIds }
        replacements.forEach { incoming ->
            val idx = master.indexOfFirst { it.id == incoming.id }
            if (idx >= 0) master[idx] = incoming
        }
        master.addAll(additions)
        refreshList()
        JOptionPane.showMessageDialog(
            list,
            "Imported ${replacements.size} updated and ${additions.size} new prompt(s).",
            "Import complete",
            JOptionPane.INFORMATION_MESSAGE,
        )
    }

    private fun handleExport() {
        if (master.isEmpty()) return
        val chooser = JFileChooser()
        chooser.fileFilter = FileNameExtensionFilter("JSON files", "json")
        chooser.selectedFile = File("burp-ai-agent-prompts.json")
        if (chooser.showSaveDialog(list) != JFileChooser.APPROVE_OPTION) return
        var target = chooser.selectedFile ?: return
        if (!target.name.lowercase().endsWith(".json")) {
            target = File(target.parentFile, target.name + ".json")
        }
        // Export in the same order that `snapshot()` would persist (favorites first), so the file
        // round-trips identically through import/export and matches what users see in the editor.
        val payload = CustomPromptDefinition.sortFavoritesFirst(master.toList())
        try {
            JSON_MAPPER.writerWithDefaultPrettyPrinter().writeValue(target, payload)
        } catch (e: Exception) {
            JOptionPane.showMessageDialog(
                list,
                "Failed to write JSON: ${e.message}",
                "Export failed",
                JOptionPane.ERROR_MESSAGE,
            )
            return
        }
        JOptionPane.showMessageDialog(
            list,
            "Exported ${master.size} prompt(s) to ${target.name}.",
            "Export complete",
            JOptionPane.INFORMATION_MESSAGE,
        )
    }

    private fun selectById(id: String) {
        for (i in 0 until listModel.size()) {
            if (listModel.get(i).id == id) {
                list.selectedIndex = i
                return
            }
        }
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
                    val star = if (value.isFavorite) "★ " else ""
                    "$star${value.title}  [$tags]$hidden"
                }
            return base.getListCellRendererComponent(list, label, index, isSelected, cellHasFocus)
        }
    }

    companion object {
        private val JSON_MAPPER: ObjectMapper =
            ObjectMapper()
                .registerKotlinModule()
                .enable(SerializationFeature.INDENT_OUTPUT)
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
        val favorite = JCheckBox("Favorite (pin to top)", existing?.isFavorite ?: false)

        val panel = JPanel(BorderLayout(8, 8))
        panel.preferredSize = Dimension(720, 440)

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
        south.add(favorite)
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
                isFavorite = favorite.isSelected,
            )
        }
    }
}
