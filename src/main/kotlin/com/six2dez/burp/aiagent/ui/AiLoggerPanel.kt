package com.six2dez.burp.aiagent.ui

import com.six2dez.burp.aiagent.audit.ActivityType
import com.six2dez.burp.aiagent.audit.AiActivityEntry
import com.six2dez.burp.aiagent.audit.AiRequestLogger
import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.databind.SerializationFeature
import java.awt.BorderLayout
import java.util.ArrayDeque
import java.awt.Component
import java.awt.FlowLayout
import java.text.SimpleDateFormat
import java.util.Date
import javax.swing.*
import javax.swing.border.EmptyBorder
import javax.swing.event.DocumentEvent
import javax.swing.event.DocumentListener
import javax.swing.table.AbstractTableModel
import javax.swing.table.DefaultTableCellRenderer

/**
 * Swing panel that displays a live, filterable table of AI request log entries
 * with a detail pane to inspect full prompt/response text.
 */
class AiLoggerPanel(private val logger: AiRequestLogger) {
    val root: JComponent = JPanel(BorderLayout())

    private val tableModel = AiLogTableModel()
    private val table = JTable(tableModel)
    private val detailArea = JTextArea()
    private val presetFilter = JComboBox(arrayOf("All", "Errors only", "Slow (>=3s)", "Tool failures"))
    private val typeFilter = JComboBox(arrayOf("All", "Prompt", "Response", "MCP Tool", "Error", "Scanner", "Retry"))
    private val sourceFilter = JComboBox(arrayOf("All", "agent", "chat", "backend", "mcp", "passive_scanner", "active_scanner"))
    private val traceFilter = JTextField(14)
    private val clearButton = JButton("Clear")
    private val exportButton = JButton("Export JSON")
    private val countLabel = JLabel("0 entries")

    private val dateFormat = SimpleDateFormat("HH:mm:ss.SSS")

    // All entries (unfiltered) — bounded to prevent OOM with prolonged use
    private val maxEntries = 5_000
    private val allEntries = ArrayDeque<AiActivityEntry>(maxEntries)

    private val listener: (AiActivityEntry) -> Unit = { entry ->
        SwingUtilities.invokeLater {
            if (allEntries.size >= maxEntries) {
                allEntries.removeFirst()
            }
            allEntries.addLast(entry)
            applyFilter()
        }
    }

    init {
        root.background = UiTheme.Colors.surface

        // ── Toolbar ──
        val toolbar = JPanel(FlowLayout(FlowLayout.LEFT, 8, 4))
        toolbar.background = UiTheme.Colors.surface
        toolbar.border = EmptyBorder(4, 8, 4, 8)

        val typeLabel = JLabel("Type:")
        typeLabel.font = UiTheme.Typography.label
        typeLabel.foreground = UiTheme.Colors.onSurfaceVariant
        val presetLabel = JLabel("Preset:")
        presetLabel.font = UiTheme.Typography.label
        presetLabel.foreground = UiTheme.Colors.onSurfaceVariant
        toolbar.add(presetLabel)
        presetFilter.font = UiTheme.Typography.body
        presetFilter.addActionListener { applyFilter() }
        toolbar.add(presetFilter)

        toolbar.add(typeLabel)
        typeFilter.font = UiTheme.Typography.body
        typeFilter.addActionListener { applyFilter() }
        toolbar.add(typeFilter)

        val sourceLabel = JLabel("Source:")
        sourceLabel.font = UiTheme.Typography.label
        sourceLabel.foreground = UiTheme.Colors.onSurfaceVariant
        toolbar.add(sourceLabel)
        sourceFilter.font = UiTheme.Typography.body
        sourceFilter.addActionListener { applyFilter() }
        toolbar.add(sourceFilter)

        toolbar.add(Box.createHorizontalStrut(16))
        val traceLabel = JLabel("Trace:")
        traceLabel.font = UiTheme.Typography.label
        traceLabel.foreground = UiTheme.Colors.onSurfaceVariant
        toolbar.add(traceLabel)
        traceFilter.font = UiTheme.Typography.body
        traceFilter.toolTipText = "Filter by trace ID"
        traceFilter.document.addDocumentListener(object : DocumentListener {
            override fun insertUpdate(e: DocumentEvent?) = applyFilter()
            override fun removeUpdate(e: DocumentEvent?) = applyFilter()
            override fun changedUpdate(e: DocumentEvent?) = applyFilter()
        })
        toolbar.add(traceFilter)
        toolbar.add(Box.createHorizontalStrut(16))

        clearButton.font = UiTheme.Typography.label
        clearButton.addActionListener {
            logger.clear()
            allEntries.clear()
            applyFilter()
        }
        toolbar.add(clearButton)

        exportButton.font = UiTheme.Typography.label
        exportButton.addActionListener { exportJson() }
        toolbar.add(exportButton)

        toolbar.add(Box.createHorizontalStrut(16))
        countLabel.font = UiTheme.Typography.body
        countLabel.foreground = UiTheme.Colors.onSurfaceVariant
        toolbar.add(countLabel)

        // ── Table ──
        table.autoResizeMode = JTable.AUTO_RESIZE_LAST_COLUMN
        table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION)
        table.font = UiTheme.Typography.body
        table.rowHeight = 22
        table.tableHeader.font = UiTheme.Typography.label
        table.setDefaultRenderer(Any::class.java, AiLogCellRenderer())

        // Column widths
        table.columnModel.getColumn(0).preferredWidth = 90   // Time
        table.columnModel.getColumn(1).preferredWidth = 80   // Type
        table.columnModel.getColumn(2).preferredWidth = 90   // Source
        table.columnModel.getColumn(3).preferredWidth = 100  // Backend
        table.columnModel.getColumn(4).preferredWidth = 110  // Operation
        table.columnModel.getColumn(5).preferredWidth = 70   // Status
        table.columnModel.getColumn(6).preferredWidth = 190  // Trace
        table.columnModel.getColumn(7).preferredWidth = 330  // Detail
        table.columnModel.getColumn(8).preferredWidth = 70   // Duration
        table.columnModel.getColumn(9).preferredWidth = 60   // Prompt
        table.columnModel.getColumn(10).preferredWidth = 60  // Response

        table.selectionModel.addListSelectionListener {
            if (!it.valueIsAdjusting) {
                showDetail()
            }
        }

        val tableScroll = JScrollPane(table)
        tableScroll.border = EmptyBorder(0, 0, 0, 0)

        // ── Detail pane ──
        detailArea.isEditable = false
        detailArea.font = UiTheme.Typography.mono
        detailArea.lineWrap = true
        detailArea.wrapStyleWord = true
        detailArea.background = UiTheme.Colors.surface
        detailArea.foreground = UiTheme.Colors.onSurface
        detailArea.border = EmptyBorder(8, 8, 8, 8)

        val detailScroll = JScrollPane(detailArea)
        detailScroll.border = EmptyBorder(0, 0, 0, 0)
        detailScroll.preferredSize = java.awt.Dimension(0, 120)

        // ── Split view ──
        val splitPane = JSplitPane(JSplitPane.VERTICAL_SPLIT, tableScroll, detailScroll)
        splitPane.resizeWeight = 0.7
        splitPane.border = EmptyBorder(0, 0, 0, 0)

        root.add(toolbar, BorderLayout.NORTH)
        root.add(splitPane, BorderLayout.CENTER)

        // Register listener
        logger.addListener(listener)
    }

    fun shutdown() {
        logger.removeListener(listener)
    }

    private fun applyFilter() {
        val selectedPreset = presetFilter.selectedItem as? String ?: "All"
        val selectedType = typeFilter.selectedItem as? String ?: "All"
        val selectedSource = sourceFilter.selectedItem as? String ?: "All"
        val traceQuery = traceFilter.text.trim().lowercase()

        val filtered = allEntries.filter { entry ->
            val typeMatch = when (selectedType) {
                "All" -> true
                "Prompt" -> entry.type == ActivityType.PROMPT_SENT
                "Response" -> entry.type == ActivityType.RESPONSE_COMPLETE
                "MCP Tool" -> entry.type == ActivityType.MCP_TOOL_CALL
                "Error" -> entry.type == ActivityType.ERROR
                "Scanner" -> entry.type == ActivityType.SCANNER_SEND
                "Retry" -> entry.type == ActivityType.RETRY
                else -> true
            }
            val sourceMatch = selectedSource == "All" || entry.source == selectedSource
            val status = entry.metadata["status"].orEmpty().lowercase()
            val presetMatch = when (selectedPreset) {
                "Errors only" -> entry.type == ActivityType.ERROR || status == "error" || status == "blocked"
                "Slow (>=3s)" -> (entry.durationMs ?: 0L) >= 3_000L
                "Tool failures" -> entry.type == ActivityType.MCP_TOOL_CALL && (status == "error" || status == "blocked")
                else -> true
            }
            val traceId = entry.metadata["traceId"].orEmpty().lowercase()
            val traceMatch = traceQuery.isBlank() || traceId.contains(traceQuery)
            typeMatch && sourceMatch && presetMatch && traceMatch
        }

        tableModel.setData(filtered)
        countLabel.text = "${filtered.size} entries (${allEntries.size} total)"
    }

    private fun showDetail() {
        val row = table.selectedRow
        if (row < 0 || row >= tableModel.rowCount) {
            detailArea.text = ""
            return
        }
        val entry = tableModel.getEntryAt(row)
        val sb = StringBuilder()
        sb.appendLine("ID: ${entry.id}")
        sb.appendLine("Time: ${dateFormat.format(Date(entry.timestamp))}")
        sb.appendLine("Type: ${entry.type}")
        sb.appendLine("Source: ${entry.source}")
        sb.appendLine("Backend: ${entry.backendId}")
        if (entry.sessionId != null) sb.appendLine("Session: ${entry.sessionId}")
        entry.metadata["operation"]?.takeIf { it.isNotBlank() }?.let { sb.appendLine("Operation: $it") }
        entry.metadata["status"]?.takeIf { it.isNotBlank() }?.let { sb.appendLine("Status: $it") }
        entry.metadata["traceId"]?.takeIf { it.isNotBlank() }?.let { sb.appendLine("Trace: $it") }
        if (entry.durationMs != null) sb.appendLine("Duration: ${entry.durationMs}ms")
        if (entry.promptChars != null) sb.appendLine("Prompt chars: ${entry.promptChars}")
        if (entry.responseChars != null) sb.appendLine("Response chars: ${entry.responseChars}")
        if (entry.tokenUsage != null) {
            sb.appendLine("Input tokens: ${entry.tokenUsage.inputTokens}")
            sb.appendLine("Output tokens: ${entry.tokenUsage.outputTokens}")
        }
        sb.appendLine()
        sb.appendLine("── Detail ──")
        sb.appendLine(entry.detail)
        if (entry.metadata.isNotEmpty()) {
            sb.appendLine()
            sb.appendLine("── Metadata ──")
            entry.metadata.forEach { (k, v) -> sb.appendLine("$k: $v") }
        }
        detailArea.text = sb.toString()
        detailArea.caretPosition = 0
    }

    private fun exportJson() {
        val chooser = JFileChooser()
        chooser.selectedFile = java.io.File("ai_request_log.json")
        val result = chooser.showSaveDialog(root)
        if (result != JFileChooser.APPROVE_OPTION) return

        try {
            val mapper = ObjectMapper().enable(SerializationFeature.INDENT_OUTPUT)
            val data = logger.exportAsMapList()
            mapper.writeValue(chooser.selectedFile, data)
            JOptionPane.showMessageDialog(root, "Exported ${data.size} entries to ${chooser.selectedFile.name}")
        } catch (e: Exception) {
            JOptionPane.showMessageDialog(root, "Export failed: ${e.message}", "Error", JOptionPane.ERROR_MESSAGE)
        }
    }

    // ── Table model ──
    private inner class AiLogTableModel : AbstractTableModel() {
        private val columns = arrayOf(
            "Time",
            "Type",
            "Source",
            "Backend",
            "Operation",
            "Status",
            "Trace",
            "Detail",
            "Duration",
            "Prompt",
            "Response"
        )
        private var data = listOf<AiActivityEntry>()

        fun setData(entries: List<AiActivityEntry>) {
            data = entries
            fireTableDataChanged()
        }

        fun getEntryAt(row: Int): AiActivityEntry = data[row]

        override fun getRowCount(): Int = data.size
        override fun getColumnCount(): Int = columns.size
        override fun getColumnName(column: Int): String = columns[column]

        override fun getValueAt(rowIndex: Int, columnIndex: Int): Any {
            val entry = data[rowIndex]
            return when (columnIndex) {
                0 -> dateFormat.format(Date(entry.timestamp))
                1 -> formatType(entry.type)
                2 -> entry.source
                3 -> entry.backendId
                4 -> entry.metadata["operation"] ?: "-"
                5 -> entry.metadata["status"] ?: "-"
                6 -> entry.metadata["traceId"] ?: "-"
                7 -> entry.detail.take(120)
                8 -> if (entry.durationMs != null) "${entry.durationMs}ms" else "-"
                9 -> entry.promptChars?.toString() ?: "-"
                10 -> entry.responseChars?.toString() ?: "-"
                else -> ""
            }
        }

        private fun formatType(type: ActivityType): String = when (type) {
            ActivityType.PROMPT_SENT -> "→ Prompt"
            ActivityType.RESPONSE_COMPLETE -> "← Response"
            ActivityType.MCP_TOOL_CALL -> "⚙ MCP Tool"
            ActivityType.RETRY -> "↻ Retry"
            ActivityType.ERROR -> "✗ Error"
            ActivityType.SCANNER_SEND -> "🔍 Scanner"
        }
    }

    // ── Cell renderer ──
    private inner class AiLogCellRenderer : DefaultTableCellRenderer() {
        override fun getTableCellRendererComponent(
            table: JTable, value: Any?, isSelected: Boolean, hasFocus: Boolean, row: Int, column: Int
        ): Component {
            val component = super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column)
            if (!isSelected && row < tableModel.rowCount) {
                val entry = tableModel.getEntryAt(row)
                foreground = when (entry.type) {
                    ActivityType.ERROR -> UiTheme.Colors.statusCrashed
                    ActivityType.PROMPT_SENT -> UiTheme.Colors.primary
                    ActivityType.RESPONSE_COMPLETE -> UiTheme.Colors.statusRunning
                    ActivityType.MCP_TOOL_CALL -> UiTheme.Colors.onSurfaceVariant
                    ActivityType.SCANNER_SEND -> UiTheme.Colors.statusTerminal
                    ActivityType.RETRY -> UiTheme.Colors.statusTerminal
                }
            }
            border = EmptyBorder(2, 6, 2, 6)
            return component
        }
    }
}
