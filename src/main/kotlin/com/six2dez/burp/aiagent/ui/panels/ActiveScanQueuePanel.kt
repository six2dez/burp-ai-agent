package com.six2dez.burp.aiagent.ui.panels

import com.six2dez.burp.aiagent.scanner.ActiveAiScanner
import com.six2dez.burp.aiagent.scanner.ActiveScanQueueItem
import com.six2dez.burp.aiagent.ui.UiTheme
import java.awt.BorderLayout
import java.awt.Dialog
import java.awt.Dimension
import java.awt.FlowLayout
import java.time.Instant
import java.time.ZoneId
import java.time.format.DateTimeFormatter
import javax.swing.*
import javax.swing.table.AbstractTableModel

object ActiveScanQueuePanel {
    fun showDialog(
        parent: JComponent?,
        scanner: ActiveAiScanner,
    ) {
        val dialog = QueueDialog(parent, scanner)
        dialog.isVisible = true
    }

    private class QueueDialog(
        parent: JComponent?,
        private val scanner: ActiveAiScanner,
    ) : JDialog(
            SwingUtilities.getWindowAncestor(parent),
            "AI Active Scanner Queue",
            Dialog.ModalityType.MODELESS,
        ) {
        private val formatter: DateTimeFormatter =
            DateTimeFormatter
                .ofPattern("yyyy-MM-dd HH:mm:ss")
                .withZone(ZoneId.systemDefault())
        private val model = QueueTableModel(formatter)
        private val table = JTable(model)
        private val statusLabel = JLabel()
        private val refreshButton = JButton("Refresh")
        private val cancelSelectedButton = JButton("Cancel selected")
        private val clearQueueButton = JButton("Clear queue")
        private val closeButton = JButton("Close")
        private val refreshTimer = javax.swing.Timer(2000) { refreshQueue() }

        init {
            layout = BorderLayout(10, 10)
            minimumSize = Dimension(900, 360)
            preferredSize = Dimension(1024, 460)
            rootPane.border = BorderFactory.createEmptyBorder(12, 12, 12, 12)

            val infoLabel = JLabel("Queued active scanner targets (snapshot). Select rows to cancel specific items.")
            infoLabel.font = UiTheme.Typography.body
            infoLabel.foreground = UiTheme.Colors.onSurfaceVariant
            add(infoLabel, BorderLayout.NORTH)

            configureTable()
            add(JScrollPane(table), BorderLayout.CENTER)
            add(buildFooter(), BorderLayout.SOUTH)

            refreshButton.addActionListener { refreshQueue() }
            cancelSelectedButton.addActionListener { cancelSelectedRows() }
            clearQueueButton.addActionListener { clearQueueWithConfirmation() }
            closeButton.addActionListener { dispose() }

            defaultCloseOperation = DISPOSE_ON_CLOSE
            addWindowListener(
                object : java.awt.event.WindowAdapter() {
                    override fun windowClosed(e: java.awt.event.WindowEvent?) {
                        refreshTimer.stop()
                    }
                },
            )

            refreshQueue()
            refreshTimer.start()
            pack()
            setLocationRelativeTo(parent)
        }

        private fun configureTable() {
            table.font = UiTheme.Typography.body
            table.rowHeight = 24
            table.setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION)
            table.autoCreateRowSorter = true
            table.fillsViewportHeight = true
            table.background = UiTheme.Colors.surface
            table.foreground = UiTheme.Colors.onSurface
            table.gridColor = UiTheme.Colors.outlineVariant
            table.tableHeader.font = UiTheme.Typography.label
            table.tableHeader.background = UiTheme.Colors.surface
            table.tableHeader.foreground = UiTheme.Colors.onSurface
        }

        private fun buildFooter(): JPanel {
            val footer = JPanel(BorderLayout(8, 8))
            footer.background = UiTheme.Colors.surface

            statusLabel.font = UiTheme.Typography.body
            statusLabel.foreground = UiTheme.Colors.onSurfaceVariant

            val buttons = JPanel(FlowLayout(FlowLayout.RIGHT, 8, 0))
            buttons.background = UiTheme.Colors.surface
            styleButton(refreshButton, outlined = true)
            styleButton(cancelSelectedButton, outlined = true)
            styleButton(clearQueueButton, outlined = true)
            styleButton(closeButton, outlined = false)
            buttons.add(refreshButton)
            buttons.add(cancelSelectedButton)
            buttons.add(clearQueueButton)
            buttons.add(closeButton)

            footer.add(statusLabel, BorderLayout.WEST)
            footer.add(buttons, BorderLayout.EAST)
            return footer
        }

        private fun styleButton(
            button: JButton,
            outlined: Boolean,
        ) {
            button.font = UiTheme.Typography.label
            button.background = UiTheme.Colors.surface
            button.foreground = UiTheme.Colors.primary
            button.isFocusPainted = false
            if (outlined) {
                button.border = BorderFactory.createLineBorder(UiTheme.Colors.outline, 1, true)
            } else {
                button.border = BorderFactory.createEmptyBorder(6, 12, 6, 12)
            }
        }

        private fun refreshQueue() {
            val items = scanner.getQueueItems(limit = 5_000)
            model.setItems(items)
            statusLabel.text = "Queue size: ${items.size}"
        }

        private fun cancelSelectedRows() {
            val selectedRows = table.selectedRows
            if (selectedRows.isEmpty()) {
                JOptionPane.showMessageDialog(
                    this,
                    "Select one or more queued rows to cancel.",
                    "No selection",
                    JOptionPane.INFORMATION_MESSAGE,
                )
                return
            }

            val ids =
                selectedRows
                    .map { table.convertRowIndexToModel(it) }
                    .distinct()
                    .mapNotNull { model.targetIdAt(it) }

            var removed = 0
            ids.forEach { id ->
                if (scanner.cancelQueuedTarget(id)) {
                    removed++
                }
            }

            refreshQueue()
            JOptionPane.showMessageDialog(
                this,
                "Cancelled $removed queued target(s).",
                "Queue updated",
                JOptionPane.INFORMATION_MESSAGE,
            )
        }

        private fun clearQueueWithConfirmation() {
            val choice =
                JOptionPane.showConfirmDialog(
                    this,
                    "Clear all queued active scan targets?",
                    "Confirm queue clear",
                    JOptionPane.YES_NO_OPTION,
                    JOptionPane.WARNING_MESSAGE,
                )
            if (choice == JOptionPane.YES_OPTION) {
                scanner.clearQueue()
                refreshQueue()
            }
        }
    }

    private class QueueTableModel(
        private val formatter: DateTimeFormatter,
    ) : AbstractTableModel() {
        private val columns = arrayOf("Queued At", "Vulnerability", "Injection Point", "URL", "Status")
        private var rows: List<ActiveScanQueueItem> = emptyList()

        fun setItems(items: List<ActiveScanQueueItem>) {
            rows = items
            fireTableDataChanged()
        }

        fun targetIdAt(modelRow: Int): String? = rows.getOrNull(modelRow)?.id

        override fun getRowCount(): Int = rows.size

        override fun getColumnCount(): Int = columns.size

        override fun getColumnName(column: Int): String = columns[column]

        override fun getValueAt(
            rowIndex: Int,
            columnIndex: Int,
        ): Any {
            val row = rows[rowIndex]
            return when (columnIndex) {
                0 -> formatter.format(Instant.ofEpochMilli(row.queuedAtEpochMs))
                1 -> row.vulnClass
                2 -> row.injectionPoint
                3 -> row.url
                4 -> row.status
                else -> ""
            }
        }
    }
}
