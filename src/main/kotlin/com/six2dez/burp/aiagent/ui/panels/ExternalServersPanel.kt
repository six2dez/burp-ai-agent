package com.six2dez.burp.aiagent.ui.panels

import com.six2dez.burp.aiagent.mcp.external.ExternalMcpServerConfig
import com.six2dez.burp.aiagent.mcp.external.ExternalMcpTransport
import com.six2dez.burp.aiagent.ui.components.AccordionPanel
import com.six2dez.burp.aiagent.ui.components.SubtleNotice
import com.six2dez.burp.aiagent.ui.components.ToggleSwitch
import com.six2dez.burp.aiagent.ui.design.BadgeStyle
import com.six2dez.burp.aiagent.ui.design.DesignTokens
import com.six2dez.burp.aiagent.ui.design.addRowFull
import com.six2dez.burp.aiagent.ui.design.addSpacerRow
import com.six2dez.burp.aiagent.ui.design.applyAreaStyle
import com.six2dez.burp.aiagent.ui.design.applyFieldStyle
import com.six2dez.burp.aiagent.ui.design.formGrid
import com.six2dez.burp.aiagent.ui.design.helpLabel
import com.six2dez.burp.aiagent.ui.design.primaryButton
import com.six2dez.burp.aiagent.ui.design.secondaryButton
import com.six2dez.burp.aiagent.ui.design.sectionPanel
import com.six2dez.burp.aiagent.ui.design.toolBadge
import com.six2dez.burp.aiagent.util.SsrfGuard
import java.awt.BorderLayout
import java.awt.Component
import java.awt.Dimension
import java.awt.EventQueue
import java.awt.FlowLayout
import java.awt.Graphics
import java.awt.Graphics2D
import java.awt.RenderingHints
import javax.swing.AbstractCellEditor
import javax.swing.BorderFactory
import javax.swing.Box
import javax.swing.BoxLayout
import javax.swing.DefaultComboBoxModel
import javax.swing.JComboBox
import javax.swing.JLabel
import javax.swing.JOptionPane
import javax.swing.JPanel
import javax.swing.JPasswordField
import javax.swing.JScrollPane
import javax.swing.JTable
import javax.swing.JTextArea
import javax.swing.JTextField
import javax.swing.ListSelectionModel
import javax.swing.border.EmptyBorder
import javax.swing.border.LineBorder
import javax.swing.event.DocumentEvent
import javax.swing.event.DocumentListener
import javax.swing.table.AbstractTableModel
import javax.swing.table.TableCellEditor
import javax.swing.table.TableCellRenderer

/**
 * CRUD UI panel for external MCP server registration.
 *
 * Crypto contract: bearer tokens are held as PLAINTEXT in [JPasswordField] and in
 * [ExternalMcpServerConfig.bearerToken]. Encryption happens in
 * [AgentSettingsRepository.saveExternalMcpServers] at the persistence boundary — this panel
 * never calls SecretCipher and never stores ENC1:-prefixed ciphertext.
 */
class ExternalServersPanel(
    private val initialServers: List<ExternalMcpServerConfig> = emptyList(),
    private val stdioEnabled: Boolean = false,
) {
    // ── Internal list of configured servers ─────────────────────────────────────────────────────
    private val servers: MutableList<ExternalMcpServerConfig> = initialServers.toMutableList()

    // ── Table model ─────────────────────────────────────────────────────────────────────────────
    private val tableModel = ExternalServerTableModel()

    // ── Form state ──────────────────────────────────────────────────────────────────────────────

    /** Index of the server being edited, or -1 when adding a new entry. */
    private var editingIndex: Int = -1

    // ── Form fields ─────────────────────────────────────────────────────────────────────────────
    private val nameField = JTextField(30).apply { applyFieldStyle(this) }
    private val transportCombo = buildTransportCombo()
    private val enabledToggle = ToggleSwitch(true)

    // SSE sub-fields
    private val urlField =
        JTextField(40).apply {
            applyFieldStyle(this)
            font = DesignTokens.Typography.mono
        }
    private val ssrfWarningLabel =
        JLabel(
            "Warning: this URL resolves to a private/internal address — verify this is intentional",
        ).apply {
            foreground = DesignTokens.Colors.statusWarning
            font = DesignTokens.Typography.caption
            isVisible = false
        }
    private val tokenField =
        JPasswordField(20).apply {
            applyFieldStyle(this)
            font = DesignTokens.Typography.mono
        }
    private val showHideButton =
        secondaryButton("Show").apply {
            addActionListener {
                if (tokenField.echoChar == '*') {
                    tokenField.echoChar = 0.toChar()
                    text = "Hide"
                } else {
                    tokenField.echoChar = '*'
                    text = "Show"
                }
            }
        }

    // stdio sub-fields
    private val commandField =
        JTextField(40).apply {
            applyFieldStyle(this)
            font = DesignTokens.Typography.mono
        }
    private val argsField =
        JTextField(40).apply {
            applyFieldStyle(this)
            font = DesignTokens.Typography.mono
        }
    private val envVarsArea =
        JTextArea(3, 30).apply {
            applyAreaStyle(this)
        }
    private val stdioNotice =
        SubtleNotice().apply {
            setMessage(
                level = SubtleNotice.Level.RISK,
                html =
                    "<b>Warning:</b> This server will run a local process using the command above. " +
                        "Only configure commands you trust. The process is spawned with no shell " +
                        "expansion and only the environment variables you provide.",
            )
            isVisible = false
        }

    // Validation error labels
    private val nameErrorLabel =
        JLabel("Display name is required").apply {
            font = DesignTokens.Typography.caption
            foreground = DesignTokens.Colors.statusError
            isVisible = false
        }
    private val urlErrorLabel =
        JLabel("URL must start with http:// or https://").apply {
            font = DesignTokens.Typography.caption
            foreground = DesignTokens.Colors.statusError
            isVisible = false
        }
    private val commandErrorLabel =
        JLabel("Command is required for stdio transport").apply {
            font = DesignTokens.Typography.caption
            foreground = DesignTokens.Colors.statusError
            isVisible = false
        }
    private val duplicateNameLabel =
        JLabel("A server with this name already exists").apply {
            font = DesignTokens.Typography.caption
            foreground = DesignTokens.Colors.statusError
            isVisible = false
        }

    // ── Dynamic UI elements ─────────────────────────────────────────────────────────────────────
    private val formTitleLabel =
        JLabel("Add External Server").apply {
            font = DesignTokens.Typography.sectionTitle
            foreground = DesignTokens.Colors.onSurface
            border = EmptyBorder(DesignTokens.Spacing.sm, 0, DesignTokens.Spacing.sm, 0)
        }
    private val serverCountLabel =
        JLabel("External Servers (${servers.size})").apply {
            font = DesignTokens.Typography.label
            foreground = DesignTokens.Colors.onSurface
        }

    // Sub-panel containers (toggled by transport selection)
    private lateinit var sseSubPanel: JPanel
    private lateinit var stdioSubPanel: JPanel
    private lateinit var formCard: JPanel
    private lateinit var emptyStateLabel: JLabel
    private lateinit var tableScrollPane: JScrollPane

    // ── Public API ───────────────────────────────────────────────────────────────────────────────

    /**
     * Returns the fully-wired section panel for embedding in SettingsPanel.
     */
    fun buildPanel(): JPanel {
        val table = buildTable()
        emptyStateLabel =
            buildEmptyStateLabel()

        val headerRow =
            JPanel(FlowLayout(FlowLayout.LEFT, 8, 4)).apply {
                background = DesignTokens.Colors.surface
                add(serverCountLabel)
                add(Box.createRigidArea(Dimension(DesignTokens.Spacing.sm, 0)))
                add(
                    primaryButton("Add Server").apply {
                        addActionListener { showAddForm() }
                    },
                )
            }

        tableScrollPane =
            JScrollPane(table).apply {
                border = EmptyBorder(0, 0, 0, 0)
                viewport.background = DesignTokens.Colors.surface
            }

        formCard = buildFormCard()

        val stack =
            JPanel().apply {
                layout = BoxLayout(this, BoxLayout.Y_AXIS)
                background = DesignTokens.Colors.surface
                add(headerRow)
                add(emptyStateLabel)
                add(tableScrollPane)
                add(formCard)
            }

        refreshEmptyState()

        val accordion =
            AccordionPanel(
                title = "External MCP Servers",
                subtitle = "Add and manage external MCP servers.",
                content = stack,
                initiallyExpanded = false,
            ).apply {
                border = BorderFactory.createEmptyBorder(DesignTokens.Spacing.sm, 0, 0, 0)
            }

        val body =
            JPanel(BorderLayout()).apply {
                background = DesignTokens.Colors.surface
                add(accordion, BorderLayout.CENTER)
            }

        return sectionPanel(
            "External MCP Servers",
            "Connect to external or custom MCP servers and use their tools alongside Burp's built-in tools.",
            body,
        )
    }

    /**
     * Returns the current list for persistence. Each item has a PLAINTEXT [bearerToken] —
     * encryption happens in [AgentSettingsRepository.saveExternalMcpServers].
     */
    fun getServers(): List<ExternalMcpServerConfig> = servers.toList()

    /**
     * Replaces the internal list and refreshes the table. Items carry PLAINTEXT [bearerToken]
     * values (decrypted by [AgentSettingsRepository.loadExternalMcpServers]).
     */
    fun setServers(newServers: List<ExternalMcpServerConfig>) {
        servers.clear()
        servers.addAll(newServers)
        tableModel.fireTableDataChanged()
        refreshEmptyState()
        updateServerCountLabel()
    }

    // ── Table construction ───────────────────────────────────────────────────────────────────────

    private fun buildTable(): JTable =
        JTable(tableModel).apply {
            autoResizeMode = JTable.AUTO_RESIZE_LAST_COLUMN
            setSelectionMode(ListSelectionModel.SINGLE_SELECTION)
            font = DesignTokens.Typography.body
            rowHeight = 24
            tableHeader.font = DesignTokens.Typography.label

            // Column widths
            columnModel.getColumn(COL_ENABLE).preferredWidth = 56
            columnModel.getColumn(COL_NAME).preferredWidth = 160
            columnModel.getColumn(COL_TRANSPORT).preferredWidth = 72
            columnModel.getColumn(COL_STATUS).preferredWidth = 120
            columnModel.getColumn(COL_ACTIONS).preferredWidth = 108

            // Transport badge renderer
            setDefaultRenderer(ExternalMcpTransport::class.java, TransportBadgeRenderer())

            // Status dot renderer
            setDefaultRenderer(String::class.java, StatusDotRenderer())

            // Actions column renderer + editor
            columnModel.getColumn(COL_ACTIONS).cellRenderer = ActionsCellRenderer()
            columnModel.getColumn(COL_ACTIONS).cellEditor = ActionsCellEditor()
        }

    private fun buildEmptyStateLabel(): JLabel =
        JLabel(
            "No external MCP servers configured. Click 'Add Server' to register one.",
        ).apply {
            font = DesignTokens.Typography.body
            foreground = DesignTokens.Colors.onSurfaceVariant
            horizontalAlignment = JLabel.CENTER
            border = EmptyBorder(DesignTokens.Spacing.lg, 0, DesignTokens.Spacing.lg, 0)
            alignmentX = Component.CENTER_ALIGNMENT
        }

    private fun refreshEmptyState() {
        if (!::emptyStateLabel.isInitialized) return
        val isEmpty = servers.isEmpty()
        emptyStateLabel.isVisible = isEmpty
        tableScrollPane.isVisible = !isEmpty
    }

    // ── Form card construction ───────────────────────────────────────────────────────────────────

    private fun buildFormCard(): JPanel {
        sseSubPanel = buildSseSubPanel()
        stdioSubPanel = buildStdioSubPanel()

        transportCombo.addActionListener { onTransportChanged() }

        val grid = formGrid()
        addRowFull(grid, "Display name", nameField)
        addRowFull(grid, "", nameErrorLabel)
        addRowFull(grid, "", duplicateNameLabel)
        addSpacerRow(grid, DesignTokens.Spacing.xs)
        addRowFull(grid, "Transport", transportCombo)
        addSpacerRow(grid, DesignTokens.Spacing.xs)
        addRowFull(grid, "Enabled", enabledToggle)
        addSpacerRow(grid, DesignTokens.Spacing.xs)
        addRowFull(grid, "", sseSubPanel)
        addRowFull(grid, "", stdioSubPanel)
        addSpacerRow(grid, DesignTokens.Spacing.xs)

        val buttonRow =
            JPanel().apply {
                layout = BoxLayout(this, BoxLayout.X_AXIS)
                isOpaque = false
                add(
                    primaryButton("Save Server").apply {
                        addActionListener { onSaveClicked() }
                    },
                )
                add(Box.createRigidArea(Dimension(DesignTokens.Spacing.sm, 0)))
                add(
                    secondaryButton("Cancel").apply {
                        addActionListener { hideFormCard() }
                    },
                )
            }

        return JPanel().apply {
            layout = BoxLayout(this, BoxLayout.Y_AXIS)
            background = DesignTokens.Colors.surface
            border = EmptyBorder(DesignTokens.Spacing.sm, 0, DesignTokens.Spacing.sm, 0)
            isVisible = false

            add(formTitleLabel)
            add(grid)
            add(buttonRow)
        }
    }

    private fun buildSseSubPanel(): JPanel {
        val tokenPanel =
            JPanel().apply {
                layout = BoxLayout(this, BoxLayout.X_AXIS)
                isOpaque = false
                add(tokenField)
                add(Box.createRigidArea(Dimension(DesignTokens.Spacing.sm, 0)))
                add(showHideButton)
            }

        // Wire SSRF warning to URL field
        urlField.document.addDocumentListener(
            object : DocumentListener {
                override fun insertUpdate(e: DocumentEvent?) = checkSsrfWarning()

                override fun removeUpdate(e: DocumentEvent?) = checkSsrfWarning()

                override fun changedUpdate(e: DocumentEvent?) = checkSsrfWarning()

                private fun checkSsrfWarning() {
                    ssrfWarningLabel.isVisible =
                        urlField.text.isNotBlank() &&
                        SsrfGuard.isPrivateOrLinkLocal(urlField.text)
                }
            },
        )

        val panel = formGrid()
        addRowFull(panel, "Server URL", urlField)
        addRowFull(panel, "", helpLabel("SSE endpoint URL (e.g. https://myserver.example.com/sse)"))
        addRowFull(panel, "", ssrfWarningLabel)
        addRowFull(panel, "", urlErrorLabel)
        addSpacerRow(panel, DesignTokens.Spacing.xs)
        addRowFull(panel, "Bearer token", tokenPanel)
        addRowFull(panel, "", helpLabel("Optional authentication token. Stored encrypted at rest."))

        return JPanel(BorderLayout()).apply {
            isOpaque = false
            add(panel, BorderLayout.CENTER)
            isVisible = true
        }
    }

    private fun buildStdioSubPanel(): JPanel {
        val panel = formGrid()
        addRowFull(panel, "Command", commandField)
        addRowFull(panel, "", helpLabel("Full command to spawn the MCP server process (e.g. npx -y @modelcontextprotocol/server-filesystem /tmp)"))
        addRowFull(panel, "", commandErrorLabel)
        addSpacerRow(panel, DesignTokens.Spacing.xs)
        addRowFull(panel, "Extra arguments", argsField)
        addRowFull(panel, "", helpLabel("Additional arguments (space-separated)"))
        addSpacerRow(panel, DesignTokens.Spacing.xs)
        addRowFull(panel, "Environment vars", JScrollPane(envVarsArea))
        addRowFull(panel, "", helpLabel("KEY=VALUE pairs (one per line). Only these variables are passed to the process."))
        addSpacerRow(panel, DesignTokens.Spacing.xs)
        addRowFull(panel, "", stdioNotice)

        return JPanel(BorderLayout()).apply {
            isOpaque = false
            add(panel, BorderLayout.CENTER)
            isVisible = false
        }
    }

    private fun buildTransportCombo(): JComboBox<String> {
        val items = if (stdioEnabled) arrayOf("SSE", "stdio") else arrayOf("SSE")
        return JComboBox<String>(DefaultComboBoxModel(items)).apply {
            font = DesignTokens.Typography.body
        }
    }

    // ── Form logic ───────────────────────────────────────────────────────────────────────────────

    private fun onTransportChanged() {
        val isStdio = transportCombo.selectedItem == "stdio"
        sseSubPanel.isVisible = !isStdio
        stdioSubPanel.isVisible = isStdio && stdioEnabled
        stdioNotice.isVisible = isStdio && stdioEnabled
        formCard.revalidate()
        formCard.repaint()
    }

    private fun showAddForm() {
        editingIndex = -1
        formTitleLabel.text = "Add External Server"

        // Reset fields
        nameField.text = ""
        transportCombo.selectedIndex = 0
        enabledToggle.isSelected = true
        urlField.text = ""
        tokenField.text = ""
        tokenField.echoChar = '*'
        showHideButton.text = "Show"
        commandField.text = ""
        argsField.text = ""
        envVarsArea.text = ""

        clearValidationErrors()
        ssrfWarningLabel.isVisible = false
        stdioNotice.isVisible = false

        sseSubPanel.isVisible = true
        stdioSubPanel.isVisible = false

        formCard.isVisible = true
        formCard.revalidate()
        formCard.repaint()
    }

    private fun showEditForm(rowIndex: Int) {
        if (rowIndex < 0 || rowIndex >= servers.size) return
        editingIndex = rowIndex
        val config = servers[rowIndex]

        formTitleLabel.text = "Edit: ${config.name}"

        nameField.text = config.name
        transportCombo.selectedItem =
            when (config.transport) {
                ExternalMcpTransport.SSE -> "SSE"
                ExternalMcpTransport.STDIO -> "stdio"
            }
        enabledToggle.isSelected = config.enabled
        urlField.text = config.url
        tokenField.text = config.bearerToken
        tokenField.echoChar = '*'
        showHideButton.text = "Show"

        commandField.text = config.command.joinToString(" ")
        argsField.text = config.extraArgs.joinToString(" ")
        envVarsArea.text = config.envVars.entries.joinToString("\n") { "${it.key}=${it.value}" }

        clearValidationErrors()

        // Re-evaluate SSRF on load
        ssrfWarningLabel.isVisible =
            config.url.isNotBlank() &&
            SsrfGuard.isPrivateOrLinkLocal(config.url)

        val isStdio = config.transport == ExternalMcpTransport.STDIO
        sseSubPanel.isVisible = !isStdio
        stdioSubPanel.isVisible = isStdio && stdioEnabled
        stdioNotice.isVisible = isStdio && stdioEnabled

        formCard.isVisible = true
        formCard.revalidate()
        formCard.repaint()
    }

    private fun hideFormCard() {
        formCard.isVisible = false
        clearValidationErrors()
    }

    private fun clearValidationErrors() {
        nameField.border = LineBorder(DesignTokens.Colors.border, 1, true)
        urlField.border = LineBorder(DesignTokens.Colors.border, 1, true)
        commandField.border = LineBorder(DesignTokens.Colors.border, 1, true)
        nameErrorLabel.isVisible = false
        urlErrorLabel.isVisible = false
        commandErrorLabel.isVisible = false
        duplicateNameLabel.isVisible = false
    }

    private fun onSaveClicked() {
        clearValidationErrors()
        var valid = true

        val name = nameField.text.trim()
        val isStdio = transportCombo.selectedItem == "stdio"
        val url = urlField.text.trim()
        val command = commandField.text.trim()

        if (name.isBlank()) {
            nameField.border = LineBorder(DesignTokens.Colors.statusError, 2, true)
            nameErrorLabel.isVisible = true
            valid = false
        }

        val duplicateExists =
            servers.indices
                .filter { it != editingIndex }
                .any { servers[it].name == name }
        if (name.isNotBlank() && duplicateExists) {
            nameField.border = LineBorder(DesignTokens.Colors.statusError, 2, true)
            duplicateNameLabel.isVisible = true
            valid = false
        }

        if (!isStdio) {
            if (url.isBlank() || (!url.startsWith("http://") && !url.startsWith("https://"))) {
                urlField.border = LineBorder(DesignTokens.Colors.statusError, 2, true)
                urlErrorLabel.isVisible = true
                valid = false
            }
        }

        if (isStdio && stdioEnabled) {
            if (command.isBlank()) {
                commandField.border = LineBorder(DesignTokens.Colors.statusError, 2, true)
                commandErrorLabel.isVisible = true
                valid = false
            }
        }

        if (!valid) return

        val transport = if (isStdio) ExternalMcpTransport.STDIO else ExternalMcpTransport.SSE

        // Parse command list for stdio
        val commandList = if (isStdio) command.split(" ").filter { it.isNotBlank() } else emptyList()
        val extraArgsList =
            argsField.text
                .trim()
                .split(" ")
                .filter { it.isNotBlank() }
        val envMap =
            envVarsArea.text
                .lines()
                .mapNotNull { line ->
                    val idx = line.indexOf('=')
                    if (idx > 0) line.substring(0, idx).trim() to line.substring(idx + 1) else null
                }.toMap()

        // Bearer token is read as PLAINTEXT from the JPasswordField —
        // encryption happens in AgentSettingsRepository.saveExternalMcpServers() at persist time.
        val bearerToken = String(tokenField.password).trim()

        val newConfig =
            ExternalMcpServerConfig(
                name = name,
                transport = transport,
                url = if (isStdio) "" else url,
                command = commandList,
                extraArgs = extraArgsList,
                envVars = envMap,
                bearerToken = bearerToken,
                enabled = enabledToggle.isSelected,
            )

        if (editingIndex >= 0) {
            servers[editingIndex] = newConfig
        } else {
            servers.add(newConfig)
        }

        tableModel.fireTableDataChanged()
        hideFormCard()
        refreshEmptyState()
        updateServerCountLabel()
    }

    private fun confirmAndRemove(rowIndex: Int) {
        if (rowIndex < 0 || rowIndex >= servers.size) return
        val config = servers[rowIndex]
        val result =
            JOptionPane.showConfirmDialog(
                null,
                "Remove '${config.name}'? The server will be disconnected and all its tools removed from the agent.",
                "Remove Server",
                JOptionPane.YES_NO_OPTION,
                JOptionPane.WARNING_MESSAGE,
            )
        if (result == JOptionPane.YES_OPTION) {
            servers.removeAt(rowIndex)
            tableModel.fireTableDataChanged()
            refreshEmptyState()
            updateServerCountLabel()
        }
    }

    private fun updateServerCountLabel() {
        serverCountLabel.text = "External Servers (${servers.size})"
    }

    // ── Column indices ───────────────────────────────────────────────────────────────────────────

    companion object {
        const val COL_ENABLE = 0
        const val COL_NAME = 1
        const val COL_TRANSPORT = 2
        const val COL_STATUS = 3
        const val COL_ACTIONS = 4

        /** Diameter of the status-indicator oval in pixels. */
        private const val STATUS_DOT_SIZE = 8

        /** Left-edge x-offset for the status-indicator oval paint position. */
        private const val STATUS_DOT_X_OFFSET = 4

        /** Horizontal gap in FlowLayout for status/badge cells. */
        private const val STATUS_CELL_HGAP = 4

        /** Vertical gap in FlowLayout for badge cells. */
        private const val BADGE_CELL_VGAP = 2
    }

    // ── Table model ──────────────────────────────────────────────────────────────────────────────

    inner class ExternalServerTableModel : AbstractTableModel() {
        private val columns =
            arrayOf("Enable", "Name", "Transport", "Status", "Actions")

        override fun getRowCount(): Int = servers.size

        override fun getColumnCount(): Int = columns.size

        override fun getColumnName(column: Int): String = columns[column]

        override fun getColumnClass(columnIndex: Int): Class<*> =
            when (columnIndex) {
                COL_ENABLE -> java.lang.Boolean::class.java
                COL_TRANSPORT -> ExternalMcpTransport::class.java
                else -> String::class.java
            }

        override fun isCellEditable(
            rowIndex: Int,
            columnIndex: Int,
        ): Boolean = columnIndex == COL_ENABLE || columnIndex == COL_ACTIONS

        override fun getValueAt(
            rowIndex: Int,
            columnIndex: Int,
        ): Any {
            if (rowIndex >= servers.size) return ""
            val config = servers[rowIndex]
            return when (columnIndex) {
                COL_ENABLE -> config.enabled
                COL_NAME -> config.name
                COL_TRANSPORT -> config.transport
                COL_STATUS -> if (config.enabled) "Disconnected" else "Disabled"
                COL_ACTIONS -> "..."
                else -> ""
            }
        }

        override fun setValueAt(
            value: Any?,
            rowIndex: Int,
            columnIndex: Int,
        ) {
            if (columnIndex == COL_ENABLE && rowIndex < servers.size) {
                val enabled = (value as? Boolean) ?: return
                servers[rowIndex] = servers[rowIndex].copy(enabled = enabled)
                fireTableCellUpdated(rowIndex, COL_ENABLE)
                fireTableCellUpdated(rowIndex, COL_STATUS)
            }
        }
    }

    // ── Transport badge renderer ─────────────────────────────────────────────────────────────────

    private inner class TransportBadgeRenderer : TableCellRenderer {
        private val sseBadge = toolBadge("SSE", BadgeStyle.FULL)
        private val stdioBadge = toolBadge("stdio", BadgeStyle.NATIVE)

        override fun getTableCellRendererComponent(
            table: JTable,
            value: Any?,
            isSelected: Boolean,
            hasFocus: Boolean,
            row: Int,
            column: Int,
        ): Component {
            val badge =
                when (value as? ExternalMcpTransport) {
                    ExternalMcpTransport.STDIO -> stdioBadge
                    else -> sseBadge
                }
            badge.background = if (isSelected) table.selectionBackground else table.background
            return JPanel(FlowLayout(FlowLayout.LEFT, STATUS_CELL_HGAP, BADGE_CELL_VGAP)).apply {
                background = if (isSelected) table.selectionBackground else table.background
                add(badge)
            }
        }
    }

    // ── Status dot renderer ──────────────────────────────────────────────────────────────────────

    private inner class StatusDotRenderer : TableCellRenderer {
        override fun getTableCellRendererComponent(
            table: JTable,
            value: Any?,
            isSelected: Boolean,
            hasFocus: Boolean,
            row: Int,
            column: Int,
        ): Component {
            val statusText = value as? String ?: ""
            val dotColor =
                when {
                    statusText.startsWith("Connected") -> DesignTokens.Colors.statusSuccess
                    statusText.startsWith("Connecting") -> DesignTokens.Colors.statusWarning
                    statusText.startsWith("Retrying") -> DesignTokens.Colors.statusWarning
                    statusText == "Error" -> DesignTokens.Colors.statusError
                    else -> DesignTokens.Colors.onSurfaceVariant
                }
            val textColor =
                when {
                    statusText.startsWith("Connected") -> DesignTokens.Colors.statusSuccess
                    statusText.startsWith("Connecting") -> DesignTokens.Colors.statusWarning
                    statusText.startsWith("Retrying") -> DesignTokens.Colors.statusWarning
                    statusText == "Error" -> DesignTokens.Colors.statusError
                    else -> DesignTokens.Colors.onSurfaceVariant
                }

            return object : JPanel(FlowLayout(FlowLayout.LEFT, STATUS_CELL_HGAP, 0)) {
                override fun paintComponent(g: Graphics) {
                    super.paintComponent(g)
                    val g2 = g as Graphics2D
                    g2.setRenderingHint(
                        RenderingHints.KEY_ANTIALIASING,
                        RenderingHints.VALUE_ANTIALIAS_ON,
                    )
                    g2.color = dotColor
                    val yOff = (height - STATUS_DOT_SIZE) / 2
                    g2.fillOval(STATUS_DOT_X_OFFSET, yOff, STATUS_DOT_SIZE, STATUS_DOT_SIZE)
                }
            }.apply {
                isOpaque = true
                background = if (isSelected) table.selectionBackground else table.background
                add(
                    JLabel(statusText).apply {
                        font = DesignTokens.Typography.body
                        foreground = textColor
                        border = EmptyBorder(0, 8, 0, 0)
                    },
                )
            }
        }
    }

    // ── Actions cell renderer ────────────────────────────────────────────────────────────────────

    private inner class ActionsCellRenderer : TableCellRenderer {
        private val panel = buildActionsPanel()

        override fun getTableCellRendererComponent(
            table: JTable,
            value: Any?,
            isSelected: Boolean,
            hasFocus: Boolean,
            row: Int,
            column: Int,
        ): Component {
            panel.background = if (isSelected) table.selectionBackground else table.background
            return panel
        }

        private fun buildActionsPanel(): JPanel =
            JPanel(FlowLayout(FlowLayout.LEFT, 0, 0)).apply {
                isOpaque = true
                add(secondaryButton("Edit"))
                add(Box.createRigidArea(Dimension(DesignTokens.Spacing.sm, 0)))
                add(secondaryButton("Remove"))
            }
    }

    // ── Actions cell editor ──────────────────────────────────────────────────────────────────────

    private inner class ActionsCellEditor :
        AbstractCellEditor(),
        TableCellEditor {
        private var currentRow: Int = -1
        private val editBtn =
            secondaryButton("Edit").apply {
                addActionListener {
                    stopCellEditing()
                    val r = currentRow
                    EventQueue.invokeLater { showEditForm(r) }
                }
            }
        private val removeBtn =
            secondaryButton("Remove").apply {
                addActionListener {
                    stopCellEditing()
                    val r = currentRow
                    EventQueue.invokeLater { confirmAndRemove(r) }
                }
            }
        private val panel =
            JPanel(FlowLayout(FlowLayout.LEFT, 0, 0)).apply {
                isOpaque = true
                add(editBtn)
                add(Box.createRigidArea(Dimension(DesignTokens.Spacing.sm, 0)))
                add(removeBtn)
            }

        override fun getCellEditorValue(): Any = "..."

        override fun getTableCellEditorComponent(
            table: JTable,
            value: Any?,
            isSelected: Boolean,
            row: Int,
            column: Int,
        ): Component {
            currentRow = row
            panel.background = table.selectionBackground
            return panel
        }
    }
}
