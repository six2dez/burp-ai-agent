package com.six2dez.burp.aiagent.ui

import burp.api.montoya.MontoyaApi
import com.six2dez.burp.aiagent.agents.AgentProfileLoader
import com.six2dez.burp.aiagent.config.AgentSettings
import com.six2dez.burp.aiagent.context.ContextCapture
import com.six2dez.burp.aiagent.mcp.McpRequestLimiter
import com.six2dez.burp.aiagent.mcp.McpToolCatalog
import com.six2dez.burp.aiagent.mcp.McpToolContext
import com.six2dez.burp.aiagent.mcp.tools.McpToolExecutor
import com.six2dez.burp.aiagent.redact.PrivacyMode
import com.six2dez.burp.aiagent.supervisor.AgentSupervisor
import com.six2dez.burp.aiagent.ui.components.ActionCard
import com.six2dez.burp.aiagent.ui.components.PrivacyPill
import java.awt.BorderLayout
import java.awt.Dimension
import java.awt.event.KeyAdapter
import java.awt.event.KeyEvent
import java.net.URI
import java.util.UUID
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import javax.swing.DefaultListModel
import javax.swing.JButton
import javax.swing.JComponent
import javax.swing.JLabel
import javax.swing.JList
import javax.swing.JPanel
import javax.swing.BoxLayout
import javax.swing.JScrollPane
import javax.swing.JTextArea
import javax.swing.ListSelectionModel
import javax.swing.SwingUtilities
import javax.swing.border.EmptyBorder

class ChatPanel(
    private val api: MontoyaApi,
    private val supervisor: AgentSupervisor,
    private val getSettings: () -> AgentSettings,
    private val applySettings: (AgentSettings) -> Unit,
    private val validateBackend: (AgentSettings) -> String?,
    private val ensureBackendReady: (AgentSettings) -> Boolean,
    private val showError: (String) -> Unit,
    private val onStatusChanged: () -> Unit,
    private val onResponseReady: () -> Unit
) {
    val root: JComponent = JPanel(BorderLayout())
    private val sessionsModel = DefaultListModel<ChatSession>()
    private val sessionsList = JList(sessionsModel)
    private val sessionsPanel = JPanel(BorderLayout())
    private val chatCards = JPanel(java.awt.CardLayout())
    private val sendBtn = JButton("Send")
    private val clearChatBtn = JButton("Clear Chat")
    private val toolsBtn = JButton("Tools")
    private val inputArea = JTextArea(3, 24)
    private val newSessionBtn = JButton("New Session")
    private val privacyPill = PrivacyPill()
    private val sessionPanels = linkedMapOf<String, SessionPanel>()
    private val sessionStates = linkedMapOf<String, ToolSessionState>()
    private val sessionsById = linkedMapOf<String, ChatSession>()
    private var mcpAvailable = true

    init {
        root.background = UiTheme.Colors.surface

        sessionsList.selectionMode = ListSelectionModel.SINGLE_SELECTION
        sessionsList.font = UiTheme.Typography.body
        sessionsList.cellRenderer = ChatSessionRenderer()
        sessionsList.background = UiTheme.Colors.surface
        sessionsList.foreground = UiTheme.Colors.onSurface
        sessionsList.addListSelectionListener {
            val selected = sessionsList.selectedValue ?: return@addListSelectionListener
            showSession(selected.id)
        }
        sessionsList.addMouseListener(object : java.awt.event.MouseAdapter() {
            override fun mousePressed(e: java.awt.event.MouseEvent) {
                if (SwingUtilities.isRightMouseButton(e)) {
                    val index = sessionsList.locationToIndex(e.point)
                    if (index != -1) {
                        sessionsList.selectedIndex = index
                        showSessionContextMenu(e.component, e.x, e.y)
                    }
                }
            }
        })

        clearChatBtn.font = UiTheme.Typography.label
        clearChatBtn.isFocusPainted = false
        clearChatBtn.addActionListener { clearCurrentChat() }

        toolsBtn.font = UiTheme.Typography.label
        toolsBtn.isFocusPainted = false
        toolsBtn.toolTipText = "Browse and invoke MCP tools. Select a tool to insert /tool <id> {} into input. Fill JSON args and Send to execute."
        toolsBtn.addActionListener { showToolsMenu() }

        newSessionBtn.font = UiTheme.Typography.label
        newSessionBtn.isFocusPainted = false
        newSessionBtn.addActionListener { createSession("Chat ${sessionsModel.size + 1}") }

        val listScroll = JScrollPane(sessionsList)
        listScroll.border = EmptyBorder(8, 8, 8, 8)
        listScroll.preferredSize = Dimension(200, 400)

        val listHeader = JPanel(BorderLayout())
        listHeader.isOpaque = false
        val listTitle = JLabel("Sessions")
        listTitle.font = UiTheme.Typography.label
        listTitle.foreground = UiTheme.Colors.onSurfaceVariant
        listHeader.add(listTitle, BorderLayout.WEST)
        listHeader.add(newSessionBtn, BorderLayout.EAST)
        listHeader.border = EmptyBorder(8, 12, 8, 12)

        sessionsPanel.add(listHeader, BorderLayout.NORTH)
        sessionsPanel.add(listScroll, BorderLayout.CENTER)
        sessionsPanel.background = UiTheme.Colors.surface

        val chatContainer = JPanel(BorderLayout())
        chatContainer.background = UiTheme.Colors.surface
        chatContainer.add(chatCards, BorderLayout.CENTER)
        chatContainer.add(inputPanel(), BorderLayout.SOUTH)

        root.add(chatContainer, BorderLayout.CENTER)
    }

    fun sessionsComponent(): JComponent = sessionsPanel

    fun setMcpAvailable(available: Boolean) {
        mcpAvailable = available
        updateChatAvailability()
    }

    fun refreshPrivacyMode() {
        updatePrivacyPill()
    }

    private fun updateChatAvailability() {
        sendBtn.isEnabled = mcpAvailable
        clearChatBtn.isEnabled = mcpAvailable
        toolsBtn.isEnabled = mcpAvailable
        inputArea.isEnabled = mcpAvailable
        newSessionBtn.isEnabled = mcpAvailable
    }

    fun startSessionFromContext(capture: ContextCapture, promptTemplate: String, actionName: String) {
        updatePrivacyPill()
        val uri = extractUriFromContext(capture)
        val title = if (uri.isNullOrBlank()) actionName else "$actionName: $uri"
        val session = createSession(title)
        val panel = sessionPanels[session.id] ?: return
        val prompt = promptTemplate.trim().ifBlank { "Analyze the provided context." }
        val state = sessionStates[session.id] ?: ToolSessionState()
        val actionCard = buildActionCard(capture, actionName, prompt, session.id, state)
        panel.addComponent(actionCard)
        panel.addMessage(
            role = "You",
            text = prompt
        )
        sendMessage(
            sessionId = session.id,
            userText = prompt,
            contextJson = capture.contextJson,
            allowToolCalls = state.toolsMode,
            actionName = actionName
        )
    }

    private fun inputPanel(): JPanel {
        val panel = JPanel(BorderLayout())
        panel.background = UiTheme.Colors.surface
        panel.border = EmptyBorder(10, 12, 12, 12)

        inputArea.lineWrap = true
        inputArea.wrapStyleWord = true
        inputArea.font = UiTheme.Typography.body
        inputArea.background = UiTheme.Colors.inputBackground
        inputArea.foreground = UiTheme.Colors.inputForeground
        inputArea.border = javax.swing.border.LineBorder(UiTheme.Colors.outline, 1, true)
        inputArea.addKeyListener(object : KeyAdapter() {
            override fun keyPressed(e: KeyEvent) {
                if (e.keyCode == KeyEvent.VK_ENTER && (e.isControlDown || e.isMetaDown)) {
                    e.consume()
                    sendFromInput()
                }
            }
        })

        sendBtn.font = UiTheme.Typography.label
        sendBtn.isFocusPainted = false
        sendBtn.addActionListener { sendFromInput() }
        updatePrivacyPill()

        panel.add(JScrollPane(inputArea), BorderLayout.CENTER)
        val actions = JPanel()
        actions.layout = javax.swing.BoxLayout(actions, javax.swing.BoxLayout.X_AXIS)
        actions.background = UiTheme.Colors.surface
        actions.add(privacyPill)
        actions.add(javax.swing.Box.createRigidArea(Dimension(8, 0)))
        actions.add(toolsBtn)
        actions.add(javax.swing.Box.createRigidArea(Dimension(8, 0)))
        actions.add(clearChatBtn)
        actions.add(javax.swing.Box.createRigidArea(Dimension(8, 0)))
        actions.add(sendBtn)
        panel.add(actions, BorderLayout.EAST)
        return panel
    }

    private fun sendFromInput() {
        val text = inputArea.text.trim()
        if (text.isBlank()) return
        val session = sessionsList.selectedValue ?: createSession("Chat ${sessionsModel.size + 1}")
        val panel = sessionPanels[session.id] ?: return
        val state = sessionStates.getOrPut(session.id) { ToolSessionState() }
        val settings = getSettings()
        updatePrivacyPill()
        if (handleToolCommand(text, session.id, panel, state, settings)) {
            inputArea.text = ""
            return
        }
        panel.addMessage("You", text)
        inputArea.text = ""
        sendMessage(
            session.id,
            text,
            contextJson = null,
            allowToolCalls = state.toolsMode,
            actionName = "Chat"
        )
    }

    private fun sendMessage(
        sessionId: String,
        userText: String,
        contextJson: String?,
        allowToolCalls: Boolean,
        actionName: String? = null
    ) {
        val settings = getSettings()
        updatePrivacyPill()
        if (!ensureBackendReady(settings)) return
        val error = validateBackend(settings)
        if (error != null) {
            showError(error)
            return
        }

        applySettings(settings)
        val session = sessionsById[sessionId]
        val backendId = session?.backendId ?: settings.preferredBackendId
        onStatusChanged()

        val sessionPanel = sessionPanels[sessionId] ?: return
        val assistant = sessionPanel.addStreamingMessage("AI")
        val state = sessionStates.getOrPut(sessionId) { ToolSessionState() }
        val toolContext = if (state.toolsMode) buildToolContext(settings, sessionId) else null
        val toolPreamble = if (state.toolsMode) buildToolPreamble(toolContext, state, mutateState = true) else null
        val prompt = buildContextPayload(userText, contextJson, actionName)
        val finalPrompt = listOfNotNull(
            toolPreamble?.takeIf { it.isNotBlank() },
            prompt.takeIf { it.isNotBlank() }
        ).joinToString("\n\n")

        val responseBuffer = StringBuilder()
        supervisor.sendChat(
            chatSessionId = sessionId,
            backendId = backendId,
            text = finalPrompt,
            contextJson = contextJson,
            privacyMode = settings.privacyMode,
            determinismMode = settings.determinismMode,
            onChunk = { chunk ->
                responseBuffer.append(chunk)
                SwingUtilities.invokeLater { assistant.append(chunk) }
            },
            onComplete = { err ->
                if (err != null) {
                    SwingUtilities.invokeLater { assistant.append("\n[Error] ${err.message}") }
                } else {
                    SwingUtilities.invokeLater {
                        assistant.append("\n")
                        onResponseReady()
                    }
                    if (allowToolCalls && state.toolsMode && toolContext != null) {
                        maybeExecuteToolCall(
                            sessionId = sessionId,
                            userText = userText,
                            responseText = responseBuffer.toString(),
                            context = toolContext,
                            settings = settings
                        )
                    }
                }
            }
        )
    }

    private fun createSession(title: String): ChatSession {
        val id = "chat-" + UUID.randomUUID().toString()
        val backendId = getSettings().preferredBackendId
        val session = ChatSession(id, title, System.currentTimeMillis(), backendId)
        sessionsModel.addElement(session)
        sessionsById[id] = session

        val panel = SessionPanel()
        sessionPanels[id] = panel
        sessionStates[id] = ToolSessionState()
        chatCards.add(panel.root, id)
        sessionsList.selectedIndex = sessionsModel.size - 1
        showSession(id)
        return session
    }

    private fun showSessionContextMenu(comp: java.awt.Component, x: Int, y: Int) {
        val selected = sessionsList.selectedValue ?: return
        val menu = javax.swing.JPopupMenu()
        
        val renameItem = javax.swing.JMenuItem("Rename")
        renameItem.addActionListener { renameSession(selected) }
        
        val deleteItem = javax.swing.JMenuItem("Delete")
        deleteItem.addActionListener { deleteSession(selected) }
        
        menu.add(renameItem)
        menu.add(deleteItem)
        menu.show(comp, x, y)
    }

    private fun renameSession(session: ChatSession) {
        val newName = javax.swing.JOptionPane.showInputDialog(
            root, 
            "Enter new session name:", 
            session.title
        )
        if (!newName.isNullOrBlank()) {
            val index = sessionsModel.indexOf(session)
            if (index != -1) {
                // To update the list view we need to replace the element or trigger update
                // Since ChatSession is immutable (data class), we create a copy
                val updated = session.copy(title = newName.trim())
                sessionsModel.set(index, updated)
                sessionsById[session.id] = updated
            }
        }
    }

    private fun deleteSession(session: ChatSession) {
        val confirm = javax.swing.JOptionPane.showConfirmDialog(
            root,
            "Delete session '${session.title}'?",
            "Delete Session",
            javax.swing.JOptionPane.YES_NO_OPTION
        )
        if (confirm == javax.swing.JOptionPane.YES_OPTION) {
            supervisor.removeChatSession(session.id)
            val removedPanel = sessionPanels.remove(session.id)
            if (removedPanel != null) {
                chatCards.remove(removedPanel.root)
            }
            sessionStates.remove(session.id)
            sessionsById.remove(session.id)
            sessionsModel.removeElement(session)
            
            if (sessionsModel.isEmpty()) {
                // Create a default session if all gone
                createSession("Chat 1")
            } else if (sessionsList.isSelectionEmpty) {
                sessionsList.selectedIndex = sessionsModel.size - 1
            }
        }
    }

    private fun showToolsMenu() {
        val menu = javax.swing.JPopupMenu()
        val tools = McpToolCatalog.all()
        val settings = getSettings()
        val enabledTools = McpToolCatalog.mergeWithDefaults(settings.mcpSettings.toolToggles)
        val unsafeEnabled = settings.mcpSettings.unsafeEnabled

        tools.groupBy { it.category }.forEach { (category, categoryTools) ->
            val submenu = javax.swing.JMenu(category)
            categoryTools.sortedBy { it.title }.forEach { tool ->
                val isEnabled = enabledTools[tool.id] == true
                val isUnsafe = tool.unsafeOnly
                val canRun = isEnabled && (!isUnsafe || unsafeEnabled)
                
                val item = javax.swing.JMenuItem(tool.title)
                item.isEnabled = canRun
                item.toolTipText = tool.description
                item.addActionListener {
                    inputArea.text = "/tool ${tool.id} {}"
                    inputArea.requestFocusInWindow()
                }
                submenu.add(item)
            }
            if (submenu.itemCount > 0) {
                menu.add(submenu)
            }
        }
        menu.show(toolsBtn, 0, toolsBtn.height)
    }

    private fun clearCurrentChat() {
        val selected = sessionsList.selectedValue ?: return
        val confirm = javax.swing.JOptionPane.showConfirmDialog(
            root,
            "Are you sure you want to clear this chat history?",
            "Clear Chat",
            javax.swing.JOptionPane.YES_NO_OPTION
        )
        if (confirm != javax.swing.JOptionPane.YES_OPTION) return

        val panel = sessionPanels[selected.id] ?: return
        panel.clearMessages()
        supervisor.removeChatSession(selected.id)
        val state = sessionStates[selected.id]
        if (state != null) {
            state.toolCatalogSent = false
        }
    }

    private fun buildActionCard(
        capture: ContextCapture,
        actionName: String,
        promptText: String,
        sessionId: String,
        state: ToolSessionState
    ): ActionCard {
        val source = extractSourceFromPreview(capture.previewText)
        val target = extractHostFromContext(capture) ?: "Unknown"
        val summary = privacySummary(getSettings().privacyMode)
        val payload = buildContextPayload(promptText, capture.contextJson, actionName)
        val toolContext = if (state.toolsMode) buildToolContext(getSettings(), sessionId) else null
        val toolPreamble = if (state.toolsMode) buildToolPreamble(toolContext, state, mutateState = false) else null
        val finalPayload = if (!toolPreamble.isNullOrBlank()) {
            toolPreamble + "\n\n" + payload
        } else {
            payload
        }
        return ActionCard(
            actionName = actionName,
            source = "Source: $source",
            target = "Target: $target",
            privacySummary = summary,
            payloadPreview = finalPayload
        )
    }

    private fun buildActionCard(capture: ContextCapture, actionName: String): ActionCard {
        return buildActionCard(
            capture = capture,
            actionName = actionName,
            promptText = "Analyze the provided context.",
            sessionId = "preview",
            state = ToolSessionState()
        )
    }

    private fun buildContextPayload(userText: String, contextJson: String?, actionName: String?): String {
        val agentBlock = AgentProfileLoader.buildInstructionBlock(actionName)
        val base = if (contextJson.isNullOrBlank()) {
            userText
        } else {
            buildString {
                appendLine(userText)
                appendLine()
                appendLine("Context (JSON):")
                append(contextJson)
            }
        }
        return listOfNotNull(
            agentBlock?.takeIf { it.isNotBlank() },
            base.takeIf { it.isNotBlank() }
        ).joinToString("\n\n")
    }

    private fun extractSourceFromPreview(preview: String): String {
        val line = preview.lineSequence().firstOrNull { it.trim().startsWith("Kind:") }
        return line?.substringAfter("Kind:")?.trim().orEmpty().ifBlank { "Context" }
    }

    private fun extractHostFromContext(capture: ContextCapture): String? {
        return try {
            val root = Json.parseToJsonElement(capture.contextJson).jsonObject
            val items = root["items"]?.jsonArray ?: return null
            items.asSequence().mapNotNull { item ->
                val obj = item.jsonObject
                val affectedHost = obj["affectedHost"]?.jsonPrimitive?.contentOrNull
                if (!affectedHost.isNullOrBlank()) return@mapNotNull affectedHost
                val url = obj["url"]?.jsonPrimitive?.contentOrNull ?: return@mapNotNull null
                runCatching { URI(url).host }.getOrNull() ?: url
            }.firstOrNull()
        } catch (_: Exception) {
            null
        }
    }
    
    /**
     * Extract a representative URI from context for session title
     * Returns: METHOD path (e.g., "GET /api/users/123")
     */
    private fun extractUriFromContext(capture: ContextCapture): String? {
        return try {
            val root = Json.parseToJsonElement(capture.contextJson).jsonObject
            val items = root["items"]?.jsonArray ?: return null
            items.asSequence().mapNotNull { item ->
                val obj = item.jsonObject
                val url = obj["url"]?.jsonPrimitive?.contentOrNull
                val method = obj["method"]?.jsonPrimitive?.contentOrNull ?: "GET"
                
                if (url != null) {
                    val uri = runCatching { URI(url) }.getOrNull()
                    if (uri != null) {
                        val path = uri.path?.takeIf { it.isNotBlank() } ?: "/"
                        val query = uri.query?.let { "?${it.take(30)}${if (it.length > 30) "..." else ""}" } ?: ""
                        // Truncate path if too long
                        val displayPath = if (path.length > 50) "...${path.takeLast(47)}" else path
                        "$method $displayPath$query"
                    } else {
                        "$method $url"
                    }
                } else {
                    null
                }
            }.firstOrNull()
        } catch (_: Exception) {
            null
        }
    }

    private fun privacySummary(mode: PrivacyMode): String {
        return when (mode) {
            PrivacyMode.STRICT -> "Privacy: STRICT (cookies stripped, tokens redacted, hosts anonymized)"
            PrivacyMode.BALANCED -> "Privacy: BALANCED (cookies stripped, tokens redacted)"
            PrivacyMode.OFF -> "Privacy: OFF (no redaction)"
        }
    }

    private fun updatePrivacyPill() {
        privacyPill.updateMode(getSettings().privacyMode)
    }

    private fun showSession(id: String) {
        val layout = chatCards.layout as java.awt.CardLayout
        layout.show(chatCards, id)
    }


    data class ChatSession(val id: String, val title: String, val createdAt: Long, val backendId: String) {
        override fun toString(): String = title
    }

    private data class ToolSessionState(
        var toolsMode: Boolean = true,
        var toolCatalogSent: Boolean = false
    )

    private class ChatSessionRenderer : javax.swing.DefaultListCellRenderer() {
        override fun getListCellRendererComponent(
            list: JList<*>,
            value: Any?,
            index: Int,
            isSelected: Boolean,
            cellHasFocus: Boolean
        ): java.awt.Component {
            val label = super.getListCellRendererComponent(list, value, index, isSelected, cellHasFocus) as JLabel
            if (value !is ChatSession) {
                label.border = EmptyBorder(6, 10, 6, 10)
                return label
            }

            val panel = JPanel()
            panel.layout = BoxLayout(panel, BoxLayout.Y_AXIS)
            panel.border = EmptyBorder(6, 10, 6, 10)
            panel.isOpaque = true
            panel.background = if (isSelected) list.selectionBackground else list.background

            val titleLabel = JLabel(value.title)
            titleLabel.font = label.font
            titleLabel.foreground = if (isSelected) list.selectionForeground else list.foreground
            titleLabel.isOpaque = false

            val backendLabel = JLabel(value.backendId)
            backendLabel.font = label.font.deriveFont((label.font.size - 2).toFloat())
            backendLabel.foreground = if (isSelected) list.selectionForeground else UiTheme.Colors.onSurfaceVariant
            backendLabel.isOpaque = false

            panel.add(titleLabel)
            panel.add(backendLabel)
            return panel
        }
    }

    private inner class SessionPanel {
        val root: JComponent = JPanel(BorderLayout())
        private val messages = JPanel()
        private val scroll = JScrollPane(messages)

        init {
            root.background = UiTheme.Colors.surface
            messages.layout = javax.swing.BoxLayout(messages, javax.swing.BoxLayout.Y_AXIS)
            messages.background = UiTheme.Colors.surface
            scroll.border = EmptyBorder(12, 12, 12, 12)
            scroll.background = UiTheme.Colors.surface
            root.add(scroll, BorderLayout.CENTER)
        }

        fun addMessage(role: String, text: String) {
            val message = ChatMessagePanel(role, text)
            messages.add(message.root)
            messages.add(javax.swing.Box.createRigidArea(Dimension(0, 10)))
            refreshScroll()
        }

        fun addComponent(component: JComponent) {
            messages.add(component)
            messages.add(javax.swing.Box.createRigidArea(Dimension(0, 10)))
            refreshScroll()
        }

        fun addStreamingMessage(role: String): StreamingMessage {
            val message = ChatMessagePanel(role, "")
            messages.add(message.root)
            messages.add(javax.swing.Box.createRigidArea(Dimension(0, 10)))
            refreshScroll()
            return StreamingMessage(message)
        }

        fun clearMessages() {
            messages.removeAll()
            messages.revalidate()
            messages.repaint()
        }

        private fun refreshScroll() {
            messages.revalidate()
            SwingUtilities.invokeLater {
                val scrollBar = scroll.verticalScrollBar
                scrollBar.value = scrollBar.maximum
            }
        }
    }

    private class StreamingMessage(private val message: ChatMessagePanel) {
        private var firstChunk = true
        fun append(text: String) {
            if (firstChunk) {
                message.hideSpinner()
                firstChunk = false
            }
            message.append(text)
        }
    }

    private class ChatMessagePanel(
        private val role: String,
        initialText: String
    ) {
        private val isUser = role == "You"
        private val showSpinner = !isUser && initialText.isEmpty()
        val root: JComponent = JPanel()
        private val editorPane = object : javax.swing.JEditorPane() {
            override fun getPreferredSize(): java.awt.Dimension {
                // Calculate preferred height based on current width
                val width = if (parent != null && parent.width > 0) parent.width else 400
                setSize(width, Short.MAX_VALUE.toInt())
                val prefSize = super.getPreferredSize()
                return java.awt.Dimension(width, prefSize.height.coerceAtLeast(20))
            }
            
            override fun getMaximumSize(): java.awt.Dimension {
                val pref = preferredSize
                return java.awt.Dimension(Int.MAX_VALUE, pref.height)
            }
        }
        private val rawText = StringBuilder(initialText)
        private val copyBtn = JButton("Copy")
        private val spinnerLabel = JLabel("Thinking...")
        private var spinnerTimer: javax.swing.Timer? = null
        private val spinnerFrames = listOf("⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏")
        private var spinnerIndex = 0
        private val bubble: JPanel

        init {
            root.layout = BorderLayout()
            root.isOpaque = false
            root.border = EmptyBorder(4, 8, 4, 8)

            bubble = JPanel(BorderLayout())
            bubble.isOpaque = true
            bubble.background = UiTheme.Colors.surface
            bubble.border = javax.swing.BorderFactory.createCompoundBorder(
                javax.swing.BorderFactory.createLineBorder(UiTheme.Colors.outline, 1),
                EmptyBorder(8, 12, 8, 12)
            )

            val header = JPanel(BorderLayout())
            header.isOpaque = false
            header.border = EmptyBorder(0, 0, 4, 0)

            val label = JLabel(role)
            label.font = UiTheme.Typography.label
            label.foreground = UiTheme.Colors.primary
            header.add(label, BorderLayout.WEST)

            copyBtn.font = UiTheme.Typography.label
            copyBtn.isFocusPainted = false
            copyBtn.margin = java.awt.Insets(2, 6, 2, 6)
            copyBtn.border = javax.swing.BorderFactory.createLineBorder(UiTheme.Colors.outline)
            copyBtn.background = UiTheme.Colors.surface
            copyBtn.foreground = UiTheme.Colors.onSurface
            copyBtn.addActionListener {
                val clipboard = java.awt.Toolkit.getDefaultToolkit().systemClipboard
                clipboard.setContents(java.awt.datatransfer.StringSelection(rawText.toString()), null)
            }
            header.add(copyBtn, BorderLayout.EAST)

            // Spinner setup
            spinnerLabel.font = UiTheme.Typography.body
            spinnerLabel.foreground = UiTheme.Colors.onSurfaceVariant
            spinnerLabel.isVisible = showSpinner

            editorPane.contentType = "text/html"
            editorPane.isEditable = false
            editorPane.background = UiTheme.Colors.inputBackground
            editorPane.border = EmptyBorder(4, 6, 4, 6)
            editorPane.isVisible = !showSpinner
            updateHtml()

            val contentPanel = JPanel(BorderLayout())
            contentPanel.isOpaque = false
            contentPanel.add(spinnerLabel, BorderLayout.NORTH)
            contentPanel.add(editorPane, BorderLayout.CENTER)

            bubble.add(header, BorderLayout.NORTH)
            bubble.add(contentPanel, BorderLayout.CENTER)

            // Full width layout - bubble takes all available space
            root.add(bubble, BorderLayout.CENTER)
            
            // Add resize listener to recalculate height when width changes
            root.addComponentListener(object : java.awt.event.ComponentAdapter() {
                override fun componentResized(e: java.awt.event.ComponentEvent?) {
                    SwingUtilities.invokeLater {
                        editorPane.revalidate()
                        bubble.revalidate()
                        root.revalidate()
                    }
                }
            })

            if (showSpinner) {
                spinnerTimer = javax.swing.Timer(100) {
                    spinnerIndex = (spinnerIndex + 1) % spinnerFrames.size
                    spinnerLabel.text = "${spinnerFrames[spinnerIndex]} Thinking..."
                }
                spinnerTimer?.start()
            }
        }

        fun hideSpinner() {
            spinnerTimer?.stop()
            spinnerTimer = null
            spinnerLabel.isVisible = false
            editorPane.isVisible = true
        }

        fun append(text: String) {
            rawText.append(text)
            updateHtml()
        }

        private fun updateHtml() {
            val isDark = UiTheme.isDarkTheme
            editorPane.text = MarkdownRenderer.toHtml(rawText.toString(), isDark = isDark)
            // Revalidate to adjust size
            SwingUtilities.invokeLater {
                editorPane.revalidate()
                bubble.revalidate()
                root.revalidate()
            }
        }
    }

    private fun handleToolCommand(
        text: String,
        sessionId: String,
        panel: SessionPanel,
        state: ToolSessionState,
        settings: AgentSettings
    ): Boolean {
        val trimmed = text.trim()
        if (trimmed == "/tools") {
            val context = buildToolContext(settings, sessionId)
            val list = McpToolExecutor.describeTools(context, includeSchemas = true)
            panel.addMessage("Tools", list)
            state.toolsMode = true
            state.toolCatalogSent = true
            return true
        }
        if (trimmed.startsWith("/tool ")) {
            val parts = trimmed.removePrefix("/tool ").trim()
            val split = parts.split(" ", limit = 2)
            val toolName = split.getOrNull(0).orEmpty()
            if (toolName.isBlank()) {
                panel.addMessage("System", "Usage: /tool <name> <json>")
                return true
            }
            val argsJson = split.getOrNull(1)
            val context = buildToolContext(settings, sessionId)
            val result = McpToolExecutor.executeTool(toolName, argsJson, context)
            panel.addMessage("Tool result: $toolName", result)
            state.toolsMode = true
            state.toolCatalogSent = state.toolCatalogSent || argsJson != null
            return true
        }
        return false
    }

    private fun maybeExecuteToolCall(
        sessionId: String,
        userText: String,
        responseText: String,
        context: McpToolContext,
        settings: AgentSettings
    ) {
        val call = extractToolCall(responseText) ?: return
        val panel = sessionPanels[sessionId] ?: return
        val result = McpToolExecutor.executeTool(call.tool, call.argsJson, context)
        panel.addMessage("Tool result: ${call.tool}", result)
        val followup = buildString {
            appendLine("Tool result for ${call.tool}:")
            appendLine(result)
            appendLine()
            appendLine("User request:")
            appendLine(userText)
            appendLine()
            appendLine("Provide the final response using the tool result.")
        }.trim()
        sendMessage(
            sessionId,
            followup,
            contextJson = null,
            allowToolCalls = false,
            actionName = "Tool Followup"
        )
    }

    private data class ToolCall(val tool: String, val argsJson: String?)

    private fun extractToolCall(text: String): ToolCall? {
        val toolBlock = extractToolBlockJson(text)
        if (toolBlock != null) {
            val call = parseToolJson(toolBlock)
            if (call != null) return call
        }
        val trimmed = text.trim()
        if (trimmed.startsWith("{") && trimmed.endsWith("}") && trimmed.contains("\"tool\"")) {
            return parseToolJson(trimmed)
        }
        return null
    }

    private fun extractToolBlockJson(text: String): String? {
        val regex = Regex("```tool\\s*([\\s\\S]*?)\\s*```", RegexOption.IGNORE_CASE)
        val match = regex.find(text) ?: return null
        val payload = match.groupValues.getOrNull(1)?.trim().orEmpty()
        if (!payload.startsWith("{") || !payload.endsWith("}")) return null
        return payload
    }

    private fun parseToolJson(jsonText: String): ToolCall? {
        return try {
            val element = Json.parseToJsonElement(jsonText)
            val obj = element.jsonObject
            val tool = obj["tool"]?.jsonPrimitive?.content ?: return null
            val args = obj["args"]?.toString()
            ToolCall(tool, args)
        } catch (_: Exception) {
            null
        }
    }

    private fun buildToolPreamble(
        context: McpToolContext?,
        state: ToolSessionState,
        mutateState: Boolean
    ): String? {
        if (context == null) return null
        val header = "Tool mode is enabled. If you need a tool, include a fenced code block " +
            "with language 'tool' that contains only the JSON call, then wait. " +
            "After the tool result, respond in clear natural language or markdown."
        if (state.toolCatalogSent) return header
        if (mutateState) {
            state.toolCatalogSent = true
        }
        val list = McpToolExecutor.describeTools(context, includeSchemas = false)
        return header + "\n\n" + list
    }

    private fun buildToolContext(settings: AgentSettings, sessionId: String): McpToolContext {
        val toggles = McpToolCatalog.mergeWithDefaults(settings.mcpSettings.toolToggles)
        return McpToolContext(
            api = api,
            privacyMode = settings.privacyMode,
            determinismMode = settings.determinismMode,
            hostSalt = sessionId,
            toolToggles = toggles,
            unsafeEnabled = settings.mcpSettings.unsafeEnabled,
            unsafeTools = McpToolCatalog.unsafeToolIds(),
            limiter = McpRequestLimiter(settings.mcpSettings.maxConcurrentRequests),
            edition = api.burpSuite().version().edition(),
            maxBodyBytes = settings.mcpSettings.maxBodyBytes
        )
    }
}
