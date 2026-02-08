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
    private val usageStatsLine1 = JLabel("No usage yet")
    private val usageStatsLine2 = JLabel("")
    private val usageStatsLine3 = JLabel("")

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

        val editSessionBtn = JButton("\u270E") // ✎ pencil
        editSessionBtn.font = UiTheme.Typography.body
        editSessionBtn.isFocusPainted = false
        editSessionBtn.toolTipText = "Rename session"
        editSessionBtn.margin = java.awt.Insets(2, 4, 2, 4)
        editSessionBtn.addActionListener {
            val s = sessionsList.selectedValue ?: return@addActionListener
            renameSession(s)
        }

        val deleteSessionBtn = JButton("\u2715") // ✕
        deleteSessionBtn.font = UiTheme.Typography.body
        deleteSessionBtn.isFocusPainted = false
        deleteSessionBtn.toolTipText = "Delete session"
        deleteSessionBtn.margin = java.awt.Insets(2, 4, 2, 4)
        deleteSessionBtn.addActionListener {
            val s = sessionsList.selectedValue ?: return@addActionListener
            deleteSession(s)
        }

        val listScroll = JScrollPane(sessionsList)
        listScroll.border = EmptyBorder(8, 8, 8, 8)

        val listHeader = JPanel(BorderLayout())
        listHeader.isOpaque = false
        val listTitle = JLabel("Sessions")
        listTitle.font = UiTheme.Typography.label
        listTitle.foreground = UiTheme.Colors.onSurfaceVariant
        listHeader.add(listTitle, BorderLayout.WEST)
        val headerActions = JPanel()
        headerActions.layout = javax.swing.BoxLayout(headerActions, javax.swing.BoxLayout.X_AXIS)
        headerActions.isOpaque = false
        headerActions.add(editSessionBtn)
        headerActions.add(javax.swing.Box.createRigidArea(Dimension(4, 0)))
        headerActions.add(deleteSessionBtn)
        headerActions.add(javax.swing.Box.createRigidArea(Dimension(4, 0)))
        headerActions.add(newSessionBtn)
        listHeader.add(headerActions, BorderLayout.EAST)
        listHeader.border = EmptyBorder(8, 12, 8, 12)

        // Usage stats footer
        val smallFont = UiTheme.Typography.body.deriveFont((UiTheme.Typography.body.size - 1).toFloat())
        val dimColor = UiTheme.Colors.onSurfaceVariant
        val usageFooter = JPanel()
        usageFooter.layout = BoxLayout(usageFooter, BoxLayout.Y_AXIS)
        usageFooter.isOpaque = false
        usageFooter.border = EmptyBorder(4, 12, 8, 12)
        for (lbl in listOf(usageStatsLine1, usageStatsLine2, usageStatsLine3)) {
            lbl.font = smallFont
            lbl.foreground = dimColor
            usageFooter.add(lbl)
        }
        updateUsageStatsLabel()

        sessionsPanel.add(listHeader, BorderLayout.NORTH)
        sessionsPanel.add(listScroll, BorderLayout.CENTER)
        sessionsPanel.add(usageFooter, BorderLayout.SOUTH)
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
        session.messages.add(com.six2dez.burp.aiagent.backends.ChatMessage("user", prompt))
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
        panel.border = javax.swing.BorderFactory.createCompoundBorder(
            javax.swing.BorderFactory.createMatteBorder(1, 0, 0, 0, UiTheme.Colors.outlineVariant),
            EmptyBorder(6, 12, 10, 12)
        )

        inputArea.lineWrap = true
        inputArea.wrapStyleWord = true
        inputArea.font = UiTheme.Typography.body
        inputArea.background = UiTheme.Colors.inputBackground
        inputArea.foreground = UiTheme.Colors.inputForeground
        inputArea.margin = java.awt.Insets(8, 10, 8, 10)
        inputArea.addKeyListener(object : KeyAdapter() {
            override fun keyPressed(e: KeyEvent) {
                if (e.keyCode == KeyEvent.VK_ENTER && !e.isShiftDown) {
                    e.consume()
                    sendFromInput()
                }
            }
        })

        sendBtn.font = UiTheme.Typography.label
        sendBtn.isFocusPainted = false
        sendBtn.addActionListener { sendFromInput() }
        updatePrivacyPill()

        // Input area in a scroll pane with rounded border
        val inputScroll = JScrollPane(inputArea)
        inputScroll.border = javax.swing.border.LineBorder(UiTheme.Colors.outline, 1, true)
        inputScroll.horizontalScrollBarPolicy = JScrollPane.HORIZONTAL_SCROLLBAR_NEVER

        // Action buttons row below input
        val actions = JPanel(java.awt.FlowLayout(java.awt.FlowLayout.RIGHT, 6, 2))
        actions.isOpaque = false
        actions.add(privacyPill)
        actions.add(toolsBtn)
        actions.add(clearChatBtn)
        actions.add(sendBtn)

        panel.add(inputScroll, BorderLayout.CENTER)
        panel.add(actions, BorderLayout.SOUTH)
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
        val sessionObj = sessionsById[session.id]
        if (sessionObj != null) {
            sessionObj.messages.add(com.six2dez.burp.aiagent.backends.ChatMessage("user", text))
        }
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
        val backendId = settings.preferredBackendId
        // Track backend usage on session
        if (session != null) {
            session.backendsUsed[backendId] = (session.backendsUsed[backendId] ?: 0) + 1
            session.messageCount++
            session.totalCharsIn += userText.length.toLong()
        }
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
        val history = session?.messages?.toList()
        
        supervisor.sendChat(
            chatSessionId = sessionId,
            backendId = backendId,
            text = finalPrompt,
            history = history,
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
                    val finalResp = responseBuffer.toString()
                    session?.messages?.add(com.six2dez.burp.aiagent.backends.ChatMessage("assistant", finalResp))
                    if (session != null) {
                        session.totalCharsOut += finalResp.length.toLong()
                    }
                    SwingUtilities.invokeLater {
                        assistant.append("\n")
                        refreshSessionList()
                        onResponseReady()
                    }
                    if (allowToolCalls && state.toolsMode && toolContext != null) {
                        maybeExecuteToolCall(
                            sessionId = sessionId,
                            userText = userText,
                            responseText = finalResp,
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
        val session = ChatSession(id, title, System.currentTimeMillis())
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

        val exportItem = javax.swing.JMenuItem("Export as Markdown")
        exportItem.addActionListener { exportCurrentChatAsMarkdown() }
        
        menu.add(renameItem)
        menu.add(deleteItem)
        menu.addSeparator()
        menu.add(exportItem)
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
            // Clean persisted messages
            try {
                api.persistence().preferences().setString(SESSION_MSG_KEY_PREFIX + session.id, "")
            } catch (_: Exception) {}
            
            if (sessionsModel.isEmpty()) {
                // Create a default session if all gone
                createSession("Chat 1")
            } else if (sessionsList.isSelectionEmpty) {
                sessionsList.selectedIndex = sessionsModel.size - 1
            }
            updateUsageStatsLabel()
        }
    }

    /** Export current session as a Markdown file */
    fun exportCurrentChatAsMarkdown() {
        val session = sessionsList.selectedValue ?: return
        if (session.messages.isEmpty()) {
            showError("No messages to export.")
            return
        }
        val md = buildString {
            appendLine("# ${session.title}")
            appendLine()
            for (msg in session.messages) {
                val label = when (msg.role) {
                    "user" -> "**You**"
                    "assistant" -> "**AI**"
                    else -> "**${msg.role}**"
                }
                appendLine("### $label")
                appendLine()
                appendLine(msg.content)
                appendLine()
                appendLine("---")
                appendLine()
            }
        }
        val chooser = javax.swing.JFileChooser()
        chooser.selectedFile = java.io.File("${session.title.replace(Regex("[^a-zA-Z0-9_\\-]"), "_")}.md")
        if (chooser.showSaveDialog(root) == javax.swing.JFileChooser.APPROVE_OPTION) {
            try {
                chooser.selectedFile.writeText(md)
            } catch (e: Exception) {
                showError("Failed to export: ${e.message}")
            }
        }
    }

    /** Create a new empty session (called from keyboard shortcut) */
    fun createNewSession() {
        createSession("Chat ${sessionsModel.size + 1}")
    }

    /** Delete the currently selected session (called from keyboard shortcut) */
    fun deleteCurrentSession() {
        val s = sessionsList.selectedValue ?: return
        deleteSession(s)
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

    fun clearCurrentChat() {
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
        selected.messages.clear()
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
        } catch (e: Exception) {
            api.logging().logToOutput("[ChatPanel] Failed to extract host from context: ${e.message}")
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
        } catch (e: Exception) {
            api.logging().logToOutput("[ChatPanel] Failed to extract URI from context: ${e.message}")
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

    private fun refreshSessionList() {
        // Trigger list repaint by resetting elements
        val selected = sessionsList.selectedIndex
        for (i in 0 until sessionsModel.size) {
            sessionsModel.set(i, sessionsModel.get(i))
        }
        if (selected >= 0 && selected < sessionsModel.size) {
            sessionsList.selectedIndex = selected
        }
        updateUsageStatsLabel()
    }

    private fun updateUsageStatsLabel() {
        val stats = usageStats()
        if (stats.totalMessages == 0) {
            usageStatsLine1.text = "No usage yet"
            usageStatsLine2.text = ""
            usageStatsLine3.text = ""
        } else {
            usageStatsLine1.text = "${stats.totalMessages} msgs | In: ${formatChars(stats.totalCharsIn)} | Out: ${formatChars(stats.totalCharsOut)}"
            usageStatsLine2.text = stats.perBackend.entries
                .sortedByDescending { it.value }
                .joinToString(", ") { "${it.key}: ${it.value}" }
            usageStatsLine3.text = ""
        }
    }

    private fun formatChars(chars: Long): String {
        return when {
            chars >= 1_000_000 -> String.format("%.1fM", chars / 1_000_000.0)
            chars >= 1_000 -> String.format("%.1fK", chars / 1_000.0)
            else -> "${chars}"
        }
    }

    companion object {
        fun formatSessionDate(epochMs: Long): String {
            val now = java.util.Calendar.getInstance()
            val then = java.util.Calendar.getInstance().apply { timeInMillis = epochMs }
            val sameDay = now.get(java.util.Calendar.YEAR) == then.get(java.util.Calendar.YEAR) &&
                    now.get(java.util.Calendar.DAY_OF_YEAR) == then.get(java.util.Calendar.DAY_OF_YEAR)
            if (sameDay) return "Today"
            now.add(java.util.Calendar.DAY_OF_YEAR, -1)
            val yesterday = now.get(java.util.Calendar.YEAR) == then.get(java.util.Calendar.YEAR) &&
                    now.get(java.util.Calendar.DAY_OF_YEAR) == then.get(java.util.Calendar.DAY_OF_YEAR)
            if (yesterday) return "Yesterday"
            val daysDiff = ((System.currentTimeMillis() - epochMs) / 86_400_000).toInt()
            if (daysDiff <= 7) return "${daysDiff}d ago"
            return java.text.SimpleDateFormat("MMM d").format(java.util.Date(epochMs))
        }
    }

    // ── Persistence: save/restore chat sessions via Burp preferences ──

    private val SESSIONS_KEY = "chat.sessions"
    private val SESSION_MSG_KEY_PREFIX = "chat.messages."

    fun saveSessions() {
        try {
            val prefs = api.persistence().preferences()
            val sessionList = sessionsById.values.map { s ->
                buildString {
                    append(s.id)
                    append('\t')
                    append(s.title)
                    append('\t')
                    append(s.createdAt)
                    append('\t')
                    append(s.backendsUsed.entries.joinToString(",") { "${it.key}:${it.value}" })
                    append('\t')
                    append(s.messageCount)
                    append('\t')
                    append(s.totalCharsIn)
                    append('\t')
                    append(s.totalCharsOut)
                }
            }
            prefs.setString(SESSIONS_KEY, sessionList.joinToString("\n"))
            // Save messages for each session
            for ((id, session) in sessionsById) {
                val msgs = session.messages.joinToString("\u001F") { "${it.role}\u001E${it.content}" }
                prefs.setString(SESSION_MSG_KEY_PREFIX + id, msgs)
            }
            api.logging().logToOutput("[ChatPanel] Saved ${sessionsById.size} sessions.")
        } catch (e: Exception) {
            api.logging().logToError("[ChatPanel] Failed to save sessions: ${e.message}")
        }
    }

    fun restoreSessions() {
        try {
            val prefs = api.persistence().preferences()
            val raw = prefs.getString(SESSIONS_KEY) ?: return
            if (raw.isBlank()) return
            val lines = raw.split('\n').filter { it.isNotBlank() }
            if (lines.isEmpty()) return

            for (line in lines) {
                val parts = line.split('\t')
                if (parts.size < 3) continue
                val id = parts[0]
                val title = parts[1]
                val createdAt = parts[2].toLongOrNull() ?: System.currentTimeMillis()
                val backendsRaw = parts.getOrNull(3).orEmpty()
                val backendsUsed = mutableMapOf<String, Int>()
                if (backendsRaw.isNotBlank()) {
                    for (entry in backendsRaw.split(",")) {
                        val kv = entry.split(":", limit = 2)
                        if (kv.size == 2 && kv[1].toIntOrNull() != null) {
                            backendsUsed[kv[0]] = kv[1].toInt()
                        } else if (kv.size == 1 && kv[0].isNotBlank()) {
                            // Backwards compat: old format stored single backendId
                            backendsUsed[kv[0]] = 0
                        }
                    }
                }
                val messageCount = parts.getOrNull(4)?.toIntOrNull() ?: 0
                val totalCharsIn = parts.getOrNull(5)?.toLongOrNull() ?: 0L
                val totalCharsOut = parts.getOrNull(6)?.toLongOrNull() ?: 0L

                val session = ChatSession(
                    id = id,
                    title = title,
                    createdAt = createdAt,
                    backendsUsed = backendsUsed,
                    messageCount = messageCount,
                    totalCharsIn = totalCharsIn,
                    totalCharsOut = totalCharsOut
                )

                // Restore messages
                val msgRaw = prefs.getString(SESSION_MSG_KEY_PREFIX + id)
                if (!msgRaw.isNullOrBlank()) {
                    val msgs = msgRaw.split('\u001F').mapNotNull { entry ->
                        val split = entry.split('\u001E', limit = 2)
                        if (split.size == 2) com.six2dez.burp.aiagent.backends.ChatMessage(split[0], split[1]) else null
                    }
                    session.messages.addAll(msgs)
                }

                sessionsModel.addElement(session)
                sessionsById[id] = session
                val panel = SessionPanel()
                sessionPanels[id] = panel
                sessionStates[id] = ToolSessionState()
                chatCards.add(panel.root, id)

                // Re-render saved messages in the panel
                for (msg in session.messages) {
                    panel.addMessage(msg.role.replaceFirstChar { c -> c.uppercase() }.let {
                        if (it == "User") "You" else if (it == "Assistant") "AI" else it
                    }, msg.content)
                }
            }

            if (sessionsModel.size > 0) {
                sessionsList.selectedIndex = sessionsModel.size - 1
                showSession(sessionsById.keys.last())
            }
            api.logging().logToOutput("[ChatPanel] Restored ${sessionsById.size} sessions.")
        } catch (e: Exception) {
            api.logging().logToError("[ChatPanel] Failed to restore sessions: ${e.message}")
        }
    }

    /** Aggregate usage stats across all sessions. */
    fun usageStats(): UsageStats {
        var totalMsgs = 0
        var totalIn = 0L
        var totalOut = 0L
        val backendCounts = mutableMapOf<String, Int>()
        for (s in sessionsById.values) {
            totalMsgs += s.messageCount
            totalIn += s.totalCharsIn
            totalOut += s.totalCharsOut
            for ((backend, count) in s.backendsUsed) {
                backendCounts[backend] = (backendCounts[backend] ?: 0) + count
            }
        }
        return UsageStats(totalMsgs, totalIn, totalOut, backendCounts)
    }

    data class UsageStats(
        val totalMessages: Int,
        val totalCharsIn: Long,
        val totalCharsOut: Long,
        val perBackend: Map<String, Int>
    )


    data class ChatSession(
        val id: String,
        val title: String,
        val createdAt: Long,
        val messages: MutableList<com.six2dez.burp.aiagent.backends.ChatMessage> = mutableListOf(),
        val backendsUsed: MutableMap<String, Int> = mutableMapOf(),
        var messageCount: Int = 0,
        var totalCharsIn: Long = 0,
        var totalCharsOut: Long = 0
    ) {
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

            val panel = JPanel(BorderLayout())
            panel.border = EmptyBorder(6, 10, 6, 10)
            panel.isOpaque = true
            panel.background = if (isSelected) list.selectionBackground else list.background

            val textPanel = JPanel()
            textPanel.layout = BoxLayout(textPanel, BoxLayout.Y_AXIS)
            textPanel.isOpaque = false

            val titleLabel = JLabel(value.title)
            titleLabel.font = label.font
            titleLabel.foreground = if (isSelected) list.selectionForeground else list.foreground
            titleLabel.isOpaque = false

            val models = value.backendsUsed.keys.joinToString(", ").ifBlank { "no model" }
            val msgCount = value.messageCount
            val dateStr = ChatPanel.formatSessionDate(value.createdAt)
            val infoText = "$models  \u00B7  $msgCount msgs  \u00B7  $dateStr"
            val backendLabel = JLabel(infoText)
            backendLabel.font = label.font.deriveFont((label.font.size - 2).toFloat())
            backendLabel.foreground = if (isSelected) list.selectionForeground else UiTheme.Colors.onSurfaceVariant
            backendLabel.isOpaque = false

            textPanel.add(titleLabel)
            textPanel.add(backendLabel)
            panel.add(textPanel, BorderLayout.CENTER)
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
            scroll.border = EmptyBorder(8, 8, 8, 8)
            scroll.background = UiTheme.Colors.surface
            scroll.verticalScrollBarPolicy = JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED
            scroll.horizontalScrollBarPolicy = JScrollPane.HORIZONTAL_SCROLLBAR_NEVER
            root.add(scroll, BorderLayout.CENTER)
        }

        fun addMessage(role: String, text: String) {
            val message = ChatMessagePanel(role, text)
            messages.add(message.root)
            messages.add(javax.swing.Box.createRigidArea(Dimension(0, 4)))
            refreshScroll()
        }

        fun addComponent(component: JComponent) {
            // Wrap in a panel that prevents vertical stretching
            val wrapper = object : JPanel(BorderLayout()) {
                override fun getMaximumSize(): Dimension =
                    Dimension(super.getMaximumSize().width, preferredSize.height)
            }
            wrapper.isOpaque = false
            wrapper.add(component, BorderLayout.CENTER)
            messages.add(wrapper)
            messages.add(javax.swing.Box.createRigidArea(Dimension(0, 4)))
            refreshScroll()
        }

        fun addStreamingMessage(role: String): StreamingMessage {
            val message = ChatMessagePanel(role, "")
            messages.add(message.root)
            messages.add(javax.swing.Box.createRigidArea(Dimension(0, 4)))
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
            message.appendChunk(text)
        }
    }

    private class ChatMessagePanel(
        private val role: String,
        initialText: String
    ) {
        private val isUser = role == "You"
        private val showSpinner = !isUser && initialText.isEmpty()
        private val rawText = StringBuilder(initialText)
        private val copyBtn = JButton("Copy")
        private val spinnerLabel = JLabel("Thinking...")
        private var spinnerTimer: javax.swing.Timer? = null
        private val spinnerFrames = listOf("\u280B", "\u2819", "\u2839", "\u2838", "\u283C", "\u2834", "\u2826", "\u2827", "\u2807", "\u280F")
        private var spinnerIndex = 0
        private val pendingText = StringBuilder()
        private var coalescingTimer: javax.swing.Timer? = null
        private val timestamp = java.text.SimpleDateFormat("h:mm a").format(java.util.Date())
        private val contentPanel: JPanel

        /** Walk up to the JScrollPane viewport to get a reliable width */
        private fun viewportWidth(): Int {
            var c: java.awt.Container? = root
            while (c != null && c !is javax.swing.JViewport) c = c.parent
            return (c as? javax.swing.JViewport)?.width?.takeIf { it > 0 } ?: 650
        }

        /** EditorPane: calculates height based on a width derived from the viewport */
        private val editorPane = object : javax.swing.JEditorPane() {
            override fun getPreferredSize(): java.awt.Dimension {
                val vpW = viewportWidth()
                val w: Int = if (isUser) {
                    // User bubble: max 60% of viewport, but shrink-to-fit for short text
                    val maxW = (vpW * 0.60).toInt().coerceAtLeast(200)
                    setSize(maxW, Short.MAX_VALUE.toInt())
                    val naturalW = super.getPreferredSize().width
                    naturalW.coerceAtMost(maxW)
                } else {
                    // AI: fill available width (viewport minus padding)
                    (vpW - 48).coerceAtLeast(200)
                }
                setSize(w, Short.MAX_VALUE.toInt())
                val pref = super.getPreferredSize()
                return java.awt.Dimension(w, pref.height.coerceAtLeast(18))
            }
            override fun getMaximumSize(): java.awt.Dimension = preferredSize
        }

        // Root panel: prevents vertical stretching in BoxLayout.Y_AXIS container
        val root: JComponent = object : JPanel(BorderLayout()) {
            init { isOpaque = false }
            override fun getMaximumSize(): Dimension =
                Dimension(super.getMaximumSize().width, preferredSize.height)
        }

        init {
            root.border = EmptyBorder(2, 0, 2, 0)

            // ── Header: role label + timestamp + copy button ──
            val header = JPanel(BorderLayout())
            header.isOpaque = false
            header.border = EmptyBorder(0, 0, 2, 0)

            val roleLabel = JLabel(role)
            roleLabel.font = UiTheme.Typography.label
            roleLabel.foreground = if (isUser) UiTheme.Colors.userRole else UiTheme.Colors.aiRole

            val timeLabel = JLabel(timestamp)
            timeLabel.font = UiTheme.Typography.body.deriveFont((UiTheme.Typography.body.size - 2).toFloat())
            timeLabel.foreground = UiTheme.Colors.onSurfaceVariant

            val leftHeader = JPanel()
            leftHeader.layout = BoxLayout(leftHeader, BoxLayout.X_AXIS)
            leftHeader.isOpaque = false
            leftHeader.add(roleLabel)
            leftHeader.add(javax.swing.Box.createRigidArea(Dimension(6, 0)))
            leftHeader.add(timeLabel)
            header.add(leftHeader, BorderLayout.WEST)

            // Copy button — borderless, appears on hover
            copyBtn.font = UiTheme.Typography.body.deriveFont((UiTheme.Typography.body.size - 2).toFloat())
            copyBtn.isFocusPainted = false
            copyBtn.isContentAreaFilled = false
            copyBtn.border = javax.swing.BorderFactory.createEmptyBorder()
            copyBtn.foreground = UiTheme.Colors.onSurfaceVariant
            copyBtn.cursor = java.awt.Cursor.getPredefinedCursor(java.awt.Cursor.HAND_CURSOR)
            copyBtn.isVisible = false
            copyBtn.addActionListener {
                val clipboard = java.awt.Toolkit.getDefaultToolkit().systemClipboard
                clipboard.setContents(java.awt.datatransfer.StringSelection(rawText.toString()), null)
                copyBtn.text = "Copied!"
                javax.swing.Timer(1500) { copyBtn.text = "Copy" }.also { it.isRepeats = false; it.start() }
            }
            header.add(copyBtn, BorderLayout.EAST)

            // ── EditorPane setup ──
            editorPane.contentType = "text/html"
            editorPane.isEditable = false
            editorPane.border = EmptyBorder(0, 0, 0, 0)
            editorPane.isVisible = !showSpinner
            editorPane.addHyperlinkListener { e ->
                if (e.eventType == javax.swing.event.HyperlinkEvent.EventType.ACTIVATED) {
                    try { java.awt.Desktop.getDesktop().browse(e.url.toURI()) } catch (_: Exception) {}
                }
            }

            // Spinner
            spinnerLabel.font = UiTheme.Typography.body
            spinnerLabel.foreground = UiTheme.Colors.onSurfaceVariant
            spinnerLabel.isVisible = showSpinner

            // ── Content: spinner above editor ──
            contentPanel = JPanel(BorderLayout())
            contentPanel.isOpaque = false
            contentPanel.add(spinnerLabel, BorderLayout.NORTH)
            contentPanel.add(editorPane, BorderLayout.CENTER)

            // ── Build the message row ──
            if (isUser) {
                // ░░ User message: right-aligned bubble with colored background
                val bubble = JPanel(BorderLayout())
                bubble.isOpaque = true
                bubble.background = UiTheme.Colors.userBubble
                bubble.border = EmptyBorder(8, 14, 8, 14)
                bubble.add(header, BorderLayout.NORTH)
                bubble.add(contentPanel, BorderLayout.CENTER)
                editorPane.background = UiTheme.Colors.userBubble

                // Wrapper: places bubble at EAST (right side)
                val wrapper = JPanel(BorderLayout())
                wrapper.isOpaque = false
                wrapper.border = EmptyBorder(0, 12, 0, 12)
                wrapper.add(bubble, BorderLayout.EAST)
                root.add(wrapper, BorderLayout.CENTER)

                // Hover: show copy on the bubble
                val hoverTarget = bubble
                val hoverListener = object : java.awt.event.MouseAdapter() {
                    override fun mouseEntered(e: java.awt.event.MouseEvent?) { copyBtn.isVisible = true }
                    override fun mouseExited(e: java.awt.event.MouseEvent?) {
                        val pt = e?.point ?: return; val src = e.component ?: return
                        val bp = javax.swing.SwingUtilities.convertPoint(src, pt, hoverTarget)
                        if (!java.awt.Rectangle(0, 0, hoverTarget.width, hoverTarget.height).contains(bp)) copyBtn.isVisible = false
                    }
                }
                bubble.addMouseListener(hoverListener); header.addMouseListener(hoverListener)
                editorPane.addMouseListener(hoverListener); copyBtn.addMouseListener(hoverListener)
            } else {
                // ░░ AI / System message: full-width, no visible bubble — clean text
                val row = JPanel(BorderLayout())
                row.isOpaque = false
                row.border = EmptyBorder(4, 12, 4, 12)
                row.add(header, BorderLayout.NORTH)
                row.add(contentPanel, BorderLayout.CENTER)

                editorPane.isOpaque = false
                editorPane.background = UiTheme.Colors.surface

                root.add(row, BorderLayout.CENTER)

                // Hover: show copy on the whole row
                val hoverTarget = row
                val hoverListener = object : java.awt.event.MouseAdapter() {
                    override fun mouseEntered(e: java.awt.event.MouseEvent?) { copyBtn.isVisible = true }
                    override fun mouseExited(e: java.awt.event.MouseEvent?) {
                        val pt = e?.point ?: return; val src = e.component ?: return
                        val bp = javax.swing.SwingUtilities.convertPoint(src, pt, hoverTarget)
                        if (!java.awt.Rectangle(0, 0, hoverTarget.width, hoverTarget.height).contains(bp)) copyBtn.isVisible = false
                    }
                }
                row.addMouseListener(hoverListener); header.addMouseListener(hoverListener)
                editorPane.addMouseListener(hoverListener); copyBtn.addMouseListener(hoverListener)
            }

            updateHtml()

            // Re-layout on resize so editorPane recalculates width
            root.addComponentListener(object : java.awt.event.ComponentAdapter() {
                override fun componentResized(e: java.awt.event.ComponentEvent?) {
                    SwingUtilities.invokeLater {
                        editorPane.revalidate()
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

            coalescingTimer = javax.swing.Timer(200) { flushPending() }
            coalescingTimer?.isRepeats = false
        }

        fun hideSpinner() {
            spinnerTimer?.stop()
            spinnerTimer = null
            spinnerLabel.isVisible = false
            editorPane.isVisible = true
        }

        /** Buffer incoming chunks, coalesce re-renders */
        fun appendChunk(text: String) {
            synchronized(pendingText) { pendingText.append(text) }
            if (coalescingTimer != null && !coalescingTimer!!.isRunning) {
                coalescingTimer?.restart()
            }
        }

        fun append(text: String) {
            rawText.append(text)
            updateHtml()
        }

        private fun flushPending() {
            val chunk: String
            synchronized(pendingText) {
                chunk = pendingText.toString()
                pendingText.setLength(0)
            }
            if (chunk.isNotEmpty()) {
                rawText.append(chunk)
                updateHtml()
            }
        }

        private fun updateHtml() {
            val isDark = UiTheme.isDarkTheme
            editorPane.text = MarkdownRenderer.toHtml(rawText.toString(), isDark = isDark)
            SwingUtilities.invokeLater {
                editorPane.revalidate()
                contentPanel.revalidate()
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
        } catch (e: Exception) {
            api.logging().logToOutput("[ChatPanel] Invalid tool JSON payload: ${e.message}")
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
