package com.six2dez.burp.aiagent.ui

import burp.api.montoya.MontoyaApi
import com.six2dez.burp.aiagent.audit.ActivityType
import com.six2dez.burp.aiagent.backends.AgentConnection
import com.six2dez.burp.aiagent.agents.AgentProfileLoader
import com.six2dez.burp.aiagent.backends.ChatMessage
import com.six2dez.burp.aiagent.backends.UsageAwareConnection
import com.six2dez.burp.aiagent.config.AgentSettings
import com.six2dez.burp.aiagent.config.Defaults
import com.six2dez.burp.aiagent.context.ContextCapture
import com.six2dez.burp.aiagent.mcp.McpRequestLimiter
import com.six2dez.burp.aiagent.mcp.McpToolCatalog
import com.six2dez.burp.aiagent.mcp.McpToolContext
import com.six2dez.burp.aiagent.mcp.tools.McpToolExecutor
import com.six2dez.burp.aiagent.redact.PrivacyMode
import com.six2dez.burp.aiagent.supervisor.AgentSupervisor
import com.six2dez.burp.aiagent.ui.components.ActionCard
import com.six2dez.burp.aiagent.ui.components.PrivacyPill
import com.six2dez.burp.aiagent.ui.components.ToolInvocationDialog
import com.six2dez.burp.aiagent.util.TokenTracker
import java.awt.BorderLayout
import java.awt.Color
import java.awt.Dimension
import java.awt.Graphics
import java.awt.event.InputEvent
import java.awt.event.KeyEvent
import java.net.URI
import java.util.UUID
import java.util.concurrent.atomic.AtomicReference
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
import javax.swing.JSeparator
import javax.swing.JTextArea
import javax.swing.ListSelectionModel
import javax.swing.SwingUtilities
import javax.swing.border.EmptyBorder
import javax.swing.event.DocumentEvent
import javax.swing.event.DocumentListener

internal class InFlightConnectionTracker {
    private val ref = AtomicReference<AgentConnection?>()

    fun set(connection: AgentConnection?) {
        ref.set(connection)
    }

    fun clearIfMatches(expected: AgentConnection?): Boolean {
        if (expected == null) return ref.get() == null
        return ref.compareAndSet(expected, null)
    }

    fun take(): AgentConnection? = ref.getAndSet(null)

    fun current(): AgentConnection? = ref.get()
}

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
    private val cancelBtn = JButton("Cancel")
    private val clearChatBtn = JButton("Clear Chat")
    private val toolsBtn = JButton("Tools")
    private val inFlightConnection = InFlightConnectionTracker()
    @Volatile private var isSending = false
    private val inputArea = JTextArea(3, 24)
    private val newSessionBtn = JButton("New Session")
    private val privacyPill = PrivacyPill()
    private val sessionPanels = linkedMapOf<String, SessionPanel>()
    private val sessionStates = linkedMapOf<String, ToolSessionState>()
    private val sessionsById = linkedMapOf<String, ChatSession>()
    private val sessionDrafts = linkedMapOf<String, String>()
    private var mcpAvailable = true
    private var activeSessionId: String? = null
    private var suppressDraftSync = false
    private val usageStatsLine1 = JLabel("No usage yet")
    private val usageStatsLine2 = JLabel("")
    private val sessionTokenLabel = JLabel("")
    private val globalTokenLabel = JLabel("")
    private val sessionTokenBar = TokenBar()
    private val globalTokenBar = TokenBar()

    init {
        root.background = UiTheme.Colors.surface

        sessionsList.selectionMode = ListSelectionModel.SINGLE_SELECTION
        sessionsList.font = UiTheme.Typography.body
        sessionsList.cellRenderer = ChatSessionRenderer()
        sessionsList.background = UiTheme.Colors.surface
        sessionsList.foreground = UiTheme.Colors.onSurface
        sessionsList.addListSelectionListener {
            if (it.valueIsAdjusting) return@addListSelectionListener
            val selected = sessionsList.selectedValue ?: return@addListSelectionListener
            switchToSession(selected.id)
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
        toolsBtn.toolTipText = "Open tool dialog. Shift-click to insert /tool command manually."
        toolsBtn.addActionListener { event ->
            if ((event.modifiers and InputEvent.SHIFT_DOWN_MASK) != 0) {
                showToolsMenu()
            } else {
                openToolDialog()
            }
        }

        newSessionBtn.font = UiTheme.Typography.label
        newSessionBtn.isFocusPainted = false
        newSessionBtn.addActionListener { createSession("Chat ${sessionsModel.size + 1}") }

        val listScroll = JScrollPane(sessionsList)
        listScroll.border = EmptyBorder(8, 8, 8, 8)

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
        for (lbl in listOf(usageStatsLine1, usageStatsLine2)) {
            lbl.font = smallFont
            lbl.foreground = dimColor
            usageFooter.add(lbl)
        }
        val sep1 = JSeparator()
        sep1.maximumSize = Dimension(Int.MAX_VALUE, 1)
        usageFooter.add(sep1)
        val sessionHeader = JLabel("── Session tokens ──")
        sessionHeader.font = smallFont
        sessionHeader.foreground = dimColor
        usageFooter.add(sessionHeader)
        sessionTokenBar.maximumSize = Dimension(Int.MAX_VALUE, 6)
        sessionTokenBar.preferredSize = Dimension(0, 6)
        usageFooter.add(sessionTokenBar)
        sessionTokenLabel.font = smallFont
        sessionTokenLabel.foreground = dimColor
        usageFooter.add(sessionTokenLabel)
        val globalHeader = JLabel("── Global tokens ──")
        globalHeader.font = smallFont
        globalHeader.foreground = dimColor
        usageFooter.add(globalHeader)
        globalTokenBar.maximumSize = Dimension(Int.MAX_VALUE, 6)
        globalTokenBar.preferredSize = Dimension(0, 6)
        usageFooter.add(globalTokenBar)
        globalTokenLabel.font = smallFont
        globalTokenLabel.foreground = dimColor
        usageFooter.add(globalTokenLabel)
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

    fun startSessionFromContext(
        capture: ContextCapture,
        promptTemplate: String,
        actionName: String,
        onCompleted: ((String, Throwable?) -> Unit)? = null
    ) {
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
        session.messages.add(ChatMessage("user", prompt))
        sendMessage(
            sessionId = session.id,
            userText = prompt,
            contextJson = capture.contextJson,
            allowToolCalls = state.toolsMode,
            actionName = actionName,
            onCompleted = onCompleted
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
        val inputMap = inputArea.getInputMap(JComponent.WHEN_FOCUSED)
        val actionMap = inputArea.actionMap
        val menuMask = java.awt.Toolkit.getDefaultToolkit().menuShortcutKeyMaskEx
        inputMap.put(javax.swing.KeyStroke.getKeyStroke(KeyEvent.VK_ENTER, 0), "sendMessage")
        inputMap.put(javax.swing.KeyStroke.getKeyStroke(KeyEvent.VK_ENTER, KeyEvent.SHIFT_DOWN_MASK), "insert-break")
        inputMap.put(javax.swing.KeyStroke.getKeyStroke(KeyEvent.VK_T, menuMask), "openToolDialog")
        inputMap.put(javax.swing.KeyStroke.getKeyStroke(KeyEvent.VK_ESCAPE, 0), "cancelInFlight")
        actionMap.put("sendMessage", object : javax.swing.AbstractAction() {
            override fun actionPerformed(e: java.awt.event.ActionEvent?) {
                sendFromInput()
            }
        })
        actionMap.put("openToolDialog", object : javax.swing.AbstractAction() {
            override fun actionPerformed(e: java.awt.event.ActionEvent?) {
                openToolDialog()
            }
        })
        actionMap.put("cancelInFlight", object : javax.swing.AbstractAction() {
            override fun actionPerformed(e: java.awt.event.ActionEvent?) {
                cancelInFlightRequest()
            }
        })
        inputArea.document.addDocumentListener(object : DocumentListener {
            override fun insertUpdate(e: DocumentEvent?) = syncDraftFromInput()
            override fun removeUpdate(e: DocumentEvent?) = syncDraftFromInput()
            override fun changedUpdate(e: DocumentEvent?) = syncDraftFromInput()
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
        cancelBtn.font = UiTheme.Typography.label
        cancelBtn.isFocusPainted = false
        cancelBtn.isVisible = false
        cancelBtn.addActionListener { cancelInFlightRequest() }

        actions.add(privacyPill)
        actions.add(toolsBtn)
        actions.add(clearChatBtn)
        actions.add(cancelBtn)
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
        session.messages.add(ChatMessage("user", text))
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
        actionName: String? = null,
        onCompleted: ((String, Throwable?) -> Unit)? = null,
        toolIterationsLeft: Int = MAX_AUTO_TOOL_ITERATIONS,
        traceId: String = "chat-turn-" + UUID.randomUUID().toString()
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
        setSendingState(true)
        val session = sessionsById[sessionId]
        val backendId = settings.preferredBackendId
        // Track backend usage on session
        if (session != null) {
            session.lastBackendId = backendId
            session.backendsUsed[backendId] = (session.backendsUsed[backendId] ?: 0) + 1
            session.messageCount++
            session.totalCharsIn += userText.length.toLong()
        }
        onStatusChanged()

        val sessionPanel = sessionPanels[sessionId]
        if (sessionPanel == null) {
            setSendingState(false)
            return
        }
        val assistant = sessionPanel.addStreamingMessage("AI")
        val state = sessionStates.getOrPut(sessionId) { ToolSessionState() }
        val toolContext = if (state.toolsMode) buildToolContext(settings, sessionId) else null
        val toolPreamble = if (state.toolsMode) buildToolPreamble(toolContext, state, mutateState = true) else null
        // Only include context JSON on the first turn — history already carries it
        val effectiveContextJson = if (session != null && session.contextSent) null else contextJson
        if (effectiveContextJson != null && session != null) {
            session.contextSent = true
        }
        // Extract agent instructions as system prompt for HTTP backends
        val agentBlock = com.six2dez.burp.aiagent.agents.AgentProfileLoader.buildInstructionBlock(actionName)
        val backendObj = supervisor.getBackend(backendId)
        val systemPrompt: String?
        val prompt: String
        if (backendObj != null && backendObj.supportsSystemRole && !agentBlock.isNullOrBlank()) {
            // Send agent instructions via system role, not in user prompt
            systemPrompt = agentBlock
            prompt = buildContextPayloadNoAgent(userText, effectiveContextJson)
        } else {
            systemPrompt = null
            prompt = buildContextPayload(userText, effectiveContextJson, actionName)
        }
        val finalPrompt = listOfNotNull(
            toolPreamble?.takeIf { it.isNotBlank() },
            prompt.takeIf { it.isNotBlank() }
        ).joinToString("\n\n")
        val promptChars = finalPrompt.length
        if (promptChars > Defaults.LARGE_PROMPT_THRESHOLD) {
            api.logging().logToOutput("[ChatPanel] Large prompt warning: ${promptChars} chars exceeds threshold (${Defaults.LARGE_PROMPT_THRESHOLD})")
        }

        val responseBuffer = StringBuilder()
        val history = session?.messages?.let { msgs ->
            val trimmed = if (msgs.isNotEmpty() &&
                normalizeRole(msgs.last().role) == "user" &&
                msgs.last().content == userText
            ) {
                msgs.dropLast(1)
            } else {
                msgs
            }
            trimmed.map { ChatMessage(normalizeRole(it.role), it.content) }
        }
        val callbackConnectionRef = AtomicReference<AgentConnection?>(null)
        val connection = supervisor.sendChat(
            chatSessionId = sessionId,
            backendId = backendId,
            text = finalPrompt,
            history = history,
            contextJson = contextJson,
            privacyMode = settings.privacyMode,
            determinismMode = settings.determinismMode,
            traceId = traceId,
            systemPrompt = systemPrompt,
            onChunk = { chunk ->
                responseBuffer.append(chunk)
                SwingUtilities.invokeLater { assistant.appendChunk(chunk) }
            },
            onComplete = { err ->
                val callbackConnection = callbackConnectionRef.get()
                val shouldSetIdle = if (callbackConnection == null) {
                    inFlightConnection.current() == null
                } else {
                    inFlightConnection.clearIfMatches(callbackConnection)
                }
                if (shouldSetIdle) {
                    SwingUtilities.invokeLater { setSendingState(false) }
                }
                val usage = (callbackConnection as? UsageAwareConnection)?.lastTokenUsage()
                TokenTracker.record(
                    flow = "chat",
                    backendId = backendId,
                    inputChars = promptChars,
                    outputChars = responseBuffer.length,
                    inputTokensActual = usage?.inputTokens,
                    outputTokensActual = usage?.outputTokens
                )
                if (session != null) {
                    val tokIn = usage?.inputTokens?.toLong()
                        ?: TokenTracker.estimateTokens(promptChars, backendId).toLong()
                    val tokOut = usage?.outputTokens?.toLong()
                        ?: TokenTracker.estimateTokens(responseBuffer.length, backendId).toLong()
                    session.totalTokensIn += tokIn
                    session.totalTokensOut += tokOut
                }
                if (err != null) {
                    SwingUtilities.invokeLater { assistant.append("\n[Error] ${err.message}") }
                    onCompleted?.invoke(responseBuffer.toString(), err)
                } else {
                    val finalResp = responseBuffer.toString()
                    if (session != null) {
                        session.totalCharsOut += finalResp.length.toLong()
                        session.messages.add(ChatMessage("assistant", finalResp))
                    }
                    SwingUtilities.invokeLater {
                        assistant.append("\n")
                        refreshSessionList()
                        onResponseReady()
                    }
                    val chained = if (allowToolCalls && state.toolsMode && toolContext != null) {
                        maybeExecuteToolCall(
                            sessionId = sessionId,
                            userText = userText,
                            responseText = finalResp,
                            context = toolContext,
                            remainingToolIterations = toolIterationsLeft,
                            traceId = traceId,
                            onCompleted = onCompleted
                        )
                    } else {
                        false
                    }
                    if (!chained) {
                        onCompleted?.invoke(finalResp, null)
                    }
                }
            }
        )
        callbackConnectionRef.set(connection)
        inFlightConnection.set(connection)
    }

    private fun sanitizeTitle(raw: String): String =
        raw.replace(Regex("[\\t\\n\\r\\u0000-\\u001F]"), " ").trim()

    private fun createSession(title: String): ChatSession {
        val id = "chat-" + UUID.randomUUID().toString()
        val backendId = getSettings().preferredBackendId
        val session = ChatSession(id, sanitizeTitle(title), System.currentTimeMillis(), lastBackendId = backendId)
        sessionsModel.addElement(session)
        sessionsById[id] = session
        sessionDrafts[id] = ""

        val panel = SessionPanel()
        sessionPanels[id] = panel
        sessionStates[id] = ToolSessionState()
        chatCards.add(panel.root, id)
        sessionsList.selectedIndex = sessionsModel.size - 1
        switchToSession(id)
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
                val updated = session.copy(title = sanitizeTitle(newName))
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
            try {
                supervisor.removeChatSession(session.id)
                val removedPanel = sessionPanels.remove(session.id)
                if (removedPanel != null) {
                    chatCards.remove(removedPanel.root)
                }
            } finally {
                sessionStates.remove(session.id)
                sessionsById.remove(session.id)
                sessionDrafts.remove(session.id)
                sessionsModel.removeElement(session)
                // Clean persisted data
                try {
                    chatPrefs().setString(SESSION_MSG_KEY_PREFIX + session.id, "")
                } catch (_: Exception) {}
            }

            if (sessionsModel.isEmpty()) {
                // Create a default session if all gone
                createSession("Chat 1")
            } else if (sessionsList.isSelectionEmpty) {
                sessionsList.selectedIndex = sessionsModel.size - 1
            } else {
                sessionsList.selectedValue?.id?.let { switchToSession(it) }
            }
            updateUsageStatsLabel()
        }
    }

    /** Export current session as a Markdown file */
    fun exportCurrentChatAsMarkdown() {
        val session = sessionsList.selectedValue ?: return
        val md = buildString {
            appendLine("# ${session.title}")
            appendLine()
            appendLine("Backend: ${session.lastBackendId ?: "unknown"}")
            appendLine("Date: ${java.text.SimpleDateFormat("yyyy-MM-dd HH:mm").format(java.util.Date(session.createdAt))}")
            appendLine()
            appendLine("---")
            appendLine()
            for (msg in session.messages) {
                val displayRole = when (msg.role.lowercase()) {
                    "user" -> "You"
                    "assistant" -> "AI"
                    else -> msg.role
                }
                appendLine("**$displayRole:**")
                appendLine()
                appendLine(msg.content.trim())
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

    /** Toggle UI between sending and idle states */
    private fun setSendingState(sending: Boolean) {
        isSending = sending
        sendBtn.isVisible = !sending
        cancelBtn.isVisible = sending
        inputArea.isEnabled = !sending
    }

    /** Cancel the current in-flight AI request */
    fun cancelInFlightRequest(): Boolean {
        val conn = inFlightConnection.take() ?: return false
        setSendingState(false)
        try {
            conn.stop()
        } catch (_: Exception) {}
        val sessionId = sessionsList.selectedValue?.id ?: return true
        val panel = sessionPanels[sessionId] ?: return true
        panel.addMessage("System", "Request cancelled.")
        return true
    }

    fun openToolDialog() {
        if (!mcpAvailable) {
            showError("MCP server is not running.")
            return
        }
        val session = sessionsList.selectedValue ?: createSession("Chat ${sessionsModel.size + 1}")
        val panel = sessionPanels[session.id] ?: return
        val state = sessionStates.getOrPut(session.id) { ToolSessionState() }
        val settings = getSettings()
        val context = buildToolContext(settings, session.id)
        val availableTools = McpToolCatalog.all()
            .filter { descriptor ->
                val enabled = context.isToolEnabled(descriptor.id) && context.isUnsafeToolAllowed(descriptor.id)
                val proAllowed = !descriptor.proOnly || context.edition == burp.api.montoya.core.BurpSuiteEdition.PROFESSIONAL
                enabled && proAllowed
            }

        if (availableTools.isEmpty()) {
            showError("No enabled MCP tools are available with current settings.")
            return
        }

        val owner = SwingUtilities.getWindowAncestor(root)
        val invocation = ToolInvocationDialog(owner, availableTools, McpToolExecutor::inputSchema).showDialog() ?: return
        val args = invocation.argsJson
        val commandPreview = if (args.isNullOrBlank()) {
            "/tool ${invocation.toolId} {}"
        } else {
            "/tool ${invocation.toolId} $args"
        }

        panel.addMessage("You", commandPreview)
        session.messages.add(ChatMessage("user", commandPreview))

        val result = McpToolExecutor.executeTool(invocation.toolId, args, context)
        panel.addMessage("Tool result: ${invocation.toolId}", result)
        session.messages.add(ChatMessage("assistant", "Tool result (${invocation.toolId}):\n$result"))
        state.toolsMode = true
        state.toolCatalogSent = true
        refreshSessionList()
    }

    private fun cancelCurrentRequest() {
        cancelInFlightRequest()
    }

    private fun showToolsMenu() {
        val menu = javax.swing.JPopupMenu()
        val tools = McpToolCatalog.all()
        val settings = getSettings()
        val sessionId = sessionsList.selectedValue?.id ?: activeSessionId ?: "preview"
        val context = buildToolContext(settings, sessionId)

        tools.groupBy { it.category }.forEach { (category, categoryTools) ->
            val submenu = javax.swing.JMenu(category)
            categoryTools.sortedBy { it.title }.forEach { tool ->
                val canRun = context.isToolEnabled(tool.id) &&
                    context.isUnsafeToolAllowed(tool.id) &&
                    (!tool.proOnly || context.edition == burp.api.montoya.core.BurpSuiteEdition.PROFESSIONAL)
                
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
        val base = buildContextPayloadNoAgent(userText, contextJson)
        return listOfNotNull(
            agentBlock?.takeIf { it.isNotBlank() },
            base.takeIf { it.isNotBlank() }
        ).joinToString("\n\n")
    }

    private fun buildContextPayloadNoAgent(userText: String, contextJson: String?): String {
        return if (contextJson.isNullOrBlank()) {
            userText
        } else {
            buildString {
                appendLine(userText)
                appendLine()
                appendLine("Context (JSON):")
                append(contextJson)
            }
        }
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

    private fun switchToSession(id: String) {
        persistActiveSessionDraft()
        activeSessionId = id
        val layout = chatCards.layout as java.awt.CardLayout
        layout.show(chatCards, id)
        restoreDraftForSession(id)
    }

    private fun persistActiveSessionDraft() {
        val id = activeSessionId ?: return
        sessionDrafts[id] = inputArea.text
    }

    private fun restoreDraftForSession(id: String) {
        val draft = sessionDrafts[id].orEmpty()
        suppressDraftSync = true
        inputArea.text = draft
        suppressDraftSync = false
    }

    private fun syncDraftFromInput() {
        if (suppressDraftSync) return
        val id = activeSessionId ?: sessionsList.selectedValue?.id ?: return
        sessionDrafts[id] = inputArea.text
    }

    companion object {
        private const val MAX_AUTO_TOOL_ITERATIONS = 8

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

    private class TokenBar : JPanel() {
        private var ratio = 0f

        init {
            isOpaque = false
        }

        fun setRatio(value: Float) {
            ratio = value.coerceIn(0f, 1f)
            repaint()
        }

        override fun paintComponent(g: Graphics) {
            super.paintComponent(g)
            val w = width
            val h = height
            if (w <= 0 || h <= 0) return
            // Background track
            g.color = Color(80, 80, 80)
            g.fillRoundRect(0, 0, w, h, h, h)
            // Filled portion
            val fillW = (w * ratio).toInt().coerceAtLeast(0)
            if (fillW > 0) {
                g.color = when {
                    ratio < 0.4f -> Color(76, 175, 80)   // green
                    ratio < 0.7f -> Color(255, 193, 7)    // yellow
                    else -> Color(255, 152, 0)             // orange
                }
                g.fillRoundRect(0, 0, fillW, h, h, h)
            }
        }
    }

    private fun refreshSessionList() {
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
            sessionTokenLabel.text = "In: 0 | Out: 0"
            globalTokenLabel.text = "In: 0 | Out: 0"
            sessionTokenBar.setRatio(0f)
            globalTokenBar.setRatio(0f)
        } else {
            usageStatsLine1.text = "${stats.totalMessages} msgs | In: ${formatChars(stats.totalCharsIn)} | Out: ${formatChars(stats.totalCharsOut)}"
            usageStatsLine2.text = stats.perBackend.entries
                .sortedByDescending { it.value }
                .joinToString(", ") { "${it.key}: ${it.value}" }

            // Per-session tokens
            val activeSession = activeSessionId?.let { sessionsById[it] }
            val sessIn = activeSession?.totalTokensIn ?: 0L
            val sessOut = activeSession?.totalTokensOut ?: 0L
            val sessTotal = sessIn + sessOut
            sessionTokenLabel.text = "In: ${formatChars(sessIn)} | Out: ${formatChars(sessOut)} | Total: ${formatChars(sessTotal)}"

            // Global tokens from TokenTracker
            val snapshots = TokenTracker.snapshot()
            val globalIn = snapshots.sumOf { it.inputTokensEstimated }
            val globalOut = snapshots.sumOf { it.outputTokensEstimated }
            val globalTotal = globalIn + globalOut
            globalTokenLabel.text = "In: ${formatChars(globalIn)} | Out: ${formatChars(globalOut)} | Total: ${formatChars(globalTotal)}"

            // Bar ratios: session relative to global, global fills fully
            val sessionRatio = if (globalTotal > 0) sessTotal.toFloat() / globalTotal.toFloat() else 0f
            sessionTokenBar.setRatio(sessionRatio.coerceIn(0f, 1f))
            globalTokenBar.setRatio(if (globalTotal > 0) 1f else 0f)
        }
    }

    private fun formatChars(chars: Long): String {
        return when {
            chars >= 1_000_000 -> String.format("%.1fM", chars / 1_000_000.0)
            chars >= 1_000 -> String.format("%.1fK", chars / 1_000.0)
            else -> "${chars}"
        }
    }

    private fun normalizeRole(role: String): String {
        return when (role.lowercase()) {
            "you", "user" -> "user"
            "ai", "assistant" -> "assistant"
            "system" -> "system"
            else -> role
        }
    }

    // ── Persistence: save/restore chat sessions via Burp preferences ──

    private val SESSIONS_KEY = "chat.sessions"
    private val SESSION_MSG_KEY_PREFIX = "chat.messages."
    private val SESSION_DRAFTS_KEY = "chat.drafts"
    private val MIGRATED_KEY = "chat.migrated_to_project"

    private fun chatPrefs(): burp.api.montoya.persistence.Preferences {
        val project = projectPrefsOrNull()
        return project ?: api.persistence().preferences()
    }

    private fun projectPrefsOrNull(): burp.api.montoya.persistence.Preferences? {
        return try {
            val persistence = api.persistence()
            val method = persistence.javaClass.methods.firstOrNull { it.name == "projectPreferences" && it.parameterCount == 0 }
            method?.invoke(persistence) as? burp.api.montoya.persistence.Preferences
        } catch (_: Exception) {
            null
        }
    }

    fun saveSessions() {
        try {
            persistActiveSessionDraft()
            val prefs = chatPrefs()
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
            for (s in sessionsById.values) {
                val msgData = s.messages.joinToString("\u001F") { msg ->
                    "${msg.role}\u001E${msg.content.replace("\n", "\u001D")}"
                }
                prefs.setString(SESSION_MSG_KEY_PREFIX + s.id, msgData)
            }
            val draftsData = sessionsById.keys.map { id ->
                val draft = sessionDrafts[id].orEmpty().replace("\n", "\u001D")
                "$id\u001E$draft"
            }
            prefs.setString(SESSION_DRAFTS_KEY, draftsData.joinToString("\n"))

            api.logging().logToOutput("[ChatPanel] Saved ${sessionsById.size} sessions with messages.")
        } catch (e: Exception) {
            api.logging().logToError("[ChatPanel] Failed to save sessions: ${e.message}")
        }
    }

    fun restoreSessions() {
        try {
            val prefs = chatPrefs()
            maybeMigrateGlobalToProject(prefs)
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
                            backendsUsed[kv[0]] = 0
                        }
                    }
                }
                val messageCount = parts.getOrNull(4)?.toIntOrNull() ?: 0
                val totalCharsIn = parts.getOrNull(5)?.toLongOrNull() ?: 0L
                val totalCharsOut = parts.getOrNull(6)?.toLongOrNull() ?: 0L

                // Restore messages
                val messages = mutableListOf<ChatMessage>()
                val msgRaw = prefs.getString(SESSION_MSG_KEY_PREFIX + id)
                if (!msgRaw.isNullOrBlank()) {
                    for (msgEntry in msgRaw.split("\u001F")) {
                        val msgParts = msgEntry.split("\u001E", limit = 2)
                        if (msgParts.size == 2) {
                            val role = msgParts[0]
                            var text = msgParts[1].replace("\u001D", "\n")
                            // Clean up noise from old persisted messages
                            text = text.lines()
                                .filterNot { it.lowercase().startsWith("hook registry initialized") }
                                .joinToString("\n")
                                .trim()
                            if (text.isNotBlank()) {
                                messages.add(ChatMessage(role, text))
                            }
                        }
                    }
                }

                val session = ChatSession(
                    id = id,
                    title = title,
                    createdAt = createdAt,
                    lastBackendId = backendsUsed.keys.firstOrNull(),
                    backendsUsed = backendsUsed,
                    messageCount = messageCount,
                    totalCharsIn = totalCharsIn,
                    totalCharsOut = totalCharsOut,
                    messages = messages
                )

                sessionsModel.addElement(session)
                sessionsById[id] = session
                sessionDrafts[id] = ""
                val panel = SessionPanel()
                sessionPanels[id] = panel
                sessionStates[id] = ToolSessionState()
                chatCards.add(panel.root, id)

                // Display restored messages
                for (msg in messages) {
                    panel.addMessage(msg.role, msg.content)
                }
            }

            val draftsRaw = prefs.getString(SESSION_DRAFTS_KEY).orEmpty()
            if (draftsRaw.isNotBlank()) {
                draftsRaw.split('\n')
                    .filter { it.isNotBlank() }
                    .forEach { entry ->
                        val parts = entry.split("\u001E", limit = 2)
                        if (parts.size != 2) return@forEach
                        val id = parts[0]
                        if (!sessionsById.containsKey(id)) return@forEach
                        sessionDrafts[id] = parts[1].replace("\u001D", "\n")
                    }
            }

            if (sessionsModel.size > 0) {
                sessionsList.selectedIndex = sessionsModel.size - 1
                switchToSession(sessionsById.keys.last())
            }
            updateUsageStatsLabel()
            api.logging().logToOutput("[ChatPanel] Restored ${sessionsById.size} sessions with messages.")
        } catch (e: Exception) {
            api.logging().logToError("[ChatPanel] Failed to restore sessions: ${e.message}")
        }
    }

    private fun maybeMigrateGlobalToProject(projectPrefs: burp.api.montoya.persistence.Preferences) {
        try {
            val already = projectPrefs.getBoolean(MIGRATED_KEY) ?: false
            if (already) return

            val globalPrefs = api.persistence().preferences()
            val raw = globalPrefs.getString(SESSIONS_KEY).orEmpty()
            if (raw.isNotBlank()) {
                projectPrefs.setString(SESSIONS_KEY, raw)
                val lines = raw.split('\n').filter { it.isNotBlank() }
                for (line in lines) {
                    val parts = line.split('\t')
                    if (parts.isEmpty()) continue
                    val id = parts[0]
                    if (id.isBlank()) continue
                    val msgRaw = globalPrefs.getString(SESSION_MSG_KEY_PREFIX + id)
                    if (!msgRaw.isNullOrBlank()) {
                        projectPrefs.setString(SESSION_MSG_KEY_PREFIX + id, msgRaw)
                    }
                }

                val draftsRaw = globalPrefs.getString(SESSION_DRAFTS_KEY)
                if (!draftsRaw.isNullOrBlank()) {
                    projectPrefs.setString(SESSION_DRAFTS_KEY, draftsRaw)
                }

                // Clear global after migration
                globalPrefs.setString(SESSIONS_KEY, "")
                globalPrefs.setString(SESSION_DRAFTS_KEY, "")
                for (line in lines) {
                    val parts = line.split('\t')
                    if (parts.isEmpty()) continue
                    val id = parts[0]
                    if (id.isNotBlank()) {
                        globalPrefs.setString(SESSION_MSG_KEY_PREFIX + id, "")
                    }
                }
            }

            projectPrefs.setBoolean(MIGRATED_KEY, true)
        } catch (e: Exception) {
            api.logging().logToError("[ChatPanel] Failed to migrate global chat sessions: ${e.message}")
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
        var lastBackendId: String? = null,
        val backendsUsed: MutableMap<String, Int> = mutableMapOf(),
        var messageCount: Int = 0,
        var totalCharsIn: Long = 0,
        var totalCharsOut: Long = 0,
        var totalTokensIn: Long = 0,
        var totalTokensOut: Long = 0,
        val messages: MutableList<ChatMessage> = mutableListOf(),
        var contextSent: Boolean = false
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

            val dateStr = ChatPanel.formatSessionDate(value.createdAt)
            val backendText = value.lastBackendId ?: "—"
            val infoText = "$backendText  \u00B7  $dateStr"
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

        fun appendChunk(text: String) {
            append(text)
        }
    }

    private class ChatMessagePanel(
        private val role: String,
        initialText: String
    ) {
        // Normalize role detection: accept "You", "user", "User" as user
        private val isUser = role.lowercase() in listOf("you", "user")
        // Display normalized labels
        private val displayRole = if (isUser) "You" else "AI"
        private val showSpinner = !isUser && initialText.isEmpty()
        private val rawText = StringBuilder(initialText)
        private val copyBtn = JButton("Copy")
        private val spinnerLabel = JLabel("Thinking...")
        private var spinnerTimer: javax.swing.Timer? = null
        private val spinnerFrames = listOf("\u280B", "\u2819", "\u2839", "\u2838", "\u283C", "\u2834", "\u2826", "\u2827", "\u2807", "\u280F")
        private var spinnerIndex = 0
        private val pendingText = StringBuilder()
        private var coalescingTimer: javax.swing.Timer? = null
        private var isStreaming = false
        private var lastRenderedLength = 0
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
                    // AI bubble: max 75% of viewport, shrink-to-fit for short text
                    val maxW = (vpW * 0.75).toInt().coerceAtLeast(200)
                    setSize(maxW, Short.MAX_VALUE.toInt())
                    val naturalW = super.getPreferredSize().width
                    naturalW.coerceAtMost(maxW)
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

            val roleLabel = JLabel(displayRole)
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
            editorPane.putClientProperty(javax.swing.JEditorPane.HONOR_DISPLAY_PROPERTIES, true)
            editorPane.font = UiTheme.Typography.chatBody
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
                // User message: right-aligned bubble with colored background
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
                // AI / System message: left-aligned bubble (like ChatGPT)
                val bubble = JPanel(BorderLayout())
                bubble.isOpaque = true
                bubble.background = UiTheme.Colors.aiBubble
                bubble.border = javax.swing.BorderFactory.createCompoundBorder(
                    javax.swing.BorderFactory.createLineBorder(UiTheme.Colors.outline, 1),
                    EmptyBorder(8, 14, 8, 14)
                )
                bubble.add(header, BorderLayout.NORTH)
                bubble.add(contentPanel, BorderLayout.CENTER)
                editorPane.background = UiTheme.Colors.aiBubble

                // Wrapper: places bubble at WEST (left side)
                val wrapper = JPanel(BorderLayout())
                wrapper.isOpaque = false
                wrapper.border = EmptyBorder(0, 12, 0, 12)
                wrapper.add(bubble, BorderLayout.WEST)

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
            isStreaming = true
            synchronized(pendingText) { pendingText.append(text) }
            coalescingTimer?.let { timer ->
                if (!timer.isRunning) timer.restart()
            }
        }

        fun append(text: String) {
            rawText.append(text)
            isStreaming = false
            lastRenderedLength = rawText.length
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
                // During streaming on long messages: only do full markdown render
                // every 2KB of new content to avoid O(n) regex on every 200ms tick
                val newBytes = rawText.length - lastRenderedLength
                if (isStreaming && rawText.length > 1024 && newBytes < 2048) {
                    // Lightweight: just set plain escaped text for intermediate updates
                    val escaped = rawText.toString()
                        .replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
                        .replace("\n", "<br>")
                    val isDark = UiTheme.isDarkTheme
                    val fontSize = (UiTheme.Typography.chatBody.size - 2).coerceAtLeast(10)
                    val textColor = if (isDark) "#e0e0e0" else "#202020"
                    editorPane.text = "<html><body style='font-family:SansSerif;color:$textColor;font-size:${fontSize}px;margin:0;padding:0;line-height:1.4;'>$escaped</body></html>"
                    SwingUtilities.invokeLater {
                        editorPane.revalidate()
                        contentPanel.revalidate()
                        root.revalidate()
                    }
                } else {
                    lastRenderedLength = rawText.length
                    updateHtml()
                }
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
        remainingToolIterations: Int,
        traceId: String,
        onCompleted: ((String, Throwable?) -> Unit)?
    ): Boolean {
        if (remainingToolIterations <= 0) return false
        val call = ToolCallParser.extractFirst(responseText) ?: return false
        val panel = sessionPanels[sessionId] ?: return false
        val backendId = sessionsById[sessionId]?.lastBackendId ?: getSettings().preferredBackendId
        val chainStep = (MAX_AUTO_TOOL_ITERATIONS - remainingToolIterations + 1).coerceAtLeast(1)
        val startedAt = System.currentTimeMillis()
        val resultOutcome = runCatching { McpToolExecutor.executeTool(call.tool, call.argsJson, context) }
        val durationMs = System.currentTimeMillis() - startedAt
        if (resultOutcome.isFailure) {
            val errorMessage = resultOutcome.exceptionOrNull()?.message ?: "Unknown MCP tool error"
            supervisor.aiRequestLogger?.log(
                type = ActivityType.MCP_TOOL_CALL,
                source = "chat",
                backendId = backendId,
                sessionId = sessionId,
                detail = "Tool ${call.tool} failed: $errorMessage",
                durationMs = durationMs,
                metadata = mapOf(
                    "operation" to "tool_chain",
                    "status" to "error",
                    "traceId" to traceId,
                    "step" to chainStep.toString(),
                    "toolName" to call.tool,
                    "errorClass" to (resultOutcome.exceptionOrNull()?.javaClass?.simpleName ?: "Exception")
                )
            )
            panel.addMessage("Tool result: ${call.tool}", "Error: $errorMessage")
            return false
        }
        val result = resultOutcome.getOrThrow()
        val status = if (result.startsWith("Error:")) "error" else "ok"
        supervisor.aiRequestLogger?.log(
            type = ActivityType.MCP_TOOL_CALL,
            source = "chat",
            backendId = backendId,
            sessionId = sessionId,
            detail = "Tool ${call.tool} executed",
            durationMs = durationMs,
            metadata = mapOf(
                "operation" to "tool_chain",
                "status" to status,
                "traceId" to traceId,
                "step" to chainStep.toString(),
                "toolName" to call.tool,
                "resultChars" to result.length.toString()
            )
        )
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
            allowToolCalls = remainingToolIterations > 1,
            actionName = "Tool Followup",
            onCompleted = onCompleted,
            toolIterationsLeft = (remainingToolIterations - 1).coerceAtLeast(0),
            traceId = traceId
        )
        return true
    }

    private fun buildToolPreamble(
        context: McpToolContext?,
        state: ToolSessionState,
        mutateState: Boolean
    ): String? {
        if (context == null) return null
        val header = """
Tool mode is enabled.
Use enabled MCP tools when needed.
For confirmed vulnerabilities that should be recorded, call `issue_create` with concrete evidence.
Tool call JSON format: `tool`+`args` (or `name`+`arguments`).
After a tool call, wait for the tool result, then continue.
        """.trim()
        if (state.toolCatalogSent) return header
        if (mutateState) {
            state.toolCatalogSent = true
        }
        val list = McpToolExecutor.describeTools(context, includeSchemas = false, includeDisabled = false)
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
            enabledUnsafeTools = settings.mcpSettings.enabledUnsafeTools,
            limiter = McpRequestLimiter(settings.mcpSettings.maxConcurrentRequests),
            edition = api.burpSuite().version().edition(),
            maxBodyBytes = settings.mcpSettings.maxBodyBytes
        )
    }
}
