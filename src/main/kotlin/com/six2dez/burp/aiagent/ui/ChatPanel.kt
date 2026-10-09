package com.six2dez.burp.aiagent.ui

import burp.api.montoya.MontoyaApi
import com.six2dez.burp.aiagent.agents.AgentProfileLoader
import com.six2dez.burp.aiagent.audit.ActivityType
import com.six2dez.burp.aiagent.audit.AuditLogger
import com.six2dez.burp.aiagent.backends.AgentConnection
import com.six2dez.burp.aiagent.backends.ChatMessage
import com.six2dez.burp.aiagent.backends.UsageAwareConnection
import com.six2dez.burp.aiagent.config.AgentSettings
import com.six2dez.burp.aiagent.config.Defaults
import com.six2dez.burp.aiagent.context.ContextCapture
import com.six2dez.burp.aiagent.mcp.ImplicitDenyReason
import com.six2dez.burp.aiagent.mcp.McpRequestLimiter
import com.six2dez.burp.aiagent.mcp.McpToolCatalog
import com.six2dez.burp.aiagent.mcp.McpToolContext
import com.six2dez.burp.aiagent.mcp.ToolApprovalGate
import com.six2dez.burp.aiagent.mcp.ToolApprovalMemory
import com.six2dez.burp.aiagent.mcp.ToolApprovalOutcome
import com.six2dez.burp.aiagent.mcp.ToolCallOrigin
import com.six2dez.burp.aiagent.mcp.ToolDecision
import com.six2dez.burp.aiagent.mcp.ToolDecisionReporter
import com.six2dez.burp.aiagent.mcp.tools.McpToolExecutor
import com.six2dez.burp.aiagent.redact.PrivacyMode
import com.six2dez.burp.aiagent.redact.SecretTripwire
import com.six2dez.burp.aiagent.scanner.PassiveAiScanner
import com.six2dez.burp.aiagent.supervisor.AgentSupervisor
import com.six2dez.burp.aiagent.ui.components.ActionCard
import com.six2dez.burp.aiagent.ui.components.ContextPreviewDialog
import com.six2dez.burp.aiagent.ui.components.PrivacyPill
import com.six2dez.burp.aiagent.ui.components.SubtleNotice
import com.six2dez.burp.aiagent.ui.components.ToolApprovalCard
import com.six2dez.burp.aiagent.ui.components.ToolInvocationDialog
import com.six2dez.burp.aiagent.ui.design.DesignTokens
import com.six2dez.burp.aiagent.util.BudgetGuard
import com.six2dez.burp.aiagent.util.GuardedBy
import com.six2dez.burp.aiagent.util.TokenTracker
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import java.awt.BorderLayout
import java.awt.Color
import java.awt.Dimension
import java.awt.Graphics
import java.awt.Rectangle
import java.awt.event.InputEvent
import java.awt.event.KeyEvent
import java.net.URI
import java.util.UUID
import java.util.concurrent.atomic.AtomicReference
import javax.swing.BoxLayout
import javax.swing.DefaultListModel
import javax.swing.JButton
import javax.swing.JComponent
import javax.swing.JLabel
import javax.swing.JList
import javax.swing.JPanel
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

/**
 * The compare-and-set cell that decides whether a returning tool worker still owns the panel (D-08).
 *
 * Deliberately the same four-method surface as [InFlightConnectionTracker] above, applied to the same
 * problem one layer over: a unit of work returns and has to find out whether anything happened while it
 * was away. The token is opaque — its identity is the whole of its meaning, so a worker whose
 * `clearIfMatches` fails knows it was superseded without needing to know by what.
 *
 * A `cancelled: Boolean` flag or a generation counter would need a second variable to say which run the
 * flag refers to; the CAS says it in one operation, and the tracker above is this file's reviewed answer
 * to exactly that question.
 */
internal class RunningToolTracker {
    private val ref = AtomicReference<Any?>()

    fun set(token: Any) {
        ref.set(token)
    }

    fun clearIfMatches(expected: Any): Boolean = ref.compareAndSet(expected, null)

    fun take(): Any? = ref.getAndSet(null)

    fun current(): Any? = ref.get()
}

class ChatPanel(
    private val api: MontoyaApi,
    private val supervisor: AgentSupervisor,
    /**
     * The applied settings snapshot (`AgentSettingsRepository.load()`). ChatPanel never saves or applies
     * settings (quick 261008-n0c, H10).
     */
    private val getSettings: () -> AgentSettings,
    private val validateBackend: (AgentSettings) -> String?,
    private val ensureBackendReady: (AgentSettings) -> Boolean,
    private val showError: (String) -> Unit,
    private val onStatusChanged: () -> Unit,
    private val onResponseReady: () -> Unit,
    // CAP-04: injected to call setBudgetPaused(true) when hard cap is reached
    private val passiveScanner: PassiveAiScanner? = null,
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
    private val runningTool = RunningToolTracker()

    @Volatile private var isSending = false
    private val inputArea = JTextArea(3, 24)
    private val newSessionBtn = JButton("New Session")
    private val privacyPill = PrivacyPill()

    @GuardedBy("EDT")
    private val sessionPanels = linkedMapOf<String, SessionPanel>()

    @GuardedBy("EDT")
    private val sessionStates = linkedMapOf<String, ToolSessionState>()

    @GuardedBy("EDT")
    private val sessionsById = linkedMapOf<String, ChatSession>()

    @GuardedBy("EDT")
    private val sessionDrafts = linkedMapOf<String, String>()

    /**
     * The SEC-06 tool call awaiting a click, per chat session (D-06).
     *
     * Same EDT discipline as every map above: written from `maybeExecuteToolCall` and read from the
     * card's `ActionListener`, both of which the AWT event pump runs on the EDT.
     *
     * **At most one entry per session, and that is an invariant rather than a convenience.** A pending
     * card parks the continuation, so no further backend turn can run in that session while one is
     * outstanding — the card was not designed for a second concurrent decision, and two of them would
     * make "what am I approving?" ambiguous.
     */
    @GuardedBy("EDT")
    private val pendingDecisions = linkedMapOf<String, PendingToolDecision>()

    /**
     * The SC3 decision record, built once and pointed at all three destinations.
     *
     * ONE instance for the panel rather than one per call, because the point of the shape is that the
     * `mcp_tool_decision` audit event, the Burp Output line and the `MCP_TOOL_CALL` metadata all come
     * from a single construction and therefore cannot disagree (T-22-09). The Output sink is a lambda
     * rather than the Burp API handle — the `McpBlockedRequestReporter` convention — which is what
     * keeps the reporter assertable with no Montoya mock.
     *
     * The verbose seam reads the Verbose audit setting from the applied snapshot ([getSettings]) at each
     * report (quick 261008-sqa), so a saved change applies to the next decision. Model-supplied args are
     * always digested as `argsSha256`; Verbose audit adds the args body under `args` in the audit event
     * only, and the metadata map the reporter returns never carries it, because AI Activity metadata
     * reaches the AI request log and `ai_audit_query`.
     */
    private val toolDecisionReporter =
        ToolDecisionReporter(
            logToOutput = { line -> api.logging().logToOutput(line) },
            verboseAudit = { getSettings().auditVerbose },
        )
    private var mcpAvailable = true
    private var activeSessionId: String? = null
    private var suppressDraftSync = false
    private val usageStatsLine1 = JLabel("No usage yet")
    private val usageStatsLine2 = JLabel("")
    private val sessionTokenLabel = JLabel("")
    private val globalTokenLabel = JLabel("")
    private val sessionTokenBar = TokenBar()
    private val globalTokenBar = TokenBar()

    // CAP-04: single SubtleNotice instance for budget warnings; starts hidden
    private val budgetNotice = SubtleNotice()

    init {
        root.background = UiTheme.Colors.surface

        sessionsList.selectionMode = ListSelectionModel.SINGLE_SELECTION
        sessionsList.font = UiTheme.Typography.body
        sessionsList.cellRenderer = ChatSessionRenderer { sessionId -> pendingDecisions.containsKey(sessionId) }
        sessionsList.background = UiTheme.Colors.surface
        sessionsList.foreground = UiTheme.Colors.onSurface
        sessionsList.addListSelectionListener {
            if (it.valueIsAdjusting) return@addListSelectionListener
            val selected = sessionsList.selectedValue ?: return@addListSelectionListener
            switchToSession(selected.id)
        }
        sessionsList.addMouseListener(
            object : java.awt.event.MouseAdapter() {
                override fun mousePressed(e: java.awt.event.MouseEvent) {
                    if (SwingUtilities.isRightMouseButton(e)) {
                        val index = sessionsList.locationToIndex(e.point)
                        if (index != -1) {
                            sessionsList.selectedIndex = index
                            showSessionContextMenu(e.component, e.x, e.y)
                        }
                    }
                }
            },
        )

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
        chatContainer.add(budgetNotice, BorderLayout.NORTH) // CAP-04: token budget banner (starts hidden)
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

    /**
     * Re-derives the panel's affordances from MCP availability, WITHOUT undoing the busy state.
     *
     * The `isSending` terms are the CR-05 limb that needs no second dialog to reproduce. Measured:
     * `MainTab.mcpStatusTimer` fires `updateMcpControls()` every 1000 ms and reaches here through
     * `setMcpAvailable`, so without those terms any tool run lasting longer than one second silently
     * regains its input area and its tool button while the worker is still in flight — UI-SPEC state
     * S3 collapsing back to S0 on a timer tick. Plan 23-06 moved `MainTab.renderStatus()` into an
     * asynchronous tail, which adds a second arrival moment for the same call.
     *
     * `sendBtn`, `clearChatBtn` and `newSessionBtn` stay on `mcpAvailable` alone on purpose: Send is
     * HIDDEN rather than disabled in S3 (Rule S-2), and Clear Chat / New Session are reachable in S3
     * today, which this plan does not change.
     */
    private fun updateChatAvailability() {
        sendBtn.isEnabled = mcpAvailable
        clearChatBtn.isEnabled = mcpAvailable
        toolsBtn.isEnabled = mcpAvailable && !isSending
        inputArea.isEnabled = mcpAvailable && !isSending
        newSessionBtn.isEnabled = mcpAvailable
    }

    fun startSessionFromContext(
        capture: ContextCapture,
        promptTemplate: String,
        actionName: String,
        onCompleted: ((String, Throwable?) -> Unit)? = null,
    ) {
        startSessionFromContext(
            capture,
            PromptLaunchSpec(
                promptText = promptTemplate,
                actionName = actionName,
                source = PromptSource.FIXED,
                contextKind = ContextKind.HTTP_SELECTION,
            ),
            onCompleted,
        )
    }

    fun startSessionFromContext(
        capture: ContextCapture,
        spec: PromptLaunchSpec,
        onCompleted: ((String, Throwable?) -> Unit)? = null,
    ) {
        updatePrivacyPill()
        val prompt = launchPrompt(spec)
        if (!ContextPreviewDialog.confirm(
                parent = root,
                privacyMode = getSettings().privacyMode,
                // D-07: the dialog's OFF hint is conditioned on this — no default on the parameter,
                // so a future second caller cannot silently inherit the wrong answer.
                customPatternsConfigured = getSettings().customRedactionPatterns.isNotEmpty(),
                actionName = spec.actionName,
                prompt = prompt,
                contextJson = capture.contextJson,
            )
        ) {
            onCompleted?.invoke("", InterruptedException("Context preview cancelled by user"))
            return
        }
        startConfirmedSessionFromContext(capture, spec, onCompleted)
    }

    /** The prompt a context launch sends: the spec's text, or the default when it is blank. */
    private fun launchPrompt(spec: PromptLaunchSpec): String = spec.promptText.trim().ifBlank { "Analyze the provided context." }

    /**
     * Everything a context launch does once the user has confirmed the context preview.
     *
     * **Split from [startSessionFromContext] so this half is reachable without the modal.**
     * `ContextPreviewDialog.confirm` builds a `JDialog`, which throws `HeadlessException` under
     * `-Djava.awt.headless=true`, so a headless test driving [startSessionFromContext] never reaches the
     * session it creates or the send it starts. The dialog is not removed and nothing a user can observe
     * changes: the dialog is the user clicking Send, and this is what that click does. EDT-confined like
     * its caller; `internal` (module-scoped) for the same reason [clearChatState] is.
     */
    internal fun startConfirmedSessionFromContext(
        capture: ContextCapture,
        spec: PromptLaunchSpec,
        onCompleted: ((String, Throwable?) -> Unit)? = null,
    ) {
        val prompt = launchPrompt(spec)
        val uri = extractUriFromContext(capture)
        val baseTitle = spec.customPromptTitle ?: spec.actionName
        val title = if (uri.isNullOrBlank()) baseTitle else "$baseTitle: $uri"
        val session = createSession(title)
        // PRIV-03 / SC3 / Phase 15: audit the "Send anyway" allowlist decision once, here, so the
        // event carries the real session id (createSession resolved it above, G3 / RESEARCH Open Q1
        // Option b). Re-scan the same final payload — cheap, same bytes confirm() already scanned.
        // Only emit when the user actually clicked "Send anyway" on a matched payload (scan.matched).
        // Do NOT emit inside confirm() to avoid double-logging (PATTERNS.md "pick ONE home").
        val tripwireScan = SecretTripwire.scan(capture.contextJson)
        if (tripwireScan.matched) {
            AuditLogger.emitGlobal(
                "secret_tripwire_allow",
                SecretTripwire.buildAllowAuditPayload(tripwireScan, session.id),
            )
        }
        session.launchMetadata = spec.toMetadataMap()
        val panel = sessionPanels[session.id] ?: return
        // getOrPut, not `?:` — the discarded-fallback form used to build a state and throw it away.
        // Unreachable today because createSession populates the map first, but it would silently drop
        // D-10's approval set the moment that ordering changed, which is the latent shape this phase
        // exists to remove. Same form as the two call sites below.
        val state = sessionStates.getOrPut(session.id) { ToolSessionState() }
        val actionCard = buildActionCard(capture, spec.actionName, prompt, session.id, state)
        panel.addComponent(actionCard)
        panel.addMessage(
            role = "You",
            text = prompt,
        )
        session.messages.add(ChatMessage("user", prompt))
        sendMessage(
            sessionId = session.id,
            userText = prompt,
            contextJson = capture.contextJson,
            allowToolCalls = state.toolsMode,
            actionName = spec.actionName,
            onCompleted = onCompleted,
        )
    }

    private fun inputPanel(): JPanel {
        val panel = JPanel(BorderLayout())
        panel.background = UiTheme.Colors.surface
        panel.border =
            javax.swing.BorderFactory.createCompoundBorder(
                javax.swing.BorderFactory.createMatteBorder(1, 0, 0, 0, UiTheme.Colors.outlineVariant),
                EmptyBorder(6, 12, 10, 12),
            )

        inputArea.lineWrap = true
        inputArea.wrapStyleWord = true
        inputArea.font = UiTheme.Typography.body
        inputArea.background = UiTheme.Colors.inputBackground
        inputArea.foreground = UiTheme.Colors.inputForeground
        inputArea.margin = java.awt.Insets(8, 10, 8, 10)
        val inputMap = inputArea.getInputMap(JComponent.WHEN_FOCUSED)
        val actionMap = inputArea.actionMap
        // SEC-06 / SC4 headless guard — do not remove as dead code.
        // `Toolkit.getDefaultToolkit().menuShortcutKeyMaskEx` is the ONLY headless-hostile call in the
        // whole ChatPanel construction path: under `-Djava.awt.headless=true` it throws from
        // `sun.awt.HeadlessToolkit.getMenuShortcutKeyMaskEx`, which alone made the constructor
        // unreachable from a test. The SC4 acceptance gate in `ChatPanelToolGateTest` needs a REAL
        // ChatPanel headlessly so the model-emitted tool-call trust boundary can be asserted against
        // the real production path rather than a modelled stand-in.
        // The fallback is not degraded UX: `CTRL_DOWN_MASK` is the correct accelerator modifier on
        // Linux and Windows, and on macOS (the only platform where the Cmd mask differs) a real Burp
        // UI is never headless, so the fallback branch is unreachable there.
        val menuMask =
            if (java.awt.GraphicsEnvironment.isHeadless()) {
                InputEvent.CTRL_DOWN_MASK
            } else {
                try {
                    java.awt.Toolkit
                        .getDefaultToolkit()
                        .menuShortcutKeyMaskEx
                } catch (_: java.awt.HeadlessException) {
                    // Narrow by design (RESEARCH Pitfall 8): a broad runCatching would also swallow a
                    // genuine toolkit misconfiguration on a user's machine.
                    InputEvent.CTRL_DOWN_MASK
                }
            }
        inputMap.put(javax.swing.KeyStroke.getKeyStroke(KeyEvent.VK_ENTER, 0), "sendMessage")
        inputMap.put(javax.swing.KeyStroke.getKeyStroke(KeyEvent.VK_ENTER, KeyEvent.SHIFT_DOWN_MASK), "insert-break")
        inputMap.put(javax.swing.KeyStroke.getKeyStroke(KeyEvent.VK_T, menuMask), "openToolDialog")
        inputMap.put(javax.swing.KeyStroke.getKeyStroke(KeyEvent.VK_ESCAPE, 0), "cancelInFlight")
        actionMap.put(
            "sendMessage",
            object : javax.swing.AbstractAction() {
                override fun actionPerformed(e: java.awt.event.ActionEvent?) {
                    sendFromInput()
                }
            },
        )
        actionMap.put(
            "openToolDialog",
            object : javax.swing.AbstractAction() {
                override fun actionPerformed(e: java.awt.event.ActionEvent?) {
                    openToolDialog()
                }
            },
        )
        actionMap.put(
            "cancelInFlight",
            object : javax.swing.AbstractAction() {
                override fun actionPerformed(e: java.awt.event.ActionEvent?) {
                    cancelInFlightRequest()
                }
            },
        )
        inputArea.document.addDocumentListener(
            object : DocumentListener {
                override fun insertUpdate(e: DocumentEvent?) = syncDraftFromInput()

                override fun removeUpdate(e: DocumentEvent?) = syncDraftFromInput()

                override fun changedUpdate(e: DocumentEvent?) = syncDraftFromInput()
            },
        )

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
        // Teardown path 1 of 5 — the user answered the card by moving on. Resolved BEFORE anything
        // below can start a second turn: a pending card parks the chain, and letting the user's turn
        // run alongside a live continuation is what clobbers inFlightConnection. No followup is sent
        // because the message the user just typed IS the continuation.
        resolvePending(session.id, ImplicitDenyReason.NEW_MESSAGE)
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
            actionName = "Chat",
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
        traceId: String = "chat-turn-" + UUID.randomUUID().toString(),
    ) {
        val settings = getSettings()
        updatePrivacyPill()
        if (supervisor.requiresBurpAiAndDisabled(settings.preferredBackendId)) {
            showError("Burp AI is disabled in Burp Suite settings. Enable 'Use AI' for extensions, or pick a different backend.")
            return
        }
        if (!ensureBackendReady(settings)) return
        val error = validateBackend(settings)
        if (error != null) {
            showError(error)
            return
        }

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
        // Captured here, on the EDT: the completion settles into THIS transcript even if Clear Chat
        // replaces the session's transcript while the send is in flight.
        val wire = state.wire
        val wireTag = ChatWireTranscript.Tag(settings.privacyMode, backendId)
        if (contextJson != null) wire.offerContext(contextJson, wireTag)
        val wirePlan = wire.planTurn(wireTag)
        if (wirePlan.contextWithheld) {
            api.logging().logToOutput(
                "[ChatPanel] The captured context was not resent: the privacy mode or the backend changed since it was captured.",
            )
        }
        val toolContext = if (state.toolsMode) buildToolContext(settings, sessionId) else null
        val toolPreamble = if (state.toolsMode) buildToolPreamble(toolContext, wirePlan.includeCatalog) else null
        // The captured context is attached until a delivered send has carried it, and only while the
        // privacy guard allows it; from then on the history carries the turn that delivered it.
        val effectiveContextJson = wirePlan.contextJson
        // The typed form of this turn, which the guard falls back to. Follow-ups have no typed text, so
        // the guard omits them.
        val typedFallback =
            session
                ?.messages
                ?.lastOrNull()
                ?.takeIf { normalizeRole(it.role) == "user" && it.content == userText }
                ?.content
        val carriedCatalog = toolPreamble != null && wirePlan.includeCatalog
        // Extract agent instructions as system prompt for HTTP backends
        val agentBlock =
            com.six2dez.burp.aiagent.agents.AgentProfileLoader
                .buildInstructionBlock(actionName)
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
        val finalPrompt =
            listOfNotNull(
                toolPreamble?.takeIf { it.isNotBlank() },
                prompt.takeIf { it.isNotBlank() },
            ).joinToString("\n\n")
        val promptChars = finalPrompt.length
        if (promptChars > Defaults.LARGE_PROMPT_THRESHOLD) {
            api.logging().logToOutput(
                "[ChatPanel] Large prompt warning: $promptChars chars exceeds threshold (${Defaults.LARGE_PROMPT_THRESHOLD})",
            )
        }

        val responseBuffer = StringBuilder()
        val callbackConnectionRef = AtomicReference<AgentConnection?>(null)
        val connection =
            supervisor.sendChat(
                chatSessionId = sessionId,
                backendId = backendId,
                text = finalPrompt,
                history = wirePlan.history,
                contextJson = effectiveContextJson,
                privacyMode = settings.privacyMode,
                determinismMode = settings.determinismMode,
                traceId = traceId,
                systemPrompt = systemPrompt,
                maxOutputTokens = Defaults.CHAT_MAX_OUTPUT_TOKENS,
                launchMetadata = session?.launchMetadata,
                onChunk = { chunk ->
                    responseBuffer.append(chunk)
                    SwingUtilities.invokeLater { assistant.appendChunk(chunk) }
                },
                onComplete = { err ->
                    val callbackConnection = callbackConnectionRef.get()
                    val shouldSetIdle =
                        if (callbackConnection == null) {
                            inFlightConnection.current() == null
                        } else {
                            inFlightConnection.clearIfMatches(callbackConnection)
                        }
                    // Settled here, on the completion thread (the transcript is synchronized), before the
                    // panel goes idle or a tool-chain continuation is queued, so the next turn always
                    // plans from a settled transcript. A send whose connection the Cancel button already took
                    // is not delivered, even when its backend still answers: it is not part of the conversation.
                    val cancelled = callbackConnection != null && !shouldSetIdle
                    if (err == null && !cancelled) {
                        wire.recordDelivered(wirePlan, finalPrompt, typedFallback, responseBuffer.toString(), carriedCatalog)
                    } else {
                        wire.recordUndelivered(typedFallback)
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
                        outputTokensActual = usage?.outputTokens,
                    )
                    // CAP-04: evaluate token budget after each response and update banner / pause scanner.
                    // WR-01/WR-02: drive the scanner pause gate through the shared single-consultation
                    // point (PassiveAiScanner.reconcileBudget) so chat and scanner use the SAME
                    // evaluation and the pause is released (not latched) once usage drops below the cap.
                    SwingUtilities.invokeLater {
                        // WR-02: capture warn/cap from a SINGLE settings snapshot and feed the SAME
                        // instance to the decision, so the banner's thresholds match the gate input.
                        // `used` is a separate live read for display only; it can momentarily differ
                        // from the gate's own internal read (a benign cosmetic staleness window — the
                        // gate decision below is authoritative, not these displayed digits).
                        val s = getSettings()
                        val warn = s.tokenBudgetWarnThreshold
                        val cap = s.tokenBudgetHardCap
                        val used = BudgetGuard.currentSessionTokens()
                        // When no scanner is wired (tests / chat-only embedding), fall back to a local
                        // evaluation so the banner still reflects the budget.
                        val state =
                            passiveScanner?.reconcileBudget(s)
                                ?: BudgetGuard.evaluate(used, warn, cap)
                        when (state) {
                            BudgetGuard.State.CAP ->
                                budgetNotice.setMessage(
                                    SubtleNotice.Level.RISK,
                                    "Token budget reached (${formatChars(
                                        used,
                                    )}/${formatChars(cap.toLong())}). Passive scanning paused; chat is still available.",
                                )
                            BudgetGuard.State.WARN ->
                                budgetNotice.setMessage(
                                    SubtleNotice.Level.WARN,
                                    "Token budget warning: ${formatChars(used)} of ${formatChars(warn.toLong())} tokens used this session.",
                                )
                            BudgetGuard.State.OFF -> budgetNotice.hideNotice()
                        }
                    }
                    if (session != null) {
                        val tokIn =
                            usage?.inputTokens?.toLong()
                                ?: TokenTracker.estimateTokens(promptChars, backendId).toLong()
                        val tokOut =
                            usage?.outputTokens?.toLong()
                                ?: TokenTracker.estimateTokens(responseBuffer.length, backendId).toLong()
                        session.totalTokensIn += tokIn
                        session.totalTokensOut += tokOut
                    }
                    if (err != null) {
                        SwingUtilities.invokeLater { assistant.finish("\n[Error] ${err.message}") }
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
                        // REL-01: maybeExecuteToolCall reads sessionPanels/sessionsById and calls
                        // panel.addMessage — all EDT-confined map/Swing operations.  This callback
                        // runs on the backend executor thread (NOT the EDT), so marshal the
                        // map-touching + Swing-mutating body onto the EDT via invokeLater.
                        // onCompleted is invoked OFF the EDT (see below) — narrowest change that
                        // keeps chained tool-call continuations from stalling the UI thread.
                        //
                        // SEC-06 / D-06 adds a THIRD outcome and no new marshalling. AWAITING_DECISION
                        // parks onCompleted inside the pending record; it is invoked later from the
                        // approval card's ActionListener, which the AWT event pump dispatches on this
                        // same EDT by definition. So the thread choice documented just below is
                        // unchanged and the REL-05 work stays Phase 23's.
                        if (allowToolCalls && state.toolsMode && toolContext != null) {
                            SwingUtilities.invokeLater {
                                // Map reads and panel.addMessage now run on the EDT (confinement fix).
                                val outcome =
                                    maybeExecuteToolCall(
                                        sessionId = sessionId,
                                        userText = userText,
                                        responseText = finalResp,
                                        context = toolContext,
                                        remainingToolIterations = toolIterationsLeft,
                                        traceId = traceId,
                                        onCompleted = onCompleted,
                                    )
                                // sendMessage (called inside maybeExecuteToolCall when CHAINED)
                                // submits work to a backend executor — it does not block the EDT.
                                // When not chained, invoke onCompleted back on this EDT-scheduled
                                // block so the continuation thread choice is consistent. When
                                // AWAITING_DECISION, it is deliberately NOT invoked here — the parked
                                // copy is discharged by the resolution callback instead.
                                if (outcome == ToolCallOutcome.NOT_CHAINED) {
                                    // onCompleted does no Swing work itself; invoking it here on the
                                    // EDT is safe — it re-enters sendMessage which dispatches to a
                                    // backend executor internally and returns immediately.
                                    onCompleted?.invoke(finalResp, null)
                                }
                            }
                        } else {
                            // No tool-call attempt: invoke onCompleted off-EDT on this backend thread,
                            // matching the existing behaviour at the error branch above (:634).
                            onCompleted?.invoke(finalResp, null)
                        }
                    }
                },
            )
        callbackConnectionRef.set(connection)
        inFlightConnection.set(connection)
    }

    /**
     * Development-time EDT check for the `@GuardedBy("EDT")` session maps — **not** a production control.
     *
     * **Read this as a statement of what the check does NOT do.** It is the JVM's debug-time assertion
     * facility, which is disabled unless the JVM was started with `-ea`. `tasks.test` passes `-ea`; no
     * shipped Burp does. So in the extension a user actually runs, this compiles to nothing and has
     * no production effect at all: it can neither stop an off-EDT touch of a session map nor report
     * that one happened. It is a development-time aid, and QUAL-07 / SC4 exists because the wording
     * around it used to suggest otherwise.
     *
     * **What actually holds REL-01 is the callers.** Every entry point reachable off the EDT marshals
     * before it touches a guarded map — the unload path is the documented example, wrapping its whole
     * teardown block in `invokeAndWait` because Burp's unload handler runs on a Montoya thread. The
     * evidence that the discipline holds is `ChatPanelEdtConfinementTest`, not this function. If you
     * meet a violation, fix the CALLER by marshalling onto the EDT; do not expect this to have caught
     * it in the field.
     *
     * **Why it was not upgraded.** Plan 26-04 measured the alternative: converting this to a throwing
     * `check(...)`, the shape `McpToolExecutorImpl`'s production door guard already uses, breaks no
     * behavioural test in the suite — the existing tests all marshal correctly. The disposition
     * recorded in `26-04-SUMMARY.md` § `SC4 decision` (and ADR-17) was nonetheless to keep the
     * mechanism and state its limits honestly, so this KDoc is the deliverable rather than a
     * consolation for one. `ChatPanelEdtGuardTest` pins the wording so it cannot drift back into
     * reading as a guarantee.
     */
    private fun assertEdt() {
        assert(SwingUtilities.isEventDispatchThread()) {
            "session maps must be touched on the EDT only — off-EDT access is a data race (REL-01)"
        }
    }

    private fun sanitizeTitle(raw: String): String = raw.replace(Regex("[\\t\\n\\r\\u0000-\\u001F]"), " ").trim()

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

    private fun showSessionContextMenu(
        comp: java.awt.Component,
        x: Int,
        y: Int,
    ) {
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
        val newName =
            javax.swing.JOptionPane.showInputDialog(
                root,
                "Enter new session name:",
                session.title,
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
        val confirm =
            javax.swing.JOptionPane.showConfirmDialog(
                root,
                "Delete session '${session.title}'?",
                "Delete Session",
                javax.swing.JOptionPane.YES_NO_OPTION,
            )
        if (confirm == javax.swing.JOptionPane.YES_OPTION) {
            deleteConfirmedSession(session)
        }
    }

    /**
     * Everything a session deletion does once the user has confirmed it.
     *
     * **Split from [deleteSession] so this teardown is reachable without the modal.**
     * `JOptionPane.showConfirmDialog` builds a `JDialog`, which throws `HeadlessException` under
     * `-Djava.awt.headless=true`, so a headless test driving [deleteSession] never reaches a single
     * line below — including the supersede this function exists to guarantee. The modal is not
     * removed and nothing a user can observe changes; the split moves the boundary of what can be
     * ASSERTED, which for a teardown path nobody exercises by hand is the difference between a
     * guarded invariant and a hoped-for one.
     *
     * `internal` for the same reason [clearChatState] and [MAX_AUTO_TOOL_ITERATIONS] are: module
     * scoped, so it stays invisible to any consumer of the extension while the test source set can
     * reach it without reflection.
     *
     * **EDT-confined** like every other function here that touches the session maps, and deliberately
     * carrying no assertion of its own: SC5's evidence is that the private EDT assertion helper keeps
     * exactly the call sites it had, and a new one would move the number that IS the evidence. Its
     * only caller is [deleteSession], which is reached from a Swing action listener.
     */
    internal fun deleteConfirmedSession(session: ChatSession) {
        // Teardown path 2 of 5 — and the ONE exit that inherits nothing. The other three supersedes
        // (the Cancel button, a Burp project change and extension unload) all route through
        // cancelInFlightRequest(), which takes the running-tool token on their behalf. This path does
        // not call it and never has, so without the take() below a session delete leaves a tool worker
        // running that returns into a panel this function has already disposed: it would render its
        // result row into a detached transcript and send a followup turn continuing a chain whose
        // session no longer exists (D-08, research F-5). The line is redundant for three exits and
        // load-bearing for this one — do not delete it as duplication.
        //
        // Both it and the resolvePending() below sit ahead of the try, so the card and the state
        // behind it are still intact even if removeChatSession throws and the finally strips the maps
        // out from under them.
        //
        // Returning the panel to S0 is conditional on a worker actually having been superseded, and
        // that is not defensiveness: cancelInFlightRequest() does it for the other three exits and
        // this path does not call it, so without the clear the Send button stays hidden forever with
        // nothing running. Doing it UNCONDITIONALLY would clobber a backend turn still streaming in
        // another session. No Rule C-1 transcript line is written here for the same reason: the only
        // transcript that could carry it is the one being deleted, and putting it in an unrelated
        // session's would be a message about a run that session never made.
        if (runningTool.take() != null) setSendingState(false)
        resolvePending(session.id, ImplicitDenyReason.SESSION_DELETED)
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
                projectData().setString(sessionMsgKeyPrefix + session.id, "")
            } catch (_: Exception) {
            }
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

    /** Export current session as a Markdown file */
    fun exportCurrentChatAsMarkdown() {
        val session = sessionsList.selectedValue ?: return
        val md =
            buildString {
                appendLine("# ${session.title}")
                appendLine()
                appendLine("Backend: ${session.lastBackendId ?: "unknown"}")
                appendLine("Date: ${java.text.SimpleDateFormat("yyyy-MM-dd HH:mm").format(java.util.Date(session.createdAt))}")
                appendLine()
                appendLine("---")
                appendLine()
                for (msg in session.messages) {
                    val displayRole =
                        when (msg.role.lowercase()) {
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

    /**
     * Toggle UI between sending and idle states.
     *
     * UI-SPEC Rule S-1 — busy is global to the panel, never per session: one tool at a time, one door.
     * The `toolsBtn` write is the second half of that rule (CR-05). Without it the tool button stays
     * live through the whole of state S3, so a user can start a second tool call whose token overwrites
     * the first one's and destroys its result with no surface indication. The button is the affordance;
     * `openToolDialog`'s own entry guard is the control, because an affordance can be bypassed.
     *
     * The `toolsBtn` write reads the FIELD rather than the parameter, so that it is textually identical
     * to [updateChatAvailability]'s: the rule "the tool button is live iff MCP is up and the panel is
     * not busy" is then one fact stated one way at both of its sites, and a structural gate that pins
     * it finds both. That depends on `isSending = sending` staying the first statement below — keep it
     * there.
     */
    private fun setSendingState(sending: Boolean) {
        isSending = sending
        sendBtn.isVisible = !sending
        cancelBtn.isVisible = sending
        inputArea.isEnabled = !sending
        toolsBtn.isEnabled = mcpAvailable && !isSending
    }

    /**
     * Cancel the current in-flight AI request.
     *
     * REL-01: reads `sessionsList.selectedValue` / `sessionPanels` (both `@GuardedBy("EDT")`)
     * and mutates Swing (`setSendingState`, `panel.addMessage`), so it MUST run on the EDT.
     * Callers reachable off the EDT must marshal with `invokeAndWait` before calling it — the unload
     * path is the worked example, and it is the one that matters most, because Burp's unload handler
     * runs on a Montoya thread rather than the EDT.
     *
     * That marshalling is the whole of the guarantee. The check on the first line is a development-time
     * aid the JVM disables without `-ea`, so it catches nothing in a shipped Burp; see its KDoc.
     */
    fun cancelInFlightRequest(): Boolean {
        assertEdt()
        // TAKEN BEFORE THE CONNECTION, and the order is the whole of UI-SPEC Rule S-5. By the time a
        // tool is running the backend turn's connection has already been cleared by `clearIfMatches` in
        // the completion handler, so a busy panel in state S3 holds no connection at all — and an early
        // return on the connection alone would present a Cancel button that does nothing and says
        // nothing, which is the worst possible affordance on a security tool.
        val toolToken = runningTool.take() as? RunningToolToken
        val conn = inFlightConnection.take()
        if (toolToken == null && conn == null) return false
        // S0 immediately. The user does not wait for the worker: Montoya's sendRequest takes no
        // cancellation token, so the worker runs to completion and its return lands in S4 instead
        // (finishApprovedToolCall's supersede branch — the token it holds no longer matches).
        setSendingState(false)
        if (conn != null) {
            try {
                conn.stop()
            } catch (_: Exception) {
            }
        }
        val sessionId = sessionsList.selectedValue?.id ?: return true
        val panel = sessionPanels[sessionId] ?: return true
        // SELECTED BY WHAT WAS TAKEN, never by which button was pressed and never by which state the
        // panel believes it is in (UI-SPEC Rule C-1). A backend turn really was cancelled, so its
        // existing line stays byte-identical; a tool call was NOT cancelled, so it gets a sibling that
        // says so. Telling a penetration tester their request was cancelled when it was actually sent to
        // the target is the kind of wrong that ends up in someone's report.
        val line = if (conn != null) "Request cancelled." else toolCancelLine(requireNotNull(toolToken).tool)
        panel.addMessage("System", line)
        return true
    }

    /**
     * UI-SPEC Rule C-1's locked tool-cancel copy — three facts, in the order a tester needs them.
     *
     * **(1)** it happened anyway, **(2)** nothing was done with the answer, **(3)** you can still find
     * out what it was. Fact 3 is not decoration: it is the user-visible half of D-07's corollary that a
     * cancelled call must never become an unlogged one, and it tells the user where to look.
     *
     * One string serves every origin — a cancelled chain step and a cancelled `/tool` or dialog
     * invocation say the same true thing.
     */
    private fun toolCancelLine(tool: String): String = "Cancelled: $tool was already sent to Burp and will finish. Its result was discarded and no follow-up was sent to the AI. The call is in the audit log."

    fun openToolDialog() {
        // FIRST STATEMENT, above every side effect, and that placement is the whole of the control
        // (CR-05, UI-SPEC Rule S-1). Below the session lookup it would already have created a session;
        // below the dialog it would already have minted a token and overwritten the running one. The
        // disabled `toolsBtn` is the affordance; this is what makes the rule true for every caller.
        if (isSending) {
            showError("A request is already running. Cancel it first.")
            return
        }
        if (!mcpAvailable) {
            showError("MCP server is not running.")
            return
        }
        val session = sessionsList.selectedValue ?: createSession("Chat ${sessionsModel.size + 1}")
        val panel = sessionPanels[session.id] ?: return
        val state = sessionStates.getOrPut(session.id) { ToolSessionState() }
        val settings = getSettings()
        val context = buildToolContext(settings, session.id)
        val availableTools =
            McpToolCatalog
                .all()
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
        val commandPreview =
            if (args.isNullOrBlank()) {
                "/tool ${invocation.toolId} {}"
            } else {
                "/tool ${invocation.toolId} $args"
            }

        panel.addMessage("You", commandPreview)
        session.messages.add(ChatMessage("user", commandPreview))
        val wire = state.wire
        wire.recordPlain("user", commandPreview)

        // UI-SPEC Rule S-2, and it is not decoration: the call below no longer blocks the EDT, so
        // without entering the busy state the user could fire a tool and press Send on the same idle,
        // live panel a millisecond later. The supersede token is minted here, on the EDT, so a Cancel
        // pressed while the tool runs has something to take (Rule S-5).
        setSendingState(true)
        val token = RunningToolToken(invocation.toolId)
        runningTool.set(token)
        val sessionId = session.id
        OffEdtDispatch.run(
            threadName = "burp-ai-tool-exec",
            label = "chat-tool-dialog-" + UUID.randomUUID().toString(),
            logError = { message -> api.logging().logToError(message) },
            // SC5: user-originated. The user picked the tool and typed the args in ToolInvocationDialog, so
            // this call is deliberately UNGATED and consults no approval gate — double-prompting a decision
            // the user just made trains them to click through (T-22-32).
            work = { McpToolExecutor.executeTool(invocation.toolId, args, context, ToolCallOrigin.UserDialog) },
            onEdt = { result ->
                finishUserOriginatedToolCall(panel, sessionId, invocation.toolId, token, result) { text ->
                    val toolResult = "Tool result (${invocation.toolId}):\n$text"
                    sessionsById[sessionId]?.messages?.add(ChatMessage("assistant", toolResult))
                    // Reaches the model with the next turn, tagged with the snapshot the tool context was built from.
                    wire.recordToolResult(toolResult, ChatWireTranscript.Tag(settings.privacyMode, settings.preferredBackendId))
                    state.toolsMode = true
                    refreshSessionList()
                }
            },
        )
    }

    /**
     * The EDT tail shared by the two user-originated tool paths (REL-05).
     *
     * **EDT-confined**, for the same reason [finishApprovedToolCall] is: it calls `panel.addMessage` and
     * [setSendingState]. Like that tail it deliberately adds no EDT assertion of its own — SC5's evidence
     * is that the existing private assertion helper keeps exactly the call sites it had, and a new one
     * would move the number that IS the evidence.
     *
     * These two paths are UNGATED by SC5 and so carry no approval record, which is why — unlike the
     * approved-chain tail — there is no decision pair to emit here. The asymmetry is deliberate and it
     * is narrow: no `toolDecisionReporter.report(...)` call belongs in this function, because the user
     * picked the tool themselves and there is no decision to report. What they do share is the
     * supersede rule: a worker whose token no longer matches lands in UI-SPEC state S4 and renders
     * nothing, because whatever superseded it already returned the panel to S0 and may have started
     * something since.
     *
     * **The superseded branch still emits an activity record, and that closes WR-04.** It is the same
     * treatment [discardSupersededToolResult] gives a superseded chain step, with the same reach and
     * the same restraint — a record, no transcript row, no touch of the busy state. The review raises
     * WR-04 only because CR-05 makes this branch reachable and legible, so closing it is an inseparable
     * consequence of CR-05's fix rather than separate scope: the call reached Burp and cannot be
     * recalled, and suppressing the record would put a hole in the audit trail at exactly the point a
     * user interrupted something (D-07's load-bearing corollary). No `durationMs` rides along — the
     * user-originated paths measure none, and inventing one would be a fabricated field in an audit
     * record.
     *
     * A failure is surfaced through the same `Tool result:` row that a success uses, with the `Error:`
     * prefix the chain path already produces. Not through [showError]: the user asked for this answer in
     * the transcript, and a modal would put it somewhere the transcript never records.
     */
    private fun finishUserOriginatedToolCall(
        panel: SessionPanel,
        sessionId: String,
        toolId: String,
        token: Any,
        result: Result<String>,
        onSuccess: (String) -> Unit,
    ) {
        if (!runningTool.clearIfMatches(token)) {
            supervisor.aiRequestLogger?.log(
                type = ActivityType.MCP_TOOL_CALL,
                source = "chat",
                backendId = backendIdFor(sessionId),
                sessionId = sessionId,
                detail = "Tool $toolId finished after its run was superseded; result discarded",
                metadata =
                    mapOf(
                        "tool" to toolId,
                        "runStatus" to SUPERSEDED_RUN_STATUS,
                        "supersedeReason" to "result discarded before it was applied",
                    ),
            )
            return
        }
        setSendingState(false)
        val failure = result.exceptionOrNull()
        val text =
            if (failure == null) {
                result.getOrThrow()
            } else {
                "Error: ${failure.javaClass.simpleName}: ${failure.message.orEmpty()}"
            }
        panel.addMessage("Tool result: $toolId", text)
        if (failure == null) onSuccess(text)
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
                val canRun =
                    context.isToolEnabled(tool.id) &&
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
        if (sessionsList.selectedValue == null) return
        val confirm =
            javax.swing.JOptionPane.showConfirmDialog(
                root,
                "Are you sure you want to clear this chat history?",
                "Clear Chat",
                javax.swing.JOptionPane.YES_NO_OPTION,
            )
        if (confirm != javax.swing.JOptionPane.YES_OPTION) return

        clearChatState()
    }

    /**
     * Everything Clear Chat does once the user has clicked Yes.
     *
     * Split out from [clearCurrentChat] so the teardown is reachable without a modal. `JOptionPane`
     * builds a `JDialog`, which throws `HeadlessException` under `-Djava.awt.headless=true` — leaving
     * the confirmation inline would put the one path research found *permanently stuck* (T-22-10)
     * beyond the reach of any test. `internal` rather than `private` for the same reason
     * [MAX_AUTO_TOOL_ITERATIONS] is: module-scoped, so it stays invisible to any consumer of the
     * shipped JAR. The dialog is the user clicking Yes; this is what that click does.
     */
    internal fun clearChatState() {
        val selected = sessionsList.selectedValue ?: return
        val panel = sessionPanels[selected.id] ?: return
        // Teardown path 3 of 5, and the one that is silently broken without it. clearMessages() below
        // removes the card from the transcript while the pending record survives, so the decision
        // becomes unresolvable by any UI and the parked continuation never fires. Resolve first.
        resolvePending(selected.id, ImplicitDenyReason.CHAT_CLEARED)
        panel.clearMessages()
        supervisor.removeChatSession(selected.id)
        // Clear logical message history so the backend doesn't receive stale context
        selected.messages.clear()
        selected.messageCount = 0
        selected.totalCharsIn = 0
        selected.totalCharsOut = 0
        selected.totalTokensIn = 0
        selected.totalTokensOut = 0
        sessionDrafts[selected.id] = ""
        val state = sessionStates.getOrPut(selected.id) { ToolSessionState() }
        state.toolsMode = true
        // T-22-34 / ADR-15: the D-10 approve/deny memory goes with the history it was granted against.
        // Clear Chat is the user declaring a new task, which is D-10's own justification for asking
        // again — an approval given while reviewing target A must not run silently against target B.
        // A fresh holder drops both session sets and the repeat counter in one assignment.
        state.approvalMemory = ToolApprovalMemory()
        // A fresh transcript drops the turns as sent and any pending context in one assignment. A send in
        // flight right now settles into the transcript it captured, never into this one.
        state.wire = ChatWireTranscript()
        // Remove persisted messages for this session
        try {
            projectData().deleteString(sessionMsgKeyPrefix + selected.id)
        } catch (_: Exception) {
        }
    }

    private fun buildActionCard(
        capture: ContextCapture,
        actionName: String,
        promptText: String,
        sessionId: String,
        state: ToolSessionState,
    ): ActionCard {
        val source = extractSourceFromPreview(capture.previewText)
        val target = extractHostFromContext(capture) ?: "Unknown"
        val summary = privacySummary(getSettings().privacyMode)
        val payload = buildContextPayload(promptText, capture.contextJson, actionName)
        val toolContext = if (state.toolsMode) buildToolContext(getSettings(), sessionId) else null
        // The preview of a new session's first send, which carries the full catalog.
        val toolPreamble = if (state.toolsMode) buildToolPreamble(toolContext, includeCatalog = true) else null
        val finalPayload =
            if (!toolPreamble.isNullOrBlank()) {
                toolPreamble + "\n\n" + payload
            } else {
                payload
            }
        return ActionCard(
            actionName = actionName,
            source = "Source: $source",
            target = "Target: $target",
            privacySummary = summary,
            payloadPreview = finalPayload,
        )
    }

    private fun buildActionCard(
        capture: ContextCapture,
        actionName: String,
    ): ActionCard =
        buildActionCard(
            capture = capture,
            actionName = actionName,
            promptText = "Analyze the provided context.",
            sessionId = "preview",
            state = ToolSessionState(),
        )

    private fun buildContextPayload(
        userText: String,
        contextJson: String?,
        actionName: String?,
    ): String {
        val agentBlock = AgentProfileLoader.buildInstructionBlock(actionName)
        val base = buildContextPayloadNoAgent(userText, contextJson)
        return listOfNotNull(
            agentBlock?.takeIf { it.isNotBlank() },
            base.takeIf { it.isNotBlank() },
        ).joinToString("\n\n")
    }

    private fun buildContextPayloadNoAgent(
        userText: String,
        contextJson: String?,
    ): String =
        if (contextJson.isNullOrBlank()) {
            userText
        } else {
            buildString {
                appendLine(userText)
                appendLine()
                appendLine("Context (JSON):")
                append(contextJson)
            }
        }

    private fun extractSourceFromPreview(preview: String): String {
        val line = preview.lineSequence().firstOrNull { it.trim().startsWith("Kind:") }
        return line
            ?.substringAfter("Kind:")
            ?.trim()
            .orEmpty()
            .ifBlank { "Context" }
    }

    private fun extractHostFromContext(capture: ContextCapture): String? {
        return try {
            val root = Json.parseToJsonElement(capture.contextJson).jsonObject
            val items = root["items"]?.jsonArray ?: return null
            items
                .asSequence()
                .mapNotNull { item ->
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
            items
                .asSequence()
                .mapNotNull { item ->
                    val obj = item.jsonObject
                    val url = obj["url"]?.jsonPrimitive?.contentOrNull
                    val method = obj["method"]?.jsonPrimitive?.contentOrNull ?: "GET"

                    if (url != null) {
                        val uri = runCatching { URI(url) }.getOrNull()
                        if (uri != null) {
                            val path = uri.path?.takeIf { it.isNotBlank() } ?: "/"
                            val query = uri.query?.let { "?${it.take(30)}${if (it.length > 30) "..." else ""}" } ?: ""
                            val displayPath = if (path.length > 50) "...${path.takeLast(47)}" else path
                            "$method $displayPath$query"
                        } else {
                            "$method $url"
                        }
                    } else {
                        // Audit issue items: extract issue name + host
                        val name = obj["name"]?.jsonPrimitive?.contentOrNull
                        if (name != null) {
                            val host = obj["affectedHost"]?.jsonPrimitive?.contentOrNull
                            val displayName = if (name.length > 60) name.take(57) + "..." else name
                            if (!host.isNullOrBlank()) "$displayName @ $host" else displayName
                        } else {
                            null
                        }
                    }
                }.firstOrNull()
        } catch (e: Exception) {
            api.logging().logToOutput("[ChatPanel] Failed to extract URI from context: ${e.message}")
            null
        }
    }

    private fun privacySummary(mode: PrivacyMode): String =
        when (mode) {
            PrivacyMode.STRICT -> "Privacy: STRICT (cookies stripped, tokens redacted, hosts anonymized)"
            PrivacyMode.BALANCED -> "Privacy: BALANCED (cookies stripped, tokens redacted)"
            // D-07: OFF disables the built-in rules only. Custom patterns are the user's "never send
            // this, ever" list and apply in every mode (D-05), so the old wording was false. Conditioned
            // on whether any are configured so the label never claims patterns run when the user has none.
            PrivacyMode.OFF ->
                if (getSettings().customRedactionPatterns.isNotEmpty()) {
                    "Privacy: OFF (built-in redaction disabled; your custom patterns still apply)"
                } else {
                    "Privacy: OFF (built-in redaction disabled; no custom patterns configured)"
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
        // Switching sessions resolves NOTHING (D-08): the pending card survives in the transcript it
        // was raised in, and coming back is how the user answers it. All this does is put it back in
        // front of them, because the transcript returns exactly where they left it and the card may
        // be far above the fold. Adding a resolve here would be a sixth teardown path outside the one
        // entry point — the exact shape the lifecycle work exists to prevent.
        pendingDecisions[id]?.let { pending -> sessionPanels[id]?.scrollToComponent(pending.card) }
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
        // sessionDrafts is @GuardedBy("EDT") like every other session map, and this writes it — so it
        // owes the same check they do. It had none, which is why the SC4 harness could type into the
        // input area from the JUnit thread for a whole phase with `-ea` on and nothing firing (WR-10).
        //
        // A DocumentListener callback is dispatched on whatever thread mutated the Document, which in
        // production is always the EDT. Anything writing inputArea.text from elsewhere must marshal
        // with invokeAndWait first, because the listener would otherwise write sessionDrafts off-EDT.
        // The check below will not tell you when that happens: the JVM disables it without `-ea`, i.e.
        // in every shipped Burp, so it is a development-time aid only. See its KDoc.
        assertEdt()
        if (suppressDraftSync) return
        val id = activeSessionId ?: sessionsList.selectedValue?.id ?: return
        sessionDrafts[id] = inputArea.text
    }

    companion object {
        // `internal`, not `private`, so the module's test compilation can READ it. The one reason is
        // ChatPanelToolGateTest.eightConsecutiveDenialsTerminateTheChainWithNoNinthTurn, which derives
        // its expected turn count from this budget instead of hardcoding 8 — a stale literal silently
        // passing is the one thing that must not happen to the phase's acceptance gate. `internal` is
        // module-scoped, so it stays invisible to any consumer of the shipped JAR. Do not narrow it
        // back without reading that test first.
        internal const val MAX_AUTO_TOOL_ITERATIONS = 8

        /**
         * SC3 run status for a call whose result was discarded (UI-SPEC S4).
         *
         * A fourth value beside `ok` / `error` / `denied`, for the same reason D-12 gave `denied` its
         * own: a cancelled run is neither a malfunction nor a policy refusal, and filing it as either
         * makes the audit log unable to tell the three apart.
         */
        internal const val SUPERSEDED_RUN_STATUS = "cancelled"

        fun formatSessionDate(epochMs: Long): String {
            val now = java.util.Calendar.getInstance()
            val then =
                java.util.Calendar
                    .getInstance()
                    .apply { timeInMillis = epochMs }
            val sameDay =
                now.get(java.util.Calendar.YEAR) == then.get(java.util.Calendar.YEAR) &&
                    now.get(java.util.Calendar.DAY_OF_YEAR) == then.get(java.util.Calendar.DAY_OF_YEAR)
            if (sameDay) return "Today"
            now.add(java.util.Calendar.DAY_OF_YEAR, -1)
            val yesterday =
                now.get(java.util.Calendar.YEAR) == then.get(java.util.Calendar.YEAR) &&
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
                g.color =
                    when {
                        ratio < 0.4f -> Color(76, 175, 80) // green
                        ratio < 0.7f -> Color(255, 193, 7) // yellow
                        else -> Color(255, 152, 0) // orange
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
            usageStatsLine1.text =
                "${stats.totalMessages} msgs | In: ${formatChars(stats.totalCharsIn)} | Out: ${formatChars(stats.totalCharsOut)}"
            usageStatsLine2.text =
                stats.perBackend.entries
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

    private fun formatChars(chars: Long): String =
        when {
            chars >= 1_000_000 -> String.format(java.util.Locale.ROOT, "%.1fM", chars / 1_000_000.0)
            chars >= 1_000 -> String.format(java.util.Locale.ROOT, "%.1fK", chars / 1_000.0)
            else -> "$chars"
        }

    private fun normalizeRole(role: String): String =
        when (role.lowercase()) {
            "you", "user" -> "user"
            "ai", "assistant" -> "assistant"
            "system" -> "system"
            else -> role
        }

    // ── Persistence: save/restore chat sessions via Burp preferences ──

    private val sessionsKey = "chat.sessions"
    private val sessionMsgKeyPrefix = "chat.messages."
    private val sessionDraftsKey = "chat.drafts"
    private val migratedKey = "chat.migrated_to_project"

    /** Project-scoped storage: extensionData() is saved inside the .burp project file. */
    private fun projectData(): burp.api.montoya.persistence.PersistedObject = api.persistence().extensionData()

    fun shutdown() {
        // REL-01: shutdown() is wired to Burp's unload handler, which runs on a Montoya/Burp
        // thread, NOT the EDT. cancelInFlightRequest() + stopAllTimers() touch @GuardedBy("EDT")
        // maps and Swing, so marshal onto the EDT. Use invokeAndWait so unload is synchronous
        // (Burp may tear down the classloader right after), guarded against EDT re-entrancy.
        val work = {
            // Teardown path 5 of 5. Inside the marshalled block because pendingDecisions is
            // @GuardedBy("EDT") like every other session map here. No backend turn is started from
            // this path: dispatching a request while Burp tears down the extension classloader is how
            // a safety control turns into an unload hang (T-22-33).
            //
            // A RUNNING tool worker is superseded through the in-flight cancel below, which takes the
            // running-tool token — this path needs no second take() of its own (D-08). And it
            // deliberately does not WAIT for that worker: a bounded join here would put the same
            // ten-second blocking wait back on the EDT that plan 23-03 removed from the Settings save
            // path. What makes that safe is the daemon flag OffEdtDispatch sets explicitly — a daemon
            // thread never holds JVM exit open — plus the supersede, which is what stops the worker's
            // tail writing into a panel whose classloader is being torn down.
            resolveAllPending(ImplicitDenyReason.UNLOAD)
            cancelInFlightRequest()
            sessionPanels.values.forEach { it.stopAllTimers() }
        }
        if (SwingUtilities.isEventDispatchThread()) {
            work()
        } else {
            try {
                SwingUtilities.invokeAndWait(work)
            } catch (_: InterruptedException) {
                Thread.currentThread().interrupt()
            } catch (_: java.lang.reflect.InvocationTargetException) {
                // Swallow: shutdown must not throw out of the unload handler.
            }
        }
    }

    /**
     * Clear all in-memory session state without touching persisted storage.
     * Called when the Burp project changes so stale sessions don't bleed across projects.
     */
    fun clearInMemorySessionState() {
        // Teardown path 4 of 5, reached from MainTab.onProjectChanged(). The same dangling
        // continuation as a session delete, but across every session at once — and D-08 does not list
        // it either. Resolved first, while the cards and the states behind them still exist.
        //
        // A RUNNING tool worker is superseded through the in-flight cancel below, which takes the
        // running-tool token and returns the panel to S0 on this path's behalf; no second take() is
        // needed here (D-08). That supersede is what stops a worker started under the OLD Burp
        // project writing its result into the new one after every map below has been cleared.
        //
        // The symbol is described rather than named on purpose: an occurrence count over this file is
        // SC5's evidence, and prose that moves it makes the evidence a measurement of comments.
        resolveAllPending(ImplicitDenyReason.PROJECT_CHANGED)
        cancelInFlightRequest()
        sessionPanels.values.forEach { it.stopAllTimers() }
        sessionsById.clear()
        sessionPanels.clear()
        sessionStates.clear()
        sessionDrafts.clear()
        sessionsModel.clear()
    }

    fun saveSessions() {
        try {
            persistActiveSessionDraft()
            val prefs = projectData()
            val sessionList =
                sessionsById.values.map { s ->
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
            prefs.setString(sessionsKey, sessionList.joinToString("\n"))

            // Save messages for each session
            for (s in sessionsById.values) {
                val msgData =
                    s.messages.joinToString("\u001F") { msg ->
                        "${msg.role}\u001E${msg.content.replace("\n", "\u001D")}"
                    }
                prefs.setString(sessionMsgKeyPrefix + s.id, msgData)
            }
            val draftsData =
                sessionsById.keys.map { id ->
                    val draft = sessionDrafts[id].orEmpty().replace("\n", "\u001D")
                    "$id\u001E$draft"
                }
            prefs.setString(sessionDraftsKey, draftsData.joinToString("\n"))

            api.logging().logToOutput("[ChatPanel] Saved ${sessionsById.size} sessions with messages.")
        } catch (e: Exception) {
            api.logging().logToError("[ChatPanel] Failed to save sessions: ${e.message}")
        }
    }

    fun restoreSessions() {
        try {
            val prefs = projectData()
            maybeMigrateGlobalToProject(prefs)
            val raw = prefs.getString(sessionsKey) ?: return
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
                val msgRaw = prefs.getString(sessionMsgKeyPrefix + id)
                if (!msgRaw.isNullOrBlank()) {
                    for (msgEntry in msgRaw.split("\u001F")) {
                        val msgParts = msgEntry.split("\u001E", limit = 2)
                        if (msgParts.size == 2) {
                            val role = msgParts[0]
                            var text = msgParts[1].replace("\u001D", "\n")
                            // Clean up noise from old persisted messages
                            text =
                                text
                                    .lines()
                                    .filterNot { it.lowercase().startsWith("hook registry initialized") }
                                    .joinToString("\n")
                                    .trim()
                            if (text.isNotBlank()) {
                                messages.add(ChatMessage(role, text))
                            }
                        }
                    }
                }

                val session =
                    ChatSession(
                        id = id,
                        title = title,
                        createdAt = createdAt,
                        lastBackendId = backendsUsed.keys.firstOrNull(),
                        backendsUsed = backendsUsed,
                        messageCount = messageCount,
                        totalCharsIn = totalCharsIn,
                        totalCharsOut = totalCharsOut,
                        messages = messages,
                    )

                sessionsModel.addElement(session)
                sessionsById[id] = session
                sessionDrafts[id] = ""
                val panel = SessionPanel()
                sessionPanels[id] = panel
                // A restored session has no wire payload: its history is its display text, and its
                // original context is never resent.
                val restoredState = ToolSessionState()
                for (msg in messages) {
                    restoredState.wire.recordPlain(normalizeRole(msg.role), msg.content)
                }
                sessionStates[id] = restoredState
                chatCards.add(panel.root, id)

                // Display restored messages
                for (msg in messages) {
                    panel.addMessage(msg.role, msg.content)
                }
            }

            val draftsRaw = prefs.getString(sessionDraftsKey).orEmpty()
            if (draftsRaw.isNotBlank()) {
                draftsRaw
                    .split('\n')
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

    private fun maybeMigrateGlobalToProject(projectStore: burp.api.montoya.persistence.PersistedObject) {
        try {
            val already = projectStore.getBoolean(migratedKey) ?: false
            if (already) return

            val globalPrefs = api.persistence().preferences()
            val raw = globalPrefs.getString(sessionsKey).orEmpty()
            if (raw.isNotBlank()) {
                projectStore.setString(sessionsKey, raw)
                val lines = raw.split('\n').filter { it.isNotBlank() }
                for (line in lines) {
                    val parts = line.split('\t')
                    if (parts.isEmpty()) continue
                    val id = parts[0]
                    if (id.isBlank()) continue
                    val msgRaw = globalPrefs.getString(sessionMsgKeyPrefix + id)
                    if (!msgRaw.isNullOrBlank()) {
                        projectStore.setString(sessionMsgKeyPrefix + id, msgRaw)
                    }
                }

                val draftsRaw = globalPrefs.getString(sessionDraftsKey)
                if (!draftsRaw.isNullOrBlank()) {
                    projectStore.setString(sessionDraftsKey, draftsRaw)
                }

                // Clear global after migration
                globalPrefs.setString(sessionsKey, "")
                globalPrefs.setString(sessionDraftsKey, "")
                for (line in lines) {
                    val parts = line.split('\t')
                    if (parts.isEmpty()) continue
                    val id = parts[0]
                    if (id.isNotBlank()) {
                        globalPrefs.setString(sessionMsgKeyPrefix + id, "")
                    }
                }
            }

            projectStore.setBoolean(migratedKey, true)
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
        val perBackend: Map<String, Int>,
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
        /**
         * Metadata describing how this chat session was launched (prompt source, prompt id,
         * context kind). Forwarded to AgentSupervisor.sendChat so it lands in
         * AuditLogger prompt bundles and AiRequestLogger entries. Null for plain chat.
         */
        var launchMetadata: Map<String, String>? = null,
    ) {
        override fun toString(): String = title
    }

    /**
     * What `maybeExecuteToolCall` did, in the three states the continuation has to tell apart (D-06).
     *
     * The old `Boolean` could only say "another turn was sent" or "invoke onCompleted now". A decision
     * card needs a third answer: neither happened *yet*, and the continuation is parked.
     */
    private enum class ToolCallOutcome {
        /** No tool call, or it failed outright. The caller invokes `onCompleted` itself. */
        NOT_CHAINED,

        /** A followup turn was sent and carries `onCompleted` with it. */
        CHAINED,

        /** A card is on screen; `onCompleted` is parked in [PendingToolDecision] until the user clicks. */
        AWAITING_DECISION,

        /**
         * A worker holds `onCompleted`; it is discharged from that worker's `invokeLater` tail
         * ([finishApprovedToolCall]) — never by the caller, which has already returned (REL-05).
         */
        EXECUTING,
    }

    /**
     * Everything the resolution callback needs to finish a tool call the user has not decided on yet.
     *
     * [onCompleted] is the parked continuation. Every path out of the callback either invokes it or
     * hands it into `sendMessage`, so the "Send to AI" launch path can never be left hanging (T-22-31).
     */
    private data class PendingToolDecision(
        val sessionId: String,
        val userText: String,
        val call: ParsedToolCall,
        val context: McpToolContext,
        val remainingToolIterations: Int,
        val traceId: String,
        val onCompleted: ((String, Throwable?) -> Unit)?,
        val card: ToolApprovalCard,
    )

    private data class ToolSessionState(
        var toolsMode: Boolean = true,
        // The session's wire transcript: the turns as they were sent. In memory only, never persisted;
        // replaced whole by Clear Chat, like approvalMemory below.
        var wire: ChatWireTranscript = ChatWireTranscript(),
        // D-10: the SEC-06 approve/deny memory is keyed on the CHAT session and dies with it — no new
        // lifecycle, no persistence. An approval granted while reviewing target A must not silently
        // apply when the user opens a new chat about target B (T-22-20).
        //
        // `var` for exactly one reason: Clear Chat replaces the whole holder (see clearChatState). A
        // fresh instance drops both session sets AND the repeat counter in one assignment, which is
        // atomic and needs no reset method on ToolApprovalMemory — the memory keeps its narrow
        // accessors, so no caller can splice a single entry in or out.
        var approvalMemory: ToolApprovalMemory = ToolApprovalMemory(),
    )

    /**
     * @param hasPendingDecision whether that session is waiting on a SEC-06 approval. Injected as a
     *   predicate rather than making this an inner class: the renderer runs on every repaint of every
     *   row and has no business reaching into the panel's session maps for anything else.
     */
    private class ChatSessionRenderer(
        private val hasPendingDecision: (String) -> Boolean,
    ) : javax.swing.DefaultListCellRenderer() {
        override fun getListCellRendererComponent(
            list: JList<*>,
            value: Any?,
            index: Int,
            isSelected: Boolean,
            cellHasFocus: Boolean,
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
            if (hasPendingDecision(value.id)) {
                // T-22-35: without this, a pending decision in a background session is invisible and
                // the chain is parked forever — the user concludes the model gave up. Text first,
                // colour redundant, so someone with no colour perception still reads the words.
                val pendingLabel = JLabel("Awaiting approval")
                // Matches backendLabel's derivation, NOT a DesignTokens typography role. This label is
                // stacked directly beneath it in the same narrow column, and the caption role is
                // baseSize * 0.9f — 11.7 pt against the sibling's 11 pt. Two small sizes differing by
                // 0.7 pt in one column read as a rendering defect rather than as a hierarchy. Matching
                // a sibling inside pre-existing renderer code adds no derivation to DesignTokens.
                pendingLabel.font = label.font.deriveFont((label.font.size - 2).toFloat())
                pendingLabel.foreground = if (isSelected) list.selectionForeground else DesignTokens.Colors.statusWarning
                pendingLabel.isOpaque = false
                textPanel.add(pendingLabel)
            }
            panel.add(textPanel, BorderLayout.CENTER)
            return panel
        }
    }

    private inner class SessionPanel {
        val root: JComponent = JPanel(BorderLayout())
        private val messages = JPanel()
        private val scroll = JScrollPane(messages)
        private val messagePanels = mutableListOf<ChatMessagePanel>()

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

        fun addMessage(
            role: String,
            text: String,
        ) {
            val message = ChatMessagePanel(role, text)
            messagePanels.add(message)
            messages.add(message.root)
            messages.add(javax.swing.Box.createRigidArea(Dimension(0, 4)))
            refreshScroll()
        }

        fun addComponent(component: JComponent) {
            // Wrap in a panel that prevents vertical stretching
            val wrapper =
                object : JPanel(BorderLayout()) {
                    override fun getMaximumSize(): Dimension = Dimension(super.getMaximumSize().width, preferredSize.height)
                }
            wrapper.isOpaque = false
            wrapper.add(component, BorderLayout.CENTER)
            messages.add(wrapper)
            messages.add(javax.swing.Box.createRigidArea(Dimension(0, 4)))
            refreshScroll()
        }

        fun addStreamingMessage(role: String): StreamingMessage {
            val message = ChatMessagePanel(role, "")
            messagePanels.add(message)
            messages.add(message.root)
            messages.add(javax.swing.Box.createRigidArea(Dimension(0, 4)))
            refreshScroll()
            return StreamingMessage(message)
        }

        fun clearMessages() {
            messagePanels.forEach { it.stopTimers() }
            messagePanels.clear()
            messages.removeAll()
            messages.revalidate()
            messages.repaint()
        }

        fun stopAllTimers() {
            messagePanels.forEach { it.stopTimers() }
        }

        private fun refreshScroll() {
            messages.revalidate()
            SwingUtilities.invokeLater {
                val scrollBar = scroll.verticalScrollBar
                scrollBar.value = scrollBar.maximum
            }
        }

        /**
         * Brings [component] into view, mirroring [refreshScroll]'s idiom.
         *
         * Revalidate first, then scroll inside `invokeLater`, so the scroll runs after layout has
         * given the component a size — asking to reveal a rectangle of height 0 reveals nothing.
         * Used when returning to a session whose pending approval card is scrolled out of sight;
         * `switchToSession` only swaps the `CardLayout` card, so the transcript comes back exactly
         * where the user left it. Deliberately moves no focus, the same rule the card itself follows.
         */
        fun scrollToComponent(component: JComponent) {
            messages.revalidate()
            SwingUtilities.invokeLater {
                component.scrollRectToVisible(Rectangle(0, 0, component.width, component.height))
            }
        }
    }

    private class StreamingMessage(
        private val message: ChatMessagePanel,
    ) {
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

        fun finish(text: String) {
            if (firstChunk) {
                message.hideSpinner()
                firstChunk = false
            }
            message.append(text)
        }
    }

    private class ChatMessagePanel(
        private val role: String,
        initialText: String,
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
        private val spinnerFrames =
            listOf("\u280B", "\u2819", "\u2839", "\u2838", "\u283C", "\u2834", "\u2826", "\u2827", "\u2807", "\u280F")
        private var spinnerIndex = 0
        private val pendingText = StringBuilder()
        private var coalescingTimer: javax.swing.Timer? = null
        private var copyResetTimer: javax.swing.Timer? = null
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
        private val editorPane =
            object : javax.swing.JEditorPane() {
                override fun getPreferredSize(): java.awt.Dimension {
                    val vpW = viewportWidth()
                    val w: Int =
                        if (isUser) {
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
        val root: JComponent =
            object : JPanel(BorderLayout()) {
                init {
                    isOpaque = false
                }

                override fun getMaximumSize(): Dimension = Dimension(super.getMaximumSize().width, preferredSize.height)
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
                val clipboard =
                    java.awt.Toolkit
                        .getDefaultToolkit()
                        .systemClipboard
                clipboard.setContents(java.awt.datatransfer.StringSelection(rawText.toString()), null)
                copyBtn.text = "Copied!"
                copyResetTimer?.stop()
                copyResetTimer =
                    javax.swing.Timer(1500) { copyBtn.text = "Copy" }.also {
                        it.isRepeats = false
                        it.start()
                    }
            }
            header.add(copyBtn, BorderLayout.EAST)

            // ── EditorPane setup ──
            editorPane.contentType = "text/html"
            editorPane.isEditable = false
            editorPane.putClientProperty(javax.swing.JEditorPane.HONOR_DISPLAY_PROPERTIES, true)
            editorPane.font = UiTheme.Typography.chatBody
            editorPane.border = EmptyBorder(0, 0, 0, 0)
            editorPane.isVisible = !showSpinner
            // Quick 261009-do9: links open only through ChatLinkPolicy (http/https) after a confirmation that shows the URL.
            editorPane.addHyperlinkListener(ChatLinkOpener())

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
                val hoverListener =
                    object : java.awt.event.MouseAdapter() {
                        override fun mouseEntered(e: java.awt.event.MouseEvent?) {
                            copyBtn.isVisible = true
                        }

                        override fun mouseExited(e: java.awt.event.MouseEvent?) {
                            val pt = e?.point ?: return
                            val src = e.component ?: return
                            val bp = javax.swing.SwingUtilities.convertPoint(src, pt, hoverTarget)
                            if (!java.awt.Rectangle(0, 0, hoverTarget.width, hoverTarget.height).contains(bp)) copyBtn.isVisible = false
                        }
                    }
                bubble.addMouseListener(hoverListener)
                header.addMouseListener(hoverListener)
                editorPane.addMouseListener(hoverListener)
                copyBtn.addMouseListener(hoverListener)
            } else {
                // AI / System message: left-aligned bubble (like ChatGPT)
                val bubble = JPanel(BorderLayout())
                bubble.isOpaque = true
                bubble.background = UiTheme.Colors.aiBubble
                bubble.border =
                    javax.swing.BorderFactory.createCompoundBorder(
                        javax.swing.BorderFactory.createLineBorder(UiTheme.Colors.outline, 1),
                        EmptyBorder(8, 14, 8, 14),
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
                val hoverListener =
                    object : java.awt.event.MouseAdapter() {
                        override fun mouseEntered(e: java.awt.event.MouseEvent?) {
                            copyBtn.isVisible = true
                        }

                        override fun mouseExited(e: java.awt.event.MouseEvent?) {
                            val pt = e?.point ?: return
                            val src = e.component ?: return
                            val bp = javax.swing.SwingUtilities.convertPoint(src, pt, hoverTarget)
                            if (!java.awt.Rectangle(0, 0, hoverTarget.width, hoverTarget.height).contains(bp)) copyBtn.isVisible = false
                        }
                    }
                bubble.addMouseListener(hoverListener)
                header.addMouseListener(hoverListener)
                editorPane.addMouseListener(hoverListener)
                copyBtn.addMouseListener(hoverListener)
            }

            updateHtml()

            // Re-layout on resize so editorPane recalculates width
            root.addComponentListener(
                object : java.awt.event.ComponentAdapter() {
                    override fun componentResized(e: java.awt.event.ComponentEvent?) {
                        SwingUtilities.invokeLater {
                            editorPane.revalidate()
                            root.revalidate()
                        }
                    }
                },
            )

            if (showSpinner) {
                spinnerTimer =
                    javax.swing.Timer(100) {
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

        fun stopTimers() {
            spinnerTimer?.stop()
            spinnerTimer = null
            coalescingTimer?.stop()
            coalescingTimer = null
            copyResetTimer?.stop()
            copyResetTimer = null
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
                    val escaped =
                        rawText
                            .toString()
                            .replace("&", "&amp;")
                            .replace("<", "&lt;")
                            .replace(">", "&gt;")
                            .replace("\n", "<br>")
                    val isDark = UiTheme.isDarkTheme
                    val fontSize = (UiTheme.Typography.chatBody.size - 2).coerceAtLeast(10)
                    val textColor = if (isDark) "#e0e0e0" else "#202020"
                    editorPane.text =
                        "<html><body style='font-family:SansSerif;color:$textColor;font-size:${fontSize}px;margin:0;padding:0;line-height:1.4;'>$escaped</body></html>"
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
        settings: AgentSettings,
    ): Boolean {
        val trimmed = text.trim()
        if (trimmed == "/tools") {
            val context = buildToolContext(settings, sessionId)
            val list = McpToolExecutor.describeTools(context, includeSchemas = true)
            panel.addMessage("Tools", list)
            state.toolsMode = true
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
            // UI-SPEC Rule S-4 — echo BEFORE going async. `sendFromInput` clears the input area and
            // returns without echoing anything on this branch, so up to now the typed command survived on
            // screen only because the EDT was frozen for the duration of the call. Asynchronously the
            // transcript would stay blank until the result row appeared: an answer with no visible
            // question, in a tool whose users have to be able to say what they just ran. The model sees
            // it too (FLAG-23-03), which removes an asymmetry with the dialog path rather than keeping it.
            panel.addMessage("You", trimmed)
            sessionsById[sessionId]?.messages?.add(ChatMessage("user", trimmed))
            state.wire.recordPlain("user", trimmed)
            // Rule S-2: the panel is busy for as long as the worker runs, and Cancel has a token to take.
            setSendingState(true)
            val token = RunningToolToken(toolName)
            runningTool.set(token)
            OffEdtDispatch.run(
                threadName = "burp-ai-tool-exec",
                label = "chat-tool-slash-" + UUID.randomUUID().toString(),
                logError = { message -> api.logging().logToError(message) },
                // SC5: user-originated. The user typed `/tool <name> <json>` themselves, so this call is
                // deliberately UNGATED and consults no approval gate (T-22-32).
                work = { McpToolExecutor.executeTool(toolName, argsJson, context, ToolCallOrigin.UserSlashCommand) },
                onEdt = { result ->
                    finishUserOriginatedToolCall(panel, sessionId, toolName, token, result) {
                        state.toolsMode = true
                    }
                },
            )
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
        onCompleted: ((String, Throwable?) -> Unit)?,
    ): ToolCallOutcome {
        // REL-01: this function reads EDT-confined maps and calls panel.addMessage (Swing), so every
        // caller must ALREADY be on the EDT; one that is not must marshal with invokeAndWait first.
        // The assertEdt() below does not make that true — the JVM disables it without -ea, i.e. in
        // every shipped Burp — so treat it as a development-time aid and read its KDoc before
        // relying on it.
        assertEdt()
        val call = if (remainingToolIterations > 0) ToolCallParser.extractFirst(responseText) else null
        val panel = sessionPanels[sessionId]
        if (call == null || panel == null) return ToolCallOutcome.NOT_CHAINED
        val state = sessionStates.getOrPut(sessionId) { ToolSessionState() }
        // SEC-06 / T-22-01 — THE trust boundary this whole phase exists to install. Model context is
        // attacker-influenceable (proxy traffic sent via "Send to AI", passive-scan findings, external
        // MCP tool results), so tool *selection* is attacker-influenceable too. The gate is consulted
        // BEFORE anything here touches McpToolExecutor, and there is no path from this function to Burp
        // that goes around it.
        return when (val outcome = ToolApprovalGate.evaluate(call.tool, state.approvalMemory)) {
            is ToolApprovalOutcome.Run -> {
                addSuppressedDecisionRow(panel, call, outcome.decision)
                executeApprovedToolCall(
                    sessionId = sessionId,
                    userText = userText,
                    call = call,
                    panel = panel,
                    context = context,
                    remainingToolIterations = remainingToolIterations,
                    traceId = traceId,
                    onCompleted = onCompleted,
                    approved = outcome,
                )
            }
            is ToolApprovalOutcome.Ask ->
                askForToolApproval(
                    sessionId = sessionId,
                    userText = userText,
                    call = call,
                    panel = panel,
                    context = context,
                    remainingToolIterations = remainingToolIterations,
                    traceId = traceId,
                    onCompleted = onCompleted,
                    ask = outcome,
                )
            is ToolApprovalOutcome.Denied -> {
                addSuppressedDecisionRow(panel, call, outcome.decision)
                denyToolCall(
                    sessionId = sessionId,
                    userText = userText,
                    call = call,
                    panel = panel,
                    context = context,
                    remainingToolIterations = remainingToolIterations,
                    traceId = traceId,
                    onCompleted = onCompleted,
                    denied = outcome,
                )
            }
        }
    }

    /**
     * Leaves a receipt when the gate applied an EARLIER click to this call without asking anyone.
     *
     * FLAG-22-03 shipped both compact variants, so neither kind of suppressed decision is invisible: a
     * session-approved call that ran against the target with nobody asked leaves a record, and a
     * session-denied call shows why the chain did not stall. [ToolDecision.AUTO] renders nothing —
     * D-02 says an `AUTO` call has no decision to report.
     */
    private fun addSuppressedDecisionRow(
        panel: SessionPanel,
        call: ParsedToolCall,
        decision: ToolDecision,
    ) {
        if (decision != ToolDecision.SESSION_APPROVED && decision != ToolDecision.SESSION_DENIED) return
        val canonicalId = McpToolExecutor.canonicalToolId(call.tool)
        panel.addComponent(
            ToolApprovalCard.compact(
                decision = decision,
                catalogTitle = catalogTitleFor(canonicalId),
                modelSuppliedToolId = call.tool,
                modelSuppliedArgsJson = call.argsJson,
            ),
        )
    }

    /** `null` means the model named a tool with no catalog entry; the card renders its unknown-tool line. */
    private fun catalogTitleFor(canonicalId: String): String? = McpToolCatalog.all().firstOrNull { it.id == canonicalId }?.title

    /**
     * Whether the canonical ID names something this extension recognises — SC3's `knownTool`.
     *
     * The reporter deliberately holds no catalog dependency, so this is the caller's to compute: a
     * catalog entry, or an `ext:` name a CONFIGURED external server actually exposes. Answering it
     * differently here from the way the tier was resolved is how an audit record ends up hashing the
     * name of a tool that ran perfectly well — so it is one function, called from every reporting
     * branch, not a repeated expression.
     *
     * **The membership half of that sentence is now checked, and it did not use to be.** This returned
     * `true` for any string starting with `ext:`, which is what the KDoc already claimed it did not do.
     * The consequence landed in the durable payload rather than in the gate: a name no server exposes
     * was filed as recognised, so `toolName` took the model's own string and `toolNameSha256` was
     * omitted entirely — bypassing the whole-name digest for precisely the class of names that had
     * nothing else identifying them, while the executor rejected the call with "External MCP client not
     * available" (WR-04 / UF-1). `ExternalMcpClientManager.availableTools()` is the same source
     * `McpToolExecutor.describeTools` advertises from, so consulting it is what makes the two agree.
     *
     * Measured, and stated so it is not rediscovered as a surprise: nothing in the main source set
     * currently builds an [McpToolContext] carrying an `externalClientManager`, so today every `ext:`
     * name resolves to `false` here — which is also the only accurate answer, because with no manager
     * the executor cannot run one. Taking the context rather than assuming its contents is what moves
     * this function for free on the day one is wired in.
     */
    private fun isKnownTool(
        canonicalId: String,
        context: McpToolContext,
    ): Boolean =
        McpToolCatalog.all().any { it.id == canonicalId } ||
            context.externalClientManager
                ?.availableTools()
                .orEmpty()
                .any { it.name == canonicalId }

    /**
     * The backend an activity-log entry for this session is attributed to.
     *
     * Derived once, for the same reason [chainStepFor] is: three reporting branches need it, and a
     * branch that fell back to the preferred backend where its sibling used the session's last one
     * would attribute the same chain to two different backends. Extracted when
     * [reportFailedToolCall] stopped taking it as a parameter — it was the tenth, and detekt's
     * LongParameterList ceiling is nine.
     */
    private fun backendIdFor(sessionId: String): String = sessionsById[sessionId]?.lastBackendId ?: getSettings().preferredBackendId

    /** SC3's 1-based chain step. Derived once so no two telemetry branches can compute it differently. */
    private fun chainStepFor(remainingToolIterations: Int): Int = (MAX_AUTO_TOOL_ITERATIONS - remainingToolIterations + 1).coerceAtLeast(1)

    /**
     * Puts the decision in front of the user and PARKS the chain (D-06, SC2).
     *
     * Nothing reaches `McpToolExecutor` from here. The card is inserted through the transcript's
     * existing [SessionPanel.addComponent], which already wraps it against vertical stretching and
     * already refreshes the scroll, and the continuation waits inside [pendingDecisions] until a click.
     */
    private fun askForToolApproval(
        sessionId: String,
        userText: String,
        call: ParsedToolCall,
        panel: SessionPanel,
        context: McpToolContext,
        remainingToolIterations: Int,
        traceId: String,
        onCompleted: ((String, Throwable?) -> Unit)?,
        ask: ToolApprovalOutcome.Ask,
    ): ToolCallOutcome {
        // Re-read rather than take an eleventh parameter: `getOrPut` returns the very instance the
        // caller just resolved, and detekt's LongParameterList ceiling is 10.
        val state = sessionStates.getOrPut(sessionId) { ToolSessionState() }
        // A card already pending for this session means the one-per-session invariant was violated
        // upstream, because a pending card is exactly what stops another turn from running here. Fail
        // closed: retire the old one as IMPLICIT_DENY and discharge its parked continuation (T-22-31)
        // before the new card goes in, so no decision is silently replaced and nothing is left hanging.
        if (pendingDecisions.containsKey(sessionId)) {
            // Routed through the ONE entry point rather than repeating its three steps here. A second
            // removal site that happens to do the same thing today is exactly the ad-hoc-hook shape
            // this plan removes: the next field added to the resolution — the SC3 record was that
            // field — would land in one copy and not the other.
            //
            // Defensive, and unreachable on the normal path now that sendFromInput retires the card
            // before it can start a turn. Reaching it means the one-card-per-session invariant broke
            // upstream, which is worth telling the user about; the resolution itself is identical.
            resolvePending(sessionId, ImplicitDenyReason.NEW_MESSAGE)
            showError("A tool approval was still pending in this chat. It was denied automatically.")
        }
        val card =
            ToolApprovalCard(
                tier = ask.tier,
                catalogTitle = catalogTitleFor(ask.canonicalId),
                modelSuppliedToolId = call.tool,
                modelSuppliedArgsJson = call.argsJson,
                // Read from the gate, never re-derived from the tier here: two surfaces deriving the
                // same four-versus-two rule is how one of them offers a session grant for a tool that
                // must never have one (T-22-18).
                offersSessionActions = ask.offersSessionActions,
                repeatCount = state.approvalMemory.recordRequest(ask.canonicalId),
                onDecision = { decision -> resolveToolDecision(sessionId, decision) },
                onRequestFocusRestore = { inputArea.requestFocusInWindow() },
            )
        panel.addComponent(card)
        pendingDecisions[sessionId] =
            PendingToolDecision(
                sessionId = sessionId,
                userText = userText,
                call = call,
                context = context,
                remainingToolIterations = remainingToolIterations,
                traceId = traceId,
                onCompleted = onCompleted,
                card = card,
            )
        // The other half of the T-22-35 marker: the sessions list re-runs its renderer on every model
        // element, so this is what puts the pending marker on this session's row. Both resolution
        // paths refresh too, so the marker clears itself however the decision is retired.
        refreshSessionList()
        return ToolCallOutcome.AWAITING_DECISION
    }

    /**
     * Applies the user's click and restarts the parked chain (D-11).
     *
     * Runs inside the card's `ActionListener`, which the AWT event pump dispatches on the EDT by
     * definition — so this adds no `invokeLater` and changes nothing about REL-01. That structural
     * fact, not the check on its first line, is why the `@GuardedBy("EDT")` reads below are safe: any
     * future caller reaching this from somewhere other than an AWT event must marshal with
     * `invokeAndWait` itself, because the check is a development-time aid the JVM disables without
     * `-ea` and so reports nothing in a shipped Burp. See its KDoc.
     */
    private fun resolveToolDecision(
        sessionId: String,
        decision: ToolDecision,
    ) {
        assertEdt()
        // PEEKED here and REMOVED below, after the one call in this function that can throw. Taking the
        // record first meant a throw out of ToolApprovalGate.resolve destroyed it on the way out: a card
        // left holding live buttons with no record behind them, a parked continuation nobody could ever
        // discharge, and a second click hitting `?: return` and silently doing nothing — the permanently
        // dead card T-22-10 exists to eliminate (WR-02).
        //
        // The double-click guard is unchanged in strength. Nothing between this line and the removal can
        // pump an AWT event: `resolve` is pure, imports no Swing type and touches only the memory holder
        // passed into it, so no second click can be dispatched inside the window.
        val pending = pendingDecisions[sessionId] ?: return
        val state = sessionStates.getOrPut(sessionId) { ToolSessionState() }
        // This is what writes D-10 session memory for the two session-scoped actions, and only those.
        val resolved =
            try {
                ToolApprovalGate.resolve(pending.call.tool, state.approvalMemory, decision)
            } catch (e: IllegalArgumentException) {
                // Both `require` blocks in resolve() reject a CALLER bug — a decision the gate never
                // offers, or a session-scoped action on a CONFIRM_EACH tool — which means the card and
                // the gate have come to disagree. Nothing was decided, so nothing is retired: the record
                // stays, the card keeps its buttons, and `Deny` (which trips neither precondition) is
                // still one click away. Failing visibly beats an IllegalArgumentException disappearing
                // into the AWT event pump with the user looking at a card that just stopped responding.
                showError("That approval action could not be applied to this tool call: ${e.message}")
                return
            }
        // Consumed only now, and only on the path that actually reached a decision.
        pendingDecisions.remove(sessionId)
        // Turns the card into a record: the buttons are removed, not disabled, and the action the user
        // clicked is named verbatim in their place (T-22-30). Idempotent, so a race cannot double it.
        pending.card.resolve(decision)
        // The session no longer awaits anything; clear its list marker before the chain restarts and
        // possibly raises the next card (T-22-35).
        refreshSessionList()
        val panel = sessionPanels[sessionId]
        if (panel == null) {
            // The transcript is gone. There is nowhere to chain to, so discharge the parked
            // continuation here rather than dropping it (T-22-31).
            //
            // SC3 still owes a record, and this is the one branch where that is easy to miss: a HUMAN
            // clicked. The decision was made and only the place to run it disappeared, so the event
            // carries the decision that was actually reached, with an error run status because
            // nothing executed. Skipping it would leave a click with no audit trail at all.
            val canonicalId = McpToolExecutor.canonicalToolId(pending.call.tool)
            toolDecisionReporter.report(
                rawToolName = pending.call.tool,
                canonicalId = canonicalId,
                knownTool = isKnownTool(canonicalId, pending.context),
                tier = ToolApprovalGate.tierFor(pending.call.tool),
                decision = decision,
                argsJson = pending.call.argsJson,
                traceId = pending.traceId,
                chainStep = chainStepFor(pending.remainingToolIterations),
                runStatus = "error",
            )
            pending.onCompleted?.invoke(ToolApprovalGate.DENIAL_RESULT, null)
        } else {
            val outcome = dispatchResolvedToolCall(pending, panel, resolved)
            // The SECOND discharge point, and the mirror of the un-asked path's NOT_CHAINED check in
            // sendMessage's completion block — the same test, in the same place relative to the call
            // that produced the outcome (T-22-31).
            //
            // NOT_CHAINED here can only mean the APPROVED tool threw: reportFailedToolCall stops the
            // chain without sending a followup turn, so nothing downstream is carrying onCompleted any
            // more and this is its last chance to be discharged rather than dropped. Both denial
            // decisions and an approved run that returned normally chain a followup and report CHAINED,
            // so neither can be discharged twice here.
            //
            // DENIAL_RESULT for the same reason the transcript-gone branch above uses it: the parked
            // continuation is the "Send to AI" caller's resume hook, not a second audit sink. The
            // throwable was already recorded, with its class, by reportFailedToolCall's SC3 event, so
            // the second argument stays null exactly as it does at the un-asked NOT_CHAINED check.
            if (outcome == ToolCallOutcome.NOT_CHAINED) {
                pending.onCompleted?.invoke(ToolApprovalGate.DENIAL_RESULT, null)
            }
        }
    }

    /**
     * The ONE way a pending decision is retired without a click (D-08).
     *
     * **Five teardown paths reach this, not D-08's three.** A new message in the session, session
     * deletion, Clear Chat, a Burp project change and extension unload all destroy either the card or
     * the state behind it. `clearCurrentChat()` and `clearInMemorySessionState()` are the two D-08 does
     * not list, and they are the dangerous ones: `panel.clearMessages()` removes the card from the
     * transcript while the pending record survives, leaving an authorisation decision that can never be
     * made and a continuation that never fires. One entry point is the fix; an ad-hoc hook per path is
     * the bug, because the sixth path someone adds later will not get its own hook (T-22-10).
     *
     * Every step here is the same one an explicit click performs, in the same order: consult the gate,
     * turn the card into a record, write the SC3 event, discharge the parked continuation.
     *
     * **No implicit denial starts a backend turn, and there is deliberately no parameter offering to.**
     * This shipped with an inert `sendFollowup: Boolean = false` whose only job was to say that at the
     * declaration rather than by the absence of a call. A parameter is the wrong medium for a comment:
     * nothing read it, so `resolvePending(id, reason, sendFollowup = true)` compiled, produced no
     * followup, and gave no warning and no compile error — on the path that decides whether a denied
     * model is left hanging. Its blanket `@Suppress("UnusedParameter")` would also have covered any
     * FUTURE parameter that became unused (WR-03). Deleted rather than implemented: the property is
     * stronger structurally, because there is now no seam for a later edit to switch on, and passing one
     * is a compile error instead of a silent no-op. If the seam is genuinely wanted later, add it WITH
     * an implementation at the same time.
     *
     * D-08 asks that the model never be left hanging and D-12 routes a denial into a followup turn;
     * those two only appear to conflict. For four of the five paths there is no session left to run a
     * turn in, and for the fifth the user's own new message IS the continuation. A live followup would
     * create exactly two hazards: on `shutdown()` it would dispatch a backend request while Burp tears
     * down the extension classloader, and on `sendFromInput()` it would run concurrently with the user's
     * own turn and clobber `inFlightConnection`. Only an explicit `Deny` / `Deny for session` click
     * sends the D-12 followup, and `shutdownResolvesAllPendingDecisionsWithoutSendingATurn` asserts this
     * function's body contains no `sendMessage(` call at all.
     */
    private fun resolvePending(
        sessionId: String,
        reason: ImplicitDenyReason,
    ) {
        // Removed FIRST, exactly as resolveToolDecision does, so a click racing a teardown path cannot
        // resolve one card twice. ToolApprovalCard.resolve is idempotent too, so this is belt and braces.
        val pending = pendingDecisions.remove(sessionId) ?: return
        val state = sessionStates.getOrPut(sessionId) { ToolSessionState() }
        // Consulted rather than assumed: resolve() is what decides that an implicit denial writes NO
        // session memory in either direction. Inferring a lasting preference from silence is the
        // opposite of consent, and that rule belongs in the gate, not in five teardown paths.
        ToolApprovalGate.resolve(pending.call.tool, state.approvalMemory, ToolDecision.IMPLICIT_DENY)
        pending.card.resolve(ToolDecision.IMPLICIT_DENY, reason)
        // SC3. For four of the five paths the transcript is about to be destroyed, so this record is
        // the ONLY surviving evidence that the model asked for a capability and never got it — which
        // is why the reason rides along: "nobody answered" is otherwise unattributable.
        val canonicalId = McpToolExecutor.canonicalToolId(pending.call.tool)
        toolDecisionReporter.report(
            rawToolName = pending.call.tool,
            canonicalId = canonicalId,
            knownTool = isKnownTool(canonicalId, pending.context),
            tier = ToolApprovalGate.tierFor(pending.call.tool),
            decision = ToolDecision.IMPLICIT_DENY,
            argsJson = pending.call.argsJson,
            traceId = pending.traceId,
            chainStep = chainStepFor(pending.remainingToolIterations),
            implicitDenyReason = reason,
        )
        // The parked continuation, discharged rather than dropped (T-22-31). Same shape as the
        // context-preview cancel at startSessionFromContext, but the second argument stays null: a
        // denial is a policy outcome, not a malfunction (D-12), so no throwable is constructed here.
        pending.onCompleted?.invoke(ToolApprovalGate.DENIAL_RESULT, null)
        refreshSessionList()
    }

    /**
     * Retires every pending decision across all sessions — the project-change and unload paths.
     *
     * Iterates a COPY of the keys because [resolvePending] mutates the map it is walking.
     */
    private fun resolveAllPending(reason: ImplicitDenyReason) {
        pendingDecisions.keys.toList().forEach { sessionId -> resolvePending(sessionId, reason) }
    }

    /**
     * Routes a resolved decision down the same two paths an un-asked call takes.
     *
     * **Returns the outcome rather than discarding it**, which is the whole of T-22-31's first clause.
     * Both branches already produce one and the un-asked path has always read it; discarding it here
     * was the asymmetry that let a click-approved tool that then threw leave the parked continuation
     * uncalled forever. [resolveToolDecision] is the caller that acts on it, so the check sits at the
     * same place relative to the dispatch as the un-asked one does in `sendMessage`'s completion block.
     */
    private fun dispatchResolvedToolCall(
        pending: PendingToolDecision,
        panel: SessionPanel,
        resolved: ToolApprovalOutcome,
    ): ToolCallOutcome =
        when (resolved) {
            is ToolApprovalOutcome.Run ->
                executeApprovedToolCall(
                    sessionId = pending.sessionId,
                    userText = pending.userText,
                    call = pending.call,
                    panel = panel,
                    context = pending.context,
                    remainingToolIterations = pending.remainingToolIterations,
                    traceId = pending.traceId,
                    onCompleted = pending.onCompleted,
                    approved = resolved,
                )
            is ToolApprovalOutcome.Denied ->
                denyToolCall(
                    sessionId = pending.sessionId,
                    userText = pending.userText,
                    call = pending.call,
                    panel = panel,
                    context = pending.context,
                    remainingToolIterations = pending.remainingToolIterations,
                    traceId = pending.traceId,
                    onCompleted = pending.onCompleted,
                    denied = resolved,
                )
            // Unreachable: resolve() maps the four D-11 actions plus IMPLICIT_DENY onto Run or Denied
            // and throws on everything else. Exhaustive rather than `else` so a future outcome fails
            // the build here, at the place that must classify it.
            is ToolApprovalOutcome.Ask ->
                error("ToolApprovalGate.resolve returned Ask for ${pending.call.tool}; only evaluate() may ask.")
        }

    /**
     * Refuses a model-emitted tool call and keeps the conversation going (SC2, D-12, D-13).
     *
     * The refusal is NOT reported as a tool failure: [ToolApprovalGate.DENIAL_RESULT] carries no
     * `Error:` prefix, because telling the model something broke invites a retry with different args —
     * the exact loop SEC-06 exists to bound (T-22-19).
     */
    private fun denyToolCall(
        sessionId: String,
        userText: String,
        call: ParsedToolCall,
        panel: SessionPanel,
        context: McpToolContext,
        remainingToolIterations: Int,
        traceId: String,
        onCompleted: ((String, Throwable?) -> Unit)?,
        denied: ToolApprovalOutcome.Denied,
    ): ToolCallOutcome {
        val backendId = backendIdFor(sessionId)
        val canonicalId = McpToolExecutor.canonicalToolId(call.tool)
        // SC3. The refusal status rule is the reporter's and is deliberately NOT recomputed here: a
        // refusal is a policy outcome, not a malfunction (D-12), and putting that rule in two places
        // is how one of them ends up recording a decision as a tool failure.
        //
        // Reported BEFORE the log call, never inside its argument list: `aiRequestLogger` is nullable,
        // so `?.log(report(...))` would skip the audit event and the Output line entirely whenever the
        // AI Activity log happens to be absent — SC3 must not depend on another sink being wired.
        val metadata =
            toolDecisionReporter.report(
                rawToolName = call.tool,
                canonicalId = canonicalId,
                knownTool = isKnownTool(canonicalId, context),
                tier = denied.tier,
                decision = denied.decision,
                argsJson = call.argsJson,
                traceId = traceId,
                chainStep = chainStepFor(remainingToolIterations),
            )
        supervisor.aiRequestLogger?.log(
            type = ActivityType.MCP_TOOL_CALL,
            source = "chat",
            backendId = backendId,
            sessionId = sessionId,
            detail = "Tool ${call.tool} not authorised",
            durationMs = 0,
            metadata = metadata,
        )
        // The user sees the outcome in the transcript whether or not a card was ever shown.
        panel.addMessage("Tool result: ${call.tool}", ToolApprovalGate.DENIAL_RESULT)
        val followup =
            buildString {
                appendLine("The tool call to ${call.tool} was not authorised and did not run.")
                appendLine(ToolApprovalGate.DENIAL_RESULT)
                appendLine()
                appendLine("User request:")
                appendLine(userText)
                appendLine()
                // Deliberately NOT the success branch's closing line, which points the model at a tool
                // result: nothing ran, so there is no result, and pointing the model at one that does
                // not exist is how a refusal turns into a retry.
                appendLine("Provide the final response using the information you already have.")
            }.trim()
        // D-13: a denied call decrements the budget exactly as an approved one does, through the SAME
        // two helpers the success branch calls — so the counter is monotone by construction rather than
        // by two copies of the same arithmetic. Free denials would let injected traffic walk the model
        // through 59 different tools and produce 59 cards: a denial of service delivered through the
        // safety control itself (T-22-08).
        sendMessage(
            sessionId,
            followup,
            contextJson = null,
            allowToolCalls = ToolApprovalGate.allowsFurtherToolCalls(remainingToolIterations),
            actionName = "Tool Followup",
            onCompleted = onCompleted,
            toolIterationsLeft = ToolApprovalGate.nextIterationBudget(remainingToolIterations),
            traceId = traceId,
        )
        return ToolCallOutcome.CHAINED
    }

    /**
     * Runs a tool call the SEC-06 gate approved, then chains the followup turn.
     *
     * [origin] cannot have come from anywhere but [ToolApprovalGate] — the model-approved variant is
     * file-private to `ToolApprovalGate.kt` and unconstructible elsewhere, and the factory that mints it
     * is `private` to the gate object, so `evaluate` and `resolve` are the only code that can call it —
     * so reaching this function with one in hand IS the evidence that a decision was reached (T-22-11).
     * The residual, recorded in that file's header rather than left implied: `ToolCallOrigin` is sealed
     * to package `mcp`, not to one file, so the guarantee covers accidental bypass, not a deliberate one.
     */
    private fun executeApprovedToolCall(
        sessionId: String,
        userText: String,
        call: ParsedToolCall,
        panel: SessionPanel,
        context: McpToolContext,
        remainingToolIterations: Int,
        traceId: String,
        onCompleted: ((String, Throwable?) -> Unit)?,
        approved: ToolApprovalOutcome.Run,
    ): ToolCallOutcome {
        val captured =
            ToolCallCapture(
                sessionId = sessionId,
                userText = userText,
                call = call,
                panel = panel,
                context = context,
                approved = approved,
                traceId = traceId,
                remainingToolIterations = remainingToolIterations,
                startedAt = System.currentTimeMillis(),
            )
        // REL-05 / AI-SPEC E5 — THE LAST EDT READ OF GUARDED STATE ON THIS PATH. `panel` was resolved
        // from `sessionPanels` by the caller and is frozen into the capture here. Below the dispatch the
        // work runs on a worker thread, which must read NONE of sessionPanels, sessionStates,
        // sessionsById, sessionDrafts or pendingDecisions: those are @GuardedBy("EDT"), an off-EDT read
        // of one is the REL-01 data race, and it would corrupt silently rather than fail loudly.
        setSendingState(true)
        val token = RunningToolToken(call.tool)
        runningTool.set(token)
        OffEdtDispatch.run(
            threadName = "burp-ai-tool-exec",
            // WR-11 / Phase 22 commit ab55ff5: the label is the trace id so an ordering assertion can
            // select by identity. Keyed on list position it would hide a reordering bug; keyed on
            // identity it reports one.
            label = traceId,
            logError = { message -> api.logging().logToError(message) },
            work = { McpToolExecutor.executeTool(call.tool, call.argsJson, captured.context, approved.origin) },
            onEdt = { result -> finishApprovedToolCall(captured, token, result, onCompleted) },
        )
        return ToolCallOutcome.EXECUTING
    }

    /**
     * The supersede token for one running tool call.
     *
     * Still opaque to [RunningToolTracker], which compares tokens by IDENTITY through
     * `AtomicReference.compareAndSet` and never by value — so this is a plain class rather than a
     * `data class`, and two runs of the same tool are two distinct tokens.
     *
     * It carries [tool] because [cancelInFlightRequest] needs the tool's name to write UI-SPEC Rule
     * C-1's line, and that name must come from the run that was actually cancelled rather than from
     * whatever the panel happens to be showing.
     */
    private class RunningToolToken(
        val tool: String,
    )

    /**
     * Everything an approved tool call's worker or its EDT tail needs, read on the EDT before dispatch.
     *
     * A capture record rather than a wide helper signature, and the reason is measured: `detekt.yml`
     * sets both `LongParameterList` thresholds at 10, and `ChatPanel`'s own ten-parameter constructor is
     * already a baseline entry — a tail taking ten captured values would be the next one, and
     * `detekt-baseline.xml` is pinned at 1096 as a v0.10.0 milestone metric.
     *
     * [approved] is carried whole rather than unpacked into `origin` / `tier` / `decision` for the same
     * reason: it is an immutable value object, so three fields cost one.
     */
    private data class ToolCallCapture(
        val sessionId: String,
        val userText: String,
        val call: ParsedToolCall,
        val panel: SessionPanel,
        val context: McpToolContext,
        val approved: ToolApprovalOutcome.Run,
        val traceId: String,
        val remainingToolIterations: Int,
        val startedAt: Long,
    )

    /**
     * The EDT tail of an approved tool call: applies the worker's outcome, or discards it (REL-05).
     *
     * **EDT-confined.** It calls `panel.addMessage`, `setSendingState` and `sendMessage`, and reads
     * `sessionsById` through [backendIdFor] — all `@GuardedBy("EDT")` state, so REL-01 applies to it
     * exactly as it does to [cancelInFlightRequest]. Off-EDT callers must marshal first; the only caller
     * is the one marshalling point inside [OffEdtDispatch], which is what makes that true by
     * construction. It deliberately adds no EDT assertion of its own — SC5's evidence is that the
     * existing private assertion helper and its six call sites stay byte-identical, and a seventh call
     * site would move the count that IS the evidence.
     *
     * **Exactly one audit pair per exit, on every exit, including the superseded one.** `report` returns
     * the metadata map `log` consumes, so their order is a data dependency rather than a convention.
     */
    private fun finishApprovedToolCall(
        captured: ToolCallCapture,
        token: Any,
        result: Result<String>,
        onCompleted: ((String, Throwable?) -> Unit)?,
    ) {
        val superseded = !runningTool.clearIfMatches(token)
        val durationMs = System.currentTimeMillis() - captured.startedAt
        val canonicalId = McpToolExecutor.canonicalToolId(captured.call.tool)
        val chainStep = chainStepFor(captured.remainingToolIterations)
        if (superseded) {
            discardSupersededToolResult(captured, canonicalId, result, durationMs)
            // The parked continuation is the "Send to AI" caller's resume hook, not a second audit sink
            // — the same reason resolveToolDecision passes DENIAL_RESULT rather than a tool result.
            onCompleted?.invoke(ToolApprovalGate.DENIAL_RESULT, null)
            return
        }
        if (result.isFailure) {
            // That branch emits its own audit pair and its own transcript row; nothing is emitted here,
            // so the "exactly one pair per exit" rule holds.
            reportFailedToolCall(
                sessionId = captured.sessionId,
                call = captured.call,
                panel = captured.panel,
                context = captured.context,
                approved = captured.approved,
                traceId = captured.traceId,
                chainStep = chainStep,
                durationMs = durationMs,
                failure = result.exceptionOrNull(),
            )
            // The chain stops here, so S3 must be left or the panel stays busy with nothing running.
            setSendingState(false)
            // T-22-31: reportFailedToolCall sends no followup turn, so nothing downstream is carrying
            // `onCompleted` any more. Both former consumers now see EXECUTING and fall through, which
            // makes this its last chance to be discharged rather than dropped.
            onCompleted?.invoke(ToolApprovalGate.DENIAL_RESULT, null)
            return
        }
        val toolResult = result.getOrThrow()
        val status = if (toolResult.startsWith("Error:")) "error" else "ok"
        // SC3, and this is the branch that makes "which calls ran with no decision at all?" answerable
        // from a historical log: an AUTO run reports too, carrying its tier and its AUTO decision, so
        // it is distinguishable from a pre-gate call that nobody classified. Reported before the log
        // call because `aiRequestLogger` is nullable — see denyToolCall.
        val metadata =
            toolDecisionReporter.report(
                rawToolName = captured.call.tool,
                canonicalId = canonicalId,
                knownTool = isKnownTool(canonicalId, captured.context),
                tier = captured.approved.tier,
                decision = captured.approved.decision,
                argsJson = captured.call.argsJson,
                traceId = captured.traceId,
                chainStep = chainStep,
                resultChars = toolResult.length,
                runStatus = status,
            )
        supervisor.aiRequestLogger?.log(
            type = ActivityType.MCP_TOOL_CALL,
            source = "chat",
            backendId = backendIdFor(captured.sessionId),
            sessionId = captured.sessionId,
            detail = "Tool ${captured.call.tool} executed",
            durationMs = durationMs,
            metadata = metadata,
        )
        captured.panel.addMessage("Tool result: ${captured.call.tool}", toolResult)
        setSendingState(false)
        val followup =
            buildString {
                appendLine("Tool result for ${captured.call.tool}:")
                appendLine(toolResult)
                appendLine()
                appendLine("User request:")
                appendLine(captured.userText)
                appendLine()
                appendLine("Provide the final response using the tool result.")
            }.trim()
        // D-13: the same two helpers the denial branch calls, so both branches provably share ONE
        // decrement. See denyToolCall for why a refusal is not free.
        sendMessage(
            captured.sessionId,
            followup,
            contextJson = null,
            allowToolCalls = ToolApprovalGate.allowsFurtherToolCalls(captured.remainingToolIterations),
            actionName = "Tool Followup",
            onCompleted = onCompleted,
            toolIterationsLeft = ToolApprovalGate.nextIterationBudget(captured.remainingToolIterations),
            traceId = captured.traceId,
        )
    }

    /**
     * UI-SPEC state S4 — the worker came back after its run stopped mattering (D-07, D-08).
     *
     * Renders no transcript row, sends no followup turn and refunds no chain iteration: a refund would
     * perturb Phase 22 D-13's monotone counter and make an unbounded chain reachable by a user
     * repeatedly cancelling. The busy state is deliberately untouched — whatever superseded this run
     * already returned the panel to S0, and re-clearing it here could clobber a turn started since.
     *
     * **The audit pair still fires, and that is the load-bearing half of D-07.** The call reached Burp
     * and cannot be recalled; suppressing the record would put a hole in the SEC-06 audit log at exactly
     * the point a user interrupted something.
     */
    private fun discardSupersededToolResult(
        captured: ToolCallCapture,
        canonicalId: String,
        result: Result<String>,
        durationMs: Long,
    ) {
        val metadata =
            toolDecisionReporter.report(
                rawToolName = captured.call.tool,
                canonicalId = canonicalId,
                knownTool = isKnownTool(canonicalId, captured.context),
                tier = captured.approved.tier,
                decision = captured.approved.decision,
                argsJson = captured.call.argsJson,
                traceId = captured.traceId,
                chainStep = chainStepFor(captured.remainingToolIterations),
                resultChars = result.getOrNull()?.length,
                runStatus = SUPERSEDED_RUN_STATUS,
            ) + ("supersedeReason" to "result discarded before it was applied")
        supervisor.aiRequestLogger?.log(
            type = ActivityType.MCP_TOOL_CALL,
            source = "chat",
            backendId = backendIdFor(captured.sessionId),
            sessionId = captured.sessionId,
            detail = "Tool ${captured.call.tool} finished after its run was superseded; result discarded",
            durationMs = durationMs,
            metadata = metadata,
        )
    }

    /**
     * Records an APPROVED call whose tool then threw, and stops the chain.
     *
     * The easiest reporting branch in the file to miss, because it sits above the success emission and
     * returns early — and missing it puts a hole in SC3 exactly where it hurts. The decision *was*
     * made: a human clicked, or an earlier click was applied, or the tier auto-ran it. Reporting only
     * the calls that succeeded would make an approved-then-broken call indistinguishable from one that
     * was never authorised at all. The run status is the failure's, not the decision's, and
     * `errorClass` rides along as an extra key the reporter does not own — merged onto the returned
     * map rather than assembled beside it, so both sinks still come from one construction.
     */
    private fun reportFailedToolCall(
        sessionId: String,
        call: ParsedToolCall,
        panel: SessionPanel,
        context: McpToolContext,
        approved: ToolApprovalOutcome.Run,
        traceId: String,
        chainStep: Int,
        durationMs: Long,
        failure: Throwable?,
    ): ToolCallOutcome {
        val errorMessage = failure?.message ?: "Unknown MCP tool error"
        val backendId = backendIdFor(sessionId)
        val canonicalId = McpToolExecutor.canonicalToolId(call.tool)
        val metadata =
            toolDecisionReporter.report(
                rawToolName = call.tool,
                canonicalId = canonicalId,
                knownTool = isKnownTool(canonicalId, context),
                tier = approved.tier,
                decision = approved.decision,
                argsJson = call.argsJson,
                traceId = traceId,
                chainStep = chainStep,
                runStatus = "error",
            ) + ("errorClass" to (failure?.javaClass?.simpleName ?: "Exception"))
        supervisor.aiRequestLogger?.log(
            type = ActivityType.MCP_TOOL_CALL,
            source = "chat",
            backendId = backendId,
            sessionId = sessionId,
            detail = "Tool ${call.tool} failed: $errorMessage",
            durationMs = durationMs,
            metadata = metadata,
        )
        panel.addMessage("Tool result: ${call.tool}", "Error: $errorMessage")
        return ToolCallOutcome.NOT_CHAINED
    }

    private fun buildToolPreamble(
        context: McpToolContext?,
        includeCatalog: Boolean,
    ): String? {
        if (context == null) return null
        val header =
            """
You have access to MCP tools via a text-based protocol. To call a tool, output ONLY a JSON code block in this exact format:

```json
{"tool": "tool_name", "args": {"param1": "value1"}}
```

The system will parse your JSON, execute the tool, and return the result. Then you continue your analysis using that result.

IMPORTANT:
- When making a tool call, output ONLY the JSON block and nothing else in that message.
- Do NOT say you cannot use tools. You CAN use them by outputting JSON as shown above.
- After receiving a tool result, continue your analysis or make another tool call.
- For confirmed vulnerabilities, call `issue_create` with concrete evidence.
        """.trim()
        // Two returns, not three: detekt's ReturnCount baseline entry names this function's old signature.
        return if (includeCatalog) {
            header + "\n\n" + McpToolExecutor.describeTools(context, includeSchemas = true, includeDisabled = false)
        } else {
            header
        }
    }

    private fun buildToolContext(
        settings: AgentSettings,
        sessionId: String,
    ): McpToolContext {
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
            maxBodyBytes = settings.mcpSettings.maxBodyBytes,
        )
    }
}
