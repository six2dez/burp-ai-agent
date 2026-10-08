package com.six2dez.burp.aiagent.ui

import burp.api.montoya.MontoyaApi
import com.six2dez.burp.aiagent.audit.AiRequestLogger
import com.six2dez.burp.aiagent.audit.AuditLogger
import com.six2dez.burp.aiagent.backends.BackendRegistry
import com.six2dez.burp.aiagent.backends.HealthCheckResult
import com.six2dez.burp.aiagent.config.AgentSettingsRepository
import com.six2dez.burp.aiagent.config.Defaults
import com.six2dez.burp.aiagent.context.ContextCapture
import com.six2dez.burp.aiagent.mcp.McpSupervisor
import com.six2dez.burp.aiagent.redact.PrivacyMode
import com.six2dez.burp.aiagent.scanner.ScanKnowledgeBase
import com.six2dez.burp.aiagent.supervisor.AgentSupervisor
import com.six2dez.burp.aiagent.ui.components.DependencyBanner
import com.six2dez.burp.aiagent.ui.components.ToggleSwitch
import java.awt.BorderLayout
import java.awt.Cursor
import java.awt.Dimension
import java.awt.Graphics
import java.awt.Graphics2D
import java.awt.RenderingHints
import java.awt.event.KeyEvent
import java.awt.event.MouseAdapter
import java.awt.event.MouseEvent
import java.time.LocalTime
import java.util.concurrent.Executors
import javax.swing.BoxLayout
import javax.swing.JComponent
import javax.swing.JLabel
import javax.swing.JOptionPane
import javax.swing.JPanel
import javax.swing.JTabbedPane
import javax.swing.SwingUtilities
import javax.swing.Timer
import javax.swing.border.EmptyBorder

/**
 * Minimum width of the chat side of the sessions split, in pixels.
 *
 * Derived from the widest row the SEC-06 approval card cannot shrink: its four-button decision row,
 * measured at 487 px on Temurin 21 headless at Dialog-12, plus 29 px of card chrome (3 px accent strip,
 * two 1 px lines, 12 + 12 px horizontal padding) and the transcript scroll pane's 8 + 8 px border, for
 * a 532 px floor. Rounded up to 560 because Burp's L&F base font is larger than Dialog-12, so those
 * measurements are a floor rather than a ceiling (22-UI-REVIEW.md, Method and Measurement Appendix).
 *
 * It bounds the DECISION CONTROLS, not the caption rows: rows 2 and 10 wrap below their preferred width
 * rather than clipping horizontally, which is what `ToolApprovalCard.wrapped` buys. Do not raise this to
 * the card's preferred width — a minimum large enough to keep every caption on one line would stop the
 * user shrinking the chat panel at all.
 */
private const val CHAT_PANEL_MIN_WIDTH = 560

class MainTab(
    private val api: MontoyaApi,
    private val settingsRepo: AgentSettingsRepository,
    private val backends: BackendRegistry,
    private val supervisor: AgentSupervisor,
    private val audit: AuditLogger,
    private val mcpSupervisor: McpSupervisor,
    private val passiveAiScanner: com.six2dez.burp.aiagent.scanner.PassiveAiScanner,
    private val activeAiScanner: com.six2dez.burp.aiagent.scanner.ActiveAiScanner,
    private val aiRequestLogger: AiRequestLogger? = null,
) {
    val root: JComponent = JPanel(BorderLayout())
    private lateinit var settingsPanel: SettingsPanel
    private lateinit var chatPanel: ChatPanel
    private lateinit var bottomTabsPanel: BottomTabsPanel
    private var aiLoggerPanel: AiLoggerPanel? = null

    private val mcpToggle = ToggleSwitch()
    private val passiveToggle = ToggleSwitch()
    private val activeToggle = ToggleSwitch()
    private val backendPicker = javax.swing.JComboBox<String>()
    private val backendLabel = JLabel("Backend")
    private val mcpLabel = JLabel("MCP")
    private val mcpStatusLabel = JLabel("MCP: -")
    private val backendStatusLabel = JLabel("AI: ?")
    private val activeScanStatsLabel = JLabel("Scans: 0 | Vulns: 0")
    private val safetyIndicator =
        com.six2dez.burp.aiagent.ui.components
            .SafetyIndicator()

    private val statusLabel = JLabel("Idle")
    private val sessionLabel = JLabel("Session: -")

    /**
     * REL-05 / SC4 / CR-02 — the one seam every header and Settings-tab settings write leaves the EDT
     * through. Disposed first in [shutdown] so no write can start after `App.shutdown()` continues on
     * to `mcpSupervisor.shutdown()`.
     */
    private val settingsPersistQueue = SettingsPersistQueue { api.logging().logToError(it) }
    private val mcpStatusTimer =
        Timer(1000) {
            updateMcpBadge()
            updateMcpControls()
            updateBackendBadge()
            updateActiveScanStats()
            updateSafetySummary()
        }
    private val baseTabCaption = "Custom AI Agent"
    private var tabbedPane: JTabbedPane? = null
    private var attentionActive = false
    private val dependencyBanner =
        DependencyBanner("MCP Server must be enabled. Toggle MCP to enable AI features.")
    private var syncingToggles = false
    private var healthTimer: Timer? = null

    // Status-pill health checks: ONE named daemon thread plus a single-flight gate, so checks never
    // overlap and never pile up threads. A Settings save / click that lands mid-check is coalesced
    // into exactly one re-check after the flight ends.
    private val healthExec =
        Executors.newSingleThreadExecutor { r -> Thread(r, "burp-ai-agent-health").apply { isDaemon = true } }
    private val healthGate =
        SingleFlightGate(healthExec) {
            SwingUtilities.invokeLater { requestHealthCheck(HealthCheckTrigger.SETTINGS_CHANGED) }
        }

    // EDT-confined: the first timer tick is the startup check (remote providers included).
    private var startupHealthCheckDone = false
    private var sessionPersistTimer: Timer? = null
    private var lastProjectId: String? = null

    init {
        settingsPanel = SettingsPanel(api, settingsRepo, backends, supervisor, audit, mcpSupervisor, passiveAiScanner, activeAiScanner)
        if (aiRequestLogger != null) {
            aiLoggerPanel = AiLoggerPanel(aiRequestLogger)
        }
        bottomTabsPanel = BottomTabsPanel(settingsPanel, aiLoggerPanel)
        chatPanel =
            ChatPanel(
                api = api,
                supervisor = supervisor,
                // Quick 261008-n0c (H10): the chat reads the applied snapshot and never saves or applies.
                getSettings = { settingsRepo.load() },
                validateBackend = { validateBackendCommand(it) },
                ensureBackendReady = { ensureBackendReady(it) },
                showError = { showError(it) },
                onStatusChanged = { refreshStatus() },
                onResponseReady = { notifyResponseReady() },
                // CAP-04: thread scanner reference so ChatPanel can call setBudgetPaused(true) on hard cap
                passiveScanner = passiveAiScanner,
            )
        root.background = UiTheme.Colors.surface

        val top = HeaderPanel()
        top.layout = BorderLayout()
        top.border = EmptyBorder(14, 16, 14, 16)

        val title = JLabel("Custom AI Agent")
        title.font = UiTheme.Typography.headline
        title.foreground = UiTheme.Colors.onSurface

        val subtitle = JLabel("Terminal-first workflows with privacy controls and audit logging.")
        subtitle.font = UiTheme.Typography.body
        subtitle.foreground = UiTheme.Colors.onSurfaceVariant

        val titleBox = JPanel()
        titleBox.layout = BoxLayout(titleBox, BoxLayout.Y_AXIS)
        titleBox.isOpaque = false
        titleBox.add(title)
        titleBox.add(javax.swing.Box.createRigidArea(Dimension(0, 4)))
        titleBox.add(subtitle)

        val actions = JPanel(java.awt.FlowLayout(java.awt.FlowLayout.RIGHT, 12, 4))
        actions.isOpaque = false

        mcpLabel.font = UiTheme.Typography.body
        mcpLabel.foreground = UiTheme.Colors.onSurfaceVariant
        backendLabel.font = UiTheme.Typography.body
        backendLabel.foreground = UiTheme.Colors.onSurfaceVariant
        backendPicker.font = UiTheme.Typography.body
        backendPicker.background = UiTheme.Colors.comboBackground
        backendPicker.foreground = UiTheme.Colors.comboForeground
        backendPicker.border = javax.swing.border.LineBorder(UiTheme.Colors.outline, 1, true)
        val initialSettings = settingsRepo.load()
        backendPicker.model = javax.swing.DefaultComboBoxModel(backends.listAllBackendIds().toTypedArray())
        backendPicker.selectedItem = initialSettings.preferredBackendId
        backendPicker.addActionListener {
            val selected = backendPicker.selectedItem as? String ?: "codex-cli"
            settingsPanel.setPreferredBackend(selected)
            persistSettings("backend-picker", HeaderSettingsChange.PreferredBackend(selected))
            requestHealthCheck(HealthCheckTrigger.SETTINGS_CHANGED)
        }

        mcpToggle.isSelected = initialSettings.mcpSettings.enabled
        passiveToggle.isSelected = initialSettings.passiveAiEnabled
        activeToggle.isSelected = initialSettings.activeAiEnabled
        mcpToggle.toolTipText = "Enable MCP server."
        passiveToggle.toolTipText = "Enable AI passive scanner."
        activeToggle.toolTipText = "Enable AI active scanner."

        val mcpGroup = JPanel()
        mcpGroup.layout = BoxLayout(mcpGroup, BoxLayout.X_AXIS)
        mcpGroup.isOpaque = false
        mcpGroup.add(mcpLabel)
        mcpGroup.add(javax.swing.Box.createRigidArea(Dimension(6, 0)))
        mcpGroup.add(mcpToggle)
        mcpGroup.add(javax.swing.Box.createRigidArea(Dimension(10, 0)))
        styleStatusLabel(mcpStatusLabel)
        mcpGroup.add(mcpStatusLabel)

        styleStatusLabel(backendStatusLabel)
        // Click the pill to re-check on demand; remote providers are never polled on a timer.
        backendStatusLabel.cursor = Cursor.getPredefinedCursor(Cursor.HAND_CURSOR)
        backendStatusLabel.toolTipText = "Click to re-check"
        backendStatusLabel.addMouseListener(
            object : MouseAdapter() {
                override fun mouseClicked(e: MouseEvent) {
                    requestHealthCheck(HealthCheckTrigger.USER_CLICK)
                }
            },
        )
        // First tick = startup check for every backend; later ticks poll local backends only.
        healthTimer =
            Timer(Defaults.LOCAL_BACKEND_HEALTH_POLL_INTERVAL_MS.toInt()) {
                val trigger = if (startupHealthCheckDone) HealthCheckTrigger.PERIODIC else HealthCheckTrigger.STARTUP
                startupHealthCheckDone = true
                requestHealthCheck(trigger)
            }.apply { initialDelay = Defaults.BACKEND_HEALTH_STARTUP_CHECK_DELAY_MS.toInt() }
        healthTimer?.start()

        val passiveLabel = JLabel("Passive")
        passiveLabel.font = UiTheme.Typography.body
        passiveLabel.foreground = UiTheme.Colors.onSurfaceVariant
        val activeLabel = JLabel("Active")
        activeLabel.font = UiTheme.Typography.body
        activeLabel.foreground = UiTheme.Colors.onSurfaceVariant

        val scannerGroup = JPanel()
        scannerGroup.layout = BoxLayout(scannerGroup, BoxLayout.X_AXIS)
        scannerGroup.isOpaque = false
        scannerGroup.add(passiveLabel)
        scannerGroup.add(javax.swing.Box.createRigidArea(Dimension(6, 0)))
        scannerGroup.add(passiveToggle)
        scannerGroup.add(javax.swing.Box.createRigidArea(Dimension(12, 0)))
        scannerGroup.add(activeLabel)
        scannerGroup.add(javax.swing.Box.createRigidArea(Dimension(6, 0)))
        scannerGroup.add(activeToggle)
        scannerGroup.add(javax.swing.Box.createRigidArea(Dimension(10, 0)))
        activeScanStatsLabel.font = UiTheme.Typography.body
        activeScanStatsLabel.foreground = UiTheme.Colors.onSurfaceVariant
        scannerGroup.add(activeScanStatsLabel)

        val clientGroup = JPanel()
        clientGroup.layout = BoxLayout(clientGroup, BoxLayout.X_AXIS)
        clientGroup.isOpaque = false
        clientGroup.add(backendLabel)
        clientGroup.add(javax.swing.Box.createRigidArea(Dimension(6, 0)))
        clientGroup.add(backendPicker)
        clientGroup.add(javax.swing.Box.createRigidArea(Dimension(16, 0)))
        styleStatusLabel(statusLabel)
        sessionLabel.font = UiTheme.Typography.body
        sessionLabel.foreground = UiTheme.Colors.onSurfaceVariant
        clientGroup.add(statusLabel)
        clientGroup.add(javax.swing.Box.createRigidArea(Dimension(10, 0)))
        clientGroup.add(backendStatusLabel)
        clientGroup.add(javax.swing.Box.createRigidArea(Dimension(10, 0)))
        clientGroup.add(sessionLabel)
        clientGroup.add(javax.swing.Box.createHorizontalGlue())
        clientGroup.add(safetyIndicator)

        actions.add(mcpGroup)
        actions.add(scannerGroup)
        actions.add(clientGroup)

        val mainContent =
            javax.swing.JSplitPane(
                javax.swing.JSplitPane.HORIZONTAL_SPLIT,
                chatPanel.sessionsComponent(),
                chatPanel.root,
            )
        mainContent.resizeWeight = 0.2
        mainContent.setDividerLocation(0.2)
        mainContent.border = EmptyBorder(0, 0, 0, 0)
        // The other half of 22-UI-REVIEW.md S-1. A JSplitPane clamps its divider to the two children's
        // minimum sizes, and nothing set one here — so the divider could be dragged until the SEC-06
        // approval card's decision buttons were off the right edge of a transcript that shows no
        // horizontal scrollbar. Setting it on the CHAT side is what turns the card's own floor into a
        // drag limit; the sessions list keeps its natural minimum so the split still moves both ways.
        chatPanel.root.minimumSize = Dimension(CHAT_PANEL_MIN_WIDTH, 0)

        val center =
            javax.swing.JSplitPane(
                javax.swing.JSplitPane.VERTICAL_SPLIT,
                mainContent,
                bottomTabsPanel.root,
            )
        center.resizeWeight = 0.7
        center.setDividerLocation(0.7)
        center.border = EmptyBorder(0, 0, 0, 0)
        center.isOneTouchExpandable = true
        bottomTabsPanel.root.minimumSize = java.awt.Dimension(0, 90)
        bottomTabsPanel.root.preferredSize = java.awt.Dimension(0, 240)

        top.add(titleBox, BorderLayout.CENTER)
        top.add(actions, BorderLayout.EAST)

        val north = JPanel(BorderLayout())
        north.background = UiTheme.Colors.surface
        north.add(top, BorderLayout.NORTH)
        north.add(dependencyBanner, BorderLayout.SOUTH)
        root.add(north, BorderLayout.NORTH)
        root.add(center, BorderLayout.CENTER)

        // ── Keyboard shortcuts ──
        val imap = root.getInputMap(JComponent.WHEN_ANCESTOR_OF_FOCUSED_COMPONENT)
        val amap = root.actionMap
        val meta =
            java.awt.Toolkit
                .getDefaultToolkit()
                .menuShortcutKeyMaskEx

        imap.put(javax.swing.KeyStroke.getKeyStroke(KeyEvent.VK_N, meta), "newSession")
        amap.put(
            "newSession",
            object : javax.swing.AbstractAction() {
                override fun actionPerformed(e: java.awt.event.ActionEvent?) {
                    chatPanel.createNewSession()
                }
            },
        )
        imap.put(javax.swing.KeyStroke.getKeyStroke(KeyEvent.VK_W, meta), "deleteSession")
        amap.put(
            "deleteSession",
            object : javax.swing.AbstractAction() {
                override fun actionPerformed(e: java.awt.event.ActionEvent?) {
                    chatPanel.deleteCurrentSession()
                }
            },
        )
        imap.put(javax.swing.KeyStroke.getKeyStroke(KeyEvent.VK_L, meta), "clearChat")
        amap.put(
            "clearChat",
            object : javax.swing.AbstractAction() {
                override fun actionPerformed(e: java.awt.event.ActionEvent?) {
                    chatPanel.clearCurrentChat()
                }
            },
        )
        imap.put(javax.swing.KeyStroke.getKeyStroke(KeyEvent.VK_E, meta), "exportChat")
        amap.put(
            "exportChat",
            object : javax.swing.AbstractAction() {
                override fun actionPerformed(e: java.awt.event.ActionEvent?) {
                    chatPanel.exportCurrentChatAsMarkdown()
                }
            },
        )
        imap.put(javax.swing.KeyStroke.getKeyStroke(KeyEvent.VK_ESCAPE, 0), "toggleSettings")
        amap.put(
            "toggleSettings",
            object : javax.swing.AbstractAction() {
                override fun actionPerformed(e: java.awt.event.ActionEvent?) {
                    if (!chatPanel.cancelInFlightRequest()) {
                        bottomTabsPanel.toggle()
                    }
                }
            },
        )
        imap.put(javax.swing.KeyStroke.getKeyStroke(KeyEvent.VK_T, meta), "openToolsDialog")
        amap.put(
            "openToolsDialog",
            object : javax.swing.AbstractAction() {
                override fun actionPerformed(e: java.awt.event.ActionEvent?) {
                    chatPanel.openToolDialog()
                }
            },
        )

        wireActions()
        renderStatus()
        mcpStatusTimer.start()

        // Restore persisted chat sessions
        chatPanel.restoreSessions()

        // Capture initial project ID
        lastProjectId =
            try {
                api.project().id()
            } catch (_: Exception) {
                null
            }

        // Auto-save sessions every 30 seconds, detect project changes, and update usage stats
        sessionPersistTimer =
            Timer(30_000) {
                val currentProjectId =
                    try {
                        api.project().id()
                    } catch (_: Exception) {
                        null
                    }
                if (lastProjectId != null && currentProjectId != null && lastProjectId != currentProjectId) {
                    onProjectChanged()
                }
                lastProjectId = currentProjectId
                chatPanel.saveSessions()
                settingsPanel.updateUsageSummary(chatPanel.usageStats())
            }
        sessionPersistTimer?.start()
    }

    private fun notifyResponseReady() {
        SwingUtilities.invokeLater {
            settingsPanel.updateUsageSummary(chatPanel.usageStats())
            val pane = ensureTabPaneAttached() ?: return@invokeLater
            if (pane.selectedComponent == root) return@invokeLater
            setAttention(true)
        }
    }

    private fun ensureTabPaneAttached(): JTabbedPane? {
        if (tabbedPane != null) return tabbedPane
        val pane = findParentTabbedPane() ?: return null
        tabbedPane = pane
        pane.addChangeListener {
            if (pane.selectedComponent == root) {
                setAttention(false)
            }
        }
        return pane
    }

    private fun findParentTabbedPane(): JTabbedPane? {
        var current: java.awt.Container? = root.parent as? java.awt.Container
        while (current != null) {
            if (current is JTabbedPane) return current
            current = current.parent as? java.awt.Container
        }
        return null
    }

    private fun setAttention(active: Boolean) {
        val pane = ensureTabPaneAttached() ?: return
        val index = pane.indexOfComponent(root)
        if (index < 0) return
        val title = if (active) "$baseTabCaption *" else baseTabCaption
        if (pane.getTitleAt(index) != title) {
            pane.setTitleAt(index, title)
        }
        attentionActive = active
    }

    private fun wireActions() {
        settingsPanel.onMcpEnabledChanged = mcpSync@{ enabled ->
            if (syncingToggles) return@mcpSync
            syncingToggles = true
            mcpToggle.isSelected = enabled
            syncingToggles = false
            persistSettingsAndApplyMcp("mcp-enabled-changed", HeaderSettingsChange.McpEnabled(enabled))
        }
        settingsPanel.onPassiveAiEnabledChanged = passiveSync@{ enabled ->
            if (syncingToggles) return@passiveSync
            syncingToggles = true
            passiveToggle.isSelected = enabled
            syncingToggles = false
            persistSettings("passive-enabled-changed", HeaderSettingsChange.PassiveAiEnabled(enabled))
        }
        settingsPanel.onActiveAiEnabledChanged = activeSync@{ enabled ->
            if (syncingToggles) return@activeSync
            syncingToggles = true
            activeToggle.isSelected = enabled
            syncingToggles = false
            persistSettings("active-enabled-changed", HeaderSettingsChange.ActiveAiEnabled(enabled))
        }

        mcpToggle.addActionListener {
            if (syncingToggles) return@addActionListener
            val enabled = mcpToggle.isSelected
            syncingToggles = true
            settingsPanel.setMcpEnabled(enabled)
            syncingToggles = false
            persistSettingsAndApplyMcp("mcp-toggle", HeaderSettingsChange.McpEnabled(enabled))
        }
        passiveToggle.addActionListener {
            if (syncingToggles) return@addActionListener
            val enabled = passiveToggle.isSelected
            syncingToggles = true
            settingsPanel.setPassiveAiEnabled(enabled)
            syncingToggles = false
            persistSettings("passive-toggle", HeaderSettingsChange.PassiveAiEnabled(enabled))
        }
        activeToggle.addActionListener {
            if (syncingToggles) return@addActionListener
            val enabled = activeToggle.isSelected
            syncingToggles = true
            settingsPanel.setActiveAiEnabled(enabled)
            syncingToggles = false
            persistSettings("active-toggle", HeaderSettingsChange.ActiveAiEnabled(enabled))
        }
        settingsPanel.onSettingsChanged = { updated ->
            SwingUtilities.invokeLater {
                aiRequestLogger?.enabled = updated.aiRequestLoggerEnabled
                aiRequestLogger?.maxEntries = updated.aiRequestLoggerMaxEntries
                val allBackends = backends.listAllBackendIds()
                backendPicker.model = javax.swing.DefaultComboBoxModel(allBackends.toTypedArray())
                if (allBackends.contains(updated.preferredBackendId)) {
                    backendPicker.selectedItem = updated.preferredBackendId
                }
                // Header sync. This fires from applyAndSaveSettingsAsync's EDT tail for BOTH callers,
                // and performs Swing writes only — no disk write, no MCP stop — so it is EDT-safe by
                // construction. It is what keeps the header honest now that the restore path no longer
                // notifies the host, and it repairs a pre-existing asymmetry: a plain Save that changed
                // MCP enabled synced backendPicker and left these three toggles stale.
                syncingToggles = true
                mcpToggle.isSelected = updated.mcpSettings.enabled
                passiveToggle.isSelected = updated.passiveAiEnabled
                activeToggle.isSelected = updated.activeAiEnabled
                syncingToggles = false
                renderStatus()
                requestHealthCheck(HealthCheckTrigger.SETTINGS_CHANGED)
            }
        }
    }

    /**
     * EDT only. Reads the current settings, asks [BackendHealthPolicy] whether [trigger] may run a
     * check for the selected backend, and hands the network I/O to the single health thread. The
     * result is painted back on the EDT.
     *
     * Any exception from a backend's health check (third-party code for external backends) must
     * still repaint the pill as Offline instead of leaving a stale "AI: OK", hence the broad catch.
     */
    @Suppress("TooGenericExceptionCaught")
    private fun requestHealthCheck(trigger: HealthCheckTrigger) {
        val settings = settingsPanel.currentSettings()
        if (!BackendHealthPolicy.shouldRun(trigger, settings)) return
        healthGate.submit(coalesce = trigger != HealthCheckTrigger.PERIODIC) {
            val health =
                try {
                    supervisor.backendHealth(settings)
                } catch (e: Exception) {
                    HealthCheckResult.Unavailable(e.message ?: "Health check failed")
                }
            val checkedAt = LocalTime.now()
            SwingUtilities.invokeLater { renderBackendHealth(health, checkedAt) }
        }
    }

    private fun renderBackendHealth(
        health: HealthCheckResult,
        checkedAt: LocalTime,
    ) {
        when (health) {
            is HealthCheckResult.Healthy -> {
                backendStatusLabel.text = "AI: OK"
                backendStatusLabel.background = UiTheme.Colors.statusRunning
                backendStatusLabel.toolTipText = BackendHealthPolicy.tooltip("Backend health check passed.", checkedAt)
            }
            is HealthCheckResult.Degraded -> {
                backendStatusLabel.text = "AI: Degraded"
                backendStatusLabel.background = UiTheme.Colors.statusTerminal
                backendStatusLabel.toolTipText = BackendHealthPolicy.tooltip(health.message, checkedAt)
            }
            else -> {
                backendStatusLabel.text = "AI: Offline"
                backendStatusLabel.background = UiTheme.Colors.statusCrashed
                val message =
                    when (health) {
                        is HealthCheckResult.Unavailable -> health.message
                        else -> "Backend did not respond."
                    }
                backendStatusLabel.toolTipText = BackendHealthPolicy.tooltip(message, checkedAt)
            }
        }
    }

    /**
     * Saves the one field [change] carries on `burp-ai-settings-sync` and nothing else — no MCP apply, no
     * scanner reload.
     *
     * Each write carries ONE field, never a snapshot read off the Settings tab: the worker
     * ([persistHeaderChange]) applies it to the SAVED snapshot inside the repository write lock, so
     * unsaved Settings edits stay unsaved and a concurrent Save settings is never torn or overwritten
     * with a stale snapshot (quick 261008-o97).
     *
     * Declared here rather than alongside the queue itself because detekt runs with
     * `buildUponDefaultConfig = true` and `detekt.yml` overrides only `complexity`, `style` and
     * `naming`, so the default `UnusedPrivateMember` rule is live: a private helper introduced one task
     * ahead of its callers would fail that task's own static-analysis gate with no sanctioned exit.
     *
     * **Mention ledger (structural gate).** `everyMainTabSettingsWriteGoesThroughThePersistQueue` reads
     * this file from disk, strips comment lines — block comments included, which is why these tokens
     * can be named here at all — and asserts these counts as EQUALITIES. An eighth write site, or a
     * seventh regressing to an inline save, moves a count and turns that test red. Update this ledger
     * deliberately; do not relax the assertions to `>=`.
     *
     * | Token | Count | Composition |
     * |---|---|---|
     * | `persistSettings(` | 6 | 1 declaration + 5 call sites (backend picker, passive/active host callbacks, passive/active header toggles) |
     * | `persistSettingsAndApplyMcp(` | 3 | 1 declaration + 2 call sites (the MCP host callback and the header mcpToggle) |
     * | `settingsRepo.save(` | 0 | header writes save one field through the worker bodies' `settingsRepo.update` |
     * | `mcpSupervisor.applySettings(` | 0 | the MCP apply lives in persistHeaderChangeAndApplyMcp, built from what was saved |
     * | `persistHeaderChange(` | 1 | persistSettings' apply lambda |
     * | `persistHeaderChangeAndApplyMcp(` | 1 | persistSettingsAndApplyMcp's apply lambda |
     * | `supervisor.applySettings(` | 0 | App's repository listener (`mirrorAppliedSettingsInto`) owns that |
     * | `getSettings = { settingsRepo.load() }` | 1 | the ChatPanel construction: the chat reads the applied snapshot |
     */
    private fun persistSettings(
        label: String,
        change: HeaderSettingsChange,
    ) {
        settingsPersistQueue.submit(
            label = label,
            supersedeKey = change.supersedeKey,
            payload = change,
            apply = { persistHeaderChange(settingsRepo, it) },
            onSettled = { renderStatus() },
        )
    }

    /**
     * Saves the MCP enabled flag [change] carries AND re-applies the MCP settings, both on
     * `burp-ai-settings-sync`.
     *
     * The worker ([persistHeaderChangeAndApplyMcp]) saves the flag onto the SAVED snapshot under the
     * repository write lock and applies MCP built from what was saved (port, external access, privacy
     * mode), never from unsaved Settings edits (quick 261008-o97).
     *
     * REL-05 / SC4: with MCP going enabled→disabled this reaches `McpSupervisor.stop()` and then
     * `KtorMcpServerManager`'s bounded `future.get(10, TimeUnit.SECONDS)`. D-14 keeps that wait
     * blocking; this moves the caller off the EDT so the ten seconds are paid by a daemon worker
     * instead of by the Burp UI. [renderStatus] runs from the queue's EDT tail, so the badge reports
     * the state AFTER the apply rather than before it.
     *
     * **Why this phase ends with TWO persist helpers rather than one flag-taking helper.** This file has
     * seven settings writes; two apply MCP, five do not. The two that do are the MCP-enabled host
     * callback and the header `mcpToggle`; the other five are the backend picker, the passive and active
     * host callbacks and the passive and active header toggles.
     * `McpSupervisor.stop()` also clears `ScannerTaskRegistry` and `CollaboratorRegistry`, so applying
     * MCP settings on every passive/active toggle would drop live scanner tasks — a behaviour change,
     * not a harmless no-op (`T-23-06-07`). Two narrow helpers keep that impossible by construction.
     */
    private fun persistSettingsAndApplyMcp(
        label: String,
        change: HeaderSettingsChange.McpEnabled,
    ) {
        settingsPersistQueue.submit(
            label = label,
            supersedeKey = change.supersedeKey,
            payload = change,
            apply = { persistHeaderChangeAndApplyMcp(settingsRepo, mcpSupervisor, it) },
            onSettled = { renderStatus() },
        )
    }

    private fun renderStatus() {
        SwingUtilities.invokeLater {
            val s = supervisor.status()
            statusLabel.text = "Status: ${s.state} | Backend: ${s.backendId ?: "-"}"
            val sessionId = supervisor.currentSessionId() ?: "-"
            sessionLabel.text = "Session: $sessionId"
            updateStatusColor(s.state)
            updateMcpControls()
            updateMcpBadge()
            chatPanel.refreshPrivacyMode()
            updateSafetySummary()
        }
    }

    fun currentSettings() = settingsRepo.load()

    fun currentSessionId(): String? = supervisor.currentSessionId()

    fun openChatWithContext(
        capture: ContextCapture,
        promptTemplate: String,
        actionName: String,
        onCompleted: ((String, Throwable?) -> Unit)? = null,
    ) {
        chatPanel.startSessionFromContext(capture, promptTemplate, actionName, onCompleted)
    }

    fun openChatWithContext(
        capture: ContextCapture,
        spec: PromptLaunchSpec,
        onCompleted: ((String, Throwable?) -> Unit)? = null,
    ) {
        chatPanel.startSessionFromContext(capture, spec, onCompleted)
    }

    fun refreshStatus() {
        renderStatus()
    }

    private fun updateMcpControls() {
        val mcpState = mcpSupervisor.status()
        val running = mcpState is com.six2dez.burp.aiagent.mcp.McpServerState.Running
        val busy =
            mcpState is com.six2dez.burp.aiagent.mcp.McpServerState.Starting ||
                mcpState is com.six2dez.burp.aiagent.mcp.McpServerState.Stopping
        mcpToggle.isEnabled = !busy
        backendPicker.isEnabled = running && !busy
        if (running) {
            dependencyBanner.hideBanner()
        } else {
            dependencyBanner.showBanner()
        }
        chatPanel.setMcpAvailable(running)
    }

    private fun updateMcpBadge() {
        val state = mcpSupervisor.status()
        val text =
            when (state) {
                is com.six2dez.burp.aiagent.mcp.McpServerState.Running -> "MCP: Running"
                is com.six2dez.burp.aiagent.mcp.McpServerState.Starting -> "MCP: Starting"
                is com.six2dez.burp.aiagent.mcp.McpServerState.Stopping -> "MCP: Stopping"
                is com.six2dez.burp.aiagent.mcp.McpServerState.Failed -> {
                    if (isBindFailure(state.exception)) "MCP: Port in use" else "MCP: Error"
                }
                else -> "MCP: Stopped"
            }
        mcpStatusLabel.text = text
        mcpStatusLabel.background =
            when (state) {
                is com.six2dez.burp.aiagent.mcp.McpServerState.Running -> UiTheme.Colors.statusRunning
                is com.six2dez.burp.aiagent.mcp.McpServerState.Failed -> UiTheme.Colors.statusCrashed
                is com.six2dez.burp.aiagent.mcp.McpServerState.Starting -> UiTheme.Colors.statusTerminal
                is com.six2dez.burp.aiagent.mcp.McpServerState.Stopping -> UiTheme.Colors.statusTerminal
                else -> UiTheme.Colors.outlineVariant
            }
    }

    private fun updateSafetySummary() {
        // Quick 261008-n0c: the header indicator states what is in effect, the same rule as the chat
        // pill. Reading the applied snapshot also means this 1 Hz tick no longer re-runs every custom
        // pattern's SafeRegex probe on the EDT.
        val settings = settingsRepo.load()
        val privacy = settings.privacyMode.name
        val mcpExposure =
            when {
                !settings.mcpSettings.enabled -> "MCP off"
                settings.mcpSettings.externalEnabled -> "MCP external"
                else -> "MCP local"
            }
        val unsafe = if (settings.mcpSettings.unsafeEnabled) "Unsafe on" else "Unsafe off"
        val scanners = "Passive ${if (settings.passiveAiEnabled) "on" else "off"} / Active ${if (settings.activeAiEnabled) "on" else "off"}"

        val level =
            when {
                settings.mcpSettings.enabled &&
                    settings.mcpSettings.externalEnabled &&
                    settings.mcpSettings.unsafeEnabled ->
                    com.six2dez.burp.aiagent.ui.components.SafetyIndicator.Level.RISK
                settings.privacyMode == PrivacyMode.OFF && settings.mcpSettings.enabled ->
                    com.six2dez.burp.aiagent.ui.components.SafetyIndicator.Level.RISK
                settings.privacyMode == PrivacyMode.OFF ||
                    settings.mcpSettings.externalEnabled ||
                    settings.mcpSettings.unsafeEnabled ->
                    com.six2dez.burp.aiagent.ui.components.SafetyIndicator.Level.WARN
                else -> com.six2dez.burp.aiagent.ui.components.SafetyIndicator.Level.OK
            }
        // HTML tooltip so the four flags wrap onto separate lines instead of one long string.
        val tooltip =
            "<html><b>Safety</b><br>" +
                "Privacy: $privacy<br>" +
                "MCP: $mcpExposure<br>" +
                unsafe +
                "<br>" +
                scanners +
                "</html>"
        safetyIndicator.setSummary(level, tooltip)
    }

    private fun updateBackendBadge() {
        // Updated by separate timer to avoid blocking EDT
    }

    private fun updateActiveScanStats() {
        if (!activeAiScanner.isEnabled()) {
            activeScanStatsLabel.text = "Active Scanner Disabled"
            return
        }
        val status = activeAiScanner.getStatus()
        val text =
            if (status.scanning) {
                "Scanning: ${status.queueSize} queued | ${status.scansCompleted} done | ${status.vulnsConfirmed} confirmed"
            } else {
                "Queue: ${status.queueSize} | Done: ${status.scansCompleted} | Confirmed: ${status.vulnsConfirmed}"
            }
        activeScanStatsLabel.text = text
    }

    private fun isBindFailure(exception: Throwable): Boolean {
        var current: Throwable? = exception
        while (current != null) {
            if (current is java.net.BindException) return true
            current = current.cause
        }
        return false
    }

    private fun styleStatusLabel(label: JLabel) {
        label.font = UiTheme.Typography.body
        label.isOpaque = true
        label.border = EmptyBorder(4, 8, 4, 8)
        label.foreground = UiTheme.Colors.onSurface
        label.background = UiTheme.Colors.outlineVariant
    }

    private fun updateStatusColor(state: String) {
        val color =
            when (state) {
                "Running" -> UiTheme.Colors.statusRunning
                "Crashed" -> UiTheme.Colors.statusCrashed
                // Terminal status removed
                else -> UiTheme.Colors.outlineVariant
            }
        statusLabel.background = color
    }

    private class HeaderPanel : JPanel() {
        init {
            isOpaque = true
            background = UiTheme.Colors.surface
        }

        override fun paintComponent(g: Graphics) {
            super.paintComponent(g)
            val g2 = g as Graphics2D
            g2.setRenderingHint(RenderingHints.KEY_RENDERING, RenderingHints.VALUE_RENDER_QUALITY)
            g2.color = background
            g2.fillRect(0, 0, width, height)
        }
    }

    internal fun validateBackendCommand(settings: com.six2dez.burp.aiagent.config.AgentSettings): String? =
        when (settings.preferredBackendId) {
            "codex-cli" -> if (settings.codexCmd.isBlank()) "Codex command is empty." else null
            "gemini-cli" -> if (settings.geminiCmd.isBlank()) "Gemini command is empty." else null
            "opencode-cli" -> {
                when {
                    settings.opencodeCmd.isBlank() -> "OpenCode command is empty."
                    isWindows() && looksLikeBareExe(settings.opencodeCmd) ->
                        "OpenCode command looks like a bare .exe. If installed via npm, use 'opencode' (without .exe) or a full path to opencode.cmd."
                    else -> null
                }
            }
            "claude-cli" -> if (settings.claudeCmd.isBlank()) "Claude command is empty." else null
            "copilot-cli" -> if (settings.copilotCmd.isBlank()) "Copilot command is empty." else null
            "ollama" -> if (settings.ollamaCliCmd.isBlank()) "Ollama CLI command is empty." else null
            "lmstudio" -> if (settings.lmStudioUrl.isBlank()) "LM Studio URL is empty." else null
            "openai-compatible" -> {
                when {
                    settings.openAiCompatibleUrl.isBlank() -> "OpenAI-compatible URL is empty."
                    settings.openAiCompatibleModel.isBlank() -> "OpenAI-compatible model is empty."
                    else -> null
                }
            }
            "nvidia-nim" -> {
                when {
                    settings.nvidiaNimUrl.isBlank() -> "NVIDIA NIM URL is empty."
                    settings.nvidiaNimModel.isBlank() -> "NVIDIA NIM model is empty."
                    else -> null
                }
            }
            "perplexity" -> {
                when {
                    settings.perplexityUrl.isBlank() -> "Perplexity URL is empty."
                    settings.perplexityModel.isBlank() -> "Perplexity model is empty."
                    else -> null
                }
            }
            "anthropic" -> {
                // WR-04: validate the keyed Anthropic backend up front, like the other HTTP
                // backends, instead of letting a blank key fall through to a raw 401 at HTTP time.
                when {
                    settings.anthropicApiKey.isBlank() -> "Anthropic API key is empty."
                    settings.anthropicModel.isBlank() -> "Anthropic model is empty."
                    else -> null
                }
            }
            "burp-ai" -> null
            else -> "Unsupported backend: ${settings.preferredBackendId}"
        }

    private fun looksLikeBareExe(cmd: String): Boolean {
        val trimmed = cmd.trim()
        if (!trimmed.lowercase().endsWith(".exe")) return false
        return !trimmed.contains("\\") && !trimmed.contains("/")
    }

    private fun isWindows(): Boolean {
        val os = System.getProperty("os.name").lowercase()
        return os.contains("win")
    }

    internal fun showError(message: String) {
        SwingUtilities.invokeLater {
            JOptionPane.showMessageDialog(
                root,
                message,
                "Custom AI Agent",
                JOptionPane.ERROR_MESSAGE,
            )
        }
    }

    internal fun ensureOllamaReadyIfNeeded(settings: com.six2dez.burp.aiagent.config.AgentSettings): Boolean {
        if (settings.preferredBackendId != "ollama") return true
        if (supervisor.isOllamaHealthy(settings)) return true
        val result =
            JOptionPane.showConfirmDialog(
                root,
                "Ollama is not running. Start it now?",
                "Custom AI Agent",
                JOptionPane.YES_NO_OPTION,
            )
        if (result != JOptionPane.YES_OPTION) return false
        if (!settings.ollamaAutoStart) {
            showError("Auto-start for Ollama is disabled in settings.")
            return false
        }
        val ok = supervisor.startOllamaService(settings)
        if (!ok) showError("Failed to start Ollama. Check the command in settings.")
        return ok
    }

    internal fun ensureLmStudioReadyIfNeeded(settings: com.six2dez.burp.aiagent.config.AgentSettings): Boolean {
        if (settings.preferredBackendId != "lmstudio") return true
        if (supervisor.isLmStudioHealthy(settings)) return true

        if (settings.lmStudioAutoStart) {
            val ok = supervisor.startLmStudioService(settings)
            if (!ok) showError("Failed to auto-start LM Studio. Check the command in settings.")
            return ok
        }

        val result =
            JOptionPane.showConfirmDialog(
                root,
                "LM Studio is not running. Start it now?",
                "Custom AI Agent",
                JOptionPane.YES_NO_OPTION,
            )
        if (result != JOptionPane.YES_OPTION) return false

        val ok = supervisor.startLmStudioService(settings)
        if (!ok) showError("Failed to start LM Studio. Check the command in settings.")
        return ok
    }

    private fun ensureBackendReady(settings: com.six2dez.burp.aiagent.config.AgentSettings): Boolean =
        when (settings.preferredBackendId) {
            "ollama" -> ensureOllamaReadyIfNeeded(settings)
            "lmstudio" -> ensureLmStudioReadyIfNeeded(settings)
            else -> true
        }

    /**
     * Called when the Burp project changes (detected via api.project().id() diff).
     * Clears all in-memory state that could bleed across projects.
     */
    private fun onProjectChanged() {
        api.logging().logToOutput("[MainTab] Project change detected — clearing session state and knowledge base")
        // Save current sessions before clearing (they belong to the OLD project)
        chatPanel.saveSessions()
        // Clear in-memory chat sessions and reload from the new project's storage
        chatPanel.clearInMemorySessionState()
        chatPanel.restoreSessions()
        // Clear scanner knowledge base to prevent cross-project contamination
        ScanKnowledgeBase.clear()
        // Clear live backend chat connections (conversation history)
        supervisor.shutdownAllChatSessions()
    }

    fun shutdown() {
        // FIRST, before settingsPanel.shutdown(): App.shutdown() calls mainTab?.shutdown() before
        // mcpSupervisor.shutdown(), so disposing here is what stops a settings write submitted just
        // before unload from starting after the supervisor is gone. It never takes the queue's lock,
        // so it cannot itself block the EDT on an in-flight bounded MCP stop.
        settingsPersistQueue.dispose()
        settingsPanel.shutdown()
        mcpStatusTimer.stop()
        healthTimer?.stop()
        healthTimer = null
        healthExec.shutdownNow()
        sessionPersistTimer?.stop()
        sessionPersistTimer = null
        chatPanel.shutdown()
        chatPanel.saveSessions()
        aiLoggerPanel?.shutdown()
    }
}
