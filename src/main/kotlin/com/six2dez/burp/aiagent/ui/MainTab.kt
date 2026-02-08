package com.six2dez.burp.aiagent.ui

import burp.api.montoya.MontoyaApi
import com.six2dez.burp.aiagent.audit.AuditLogger
import com.six2dez.burp.aiagent.backends.BackendRegistry
import com.six2dez.burp.aiagent.config.AgentSettingsRepository
import com.six2dez.burp.aiagent.context.ContextCapture
import com.six2dez.burp.aiagent.mcp.McpSupervisor
import com.six2dez.burp.aiagent.supervisor.AgentSupervisor
import com.six2dez.burp.aiagent.ui.components.DependencyBanner
import com.six2dez.burp.aiagent.ui.components.ToggleSwitch
import java.awt.BorderLayout
import java.awt.Dimension
import java.awt.Graphics
import java.awt.Graphics2D
import java.awt.RenderingHints
import java.awt.event.KeyEvent
import javax.swing.BoxLayout
import javax.swing.JComponent
import javax.swing.JLabel
import javax.swing.JPanel
import javax.swing.JOptionPane
import javax.swing.JTabbedPane
import javax.swing.SwingUtilities
import javax.swing.Timer
import javax.swing.border.EmptyBorder

class MainTab(
    private val api: MontoyaApi,
    private val backends: BackendRegistry,
    private val supervisor: AgentSupervisor,
    private val audit: AuditLogger,
    private val mcpSupervisor: McpSupervisor,
    private val passiveAiScanner: com.six2dez.burp.aiagent.scanner.PassiveAiScanner,
    private val activeAiScanner: com.six2dez.burp.aiagent.scanner.ActiveAiScanner
) {
    val root: JComponent = JPanel(BorderLayout())
    private lateinit var settingsPanel: SettingsPanel
    private lateinit var chatPanel: ChatPanel
    private lateinit var bottomTabsPanel: BottomTabsPanel

    private val mcpToggle = ToggleSwitch()
    private val passiveToggle = ToggleSwitch()
    private val activeToggle = ToggleSwitch()
    private val backendPicker = javax.swing.JComboBox<String>()
    private val backendLabel = JLabel("Backend")
    private val mcpLabel = JLabel("MCP")
    private val mcpStatusLabel = JLabel("MCP: -")
    private val backendStatusLabel = JLabel("AI: ?")
    private val activeScanStatsLabel = JLabel("Scans: 0 | Vulns: 0")

    private val statusLabel = JLabel("Idle")
    private val sessionLabel = JLabel("Session: -")
    private val settingsRepo = AgentSettingsRepository(api)
    private val mcpStatusTimer = Timer(1000) {
        updateMcpBadge()
        updateMcpControls()
        updateBackendBadge()
        updateActiveScanStats()
    }
    private val baseTabCaption = "AI Agent"
    private var tabbedPane: JTabbedPane? = null
    private var attentionActive = false
    private val dependencyBanner =
        DependencyBanner("MCP Server must be enabled. Toggle MCP to enable AI features.")
    private var syncingToggles = false
    private var healthTimer: Timer? = null
    private var sessionPersistTimer: Timer? = null

    init {
        settingsPanel = SettingsPanel(api, backends, supervisor, audit, mcpSupervisor, passiveAiScanner, activeAiScanner)
        bottomTabsPanel = BottomTabsPanel(settingsPanel)
        chatPanel = ChatPanel(
            api = api,
            supervisor = supervisor,
            getSettings = { settingsPanel.currentSettings() },
            applySettings = { settings ->
                settingsRepo.save(settings)
                supervisor.applySettings(settings)
            },
            validateBackend = { validateBackendCommand(it) },
            ensureBackendReady = { ensureBackendReady(it) },
            showError = { showError(it) },
            onStatusChanged = { refreshStatus() },
            onResponseReady = { notifyResponseReady() }
        )
        root.background = UiTheme.Colors.surface

        val top = HeaderPanel()
        top.layout = BorderLayout()
        top.border = EmptyBorder(14, 16, 14, 16)

        val title = JLabel("Burp AI Agent")
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

        val actions = JPanel()
        actions.layout = BoxLayout(actions, BoxLayout.X_AXIS)
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
        backendPicker.model = javax.swing.DefaultComboBoxModel(backends.listBackendIds(initialSettings).toTypedArray())
        backendPicker.selectedItem = initialSettings.preferredBackendId
        backendPicker.addActionListener {
            val selected = backendPicker.selectedItem as? String ?: "codex-cli"
            settingsPanel.setPreferredBackend(selected)
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
        // Check health in background every 5s, not every 1s to avoid spam
        healthTimer = Timer(5000) {
            val settings = settingsPanel.currentSettings()
            Thread {
                val healthy = supervisor.isBackendHealthy(settings)
                SwingUtilities.invokeLater {
                    backendStatusLabel.text = if(healthy) "AI: OK" else "AI: Offline"
                    backendStatusLabel.background = if(healthy) UiTheme.Colors.statusRunning else UiTheme.Colors.statusCrashed
                }
            }.start()
        }
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

        actions.add(mcpGroup)
        actions.add(javax.swing.Box.createRigidArea(Dimension(24, 0)))
        actions.add(scannerGroup)
        actions.add(javax.swing.Box.createRigidArea(Dimension(24, 0)))
        actions.add(clientGroup)

        val mainContent = javax.swing.JSplitPane(
            javax.swing.JSplitPane.HORIZONTAL_SPLIT,
            chatPanel.sessionsComponent(),
            chatPanel.root
        )
        mainContent.resizeWeight = 0.2
        mainContent.setDividerLocation(0.2)
        mainContent.border = EmptyBorder(0, 0, 0, 0)

        val center = javax.swing.JSplitPane(
            javax.swing.JSplitPane.VERTICAL_SPLIT,
            mainContent,
            bottomTabsPanel.root
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
        val meta = java.awt.Toolkit.getDefaultToolkit().menuShortcutKeyMaskEx

        imap.put(javax.swing.KeyStroke.getKeyStroke(KeyEvent.VK_N, meta), "newSession")
        amap.put("newSession", object : javax.swing.AbstractAction() {
            override fun actionPerformed(e: java.awt.event.ActionEvent?) { chatPanel.createNewSession() }
        })
        imap.put(javax.swing.KeyStroke.getKeyStroke(KeyEvent.VK_W, meta), "deleteSession")
        amap.put("deleteSession", object : javax.swing.AbstractAction() {
            override fun actionPerformed(e: java.awt.event.ActionEvent?) { chatPanel.deleteCurrentSession() }
        })
        imap.put(javax.swing.KeyStroke.getKeyStroke(KeyEvent.VK_L, meta), "clearChat")
        amap.put("clearChat", object : javax.swing.AbstractAction() {
            override fun actionPerformed(e: java.awt.event.ActionEvent?) { chatPanel.clearCurrentChat() }
        })
        imap.put(javax.swing.KeyStroke.getKeyStroke(KeyEvent.VK_E, meta), "exportChat")
        amap.put("exportChat", object : javax.swing.AbstractAction() {
            override fun actionPerformed(e: java.awt.event.ActionEvent?) { chatPanel.exportCurrentChatAsMarkdown() }
        })
        imap.put(javax.swing.KeyStroke.getKeyStroke(KeyEvent.VK_ESCAPE, 0), "toggleSettings")
        amap.put("toggleSettings", object : javax.swing.AbstractAction() {
            override fun actionPerformed(e: java.awt.event.ActionEvent?) { bottomTabsPanel.toggle() }
        })

        wireActions()
        renderStatus()
        mcpStatusTimer.start()

        // Restore persisted chat sessions
        chatPanel.restoreSessions()

        // Auto-save sessions every 30 seconds and update usage stats
        sessionPersistTimer = Timer(30_000) {
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
            val settings = settingsPanel.currentSettings()
            val updated = settings.copy(mcpSettings = settings.mcpSettings.copy(enabled = enabled))
            settingsRepo.save(updated)
            mcpSupervisor.applySettings(updated.mcpSettings, updated.privacyMode, updated.determinismMode)
            renderStatus()
        }
        settingsPanel.onPassiveAiEnabledChanged = passiveSync@{ enabled ->
            if (syncingToggles) return@passiveSync
            syncingToggles = true
            passiveToggle.isSelected = enabled
            syncingToggles = false
            settingsRepo.save(settingsPanel.currentSettings())
            renderStatus()
        }
        settingsPanel.onActiveAiEnabledChanged = activeSync@{ enabled ->
            if (syncingToggles) return@activeSync
            syncingToggles = true
            activeToggle.isSelected = enabled
            syncingToggles = false
            settingsRepo.save(settingsPanel.currentSettings())
            renderStatus()
        }

        mcpToggle.addActionListener {
            if (syncingToggles) return@addActionListener
            val enabled = mcpToggle.isSelected
            syncingToggles = true
            settingsPanel.setMcpEnabled(enabled)
            syncingToggles = false
            val settings = settingsPanel.currentSettings()
            val updated = settings.copy(mcpSettings = settings.mcpSettings.copy(enabled = enabled))
            settingsRepo.save(updated)
            mcpSupervisor.applySettings(updated.mcpSettings, updated.privacyMode, updated.determinismMode)
            renderStatus()
        }
        passiveToggle.addActionListener {
            if (syncingToggles) return@addActionListener
            val enabled = passiveToggle.isSelected
            syncingToggles = true
            settingsPanel.setPassiveAiEnabled(enabled)
            syncingToggles = false
            settingsRepo.save(settingsPanel.currentSettings())
            renderStatus()
        }
        activeToggle.addActionListener {
            if (syncingToggles) return@addActionListener
            val enabled = activeToggle.isSelected
            syncingToggles = true
            settingsPanel.setActiveAiEnabled(enabled)
            syncingToggles = false
            settingsRepo.save(settingsPanel.currentSettings())
            renderStatus()
        }
        settingsPanel.onSettingsChanged = { updated ->
            SwingUtilities.invokeLater {
                val available = backends.listBackendIds(updated)
                backendPicker.model = javax.swing.DefaultComboBoxModel(available.toTypedArray())
                if (available.contains(updated.preferredBackendId)) {
                    backendPicker.selectedItem = updated.preferredBackendId
                }
            }
        }
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
        }
    }

    fun currentSettings() = settingsRepo.load()

    fun currentSessionId(): String? = supervisor.currentSessionId()

    fun openChatWithContext(capture: ContextCapture, promptTemplate: String, actionName: String) {
        chatPanel.startSessionFromContext(capture, promptTemplate, actionName)
    }

    fun refreshStatus() {
        renderStatus()
    }

    private fun updateMcpControls() {
        val mcpState = mcpSupervisor.status()
        val running = mcpState is com.six2dez.burp.aiagent.mcp.McpServerState.Running
        val busy = mcpState is com.six2dez.burp.aiagent.mcp.McpServerState.Starting ||
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
        val text = when (state) {
            is com.six2dez.burp.aiagent.mcp.McpServerState.Running -> "MCP: Running"
            is com.six2dez.burp.aiagent.mcp.McpServerState.Starting -> "MCP: Starting"
            is com.six2dez.burp.aiagent.mcp.McpServerState.Stopping -> "MCP: Stopping"
            is com.six2dez.burp.aiagent.mcp.McpServerState.Failed -> {
                if (isBindFailure(state.exception)) "MCP: Port in use" else "MCP: Error"
            }
            else -> "MCP: Stopped"
        }
        mcpStatusLabel.text = text
        mcpStatusLabel.background = when (state) {
            is com.six2dez.burp.aiagent.mcp.McpServerState.Running -> UiTheme.Colors.statusRunning
            is com.six2dez.burp.aiagent.mcp.McpServerState.Failed -> UiTheme.Colors.statusCrashed
            is com.six2dez.burp.aiagent.mcp.McpServerState.Starting -> UiTheme.Colors.statusTerminal
            is com.six2dez.burp.aiagent.mcp.McpServerState.Stopping -> UiTheme.Colors.statusTerminal
            else -> UiTheme.Colors.outlineVariant
        }
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
        val text = if (status.scanning) {
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
        val color = when (state) {
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

    internal fun validateBackendCommand(settings: com.six2dez.burp.aiagent.config.AgentSettings): String? {
        return when (settings.preferredBackendId) {
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
            "ollama" -> if (settings.ollamaCliCmd.isBlank()) "Ollama CLI command is empty." else null
            "lmstudio" -> if (settings.lmStudioUrl.isBlank()) "LM Studio URL is empty." else null
            "openai-compatible" -> {
                when {
                    settings.openAiCompatibleUrl.isBlank() -> "OpenAI-compatible URL is empty."
                    settings.openAiCompatibleModel.isBlank() -> "OpenAI-compatible model is empty."
                    else -> null
                }
            }
            else -> "Unsupported backend: ${settings.preferredBackendId}"
        }
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
                "AI Agent",
                JOptionPane.ERROR_MESSAGE
            )
        }
    }

    internal fun ensureOllamaReadyIfNeeded(settings: com.six2dez.burp.aiagent.config.AgentSettings): Boolean {
        if (settings.preferredBackendId != "ollama") return true
        if (supervisor.isOllamaHealthy(settings)) return true
        val result = JOptionPane.showConfirmDialog(
            root,
            "Ollama is not running. Start it now?",
            "AI Agent",
            JOptionPane.YES_NO_OPTION
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

        val result = JOptionPane.showConfirmDialog(
            root,
            "LM Studio is not running. Start it now?",
            "AI Agent",
            JOptionPane.YES_NO_OPTION
        )
        if (result != JOptionPane.YES_OPTION) return false
        
        val ok = supervisor.startLmStudioService(settings)
        if (!ok) showError("Failed to start LM Studio. Check the command in settings.")
        return ok
    }

    private fun ensureBackendReady(settings: com.six2dez.burp.aiagent.config.AgentSettings): Boolean {
        return when (settings.preferredBackendId) {
            "ollama" -> ensureOllamaReadyIfNeeded(settings)
            "lmstudio" -> ensureLmStudioReadyIfNeeded(settings)
            else -> true
        }
    }

    fun shutdown() {
        mcpStatusTimer.stop()
        healthTimer?.stop()
        healthTimer = null
        sessionPersistTimer?.stop()
        sessionPersistTimer = null
        chatPanel.saveSessions()
    }
}
