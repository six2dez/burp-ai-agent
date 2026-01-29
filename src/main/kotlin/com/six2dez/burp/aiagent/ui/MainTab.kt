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

    private val mcpToggle = ToggleSwitch()
    private val passiveToggle = ToggleSwitch()
    private val activeToggle = ToggleSwitch()
    private val backendPicker = javax.swing.JComboBox<String>()
    private val backendLabel = JLabel("Backend")
    private val mcpLabel = JLabel("MCP")
    private val mcpStatusLabel = JLabel("MCP: -")

    private val statusLabel = JLabel("Idle")
    private val sessionLabel = JLabel("Session: -")
    private val settingsRepo = AgentSettingsRepository(api)
    private val mcpStatusTimer = Timer(1000) {
        updateMcpBadge()
        updateMcpControls()
    }
    private val baseTabCaption = "AI Agent"
    private var tabbedPane: JTabbedPane? = null
    private var attentionActive = false
    private val dependencyBanner =
        DependencyBanner("MCP Server must be enabled. Toggle MCP to enable AI features.")
    private var syncingToggles = false

    init {
        settingsPanel = SettingsPanel(api, backends, supervisor, audit, mcpSupervisor, passiveAiScanner, activeAiScanner)
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
        backendPicker.model = javax.swing.DefaultComboBoxModel(backends.listBackendIds().toTypedArray())
        backendPicker.selectedItem = settingsRepo.load().preferredBackendId
        backendPicker.addActionListener {
            val selected = backendPicker.selectedItem as? String ?: "codex-cli"
            settingsPanel.setPreferredBackend(selected)
        }

        val initialSettings = settingsRepo.load()
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
        clientGroup.add(sessionLabel)

        actions.add(mcpGroup)
        actions.add(javax.swing.Box.createRigidArea(Dimension(24, 0)))
        actions.add(scannerGroup)
        actions.add(javax.swing.Box.createRigidArea(Dimension(24, 0)))
        actions.add(clientGroup)

        val innerSplit = javax.swing.JSplitPane(
            javax.swing.JSplitPane.HORIZONTAL_SPLIT,
            chatPanel.root,
            settingsPanel.panelComponent()
        )
        innerSplit.resizeWeight = 0.75
        innerSplit.setDividerLocation(0.75)
        innerSplit.border = EmptyBorder(0, 0, 0, 0)

        val center = javax.swing.JSplitPane(
            javax.swing.JSplitPane.HORIZONTAL_SPLIT,
            chatPanel.sessionsComponent(),
            innerSplit
        )
        center.resizeWeight = 0.2
        center.setDividerLocation(0.2)
        center.border = EmptyBorder(0, 0, 0, 0)

        top.add(titleBox, BorderLayout.CENTER)
        top.add(actions, BorderLayout.EAST)

        val north = JPanel(BorderLayout())
        north.background = UiTheme.Colors.surface
        north.add(top, BorderLayout.NORTH)
        north.add(dependencyBanner, BorderLayout.SOUTH)
        root.add(north, BorderLayout.NORTH)
        root.add(center, BorderLayout.CENTER)

        wireActions()
        renderStatus()
        mcpStatusTimer.start()
    }

    private fun notifyResponseReady() {
        SwingUtilities.invokeLater {
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
                        "OpenCode command looks like a bare .exe. If installed via npm, use 'opencode' (without .exe)."
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
}
