package com.six2dez.burp.aiagent.ui.panels

import com.six2dez.burp.aiagent.ui.UiTheme
import java.awt.BorderLayout
import java.awt.CardLayout
import java.awt.GridBagConstraints
import java.awt.GridBagLayout
import java.awt.Insets
import javax.swing.JComponent
import javax.swing.JLabel
import javax.swing.JPanel
import javax.swing.JTextField
import javax.swing.JTextArea
import javax.swing.JScrollPane
import javax.swing.JPasswordField
import javax.swing.JButton
import javax.swing.border.EmptyBorder
import javax.swing.border.LineBorder
import com.six2dez.burp.aiagent.ui.components.ToggleSwitch

data class BackendConfigState(
    val codexCmd: String = "",
    val geminiCmd: String = "",
    val opencodeCmd: String = "",
    val claudeCmd: String = "",
    val ollamaCliCmd: String = "",
    val ollamaModel: String = "",
    val ollamaUrl: String = "",
    val ollamaServeCmd: String = "",
    val ollamaAutoStart: Boolean = false,
    val ollamaApiKey: String = "",
    val ollamaHeaders: String = "",
    val lmStudioUrl: String = "",
    val lmStudioModel: String = "",
    val lmStudioTimeoutSeconds: String = "",
    val lmStudioServerCmd: String = "",
    val lmStudioAutoStart: Boolean = true,
    val lmStudioApiKey: String = "",
    val lmStudioHeaders: String = "",
    val openAiCompatUrl: String = "",
    val openAiCompatModel: String = "",
    val openAiCompatApiKey: String = "",
    val openAiCompatHeaders: String = "",
    val openAiCompatTimeoutSeconds: String = ""
)

class BackendConfigPanel(
    initialState: BackendConfigState = BackendConfigState()
) : JPanel(BorderLayout()) {
    var onOpenCli: ((backendId: String, command: String) -> Unit)? = null
    private val cardLayout = CardLayout()
    private val cards = JPanel(cardLayout)

    private val codexCmd = JTextField(initialState.codexCmd)
    private val geminiCmd = JTextField(initialState.geminiCmd)
    private val opencodeCmd = JTextField(initialState.opencodeCmd)
    private val claudeCmd = JTextField(initialState.claudeCmd)
    private val ollamaCliCmd = JTextField(initialState.ollamaCliCmd)
    private val ollamaModel = JTextField(initialState.ollamaModel)
    private val ollamaUrl = JTextField(initialState.ollamaUrl)
    private val ollamaServeCmd = JTextField(initialState.ollamaServeCmd)
    private val ollamaAutoStart = ToggleSwitch(initialState.ollamaAutoStart)
    private val ollamaApiKey = JPasswordField(initialState.ollamaApiKey)
    private val ollamaHeaders = JTextArea(initialState.ollamaHeaders, 3, 20)
    private val lmStudioUrl = JTextField(initialState.lmStudioUrl)
    private val lmStudioModel = JTextField(initialState.lmStudioModel)
    private val lmStudioTimeout = JTextField(initialState.lmStudioTimeoutSeconds)
    private val lmStudioServeCmd = JTextField(initialState.lmStudioServerCmd)
    private val lmStudioAutoStart = ToggleSwitch(initialState.lmStudioAutoStart)
    private val lmStudioApiKey = JPasswordField(initialState.lmStudioApiKey)
    private val lmStudioHeaders = JTextArea(initialState.lmStudioHeaders, 3, 20)
    private val openAiCompatUrl = JTextField(initialState.openAiCompatUrl)
    private val openAiCompatModel = JTextField(initialState.openAiCompatModel)
    private val openAiCompatApiKey = JPasswordField(initialState.openAiCompatApiKey)
    private val openAiCompatHeaders = JTextArea(initialState.openAiCompatHeaders, 3, 20)
    private val openAiCompatTimeout = JTextField(initialState.openAiCompatTimeoutSeconds)

    init {
        background = UiTheme.Colors.surface
        cards.background = UiTheme.Colors.surface

        applyFieldStyle(codexCmd)
        applyFieldStyle(geminiCmd)
        applyFieldStyle(opencodeCmd)
        applyFieldStyle(claudeCmd)
        applyFieldStyle(ollamaCliCmd)
        applyFieldStyle(ollamaModel)
        applyFieldStyle(ollamaUrl)
        applyFieldStyle(ollamaServeCmd)
        applyFieldStyle(ollamaApiKey)
        applyAreaStyle(ollamaHeaders)
        applyFieldStyle(lmStudioUrl)
        applyFieldStyle(lmStudioModel)
        applyFieldStyle(lmStudioTimeout)
        applyFieldStyle(lmStudioServeCmd)
        applyFieldStyle(lmStudioApiKey)
        applyAreaStyle(lmStudioHeaders)
        applyFieldStyle(openAiCompatUrl)
        applyFieldStyle(openAiCompatModel)
        applyFieldStyle(openAiCompatApiKey)
        applyAreaStyle(openAiCompatHeaders)
        applyFieldStyle(openAiCompatTimeout)

        codexCmd.toolTipText = "Command used to launch Codex CLI."
        geminiCmd.toolTipText = "Command used to launch Gemini CLI."
        opencodeCmd.toolTipText = "Command used to launch OpenCode CLI with the model (e.g., opencode --model anthropic/claude-sonnet-4-5)."
        claudeCmd.toolTipText = "Command used to launch Claude Code CLI (e.g., claude)."
        ollamaCliCmd.toolTipText = "Command used to launch Ollama CLI with a model."
        ollamaModel.toolTipText = "Model name for Ollama HTTP backend. If empty, the CLI command is parsed."
        ollamaUrl.toolTipText = "Base URL for Ollama HTTP backend and health checks."
        ollamaServeCmd.toolTipText = "Command used to start the Ollama server."
        ollamaAutoStart.toolTipText = "Automatically start the Ollama server when needed."
        ollamaApiKey.toolTipText = "API key for Ollama-compatible servers (Authorization: Bearer ...)."
        ollamaHeaders.toolTipText = "Extra headers (one per line: Header: value)."
        lmStudioUrl.toolTipText = "Base URL for LM Studio OpenAI-compatible endpoint."
        lmStudioModel.toolTipText = "Model name sent to LM Studio."
        lmStudioTimeout.toolTipText = "Request timeout in seconds."
        lmStudioServeCmd.toolTipText = "Command used to start the LM Studio server."
        lmStudioAutoStart.toolTipText = "Automatically start the LM Studio server when needed."
        lmStudioApiKey.toolTipText = "API key for LM Studio-compatible servers (Authorization: Bearer ...)."
        lmStudioHeaders.toolTipText = "Extra headers (one per line: Header: value)."
        openAiCompatUrl.toolTipText = "Base URL for OpenAI-compatible HTTP endpoint."
        openAiCompatModel.toolTipText = "Model name sent to the provider."
        openAiCompatApiKey.toolTipText = "API key (Authorization: Bearer ...)."
        openAiCompatHeaders.toolTipText = "Extra headers (one per line: Header: value)."
        openAiCompatTimeout.toolTipText = "Request timeout in seconds."

        cards.add(buildSingleFieldPanelWithCli("Codex CLI command", codexCmd, "codex-cli") { codexCmd.text.trim() }, "codex-cli")
        cards.add(buildSingleFieldPanelWithCli("Gemini CLI command", geminiCmd, "gemini-cli") { geminiCmd.text.trim() }, "gemini-cli")
        cards.add(buildOpenCodePanel(), "opencode-cli")
        cards.add(buildSingleFieldPanelWithCli("Claude Code command", claudeCmd, "claude-cli") { claudeCmd.text.trim() }, "claude-cli")
        cards.add(buildOllamaPanel(), "ollama")
        cards.add(buildLmStudioPanel(), "lmstudio")
        cards.add(buildOpenAiCompatPanel(), "openai-compatible")

        add(cards, BorderLayout.CENTER)
    }

    fun setBackend(id: String) {
        cardLayout.show(cards, id)
    }

    fun currentBackendSettings(): BackendConfigState {
        return BackendConfigState(
            codexCmd = codexCmd.text.trim(),
            geminiCmd = geminiCmd.text.trim(),
            opencodeCmd = opencodeCmd.text.trim(),
            claudeCmd = claudeCmd.text.trim(),
            ollamaCliCmd = ollamaCliCmd.text.trim(),
            ollamaModel = ollamaModel.text.trim(),
            ollamaUrl = ollamaUrl.text.trim(),
            ollamaServeCmd = ollamaServeCmd.text.trim(),
            ollamaAutoStart = ollamaAutoStart.isSelected,
            ollamaApiKey = String(ollamaApiKey.password).trim(),
            ollamaHeaders = ollamaHeaders.text.trim(),
            lmStudioUrl = lmStudioUrl.text.trim(),
            lmStudioModel = lmStudioModel.text.trim(),
            lmStudioTimeoutSeconds = lmStudioTimeout.text.trim(),
            lmStudioServerCmd = lmStudioServeCmd.text.trim(),
            lmStudioAutoStart = lmStudioAutoStart.isSelected,
            lmStudioApiKey = String(lmStudioApiKey.password).trim(),
            lmStudioHeaders = lmStudioHeaders.text.trim(),
            openAiCompatUrl = openAiCompatUrl.text.trim(),
            openAiCompatModel = openAiCompatModel.text.trim(),
            openAiCompatApiKey = String(openAiCompatApiKey.password).trim(),
            openAiCompatHeaders = openAiCompatHeaders.text.trim(),
            openAiCompatTimeoutSeconds = openAiCompatTimeout.text.trim()
        )
    }

    fun applyState(state: BackendConfigState) {
        codexCmd.text = state.codexCmd
        geminiCmd.text = state.geminiCmd
        opencodeCmd.text = state.opencodeCmd
        claudeCmd.text = state.claudeCmd
        ollamaCliCmd.text = state.ollamaCliCmd
        ollamaModel.text = state.ollamaModel
        ollamaUrl.text = state.ollamaUrl
        ollamaServeCmd.text = state.ollamaServeCmd
        ollamaAutoStart.isSelected = state.ollamaAutoStart
        ollamaApiKey.text = state.ollamaApiKey
        ollamaHeaders.text = state.ollamaHeaders
        lmStudioUrl.text = state.lmStudioUrl
        lmStudioModel.text = state.lmStudioModel
        lmStudioTimeout.text = state.lmStudioTimeoutSeconds
        lmStudioServeCmd.text = state.lmStudioServerCmd
        lmStudioAutoStart.isSelected = state.lmStudioAutoStart
        lmStudioApiKey.text = state.lmStudioApiKey
        lmStudioHeaders.text = state.lmStudioHeaders
        openAiCompatUrl.text = state.openAiCompatUrl
        openAiCompatModel.text = state.openAiCompatModel
        openAiCompatApiKey.text = state.openAiCompatApiKey
        openAiCompatHeaders.text = state.openAiCompatHeaders
        openAiCompatTimeout.text = state.openAiCompatTimeoutSeconds
    }

    private fun buildSingleFieldPanel(labelText: String, field: JComponent): JPanel {
        val panel = JPanel(GridBagLayout())
        panel.background = UiTheme.Colors.surface
        panel.border = EmptyBorder(4, 8, 0, 8)
        addRow(panel, 0, labelText, field)
        addVerticalFiller(panel, 1)
        return panel
    }

    private fun buildSingleFieldPanelWithCli(
        labelText: String,
        field: JComponent,
        backendId: String,
        commandProvider: () -> String
    ): JPanel {
        val panel = JPanel(GridBagLayout())
        panel.background = UiTheme.Colors.surface
        panel.border = EmptyBorder(4, 8, 0, 8)
        addRow(panel, 0, labelText, field)
        addButtonRow(panel, 1, buildOpenCliButton(backendId, commandProvider))
        addVerticalFiller(panel, 2)
        return panel
    }

    private fun buildOllamaPanel(): JPanel {
        val panel = JPanel(GridBagLayout())
        panel.background = UiTheme.Colors.surface
        panel.border = EmptyBorder(8, 8, 8, 8)
        var row = 0
        addRow(panel, row++, "Ollama CLI command", ollamaCliCmd)
        addButtonRow(panel, row++, buildOpenCliButton("ollama", { ollamaCliCmd.text.trim() }))
        addRow(panel, row++, "Ollama model", ollamaModel)
        addRow(panel, row++, "Ollama base URL", ollamaUrl)
        addRow(panel, row++, "Ollama API key (Bearer)", ollamaApiKey)
        addRow(panel, row++, "Ollama extra headers", JScrollPane(ollamaHeaders))
        addRow(panel, row++, "Ollama serve command", ollamaServeCmd)
        addToggleRow(panel, row, "Auto-start Ollama server", ollamaAutoStart)
        return panel
    }

    private fun buildOpenCodePanel(): JPanel {
        val panel = JPanel(GridBagLayout())
        panel.background = UiTheme.Colors.surface
        panel.border = EmptyBorder(8, 8, 8, 8)
        addRow(panel, 0, "OpenCode CLI command", opencodeCmd)
        addButtonRow(panel, 1, buildOpenCliButton("opencode-cli", { opencodeCmd.text.trim() }))
        return panel
    }

    private fun buildLmStudioPanel(): JPanel {
        val panel = JPanel(GridBagLayout())
        panel.background = UiTheme.Colors.surface
        panel.border = EmptyBorder(8, 8, 8, 8)
        addRow(panel, 0, "LM Studio base URL", lmStudioUrl)
        addRow(panel, 1, "LM Studio model", lmStudioModel)
        addRow(panel, 2, "LM Studio timeout (seconds)", lmStudioTimeout)
        addRow(panel, 3, "LM Studio serve command", lmStudioServeCmd)
        addRow(panel, 4, "LM Studio API key (Bearer)", lmStudioApiKey)
        addRow(panel, 5, "LM Studio extra headers", JScrollPane(lmStudioHeaders))
        addToggleRow(panel, 6, "Auto-start LM Studio server", lmStudioAutoStart)
        return panel
    }

    private fun buildOpenAiCompatPanel(): JPanel {
        val panel = JPanel(GridBagLayout())
        panel.background = UiTheme.Colors.surface
        panel.border = EmptyBorder(8, 8, 8, 8)
        addRow(panel, 0, "Base URL", openAiCompatUrl)
        addRow(panel, 1, "Model", openAiCompatModel)
        addRow(panel, 2, "API key (Bearer)", openAiCompatApiKey)
        addRow(panel, 3, "Extra headers", JScrollPane(openAiCompatHeaders))
        addRow(panel, 4, "Timeout (seconds)", openAiCompatTimeout)
        addVerticalFiller(panel, 5)
        return panel
    }

    private fun addRow(panel: JPanel, row: Int, labelText: String, field: JComponent) {
        val label = JLabel(labelText)
        label.font = UiTheme.Typography.body
        label.foreground = UiTheme.Colors.onSurface

        val labelConstraints = GridBagConstraints().apply {
            gridx = 0
            gridy = row
            anchor = GridBagConstraints.WEST
            insets = Insets(4, 0, 4, 10)
        }
        val fieldConstraints = GridBagConstraints().apply {
            gridx = 1
            gridy = row
            weightx = 1.0
            fill = GridBagConstraints.HORIZONTAL
            insets = Insets(4, 0, 4, 0)
        }
        panel.add(label, labelConstraints)
        panel.add(field, fieldConstraints)
    }

    private fun addButtonRow(panel: JPanel, row: Int, button: JButton) {
        val labelConstraints = GridBagConstraints().apply {
            gridx = 0
            gridy = row
            anchor = GridBagConstraints.WEST
            insets = Insets(4, 0, 4, 10)
        }
        val buttonConstraints = GridBagConstraints().apply {
            gridx = 1
            gridy = row
            anchor = GridBagConstraints.WEST
            insets = Insets(4, 0, 4, 0)
        }
        panel.add(JLabel(""), labelConstraints)
        panel.add(button, buttonConstraints)
    }

    private fun addToggleRow(panel: JPanel, row: Int, labelText: String, toggle: ToggleSwitch) {
        val label = JLabel(labelText)
        label.font = UiTheme.Typography.body
        label.foreground = UiTheme.Colors.onSurface
        val labelConstraints = GridBagConstraints().apply {
            gridx = 0
            gridy = row
            anchor = GridBagConstraints.WEST
            insets = Insets(6, 0, 4, 10)
        }
        val toggleConstraints = GridBagConstraints().apply {
            gridx = 1
            gridy = row
            anchor = GridBagConstraints.WEST
            insets = Insets(6, 0, 4, 0)
        }
        panel.add(label, labelConstraints)
        panel.add(toggle, toggleConstraints)
    }

    private fun addVerticalFiller(panel: JPanel, row: Int) {
        val filler = JPanel()
        filler.isOpaque = false
        val constraints = GridBagConstraints().apply {
            gridx = 0
            gridy = row
            gridwidth = 2
            weighty = 1.0
            fill = GridBagConstraints.VERTICAL
        }
        panel.add(filler, constraints)
    }

    private fun applyFieldStyle(field: JTextField) {
        field.font = UiTheme.Typography.mono
        field.border = LineBorder(UiTheme.Colors.outline, 1, true)
        field.background = UiTheme.Colors.inputBackground
        field.foreground = UiTheme.Colors.inputForeground
    }

    private fun applyAreaStyle(area: JTextArea) {
        area.font = UiTheme.Typography.mono
        area.border = LineBorder(UiTheme.Colors.outline, 1, true)
        area.background = UiTheme.Colors.inputBackground
        area.foreground = UiTheme.Colors.inputForeground
        area.lineWrap = true
        area.wrapStyleWord = true
    }

    private fun buildOpenCliButton(backendId: String, commandProvider: () -> String): JButton {
        return JButton("Open CLI").apply {
            font = UiTheme.Typography.body
            toolTipText = "Open a terminal with the configured command and MCP tools access."
            addActionListener {
                onOpenCli?.invoke(backendId, commandProvider())
            }
        }
    }

}
