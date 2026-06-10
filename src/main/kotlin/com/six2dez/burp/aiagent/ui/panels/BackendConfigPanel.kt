package com.six2dez.burp.aiagent.ui.panels

import com.six2dez.burp.aiagent.ui.components.ToggleSwitch
import com.six2dez.burp.aiagent.ui.design.DesignTokens
import com.six2dez.burp.aiagent.util.SsrfGuard
import com.six2dez.burp.aiagent.ui.design.addRowFull
import com.six2dez.burp.aiagent.ui.design.addSpacerRow
import com.six2dez.burp.aiagent.ui.design.applyAreaStyle
import com.six2dez.burp.aiagent.ui.design.applyFieldStyle
import com.six2dez.burp.aiagent.ui.design.formGrid
import java.awt.BorderLayout
import java.awt.CardLayout
import java.awt.GridBagConstraints
import java.awt.GridBagLayout
import java.awt.Insets
import javax.swing.JButton
import javax.swing.JComponent
import javax.swing.JLabel
import javax.swing.JPanel
import javax.swing.JPasswordField
import javax.swing.JScrollPane
import javax.swing.JTextArea
import javax.swing.JTextField
import javax.swing.border.EmptyBorder

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
    val ollamaTimeoutSeconds: String = "",
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
    val openAiCompatTimeoutSeconds: String = "",
    val nvidiaNimUrl: String = "https://integrate.api.nvidia.com",
    val nvidiaNimModel: String = "",
    val nvidiaNimApiKey: String = "",
    val nvidiaNimHeaders: String = "",
    val nvidiaNimTimeoutSeconds: String = "",
    val perplexityUrl: String = "https://api.perplexity.ai",
    val perplexityModel: String = "",
    val perplexityApiKey: String = "",
    val perplexityHeaders: String = "",
    val perplexityTimeoutSeconds: String = "",
    val copilotCmd: String = "",
)

class BackendConfigPanel(
    initialState: BackendConfigState = BackendConfigState(),
) : JPanel(BorderLayout()) {
    var onOpenCli: ((backendId: String, command: String) -> Unit)? = null
    var onTestConnection: ((backendId: String) -> Unit)? = null
    private val cardLayout = CardLayout()
    private val cards = JPanel(cardLayout)

    /**
     * SEC-03 / A6: inline, non-blocking SSRF advisory shown when a backend base-URL resolves to a
     * private/link-local/cloud-metadata address. Hidden by default (takes no visible space). Shared
     * across all backend cards via the panel's SOUTH bar — it never blocks saving.
     */
    private val ssrfWarningLabel =
        JLabel("Warning: this URL resolves to a private/internal address — verify this is intentional").apply {
            foreground = DesignTokens.Colors.statusWarning
            isVisible = false
        }

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
    private val ollamaTimeout = JTextField(initialState.ollamaTimeoutSeconds)
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
    private val nvidiaNimUrl = JTextField(initialState.nvidiaNimUrl)
    private val nvidiaNimModel = JTextField(initialState.nvidiaNimModel)
    private val nvidiaNimApiKey = JPasswordField(initialState.nvidiaNimApiKey)
    private val nvidiaNimHeaders = JTextArea(initialState.nvidiaNimHeaders, 3, 20)
    private val nvidiaNimTimeout = JTextField(initialState.nvidiaNimTimeoutSeconds)
    private val perplexityUrl = JTextField(initialState.perplexityUrl)
    private val perplexityModel = JTextField(initialState.perplexityModel)
    private val perplexityApiKey = JPasswordField(initialState.perplexityApiKey)
    private val perplexityHeaders = JTextArea(initialState.perplexityHeaders, 3, 20)
    private val perplexityTimeout = JTextField(initialState.perplexityTimeoutSeconds)
    private val copilotCmd = JTextField(initialState.copilotCmd)

    init {
        background = DesignTokens.Colors.surface
        cards.background = DesignTokens.Colors.surface

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
        applyFieldStyle(ollamaTimeout)
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
        applyFieldStyle(nvidiaNimUrl)
        applyFieldStyle(nvidiaNimModel)
        applyFieldStyle(nvidiaNimApiKey)
        applyAreaStyle(nvidiaNimHeaders)
        applyFieldStyle(nvidiaNimTimeout)
        applyFieldStyle(perplexityUrl)
        applyFieldStyle(perplexityModel)
        applyFieldStyle(perplexityApiKey)
        applyAreaStyle(perplexityHeaders)
        applyFieldStyle(perplexityTimeout)
        applyFieldStyle(copilotCmd)

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
        ollamaTimeout.toolTipText = "Request timeout in seconds (30-3600)."
        lmStudioUrl.toolTipText = "Base URL for LM Studio OpenAI-compatible endpoint."
        lmStudioModel.toolTipText = "Model name sent to LM Studio."
        lmStudioTimeout.toolTipText = "Request timeout in seconds."
        lmStudioServeCmd.toolTipText = "Command used to start the LM Studio server."
        lmStudioAutoStart.toolTipText = "Automatically start the LM Studio server when needed."
        lmStudioApiKey.toolTipText = "API key for LM Studio-compatible servers (Authorization: Bearer ...)."
        lmStudioHeaders.toolTipText = "Extra headers (one per line: Header: value)."
        openAiCompatUrl.toolTipText = "Base URL for OpenAI-compatible HTTP endpoint (include /v1 or /v4 if required)."
        openAiCompatModel.toolTipText = "Model name sent to the provider."
        openAiCompatApiKey.toolTipText = "API key (Authorization: Bearer ...)."
        openAiCompatHeaders.toolTipText = "Extra headers (one per line: Header: value)."
        openAiCompatTimeout.toolTipText = "Request timeout in seconds."
        nvidiaNimUrl.toolTipText = "Base URL for NVIDIA NIM. Leave the default unless you use a custom endpoint."
        nvidiaNimModel.toolTipText = "Model name sent to NVIDIA NIM (for example, moonshotai/kimi-k2.5)."
        nvidiaNimApiKey.toolTipText = "NVIDIA API key (Authorization: Bearer ...)."
        nvidiaNimHeaders.toolTipText = "Extra headers (one per line: Header: value)."
        nvidiaNimTimeout.toolTipText = "Request timeout in seconds."
        perplexityUrl.toolTipText = "Base URL for Perplexity. Leave the default unless you use a custom endpoint."
        perplexityModel.toolTipText = "Model name sent to Perplexity (for example, sonar, sonar-pro, sonar-reasoning)."
        perplexityApiKey.toolTipText = "Perplexity API key (Authorization: Bearer pplx-...)."
        perplexityHeaders.toolTipText = "Extra headers (one per line: Header: value)."
        perplexityTimeout.toolTipText = "Request timeout in seconds."
        copilotCmd.toolTipText = "Command used to launch Copilot CLI (e.g., copilot)."

        cards.add(buildBurpAiPanel(), "burp-ai")
        cards.add(buildSingleFieldPanelWithCli("Codex CLI command", codexCmd, "codex-cli") { codexCmd.text.trim() }, "codex-cli")
        cards.add(buildSingleFieldPanelWithCli("Gemini CLI command", geminiCmd, "gemini-cli") { geminiCmd.text.trim() }, "gemini-cli")
        cards.add(buildOpenCodePanel(), "opencode-cli")
        cards.add(buildSingleFieldPanelWithCli("Claude Code command", claudeCmd, "claude-cli") { claudeCmd.text.trim() }, "claude-cli")
        cards.add(buildOllamaPanel(), "ollama")
        cards.add(buildLmStudioPanel(), "lmstudio")
        cards.add(buildOpenAiCompatPanel(), "openai-compatible")
        cards.add(buildNvidiaNimPanel(), "nvidia-nim")
        cards.add(buildPerplexityPanel(), "perplexity")
        cards.add(buildSingleFieldPanelWithCli("Copilot CLI command", copilotCmd, "copilot-cli") { copilotCmd.text.trim() }, "copilot-cli")

        add(cards, BorderLayout.CENTER)

        // SEC-03 / A6: shared SSRF advisory bar, always present but only visible when the warning
        // fires. Placed outside the CardLayout so it shows regardless of which backend card is up.
        val ssrfWarningBar =
            JPanel(BorderLayout()).apply {
                background = DesignTokens.Colors.surface
                border =
                    EmptyBorder(0, DesignTokens.Spacing.sectionPad, DesignTokens.Spacing.sm, DesignTokens.Spacing.sectionPad)
                add(ssrfWarningLabel, BorderLayout.WEST)
            }
        add(ssrfWarningBar, BorderLayout.SOUTH)
    }

    /**
     * SEC-03 / A6: toggles the inline SSRF advisory based on the supplied URL field values. Pure UI
     * side effect — never blocks; the settings are saved regardless.
     */
    private fun checkAndShowSsrfWarning(urls: List<String>) {
        ssrfWarningLabel.isVisible = urls.any { it.isNotBlank() && SsrfGuard.isPrivateOrLinkLocal(it) }
    }

    fun setBackend(id: String) {
        cardLayout.show(cards, id)
    }

    fun currentBackendSettings(): BackendConfigState {
        // SEC-03 / A6: fire the non-blocking SSRF advisory whenever settings are collected (Save).
        checkAndShowSsrfWarning(
            listOf(
                ollamaUrl.text,
                lmStudioUrl.text,
                openAiCompatUrl.text,
                nvidiaNimUrl.text,
                perplexityUrl.text,
            ),
        )
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
            ollamaTimeoutSeconds = ollamaTimeout.text.trim(),
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
            openAiCompatTimeoutSeconds = openAiCompatTimeout.text.trim(),
            nvidiaNimUrl = nvidiaNimUrl.text.trim(),
            nvidiaNimModel = nvidiaNimModel.text.trim(),
            nvidiaNimApiKey = String(nvidiaNimApiKey.password).trim(),
            nvidiaNimHeaders = nvidiaNimHeaders.text.trim(),
            nvidiaNimTimeoutSeconds = nvidiaNimTimeout.text.trim(),
            perplexityUrl = perplexityUrl.text.trim(),
            perplexityModel = perplexityModel.text.trim(),
            perplexityApiKey = String(perplexityApiKey.password).trim(),
            perplexityHeaders = perplexityHeaders.text.trim(),
            perplexityTimeoutSeconds = perplexityTimeout.text.trim(),
            copilotCmd = copilotCmd.text.trim(),
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
        ollamaTimeout.text = state.ollamaTimeoutSeconds
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
        nvidiaNimUrl.text = state.nvidiaNimUrl
        nvidiaNimModel.text = state.nvidiaNimModel
        nvidiaNimApiKey.text = state.nvidiaNimApiKey
        nvidiaNimHeaders.text = state.nvidiaNimHeaders
        nvidiaNimTimeout.text = state.nvidiaNimTimeoutSeconds
        perplexityUrl.text = state.perplexityUrl
        perplexityModel.text = state.perplexityModel
        perplexityApiKey.text = state.perplexityApiKey
        perplexityHeaders.text = state.perplexityHeaders
        perplexityTimeout.text = state.perplexityTimeoutSeconds
        copilotCmd.text = state.copilotCmd
        // IN-03: show the SSRF advisory immediately on load so a previously-saved private-range
        // URL is flagged without requiring the user to click Save first.
        checkAndShowSsrfWarning(
            listOf(
                state.ollamaUrl,
                state.lmStudioUrl,
                state.openAiCompatUrl,
                state.nvidiaNimUrl,
                state.perplexityUrl,
            ),
        )
    }

    private fun buildSingleFieldPanel(
        labelText: String,
        field: JComponent,
    ): JPanel {
        val panel = formGrid()
        panel.border = EmptyBorder(DesignTokens.Spacing.sectionPad, DesignTokens.Spacing.sectionPad, 0, DesignTokens.Spacing.sectionPad)
        addRowFull(panel, labelText, field)
        addSpacerRow(panel, DesignTokens.Spacing.sm)
        return panel
    }

    private fun buildSingleFieldPanelWithCli(
        labelText: String,
        field: JComponent,
        backendId: String,
        commandProvider: () -> String,
    ): JPanel {
        val panel = formGrid()
        panel.border = EmptyBorder(DesignTokens.Spacing.sectionPad, DesignTokens.Spacing.sectionPad, 0, DesignTokens.Spacing.sectionPad)
        addRowFull(panel, labelText, field)
        addRowFull(
            panel,
            "",
            buildButtonRowPanel(
                buildOpenCliButton(backendId, commandProvider),
                buildTestConnectionButton(backendId),
            ),
        )
        addSpacerRow(panel, DesignTokens.Spacing.sm)
        return panel
    }

    private fun buildBurpAiPanel(): JPanel {
        val panel = formGrid()
        panel.border = EmptyBorder(DesignTokens.Spacing.sectionPad, DesignTokens.Spacing.sectionPad, DesignTokens.Spacing.sectionPad, DesignTokens.Spacing.sectionPad)

        val info =
            JTextArea(
                "Burp AI uses the built-in AI provider. No configuration needed.\n\n" +
                    "Requires Burp Suite Professional with AI features enabled.\n" +
                    "Go to Extensions > Settings and enable 'Use AI'.",
            ).apply {
                isEditable = false
                isOpaque = false
                lineWrap = true
                wrapStyleWord = true
                font = DesignTokens.Typography.body
                border = null
            }
        val gbc =
            GridBagConstraints().apply {
                gridx = 0
                gridy = (panel.getClientProperty("row") as? Int) ?: 0
                gridwidth = 4
                fill = GridBagConstraints.HORIZONTAL
                insets = Insets(DesignTokens.Spacing.xs, 0, DesignTokens.Spacing.xs, 0)
                weightx = 1.0
            }
        panel.putClientProperty("row", (gbc.gridy + 1))
        panel.add(info, gbc)
        addSpacerRow(panel, DesignTokens.Spacing.sm)
        return panel
    }

    private fun buildOllamaPanel(): JPanel {
        val panel = formGrid()
        panel.border = EmptyBorder(DesignTokens.Spacing.sectionPad, DesignTokens.Spacing.sectionPad, DesignTokens.Spacing.sectionPad, DesignTokens.Spacing.sectionPad)
        addRowFull(panel, "Ollama CLI command", ollamaCliCmd)
        addRowFull(
            panel,
            "",
            buildButtonRowPanel(
                buildOpenCliButton("ollama", { ollamaCliCmd.text.trim() }),
                buildTestConnectionButton("ollama"),
            ),
        )
        addRowFull(panel, "Ollama model", ollamaModel)
        addRowFull(panel, "Ollama base URL", ollamaUrl)
        addRowFull(panel, "Ollama API key (Bearer)", ollamaApiKey)
        addRowFull(panel, "Ollama extra headers", JScrollPane(ollamaHeaders))
        addRowFull(panel, "Ollama timeout (seconds)", ollamaTimeout)
        addRowFull(panel, "Ollama serve command", ollamaServeCmd)
        addRowFull(panel, "Auto-start Ollama server", ollamaAutoStart)
        return panel
    }

    private fun buildOpenCodePanel(): JPanel {
        val panel = formGrid()
        panel.border = EmptyBorder(DesignTokens.Spacing.sectionPad, DesignTokens.Spacing.sectionPad, DesignTokens.Spacing.sectionPad, DesignTokens.Spacing.sectionPad)
        addRowFull(panel, "OpenCode CLI command", opencodeCmd)
        addRowFull(
            panel,
            "",
            buildButtonRowPanel(
                buildOpenCliButton("opencode-cli", { opencodeCmd.text.trim() }),
                buildTestConnectionButton("opencode-cli"),
            ),
        )
        return panel
    }

    private fun buildLmStudioPanel(): JPanel {
        val panel = formGrid()
        panel.border = EmptyBorder(DesignTokens.Spacing.sectionPad, DesignTokens.Spacing.sectionPad, DesignTokens.Spacing.sectionPad, DesignTokens.Spacing.sectionPad)
        addRowFull(panel, "LM Studio base URL", lmStudioUrl)
        addRowFull(panel, "", buildButtonRowPanel(buildTestConnectionButton("lmstudio")))
        addRowFull(panel, "LM Studio model", lmStudioModel)
        addRowFull(panel, "LM Studio timeout (seconds)", lmStudioTimeout)
        addRowFull(panel, "LM Studio serve command", lmStudioServeCmd)
        addRowFull(panel, "LM Studio API key (Bearer)", lmStudioApiKey)
        addRowFull(panel, "LM Studio extra headers", JScrollPane(lmStudioHeaders))
        addRowFull(panel, "Auto-start LM Studio server", lmStudioAutoStart)
        return panel
    }

    private fun buildOpenAiCompatPanel(): JPanel {
        val panel = formGrid()
        panel.border = EmptyBorder(DesignTokens.Spacing.sectionPad, DesignTokens.Spacing.sectionPad, DesignTokens.Spacing.sectionPad, DesignTokens.Spacing.sectionPad)
        addRowFull(panel, "Base URL", openAiCompatUrl)
        addRowFull(panel, "", buildButtonRowPanel(buildTestConnectionButton("openai-compatible")))
        addRowFull(panel, "Model", openAiCompatModel)
        addRowFull(panel, "API key (Bearer)", openAiCompatApiKey)
        addRowFull(panel, "Extra headers", JScrollPane(openAiCompatHeaders))
        addRowFull(panel, "Timeout (seconds)", openAiCompatTimeout)
        addSpacerRow(panel, DesignTokens.Spacing.sm)
        return panel
    }

    private fun buildNvidiaNimPanel(): JPanel {
        val panel = formGrid()
        panel.border = EmptyBorder(DesignTokens.Spacing.sectionPad, DesignTokens.Spacing.sectionPad, DesignTokens.Spacing.sectionPad, DesignTokens.Spacing.sectionPad)
        addRowFull(panel, "Base URL", nvidiaNimUrl)
        addRowFull(panel, "", buildButtonRowPanel(buildTestConnectionButton("nvidia-nim")))
        addRowFull(panel, "Model", nvidiaNimModel)
        addRowFull(panel, "API key (Bearer)", nvidiaNimApiKey)
        addRowFull(panel, "Extra headers", JScrollPane(nvidiaNimHeaders))
        addRowFull(panel, "Timeout (seconds)", nvidiaNimTimeout)
        addSpacerRow(panel, DesignTokens.Spacing.sm)
        return panel
    }

    private fun buildPerplexityPanel(): JPanel {
        val panel = formGrid()
        panel.border = EmptyBorder(DesignTokens.Spacing.sectionPad, DesignTokens.Spacing.sectionPad, DesignTokens.Spacing.sectionPad, DesignTokens.Spacing.sectionPad)
        addRowFull(panel, "Base URL", perplexityUrl)
        addRowFull(panel, "", buildButtonRowPanel(buildTestConnectionButton("perplexity")))
        addRowFull(panel, "Model", perplexityModel)
        addRowFull(panel, "API key (Bearer)", perplexityApiKey)
        addRowFull(panel, "Extra headers", JScrollPane(perplexityHeaders))
        addRowFull(panel, "Timeout (seconds)", perplexityTimeout)
        addSpacerRow(panel, DesignTokens.Spacing.sm)
        return panel
    }

    private fun buildOpenCliButton(
        backendId: String,
        commandProvider: () -> String,
    ): JButton =
        JButton("Open CLI").apply {
            font = DesignTokens.Typography.body
            toolTipText = "Open a terminal with the configured command and MCP tools access."
            addActionListener {
                onOpenCli?.invoke(backendId, commandProvider())
            }
        }

    private fun buildTestConnectionButton(backendId: String): JButton =
        JButton("Test connection").apply {
            font = DesignTokens.Typography.body
            toolTipText = "Run backend health check with current settings."
            addActionListener {
                onTestConnection?.invoke(backendId)
            }
        }

    private fun buildButtonRowPanel(vararg buttons: JButton): JPanel =
        JPanel().apply {
            layout = javax.swing.BoxLayout(this, javax.swing.BoxLayout.X_AXIS)
            isOpaque = false
            background = DesignTokens.Colors.surface
            buttons.forEachIndexed { index, button ->
                add(button)
                if (index < buttons.lastIndex) {
                    add(javax.swing.Box.createRigidArea(java.awt.Dimension(DesignTokens.Spacing.sm, 0)))
                }
            }
        }
}
