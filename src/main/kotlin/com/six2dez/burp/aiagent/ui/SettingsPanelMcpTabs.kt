package com.six2dez.burp.aiagent.ui

import burp.api.montoya.core.BurpSuiteEdition
import com.six2dez.burp.aiagent.mcp.McpToolCatalog
import com.six2dez.burp.aiagent.redact.PrivacyMode
import com.six2dez.burp.aiagent.ui.components.AccordionPanel
import com.six2dez.burp.aiagent.ui.components.SubtleNotice
import com.six2dez.burp.aiagent.ui.design.DesignTokens
import com.six2dez.burp.aiagent.ui.design.applyFieldStyle
import com.six2dez.burp.aiagent.ui.design.buildTabPanel
import com.six2dez.burp.aiagent.ui.design.helpLabel
import com.six2dez.burp.aiagent.ui.design.secondaryButton
import com.six2dez.burp.aiagent.ui.design.sectionPanel
import com.six2dez.burp.aiagent.ui.design.toolBadge
import com.six2dez.burp.aiagent.ui.panels.McpConfigPanel
import java.awt.BorderLayout
import java.awt.Toolkit
import java.awt.datatransfer.StringSelection
import javax.swing.Box
import javax.swing.BoxLayout
import javax.swing.JButton
import javax.swing.JCheckBox
import javax.swing.JLabel
import javax.swing.JPanel
import javax.swing.JScrollPane
import javax.swing.JTextField
import javax.swing.border.EmptyBorder
import javax.swing.border.LineBorder
import javax.swing.event.DocumentEvent
import javax.swing.event.DocumentListener

internal fun SettingsPanel.mcpSection(): JPanel {
    val mcpPanel =
        McpConfigPanel(
            mcpEnabled = mcpEnabled,
            mcpHost = mcpHost,
            mcpPort = mcpPort,
            mcpExternal = mcpExternal,
            mcpStdio = mcpStdio,
            // 07-03 D-03: pass the new scope-only checkbox into McpConfigPanel.
            mcpScopeOnlyCheckbox = mcpScopeOnly,
            mcpTlsEnabled = mcpTlsEnabled,
            mcpTlsAuto = mcpTlsAuto,
            mcpKeystorePath = mcpKeystorePath,
            mcpKeystorePassword = mcpKeystorePassword,
            mcpAllowedOrigins =
                JScrollPane(mcpAllowedOrigins).apply {
                    border = LineBorder(DesignTokens.Colors.border, 1, true)
                    verticalScrollBarPolicy = JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED
                    horizontalScrollBarPolicy = JScrollPane.HORIZONTAL_SCROLLBAR_NEVER
                },
            mcpNotice = mcpNotice,
            mcpMaxConcurrent = mcpMaxConcurrent,
            // 07-02 D-02: McpConfigPanel constructor param name is preserved to minimise the
            // refactor; only the bound variable changes to the KB-denominated spinner.
            mcpMaxBodyMb = mcpMaxBodyKb,
            mcpProxyHistoryMaxItems = mcpProxyHistoryMaxItems,
            mcpProxyHistorySortOrder = mcpProxyHistorySortOrder,
            mcpAllowUnpreprocessedProxyHistory = mcpAllowUnpreprocessedProxyHistory,
            mcpUnsafe = mcpUnsafe,
            preprocessProxyHistory = preprocessProxyHistory,
            preprocessMaxResponseSizeKb = preprocessMaxResponseSizeKb,
            preprocessFilterBinaryContent = preprocessFilterBinaryContent,
            preprocessAllowedContentTypes =
                JScrollPane(preprocessAllowedContentTypes).apply {
                    border = LineBorder(DesignTokens.Colors.border, 1, true)
                    verticalScrollBarPolicy = JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED
                    horizontalScrollBarPolicy = JScrollPane.HORIZONTAL_SCROLLBAR_NEVER
                },
            tokenPanelFactory = ::tokenPanel,
            quickActionsFactory = ::mcpQuickActions,
        ).build()

    // Phase 16-05: append ExternalServersPanel accordion below the McpConfigPanel section.
    val externalPanel = externalServersPanel.buildPanel()
    return JPanel().apply {
        layout = BoxLayout(this, BoxLayout.Y_AXIS)
        background = DesignTokens.Colors.surface
        add(mcpPanel)
        add(externalPanel)
    }
}

internal fun SettingsPanel.tokenPanel(): JPanel {
    val panel = JPanel()
    panel.layout = BoxLayout(panel, BoxLayout.X_AXIS)
    panel.background = DesignTokens.Colors.surface
    panel.add(mcpToken)
    panel.add(Box.createRigidArea(java.awt.Dimension(8, 0)))
    panel.add(mcpTokenRegenerate)
    return panel
}

internal fun SettingsPanel.mcpQuickActions(): JPanel {
    val panel = JPanel()
    panel.layout = BoxLayout(panel, BoxLayout.X_AXIS)
    panel.background = DesignTokens.Colors.surface

    val copyUrl = JButton("Copy SSE URL")
    val copyToken = JButton("Copy Token")
    val copyCurl = JButton("Copy curl")

    listOf(copyUrl, copyToken, copyCurl).forEach { btn ->
        btn.font = DesignTokens.Typography.label
        btn.isFocusPainted = false
        btn.background = DesignTokens.Colors.surface
        btn.foreground = DesignTokens.Colors.primary
        btn.border = LineBorder(DesignTokens.Colors.border, 1, true)
    }

    copyUrl.addActionListener { copyToClipboard(buildSseUrl()) }
    copyToken.addActionListener { copyToClipboard(mcpToken.text.trim()) }
    copyCurl.addActionListener { copyToClipboard(buildCurlCommand()) }

    panel.add(copyUrl)
    panel.add(Box.createRigidArea(java.awt.Dimension(8, 0)))
    panel.add(copyToken)
    panel.add(Box.createRigidArea(java.awt.Dimension(8, 0)))
    panel.add(copyCurl)
    return panel
}

internal fun SettingsPanel.buildSseUrl(): String {
    val scheme = if (mcpTlsEnabled.isSelected) "https" else "http"
    val host = mcpHost.text.trim().ifBlank { "127.0.0.1" }
    val port = (mcpPort.value as? Int) ?: 9876
    return "$scheme://$host:$port/sse"
}

internal fun SettingsPanel.buildCurlCommand(): String {
    val url = buildSseUrl()
    val token = mcpToken.text.trim()
    val header =
        if (mcpExternal.isSelected && token.isNotBlank()) {
            "-H \"Authorization: Bearer $token\" "
        } else {
            ""
        }
    return "curl -v ${header}$url"
}

internal fun SettingsPanel.copyToClipboard(text: String) {
    if (text.isBlank()) return
    val clipboard = Toolkit.getDefaultToolkit().systemClipboard
    clipboard.setContents(StringSelection(text), null)
}

@Suppress("LongMethod")
internal fun SettingsPanel.buildMcpToolsPanel(): JScrollPane {
    // STEP 1 — Shared state (UI-07: unchanged from original)
    val effectiveToggles = McpToolCatalog.mergeWithDefaults(settings.mcpSettings.toolToggles)
    val edition = api.burpSuite().version().edition()
    val unsafeEnabled = mcpUnsafe.isSelected
    val unsafeAllowlist = settings.mcpSettings.enabledUnsafeTools
    val grouping = McpToolTabModel.groupTools(McpToolCatalog.available())

    // STEP 2 — Search bar panel (full-width, above both sections)
    val searchField = JTextField()
    applyFieldStyle(searchField)
    searchField.toolTipText = "Search tools by name or description…"
    searchField.maximumSize = java.awt.Dimension(Int.MAX_VALUE, searchField.preferredSize.height)
    val totalTools = McpToolCatalog.available().size
    val resultCountLabel = helpLabel("$totalTools tools")
    val searchBarPanel =
        JPanel().apply {
            layout = BoxLayout(this, BoxLayout.X_AXIS)
            background = DesignTokens.Colors.surface
            border = EmptyBorder(0, 0, DesignTokens.Spacing.lg, 0)
            add(searchField)
            add(Box.createRigidArea(java.awt.Dimension(DesignTokens.Spacing.sm, 0)))
            add(resultCountLabel)
        }

    // STEP 3 — Tool-row builder (local helper)
    fun buildToolRow(tool: com.six2dez.burp.aiagent.mcp.McpToolDescriptor): JPanel {
        val checkbox = JCheckBox(tool.title, effectiveToggles[tool.id] ?: false)
        checkbox.putClientProperty("unsafeOnly", tool.unsafeOnly)
        checkbox.putClientProperty("description", tool.description)
        // Tooltip logic: preserved verbatim from original (UI-07)
        checkbox.toolTipText =
            when {
                !tool.unsafeOnly -> tool.description
                unsafeEnabled -> "${tool.description} Allowed by global unsafe mode."
                unsafeAllowlist.contains(tool.id) -> "${tool.description} Allowed by per-tool unsafe approval."
                else -> "${tool.description} Blocked until unsafe mode is enabled globally or approved in allowlist."
            }
        // isEnabled logic: preserved verbatim (UI-07 — only proOnly tools disabled at build time)
        if (tool.proOnly && edition != BurpSuiteEdition.PROFESSIONAL) {
            checkbox.isEnabled = false
            checkbox.putClientProperty("proDisabled", true)
            checkbox.toolTipText = "${tool.description} (Pro only)"
        } else {
            checkbox.putClientProperty("proDisabled", false)
            // NOTE: unsafe checkbox gating (unsafeOnly + unsafe OFF + not allowlisted → disabled)
            // is intentionally DEFERRED to Phase 11. Checkboxes start enabled here per UI-07.
        }
        mcpToolCheckboxes[tool.id] = checkbox

        // North sub-row: checkbox + gap + badge + glue + optional indicator
        val badge =
            toolBadge(
                if (tool.nativeTool) "Store + Full" else "Full only",
                McpToolTabModel.badgeStyle(tool),
            )
        val northRow =
            JPanel().apply {
                layout = BoxLayout(this, BoxLayout.X_AXIS)
                isOpaque = false
                add(checkbox)
                add(Box.createRigidArea(java.awt.Dimension(DesignTokens.Spacing.sm, 0)))
                add(badge)
                add(Box.createHorizontalGlue())
            }
        // Optional indicator label (right-aligned, visual only — does NOT affect isEnabled)
        val indicator: JLabel? =
            when {
                tool.proOnly && edition != BurpSuiteEdition.PROFESSIONAL ->
                    JLabel("Pro only").apply {
                        font = DesignTokens.Typography.caption
                        foreground = DesignTokens.Colors.onSurfaceVariant
                    }
                tool.unsafeOnly && !unsafeEnabled && unsafeAllowlist.contains(tool.id) ->
                    JLabel("allowlisted").apply {
                        font = DesignTokens.Typography.caption
                        foreground = DesignTokens.Colors.statusWarning
                    }
                tool.unsafeOnly && !unsafeEnabled ->
                    JLabel("unsafe").apply {
                        font = DesignTokens.Typography.caption
                        foreground = DesignTokens.Colors.statusError
                    }
                else -> null
            }
        if (indicator != null) northRow.add(indicator)

        // South sub-row: description help label
        val descLabel = helpLabel(tool.description)
        descLabel.border = EmptyBorder(0, DesignTokens.Spacing.md, 0, 0)

        return JPanel(BorderLayout()).apply {
            isOpaque = false
            border =
                EmptyBorder(
                    DesignTokens.Spacing.xs,
                    DesignTokens.Spacing.md,
                    DesignTokens.Spacing.xs,
                    DesignTokens.Spacing.md,
                )
            add(northRow, BorderLayout.NORTH)
            add(descLabel, BorderLayout.SOUTH)
        }
    }

    // Helper: compute set of disabled checkbox tool IDs at call time
    val disabledCheckboxIds: () -> Set<String> = {
        mcpToolCheckboxes.entries
            .filter { !it.value.isEnabled }
            .map { it.key }
            .toSet()
    }

    // STEP 4 — AI Tools section
    val aiToolRows = mutableListOf<Pair<com.six2dez.burp.aiagent.mcp.McpToolDescriptor, JPanel>>()
    val aiEnableAll = secondaryButton("Enable all")
    val aiDisableAll = secondaryButton("Disable all")
    val aiBulkBar =
        JPanel().apply {
            layout = BoxLayout(this, BoxLayout.X_AXIS)
            isOpaque = false
            border = EmptyBorder(0, 0, DesignTokens.Spacing.sm, 0)
            add(aiEnableAll)
            add(Box.createRigidArea(java.awt.Dimension(DesignTokens.Spacing.sm, 0)))
            add(aiDisableAll)
            add(Box.createHorizontalGlue())
        }
    val aiEmptyLabel = helpLabel("No tools match your search.").also { it.isVisible = false }
    val aiListPanel =
        JPanel().apply {
            layout = BoxLayout(this, BoxLayout.Y_AXIS)
            isOpaque = false
            add(aiBulkBar)
        }
    for (tool in grouping.native) {
        val row = buildToolRow(tool)
        aiToolRows.add(tool to row)
        aiListPanel.add(row)
    }
    aiListPanel.add(aiEmptyLabel)

    aiEnableAll.addActionListener {
        val targets = McpToolTabModel.bulkToggleTargets(grouping.native, searchField.text, disabledCheckboxIds())
        for (target in targets) mcpToolCheckboxes[target.id]?.isSelected = true
    }
    aiDisableAll.addActionListener {
        val targets = McpToolTabModel.bulkToggleTargets(grouping.native, searchField.text, disabledCheckboxIds())
        for (target in targets) mcpToolCheckboxes[target.id]?.isSelected = false
    }

    val aiSection =
        sectionPanel(
            title = "AI Tools (extension-native)",
            subtitle = "Extension-native tools — available in both the BApp Store and the full build.",
            content = aiListPanel,
        )

    // STEP 5 — Montoya Tools section
    val montoyaToolRows = mutableListOf<Pair<com.six2dez.burp.aiagent.mcp.McpToolDescriptor, JPanel>>()
    val montoyaCategoryHeaders = mutableListOf<Pair<String, JLabel>>()
    val montoyaEnableAll = secondaryButton("Enable all")
    val montoyaDisableAll = secondaryButton("Disable all")
    val montoyaBulkBar =
        JPanel().apply {
            layout = BoxLayout(this, BoxLayout.X_AXIS)
            isOpaque = false
            border = EmptyBorder(0, 0, DesignTokens.Spacing.sm, 0)
            add(montoyaEnableAll)
            add(Box.createRigidArea(java.awt.Dimension(DesignTokens.Spacing.sm, 0)))
            add(montoyaDisableAll)
            add(Box.createHorizontalGlue())
        }
    val montoyaEmptyLabel = helpLabel("No tools match your search.").also { it.isVisible = false }
    val montoyaListPanel =
        JPanel().apply {
            layout = BoxLayout(this, BoxLayout.Y_AXIS)
            isOpaque = false
        }

    val categoryMap = McpToolTabModel.categoryGroups(grouping.generic)
    if (grouping.generic.isEmpty()) {
        montoyaBulkBar.isVisible = false
        montoyaListPanel.add(helpLabel("No Montoya tools available in this build."))
    } else {
        montoyaListPanel.add(montoyaBulkBar)
        for ((category, tools) in categoryMap) {
            val catHeader =
                JLabel(category).apply {
                    font = DesignTokens.Typography.label
                    foreground = DesignTokens.Colors.onSurfaceVariant
                    border = EmptyBorder(DesignTokens.Spacing.sm, 0, DesignTokens.Spacing.xs, 0)
                }
            montoyaCategoryHeaders.add(category to catHeader)
            montoyaListPanel.add(catHeader)
            for (tool in tools) {
                val row = buildToolRow(tool)
                montoyaToolRows.add(tool to row)
                montoyaListPanel.add(row)
            }
        }
    }
    montoyaListPanel.add(montoyaEmptyLabel)

    montoyaEnableAll.addActionListener {
        val targets = McpToolTabModel.bulkToggleTargets(grouping.generic, searchField.text, disabledCheckboxIds())
        for (target in targets) mcpToolCheckboxes[target.id]?.isSelected = true
    }
    montoyaDisableAll.addActionListener {
        val targets = McpToolTabModel.bulkToggleTargets(grouping.generic, searchField.text, disabledCheckboxIds())
        for (target in targets) mcpToolCheckboxes[target.id]?.isSelected = false
    }

    // STEP 6 — Unsafe Allowlist AccordionPanel (bottom of Montoya section)
    val allowlistContentPanel =
        JPanel().apply {
            layout = BoxLayout(this, BoxLayout.Y_AXIS)
            isOpaque = false
        }
    val unsafeTools = McpToolCatalog.available().filter { it.unsafeOnly }.sortedBy { it.title }
    for (tool in unsafeTools) {
        val approved = unsafeAllowlist.contains(tool.id)
        val approval =
            JCheckBox(tool.title, approved).apply {
                toolTipText = tool.description
                putClientProperty("proOnly", tool.proOnly)
                putClientProperty("toolId", tool.id)
            }
        val proDisabled = tool.proOnly && edition != BurpSuiteEdition.PROFESSIONAL
        if (proDisabled) {
            approval.isEnabled = false
            approval.toolTipText = "${tool.description} (Pro only)"
        } else {
            approval.isEnabled = !unsafeEnabled
        }
        approval.addActionListener { updateUnsafeToolStates() }
        mcpUnsafeApprovalCheckboxes[tool.id] = approval
        val row =
            JPanel().apply {
                layout = BoxLayout(this, BoxLayout.X_AXIS)
                isOpaque = false
                border = EmptyBorder(DesignTokens.Spacing.xs, DesignTokens.Spacing.md, DesignTokens.Spacing.xs, DesignTokens.Spacing.md)
                add(approval)
                add(Box.createHorizontalGlue())
            }
        allowlistContentPanel.add(row)
    }
    val allowlistAccordion =
        AccordionPanel(
            "Unsafe tool allowlist",
            "Approve individual unsafe tools without enabling global unsafe mode.",
            allowlistContentPanel,
            initiallyExpanded = false,
        )
    montoyaListPanel.add(Box.createRigidArea(java.awt.Dimension(0, DesignTokens.Spacing.sm)))
    montoyaListPanel.add(allowlistAccordion)

    val montoyaSection =
        sectionPanel(
            title = "Montoya Tools (generic)",
            subtitle = "Generic Montoya API wrappers — available in the full build only.",
            content = montoyaListPanel,
        )

    // STEP 7 — Section separator (Spacing.xl gap between AI and Montoya sections)
    val sectionSeparator =
        JPanel().apply {
            isOpaque = false
            preferredSize = java.awt.Dimension(0, DesignTokens.Spacing.xl)
            maximumSize = java.awt.Dimension(Int.MAX_VALUE, DesignTokens.Spacing.xl)
        }

    // STEP 8 — DocumentListener for live filter (Option B — show/hide rows)
    fun applyFilter(query: String) {
        var visibleAiCount = 0
        for ((tool, row) in aiToolRows) {
            val visible = McpToolTabModel.filterPredicate(query, tool)
            row.isVisible = visible
            if (visible) visibleAiCount++
        }
        var visibleMontoyaCount = 0
        for ((tool, row) in montoyaToolRows) {
            val visible = McpToolTabModel.filterPredicate(query, tool)
            row.isVisible = visible
            if (visible) visibleMontoyaCount++
        }
        for ((category, header) in montoyaCategoryHeaders) {
            val hasVisible = categoryMap[category]?.any { McpToolTabModel.filterPredicate(query, it) } == true
            header.isVisible = hasVisible
        }
        aiEmptyLabel.isVisible = visibleAiCount == 0 && query.isNotBlank()
        aiBulkBar.isVisible = visibleAiCount > 0
        montoyaEmptyLabel.isVisible = visibleMontoyaCount == 0 && query.isNotBlank() && grouping.generic.isNotEmpty()
        montoyaBulkBar.isVisible = visibleMontoyaCount > 0 && grouping.generic.isNotEmpty()
        val totalVisible = visibleAiCount + visibleMontoyaCount
        resultCountLabel.text = if (query.isBlank()) "$totalTools tools" else "$totalVisible of $totalTools tools"
        aiListPanel.revalidate()
        aiListPanel.repaint()
        montoyaListPanel.revalidate()
        montoyaListPanel.repaint()
    }

    searchField.document.addDocumentListener(
        object : DocumentListener {
            override fun insertUpdate(e: DocumentEvent) = applyFilter(searchField.text)

            override fun removeUpdate(e: DocumentEvent) = applyFilter(searchField.text)

            override fun changedUpdate(e: DocumentEvent) = applyFilter(searchField.text)
        },
    )

    // STEP 9 — Return via buildTabPanel from design module
    return buildTabPanel(listOf(searchBarPanel, aiSection, sectionSeparator, montoyaSection))
}

internal fun SettingsPanel.updateUnsafeToolStates() {
    val unsafeEnabled = mcpUnsafe.isSelected
    mcpToolCheckboxes.values.forEach { checkbox ->
        val proDisabled = checkbox.getClientProperty("proDisabled") as? Boolean ?: false
        if (proDisabled) {
            checkbox.isEnabled = false
            return@forEach
        }
        val unsafeOnly = checkbox.getClientProperty("unsafeOnly") as? Boolean ?: false
        val description = checkbox.getClientProperty("description") as? String ?: ""
        val toolId = mcpToolCheckboxes.entries.firstOrNull { it.value === checkbox }?.key
        val allowlisted = toolId != null && mcpUnsafeApprovalCheckboxes[toolId]?.isSelected == true
        checkbox.isEnabled = true
        checkbox.toolTipText =
            if (unsafeOnly) {
                when {
                    unsafeEnabled -> "$description Allowed by global unsafe mode."
                    allowlisted -> "$description Allowed by per-tool unsafe approval."
                    else -> "$description Blocked until unsafe mode is enabled globally or approved in allowlist."
                }
            } else {
                description
            }
    }
    mcpUnsafeApprovalCheckboxes.forEach { (id, checkbox) ->
        val proOnly = checkbox.getClientProperty("proOnly") as? Boolean ?: false
        val proDisabled = proOnly && api.burpSuite().version().edition() != BurpSuiteEdition.PROFESSIONAL
        checkbox.isEnabled = !unsafeEnabled && !proDisabled
        val description =
            McpToolCatalog
                .all()
                .firstOrNull { it.id == id }
                ?.description
                .orEmpty()
        checkbox.toolTipText =
            when {
                proDisabled -> "$description (Pro only)"
                unsafeEnabled -> "$description Ignored while global unsafe mode is ON."
                else -> description
            }
    }
    updateProfileWarnings()
    updateRiskWarnings()
}

internal fun SettingsPanel.collectMcpToolToggles(): Map<String, Boolean> = mcpToolCheckboxes.mapValues { it.value.isSelected }

internal fun SettingsPanel.collectEnabledUnsafeTools(): Set<String> =
    mcpUnsafeApprovalCheckboxes
        .filterValues { it.isSelected }
        .keys

internal fun SettingsPanel.applyUnsafeToolApprovals(enabledUnsafeTools: Set<String>) {
    mcpUnsafeApprovalCheckboxes.forEach { (id, checkbox) ->
        checkbox.isSelected = enabledUnsafeTools.contains(id)
    }
}

internal fun SettingsPanel.availableMcpToolsWithReasons(): Pair<Set<String>, Map<String, String>> {
    val edition = api.burpSuite().version().edition()
    val unsafeEnabled = mcpUnsafe.isSelected
    val enabledUnsafeTools = collectEnabledUnsafeTools()
    val effectiveToggles = McpToolCatalog.mergeWithDefaults(collectMcpToolToggles())
    val available = mutableSetOf<String>()
    val reasons = mutableMapOf<String, String>()
    for (tool in McpToolCatalog.available()) {
        val id = tool.id.lowercase()
        when {
            tool.proOnly && edition != BurpSuiteEdition.PROFESSIONAL ->
                reasons[id] = "requires Burp Professional."
            tool.unsafeOnly && !unsafeEnabled && !enabledUnsafeTools.contains(tool.id) ->
                reasons[id] = "requires Unsafe mode or explicit per-tool unsafe approval."
            effectiveToggles[tool.id] != true ->
                reasons[id] = "disabled in MCP Tools settings."
            else -> available.add(id)
        }
    }
    return available to reasons
}

internal fun SettingsPanel.availableMcpTools(): Set<String> = availableMcpToolsWithReasons().first

internal fun SettingsPanel.updateMcpTlsState() {
    val external = mcpExternal.isSelected
    val tlsEnabled = if (external) true else mcpTlsEnabled.isSelected
    mcpTlsEnabled.isSelected = tlsEnabled
    mcpTlsEnabled.isEnabled = !external
    mcpTlsAuto.isEnabled = tlsEnabled
    mcpKeystorePath.isEnabled = tlsEnabled
    mcpKeystorePassword.isEnabled = tlsEnabled
    updateFieldStyle(mcpKeystorePath)
    mcpKeystorePassword.foreground =
        if (mcpKeystorePassword.isEnabled) DesignTokens.Colors.inputForeground else DesignTokens.Colors.onSurfaceVariant
}

/**
 * Legacy entry point — kept so existing listeners (Allowed Origins document changes) still
 * compile. Routes into the consolidated MCP notice.
 */
internal fun SettingsPanel.updateMcpCorsWarning() {
    refreshMcpNotice()
}

/**
 * Compose a single advisory for the MCP Server tab. Replaces the previous pair of stacked
 * banners (mcpCorsWarning + mcpRiskWarning) with one SubtleNotice that surfaces
 * every applicable misconfiguration as a bulleted list — accent color follows the
 * highest-severity entry. Earlier draft used a when chain that returned only the first
 * matching branch, dropping the CORS-open warning in combined-risk states; the accumulator
 * below preserves all caveats simultaneously.
 */
internal fun SettingsPanel.refreshMcpNotice() {
    val selectedPrivacy = privacyMode.selectedItem as? PrivacyMode ?: PrivacyMode.STRICT
    val mcpOn = mcpEnabled.isSelected
    val external = mcpExternal.isSelected
    val unsafeEnabled = mcpUnsafe.isSelected
    val tokenBlank = mcpToken.text.trim().isBlank()
    val hasAllowedOrigins = parseAllowedOriginsInput(mcpAllowedOrigins.text).isNotEmpty()

    if (!mcpOn) {
        mcpNotice.hideNotice()
        return
    }

    data class Item(
        val level: SubtleNotice.Level,
        val html: String,
    )
    val items = mutableListOf<Item>()
    if (external && unsafeEnabled) {
        items +=
            Item(
                SubtleNotice.Level.RISK,
                "<b>External MCP + Unsafe mode.</b> Remote callers can invoke state-changing tools.",
            )
    }
    if (external && tokenBlank) {
        items +=
            Item(
                SubtleNotice.Level.RISK,
                "<b>External MCP with empty token.</b> The endpoint is reachable without authentication.",
            )
    }
    if (external && selectedPrivacy == PrivacyMode.OFF) {
        items +=
            Item(
                SubtleNotice.Level.WARN,
                "<b>External MCP with Privacy OFF.</b> Raw traffic may leave the host.",
            )
    }
    if (external && !hasAllowedOrigins) {
        items +=
            Item(
                SubtleNotice.Level.WARN,
                "<b>External MCP with no allowed origins.</b> CORS will accept requests from any origin.",
            )
    }
    if (items.isEmpty()) {
        mcpNotice.hideNotice()
        return
    }
    val highest =
        if (items.any { it.level == SubtleNotice.Level.RISK }) {
            SubtleNotice.Level.RISK
        } else {
            SubtleNotice.Level.WARN
        }
    val body = items.joinToString("<br>") { "• ${it.html}" }
    mcpNotice.setMessage(highest, body)
}
