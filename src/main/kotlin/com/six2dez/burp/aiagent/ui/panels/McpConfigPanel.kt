package com.six2dez.burp.aiagent.ui.panels

import com.six2dez.burp.aiagent.ui.UiTheme
import com.six2dez.burp.aiagent.ui.components.AccordionPanel
import java.awt.BorderLayout
import javax.swing.BorderFactory
import javax.swing.BoxLayout
import javax.swing.JComponent
import javax.swing.JPanel

class McpConfigPanel(
    private val sectionPanel: (String, String, JComponent) -> JPanel,
    private val formGrid: () -> JPanel,
    private val addRowFull: (JPanel, String, JComponent) -> Unit,
    private val addRowPair: (JPanel, String, JComponent, String, JComponent) -> Unit,
    private val addSpacerRow: (JPanel, Int) -> Unit,
    private val mcpEnabled: JComponent,
    private val mcpHost: JComponent,
    private val mcpPort: JComponent,
    private val mcpExternal: JComponent,
    private val mcpStdio: JComponent,
    // 07-03 D-03: scope-only toggle; renamed to *Checkbox to avoid clashing with the
    // SettingsPanel field name `mcpScopeOnly` when both files are read together.
    private val mcpScopeOnlyCheckbox: JComponent,
    private val mcpTlsEnabled: JComponent,
    private val mcpTlsAuto: JComponent,
    private val mcpKeystorePath: JComponent,
    private val mcpKeystorePassword: JComponent,
    private val mcpAllowedOrigins: JComponent,
    // Single advisory replaces the previous mcpCorsWarning + mcpRiskWarning pair. Caller drives
    // level + visibility from `refreshMcpNotice()` in `SettingsPanel`.
    private val mcpNotice: JComponent,
    private val mcpMaxConcurrent: JComponent,
    private val mcpMaxBodyMb: JComponent,
    private val mcpProxyHistoryMaxItems: JComponent,
    private val mcpProxyHistorySortOrder: JComponent,
    private val mcpAllowUnpreprocessedProxyHistory: JComponent,
    private val mcpUnsafe: JComponent,
    private val preprocessProxyHistory: JComponent,
    private val preprocessMaxResponseSizeKb: JComponent,
    private val preprocessFilterBinaryContent: JComponent,
    private val preprocessAllowedContentTypes: JComponent,
    private val tokenPanelFactory: () -> JPanel,
    private val quickActionsFactory: () -> JPanel,
) : ConfigPanel {
    override fun build(): JPanel {
        val body = JPanel(BorderLayout())
        body.background = UiTheme.Colors.surface
        val wrapper =
            sectionPanel(
                "MCP Server",
                "Built-in MCP server (SSE + optional stdio bridge).",
                body,
            )

        // ── Core grid: everything except the proxy-history preprocessing knobs.
        val grid = formGrid()
        addRowPair(grid, "Enabled", mcpEnabled, "Unsafe mode", mcpUnsafe)
        addSpacerRow(grid, 4)
        addRowPair(grid, "Host", mcpHost, "Port", mcpPort)
        addSpacerRow(grid, 4)
        addRowPair(grid, "External access", mcpExternal, "Stdio bridge", mcpStdio)
        addSpacerRow(grid, 4)
        // 07-03 D-03: scope-only toggle lives adjacent to the security-impact toggles so users
        // see it next to External access / Stdio bridge when assessing MCP exposure.
        addRowFull(grid, "Restrict to in-scope hosts", mcpScopeOnlyCheckbox)
        addSpacerRow(grid, 4)
        addRowPair(grid, "TLS enabled", mcpTlsEnabled, "Auto-generate TLS", mcpTlsAuto)
        addSpacerRow(grid, 4)
        addRowFull(grid, "TLS keystore path", mcpKeystorePath)
        addSpacerRow(grid, 4)
        addRowFull(grid, "TLS keystore password", mcpKeystorePassword)
        addSpacerRow(grid, 4)
        addRowFull(grid, "Allowed origins (external mode)", mcpAllowedOrigins)
        addSpacerRow(grid, 4)
        addRowFull(grid, "Token", tokenPanelFactory())
        addSpacerRow(grid, 4)
        addRowFull(grid, "Quick actions", quickActionsFactory())
        addSpacerRow(grid, 4)
        // 07-02 D-02: human label is now KB; constructor param name preserved to avoid churn.
        addRowPair(grid, "Max concurrent requests", mcpMaxConcurrent, "Max body size (KB)", mcpMaxBodyMb)
        addSpacerRow(grid, 4)
        addRowPair(
            grid,
            "Proxy history max items",
            mcpProxyHistoryMaxItems,
            "Proxy history sort",
            mcpProxyHistorySortOrder,
        )
        addSpacerRow(grid, 6)

        // ── MCP advisory lives outside the grid so it collapses cleanly when there is nothing to
        // report (no dangling label residue).
        val noticeWrapper =
            JPanel(BorderLayout()).apply {
                isOpaque = false
                border = BorderFactory.createEmptyBorder(8, 0, 0, 0)
                add(mcpNotice, BorderLayout.CENTER)
            }

        // ── Proxy-history preprocessing collapsed into an accordion. Mounted outside the GridBag
        // so collapsing the content panel does not leave an empty grid row gap.
        val preprocessingGrid = formGrid()
        addRowFull(preprocessingGrid, "Enabled", preprocessProxyHistory)
        addSpacerRow(preprocessingGrid, 4)
        addRowFull(preprocessingGrid, "Allow unpreprocessed proxy history", mcpAllowUnpreprocessedProxyHistory)
        addSpacerRow(preprocessingGrid, 4)
        addRowFull(preprocessingGrid, "Max response size (KB)", preprocessMaxResponseSizeKb)
        addSpacerRow(preprocessingGrid, 4)
        addRowFull(preprocessingGrid, "Filter binary content", preprocessFilterBinaryContent)
        addSpacerRow(preprocessingGrid, 4)
        addRowFull(preprocessingGrid, "Allowed content type prefixes", preprocessAllowedContentTypes)

        val preprocessingAccordion =
            AccordionPanel(
                title = "Proxy history preprocessing",
                subtitle = "Trim large or binary responses before MCP returns them.",
                content = preprocessingGrid,
                initiallyExpanded = false,
            ).apply {
                border = BorderFactory.createEmptyBorder(8, 0, 0, 0)
            }

        // Stack: core grid + advisory + accordion, all top-aligned in a vertical box.
        val stack =
            JPanel().apply {
                layout = BoxLayout(this, BoxLayout.Y_AXIS)
                background = UiTheme.Colors.surface
                add(grid)
                add(noticeWrapper)
                add(preprocessingAccordion)
            }

        // CENTER (not NORTH) so the stack can grow vertically as the accordion expands; pinning to
        // NORTH would cap the panel at the stack's preferred height regardless of available room.
        body.add(stack, BorderLayout.CENTER)
        return wrapper
    }
}
