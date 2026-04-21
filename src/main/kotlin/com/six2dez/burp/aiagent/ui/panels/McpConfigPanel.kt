package com.six2dez.burp.aiagent.ui.panels

import com.six2dez.burp.aiagent.ui.UiTheme
import java.awt.BorderLayout
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
    private val mcpTlsEnabled: JComponent,
    private val mcpTlsAuto: JComponent,
    private val mcpKeystorePath: JComponent,
    private val mcpKeystorePassword: JComponent,
    private val mcpAllowedOrigins: JComponent,
    private val mcpCorsWarning: JComponent,
    private val mcpRiskWarning: JComponent,
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

        val grid = formGrid()
        addRowFull(grid, "Enabled", mcpEnabled)
        addSpacerRow(grid, 4)
        addRowPair(grid, "Host", mcpHost, "Port", mcpPort)
        addSpacerRow(grid, 4)
        addRowPair(grid, "External access", mcpExternal, "Stdio bridge", mcpStdio)
        addSpacerRow(grid, 4)
        addRowPair(grid, "TLS enabled", mcpTlsEnabled, "Auto-generate TLS", mcpTlsAuto)
        addSpacerRow(grid, 4)
        addRowFull(grid, "TLS keystore path", mcpKeystorePath)
        addSpacerRow(grid, 4)
        addRowFull(grid, "TLS keystore password", mcpKeystorePassword)
        addSpacerRow(grid, 4)
        addRowFull(grid, "Allowed origins (external mode)", mcpAllowedOrigins)
        addSpacerRow(grid, 4)
        addRowFull(grid, "CORS warning", mcpCorsWarning)
        addSpacerRow(grid, 4)
        addRowFull(grid, "Risk warning", mcpRiskWarning)
        addSpacerRow(grid, 4)
        addRowFull(grid, "Token", tokenPanelFactory())
        addSpacerRow(grid, 4)
        addRowFull(grid, "Quick actions", quickActionsFactory())
        addSpacerRow(grid, 4)
        addRowFull(grid, "Max concurrent requests", mcpMaxConcurrent)
        addSpacerRow(grid, 4)
        addRowFull(grid, "Max body size (MB)", mcpMaxBodyMb)
        addSpacerRow(grid, 4)
        addRowPair(grid, "Proxy history max items", mcpProxyHistoryMaxItems, "Proxy history sort", mcpProxyHistorySortOrder)
        addSpacerRow(grid, 4)
        addRowFull(grid, "Unsafe mode", mcpUnsafe)
        addSpacerRow(grid, 4)
        addRowFull(grid, "Proxy history preprocessing (master switch)", preprocessProxyHistory)
        addSpacerRow(grid, 4)
        addRowFull(grid, "↳ Allow unpreprocessed proxy history", mcpAllowUnpreprocessedProxyHistory)
        addSpacerRow(grid, 4)
        addRowFull(grid, "↳ Max response size (KB)", preprocessMaxResponseSizeKb)
        addSpacerRow(grid, 4)
        addRowFull(grid, "↳ Filter binary content", preprocessFilterBinaryContent)
        addSpacerRow(grid, 4)
        addRowFull(grid, "↳ Allowed content type prefixes", preprocessAllowedContentTypes)
        addSpacerRow(grid, 6)

        val container = JPanel(BorderLayout())
        container.background = UiTheme.Colors.surface
        container.add(grid, BorderLayout.NORTH)
        body.add(container, BorderLayout.CENTER)
        return wrapper
    }
}
