package com.six2dez.burp.aiagent.ui

import burp.api.montoya.MontoyaApi
import java.awt.BorderLayout
import javax.swing.BorderFactory
import javax.swing.JPanel
import javax.swing.JTextArea

class McpHelpPanel(
    api: MontoyaApi,
) {
    val panel = JPanel(BorderLayout())

    init {
        val t = JTextArea()
        t.isEditable = false
        t.lineWrap = true
        t.wrapStyleWord = true
        t.border = BorderFactory.createTitledBorder("MCP notes (Codex/Gemini)")

        t.text =
            """
            This extension ships its own MCP server:
            - SSE endpoint: http://127.0.0.1:9876/sse (or https when TLS is enabled).
            - Optional stdio bridge can be enabled in settings for clients that require stdio.
            - Token is required for external access: Authorization: Bearer <token>
            - Unsafe mode gates tools that modify Burp state or write files.

            MCP tool outputs honor privacy mode when enabled and are capped by the max body size.

            Claude Desktop:
            - Add a custom MCP server in Claude Desktop and point it to this SSE endpoint.
            - If TLS is enabled, use https and provide the Bearer token.
            """.trimIndent()

        panel.add(t, BorderLayout.CENTER)
    }
}
