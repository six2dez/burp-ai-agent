package com.six2dez.burp.aiagent.ui

object MarkdownRenderer {
    fun toHtml(
        text: String,
        isDark: Boolean,
    ): String {
        val fontSize = (UiTheme.Typography.chatBody.size - 2).coerceAtLeast(10)
        val codeFontSize = (fontSize - 1).coerceAtLeast(10)
        val textColor = if (isDark) "#e0e0e0" else "#202020"
        val linkColor = if (isDark) "#64B5F6" else "#1565C0"
        val codeBg = colorToHex(UiTheme.Colors.codeBlockBg)
        val inlineCodeBg = colorToHex(UiTheme.Colors.inlineCodeBg)
        val blockquoteBorder = if (isDark) "#555555" else "#CCCCCC"
        val blockquoteFg = if (isDark) "#BBBBBB" else "#555555"

        // Escape HTML special characters first
        var html =
            text
                .replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;")

        // Code blocks (```language ... ```)
        html =
            html.replace(CODE_BLOCK_REGEX) { m ->
                val lang = m.groupValues[1]
                val code = m.groupValues[2].trimEnd()
                val langTag = if (lang.isNotBlank()) "<div style='font-size:${codeFontSize - 1}px;color:$blockquoteFg;margin-bottom:2px;'>$lang</div>" else ""
                "$langTag<pre style='background-color:$codeBg;padding:8px 10px;font-family:Monospaced;font-size:${codeFontSize}px;border-radius:4px;overflow-x:auto;white-space:pre-wrap;word-wrap:break-word;margin:4px 0;'><code>$code</code></pre>"
            }

        // Inline code (`...`)
        html =
            html.replace(INLINE_CODE_REGEX) { m ->
                "<code style='background-color:$inlineCodeBg;padding:1px 4px;font-family:Monospaced;font-size:${codeFontSize}px;border-radius:3px;'>${m.groupValues[1]}</code>"
            }

        // Headings (### before ## before #)
        html =
            html.replace(HEADING_H3_REGEX) { m ->
                "<div style='font-size:${fontSize + 1}px;font-weight:bold;margin:8px 0 4px 0;'>${m.groupValues[1]}</div>"
            }
        html =
            html.replace(HEADING_H2_REGEX) { m ->
                "<div style='font-size:${fontSize + 3}px;font-weight:bold;margin:10px 0 4px 0;'>${m.groupValues[1]}</div>"
            }
        html =
            html.replace(HEADING_H1_REGEX) { m ->
                "<div style='font-size:${fontSize + 5}px;font-weight:bold;margin:12px 0 6px 0;'>${m.groupValues[1]}</div>"
            }

        // Blockquotes (> text) — must be before line break processing
        html =
            html.replace(BLOCKQUOTE_REGEX) { m ->
                "<div style='border-left:3px solid $blockquoteBorder;padding:2px 8px;margin:4px 0;color:$blockquoteFg;font-style:italic;'>${m.groupValues[1]}</div>"
            }

        // Unordered lists (- item or * item at start of line)
        html =
            html.replace(UNORDERED_LIST_REGEX) { m ->
                "<div style='margin:1px 0 1px 16px;'>\u2022 ${m.groupValues[1]}</div>"
            }

        // Ordered lists (1. item at start of line)
        html =
            html.replace(ORDERED_LIST_REGEX) { m ->
                "<div style='margin:1px 0 1px 16px;'>${m.groupValues[1]}. ${m.groupValues[2]}</div>"
            }

        // Bold (**...**)
        html =
            html.replace(BOLD_REGEX) { m ->
                "<b>${m.groupValues[1]}</b>"
            }

        // Italic (*...*)
        html =
            html.replace(ITALIC_REGEX) { m ->
                "<i>${m.groupValues[1]}</i>"
            }

        // Links [text](url)
        html =
            html.replace(LINK_REGEX) { m ->
                "<a href='${m.groupValues[2]}' style='color:$linkColor;'>${m.groupValues[1]}</a>"
            }

        // Horizontal rule (--- or ***)
        html =
            html.replace(HORIZONTAL_RULE_REGEX) {
                "<hr style='border:none;border-top:1px solid $blockquoteBorder;margin:8px 0;'>"
            }

        // Line breaks - preserve them
        html = html.replace("\n\n", "<br><br>")
        html = html.replace("\n", "<br>")

        return """
            <html>
            <body style='font-family:SansSerif;color:$textColor;font-size:${fontSize}px;margin:0;padding:0;line-height:1.4;'>
            $html
            </body>
            </html>
            """.trimIndent()
    }

    private fun colorToHex(c: java.awt.Color): String = "#%02x%02x%02x".format(c.red, c.green, c.blue)

    private val CODE_BLOCK_REGEX = Regex("```([a-zA-Z0-9]*)\\n?([\\s\\S]*?)```")
    private val INLINE_CODE_REGEX = Regex("`([^`]+)`")
    private val HEADING_H3_REGEX = Regex("(?m)^### (.+)$")
    private val HEADING_H2_REGEX = Regex("(?m)^## (.+)$")
    private val HEADING_H1_REGEX = Regex("(?m)^# (.+)$")
    private val BLOCKQUOTE_REGEX = Regex("(?m)^&gt; (.+)$")
    private val UNORDERED_LIST_REGEX = Regex("(?m)^[\\-\\*] (.+)$")
    private val ORDERED_LIST_REGEX = Regex("(?m)^(\\d+)\\. (.+)$")
    private val BOLD_REGEX = Regex("\\*\\*(.*?)\\*\\*")
    private val ITALIC_REGEX = Regex("(?<!\\*)\\*([^*\\r\\n]+)\\*(?!\\*)")
    private val LINK_REGEX = Regex("\\[([^\\]]+)\\]\\(([^)]+)\\)")
    private val HORIZONTAL_RULE_REGEX = Regex("(?m)^(---+|\\*\\*\\*+)$")
}
