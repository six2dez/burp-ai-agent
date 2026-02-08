package com.six2dez.burp.aiagent.ui

object MarkdownRenderer {

    fun toHtml(text: String, isDark: Boolean): String {
        val fontSize = UiTheme.Typography.body.size
        val codeFontSize = (fontSize - 1).coerceAtLeast(10)
        val textColor = if (isDark) "#e0e0e0" else "#202020"
        val linkColor = if (isDark) "#64B5F6" else "#1565C0"
        val codeBg = colorToHex(UiTheme.Colors.codeBlockBg)
        val inlineCodeBg = colorToHex(UiTheme.Colors.inlineCodeBg)
        val blockquoteBorder = if (isDark) "#555555" else "#CCCCCC"
        val blockquoteFg = if (isDark) "#BBBBBB" else "#555555"

        // Escape HTML special characters first
        var html = text.replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")

        // Code blocks (```language ... ```)
        html = html.replace(Regex("```([a-zA-Z0-9]*)\\n?([\\s\\S]*?)```")) { m ->
            val lang = m.groupValues[1]
            val code = m.groupValues[2].trimEnd()
            val langTag = if (lang.isNotBlank()) "<div style='font-size:${codeFontSize - 1}px;color:$blockquoteFg;margin-bottom:2px;'>$lang</div>" else ""
            "$langTag<pre style='background-color:$codeBg;padding:8px 10px;font-family:Monospaced;font-size:${codeFontSize}px;border-radius:4px;overflow-x:auto;white-space:pre-wrap;word-wrap:break-word;margin:4px 0;'><code>$code</code></pre>"
        }

        // Inline code (`...`)
        html = html.replace(Regex("`([^`]+)`")) { m ->
            "<code style='background-color:$inlineCodeBg;padding:1px 4px;font-family:Monospaced;font-size:${codeFontSize}px;border-radius:3px;'>${m.groupValues[1]}</code>"
        }

        // Headings (### before ## before #)
        html = html.replace(Regex("(?m)^### (.+)$")) { m ->
            "<div style='font-size:${fontSize + 1}px;font-weight:bold;margin:8px 0 4px 0;'>${m.groupValues[1]}</div>"
        }
        html = html.replace(Regex("(?m)^## (.+)$")) { m ->
            "<div style='font-size:${fontSize + 3}px;font-weight:bold;margin:10px 0 4px 0;'>${m.groupValues[1]}</div>"
        }
        html = html.replace(Regex("(?m)^# (.+)$")) { m ->
            "<div style='font-size:${fontSize + 5}px;font-weight:bold;margin:12px 0 6px 0;'>${m.groupValues[1]}</div>"
        }

        // Blockquotes (> text) — must be before line break processing
        html = html.replace(Regex("(?m)^&gt; (.+)$")) { m ->
            "<div style='border-left:3px solid $blockquoteBorder;padding:2px 8px;margin:4px 0;color:$blockquoteFg;font-style:italic;'>${m.groupValues[1]}</div>"
        }

        // Unordered lists (- item or * item at start of line)
        html = html.replace(Regex("(?m)^[\\-\\*] (.+)$")) { m ->
            "<div style='margin:1px 0 1px 16px;'>\u2022 ${m.groupValues[1]}</div>"
        }

        // Ordered lists (1. item at start of line)
        var olCounter = 0
        html = html.replace(Regex("(?m)^(\\d+)\\. (.+)$")) { m ->
            olCounter++
            "<div style='margin:1px 0 1px 16px;'>${m.groupValues[1]}. ${m.groupValues[2]}</div>"
        }

        // Bold (**...**)
        html = html.replace(Regex("\\*\\*(.*?)\\*\\*")) { m ->
            "<b>${m.groupValues[1]}</b>"
        }

        // Italic (*...*)
        html = html.replace(Regex("(?<!\\*)\\*(?!\\*)(.*?)(?<!\\*)\\*(?!\\*)")) { m ->
            "<i>${m.groupValues[1]}</i>"
        }

        // Links [text](url)
        html = html.replace(Regex("\\[([^\\]]+)\\]\\(([^)]+)\\)")) { m ->
            "<a href='${m.groupValues[2]}' style='color:$linkColor;'>${m.groupValues[1]}</a>"
        }

        // Horizontal rule (--- or ***)
        html = html.replace(Regex("(?m)^(---+|\\*\\*\\*+)$")) {
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

    private fun colorToHex(c: java.awt.Color): String {
        return "#%02x%02x%02x".format(c.red, c.green, c.blue)
    }
}
