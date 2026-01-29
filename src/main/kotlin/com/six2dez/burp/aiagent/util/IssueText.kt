package com.six2dez.burp.aiagent.util

object IssueText {
    fun sanitize(input: String): String {
        if (input.isBlank()) return input
        var text = input.replace("\r\n", "\n").replace("\r", "\n")

        // Remove fenced code blocks but keep their content.
        text = text.replace(Regex("(?s)```[a-zA-Z0-9_-]*\\n(.*?)```")) { m ->
            m.groupValues[1]
        }

        // Inline code/backticks.
        text = text.replace("`", "")

        // Markdown links: [text](url) -> text (url)
        text = text.replace(Regex("\\[([^\\]]+)]\\(([^)]+)\\)"), "$1 ($2)")

        // Headings and blockquotes.
        text = text.replace(Regex("(?m)^#{1,6}\\s+"), "")
        text = text.replace(Regex("(?m)^>\\s?"), "")

        // Bold/italic markers.
        text = text.replace("**", "").replace("__", "").replace("*", "").replace("_", "")

        return text.trim()
    }
}
