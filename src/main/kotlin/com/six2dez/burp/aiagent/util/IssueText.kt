package com.six2dez.burp.aiagent.util

object IssueText {
    private val fencedCodeRegex = Regex("(?s)```[a-zA-Z0-9_-]*\\n(.*?)```")
    private val markdownLinkRegex = Regex("\\[([^\\]]+)]\\(([^)]+)\\)")
    private val headingRegex = Regex("(?m)^#{1,6}\\s+")
    private val blockquoteRegex = Regex("(?m)^>\\s?")

    fun sanitize(input: String): String {
        if (input.isBlank()) return input
        var text = input.replace("\r\n", "\n").replace("\r", "\n")

        // Remove fenced code blocks but keep their content.
        text =
            text.replace(fencedCodeRegex) { m ->
                m.groupValues[1]
            }

        // Inline code/backticks.
        text = text.replace("`", "")

        // Markdown links: [text](url) -> text (url)
        text = text.replace(markdownLinkRegex, "$1 ($2)")

        // Headings and blockquotes.
        text = text.replace(headingRegex, "")
        text = text.replace(blockquoteRegex, "")

        // Bold/italic markers.
        text =
            text
                .replace("**", "")
                .replace("__", "")
                .replace("*", "")
                .replace("_", "")

        return text.trim()
    }
}
