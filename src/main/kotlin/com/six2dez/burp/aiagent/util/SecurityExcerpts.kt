package com.six2dez.burp.aiagent.util

/**
 * Shared utility for extracting security-relevant keyword lines from
 * response bodies that extend beyond the truncation point.
 */
object SecurityExcerpts {
    const val MAX_CHARS = 500

    val KEYWORD_REGEX =
        Regex(
            "(error|exception|stack.?trace|password|passwd|secret|token|api[_-]?key|apikey|credential|admin|root|debug|internal|private|ssn|credit.?card|access.?denied|unauthorized|forbidden)",
            RegexOption.IGNORE_CASE,
        )

    /**
     * Extract lines with security-relevant keywords from text beyond what was already included.
     * Returns null if no relevant excerpts are found.
     *
     * @param fullBody    the complete response body
     * @param includedLen the character offset marking the end of already-included text
     * @param maxChars    maximum total characters to return
     */
    fun extract(
        fullBody: String,
        includedLen: Int,
        maxChars: Int = MAX_CHARS,
    ): String? {
        if (fullBody.length <= includedLen) return null
        val remaining = fullBody.substring(includedLen.coerceAtMost(fullBody.length))
        if (remaining.isBlank()) return null

        val seen = HashSet<String>()
        val result = StringBuilder()

        for (rawLine in remaining.lineSequence()) {
            if (rawLine.isBlank() || !KEYWORD_REGEX.containsMatchIn(rawLine)) continue
            val line = rawLine.trim().take(200)
            if (!seen.add(line)) continue
            if (result.length + line.length + 1 > maxChars) break
            result.appendLine(line)
        }

        return result.toString().trimEnd().ifBlank { null }
    }
}
