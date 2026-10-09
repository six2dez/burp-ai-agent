package com.six2dez.burp.aiagent.ui

/**
 * Quick 261009-do9 shared href table, used by both the renderer tests ([ChatLinkRenderingTest]) and
 * the click handler tests ([ChatLinkOpenerTest]), so the two gates are proven against the same rows.
 *
 * Every invisible or non-ASCII character is written as a `\u` escape, so the source never hides text.
 */
internal object ChatLinkHrefRows {
    /** Plain http/https URLs with a host and no userinfo: the only shape a chat link may take. */
    val ALLOWED: List<String> =
        listOf(
            "https://example.com",
            "HTTPS://Example.com/a?b=1&c=2",
            "http://127.0.0.1:8080/x",
        )

    /**
     * Accepted by the policy; they exist to prove that a quote in the URL cannot break out of the
     * generated href attribute.
     */
    val QUOTED: List<String> =
        listOf(
            "https://example.com/x'onmouseover='alert",
            "https://example.com/x'style='font-size:40px",
        )

    /** Every shape that must never become an anchor nor be opened. */
    val REJECTED: List<String> =
        listOf(
            // The brief's rows.
            "javascript:alert(1)",
            "JaVaScRiPt:alert(1)",
            " javascript:alert(1)",
            "java\tscript:alert(1)",
            "file://attacker/share",
            "file:///etc/passwd",
            "\\\\attacker\\share",
            "//attacker/share",
            "mailto:a@b.c",
            "ftp://host/x",
            "jar:file:/x!/y",
            "data:text/html,x",
            "https://user:pass@host/",
            "https://bank.example@evil.example/",
            "https:///nohost",
            "https://example.com/\u0000x",
            "https://example.com/a\nb",
            // Planner rows (PF-9).
            "https://example.com/x\"onclick=\"y",
            "https://@example.com/",
            "http:example.com",
            "https://example.com/\u202Egnp.exe",
            "https://example.com/\u200Bx",
            "https://exa_mple.com/",
            "https://ex\u00E1mple.com/",
        )

    /** [s] with every ISO control and Unicode format character shown as `\uXXXX`, for failure messages. */
    fun visible(s: String): String =
        buildString {
            s.forEach { c ->
                if (c.isISOControl() || c.category == CharCategory.FORMAT) {
                    append("\\u%04X".format(c.code))
                } else {
                    append(c)
                }
            }
        }
}
