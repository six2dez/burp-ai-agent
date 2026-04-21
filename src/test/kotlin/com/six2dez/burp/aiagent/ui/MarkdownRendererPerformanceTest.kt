package com.six2dez.burp.aiagent.ui

import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertTimeoutPreemptively
import java.time.Duration

class MarkdownRendererPerformanceTest {
    @Test
    fun toHtml_rendersCommonMarkdownShapes() {
        val input =
            """
            # Title
            ## Subtitle
            ### Section
            > Quote
            - Item
            1. First
            **bold** and *italic* and `code` [Link](https://example.com)
            ---
            ```kotlin
            val x = 1
            ```
            """.trimIndent()

        val html = MarkdownRenderer.toHtml(input, isDark = false)

        assertTrue(html.contains("<b>bold</b>"))
        assertTrue(html.contains("<i>italic</i>"))
        assertTrue(html.contains("href='https://example.com'"))
        assertTrue(html.contains("<hr style='border:none;border-top:1px solid"))
        assertTrue(html.contains("<pre style='background-color:"))
    }

    @Test
    fun toHtml_escapesRawHtmlBeforeFormatting() {
        val html = MarkdownRenderer.toHtml("<script>alert(1)</script> *safe*", isDark = false)

        assertTrue(html.contains("&lt;script&gt;alert(1)&lt;/script&gt;"))
        assertFalse(html.contains("<script>alert(1)</script>"))
        assertTrue(html.contains("<i>safe</i>"))
    }

    @Test
    fun toHtml_handlesAsteriskHeavyInputWithinBoundedTime() {
        val payload =
            buildString {
                repeat(12_000) {
                    append("*")
                }
                append("normal text")
                repeat(12_000) {
                    append("*")
                }
            }

        assertTimeoutPreemptively(Duration.ofSeconds(2)) {
            MarkdownRenderer.toHtml(payload, isDark = true)
        }
    }
}
