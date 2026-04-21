package com.six2dez.burp.aiagent.mcp.tools

import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class McpToolErrorSanitizationTest {
    @Test
    fun sanitizeErrorMessage_redactsPathsAndInternalClassNames() {
        val error =
            IllegalStateException(
                "Failed loading /Users/alice/work/project/config.json from com.six2dez.burp.aiagent.mcp.KtorMcpServerManager",
            )

        val sanitized = invokeSanitize(error)

        assertTrue(sanitized.contains("[path]"))
        assertTrue(sanitized.contains("[internal]"))
        assertFalse(sanitized.contains("/Users/alice"))
        assertFalse(sanitized.contains("com.six2dez.burp.aiagent"))
    }

    @Test
    fun sanitizeErrorMessage_truncatesOverlyLongOutput() {
        val longPayload =
            buildString {
                append("Error in C:\\\\Users\\\\alice\\\\very\\\\secret\\\\file.txt ")
                repeat(120) { append("abcdef") }
            }
        val error = RuntimeException(longPayload)

        val sanitized = invokeSanitize(error)

        assertTrue(sanitized.length <= 503)
        assertTrue(sanitized.endsWith("..."))
        assertFalse(sanitized.contains("C:\\\\Users\\\\alice"))
    }

    private fun invokeSanitize(error: Exception): String {
        val holder = Class.forName("com.six2dez.burp.aiagent.mcp.tools.McpToolKt")
        val method = holder.getDeclaredMethod("sanitizeErrorMessage", Exception::class.java)
        method.isAccessible = true
        return method.invoke(null, error) as String
    }
}
