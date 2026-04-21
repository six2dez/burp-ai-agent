package com.six2dez.burp.aiagent.mcp

import burp.api.montoya.MontoyaApi
import burp.api.montoya.core.BurpSuiteEdition
import com.six2dez.burp.aiagent.mcp.tools.runTool
import com.six2dez.burp.aiagent.redact.PrivacyMode
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.mockito.Answers
import org.mockito.kotlin.mock
import org.mockito.kotlin.whenever

class McpUnsafeGatingTest {
    @Test
    fun unsafeTool_isBlockedWithoutGlobalOrPerToolApproval() {
        val context =
            contextFor(
                toolName = "unsafe_tool",
                unsafeTools = setOf("unsafe_tool"),
                unsafeEnabled = false,
                enabledUnsafeTools = emptySet(),
            )

        val result = runTool(context, "unsafe_tool") { "ok" }
        val text = result.content.joinToString("\n") { it.toString() }

        assertTrue(result.isError == true)
        assertTrue(text.contains("Unsafe mode is disabled"))
    }

    @Test
    fun unsafeTool_isAllowedWithPerToolApproval() {
        val context =
            contextFor(
                toolName = "unsafe_tool",
                unsafeTools = setOf("unsafe_tool"),
                unsafeEnabled = false,
                enabledUnsafeTools = setOf("unsafe_tool"),
            )

        val result = runTool(context, "unsafe_tool") { "ok" }
        val text = result.content.joinToString("\n") { it.toString() }

        assertFalse(result.isError == true)
        assertTrue(text.contains("ok"))
    }

    @Test
    fun unsafeTool_isAllowedWhenGlobalUnsafeIsEnabled() {
        val context =
            contextFor(
                toolName = "unsafe_tool",
                unsafeTools = setOf("unsafe_tool"),
                unsafeEnabled = true,
                enabledUnsafeTools = emptySet(),
            )

        val result = runTool(context, "unsafe_tool") { "ok" }
        val text = result.content.joinToString("\n") { it.toString() }

        assertFalse(result.isError == true)
        assertTrue(text.contains("ok"))
    }

    @Test
    fun safeTool_ignoresUnsafeApprovals() {
        val context =
            contextFor(
                toolName = "safe_tool",
                unsafeTools = setOf("unsafe_tool"),
                unsafeEnabled = false,
                enabledUnsafeTools = emptySet(),
            )

        val result = runTool(context, "safe_tool") { "ok" }
        val text = result.content.joinToString("\n") { it.toString() }

        assertFalse(result.isError == true)
        assertTrue(text.contains("ok"))
    }

    private fun contextFor(
        toolName: String,
        unsafeTools: Set<String>,
        unsafeEnabled: Boolean,
        enabledUnsafeTools: Set<String>,
    ): McpToolContext {
        val api = mock<MontoyaApi>(defaultAnswer = Answers.RETURNS_DEEP_STUBS)
        whenever(api.burpSuite().version().edition()).thenReturn(BurpSuiteEdition.PROFESSIONAL)
        return McpToolContext(
            api = api,
            privacyMode = PrivacyMode.OFF,
            determinismMode = false,
            hostSalt = "test",
            toolToggles = mapOf(toolName to true),
            unsafeEnabled = unsafeEnabled,
            unsafeTools = unsafeTools,
            enabledUnsafeTools = enabledUnsafeTools,
            limiter = McpRequestLimiter(4),
            edition = BurpSuiteEdition.PROFESSIONAL,
            maxBodyBytes = 1024,
        )
    }
}
