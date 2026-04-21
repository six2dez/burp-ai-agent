package com.six2dez.burp.aiagent.mcp.tools

import burp.api.montoya.MontoyaApi
import burp.api.montoya.core.BurpSuiteEdition
import com.six2dez.burp.aiagent.mcp.McpRequestLimiter
import com.six2dez.burp.aiagent.mcp.McpToolCatalog
import com.six2dez.burp.aiagent.mcp.McpToolContext
import com.six2dez.burp.aiagent.redact.PrivacyMode
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.mockito.Answers
import org.mockito.kotlin.mock
import org.mockito.kotlin.whenever

class McpToolParityTest {
    @Test
    fun registeredToolIds_matchCatalog() {
        val catalogIds = McpToolCatalog.all().map { it.id }.toSet()
        val registered = McpToolRegistrations.allIds()
        assertEquals(catalogIds, registered)
    }

    @Test
    fun inputSchema_mapping_coversCatalogTools() {
        val noArgTools =
            setOf(
                "status",
                "editor_get",
                "project_options_get",
                "user_options_get",
            )
        McpToolCatalog.all().forEach { descriptor ->
            val schema = McpToolExecutor.inputSchema(descriptor.id)
            if (!noArgTools.contains(descriptor.id)) {
                assertTrue(schema.properties.isNotEmpty(), "Missing schema mapping for ${descriptor.id}")
            }
        }
    }

    @Test
    fun executeTool_and_executeToolResult_stayAlignedForUnknownTool() {
        val api = mock<MontoyaApi>(defaultAnswer = Answers.RETURNS_DEEP_STUBS)
        whenever(api.burpSuite().version().edition()).thenReturn(BurpSuiteEdition.PROFESSIONAL)
        val context =
            McpToolContext(
                api = api,
                privacyMode = PrivacyMode.OFF,
                determinismMode = false,
                hostSalt = "test",
                toolToggles = McpToolCatalog.all().associate { it.id to true },
                unsafeEnabled = false,
                unsafeTools = McpToolCatalog.unsafeToolIds(),
                enabledUnsafeTools = emptySet(),
                limiter = McpRequestLimiter(4),
                edition = BurpSuiteEdition.PROFESSIONAL,
                maxBodyBytes = 1024,
            )

        val text = McpToolExecutor.executeTool("missing_tool", null, context)
        val result = McpToolExecutor.executeToolResult("missing_tool", null, context)

        assertEquals("Unknown tool: missing_tool", text)
        assertTrue(result.isError == true)
    }
}
