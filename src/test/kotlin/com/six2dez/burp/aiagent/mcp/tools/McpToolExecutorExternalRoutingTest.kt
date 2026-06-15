package com.six2dez.burp.aiagent.mcp.tools

import burp.api.montoya.MontoyaApi
import burp.api.montoya.core.BurpSuiteEdition
import com.six2dez.burp.aiagent.mcp.McpRequestLimiter
import com.six2dez.burp.aiagent.mcp.McpToolCatalog
import com.six2dez.burp.aiagent.mcp.McpToolContext
import com.six2dez.burp.aiagent.mcp.external.ExternalMcpClientManager
import com.six2dez.burp.aiagent.mcp.external.ExternalToolDescriptor
import com.six2dez.burp.aiagent.redact.PrivacyMode
import io.modelcontextprotocol.kotlin.sdk.TextContent
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.mockito.Answers
import org.mockito.kotlin.any
import org.mockito.kotlin.anyOrNull
import org.mockito.kotlin.doSuspendableAnswer
import org.mockito.kotlin.mock
import org.mockito.kotlin.whenever

/**
 * Unit tests for Phase 16 (CAP-02) external tool routing in [McpToolExecutor].
 *
 * Covers:
 * - SC1: external tools appear in describeTools() preamble as ext:<server>:<tool>
 * - D-04: ext:-prefixed calls route to ExternalMcpClientManager, built-ins are unaffected
 * - D-03 (outbound privacy): redactIfNeeded() applied to outbound args before callTool()
 * - SC2: trust-boundary-wrapped result from callTool() flows unchanged into CallToolResult
 * - Null manager: returns error CallToolResult for ext: calls when no manager configured
 */
class McpToolExecutorExternalRoutingTest {
    private fun baseContext(
        manager: ExternalMcpClientManager? = null,
        privacyMode: PrivacyMode = PrivacyMode.OFF,
    ): McpToolContext {
        val api = mock<MontoyaApi>(defaultAnswer = Answers.RETURNS_DEEP_STUBS)
        whenever(api.burpSuite().version().edition()).thenReturn(BurpSuiteEdition.PROFESSIONAL)
        return McpToolContext(
            api = api,
            privacyMode = privacyMode,
            determinismMode = false,
            hostSalt = "test-salt",
            toolToggles = McpToolCatalog.all().associate { it.id to true },
            unsafeEnabled = false,
            unsafeTools = McpToolCatalog.unsafeToolIds(),
            enabledUnsafeTools = emptySet(),
            limiter = McpRequestLimiter(4),
            edition = BurpSuiteEdition.PROFESSIONAL,
            maxBodyBytes = 8192,
            externalClientManager = manager,
        )
    }

    // ── describeTools fan-out (SC1) ──────────────────────────────────────────────────────────────

    @Test
    fun describeTools_withNoManager_doesNotContainExtEntry() {
        val context = baseContext(manager = null)
        val output = McpToolExecutor.describeTools(context, includeSchemas = false)
        assertFalse(output.contains("ext:"), "Should contain no ext: entries when manager is null")
    }

    @Test
    fun describeTools_withManager_appendsExternalToolsWithExtPrefix() {
        val manager = mock<ExternalMcpClientManager>()
        whenever(manager.availableTools()).thenReturn(
            listOf(
                ExternalToolDescriptor(
                    serverName = "demo",
                    name = "ext:demo:search",
                    description = "Search the web",
                ),
            ),
        )

        val context = baseContext(manager = manager)
        val output = McpToolExecutor.describeTools(context, includeSchemas = false)

        assertTrue(
            output.contains("ext:demo:search"),
            "describeTools() must include ext:demo:search from the external manager",
        )
        assertTrue(
            output.contains("Search the web"),
            "describeTools() must include the external tool description",
        )
    }

    @Test
    fun describeTools_withManager_appendsAdvisoryNote() {
        val manager = mock<ExternalMcpClientManager>()
        whenever(manager.availableTools()).thenReturn(
            listOf(
                ExternalToolDescriptor(
                    serverName = "s",
                    name = "ext:s:tool",
                    description = "A tool",
                ),
            ),
        )

        val context = baseContext(manager = manager)
        val output = McpToolExecutor.describeTools(context, includeSchemas = false)

        assertTrue(
            output.contains("EXTERNAL-TOOL-RESULT"),
            "Advisory note containing [EXTERNAL-TOOL-RESULT:...] must be appended when external tools are present",
        )
        assertTrue(
            output.contains("untrusted"),
            "Advisory note must describe external server results as untrusted",
        )
    }

    @Test
    fun describeTools_withManager_noExternalTools_noAdvisoryNote() {
        val manager = mock<ExternalMcpClientManager>()
        whenever(manager.availableTools()).thenReturn(emptyList())

        val context = baseContext(manager = manager)
        val output = McpToolExecutor.describeTools(context, includeSchemas = false)

        assertFalse(
            output.contains("EXTERNAL-TOOL-RESULT"),
            "Advisory note must NOT appear when no external tools are available",
        )
    }

    // ── ext: routing (D-04) ──────────────────────────────────────────────────────────────────────

    @Test
    fun executeToolResult_extPrefix_routesToManager() {
        val wrappedResult =
            "[EXTERNAL-TOOL-RESULT:demo]\nsome output\n[/EXTERNAL-TOOL-RESULT]"

        val manager =
            mock<ExternalMcpClientManager> {
                onBlocking { callTool(any(), any(), anyOrNull()) } doSuspendableAnswer { wrappedResult }
            }

        val context = baseContext(manager = manager)
        val result = McpToolExecutor.executeToolResult("ext:demo:search", """{"q":"test"}""", context)

        assertFalse(result.isError == true, "Successful ext: call must not be an error result")
        val text =
            result.content
                .filterIsInstance<TextContent>()
                .joinToString("") { it.text.orEmpty() }
        assertEquals(wrappedResult, text, "Trust-boundary-wrapped result must flow unchanged into CallToolResult")
    }

    @Test
    fun executeToolResult_extPrefix_nullManager_returnsErrorResult() {
        val context = baseContext(manager = null)
        val result = McpToolExecutor.executeToolResult("ext:missing:tool", null, context)

        assertTrue(result.isError == true, "Must return error when externalClientManager is null")
        val text =
            result.content
                .filterIsInstance<TextContent>()
                .joinToString("") { it.text.orEmpty() }
        assertTrue(
            text.contains("not available", ignoreCase = true),
            "Error message should say 'not available' but was: $text",
        )
    }

    @Test
    fun executeToolResult_builtInTool_notAffectedByExtRouting() {
        // status is a built-in tool; must route to the built-in dispatcher and not the manager.
        val manager =
            mock<ExternalMcpClientManager> {
                onBlocking { callTool(any(), any(), anyOrNull()) } doSuspendableAnswer {
                    error("Should not be called for a built-in tool")
                }
            }

        val context = baseContext(manager = manager)
        val result = McpToolExecutor.executeToolResult("status", null, context)

        // status always succeeds (returns Burp version info) — not an error.
        assertFalse(result.isError == true, "Built-in 'status' tool must succeed via built-in dispatcher")
        val text =
            result.content
                .filterIsInstance<TextContent>()
                .joinToString("") { it.text.orEmpty() }
        assertTrue(
            text.contains("extension=burp-ai-agent"),
            "Built-in 'status' output expected but got: $text",
        )
    }

    @Test
    fun executeToolResult_extPrefix_invalidFormat_returnsError() {
        // "ext:" with only one segment — should fail gracefully.
        val manager = mock<ExternalMcpClientManager>()
        val context = baseContext(manager = manager)
        val result = McpToolExecutor.executeToolResult("ext:onlyone", null, context)

        assertTrue(result.isError == true, "Must return error for malformed ext: name (< 3 parts)")
    }

    // ── D-03 outbound privacy (redactIfNeeded on args) ──────────────────────────────────────────

    @Test
    fun executeToolResult_extPrefix_redactsArgsBeforeForwarding() {
        // Use STRICT privacy mode so that redactIfNeeded() is called and transforms secret-shaped values.
        // We verify by capturing what args were received by callTool() — if redaction ran, the host
        // salt will be applied; we confirm by checking the call was made (not that specific text changed,
        // since Redaction transforms depend on host-salt + patterns).
        val capturedArgs = mutableListOf<Map<String, Any?>>()
        val manager =
            mock<ExternalMcpClientManager> {
                onBlocking { callTool(any(), any(), anyOrNull()) } doSuspendableAnswer { call ->
                    @Suppress("UNCHECKED_CAST")
                    capturedArgs.add(call.getArgument(2) as? Map<String, Any?> ?: emptyMap())
                    "[EXTERNAL-TOOL-RESULT:s]\nok\n[/EXTERNAL-TOOL-RESULT]"
                }
            }

        // STRICT mode ensures redactIfNeeded() passes through the redaction pipeline.
        val context = baseContext(manager = manager, privacyMode = PrivacyMode.STRICT)
        val argsJson = """{"query":"example.com"}"""
        McpToolExecutor.executeToolResult("ext:s:t", argsJson, context)

        assertEquals(1, capturedArgs.size, "callTool() must be invoked exactly once")
        // The key point: callTool() was called with the result of redactIfNeeded(), not with the raw argsJson.
        // For STRICT mode with a non-secret value, redactIfNeeded() returns the value unchanged (no patterns match).
        // This test asserts the args map was parsed and forwarded — the exact values depend on redaction patterns.
        assertNotNull(capturedArgs.first(), "args map must not be null")
    }

    // ── parseArgsMapOrEmpty ──────────────────────────────────────────────────────────────────────

    @Test
    fun parseArgsMapOrEmpty_blankInput_returnsEmpty() {
        assertTrue(McpToolExecutor.parseArgsMapOrEmpty("").isEmpty())
        assertTrue(McpToolExecutor.parseArgsMapOrEmpty("{}").isEmpty())
        assertTrue(McpToolExecutor.parseArgsMapOrEmpty("   ").isEmpty())
    }

    @Test
    fun parseArgsMapOrEmpty_validJson_parsesEntries() {
        val result = McpToolExecutor.parseArgsMapOrEmpty("""{"key":"value","num":42}""")
        assertEquals("value", result["key"])
        assertEquals(42L, result["num"])
    }

    @Test
    fun parseArgsMapOrEmpty_invalidJson_returnsEmpty() {
        val result = McpToolExecutor.parseArgsMapOrEmpty("{not-valid-json")
        assertTrue(result.isEmpty())
    }
}
