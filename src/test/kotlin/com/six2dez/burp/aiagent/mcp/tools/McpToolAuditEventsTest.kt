package com.six2dez.burp.aiagent.mcp.tools

import burp.api.montoya.MontoyaApi
import burp.api.montoya.core.BurpSuiteEdition
import com.six2dez.burp.aiagent.audit.AuditLogger
import com.six2dez.burp.aiagent.audit.Hashing
import com.six2dez.burp.aiagent.mcp.McpRequestLimiter
import com.six2dez.burp.aiagent.mcp.McpToolContext
import com.six2dez.burp.aiagent.redact.PrivacyMode
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.mockito.Answers
import org.mockito.kotlin.mock
import org.mockito.kotlin.whenever

class McpToolAuditEventsTest {
    private val events = mutableListOf<Pair<String, Map<String, Any?>>>()

    @AfterEach
    fun tearDown() {
        AuditLogger.registerGlobalEmitter(null)
        events.clear()
    }

    @Test
    fun runTool_emitsStartAndEndWithArgHash_withoutRawArgsLeak() {
        installCollector()
        val context = contextFor(toolEnabled = true)
        val args = """{"token":"secret-token","count":2}"""

        val result = runTool(context, "status", args) { "ok" }

        assertFalse(result.isError == true)
        assertEquals(listOf("mcp_tool_start", "mcp_tool_end"), events.map { it.first })

        val start = events[0].second
        val end = events[1].second

        assertEquals("status", start["tool"])
        assertEquals(true, start["hasArgs"])
        assertEquals(Hashing.sha256Hex(args.trim()), start["argsSha256"])
        assertFalse(start.toString().contains("secret-token"))

        assertEquals("success", end["outcome"])
        assertTrue((end["durationMs"] as Number).toLong() >= 0)
        assertFalse(end.toString().contains("secret-token"))
    }

    @Test
    fun runTool_emitsBlockedEvent_whenToolIsDisabled() {
        installCollector()
        val context = contextFor(toolEnabled = false)

        val result = runTool(context, "status", "{}") { "ok" }

        assertTrue(result.isError == true)
        assertEquals(1, events.size)
        assertEquals("mcp_tool_blocked", events.first().first)
        assertEquals("disabled", events.first().second["reason"])
    }

    @Test
    fun runTool_errorEndEvent_doesNotContainExceptionMessage() {
        installCollector()
        val context = contextFor(toolEnabled = true)

        val result =
            runTool(context, "status", """{"token":"very-secret"}""") {
                error("boom /Users/alice/very-secret.txt")
            }

        assertTrue(result.isError == true)
        assertEquals(listOf("mcp_tool_start", "mcp_tool_end"), events.map { it.first })

        val end = events.last().second
        assertEquals("error", end["outcome"])
        assertEquals("exception", end["errorType"])
        assertFalse(end.toString().contains("very-secret"))
        assertFalse(end.toString().contains("/Users/alice"))
    }

    private fun installCollector() {
        events.clear()
        AuditLogger.registerGlobalEmitter { type, payload ->
            @Suppress("UNCHECKED_CAST")
            val mapPayload = payload as? Map<String, Any?> ?: emptyMap()
            events += type to mapPayload
        }
    }

    private fun contextFor(toolEnabled: Boolean): McpToolContext {
        val api = mock<MontoyaApi>(defaultAnswer = Answers.RETURNS_DEEP_STUBS)
        whenever(api.burpSuite().version().edition()).thenReturn(BurpSuiteEdition.PROFESSIONAL)
        return McpToolContext(
            api = api,
            privacyMode = PrivacyMode.OFF,
            determinismMode = false,
            hostSalt = "test",
            toolToggles = mapOf("status" to toolEnabled),
            unsafeEnabled = false,
            unsafeTools = emptySet(),
            enabledUnsafeTools = emptySet(),
            limiter = McpRequestLimiter(2),
            edition = BurpSuiteEdition.PROFESSIONAL,
            maxBodyBytes = 1024,
        )
    }
}
