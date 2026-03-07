package com.six2dez.burp.aiagent.ui

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class ToolCallParserTest {

    @Test
    fun `extracts direct tool payload`() {
        val payload = """{"tool":"status","args":{}}"""
        val call = ToolCallParser.extractFirst(payload)
        assertNotNull(call)
        assertEquals("status", call?.tool)
        assertEquals("{}", call?.argsJson)
    }

    @Test
    fun `extracts fenced json tool payload`() {
        val payload = """
            I will query Burp first.
            ```json
            {"name":"proxy_http_history","arguments":{"limit":5}}
            ```
        """.trimIndent()
        val call = ToolCallParser.extractFirst(payload)
        assertNotNull(call)
        assertEquals("proxy_http_history", call?.tool)
        assertEquals("""{"limit":5}""", call?.argsJson)
    }

    @Test
    fun `extracts openai style tool_calls payload`() {
        val payload = """
            {
              "choices": [
                {
                  "message": {
                    "tool_calls": [
                      {
                        "id": "call_1",
                        "type": "function",
                        "function": {
                          "name": "http1_request",
                          "arguments": "{\"targetHostname\":\"example.com\",\"targetPort\":443}"
                        }
                      }
                    ]
                  }
                }
              ]
            }
        """.trimIndent()
        val call = ToolCallParser.extractFirst(payload)
        assertNotNull(call)
        assertEquals("http1_request", call?.tool)
        assertTrue(call?.argsJson?.contains("targetHostname") == true)
    }

    @Test
    fun `extracts inline mixed text json payload`() {
        val payload = "Let me call this tool now: {\"tool\":\"scope_check\",\"args\":{\"url\":\"https://target.test\"}} and continue."
        val call = ToolCallParser.extractFirst(payload)
        assertNotNull(call)
        assertEquals("scope_check", call?.tool)
        assertTrue(call?.argsJson?.contains("target.test") == true)
    }

    @Test
    fun `returns null when no tool call exists`() {
        val payload = "I will analyze and then provide a final answer without using any tool."
        val call = ToolCallParser.extractFirst(payload)
        assertNull(call)
    }
}
