package com.six2dez.burp.aiagent.integration

import com.six2dez.burp.aiagent.config.McpSettings
import com.six2dez.burp.aiagent.mcp.McpRequestLimiter
import com.six2dez.burp.aiagent.mcp.McpToolCatalog
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class CompatibilitySmokeTest {
    @Test
    fun mcpToolCatalog_defaultsCoverAllRegisteredTools() {
        val allIds = McpToolCatalog.all().map { it.id }
        val defaults = McpToolCatalog.defaults()

        assertEquals(allIds.size, allIds.toSet().size)
        assertEquals(allIds.toSet(), defaults.keys)
        assertTrue(defaults.containsKey("status"))
    }

    @Test
    fun mcpAllowedOrigins_roundTripIsStable() {
        val input = listOf("https://app.example.com", "https://app.example.com", "http://localhost:3000")

        val serialized = McpSettings.serializeAllowedOrigins(input)
        val parsed = McpSettings.parseAllowedOrigins(serialized)

        assertEquals(listOf("https://app.example.com", "http://localhost:3000"), parsed)
    }

    @Test
    fun mcpRequestLimiter_allowsAcquireAfterRelease() {
        val limiter = McpRequestLimiter(1)

        assertTrue(limiter.tryAcquire(5L))
        limiter.release()
        assertTrue(limiter.tryAcquire(5L))
        limiter.release()
    }
}
