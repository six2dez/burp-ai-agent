package com.six2dez.burp.aiagent.config

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class McpSettingsTest {
    @Test
    fun roundTripToolToggles() {
        val input =
            mapOf(
                "http1_request" to false,
                "url_encode" to true,
            )
        val serialized = McpSettings.serializeToolToggles(input)
        val parsed = McpSettings.parseToolToggles(serialized)
        assertEquals(input, parsed)
    }

    @Test
    fun tokenGenerationProducesNonEmptyValue() {
        val token = McpSettings.generateToken()
        assertTrue(token.isNotBlank())
        assertTrue(token.length >= 32)
    }

    @Test
    fun roundTripAllowedOrigins() {
        val input =
            listOf(
                "https://app.example.com",
                "https://app.example.com",
                "http://localhost:3000",
            )
        val serialized = McpSettings.serializeAllowedOrigins(input)
        val parsed = McpSettings.parseAllowedOrigins(serialized)
        assertEquals(listOf("https://app.example.com", "http://localhost:3000"), parsed)
    }
}
