package com.six2dez.burp.aiagent.mcp

import burp.api.montoya.MontoyaApi
import burp.api.montoya.core.BurpSuiteEdition
import com.six2dez.burp.aiagent.config.McpSettings
import com.six2dez.burp.aiagent.mcp.tools.ResponsePreprocessorSettings
import com.six2dez.burp.aiagent.redact.PrivacyMode
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.mockito.Answers
import org.mockito.kotlin.mock
import org.mockito.kotlin.whenever

class McpRuntimeContextFactoryTest {

    @Test
    fun create_buildsContextFromSettingsAndRuntimeFlags() {
        val api = mock<MontoyaApi>(defaultAnswer = Answers.RETURNS_DEEP_STUBS)
        whenever(api.burpSuite().version().edition()).thenReturn(BurpSuiteEdition.PROFESSIONAL)
        val factory = McpRuntimeContextFactory(api)
        val settings = mcpSettings(
            token = "token-1234567890",
            maxConcurrentRequests = 3,
            maxBodyBytes = 1234,
            unsafeEnabled = true,
            toolToggles = mapOf(
                "status" to false,
                "url_encode" to true
            )
        )

        val context = factory.create(
            settings = settings,
            privacyMode = PrivacyMode.STRICT,
            determinismMode = true,
            preprocessSettings = ResponsePreprocessorSettings()
        )

        assertEquals("mcp-token-123456", context.hostSalt)
        assertEquals(PrivacyMode.STRICT, context.privacyMode)
        assertTrue(context.determinismMode)
        assertTrue(context.unsafeEnabled)
        assertEquals(1234, context.maxBodyBytes)
        assertEquals(BurpSuiteEdition.PROFESSIONAL, context.edition)

        assertFalse(context.isToolEnabled("status"))
        assertTrue(context.isToolEnabled("url_encode"))
    }

    private fun mcpSettings(
        token: String,
        maxConcurrentRequests: Int,
        maxBodyBytes: Int,
        unsafeEnabled: Boolean,
        toolToggles: Map<String, Boolean>
    ): McpSettings {
        return McpSettings(
            enabled = true,
            host = "127.0.0.1",
            port = 8765,
            externalEnabled = false,
            stdioEnabled = false,
            token = token,
            allowedOrigins = emptyList(),
            tlsEnabled = false,
            tlsAutoGenerate = true,
            tlsKeystorePath = "",
            tlsKeystorePassword = "",
            scanTaskTtlMinutes = 120,
            collaboratorClientTtlMinutes = 60,
            maxConcurrentRequests = maxConcurrentRequests,
            maxBodyBytes = maxBodyBytes,
            toolToggles = toolToggles,
            enabledUnsafeTools = emptySet(),
            unsafeEnabled = unsafeEnabled
        )
    }
}
