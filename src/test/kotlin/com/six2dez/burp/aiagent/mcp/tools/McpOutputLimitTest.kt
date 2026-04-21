package com.six2dez.burp.aiagent.mcp.tools

import burp.api.montoya.MontoyaApi
import burp.api.montoya.core.BurpSuiteEdition
import com.six2dez.burp.aiagent.mcp.McpRequestLimiter
import com.six2dez.burp.aiagent.mcp.McpToolContext
import com.six2dez.burp.aiagent.redact.PrivacyMode
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.mockito.Answers
import org.mockito.kotlin.mock
import org.mockito.kotlin.whenever

class McpOutputLimitTest {
    @Test
    fun limitedStringBuilder_stopsGrowthAtByteLimit() {
        val builder = LimitedStringBuilder(32)
        builder.append("alpha")
        builder.append("-")
        val complete = builder.append("beta-gamma-delta-epsilon-zeta")
        val output = builder.build()

        assertTrue(!complete)
        assertTrue(output.toByteArray(Charsets.UTF_8).size <= 32)
        assertTrue(output.contains("truncated"))
    }

    @Test
    fun contextLimitedJoin_capsLargeSequences() {
        val context = testContext(maxBodyBytes = 96)
        val entries =
            sequence {
                repeat(1000) { idx ->
                    yield("entry=$idx payload=${"A".repeat(32)}")
                }
            }

        val output = context.limitedJoin(entries)

        assertTrue(output.toByteArray(Charsets.UTF_8).size <= 96)
        assertTrue(output.isNotBlank())
    }

    @Test
    fun limitOutput_fallbackStillTruncatesLegacyStrings() {
        val context = testContext(maxBodyBytes = 64)
        val oversized = "X".repeat(4096)

        val output = context.limitOutput(oversized)

        assertTrue(output.contains("truncated"))
        assertTrue(output.toByteArray(Charsets.UTF_8).size > 64)
    }

    private fun testContext(maxBodyBytes: Int): McpToolContext {
        val api = mock<MontoyaApi>(defaultAnswer = Answers.RETURNS_DEEP_STUBS)
        whenever(api.burpSuite().version().edition()).thenReturn(BurpSuiteEdition.PROFESSIONAL)
        return McpToolContext(
            api = api,
            privacyMode = PrivacyMode.OFF,
            determinismMode = false,
            hostSalt = "test",
            toolToggles = emptyMap(),
            unsafeEnabled = false,
            unsafeTools = emptySet(),
            enabledUnsafeTools = emptySet(),
            limiter = McpRequestLimiter(4),
            edition = BurpSuiteEdition.PROFESSIONAL,
            maxBodyBytes = maxBodyBytes,
        )
    }
}
