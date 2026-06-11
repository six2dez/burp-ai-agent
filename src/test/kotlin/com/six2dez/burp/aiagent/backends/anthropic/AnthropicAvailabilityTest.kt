package com.six2dez.burp.aiagent.backends.anthropic

import com.six2dez.burp.aiagent.TestSettings
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

/**
 * WR-04: the keyed Anthropic backend must report availability based on the configured API key,
 * like the other keyed HTTP backends. A blank key must NOT report as available (which the registry
 * would otherwise map, via Unknown + available, to "Healthy" — masking the missing credential until
 * the first 401).
 */
class AnthropicAvailabilityTest {
    @Test
    fun isAvailable_blankApiKey_returnsFalse() {
        val backend = AnthropicBackend()
        val settings = TestSettings.baselineSettings().copy(anthropicApiKey = "")

        assertFalse(
            backend.isAvailable(settings),
            "WR-04: Anthropic must not be available with a blank API key",
        )
    }

    @Test
    fun isAvailable_whitespaceApiKey_returnsFalse() {
        val backend = AnthropicBackend()
        val settings = TestSettings.baselineSettings().copy(anthropicApiKey = "   ")

        assertFalse(
            backend.isAvailable(settings),
            "WR-04: a whitespace-only API key must be treated as blank/unavailable",
        )
    }

    @Test
    fun isAvailable_nonBlankApiKey_returnsTrue() {
        val backend = AnthropicBackend()
        val settings = TestSettings.baselineSettings().copy(anthropicApiKey = "sk-ant-test")

        assertTrue(
            backend.isAvailable(settings),
            "Anthropic must be available once a non-blank API key is configured",
        )
    }
}
