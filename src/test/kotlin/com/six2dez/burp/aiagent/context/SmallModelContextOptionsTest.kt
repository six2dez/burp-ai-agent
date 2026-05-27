package com.six2dez.burp.aiagent.context

import burp.api.montoya.MontoyaApi
import burp.api.montoya.persistence.Preferences
import com.six2dez.burp.aiagent.config.AgentSettingsRepository
import com.six2dez.burp.aiagent.ui.buildContextOptionsFromSettings
import org.junit.jupiter.api.Assertions.assertEquals
import org.mockito.Answers
import org.mockito.kotlin.any
import org.mockito.kotlin.mock
import org.mockito.kotlin.whenever

/**
 * Covers BUG-69-02 / D-02: when `smallModelMode = true` the helper must cap
 * `maxRequestBodyChars` to 1500 and `maxResponseBodyChars` to 750. When
 * `smallModelMode = false` the helper must pass through the user-configured
 * `contextRequestBodyMaxChars` / `contextResponseBodyMaxChars` verbatim.
 */
class SmallModelContextOptionsTest {
    @org.junit.jupiter.api.Test
    fun contextOptionsRespectSmallModelMode_trueBranchCapsAt1500_750() {
        val base = defaultSettings()
        val withSmallMode =
            base.copy(
                smallModelMode = true,
                contextRequestBodyMaxChars = 9_999,
                contextResponseBodyMaxChars = 9_999,
            )

        val options = buildContextOptionsFromSettings(withSmallMode)

        assertEquals(1_500, options.maxRequestBodyChars)
        assertEquals(750, options.maxResponseBodyChars)
        assertEquals(withSmallMode.privacyMode, options.privacyMode)
        assertEquals(withSmallMode.determinismMode, options.deterministic)
        assertEquals(withSmallMode.hostAnonymizationSalt, options.hostSalt)
        assertEquals(withSmallMode.contextCompactJson, options.compactJson)
    }

    @org.junit.jupiter.api.Test
    fun contextOptionsRespectSmallModelMode_falseBranchPassesThroughVerbatim() {
        val base = defaultSettings()
        val withoutSmallMode =
            base.copy(
                smallModelMode = false,
                contextRequestBodyMaxChars = 9_999,
                contextResponseBodyMaxChars = 9_999,
            )

        val options = buildContextOptionsFromSettings(withoutSmallMode)

        assertEquals(9_999, options.maxRequestBodyChars)
        assertEquals(9_999, options.maxResponseBodyChars)
    }

    @org.junit.jupiter.api.Test
    fun contextOptionsDefaultsAreUnchangedForFalse() {
        val defaults = defaultSettings()

        val options = buildContextOptionsFromSettings(defaults)

        // defaultSettings() ships smallModelMode = false plus the existing 4000/8000 caps.
        assertEquals(4_000, options.maxRequestBodyChars)
        assertEquals(8_000, options.maxResponseBodyChars)
    }

    private fun defaultSettings() = AgentSettingsRepository(apiWith(emptyPreferences())).defaultSettings()

    private fun apiWith(preferences: Preferences): MontoyaApi {
        val api = mock<MontoyaApi>(defaultAnswer = Answers.RETURNS_DEEP_STUBS)
        whenever(api.persistence().preferences()).thenReturn(preferences)
        return api
    }

    private fun emptyPreferences(): Preferences {
        val strings = mutableMapOf<String, String>()
        val booleans = mutableMapOf<String, Boolean>()
        val integers = mutableMapOf<String, Int>()
        return mock<Preferences>().also { prefs ->
            whenever(prefs.getString(any())).thenAnswer { invocation ->
                strings[invocation.getArgument<String>(0)]
            }
            whenever(prefs.setString(any(), any())).thenAnswer { invocation ->
                strings[invocation.getArgument<String>(0)] = invocation.getArgument<String>(1)
                null
            }
            whenever(prefs.getBoolean(any())).thenAnswer { invocation ->
                booleans[invocation.getArgument<String>(0)]
            }
            whenever(prefs.setBoolean(any(), any())).thenAnswer { invocation ->
                booleans[invocation.getArgument<String>(0)] = invocation.getArgument<Boolean>(1)
                null
            }
            whenever(prefs.getInteger(any())).thenAnswer { invocation ->
                integers[invocation.getArgument<String>(0)]
            }
            whenever(prefs.setInteger(any(), any())).thenAnswer { invocation ->
                integers[invocation.getArgument<String>(0)] = invocation.getArgument<Int>(1)
                null
            }
        }
    }
}
