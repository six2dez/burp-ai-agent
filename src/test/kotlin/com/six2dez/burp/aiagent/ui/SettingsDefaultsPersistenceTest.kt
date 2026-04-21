package com.six2dez.burp.aiagent.ui

import burp.api.montoya.MontoyaApi
import burp.api.montoya.persistence.Preferences
import com.six2dez.burp.aiagent.config.AgentSettingsRepository
import com.six2dez.burp.aiagent.redact.PrivacyMode
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Test
import org.mockito.Answers
import org.mockito.kotlin.any
import org.mockito.kotlin.mock
import org.mockito.kotlin.whenever

class SettingsDefaultsPersistenceTest {
    @Test
    fun load_usesStableDefaults_whenPreferencesAreMissing() {
        val repo = AgentSettingsRepository(apiWith(inMemoryPreferences()))

        val loaded = repo.load()

        assertEquals("127.0.0.1", loaded.mcpSettings.host)
        assertEquals(9876, loaded.mcpSettings.port)
        assertFalse(loaded.mcpSettings.externalEnabled)
        assertEquals(emptyList<String>(), loaded.mcpSettings.allowedOrigins)
        assertFalse(loaded.mcpSettings.unsafeEnabled)
    }

    @Test
    fun saveAndLoad_roundTripPreservesSafetyRelevantFields() {
        val repo = AgentSettingsRepository(apiWith(inMemoryPreferences()))
        val defaults = repo.defaultSettings()
        val updated =
            defaults.copy(
                privacyMode = PrivacyMode.STRICT,
                auditEnabled = true,
                mcpSettings =
                    defaults.mcpSettings.copy(
                        enabled = true,
                        externalEnabled = true,
                        tlsEnabled = true,
                        allowedOrigins = listOf("https://ops.example.com"),
                        unsafeEnabled = true,
                    ),
                passiveAiEnabled = true,
                activeAiEnabled = true,
            )

        repo.save(updated)
        val loaded = repo.load()

        assertEquals(updated.privacyMode, loaded.privacyMode)
        assertEquals(updated.auditEnabled, loaded.auditEnabled)
        assertEquals(updated.mcpSettings.enabled, loaded.mcpSettings.enabled)
        assertEquals(updated.mcpSettings.externalEnabled, loaded.mcpSettings.externalEnabled)
        assertEquals(updated.mcpSettings.allowedOrigins, loaded.mcpSettings.allowedOrigins)
        assertEquals(updated.mcpSettings.unsafeEnabled, loaded.mcpSettings.unsafeEnabled)
        assertEquals(updated.passiveAiEnabled, loaded.passiveAiEnabled)
        assertEquals(updated.activeAiEnabled, loaded.activeAiEnabled)
    }

    private fun apiWith(preferences: Preferences): MontoyaApi {
        val api = mock<MontoyaApi>(defaultAnswer = Answers.RETURNS_DEEP_STUBS)
        whenever(api.persistence().preferences()).thenReturn(preferences)
        return api
    }

    private fun inMemoryPreferences(): Preferences {
        val strings = mutableMapOf<String, String>()
        val booleans = mutableMapOf<String, Boolean>()
        val integers = mutableMapOf<String, Int>()

        val prefs = mock<Preferences>()
        whenever(prefs.getString(any())).thenAnswer { invocation ->
            val key = invocation.getArgument<String>(0)
            strings[key]
        }
        whenever(prefs.setString(any(), any())).thenAnswer { invocation ->
            val key = invocation.getArgument<String>(0)
            val value = invocation.getArgument<String>(1)
            strings[key] = value
            null
        }

        whenever(prefs.getBoolean(any())).thenAnswer { invocation ->
            val key = invocation.getArgument<String>(0)
            booleans[key]
        }
        whenever(prefs.setBoolean(any(), any())).thenAnswer { invocation ->
            val key = invocation.getArgument<String>(0)
            val value = invocation.getArgument<Boolean>(1)
            booleans[key] = value
            null
        }

        whenever(prefs.getInteger(any())).thenAnswer { invocation ->
            val key = invocation.getArgument<String>(0)
            integers[key]
        }
        whenever(prefs.setInteger(any(), any())).thenAnswer { invocation ->
            val key = invocation.getArgument<String>(0)
            val value = invocation.getArgument<Int>(1)
            integers[key] = value
            null
        }

        return prefs
    }
}
