package com.six2dez.burp.aiagent.config

import burp.api.montoya.MontoyaApi
import burp.api.montoya.persistence.Preferences
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.mockito.Answers
import org.mockito.kotlin.any
import org.mockito.kotlin.mock
import org.mockito.kotlin.whenever

class AgentSettingsMigrationTest {
    @Test
    fun load_migratesLegacySchemaAndUpdatesVersionMarker() {
        val prefs = InMemoryPrefs()
        prefs.strings["gemini.cmd"] = "gemini --output-format text --model gemini-2.5-flash"
        prefs.strings["mcp.allowed.origins"] = "https://ops.example.com, https://ops.example.com ; http://127.0.0.1"

        val repo = AgentSettingsRepository(apiWith(prefs.mock))
        val loaded = repo.load()

        assertEquals("gemini --output-format text --model gemini-2.5-flash --yolo", loaded.geminiCmd)
        assertEquals(
            listOf("https://ops.example.com", "http://127.0.0.1"),
            loaded.mcpSettings.allowedOrigins,
        )
        assertEquals(3, prefs.integers["settings.schema.version"])
        assertTrue((prefs.strings["mcp.allowed.origins"] ?: "").contains("\n"))
    }

    @Test
    fun save_persistsCurrentSchemaVersion() {
        val prefs = InMemoryPrefs()
        val repo = AgentSettingsRepository(apiWith(prefs.mock))

        repo.save(repo.defaultSettings())

        assertEquals(3, prefs.integers["settings.schema.version"])
    }

    @Test
    fun load_v2InstallLoadsEmptyCustomPromptLibraryAndStampsV3() {
        val prefs = InMemoryPrefs()
        prefs.integers["settings.schema.version"] = 2
        val repo = AgentSettingsRepository(apiWith(prefs.mock))

        val loaded = repo.load()

        assertEquals(emptyList<CustomPromptDefinition>(), loaded.customPromptLibrary)
        assertEquals(3, prefs.integers["settings.schema.version"])
    }

    private fun apiWith(preferences: Preferences): MontoyaApi {
        val api = mock<MontoyaApi>(defaultAnswer = Answers.RETURNS_DEEP_STUBS)
        whenever(api.persistence().preferences()).thenReturn(preferences)
        return api
    }

    private class InMemoryPrefs {
        val strings = mutableMapOf<String, String>()
        val booleans = mutableMapOf<String, Boolean>()
        val integers = mutableMapOf<String, Int>()
        val mock: Preferences =
            mock<Preferences>().also { prefs ->
                whenever(prefs.getString(any())).thenAnswer { invocation ->
                    strings[invocation.getArgument(0)]
                }
                whenever(prefs.setString(any(), any())).thenAnswer { invocation ->
                    strings[invocation.getArgument(0)] = invocation.getArgument(1)
                    null
                }
                whenever(prefs.getBoolean(any())).thenAnswer { invocation ->
                    booleans[invocation.getArgument(0)]
                }
                whenever(prefs.setBoolean(any(), any())).thenAnswer { invocation ->
                    booleans[invocation.getArgument(0)] = invocation.getArgument(1)
                    null
                }
                whenever(prefs.getInteger(any())).thenAnswer { invocation ->
                    integers[invocation.getArgument(0)]
                }
                whenever(prefs.setInteger(any(), any())).thenAnswer { invocation ->
                    integers[invocation.getArgument(0)] = invocation.getArgument(1)
                    null
                }
            }
    }
}
