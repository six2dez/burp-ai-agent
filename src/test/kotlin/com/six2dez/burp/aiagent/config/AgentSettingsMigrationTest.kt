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
        assertEquals(4, prefs.integers["settings.schema.version"])
        assertTrue((prefs.strings["mcp.allowed.origins"] ?: "").contains("\n"))
    }

    @Test
    fun save_persistsCurrentSchemaVersion() {
        val prefs = InMemoryPrefs()
        val repo = AgentSettingsRepository(apiWith(prefs.mock))

        repo.save(repo.defaultSettings())

        assertEquals(4, prefs.integers["settings.schema.version"])
    }

    @Test
    fun load_v2InstallLoadsEmptyCustomPromptLibraryAndStampsV3() {
        val prefs = InMemoryPrefs()
        prefs.integers["settings.schema.version"] = 2
        val repo = AgentSettingsRepository(apiWith(prefs.mock))

        val loaded = repo.load()

        assertEquals(emptyList<CustomPromptDefinition>(), loaded.customPromptLibrary)
        assertEquals(4, prefs.integers["settings.schema.version"])
    }

    @Test
    fun load_v06xPreferencesYieldSafePerplexityDefaultsAndSchemaStaysV3() {
        val prefs = InMemoryPrefs()
        // Simulate v0.6.x install: schema marker at the version that shipped before this phase, no perplexity.* keys.
        prefs.integers["settings.schema.version"] = 3

        val repo = AgentSettingsRepository(apiWith(prefs.mock))
        val loaded = repo.load()

        assertEquals("https://api.perplexity.ai", loaded.perplexityUrl)
        assertEquals("", loaded.perplexityModel)
        assertEquals("", loaded.perplexityApiKey)
        assertEquals("", loaded.perplexityHeaders)
        assertEquals(120, loaded.perplexityTimeoutSeconds)
        assertEquals(4, prefs.integers["settings.schema.version"])
    }

    @Test
    fun smallModelMode_roundTripsThroughSaveLoad() {
        // Round-trip with smallModelMode = true.
        run {
            val prefs = InMemoryPrefs()
            val writer = AgentSettingsRepository(apiWith(prefs.mock))
            writer.save(writer.defaultSettings().copy(smallModelMode = true))

            // Fresh repository on the same prefs so the cache is empty and load() actually
            // re-reads from preferences.
            val reader = AgentSettingsRepository(apiWith(prefs.mock))
            val loaded = reader.load()

            assertTrue(loaded.smallModelMode, "smallModelMode should round-trip as true")
        }

        // Round-trip with smallModelMode = false (the default).
        run {
            val prefs = InMemoryPrefs()
            val writer = AgentSettingsRepository(apiWith(prefs.mock))
            writer.save(writer.defaultSettings().copy(smallModelMode = false))

            val reader = AgentSettingsRepository(apiWith(prefs.mock))
            val loaded = reader.load()

            assertEquals(false, loaded.smallModelMode, "smallModelMode should round-trip as false")
        }
    }

    @Test
    fun mcpBodyBytesBelow32KbIsClampedOnLoad() {
        // Legacy v0.6.x stored value below the new 32 KB floor must clamp up to 32 KB on load.
        val tooSmallPrefs = InMemoryPrefs()
        tooSmallPrefs.integers["mcp.max.body.bytes"] = 16 * 1024 // 16 KB, below the new floor.
        val tooSmallRepo = AgentSettingsRepository(apiWith(tooSmallPrefs.mock))
        val clampedUp = tooSmallRepo.load()
        assertEquals(32 * 1024, clampedUp.mcpSettings.maxBodyBytes, "values < 32 KB must be clamped up to 32 KB")

        // A value above the new floor and below the ceiling must be preserved verbatim.
        val safePrefs = InMemoryPrefs()
        safePrefs.integers["mcp.max.body.bytes"] = 64 * 1024 // 64 KB, well above the 32 KB floor.
        val safeRepo = AgentSettingsRepository(apiWith(safePrefs.mock))
        val preserved = safeRepo.load()
        assertEquals(64 * 1024, preserved.mcpSettings.maxBodyBytes, "values within range must be preserved")
    }

    @Test
    fun mcpBodyBytesAbove100MbIsClampedOnLoad() {
        // Existing ceiling behaviour: a stored value above 100 MB must clamp down to 100 MB.
        val prefs = InMemoryPrefs()
        prefs.integers["mcp.max.body.bytes"] = 200 * 1024 * 1024
        val repo = AgentSettingsRepository(apiWith(prefs.mock))
        val loaded = repo.load()
        assertEquals(100 * 1024 * 1024, loaded.mcpSettings.maxBodyBytes, "values > 100 MB must be clamped down")
    }

    @Test
    fun mcpScopeOnly_roundTripsThroughSaveLoad() {
        // 07-03 D-03: round-trip the new mcpSettings.scopeOnly knob through Preferences.
        // Save with scopeOnly = true.
        run {
            val prefs = InMemoryPrefs()
            val writer = AgentSettingsRepository(apiWith(prefs.mock))
            val defaults = writer.defaultSettings()
            writer.save(defaults.copy(mcpSettings = defaults.mcpSettings.copy(scopeOnly = true)))

            // Fresh repo + same prefs → load() actually re-reads from preferences.
            val reader = AgentSettingsRepository(apiWith(prefs.mock))
            val loaded = reader.load()

            assertTrue(loaded.mcpSettings.scopeOnly, "scopeOnly should round-trip as true")
        }

        // Save with scopeOnly = false (the default).
        run {
            val prefs = InMemoryPrefs()
            val writer = AgentSettingsRepository(apiWith(prefs.mock))
            val defaults = writer.defaultSettings()
            writer.save(defaults.copy(mcpSettings = defaults.mcpSettings.copy(scopeOnly = false)))

            val reader = AgentSettingsRepository(apiWith(prefs.mock))
            val loaded = reader.load()

            assertEquals(false, loaded.mcpSettings.scopeOnly, "scopeOnly should round-trip as false")
        }

        // Absent preference → defaults to false on a fresh install with no migrations needed.
        run {
            val prefs = InMemoryPrefs()
            val reader = AgentSettingsRepository(apiWith(prefs.mock))
            val loaded = reader.load()
            assertEquals(false, loaded.mcpSettings.scopeOnly, "absent preference must default to false")
        }
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
