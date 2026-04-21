package com.six2dez.burp.aiagent.config

import burp.api.montoya.MontoyaApi
import burp.api.montoya.logging.Logging
import burp.api.montoya.persistence.Preferences
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.mockito.Answers
import org.mockito.kotlin.any
import org.mockito.kotlin.mock
import org.mockito.kotlin.whenever

class CustomPromptLibraryTest {
    @Test
    fun serialize_roundtripsUnicodeAndSpecials() {
        val lib =
            listOf(
                CustomPromptDefinition(
                    id = "1",
                    title = "SQLi on id (¡con eñe!)",
                    promptText = "Test \"id\" param,\nnewlines, and 日本語",
                    tags = setOf(CustomPromptTag.HTTP_SELECTION),
                ),
                CustomPromptDefinition(
                    id = "2",
                    title = "Issue audit",
                    promptText = "Summarize {this issue}",
                    tags = setOf(CustomPromptTag.SCANNER_ISSUE, CustomPromptTag.HTTP_SELECTION),
                    showInContextMenu = false,
                ),
            )
        val prefs = InMemoryPrefs()
        val repo = AgentSettingsRepository(apiWith(prefs.mock))
        val base = repo.defaultSettings()

        repo.save(base.copy(customPromptLibrary = lib))
        val loaded = AgentSettingsRepository(apiWith(prefs.mock)).load()

        assertEquals(lib, loaded.customPromptLibrary)
    }

    @Test
    fun malformedJsonReturnsEmptyAndLogs() {
        val prefs = InMemoryPrefs()
        prefs.strings["custom.prompt.library.v1"] = "not json {"
        val errors = mutableListOf<String>()
        val repo = AgentSettingsRepository(apiWith(prefs.mock, errors))

        val loaded = repo.load()

        assertEquals(emptyList<CustomPromptDefinition>(), loaded.customPromptLibrary)
        assertTrue(errors.any { it.contains("custom prompt library JSON invalid") }, "expected error log, got: $errors")
    }

    @Test
    fun orderPreservedAcrossSaveAndLoad() {
        val lib =
            (1..5).map {
                CustomPromptDefinition(
                    id = "id-$it",
                    title = "Prompt $it",
                    promptText = "text $it",
                    tags = setOf(CustomPromptTag.HTTP_SELECTION),
                )
            }
        val prefs = InMemoryPrefs()
        val repo = AgentSettingsRepository(apiWith(prefs.mock))
        repo.save(repo.defaultSettings().copy(customPromptLibrary = lib))

        val loaded = AgentSettingsRepository(apiWith(prefs.mock)).load()

        assertEquals(lib.map { it.id }, loaded.customPromptLibrary.map { it.id })
    }

    @Test
    fun blankAndTaglessEntriesDroppedOnLoad() {
        val validEntry =
            CustomPromptDefinition(
                id = "ok",
                title = "Valid",
                promptText = "good",
                tags = setOf(CustomPromptTag.HTTP_SELECTION),
            )
        // Bypass the save-time filter by injecting raw JSON that contains invalid entries.
        val prefs = InMemoryPrefs()
        val bad =
            """
            [
              {"id":"","title":"missing id","promptText":"x","tags":["HTTP_SELECTION"],"showInContextMenu":true},
              {"id":"x","title":"","promptText":"x","tags":["HTTP_SELECTION"],"showInContextMenu":true},
              {"id":"y","title":"no tags","promptText":"x","tags":[],"showInContextMenu":true},
              {"id":"ok","title":"Valid","promptText":"good","tags":["HTTP_SELECTION"],"showInContextMenu":true}
            ]
            """.trimIndent()
        prefs.strings["custom.prompt.library.v1"] = bad

        val repo = AgentSettingsRepository(apiWith(prefs.mock))
        val loaded = repo.load()

        assertEquals(listOf(validEntry), loaded.customPromptLibrary)
    }

    private fun apiWith(
        preferences: Preferences,
        errors: MutableList<String>? = null,
    ): MontoyaApi {
        val api = mock<MontoyaApi>(defaultAnswer = Answers.RETURNS_DEEP_STUBS)
        whenever(api.persistence().preferences()).thenReturn(preferences)
        if (errors != null) {
            val logging = mock<Logging>()
            whenever(logging.logToError(any<String>())).thenAnswer { inv ->
                errors.add(inv.getArgument(0))
                null
            }
            whenever(api.logging()).thenReturn(logging)
        }
        return api
    }

    private class InMemoryPrefs {
        val strings = mutableMapOf<String, String>()
        val booleans = mutableMapOf<String, Boolean>()
        val integers = mutableMapOf<String, Int>()
        val mock: Preferences =
            mock<Preferences>().also { prefs ->
                whenever(prefs.getString(any())).thenAnswer { inv -> strings[inv.getArgument(0)] }
                whenever(prefs.setString(any(), any())).thenAnswer { inv ->
                    strings[inv.getArgument(0)] = inv.getArgument(1)
                    null
                }
                whenever(prefs.getBoolean(any())).thenAnswer { inv -> booleans[inv.getArgument(0)] }
                whenever(prefs.setBoolean(any(), any())).thenAnswer { inv ->
                    booleans[inv.getArgument(0)] = inv.getArgument(1)
                    null
                }
                whenever(prefs.getInteger(any())).thenAnswer { inv -> integers[inv.getArgument(0)] }
                whenever(prefs.setInteger(any(), any())).thenAnswer { inv ->
                    integers[inv.getArgument(0)] = inv.getArgument(1)
                    null
                }
            }
    }
}
