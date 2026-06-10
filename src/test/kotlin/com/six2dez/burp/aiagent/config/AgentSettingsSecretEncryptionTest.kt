package com.six2dez.burp.aiagent.config

import burp.api.montoya.MontoyaApi
import burp.api.montoya.persistence.Preferences
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.mockito.Answers
import org.mockito.kotlin.any
import org.mockito.kotlin.mock
import org.mockito.kotlin.whenever

/**
 * Verifies the SEC-01 persistence I/O boundary: the 7 secret preferences are encrypted at rest,
 * migrated idempotently from schema v3, fail soft on corruption, and stay plaintext in memory.
 */
class AgentSettingsSecretEncryptionTest {
    @Test
    fun roundTrip_ollamaApiKey_encryptedAtRestPlaintextInMemory() {
        val prefs = InMemoryPrefs()
        val writer = AgentSettingsRepository(apiWith(prefs.mock))
        writer.save(writer.defaultSettings().copy(ollamaApiKey = "sk-test"))

        // Stored ciphertext must be encrypted, not plaintext.
        val rawStored = prefs.strings["ollama.apiKey"] ?: ""
        assertTrue(rawStored.startsWith("ENC1:"), "stored ollama.apiKey must be ENC1:-encrypted")
        assertFalse(rawStored.contains("sk-test"), "plaintext must not appear in the stored pref")

        // Fresh repo over same prefs → load() re-reads and decrypts.
        val reader = AgentSettingsRepository(apiWith(prefs.mock))
        assertEquals("sk-test", reader.load().ollamaApiKey, "in-memory value must be plaintext")
    }

    @Test
    fun migration_v3PlaintextEncryptedOnLoad_andIdempotentOnReRun() {
        val prefs = InMemoryPrefs()
        prefs.integers["settings.schema.version"] = 3
        prefs.strings["ollama.apiKey"] = "sk-oldkey" // legacy plaintext

        val repo = AgentSettingsRepository(apiWith(prefs.mock))
        val loaded = repo.load()
        assertEquals(4, prefs.integers["settings.schema.version"], "schema must advance to 4")
        assertEquals("sk-oldkey", loaded.ollamaApiKey, "migrated value must decrypt to original plaintext")
        val afterFirst = prefs.strings["ollama.apiKey"] ?: ""
        assertTrue(afterFirst.startsWith("ENC1:"), "pref must be encrypted after migration")

        // Re-run migration on a fresh repo (cache cleared) — must not double-encrypt.
        val repo2 = AgentSettingsRepository(apiWith(prefs.mock))
        val loaded2 = repo2.load()
        assertEquals(4, prefs.integers["settings.schema.version"])
        assertEquals("sk-oldkey", loaded2.ollamaApiKey, "value still decrypts to original after re-run")
        assertEquals(afterFirst, prefs.strings["ollama.apiKey"], "ciphertext unchanged — no double-encrypt")
    }

    @Test
    fun roundTrip_allEightSecretKeys_encryptedAtRest() {
        // Eight keys: the original seven + anthropic.apiKey (14-01 CAP-01).
        val prefs = InMemoryPrefs()
        val writer = AgentSettingsRepository(apiWith(prefs.mock))
        val base = writer.defaultSettings()
        writer.save(
            base.copy(
                ollamaApiKey = "k-ollama",
                lmStudioApiKey = "k-lmstudio",
                openAiCompatibleApiKey = "k-openai",
                nvidiaNimApiKey = "k-nvidia",
                perplexityApiKey = "k-perplexity",
                anthropicApiKey = "k-anthropic",
                mcpSettings = base.mcpSettings.copy(token = "k-mcp-token", tlsKeystorePassword = "k-mcp-tls"),
            ),
        )

        val encryptedKeys =
            listOf(
                "ollama.apiKey",
                "lmstudio.apiKey",
                "openai.compat.apiKey",
                "nvidia.nim.apiKey",
                "perplexity.apiKey",
                "anthropic.apiKey",
                "mcp.token",
                "mcp.tls.keystore.password",
            )
        for (key in encryptedKeys) {
            val raw = prefs.strings[key] ?: ""
            assertTrue(raw.startsWith("ENC1:"), "secret pref $key must be encrypted at rest")
        }

        val reader = AgentSettingsRepository(apiWith(prefs.mock))
        val loaded = reader.load()
        assertEquals("k-ollama", loaded.ollamaApiKey)
        assertEquals("k-lmstudio", loaded.lmStudioApiKey)
        assertEquals("k-openai", loaded.openAiCompatibleApiKey)
        assertEquals("k-nvidia", loaded.nvidiaNimApiKey)
        assertEquals("k-perplexity", loaded.perplexityApiKey)
        assertEquals("k-anthropic", loaded.anthropicApiKey)
        assertEquals("k-mcp-token", loaded.mcpSettings.token)
        assertEquals("k-mcp-tls", loaded.mcpSettings.tlsKeystorePassword)
    }

    @Test
    fun failSoft_corruptedSecret_loadsEmptyWithoutFailingOtherKeys() {
        val prefs = InMemoryPrefs()
        val writer = AgentSettingsRepository(apiWith(prefs.mock))
        // Persist valid encrypted values for all secrets first (also writes the master key).
        writer.save(writer.defaultSettings().copy(ollamaApiKey = "good-ollama", openAiCompatibleApiKey = "good-openai"))

        // Now corrupt only the openai compat key's ciphertext.
        prefs.strings["openai.compat.apiKey"] = "ENC1:corrupted_garbage"

        val reader = AgentSettingsRepository(apiWith(prefs.mock))
        val loaded = reader.load() // must not throw
        assertEquals("", loaded.openAiCompatibleApiKey, "corrupted secret must fail soft to empty")
        assertEquals("good-ollama", loaded.ollamaApiKey, "other keys must still load correctly")
    }

    @Test
    fun load_succeedsHeadless_noHeadlessException() {
        val previous = System.getProperty("java.awt.headless")
        System.setProperty("java.awt.headless", "true")
        try {
            val prefs = InMemoryPrefs()
            val repo = AgentSettingsRepository(apiWith(prefs.mock))
            repo.load() // must not throw HeadlessException
        } finally {
            if (previous == null) System.clearProperty("java.awt.headless") else System.setProperty("java.awt.headless", previous)
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
