package com.six2dez.burp.aiagent.config

import burp.api.montoya.MontoyaApi
import burp.api.montoya.persistence.Preferences
import com.fasterxml.jackson.databind.json.JsonMapper
import com.fasterxml.jackson.module.kotlin.registerKotlinModule
import com.six2dez.burp.aiagent.mcp.external.ExternalMcpServerConfig
import com.six2dez.burp.aiagent.mcp.external.ExternalMcpTransport
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.mockito.Answers
import org.mockito.kotlin.any
import org.mockito.kotlin.mock
import org.mockito.kotlin.whenever

/**
 * Migration tests for ExternalMcpSettings (schema v4 -> v5).
 *
 * Covers (per 16-02 must_haves):
 * - Round-trip: save a list with one SSE config, reload, name and token survive
 * - Encryption: per-field bearerToken stored with ENC1: prefix (not the whole blob)
 * - Schema bump: settings.schema.version pref is set to 5 after load
 * - Idempotency: load+save+load does not double-encrypt (no ENC1:ENC1: prefix)
 *
 * Pattern mirrors AgentSettingsMigrationTest.kt (InMemoryPrefs + apiWith() helper).
 */
class ExternalMcpSettingsMigrationTest {
    /**
     * Verifies that a list of ExternalMcpServerConfig entries is saved and loaded correctly.
     * After save(), a fresh AgentSettingsRepository instance can reload the list and the
     * server name is preserved. Bearer token round-trips as plaintext.
     *
     * See: 16-PATTERNS.md "Round-trip test pattern"
     * See: 16-RESEARCH.md "Bearer Token Storage (SC4)"
     */
    @Test
    fun externalMcpServers_roundTripsThroughSaveLoad() {
        val prefs = InMemoryPrefs()

        val writer = AgentSettingsRepository(apiWith(prefs.mock))
        val testConfig =
            ExternalMcpServerConfig(
                name = "test-server",
                transport = ExternalMcpTransport.SSE,
                url = "https://example.com/sse",
                bearerToken = "mySecret",
            )
        val defaults = writer.defaultSettings()
        writer.save(defaults.copy(mcpSettings = defaults.mcpSettings.copy(externalMcpServers = listOf(testConfig))))

        val reader = AgentSettingsRepository(apiWith(prefs.mock))
        val loaded = reader.load()

        assertEquals(1, loaded.mcpSettings.externalMcpServers.size)
        assertEquals("test-server", loaded.mcpSettings.externalMcpServers[0].name)
        // bearerToken must come back as plaintext — not as ENC1:-prefixed ciphertext
        assertEquals("mySecret", loaded.mcpSettings.externalMcpServers[0].bearerToken)
        assertEquals(ExternalMcpTransport.SSE, loaded.mcpSettings.externalMcpServers[0].transport)
        assertEquals("https://example.com/sse", loaded.mcpSettings.externalMcpServers[0].url)
    }

    /**
     * Verifies that the bearer token for an external server is stored encrypted in preferences
     * AT THE PER-FIELD LEVEL. The bearerToken JSON field value inside the blob must start with
     * 'ENC1:' — NOT the blob itself.
     *
     * See: 16-PATTERNS.md "ENC1: prefix idempotency assertion"
     * See: 16-RESEARCH.md "Bearer Token Storage (SC4)"
     */
    @Test
    fun externalServerBlob_isStoredEncrypted() {
        val prefs = InMemoryPrefs()

        val writer = AgentSettingsRepository(apiWith(prefs.mock))
        val testConfig =
            ExternalMcpServerConfig(
                name = "secure-server",
                transport = ExternalMcpTransport.SSE,
                url = "https://example.com/sse",
                bearerToken = "super-secret-token",
            )
        val defaults = writer.defaultSettings()
        writer.save(defaults.copy(mcpSettings = defaults.mcpSettings.copy(externalMcpServers = listOf(testConfig))))

        // The blob stored under the key must be a JSON array (not encrypted at blob level)
        val storedBlob = prefs.strings["mcp.external.servers.v1"] ?: ""
        assertFalse(storedBlob.isBlank(), "External server blob must not be empty after save")
        // Blob is NOT encrypted at blob level — it is a JSON array
        assertFalse(storedBlob.startsWith("ENC1:"), "Blob itself must NOT be encrypted (per-field only)")

        // Parse the blob and check the per-field bearerToken is ENC1:-prefixed
        val mapper = JsonMapper.builder().build().registerKotlinModule()
        val parsed = mapper.readValue(storedBlob, Array<ExternalMcpServerConfig>::class.java)
        assertEquals(1, parsed.size)
        assertTrue(
            parsed[0].bearerToken.startsWith("ENC1:"),
            "Per-field bearerToken in blob must start with ENC1: (got: ${parsed[0].bearerToken})",
        )
    }

    /**
     * Verifies that the schema version is bumped to 5 after loading settings
     * from an installation that previously had schema version 4 (pre-Phase-16).
     *
     * See: 16-PATTERNS.md "Versioned constant bump" + "Migration ladder pattern"
     */
    @Test
    fun schemaVersion_bumpedToFive() {
        val prefs = InMemoryPrefs()
        // Simulate a pre-Phase-16 install: schema version at 4
        prefs.integers["settings.schema.version"] = 4

        val repo = AgentSettingsRepository(apiWith(prefs.mock))
        repo.load()

        // After loading, the migration ladder must have written v5
        assertEquals(5, prefs.integers["settings.schema.version"], "Schema version must be bumped to 5 after load")
    }

    /**
     * Verifies that loading settings twice does not double-encrypt the bearer token.
     * After a save+load cycle, calling save again and loading once more must still produce
     * a per-field bearerToken that starts with exactly one 'ENC1:' prefix (not 'ENC1:ENC1:').
     *
     * See: 16-PATTERNS.md "migrateToSchemaV4 idempotency pattern"
     * See: 16-RESEARCH.md "Pitfall 6: ExternalMcpServerConfig persisted without schema migration gate"
     */
    @Test
    fun migrationIsIdempotent_doubleLoadDoesNotDoubleEncrypt() {
        val prefs = InMemoryPrefs()

        // First cycle: save with a non-blank token
        val repo1 = AgentSettingsRepository(apiWith(prefs.mock))
        val testConfig =
            ExternalMcpServerConfig(
                name = "idem-server",
                transport = ExternalMcpTransport.SSE,
                bearerToken = "idem-secret",
            )
        val defaults = repo1.defaultSettings()
        repo1.save(defaults.copy(mcpSettings = defaults.mcpSettings.copy(externalMcpServers = listOf(testConfig))))

        // First load: should decrypt and return plaintext
        val repo2 = AgentSettingsRepository(apiWith(prefs.mock))
        val loaded1 = repo2.load()
        assertEquals("idem-secret", loaded1.mcpSettings.externalMcpServers[0].bearerToken)

        // Second save: re-encrypts the plaintext token (must produce exactly one ENC1: level)
        repo2.save(loaded1)

        // Check the stored blob — bearerToken must still start with ENC1: but NOT ENC1:ENC1:
        val storedBlob = prefs.strings["mcp.external.servers.v1"] ?: ""
        val mapper = JsonMapper.builder().build().registerKotlinModule()
        val parsed = mapper.readValue(storedBlob, Array<ExternalMcpServerConfig>::class.java)
        val storedToken = parsed[0].bearerToken

        assertTrue(storedToken.startsWith("ENC1:"), "After second save, token must still start with ENC1: (got: $storedToken)")
        assertFalse(storedToken.startsWith("ENC1:ENC1:"), "Token must NOT be double-encrypted (got: $storedToken)")

        // Second load: must still return the original plaintext
        val repo3 = AgentSettingsRepository(apiWith(prefs.mock))
        val loaded2 = repo3.load()
        assertEquals("idem-secret", loaded2.mcpSettings.externalMcpServers[0].bearerToken)
    }

    // ---------------------------------------------------------------------------
    // Test infrastructure (mirrors AgentSettingsMigrationTest.kt pattern exactly)
    // ---------------------------------------------------------------------------

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
