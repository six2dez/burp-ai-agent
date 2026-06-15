package com.six2dez.burp.aiagent.config

import burp.api.montoya.MontoyaApi
import burp.api.montoya.persistence.Preferences
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Disabled
import org.junit.jupiter.api.Test
import org.mockito.Answers
import org.mockito.kotlin.any
import org.mockito.kotlin.mock
import org.mockito.kotlin.whenever

/**
 * Wave 0 test scaffold for ExternalMcpSettings migration (schema v4 → v5).
 *
 * These tests are stubs that document the intended behavior for Plan 16-02.
 * All tests are @Disabled until the production migration code in AgentSettings is
 * implemented. The test shape and assertions here form the Wave-1 implementation contract.
 *
 * Behaviors covered (per 16-VALIDATION.md Wave 0 requirements):
 * - Round-trip: save a list with one SSE config, reload, name survives
 * - Encryption: stored pref string starts with ENC1: prefix
 * - Schema bump: settings.schema.version pref is set to 5 after load
 * - Idempotency: loading twice does not double-encrypt (still exactly one ENC1: prefix)
 *
 * Pattern: mirrors AgentSettingsMigrationTest.kt (InMemoryPrefs + apiWith() helper).
 */
class ExternalMcpSettingsMigrationTest {
    /**
     * Verifies that a list of ExternalMcpServerConfig entries is saved and loaded correctly.
     * After save(), a fresh AgentSettingsRepository instance can reload the list and the
     * server name is preserved.
     *
     * See: 16-PATTERNS.md "Round-trip test pattern"
     * See: 16-RESEARCH.md "Bearer Token Storage (SC4)"
     */
    @Test
    @Disabled("Wave 0 stub — implementation in plan 16-02; ExternalMcpServerConfig and schema-v5 migration not yet created")
    fun externalMcpServers_roundTripsThroughSaveLoad() {
        val prefs = InMemoryPrefs()

        // Save a settings object with one external SSE server config
        // val writer = AgentSettingsRepository(apiWith(prefs.mock))
        // val testConfig = ExternalMcpServerConfig(
        //     name = "test-server",
        //     transport = ExternalMcpTransport.SSE,
        //     url = "https://example.com/sse",
        //     bearerToken = "",
        // )
        // val defaults = writer.defaultSettings()
        // writer.save(defaults.copy(mcpSettings = defaults.mcpSettings.copy(externalMcpServers = listOf(testConfig))))

        // Load from the same in-memory preferences
        // val reader = AgentSettingsRepository(apiWith(prefs.mock))
        // val loaded = reader.load()

        // Assert the list is preserved
        // assertEquals(1, loaded.mcpSettings.externalMcpServers.size)
        // assertEquals("test-server", loaded.mcpSettings.externalMcpServers[0].name)

        assertTrue(true, "Placeholder — implement after ExternalMcpServerConfig exists (plan 16-02)")
    }

    /**
     * Verifies that the bearer token for an external server is stored encrypted in preferences.
     * The persisted blob under the 'mcp.external.servers.v1' key must start with 'ENC1:'.
     *
     * See: 16-PATTERNS.md "ENC1: prefix idempotency assertion"
     * See: 16-RESEARCH.md "Bearer Token Storage (SC4)"
     */
    @Test
    @Disabled("Wave 0 stub — implementation in plan 16-02; schema-v5 migration not yet created")
    fun externalServerBlob_isStoredEncrypted() {
        val prefs = InMemoryPrefs()

        // Save a config with a bearer token
        // val writer = AgentSettingsRepository(apiWith(prefs.mock))
        // val testConfig = ExternalMcpServerConfig(
        //     name = "secure-server",
        //     transport = ExternalMcpTransport.SSE,
        //     url = "https://example.com/sse",
        //     bearerToken = "super-secret-token",
        // )
        // val defaults = writer.defaultSettings()
        // writer.save(defaults.copy(mcpSettings = defaults.mcpSettings.copy(externalMcpServers = listOf(testConfig))))

        // Assert the stored blob is encrypted
        // val stored = prefs.strings["mcp.external.servers.v1"] ?: ""
        // assertTrue(stored.startsWith("ENC1:"), "External server blob must be encrypted (got: $stored)")

        assertTrue(true, "Placeholder — implement after schema-v5 migration exists (plan 16-02)")
    }

    /**
     * Verifies that the schema version is bumped to 5 after loading settings
     * from an installation that previously had schema version 4 (pre-Phase-16).
     *
     * See: 16-PATTERNS.md "Versioned constant bump" + "Migration ladder pattern"
     */
    @Test
    @Disabled("Wave 0 stub — implementation in plan 16-02; CURRENT_SETTINGS_SCHEMA_VERSION not yet bumped to 5")
    fun schemaVersion_bumpedToFive() {
        val prefs = InMemoryPrefs()
        // Simulate a pre-Phase-16 install: schema version at 4
        prefs.integers["settings.schema.version"] = 4

        // val repo = AgentSettingsRepository(apiWith(prefs.mock))
        // repo.load()

        // After loading, the migration ladder must have written v5
        // assertEquals(5, prefs.integers["settings.schema.version"])

        // Placeholder assertion while stub
        assertEquals(4, prefs.integers["settings.schema.version"], "Placeholder — implement after schema-v5 migration exists (plan 16-02)")
    }

    /**
     * Verifies that loading settings twice does not double-encrypt the bearer token blob.
     * The stored value should still begin with exactly one 'ENC1:' prefix after two loads.
     *
     * See: 16-PATTERNS.md "migrateToSchemaV4 idempotency pattern"
     * See: 16-RESEARCH.md "Pitfall 6: ExternalMcpServerConfig persisted without schema migration gate"
     */
    @Test
    @Disabled("Wave 0 stub — implementation in plan 16-02; idempotency requires schema-v5 migration")
    fun migrationIsIdempotent_doubleLoadDoesNotDoubleEncrypt() {
        val prefs = InMemoryPrefs()

        // val repo = AgentSettingsRepository(apiWith(prefs.mock))
        // First load triggers migration and writes encrypted blob
        // repo.load()
        // val afterFirstLoad = prefs.strings["mcp.external.servers.v1"] ?: ""
        // assertTrue(afterFirstLoad.startsWith("ENC1:"), "Must be encrypted after first load")

        // Second load must not double-encrypt (ENC1:ENC1: would be wrong)
        // repo.load()
        // val afterSecondLoad = prefs.strings["mcp.external.servers.v1"] ?: ""
        // assertTrue(afterSecondLoad.startsWith("ENC1:"), "Still starts with ENC1: after second load")
        // assertFalse(afterSecondLoad.startsWith("ENC1:ENC1:"), "Must NOT be double-encrypted")

        assertTrue(true, "Placeholder — implement after schema-v5 migration exists (plan 16-02)")
    }

    // ---------------------------------------------------------------------------
    // Test infrastructure (mirrors AgentSettingsMigrationTest.kt pattern exactly)
    // ---------------------------------------------------------------------------

    // Called by disabled stub tests; will be used directly once plan 16-02 enables them.
    @Suppress("UnusedPrivateMember")
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
