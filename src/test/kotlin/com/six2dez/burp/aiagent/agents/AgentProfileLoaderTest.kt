package com.six2dez.burp.aiagent.agents

import java.nio.file.Files
import java.nio.file.Path
import kotlin.io.path.writeText
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test

class AgentProfileLoaderTest {
    private lateinit var tempDir: Path

    @BeforeEach
    fun setUp() {
        tempDir = Files.createTempDirectory("agent-profiles-test")
        AgentProfileLoader.setBaseDirForTests(tempDir)
    }

    @AfterEach
    fun tearDown() {
        AgentProfileLoader.setBaseDirForTests(null)
        tempDir.toFile().deleteRecursively()
    }

    @Test
    fun `installs bundled profiles when directory is empty`() {
        val profiles = AgentProfileLoader.listAvailableProfiles()
        assertTrue(profiles.any { it.equals("pentester", ignoreCase = true) })
        assertTrue(profiles.any { it.equals("bughunter", ignoreCase = true) })
        assertTrue(profiles.any { it.equals("auditor", ignoreCase = true) })
    }

    @Test
    fun `discovers custom profiles`() {
        val custom = tempDir.resolve("custom.md")
        custom.writeText("[GLOBAL]\nCustom profile")
        val profiles = AgentProfileLoader.listAvailableProfiles()
        assertTrue(profiles.any { it.equals("custom", ignoreCase = true) })
    }

    @Test
    fun `validate profile reports missing tools`() {
        val custom = tempDir.resolve("custom.md")
        custom.writeText(
            """
            [GLOBAL]
            Available MCP Tools:
            - status: health/status
            - issue_create: create findings
            Use /tool proxy_http_history {}
            {"tool":"repeater_tab","args":{}}
            """.trimIndent()
        )

        val warnings = AgentProfileLoader.validateProfile(
            profileName = "custom",
            availableTools = setOf("status", "proxy_http_history")
        )

        assertTrue(warnings.any { it.contains("issue_create") })
        assertTrue(warnings.any { it.contains("repeater_tab") })
    }

    @Test
    fun `validate profile returns empty when all tools are available`() {
        val custom = tempDir.resolve("custom.md")
        custom.writeText(
            """
            [GLOBAL]
            - status
            Use /tool proxy_http_history {}
            """.trimIndent()
        )

        val warnings = AgentProfileLoader.validateProfile(
            profileName = "custom",
            availableTools = setOf("status", "proxy_http_history")
        )

        assertFalse(warnings.isNotEmpty())
    }

    @Test
    fun `validate profile ignores narrative bullets and only parses explicit tool references`() {
        val custom = tempDir.resolve("custom.md")
        custom.writeText(
            """
            [GLOBAL]
            Available MCP Tools:
            - status: Check current status
            - issue_create: Create issues
            - http1_request / http2_request: Send test requests

            AUTOMATIC ISSUE CREATION:
            - Automatically create issues when verified
            - Creates [AI Passive] issues automatically when confidence >= 85%
            """.trimIndent()
        )

        val warnings = AgentProfileLoader.validateProfile(
            profileName = "custom",
            availableTools = setOf("status", "issue_create")
        )

        assertTrue(warnings.any { it.contains("http1_request") })
        assertTrue(warnings.any { it.contains("http2_request") })
        assertFalse(warnings.any { it.contains("automatically") })
        assertFalse(warnings.any { it.contains("creates") })
    }

    @Test
    fun `validate profile suppresses unsafe warnings for catalog-only tools`() {
        val custom = tempDir.resolve("custom.md")
        custom.writeText(
            """
            [GLOBAL]
            Available MCP Tools:
            - status: Check status
            - http1_request / http2_request: Send test requests
            """.trimIndent()
        )

        val warnings = AgentProfileLoader.validateProfile(
            profileName = "custom",
            availableTools = setOf("status"),
            disabledReasons = mapOf(
                "http1_request" to "requires Unsafe mode or explicit per-tool unsafe approval.",
                "http2_request" to "requires Unsafe mode or explicit per-tool unsafe approval."
            )
        )

        assertFalse(warnings.any { it.contains("http1_request") })
        assertFalse(warnings.any { it.contains("http2_request") })
    }

    @Test
    fun `validate profile still warns for explicit unsafe tool calls`() {
        val custom = tempDir.resolve("custom.md")
        custom.writeText(
            """
            [GLOBAL]
            Use /tool http1_request {}
            """.trimIndent()
        )

        val warnings = AgentProfileLoader.validateProfile(
            profileName = "custom",
            availableTools = emptySet(),
            disabledReasons = mapOf(
                "http1_request" to "requires Unsafe mode or explicit per-tool unsafe approval."
            )
        )

        assertTrue(warnings.any { it.contains("http1_request") })
    }
}
