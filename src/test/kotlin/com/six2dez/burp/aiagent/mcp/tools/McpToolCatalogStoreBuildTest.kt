package com.six2dez.burp.aiagent.mcp.tools

import com.six2dez.burp.aiagent.mcp.McpToolCatalog
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class McpToolCatalogStoreBuildTest {
    @Test
    fun available_returnsOnlyNativeToolsWhenStoreBuildTrue() {
        val result = McpToolCatalog.available(storeBuild = true)
        assertTrue(result.all { it.nativeTool }, "Store build must return only native tools")
        assertTrue(result.isNotEmpty(), "At least one native tool must exist")
    }

    @Test
    fun available_returnsAllToolsWhenStoreBuildFalse() {
        val all = McpToolCatalog.all()
        val result = McpToolCatalog.available(storeBuild = false)
        assertEquals(all.size, result.size, "Full build returns all tools")
    }

    @Test
    fun available_nativeSubsetIsSubsetOfAll() {
        val allIds = McpToolCatalog.all().map { it.id }.toSet()
        val nativeIds = McpToolCatalog.available(storeBuild = true).map { it.id }.toSet()
        assertTrue(allIds.containsAll(nativeIds), "Native tools must be a subset of all tools")
    }
}
