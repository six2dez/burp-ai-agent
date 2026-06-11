package com.six2dez.burp.aiagent.ui

import com.six2dez.burp.aiagent.mcp.McpToolDescriptor
import com.six2dez.burp.aiagent.ui.design.BadgeStyle
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

/**
 * Unit tests for [McpToolTabModel] — pure grouping/badge/filter/bulk-toggle helpers.
 *
 * No Swing instantiation. No javax.swing or java.awt imports.
 * All 14+ tests exercise observable behaviour defined in the UI-SPEC.
 */
class McpToolTabModelTest {
    // -------------------------------------------------------------------------
    // Test helper — builds a McpToolDescriptor with minimal repetition
    // -------------------------------------------------------------------------

    private fun descriptor(
        id: String,
        title: String,
        description: String = "",
        category: String = "Cat",
        nativeTool: Boolean = false,
        proOnly: Boolean = false,
        unsafeOnly: Boolean = false,
    ) = McpToolDescriptor(
        id = id,
        title = title,
        description = description,
        category = category,
        defaultEnabled = true,
        nativeTool = nativeTool,
        proOnly = proOnly,
        unsafeOnly = unsafeOnly,
    )

    // -------------------------------------------------------------------------
    // groupTools — native list
    // -------------------------------------------------------------------------

    @Test
    fun groupTools_nativeToolsGoToNativeList() {
        val tools =
            listOf(
                descriptor("n1", "Native One", nativeTool = true),
                descriptor("n2", "Native Two", nativeTool = true),
                descriptor("g1", "Generic One", nativeTool = false),
                descriptor("g2", "Generic Two", nativeTool = false),
            )
        val grouping = McpToolTabModel.groupTools(tools)

        assertEquals(2, grouping.native.size)
        assertEquals(2, grouping.generic.size)
        assertTrue(grouping.native.all { it.nativeTool })
        assertFalse(grouping.generic.any { it.nativeTool })
    }

    @Test
    fun groupTools_nativeListIsSortedByTitle() {
        val tools =
            listOf(
                descriptor("z", "Zebra", nativeTool = true),
                descriptor("a", "Alpha", nativeTool = true),
                descriptor("m", "Mango", nativeTool = true),
            )
        val grouping = McpToolTabModel.groupTools(tools)

        assertEquals(listOf("Alpha", "Mango", "Zebra"), grouping.native.map { it.title })
    }

    @Test
    fun groupTools_genericListIsSortedByTitle() {
        val tools =
            listOf(
                descriptor("z", "Zebra", nativeTool = false),
                descriptor("a", "Alpha", nativeTool = false),
                descriptor("m", "Mango", nativeTool = false),
            )
        val grouping = McpToolTabModel.groupTools(tools)

        assertEquals(listOf("Alpha", "Mango", "Zebra"), grouping.generic.map { it.title })
    }

    @Test
    fun groupTools_noNativeToolsGivesEmptyNativeList() {
        val tools =
            listOf(
                descriptor("g1", "Generic One", nativeTool = false),
                descriptor("g2", "Generic Two", nativeTool = false),
            )
        val grouping = McpToolTabModel.groupTools(tools)

        assertTrue(grouping.native.isEmpty())
        assertEquals(2, grouping.generic.size)
    }

    // -------------------------------------------------------------------------
    // badgeStyle — UI-04
    // -------------------------------------------------------------------------

    @Test
    fun badgeStyle_nativeToolReturnsBadgeNative() {
        val tool = descriptor("t1", "Tool", nativeTool = true)
        assertEquals(BadgeStyle.NATIVE, McpToolTabModel.badgeStyle(tool))
    }

    @Test
    fun badgeStyle_genericToolReturnsBadgeFull() {
        val tool = descriptor("t1", "Tool", nativeTool = false)
        assertEquals(BadgeStyle.FULL, McpToolTabModel.badgeStyle(tool))
    }

    // -------------------------------------------------------------------------
    // filterPredicate — UI-05 search
    // -------------------------------------------------------------------------

    @Test
    fun filterPredicate_blankQueryMatchesAll() {
        val tool = descriptor("t1", "Some Tool", description = "Does something")

        // Empty string
        assertTrue(McpToolTabModel.filterPredicate("", tool))
        // Whitespace-only
        assertTrue(McpToolTabModel.filterPredicate("   ", tool))
    }

    @Test
    fun filterPredicate_titleMatchCaseInsensitive() {
        val tool = descriptor("t1", "AI Analyze", description = "Sends text to AI backend")

        assertTrue(McpToolTabModel.filterPredicate("analyze", tool))
        assertTrue(McpToolTabModel.filterPredicate("ANALYZE", tool))
        assertTrue(McpToolTabModel.filterPredicate("Analyze", tool))
    }

    @Test
    fun filterPredicate_descriptionMatchCaseInsensitive() {
        val tool = descriptor("t1", "Proxy History", description = "Displays proxy history items")

        assertTrue(McpToolTabModel.filterPredicate("PROXY", tool))
        assertTrue(McpToolTabModel.filterPredicate("proxy", tool))
        assertTrue(McpToolTabModel.filterPredicate("history items", tool))
    }

    @Test
    fun filterPredicate_nonMatchReturnsFalse() {
        val tool = descriptor("t1", "URL Encode", description = "URL encodes the input string")

        assertFalse(McpToolTabModel.filterPredicate("xyzzy", tool))
    }

    // -------------------------------------------------------------------------
    // bulkToggleTargets — UI-05 bulk toggle
    // -------------------------------------------------------------------------

    @Test
    fun bulkToggleTargets_excludesDisabledIds() {
        val tools =
            listOf(
                descriptor("t1", "Tool One"),
                descriptor("t2", "Tool Two"),
                descriptor("t3", "Tool Three"),
            )
        val disabledIds = setOf("t2")
        val result = McpToolTabModel.bulkToggleTargets(tools, "", disabledIds)

        assertEquals(2, result.size)
        assertFalse(result.any { it.id == "t2" })
        assertTrue(result.any { it.id == "t1" })
        assertTrue(result.any { it.id == "t3" })
    }

    @Test
    fun bulkToggleTargets_filterApplied() {
        val tools =
            listOf(
                descriptor("t1", "Proxy History", description = "Shows proxy items"),
                descriptor("t2", "Scanner Issues", description = "Shows scanner findings"),
                descriptor("t3", "Site Map", description = "Shows site map entries"),
            )
        // Query matches only "Proxy History" by title
        val result = McpToolTabModel.bulkToggleTargets(tools, "proxy", emptySet())

        assertEquals(1, result.size)
        assertEquals("t1", result[0].id)
    }

    @Test
    fun bulkToggleTargets_allVisibleWhenQueryBlankAndNoDisabledIds() {
        val tools =
            listOf(
                descriptor("t1", "Tool One"),
                descriptor("t2", "Tool Two"),
                descriptor("t3", "Tool Three"),
            )
        val result = McpToolTabModel.bulkToggleTargets(tools, "", emptySet())

        assertEquals(3, result.size)
    }

    // -------------------------------------------------------------------------
    // categoryGroups
    // -------------------------------------------------------------------------

    @Test
    fun categoryGroups_sortedAlphabetically() {
        val tools =
            listOf(
                descriptor("u1", "Encode", category = "Utilities"),
                descriptor("b1", "Pause", category = "Burp Control"),
                descriptor("h1", "Proxy History", category = "History"),
            )
        val groups = McpToolTabModel.categoryGroups(tools)

        assertEquals(listOf("Burp Control", "History", "Utilities"), groups.keys.toList())
    }

    @Test
    fun categoryGroups_toolsWithinGroupSortedByTitle() {
        val tools =
            listOf(
                descriptor("z", "Zap", category = "Requests"),
                descriptor("a", "Alpha", category = "Requests"),
            )
        val groups = McpToolTabModel.categoryGroups(tools)
        val titles = groups.getValue("Requests").map { it.title }

        assertEquals(listOf("Alpha", "Zap"), titles)
    }
}
