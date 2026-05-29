package com.six2dez.burp.aiagent.ui

import com.six2dez.burp.aiagent.mcp.McpToolDescriptor
import com.six2dez.burp.aiagent.ui.design.BadgeStyle

/**
 * Grouping result from [McpToolTabModel.groupTools].
 *
 * [native] contains tools where [McpToolDescriptor.nativeTool] is true, sorted by title.
 * [generic] contains tools where [McpToolDescriptor.nativeTool] is false, sorted by title.
 */
data class ToolGrouping(
    val native: List<McpToolDescriptor>,
    val generic: List<McpToolDescriptor>,
)

/**
 * Pure, Swing-free model helpers for the redesigned MCP Tools tab.
 *
 * This object contains only computation — no Swing imports, no mutable state, no I/O.
 * All helpers receive their inputs as parameters and return new values; callers own state.
 *
 * Contract reference: `.planning/phases/10-mcp-tools-tab-redesign/10-UI-SPEC.md`
 * Consumed by: Plan 02 (Swing rebuild of `buildMcpToolsPanel()`).
 */
object McpToolTabModel {

    /**
     * Splits [tools] into native (extension-native, BApp Store compatible) and generic
     * (Montoya API wrappers, full build only) groups, each sorted ascending by title.
     *
     * UI-03: the two groups are rendered as separate sections in the MCP tools tab.
     */
    fun groupTools(tools: List<McpToolDescriptor>): ToolGrouping {
        val (native, generic) = tools.partition { it.nativeTool }
        return ToolGrouping(
            native = native.sortedBy { it.title },
            generic = generic.sortedBy { it.title },
        )
    }

    /**
     * Returns the [BadgeStyle] for a given tool.
     *
     * UI-04: native tools display "Store + Full" with [BadgeStyle.NATIVE];
     * generic tools display "Full only" with [BadgeStyle.FULL].
     *
     * This is the sole source of truth for badge assignment; the Swing layer in Plan 02
     * calls this and passes the result to `toolBadge()`.
     */
    fun badgeStyle(tool: McpToolDescriptor): BadgeStyle =
        if (tool.nativeTool) BadgeStyle.NATIVE else BadgeStyle.FULL

    /**
     * Returns true when [tool] should be visible for the given [query].
     *
     * UI-05: match is case-insensitive against [McpToolDescriptor.title] or
     * [McpToolDescriptor.description]. A blank or whitespace-only [query] matches all tools.
     */
    fun filterPredicate(query: String, tool: McpToolDescriptor): Boolean {
        val trimmed = query.trim()
        if (trimmed.isEmpty()) return true
        return tool.title.contains(trimmed, ignoreCase = true) ||
            tool.description.contains(trimmed, ignoreCase = true)
    }

    /**
     * Returns the subset of [tools] that are both visible (pass [filterPredicate]) and
     * enabled (their id is NOT in [disabledIds]).
     *
     * UI-05 bulk toggle: "Enable all" / "Disable all" buttons operate only on tools
     * that are currently visible in the group and whose checkbox is enabled (not locked
     * by pro-only or unsafe-locked constraints). The caller builds [disabledIds] from
     * the set of tool IDs where `checkbox.isEnabled == false` and passes it here.
     *
     * This function contains no Swing dependency — it takes and returns plain
     * [McpToolDescriptor] lists.
     */
    fun bulkToggleTargets(
        tools: List<McpToolDescriptor>,
        query: String,
        disabledIds: Set<String>,
    ): List<McpToolDescriptor> =
        tools.filter { tool ->
            filterPredicate(query, tool) && tool.id !in disabledIds
        }

    /**
     * Groups [tools] by [McpToolDescriptor.category] and returns a [LinkedHashMap] with
     * categories sorted alphabetically (ascending, case-sensitive). Within each category,
     * tools are sorted ascending by [McpToolDescriptor.title].
     *
     * UI-03: drives the Montoya section's category sub-header rendering. The returned map
     * preserves insertion order, so iterating the map yields alphabetical category order.
     */
    fun categoryGroups(tools: List<McpToolDescriptor>): Map<String, List<McpToolDescriptor>> {
        val grouped = tools.groupBy { it.category }
        return LinkedHashMap<String, List<McpToolDescriptor>>().also { result ->
            grouped.keys
                .sorted()
                .forEach { category ->
                    result[category] = grouped.getValue(category).sortedBy { it.title }
                }
        }
    }
}
