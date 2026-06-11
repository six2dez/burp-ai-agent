package com.six2dez.burp.aiagent.mcp.tools

import burp.api.montoya.MontoyaApi
import burp.api.montoya.core.BurpSuiteEdition
import burp.api.montoya.http.message.requests.HttpRequest
import burp.api.montoya.http.message.responses.HttpResponse
import burp.api.montoya.proxy.ProxyHttpRequestResponse
import com.six2dez.burp.aiagent.mcp.McpRequestLimiter
import com.six2dez.burp.aiagent.mcp.McpToolCatalog
import com.six2dez.burp.aiagent.mcp.McpToolContext
import com.six2dez.burp.aiagent.redact.PrivacyMode
import org.junit.jupiter.api.Assertions.assertDoesNotThrow
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.mockito.Answers
import org.mockito.kotlin.mock
import org.mockito.kotlin.whenever

/**
 * SC5 — listener-port filter for proxy_http_history (CAP-03, 14-03-PLAN).
 *
 * Covers:
 *  - Filter to a specific port: only items on that port are returned.
 *  - No-match port: empty result, NOT an error.
 *  - Unset listener_port (null): all items returned (current behaviour preserved).
 *
 * Both dispatch paths are exercised (Pitfall 4 — 14-RESEARCH.md §Pitfall 4):
 *
 *  Path A — the mcpPaginatedTool<GetProxyHttpHistory> registration lambda (~L649 McpTools.kt).
 *    This path has `GetProxyHttpHistory` as `this` (lambda receiver), so `listenerPort` is in
 *    scope directly. We test it by simulating the filter step that the lambda applies to `seq`
 *    via `orderedProxyHistory`. Since the paginated lambda and the manual-decode path share
 *    the same `GetProxyHttpHistory` data class, referencing `listenerPort` in THIS test file
 *    already enforces the RED state (compilation error) until the field is added to the class.
 *    We exercise the filter predicate in the same way the lambda does:
 *        if (listenerPort != null) seq.filter { it.listenerPort() == listenerPort } else seq
 *
 *  Path B — the manual decode path in McpToolExecutor.executeToolResult (~L1860 McpTools.kt).
 *    We call McpToolExecutor.executeTool("proxy_http_history", ...) which goes through the full
 *    runTool dispatch. This verifies the filter is wired end-to-end in the manual path.
 */
class ProxyHistoryListenerPortFilterTest {
    // ── Fixtures ─────────────────────────────────────────────────────────────────

    private val host8080 = "port8080.example.com"
    private val host8081 = "port8081.example.com"
    private val host9999 = "port9999.example.com"

    /** Builds a stubbed ProxyHttpRequestResponse whose listenerPort() returns [port]. */
    private fun stubItem(
        url: String,
        port: Int,
    ): ProxyHttpRequestResponse {
        val item = mock<ProxyHttpRequestResponse>(defaultAnswer = Answers.RETURNS_DEEP_STUBS)
        val request = mock<HttpRequest>(defaultAnswer = Answers.RETURNS_DEEP_STUBS)
        whenever(request.url()).thenReturn(url)
        whenever(request.toString()).thenReturn("GET $url")
        whenever(item.request()).thenReturn(request)
        whenever(item.response()).thenReturn(null as HttpResponse?)
        whenever(item.annotations().notes()).thenReturn("")
        // CAP-03: the Montoya 2026.2 accessor under test
        whenever(item.listenerPort()).thenReturn(port)
        return item
    }

    /** Mixed history: two 8080 items, one 8081 item. */
    private fun mixedItems(): List<ProxyHttpRequestResponse> =
        listOf(
            stubItem("https://$host8080/a", 8080),
            stubItem("https://$host8080/b", 8080),
            stubItem("https://$host8081/x", 8081),
        )

    private fun stubApi(items: List<ProxyHttpRequestResponse>): MontoyaApi {
        val api = mock<MontoyaApi>(defaultAnswer = Answers.RETURNS_DEEP_STUBS)
        whenever(api.burpSuite().version().edition()).thenReturn(BurpSuiteEdition.PROFESSIONAL)
        whenever(api.proxy().history()).thenReturn(items)
        return api
    }

    private fun contextWith(api: MontoyaApi): McpToolContext =
        McpToolContext(
            api = api,
            privacyMode = PrivacyMode.OFF,
            determinismMode = false,
            hostSalt = "test",
            toolToggles = McpToolCatalog.all().associate { it.id to true },
            unsafeEnabled = false,
            unsafeTools = emptySet(),
            enabledUnsafeTools = emptySet(),
            limiter = McpRequestLimiter(8),
            edition = BurpSuiteEdition.PROFESSIONAL,
            maxBodyBytes = 65_536,
            scopeOnly = false,
        )

    // ── Path B: McpToolExecutor.executeTool (manual decode path ~L1860) ──────────

    @Test
    fun pathB_filterPort8080_returnsOnly8080Items() {
        val api = stubApi(mixedItems())
        val context = contextWith(api)

        // The decode path uses kotlinx-serialization with camelCase field names.
        // The MCP JSON parameter name matches the Kotlin field name: listenerPort (camelCase).
        val result =
            McpToolExecutor.executeTool(
                "proxy_http_history",
                "{\"count\":10,\"listenerPort\":8080}",
                context,
            )

        assertTrue(result.contains(host8080), "8080 host must be present: $result")
        assertFalse(result.contains(host8081), "8081 host must be absent: $result")
    }

    @Test
    fun pathB_filterPort9999_returnsEmptyNotError() {
        val api = stubApi(mixedItems())
        val context = contextWith(api)

        // Must not throw (no-match is an empty result, NOT an error).
        val result =
            assertDoesNotThrow<String> {
                McpToolExecutor.executeTool(
                    "proxy_http_history",
                    "{\"count\":10,\"listenerPort\":9999}",
                    context,
                )
            }

        assertFalse(result.startsWith("Error:"), "No-match must not return an error: $result")
        assertFalse(result.contains(host8080), "8080 items must not appear: $result")
        assertFalse(result.contains(host8081), "8081 items must not appear: $result")
    }

    @Test
    fun pathB_noListenerPort_returnsAllPorts() {
        val api = stubApi(mixedItems())
        val context = contextWith(api)

        val result =
            McpToolExecutor.executeTool(
                "proxy_http_history",
                "{\"count\":10}",
                context,
            )

        assertTrue(result.contains(host8080), "8080 host must be present: $result")
        assertTrue(result.contains(host8081), "8081 host must be present: $result")
    }

    // ── Path A: paginated lambda (~L649) — filter predicate exercised directly ──

    /**
     * The mcpPaginatedTool<GetProxyHttpHistory> lambda at ~L649 has `GetProxyHttpHistory` as
     * `this`. The filter it applies is:
     *
     *     val lp = listenerPort  // `this.listenerPort`
     *     seq.let { s -> if (lp != null) s.filter { it.listenerPort() == lp } else s }
     *
     * We replicate this predicate here using the SAME field from GetProxyHttpHistory.
     * Referencing `GetProxyHttpHistory(listenerPort = ...)` causes compilation failure (RED)
     * until the field is added — proving the paginated path's schema dependency.
     */
    @Test
    fun pathA_filterPort8080_predicateKeepsOnly8080Items() {
        val input = GetProxyHttpHistory(count = 10, offset = 0, listenerPort = 8080)
        val items = mixedItems()

        // Simulate the paginated-path filter exactly as the lambda will apply it.
        val lp = input.listenerPort
        val filtered = if (lp != null) items.filter { it.listenerPort() == lp } else items

        assertEquals(2, filtered.size, "Expected exactly 2 items on port 8080")
        assertTrue(filtered.all { it.listenerPort() == 8080 }, "All filtered items must be on port 8080")
    }

    @Test
    fun pathA_filterPort9999_predicateReturnsEmpty() {
        val input = GetProxyHttpHistory(count = 10, offset = 0, listenerPort = 9999)
        val items = mixedItems()

        val lp = input.listenerPort
        val filtered = if (lp != null) items.filter { it.listenerPort() == lp } else items

        assertTrue(filtered.isEmpty(), "No-match must return empty list, not throw: $filtered")
    }

    @Test
    fun pathA_noListenerPort_predicateReturnsAll() {
        val input = GetProxyHttpHistory(count = 10, offset = 0, listenerPort = null)
        val items = mixedItems()

        val lp = input.listenerPort
        val filtered = if (lp != null) items.filter { it.listenerPort() == lp } else items

        assertEquals(3, filtered.size, "All items must be returned when listenerPort is null")
    }

    // ── GetProxyHttpHistoryRestricted schema coverage ────────────────────────────

    /**
     * Ensures GetProxyHttpHistoryRestricted also gains the listenerPort field (the manual
     * schema branch at ~L2320 exposes this class under restricted settings). The field must
     * appear in BOTH data classes so listener_port is in the tool schema under BOTH the
     * unpreprocessed-allowed and restricted branches.
     */
    @Test
    fun restrictedDataClass_hasListenerPortField() {
        // Referencing listenerPort on GetProxyHttpHistoryRestricted causes RED until added.
        val restricted = GetProxyHttpHistoryRestricted(count = 5, offset = 0, listenerPort = 8080)
        assertEquals(8080, restricted.listenerPort, "GetProxyHttpHistoryRestricted must expose listenerPort")
    }
}
