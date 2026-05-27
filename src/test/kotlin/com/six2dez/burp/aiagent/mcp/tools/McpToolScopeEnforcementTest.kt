package com.six2dez.burp.aiagent.mcp.tools

import burp.api.montoya.MontoyaApi
import burp.api.montoya.core.BurpSuiteEdition
import burp.api.montoya.http.HttpService
import burp.api.montoya.http.message.requests.HttpRequest
import burp.api.montoya.http.message.responses.HttpResponse
import burp.api.montoya.proxy.ProxyHttpRequestResponse
import burp.api.montoya.proxy.ProxyWebSocketMessage
import burp.api.montoya.websocket.Direction
import com.six2dez.burp.aiagent.mcp.McpRequestLimiter
import com.six2dez.burp.aiagent.mcp.McpToolCatalog
import com.six2dez.burp.aiagent.mcp.McpToolContext
import com.six2dez.burp.aiagent.redact.PrivacyMode
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.mockito.Answers
import org.mockito.kotlin.any
import org.mockito.kotlin.anyOrNull
import org.mockito.kotlin.mock
import org.mockito.kotlin.never
import org.mockito.kotlin.verify
import org.mockito.kotlin.whenever

/**
 * Per-tool scope-enforcement integration tests covering BUG-69-03 / 07-03-PLAN Task 2.
 *
 * Strategy:
 *  - For each READ tool that consults `McpScopeFilter.filterInScope`, build a stubbed Montoya
 *    API that returns a mix of in-scope and out-of-scope items. With `ctx.scopeOnly = true` the
 *    tool must omit out-of-scope items; with `ctx.scopeOnly = false` it must return all items
 *    (bytewise no-op for backwards compatibility).
 *  - For each WRITE tool that consults `McpScopeFilter.rejectIfOutOfScope`, stub `api.scope()`
 *    so the target URL is out of scope and assert the tool returns the documented rejection
 *    string AND never calls the corresponding `api.http()/api.repeater()/api.intruder()` sink.
 *    With `scopeOnly = false` the tool must proceed exactly as it does today.
 *
 * All MCP tool calls go through `McpToolExecutor.executeToolResult` so the tests exercise the
 * real handler dispatch, the toolToggles gate, and the per-tool URL extraction logic.
 */
class McpToolScopeEnforcementTest {
    private val inScopeHost = "example.com"
    private val outOfScopeHost = "blocked.test"

    // ── proxy_http_history ───────────────────────────────────────────────────────────────

    @Test
    fun proxyHttpHistory_scopeOn_filtersOutOfScopeItems() {
        val api = stubProxyHistoryApi(mixedHistoryItems())
        val context = contextWith(api, scopeOnly = true)
        val result = exec("proxy_http_history", "{\"count\":10}", context)

        assertTrue(result.contains(inScopeHost), "in-scope item should remain in output")
        assertFalse(result.contains(outOfScopeHost), "out-of-scope item must be filtered out")
    }

    @Test
    fun proxyHttpHistory_scopeOff_isNoOp() {
        val api = stubProxyHistoryApi(mixedHistoryItems())
        val context = contextWith(api, scopeOnly = false)
        val result = exec("proxy_http_history", "{\"count\":10}", context)

        assertTrue(result.contains(inScopeHost), "in-scope item should be present")
        assertTrue(result.contains(outOfScopeHost), "scopeOnly=false MUST keep out-of-scope items")
    }

    // ── proxy_http_history_regex ─────────────────────────────────────────────────────────

    @Test
    fun proxyHttpHistoryRegex_scopeOn_filtersOutOfScopeItems() {
        val api = stubProxyHistoryRegexApi(mixedHistoryItems())
        val context = contextWith(api, scopeOnly = true)
        val result = exec("proxy_http_history_regex", "{\"regex\":\".*\",\"count\":10}", context)

        assertTrue(result.contains(inScopeHost))
        assertFalse(result.contains(outOfScopeHost))
    }

    @Test
    fun proxyHttpHistoryRegex_scopeOff_isNoOp() {
        val api = stubProxyHistoryRegexApi(mixedHistoryItems())
        val context = contextWith(api, scopeOnly = false)
        val result = exec("proxy_http_history_regex", "{\"regex\":\".*\",\"count\":10}", context)

        assertTrue(result.contains(inScopeHost))
        assertTrue(result.contains(outOfScopeHost))
    }

    // ── proxy_history_annotate ───────────────────────────────────────────────────────────

    @Test
    fun proxyHistoryAnnotate_perCallScopeOnlyFalseAndCtxScopeOnlyTrue_stillFilters() {
        // Sanity for the OR'd semantics: the global mcpScopeOnly toggle MUST override a
        // per-call `scopeOnly = false`. Tests the (scopeOnly || context.scopeOnly) line.
        val api = stubProxyHistoryRegexApi(mixedHistoryItems())
        val context = contextWith(api, scopeOnly = true)
        val result =
            exec(
                "proxy_history_annotate",
                "{\"regex\":\".*\",\"note\":\"t\",\"scopeOnly\":false,\"limit\":50}",
                context,
            )

        assertTrue(result.contains(inScopeHost), "in-scope URL should be annotated")
        assertFalse(result.contains(outOfScopeHost), "global scopeOnly must beat per-call scopeOnly=false")
    }

    @Test
    fun proxyHistoryAnnotate_perCallScopeOnlyTrueAndCtxScopeOnlyFalse_stillFilters() {
        // Backwards-compat: the existing per-call `scopeOnly = true` parameter MUST continue
        // to filter even when the global toggle is off. This is the historical behaviour.
        val api = stubProxyHistoryRegexApi(mixedHistoryItems())
        val context = contextWith(api, scopeOnly = false)
        val result =
            exec(
                "proxy_history_annotate",
                "{\"regex\":\".*\",\"note\":\"t\",\"scopeOnly\":true,\"limit\":50}",
                context,
            )

        assertTrue(result.contains(inScopeHost))
        assertFalse(result.contains(outOfScopeHost))
    }

    @Test
    fun proxyHistoryAnnotate_bothScopeOnlyFalse_doesNotFilter() {
        val api = stubProxyHistoryRegexApi(mixedHistoryItems())
        val context = contextWith(api, scopeOnly = false)
        val result =
            exec(
                "proxy_history_annotate",
                "{\"regex\":\".*\",\"note\":\"t\",\"scopeOnly\":false,\"limit\":50}",
                context,
            )

        assertTrue(result.contains(inScopeHost))
        assertTrue(result.contains(outOfScopeHost))
    }

    // ── response_body_search ─────────────────────────────────────────────────────────────

    @Test
    fun responseBodySearch_perCallScopeOnlyFalseAndCtxScopeOnlyTrue_stillFilters() {
        val api = stubProxyHistoryApi(mixedHistoryItemsWithBodies())
        val context = contextWith(api, scopeOnly = true)
        val result =
            exec(
                "response_body_search",
                "{\"regex\":\"needle\",\"scopeOnly\":false,\"count\":10}",
                context,
            )

        assertTrue(result.contains(inScopeHost))
        assertFalse(result.contains(outOfScopeHost))
    }

    @Test
    fun responseBodySearch_bothScopeOnlyFalse_returnsAllMatches() {
        val api = stubProxyHistoryApi(mixedHistoryItemsWithBodies())
        val context = contextWith(api, scopeOnly = false)
        val result =
            exec(
                "response_body_search",
                "{\"regex\":\"needle\",\"scopeOnly\":false,\"count\":10}",
                context,
            )

        assertTrue(result.contains(inScopeHost))
        assertTrue(result.contains(outOfScopeHost))
    }

    // ── proxy_ws_history / proxy_ws_history_regex ────────────────────────────────────────

    @Test
    fun proxyWsHistory_scopeOn_filtersOutOfScopeUpgrades() {
        val api = stubWebSocketHistoryApi(mixedWebSocketItems())
        val context = contextWith(api, scopeOnly = true)
        val result = exec("proxy_ws_history", "{\"count\":10}", context)

        assertTrue(result.contains("in-scope-payload"))
        assertFalse(result.contains("out-of-scope-payload"))
    }

    @Test
    fun proxyWsHistory_scopeOff_isNoOp() {
        val api = stubWebSocketHistoryApi(mixedWebSocketItems())
        val context = contextWith(api, scopeOnly = false)
        val result = exec("proxy_ws_history", "{\"count\":10}", context)

        assertTrue(result.contains("in-scope-payload"))
        assertTrue(result.contains("out-of-scope-payload"))
    }

    @Test
    fun proxyWsHistoryRegex_scopeOn_filtersOutOfScopeUpgrades() {
        val api = stubWebSocketHistoryRegexApi(mixedWebSocketItems())
        val context = contextWith(api, scopeOnly = true)
        val result = exec("proxy_ws_history_regex", "{\"regex\":\".*\",\"count\":10}", context)

        assertTrue(result.contains("in-scope-payload"))
        assertFalse(result.contains("out-of-scope-payload"))
    }

    @Test
    fun proxyWsHistoryRegex_scopeOff_isNoOp() {
        val api = stubWebSocketHistoryRegexApi(mixedWebSocketItems())
        val context = contextWith(api, scopeOnly = false)
        val result = exec("proxy_ws_history_regex", "{\"regex\":\".*\",\"count\":10}", context)

        assertTrue(result.contains("in-scope-payload"))
        assertTrue(result.contains("out-of-scope-payload"))
    }

    // ── site_map / site_map_regex ────────────────────────────────────────────────────────

    @Test
    fun siteMap_scopeOn_filtersOutOfScopeItems() {
        val api = stubSiteMapApi(mixedSiteMapItems())
        val context = contextWith(api, scopeOnly = true)
        val result = exec("site_map", "{\"count\":10}", context)

        assertTrue(result.contains(inScopeHost))
        assertFalse(result.contains(outOfScopeHost))
    }

    @Test
    fun siteMap_scopeOff_isNoOp() {
        val api = stubSiteMapApi(mixedSiteMapItems())
        val context = contextWith(api, scopeOnly = false)
        val result = exec("site_map", "{\"count\":10}", context)

        assertTrue(result.contains(inScopeHost))
        assertTrue(result.contains(outOfScopeHost))
    }

    @Test
    fun siteMapRegex_scopeOn_filtersOutOfScopeItems() {
        val api = stubSiteMapRegexApi(mixedSiteMapItems())
        val context = contextWith(api, scopeOnly = true)
        val result = exec("site_map_regex", "{\"regex\":\".*\",\"count\":10}", context)

        assertTrue(result.contains(inScopeHost))
        assertFalse(result.contains(outOfScopeHost))
    }

    @Test
    fun siteMapRegex_scopeOff_isNoOp() {
        val api = stubSiteMapRegexApi(mixedSiteMapItems())
        val context = contextWith(api, scopeOnly = false)
        val result = exec("site_map_regex", "{\"regex\":\".*\",\"count\":10}", context)

        assertTrue(result.contains(inScopeHost))
        assertTrue(result.contains(outOfScopeHost))
    }

    // ── WRITE-style tools ────────────────────────────────────────────────────────────────

    @Test
    fun http1Request_scopeOn_rejectsOutOfScopeAndNeverHitsApi() {
        val api = stubWriteApi()
        val context = contextWith(api, scopeOnly = true)

        val rawRequest = "GET / HTTP/1.1\r\nHost: $outOfScopeHost\r\n\r\n"
        val args =
            "{\"content\":${jsonString(rawRequest)},\"targetHostname\":\"$outOfScopeHost\"," +
                "\"targetPort\":443,\"usesHttps\":true}"
        val result = exec("http1_request", args, context)

        assertTrue(
            result.contains("is out of scope (mcpScopeOnly=true)"),
            "expected rejection string, got: $result",
        )
        verify(api.http(), never()).sendRequest(any<HttpRequest>(), any<burp.api.montoya.http.RequestOptions>())
    }

    @Test
    fun http1Request_scopeOff_doesNotShortCircuitOnScope() {
        // With scopeOnly off, the tool MUST NOT return the scope-rejection string for an
        // out-of-scope URL. In a pure-JVM test the underlying HttpRequest.httpRequest() factory
        // is not loaded so the handler will surface an error string, but the critical guarantee
        // is the absence of the McpScopeFilter rejection text.
        val api = stubWriteApi()
        val context = contextWith(api, scopeOnly = false)

        val rawRequest = "GET / HTTP/1.1\r\nHost: $outOfScopeHost\r\n\r\n"
        val args =
            "{\"content\":${jsonString(rawRequest)},\"targetHostname\":\"$outOfScopeHost\"," +
                "\"targetPort\":443,\"usesHttps\":true}"
        val result = exec("http1_request", args, context)

        assertFalse(
            result.contains("is out of scope (mcpScopeOnly=true)"),
            "scopeOnly=false must not return the McpScopeFilter rejection string",
        )
        // Scope was never consulted in the off branch.
        verify(api.scope(), never()).isInScope(any())
    }

    @Test
    fun http2Request_scopeOn_rejectsOutOfScopeAndNeverHitsApi() {
        val api = stubWriteApi()
        val context = contextWith(api, scopeOnly = true)

        val args =
            "{\"pseudoHeaders\":{\"method\":\"GET\",\"path\":\"/\",\"scheme\":\"https\",\"authority\":\"$outOfScopeHost\"}," +
                "\"headers\":{},\"requestBody\":\"\",\"targetHostname\":\"$outOfScopeHost\"," +
                "\"targetPort\":443,\"usesHttps\":true}"
        val result = exec("http2_request", args, context)

        assertTrue(
            result.contains("is out of scope (mcpScopeOnly=true)"),
            "expected rejection, got: $result",
        )
        verify(api.http(), never()).sendRequest(any<HttpRequest>(), any<burp.api.montoya.http.RequestOptions>())
    }

    @Test
    fun repeaterTab_scopeOn_rejectsOutOfScopeAndNeverHitsApi() {
        val api = stubWriteApi()
        val context = contextWith(api, scopeOnly = true)

        val rawRequest = "GET / HTTP/1.1\r\nHost: $outOfScopeHost\r\n\r\n"
        val args =
            "{\"tabName\":\"t\",\"content\":${jsonString(rawRequest)},\"targetHostname\":\"$outOfScopeHost\"," +
                "\"targetPort\":443,\"usesHttps\":true}"
        val result = exec("repeater_tab", args, context)

        assertTrue(result.contains("is out of scope (mcpScopeOnly=true)"))
        verify(api.repeater(), never()).sendToRepeater(any<HttpRequest>(), anyOrNull<String>())
    }

    @Test
    fun repeaterTabWithPayload_scopeOn_rejectsOutOfScopeAndNeverHitsApi() {
        val api = stubWriteApi()
        val context = contextWith(api, scopeOnly = true)

        val rawRequest = "GET / HTTP/1.1\r\nHost: $outOfScopeHost\r\n\r\n"
        val args =
            "{\"tabName\":\"t\",\"content\":${jsonString(rawRequest)},\"replacements\":{}," +
                "\"targetHostname\":\"$outOfScopeHost\",\"targetPort\":443,\"usesHttps\":true}"
        val result = exec("repeater_tab_with_payload", args, context)

        assertTrue(result.contains("is out of scope (mcpScopeOnly=true)"))
        verify(api.repeater(), never()).sendToRepeater(any<HttpRequest>(), anyOrNull<String>())
    }

    @Test
    fun intruder_scopeOn_rejectsOutOfScopeAndNeverHitsApi() {
        val api = stubWriteApi()
        val context = contextWith(api, scopeOnly = true)

        val rawRequest = "GET / HTTP/1.1\r\nHost: $outOfScopeHost\r\n\r\n"
        val args =
            "{\"tabName\":\"t\",\"content\":${jsonString(rawRequest)},\"targetHostname\":\"$outOfScopeHost\"," +
                "\"targetPort\":443,\"usesHttps\":true}"
        val result = exec("intruder", args, context)

        assertTrue(result.contains("is out of scope (mcpScopeOnly=true)"))
        verify(api.intruder(), never()).sendToIntruder(any<HttpRequest>(), anyOrNull<String>())
    }

    @Test
    fun intruderPrepare_scopeOn_rejectsOutOfScopeAndNeverHitsApi() {
        val api = stubWriteApi()
        val context = contextWith(api, scopeOnly = true)

        val rawRequest = "GET / HTTP/1.1\r\nHost: $outOfScopeHost\r\n\r\n"
        val args =
            "{\"tabName\":\"t\",\"content\":${jsonString(rawRequest)},\"insertionPoints\":[]," +
                "\"mode\":\"REPLACE_BASE_PARAMETER_VALUE_WITH_OFFSETS\"," +
                "\"targetHostname\":\"$outOfScopeHost\",\"targetPort\":443,\"usesHttps\":true}"
        val result = exec("intruder_prepare", args, context)

        assertTrue(result.contains("is out of scope (mcpScopeOnly=true)"))
        // The handler MUST short-circuit before sendToIntruder is called.
        verify(api.intruder(), never()).sendToIntruder(
            any<HttpService>(),
            any<burp.api.montoya.intruder.HttpRequestTemplate>(),
            any(),
        )
    }

    // ── Test fixtures ────────────────────────────────────────────────────────────────────

    private fun exec(
        toolId: String,
        argsJson: String,
        context: McpToolContext,
    ): String = McpToolExecutor.executeTool(toolId, argsJson, context)

    /**
     * Builds an [McpToolContext] with every catalog tool enabled (so `runTool`'s toggle gate
     * never blocks the call), every unsafe tool pre-approved (so the unsafe gate is open for
     * write-style tools), and a stubbed scope where the configured in-scope host is the only
     * host that satisfies `api.scope().isInScope(...)`.
     */
    private fun contextWith(
        api: MontoyaApi,
        scopeOnly: Boolean,
    ): McpToolContext =
        McpToolContext(
            api = api,
            privacyMode = PrivacyMode.OFF,
            determinismMode = false,
            hostSalt = "test",
            toolToggles = McpToolCatalog.all().associate { it.id to true },
            unsafeEnabled = true,
            unsafeTools = McpToolCatalog.unsafeToolIds(),
            enabledUnsafeTools = McpToolCatalog.unsafeToolIds(),
            limiter = McpRequestLimiter(8),
            edition = BurpSuiteEdition.PROFESSIONAL,
            maxBodyBytes = 16_384,
            scopeOnly = scopeOnly,
        )

    private fun newDeepStubApi(): MontoyaApi {
        val api = mock<MontoyaApi>(defaultAnswer = Answers.RETURNS_DEEP_STUBS)
        whenever(api.burpSuite().version().edition()).thenReturn(BurpSuiteEdition.PROFESSIONAL)
        // In-scope only for the canonical host; everything else is out of scope.
        whenever(api.scope().isInScope(any())).thenAnswer { invocation ->
            val url = invocation.getArgument<String>(0)
            url.contains(inScopeHost)
        }
        return api
    }

    private fun stubProxyHistoryApi(items: List<ProxyHttpRequestResponse>): MontoyaApi {
        val api = newDeepStubApi()
        whenever(api.proxy().history()).thenReturn(items)
        return api
    }

    private fun stubProxyHistoryRegexApi(items: List<ProxyHttpRequestResponse>): MontoyaApi {
        val api = newDeepStubApi()
        whenever(api.proxy().history()).thenReturn(items) // for response_body_search fallback
        whenever(api.proxy().history(any())).thenReturn(items)
        return api
    }

    private fun stubWebSocketHistoryApi(items: List<ProxyWebSocketMessage>): MontoyaApi {
        val api = newDeepStubApi()
        whenever(api.proxy().webSocketHistory()).thenReturn(items)
        return api
    }

    private fun stubWebSocketHistoryRegexApi(items: List<ProxyWebSocketMessage>): MontoyaApi {
        val api = newDeepStubApi()
        whenever(api.proxy().webSocketHistory(any())).thenReturn(items)
        return api
    }

    private fun stubSiteMapApi(items: List<burp.api.montoya.http.message.HttpRequestResponse>): MontoyaApi {
        val api = newDeepStubApi()
        whenever(api.siteMap().requestResponses()).thenReturn(items)
        return api
    }

    private fun stubSiteMapRegexApi(items: List<burp.api.montoya.http.message.HttpRequestResponse>): MontoyaApi {
        val api = newDeepStubApi()
        whenever(api.siteMap().requestResponses(any())).thenReturn(items)
        return api
    }

    private fun stubWriteApi(): MontoyaApi {
        val api = newDeepStubApi()
        // sendRequest returns null by default for deep stubs; we let the handler render its
        // own "<no response>" string. The important assertion is verify(...).never() OR
        // verify(...) — we don't need a meaningful response object.
        return api
    }

    // ── Stubbed Montoya items ────────────────────────────────────────────────────────────

    private fun mixedHistoryItems(): List<ProxyHttpRequestResponse> =
        listOf(
            stubProxyItem("https://$inScopeHost/a", ""),
            stubProxyItem("https://$outOfScopeHost/x", ""),
        )

    private fun mixedHistoryItemsWithBodies(): List<ProxyHttpRequestResponse> =
        listOf(
            // response_body_search splits the response at \r\n\r\n and matches against the body.
            stubProxyItem(
                "https://$inScopeHost/a",
                "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nneedle here",
            ),
            stubProxyItem(
                "https://$outOfScopeHost/x",
                "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nneedle here too",
            ),
        )

    private fun mixedSiteMapItems(): List<burp.api.montoya.http.message.HttpRequestResponse> =
        listOf(
            stubSiteMapItem("https://$inScopeHost/a"),
            stubSiteMapItem("https://$outOfScopeHost/x"),
        )

    private fun mixedWebSocketItems(): List<ProxyWebSocketMessage> =
        listOf(
            stubWsItem("https://$inScopeHost/ws", "in-scope-payload"),
            stubWsItem("https://$outOfScopeHost/ws", "out-of-scope-payload"),
        )

    private fun stubProxyItem(
        url: String,
        rawResponse: String,
    ): ProxyHttpRequestResponse {
        val item = mock<ProxyHttpRequestResponse>(defaultAnswer = Answers.RETURNS_DEEP_STUBS)
        val request = mock<HttpRequest>(defaultAnswer = Answers.RETURNS_DEEP_STUBS)
        whenever(request.url()).thenReturn(url)
        whenever(request.toString()).thenReturn("GET $url")
        whenever(item.request()).thenReturn(request)
        if (rawResponse.isBlank()) {
            whenever(item.response()).thenReturn(null)
        } else {
            val response = mock<HttpResponse>(defaultAnswer = Answers.RETURNS_DEEP_STUBS)
            whenever(response.toString()).thenReturn(rawResponse)
            whenever(item.response()).thenReturn(response)
        }
        whenever(item.annotations().notes()).thenReturn("")
        return item
    }

    private fun stubSiteMapItem(url: String): burp.api.montoya.http.message.HttpRequestResponse {
        val item =
            mock<burp.api.montoya.http.message.HttpRequestResponse>(
                defaultAnswer = Answers.RETURNS_DEEP_STUBS,
            )
        val request = mock<HttpRequest>(defaultAnswer = Answers.RETURNS_DEEP_STUBS)
        whenever(request.url()).thenReturn(url)
        whenever(request.toString()).thenReturn("GET $url")
        whenever(item.request()).thenReturn(request)
        whenever(item.response()).thenReturn(null)
        whenever(item.annotations().notes()).thenReturn("")
        return item
    }

    private fun stubWsItem(
        upgradeUrl: String,
        payload: String,
    ): ProxyWebSocketMessage {
        val item = mock<ProxyWebSocketMessage>(defaultAnswer = Answers.RETURNS_DEEP_STUBS)
        val upgrade = mock<HttpRequest>(defaultAnswer = Answers.RETURNS_DEEP_STUBS)
        whenever(upgrade.url()).thenReturn(upgradeUrl)
        whenever(item.upgradeRequest()).thenReturn(upgrade)
        whenever(item.direction()).thenReturn(Direction.CLIENT_TO_SERVER)
        // Mock ByteArray to dodge the Montoya factory dependency in pure-JVM tests.
        // The serializer calls toString() on it, so that's the only method we need to stub.
        val byteArray = mock<burp.api.montoya.core.ByteArray>()
        whenever(byteArray.toString()).thenReturn(payload)
        whenever(item.payload()).thenReturn(byteArray)
        whenever(item.annotations().notes()).thenReturn("")
        return item
    }

    private fun jsonString(raw: String): String {
        val escaped =
            raw
                .replace("\\", "\\\\")
                .replace("\"", "\\\"")
                .replace("\r", "\\r")
                .replace("\n", "\\n")
        return "\"$escaped\""
    }
}
