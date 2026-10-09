package com.six2dez.burp.aiagent.mcp.tools

import burp.api.montoya.MontoyaApi
import burp.api.montoya.core.Annotations
import burp.api.montoya.core.BurpSuiteEdition
import burp.api.montoya.http.message.HttpRequestResponse
import burp.api.montoya.http.message.requests.HttpRequest
import burp.api.montoya.http.message.responses.HttpResponse
import burp.api.montoya.internal.MontoyaObjectFactory
import burp.api.montoya.internal.ObjectFactoryLocator
import burp.api.montoya.proxy.ProxyHttpRequestResponse
import com.six2dez.burp.aiagent.mcp.McpRequestLimiter
import com.six2dez.burp.aiagent.mcp.McpToolCatalog
import com.six2dez.burp.aiagent.mcp.McpToolContext
import com.six2dez.burp.aiagent.mcp.ToolCallOrigin
import com.six2dez.burp.aiagent.redact.PrivacyMode
import com.six2dez.burp.aiagent.scanner.PassiveAiScanner
import com.six2dez.burp.aiagent.supervisor.AgentSupervisor
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertSame
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.mockito.Answers
import org.mockito.kotlin.any
import org.mockito.kotlin.anyOrNull
import org.mockito.kotlin.argumentCaptor
import org.mockito.kotlin.doReturn
import org.mockito.kotlin.mock
import org.mockito.kotlin.verify
import org.mockito.kotlin.whenever

/**
 * Issue #90 - from Burp 2026.9, `api.proxy().history()` returns elements that implement ONLY
 * [ProxyHttpRequestResponse], which does not extend [HttpRequestResponse]. The `ai_passive_scan`
 * MCP tool must convert each kept history entry into an [HttpRequestResponse] (from the entry's
 * request, response and annotations) before handing the list to [PassiveAiScanner.manualScan],
 * instead of casting the history list.
 *
 * The history entries below are created with `mock<ProxyHttpRequestResponse>()`, so they implement
 * only that interface, exactly like Burp 2026.9's proxies. The scanner is a mock that does not
 * iterate its argument, so every test iterates the captured list itself with a type check.
 */
class AiPassiveScanProxyHistoryTest {
    private var savedFactory: MontoyaObjectFactory? = null
    private lateinit var api: MontoyaApi
    private lateinit var scanner: PassiveAiScanner

    @BeforeEach
    fun setUp() {
        savedFactory = ObjectFactoryLocator.FACTORY
        val factory = mock<MontoyaObjectFactory>(defaultAnswer = Answers.RETURNS_MOCKS)
        whenever(
            factory.httpRequestResponse(any<HttpRequest>(), anyOrNull<HttpResponse>(), anyOrNull<Annotations>()),
        ).thenAnswer { invocation ->
            val request = invocation.getArgument<HttpRequest>(0)
            val response = invocation.getArgument<HttpResponse?>(1)
            mock<HttpRequestResponse> {
                on { request() } doReturn request
                on { response() } doReturn response
                on { hasResponse() } doReturn (response != null)
            }
        }
        ObjectFactoryLocator.FACTORY = factory

        api = mock<MontoyaApi>(defaultAnswer = Answers.RETURNS_DEEP_STUBS)
        whenever(api.ai().isEnabled()).thenReturn(true)
        whenever(api.burpSuite().version().edition()).thenReturn(BurpSuiteEdition.PROFESSIONAL)

        scanner = mock<PassiveAiScanner>()
        whenever(scanner.manualScan(any(), any())).thenAnswer { invocation ->
            invocation.getArgument<List<*>>(0).size
        }
    }

    @AfterEach
    fun restoreFactory() {
        ObjectFactoryLocator.FACTORY = savedFactory
    }

    @Test
    fun queuesEveryProxyHistoryEntryAsAnHttpRequestResponse() {
        val entries =
            listOf(
                entry("https://a.example/one"),
                entry("https://b.example/two"),
                entry("https://c.example/three"),
            )
        whenever(api.proxy().history()).thenReturn(entries)

        val result = run("""{}""")

        assertEquals("Queued 3 requests for AI passive scan.", result)
        assertConvertedFrom(entries, capturedScanList())
    }

    @Test
    fun siteMapUrlFiltersOnTheEntryUrlAndMaxRequestsCapsTheCount() {
        val matching =
            listOf(
                entry("https://target.example/a"),
                entry("https://target.example/b"),
                entry("https://target.example/c"),
            )
        val entries =
            listOf(
                entry("https://other.example/x"),
                matching[0],
                entry("https://other.example/y"),
                matching[1],
                matching[2],
            )
        whenever(api.proxy().history()).thenReturn(entries)

        val result = run("""{"siteMapUrl":"target.example","maxRequests":2}""")

        assertEquals("Queued 2 requests for AI passive scan.", result)
        assertConvertedFrom(matching.take(2), capturedScanList())
    }

    @Test
    fun anEntryWithoutAResponseIsStillPassedWithANullResponse() {
        val withResponse = entry("https://a.example/ok")
        val withoutResponse = entry("https://a.example/pending", withResponse = false)
        whenever(api.proxy().history()).thenReturn(listOf(withResponse, withoutResponse))

        val result = run("""{}""")

        assertEquals("Queued 2 requests for AI passive scan.", result)
        val converted = capturedScanList()
        assertConvertedFrom(listOf(withResponse, withoutResponse), converted)
        assertNull((converted[1] as HttpRequestResponse).response(), "an entry with no response keeps a null response")
    }

    private fun run(argsJson: String): String {
        val supervisor = mock<AgentSupervisor>()
        whenever(supervisor.isAiEnabled()).thenReturn(true)
        val context =
            McpToolContext(
                api = api,
                privacyMode = PrivacyMode.OFF,
                determinismMode = false,
                hostSalt = "test",
                toolToggles = McpToolCatalog.all().associate { it.id to true },
                unsafeEnabled = false,
                unsafeTools = McpToolCatalog.unsafeToolIds(),
                enabledUnsafeTools = emptySet(),
                limiter = McpRequestLimiter(4),
                edition = BurpSuiteEdition.PROFESSIONAL,
                maxBodyBytes = 1024,
                supervisor = supervisor,
                passiveScanner = scanner,
            )
        return McpToolExecutor.executeTool("ai_passive_scan", argsJson, context, ToolCallOrigin.UserSlashCommand)
    }

    /** The list `manualScan` received, read as `List<*>` so a wrong element type fails an assertion. */
    private fun capturedScanList(): List<*> {
        val captor = argumentCaptor<List<HttpRequestResponse>>()
        verify(scanner).manualScan(captor.capture(), any())
        return captor.firstValue as List<*>
    }

    private fun assertConvertedFrom(
        expected: List<ProxyHttpRequestResponse>,
        actual: List<*>,
    ) {
        assertEquals(expected.size, actual.size, "manualScan must receive one element per kept history entry")
        actual.forEachIndexed { index, element ->
            assertTrue(
                element is HttpRequestResponse,
                "manualScan element $index must be an HttpRequestResponse, got ${element?.javaClass?.name}",
            )
            val converted = element as HttpRequestResponse
            assertSame(expected[index].request(), converted.request(), "element $index must carry its entry's request")
            assertSame(expected[index].response(), converted.response(), "element $index must carry its entry's response")
        }
    }

    private fun entry(
        url: String,
        withResponse: Boolean = true,
    ): ProxyHttpRequestResponse {
        val request = mock<HttpRequest> { on { url() } doReturn url }
        val response: HttpResponse? = if (withResponse) mock<HttpResponse>() else null
        val annotations = mock<Annotations>()
        return mock<ProxyHttpRequestResponse> {
            on { url() } doReturn url
            on { request() } doReturn request
            on { response() } doReturn response
            on { hasResponse() } doReturn withResponse
            on { annotations() } doReturn annotations
        }
    }
}
