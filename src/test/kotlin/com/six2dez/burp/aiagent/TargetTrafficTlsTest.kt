package com.six2dez.burp.aiagent

import burp.api.montoya.MontoyaApi
import burp.api.montoya.core.BurpSuiteEdition
import burp.api.montoya.http.Http
import burp.api.montoya.http.HttpMode
import burp.api.montoya.http.HttpService
import burp.api.montoya.http.RequestOptions
import burp.api.montoya.http.message.HttpRequestResponse
import burp.api.montoya.http.message.requests.HttpRequest
import burp.api.montoya.http.message.responses.HttpResponse
import burp.api.montoya.internal.MontoyaObjectFactory
import burp.api.montoya.internal.ObjectFactoryLocator
import burp.api.montoya.scanner.audit.insertionpoint.AuditInsertionPoint
import burp.api.montoya.scanner.audit.insertionpoint.AuditInsertionPointType
import com.six2dez.burp.aiagent.audit.AuditLogger
import com.six2dez.burp.aiagent.backends.http.MontoyaHttpTransport
import com.six2dez.burp.aiagent.mcp.McpRequestLimiter
import com.six2dez.burp.aiagent.mcp.McpToolCatalog
import com.six2dez.burp.aiagent.mcp.McpToolContext
import com.six2dez.burp.aiagent.mcp.ToolCallOrigin
import com.six2dez.burp.aiagent.mcp.tools.McpToolExecutor
import com.six2dez.burp.aiagent.redact.PrivacyMode
import com.six2dez.burp.aiagent.scanner.ActiveAiScanner
import com.six2dez.burp.aiagent.scanner.ActiveScanResult
import com.six2dez.burp.aiagent.scanner.ActiveScanTarget
import com.six2dez.burp.aiagent.scanner.AiScanCheck
import com.six2dez.burp.aiagent.scanner.InjectionPoint
import com.six2dez.burp.aiagent.scanner.InjectionType
import com.six2dez.burp.aiagent.scanner.ScanMode
import com.six2dez.burp.aiagent.scanner.VulnClass
import com.six2dez.burp.aiagent.scanner.VulnHint
import com.six2dez.burp.aiagent.supervisor.AgentSupervisor
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.mockito.Answers
import org.mockito.Mockito
import org.mockito.kotlin.any
import org.mockito.kotlin.doAnswer
import org.mockito.kotlin.doReturn
import org.mockito.kotlin.eq
import org.mockito.kotlin.mock
import org.mockito.kotlin.verify
import org.mockito.kotlin.whenever
import org.mockito.stubbing.Answer
import java.io.File
import java.lang.reflect.InvocationTargetException
import burp.api.montoya.core.ByteArray as MontoyaByteArray

/**
 * Hotfix 1.0.1 (quick 261008-vau): which outbound traffic asks Burp for upstream TLS certificate
 * verification.
 *
 * | Site | Traffic | Upstream TLS verification |
 * |---|---|---|
 * | scanner/ActiveAiScanner.kt (every baseline, payload, IDOR neighbour and 403 variant) | target | never |
 * | scanner/AiScanCheck.kt (attack and time-based baseline) | target | never |
 * | mcp/tools/McpToolExecutorImpl.kt (`http1_request`, `http2_request`) | target | never |
 * | mcp/tools/McpToolLegacy.kt (`registerToolsLegacy`, dead code) | target | exempt only while dead |
 * | backends/http/MontoyaHttpTransport.kt (`execute`) | AI provider | always |
 *
 * Target sends never require upstream verification, so self-signed and internal-CA targets can be
 * tested and Burp's own TLS settings apply to them as they do to every other Burp tool. The
 * AI-provider transport always requires it (PortSwigger's AI-extension requirement): prompts and
 * credentials cross to a third party there.
 *
 * The behaviour tests drive the real send paths through a mock Montoya object factory whose one
 * [RequestOptions] mock records every option invoked on it. The ledger tests pin the source tree:
 * a new `.sendRequest(` site turns [everyMontoyaSendSiteIsClassified] red until its author
 * classifies it in the table above and raises the count.
 */
class TargetTrafficTlsTest {
    private var savedFactory: MontoyaObjectFactory? = null
    private lateinit var factory: MontoyaObjectFactory
    private lateinit var options: RequestOptions
    private val scanners = mutableListOf<ActiveAiScanner>()

    @BeforeEach
    fun installFactory() {
        savedFactory = ObjectFactoryLocator.FACTORY
        options = mock<RequestOptions>(defaultAnswer = Answers.RETURNS_SELF)
        factory = mock<MontoyaObjectFactory>(defaultAnswer = Answers.RETURNS_MOCKS)
        whenever(factory.requestOptions()).thenReturn(options)
        whenever(factory.httpRequestResponse(any<HttpRequest>(), any<HttpResponse>())).thenAnswer { invocation ->
            pairOf(invocation.getArgument(0), invocation.getArgument(1))
        }
        ObjectFactoryLocator.FACTORY = factory
    }

    @AfterEach
    fun restoreFactory() {
        scanners.forEach { it.shutdown() }
        scanners.clear()
        ObjectFactoryLocator.FACTORY = savedFactory
    }

    // ---------------------------------------------------------------------------------------------
    // Behaviour pins
    // ---------------------------------------------------------------------------------------------

    @Test
    fun theActiveScannerSendsTargetRequestsWithoutUpstreamTlsVerification() {
        val http = answeringHttp()
        val api = mock<MontoyaApi>(defaultAnswer = Answers.RETURNS_DEEP_STUBS)
        whenever(api.http()).thenReturn(http)
        val scanner =
            ActiveAiScanner(api, mock<AgentSupervisor>(), mock<AuditLogger>()) { TestSettings.baselineSettings() }
        scanner.scopeOnly = false
        scanner.scanMode = ScanMode.FULL
        scanner.requestDelayMs = 0
        scanner.maxPayloadsPerPoint = 1
        scanners += scanner

        val derived = getRequest("https://target.example/items/x", "/items/x")
        val original = getRequest("https://target.example/items/42", "/items/42")
        whenever(original.withPath(any())).thenReturn(derived)
        val requestResponse = mock<HttpRequestResponse> { on { request() } doReturn original }
        val target =
            ActiveScanTarget(
                originalRequest = requestResponse,
                injectionPoint = InjectionPoint(InjectionType.PATH_SEGMENT, "id", "42"),
                vulnHint = VulnHint(VulnClass.SQLI, 50, "test"),
                priority = 50,
            )

        executeScan(scanner, target)

        assertTrue(sendsOn(http) >= 2, "expected the baseline and at least one payload send, got ${sendsOn(http)}")
        assertEquals(0, tlsOptionCalls(), "the active scanner must not require upstream TLS verification on target traffic")
    }

    @Test
    fun theBurpScannerCheckSendsWithoutUpstreamTlsVerification() {
        val apiHttp = answeringHttp()
        val scanHttp = answeringHttp()
        val api = mock<MontoyaApi>(defaultAnswer = Answers.RETURNS_DEEP_STUBS)
        whenever(api.http()).thenReturn(apiHttp)
        val settings =
            TestSettings.baselineSettings().copy(
                activeAiEnabled = true,
                activeAiScopeOnly = false,
                activeAiMaxPayloadsPerPoint = 15,
                activeAiRequestDelayMs = 0,
            )
        val baseRequest = getRequest("https://target.example/s?q=abc", "/s?q=abc")
        val baseService = service()
        val baseResponse = okResponse()
        val base =
            mock<HttpRequestResponse> {
                on { request() } doReturn baseRequest
                on { httpService() } doReturn baseService
                on { response() } doReturn baseResponse
            }

        AiScanCheck(api) { settings }.doCheck(base, insertionPoint(), scanHttp)

        val sends = sendsOn(apiHttp) + sendsOn(scanHttp)
        assertTrue(sends >= 2, "expected at least two sends, got $sends")
        assertEquals(0, tlsOptionCalls(), "the Burp Scanner AI check must not require upstream TLS verification on target traffic")
    }

    @Test
    fun theMcpHttp1ToolSendsWithoutUpstreamTlsVerification() {
        val api = newDeepStubApi()
        val rawRequest = "GET / HTTP/1.1\r\nHost: $HOST\r\n\r\n"
        val args =
            "{\"content\":${jsonString(rawRequest)},\"targetHostname\":\"$HOST\"," +
                "\"targetPort\":443,\"usesHttps\":true}"

        val result = exec("http1_request", args, contextWith(api))

        assertEquals(1, sendsOn(api.http()), "expected exactly one send, tool output: $result")
        assertEquals(0, tlsOptionCalls(), "http1_request must not require upstream TLS verification on target traffic")
    }

    @Test
    fun theMcpHttp2ToolKeepsHttp2ModeWithoutUpstreamTlsVerification() {
        val api = newDeepStubApi()
        val args =
            "{\"pseudoHeaders\":{\"method\":\"GET\",\"path\":\"/\",\"scheme\":\"https\",\"authority\":\"$HOST\"}," +
                "\"headers\":{},\"requestBody\":\"\",\"targetHostname\":\"$HOST\"," +
                "\"targetPort\":443,\"usesHttps\":true}"

        val result = exec("http2_request", args, contextWith(api))

        assertEquals(1, sendsOn(api.http()), "expected exactly one send, tool output: $result")
        verify(options).withHttpMode(HttpMode.HTTP_2)
        assertEquals(0, tlsOptionCalls(), "http2_request must not require upstream TLS verification on target traffic")
    }

    @Test
    fun theAiProviderTransportStillRequiresUpstreamTlsVerification() {
        val request = mock<HttpRequest>(defaultAnswer = Answers.RETURNS_SELF)
        whenever(factory.httpRequestFromUrl(any<String>())).thenReturn(request)
        whenever(factory.byteArray(any<ByteArray>())).thenReturn(mock<MontoyaByteArray>())
        val responseBody = mock<MontoyaByteArray> { on { getBytes() } doReturn "{}".toByteArray(Charsets.UTF_8) }
        val response =
            mock<HttpResponse> {
                on { statusCode() } doReturn 200.toShort()
                on { body() } doReturn responseBody
            }
        val requestResponse = mock<HttpRequestResponse> { on { response() } doReturn response }
        val http = mock<Http> { on { sendRequest(any<HttpRequest>(), any<RequestOptions>()) } doReturn requestResponse }
        val api = mock<MontoyaApi> { on { http() } doReturn http }

        MontoyaHttpTransport(api).post(PROVIDER_URL, emptyMap(), "{}")

        assertEquals(1, tlsOptionCalls(), "the AI-provider transport must keep requiring upstream TLS verification")
        verify(http).sendRequest(any<HttpRequest>(), eq(options))
    }

    // ---------------------------------------------------------------------------------------------
    // Whole-tree ledgers
    // ---------------------------------------------------------------------------------------------

    @Test
    fun onlyTheAiProviderTransportRequiresUpstreamTlsVerification() {
        assertEquals(
            sortedMapOf(
                "backends/http/MontoyaHttpTransport.kt" to 1,
                "mcp/tools/McpToolLegacy.kt" to 2,
            ),
            occurrencesPerFile(TLS_OPTION),
            "Only the AI-provider transport may require upstream TLS verification (plus the dead legacy " +
                "registrar, see theLegacyRegistrarStaysDeadSoItsExemptionHolds). Target traffic follows Burp's " +
                "own TLS settings so self-signed and internal-CA targets can be tested.",
        )
    }

    @Test
    fun theLegacyRegistrarStaysDeadSoItsExemptionHolds() {
        val lines =
            sourceFiles().flatMap { file ->
                codeLinesOf(file).filter { it.contains("registerToolsLegacy") }.map { relativePath(file) to it.trim() }
            }
        assertEquals(
            listOf("mcp/tools/McpToolLegacy.kt"),
            lines.map { it.first },
            "registerToolsLegacy must have no reference besides its declaration. Reviving it re-adds upstream TLS " +
                "verification to two target sends: remove those calls first and drop the exemption in " +
                "onlyTheAiProviderTransportRequiresUpstreamTlsVerification. Found: $lines",
        )
    }

    @Test
    fun everyMontoyaSendSiteIsClassified() {
        assertEquals(
            sortedMapOf(
                "backends/http/MontoyaHttpTransport.kt" to 2,
                "mcp/tools/McpToolExecutorImpl.kt" to 2,
                "mcp/tools/McpToolLegacy.kt" to 2,
                "scanner/ActiveAiScanner.kt" to 1,
                "scanner/AiScanCheck.kt" to 2,
            ),
            occurrencesPerFile(".sendRequest("),
            "Every Montoya send site is classified as target or AI-provider traffic in this class's KDoc. " +
                "Classify a new site there before raising its count.",
        )
    }

    // ---------------------------------------------------------------------------------------------
    // Fixture
    // ---------------------------------------------------------------------------------------------

    private fun tlsOptionCalls(): Int = Mockito.mockingDetails(options).invocations.count { it.method.name == TLS_OPTION }

    private fun sendsOn(http: Http): Int = Mockito.mockingDetails(http).invocations.count { it.method.name == "sendRequest" }

    private fun okResponse(): HttpResponse {
        val body = mock<MontoyaByteArray> { on { length() } doReturn 2 }
        return mock {
            on { statusCode() } doReturn 200.toShort()
            on { bodyToString() } doReturn "ok"
            on { headers() } doReturn emptyList()
            on { body() } doReturn body
        }
    }

    /** An Http mock whose every `sendRequest` overload answers the sent request with [okResponse]. */
    private fun answeringHttp(): Http =
        Mockito.mock(
            Http::class.java,
            Answer<Any?> { invocation ->
                if (invocation.method.name == "sendRequest") {
                    pairOf(invocation.getArgument(0), okResponse())
                } else {
                    Answers.RETURNS_DEFAULTS.answer(invocation)
                }
            },
        )

    private fun pairOf(
        sent: HttpRequest?,
        answer: HttpResponse?,
    ): HttpRequestResponse =
        mock {
            on { request() } doReturn sent
            on { response() } doReturn answer
        }

    private fun service(): HttpService =
        mock {
            on { host() } doReturn "target.example"
            on { port() } doReturn 443
            on { secure() } doReturn true
        }

    private fun getRequest(
        url: String,
        path: String,
    ): HttpRequest {
        val service = service()
        return mock {
            on { method() } doReturn "GET"
            on { url() } doReturn url
            on { path() } doReturn path
            on { httpService() } doReturn service
            on { httpVersion() } doReturn "HTTP/1.1"
            on { parameters() } doReturn emptyList()
            on { headers() } doReturn emptyList()
            on { bodyToString() } doReturn ""
        }
    }

    private fun insertionPoint(): AuditInsertionPoint {
        val service = service()
        return mock {
            on { name() } doReturn "q"
            on { baseValue() } doReturn "abc"
            on { type() } doReturn AuditInsertionPointType.PARAM_URL
            on { buildHttpRequestWithPayload(any()) } doAnswer {
                mock<HttpRequest> {
                    on { httpService() } doReturn service
                    on { url() } doReturn "https://target.example/s"
                }
            }
        }
    }

    private fun executeScan(
        scanner: ActiveAiScanner,
        target: ActiveScanTarget,
    ): ActiveScanResult {
        val method = ActiveAiScanner::class.java.getDeclaredMethod("executeScan", ActiveScanTarget::class.java)
        method.isAccessible = true
        return try {
            method.invoke(scanner, target) as ActiveScanResult
        } catch (e: InvocationTargetException) {
            throw e.cause ?: e
        }
    }

    private fun exec(
        toolId: String,
        argsJson: String,
        context: McpToolContext,
    ): String = McpToolExecutor.executeTool(toolId, argsJson, context, ToolCallOrigin.UserSlashCommand)

    private fun contextWith(api: MontoyaApi): McpToolContext =
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
            scopeOnly = false,
        )

    private fun newDeepStubApi(): MontoyaApi {
        val api = mock<MontoyaApi>(defaultAnswer = Answers.RETURNS_DEEP_STUBS)
        whenever(api.burpSuite().version().edition()).thenReturn(BurpSuiteEdition.PROFESSIONAL)
        whenever(api.scope().isInScope(any())).thenReturn(true)
        return api
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

    private fun sourceFiles(): List<File> {
        val root = File(SOURCE_ROOT)
        assertTrue(root.isDirectory, "Expected `$SOURCE_ROOT` under `${System.getProperty("user.dir")}`.")
        return root.walkTopDown().filter { it.isFile && it.extension == "kt" }.toList()
    }

    private fun relativePath(file: File): String = file.relativeTo(File(SOURCE_ROOT)).invariantSeparatorsPath

    private fun occurrencesPerFile(token: String): Map<String, Int> =
        sourceFiles()
            .associate { file ->
                relativePath(file) to codeLinesOf(file).sumOf { line -> line.windowed(token.length).count { it == token } }
            }.filterValues { it > 0 }
            .toSortedMap()

    /** Non-comment lines: a line-comment marker, a continuation asterisk or a block opener first. */
    private fun codeLinesOf(file: File): List<String> =
        file.readText(Charsets.UTF_8).lines().filterNot { line ->
            val trimmed = line.trimStart()
            trimmed.startsWith("//") || trimmed.startsWith("*") || trimmed.startsWith("/*")
        }

    private companion object {
        const val SOURCE_ROOT = "src/main/kotlin/com/six2dez/burp/aiagent"
        const val TLS_OPTION = "withUpstreamTLSVerification"
        const val HOST = "example.com"
        const val PROVIDER_URL = "http://127.0.0.1:1234/v1/chat/completions"
    }
}
