package com.six2dez.burp.aiagent.scanner

import burp.api.montoya.MontoyaApi
import burp.api.montoya.http.Http
import burp.api.montoya.http.HttpService
import burp.api.montoya.http.RequestOptions
import burp.api.montoya.http.message.HttpRequestResponse
import burp.api.montoya.http.message.requests.HttpRequest
import burp.api.montoya.http.message.responses.HttpResponse
import burp.api.montoya.internal.MontoyaObjectFactory
import burp.api.montoya.internal.ObjectFactoryLocator
import burp.api.montoya.scanner.audit.insertionpoint.AuditInsertionPoint
import burp.api.montoya.scanner.audit.insertionpoint.AuditInsertionPointType
import com.six2dez.burp.aiagent.TestSettings
import com.six2dez.burp.aiagent.config.AgentSettings
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertTimeoutPreemptively
import org.mockito.Answers
import org.mockito.Mockito
import org.mockito.kotlin.any
import org.mockito.kotlin.doAnswer
import org.mockito.kotlin.doReturn
import org.mockito.kotlin.mock
import org.mockito.kotlin.whenever
import org.mockito.stubbing.Answer
import java.io.File
import java.time.Duration
import java.util.Collections
import burp.api.montoya.core.ByteArray as MontoyaByteArray

/**
 * Quick 261008-vau — the Burp Scanner AI check ([AiScanCheck]) sends through the `http` Burp hands
 * each scan check, so the scan's resource pool, pause and session-handling rules apply to it. It
 * measures the time-based baseline once per `doCheck` (not once per time-based payload), never
 * sleeps in Burp's scanner thread, and skips time-based payloads when that baseline gets no
 * response.
 *
 * Both Http mocks answer every `sendRequest` overload, so the pre-fix code (which sent through
 * `api.http()`) runs to completion and fails on the assertions, not on a missing stub.
 */
class AiScanCheckScanHttpTest {
    private var savedFactory: MontoyaObjectFactory? = null
    private val testedPayloads: MutableList<String> = Collections.synchronizedList(mutableListOf())
    private val apiSends = Recorder()
    private val scanSends = Recorder()
    private lateinit var api: MontoyaApi
    private lateinit var baseRequest: HttpRequest
    private lateinit var base: HttpRequestResponse

    @BeforeEach
    fun installFactory() {
        savedFactory = ObjectFactoryLocator.FACTORY
        val options = mock<RequestOptions>(defaultAnswer = Answers.RETURNS_SELF)
        val factory = mock<MontoyaObjectFactory>(defaultAnswer = Answers.RETURNS_MOCKS)
        whenever(factory.requestOptions()).thenReturn(options)
        whenever(factory.httpRequestResponse(any<HttpRequest>(), any<HttpResponse>())).thenAnswer { invocation ->
            pairOf(invocation.getArgument(0), invocation.getArgument(1))
        }
        whenever(factory.byteArray(any<String>())).thenAnswer { invocation ->
            testedPayloads += invocation.getArgument<String>(0)
            mock<MontoyaByteArray>()
        }
        ObjectFactoryLocator.FACTORY = factory

        api = mock<MontoyaApi>(defaultAnswer = Answers.RETURNS_DEEP_STUBS)
        whenever(api.http()).thenReturn(apiSends.http)
        val service = service()
        baseRequest =
            mock {
                on { method() } doReturn "GET"
                on { url() } doReturn "https://target.example/s?q=abc"
                on { httpService() } doReturn service
            }
        val baseResponse = okResponse()
        base =
            mock {
                on { request() } doReturn baseRequest
                on { httpService() } doReturn service
                on { response() } doReturn baseResponse
            }
    }

    @AfterEach
    fun restoreFactory() {
        ObjectFactoryLocator.FACTORY = savedFactory
    }

    @Test
    fun everyRequestGoesThroughTheScansHttp() {
        doCheck(settings())

        assertEquals(0, apiSends.sent.size, "no request may bypass the scan's Http through api.http()")
        assertTrue(scanSends.sent.size >= 15, "expected every payload on the scan's Http, got ${scanSends.sent.size}")
    }

    @Test
    fun theTimeBasedBaselineIsSentOncePerCheck() {
        doCheck(settings())

        TIME_MARKERS.forEach { marker ->
            assertTrue(testedPayloads.any { it.contains(marker) }, "anti-vacuity: no tested payload contains `$marker`")
        }
        val baseSends = apiSends.sent.count { it === baseRequest } + scanSends.sent.count { it === baseRequest }
        assertEquals(1, baseSends, "the base request is sent once per doCheck for all time-based payloads")
        assertEquals(1, scanSends.sent.count { it === baseRequest }, "the time-based baseline goes through the scan's Http")
    }

    @Test
    fun theCheckNoLongerSleepsInTheScannerThread() {
        assertTimeoutPreemptively(Duration.ofSeconds(4)) { doCheck(settings().copy(activeAiRequestDelayMs = 5000)) }
        assertTrue(apiSends.sent.size + scanSends.sent.size >= 2, "the check must still send its payloads")

        val code =
            File(SOURCE).readText(Charsets.UTF_8).lines().filterNot { line ->
                val trimmed = line.trimStart()
                trimmed.startsWith("//") || trimmed.startsWith("*") || trimmed.startsWith("/*")
            }
        assertFalse(code.any { it.contains("sleep(") }, "AiScanCheck must not sleep in Burp's scanner thread")
        assertFalse(
            code.any { it.contains("activeAiRequestDelayMs") },
            "the request delay paces only the AI active scanner queue; Burp's resource pool paces this check",
        )
    }

    @Test
    fun aFailedTimeBaselineSkipsTimeBasedPayloadsAndIsNotRetried() {
        scanSends.answerFor = { request -> if (request === baseRequest) pairOf(request, null) else null }

        doCheck(settings())

        val baseSends = apiSends.sent.count { it === baseRequest } + scanSends.sent.count { it === baseRequest }
        assertEquals(1, baseSends, "a failed time baseline is not retried within the check")
        TIME_MARKERS.forEach { marker ->
            assertFalse(testedPayloads.any { it.contains(marker) }, "time-based payload `$marker` tested without a baseline")
        }
        val attackSends = apiSends.sent.count { it !== baseRequest } + scanSends.sent.count { it !== baseRequest }
        assertTrue(attackSends >= 12, "the other payloads still run: $attackSends attack sends")
    }

    // ---------------------------------------------------------------------------------------------
    // Fixture
    // ---------------------------------------------------------------------------------------------

    /** An Http mock recording every `sendRequest`; [answerFor] may override the default 200 answer. */
    private inner class Recorder {
        val sent: MutableList<HttpRequest> = Collections.synchronizedList(mutableListOf())
        var answerFor: (HttpRequest) -> HttpRequestResponse? = { null }
        val http: Http =
            Mockito.mock(
                Http::class.java,
                Answer<Any?> { invocation ->
                    if (invocation.method.name == "sendRequest") {
                        val request = invocation.getArgument<HttpRequest>(0)
                        sent += request
                        answerFor(request) ?: pairOf(request, okResponse())
                    } else {
                        Answers.RETURNS_DEFAULTS.answer(invocation)
                    }
                },
            )
    }

    private fun settings(): AgentSettings =
        TestSettings.baselineSettings().copy(
            activeAiEnabled = true,
            activeAiScopeOnly = false,
            activeAiMaxPayloadsPerPoint = 15,
            activeAiRequestDelayMs = 0,
        )

    private fun doCheck(settings: AgentSettings) {
        AiScanCheck(api) { settings }.doCheck(base, insertionPoint(), scanSends.http)
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

    private fun okResponse(): HttpResponse {
        val body = mock<MontoyaByteArray> { on { length() } doReturn 2 }
        return mock {
            on { statusCode() } doReturn 200.toShort()
            on { bodyToString() } doReturn "ok"
            on { headers() } doReturn emptyList()
            on { body() } doReturn body
        }
    }

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

    private companion object {
        const val SOURCE = "src/main/kotlin/com/six2dez/burp/aiagent/scanner/AiScanCheck.kt"
        val TIME_MARKERS = listOf("SLEEP(5)", "WAITFOR DELAY", "pg_sleep(5)")
    }
}
