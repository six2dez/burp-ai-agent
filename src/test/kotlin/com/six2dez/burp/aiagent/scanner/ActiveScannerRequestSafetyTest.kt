package com.six2dez.burp.aiagent.scanner

import burp.api.montoya.MontoyaApi
import burp.api.montoya.http.Http
import burp.api.montoya.http.HttpService
import burp.api.montoya.http.RequestOptions
import burp.api.montoya.http.message.HttpRequestResponse
import burp.api.montoya.http.message.params.HttpParameterType
import burp.api.montoya.http.message.params.ParsedHttpParameter
import burp.api.montoya.http.message.requests.HttpRequest
import burp.api.montoya.http.message.responses.HttpResponse
import burp.api.montoya.internal.MontoyaObjectFactory
import burp.api.montoya.internal.ObjectFactoryLocator
import com.six2dez.burp.aiagent.TestSettings
import com.six2dez.burp.aiagent.audit.AuditLogger
import com.six2dez.burp.aiagent.supervisor.AgentSupervisor
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertTimeoutPreemptively
import org.mockito.Answers
import org.mockito.Mockito
import org.mockito.kotlin.any
import org.mockito.kotlin.mock
import org.mockito.kotlin.whenever
import org.mockito.stubbing.Answer
import java.io.File
import java.lang.reflect.InvocationTargetException
import java.time.Duration
import java.util.Collections
import java.util.concurrent.atomic.AtomicInteger
import burp.api.montoya.core.ByteArray as MontoyaByteArray

/**
 * Quick 261008-vau — request safety of the AI active scanner, driven through the REAL
 * [ActiveAiScanner] over a mocked Montoya API (statics served by a mock object factory).
 *
 * - IDOR/BOLA tests replay a request whose method is not GET, HEAD or OPTIONS with neighbouring IDs
 *   only at [PayloadRisk.DANGEROUS] (the user decision's "AGGRESSIVE"); below it the target sends
 *   nothing and its result says why (I-1..I-5).
 * - The 403 bypass switches methods to POST or PUT only at DANGEROUS; below it only GET and HEAD
 *   (M-1, M-2), from one safe-method set read from one risk source (P-1, P-2).
 * - One baseline per original request is shared by all its targets across points, classes and
 *   sources, never caches a failure, and is dropped when the scanner stops (B-1..B-4).
 *
 * Requests are fakes whose derivations (`withPath`, `withBody`, `withMethod`, header edits) are NEW
 * objects, so identity (`===`) tells the original request apart from every payload request. No
 * assertion compares an elapsed duration; the one held send (B-1) only widens the in-flight window.
 */
class ActiveScannerRequestSafetyTest {
    private var savedFactory: MontoyaObjectFactory? = null
    private val scanners = mutableListOf<ActiveAiScanner>()

    @BeforeEach
    fun installFactory() {
        savedFactory = ObjectFactoryLocator.FACTORY
        val options = mock<RequestOptions>(defaultAnswer = Answers.RETURNS_SELF)
        val factory = mock<MontoyaObjectFactory>(defaultAnswer = Answers.RETURNS_MOCKS)
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
    // IDOR / BOLA gate
    // ---------------------------------------------------------------------------------------------

    @Test
    fun aStateChangingIdorTargetSendsNothingBelowDangerous() {
        for (risk in listOf(PayloadRisk.SAFE, PayloadRisk.MODERATE)) {
            for (method in listOf("DELETE", "PUT", "POST", "PATCH")) {
                for (vulnClass in listOf(VulnClass.IDOR, VulnClass.BOLA)) {
                    val recorder = Recorder()
                    val original = fakeRequest(method, "/api/users/42")
                    val result = run(newScanner(recorder, risk), idorTarget(original, vulnClass))
                    val case = "$method $vulnClass at $risk"

                    assertEquals(0, recorder.sent.size, "$case must send nothing, sent ${recorder.sentMethods()}")
                    assertNotNull(result.error, "$case must say why it was skipped")
                    val error = result.error.orEmpty()
                    assertTrue(error.contains(method), "$case reason must name the method: $error")
                    assertTrue(error.contains("state-changing"), "$case reason: $error")
                    assertTrue(error.contains("DANGEROUS"), "$case reason: $error")
                    assertEquals(0, result.payloadsTested, case)
                    assertNull(result.confirmation, case)
                }
            }
        }
    }

    @Test
    fun aSkippedIdorTargetIsReportedOnTheOutputTab() {
        val recorder = Recorder()
        val original = fakeRequest("DELETE", "/api/users/42")
        val target = idorTarget(original, VulnClass.IDOR)

        run(newScanner(recorder, PayloadRisk.SAFE), target)

        val lines =
            outputLines(recorder.api).filter {
                it.startsWith("[ActiveAiScanner] ") && it.contains(target.id) && it.contains("DANGEROUS")
            }
        assertEquals(1, lines.size, "expected one Output line naming the skipped target, got ${outputLines(recorder.api)}")
    }

    @Test
    fun aStateChangingIdorTargetRunsAtDangerous() {
        val recorder = Recorder()
        val original = fakeRequest("DELETE", "/api/users/42")
        recorder.originals += original

        run(newScanner(recorder, PayloadRisk.DANGEROUS), idorTarget(original, VulnClass.IDOR))

        assertEquals(1, recorder.originalSends(original), "the baseline is sent once")
        val others = recorder.sent.filterNot { it === original }
        assertTrue(others.size >= 2, "neighbour-ID requests are sent at DANGEROUS, got ${others.size}")
        assertTrue(others.all { it.method() == "DELETE" }, "every neighbour-ID request keeps DELETE: ${others.map { it.method() }}")
    }

    @Test
    fun safeMethodsRunAtEveryRiskLevel() {
        for (method in listOf("GET", "HEAD", "OPTIONS", "get")) {
            val recorder = Recorder()
            val original = fakeRequest(method, "/api/users/42")
            recorder.originals += original

            val result = run(newScanner(recorder, PayloadRisk.SAFE), idorTarget(original, VulnClass.IDOR))

            assertTrue(recorder.sent.count { it !== original } >= 1, "$method must still run its IDOR test at SAFE")
            assertFalse(result.error.orEmpty().contains("state-changing"), "$method is safe: ${result.error}")
        }
    }

    @Test
    fun theIdorTestStillRequiresA2xxBaseline() {
        val recorder = Recorder()
        val original = fakeRequest("GET", "/api/users/42")
        recorder.originals += original
        recorder.statusFor = { if (it === original) 404 else 200 }

        val result = run(newScanner(recorder, PayloadRisk.SAFE), idorTarget(original, VulnClass.IDOR))

        assertEquals("Baseline response not successful", result.error)
        assertEquals(listOf(original), recorder.sent.toList(), "only the baseline is sent")
    }

    // ---------------------------------------------------------------------------------------------
    // 403 bypass method switching
    // ---------------------------------------------------------------------------------------------

    @Test
    fun belowDangerousMethodSwitchingSendsOnlySafeAlternatives() {
        val expected =
            mapOf(
                "GET" to setOf("HEAD"),
                "POST" to setOf("GET", "HEAD"),
                "DELETE" to setOf("GET", "HEAD"),
            )
        for (risk in listOf(PayloadRisk.SAFE, PayloadRisk.MODERATE)) {
            for ((method, alternatives) in expected) {
                assertEquals(alternatives, switchedMethods(method, risk), "$method original at $risk")
            }
        }
    }

    @Test
    fun atDangerousMethodSwitchingAlsoSendsStateChangingAlternatives() {
        assertEquals(setOf("HEAD", "POST", "PUT"), switchedMethods("GET", PayloadRisk.DANGEROUS))
    }

    // ---------------------------------------------------------------------------------------------
    // One policy, one risk source
    // ---------------------------------------------------------------------------------------------

    @Test
    fun theSafeMethodSetIsDefinedOnceAndCaseInsensitive() {
        for (method in listOf("GET", "get", " Head ", "OPTIONS")) {
            assertTrue(ScanPolicy.isSafeMethod(method), "`$method` is safe")
        }
        for (method in listOf("DELETE", "PUT", "POST", "PATCH", "TRACE", "CONNECT", " ", null)) {
            assertFalse(ScanPolicy.isSafeMethod(method), "`$method` is state-changing (fail closed)")
        }

        assertEquals(listOf("HEAD"), ScanPolicy.methodSwitchAlternatives("GET", PayloadRisk.SAFE))
        assertEquals(listOf("GET", "HEAD"), ScanPolicy.methodSwitchAlternatives("post", PayloadRisk.MODERATE))
        assertEquals(listOf("GET", "HEAD"), ScanPolicy.methodSwitchAlternatives("DELETE", PayloadRisk.SAFE))
        assertEquals(listOf("HEAD", "POST", "PUT"), ScanPolicy.methodSwitchAlternatives("GET", PayloadRisk.DANGEROUS))
        assertEquals(listOf("GET", "HEAD", "PUT"), ScanPolicy.methodSwitchAlternatives("POST", PayloadRisk.DANGEROUS))

        assertNull(ScanPolicy.idorReplayBlockReason("GET", PayloadRisk.SAFE))
        assertNull(ScanPolicy.idorReplayBlockReason("DELETE", PayloadRisk.DANGEROUS))
        assertNotNull(ScanPolicy.idorReplayBlockReason("DELETE", PayloadRisk.MODERATE))
        assertNotNull(ScanPolicy.idorReplayBlockReason(null, PayloadRisk.SAFE))

        val definitions =
            sourceFiles().flatMap { file ->
                codeLinesOf(file).filter { it.contains(SAFE_SET_LITERAL) }.map { relativePath(file) }
            }
        assertEquals(listOf("scanner/ActiveScanModels.kt"), definitions, "the safe-method set is defined exactly once")
    }

    @Test
    fun theGatesReadTheSameRiskSourceAsPayloadFiltering() {
        val scanner = codeLinesOf(File(SOURCE_ROOT, "scanner/ActiveAiScanner.kt"))
        assertEquals(0, scanner.count { it.contains("activeAiMaxRiskLevel") }, "ActiveAiScanner reads its own maxRiskLevel field only")
        assertEquals(
            1,
            codeLinesOf(File(SOURCE_ROOT, "ui/SettingsPanelSettingsIO.kt")).count {
                it.contains("activeAiScanner.maxRiskLevel = updated.activeAiMaxRiskLevel")
            },
            "every Save writes the field the gates read",
        )
        assertEquals(
            1,
            codeLinesOf(File(SOURCE_ROOT, "App.kt")).count { it.contains("activeAiScanner.maxRiskLevel = settings.activeAiMaxRiskLevel") },
            "startup writes the field the gates read",
        )
        val declaration = scanner.indexOfFirst { it.contains("var maxRiskLevel") }
        assertTrue(declaration > 0, "maxRiskLevel declaration not found")
        assertTrue(
            scanner[declaration].contains("@Volatile") || scanner[declaration - 1].trim() == "@Volatile",
            "maxRiskLevel is written on the EDT / Save worker and read by scan workers: it must be @Volatile",
        )
    }

    // ---------------------------------------------------------------------------------------------
    // Shared baseline
    // ---------------------------------------------------------------------------------------------

    @Test
    fun oneBaselinePerOriginalRequestAcrossPointsClassesAndSources() {
        val recorder = Recorder()
        recorder.originalSendDelayMs = ORIGINAL_SEND_HOLD_MS
        val params = listOf(bodyParam("a", "1"), bodyParam("b", "2"))
        val first = fakeRequest("POST", "/form", body = "a=1&b=2", params = params)
        val second = fakeRequest("POST", "/form", body = "a=1&b=2", params = params)
        recorder.originals += first
        recorder.originals += second
        val rr = requestResponse(first)
        val rr2 = requestResponse(second)
        val scanner = newScanner(recorder, PayloadRisk.SAFE)
        scanner.maxConcurrent = 3
        scanner.setEnabled(true)

        val queued = scanner.manualScan(listOf(rr), listOf(VulnClass.SQLI, VulnClass.XSS_REFLECTED, VulnClass.LFI))
        assertTrue(queued >= 4, "anti-vacuity: expected at least four targets, got $queued")
        assertTimeoutPreemptively(Duration.ofSeconds(AWAIT_SECONDS)) { awaitScansCompleted(scanner, queued) }

        scanner.queueTarget(
            ActiveScanTarget(
                originalRequest = rr2,
                injectionPoint = InjectionPoint(InjectionType.BODY_PARAM, "c", "3"),
                vulnHint = VulnHint(VulnClass.SQLI, 50, "passive"),
                priority = 50,
            ),
        )
        assertTimeoutPreemptively(Duration.ofSeconds(AWAIT_SECONDS)) { awaitScansCompleted(scanner, queued + 1) }

        assertEquals(1, recorder.originalSends(first, second), "the original request is sent once for all its targets")
        assertTrue(
            recorder.sent.size >= queued + 2,
            "every target still sends its payload: ${recorder.sent.size} sends for ${queued + 1} targets",
        )
    }

    @Test
    fun aFailedOrEmptyBaselineIsNotCached() {
        val recorder = Recorder()
        val original = fakeRequest("GET", "/search", params = listOf(urlParam("q", "x")))
        recorder.originals += original
        recorder.originalScript = { call ->
            when (call) {
                1 -> error("connection reset")
                2 -> pairOf(original, null)
                else -> null
            }
        }
        val scanner = newScanner(recorder, PayloadRisk.SAFE)
        val point = InjectionPoint(InjectionType.URL_PARAM, "q", "x")

        val t1 = run(scanner, target(original, point, VulnClass.SQLI))
        val t2 = run(scanner, target(original, point, VulnClass.XSS_REFLECTED))
        val t3 = run(scanner, target(original, point, VulnClass.LFI))
        val beforeT4 = recorder.originalSends(original)
        run(scanner, target(original, point, VulnClass.CMDI))

        assertTrue(t1.error.orEmpty().startsWith("Failed to send baseline request"), "a throwing baseline fails t1: ${t1.error}")
        assertTrue(t2.error.orEmpty().startsWith("Failed to send baseline request"), "a response-less baseline fails t2: ${t2.error}")
        assertFalse(t3.error.orEmpty().startsWith("Failed to send baseline request"), "t3 measures again and succeeds: ${t3.error}")
        assertEquals(beforeT4, recorder.originalSends(original), "t4 reuses t3's baseline")
        assertEquals(3, recorder.originalSends(original), "two failures re-measured, one success shared")
    }

    @Test
    fun stoppingTheScannerDropsSharedBaselines() {
        val recorder = Recorder()
        val original = fakeRequest("GET", "/search", params = listOf(urlParam("q", "x")))
        recorder.originals += original
        val scanner = newScanner(recorder, PayloadRisk.SAFE)
        val point = InjectionPoint(InjectionType.URL_PARAM, "q", "x")

        run(scanner, target(original, point, VulnClass.SQLI))
        run(scanner, target(original, point, VulnClass.XSS_REFLECTED))
        assertEquals(1, recorder.originalSends(original), "two classes of one request share one baseline")

        scanner.setEnabled(false)
        run(scanner, target(original, point, VulnClass.LFI))
        assertEquals(2, recorder.originalSends(original), "stopping the scanner drops the shared baseline")
    }

    @Test
    fun requestsThatDifferInBytesHostPortOrSchemeGetTheirOwnBaseline() {
        val recorder = Recorder()
        val originals =
            listOf(
                fakeRequest("GET", "/search"),
                fakeRequest("GET", "/search", body = "other"),
                fakeRequest("GET", "/search", host = "other.example"),
                fakeRequest("GET", "/search", port = 8443),
                fakeRequest("GET", "/search", secure = false),
            )
        recorder.originals += originals
        val scanner = newScanner(recorder, PayloadRisk.SAFE)

        originals.forEach { run(scanner, target(it, InjectionPoint(InjectionType.HEADER, "X-Test", "1"), VulnClass.SQLI)) }

        assertEquals(5, recorder.originalSends(*originals.toTypedArray()), "each distinct request measures its own baseline")
    }

    // ---------------------------------------------------------------------------------------------
    // Fixture
    // ---------------------------------------------------------------------------------------------

    /** Records every request sent through `api.http()`; answers each with [statusFor] and `ok 42`. */
    private inner class Recorder {
        val sent: MutableList<HttpRequest> = Collections.synchronizedList(mutableListOf())
        val originals: MutableList<HttpRequest> = Collections.synchronizedList(mutableListOf())
        var statusFor: (HttpRequest) -> Int = { 200 }
        var originalSendDelayMs: Long = 0

        /** Per-call script for the originals: a non-null answer replaces the default 200. */
        var originalScript: (Int) -> HttpRequestResponse? = { null }
        private val originalCalls = AtomicInteger(0)

        val http: Http =
            Mockito.mock(
                Http::class.java,
                Answer<Any?> { invocation ->
                    if (invocation.method.name == "sendRequest") {
                        answer(invocation.getArgument(0))
                    } else {
                        Answers.RETURNS_DEFAULTS.answer(invocation)
                    }
                },
            )

        val api: MontoyaApi =
            mock<MontoyaApi>(defaultAnswer = Answers.RETURNS_DEEP_STUBS).also { whenever(it.http()).thenReturn(http) }

        fun sentMethods(): List<String> = sent.toList().map { it.method() }

        fun originalSends(vararg candidates: HttpRequest): Int = sent.toList().count { sentRequest -> candidates.any { it === sentRequest } }

        private fun answer(request: HttpRequest): HttpRequestResponse {
            sent += request
            if (originals.toList().any { it === request }) {
                if (originalSendDelayMs > 0) Thread.sleep(originalSendDelayMs)
                originalScript(originalCalls.incrementAndGet())?.let { return it }
            }
            return pairOf(request, response(statusFor(request)))
        }
    }

    private fun newScanner(
        recorder: Recorder,
        risk: PayloadRisk,
    ): ActiveAiScanner {
        val created =
            ActiveAiScanner(recorder.api, mock<AgentSupervisor>(), mock<AuditLogger>()) { TestSettings.baselineSettings() }
        created.scopeOnly = false
        created.scanMode = ScanMode.FULL
        created.requestDelayMs = 0
        created.maxPayloadsPerPoint = 1
        created.maxRiskLevel = risk
        scanners += created
        return created
    }

    private fun run(
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

    private fun awaitScansCompleted(
        scanner: ActiveAiScanner,
        expected: Int,
    ) {
        while (scanner.getStatus().scansCompleted < expected) {
            Thread.sleep(POLL_INTERVAL_MS)
        }
    }

    /** The methods the 403 bypass switched to: every sent method other than the original's. */
    private fun switchedMethods(
        method: String,
        risk: PayloadRisk,
    ): Set<String> {
        val recorder = Recorder()
        recorder.statusFor = { 403 }
        val original = fakeRequest(method, "/admin")
        recorder.originals += original
        run(
            newScanner(recorder, risk),
            target(original, InjectionPoint(InjectionType.URL_PARAM, "x", "1"), VulnClass.ACCESS_CONTROL_BYPASS),
        )
        assertEquals(1, recorder.originalSends(original), "the 403 baseline is sent once")
        return recorder.sentMethods().filterNot { it == method }.toSet()
    }

    private fun outputLines(api: MontoyaApi): List<String> =
        Mockito
            .mockingDetails(api.logging())
            .invocations
            .filter { it.method.name == "logToOutput" }
            .map { it.arguments.first().toString() }

    private fun idorTarget(
        original: HttpRequest,
        vulnClass: VulnClass,
    ): ActiveScanTarget = target(original, InjectionPoint(InjectionType.PATH_SEGMENT, "id", "42"), vulnClass)

    private fun target(
        original: HttpRequest,
        point: InjectionPoint,
        vulnClass: VulnClass,
    ): ActiveScanTarget =
        ActiveScanTarget(
            originalRequest = requestResponse(original),
            injectionPoint = point,
            vulnHint = VulnHint(vulnClass, 50, "test"),
            priority = 50,
        )

    private fun requestResponse(request: HttpRequest): HttpRequestResponse = pairOf(request, null)

    private fun pairOf(
        sent: HttpRequest?,
        answer: HttpResponse?,
    ): HttpRequestResponse =
        answering(HttpRequestResponse::class.java) { name, _ ->
            when (name) {
                "request" -> sent
                "response" -> answer
                else -> DEFAULT
            }
        }

    private fun response(status: Int): HttpResponse {
        val body = answering(MontoyaByteArray::class.java) { name, _ -> if (name == "length") RESPONSE_BODY.length else DEFAULT }
        return answering(HttpResponse::class.java) { name, _ ->
            when (name) {
                "statusCode" -> status.toShort()
                "bodyToString" -> RESPONSE_BODY
                "body" -> body
                "headers" -> emptyList<Any>()
                else -> DEFAULT
            }
        }
    }

    private fun bodyParam(
        name: String,
        value: String,
    ): ParsedHttpParameter = parameter(HttpParameterType.BODY, name, value)

    private fun urlParam(
        name: String,
        value: String,
    ): ParsedHttpParameter = parameter(HttpParameterType.URL, name, value)

    private fun parameter(
        type: HttpParameterType,
        paramName: String,
        paramValue: String,
    ): ParsedHttpParameter =
        answering(ParsedHttpParameter::class.java) { name, _ ->
            when (name) {
                "type" -> type
                "name" -> paramName
                "value" -> paramValue
                else -> DEFAULT
            }
        }

    /** The content of a request fake; [fakeRequest] answers every accessor from it. */
    private data class FakeSpec(
        val method: String,
        val path: String,
        val body: String,
        val params: List<ParsedHttpParameter>,
        val host: String,
        val port: Int,
        val secure: Boolean,
    )

    /**
     * A request fake. Every derivation answers a FRESH fake built lazily inside the answer, so
     * identity tells the original apart: `withPath` / `withBody` keep the method, header edits keep
     * method, path and body, `withMethod` keeps path and body.
     */
    private fun fakeRequest(
        method: String,
        path: String,
        body: String = "",
        params: List<ParsedHttpParameter> = emptyList(),
        host: String = "target.example",
        port: Int = 443,
        secure: Boolean = true,
    ): HttpRequest = fakeRequest(FakeSpec(method, path, body, params, host, port, secure))

    private fun fakeRequest(spec: FakeSpec): HttpRequest {
        val service =
            answering(HttpService::class.java) { name, _ ->
                when (name) {
                    "host" -> spec.host
                    "port" -> spec.port
                    "secure" -> spec.secure
                    else -> DEFAULT
                }
            }
        val raw = "${spec.method} ${spec.path} HTTP/1.1\r\nHost: ${spec.host}\r\n\r\n${spec.body}".toByteArray(Charsets.UTF_8)
        val bytes = answering(MontoyaByteArray::class.java) { name, _ -> if (name == "getBytes") raw.copyOf() else DEFAULT }
        return answering(HttpRequest::class.java) { name, args ->
            when (name) {
                "httpService" -> service
                "toByteArray" -> bytes
                else -> requestAnswer(spec, name, args)
            }
        }
    }

    private fun requestAnswer(
        spec: FakeSpec,
        name: String,
        args: Array<Any?>,
    ): Any? =
        when (name) {
            "method" -> spec.method
            "url" -> "${if (spec.secure) "https" else "http"}://${spec.host}${spec.path}"
            "path" -> spec.path
            "httpVersion" -> "HTTP/1.1"
            "parameters" -> spec.params
            "headers" -> emptyList<Any>()
            "headerValue" -> if (args.first() == "Content-Type" && spec.params.any { it.type() == HttpParameterType.BODY }) FORM_TYPE else null
            "bodyToString" -> spec.body
            else -> derivedRequest(spec, name, args)
        }

    private fun derivedRequest(
        spec: FakeSpec,
        name: String,
        args: Array<Any?>,
    ): Any? =
        when (name) {
            "withPath" -> fakeRequest(spec.copy(path = args.first() as String))
            "withBody" -> fakeRequest(spec.copy(body = args.first().toString()))
            "withMethod" -> fakeRequest(spec.copy(method = args.first() as String))
            "withAddedHeader", "withRemovedHeader" -> fakeRequest(spec)
            else -> DEFAULT
        }

    /** A mock answered by [answer] per method name; [DEFAULT] falls back to Mockito's defaults. */
    private fun <T> answering(
        type: Class<T>,
        answer: (String, Array<Any?>) -> Any?,
    ): T =
        Mockito.mock(
            type,
            Answer<Any?> { invocation ->
                val result = answer(invocation.method.name, invocation.arguments)
                if (result === DEFAULT) Answers.RETURNS_DEFAULTS.answer(invocation) else result
            },
        )

    private fun sourceFiles(): List<File> {
        val root = File(SOURCE_ROOT)
        assertTrue(root.isDirectory, "Expected `$SOURCE_ROOT` under `${System.getProperty("user.dir")}`.")
        return root.walkTopDown().filter { it.isFile && it.extension == "kt" }.toList()
    }

    private fun relativePath(file: File): String = file.relativeTo(File(SOURCE_ROOT)).invariantSeparatorsPath

    /** Non-comment lines: a line-comment marker, a continuation asterisk or a block opener first. */
    private fun codeLinesOf(file: File): List<String> =
        file.readText(Charsets.UTF_8).lines().filterNot { line ->
            val trimmed = line.trimStart()
            trimmed.startsWith("//") || trimmed.startsWith("*") || trimmed.startsWith("/*")
        }

    private companion object {
        val DEFAULT = Any()
        const val SOURCE_ROOT = "src/main/kotlin/com/six2dez/burp/aiagent"
        const val SAFE_SET_LITERAL = "setOf(\"GET\", \"HEAD\", \"OPTIONS\")"
        const val RESPONSE_BODY = "ok 42"
        const val FORM_TYPE = "application/x-www-form-urlencoded"
        const val ORIGINAL_SEND_HOLD_MS = 300L
        const val AWAIT_SECONDS = 15L
        const val POLL_INTERVAL_MS = 20L
    }
}
