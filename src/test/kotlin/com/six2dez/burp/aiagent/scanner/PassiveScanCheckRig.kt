package com.six2dez.burp.aiagent.scanner

import burp.api.montoya.MontoyaApi
import burp.api.montoya.http.HttpService
import burp.api.montoya.http.message.HttpHeader
import burp.api.montoya.http.message.HttpRequestResponse
import burp.api.montoya.http.message.params.HttpParameterType
import burp.api.montoya.http.message.params.ParsedHttpParameter
import burp.api.montoya.http.message.requests.HttpRequest
import burp.api.montoya.http.message.responses.HttpResponse
import burp.api.montoya.internal.MontoyaObjectFactory
import burp.api.montoya.internal.ObjectFactoryLocator
import burp.api.montoya.logging.Logging
import burp.api.montoya.scanner.AuditResult
import burp.api.montoya.scanner.audit.issues.AuditIssue
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity
import burp.api.montoya.sitemap.SiteMap
import com.six2dez.burp.aiagent.TestSettings
import com.six2dez.burp.aiagent.audit.AuditLogger
import com.six2dez.burp.aiagent.config.AgentSettings
import com.six2dez.burp.aiagent.supervisor.AgentSupervisor
import org.mockito.Answers
import org.mockito.kotlin.any
import org.mockito.kotlin.anyOrNull
import org.mockito.kotlin.doAnswer
import org.mockito.kotlin.doReturn
import org.mockito.kotlin.mock
import org.mockito.kotlin.whenever
import java.util.Collections
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import burp.api.montoya.core.ByteArray as MontoyaByteArray

/** One `AuditIssue.auditIssue(...)` call as the Montoya factory saw it. */
internal data class FiledIssue(
    val name: String,
    val detail: String,
    val remediation: String?,
    val baseUrl: String,
    val severity: AuditIssueSeverity,
    val confidence: AuditIssueConfidence,
    val typicalSeverity: AuditIssueSeverity?,
    val requestResponses: List<HttpRequestResponse>,
)

/**
 * Quick 261009-1ao - drives the REAL [AiPassiveScanCheck] over a REAL [PassiveAiScanner] built on a
 * mocked MontoyaApi. Montoya statics (`AuditIssue.auditIssue`, `AuditResult.auditResult`) are served by
 * a mock `ObjectFactoryLocator.FACTORY` that records every issue built; the Burp site map is a plain
 * list. Burp's own filing of the AuditResult a scan check returns is simulated by [fileLikeBurp];
 * issues the extension files itself go through `api.siteMap().add` and land in [extensionAdds].
 *
 * Use as `PassiveScanCheckRig().use { rig -> ... }`. Every test should use its own host because
 * ScanKnowledgeBase is a process-wide singleton.
 */
internal class PassiveScanCheckRig(
    val settings: AgentSettings =
        TestSettings.baselineSettings().copy(passiveAiEnabled = true, passiveAiScopeOnly = false),
) : AutoCloseable {
    private val savedFactory: MontoyaObjectFactory? = ObjectFactoryLocator.FACTORY

    val built: MutableList<FiledIssue> = Collections.synchronizedList(mutableListOf())
    val output: MutableList<String> = Collections.synchronizedList(mutableListOf())
    val errors: MutableList<String> = Collections.synchronizedList(mutableListOf())
    val siteMap: MutableList<AuditIssue> = Collections.synchronizedList(mutableListOf())
    val extensionAdds: MutableList<AuditIssue> = Collections.synchronizedList(mutableListOf())
    val auditEvents: MutableList<Pair<String, Any>> = Collections.synchronizedList(mutableListOf())

    init {
        ObjectFactoryLocator.FACTORY = recordingFactory(built)
    }

    val api: MontoyaApi = recordingApi(output, errors, siteMap, extensionAdds)
    val supervisor: AgentSupervisor =
        mock {
            on { status() } doReturn AgentSupervisor.Status("stopped", null)
        }
    val audit: AuditLogger =
        mock {
            on { logEvent(any(), any()) } doAnswer { invocation ->
                auditEvents += invocation.getArgument<String>(0) to invocation.getArgument<Any>(1)
                Unit
            }
        }
    val scanner = PassiveAiScanner(api, supervisor, audit) { settings }
    val check = AiPassiveScanCheck(api, scanner) { settings }

    /**
     * POST with a session cookie, a form body and no CSRF token: its single local finding is
     * "Potential CSRF (Missing Token)" (Low, 85). Its analysis ends at the 204 skip.
     */
    fun csrfPost(host: String): HttpRequestResponse {
        val cookie = header("Cookie", "session=abc123")
        val email =
            mock<ParsedHttpParameter> {
                on { name() } doReturn "email"
                on { value() } doReturn "a@b.example"
                on { type() } doReturn HttpParameterType.BODY
            }
        val request =
            request("POST", host, "/account/email", listOf(cookie)) {
                on { headerValue("Cookie") } doReturn "session=abc123"
                on { headerValue("Content-Type") } doReturn "application/x-www-form-urlencoded"
                on { parameters() } doReturn listOf(email)
                on { bodyToString() } doReturn "email=a@b.example"
            }
        return pair(request, response(NO_CONTENT, ""))
    }

    /**
     * GET with no parameters and an empty body. With [smugglingIndicators] its single local finding is
     * "HTTP Request Smuggling Indicators" (Medium, 90) and its analysis ends at the local-findings skip;
     * without them it has no local finding and its analysis reaches the backend step.
     */
    fun pageGet(
        host: String,
        smugglingIndicators: Boolean,
    ): HttpRequestResponse {
        val headers =
            if (smugglingIndicators) {
                listOf(header("Content-Length", "5"), header("Transfer-Encoding", "chunked"))
            } else {
                emptyList()
            }
        val request = request("GET", host, "/index", headers) { on { bodyToString() } doReturn "" }
        return pair(request, response(OK, "x".repeat(PAGE_BODY_CHARS)))
    }

    /** Waits until every task submitted to the scanner's single-thread executor so far has run (FIFO). */
    fun drain() {
        scanner.executor.submit {}.get(WAIT_SECONDS, TimeUnit.SECONDS)
    }

    /** Occupies the scanner's executor until the returned latch is released (capped at the wait limit). */
    fun blockExecutor(): CountDownLatch {
        val latch = CountDownLatch(1)
        val started = CountDownLatch(1)
        scanner.executor.submit {
            started.countDown()
            latch.await(WAIT_SECONDS, TimeUnit.SECONDS)
        }
        check(started.await(WAIT_SECONDS, TimeUnit.SECONDS)) { "executor did not start the blocking task" }
        return latch
    }

    /** What Burp does with a scan check's AuditResult: its issues enter the site map. */
    fun fileLikeBurp(result: AuditResult) {
        siteMap.addAll(result.auditIssues())
    }

    fun analyzed(): Int {
        drain()
        return scanner.getStatus().requestsAnalyzed
    }

    fun passiveIssueEvents(): List<Map<*, *>> =
        synchronized(auditEvents) {
            auditEvents.filter { it.first == "passive_ai_issue" }.map { it.second as Map<*, *> }
        }

    override fun close() {
        scanner.shutdown()
        ObjectFactoryLocator.FACTORY = savedFactory
    }

    private companion object {
        const val WAIT_SECONDS = 10L
        const val NO_CONTENT: Short = 204
        const val OK: Short = 200
        const val PAGE_BODY_CHARS = 64
    }
}

private fun recordingFactory(built: MutableList<FiledIssue>): MontoyaObjectFactory {
    val factory = mock<MontoyaObjectFactory>(defaultAnswer = Answers.RETURNS_MOCKS)
    whenever(
        factory.auditIssue(
            anyOrNull(),
            anyOrNull(),
            anyOrNull(),
            anyOrNull(),
            anyOrNull(),
            anyOrNull(),
            anyOrNull(),
            anyOrNull(),
            anyOrNull(),
            any<List<HttpRequestResponse>>(),
        ),
    ).thenAnswer { invocation ->
        val filed =
            FiledIssue(
                name = invocation.getArgument(0),
                detail = invocation.getArgument(1),
                remediation = invocation.getArgument(2),
                baseUrl = invocation.getArgument(3),
                severity = invocation.getArgument(4),
                confidence = invocation.getArgument(5),
                typicalSeverity = invocation.getArgument(8),
                requestResponses = invocation.getArgument(9),
            )
        built += filed
        mock<AuditIssue> {
            on { name() } doReturn filed.name
            on { detail() } doReturn filed.detail
            on { baseUrl() } doReturn filed.baseUrl
            on { severity() } doReturn filed.severity
            on { confidence() } doReturn filed.confidence
        }
    }
    whenever(factory.auditResult(any<List<AuditIssue>>())).thenAnswer { invocation ->
        val issues = invocation.getArgument<List<AuditIssue>>(0).toList()
        mock<AuditResult> { on { auditIssues() } doReturn issues }
    }
    return factory
}

private fun recordingApi(
    output: MutableList<String>,
    errors: MutableList<String>,
    siteMap: MutableList<AuditIssue>,
    extensionAdds: MutableList<AuditIssue>,
): MontoyaApi {
    val logging =
        mock<Logging> {
            on { logToOutput(any<String>()) } doAnswer { output += it.getArgument<String>(0) }
            on { logToError(any<String>()) } doAnswer { errors += it.getArgument<String>(0) }
        }
    val map =
        mock<SiteMap> {
            on { issues() } doAnswer { synchronized(siteMap) { siteMap.toList() } }
            on { add(any<AuditIssue>()) } doAnswer {
                val issue = it.getArgument<AuditIssue>(0)
                extensionAdds += issue
                siteMap += issue
            }
        }
    val api = mock<MontoyaApi>(defaultAnswer = Answers.RETURNS_DEEP_STUBS)
    whenever(api.logging()).thenReturn(logging)
    whenever(api.siteMap()).thenReturn(map)
    return api
}

private fun header(
    name: String,
    value: String,
): HttpHeader =
    mock {
        on { name() } doReturn name
        on { value() } doReturn value
    }

private fun request(
    method: String,
    host: String,
    path: String,
    headers: List<HttpHeader>,
    extra: org.mockito.kotlin.KStubbing<HttpRequest>.(HttpRequest) -> Unit,
): HttpRequest {
    val service =
        mock<HttpService> {
            on { host() } doReturn host
            on { port() } doReturn 443
            on { secure() } doReturn true
        }
    return mock {
        on { method() } doReturn method
        on { url() } doReturn "https://$host$path"
        on { path() } doReturn path
        on { httpService() } doReturn service
        on { headers() } doReturn headers
        extra(it)
    }
}

private fun response(
    status: Short,
    body: String,
): HttpResponse {
    val bytes =
        mock<MontoyaByteArray> {
            on { getBytes() } doReturn ByteArray(0)
            on { length() } doReturn 0
        }
    return mock {
        on { statusCode() } doReturn status
        on { headers() } doReturn emptyList()
        on { bodyToString() } doReturn body
        on { toByteArray() } doReturn bytes
    }
}

private fun pair(
    request: HttpRequest,
    response: HttpResponse,
): HttpRequestResponse {
    val service = request.httpService()
    return mock {
        on { request() } doReturn request
        on { response() } doReturn response
        on { httpService() } doReturn service
    }
}
