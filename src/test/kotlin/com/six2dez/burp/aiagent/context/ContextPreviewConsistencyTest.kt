package com.six2dez.burp.aiagent.context

import burp.api.montoya.MontoyaApi
import burp.api.montoya.http.HttpService
import burp.api.montoya.http.message.HttpRequestResponse
import burp.api.montoya.http.message.requests.HttpRequest
import burp.api.montoya.http.message.responses.HttpResponse
import burp.api.montoya.scanner.audit.issues.AuditIssue
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity
import com.six2dez.burp.aiagent.redact.PrivacyMode
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.mockito.kotlin.mock
import org.mockito.kotlin.whenever

class ContextPreviewConsistencyTest {
    @Test
    fun httpPreview_isDeterministicAndHostRedactedInStrictMode() {
        val collector = ContextCollector(mock<MontoyaApi>())
        val rrBeta = requestResponse("POST", "https://api.beta.test/b")
        val rrAlpha = requestResponse("GET", "https://api.alpha.test/a")

        val capture =
            collector.fromRequestResponses(
                listOf(rrBeta, rrAlpha),
                ContextOptions(
                    privacyMode = PrivacyMode.STRICT,
                    deterministic = true,
                    hostSalt = "preview-salt",
                ),
            )

        val preview = capture.previewText
        assertTrue(preview.contains("Sample:"))
        assertTrue(preview.contains("host-"))
        assertFalse(preview.contains("api.alpha.test"))
        assertFalse(preview.contains("api.beta.test"))

        val alphaIndex = preview.indexOf("/a")
        val betaIndex = preview.indexOf("/b")
        assertTrue(alphaIndex >= 0)
        assertTrue(betaIndex >= 0)
        assertTrue(alphaIndex < betaIndex)
    }

    @Test
    fun issuePreview_redactsAffectedHostInStrictMode() {
        val collector = ContextCollector(mock<MontoyaApi>())
        val service = mock<HttpService>()
        whenever(service.host()).thenReturn("internal.example")

        val issue = mock<AuditIssue>()
        whenever(issue.name()).thenReturn("SQL injection")
        whenever(issue.severity()).thenReturn(AuditIssueSeverity.HIGH)
        whenever(issue.confidence()).thenReturn(AuditIssueConfidence.FIRM)
        whenever(issue.detail()).thenReturn("detail")
        whenever(issue.remediation()).thenReturn("remediation")
        whenever(issue.httpService()).thenReturn(service)

        val capture =
            collector.fromAuditIssues(
                listOf(issue),
                ContextOptions(
                    privacyMode = PrivacyMode.STRICT,
                    deterministic = true,
                    hostSalt = "preview-salt",
                ),
            )

        val preview = capture.previewText
        assertTrue(preview.contains("SQL injection"))
        assertTrue(preview.contains("host-"))
        assertFalse(preview.contains("internal.example"))
    }

    private fun requestResponse(
        method: String,
        url: String,
    ): HttpRequestResponse {
        val host = java.net.URI(url).host
        val path = java.net.URI(url).rawPath
        val request = mock<HttpRequest>()
        whenever(request.method()).thenReturn(method)
        whenever(request.url()).thenReturn(url)
        whenever(request.toString()).thenReturn(
            "$method $path HTTP/1.1\\r\\n" +
                "Host: $host\\r\\n" +
                "Authorization: Bearer secret-token\\r\\n\\r\\n" +
                "{\"demo\":\"value\"}",
        )

        val response = mock<HttpResponse>()
        whenever(response.toString()).thenReturn(
            "HTTP/1.1 200 OK\\r\\n" +
                "Set-Cookie: session=secret\\r\\n\\r\\n" +
                "ok",
        )

        val rr = mock<HttpRequestResponse>()
        whenever(rr.request()).thenReturn(request)
        whenever(rr.response()).thenReturn(response)
        return rr
    }
}
