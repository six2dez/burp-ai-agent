package com.six2dez.burp.aiagent.context

import burp.api.montoya.MontoyaApi
import burp.api.montoya.http.HttpService
import burp.api.montoya.http.message.HttpRequestResponse
import burp.api.montoya.http.message.requests.HttpRequest
import burp.api.montoya.http.message.responses.HttpResponse
import burp.api.montoya.scanner.audit.issues.AuditIssue
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity
import com.fasterxml.jackson.databind.ObjectMapper
import com.six2dez.burp.aiagent.redact.PrivacyMode
import com.six2dez.burp.aiagent.redact.Redaction
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.mockito.kotlin.mock
import org.mockito.kotlin.whenever

/**
 * End-to-end privacy probes for the right-click "send to AI" capture (quick task 261008-jx2).
 *
 * Each case drives [ContextCollector] the way the context menu does and inspects BOTH the JSON
 * that is sent and the preview the user approves. The fixture carries the item's own hostname in
 * places the Host-line rule never sees (Referer, Origin, Location, an absolute URL in the body)
 * and a query-string token in the URL itself.
 *
 * Survival-sweep discipline: assertions that a value is PRESENT live only in OFF-only functions;
 * functions that name a redacting mode assert absence or exact redacted output.
 */
class ContextCollectorPrivacyTest {
    private val mapper = ObjectMapper()

    @Test
    fun strictCapture_hidesOwnHostAndQueryTokenEverywhere() {
        val capture = capture(PrivacyMode.STRICT, withService = true)

        assertFalse(capture.contextJson.contains("realcorp", ignoreCase = true), capture.contextJson)
        assertFalse(capture.previewText.contains("realcorp", ignoreCase = true), capture.previewText)
        assertFalse(capture.contextJson.contains(QUERY_SECRET))
        assertFalse(capture.previewText.contains(QUERY_SECRET))
    }

    @Test
    fun strictCapture_withoutHttpService_fallsBackToUrlHost() {
        val capture = capture(PrivacyMode.STRICT, withService = false)

        assertFalse(capture.contextJson.contains("realcorp", ignoreCase = true), capture.contextJson)
        assertFalse(capture.previewText.contains("realcorp", ignoreCase = true), capture.previewText)
        assertFalse(capture.contextJson.contains(QUERY_SECRET))
        assertFalse(capture.previewText.contains(QUERY_SECRET))
    }

    @Test
    fun strictCapture_previewPrintsExactlyTheUrlThatIsSent() {
        val capture = capture(PrivacyMode.STRICT, withService = true)
        val sentUrl = urlField(capture)

        assertTrue(capture.previewText.contains("GET $sentUrl"), capture.previewText)
    }

    @Test
    fun balancedCapture_redactsQueryTokenInUrlFieldAndPreview() {
        val capture = capture(PrivacyMode.BALANCED, withService = true)

        assertFalse(capture.contextJson.contains(QUERY_SECRET), capture.contextJson)
        assertFalse(capture.previewText.contains(QUERY_SECRET), capture.previewText)
        val expectedUrl = "https://api.realcorp.com/api/v1/me?access_token=[REDACTED]&x=1"
        assertEquals(expectedUrl, urlField(capture))
        assertTrue(capture.previewText.contains("GET $expectedUrl"), capture.previewText)
    }

    @Test
    fun offCapture_keepsUrlByteIdentical() {
        val capture = capture(PrivacyMode.OFF, withService = true)

        assertEquals(RAW_URL, urlField(capture))
    }

    @Test
    fun offCapture_appliesCustomPatternsToUrlAndRequest() {
        Redaction.setCustomPatterns(listOf(QUERY_SECRET))
        try {
            val capture = capture(PrivacyMode.OFF, withService = true)
            val items = mapper.readTree(capture.contextJson)["items"][0]

            assertFalse(items["url"].asText().contains(QUERY_SECRET), items["url"].asText())
            assertFalse(items["request"].asText().contains(QUERY_SECRET), items["request"].asText())
        } finally {
            Redaction.setCustomPatterns(emptyList())
        }
    }

    @Test
    fun strictIssueCapture_redactsTokensJwtAndOwnHostInIssueText() {
        val capture = issueCapture(PrivacyMode.STRICT)

        for (text in listOf(capture.contextJson, capture.previewText)) {
            assertFalse(text.contains(SESSION_SECRET), text)
            assertFalse(text.contains(JWT), text)
            assertFalse(text.contains(JWT_PAYLOAD), text)
            assertFalse(text.contains("realcorp", ignoreCase = true), text)
        }
    }

    @Test
    fun balancedIssueCapture_redactsTokensAndJwtInIssueText() {
        val capture = issueCapture(PrivacyMode.BALANCED)

        for (text in listOf(capture.contextJson, capture.previewText)) {
            assertFalse(text.contains(SESSION_SECRET), text)
            assertFalse(text.contains(JWT), text)
            assertFalse(text.contains(JWT_PAYLOAD), text)
        }
    }

    @Test
    fun strictIssueCapture_affectedHostMatchesTheAliasInsideTheDetail() {
        val capture = issueCapture(PrivacyMode.STRICT)
        val item = mapper.readTree(capture.contextJson)["items"][0]
        val alias = item["affectedHost"].asText()

        assertTrue(alias.startsWith("host-"), alias)
        assertTrue(item["detail"].asText().contains("https://$alias/app"), item["detail"].asText())
    }

    private fun issueCapture(mode: PrivacyMode): ContextCapture {
        val service = mock<HttpService>()
        whenever(service.host()).thenReturn(ISSUE_HOST)
        val issue = mock<AuditIssue>()
        whenever(issue.name()).thenReturn("Session token in URL https://$ISSUE_HOST/app?JSESSIONID=$SESSION_SECRET")
        whenever(issue.severity()).thenReturn(AuditIssueSeverity.MEDIUM)
        whenever(issue.confidence()).thenReturn(AuditIssueConfidence.FIRM)
        whenever(issue.detail()).thenReturn(
            "<p>The application exposes a session token in the URL " +
                "<b>https://$ISSUE_HOST/app?JSESSIONID=$SESSION_SECRET</b>.</p>" +
                "<p>The request carried <code>Authorization: Bearer $JWT</code>.</p>",
        )
        whenever(issue.remediation()).thenReturn(
            "Move the token out of https://$ISSUE_HOST/app?JSESSIONID=$SESSION_SECRET and into a cookie.",
        )
        whenever(issue.httpService()).thenReturn(service)

        return ContextCollector(mock<MontoyaApi>()).fromAuditIssues(
            listOf(issue),
            ContextOptions(privacyMode = mode, deterministic = true, hostSalt = SALT),
        )
    }

    private fun urlField(capture: ContextCapture): String = mapper.readTree(capture.contextJson)["items"][0]["url"].asText()

    private fun capture(
        mode: PrivacyMode,
        withService: Boolean,
    ): ContextCapture =
        ContextCollector(mock<MontoyaApi>()).fromRequestResponses(
            listOf(requestResponse(withService)),
            ContextOptions(privacyMode = mode, deterministic = true, hostSalt = SALT),
        )

    private fun requestResponse(withService: Boolean): HttpRequestResponse {
        val request = mock<HttpRequest>()
        whenever(request.method()).thenReturn("GET")
        whenever(request.url()).thenReturn(RAW_URL)
        whenever(request.toString()).thenReturn(
            "GET /api/v1/me?access_token=$QUERY_SECRET&x=1 HTTP/1.1\r\n" +
                "Host: api.realcorp.com\r\n" +
                "Referer: https://api.realcorp.com/hr/x\r\n" +
                "Origin: https://api.realcorp.com\r\n" +
                "Accept: */*\r\n\r\n",
        )

        val response = mock<HttpResponse>()
        whenever(response.toString()).thenReturn(
            "HTTP/1.1 302 Found\r\n" +
                "Location: https://api.realcorp.com/login\r\n" +
                "Content-Type: text/html\r\n\r\n" +
                "<script src=\"https://api.realcorp.com/assets/a.js\"></script>",
        )

        val rr = mock<HttpRequestResponse>()
        whenever(rr.request()).thenReturn(request)
        whenever(rr.response()).thenReturn(response)
        if (withService) {
            val service = mock<HttpService>()
            whenever(service.host()).thenReturn("api.realcorp.com")
            whenever(rr.httpService()).thenReturn(service)
        }
        return rr
    }

    private companion object {
        const val SALT = "jx2-privacy-salt"
        const val QUERY_SECRET = "SECRETQ9"
        const val RAW_URL = "https://api.realcorp.com/api/v1/me?access_token=SECRETQ9&x=1"
        const val ISSUE_HOST = "intranet.realcorp.local"
        const val SESSION_SECRET = "SECRETS1"
        const val JWT_PAYLOAD = "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ"
        const val JWT =
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.$JWT_PAYLOAD.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
    }
}
