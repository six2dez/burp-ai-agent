package com.six2dez.burp.aiagent.context

import burp.api.montoya.MontoyaApi
import burp.api.montoya.http.HttpService
import burp.api.montoya.http.message.HttpRequestResponse
import burp.api.montoya.http.message.requests.HttpRequest
import burp.api.montoya.http.message.responses.HttpResponse
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
    }
}
