package com.six2dez.burp.aiagent.prompts.bountyprompt

import burp.api.montoya.http.message.HttpRequestResponse
import burp.api.montoya.http.message.params.HttpParameterType
import burp.api.montoya.http.message.params.ParsedHttpParameter
import burp.api.montoya.http.message.requests.HttpRequest
import burp.api.montoya.http.message.responses.HttpResponse
import com.six2dez.burp.aiagent.context.ContextOptions
import com.six2dez.burp.aiagent.redact.PrivacyMode
import org.mockito.kotlin.mock
import org.mockito.kotlin.whenever
import kotlin.test.Test
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class BountyPromptTagResolverTest {

    @Test
    fun resolve_replacesTagsAndAppliesRedaction() {
        val urlParam = mock<ParsedHttpParameter>()
        whenever(urlParam.type()).thenReturn(HttpParameterType.URL)
        whenever(urlParam.name()).thenReturn("token")
        whenever(urlParam.value()).thenReturn("abc123")

        val request = mock<HttpRequest>()
        whenever(request.toString()).thenReturn(
            """
            POST /api/login?token=abc123 HTTP/1.1
            Host: example.com
            Authorization: Bearer abc.def.ghi
            Cookie: session=supersecret
            Content-Type: application/json
            
            {"username":"alice","password":"secret"}
            """.trimIndent()
        )
        whenever(request.method()).thenReturn("POST")
        whenever(request.url()).thenReturn("https://example.com/api/login?token=abc123&next=/home")
        whenever(request.parameters()).thenReturn(listOf(urlParam))

        val response = mock<HttpResponse>()
        whenever(response.toString()).thenReturn(
            """
            HTTP/1.1 200 OK
            Set-Cookie: sid=123; HttpOnly
            Content-Type: application/json
            
            {"status":"ok"}
            """.trimIndent()
        )
        whenever(response.statusCode()).thenReturn(200)

        val rr = mock<HttpRequestResponse>()
        whenever(rr.request()).thenReturn(request)
        whenever(rr.response()).thenReturn(response)

        val promptText = """
            Check:
            [HTTP_Requests_Headers]
            [HTTP_Response_Headers]
            [HTTP_Requests_Parameters]
            [HTTP_Cookies]
            [HTTP_Status_Code]
        """.trimIndent()
        val definition = BountyPromptDefinition(
            id = "Security_Headers_Analysis",
            title = "Security Headers Analysis",
            category = BountyPromptCategory.DETECTION,
            outputType = BountyPromptOutputType.ISSUE,
            systemPrompt = "System",
            userPrompt = promptText,
            severity = "Information",
            confidence = BountyPromptConfidence.TENTATIVE,
            tagsUsed = BountyPromptTag.extractFrom(promptText)
        )

        val resolved = BountyPromptTagResolver().resolve(
            definition = definition,
            requestResponses = listOf(rr),
            options = ContextOptions(
                privacyMode = PrivacyMode.STRICT,
                deterministic = true,
                hostSalt = "test-salt"
            )
        )

        assertFalse(resolved.resolvedUserPrompt.contains("[HTTP_"))
        assertTrue(resolved.resolvedUserPrompt.contains("Host: host-"))
        assertTrue(resolved.resolvedUserPrompt.contains("Authorization: [REDACTED]"))
        assertTrue(resolved.resolvedUserPrompt.contains("Cookie: [STRIPPED]"))
        assertTrue(resolved.resolvedUserPrompt.contains("token=[REDACTED]"))
        assertTrue(resolved.resolvedUserPrompt.contains("200"))
    }
}
