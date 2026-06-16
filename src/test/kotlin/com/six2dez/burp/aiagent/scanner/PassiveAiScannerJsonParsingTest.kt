package com.six2dez.burp.aiagent.scanner

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class PassiveAiScannerJsonParsingTest {
    @Test
    fun cleanJsonResponse_extractsArrayFromMarkdownCodeFence() {
        val raw =
            """
            ```json
            [{"title":"A","severity":"High","detail":"x","confidence":90}]
            ```
            """.trimIndent()

        val cleaned = cleanJsonResponse(raw)

        assertTrue(cleaned.startsWith("["))
        assertTrue(cleaned.endsWith("]"))
    }

    @Test
    fun parseIssuesJson_supportsNestedContentAndEscapedQuotes() {
        val cleaned =
            """
            [
              {
                "title":"SQL Injection",
                "severity":"High",
                "detail":"Found evidence in {\"db\":\"mysql\"} and \"quoted\" value",
                "reasoning":"Observed database error patterns",
                "confidence":95
              }
            ]
            """.trimIndent()

        val issues = parseIssuesJson(cleaned)

        assertEquals(1, issues.size)
        assertEquals("SQL Injection", issues.first().title)
        assertEquals(95, issues.first().confidence)
        assertTrue(issues.first().detail?.contains("mysql") == true)
        assertTrue(issues.first().detail?.contains("\"quoted\"") == true)
    }

    @Test
    fun cleanJsonResponse_extractsJsonFromMixedCliNoise() {
        val raw =
            """
            [PassiveAiScanner] Analyzing [1/3]: https://example.test/login
            [Burp AI Agent] Resolved absolute: /Users/test/.local/bin/claude
            ```json
            [{"title":"Missing Security Header","severity":"Low","detail":"X-Frame-Options missing","confidence":88}]
            ```
            """.trimIndent()

        val cleaned = cleanJsonResponse(raw)
        val issues = parseIssuesJson(cleaned)

        assertEquals(1, issues.size)
        assertEquals("Missing Security Header", issues.first().title)
        assertEquals(88, issues.first().confidence)
    }

    @Test
    fun parseIssuesJson_supportsObjectWrapperWithIssuesArray() {
        val cleaned =
            """
            {
              "issues": [
                {
                  "title":"Debug Endpoint Exposed",
                  "severity":"Medium",
                  "detail":"Found /_status endpoint without auth.",
                  "confidence":90
                }
              ]
            }
            """.trimIndent()

        val issues = parseIssuesJson(cleaned)

        assertEquals(1, issues.size)
        assertEquals("Debug Endpoint Exposed", issues.first().title)
        assertEquals(90, issues.first().confidence)
    }
}
