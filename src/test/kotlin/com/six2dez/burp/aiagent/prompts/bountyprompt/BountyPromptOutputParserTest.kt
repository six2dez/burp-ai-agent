package com.six2dez.burp.aiagent.prompts.bountyprompt

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class BountyPromptOutputParserTest {

    private fun definition(): BountyPromptDefinition {
        return BountyPromptDefinition(
            id = "Security_Headers_Analysis",
            title = "Security Headers Analysis",
            category = BountyPromptCategory.DETECTION,
            outputType = BountyPromptOutputType.ISSUE,
            systemPrompt = "System prompt",
            userPrompt = "User prompt",
            severity = "Information",
            confidence = BountyPromptConfidence.FIRM,
            tagsUsed = emptySet()
        )
    }

    @Test
    fun parse_jsonArrayFindings() {
        val parser = BountyPromptOutputParser()
        val raw = """
            ```json
            [
              {
                "title":"Missing CSP",
                "detail":"Content-Security-Policy header is missing.",
                "severity":"Medium",
                "confidence":92
              }
            ]
            ```
        """.trimIndent()

        val findings = parser.parse(raw, definition())

        assertEquals(1, findings.size)
        assertEquals("Missing CSP", findings.first().title)
        assertEquals("Medium", findings.first().severity)
        assertEquals(92, findings.first().confidence)
    }

    @Test
    fun parse_noneReturnsEmpty() {
        val parser = BountyPromptOutputParser()
        val findings = parser.parse("NONE", definition())
        assertTrue(findings.isEmpty())
    }

    @Test
    fun parse_plainTextFallsBackToSingleFinding() {
        val parser = BountyPromptOutputParser()
        val findings = parser.parse("Potential issue in /admin endpoint", definition())
        assertEquals(1, findings.size)
        assertEquals("Security Headers Analysis", findings.first().title)
        assertEquals(BountyPromptConfidence.FIRM.score, findings.first().confidence)
    }
}
