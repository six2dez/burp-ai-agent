package com.six2dez.burp.aiagent.prompts.bountyprompt

import java.nio.file.Files
import kotlin.io.path.writeText
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class BountyPromptLoaderTest {

    @Test
    fun loadFromDirectory_onlyLoadsCuratedEnabledPrompts() {
        val dir = Files.createTempDirectory("bounty-loader-test")
        dir.resolve("API_Keys_Exposure_Detection.json").writeText(
            """
            {
              "title": "API Keys Exposure Detection",
              "outputType": "Issue",
              "systemPrompt": "Detect leaked API keys.",
              "userPrompt": "Analyze [HTTP_Responses]",
              "severity": "High",
              "confidence": "Certain"
            }
            """.trimIndent()
        )
        dir.resolve("Non_Curated_Prompt.json").writeText(
            """
            {
              "title": "Non Curated",
              "outputType": "Issue",
              "systemPrompt": "noop",
              "userPrompt": "noop"
            }
            """.trimIndent()
        )

        val loader = BountyPromptLoader()
        val loaded = loader.loadFromDirectory(
            directoryPath = dir.toString(),
            enabledPromptIds = setOf("API_Keys_Exposure_Detection", "Non_Curated_Prompt")
        )

        assertEquals(1, loaded.prompts.size)
        assertEquals("API_Keys_Exposure_Detection", loaded.prompts.first().id)
    }

    @Test
    fun loadFromDirectory_skipsMalformedPrompt() {
        val dir = Files.createTempDirectory("bounty-loader-malformed")
        dir.resolve("Extract_Endpoints.json").writeText(
            """
            {
              "title": "Extract Endpoints",
              "outputType": "Issue",
              "systemPrompt": "",
              "userPrompt": ""
            }
            """.trimIndent()
        )

        val loader = BountyPromptLoader()
        val loaded = loader.loadFromDirectory(
            directoryPath = dir.toString(),
            enabledPromptIds = setOf("Extract_Endpoints")
        )

        assertTrue(loaded.prompts.isEmpty())
        assertTrue(loaded.errors.isNotEmpty())
    }
}
