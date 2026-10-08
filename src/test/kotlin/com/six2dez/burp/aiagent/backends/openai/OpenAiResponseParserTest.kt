package com.six2dez.burp.aiagent.backends.openai

import com.fasterxml.jackson.core.JsonProcessingException
import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.module.kotlin.registerKotlinModule
import com.six2dez.burp.aiagent.backends.TokenUsage
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows

class OpenAiResponseParserTest {
    private val mapper = ObjectMapper().registerKotlinModule()

    @Test
    fun singleJsonDocumentYieldsMessageContentAndUsage() {
        val parsed =
            OpenAiResponseParser.parse(
                mapper,
                """{"choices":[{"message":{"content":"Hi"}}],"usage":{"prompt_tokens":3,"completion_tokens":1}}""",
            )
        assertEquals("Hi", parsed.content)
        assertEquals(TokenUsage(inputTokens = 3, outputTokens = 1), parsed.usage)
    }

    @Test
    fun singleJsonDocumentWithoutUsageYieldsNullUsage() {
        val parsed = OpenAiResponseParser.parse(mapper, """{"choices":[{"message":{"content":"Hi"}}]}""")
        assertEquals("Hi", parsed.content)
        assertNull(parsed.usage)
    }

    @Test
    fun sseDeltasAreAggregated() {
        val body =
            "data: {\"choices\":[{\"delta\":{\"content\":\"Hel\"}}]}\n\n" +
                "data: {\"choices\":[{\"delta\":{\"content\":\"lo\"}}]}\n\n" +
                "data: [DONE]\n\n"
        val parsed = OpenAiResponseParser.parse(mapper, body)
        assertEquals("Hello", parsed.content)
        assertNull(parsed.usage)
    }

    @Test
    fun sseWithCrlfCommentsEventsAndNullContentFinalChunk() {
        val body =
            ": keep-alive\r\n\r\n" +
                "event: message\r\n" +
                "data: {\"choices\":[{\"delta\":{\"content\":\"Hel\"}}],\"usage\":{\"prompt_tokens\":1,\"completion_tokens\":1}}\r\n\r\n" +
                "event: message\r\n" +
                "data: {\"choices\":[{\"delta\":{\"content\":\"lo\"}}]}\r\n\r\n" +
                "data: {\"choices\":[{\"delta\":{\"content\":null},\"finish_reason\":\"stop\"}]," +
                "\"usage\":{\"prompt_tokens\":7,\"completion_tokens\":2}}\r\n\r\n" +
                "data: [DONE]\r\n\r\n"
        val parsed = OpenAiResponseParser.parse(mapper, body)
        assertEquals("Hello", parsed.content, "a JSON null delta must never become the text \"null\"")
        assertEquals(TokenUsage(inputTokens = 7, outputTokens = 2), parsed.usage)
    }

    @Test
    fun sseChunkWithMessageContentInsteadOfDeltaIsUsed() {
        val body =
            "data: {\"choices\":[{\"message\":{\"content\":\"Whole answer\"}}]}\n\n" +
                "data: [DONE]\n\n"
        assertEquals("Whole answer", OpenAiResponseParser.parse(mapper, body).content)
    }

    @Test
    fun malformedSseLineIsSkipped() {
        val body =
            "data: {\"choices\":[{\"delta\":{\"content\":\"Hel\"}}]}\n\n" +
                "data: {oops\n\n" +
                "data: {\"choices\":[{\"delta\":{\"content\":\"lo\"}}]}\n\n" +
                "data: [DONE]\n\n"
        assertEquals("Hello", OpenAiResponseParser.parse(mapper, body).content)
    }

    @Test
    fun sseWithOnlyDoneYieldsBlankContent() {
        val parsed = OpenAiResponseParser.parse(mapper, "data: [DONE]\n\n")
        assertTrue(parsed.content.isBlank())
        assertNull(parsed.usage)
    }

    @Test
    fun malformedNonSseBodyPropagatesTheJacksonException() {
        assertThrows<JsonProcessingException> {
            OpenAiResponseParser.parse(mapper, "{not json")
        }
    }
}
