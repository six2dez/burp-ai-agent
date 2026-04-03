package com.six2dez.burp.aiagent.mcp.tools

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class ResponsePreprocessorTest {

    @Test
    fun preprocessResponse_filtersBinaryContentType() {
        val response =
            "HTTP/1.1 200 OK\r\n" +
                "Content-Type: image/png\r\n" +
                "\r\n" +
                "PNGDATA"

        val processed = ResponsePreprocessor.preprocessResponse(response, ResponsePreprocessorSettings())

        assertTrue(processed.contains("Binary content filtered out"))
        assertTrue(processed.contains("Content-Type: image/png"))
        assertFalse(processed.endsWith("PNGDATA"))
    }

    @Test
    fun preprocessResponse_keepsTextContentType() {
        val response =
            "HTTP/1.1 200 OK\r\n" +
                "Content-Type: text/plain\r\n" +
                "\r\n" +
                "hello"

        val processed = ResponsePreprocessor.preprocessResponse(response, ResponsePreprocessorSettings())

        assertEquals(response, processed)
    }

    @Test
    fun preprocessResponse_truncatesUtf8WithoutBreakingMultibyteChars() {
        val body = "🙂".repeat(300)
        val response =
            "HTTP/1.1 200 OK\r\n" +
                "Content-Type: text/plain\r\n" +
                "\r\n" +
                body

        val processed = ResponsePreprocessor.preprocessResponse(
            response,
            ResponsePreprocessorSettings(preprocessMaxResponseSizeKb = 1)
        )

        assertTrue(processed.contains("[SNIP -"))
        val truncatedBody = processed.substringAfter("\r\n\r\n")
        val parts = truncatedBody.split("\n[SNIP -")
        assertEquals(2, parts.size)
        val first = parts[0]
        val last = parts[1].substringAfter("]\n")
        assertTrue(first.isNotBlank())
        assertTrue(last.isNotBlank())
        assertFalse(first.contains("\uFFFD"))
        assertFalse(last.contains("\uFFFD"))
    }

    @Test
    fun extractContentType_supportsCrlfAndLf() {
        val crlfHeaders = "HTTP/1.1 200 OK\r\nContent-Type: application/json; charset=utf-8"
        val lfHeaders = "HTTP/1.1 200 OK\nContent-Type: application/json; charset=utf-8"

        assertEquals("application/json", ResponsePreprocessor.extractContentType(crlfHeaders))
        assertEquals("application/json", ResponsePreprocessor.extractContentType(lfHeaders))
    }
}
