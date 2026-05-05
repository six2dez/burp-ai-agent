package com.six2dez.burp.aiagent.backends.http

import burp.api.montoya.http.message.responses.HttpResponse
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.mockito.kotlin.doReturn
import org.mockito.kotlin.mock
import burp.api.montoya.core.ByteArray as MontoyaByteArray

class MontoyaHttpTransportUtf8Test {
    @Test
    fun `decodes multibyte body as UTF-8 instead of platform charset`() {
        val original = "héllo 中文測試 ☃ 🚀"
        val rawBytes = original.toByteArray(Charsets.UTF_8)

        val result = MontoyaHttpTransport.decodeResponse(buildResponse(200, rawBytes))

        assertEquals(original, result.body)
        assertEquals(200, result.statusCode)
        assertTrue(result.isSuccessful)
    }

    @Test
    fun `decodes ascii body unchanged`() {
        val original = """{"choices":[{"message":{"content":"ok"}}]}"""
        val rawBytes = original.toByteArray(Charsets.UTF_8)

        val result = MontoyaHttpTransport.decodeResponse(buildResponse(200, rawBytes))

        assertEquals(original, result.body)
    }

    @Test
    fun `null response yields empty body and zero status`() {
        val result = MontoyaHttpTransport.decodeResponse(null)

        assertEquals("", result.body)
        assertEquals(0, result.statusCode)
        assertFalse(result.isSuccessful)
    }

    @Test
    fun `non-2xx status is not successful but body is preserved`() {
        val original = "rate limited 限速"
        val result =
            MontoyaHttpTransport.decodeResponse(
                buildResponse(429, original.toByteArray(Charsets.UTF_8)),
            )

        assertEquals(original, result.body)
        assertEquals(429, result.statusCode)
        assertFalse(result.isSuccessful)
    }

    private fun buildResponse(
        statusCode: Int,
        bytes: ByteArray,
    ): HttpResponse {
        val byteArray =
            mock<MontoyaByteArray> {
                on { getBytes() } doReturn bytes
            }
        return mock<HttpResponse> {
            on { statusCode() } doReturn statusCode.toShort()
            on { body() } doReturn byteArray
        }
    }
}
