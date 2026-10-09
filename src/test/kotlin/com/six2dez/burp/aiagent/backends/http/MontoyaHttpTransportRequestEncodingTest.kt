package com.six2dez.burp.aiagent.backends.http

import burp.api.montoya.MontoyaApi
import burp.api.montoya.http.Http
import burp.api.montoya.http.RequestOptions
import burp.api.montoya.http.message.HttpRequestResponse
import burp.api.montoya.http.message.requests.HttpRequest
import burp.api.montoya.http.message.responses.HttpResponse
import burp.api.montoya.internal.MontoyaObjectFactory
import burp.api.montoya.internal.ObjectFactoryLocator
import com.fasterxml.jackson.databind.ObjectMapper
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.mockito.Answers
import org.mockito.kotlin.any
import org.mockito.kotlin.argumentCaptor
import org.mockito.kotlin.doReturn
import org.mockito.kotlin.mock
import org.mockito.kotlin.never
import org.mockito.kotlin.times
import org.mockito.kotlin.verify
import java.nio.ByteBuffer
import java.nio.charset.CodingErrorAction
import burp.api.montoya.core.ByteArray as MontoyaByteArray

/**
 * Drives the REAL [MontoyaHttpTransport.post] (no spy, no OkHttp substitution) through a mock
 * Montoya object factory, so the exact bytes handed to Burp are observable. Burp's String-body
 * conversion keeps only the low byte of each char, which corrupted non-ASCII request content
 * (#84 #85 #86 #88) and could even produce raw JSON structural bytes.
 */
class MontoyaHttpTransportRequestEncodingTest {
    private var savedFactory: MontoyaObjectFactory? = null
    private lateinit var factory: MontoyaObjectFactory
    private lateinit var request: HttpRequest
    private lateinit var bodyBytes: MontoyaByteArray
    private lateinit var api: MontoyaApi

    @BeforeEach
    fun installFactory() {
        savedFactory = ObjectFactoryLocator.FACTORY
        request = mock<HttpRequest>(defaultAnswer = Answers.RETURNS_SELF)
        bodyBytes = mock<MontoyaByteArray>()
        val options = mock<RequestOptions>(defaultAnswer = Answers.RETURNS_SELF)
        factory =
            mock<MontoyaObjectFactory> {
                on { httpRequestFromUrl(any<String>()) } doReturn request
                on { requestOptions() } doReturn options
                on { byteArray(any<ByteArray>()) } doReturn bodyBytes
            }
        ObjectFactoryLocator.FACTORY = factory
        api = buildApi()
    }

    @AfterEach
    fun restoreFactory() {
        ObjectFactoryLocator.FACTORY = savedFactory
    }

    @Test
    fun `post hands Burp the exact UTF-8 bytes and never the String body`() {
        val json = jacksonFixture()

        MontoyaHttpTransport(api).post(URL, emptyMap(), json)

        assertArrayEquals(json.toByteArray(Charsets.UTF_8), capturedBodyBytes())
        verify(request).withBody(bodyBytes)
        verify(request, never()).withBody(any<String>())
    }

    @Test
    fun `sent bytes are strict UTF-8 and parse to the original JSON tree`() {
        val json = jacksonFixture()
        val lowByteProjection = ByteArray(json.length) { json[it].code.toByte() }
        assertFalse(lowByteProjection.contentEquals(json.toByteArray(Charsets.UTF_8)))

        MontoyaHttpTransport(api).post(URL, emptyMap(), json)

        val decoded = strictUtf8(capturedBodyBytes())
        assertEquals(json, decoded)
        val mapper = ObjectMapper()
        assertEquals(mapper.readTree(json), mapper.readTree(decoded))
    }

    @Test
    fun `unpaired surrogate is sent as a question mark, never as invalid UTF-8`() {
        val json = "{\"content\":\"broken \uD83D pair\"}"

        MontoyaHttpTransport(api).post(URL, emptyMap(), json)

        assertEquals(json.replace('\uD83D', '?'), strictUtf8(capturedBodyBytes()))
    }

    @Test
    fun `post declares charset utf-8 and keeps caller headers`() {
        val result =
            MontoyaHttpTransport(api).post(URL, mapOf("Authorization" to "Bearer test"), "{}")

        verify(request, times(1)).withAddedHeader("Content-Type", "application/json; charset=utf-8")
        verify(request).withAddedHeader("Authorization", "Bearer test")
        assertEquals(200, result.statusCode)
        assertTrue(result.isSuccessful)
        assertEquals("{}", result.body)
    }

    private fun capturedBodyBytes(): ByteArray {
        val captor = argumentCaptor<ByteArray>()
        verify(factory).byteArray(captor.capture())
        return captor.firstValue
    }

    private fun strictUtf8(bytes: ByteArray): String =
        Charsets.UTF_8
            .newDecoder()
            .onMalformedInput(CodingErrorAction.REPORT)
            .onUnmappableCharacter(CodingErrorAction.REPORT)
            .decode(ByteBuffer.wrap(bytes))
            .toString()

    private fun jacksonFixture(): String =
        ObjectMapper().writeValueAsString(
            mapOf(
                "model" to "m",
                "messages" to listOf(mapOf("role" to "user", "content" to "→ — • é ñ 😀 Ģ")),
            ),
        )

    private fun buildApi(): MontoyaApi {
        val responseBody =
            mock<MontoyaByteArray> {
                on { getBytes() } doReturn "{}".toByteArray(Charsets.UTF_8)
            }
        val response =
            mock<HttpResponse> {
                on { statusCode() } doReturn 200.toShort()
                on { body() } doReturn responseBody
            }
        val requestResponse = mock<HttpRequestResponse> { on { response() } doReturn response }
        val http =
            mock<Http> {
                on { sendRequest(any<HttpRequest>(), any<RequestOptions>()) } doReturn requestResponse
            }
        return mock<MontoyaApi> { on { http() } doReturn http }
    }

    private companion object {
        const val URL = "http://127.0.0.1:1234/v1/chat/completions"
    }
}
