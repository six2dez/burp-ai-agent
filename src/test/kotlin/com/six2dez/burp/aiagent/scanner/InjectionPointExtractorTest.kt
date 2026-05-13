package com.six2dez.burp.aiagent.scanner

import burp.api.montoya.core.Range
import burp.api.montoya.http.message.HttpHeader
import burp.api.montoya.http.message.params.HttpParameterType
import burp.api.montoya.http.message.params.ParsedHttpParameter
import burp.api.montoya.http.message.requests.HttpRequest
import org.mockito.kotlin.mock
import org.mockito.kotlin.whenever
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue

class InjectionPointExtractorTest {
    @Test
    fun extractsJsonAndPathAndHeaderPoints() {
        val urlParam = mock<ParsedHttpParameter>()
        whenever(urlParam.type()).thenReturn(HttpParameterType.URL)
        whenever(urlParam.name()).thenReturn("search")
        whenever(urlParam.value()).thenReturn("test")

        val cookieParam = mock<ParsedHttpParameter>()
        whenever(cookieParam.type()).thenReturn(HttpParameterType.COOKIE)
        whenever(cookieParam.name()).thenReturn("session")
        whenever(cookieParam.value()).thenReturn("abc")

        val header = mock<HttpHeader>()
        whenever(header.name()).thenReturn("X-Forwarded-Host")
        whenever(header.value()).thenReturn("attacker.com")

        val request = mock<HttpRequest>()
        whenever(request.parameters()).thenReturn(listOf(urlParam, cookieParam))
        whenever(request.headers()).thenReturn(listOf(header))
        whenever(request.headerValue("Content-Type")).thenReturn("application/json")
        whenever(request.bodyToString()).thenReturn("{\"userId\":123,\"role\":\"user\"}")
        whenever(request.url()).thenReturn("http://example.com/api/users/123?search=test")
        val points =
            InjectionPointExtractor.extract(
                request,
                setOf("x-forwarded-host"),
            )

        assertTrue(points.any { it.type == InjectionType.URL_PARAM && it.name == "search" })
        assertTrue(points.any { it.type == InjectionType.COOKIE && it.name == "session" })
        assertTrue(points.any { it.type == InjectionType.HEADER && it.name.equals("X-Forwarded-Host", true) })
        assertTrue(points.any { it.type == InjectionType.JSON_FIELD && it.name == "userId" })
        assertTrue(points.any { it.type == InjectionType.JSON_FIELD && it.name == "role" })
        assertTrue(points.any { it.type == InjectionType.PATH_SEGMENT && it.originalValue == "123" })
    }

    @Test
    fun extractsXmlFields() {
        val request = mock<HttpRequest>()
        whenever(request.parameters()).thenReturn(emptyList())
        whenever(request.headers()).thenReturn(emptyList())
        whenever(request.headerValue("Content-Type")).thenReturn("application/xml")
        whenever(request.bodyToString()).thenReturn("<order><id>42</id><item>book</item></order>")
        whenever(request.url()).thenReturn("http://example.com/api/order")
        val points =
            InjectionPointExtractor.extract(
                request,
                emptySet(),
            )

        assertTrue(points.any { it.type == InjectionType.XML_ELEMENT && it.name == "id" && it.originalValue == "42" })
        assertTrue(points.any { it.type == InjectionType.XML_ELEMENT && it.name == "item" && it.originalValue == "book" })
    }

    @Test
    fun extractsJsonBooleansNullAndEscapedStrings() {
        val request = mock<HttpRequest>()
        whenever(request.parameters()).thenReturn(emptyList())
        whenever(request.headers()).thenReturn(emptyList())
        whenever(request.headerValue("Content-Type")).thenReturn("application/json")
        whenever(request.bodyToString()).thenReturn("""{"name":"a\\\"b","enabled":true,"deleted":null}""")
        whenever(request.url()).thenReturn("http://example.com/api/user")

        val points = InjectionPointExtractor.extract(request, emptySet())

        assertTrue(points.any { it.type == InjectionType.JSON_FIELD && it.name == "name" && it.originalValue.contains("a") })
        assertTrue(points.any { it.type == InjectionType.JSON_FIELD && it.name == "enabled" && it.originalValue == "true" })
        assertTrue(points.any { it.type == InjectionType.JSON_FIELD && it.name == "deleted" && it.originalValue == "null" })
    }

    @Test
    fun matchInsertionPointPicksOverlappingUrlParam() {
        val raw =
            "GET /search?q=hello&page=1 HTTP/1.1\r\n" +
                "Host: example.com\r\n\r\n"
        val qStart = raw.indexOf("hello")
        val qEnd = qStart + "hello".length
        val pageStart = raw.indexOf("page=1") + "page=".length

        val qRange = rangeMock(qStart, qEnd)
        val pageRange = rangeMock(pageStart, pageStart + 1)

        val qParam = mock<ParsedHttpParameter>()
        whenever(qParam.type()).thenReturn(HttpParameterType.URL)
        whenever(qParam.name()).thenReturn("q")
        whenever(qParam.value()).thenReturn("hello")
        whenever(qParam.valueOffsets()).thenReturn(qRange)

        val pageParam = mock<ParsedHttpParameter>()
        whenever(pageParam.type()).thenReturn(HttpParameterType.URL)
        whenever(pageParam.name()).thenReturn("page")
        whenever(pageParam.value()).thenReturn("1")
        whenever(pageParam.valueOffsets()).thenReturn(pageRange)

        val rawBa = byteArrayMock(raw)
        val request = mock<HttpRequest>()
        whenever(request.parameters()).thenReturn(listOf(qParam, pageParam))
        whenever(request.headers()).thenReturn(emptyList())
        whenever(request.toByteArray()).thenReturn(rawBa)
        whenever(request.bodyOffset()).thenReturn(raw.length)
        whenever(request.bodyToString()).thenReturn("")
        whenever(request.headerValue("Content-Type")).thenReturn(null)
        whenever(request.url()).thenReturn("http://example.com/search?q=hello&page=1")

        // Selecting "ello" inside "hello" should match the q param, not page.
        val match =
            InjectionPointExtractor.matchInsertionPoint(
                request = request,
                selectionStart = qStart + 1,
                selectionEnd = qStart + 4,
            )
        assertTrue(match != null)
        assertEquals(InjectionType.URL_PARAM, match!!.type)
        assertEquals("q", match.name)
    }

    @Test
    fun matchInsertionPointPicksBodyParam() {
        val raw =
            "POST /api HTTP/1.1\r\n" +
                "Host: example.com\r\n" +
                "Content-Type: application/x-www-form-urlencoded\r\n" +
                "\r\n" +
                "username=alice&role=user"
        val aliceStart = raw.indexOf("alice")
        val aliceEnd = aliceStart + "alice".length

        val aliceRange = rangeMock(aliceStart, aliceEnd)

        val usernameParam = mock<ParsedHttpParameter>()
        whenever(usernameParam.type()).thenReturn(HttpParameterType.BODY)
        whenever(usernameParam.name()).thenReturn("username")
        whenever(usernameParam.value()).thenReturn("alice")
        whenever(usernameParam.valueOffsets()).thenReturn(aliceRange)

        val rawBa = byteArrayMock(raw)
        val request = mock<HttpRequest>()
        whenever(request.parameters()).thenReturn(listOf(usernameParam))
        whenever(request.headers()).thenReturn(emptyList())
        whenever(request.toByteArray()).thenReturn(rawBa)
        whenever(request.bodyOffset()).thenReturn(raw.length - "username=alice&role=user".length)
        whenever(request.bodyToString()).thenReturn("username=alice&role=user")
        whenever(request.headerValue("Content-Type")).thenReturn("application/x-www-form-urlencoded")
        whenever(request.url()).thenReturn("http://example.com/api")

        val match =
            InjectionPointExtractor.matchInsertionPoint(
                request = request,
                selectionStart = aliceStart + 1,
                selectionEnd = aliceEnd - 1,
            )
        assertTrue(match != null)
        assertEquals(InjectionType.BODY_PARAM, match!!.type)
        assertEquals("username", match.name)
    }

    @Test
    fun matchInsertionPointPicksCookie() {
        val raw =
            "GET / HTTP/1.1\r\n" +
                "Host: example.com\r\n" +
                "Cookie: session=abc; tracker=xyz\r\n" +
                "\r\n"
        val abcStart = raw.indexOf("abc")
        val abcEnd = abcStart + "abc".length

        val abcRange = rangeMock(abcStart, abcEnd)

        val sessionParam = mock<ParsedHttpParameter>()
        whenever(sessionParam.type()).thenReturn(HttpParameterType.COOKIE)
        whenever(sessionParam.name()).thenReturn("session")
        whenever(sessionParam.value()).thenReturn("abc")
        whenever(sessionParam.valueOffsets()).thenReturn(abcRange)

        val rawBa = byteArrayMock(raw)
        val request = mock<HttpRequest>()
        whenever(request.parameters()).thenReturn(listOf(sessionParam))
        whenever(request.headers()).thenReturn(emptyList())
        whenever(request.toByteArray()).thenReturn(rawBa)
        whenever(request.bodyOffset()).thenReturn(raw.length)
        whenever(request.bodyToString()).thenReturn("")
        whenever(request.headerValue("Content-Type")).thenReturn(null)
        whenever(request.url()).thenReturn("http://example.com/")

        val match =
            InjectionPointExtractor.matchInsertionPoint(
                request = request,
                selectionStart = abcStart + 1,
                selectionEnd = abcEnd - 1,
            )
        assertTrue(match != null)
        assertEquals(InjectionType.COOKIE, match!!.type)
        assertEquals("session", match.name)
    }

    @Test
    fun matchInsertionPointFallsBackToHeaderWhenSelectionHitsHeaderLine() {
        val raw =
            "GET / HTTP/1.1\r\n" +
                "Host: example.com\r\n" +
                "X-Forwarded-Host: attacker.com\r\n\r\n"
        val xfhStart = raw.indexOf("X-Forwarded-Host:")
        val xfhEnd = xfhStart + "X-Forwarded-Host: attacker.com".length

        val header = mock<HttpHeader>()
        whenever(header.name()).thenReturn("X-Forwarded-Host")
        whenever(header.value()).thenReturn("attacker.com")

        val rawBa = byteArrayMock(raw)
        val request = mock<HttpRequest>()
        whenever(request.parameters()).thenReturn(emptyList())
        whenever(request.headers()).thenReturn(listOf(header))
        whenever(request.toByteArray()).thenReturn(rawBa)
        whenever(request.bodyOffset()).thenReturn(raw.length)
        whenever(request.bodyToString()).thenReturn("")
        whenever(request.headerValue("Content-Type")).thenReturn(null)
        whenever(request.url()).thenReturn("http://example.com/")

        val match =
            InjectionPointExtractor.matchInsertionPoint(
                request = request,
                selectionStart = xfhStart + 5,
                selectionEnd = xfhEnd,
            )
        assertTrue(match != null)
        assertEquals(InjectionType.HEADER, match!!.type)
        assertEquals("X-Forwarded-Host", match.name)
    }

    @Test
    fun matchInsertionPointRespectsNonEmptyHeaderAllowlist() {
        val raw =
            "GET / HTTP/1.1\r\n" +
                "Host: example.com\r\n" +
                "X-Forwarded-Host: attacker.com\r\n" +
                "\r\n"
        val xfhStart = raw.indexOf("X-Forwarded-Host:")
        val xfhEnd = xfhStart + "X-Forwarded-Host: attacker.com".length

        val header = mock<HttpHeader>()
        whenever(header.name()).thenReturn("X-Forwarded-Host")
        whenever(header.value()).thenReturn("attacker.com")

        val rawBa = byteArrayMock(raw)
        val request = mock<HttpRequest>()
        whenever(request.parameters()).thenReturn(emptyList())
        whenever(request.headers()).thenReturn(listOf(header))
        whenever(request.toByteArray()).thenReturn(rawBa)
        whenever(request.bodyOffset()).thenReturn(raw.length)
        whenever(request.bodyToString()).thenReturn("")
        whenever(request.headerValue("Content-Type")).thenReturn(null)
        whenever(request.url()).thenReturn("http://example.com/")

        val match =
            InjectionPointExtractor.matchInsertionPoint(
                request = request,
                selectionStart = xfhStart + 5,
                selectionEnd = xfhEnd,
                headerAllowlist = setOf("x-foo-only"),
            )
        assertNull(match)
    }

    @Test
    fun matchInsertionPointReturnsNullWhenSelectionMissesEverything() {
        val raw = "GET /static/ HTTP/1.1\r\nHost: example.com\r\n\r\n"

        val rawBa = byteArrayMock(raw)
        val request = mock<HttpRequest>()
        whenever(request.parameters()).thenReturn(emptyList())
        whenever(request.headers()).thenReturn(emptyList())
        whenever(request.toByteArray()).thenReturn(rawBa)
        whenever(request.bodyOffset()).thenReturn(raw.length)
        whenever(request.bodyToString()).thenReturn("")
        whenever(request.headerValue("Content-Type")).thenReturn(null)
        whenever(request.url()).thenReturn("http://example.com/static/")

        val match =
            InjectionPointExtractor.matchInsertionPoint(
                request = request,
                selectionStart = 0,
                selectionEnd = 3,
            )
        assertNull(match)
    }

    private fun byteArrayMock(text: String): burp.api.montoya.core.ByteArray {
        val ba = mock<burp.api.montoya.core.ByteArray>()
        whenever(ba.bytes).thenReturn(text.toByteArray(Charsets.UTF_8))
        return ba
    }

    private fun rangeMock(
        start: Int,
        end: Int,
    ): Range {
        val r = mock<Range>()
        whenever(r.startIndexInclusive()).thenReturn(start)
        whenever(r.endIndexExclusive()).thenReturn(end)
        return r
    }

    @Test
    fun matchInsertionPointPicksJsonFieldWhenSelectionInBody() {
        val headers = "POST /api/user HTTP/1.1\r\nHost: example.com\r\nContent-Type: application/json\r\n\r\n"
        val body = """{"name":"alice","role":"user"}"""
        val raw = headers + body

        val rawBa = byteArrayMock(raw)
        val request = mock<HttpRequest>()
        whenever(request.parameters()).thenReturn(emptyList())
        whenever(request.headers()).thenReturn(emptyList())
        whenever(request.toByteArray()).thenReturn(rawBa)
        whenever(request.bodyOffset()).thenReturn(headers.length)
        whenever(request.bodyToString()).thenReturn(body)
        whenever(request.headerValue("Content-Type")).thenReturn("application/json")
        whenever(request.url()).thenReturn("http://example.com/api/user")

        // Select the literal "alice" inside the body
        val aliceStart = raw.indexOf("alice")
        val match =
            InjectionPointExtractor.matchInsertionPoint(
                request = request,
                selectionStart = aliceStart,
                selectionEnd = aliceStart + "alice".length,
            )
        assertTrue(match != null)
        assertEquals(InjectionType.JSON_FIELD, match!!.type)
        assertEquals("name", match.name)
    }

    @Test
    fun matchInsertionPointPicksXmlElement() {
        val headers = "POST /api HTTP/1.1\r\nHost: example.com\r\nContent-Type: application/xml\r\n\r\n"
        val body = "<order><id>42</id></order>"
        val raw = headers + body

        val rawBa = byteArrayMock(raw)
        val request = mock<HttpRequest>()
        whenever(request.parameters()).thenReturn(emptyList())
        whenever(request.headers()).thenReturn(emptyList())
        whenever(request.toByteArray()).thenReturn(rawBa)
        whenever(request.bodyOffset()).thenReturn(headers.length)
        whenever(request.bodyToString()).thenReturn(body)
        whenever(request.headerValue("Content-Type")).thenReturn("application/xml")
        whenever(request.url()).thenReturn("http://example.com/api")

        val fortyTwoStart = raw.indexOf("42")
        val fortyTwoEnd = fortyTwoStart + "42".length
        val match =
            InjectionPointExtractor.matchInsertionPoint(
                request = request,
                selectionStart = fortyTwoStart,
                selectionEnd = fortyTwoEnd,
            )
        assertTrue(match != null)
        assertEquals(InjectionType.XML_ELEMENT, match!!.type)
        assertEquals("id", match.name)
        assertEquals("42", match.originalValue)
    }

    @Test
    fun matchInsertionPointPicksPathSegment() {
        val raw = "GET /api/users/12345 HTTP/1.1\r\nHost: example.com\r\n\r\n"
        val idStart = raw.indexOf("12345")
        val idEnd = idStart + "12345".length

        val rawBa = byteArrayMock(raw)
        val request = mock<HttpRequest>()
        whenever(request.parameters()).thenReturn(emptyList())
        whenever(request.headers()).thenReturn(emptyList())
        whenever(request.toByteArray()).thenReturn(rawBa)
        whenever(request.bodyOffset()).thenReturn(raw.length)
        whenever(request.bodyToString()).thenReturn("")
        whenever(request.headerValue("Content-Type")).thenReturn(null)
        whenever(request.url()).thenReturn("http://example.com/api/users/12345")

        val match =
            InjectionPointExtractor.matchInsertionPoint(
                request = request,
                selectionStart = idStart,
                selectionEnd = idEnd,
            )
        assertTrue(match != null)
        assertEquals(InjectionType.PATH_SEGMENT, match!!.type)
        assertEquals("12345", match.originalValue)
    }
}
