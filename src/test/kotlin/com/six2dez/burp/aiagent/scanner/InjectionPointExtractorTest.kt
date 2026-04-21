package com.six2dez.burp.aiagent.scanner

import burp.api.montoya.http.message.HttpHeader
import burp.api.montoya.http.message.params.HttpParameterType
import burp.api.montoya.http.message.params.ParsedHttpParameter
import burp.api.montoya.http.message.requests.HttpRequest
import org.mockito.kotlin.mock
import org.mockito.kotlin.whenever
import kotlin.test.Test
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
}
