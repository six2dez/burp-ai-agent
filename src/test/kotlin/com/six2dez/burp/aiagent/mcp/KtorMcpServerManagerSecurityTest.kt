package com.six2dez.burp.aiagent.mcp

import burp.api.montoya.MontoyaApi
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.mockito.kotlin.mock
import java.lang.reflect.Method

class KtorMcpServerManagerSecurityTest {
    private val manager = KtorMcpServerManager(mock<MontoyaApi>())

    @Test
    fun isAuthorized_acceptsOnlyExactBearerToken() {
        assertTrue(invokeBoolean("isAuthorized", "Bearer token-123", "token-123"))
        assertFalse(invokeBoolean("isAuthorized", "", "token-123"))
        assertFalse(invokeBoolean("isAuthorized", "Bearer wrong", "token-123"))
        assertFalse(invokeBoolean("isAuthorized", "bearer token-123", "token-123"))
    }

    @Test
    fun constantTimeEquals_handlesEqualAndDifferentLengths() {
        assertTrue(invokeBoolean("constantTimeEquals", "abc123", "abc123"))
        assertFalse(invokeBoolean("constantTimeEquals", "abc123", "abc124"))
        assertFalse(invokeBoolean("constantTimeEquals", "short", "much-longer-value"))
    }

    @Test
    fun parseExternalCorsHosts_normalizes_filters_and_deduplicatesOrigins() {
        val hosts =
            invokeCorsHosts(
                listOf(
                    "https://Example.com",
                    "http://example.com:8443/path",
                    "://broken-origin",
                    "https://example.com",
                ),
            )

        assertEquals(2, hosts.size)
        val rendered = hosts.joinToString("\n") { it.toString() }
        assertTrue(rendered.contains("hostAndPort=example.com"))
        assertTrue(rendered.contains("scheme=https"))
        assertTrue(rendered.contains("hostAndPort=example.com:8443"))
        assertTrue(rendered.contains("scheme=http"))
    }

    private fun invokeBoolean(
        methodName: String,
        vararg args: String,
    ): Boolean {
        val method: Method =
            manager.javaClass.getDeclaredMethod(
                methodName,
                String::class.java,
                String::class.java,
            )
        method.isAccessible = true
        return method.invoke(manager, args[0], args[1]) as Boolean
    }

    private fun invokeCorsHosts(origins: List<String>): List<Any> {
        val method = manager.javaClass.getDeclaredMethod("parseExternalCorsHosts", List::class.java)
        method.isAccessible = true
        @Suppress("UNCHECKED_CAST")
        return method.invoke(manager, origins) as List<Any>
    }
}
