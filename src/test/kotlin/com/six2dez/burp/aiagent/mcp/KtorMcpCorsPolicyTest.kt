package com.six2dez.burp.aiagent.mcp

import burp.api.montoya.MontoyaApi
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.mockito.kotlin.mock

class KtorMcpCorsPolicyTest {
    private val manager = KtorMcpServerManager(mock<MontoyaApi>())

    @Test
    fun parseExternalCorsHosts_returnsEmptyForBlankInput() {
        val hosts = invokeCorsHosts(emptyList())
        assertTrue(hosts.isEmpty())
    }

    @Test
    fun parseExternalCorsHosts_acceptsHostWithoutSchemeAsHttps() {
        val hosts = invokeCorsHosts(listOf("portal.example.com:8443"))

        assertEquals(1, hosts.size)
        val rendered = hosts.first().toString()
        assertTrue(rendered.contains("hostAndPort=portal.example.com:8443"))
        assertTrue(rendered.contains("scheme=https"))
    }

    @Test
    fun parseExternalCorsHosts_rejectsUnsupportedScheme() {
        val hosts = invokeCorsHosts(listOf("ftp://portal.example.com"))
        assertTrue(hosts.isEmpty())
    }

    private fun invokeCorsHosts(origins: List<String>): List<Any> {
        val method = manager.javaClass.getDeclaredMethod("parseExternalCorsHosts", List::class.java)
        method.isAccessible = true
        @Suppress("UNCHECKED_CAST")
        return method.invoke(manager, origins) as List<Any>
    }
}
