package com.six2dez.burp.aiagent.mcp

import burp.api.montoya.MontoyaApi
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Test
import org.mockito.kotlin.mock
import java.lang.reflect.Method
import java.net.URL
import java.net.URLConnection
import java.net.URLStreamHandler
import java.security.Principal
import java.security.cert.Certificate
import javax.net.ssl.HostnameVerifier
import javax.net.ssl.HttpsURLConnection
import javax.net.ssl.SSLSocketFactory

@Suppress("DEPRECATION")
class McpSupervisorConnectionTest {
    private val supervisor = McpSupervisor(mock<MontoyaApi>())

    @Test
    fun openConnection_loopbackTls_setsCustomTrustAndHostnameVerifier() {
        val url = URL(null, "https://localhost:8443/test", connectionHandler())
        val connection = invokeOpenConnection(url, tlsEnabled = true) as FakeHttpsURLConnection

        assertNotNull(connection.assignedSslSocketFactory)
        assertNotNull(connection.assignedHostnameVerifier)
    }

    @Test
    fun openConnection_nonLoopbackTls_doesNotOverrideTlsVerifier() {
        val url = URL(null, "https://example.com:8443/test", connectionHandler())
        val connection = invokeOpenConnection(url, tlsEnabled = true) as FakeHttpsURLConnection

        assertNull(connection.assignedSslSocketFactory)
        assertNull(connection.assignedHostnameVerifier)
    }

    @Test
    fun openConnection_loopbackWithoutTls_doesNotOverrideTlsVerifier() {
        val url = URL(null, "https://localhost:8443/test", connectionHandler())
        val connection = invokeOpenConnection(url, tlsEnabled = false) as FakeHttpsURLConnection

        assertNull(connection.assignedSslSocketFactory)
        assertNull(connection.assignedHostnameVerifier)
    }

    private fun invokeOpenConnection(
        url: URL,
        tlsEnabled: Boolean,
    ): URLConnection {
        val method: Method =
            supervisor.javaClass.getDeclaredMethod(
                "openConnection",
                URL::class.java,
                Boolean::class.javaPrimitiveType,
            )
        method.isAccessible = true
        return method.invoke(supervisor, url, tlsEnabled) as URLConnection
    }

    private fun connectionHandler(): URLStreamHandler =
        object : URLStreamHandler() {
            override fun openConnection(url: URL): URLConnection = FakeHttpsURLConnection(url)
        }

    private class FakeHttpsURLConnection(
        url: URL,
    ) : HttpsURLConnection(url) {
        var assignedSslSocketFactory: SSLSocketFactory? = null
        var assignedHostnameVerifier: HostnameVerifier? = null

        override fun connect() = Unit

        override fun disconnect() = Unit

        override fun usingProxy(): Boolean = false

        override fun setSSLSocketFactory(sf: SSLSocketFactory?) {
            assignedSslSocketFactory = sf
        }

        override fun getSSLSocketFactory(): SSLSocketFactory? = assignedSslSocketFactory

        override fun setHostnameVerifier(v: HostnameVerifier?) {
            assignedHostnameVerifier = v
        }

        override fun getHostnameVerifier(): HostnameVerifier? = assignedHostnameVerifier

        override fun getCipherSuite(): String = "TLS_FAKE"

        override fun getLocalCertificates(): Array<Certificate>? = null

        override fun getServerCertificates(): Array<Certificate>? = null

        override fun getPeerPrincipal(): Principal? = null

        override fun getLocalPrincipal(): Principal? = null
    }
}
