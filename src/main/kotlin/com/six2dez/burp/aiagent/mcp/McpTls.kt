package com.six2dez.burp.aiagent.mcp

import com.six2dez.burp.aiagent.config.McpSettings
import io.netty.handler.ssl.util.SelfSignedCertificate
import java.io.File
import java.io.FileOutputStream
import java.security.KeyStore
import java.security.cert.X509Certificate

private const val KEY_ALIAS = "mcp"

data class McpTlsMaterial(
    val keyStore: KeyStore,
    val password: CharArray,
    val keyAlias: String
)

object McpTls {
    fun resolve(settings: McpSettings): McpTlsMaterial? {
        val keystorePath = settings.tlsKeystorePath.trim()
        if (keystorePath.isBlank()) return null

        val password = settings.tlsKeystorePassword.toCharArray()
        val keystoreFile = File(keystorePath)

        if (!keystoreFile.exists()) {
            if (!settings.tlsAutoGenerate) return null
            generateSelfSigned(keystoreFile, password)
        }

        var keyStore = KeyStore.getInstance("PKCS12")
        keystoreFile.inputStream().use { input ->
            keyStore.load(input, password)
        }

        // Regenerate if existing cert has wrong CN (e.g. old "burp-mcp" instead of "localhost")
        if (settings.tlsAutoGenerate && needsRegeneration(keyStore)) {
            keystoreFile.delete()
            generateSelfSigned(keystoreFile, password)
            keyStore = KeyStore.getInstance("PKCS12")
            keystoreFile.inputStream().use { input ->
                keyStore.load(input, password)
            }
        }

        val alias = if (keyStore.containsAlias(KEY_ALIAS)) KEY_ALIAS
                    else keyStore.aliases().toList().firstOrNull() ?: KEY_ALIAS
        return McpTlsMaterial(keyStore = keyStore, password = password, keyAlias = alias)
    }

    private fun needsRegeneration(keyStore: KeyStore): Boolean {
        return try {
            val alias = if (keyStore.containsAlias(KEY_ALIAS)) KEY_ALIAS
                        else keyStore.aliases().toList().firstOrNull() ?: return true
            val cert = keyStore.getCertificate(alias) as? X509Certificate ?: return true
            val cn = cert.subjectX500Principal.name
            // Regenerate if CN is the old "burp-mcp" instead of "localhost"
            !cn.contains("CN=localhost", ignoreCase = true)
        } catch (_: Exception) {
            true
        }
    }

    private fun generateSelfSigned(keystoreFile: File, password: CharArray) {
        val parentDir = keystoreFile.parentFile
        if (parentDir != null && !parentDir.exists()) {
            if (!parentDir.mkdirs()) {
                throw IllegalStateException("Failed to create keystore directory: ${parentDir.absolutePath}")
            }
        }
        // Use "localhost" as CN so the certificate matches loopback hostname verification
        val ssc = SelfSignedCertificate("localhost")
        try {
            val keyStore = KeyStore.getInstance("PKCS12")
            keyStore.load(null, password)
            keyStore.setKeyEntry(KEY_ALIAS, ssc.key(), password, arrayOf(ssc.cert()))
            FileOutputStream(keystoreFile).use { out ->
                keyStore.store(out, password)
            }
        } finally {
            cleanupSelfSigned(ssc)
        }
    }

    private fun cleanupSelfSigned(cert: SelfSignedCertificate) {
        try {
            cert.delete()
        } catch (e: Exception) {
            System.err.println("[Burp AI Agent] Failed to cleanup self-signed cert temp files: ${e.message}")
        }
    }
}
