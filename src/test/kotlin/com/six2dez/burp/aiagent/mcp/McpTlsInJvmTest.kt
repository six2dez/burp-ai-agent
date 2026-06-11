package com.six2dez.burp.aiagent.mcp

import com.six2dez.burp.aiagent.TestSettings
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import java.io.File
import java.nio.file.Files
import java.security.KeyStore
import java.security.cert.X509Certificate
import java.util.Date

/**
 * Verifies the SEC-02 / A3 fix: the keytool keystore password is passed via the child-process
 * environment (KS_PASS) using -storepass:env / -keypass:env, never as a literal argv token.
 */
class McpTlsInJvmTest {
    private fun mcpTlsSource(): String {
        val root = System.getProperty("user.dir")
        return File(root, "src/main/kotlin/com/six2dez/burp/aiagent/mcp/McpTls.kt").readText()
    }

    @Test
    fun generateSelfSigned_writesKeystoreFile() {
        val dir = Files.createTempDirectory("mcp-tls-test").toFile()
        val ks = File(dir, "ks.p12")
        invokeGenerate(ks, "testpass".toCharArray())
        assertTrue(ks.exists(), "keystore file must be created")
    }

    @Test
    fun generatedKeystore_loadsBackWithCorrectPassword() {
        val dir = Files.createTempDirectory("mcp-tls-test").toFile()
        val ks = File(dir, "ks.p12")
        invokeGenerate(ks, "testpass".toCharArray())

        val keyStore = KeyStore.getInstance("PKCS12")
        ks.inputStream().use { keyStore.load(it, "testpass".toCharArray()) }
        assertTrue(keyStore.aliases().toList().isNotEmpty(), "loaded keystore must contain an alias")
    }

    @Test
    fun generatedCertificate_isBurpMcpRsa() {
        val dir = Files.createTempDirectory("mcp-tls-test").toFile()
        val ks = File(dir, "ks.p12")
        invokeGenerate(ks, "testpass".toCharArray())

        val keyStore = KeyStore.getInstance("PKCS12")
        ks.inputStream().use { keyStore.load(it, "testpass".toCharArray()) }
        val alias = keyStore.aliases().toList().first()
        val cert = keyStore.getCertificate(alias) as X509Certificate
        assertTrue(cert.subjectX500Principal.name.contains("burp-mcp"), "subject must contain burp-mcp")
        assertTrue(cert.publicKey.algorithm == "RSA", "key algorithm must be RSA")
    }

    @Test
    fun generatedCertificate_validityAtLeast364Days() {
        val dir = Files.createTempDirectory("mcp-tls-test").toFile()
        val ks = File(dir, "ks.p12")
        invokeGenerate(ks, "testpass".toCharArray())

        val keyStore = KeyStore.getInstance("PKCS12")
        ks.inputStream().use { keyStore.load(it, "testpass".toCharArray()) }
        val alias = keyStore.aliases().toList().first()
        val cert = keyStore.getCertificate(alias) as X509Certificate
        val now = Date()
        assertTrue(cert.notBefore <= now, "notBefore must be at or before now")
        val plus364 = Date(now.time + 364L * 24 * 60 * 60 * 1000)
        assertTrue(cert.notAfter >= plus364, "notAfter must be >= now + 364 days")
    }

    @Test
    fun source_usesEnvPasswordNotLiteralArgv() {
        val src = mcpTlsSource()
        assertFalse(
            src.contains("\"-storepass\",\n                passStr") || src.contains("\"-storepass\", passStr"),
            "no literal -storepass passStr argv",
        )
        assertFalse(
            src.contains("\"-keypass\",\n                passStr") || src.contains("\"-keypass\", passStr"),
            "no literal -keypass passStr argv",
        )
        assertTrue(src.contains("storepass:env"), "must use -storepass:env")
        assertTrue(src.contains("keypass:env"), "must use -keypass:env")
    }

    @Test
    fun source_referencesKsPassEnvVar() {
        assertTrue(mcpTlsSource().contains("KS_PASS"), "must reference the KS_PASS env var name")
    }

    @Test
    fun resolve_autoGeneratesWhenKeystoreMissing() {
        val dir = Files.createTempDirectory("mcp-tls-resolve").toFile()
        val ks = File(dir, "auto.p12")
        val settings =
            TestSettings.baselineSettings().mcpSettings.copy(
                tlsKeystorePath = ks.absolutePath,
                tlsKeystorePassword = "auto-pass",
                tlsAutoGenerate = true,
            )
        val material = McpTls.resolve(settings)
        assertNotNull(material, "resolve must return non-null material when auto-generating")
        assertTrue(ks.exists(), "resolve must have generated the keystore file")
    }

    /** Invokes the private generateSelfSigned via resolve() (which calls it when the file is absent). */
    private fun invokeGenerate(
        keystoreFile: File,
        password: CharArray,
    ) {
        val settings =
            TestSettings.baselineSettings().mcpSettings.copy(
                tlsKeystorePath = keystoreFile.absolutePath,
                tlsKeystorePassword = String(password),
                tlsAutoGenerate = true,
            )
        McpTls.resolve(settings)
    }
}
