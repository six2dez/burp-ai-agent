package com.six2dez.burp.aiagent.mcp

import com.six2dez.burp.aiagent.config.McpSettings
import java.io.File
import java.security.KeyStore

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

        val keyStore = KeyStore.getInstance("PKCS12")
        keystoreFile.inputStream().use { input ->
            keyStore.load(input, password)
        }

        val alias = keyStore.aliases().toList().firstOrNull() ?: "mcp"
        return McpTlsMaterial(keyStore = keyStore, password = password, keyAlias = alias)
    }

    private fun generateSelfSigned(keystoreFile: File, password: CharArray) {
        keystoreFile.parentFile?.mkdirs()
        val passStr = String(password)

        // Use keytool from the running JDK - available in all JDK versions
        val keytoolPath = findKeytool()
        val process = ProcessBuilder(
            keytoolPath,
            "-genkeypair",
            "-alias", "mcp",
            "-keyalg", "RSA",
            "-keysize", "2048",
            "-validity", "365",
            "-storetype", "PKCS12",
            "-keystore", keystoreFile.absolutePath,
            "-storepass", passStr,
            "-keypass", passStr,
            "-dname", "CN=burp-mcp",
            "-sigalg", "SHA256withRSA"
        ).redirectErrorStream(true).start()

        val output = process.inputStream.bufferedReader().readText()
        val exitCode = process.waitFor()
        if (exitCode != 0) {
            throw RuntimeException("keytool failed (exit $exitCode): $output")
        }
    }

    private fun findKeytool(): String {
        val javaHome = System.getProperty("java.home")
        val keytool = File(javaHome, "bin/keytool")
        if (keytool.exists()) return keytool.absolutePath
        // Windows
        val keytoolExe = File(javaHome, "bin/keytool.exe")
        if (keytoolExe.exists()) return keytoolExe.absolutePath
        // Fallback to PATH
        return "keytool"
    }
}
