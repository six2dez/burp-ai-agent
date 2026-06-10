package com.six2dez.burp.aiagent.mcp

import com.six2dez.burp.aiagent.config.McpSettings
import java.io.File
import java.security.KeyStore

data class McpTlsMaterial(
    val keyStore: KeyStore,
    val password: CharArray,
    val keyAlias: String,
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

    private fun generateSelfSigned(
        keystoreFile: File,
        password: CharArray,
    ) {
        keystoreFile.parentFile?.mkdirs()
        // IN-01: keep a local copy of the password array and zero it in a finally block.
        // Do NOT zero the caller's array — resolve() still needs it to load the keystore after
        // this function returns. The String materialisation (passStr) is unavoidable for
        // ProcessBuilder.environment(), but its lifetime is bounded to this call frame.
        val localPassword = password.copyOf()
        val passStr = String(localPassword)
        try {
            // Use keytool from the running JDK - available in all JDK versions.
            // SEC-02 / A3: pass the keystore password via the child-process environment (KS_PASS)
            // using -storepass:env / -keypass:env instead of a literal argv token, so the password
            // is never visible in a `ps aux` process listing.
            val keytoolPath = findKeytool()
            val process =
                ProcessBuilder(
                    keytoolPath,
                    "-genkeypair",
                    "-alias",
                    "mcp",
                    "-keyalg",
                    "RSA",
                    "-keysize",
                    "2048",
                    "-validity",
                    "365",
                    "-storetype",
                    "PKCS12",
                    "-keystore",
                    keystoreFile.absolutePath,
                    "-storepass:env",
                    "KS_PASS",
                    "-keypass:env",
                    "KS_PASS",
                    "-dname",
                    "CN=burp-mcp",
                    "-sigalg",
                    "SHA256withRSA",
                ).redirectErrorStream(true)
                    .also { it.environment()["KS_PASS"] = passStr }
                    .start()

            val output = process.inputStream.bufferedReader().readText()
            val exitCode = process.waitFor()
            if (exitCode != 0) {
                throw RuntimeException("keytool failed (exit $exitCode): $output")
            }
        } finally {
            // Defense-in-depth: zero the local copy so it does not linger on the heap. The String
            // copy (passStr) is immutable and cannot be zeroed, but its lifetime is bounded to
            // this call frame and it will be eligible for GC as soon as this method returns.
            localPassword.fill(' ')
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
