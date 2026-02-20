package com.six2dez.burp.aiagent.audit

import burp.api.montoya.MontoyaApi
import com.fasterxml.jackson.databind.MapperFeature
import com.fasterxml.jackson.databind.SerializationFeature
import com.fasterxml.jackson.databind.json.JsonMapper
import com.fasterxml.jackson.module.kotlin.registerKotlinModule
import com.six2dez.burp.aiagent.backends.BackendLaunchConfig
import com.six2dez.burp.aiagent.redact.PrivacyMode
import java.io.File
import java.nio.charset.StandardCharsets
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream

class AuditLogger(private val api: MontoyaApi) {
    @Volatile
    private var enabled: Boolean = false
    private val mapper = JsonMapper.builder()
        .enable(MapperFeature.SORT_PROPERTIES_ALPHABETICALLY)
        .enable(SerializationFeature.ORDER_MAP_ENTRIES_BY_KEYS)
        .build()
        .registerKotlinModule()
    private val baseDir: File = File(System.getProperty("user.home"), ".burp-ai-agent").also { it.mkdirs() }
    private val logFile: File = File(baseDir, "audit.jsonl")
    private val bundleDir: File = File(baseDir, "bundles").also { it.mkdirs() }
    private val contextDir: File = File(baseDir, "contexts").also { it.mkdirs() }

    fun setEnabled(value: Boolean) {
        enabled = value
    }

    fun isEnabled(): Boolean = enabled

    fun logEvent(type: String, payload: Any) {
        if (!enabled) return
        try {
            val payloadJson = mapper.writeValueAsString(payload)
            val record = mapOf(
                "ts" to System.currentTimeMillis(),
                "type" to type,
                "payload" to payload,
                "payloadSha256" to Hashing.sha256Hex(payloadJson)
            )
            logFile.appendText(mapper.writeValueAsString(record) + "\n")
        } catch (e: Exception) {
            api.logging().logToError("Audit log failed: ${e.message}")
        }
    }

    fun buildPromptBundle(
        sessionId: String,
        backendId: String,
        backendConfig: BackendLaunchConfig,
        promptText: String,
        contextJson: String?,
        privacyMode: PrivacyMode,
        determinismMode: Boolean
    ): PromptBundle {
        val sha = Hashing.sha256Hex(promptText)
        val contextSha = contextJson?.let { Hashing.sha256Hex(it) }
        val safeConfig = backendConfig.copy(headers = redactHeaders(backendConfig.headers))
        return PromptBundle(
            createdAtEpochMs = System.currentTimeMillis(),
            sessionId = sessionId,
            backendId = backendId,
            backendConfig = safeConfig,
            promptText = promptText,
            promptSha256 = sha,
            contextJson = contextJson,
            contextSha256 = contextSha,
            privacyMode = privacyMode.name,
            determinismMode = determinismMode
        )
    }

    private fun redactHeaders(headers: Map<String, String>): Map<String, String> {
        if (headers.isEmpty()) return headers
        return headers.mapValues { (name, value) ->
            val lower = name.lowercase()
            if (lower == "authorization" || lower.contains("api-key") || lower.contains("token")) {
                "REDACTED"
            } else {
                value
            }
        }
    }

    fun writePromptBundle(bundle: PromptBundle): File {
        if (!enabled) return File(bundleDir, "bundle-disabled.json")
        val file = File(bundleDir, "bundle-${bundle.sessionId}-${bundle.promptSha256.take(8)}.json")
        file.writeText(mapper.writeValueAsString(bundle))
        return file
    }

    data class ContextFile(val file: File, val sha256: String)

    fun writeContextFile(sessionId: String, contextJson: String): ContextFile {
        val sha = Hashing.sha256Hex(contextJson)
        val file = File(contextDir, "context-$sessionId-${sha.take(8)}.json")
        file.writeText(contextJson)
        return ContextFile(file = file, sha256 = sha)
    }

    fun exportPromptBundleZip(bundle: PromptBundle): File {
        if (!enabled) return File(bundleDir, "bundle-disabled.zip")
        val zipFile = File(bundleDir, "bundle-${bundle.sessionId}-${bundle.promptSha256.take(8)}.zip")
        ZipOutputStream(zipFile.outputStream()).use { zip ->
            zip.putNextEntry(ZipEntry("bundle.json"))
            zip.write(mapper.writeValueAsBytes(bundle))
            zip.closeEntry()
            if (bundle.contextJson != null) {
                zip.putNextEntry(ZipEntry("context.json"))
                zip.write(bundle.contextJson.toByteArray(StandardCharsets.UTF_8))
                zip.closeEntry()
            }
        }
        return zipFile
    }
}
