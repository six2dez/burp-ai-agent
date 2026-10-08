package com.six2dez.burp.aiagent.audit

import burp.api.montoya.MontoyaApi
import com.fasterxml.jackson.databind.MapperFeature
import com.fasterxml.jackson.databind.SerializationFeature
import com.fasterxml.jackson.databind.json.JsonMapper
import com.fasterxml.jackson.module.kotlin.registerKotlinModule
import com.six2dez.burp.aiagent.backends.BackendLaunchConfig
import com.six2dez.burp.aiagent.redact.PrivacyMode
import java.io.File
import java.nio.channels.Channels
import java.nio.charset.StandardCharsets
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream

/**
 * Opt-in JSONL audit trail under [baseDir] (quick 261008-sqa).
 *
 * Bodies (prompt, context, response chunks, error texts, active payloads) are recorded as a digest
 * pair, `<name>Sha256` + `<name>Utf8Bytes`, computed from the same UTF-8 bytes; the body itself is
 * added next to the pair only while [verbose] is on. Credentials are never recorded in either mode:
 * a prompt bundle carries the allowlisted [AuditBackendConfig] only. Nothing is created on disk until
 * an enabled write happens, and every file goes through [PrivateAuditFiles] (owner-only on POSIX).
 */
class AuditLogger(
    private val api: MontoyaApi,
    private val baseDir: File = File(System.getProperty("user.home"), ".burp-ai-agent"),
) {
    companion object {
        @Volatile
        private var globalEmitter: ((String, Any) -> Unit)? = null

        fun registerGlobalEmitter(emitter: ((String, Any) -> Unit)?) {
            globalEmitter = emitter
        }

        fun emitGlobal(
            type: String,
            payload: Any,
        ) {
            globalEmitter?.invoke(type, payload)
        }

        /**
         * The endpoint form of [url] for an audit record: scheme, host, port and path. Userinfo (everything
         * up to the last `@` of the authority, so an `@` or `?` inside a password is removed too), query and
         * fragment are dropped in both audit modes. Null or blank input gives null.
         */
        fun endpointOf(url: String?): String? {
            if (url.isNullOrBlank()) return null
            val trimmed = url.trim()
            val authorityMarker = trimmed.indexOf("//")
            val withoutUserInfo =
                if (authorityMarker < 0) {
                    trimmed
                } else {
                    val authorityStart = authorityMarker + 2
                    val slash = trimmed.indexOf('/', authorityStart)
                    val authorityEnd = if (slash < 0) trimmed.length else slash
                    val at = trimmed.lastIndexOf('@', authorityEnd - 1)
                    if (at >= authorityStart) trimmed.substring(0, authorityStart) + trimmed.substring(at + 1) else trimmed
                }
            val cut = withoutUserInfo.indexOfAny(charArrayOf('?', '#'))
            val endpoint = if (cut < 0) withoutUserInfo else withoutUserInfo.substring(0, cut)
            return endpoint.trim().ifBlank { null }
        }
    }

    // Starts off: App applies the saved setting before anything is emitted.
    @Volatile
    private var enabled: Boolean = false

    /** Verbose audit: adds the bodies next to their digest pairs. Never adds a credential. */
    @Volatile
    var verbose: Boolean = false

    private val mapper =
        JsonMapper
            .builder()
            .enable(MapperFeature.SORT_PROPERTIES_ALPHABETICALLY)
            .enable(SerializationFeature.ORDER_MAP_ENTRIES_BY_KEYS)
            .build()
            .registerKotlinModule()
    private val logFile: File = File(baseDir, "audit.jsonl")
    private val bundleDir: File = File(baseDir, "bundles")
    private val contextDir: File = File(baseDir, "contexts")
    private val writeLock = Any()

    fun setEnabled(value: Boolean) {
        enabled = value
    }

    fun isEnabled(): Boolean = enabled

    fun logEvent(
        type: String,
        payload: Any,
    ) {
        if (!enabled) return
        try {
            val payloadJson = mapper.writeValueAsString(payload)
            val record =
                mapOf(
                    "ts" to System.currentTimeMillis(),
                    "type" to type,
                    "payload" to payload,
                    "payloadSha256" to Hashing.sha256Hex(payloadJson),
                )
            val line = (mapper.writeValueAsString(record) + "\n").toByteArray(StandardCharsets.UTF_8)
            synchronized(writeLock) {
                PrivateAuditFiles.ensureDirectory(baseDir.toPath(), ownedByAudit = false)
                PrivateAuditFiles.append(logFile.toPath(), line)
            }
        } catch (e: Exception) {
            api.logging().logToError("Audit log failed: ${e.message}")
        }
    }

    /**
     * The digest pair of [value] (`<name>Sha256` + `<name>Utf8Bytes`, from the same UTF-8 bytes), plus
     * `<name>` -> [value] while [verbose] is on. Empty for a null value.
     */
    fun bodyFields(
        name: String,
        value: String?,
    ): Map<String, Any> {
        if (value == null) return emptyMap()
        val bytes = value.toByteArray(StandardCharsets.UTF_8)
        val digest = mapOf<String, Any>("${name}Sha256" to Hashing.sha256Hex(bytes), "${name}Utf8Bytes" to bytes.size)
        return if (verbose) digest + (name to value) else digest
    }

    /** `errorClass` (the exception's simple name) plus [bodyFields] of its message. Empty for null. */
    fun errorFields(err: Throwable?): Map<String, Any> =
        if (err == null) {
            emptyMap()
        } else {
            mapOf<String, Any>("errorClass" to err.javaClass.simpleName) + bodyFields("error", err.message)
        }

    fun buildPromptBundle(
        sessionId: String,
        backendId: String,
        backendConfig: BackendLaunchConfig,
        promptText: String,
        contextJson: String?,
        privacyMode: PrivacyMode,
        determinismMode: Boolean,
        promptSource: String? = null,
        promptId: String? = null,
        promptTitle: String? = null,
        contextKind: String? = null,
    ): PromptBundle {
        val verboseNow = verbose
        val promptBytes = promptText.toByteArray(StandardCharsets.UTF_8)
        val contextBytes = contextJson?.toByteArray(StandardCharsets.UTF_8)
        return PromptBundle(
            createdAtEpochMs = System.currentTimeMillis(),
            sessionId = sessionId,
            backendId = backendId,
            backendConfig = AuditBackendConfig.from(backendConfig),
            verbose = verboseNow,
            promptText = promptText.takeIf { verboseNow },
            promptSha256 = Hashing.sha256Hex(promptBytes),
            promptUtf8Bytes = promptBytes.size,
            contextJson = contextJson?.takeIf { verboseNow },
            contextSha256 = contextBytes?.let { Hashing.sha256Hex(it) },
            contextUtf8Bytes = contextBytes?.size,
            privacyMode = privacyMode.name,
            determinismMode = determinismMode,
            promptSource = promptSource,
            promptId = promptId,
            promptTitle = promptTitle,
            contextKind = contextKind,
        )
    }

    /** Writes [bundle] to bundles/; never throws into the send path (a failure is logged and skipped). */
    fun writePromptBundle(bundle: PromptBundle): File {
        if (!enabled) return File(bundleDir, "bundle-disabled.json")
        val file = File(bundleDir, "bundle-${bundle.sessionId}-${bundle.promptSha256.take(8)}.json")
        try {
            val bytes = mapper.writeValueAsBytes(bundle)
            synchronized(writeLock) {
                PrivateAuditFiles.ensureDirectory(bundleDir.toPath(), ownedByAudit = true)
                PrivateAuditFiles.replace(file.toPath(), bytes)
            }
        } catch (e: Exception) {
            api.logging().logToError("Audit bundle write failed: ${e.message}")
        }
        return file
    }

    data class ContextFile(
        val file: File,
        val sha256: String,
    )

    /** Writes the context body only when audit logging AND verbose audit are on; otherwise no I/O. */
    fun writeContextFile(
        sessionId: String,
        contextJson: String,
    ): ContextFile {
        val sha = Hashing.sha256Hex(contextJson)
        val file = File(contextDir, "context-$sessionId-${sha.take(8)}.json")
        if (enabled && verbose) {
            synchronized(writeLock) {
                PrivateAuditFiles.ensureDirectory(contextDir.toPath(), ownedByAudit = true)
                PrivateAuditFiles.replace(file.toPath(), contextJson.toByteArray(StandardCharsets.UTF_8))
            }
        }
        return ContextFile(file = file, sha256 = sha)
    }

    /** Zips [bundle]; `context.json` is present only when the bundle was built verbose. */
    fun exportPromptBundleZip(bundle: PromptBundle): File {
        if (!enabled) return File(bundleDir, "bundle-disabled.zip")
        val zipFile = File(bundleDir, "bundle-${bundle.sessionId}-${bundle.promptSha256.take(8)}.zip")
        synchronized(writeLock) {
            PrivateAuditFiles.ensureDirectory(bundleDir.toPath(), ownedByAudit = true)
            PrivateAuditFiles.openForReplace(zipFile.toPath()).use { channel ->
                ZipOutputStream(Channels.newOutputStream(channel)).use { zip ->
                    zip.putNextEntry(ZipEntry("bundle.json"))
                    zip.write(mapper.writeValueAsBytes(bundle))
                    zip.closeEntry()
                    if (bundle.contextJson != null) {
                        zip.putNextEntry(ZipEntry("context.json"))
                        zip.write(bundle.contextJson.toByteArray(StandardCharsets.UTF_8))
                        zip.closeEntry()
                    }
                }
            }
        }
        return zipFile
    }
}
