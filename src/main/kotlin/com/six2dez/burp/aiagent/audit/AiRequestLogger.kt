package com.six2dez.burp.aiagent.audit

import com.fasterxml.jackson.databind.ObjectMapper
import com.six2dez.burp.aiagent.backends.TokenUsage
import java.nio.charset.StandardCharsets
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.StandardCopyOption
import java.nio.file.StandardOpenOption
import java.util.concurrent.ConcurrentLinkedDeque
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.atomic.AtomicLong

/**
 * Type of AI activity being logged.
 */
enum class ActivityType {
    PROMPT_SENT,
    RESPONSE_COMPLETE,
    MCP_TOOL_CALL,
    RETRY,
    ERROR,
    SCANNER_SEND
}

/**
 * A single entry in the AI request log.
 */
data class AiActivityEntry(
    val id: Long,
    val timestamp: Long,
    val type: ActivityType,
    val source: String,
    val backendId: String,
    val sessionId: String? = null,
    val detail: String,
    val durationMs: Long? = null,
    val promptChars: Int? = null,
    val responseChars: Int? = null,
    val tokenUsage: TokenUsage? = null,
    val metadata: Map<String, String> = emptyMap()
)

data class RollingLogConfig(
    val directory: Path,
    val baseFileName: String = "ai-request-log",
    val maxFileBytes: Long = AiRequestLogger.DEFAULT_ROLLING_MAX_FILE_BYTES,
    val maxFiles: Int = AiRequestLogger.DEFAULT_ROLLING_MAX_FILES
) {
    fun normalized(): RollingLogConfig = copy(
        maxFileBytes = maxFileBytes.coerceAtLeast(AiRequestLogger.MIN_ROLLING_FILE_BYTES),
        maxFiles = maxFiles.coerceIn(1, AiRequestLogger.MAX_ROLLING_FILES)
    )

    fun activeFile(): Path = directory.resolve("$baseFileName.jsonl")

    fun rolledFile(index: Int): Path = directory.resolve("$baseFileName.$index.jsonl")
}

/**
 * Thread-safe AI request logger with bounded circular buffer.
 *
 * Records all AI interactions (prompts, responses, MCP tool calls, retries, errors,
 * scanner sends) in a fixed-size buffer. Oldest entries are evicted when the limit
 * is reached. Listeners are notified asynchronously on each new entry.
 */
class AiRequestLogger(
    @Volatile var maxEntries: Int = DEFAULT_MAX_ENTRIES
) {
    private val buffer = ConcurrentLinkedDeque<AiActivityEntry>()
    private val idCounter = AtomicLong(0)
    private val listeners = CopyOnWriteArrayList<(AiActivityEntry) -> Unit>()
    private val objectMapper = ObjectMapper()
    private val persistenceLock = Any()

    @Volatile
    private var rollingLogConfig: RollingLogConfig? = null

    @Volatile
    var enabled: Boolean = true

    fun configureRollingPersistence(config: RollingLogConfig?) {
        rollingLogConfig = config?.normalized()
    }

    fun rollingPersistenceConfig(): RollingLogConfig? = rollingLogConfig

    /**
     * Log a new activity entry.
     */
    fun log(
        type: ActivityType,
        source: String,
        backendId: String,
        detail: String,
        sessionId: String? = null,
        durationMs: Long? = null,
        promptChars: Int? = null,
        responseChars: Int? = null,
        tokenUsage: TokenUsage? = null,
        metadata: Map<String, String> = emptyMap()
    ) {
        if (!enabled) return

        val entry = AiActivityEntry(
            id = idCounter.incrementAndGet(),
            timestamp = System.currentTimeMillis(),
            type = type,
            source = source,
            backendId = backendId,
            sessionId = sessionId,
            detail = detail,
            durationMs = durationMs,
            promptChars = promptChars,
            responseChars = responseChars,
            tokenUsage = tokenUsage,
            metadata = metadata
        )

        buffer.addLast(entry)
        trim()
        persistIfConfigured(entry)

        for (listener in listeners) {
            try {
                listener(entry)
            } catch (_: Exception) {
                // Never let a listener failure break the logger
            }
        }
    }

    /**
     * Get all current entries (newest last).
     */
    fun entries(): List<AiActivityEntry> = buffer.toList()

    /**
     * Get entries filtered by type.
     */
    fun entries(type: ActivityType): List<AiActivityEntry> =
        buffer.filter { it.type == type }

    /**
     * Get entries filtered by source.
     */
    fun entriesBySource(source: String): List<AiActivityEntry> =
        buffer.filter { it.source == source }

    /**
     * Current number of entries.
     */
    fun size(): Int = buffer.size

    /**
     * Clear all entries.
     */
    fun clear() {
        buffer.clear()
    }

    /**
     * Register a listener that will be notified on each new entry.
     */
    fun addListener(listener: (AiActivityEntry) -> Unit) {
        listeners.add(listener)
    }

    /**
     * Remove a previously registered listener.
     */
    fun removeListener(listener: (AiActivityEntry) -> Unit) {
        listeners.remove(listener)
    }

    /**
     * Export all entries as a list of maps suitable for JSON serialization.
     */
    fun exportAsMapList(): List<Map<String, Any?>> {
        return entries().map(::entryToMap)
    }

    fun shutdown() {
        listeners.clear()
    }

    private fun trim() {
        val max = maxEntries.coerceAtLeast(MIN_ENTRIES)
        while (buffer.size > max) {
            buffer.pollFirst()
        }
    }

    private fun entryToMap(entry: AiActivityEntry): Map<String, Any?> {
        val map = mutableMapOf<String, Any?>(
            "id" to entry.id,
            "timestamp" to entry.timestamp,
            "type" to entry.type.name,
            "source" to entry.source,
            "backendId" to entry.backendId,
            "sessionId" to entry.sessionId,
            "detail" to entry.detail,
            "durationMs" to entry.durationMs,
            "promptChars" to entry.promptChars,
            "responseChars" to entry.responseChars
        )
        if (entry.tokenUsage != null) {
            map["inputTokens"] = entry.tokenUsage.inputTokens
            map["outputTokens"] = entry.tokenUsage.outputTokens
        }
        if (entry.metadata.isNotEmpty()) {
            map["metadata"] = entry.metadata
        }
        return map
    }

    private fun persistIfConfigured(entry: AiActivityEntry) {
        val config = rollingLogConfig ?: return
        try {
            val jsonLine = objectMapper.writeValueAsString(entryToMap(entry)) + "\n"
            val bytes = jsonLine.toByteArray(StandardCharsets.UTF_8)
            synchronized(persistenceLock) {
                Files.createDirectories(config.directory)
                rotateIfNeeded(config, bytes.size.toLong())
                Files.write(
                    config.activeFile(),
                    bytes,
                    StandardOpenOption.CREATE,
                    StandardOpenOption.APPEND
                )
            }
        } catch (_: Exception) {
            // Logging persistence must never break request flow.
        }
    }

    private fun rotateIfNeeded(config: RollingLogConfig, incomingBytes: Long) {
        val activeFile = config.activeFile()
        val currentSize = if (Files.exists(activeFile)) Files.size(activeFile) else 0L
        if (currentSize + incomingBytes <= config.maxFileBytes) return

        val oldest = config.rolledFile(config.maxFiles)
        if (Files.exists(oldest)) {
            Files.delete(oldest)
        }

        for (index in (config.maxFiles - 1) downTo 1) {
            val from = config.rolledFile(index)
            if (!Files.exists(from)) continue
            val to = config.rolledFile(index + 1)
            Files.move(from, to, StandardCopyOption.REPLACE_EXISTING)
        }

        if (Files.exists(activeFile)) {
            Files.move(activeFile, config.rolledFile(1), StandardCopyOption.REPLACE_EXISTING)
        }
    }

    companion object {
        const val DEFAULT_MAX_ENTRIES = 500
        private const val MIN_ENTRIES = 10
        const val DEFAULT_ROLLING_MAX_FILE_BYTES = 1_048_576L
        const val DEFAULT_ROLLING_MAX_FILES = 5
        const val MIN_ROLLING_FILE_BYTES = 10_240L
        const val MAX_ROLLING_FILES = 20
    }
}
