package com.six2dez.burp.aiagent.mcp.tools

import burp.api.montoya.scanner.ScanTask
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicLong
import java.util.concurrent.atomic.AtomicReference

object ScannerTaskRegistry {
    private data class TimedScanTask(
        val task: ScanTask,
        val createdAtMs: Long,
    )

    private val idToTask: MutableMap<String, TimedScanTask> = ConcurrentHashMap()
    private val ttlMs = AtomicLong(TimeUnit.MINUTES.toMillis(DEFAULT_TTL_MINUTES.toLong()))
    private val loggerRef = AtomicReference<(String) -> Unit>({})
    private val cleaner =
        Executors.newSingleThreadScheduledExecutor { runnable ->
            Thread(runnable, "McpScannerTaskRegistryCleaner").apply { isDaemon = true }
        }

    init {
        cleaner.scheduleWithFixedDelay(
            { cleanupExpired() },
            CLEANUP_INTERVAL_MINUTES,
            CLEANUP_INTERVAL_MINUTES,
            TimeUnit.MINUTES,
        )
    }

    fun put(task: ScanTask): String {
        val id = UUID.randomUUID().toString()
        idToTask[id] = TimedScanTask(task = task, createdAtMs = System.currentTimeMillis())
        return id
    }

    fun get(id: String): ScanTask? {
        val now = System.currentTimeMillis()
        val entry = idToTask[id] ?: return null
        if (isExpired(entry, now)) {
            if (idToTask.remove(id, entry)) {
                log("Expired MCP scanner task id=$id")
            }
            return null
        }
        return entry.task
    }

    fun remove(id: String): ScanTask? = idToTask.remove(id)?.task

    fun clear() {
        idToTask.clear()
    }

    fun configureTtlMinutes(minutes: Int) {
        ttlMs.set(TimeUnit.MINUTES.toMillis(minutes.coerceIn(5, 24 * 60).toLong()))
    }

    fun setLogger(logger: (String) -> Unit) {
        loggerRef.set(logger)
    }

    internal fun configureTtlMillisForTests(milliseconds: Long) {
        ttlMs.set(milliseconds.coerceAtLeast(1L))
    }

    private fun cleanupExpired() {
        val now = System.currentTimeMillis()
        var removed = 0
        val iterator = idToTask.entries.iterator()
        while (iterator.hasNext()) {
            val (id, entry) = iterator.next()
            if (isExpired(entry, now)) {
                iterator.remove()
                removed++
                log("Expired MCP scanner task id=$id")
            }
        }
        if (removed > 0) {
            log("Removed $removed expired MCP scanner task(s)")
        }
    }

    private fun isExpired(
        entry: TimedScanTask,
        nowMs: Long,
    ): Boolean = nowMs - entry.createdAtMs >= ttlMs.get()

    private fun log(message: String) {
        try {
            loggerRef.get().invoke(message)
        } catch (_: Exception) {
            // Ignore logging callback failures; registry behavior should stay deterministic.
        }
    }

    private const val DEFAULT_TTL_MINUTES = 120
    private const val CLEANUP_INTERVAL_MINUTES = 5L
}
