package com.six2dez.burp.aiagent.mcp.tools

import burp.api.montoya.collaborator.CollaboratorClient
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicLong
import java.util.concurrent.atomic.AtomicReference

object CollaboratorRegistry {
    private data class TimedCollaboratorClient(
        val client: CollaboratorClient,
        val createdAtMs: Long,
    )

    private val clients = ConcurrentHashMap<String, TimedCollaboratorClient>()
    private val ttlMs = AtomicLong(TimeUnit.MINUTES.toMillis(DEFAULT_TTL_MINUTES.toLong()))
    private val loggerRef = AtomicReference<(String) -> Unit>({})
    private val cleaner =
        Executors.newSingleThreadScheduledExecutor { runnable ->
            Thread(runnable, "McpCollaboratorRegistryCleaner").apply { isDaemon = true }
        }

    init {
        cleaner.scheduleWithFixedDelay(
            { cleanupExpired() },
            CLEANUP_INTERVAL_MINUTES,
            CLEANUP_INTERVAL_MINUTES,
            TimeUnit.MINUTES,
        )
    }

    fun put(
        key: String,
        client: CollaboratorClient,
    ) {
        clients[key] = TimedCollaboratorClient(client = client, createdAtMs = System.currentTimeMillis())
    }

    fun get(key: String): CollaboratorClient? {
        val now = System.currentTimeMillis()
        val entry = clients[key] ?: return null
        if (isExpired(entry, now)) {
            if (clients.remove(key, entry)) {
                log("Expired MCP collaborator client key=$key")
            }
            return null
        }
        return entry.client
    }

    fun remove(key: String): CollaboratorClient? = clients.remove(key)?.client

    fun clear() {
        clients.clear()
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
        val iterator = clients.entries.iterator()
        while (iterator.hasNext()) {
            val (key, entry) = iterator.next()
            if (isExpired(entry, now)) {
                iterator.remove()
                removed++
                log("Expired MCP collaborator client key=$key")
            }
        }
        if (removed > 0) {
            log("Removed $removed expired MCP collaborator client(s)")
        }
    }

    private fun isExpired(
        entry: TimedCollaboratorClient,
        nowMs: Long,
    ): Boolean = nowMs - entry.createdAtMs >= ttlMs.get()

    private fun log(message: String) {
        try {
            loggerRef.get().invoke(message)
        } catch (_: Exception) {
            // Ignore logging callback failures; registry behavior should stay deterministic.
        }
    }

    private const val DEFAULT_TTL_MINUTES = 60
    private const val CLEANUP_INTERVAL_MINUTES = 5L
}
