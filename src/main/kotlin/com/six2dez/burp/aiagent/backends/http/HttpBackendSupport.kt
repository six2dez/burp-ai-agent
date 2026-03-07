package com.six2dez.burp.aiagent.backends.http

import com.six2dez.burp.aiagent.backends.HealthCheckResult
import com.six2dez.burp.aiagent.config.Defaults
import okhttp3.OkHttpClient
import okhttp3.Request
import java.io.EOFException
import java.net.ProxySelector
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.ConcurrentLinkedDeque

object HttpBackendSupport {
    const val CIRCUIT_FAILURE_THRESHOLD: Int = 5
    const val CIRCUIT_RESET_TIMEOUT_MS: Long = 30_000
    const val CIRCUIT_HALF_OPEN_MAX_ATTEMPTS: Int = 1
    /** Max idle time before a cached client is eligible for eviction */
    private const val CLIENT_EVICTION_AGE_MS: Long = 10 * 60 * 1000 // 10 minutes

    private data class ClientKey(
        val baseUrl: String,
        val timeoutSeconds: Long
    )

    private data class ClientEntry(
        val client: OkHttpClient,
        @Volatile var lastUsedAt: Long = System.currentTimeMillis()
    )

    private val sharedClients = ConcurrentHashMap<ClientKey, ClientEntry>()

    fun buildClient(timeoutSeconds: Long): OkHttpClient {
        return OkHttpClient.Builder()
            .connectTimeout(java.time.Duration.ofSeconds(10))
            .writeTimeout(java.time.Duration.ofSeconds(30))
            .readTimeout(java.time.Duration.ofSeconds(timeoutSeconds))
            .callTimeout(java.time.Duration.ofSeconds(timeoutSeconds))
            // Use system proxy settings (respects Burp/JVM proxy config)
            .proxySelector(ProxySelector.getDefault() ?: ProxySelector.of(null))
            .build()
    }

    fun sharedClient(baseUrl: String?, timeoutSeconds: Long): OkHttpClient {
        val safeTimeout = timeoutSeconds.coerceIn(5L, 3600L)
        val key = ClientKey(
            baseUrl = baseUrl.orEmpty().trim().lowercase(),
            timeoutSeconds = safeTimeout
        )
        val entry = sharedClients.computeIfAbsent(key) { ClientEntry(buildClient(safeTimeout)) }
        entry.lastUsedAt = System.currentTimeMillis()
        // Opportunistic eviction of stale clients
        evictStaleClients()
        return entry.client
    }

    fun shutdownSharedClients() {
        val entries = sharedClients.values.toList()
        sharedClients.clear()
        entries.forEach { entry ->
            entry.client.dispatcher.executorService.shutdown()
            entry.client.connectionPool.evictAll()
            entry.client.cache?.close()
        }
    }

    /** Evict clients not used in the last CLIENT_EVICTION_AGE_MS */
    private fun evictStaleClients() {
        val now = System.currentTimeMillis()
        val iterator = sharedClients.entries.iterator()
        while (iterator.hasNext()) {
            val (_, entry) = iterator.next()
            if (now - entry.lastUsedAt > CLIENT_EVICTION_AGE_MS) {
                iterator.remove()
                try {
                    entry.client.connectionPool.evictAll()
                    entry.client.dispatcher.executorService.shutdown()
                } catch (_: Exception) {}
            }
        }
    }

    fun healthCheckGet(
        url: String,
        headers: Map<String, String>,
        timeoutSeconds: Long = 3L
    ): HealthCheckResult {
        return try {
            val client = sharedClient(url, timeoutSeconds.coerceAtLeast(1L))
            val request = Request.Builder()
                .url(url)
                .apply { headers.forEach { (name, value) -> header(name, value) } }
                .get()
                .build()
            client.newCall(request).execute().use { response ->
                when {
                    response.isSuccessful -> HealthCheckResult.Healthy
                    response.code == 401 || response.code == 403 ->
                        HealthCheckResult.Degraded("Endpoint reachable but authentication failed (HTTP ${response.code}).")
                    else -> HealthCheckResult.Unavailable("HTTP ${response.code}.")
                }
            }
        } catch (e: Exception) {
            HealthCheckResult.Unavailable(e.message ?: "Request failed")
        }
    }

    fun isRetryableConnectionError(e: Exception): Boolean {
        if (e is EOFException) return true
        if (e is java.net.ConnectException || e is java.net.SocketTimeoutException) return true
        if (e is java.net.SocketException) return true
        val msg = e.message?.lowercase().orEmpty()
        return msg.contains("failed to connect") ||
            msg.contains("connection refused") ||
            msg.contains("timeout") ||
            msg.contains("unexpected end of stream") ||
            msg.contains("stream was reset") ||
            msg.contains("end of input")
    }

    fun retryDelayMs(attempt: Int): Long {
        return when (attempt) {
            0 -> 500
            1 -> 1000
            2 -> 1500
            3 -> 2000
            4 -> 3000
            else -> 4000
        }
    }

    fun newCircuitBreaker(): CircuitBreaker {
        return CircuitBreaker(
            failureThreshold = CIRCUIT_FAILURE_THRESHOLD,
            resetTimeoutMs = CIRCUIT_RESET_TIMEOUT_MS,
            halfOpenMaxAttempts = CIRCUIT_HALF_OPEN_MAX_ATTEMPTS
        )
    }

    fun openCircuitError(backendDisplayName: String, retryAfterMs: Long): IllegalStateException {
        val retryDelay = retryAfterMs.coerceAtLeast(1L)
        return IllegalStateException(
            "$backendDisplayName backend is temporarily unavailable (circuit open). Retry in ${retryDelay}ms."
        )
    }
}

class ConversationHistory(
    private val maxMessages: Int = Defaults.MAX_HISTORY_MESSAGES,
    private val maxTotalChars: Int = Defaults.MAX_HISTORY_TOTAL_CHARS
) {
    private val history = ConcurrentLinkedDeque<Map<String, String>>()
    private val lock = Any()
    private var runningTotalChars: Int = 0

    @Volatile
    private var systemPromptEntry: Map<String, String>? = null

    fun addUser(content: String) { synchronized(lock) {
        val entry = mapOf("role" to "user", "content" to content)
        history.addLast(entry)
        runningTotalChars += entryChars(entry)
        trim()
    }}

    fun addAssistant(content: String) { synchronized(lock) {
        val entry = mapOf("role" to "assistant", "content" to content)
        history.addLast(entry)
        runningTotalChars += entryChars(entry)
        trim()
    }}

    fun setSystemPrompt(prompt: String?) {
        systemPromptEntry = if (prompt.isNullOrBlank()) null else mapOf("role" to "system", "content" to prompt)
    }

    fun snapshot(): List<Map<String, String>> { synchronized(lock) {
        val sys = systemPromptEntry
        val msgs = history.toList()
        return if (sys != null) listOf(sys) + msgs else msgs
    }}

    fun setHistory(newHistory: List<com.six2dez.burp.aiagent.backends.ChatMessage>) { synchronized(lock) {
        history.clear()
        runningTotalChars = 0
        newHistory.forEach { msg ->
            val entry = mapOf("role" to msg.role, "content" to msg.content)
            history.addLast(entry)
            runningTotalChars += entryChars(entry)
        }
        trim()
    }}

    private fun trim() {
        while (history.size > maxMessages) {
            val removed = history.pollFirst() ?: break
            runningTotalChars -= entryChars(removed)
        }
        while (history.size > MIN_MESSAGES_TO_KEEP && runningTotalChars > maxTotalChars) {
            val removed = history.pollFirst() ?: break
            runningTotalChars -= entryChars(removed)
        }
    }

    private fun entryChars(entry: Map<String, String>): Int {
        return entry["role"].orEmpty().length + entry["content"].orEmpty().length + 2
    }

    private companion object {
        private const val MIN_MESSAGES_TO_KEEP = 2
    }
}
