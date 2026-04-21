package com.six2dez.burp.aiagent.scanner

import burp.api.montoya.http.message.HttpRequestResponse
import java.util.concurrent.ConcurrentLinkedQueue
import java.util.concurrent.atomic.AtomicLong

internal data class PendingAnalysis(
    val metadata: String,
    val requestResponse: HttpRequestResponse,
    val minSeverity: String,
    val host: String,
    val enqueuedAtMs: Long = System.currentTimeMillis(),
)

internal class BatchAnalysisQueue(
    maxBatchSize: Int = DEFAULT_BATCH_SIZE,
    private val flushTimeoutMs: Long = DEFAULT_FLUSH_TIMEOUT_MS,
) {
    @Volatile
    var maxBatchSize: Int = maxBatchSize
        internal set
    private val queue = ConcurrentLinkedQueue<PendingAnalysis>()
    private val oldestEnqueueMs = AtomicLong(0L)

    fun enqueue(item: PendingAnalysis) {
        oldestEnqueueMs.compareAndSet(0L, item.enqueuedAtMs)
        queue.add(item)
    }

    fun shouldFlush(): Boolean {
        val size = queue.size
        if (size == 0) return false
        if (size >= maxBatchSize) return true
        val oldest = oldestEnqueueMs.get()
        return oldest > 0L && System.currentTimeMillis() - oldest >= flushTimeoutMs
    }

    fun drain(): List<PendingAnalysis> {
        val batch = mutableListOf<PendingAnalysis>()
        while (batch.size < maxBatchSize) {
            val item = queue.poll() ?: break
            batch.add(item)
        }
        if (queue.isEmpty()) {
            oldestEnqueueMs.set(0L)
        } else {
            queue.peek()?.let { oldestEnqueueMs.set(it.enqueuedAtMs) }
        }
        return batch
    }

    fun isEmpty(): Boolean = queue.isEmpty()

    fun clear() {
        queue.clear()
        oldestEnqueueMs.set(0L)
    }

    companion object {
        const val DEFAULT_BATCH_SIZE = 3
        const val DEFAULT_FLUSH_TIMEOUT_MS = 5_000L
    }
}
