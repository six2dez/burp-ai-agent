package com.six2dez.burp.aiagent.mcp

import java.util.concurrent.Semaphore
import java.util.concurrent.TimeUnit

class McpRequestLimiter(
    maxConcurrent: Int,
) {
    private val semaphore = Semaphore(maxConcurrent, true)

    fun tryAcquire(timeoutMs: Long = 250): Boolean =
        try {
            semaphore.tryAcquire(timeoutMs, TimeUnit.MILLISECONDS)
        } catch (_: InterruptedException) {
            false
        }

    fun release() {
        semaphore.release()
    }
}
