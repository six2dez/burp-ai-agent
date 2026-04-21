package com.six2dez.burp.aiagent.mcp

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger

class McpRequestLimiterConcurrencyTest {
    @Test
    fun limiterDoesNotExceedConfiguredConcurrency() {
        val limiter = McpRequestLimiter(maxConcurrent = 3)
        val workers = 18
        val pool = Executors.newFixedThreadPool(8)
        val start = CountDownLatch(1)
        val done = CountDownLatch(workers)
        val inFlight = AtomicInteger(0)
        val peak = AtomicInteger(0)
        val acquired = AtomicInteger(0)

        repeat(workers) {
            pool.submit {
                try {
                    start.await(2, TimeUnit.SECONDS)
                    if (limiter.tryAcquire(timeoutMs = 1_000)) {
                        acquired.incrementAndGet()
                        val now = inFlight.incrementAndGet()
                        peak.updateAndGet { prev -> maxOf(prev, now) }
                        Thread.sleep(40)
                        inFlight.decrementAndGet()
                        limiter.release()
                    }
                } finally {
                    done.countDown()
                }
            }
        }

        start.countDown()
        assertTrue(done.await(5, TimeUnit.SECONDS))
        pool.shutdownNow()

        assertEquals(workers, acquired.get())
        assertTrue(peak.get() <= 3, "Observed ${peak.get()} concurrent holders")
    }

    @Test
    fun tryAcquireTimesOutWhenPermitNotReleasedInTime() {
        val limiter = McpRequestLimiter(maxConcurrent = 1)

        assertTrue(limiter.tryAcquire(timeoutMs = 10))
        val secondAttempt = limiter.tryAcquire(timeoutMs = 50)
        assertFalse(secondAttempt)
        limiter.release()

        assertTrue(limiter.tryAcquire(timeoutMs = 10))
        limiter.release()
    }
}
