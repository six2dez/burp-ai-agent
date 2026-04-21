package com.six2dez.burp.aiagent.backends.http

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import java.util.concurrent.atomic.AtomicLong

class CircuitBreakerTest {
    @Test
    fun opensAfterFailureThresholdAndBlocksRequests() {
        val now = AtomicLong(0)
        val breaker =
            CircuitBreaker(
                failureThreshold = 3,
                resetTimeoutMs = 1_000,
                halfOpenMaxAttempts = 1,
                nowProvider = now::get,
            )

        repeat(3) {
            assertTrue(breaker.tryAcquire().allowed)
            breaker.recordFailure()
        }

        val blocked = breaker.tryAcquire()
        assertFalse(blocked.allowed)
        assertEquals(CircuitBreaker.State.OPEN, blocked.state)
        assertEquals(1_000L, blocked.retryAfterMs)
    }

    @Test
    fun transitionsToHalfOpenAfterTimeoutAndClosesOnSuccess() {
        val now = AtomicLong(0)
        val breaker =
            CircuitBreaker(
                failureThreshold = 2,
                resetTimeoutMs = 250,
                halfOpenMaxAttempts = 1,
                nowProvider = now::get,
            )

        repeat(2) {
            assertTrue(breaker.tryAcquire().allowed)
            breaker.recordFailure()
        }
        assertEquals(CircuitBreaker.State.OPEN, breaker.state())

        now.addAndGet(250)
        val probe = breaker.tryAcquire()
        assertTrue(probe.allowed)
        assertEquals(CircuitBreaker.State.HALF_OPEN, probe.state)

        breaker.recordSuccess()
        val allowed = breaker.tryAcquire()
        assertTrue(allowed.allowed)
        assertEquals(CircuitBreaker.State.CLOSED, allowed.state)
    }

    @Test
    fun halfOpenFailureReopensCircuit() {
        val now = AtomicLong(0)
        val breaker =
            CircuitBreaker(
                failureThreshold = 1,
                resetTimeoutMs = 100,
                halfOpenMaxAttempts = 1,
                nowProvider = now::get,
            )

        assertTrue(breaker.tryAcquire().allowed)
        breaker.recordFailure()
        assertEquals(CircuitBreaker.State.OPEN, breaker.state())

        now.addAndGet(100)
        val halfOpenAttempt = breaker.tryAcquire()
        assertTrue(halfOpenAttempt.allowed)
        assertEquals(CircuitBreaker.State.HALF_OPEN, halfOpenAttempt.state)

        breaker.recordFailure()
        val blocked = breaker.tryAcquire()
        assertFalse(blocked.allowed)
        assertEquals(CircuitBreaker.State.OPEN, blocked.state)
    }
}
