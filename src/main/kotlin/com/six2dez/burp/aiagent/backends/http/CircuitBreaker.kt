package com.six2dez.burp.aiagent.backends.http

class CircuitBreaker(
    private val failureThreshold: Int = 5,
    private val resetTimeoutMs: Long = 30_000,
    private val halfOpenMaxAttempts: Int = 1,
    private val nowProvider: () -> Long = { System.currentTimeMillis() },
) {
    init {
        require(failureThreshold > 0) { "failureThreshold must be > 0" }
        require(resetTimeoutMs > 0) { "resetTimeoutMs must be > 0" }
        require(halfOpenMaxAttempts > 0) { "halfOpenMaxAttempts must be > 0" }
    }

    enum class State {
        CLOSED,
        OPEN,
        HALF_OPEN,
    }

    data class Permission(
        val allowed: Boolean,
        val state: State,
        val retryAfterMs: Long,
    )

    private val lock = Any()
    private var state: State = State.CLOSED
    private var consecutiveFailures: Int = 0
    private var openedAtMs: Long = 0
    private var halfOpenAttempts: Int = 0

    fun tryAcquire(): Permission {
        synchronized(lock) {
            val now = nowProvider()
            if (state == State.OPEN) {
                val elapsed = now - openedAtMs
                if (elapsed >= resetTimeoutMs) {
                    state = State.HALF_OPEN
                    halfOpenAttempts = 0
                } else {
                    return Permission(
                        allowed = false,
                        state = State.OPEN,
                        retryAfterMs = (resetTimeoutMs - elapsed).coerceAtLeast(1L),
                    )
                }
            }

            if (state == State.HALF_OPEN) {
                if (halfOpenAttempts >= halfOpenMaxAttempts) {
                    return Permission(
                        allowed = false,
                        state = State.HALF_OPEN,
                        retryAfterMs = resetTimeoutMs,
                    )
                }
                halfOpenAttempts++
                return Permission(
                    allowed = true,
                    state = State.HALF_OPEN,
                    retryAfterMs = 0,
                )
            }

            return Permission(
                allowed = true,
                state = State.CLOSED,
                retryAfterMs = 0,
            )
        }
    }

    fun recordSuccess() {
        synchronized(lock) {
            state = State.CLOSED
            consecutiveFailures = 0
            openedAtMs = 0
            halfOpenAttempts = 0
        }
    }

    fun recordFailure() {
        synchronized(lock) {
            when (state) {
                State.CLOSED -> {
                    consecutiveFailures++
                    if (consecutiveFailures >= failureThreshold) {
                        open(nowProvider())
                    }
                }

                State.HALF_OPEN -> {
                    open(nowProvider())
                }

                State.OPEN -> Unit
            }
        }
    }

    fun state(): State {
        synchronized(lock) {
            return state
        }
    }

    private fun open(nowMs: Long) {
        state = State.OPEN
        openedAtMs = nowMs
        consecutiveFailures = 0
        halfOpenAttempts = 0
    }
}
