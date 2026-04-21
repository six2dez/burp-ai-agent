package com.six2dez.burp.aiagent.util

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class TokenTrackerTest {
    @Test
    fun estimatesTokensFromCharacters() {
        assertEquals(0, TokenTracker.estimateTokens(0))
        assertEquals(1, TokenTracker.estimateTokens(1))
        assertEquals(1, TokenTracker.estimateTokens(4))
        assertEquals(2, TokenTracker.estimateTokens(5))
        assertEquals(10, TokenTracker.estimateTokens(36, "openai-compatible"))
    }

    @Test
    fun recordsAndExposesSnapshot() {
        val flow = "token-test-flow"
        val backend = "token-test-backend"
        TokenTracker.record(flow, backend, inputChars = 80, outputChars = 40, cacheHit = true)
        TokenTracker.record(flow, backend, inputChars = 20, outputChars = 8, cacheHit = false)

        val row = TokenTracker.snapshot().firstOrNull { it.flow == flow && it.backendId == backend }
        assertTrue(row != null)
        assertEquals(2, row.calls)
        assertEquals(1, row.cacheHits)
        assertEquals(100, row.inputChars)
        assertEquals(48, row.outputChars)
        assertEquals(25, row.inputTokensEstimated)
        assertEquals(12, row.outputTokensEstimated)
    }

    @Test
    fun combinesActualUsageWithEstimatedRemainder() {
        val flow = "token-test-flow-actual"
        val backend = "openai-compatible"

        TokenTracker.record(
            flow = flow,
            backendId = backend,
            inputChars = 36,
            outputChars = 18,
            inputTokensActual = 7,
            outputTokensActual = 3,
        )
        TokenTracker.record(
            flow = flow,
            backendId = backend,
            inputChars = 36,
            outputChars = 18,
        )

        val row = TokenTracker.snapshot().firstOrNull { it.flow == flow && it.backendId == backend }
        assertTrue(row != null)
        assertEquals(72, row.inputChars)
        assertEquals(36, row.outputChars)
        assertEquals(17, row.inputTokensEstimated)
        assertEquals(8, row.outputTokensEstimated)
    }
}
