package com.six2dez.burp.aiagent.scanner

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class ResponseAnalyzerTest {
    private val analyzer = ResponseAnalyzer()

    @Test
    fun calculateDifferenceReturnsPerfectSimilarityForEqualBodies() {
        val diff = analyzer.calculateDifference("a\nb\nc", "a\nb\nc")

        assertEquals(1.0, diff.similarity)
        assertEquals(0, diff.addedLines)
        assertEquals(0, diff.removedLines)
    }

    @Test
    fun calculateDifferenceDetectsAddedAndRemovedLines() {
        val diff = analyzer.calculateDifference("a\nb\nc", "a\nc\nd")

        assertTrue(diff.similarity in 0.0..1.0)
        assertEquals(1, diff.addedLines)
        assertEquals(1, diff.removedLines)
    }

    @Test
    fun analyzeTimeBasedRejectsSlowBaseline() {
        val result =
            analyzer.analyzeTimeBased(
                baselineTimeMs = 1_500,
                payloadTimeMs = 6_500,
                expectedDelayMs = 5_000,
            )

        assertFalse(result)
    }

    @Test
    fun analyzeTimeBasedAcceptsDelayWithinStrictWindow() {
        val result =
            analyzer.analyzeTimeBased(
                baselineTimeMs = 200,
                payloadTimeMs = 5_200,
                expectedDelayMs = 5_000,
            )

        assertTrue(result)
    }

    @Test
    fun analyzeTimeBasedRejectsDelayOutsideStrictWindow() {
        val tooLow =
            analyzer.analyzeTimeBased(
                baselineTimeMs = 100,
                payloadTimeMs = 4_200,
                expectedDelayMs = 5_000,
            )
        val tooHigh =
            analyzer.analyzeTimeBased(
                baselineTimeMs = 100,
                payloadTimeMs = 8_000,
                expectedDelayMs = 5_000,
            )

        assertFalse(tooLow)
        assertFalse(tooHigh)
    }
}
