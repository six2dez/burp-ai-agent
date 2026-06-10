package com.six2dez.burp.aiagent.util

import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test

/**
 * SC4a: WARN/CAP/CAP-over-WARN + OFF
 * SC4c: zero thresholds always return OFF (off-by-default)
 * currentSessionTokens(): delegation to TokenTracker.snapshot()
 */
class BudgetGuardTest {

    private val TEST_FLOW = "budget-guard-test-flow"
    private val TEST_BACKEND = "budget-guard-test-backend"

    @AfterEach
    fun clearTokenTracker() {
        // Reset TokenTracker after each test to avoid cross-test bleed.
        // TokenTracker is a global singleton; use reflection to clear the counters map.
        val countersField = TokenTracker::class.java.getDeclaredField("counters")
        countersField.isAccessible = true
        val counters = countersField.get(TokenTracker) as java.util.concurrent.ConcurrentHashMap<*, *>
        counters.clear()
    }

    // --- SC4a: WARN cases ---

    @Test
    fun evaluate_usedEqualsWarnThreshold_returnsWarn() {
        val state = BudgetGuard.evaluate(usedTokens = 1000L, warnThreshold = 1000, hardCap = 5000)
        assertEquals(BudgetGuard.State.WARN, state, "At warn threshold should return WARN")
    }

    @Test
    fun evaluate_usedExceedsWarnButBelowCap_returnsWarn() {
        val state = BudgetGuard.evaluate(usedTokens = 1500L, warnThreshold = 1000, hardCap = 5000)
        assertEquals(BudgetGuard.State.WARN, state, "Between warn and cap should return WARN")
    }

    // --- SC4a: CAP cases ---

    @Test
    fun evaluate_usedEqualsHardCap_returnsCap() {
        val state = BudgetGuard.evaluate(usedTokens = 5000L, warnThreshold = 1000, hardCap = 5000)
        assertEquals(BudgetGuard.State.CAP, state, "At hard cap should return CAP")
    }

    @Test
    fun evaluate_usedExceedsHardCap_returnsCap() {
        val state = BudgetGuard.evaluate(usedTokens = 9999L, warnThreshold = 1000, hardCap = 5000)
        assertEquals(BudgetGuard.State.CAP, state, "Exceeding cap should return CAP")
    }

    @Test
    fun evaluate_capTakesPrecedenceOverWarn_returnsCap() {
        // usedTokens exceeds BOTH warn and cap thresholds — CAP must win
        val state = BudgetGuard.evaluate(usedTokens = 8000L, warnThreshold = 1000, hardCap = 5000)
        assertEquals(BudgetGuard.State.CAP, state, "CAP must take precedence over WARN when both exceeded")
    }

    // --- SC4c: zero-threshold OFF cases (off by default) ---

    @Test
    fun evaluate_bothThresholdsZero_returnsOff() {
        val state = BudgetGuard.evaluate(usedTokens = 999_999L, warnThreshold = 0, hardCap = 0)
        assertEquals(BudgetGuard.State.OFF, state, "Zero thresholds must never fire (off by default)")
    }

    @Test
    fun evaluate_usedZeroNonZeroThresholds_returnsOff() {
        val state = BudgetGuard.evaluate(usedTokens = 0L, warnThreshold = 100, hardCap = 200)
        assertEquals(BudgetGuard.State.OFF, state, "Zero usage below warn threshold should return OFF")
    }

    @Test
    fun evaluate_onlyCapZeroWarnNonZero_capNeverFires() {
        // hardCap = 0 means unlimited — even though usedTokens is very large, cap must not fire
        val state = BudgetGuard.evaluate(usedTokens = 1_000_000L, warnThreshold = 100, hardCap = 0)
        assertEquals(BudgetGuard.State.WARN, state, "Cap=0 means unlimited; only WARN should fire when exceeded")
    }

    @Test
    fun evaluate_onlyWarnZeroCapNonZero_warnNeverFires() {
        // warnThreshold = 0 means off; if used < cap should return OFF
        val state = BudgetGuard.evaluate(usedTokens = 200L, warnThreshold = 0, hardCap = 5000)
        assertEquals(BudgetGuard.State.OFF, state, "Warn=0 means unlimited; below cap should return OFF")
    }

    // --- currentSessionTokens() delegation to TokenTracker ---

    @Test
    fun currentSessionTokens_afterRecord_matchesSummedEstimated() {
        // Record known amounts to a test-specific flow/backend so we can verify the sum
        TokenTracker.record(
            flow = TEST_FLOW,
            backendId = TEST_BACKEND,
            inputChars = 400,   // 400/4.0 = 100 input tokens estimated
            outputChars = 200,  // 200/4.0 = 50  output tokens estimated
        )

        val snapshot = TokenTracker.snapshot().filter { it.flow == TEST_FLOW && it.backendId == TEST_BACKEND }
        assertEquals(1, snapshot.size, "Snapshot must include test flow entry")
        val expected = snapshot.sumOf { it.inputTokensEstimated + it.outputTokensEstimated }
        val actual = BudgetGuard.currentSessionTokens()

        // currentSessionTokens sums ALL entries; the test-specific entries must be included
        // and the sum must be >= expected (other flows may also be present from prior unrelated tests)
        assert(actual >= expected) {
            "currentSessionTokens() = $actual must be >= expected contribution $expected"
        }
    }
}
