package com.six2dez.burp.aiagent.redact

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import java.util.regex.Pattern

// PRIV-02 / SC3: unit tests for the SafeRegex interruptible-CharSequence ReDoS guard.
// All tests run headless (no AWT) and must complete well under the CI timeout budget.
class SafeRegexTest {
    // PRIV-02 / SC3: a catastrophically-backtracking pattern should be rejected within the
    // timeout budget and the call must return within ~200 ms wall-clock.
    @Test
    fun catastrophicPatternIsRejectedWithinBudget() {
        val start = System.currentTimeMillis()
        val safe = SafeRegex.isPatternSafe("(a+)+\$")
        val elapsed = System.currentTimeMillis() - start

        assertFalse(safe, "Catastrophic pattern (a+)+\$ must return false")
        assertTrue(elapsed < 200L, "isPatternSafe must return within 200 ms; took $elapsed ms")
    }

    // PRIV-02 / SC3: a benign pattern must be accepted.
    @Test
    fun benignPatternIsAccepted() {
        assertTrue(SafeRegex.isPatternSafe("\\d+"), "Benign pattern \\d+ must be accepted")
    }

    // PRIV-02 / SC3: replaceAllSafe on a catastrophic pattern with a long matching-resistant
    // input must return the original input unchanged (fail-open) and not hang.
    @Test
    fun catastrophicPatternTimesOutAndReturnsInput() {
        // 64 'a' characters followed by '!' — the canonical catastrophic-backtracking input
        // that maximises backtracking for patterns like (a+)+$ anchored at the end.
        val input = "a".repeat(64) + "!"
        val pattern = Pattern.compile("(a+)+\$")

        val start = System.currentTimeMillis()
        val result = SafeRegex.replaceAllSafe(input, pattern, "[REDACTED]")
        val elapsed = System.currentTimeMillis() - start

        assertEquals(input, result, "On timeout replaceAllSafe must return the original input unchanged (fail-open)")
        assertTrue(elapsed < 200L, "replaceAllSafe must return within 200 ms; took $elapsed ms")
    }

    // PRIV-02: replaceAllSafe on a benign pattern must apply the replacement correctly.
    @Test
    fun benignReplaceAppliesReplacement() {
        val result = SafeRegex.replaceAllSafe(
            "id=12345",
            Pattern.compile("\\d+"),
            "[REDACTED]",
        )
        assertEquals("id=[REDACTED]", result)
    }
}
