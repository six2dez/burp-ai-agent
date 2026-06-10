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
        // 2 000 'a' characters followed by '!' — on JDK 21 this reliably triggers the 50 ms
        // deadline for pathological patterns like (a+)+$ anchored at the end. The shorter
        // 64-char probe is handled by JDK 21's improved NFA engine without catastrophic blowup.
        val input = "a".repeat(2_000) + "!"
        val pattern = Pattern.compile("(a+)+\$")

        val start = System.currentTimeMillis()
        val result = SafeRegex.replaceAllSafe(input, pattern, "[REDACTED]")
        val elapsed = System.currentTimeMillis() - start

        assertEquals(input, result, "On timeout replaceAllSafe must return the original input unchanged (fail-open)")
        assertTrue(elapsed < 200L, "replaceAllSafe must return within 200 ms; took $elapsed ms")
    }

    // WR-01: patterns that can match the empty (zero-width) string must be rejected. Otherwise
    // replaceAll would insert the replacement between every character, corrupting/bloating the
    // outbound context. Covers the common footguns: *, ?, and alternations with an empty branch.
    @Test
    fun emptyMatchingPatternsAreRejected() {
        val emptyMatchers = listOf("a*", "\\d*", "[0-9]*", "\\s*", "x?", "(foo)?", ".*", "(abc)*", "a|")
        for (p in emptyMatchers) {
            assertFalse(SafeRegex.isPatternSafe(p), "Empty-matching pattern must be rejected: $p")
        }
    }

    // WR-01: a pattern that requires at least one character (cannot match empty) must still pass.
    @Test
    fun nonEmptyMatchingPatternsStillAccepted() {
        val nonEmptyMatchers = listOf("\\bSECRET-\\d{4}\\b", "\\d+", "[A-Z]+", "INTERNAL-[A-Z0-9]{6}", "a+")
        for (p in nonEmptyMatchers) {
            assertTrue(SafeRegex.isPatternSafe(p), "Non-empty-matching pattern must be accepted: $p")
        }
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
