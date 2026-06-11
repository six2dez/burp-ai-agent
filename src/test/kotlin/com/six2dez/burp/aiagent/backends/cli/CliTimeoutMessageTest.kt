package com.six2dez.burp.aiagent.backends.cli

import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

/**
 * SC4 / Issue #71 — pins the contract for the extracted buildTimeoutMessage helper.
 *
 * The helper must:
 *  1. State that the CLI timed out ("timed out" in the message).
 *  2. Surface the configured limit (the timeoutSeconds number).
 *  3. Suggest remediation ("increase" or "pre-install") so users know what to do.
 *  4. Include the tail when non-blank (bounded by the existing take(2000) discipline).
 *
 * Visibility: buildTimeoutMessage is `internal` (same pattern as buildCopilotCommand /
 * CopilotCommandBuilderTest) so it can be called directly without reflection.
 */
class CliTimeoutMessageTest {
    @Test
    fun blankTailMessageContainsTimedOut() {
        val msg = buildTimeoutMessage("", timeoutSeconds = 120)
        assertTrue(msg.contains("timed out", ignoreCase = true), "expected 'timed out' in: $msg")
    }

    @Test
    fun blankTailMessageContainsConfiguredLimit() {
        val msg = buildTimeoutMessage("", timeoutSeconds = 120)
        assertTrue(msg.contains("120"), "expected timeout value '120' in: $msg")
    }

    @Test
    fun blankTailMessageContainsRemediation() {
        val msg = buildTimeoutMessage("", timeoutSeconds = 120)
        assertTrue(
            msg.contains("increase", ignoreCase = true) || msg.contains("pre-install", ignoreCase = true),
            "expected remediation hint ('increase' or 'pre-install') in: $msg",
        )
    }

    @Test
    fun nonBlankTailIsIncludedInMessage() {
        val tail = "some output from the CLI"
        val msg = buildTimeoutMessage(tail, timeoutSeconds = 60)
        assertTrue(msg.contains(tail), "expected tail in message: $msg")
    }

    @Test
    fun nonBlankTailMessageContainsTimedOut() {
        val msg = buildTimeoutMessage("some output", timeoutSeconds = 60)
        assertTrue(msg.contains("timed out", ignoreCase = true), "expected 'timed out' in: $msg")
    }

    @Test
    fun nonBlankTailMessageContainsConfiguredLimit() {
        val msg = buildTimeoutMessage("some output", timeoutSeconds = 60)
        assertTrue(msg.contains("60"), "expected timeout value '60' in: $msg")
    }

    @Test
    fun nonBlankTailMessageContainsRemediation() {
        val msg = buildTimeoutMessage("some output", timeoutSeconds = 60)
        assertTrue(
            msg.contains("increase", ignoreCase = true) || msg.contains("pre-install", ignoreCase = true),
            "expected remediation hint in: $msg",
        )
    }

    @Test
    fun customTimeoutValueAppearsInMessage() {
        // Verify the limit is the one passed in (not a hardcoded 120)
        val msg = buildTimeoutMessage("", timeoutSeconds = 300)
        assertTrue(msg.contains("300"), "expected custom timeout value '300' in: $msg")
    }
}
