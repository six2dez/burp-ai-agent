package com.six2dez.burp.aiagent.redact

import java.util.regex.Pattern
import java.util.regex.PatternSyntaxException

// ReDoS-safe regex utility.
//
// The JDK Matcher has no built-in timeout (JDK-8234713 "Won't fix"). This object bounds any
// single regex match to ~50 ms by wrapping the input in a DeadlineCharSequence whose get()
// throws RegexTimeoutException once System.nanoTime() exceeds the deadline. The Matcher reads
// input characters via CharSequence.get() during backtracking, so the deadline is observed
// promptly even under catastrophic backtracking.
//
// Reference: https://www.ocpsoft.org/regex/how-to-interrupt-a-long-running-infinite-java-regular-expression/
// [CITED — interruptible-CharSequence idiom, adapted to use a nanoTime deadline instead of
//  Thread.interrupted() so it works without requiring external thread management.]
//
// Design decisions mirrored from SecretCipher.kt:
//   - fail-soft: never throw into the redaction pipeline; return a safe fallback.
//   - no ExecutorService: avoids orphaned threads in Burp's long-lived JVM process.
//   - AWT-free: no java.awt / javax.swing imports so Phase 15's scanner-side tripwire can reuse
//     this file headless.

// Thrown by DeadlineCharSequence.get() when the match deadline is exceeded.
internal class RegexTimeoutException : RuntimeException()

// Wraps a CharSequence so that each get() call checks a nanoTime deadline before returning the
// character. The Matcher's inner backtracking loop calls CharSequence.get() (charAt) on every
// character access, so the deadline is observed promptly even under catastrophic backtracking.
private class DeadlineCharSequence(
    private val inner: CharSequence,
    private val deadlineNanos: Long,
) : CharSequence {
    override val length: Int get() = inner.length

    override fun get(index: Int): Char {
        if (System.nanoTime() > deadlineNanos) throw RegexTimeoutException()
        return inner[index]
    }

    override fun subSequence(
        startIndex: Int,
        endIndex: Int,
    ): CharSequence = DeadlineCharSequence(inner.subSequence(startIndex, endIndex), deadlineNanos)

    override fun toString(): String = inner.toString()
}

object SafeRegex {
    /**
     * Maximum wall-clock time (in milliseconds) allowed for a single regex match or probe.
     * Corresponds to the "50 ms per-pattern timeout" described in PRIV-02 / SC3.
     */
    const val DEFAULT_TIMEOUT_MS = 50L

    /**
     * Replaces all matches of [pattern] in [input] with [replacement], bounding the match to
     * [timeoutMs] milliseconds.
     *
     * If the pattern times out (RegexTimeoutException from the DeadlineCharSequence), the
     * ORIGINAL [input] is returned unchanged — fail-open so the redaction pipeline never hangs
     * and never corrupts content on account of a slow pattern.
     */
    fun replaceAllSafe(
        input: String,
        pattern: Pattern,
        replacement: String,
        timeoutMs: Long = DEFAULT_TIMEOUT_MS,
    ): String =
        try {
            val deadline = System.nanoTime() + timeoutMs * 1_000_000L
            val matcher = pattern.matcher(DeadlineCharSequence(input, deadline))
            matcher.replaceAll(replacement)
        } catch (_: RegexTimeoutException) {
            // Fail-open: give up on this pattern; never corrupt or hang the pipeline.
            input
        }

    /**
     * Returns true if [regex] compiles successfully AND finishes matching the adversarial probe
     * within [timeoutMs] milliseconds.
     *
     * Returns false if:
     *   - the regex fails to compile (PatternSyntaxException), or
     *   - the match against the adversarial probe times out (RegexTimeoutException).
     *
     * Used by the custom-pattern save-validation path (PrivacyConfigPanel) per SC3.
     */
    fun isPatternSafe(
        regex: String,
        timeoutMs: Long = DEFAULT_TIMEOUT_MS,
    ): Boolean =
        try {
            val compiled = Pattern.compile(regex) // syntax check — throws PatternSyntaxException on bad regex
            // WR-01: reject patterns that can match the empty (zero-width) string, e.g. a*, \d*,
            // [0-9]*, \s*, x?, (foo)?, .*. Matcher.replaceAll advances past zero-width matches one
            // character at a time, inserting the replacement between EVERY character — corrupting
            // and bloating the outbound context (a 44-char body explodes to ~490 chars). Fail-safe
            // for secrecy, but a foreseeable footgun for non-expert regex users, so reject it up
            // front and surface a distinct rejection message in the save path.
            if (compiled.matcher("").find()) {
                false
            } else {
                val deadline = System.nanoTime() + timeoutMs * 1_000_000L
                compiled.matcher(DeadlineCharSequence(ADVERSARIAL_PROBE, deadline)).find()
                true
            }
        } catch (_: PatternSyntaxException) {
            false
        } catch (_: RegexTimeoutException) {
            false
        }

    // Catastrophic-backtracking probe for isPatternSafe.
    // On JDK 21 the classic (a+)+$ pattern requires ~2 000+ characters before the timeout
    // fires within the 50 ms budget (JDK 21 has improved its NFA engine for shorter inputs).
    // Using 2 000 'a' characters followed by '!' reliably triggers the 50 ms deadline for
    // truly pathological patterns while benign patterns (\d+, [A-Z]+, etc.) complete in
    // microseconds on the same probe.
    private val ADVERSARIAL_PROBE: String = "a".repeat(2_000) + "!"
}
