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

    // PRIV-02 / SC3 / WR-03: THE TEXT HALF of the bounded-replacement contract — on timeout the
    // returned text is the ORIGINAL input, unchanged and uncorrupted, and the call does not hang.
    //
    // This assertion used to run against the deleted replaceAllSafe façade. WR-03 removed that
    // façade (see SafeReplaceResult's KDoc); the fail-soft TEXT behaviour it pinned is unchanged and
    // is still a real, separately-stated guarantee, so the assertion moved onto
    // replaceAllSafeReporting(...).text rather than being dropped. D-14's clause that
    // "SafeRegexTest:44 stays green unchanged" described plan 21-02's scope, and is superseded by
    // the maintainer's 2026-08-12 decision to close WR-03 — the behaviour survives, the façade does
    // not.
    @Test
    fun catastrophicPatternTimesOutAndReturnsInput() {
        // 2 000 'a' characters followed by '!' — on JDK 21 this reliably triggers the 50 ms
        // deadline for pathological patterns like (a+)+$ anchored at the end. The shorter
        // 64-char probe is handled by JDK 21's improved NFA engine without catastrophic blowup.
        val input = "a".repeat(2_000) + "!"
        val pattern = Pattern.compile("(a+)+\$")

        val start = System.currentTimeMillis()
        val result = SafeRegex.replaceAllSafeReporting(input, pattern, "[REDACTED]").text
        val elapsed = System.currentTimeMillis() - start

        assertEquals(
            input,
            result,
            "On timeout replaceAllSafeReporting(...).text must be the original input unchanged (fail-soft on the text)",
        )
        assertTrue(elapsed < 200L, "replaceAllSafeReporting must return within 200 ms; took $elapsed ms")
    }

    // PRIV-06 / D-14: the pair of tests is deliberate, and stays a pair after WR-03.
    // catastrophicPatternTimesOutAndReturnsInput above pins the TEXT half ("what you get back is
    // safe"); this one pins the FLAG half ("you can tell that you got it back for the wrong
    // reason"), which is what makes fail-closed possible. The returned text is identical in both the
    // "no matches" and the "timed out" cases, so timedOut is the only way a body-redaction caller
    // can tell that a window was never fully scanned and must be dropped rather than sent. Merging
    // the two would lose exactly that distinction.
    @Test
    fun catastrophicPatternReportsTimedOut() {
        // Same input and pattern as catastrophicPatternTimesOutAndReturnsInput — 2 000 'a'
        // characters followed by '!' reliably trips the 50 ms deadline on JDK 21 for (a+)+$.
        val input = "a".repeat(2_000) + "!"
        val pattern = Pattern.compile("(a+)+\$")

        val start = System.currentTimeMillis()
        val result = SafeRegex.replaceAllSafeReporting(input, pattern, "[REDACTED]")
        val elapsed = System.currentTimeMillis() - start

        assertTrue(result.timedOut, "On timeout replaceAllSafeReporting must report timedOut = true")
        assertEquals(input, result.text, "On timeout replaceAllSafeReporting must still return the original input as text")
        assertTrue(elapsed < 200L, "replaceAllSafeReporting must return within 200 ms; took $elapsed ms")
    }

    // PRIV-06 / D-14: the counter-assertion — timedOut must be false for a pattern that completes,
    // otherwise a fail-closed caller would drop every window and the flag would prove nothing.
    @Test
    fun benignPatternReportsNotTimedOut() {
        val result = SafeRegex.replaceAllSafeReporting("abc123", Pattern.compile("\\d+"), "[REDACTED]")

        assertFalse(result.timedOut, "A pattern that completes must report timedOut = false")
        assertEquals("abc[REDACTED]", result.text, "replaceAllSafeReporting must apply the replacement when it completes")
    }

    // A LINEAR pattern over a LARGE input must complete, whatever the speed or load of the machine.
    //
    // [a-z]{1,8}# over 2 000 000 'a' followed by '#' costs 17 character accesses per input char: 8
    // greedy reads, 8 '#' checks while backtracking, plus 1. That is about 34.0 M accesses in total.
    // Under the former wall-clock deadline, at about 20 ns per access with the clock read, that is
    // about 0.7 s of matcher work, about 14x over the deadline, so the call reported timedOut on any
    // machine. Under the access budget it gets 1 000 000 + 64 x 2 000 001 = 129 000 064 accesses,
    // about 3.8x headroom. The property pinned: whether a linear scan completes no longer depends on
    // the speed of the machine.
    @Test
    fun aLinearScanOverALargeInputNeverReportsTimedOut() {
        val input = "a".repeat(2_000_000) + "#"

        val result = SafeRegex.replaceAllSafeReporting(input, Pattern.compile("[a-z]{1,8}#"), "X")

        assertFalse(
            result.timedOut,
            "a linear pattern over a large input must never report timedOut; the bound must not depend on machine speed",
        )
        assertEquals("a".repeat(1_999_992) + "X", result.text, "the linear scan must run to completion")
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

    // WR-07: ANTI-VACUITY PRECONDITION for the three rejection tests below, hoisted into its own
    // assertion so a reader can see it was checked rather than assumed.
    //
    // Every catastrophic candidate below must be rejected BY THE PROBE DEADLINE, not by WR-01's
    // zero-width guard, which runs first and would make the rejection tests green for entirely the
    // wrong reason. A candidate that matched the empty string would be rejected before a single
    // probe ran, and the test would pass identically with the corpus widening reverted. That is
    // exactly the vacuity class this phase has hit nine times.
    @Test
    fun wr07CandidatesAreNotRejectedByTheZeroWidthGuard() {
        val candidates = listOf("(\\d+)+@", "(\\d+)+!", "([a-z]+)+!", "([A-Z]+)+!", "(\\w+\\s?)+\$")
        for (p in candidates) {
            assertFalse(
                Pattern.compile(p).matcher("").find(),
                "WR-07 candidate must NOT match the empty string, or WR-01's guard rejects it before any probe runs: $p",
            )
        }
    }

    // WR-07 (a): catastrophic on DIGITS. RED before the probe corpus widened — the single
    // all-lowercase probe contains no digit at all, so (\d+)+@ finds nothing and completes in
    // microseconds, and isPatternSafe ACCEPTED it. Feed it 2 000 digits with no '@' and it is the
    // classic nested-quantifier blow-up.
    //
    // This is WR-07's own first example, verified accepted-today before the change rather than taken
    // on trust: rejectedBy=[digit! digit-] after the widening, safeBEFORE=true.
    @Test
    fun catastrophicOnDigitsIsRejected() {
        assertFalse(
            SafeRegex.isPatternSafe("(\\d+)+@"),
            "WR-07: (\\d+)+@ is catastrophic on a run of digits and must be rejected; " +
                "the all-lowercase probe alone accepts it because it contains no digit",
        )
        assertFalse(
            SafeRegex.isPatternSafe("(\\d+)+!"),
            "WR-07: (\\d+)+! is catastrophic on a digit run NOT terminated by '!' and must be rejected; " +
                "every '!'-terminated probe accepts it because the trailing literal matches",
        )
    }

    // WR-07 (b): catastrophic on LOWERCASE — and the reason the corpus needs more than one
    // TERMINATOR, not merely more than one character class.
    //
    // ([a-z]+)+! is WR-07's own second example. It escapes the original probe not because that probe
    // lacks lowercase but because that probe ENDS IN '!', which is this pattern's trailing literal:
    // the greedy match succeeds immediately and never backtracks. Measured: it survives every
    // '!'-terminated probe, including the digit, mixed-alphanumeric and space-separated-word probes
    // the review proposed. Only a lowercase run with a DIFFERENT terminator forces the failure that
    // triggers the blow-up. That finding is why the shipped corpus is (class x terminator) rather
    // than the four probes WR-07 suggested. rejectedBy=[lower-], safeBEFORE=true.
    @Test
    fun catastrophicOnLowercaseWithNonMatchingTerminatorIsRejected() {
        assertFalse(
            SafeRegex.isPatternSafe("([a-z]+)+!"),
            "WR-07: ([a-z]+)+! must be rejected; it survives EVERY '!'-terminated probe because its " +
                "own trailing literal is '!', so the corpus must terminate a lowercase run some other way",
        )
    }

    // WR-07 (c): catastrophic on UPPERCASE. Not one of WR-07's three examples — added because the
    // same (class x terminator) analysis showed uppercase-only patterns escaping every probe the
    // review proposed, and realistic user patterns are full of uppercase token shapes
    // (AKIA…, INTERNAL-…, ghp_…). rejectedBy=[upper-], safeBEFORE=true.
    @Test
    fun catastrophicOnUppercaseIsRejected() {
        assertFalse(
            SafeRegex.isPatternSafe("([A-Z]+)+!"),
            "WR-07: ([A-Z]+)+! is catastrophic on a run of uppercase and must be rejected; " +
                "no lowercase or digit probe reaches it",
        )
    }

    // WR-07 (d): REGRESSION PIN, NOT A NEW GUARD — labelled as such deliberately.
    //
    // (\w+\s?)+$ is WR-07's third example, and screening it BEFORE the change showed it was ALREADY
    // rejected by the single original probe (safeBEFORE=false): \w matches 'a', so 2 000 'a'
    // characters followed by '!' already defeats the $ anchor and blows up. It is therefore green on
    // both sides of the widening and proves nothing about the corpus. It ships anyway, because the
    // property is real and worth pinning, but it is recorded here as an already-green pin so that
    // nobody later reads it as evidence the corpus works. The three tests above are the evidence.
    @Test
    fun wordAndWhitespaceCatastrophicPatternStaysRejected() {
        assertFalse(
            SafeRegex.isPatternSafe("(\\w+\\s?)+\$"),
            "WR-07: (\\w+\\s?)+\$ must stay rejected (already rejected before the widening — regression pin)",
        )
    }

    // WR-07: the counter-assertion the rejection tests are worthless without. A corpus that rejects
    // everything would satisfy all four tests above and destroy the feature, so the realistic
    // user-pattern shapes must all still be ACCEPTED after the widening.
    //
    // These are the shapes the Settings panel's custom-pattern field actually receives: cloud key
    // prefixes, hex digests, bearer shapes, internal identifiers. Each was measured completing in
    // microseconds against every probe in the corpus, so widening costs them nothing.
    @Test
    fun realisticUserPatternsSurviveTheWidenedProbeCorpus() {
        val realistic =
            listOf(
                "\\d+",
                "[A-Z]+",
                "secret[0-9]+",
                "AKIA[0-9A-Z]{16}",
                "sk-[A-Za-z0-9]{20,}",
                "ghp_[A-Za-z0-9]{36}",
                "[a-f0-9]{32}",
                "\\bpassword=\\S+",
                "Bearer\\s+[A-Za-z0-9._-]+",
                "INTERNAL-[A-Z0-9]{6}",
            )
        for (p in realistic) {
            assertTrue(
                SafeRegex.isPatternSafe(p),
                "WR-07: a realistic user pattern must still be accepted after the probe corpus widened: $p",
            )
        }
    }

    // WR-07 / WR-01: the two rejection paths must stay DISTINCT. A zero-width pattern has to be
    // rejected by the WR-01 guard BEFORE any probe runs, not by a probe timing out — otherwise
    // widening the corpus would have quietly swallowed a separately documented control and its
    // distinct save-path rejection message.
    //
    // Asserted by cost, which is the only externally visible difference: the guard returns in
    // microseconds while any probe timeout costs at least DEFAULT_TIMEOUT_MS (50 ms). Nine
    // empty-matchers, so a corpus-driven rejection could not hide inside the bound.
    @Test
    fun zeroWidthPatternsAreRejectedWithoutRunningAnyProbe() {
        val emptyMatchers = listOf("a*", "\\d*", "[0-9]*", "\\s*", "x?", "(foo)?", ".*", "(abc)*", "a|")

        val start = System.currentTimeMillis()
        for (p in emptyMatchers) {
            assertFalse(SafeRegex.isPatternSafe(p), "Empty-matching pattern must be rejected: $p")
        }
        val elapsed = System.currentTimeMillis() - start

        assertTrue(
            elapsed < SafeRegex.DEFAULT_TIMEOUT_MS,
            "WR-01's zero-width guard must reject before any probe runs: ${emptyMatchers.size} empty-matchers " +
                "took $elapsed ms, which is at least one probe deadline (${SafeRegex.DEFAULT_TIMEOUT_MS} ms)",
        )
    }

    // PRIV-02 / WR-03: the counter-assertion to catastrophicPatternTimesOutAndReturnsInput — a
    // benign pattern must actually APPLY its replacement. Without it, "returns the input unchanged"
    // would be satisfiable by a function that never replaces anything at all. Moved onto
    // replaceAllSafeReporting(...).text when WR-03 deleted the un-reporting façade; the guarantee is
    // unchanged.
    @Test
    fun benignReplaceAppliesReplacement() {
        val result =
            SafeRegex
                .replaceAllSafeReporting(
                    "id=12345",
                    Pattern.compile("\\d+"),
                    "[REDACTED]",
                ).text
        assertEquals("id=[REDACTED]", result)
    }

    // The third rejection arm, and the only one with no test until now: a pattern that does not
    // COMPILE. The save path hands isPatternSafe raw user input, so a typo — an unclosed group, a
    // dangling quantifier, an unterminated character class — is the most likely bad input of all,
    // and it must be a quiet `false` rather than a PatternSyntaxException escaping onto the EDT.
    @Test
    fun syntacticallyInvalidPatternsAreRejectedWithoutThrowing() {
        val invalid = listOf("(unclosed", "[a-", "a{2,1}", "*leading-quantifier", "(?<bad")
        for (p in invalid) {
            assertFalse(
                SafeRegex.isPatternSafe(p),
                "An uncompilable pattern must be rejected as false, never thrown: $p",
            )
        }
    }

    // A bounded literal pattern — the acceptance counter-assertion stated in its simplest form, so
    // the three arms of isPatternSafe (reject-uncompilable, reject-zero-width, accept) each have a
    // test that names which arm it is exercising.
    @Test
    fun boundedLiteralPatternIsAccepted() {
        assertTrue(SafeRegex.isPatternSafe("INTERNAL-SECRET"), "a bounded literal must be accepted")
        assertTrue(SafeRegex.isPatternSafe("SECRET-[0-9]{4}"), "a bounded literal with a counted class must be accepted")
    }

    // A replacement carrying a back-reference makes the matcher materialise the captured group,
    // which slices the deadline-wrapped input rather than reading it character by character. The
    // slice must stay deadline-aware — a plain String slice would silently drop the interruption
    // guarantee for exactly the patterns most likely to backtrack. Asserted on the produced text;
    // no wall-clock threshold is involved.
    @Test
    fun groupReferencingReplacementSlicesTheInputAndKeepsWorking() {
        val result =
            SafeRegex.replaceAllSafeReporting(
                "token=abc123 and token=def456",
                Pattern.compile("token=([a-z]+)([0-9]+)"),
                "token=\$1[REDACTED]",
            )

        assertFalse(result.timedOut, "a benign group-referencing pattern must not report a timeout")
        assertEquals("token=abc[REDACTED] and token=def[REDACTED]", result.text)
    }
}
