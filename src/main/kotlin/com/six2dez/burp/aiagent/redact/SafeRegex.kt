package com.six2dez.burp.aiagent.redact

import java.util.regex.Pattern
import java.util.regex.PatternSyntaxException

// ReDoS-safe regex utility.
//
// The JDK Matcher has no built-in timeout (JDK-8234713 "Won't fix"). This object bounds any
// single regex call by a CHARACTER-ACCESS budget: the input is wrapped in a BudgetedCharSequence
// whose get() spends one access and throws RegexTimeoutException once the budget is spent. The
// Matcher reads every character through get(), backtracking included, so the bound holds under
// catastrophic backtracking. No clock is read: a wall-clock bound made the outcome depend on
// machine speed and load, and dropped content nondeterministically.
//
// Reference: https://www.ocpsoft.org/regex/how-to-interrupt-a-long-running-infinite-java-regular-expression/
// [CITED - interruptible-CharSequence idiom, adapted to count accesses instead of reading
//  Thread.interrupted() so it needs no external thread management and no clock.]
//
// Design decisions mirrored from SecretCipher.kt:
//   - fail-soft: never throw into the redaction pipeline; return a safe fallback.
//   - no ExecutorService: avoids orphaned threads in Burp's long-lived JVM process.
//   - AWT-free: no java.awt / javax.swing imports so Phase 15's scanner-side tripwire can reuse
//     this file headless.

// Thrown by BudgetedCharSequence.get() when the access budget is spent. The name is historical:
// "timeout" now means "access budget exhausted".
internal class RegexTimeoutException : RuntimeException()

// The remaining character accesses for ONE regex call. It allows exactly N accesses: the
// (N+1)-th throws, and a budget of 0 or less throws on the first access. Single-threaded by
// construction: each call creates its own instance as a local.
internal class AccessBudget(
    private var remaining: Long,
) {
    fun spend() {
        if (remaining <= 0L) throw RegexTimeoutException()
        remaining--
    }
}

// Wraps a CharSequence so that each get() spends one access from [budget]. subSequence wraps the
// slice with the SAME budget instance, so a slice the Matcher materialises cannot escape the
// bound. length and toString() spend nothing.
internal class BudgetedCharSequence(
    private val inner: CharSequence,
    private val budget: AccessBudget,
) : CharSequence {
    override val length: Int get() = inner.length

    override fun get(index: Int): Char {
        budget.spend()
        return inner[index]
    }

    override fun subSequence(
        startIndex: Int,
        endIndex: Int,
    ): CharSequence = BudgetedCharSequence(inner.subSequence(startIndex, endIndex), budget)

    override fun toString(): String = inner.toString()
}

// Why isPatternSafe rejected a pattern, or ACCEPTED. A test seam: a verdict proves which arm
// rejected without timing anything.
internal enum class PatternVerdict { ACCEPTED, UNCOMPILABLE, MATCHES_EMPTY, PROBE_BUDGET_EXHAUSTED }

object SafeRegex {
    /**
     * Character accesses per probe in [isPatternSafe], and the per-call base of [accessBudgetFor].
     * Measured on JDK 21: 4.0x under the cheapest known catastrophe ((a+)+$ needs 4 011 997) and
     * 167x over the most expensive realistic custom pattern (5 975).
     */
    const val PROBE_ACCESS_BUDGET = 1_000_000L

    /**
     * Character accesses granted per input char. Measured maxima per char per built-in body rule:
     * 30.0 on degenerate 1 MB bodies (2.1x), 11.2 on realistic bodies (5.7x), 8.15 on the
     * boundary-sweep fixtures (7.9x). Counts do not depend on the machine.
     */
    const val ACCESS_BUDGET_PER_CHAR = 64L

    /**
     * The access budget for one call over [length] chars. Proportional to length because no fixed
     * budget can both cover a 1 MB window and stay cheap to exhaust on a probe. Any input no longer
     * than a probe gets at least the budget the validator granted on each probe.
     */
    fun accessBudgetFor(length: Int): Long = PROBE_ACCESS_BUDGET + ACCESS_BUDGET_PER_CHAR * length

    /**
     * Outcome of a bounded replacement (PRIV-06 / D-14).
     *
     * [timedOut] is the ONLY reliable signal that the pattern did not complete. [text] equals the
     * original input in BOTH the "the pattern matched nothing" case and the "the pattern never
     * finished" case, so a caller that inspects [text] alone cannot tell those two apart. A caller
     * that must fail closed — a body-redaction window whose unscanned bytes must never reach a
     * backend — has to branch on [timedOut], never on whether [text] changed.
     *
     * WR-03: THERE IS DELIBERATELY NO UN-REPORTING FAÇADE, and this note exists so the next person
     * who wants one finds the reason here instead of re-adding it.
     *
     * The DELETED function was `replaceAllSafe` — a `String`-returning one-line delegate that sat
     * beside [replaceAllSafeReporting] and returned exactly this [text] (the name is spelled out on
     * this line on purpose, so that grepping for it lands on its obituary). It ended Phase 21 with
     * ZERO production callers while its own KDoc named its hazard — "fail-open", "conflates
     * 'matched nothing' with 'timed out'" — i.e. a public fail-open replacement entry point inside
     * the redaction package, one autocomplete away from the next contributor who adds a rule. It was
     * removed (maintainer scope decision, 2026-08-12) rather than deprecated, because a `String`
     * return type structurally CANNOT carry [timedOut] and D-02 requires every body rule to fail
     * CLOSED on a timeout: a deprecated-but-callable fail-open helper is still a fail-open helper.
     * The shape that replaces it is explicit and one line longer:
     * `val r = replaceAllSafeReporting(...); if (r.timedOut) <fail closed> else r.text`.
     */
    data class SafeReplaceResult(
        val text: String,
        val timedOut: Boolean,
    )

    /**
     * Replaces all matches of [pattern] in [input] with [replacement], bounding the match to
     * [accessBudget] character accesses, and reports whether it ran to completion (PRIV-06 / D-14).
     *
     * This is the ONLY replacement entry point in the redaction package (WR-03).
     *
     * On timeout (the access budget is spent) [SafeReplaceResult.text] is the ORIGINAL [input],
     * fail-soft on the TEXT, so the redaction pipeline never hangs and never corrupts content on
     * account of a slow pattern, but
     * [SafeReplaceResult.timedOut] is true, which is what lets a caller drop unscanned content
     * instead of silently passing it through. See [SafeReplaceResult] for why the flag, not the
     * text, is the signal, and for why no `String`-returning convenience wrapper exists.
     */
    fun replaceAllSafeReporting(
        input: String,
        pattern: Pattern,
        replacement: String,
        accessBudget: Long = accessBudgetFor(input.length),
    ): SafeReplaceResult =
        try {
            val matcher = pattern.matcher(BudgetedCharSequence(input, AccessBudget(accessBudget)))
            SafeReplaceResult(matcher.replaceAll(replacement), false)
        } catch (_: RegexTimeoutException) {
            // Fail-soft on the text as before, but report the timeout so the caller can fail closed.
            SafeReplaceResult(input, true)
        }

    /**
     * Returns true if [regex] compiles successfully AND finishes matching EVERY probe in
     * [ADVERSARIAL_PROBES] within [probeBudget] character accesses each.
     *
     * Returns false if:
     *   - the regex fails to compile (PatternSyntaxException), or
     *   - the regex can match the empty string (WR-01 - its own distinct rejection, below), or
     *   - the match against ANY probe spends its budget (RegexTimeoutException). The first
     *     exhaustion rejects; the remaining probes are not run.
     *
     * Used by the custom-pattern save-validation path (`SettingsPanel.validateAndCollectCustomPatterns`,
     * on the EDT) per SC3, and by `App.initialize`'s startup re-validation of the persisted list
     * (WR-07 / T-21-64).
     *
     * COST. Benign patterns complete in microseconds against every probe: a realistic ten-pattern
     * list measured 2.2 ms across the whole corpus. Only a pathological pattern exhausts a probe
     * budget, at most once before the first exhaustion ends the loop; a measured catastrophic
     * rejection costs 8-15 ms. See [ADVERSARIAL_PROBES] for the worst-case bound and the EDT note.
     */
    fun isPatternSafe(
        regex: String,
        probeBudget: Long = PROBE_ACCESS_BUDGET,
    ): Boolean = patternVerdict(regex, probeBudget) == PatternVerdict.ACCEPTED

    // The logic behind isPatternSafe, reporting WHICH arm decided. Each probe gets a FRESH budget.
    internal fun patternVerdict(
        regex: String,
        probeBudget: Long = PROBE_ACCESS_BUDGET,
    ): PatternVerdict =
        try {
            val compiled = Pattern.compile(regex) // syntax check - throws PatternSyntaxException on bad regex
            // WR-01: reject patterns that can match the empty (zero-width) string, e.g. a*, \d*,
            // [0-9]*, \s*, x?, (foo)?, .*. Matcher.replaceAll advances past zero-width matches one
            // character at a time, inserting the replacement between EVERY character, corrupting
            // and bloating the outbound context (a 44-char body explodes to ~490 chars). Fail-safe
            // for secrecy, but a foreseeable footgun for non-expert regex users, so reject it up
            // front and surface a distinct rejection message in the save path.
            //
            // This check stays ABOVE the probe loop and keeps its own separate verdict, so a
            // zero-width pattern is rejected for BEING zero-width rather than for exhausting a probe.
            // Guard: SafeRegexTest.zeroWidthPatternsAreRejectedWithoutRunningAnyProbe, which asserts
            // MATCHES_EMPTY under a probe budget of 0, where any probe that ran would exhaust.
            if (compiled.matcher("").find()) {
                PatternVerdict.MATCHES_EMPTY
            } else {
                // WR-07: EVERY probe, and the first exhaustion rejects. Each probe gets its own fresh
                // budget: a shared budget across the corpus would let a pattern that is merely
                // slow on probe 1 exhaust the budget and be rejected on probe 2 for the wrong reason.
                for (probe in ADVERSARIAL_PROBES) {
                    compiled.matcher(BudgetedCharSequence(probe, AccessBudget(probeBudget))).find()
                }
                PatternVerdict.ACCEPTED
            }
        } catch (_: PatternSyntaxException) {
            PatternVerdict.UNCOMPILABLE
        } catch (_: RegexTimeoutException) {
            PatternVerdict.PROBE_BUDGET_EXHAUSTED
        }

    // (PRIV-02) WR-07 / T-21-63: the catastrophic-backtracking probe corpus for isPatternSafe.
    //
    // WHY THIS IS A SECURITY CONTROL AND NOT A TIDY-UP. Before this phase, a custom pattern that
    // was accepted but slow degraded gracefully: custom patterns ran only inside the redactTokens
    // branch and an overrunning one was simply skipped. D-05 changed both halves of that. Custom
    // patterns now run in EVERY privacy mode INCLUDING OFF (they are a "never send this, ever" list,
    // independent of the mode — see Redaction.bodyRules), and bodyStage now fails CLOSED. So an
    // accepted-but-slow pattern no longer degrades: it spends Defaults.MAX_REDACTION_BUDGET_MS and
    // drops real content behind markers on EVERY call, including the calls a user in OFF mode
    // believes are unfiltered. The blast radius of a bad accept grew in both directions during this
    // phase without the gate being strengthened. This corpus is the strengthening.
    //
    // THE DESIGN PRINCIPLE IS (CHARACTER CLASS x TERMINATOR), and the terminator half is the part
    // WR-07 missed. Catastrophic backtracking in the (X+)+L family needs a long run of X that is
    // NOT followed by L, so the match fails and the engine explores the run's partitions. WR-07
    // proposed varying only the character class, all four probes still ending in '!'. Measured, that
    // does not reject WR-07's OWN second example: ([a-z]+)+! survives a lowercase probe ending in
    // '!' because the greedy match SUCCEEDS immediately and never backtracks, and survives the digit,
    // mixed-alphanumeric and space-separated-word probes because none of them contains a long
    // lowercase run. Only a lowercase run with a different terminator rejects it.
    //
    // Hence three classes x two terminators. Every realistic user-pattern class — hex [a-f0-9],
    // base64 [A-Za-z0-9+/=], \w, [a-z], [A-Z], \d, \S, '.' — contains 'a', '1' or 'A', so each is
    // reachable by at least one probe under at least one non-matching terminator.
    //
    // NO WHITESPACE PROBE, deliberately, and this is a measurement rather than an omission. WR-07
    // proposed ("x"*50 + " ")*40 + "!". Eleven whitespace-targeting candidates were screened against
    // it — (x+ ?)+$, (x+ )+$, ([a-z]+ )+$, (\w+ )+$, ([a-z]+ )+#, (x+ )+@, (x+\s)+!, (\w+\s)+$,
    // (\S+\s)+$, ([a-z ]+)+#, ([a-z]+\s?)+# — and NOT ONE is rejected by that probe alone: the ones
    // it catches are already caught by the lowercase probes, and the rest are not catastrophic at
    // all, because a MANDATORY separator inside the group removes the ambiguity that drives the
    // blow-up. Adding it would have cost a probe's worth of worst case for coverage that could not
    // be demonstrated — the "named guard pointing at nothing" defect this round exists to close. If
    // someone later finds a genuine whitespace-only fixture, add the probe WITH that fixture.
    //
    // SIZING. The first entry is the original single probe, kept BYTE-FOR-BYTE. On JDK 21 the
    // catastrophes in this family are POLYNOMIAL, not exponential (its NFA engine handles short
    // inputs without blow-up), so each probe carries a 2 000-char run: long enough that the
    // cheapest known catastrophe, (a+)+$, needs 4 011 997 accesses, 4.0x over PROBE_ACCESS_BUDGET,
    // while realistic patterns need at most 5 975. A shorter run would shrink that margin.
    //
    // WORST CASE, stated rather than assumed: 6 probes x PROBE_ACCESS_BUDGET = 6 M accesses for ONE
    // pattern, about 36-72 ms at 6-12 ns per access, only for a pattern slow-but-completing on five
    // probes and pathological on the sixth. Measured: a catastrophic rejection costs 8-15 ms. An
    // exhausted call on a large window costs about 0.6 s per MB, as the budget grows with length.
    //
    // EDT NOTE - REPORTED, NOT FIXED HERE (T-21-67, Phase 23 / REL-05). isPatternSafe runs ON THE
    // EDT at save time via SettingsPanel.validateAndCollectCustomPatterns, so the probe count
    // multiplies that path's worst case; the bound above is what one pattern can cost it. Phase 23
    // owns EDT confinement. The startup seeding path in App.initialize is NOT on the EDT-critical
    // path.
    private val ADVERSARIAL_PROBES: List<String> =
        listOf(
            "a".repeat(2_000) + "!", // original probe, verbatim — lowercase run, '!' terminator
            "a".repeat(2_000) + "-", // lowercase run, non-'!' terminator: rejects ([a-z]+)+!
            "1".repeat(2_000) + "!", // digit run: rejects (\d+)+@
            "1".repeat(2_000) + "-", // digit run, non-'!' terminator: rejects (\d+)+!
            "A".repeat(2_000) + "!", // uppercase run
            "A".repeat(2_000) + "-", // uppercase run, non-'!' terminator: rejects ([A-Z]+)+!
        )
}
