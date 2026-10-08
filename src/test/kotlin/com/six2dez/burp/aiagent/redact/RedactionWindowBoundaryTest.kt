package com.six2dez.burp.aiagent.redact

import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

/**
 * Deterministic seam tests for the windowed body stage's fail-closed boundary decisions
 * (quick task 261008-m2n): the budget-spent drop, [Redaction.testSplitPoint] and
 * [Redaction.testWindowEnd]. None of them depends on wall-clock time except the budget test, whose
 * zero budget is already spent before the first scan by construction.
 *
 * Every windowEnd fixture computes its expected index from the fixture itself, and asserts the
 * geometry it relies on (the natural cut lands just past a newline, on a non-newline character).
 */
class RedactionWindowBoundaryTest {
    @AfterEach
    fun resetTruncationLimiter() {
        // The budget test reaches maybeLogTruncation with the real clock, and Redaction is a
        // singleton shared by every test class in this JVM.
        Redaction.resetTruncationWindowForTest()
    }

    // Fail closed when the budget is already spent: the whole body is replaced by one marker and
    // none of it, the secret value included, is emitted.
    @Test
    fun windowedBodyStageWithNoBudgetLeftDropsTheWholeBodyBehindOneMarker() {
        val body = "{\"api_key\":\"M2N-BUDGET-VALUE-7\"}" + "\n" + FILLER

        val out = Redaction.testWindowedBodyStage(body, budgetMs = 0L)

        assertEquals("[REDACTION BUDGET EXCEEDED - ${body.length} CHARS DROPPED AND NOT SENT]", out)
        assertFalse(out.contains("M2N-BUDGET-VALUE-7"), out)
    }

    // A newline past the midpoint is still a line boundary: the cut lands just after it, so both
    // halves stay line-aligned.
    @Test
    fun splitPointCutsJustAfterTheOnlyNewlineWhenItLiesPastTheMidpoint() {
        val window = "x".repeat(10) + "\n" + "yyy"
        assertTrue(window.lastIndexOf('\n', window.length / 2) < 0, "the newline must lie past the midpoint")

        val cut = Redaction.testSplitPoint(window)

        assertEquals(window.indexOf('\n') + 1, cut)
        assertEquals('\n', window[cut - 1])
    }

    // A cut equal to window.length would make dropOrRetry drop the window on its
    // `cut >= window.length` limb; a trailing newline is unusable, so the safe-cut fallback must
    // return an index strictly inside the window.
    @Test
    fun splitPointNeverCutsAtTheEndOfAWindowWhoseOnlyNewlineIsItsLastCharacter() {
        val window = "x".repeat(10) + "\n"
        assertTrue(window.none { it in TERMINATORS_MIRROR }, "no terminator may move the cut off mid")

        val cut = Redaction.testSplitPoint(window)

        assertTrue(cut > 0 && cut < window.length, "cut $cut must be strictly inside the window")
        assertEquals(window.length / 2, cut)
    }

    // 0 is what makes dropOrRetry drop a window too short to split behind a marker instead of
    // recursing on it forever.
    @Test
    fun splitPointRefusesAWindowTooShortToSplit() {
        assertEquals(0, Redaction.testSplitPoint(""))
        assertEquals(0, Redaction.testSplitPoint("x"))
        assertEquals(0, Redaction.testSplitPoint("\n"))
    }

    // A newline-free prose window is cut just after whitespace, which no built-in body rule's
    // match can span, rather than at the bare midpoint.
    @Test
    fun splitPointCutsANewlineFreeProseWindowJustAfterWhitespace() {
        val window = "abcdefg ".repeat(10)
        val mid = window.length / 2
        assertFalse(window.contains('\n'), "the window must be newline-free")
        assertTrue(window.none { it in TERMINATORS_MIRROR }, "only the whitespace limb may move the cut")
        assertFalse(window[mid].isWhitespace(), "the midpoint itself must not be whitespace")

        val cut = Redaction.testSplitPoint(window)

        assertEquals(window.indexOf(' ', mid) + 1, cut)
        assertEquals(' ', window[cut - 1])
    }

    // An over-width line is never cut mid-line: it becomes its own window, ending just after its
    // newline, and is not merged with what follows.
    @Test
    fun windowEndKeepsAnOverWidthLineWholeAndEndsJustAfterIt() {
        val s = "x".repeat(30) + "\n" + "tail\n" + "more\n"

        assertEquals(s.indexOf('\n') + 1, Redaction.testWindowEnd(s, 0, 10))

        val noNewline = "x".repeat(30)
        assertEquals(noNewline.length, Redaction.testWindowEnd(noNewline, 0, 10))
    }

    // A key whose value is the unterminated last line pulls the rest of the input into the window,
    // so the key and its value are scanned together.
    @Test
    fun windowEndPullsTheRestOfTheInputWhenAKeysValueIsTheUnterminatedLastLine() {
        val value = "\"M2N-TAIL-VALUE\""
        val s = FILLER + KEY + "\n" + value
        val natural = FILLER.length + KEY.length + 1
        assertBoundaryGeometry(s, natural)

        val control = FILLER + "y".repeat(KEY.length) + "\n" + value
        assertBoundaryGeometry(control, natural)
        assertEquals(natural, Redaction.testWindowEnd(control, 0, natural))

        assertEquals(s.length, Redaction.testWindowEnd(s, 0, natural))
    }

    // The blank-line walk-back never crosses the window start, so this window's boundary decision
    // stays independent of earlier windows.
    @Test
    fun windowEndBlankLineWalkBackNeverCrossesTheWindowStart() {
        val s = KEY + "\n" + "\n" + "\n" + FILLER + FILLER
        val start = KEY.length + 1
        assertBoundaryGeometry(s, start + 2)

        assertEquals(start + 2, Redaction.testWindowEnd(s, start, 2))

        // Control: with the key inside the window, the same blank run does start an extension, so
        // the real case stopped because of the window start and not for lack of a key.
        assertEquals(start + 2 + FILLER.length, Redaction.testWindowEnd(s, 0, start + 2))
    }

    // The backward scan over a target-controlled blank run is bounded by the lookahead cap. A pair
    // spread over more blank lines than the cap is the residual already recorded next to
    // MAX_JSON_BOUNDARY_LOOKAHEAD_LINES (ADR-14); this test pins that bound and does not widen it.
    @Test
    fun windowEndBlankLineWalkBackIsBoundedByTheLookaheadCap() {
        fun fixture(b: Int) = FILLER + KEY + "\n" + "\n".repeat(b) + FILLER + FILLER

        fun natural(b: Int) = FILLER.length + KEY.length + 1 + b

        val atCap = CAP_MIRROR
        assertBoundaryGeometry(fixture(atCap), natural(atCap))
        assertEquals(natural(atCap) + FILLER.length, Redaction.testWindowEnd(fixture(atCap), 0, natural(atCap)))

        val pastCap = CAP_MIRROR + 1
        assertBoundaryGeometry(fixture(pastCap), natural(pastCap))
        assertEquals(natural(pastCap), Redaction.testWindowEnd(fixture(pastCap), 0, natural(pastCap)))
    }

    // A backslash-escaped quote does not close a value: a line whose naive quote count is even but
    // whose unescaped count is odd ends inside an open value, so the boundary is extended.
    @Test
    fun windowEndTreatsABackslashEscapedQuoteAsInsideAnOpenValue() {
        val line = "\"password\": \"a" + '\\' + "\"b"
        assertEquals(17, line.length)
        assertEquals(4, line.count { it == '"' })
        assertEquals(1, line.count { it == '\\' })
        assertFalse(line.trimEnd().endsWith(":") || line.trimEnd().endsWith("\""), line)

        val s = FILLER + line + "\n" + FILLER + FILLER
        val natural = FILLER.length + line.length + 1
        assertBoundaryGeometry(s, natural)
        assertEquals(natural + FILLER.length, Redaction.testWindowEnd(s, 0, natural))

        val closedLine = "\"password\": \"a\"b"
        assertEquals(4, closedLine.count { it == '"' })
        assertEquals(0, closedLine.count { it == '\\' })
        val control = FILLER + closedLine + "\n" + FILLER + FILLER
        val controlNatural = FILLER.length + closedLine.length + 1
        assertBoundaryGeometry(control, controlNatural)
        assertEquals(controlNatural, Redaction.testWindowEnd(control, 0, controlNatural))
    }

    private companion object {
        // 19 'y' plus '\n': a plain, risk-free line.
        val FILLER = "y".repeat(19) + "\n"

        // The 11-char key line `"password":`, which ends where a JSON pair is still in flight.
        const val KEY = "\"password\":"

        // Mirrors Redaction.MAX_JSON_BOUNDARY_LOOKAHEAD_LINES.
        const val CAP_MIRROR = 8

        // Mirrors Redaction.SAFE_CUT_TERMINATORS.
        const val TERMINATORS_MIRROR = "&,}]"

        // Anti-vacuity: the natural cut sits just past a newline and on a non-newline character, so
        // lastIndexOf('\n', hard) lands on the boundary newline under test.
        fun assertBoundaryGeometry(
            s: String,
            natural: Int,
        ) {
            assertTrue(natural in 1 until s.length, "natural cut $natural must be inside the input")
            assertEquals('\n', s[natural - 1], "the natural cut must follow a newline")
            assertTrue(s[natural] != '\n', "the character at the natural cut must not be a newline")
        }
    }
}
