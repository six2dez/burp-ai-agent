package com.six2dez.burp.aiagent.redact

import com.six2dez.burp.aiagent.config.Defaults
import com.six2dez.burp.aiagent.scanner.COOKIES_MAX_COUNT
import com.six2dez.burp.aiagent.scanner.COOKIES_MAX_COUNT_INTENDED
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import java.util.concurrent.CopyOnWriteArrayList

// RFC 5869 Test Case 1 inputs/outputs for the HKDF vector test.
// Source: https://www.rfc-editor.org/rfc/rfc5869 Appendix A.1
private object Rfc5869TestCase1 {
    // IKM = 22 bytes of 0x0b
    val ikm: ByteArray = ByteArray(22) { 0x0b.toByte() }

    // salt = 0x000102...0c (13 bytes)
    val salt: ByteArray = ByteArray(13) { i -> i.toByte() }

    // info = 0xf0f1...f9 (10 bytes)
    val info: ByteArray = ByteArray(10) { i -> (0xf0 + i).toByte() }

    // RFC 5869 names this output length L; the const keeps the RFC's own notation.
    const val L = 42

    // Expected PRK (HMAC-SHA256 of salt over IKM):
    // 077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5
    val expectedPrk: ByteArray =
        byteArrayOf(
            0x07,
            0x77,
            0x09,
            0x36,
            0x2c,
            0x2e,
            0x32,
            0xdf.toByte(),
            0x0d,
            0xdc.toByte(),
            0x3f,
            0x0d,
            0xc4.toByte(),
            0x7b,
            0xba.toByte(),
            0x63,
            0x90.toByte(),
            0xb6.toByte(),
            0xc7.toByte(),
            0x3b,
            0xb5.toByte(),
            0x0f,
            0x9c.toByte(),
            0x31,
            0x22,
            0xec.toByte(),
            0x84.toByte(),
            0x4a,
            0xd7.toByte(),
            0xc2.toByte(),
            0xb3.toByte(),
            0xe5.toByte(),
        )

    // Expected OKM (first 42 bytes):
    // 3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf
    // 34007208d5b887185865
    val expectedOkm: ByteArray =
        byteArrayOf(
            0x3c,
            0xb2.toByte(),
            0x5f,
            0x25,
            0xfa.toByte(),
            0xac.toByte(),
            0xd5.toByte(),
            0x7a,
            0x90.toByte(),
            0x43,
            0x4f,
            0x64,
            0xd0.toByte(),
            0x36,
            0x2f,
            0x2a,
            0x2d,
            0x2d,
            0x0a,
            0x90.toByte(),
            0xcf.toByte(),
            0x1a,
            0x5a,
            0x4c,
            0x5d,
            0xb0.toByte(),
            0x2d,
            0x56,
            0xec.toByte(),
            0xc4.toByte(),
            0xc5.toByte(),
            0xbf.toByte(),
            0x34,
            0x00,
            0x72,
            0x08,
            0xd5.toByte(),
            0xb8.toByte(),
            0x87.toByte(),
            0x18,
            0x58,
            0x65,
        )
}

// (PRIV-05) SC3: the single sentinel value used by the whole sensitive-key corpus. It is chosen so
// it matches NO other redaction rule — not bearer-prefixed, not basic-prefixed, does not start with
// "eyJ" and contains no '=' — so its disappearance is attributable to the sensitive-key expression
// alone and to nothing else in the pipeline.
private const val SC3_SENTINEL = "SENTINEL-VALUE-9F2A7C"

// (PRIV-05) W-06 / Pitfall 7: a key expression carrying NO capturing group, substituted into each
// consumer template so the template's own capturing-group count can be measured rather than
// remembered. Its value is irrelevant beyond having no parentheses in it.
private const val GROUP_FREE_KEY_EXPR = "x"

// (PRIV-05) W-06 / Pitfall 7: a $n group reference in a replacement string. The negative lookbehind
// excludes an escaped \$, which is a literal dollar sign and not a reference.
private val GROUP_REFERENCE_REGEX = Regex("(?<!\\\\)[$](\\d+)")

// (PRIV-05) W-06: one shipped consumer of SENSITIVE_KEY_EXPR, as the equivalence test needs it —
// the template that rebuilds the rule around ANY key expression, the replacement the NAIVE side
// applies, and the document shape the rule is anchored for. Held together in one object so a
// consumer cannot be half-added: a template with no matching document shape would compare a rule
// against a document it was never anchored for and agree vacuously.
private class KeyRuleContext(
    val rule: (String) -> Regex,
    val naiveReplacement: String,
    val document: (String) -> String,
)

// (PRIV-06) D-03: the injected clock for the truncation-notice window. Named constants rather than
// inline literals so the relationship to the 10 s window is readable: T_INSIDE_WINDOW is 5 s after
// T0 and must be suppressed, T_AFTER_WINDOW is 11 s after T0 and must emit. Nothing here sleeps.
private const val T0 = 1_000_000L
private const val T_INSIDE_WINDOW = 1_005_000L
private const val T_AFTER_WINDOW = 1_011_000L

// (PRIV-06) CR-02 / WR-06: parameters of the shifted-fixture sweep below. Named rather than inlined
// so the relationship between them is the argument, not a coincidence of three literals.
//
// PAD_LINE_CHARS is the length of one filler line, and therefore the PERIOD of the pair's alignment
// against the deterministic window cut: shifting the pair by PAD_LINE_CHARS characters reproduces
// the same alignment one line later. BOUNDARY_SWEEP_SHIFTS is one full period plus slack, so every
// possible alignment is exercised at least once rather than an arbitrary number of them. The
// reviewer's reproduced counterexample sits at shift 7, well inside the first period.
private const val PAD_LINE_CHARS = 20
private const val BOUNDARY_SWEEP_SHIFTS = 24

// How far past the window width the fixture runs, so the pair is followed by a genuine second
// window rather than sitting at the very end of the input.
private const val SWEEP_TAIL_CHARS = 800

// (PRIV-06) CR-04 / T-21-33 / W-04: parameters of the newline-free oversize fixture below.
//
// A newline-free body becomes exactly ONE window at any size, because windowEnd gives an over-width
// line its own window and a body with no '\n' is a single line. The multiplier therefore does not
// control how many windows there are, only how large that one window is.
//
// THE WALL-CLOCK LOWER/UPPER BOUND ARGUMENT IS RETIRED. This fixture used to be sized between two
// clock-dependent bounds: large enough that the single pass overran the former per-rule wall clock
// (so the ladder engaged), small enough that the deepest piece then scanned inside it. Both bounds
// moved with machine speed and JaCoCo, and a rule that got more expensive once pushed the upper one
// under a 4x fixture, destroying it on every run. The per-rule bound is now a deterministic access
// budget, and newlineFreeOversizeBodyIsScannedNotDestroyed FORCES the ladder by injecting it (see
// NEWLINE_FREE_LADDER_EXHAUST_ABOVE), so which depths exhaust and which scan is arithmetic.
//
// WHY 1x: speed. Any size above the window width exercises the same wiring, and 1x is the cheapest.
//
// THE FORMER ~3 MB NEWLINE-FREE CEILING NO LONGER APPLIES to the built-in rules. It was the ladder's
// reach under a fixed per-rule wall clock: 2^WINDOW_RETRY_MAX_DEPTH times what one call could scan.
// Under a length-proportional access budget a newline-free window of any size scans in ONE pass
// with the built-in rules, and only the 2 s stage budget bounds it.
private const val NEWLINE_FREE_WINDOW_MULTIPLIER = 1

// (PRIV-06) W-04 / T-21-52: the total body-stage budget injected into Redaction.testWindowedBodyStage
// by newlineFreeOversizeBodyIsScannedNotDestroyed.
//
// THE ARITHMETIC, so this is a derivation rather than a round number. Driven through the seam - which
// bypasses the header stage entirely - with the ladder forced to depth 2, the fixture's windowed body
// stage measured about 110 ms on Apple Silicon / JDK 21 with the JaCoCo agent attached. 60 000 ms is
// therefore several hundred times that run: the budget cannot be reached on any machine this project
// targets, including a CI runner an order of magnitude slower and instrumented on top of that.
//
// WHY AN INJECTED BUDGET IS NEEDED AT ALL: under the former per-rule wall clock this stage measured
// 591-779 ms against the shipped 2 000 ms, UNDER this phase's own 3x bar for a wall-clock-dependent
// assertion. Injecting a total budget far above any run keeps the stage clock out of the outcome.
//
// IT IS NOT Defaults.MAX_REDACTION_BUDGET_MS AND MUST NEVER BE SET FROM IT. The shipped 2 s budget is
// a product decision (2 s covers tens of megabytes on a background scanner thread) and is untouched by
// this test; this number exists so the assertions below measure SCANNING BEHAVIOUR rather than machine
// speed. Raising the shipped constant to make an assertion pass is the move this seam exists to make
// unnecessary.
private const val NEWLINE_FREE_INJECTED_BUDGET_MS = 60_000L

// (PRIV-06) W-04: the piece length above which newlineFreeOversizeBodyIsScannedNotDestroyed injects
// a per-rule access budget of 0. The fixture is 1 000 021 characters, so depth 0 (the whole body)
// and depth 1 (~500 000) exhaust and dropOrRetry must split again; depth 2 (~250 000) gets the
// shipped budget and scans. Arithmetic on the fixture, not a timing: the ladder engages and
// completes at the same depth on every machine.
private const val NEWLINE_FREE_LADDER_EXHAUST_ABOVE = 300_000

// The repeating minified-JSON fragment. No '=', no whitespace, no newline — the exact shape
// toolJson.encodeToString(...) emits into McpToolContext.redactIfNeeded, which is what makes CR-04
// a default-configuration defect rather than a pathological one. Neither "id" nor "name" is in
// SENSITIVE_WORDS or KNOWN_SESSION_KEYS, so the filler cannot itself produce a "[REDACTED]" and
// create a false positive on the assertions below.
private const val NEWLINE_FREE_FRAGMENT = """{"id":123,"name":"alice"},"""

// The planted pair. "api_key" is in SENSITIVE_WORDS, so jsonSecretKeyRegex reaches it — and nothing
// else in either stage can (see the fixture-reachability note on the test itself).
private const val NEWLINE_FREE_SECRET_PAIR = """{"api_key":"SC4-NEWLINE-SECRET-9"},"""

// (PRIV-06) CR-04: the non-whitespace half of the value-terminating set splitPoint prefers to cut
// just after when a window has no line boundary at all. Mirrored here rather than reached into,
// because the source constant is private to Redaction; the comment on SAFE_CUT_SEARCH_CHARS derives
// this set from the value classes of the three built-in body rules ([^&\s"'<>]+ for the form and
// URL rules, and a '"'-delimited string or a scalar followed by ','/'}'/']' for JSON), and the test
// below asserts that the shipped cut actually lands on it.
private const val SAFE_CUT_TERMINATORS = "&,}]"

// Mirrors Redaction.isSafeCutTerminator so the anti-vacuity guards below can state a fixture's
// misalignment in the same terms the implementation uses, rather than by hand-picking a character.
private fun isSafeCutTerminatorForTest(c: Char): Boolean = c in SAFE_CUT_TERMINATORS || c.isWhitespace()

// (PRIV-06) CR-02 / IN-03: a MIRROR of Redaction.MAX_JSON_BOUNDARY_LOOKAHEAD_LINES, which is private
// and STAYS private — needing to read a constant from a test is not a reason to widen a production
// symbol's visibility. Mirrored exactly the way SAFE_CUT_TERMINATORS above is mirrored, and named
// after its source so that source is findable from here.
//
// A mirror can go stale, so windowEndStopsAtTheJsonBoundaryLookaheadCap does not trust it: it asserts
// the fixture supplies strictly MORE continuing lines than this value, and it compares the observed
// boundary against an offset computed from it. If the real cap is raised, the offset assertion goes
// red rather than the test silently ceasing to reach the cap at all.
private const val LOOKAHEAD_CAP_MIRROR = 8

// (PRIV-06) IN-03: geometry of the windowEnd lookahead-cap fixture, named so the expected boundary
// below is ARITHMETIC over these values rather than a hard-coded index that a fixture edit would
// silently invalidate. Every line is exactly LOOKAHEAD_LINE_CHARS long INCLUDING its newline, which
// is the only reason the arithmetic is this simple.
private const val LOOKAHEAD_LINE_CHARS = 20
private const val LOOKAHEAD_LEAD_LINES = 5

// Strictly greater than LOOKAHEAD_CAP_MIRROR, and asserted to be: the fixture must be able to supply
// MORE continuing lines than the loop is allowed to take, or the test would be satisfied by a
// windowEnd that simply ran out of input — which is a different behaviour with a different branch
// (`if (following < 0) return s.length`).
private const val LOOKAHEAD_CONTINUING_LINES = 9
private const val LOOKAHEAD_TRAIL_LINES = 5

// Two line shapes of identical length, differing only in whether they can carry a JSON pair across a
// boundary. FILLER ends on an ordinary character and holds no quote at all, so it is neither a risk
// (isJsonPairBoundaryRisk) nor an open quoted value (endsInsideOpenQuotedValue). RISKY ends on ':',
// which is the newline-spanning whitespace state between a key and its value.
//
// DELIBERATELY NOT BLANK LINES, and that is load-bearing. A blank line also continues an extension
// (isJsonPairBoundaryContinuation), so a fixture built from blank lines would be guarding the same
// mechanism as jsonPairWithBlankLineBetweenKeyAndValueIsRedacted and both tests would go red on the
// same mutation. Built from ':' lines, this fixture is orthogonal to that one — confirmed by mutation
// M4, which removes the blank-line limb and fails only the blank-line test.
private val LOOKAHEAD_FILLER_LINE = "y".repeat(LOOKAHEAD_LINE_CHARS - 1) + "\n"
private val LOOKAHEAD_RISKY_LINE = "y".repeat(LOOKAHEAD_LINE_CHARS - 2) + ":\n"

// (PRIV-06) CR-04: the minified-JSON fixture for splitPointPrefersASafeCutBoundaryInMinifiedJson.
//
// ITS LENGTH IS LOAD-BEARING, and that is not a theoretical worry — it is a defect this plan's own
// mutation check caught. The first version repeated a 10-character fragment whose exact midpoint
// landed immediately after a ',' by pure arithmetic coincidence. The test then passed against a
// mutation that deleted the forward search entirely and always returned the midpoint: a vacuous test
// of exactly the kind WR-05 exists to stamp out, very nearly shipped inside the plan that closes
// WR-05. Twelve characters times 167 repetitions puts the midpoint of the 2 004-character window
// after a ':' instead, which no terminator set contains, so only a real forward search can satisfy
// the assertion. The guard in the test asserts that misalignment rather than trusting this comment.
private const val SAFE_CUT_JSON_FRAGMENT = """{"kk":"vv"},"""
private const val SAFE_CUT_JSON_REPEATS = 167

// (PRIV-06) CR-04: the line-bearing fixture for splitPointStillCutsAtALineBoundaryWhenOneExists.
//
// THE SPACES AND THE COMMA ARE THE WHOLE POINT, and this too is a defect the mutation checks caught
// rather than a precaution. The first version was a run of hyphenated words with no spaces and no
// commas, so the ONLY safe-cut terminator anywhere in it was the newline itself — '\n' is
// whitespace, and safeCutPoint treats whitespace as a terminator. The test therefore passed against
// a mutation that deleted splitPoint's two line-boundary branches outright and always took the
// character cut, because the forward search then found the newline anyway and the assertion could
// not tell the two paths apart. That mutation is not benign: without the line branches, a window of
// ordinary prose or HTML would be cut at the first SPACE past the midpoint, which is the (?m)^ trap
// reopened in full.
//
// With spaces and a comma present, a naive forward search lands on one of THOSE first, so only the
// backward line search can satisfy the assertion. 26 characters times 41 repetitions also puts the
// midpoint (533) MID-LINE rather than on a line start, so the backward search is genuinely
// exercised instead of being handed a boundary it did not have to look for.
private const val SAFE_CUT_LINE_FIXTURE = "key value, more text here\n"
private const val SAFE_CUT_LINE_REPEATS = 41

// detekt LargeClass, suppressed on the declaration rather than baselined: QUAL-07 forbids growing
// detekt-baseline.xml, and the existing LargeClass entries there are all main-source classes. This
// is the single regression suite for redact/, and its size is the point — the CR-01/CR-03 guards
// added here are only meaningful sitting beside the SC1..SC6 corpus they must not regress. Splitting
// it would scatter the monotonicity canaries across files and make that relationship invisible.
@Suppress("LargeClass")
class RedactionTest {
    @AfterEach
    fun resetCustomPatterns() {
        // Prevent custom-pattern bleed across tests: reset after each test.
        Redaction.setCustomPatterns(emptyList())
    }

    @AfterEach
    fun resetTruncationSignal() {
        // Redaction is a singleton object: a capturing sink left registered here would keep firing
        // on every later test in the shared JVM, and the limiter's window would carry over and make
        // the injected-clock assertions order-dependent.
        Redaction.truncationLogger = null
        Redaction.resetTruncationWindowForTest()
    }

    @Test
    fun strictModeStripsCookiesTokensAndHosts() {
        val input =
            """
            GET / HTTP/1.1
            Host: example.com
            Cookie: a=b
            Authorization: Bearer abc.def.ghi

            """.trimIndent()

        val policy = RedactionPolicy.fromMode(PrivacyMode.STRICT)
        val output = Redaction.apply(input, policy, stableHostSalt = "salt")

        assertTrue(output.contains("Cookie: [STRIPPED]"))
        assertTrue(output.contains("Authorization: [REDACTED]"))
        assertTrue(output.contains("Host: host-"))
    }

    @Test
    fun hostAnonymizationIsStablePerSalt() {
        val a = Redaction.anonymizeHost("example.com", "salt-a")
        val b = Redaction.anonymizeHost("example.com", "salt-a")
        val c = Redaction.anonymizeHost("example.com", "salt-b")

        assertEquals(a, b)
        assertTrue(a != c)
    }

    @Test
    fun balancedModeRedactsCustomAuthHeaders() {
        val input =
            """
            GET / HTTP/1.1
            Host: example.com
            X-Auth-Token: abc123
            X-Access-Token: xyz789
            X-CSRF-Token: csrf123
            X-Api-Secret: secret!
            Authorization: Basic dXNlcjpwYXNz

            """.trimIndent()

        val policy = RedactionPolicy.fromMode(PrivacyMode.BALANCED)
        val output = Redaction.apply(input, policy, stableHostSalt = "salt")

        assertTrue(output.contains("X-Auth-Token: [REDACTED]"), "X-Auth-Token must be redacted")
        assertTrue(output.contains("X-Access-Token: [REDACTED]"), "X-Access-Token must be redacted")
        assertTrue(output.contains("X-CSRF-Token: [REDACTED]"), "X-CSRF-Token must be redacted")
        assertTrue(output.contains("X-Api-Secret: [REDACTED]"), "X-Api-Secret must be redacted")
        assertTrue(output.contains("Authorization: [REDACTED]"), "Authorization header must be redacted")
        assertTrue(!output.contains("abc123") && !output.contains("xyz789") && !output.contains("dXNlcjpwYXNz"))
    }

    // W-A: the five header NAMES the phase verifier actually measured reaching an AI backend verbatim
    // under STRICT and BALANCED. sanitizeHeadersForPrompt admits any header whose lowercased name
    // CONTAINS "cookie", while the two redaction rules anchored on the exact names "cookie:" and
    // "set-cookie:" — so everything in between was admitted and never stripped.
    //
    // FIXTURE REACHABILITY (the whole point of this test — nine vacuous fixtures in this phase came
    // from a value some OTHER rule also caught). Each sentinel is a bare lowercase alphabetic word,
    // so a cookie HEADER rule is the only thing in the pipeline that can remove it:
    //   - no '=' anywhere on the line => formBodyParamRegex ((^|[?&])KEY=...), urlTokenParamRegex
    //     ([?&]KEY=...) and cookieTypedParamRegex (NAME=VALUE (type)) all fail to match;
    //   - the name is unquoted at line start => the JSON rule ("KEY"\s*:\s*VALUE) cannot match, since
    //     '"' is not a header-name character;
    //   - no "Bearer "/"Basic " prefix, no dotted "eyJ" segment => bearerRegex, basicAuthRegex and
    //     jwtRegex all fail to match;
    //   - none of the five names appears in authHeaderRegex's 14-name list, and none of the sentinels
    //     is a name in KNOWN_SESSION_KEYS or otherwise reachable by SENSITIVE_KEY_EXPR (which is only
    //     ever consulted as a KEY immediately followed by '=' or inside quotes);
    //   - the blob carries no "=== COOKIES ===" header => redactCookieSections never runs on it.
    // The argument above is checked by MUTATION, not by inspection: reverting either regex to its
    // exact-name form turns this test red (failure sets recorded in the plan summary).
    //
    // The NAME assertions are load-bearing in their own right. The two cookie rules used FIXED
    // replacement strings, so widening the match alone would have rewritten "X-Cookie: v" into
    // "Cookie: [STRIPPED]" — silently renaming a header in the analyst's view of the traffic
    // (T-21-WA2). X-Request-Id is the negative control: it carries no "cookie" in its name and must
    // survive both modes untouched, which is what distinguishes stripping from blanket header loss.
    @Test
    fun cookieHeaderNameVariantsAreStripped() {
        val input =
            """
            GET / HTTP/1.1
            Host: example.com
            Cookie2: sentinelalphaone
            X-Cookie: sentinelbravotwo
            Set-Cookie2: sentinelcharliethree
            X-Original-Cookie: sentineldeltafour
            X-Forwarded-Cookie: sentinelechofive
            X-Request-Id: benignidcontrolvalue

            """.trimIndent()

        val variants =
            listOf(
                "Cookie2" to "sentinelalphaone",
                "X-Cookie" to "sentinelbravotwo",
                "Set-Cookie2" to "sentinelcharliethree",
                "X-Original-Cookie" to "sentineldeltafour",
                "X-Forwarded-Cookie" to "sentinelechofive",
            )

        for (mode in listOf(PrivacyMode.STRICT, PrivacyMode.BALANCED)) {
            val policy = RedactionPolicy.fromMode(mode)
            val output = Redaction.apply(input, policy, stableHostSalt = "salt")

            for ((header, sentinel) in variants) {
                assertTrue(
                    !output.contains(sentinel),
                    "$mode: the value of $header must not reach the prompt (leaked: $output)",
                )
                assertTrue(
                    output.contains("$header: [STRIPPED]"),
                    "$mode: $header must keep its OWN name, not be renamed to Cookie/Set-Cookie (got: $output)",
                )
            }

            assertTrue(
                output.contains("X-Request-Id: benignidcontrolvalue"),
                "$mode: a header with no 'cookie' in its name must be left untouched (got: $output)",
            )
        }
    }

    @Test
    fun balancedModeRedactsUrlTokensInQueryStrings() {
        val input =
            """
            GET /api/user?api_key=secret123&token=xyz987&name=alice HTTP/1.1
            Host: example.com
            Referer: https://example.com/callback?access_token=ABC.DEF.GHI&state=open

            """.trimIndent()

        val policy = RedactionPolicy.fromMode(PrivacyMode.BALANCED)
        val output = Redaction.apply(input, policy, stableHostSalt = "salt")

        assertTrue(output.contains("api_key=[REDACTED]"), "api_key query param must be redacted")
        assertTrue(output.contains("token=[REDACTED]"), "token query param must be redacted")
        assertTrue(output.contains("access_token=[REDACTED]"), "access_token query param must be redacted")
        assertTrue(output.contains("name=alice"), "non-sensitive params must not be touched")
        assertTrue(!output.contains("secret123") && !output.contains("xyz987") && !output.contains("ABC.DEF.GHI"))
    }

    @Test
    fun offModePreservesAllTokens() {
        val input =
            """
            GET /api?api_key=secret123 HTTP/1.1
            Authorization: Bearer TOKEN
            X-Auth-Token: abc

            """.trimIndent()
        val policy = RedactionPolicy.fromMode(PrivacyMode.OFF)
        val output = Redaction.apply(input, policy, stableHostSalt = "salt")

        assertTrue(output.contains("api_key=secret123"))
        assertTrue(output.contains("Bearer TOKEN"))
        assertTrue(output.contains("X-Auth-Token: abc"))
    }

    @Test
    fun clearMappings_removesOnlyRequestedSaltOrAll() {
        val anonA = Redaction.anonymizeHost("a.example", "salt-a")
        val anonB = Redaction.anonymizeHost("b.example", "salt-b")
        assertEquals("a.example", Redaction.deAnonymizeHost(anonA, "salt-a"))
        assertEquals("b.example", Redaction.deAnonymizeHost(anonB, "salt-b"))

        Redaction.clearMappings("salt-a")
        assertEquals(null, Redaction.deAnonymizeHost(anonA, "salt-a"))
        assertEquals("b.example", Redaction.deAnonymizeHost(anonB, "salt-b"))

        Redaction.clearMappings()
        assertEquals(null, Redaction.deAnonymizeHost(anonB, "salt-b"))
    }

    // PRIV-01: output format test — added for HKDF swap (Task 1 Wave 0 RED)
    @Test
    fun hostAnonymizationFormatIsStable() {
        val result = Redaction.anonymizeHost("example.com", "salt")
        // Assert format only — never hardcode the hex value so the crypto can evolve.
        assertTrue(
            result.matches(Regex("^host-[0-9a-f]{12}\\.local$")),
            "Expected format host-<12hex>.local but got: $result",
        )
    }

    // PRIV-01: RFC 5869 Test Case 1 HKDF vector — proves the HMAC-SHA256 extract/expand
    // math is correct against a published reference vector.
    // Source: https://www.rfc-editor.org/rfc/rfc5869 Appendix A.1
    @Test
    fun hkdfMatchesRfc5869Vector() {
        // Access the internal HKDF helpers via the test-internal seam exposed on Redaction.
        val prk = Redaction.testHkdfExtract(Rfc5869TestCase1.salt, Rfc5869TestCase1.ikm)
        assertEquals(
            Rfc5869TestCase1.expectedPrk.toList(),
            prk.toList(),
            "PRK must match RFC 5869 Test Case 1",
        )

        val okm = Redaction.testHkdfExpand(prk, Rfc5869TestCase1.info, Rfc5869TestCase1.L)
        assertEquals(
            Rfc5869TestCase1.expectedOkm.toList(),
            okm.toList(),
            "OKM must match RFC 5869 Test Case 1",
        )
    }

    // PRIV-02: Leading x-www-form-urlencoded field (no leading ?/&) must be redacted in STRICT
    // and BALANCED. This is the documented gap: the old [?&]-only urlTokenParamRegex missed the
    // first field of a body like apikey=sk-abc123&user=bob.
    @Test
    fun bodyFormLeadingFieldRedacted() {
        val body = "apikey=sk-abc123&user=bob"

        for (mode in listOf(PrivacyMode.STRICT, PrivacyMode.BALANCED)) {
            val policy = RedactionPolicy.fromMode(mode)
            val output = Redaction.apply(body, policy, stableHostSalt = "salt")
            assertTrue(output.contains("apikey=[REDACTED]"), "$mode: leading form field apikey must be redacted")
            assertTrue(output.contains("user=bob"), "$mode: non-sensitive param user must NOT be touched")
            assertFalse(output.contains("sk-abc123"), "$mode: original secret value must not appear")
        }
    }

    // PRIV-02: Known-sensitive JSON keys must be redacted (key-scoped — only the value under
    // a sensitive key name is replaced). Non-sensitive keys must be left untouched.
    @Test
    fun bodyJsonSecretKeysRedacted() {
        val body = """{"api_key":"sk-xyz","name":"alice","token":"abc"}"""

        for (mode in listOf(PrivacyMode.STRICT, PrivacyMode.BALANCED)) {
            val policy = RedactionPolicy.fromMode(mode)
            val output = Redaction.apply(body, policy, stableHostSalt = "salt")
            assertTrue(output.contains("\"api_key\":\"[REDACTED]\""), "$mode: api_key JSON value must be redacted")
            assertTrue(output.contains("\"token\":\"[REDACTED]\""), "$mode: token JSON value must be redacted")
            assertTrue(output.contains("\"name\":\"alice\""), "$mode: non-sensitive name key must NOT be touched")
            assertFalse(output.contains("sk-xyz"), "$mode: original api_key value must not appear")
            assertFalse(output.contains("\"abc\""), "$mode: original token value must not appear")
        }
    }

    // WR-03: JSON values under a sensitive key that are numeric / boolean / null (not quoted
    // strings) must also be redacted. The old "(key)":"[^"]*" pattern matched only quoted string
    // values, silently leaking numeric secrets such as {"token":12345}. Every redacted value is
    // normalized to the quoted token "[REDACTED]" so the output stays valid JSON.
    @Test
    fun bodyJsonUnquotedSecretValuesRedacted() {
        // token / api_key / secret / sid are in SENSITIVE_KEYS; name / balance are not.
        val body = """{"token":12345,"api_key":true,"secret":null,"sid":-42,"balance":99.5,"name":"alice"}"""

        for (mode in listOf(PrivacyMode.STRICT, PrivacyMode.BALANCED)) {
            val policy = RedactionPolicy.fromMode(mode)
            val output = Redaction.apply(body, policy, stableHostSalt = "salt")
            assertTrue(output.contains("\"token\":\"[REDACTED]\""), "$mode: numeric token value must be redacted")
            assertTrue(output.contains("\"api_key\":\"[REDACTED]\""), "$mode: boolean api_key value must be redacted")
            assertTrue(output.contains("\"secret\":\"[REDACTED]\""), "$mode: null secret value must be redacted")
            assertTrue(output.contains("\"sid\":\"[REDACTED]\""), "$mode: negative-int sid value must be redacted")
            assertTrue(output.contains("\"name\":\"alice\""), "$mode: non-sensitive name key must NOT be touched")
            assertTrue(output.contains("\"balance\":99.5"), "$mode: non-sensitive numeric balance must NOT be touched")
            assertFalse(output.contains("12345"), "$mode: original numeric token must not appear")
        }
    }

    // (PRIV-05) SC3 helpers. One key is rendered into each of the three consumer contexts, so a
    // single corpus exercises urlTokenParamRegex, formBodyParamRegex and jsonSecretKeyRegex —
    // all three are driven by the same shared key expression, so widening it widens all three.
    private fun sc3Query(key: String) = "https://example.com/a?$key=$SC3_SENTINEL&name=alice"

    private fun sc3Form(key: String) = "$key=$SC3_SENTINEL&user=bob"

    private fun sc3Json(key: String) = """{"$key":"$SC3_SENTINEL","name":"alice"}"""

    private fun redactWith(
        input: String,
        mode: PrivacyMode,
    ): String = Redaction.apply(input, RedactionPolicy.fromMode(mode), stableHostSalt = "salt")

    // Context label -> redacted output, so every assertion message can name the exact cell that
    // failed rather than reporting a bare "expected true".
    private fun sc3Contexts(
        key: String,
        mode: PrivacyMode,
    ): Map<String, String> =
        mapOf(
            "query string" to redactWith(sc3Query(key), mode),
            "form body" to redactWith(sc3Form(key), mode),
            "JSON body" to redactWith(sc3Json(key), mode),
        )

    // The benign companion parameter carried by each context. Asserting it survives in the SAME
    // pass that asserts the secret disappeared is what proves the widening stayed key-scoped
    // instead of degrading into a blanket rule (T-21-06).
    private val sc3Survivors =
        mapOf(
            "query string" to "name=alice",
            "form body" to "user=bob",
            "JSON body" to "\"name\":\"alice\"",
        )

    // (PRIV-05) SC3 / D-11: the 31 key names whose value MUST be redacted. The first 18 were
    // measured as passing through UNREDACTED in STRICT and BALANCED before the key expression
    // landed — that is the PRIV-05 defect class. The remaining 13 already redacted and are carried
    // here as the monotonicity half: the widening must not take any of them away.
    private val sc3MustRedactKeys =
        listOf(
            // Previously missed: compound, separator-delimited and vendor key names.
            "auth_token",
            "api-key",
            "X-Session-Id",
            "api.key",
            "session_id",
            "_csrf",
            "connect.sid",
            "remember_me",
            "JSESSIONID",
            "PHPSESSID",
            "csrftoken",
            "ASP.NET_SessionId",
            "laravel_session",
            "user_api_key",
            "x-auth-token",
            "auth-token",
            "access-token",
            "XSRF-TOKEN",
            // Already redacted before the change — must still redact after it.
            "access_token",
            "api_key",
            "apikey",
            "auth",
            "token",
            "key",
            "secret",
            "password",
            "pwd",
            "session",
            "sid",
            "code",
            "SESSION",
        )

    // (PRIV-05) SC3: the 21 benign key names whose value must survive untouched.
    private val sc3BenignKeys =
        listOf(
            "keyboard_layout",
            "codename",
            "sidebar",
            "keychain",
            "passwordless_enabled",
            "description",
            "codes",
            "tokenizer",
            "monkey",
            "broken",
            "secretary",
            "authority",
            "encoded",
            "decode_me",
            "username",
            "name",
            "email",
            "q",
            "page",
            "filename",
            "locale",
        )

    // (PRIV-05) WR-01: the 32 broad-word key names that MUST survive after the narrowing.
    //
    // These are a SEPARATE corpus from sc3BenignKeys on purpose. The 31/21/8 SC3 corpora are the
    // record of what plan 21-04 measured, and ADR-14 and CONCERNS.md both cite those sizes by name;
    // folding WR-01's names into them would rewrite a historical measurement rather than add to it.
    // Both corpora run through the same sc3Contexts helper, so the coverage is identical.
    //
    // The first 28 are the code-review's measured over-redaction list. The last four —
    // key_size, code_version, codeName and keyName — were four of the TEN accepted over-redactions
    // recorded in Redaction.kt before WR-01; they are broad-word driven, so the narrowing freed
    // them and they move from "accepted" to "must not redact".
    //
    // public_key and publicKey sit here because the maintainer-confirmed CREDENTIAL_PREFIXES set
    // does not contain 'public'. That is the deliberate reading of the ruling, not an executor
    // judgement call: a public key is publishable by definition. If that is ever revisited, the
    // change is visible here rather than silent.
    private val wr01BroadWordBenignKeys =
        listOf(
            // The names the analysis prompt cannot function without.
            "status_code",
            "error_code",
            "response_code",
            "http_code",
            "statusCode",
            "errorCode",
            // Ordinary business vocabulary that merely contains 'code'.
            "zip_code",
            "country_code",
            "postal_code",
            "currency_code",
            "language_code",
            "product_code",
            "promo_code",
            "coupon_code",
            "area_code",
            "qr_code",
            // Ordinary storage/indexing vocabulary that merely contains 'key'.
            "primary_key",
            "foreign_key",
            "sort_key",
            "partition_key",
            "cache_key",
            "idempotency_key",
            "row_key",
            "sortKey",
            "cacheKey",
            "zipCode",
            "public_key",
            "publicKey",
            // Formerly ACCEPTED over-redactions, freed by the narrowing.
            "key_size",
            "code_version",
            "codeName",
            "keyName",
        )

    // (PRIV-05) WR-01: the 24 broad-word key names that MUST STILL redact. This is the half that
    // matters — the narrowing is the dangerous direction, and under-redaction is the failure mode
    // that ships a leak. Two mechanisms are covered: whole-key equality ('key', 'code' — which have
    // no code of their own and rely entirely on each consumer's anchors) and the CREDENTIAL_PREFIXES
    // path in every separator shape the prefix rule admits, including the no-separator camelCase
    // and all-lowercase forms.
    private val wr01CredentialBroadWordKeys =
        listOf(
            // Whole-key equality. Also carried in sc3MustRedactKeys; asserted here too because this
            // is the corpus a future narrowing would be measured against.
            "key",
            "code",
            // 'api' prefix, every separator shape.
            "api_key",
            "api-key",
            "api.key",
            "apiKey",
            "apikey",
            "x_api_key",
            "user_api_key",
            // The remaining six confirmed prefixes.
            "access_code",
            "access-key",
            "accessKey",
            "secret_key",
            "secretKey",
            "auth_code",
            "authKey",
            "private_key",
            "privateKey",
            "signing_key",
            "signingKey",
            "enc_key",
            "encKey",
            // No separator at all: these two did NOT redact before WR-01, because 'key'/'code' were
            // preceded by an alphanumeric and D-11's boundary rejected them. They are a small gain
            // in the fail-safe direction rather than a cost.
            "accesscode",
            "authcode",
        )

    // (PRIV-05) WR-01: names the code review measured as over-redacted that the narrowing does NOT
    // reach, asserted AS ACCEPTED so the limit of the decision is visible rather than assumed.
    //
    // Every one of these is driven by 'auth', 'session' or 'token' — words the WR-01 ruling left
    // alone, because it narrowed 'key' and 'code' only. token_type and tokenType are the painful
    // pair: token_type: "Bearer" is benign OAuth metadata and the plan's own text expects it to
    // survive, but it cannot without either a suffix denylist (which D-12 rejects on principle, as
    // every entry is a place a real credential could be allowlisted) or a narrowing of 'token'
    // itself, which would put access-token and XSRF-TOKEN at risk. Both are maintainer decisions.
    // Pinned here so the gap is asserted, dated and discoverable instead of being rediscovered.
    private val wr01AcceptedOverRedactions =
        listOf(
            "token_type",
            "tokenType",
            "session_count",
            "auth_type",
            "auth_url",
        )

    // (PRIV-05) SC3 / D-11: real-world sensitive key names must have their value redacted in all
    // three consumer contexts, under STRICT and BALANCED.
    //
    // Before the key expression, a key had to be EXACTLY one of the twelve vocabulary words. That
    // is why auth_token missed (auth was followed by '_', not '='), why only a cookie literally
    // named "session" was caught, and why JSESSIONID, PHPSESSID, connect.sid, csrftoken,
    // remember_me, api-key and X-Session-Id all reached the backend verbatim.
    //
    // Each iteration also asserts the context's benign companion survives, so a regression that
    // "fixes" this test by redacting everything fails it instead.
    @Test
    fun sensitiveKeyNamesRedacted() {
        assertEquals(31, sc3MustRedactKeys.size, "SC3 must-redact corpus must stay at 31 keys")

        for (mode in listOf(PrivacyMode.STRICT, PrivacyMode.BALANCED)) {
            for (key in sc3MustRedactKeys) {
                for ((context, output) in sc3Contexts(key, mode)) {
                    assertFalse(
                        output.contains(SC3_SENTINEL),
                        "$mode / $context: the value of sensitive key '$key' must be redacted",
                    )
                    assertTrue(
                        output.contains(sc3Survivors.getValue(context)),
                        "$mode / $context: benign companion must survive alongside '$key'",
                    )
                }
            }
        }
    }

    // (PRIV-05) SC3 / D-12: this is a REGRESSION GUARD on the new mechanism, NOT a fix.
    //
    // keyboard_layout and codename are NOT over-redacted today and never were: formBodyParamRegex's
    // (^|[?&])…= already delimits the word on both sides, so the exact-word alternation could not
    // match them either. These assertions are therefore green BEFORE and AFTER the key expression
    // landed, by design. Phase 20's SC4 discipline says a test green on both sides has tested
    // nothing, so this one is explicitly labelled a guard rather than counted as evidence of a fix;
    // a task framed as "stop over-redacting keyboard_layout" would have been a no-op.
    //
    // What it does buy: the widening is the moment these could START failing, and the 21 keys below
    // are the standing proof that it did not happen. This is also why no benign-key denylist exists
    // in Redaction.kt (D-12) — there was measurably nothing to guard against.
    @Test
    fun benignKeyNamesNotRedacted() {
        assertEquals(21, sc3BenignKeys.size, "SC3 must-not-redact corpus must stay at 21 keys")

        for (key in sc3BenignKeys) {
            for ((context, output) in sc3Contexts(key, PrivacyMode.STRICT)) {
                assertTrue(
                    output.contains(SC3_SENTINEL),
                    "STRICT / $context: the value of benign key '$key' must NOT be redacted",
                )
            }
        }
    }

    // (PRIV-05) WR-01: the narrowing decision, pinned in the direction it went.
    //
    // Plan 21-04's SENSITIVE_KEY_EXPR let the two broadest vocabulary words, 'key' and 'code',
    // take part in D-11's free containment rule. The Phase 21 code review drove the live
    // formBodyParamRegex and jsonSecretKeyRegex over a wider corpus and measured the resulting
    // class: 32 names, including status_code, error_code, statusCode and errorCode. That is not a
    // cosmetic over-redaction — {"statusCode": 401, "errorCode": "AUTH_FAILED"} reached the
    // analysis prompt as two [REDACTED] tokens while the model was being asked to find an
    // authentication flaw, which is a functional regression in a passive vulnerability scanner.
    //
    // The maintainer ruled on 2026-08-12 to narrow (option-b): 'key' and 'code' now require either
    // whole-key equality or one of the confirmed CREDENTIAL_PREFIXES. This test is the assertion of
    // that ruling. It is deliberately BOTH directions in one place, because the narrowing is a
    // LOOSENING of a security pattern under CONCERNS.md's tightening protocol, and a corpus that
    // only asserted the names that now survive would let the credential half rot silently.
    @Test
    fun wr01BroadWordKeysSurviveUnlessCredentialBearing() {
        assertEquals(32, wr01BroadWordBenignKeys.size, "WR-01 must-not-redact corpus must stay at 32 keys")
        assertEquals(24, wr01CredentialBroadWordKeys.size, "WR-01 must-redact corpus must stay at 24 keys")

        for (key in wr01BroadWordBenignKeys) {
            for ((context, output) in sc3Contexts(key, PrivacyMode.STRICT)) {
                assertTrue(
                    output.contains(SC3_SENTINEL),
                    "STRICT / $context: WR-01 narrowed the broad words, so '$key' must NOT be redacted",
                )
            }
        }

        // The direction that ships a leak if it regresses, so it runs in BALANCED as well as
        // STRICT, and asserts the benign companion survives in the same pass — a mutation that
        // "passes" this half by redacting everything fails it instead.
        for (mode in listOf(PrivacyMode.STRICT, PrivacyMode.BALANCED)) {
            for (key in wr01CredentialBroadWordKeys) {
                for ((context, output) in sc3Contexts(key, mode)) {
                    assertFalse(
                        output.contains(SC3_SENTINEL),
                        "$mode / $context: credential-bearing broad-word key '$key' must STILL be redacted",
                    )
                    assertTrue(
                        output.contains(sc3Survivors.getValue(context)),
                        "$mode / $context: benign companion must survive alongside '$key'",
                    )
                }
            }
        }
    }

    // (PRIV-05) W-06: the three consumer TEMPLATES, parameterised by the key expression they embed.
    //
    // The anchors are copied from the shipped declarations in Redaction.kt, not from 21-REVIEW-2's
    // §W-06 §Fix. The two agree exactly — checked character by character against the compiled
    // patterns, and recorded rather than assumed, because a naive side copied from a review would
    // guard the review instead of the code.
    //
    // Parameterising by the key expression is what makes the Pitfall 7 assertion derivable: the same
    // template built around a group-free placeholder yields the capturing-group count each
    // consumer's replacement string numbering actually depends on, with no hard-coded 2 anywhere.
    private fun urlRuleFor(keyExpr: String) = Regex("(?i)([?&](?:$keyExpr)=)[^&\\s\"'<>]+")

    private fun formRuleFor(keyExpr: String) = Regex("(?im)(^|[?&])($keyExpr)=[^&\\s\"'<>]+")

    private fun jsonRuleFor(keyExpr: String) = Regex("(?i)(\"$keyExpr\"\\s*:\\s*)(\"[^\"]*\"|true|false|null|-?\\d+(?:\\.\\d+)?)")

    // (PRIV-05) W-06: the naive side of the equivalence comparison, keyed by the SAME label
    // Redaction.testKeyRules() reports, so the two are paired by name rather than by position.
    //
    // The naive replacement strings are written HERE rather than borrowed from the seam on purpose.
    // If both sides used the shipped replacement, a drifted replacement would cancel out and be
    // invisible; written independently, the output-equality assertion below pins all three shipped
    // replacements as a side effect.
    private val naiveConsumerContexts: Map<String, KeyRuleContext> =
        mapOf(
            "urlTokenParamRegex" to KeyRuleContext(::urlRuleFor, "\$1[REDACTED]") { sc3Query(it) },
            "formBodyParamRegex" to KeyRuleContext(::formRuleFor, "\$1\$2=[REDACTED]") { sc3Form(it) },
            "jsonSecretKeyRegex" to KeyRuleContext(::jsonRuleFor, "\$1\"[REDACTED]\"") { sc3Json(it) },
        )

    // (PRIV-05) W-06: every key name any corpus in this file mentions, plus the camelCase and
    // accepted-over-redaction names that exercise the boundary rules. Hoisted out of the test body
    // so the anti-vacuity guard and the loop can be shown to measure the same list.
    private val equivalenceCorpus =
        sc3MustRedactKeys + sc3BenignKeys + wr01BroadWordBenignKeys +
            wr01CredentialBroadWordKeys + wr01AcceptedOverRedactions +
            listOf(
                "authToken",
                "accessToken",
                "userSessionId",
                "tokenCount",
                "keyboardLayout",
                "monkeyBars",
                "token_bucket_size",
                "session_timeout_seconds",
                "auth_provider",
                "secret_santa",
                "password_hint_enabled",
                "abtest_bucket",
                "stripe_key",
                "encrypted_key",
                "myapi_key",
            )

    // (PRIV-05) W-06 / Pitfall 7: the highest $n a replacement string references, derived from the
    // string itself so that nobody has to remember to update a hard-coded number — a hard-coded
    // expectation would have to be edited by whoever breaks the invariant, which is the wrong
    // direction of pressure. The negative lookbehind skips an escaped \$, which is a literal dollar
    // rather than a group reference.
    private fun maxGroupReference(replacement: String): Int = GROUP_REFERENCE_REGEX.findAll(replacement).map { it.groupValues[1].toInt() }.maxOrNull() ?: 0

    private fun capturingGroupCount(rule: Regex): Int = rule.toPattern().matcher("").groupCount()

    // (PRIV-05) WR-01 / W-06 / T-21-38 / T-21-57 / T-21-58: the shipped SENSITIVE_KEY_EXPR is
    // hand-factored by first letter for a measured reason (see SENSITIVE_KEY_WORDS in Redaction.kt:
    // the unfactored WR-01 vocabulary cost +16% on the dominant JSON rule and exhausted the body
    // stage's 2 s budget on the 4 MB newline-free fixture). Hand-factoring a security-critical
    // alternation is exactly the kind of change that looks right and is subtly wrong, so it is
    // CHECKED here rather than trusted. Redaction.naiveKeyExprForTest() is the same expression built
    // straight from the readable SENSITIVE_WORDS / CREDENTIAL_PREFIXES / BROAD_WORDS constants.
    //
    // WHAT THIS GUARDS, AND WHAT THE PREVIOUS FORM DID NOT (W-06).
    // Until now the comparison was ASYMMETRIC: one naive JSON rule on the left, redactWith(doc,
    // STRICT) — the WHOLE pipeline — on the right. authHeaderRegex, bearerRegex, basicAuthRegex,
    // jwtRegex, the other two key consumers, both cookie rules and any custom pattern all run in
    // there, and ANY of them firing marked the input "redacted" and could MASK an under-match in the
    // factored form. Eight other rules were free to answer for the one under test. It also exercised
    // ONE of the three consumers, while the same expression is embedded behind three different
    // anchors — so a factoring error could be invisible in the JSON rule and live in the form rule.
    //
    // The comparison is now RULE FOR RULE, IN EVERY CONTEXT THE EXPRESSION IS EMBEDDED IN. For each
    // key and each consumer the naive rule and the shipped rule are applied to the same document
    // with their own replacement strings, and both the classification AND the full output must
    // agree. Nothing here may call redactWith or Redaction.apply: reintroducing the pipeline is the
    // defect, not a convenience.
    //
    // THIS IS A STRENGTHENING OF THE GUARD, NOT A FIX TO THE CODE IT GUARDS. The 21-REVIEW-2
    // re-review ran a differential fuzz of the shipped expression against the naive one — 400 000
    // random keys across all three consumer contexts, 500 000 additional camelCase-heavy keys, and
    // an exhaustive sweep of every key of length <= 4 over a 14-character alphabet — and found ZERO
    // divergences, with matching group counts. A future reader must not read this rewrite as
    // evidence that the shipped vocabulary was ever wrong.
    @Test
    fun factoredKeyVocabularyMatchesItsReadableSpecification() {
        val naiveKeyExpr = Redaction.naiveKeyExprForTest()
        val shippedRules = Redaction.testKeyRules()

        // Coverage asserted rather than assumed: a seam that dropped or renamed a consumer would
        // otherwise make a third of this test vanish in silence.
        assertEquals(
            naiveConsumerContexts.keys,
            shippedRules.map { it.first }.toSet(),
            "testKeyRules() must expose exactly the three consumers this test builds naive rules for",
        )

        // The anti-vacuity guard now measures the list the loop ACTUALLY iterates. It used to
        // measure `corpus` while the loop ran `corpus.distinct()`, so it bounded neither.
        val corpus = equivalenceCorpus.distinct()
        assertTrue(
            corpus.size > 100,
            "The equivalence corpus must be substantial; ${equivalenceCorpus.size} entries, ${corpus.size} distinct",
        )

        var comparisons = 0
        for ((label, shippedRule, shippedReplacement) in shippedRules) {
            val context = naiveConsumerContexts.getValue(label)
            val naiveRule = context.rule(naiveKeyExpr)
            comparisons += compareRuleForRule(label, corpus, context, naiveRule, shippedRule, shippedReplacement)
            assertGroupNumberingPinned(label, context, naiveRule, shippedRule, shippedReplacement)
        }

        assertEquals(
            corpus.size * naiveConsumerContexts.size,
            comparisons,
            "Every corpus key must have been compared in every consumer context",
        )
    }

    // (PRIV-05) W-06: the like-for-like half — one rule on each side, same document, same context.
    // Returns the number of comparisons made so the caller can assert the loop was not vacuous.
    private fun compareRuleForRule(
        label: String,
        corpus: List<String>,
        context: KeyRuleContext,
        naiveRule: Regex,
        shippedRule: Regex,
        shippedReplacement: String,
    ): Int {
        var comparisons = 0
        for (key in corpus) {
            val doc = context.document(key)
            val naiveOut = naiveRule.replace(doc, context.naiveReplacement)
            val shippedOut = shippedRule.replace(doc, shippedReplacement)
            assertEquals(
                !naiveOut.contains(SC3_SENTINEL),
                !shippedOut.contains(SC3_SENTINEL),
                "$label: the factored vocabulary must classify '$key' exactly as the readable specification does",
            )
            // Stronger than the classification above and free: byte-identical output also catches a
            // renumbered group or a drifted replacement string, neither of which changes whether the
            // sentinel survives.
            assertEquals(
                naiveOut,
                shippedOut,
                "$label: the factored and readable forms must produce byte-identical output for '$key'",
            )
            comparisons++
        }
        return comparisons
    }

    // (PRIV-05) W-06 / T-21-58 / Pitfall 7: the group numbering every replacement string depends on.
    //
    // The expectation is DERIVED, not hard-coded: the same consumer template built around a
    // group-free placeholder has exactly the capturing groups the consumer itself declares, so
    // asserting the shipped rule matches it is asserting that SENSITIVE_KEY_EXPR contributes ZERO
    // capturing groups — which is precisely what clause (c) of its comment in Redaction.kt claims.
    //
    // CONCRETE CONSEQUENCE, so nobody has to take Pitfall 7 on trust: turning one of the
    // expression's (?: groups into a capturing ( shifts every group number after it. In
    // formBodyParamRegex that puts the key somewhere other than group 2, so "$1$2=[REDACTED]" writes
    // a fragment of the key — or, if the group is gone entirely, a literal $2 — into the outbound
    // prompt; in jsonSecretKeyRegex it moves the VALUE out of group 2. Measured during this plan:
    // NO behavioural test in the suite fails on that mutation, because the expression is always
    // nested inside a consumer's first capturing group, so the damage is latent rather than
    // immediate. These two assertions are the only guard on it.
    private fun assertGroupNumberingPinned(
        label: String,
        context: KeyRuleContext,
        naiveRule: Regex,
        shippedRule: Regex,
        shippedReplacement: String,
    ) {
        val anchorOnlyGroups = capturingGroupCount(context.rule(GROUP_FREE_KEY_EXPR))
        val shippedGroups = capturingGroupCount(shippedRule)
        assertEquals(
            anchorOnlyGroups,
            shippedGroups,
            "$label: SENSITIVE_KEY_EXPR must add NO capturing group (Pitfall 7) — a shifted number " +
                "makes this rule's replacement write key fragments or a literal \$n into the prompt",
        )
        assertEquals(
            anchorOnlyGroups,
            capturingGroupCount(naiveRule),
            "$label: the naive template must carry the same anchors, and therefore the same groups, as the shipped rule",
        )
        assertTrue(
            maxGroupReference(shippedReplacement) <= shippedGroups,
            "$label: replacement '$shippedReplacement' references a group this rule does not have",
        )
    }

    // (PRIV-05) WR-01: the LIMIT of the narrowing, asserted rather than assumed.
    //
    // These five names were in the code review's measured over-redaction list and are still
    // redacted, because they are driven by 'auth', 'session' and 'token' — words the ruling left
    // alone. Asserting them as accepted is the same discipline the D-13 block below applies:
    // silently accepting a name is not the same as deciding it. See wr01AcceptedOverRedactions for
    // why token_type in particular cannot be freed without a separate maintainer decision.
    @Test
    fun wr01NonBroadWordOverRedactionsRemainAccepted() {
        assertEquals(5, wr01AcceptedOverRedactions.size, "WR-01 accepted-residual corpus must stay at 5 keys")

        for (key in wr01AcceptedOverRedactions) {
            for ((context, output) in sc3Contexts(key, PrivacyMode.STRICT)) {
                assertFalse(
                    output.contains(SC3_SENTINEL),
                    "STRICT / $context: '$key' is an ACCEPTED over-redaction WR-01 did not reach and must stay redacted",
                )
            }
        }
    }

    // (PRIV-05) SC3 / D-13: camelCase key matching.
    //
    // authToken, accessToken and userSessionId are extremely common modern JSON key names and are
    // NOT reachable by the separator rule alone (auth is followed by 'T', which is alphanumeric).
    // The camelCase boundary is written with Java's inline flag-off group (?-i:...) because under
    // the consumers' (?i) the class [A-Z] also matches lowercase.
    //
    // ACCEPTED OVER-REDACTION: tokenCount is asserted as REDACTED on purpose. It is the price of
    // D-13 — recorded here as deliberate behaviour rather than discovered in the field. It
    // over-redacts (the fail-safe direction) and is structurally identical to the already-accepted
    // token_bucket_size case. codeName and keyName were asserted alongside it until WR-01 narrowed
    // the two broad words out of the containment rule; they now survive and are pinned in
    // wr01BroadWordBenignKeys, so this block names one case rather than three.
    // REVERT POINT: deleting the (?-i:...) alternative from WORD_BEFORE and WORD_AFTER in
    // Redaction.kt drops D-13 entirely — it loses nothing SC3 requires and removes tokenCount here
    // and tokenType in wr01AcceptedOverRedactions.
    //
    // keyboardLayout and monkeyBars must still survive: they are what distinguishes a camelCase
    // boundary from a plain substring match. SC3's literal all-lowercase codename is covered by
    // benignKeyNamesNotRedacted and is unaffected by D-13.
    @Test
    fun camelCaseKeysRedactedWithAcceptedOverRedactions() {
        for (key in listOf("authToken", "accessToken", "userSessionId")) {
            for ((context, output) in sc3Contexts(key, PrivacyMode.STRICT)) {
                assertFalse(
                    output.contains(SC3_SENTINEL),
                    "STRICT / $context: camelCase key '$key' must be redacted (D-13 gain)",
                )
            }
        }

        for (key in listOf("tokenCount")) {
            for ((context, output) in sc3Contexts(key, PrivacyMode.STRICT)) {
                assertFalse(
                    output.contains(SC3_SENTINEL),
                    "STRICT / $context: '$key' is an ACCEPTED D-13 over-redaction and must stay redacted",
                )
            }
        }

        for (key in listOf("keyboardLayout", "monkeyBars")) {
            for ((context, output) in sc3Contexts(key, PrivacyMode.STRICT)) {
                assertTrue(
                    output.contains(SC3_SENTINEL),
                    "STRICT / $context: '$key' has no lower-to-upper boundary after the word and must NOT be redacted",
                )
            }
        }
    }

    // (PRIV-05) SC1 / D-09: every cookie value in the passive scanner's dedicated cookie section
    // must be absent in STRICT and in BALANCED, with the cookie NAME preserved.
    //
    // The scanner splits the Cookie: header on ';' into bare name=value lines, dropping the prefix
    // cookieHeaderRegex keys on — so the header-line rule never sees these and every value reached
    // the AI backend verbatim. Asserted PER NAME rather than on an aggregate: a single "no secret
    // survives" assertion would pass while four of the six leaked.
    //
    // abtest_bucket is the entry only the section rule saves. The widened key expression from plan
    // 21-04 does not recognise that name, which is why both mechanisms are kept rather than treated
    // as redundant.
    @Test
    fun cookieSectionValuesRedactedPerName() {
        val cookieValues =
            mapOf(
                "JSESSIONID" to "8F3A9C2B7E1D4A6F0B5C8E2D",
                "PHPSESSID" to "abc123def456",
                "connect.sid" to "s%3ARZxYqL9.opaquevalue",
                "auth_token" to "secretvalue123",
                "csrftoken" to "abcdef",
                "abtest_bucket" to "OPAQUE_VALUE_XYZ",
            )

        // The blank line and the following section exercise the span bound: the rule must stop at
        // the end of the cookie section rather than running on to the end of the blob.
        val blob =
            """
            === COOKIES ===
            JSESSIONID=8F3A9C2B7E1D4A6F0B5C8E2D
            PHPSESSID=abc123def456
            connect.sid=s%3ARZxYqL9.opaquevalue
            auth_token=secretvalue123
            csrftoken=abcdef
            abtest_bucket=OPAQUE_VALUE_XYZ

            === PARAMETERS ===
            q=red running shoes (URL)
            """.trimIndent()

        for (mode in listOf(PrivacyMode.STRICT, PrivacyMode.BALANCED)) {
            val output = redactWith(blob, mode)
            for ((name, value) in cookieValues) {
                assertFalse(
                    output.contains(value),
                    "$mode: the value of cookie '$name' must be absent from the redacted prompt",
                )
                assertTrue(
                    output.lines().contains("$name=[REDACTED]"),
                    "$mode: cookie '$name' must keep its name and lose only its value",
                )
            }
            assertTrue(
                output.lines().contains("q=red running shoes (URL)"),
                "$mode: a line past the cookie section's blank-line terminator must be untouched",
            )
        }
    }

    // (PRIV-05) SC2: request.parameters() surfaces COOKIE-typed parameters into the parameters
    // section as "name=value (TYPE)" — the same values leaking a second way, in a section the
    // section-scoped cookie rule deliberately does not cover.
    //
    // The (URL) and (BODY) survivors are the point of the test: they are what proves the rule is
    // type-discriminating rather than a blanket line rule. The rejected context-free "^name=value$"
    // alternative would have mangled both and still could not have satisfied SC2, because the
    // trailing type suffix defeats its end anchor.
    //
    // abtest_bucket is the DECISIVE line and was added after measurement, not from the spec. With
    // only JSESSIONID and remember_me present this test passed with the type-suffix rule unwired:
    // both names are already reachable by plan 21-04's key expression, so formBodyParamRegex
    // redacted them from the leading-field position and the assertions could not see the defect.
    // An unremarkable cookie name is the only input the type-suffix rule alone can save. Do not
    // remove it.
    @Test
    fun cookieTypedParametersRedacted() {
        val blob =
            """
            === PARAMETERS ===
            JSESSIONID=8F3A9C2B7E1D4A6F0B5C8E2D (COOKIE)
            remember_me=deadbeefcafe (COOKIE)
            abtest_bucket=OPAQUE_PARAM_XYZ (COOKIE)
            q=red running shoes (URL)
            quantity=2 (BODY)
            """.trimIndent()

        for (mode in listOf(PrivacyMode.STRICT, PrivacyMode.BALANCED)) {
            val lines = redactWith(blob, mode).lines()

            assertTrue(
                lines.contains("JSESSIONID=[REDACTED] (COOKIE)"),
                "$mode: a COOKIE-typed parameter must keep both its name and its type suffix",
            )
            assertTrue(
                lines.contains("remember_me=[REDACTED] (COOKIE)"),
                "$mode: EVERY COOKIE-typed parameter is redacted, not only the session-named ones",
            )
            assertTrue(
                lines.contains("abtest_bucket=[REDACTED] (COOKIE)"),
                "$mode: an unremarkably-named COOKIE-typed parameter is saved by the type suffix alone",
            )
            assertFalse(
                lines.any {
                    it.contains("8F3A9C2B7E1D4A6F0B5C8E2D") ||
                        it.contains("deadbeefcafe") ||
                        it.contains("OPAQUE_PARAM_XYZ")
                },
                "$mode: no COOKIE-typed parameter value may survive",
            )
            assertTrue(
                lines.contains("q=red running shoes (URL)"),
                "$mode: a URL-typed parameter line must survive byte-for-byte",
            )
            assertTrue(
                lines.contains("quantity=2 (BODY)"),
                "$mode: a BODY-typed parameter line must survive byte-for-byte",
            )
        }
    }

    // (PRIV-05) SC1 / D-10: the named security regression guard for section-header poisoning.
    //
    // This reproduces a DEMONSTRATED exploit, not a hypothetical one, so it is a security guard
    // rather than a robustness nicety. ScanKnowledgeBase.recordTechStack builds its technology list
    // from the response's Server / X-Powered-By / X-AspNet-Version / X-Generator headers — all
    // attacker-controlled — and buildContextSummary emits that list into the prior-knowledge block,
    // which the emitter appends BEFORE the cookie section. A first-occurrence-only indexOf was
    // measured redacting the decoy below while BOTH genuine cookie values leaked intact; only
    // iterating every occurrence of the header saves them.
    //
    // abtest_bucket is the load-bearing half. Its name is deliberately unreachable by the widened
    // key expression from plan 21-04, so nothing but the section rule can save it — swapping it for
    // a name the key expression already covers would make this test pass with the defect present.
    // The decoy's own value is over-redacted as a result; that residual is accepted and documented
    // in Redaction.redactCookieSections.
    @Test
    fun cookieSectionDecoyDoesNotShieldRealSection() {
        val blob =
            """
            === PRIOR KNOWLEDGE ===
            Detected technologies: === COOKIES ===
            decoy=DECOY_VALUE

            === COOKIES ===
            JSESSIONID=REAL_SESSION_SECRET
            abtest_bucket=OPAQUE_VALUE_XYZ
            """.trimIndent()

        val output = redactWith(blob, PrivacyMode.STRICT)

        assertFalse(
            output.contains("REAL_SESSION_SECRET"),
            "STRICT: a decoy section header must not shield the real session cookie value",
        )
        assertFalse(
            output.contains("OPAQUE_VALUE_XYZ"),
            "STRICT: a decoy section header must not shield an unremarkably-named real cookie",
        )
        assertTrue(
            output.lines().contains("abtest_bucket=[REDACTED]"),
            "STRICT: the real cookie section is redacted in place, with its names preserved",
        )
    }

    // (PRIV-05) W-01: EVERY entry of a section that is exactly MAX_COOKIE_SECTION_LINES long is
    // redacted — the walk covers the whole budget it claims, with no off-by-one at either end.
    //
    // THIS IS A LATENT-TRAP CLOSURE, NOT A LIVE LEAK, and saying so is the point. The test is GREEN
    // before this plan and GREEN after it, because COOKIES_MAX_COUNT is 6 today and a 16-entry
    // section is unreachable through the emitter. Presenting it as a red-before-green gate would be
    // the vacuity this phase keeps paying for. Its honest gate is MUTATION: an off-by-one in
    // cookieSectionEnd's walk (lines < MAX_COOKIE_SECTION_LINES - 1) makes it fail naming ck15.
    // Note it CANNOT catch a shrink of MAX_COOKIE_SECTION_LINES itself — the fixture size is derived
    // from that constant, so both sides move together; that hazard is
    // cookieEmitterBoundStaysWithinTheRedactorBound's headroom assertion below, and the two tests
    // are deliberately not merged.
    //
    // FIXTURE REACHABILITY, as a rule-by-rule elimination. The names ckN are tokens that are members
    // of none of SENSITIVE_WORDS, BROAD_WORDS, CREDENTIAL_PREFIXES or KNOWN_SESSION_KEYS, so
    // SENSITIVE_KEY_EXPR and its three consumers (urlTokenParamRegex, formBodyParamRegex,
    // jsonSecretKeyRegex) cannot reach them. The values contain no '=', sit behind no '?' or '&',
    // carry no "Bearer " or "Basic " prefix, do not begin with "eyJ", sit inside no JSON pair and
    // carry no " (COOKIE)" type suffix — so redactCookieSections is the ONLY rule in Redaction.apply
    // that can touch them. Swapping in a name like session0 or key0 would make this test pass with
    // the defect fully present, which is exactly how the pre-CR-01 suite stayed green on a live leak.
    // Do not "improve" the names.
    @Test
    fun everyEntryOfAMaximalCookieSectionIsRedacted() {
        val entryCount = Redaction.MAX_COOKIE_SECTION_LINES
        val entries = (0 until entryCount).map { "ck$it=OPAQUE_ZZ${it}_END" }
        val blob = Redaction.COOKIE_SECTION_HEADER + "\n" + entries.joinToString("\n") + "\n"

        // Anti-vacuity: assert the fixture really is a MAXIMAL section before asserting behaviour,
        // so a future edit cannot quietly shrink it into a duplicate of cookieSectionValuesRedactedPerName.
        assertEquals(
            entryCount,
            blob.lines().count { it.startsWith("ck") },
            "The fixture must carry exactly MAX_COOKIE_SECTION_LINES entry lines",
        )

        for (mode in listOf(PrivacyMode.STRICT, PrivacyMode.BALANCED)) {
            val output = redactWith(blob, mode)
            // Asserted PER INDEX, in the style of cookieSectionValuesRedactedPerName: a single
            // aggregate assertion would report "some value survived" where the useful fact is WHICH
            // entry the span stopped covering.
            for (i in 0 until entryCount) {
                assertFalse(
                    output.contains("OPAQUE_ZZ${i}_END"),
                    "$mode: cookie entry ck$i sits inside the $entryCount-line section bound and must be " +
                        "redacted — this index is the FIRST entry the span stops covering",
                )
                assertTrue(
                    output.lines().contains("ck$i=[REDACTED]"),
                    "$mode: cookie ck$i must keep its name and lose only its value",
                )
            }
        }
    }

    // (PRIV-05) W-01: the emitter's cookie bound may never exceed the redactor's section bound.
    //
    // THE DEFECT THIS EXISTS FOR. MAX_COOKIE_SECTION_LINES lives in redact/ and COOKIES_MAX_COUNT in
    // scanner/ — a different file, a different package, and a name that gives no hint the redactor
    // depends on it. Measured on the shipped rule: a 20-entry section leaks ck16..ck19. So raising
    // the emitter's literal past the redactor's bound reopens PRIV-05 for every entry past the
    // sixteenth, and nothing in the suite went red. COOKIES_MAX_COUNT is now clamped at compile time
    // so the leak cannot actually reopen; this test is what stops the clamp absorbing the drift
    // silently, because a silent clamp is just a second unasserted coupling.
    //
    // This test needs no fixture and therefore has no fixture-reachability argument: it reads the two
    // shipped constants directly, which is precisely why it cannot be defused by an input change.
    @Test
    fun cookieEmitterBoundStaysWithinTheRedactorBound() {
        assertTrue(
            COOKIES_MAX_COUNT_INTENDED <= Redaction.MAX_COOKIE_SECTION_LINES,
            "PRIV-05: PassiveAiScannerAnalysis intends to emit $COOKIES_MAX_COUNT_INTENDED cookie entries but " +
                "Redaction redacts a cookie section only ${Redaction.MAX_COOKIE_SECTION_LINES} lines deep. " +
                "Every entry past that bound reaches the AI backend UNREDACTED. Raise " +
                "Redaction.MAX_COOKIE_SECTION_LINES first; never raise COOKIES_MAX_COUNT_INTENDED alone.",
        )
        assertTrue(
            COOKIES_MAX_COUNT_INTENDED * 2 <= Redaction.MAX_COOKIE_SECTION_LINES,
            "PRIV-05: MAX_COOKIE_SECTION_LINES counts LINES, not entries, and cookieSectionEnd skips blank " +
                "lines without terminating, so one blank line per entry doubles the lines a " +
                "$COOKIES_MAX_COUNT_INTENDED-entry section occupies. Measured at the shipped 16-line bound: " +
                "12 entries interleaved with blanks leak ck8..ck11. The redactor's bound must therefore stay " +
                "at or above ${COOKIES_MAX_COUNT_INTENDED * 2} — which is also why shrinking it to " +
                "COOKIES_MAX_COUNT + 2, the alternative 21-REVIEW-2 W-02 proposes, was rejected.",
        )
        assertEquals(
            COOKIES_MAX_COUNT_INTENDED,
            COOKIES_MAX_COUNT,
            "The compile-time clamp is a FAIL-SAFE, not a silent absorber. If it is currently reducing the " +
                "emitter's bound then the model is being shown fewer cookies than intended and nothing else " +
                "in the build would say so. Raise Redaction.MAX_COOKIE_SECTION_LINES to match.",
        )
    }

    // (PRIV-05) CR-01 / T-21-28: a BLANK cookie entry must not collapse or truncate the span.
    //
    // This is the live PRIV-05 leak the phase's own code review REPRODUCED, not a hypothetical.
    // COOKIE_SECTION_HEADER carries no trailing newline while the emitter uses appendLine, so
    // bodyStart lands on the header line's OWN newline. The pre-fix bound was
    // out.indexOf("\n\n", bodyStart), which therefore matched AT bodyStart whenever the first
    // emitted cookie entry was blank: the span became the empty string and EVERY cookie value in
    // the section reached the AI backend verbatim. A blank entry further down the list truncated
    // the span at that point instead, leaking every cookie below it.
    //
    // The emitter really does produce blank entries. PassiveAiScannerAnalysis splits the Cookie:
    // header with .split(";").map { c -> c.trim() } and applies no blank filter, so
    // "Cookie: ; JSESSIONID=..." — or any "a=b;;c=d" — yields one.
    //
    // FIXTURE REACHABILITY — what makes this reachable ONLY by redactCookieSections.
    // abtest_bucket=OPAQUE_VALUE_XYZ is the decisive line. The name's tokens are "abtest" and
    // "bucket", neither of which is a member of SENSITIVE_WORDS or KNOWN_SESSION_KEYS, so
    // SENSITIVE_KEY_EXPR and its three consumers cannot reach it. Its value contains no '=', is not
    // preceded by '?' or '&', does not start with "eyJ", is neither Bearer- nor Basic-prefixed,
    // sits inside no JSON key/value pair and carries no " (COOKIE)" suffix — so not one other rule
    // in Redaction.apply can touch it either. JSESSIONID and PHPSESSID are deliberately NOT
    // decisive: SENSITIVE_KEY_EXPR rescues both from the leading-field position even with the
    // section rule fully unwired, which is precisely why the pre-fix suite was green on this defect.
    // Do not swap abtest_bucket for a name the key expression already covers.
    //
    // The abtest_bucket line sits AFTER the mid-list blank on purpose. That is the half the code
    // review's own proposed one-line patch leaves leaking, so its position is what proves the span
    // bound was genuinely repaired rather than special-cased on the first line.
    @Test
    fun cookieSectionBlankEntriesDoNotCollapseSpan() {
        val cookieValues =
            mapOf(
                "JSESSIONID" to "8F3A9C2B7E1D4A6F0B5C8E2D",
                "PHPSESSID" to "abc123def456",
                "abtest_bucket" to "OPAQUE_VALUE_XYZ",
            )

        // First entry blank, fourth entry blank. trimIndent() maps interior blank lines to empty
        // strings rather than dropping them, so this shape is expressible directly.
        val blob =
            """
            === COOKIES ===

            JSESSIONID=8F3A9C2B7E1D4A6F0B5C8E2D
            PHPSESSID=abc123def456

            abtest_bucket=OPAQUE_VALUE_XYZ

            === PARAMETERS ===
            q=red running shoes (URL)
            """.trimIndent()

        // The fixture is asserted BEFORE the behaviour, so a future reformat that dropped either
        // blank line could not silently defuse the test into a duplicate of the sibling above.
        assertTrue(
            blob.contains(Redaction.COOKIE_SECTION_HEADER + "\n\n"),
            "The fixture must put a BLANK first entry directly after the header, producing the \"\\n\\n\" at bodyStart",
        )
        assertTrue(
            blob.contains("PHPSESSID=abc123def456\n\nabtest_bucket="),
            "The fixture must put a BLANK entry MID-LIST, immediately before the decisive abtest_bucket line",
        )

        for (mode in listOf(PrivacyMode.STRICT, PrivacyMode.BALANCED)) {
            val output = redactWith(blob, mode)
            for ((name, value) in cookieValues) {
                assertFalse(
                    output.contains(value),
                    "$mode: a blank cookie entry must not let the value of '$name' reach the backend",
                )
                assertTrue(
                    output.lines().contains("$name=[REDACTED]"),
                    "$mode: cookie '$name' must keep its name and lose only its value across the blank entries",
                )
            }
            assertTrue(
                output.lines().contains("q=red running shoes (URL)"),
                "$mode: skipping blank lines must not extend the span past the next section header",
            )
        }
    }

    // (PRIV-05) CR-01 / T-21-32: the DOCUMENTED RESIDUAL — a cookie element shaped like a section
    // header still terminates the span, so the cookie after it survives.
    //
    // This test asserts the residual AS IT STANDS. It is GREEN before this plan and GREEN after it,
    // BY DESIGN, and that is the whole point: the class is real, it is not closed here, and pinning
    // it makes the dependency visible instead of leaving it implicit in prose.
    //
    // Why no redactor-side rule can close it: this is IN-BAND SIGNALLING. The span terminator is
    // derived from content sitting INSIDE the region the span is supposed to protect, so the
    // redactor cannot tell a planted "=== FOO ===" cookie value from a genuine next prompt section.
    // Refusing to terminate on "=== " instead would hand an attacker the opposite primitive — one
    // planted line would swallow the remainder of the prompt.
    //
    // The class is therefore closed at the EMITTER and only at the emitter, by
    // Redaction.sanitizeCookieSectionEntries — exported from redact/ by this plan and wired into
    // PassiveAiScannerPrompts.buildScanMetadataText by plan 21-10. Its end-to-end guard is
    // poisonedCookieHeaderCannotTerminateTheCookieSection, in
    // src/test/kotlin/com/six2dez/burp/aiagent/scanner/PassiveAiScannerPromptRedactionTest.kt. If
    // that sanitizer is ever removed this test keeps passing while the end-to-end guard fails, which
    // is the correct division of labour between the two.
    //
    // W-07 — this reference named a method that DOES NOT EXIST until 21-16 corrected it, and the
    // correction is recorded rather than made silently, because the failure mode is the point: a
    // reader who followed the old name found nothing and would reasonably conclude the guard had
    // been deleted. That devalues every other "the named guard is X" comment in this codebase, and
    // several of those are the only thing telling a contributor that removing a line reopens a leak.
    // The reference now names the FILE as well as the method, so it can be found by path even if the
    // method is renamed, and the selector is registered in 21-VALIDATION.md §"Named-Guard Selectors"
    // so a rename fails a runnable check instead of quietly rotting a comment.
    //
    // FIXTURE REACHABILITY: abtest_bucket=OPAQUE_VALUE_XYZ again, for the reason given in full on
    // cookieSectionBlankEntriesDoNotCollapseSpan — nothing but the section rule can redact it, so
    // its SURVIVAL here is genuine evidence of the residual rather than an artefact of some other
    // rule declining to fire.
    @Test
    fun cookieSectionHeaderShapedEntryTerminatesSpan_documentedResidual() {
        val blob =
            """
            === COOKIES ===
            JSESSIONID=REALSECRET
            === FOO ===
            abtest_bucket=OPAQUE_VALUE_XYZ
            """.trimIndent()

        val output = redactWith(blob, PrivacyMode.STRICT)

        assertFalse(
            output.contains("REALSECRET"),
            "STRICT: the cookie ABOVE the planted section header is inside the span and must be redacted",
        )
        assertTrue(
            output.contains("OPAQUE_VALUE_XYZ"),
            "STRICT: RESIDUAL, asserted deliberately — a section-shaped cookie element ends the span, " +
                "and only Redaction.sanitizeCookieSectionEntries at the emitter (plan 21-10) can close it",
        )
    }

    // (PRIV-05) W-02 / T-21-49: the ACCEPTED-RESIDUAL PIN for a planted === COOKIES === header.
    //
    // WHAT IT PINS. A response body that plants the section header blinds exactly
    // MAX_COOKIE_SECTION_LINES lines of the attacker's OWN content, and the first line past the
    // bound survives. Both halves are asserted, because the boundary is the whole point: a test that
    // only asserted the redaction would stay green if the bound grew without limit.
    //
    // IT IS A RESIDUAL PIN, NOT A SECURITY GUARD, and it is deliberately NOT merged with
    // everyEntryOfAMaximalCookieSectionIsRedacted even though both build a maximal section. That
    // test is a security guard whose failure means cookies leaked; this one is green before and
    // after by design, and its failure means the accepted over-redaction boundary moved. A residual
    // pin and a security guard failing for the same reason is how a regression gets misread — the
    // same division of labour cookieSectionHeaderShapedEntryTerminatesSpan_documentedResidual above
    // already follows.
    //
    // DISPOSITION: ACCEPT, on two grounds this plan MEASURED rather than assumed. Requiring the
    // emitter's blank-line framing made three genuine unframed cookie sections leak on the
    // McpToolContext.redactIfNeeded / redact_preview paths while the whole suite stayed green;
    // shrinking the bound to COOKIES_MAX_COUNT + 2 moved the first leaking entry of a 20-entry
    // section from index 16 down to index 8. Both alternatives trade an over-redaction nuisance for
    // an under-redaction leak, which is the wrong direction in the requirement this phase exists
    // for. The full argument lives on Redaction.redactCookieSections.
    //
    // FIXTURE REACHABILITY: the planted lines are named debug, sql, internal, version and l0..lN —
    // none is a member of SENSITIVE_WORDS, BROAD_WORDS, CREDENTIAL_PREFIXES or KNOWN_SESSION_KEYS,
    // and no value contains '=', sits behind '?' or '&', carries a Bearer/Basic prefix, begins with
    // "eyJ" or carries a " (COOKIE)" suffix. So redactCookieSections is the only rule that can touch
    // them, which is what makes the SURVIVAL of the line past the bound genuine evidence of the
    // residual rather than some other rule declining to fire.
    @Test
    fun plantedCookieHeaderBlastRadiusIsBoundedToTheSectionBound_acceptedResidual() {
        val bound = Redaction.MAX_COOKIE_SECTION_LINES
        // A response body an attacker controls, with the section header planted mid-body. The first
        // four lines are the analytically load-bearing shapes a passive scanner most needs.
        val planted =
            listOf("debug=verbose_stack_trace_here", "sql=SELECT * FROM users WHERE id=1", "internal=10.0.0.5") +
                (3 until bound).map { "l$it=BLINDED_$it" }
        val survivor = "l$bound=SURVIVES_PAST_THE_BOUND"
        val blob =
            "=== RESPONSE BODY ===\n<html>\n" + Redaction.COOKIE_SECTION_HEADER + "\n" +
                planted.joinToString("\n") + "\n" + survivor + "\n</html>\n"

        // Anti-vacuity: the planted region must be exactly as long as the bound, or the "first line
        // past the bound" assertion below would not be testing the boundary at all.
        assertEquals(bound, planted.size, "The planted region must be exactly MAX_COOKIE_SECTION_LINES lines")

        val output = redactWith(blob, PrivacyMode.STRICT)

        assertTrue(
            output.lines().contains("debug=[REDACTED]"),
            "RESIDUAL: a planted header blinds the attacker's own body lines — including the debug/sql/internal " +
                "shapes a passive scanner most needs. Accepted, not desired; see redactCookieSections",
        )
        assertFalse(
            output.contains("SELECT * FROM users WHERE id=1"),
            "RESIDUAL: the value of a planted name=value line inside the bound is destroyed",
        )
        for (i in 3 until bound) {
            assertFalse(
                output.contains("BLINDED_$i"),
                "RESIDUAL: planted line l$i sits inside the $bound-line bound and loses its value",
            )
        }
        assertTrue(
            output.lines().contains(survivor),
            "RESIDUAL BOUNDARY: the FIRST line past MAX_COOKIE_SECTION_LINES must survive intact. If this " +
                "fails the accepted blast radius has grown, which is a deliberate decision to re-take, not a bug " +
                "to fix by editing this test",
        )
    }

    // (PRIV-05) CR-03 / T-21-29: redactCookieSections must be O(n) in the input length, not O(k*n).
    //
    // Pre-fix the loop rebuilt the ENTIRE string once per occurrence of the header
    // (out.substring(0, bodyStart) + replaced + out.substring(end)), which is an O(n) copy per
    // occurrence. The occurrence count k is attacker-controlled: buildScanMetadataText emits
    // response headers and body verbatim, and McpToolContext.redactIfNeeded runs the same rule over
    // raw tool output. The reviewer measured a clean 4x per doubling on Apple Silicon / JDK 21 —
    // 65.3 ms at 64 KB, 187.7 ms at 128 KB, 682.4 ms at 256 KB, 2630.9 ms at 512 KB — extrapolating
    // to ~42 s at the MCP default maxBodyBytes of 2 MiB, on an uninterruptible worker thread with
    // no budget and no marker. This fixture is that 512 KB row exactly.
    //
    // THRESHOLD JUSTIFICATION: 2 631 ms is the pre-fix cost on the FASTEST hardware this project
    // targets, so a 1 000 ms bound is unreachable pre-fix on any machine, while the post-fix single
    // pass is a few tens of milliseconds. That leaves more than an order of magnitude of headroom in
    // both directions, so the test is neither flaky on slow hardware nor blind to a regression. Same
    // timing-assertion idiom as oversizeBodySecretDoesNotSurvive and oversizeBodyFailsClosed below.
    //
    // The marker assertion is load-bearing, not decoration: without it a future change could make
    // this test pass by tripping COOKIE_SECTION_BUDGET_MS immediately and dropping the tail, which
    // is fast but is fail-closed truncation rather than the linear pass under test.
    @Test
    fun redactCookieSectionsIsLinearInSectionCount() {
        // 32 768 x 16 chars ("=== COOKIES ===" plus a newline) = 524 288 chars, the 512 KB row.
        val input = (Redaction.COOKIE_SECTION_HEADER + "\n").repeat(32_768)
        assertEquals(
            524_288,
            input.length,
            "The fixture must stay at the reviewer's measured 512 KB / 32 768-occurrence point",
        )

        val policy = RedactionPolicy.fromMode(PrivacyMode.STRICT)
        val start = System.currentTimeMillis()
        val output = Redaction.apply(input, policy, stableHostSalt = "salt")
        val elapsed = System.currentTimeMillis() - start

        assertFalse(
            output.contains("REDACTION INCOMPLETE"),
            "The single pass must COMPLETE inside its budget, not reach 1 000 ms by failing closed early",
        )
        assertTrue(
            elapsed < 1_000,
            "redactCookieSections must be linear in input length; took ${elapsed}ms " +
                "(pre-fix this same fixture measured 2 631 ms and rose 4x per doubling)",
        )
    }

    // (PRIV-06) CR-03 / D-02 / T-21-29: when the cookie rule's wall-clock budget expires it must
    // FAIL CLOSED — drop the remainder behind a marker rather than pass it through unscanned.
    //
    // Pre-fix this rule was the only one the phase added that bypassed both SafeRegex and
    // MAX_REDACTION_BUDGET_MS entirely: no deadline, no marker, and no seam to assert either.
    //
    // WHY THE BUDGET IS A PARAMETER rather than a constant: reaching a 250 ms deadline through the
    // real entry point would need a tens-of-megabytes fixture, making the assertion slow and
    // machine-speed dependent — i.e. exactly the flakiness that an injected bound removes. The
    // project's established answer is the one maybeLogTruncation(nowMs, droppedChars) already uses:
    // pass the bound in, never read the clock inside the assertion. testRedactCookieSections is the
    // matching internal seam, in the style of resetTruncationWindowForTest and testHkdfExtract.
    //
    // FIXTURE REACHABILITY: abtest_bucket=OPAQUE_VALUE_XYZ once more, and here the seam makes it
    // airtight — the call bypasses Redaction.apply altogether, so no other rule even runs, and the
    // absence of the value can only be the deadline branch dropping the tail.
    @Test
    fun cookieSectionDeadlineFailsClosed() {
        val blob = Redaction.COOKIE_SECTION_HEADER + "\nabtest_bucket=OPAQUE_VALUE_XYZ"

        val output = Redaction.testRedactCookieSections(blob, budgetMs = 0L)

        assertTrue(
            output.contains("REDACTION INCOMPLETE"),
            "An expired cookie-section budget must leave the windowDroppedMarker, not silence",
        )
        assertFalse(
            output.contains("OPAQUE_VALUE_XYZ"),
            "An expired budget must DROP the unscanned remainder, never pass it through unredacted",
        )
    }

    // (PRIV-06) W-05 / T-21-48: an expired cookie-section budget with NO cookie section left in the
    // text must preserve the text, not replace it with one drop marker.
    //
    // THE DEFECT. The deadline check sat at the top of the loop, ABOVE indexOf. So a stop-the-world
    // pause anywhere in the loop — or simply a text long enough that the previous occurrence used up
    // the budget — caused the ENTIRE remaining prompt, up to the MCP default maxBodyBytes of 2 MiB,
    // to be replaced by one windowDroppedMarker even when no further cookie section existed. That
    // fails CLOSED, so it is not a leak; it is a silent total loss of analytic context on a
    // well-behaved input, triggered by nothing the user did. Hoisting indexOf above the check makes
    // the fail-closed price payable only when a section is genuinely still pending.
    //
    // This one IS a genuine red-before-green, unlike the two W-01 tests and the sanitizer test below.
    //
    // FIXTURE REACHABILITY is exact, and the seam is what makes it exact: testRedactCookieSections
    // bypasses Redaction.apply entirely, so NO other rule runs at all — not the two header rules, not
    // the typed-parameter rule, not the body stage. Byte-identity of the output can therefore only
    // come from the loop breaking on "no section found". The fixture deliberately carries
    // name=value-shaped lines that the cookie pair regex WOULD rewrite if a section were ever opened,
    // so passing by accident is not available either: the only ways to satisfy assertEquals are the
    // correct break, or never entering the section body at all.
    @Test
    fun cookieSectionBudgetExpiryWithNoSectionRemainingPreservesTheText() {
        // Analytically valuable, cookie-section-free content: the debug/sql/internal shaped lines a
        // passive scanner most needs, and exactly what the drop marker would have destroyed.
        val text =
            """
            === RESPONSE BODY ===
            <html><body>
            debug=verbose_stack_trace_here
            sql=SELECT * FROM users WHERE id=1
            internal=10.0.0.5
            version=4.2.1-rc3
            </body></html>
            """.trimIndent()

        // Anti-vacuity: the fixture must genuinely contain NO cookie section header, or the test
        // would be asserting the wrong branch.
        assertFalse(
            text.contains(Redaction.COOKIE_SECTION_HEADER),
            "The fixture must contain no cookie section header at all — that is the branch under test",
        )

        val output = Redaction.testRedactCookieSections(text, budgetMs = 0L)

        assertEquals(
            text,
            output,
            "W-05: an expired budget with NO cookie section pending must return the text BYTE-IDENTICALLY. " +
                "Dropping it behind a marker destroys up to 2 MiB of prompt for a hazard that is not present.",
        )
        assertFalse(
            output.contains("REDACTION INCOMPLETE"),
            "No drop marker may be emitted when there was no cookie section to fail closed on",
        )
        assertFalse(
            output.contains("REDACTION BUDGET EXCEEDED"),
            "No budget marker of any shape may be emitted when there was no cookie section to fail closed on",
        )
    }

    // (PRIV-05) W-03 / T-21-47: a DIRECT unit test on Redaction.sanitizeCookieSectionEntries.
    //
    // WHY A DIRECT TEST IS REQUIRED RATHER THAN REDUNDANT. The function has three limbs and its own
    // KDoc calls the middle one load-bearing: every CR and LF inside an entry becomes a single space,
    // so one entry can never become two emitted lines. The two named end-to-end guards
    // (PassiveAiScannerPromptRedactionTest.poisonedCookieHeaderCannotTerminateTheCookieSection and
    // .cookieSectionEntriesAreSanitizedAtTheEmitter) both use the literal "=== FOO ===" with NO
    // embedded newline, so neither can reach the CR/LF limb. Asked the standing question — what else
    // in the pipeline would catch this input? — the answer for that limb was NOTHING: deleting
    // .replace('\r', ' ').replace('\n', ' ') left the entire suite green while CR-01's second trigger
    // was reopened in full. Mutation M3 in the 21-15 summary is that measurement.
    //
    // INPUT REACHABILITY. cookieSectionLines splits the raw Cookie: header value on ';' and trims
    // each element; it does not remove interior newlines. A hand-edited Repeater or Intruder request
    // carrying an embedded newline in a Cookie: header is ordinary Burp usage, so an entry of the
    // shape "a=1\n=== FOO ===" reaches the emitter, where appendLine writes it as TWO lines — the
    // second sitting at a line start and terminating the cookie span, leaking every cookie below it.
    //
    // LATENT-TRAP CLOSURE, stated plainly: this test is green before and after, because the limb
    // ships today. Its gate is mutation, not a red-before-green.
    //
    // The test is cheap precisely because the function is pure — no pipeline, no policy, no seam.
    @Test
    fun sanitizeCookieSectionEntriesNeutralisesEveryFramingPrimitive() {
        val out =
            Redaction.sanitizeCookieSectionEntries(
                listOf("a=1\n=== FOO ===", "b=2\r=== BAR ===", "   ", "", "=== BAZ ===", "c=3"),
            )

        assertEquals(
            listOf("a=1 === FOO ===", "b=2 === BAR ===", " === BAZ ===", "c=3"),
            out,
            "All three limbs, asserted as one exact list: blank-after-trim entries dropped, CR and LF " +
                "flattened to a single space, and a still-===-leading entry space-prefixed rather than lost",
        )
        assertTrue(
            out.none { it.contains('\n') || it.contains('\r') },
            "The load-bearing limb: one entry must NEVER become two emitted lines, because the second " +
                "would sit at a line start and terminate the cookie span (CR-01's second trigger)",
        )
        assertTrue(
            out.none { it.startsWith("===") },
            "No entry may forge a section boundary — cookieSectionEnd terminates on a RAW, untrimmed " +
                "startsWith(NEXT_SECTION_PREFIX) at a line start, so the raw predicate is the one that matters",
        )
        assertTrue(
            out.contains(" === BAZ ==="),
            "The ===-leading entry is NEUTRALISED, not dropped: its value is preserved so nothing " +
                "analytically useful is lost, which is the point of the space prefix over deletion",
        )
    }

    // PRIV-02: OFF mode must leave bodies completely untouched — no form-body or JSON redaction.
    @Test
    fun offModePreservesBodies() {
        val formBody = "apikey=sk-abc123&user=bob"
        val jsonBody = """{"api_key":"sk-xyz","name":"alice","token":"abc"}"""

        val policy = RedactionPolicy.fromMode(PrivacyMode.OFF)

        val formOutput = Redaction.apply(formBody, policy, stableHostSalt = "salt")
        assertEquals(formBody, formOutput, "OFF mode must not touch form body")

        val jsonOutput = Redaction.apply(jsonBody, policy, stableHostSalt = "salt")
        assertEquals(jsonBody, jsonOutput, "OFF mode must not touch JSON body")
    }

    // PRIV-02: User-supplied custom pattern applied in STRICT and BALANCED, inactive in OFF.
    // The test resets patterns in @AfterEach to avoid cross-test bleed.
    @Test
    fun customPatternRedactsInStrictAndBalanced() {
        Redaction.setCustomPatterns(listOf("\\bSECRET-\\d{4}\\b"))

        val input = "Content: SECRET-1234 is the value"

        for (mode in listOf(PrivacyMode.STRICT, PrivacyMode.BALANCED)) {
            val policy = RedactionPolicy.fromMode(mode)
            val output = Redaction.apply(input, policy, stableHostSalt = "salt")
            assertTrue(output.contains("[REDACTED]"), "$mode: custom pattern must redact SECRET-1234")
            assertFalse(output.contains("SECRET-1234"), "$mode: original value must not appear after redaction")
        }

        // (PRIV-06) D-05: this limb is DELIBERATELY INVERTED. It previously asserted
        // assertEquals(input, offOutput) because the custom-pattern loop lived inside the
        // redactTokens branch and was therefore inert under OFF. The loop now sits outside that
        // branch, so a user's custom patterns are a "never send this, ever" list that is
        // independent of the privacy mode: OFF means "no BUILT-IN redaction", not "no redaction at
        // all". 21-VALIDATION.md records this as one of SC6's two named exceptions, so it must not
        // be read as a regression. The method NAME is kept unchanged on purpose — 21-CONTEXT.md,
        // 21-VALIDATION.md and 21-VERIFICATION.md all refer to this test by name and a rename would
        // break that traceability.
        val offPolicy = RedactionPolicy.fromMode(PrivacyMode.OFF)
        val offOutput = Redaction.apply(input, offPolicy, stableHostSalt = "salt")
        assertTrue(offOutput.contains("[REDACTED]"), "OFF: a custom pattern must still redact SECRET-1234")
        assertFalse(offOutput.contains("SECRET-1234"), "OFF: the original custom-pattern value must not survive")
    }

    // PRIV-02 / CR-01: regression — custom patterns carried on a loaded settings object must
    // become active when seeded into the engine (the App.initialize startup step), NOT only
    // after a manual re-save. The previous bug was that App.initialize never called
    // setCustomPatterns(settings.customRedactionPatterns), so on every Burp launch the live
    // custom-pattern list silently reset to empty and configured secrets leaked to the backend.
    // This exercises the load -> seed -> apply contract that App.kt now relies on, using a
    // pattern sourced from a settings object rather than set directly inline.
    @Test
    fun customPatternsFromSettingsAreActiveAfterSeeding() {
        // Stands in for AgentSettings.customRedactionPatterns as returned by
        // AgentSettingsRepository.load() — the persisted, save-validated pattern list that
        // App.initialize must push into the engine at startup.
        val persistedPatterns = listOf("\\bINTERNAL-[A-Z0-9]{6}\\b")

        // Sanity: the engine starts with NO custom patterns active (simulating a fresh launch
        // before the seeding step). The pattern must NOT redact yet.
        Redaction.setCustomPatterns(emptyList())
        val input = "Leak check: INTERNAL-ABC123 must be stripped"
        val strict = RedactionPolicy.fromMode(PrivacyMode.STRICT)
        val beforeSeed = Redaction.apply(input, strict, stableHostSalt = "salt")
        assertTrue(beforeSeed.contains("INTERNAL-ABC123"), "Pre-seed: custom pattern must be inactive")

        // The App.initialize seeding step: push the loaded settings' patterns into the engine.
        // This is exactly Redaction.setCustomPatterns(settings.customRedactionPatterns).
        Redaction.setCustomPatterns(persistedPatterns)

        val afterSeed = Redaction.apply(input, strict, stableHostSalt = "salt")
        assertTrue(afterSeed.contains("[REDACTED]"), "Post-seed: loaded custom pattern must redact")
        assertFalse(afterSeed.contains("INTERNAL-ABC123"), "Post-seed: original secret must not appear")
    }

    // (PRIV-06) D-03: the truncation notice is rate-limited to one line per 10 s window, and the
    // line that ends a window reports how many notices were suppressed inside it.
    //
    // The clock is injected through maybeLogTruncation's nowMs parameter — the
    // PassiveAiScannerAnalysis.maybeLogBackoff convention — so the window is asserted exactly and
    // nothing sleeps. resetTruncationWindowForTest() is called first because Redaction is a
    // singleton object and a previous test in the same JVM may have opened the window already.
    @Test
    fun truncationSignalIsRateLimited() {
        Redaction.resetTruncationWindowForTest()
        // The sink fires on the caller's thread (a scanner or MCP tool thread in production) and is
        // read from the JUnit thread, so the capture list must be concurrent.
        val lines = CopyOnWriteArrayList<String>()
        Redaction.truncationLogger = { lines += it }

        Redaction.maybeLogTruncation(T0, 1_000L)
        assertEquals(1, lines.size, "The first truncation in a window must emit a notice")

        Redaction.maybeLogTruncation(T_INSIDE_WINDOW, 2_000L)
        assertEquals(1, lines.size, "A second truncation inside the same window must be suppressed")

        Redaction.maybeLogTruncation(T_AFTER_WINDOW, 3_000L)
        assertEquals(2, lines.size, "A truncation past the window must emit a second notice")
        assertTrue(
            lines[1].contains("Further notices suppressed since the previous line: 1"),
            "The notice that closes a window must report the suppressed count; got: ${lines[1]}",
        )
        assertFalse(
            lines[0].contains("suppressed"),
            "The first notice of a burst must not claim a suppressed count",
        )
    }

    // (PRIV-06) WR-04 / W-08 / T-21-65: A FAILING DIAGNOSTICS SINK MUST NEVER ABORT A REDACTION PASS.
    //
    // THE RACE. App.initialize sets Redaction.truncationLogger to a lambda that CAPTURES `api`
    // (App.kt:69). App.shutdown() unwires every other global sink — BackendDiagnostics.retry,
    // AuditLogger's global emitter, Redaction.clearMappings() — and this phase's task 3 now unwires
    // this one too. But a redaction already in flight on a Burp scanner thread or an MCP tool thread
    // during teardown can still reach the sink between the extension being torn down and the field
    // being nulled, and `api.logging()` on a torn-down API throws. Without the wrap, that throw
    // propagates out through redactCookieSections -> apply -> the caller, turning a lost log line
    // into a failed redaction. The truncationLogger KDoc already promises "a missing sink costs the
    // user visibility, never correctness"; this is what makes the same true of a FAILING sink.
    //
    // WHY THE EXPOSURE GREW ENOUGH TO STOP DEFERRING IT. Plan 21-12 deferred WR-04 as a teardown-race
    // robustness issue, which was accurate when written: the only maybeLogTruncation call sites were
    // in windowedScan's budget-exhaustion branch and dropOrRetry, i.e. oversized bodies only. This
    // phase added a THIRD call site inside redactCookieSections, which runs in the HEADER stage of
    // every Redaction.apply where stripCookies is true — the default BALANCED mode, on every MCP tool
    // call and every passive scan. The window is now reachable far more often than when it was
    // recorded.
    //
    // FIXTURE REACHABILITY is exact, and the seam is what makes it exact. testRedactCookieSections
    // bypasses Redaction.apply entirely, so no other rule runs, and budgetMs = 0 is deterministically
    // expired on the first iteration (the ">= 0L" comparison, see redactCookieSections). The deadline
    // branch is therefore the ONLY maybeLogTruncation call site this call can reach, so an escaping
    // exception can only have come from the sink invocation — not from any other part of the pass.
    //
    // The throwing sink is restored in a finally so it cannot bleed into another test through the
    // Redaction singleton; @AfterEach resetTruncationSignal is the second layer.
    @Test
    fun truncationLoggerThatThrowsDoesNotAbortRedaction() {
        Redaction.resetTruncationWindowForTest()
        val blob = Redaction.COOKIE_SECTION_HEADER + "\nabtest_bucket=OPAQUE_VALUE_XYZ"
        val t0Real = System.currentTimeMillis()

        val output: String
        try {
            Redaction.truncationLogger = { throw IllegalStateException("Extension has been unloaded") }
            output = Redaction.testRedactCookieSections(blob, budgetMs = 0L)
        } finally {
            Redaction.truncationLogger = null
        }

        assertTrue(
            output.contains("REDACTION INCOMPLETE"),
            "A throwing truncation sink must not stop the pass from emitting its drop marker",
        )
        assertFalse(
            output.contains("OPAQUE_VALUE_XYZ"),
            "A throwing truncation sink must not weaken the fail-closed drop of the unscanned remainder",
        )

        // THE LIMITER'S ACCOUNTING MUST SURVIVE THE THROW. The fix wraps the sink invocation; a wrap
        // placed one line wider would also swallow the compareAndSet and the getAndSet, so the window
        // would never actually open and every later notice would emit instead of being suppressed.
        // These two assertions are what tell those two placements apart (mutation M5).
        //
        // Offsets mirror the T0 / T_INSIDE_WINDOW / T_AFTER_WINDOW convention above — 5 s inside the
        // 10 s window, 11 s past it — but are taken relative to the real clock, because the call
        // above went through redactCookieSections, which reads System.currentTimeMillis() itself.
        val lines = CopyOnWriteArrayList<String>()
        Redaction.truncationLogger = { lines += it }

        Redaction.maybeLogTruncation(t0Real + 5_000L, 1_000L)
        assertEquals(
            0,
            lines.size,
            "The throwing call must still have OPENED the rate-limiter window: a notice 5 s later must be suppressed",
        )

        Redaction.maybeLogTruncation(t0Real + 11_000L, 2_000L)
        assertEquals(
            1,
            lines.size,
            "A notice 11 s later, past the window, must still emit — the throw must not have frozen the limiter",
        )
        assertTrue(
            lines[0].contains("Further notices suppressed since the previous line: 1"),
            "The suppressed COUNT must survive the throwing call too; got: ${lines[0]}",
        )
    }

    // (PRIV-06) SC4 / T-21-02: a body above the old size cap must not smuggle a secret past the
    // body stage.
    //
    // This test is a DELIBERATE REWRITE, not an extension. It previously asserted the fail-open as
    // correct behaviour: its comment recorded that an over-cap secret was allowed to remain, and
    // its only substantive assertion was that the call returned quickly — which stayed true
    // precisely BECAUSE every body rule was skipped. That is the PRIV-06 defect asserted as a
    // contract. 21-VALIDATION.md records this rewrite as one of SC6's two named exceptions, so it
    // is not a regression; plan 21-07 proves it goes RED against the pre-fix body stage. The old
    // name would now misdescribe the contract, and 21-VALIDATION.md's automated selector
    // *RedactionTest.oversizeBody* matches both the old and the new name.
    //
    // Two properties make this a real gate rather than a smoke test:
    //   - the filler is MULTI-LINE, so line-boundary windowing genuinely produces more than one
    //     window and the secret sits past the old cut-off, inside the second one;
    //   - the secret is reachable by a body-stage rule ALONE. formBodyParamRegex catches it through
    //     its (^|[?&]) leading-field anchor, while urlTokenParamRegex — which runs unbounded in the
    //     header stage and would otherwise mask the defect — requires a '?' or '&' before the key
    //     and cannot reach it. The value is not bearer- or basic-prefixed and does not start with
    //     "eyJ", so no other rule can save it either. If the body stage skips, the secret survives.
    @Test
    fun oversizeBodySecretDoesNotSurvive() {
        // 10 001 lines of 99 'x' plus a newline is 1 000 100 characters, just over the window width.
        val filler = ("x".repeat(99) + "\n").repeat(10_001)
        val oversizeBody = filler + "api_key=SC4-SECRET-VALUE-7B3E\n"
        assertTrue(
            oversizeBody.length > Defaults.MAX_REDACTION_BODY_CHARS,
            "The fixture must exceed the window width or this test proves nothing",
        )

        val policy = RedactionPolicy.fromMode(PrivacyMode.STRICT)
        val start = System.currentTimeMillis()
        val output = Redaction.apply(oversizeBody, policy, stableHostSalt = "salt")
        val elapsed = System.currentTimeMillis() - start

        assertFalse(
            output.contains("SC4-SECRET-VALUE-7B3E"),
            "STRICT: a secret past the old size cap must not survive the body stage",
        )
        assertTrue(
            output.contains("api_key=[REDACTED]"),
            "STRICT: the over-cap field must be redacted in place, keeping its key",
        )
        assertTrue(elapsed < 5_000, "The windowed body stage must stay bounded; took ${elapsed}ms")
    }

    // (PRIV-06) SC4 / D-02 / D-14 / T-21-03: a pathological pattern on an oversized input must
    // produce a MARKER, never passthrough.
    //
    // This is the fail-CLOSED half of SC4 and the explicit guard against treating
    // SafeRegex.replaceAllSafeReporting(...).text as success without checking timedOut: on timeout
    // that text is the input unchanged, byte-identical to "the pattern matched nothing", so a body
    // stage that assigned it blind would silently emit unscanned bytes while looking correct. Only
    // the timedOut flag tells the two apart. (WR-03 deleted the String-returning replaceAllSafe
    // façade this comment used to name, so the hazard is now spelled out in the form that ships.)
    //
    // (a+)+$ is the classic catastrophic-backtracking pattern and 2 000 'a' characters followed by
    // '!' is the input shape on which SafeRegexTest proves (a+)+$ exhausts its access budget. It is
    // pushed in through setCustomPatterns rather than through the save path on purpose: isPatternSafe
    // rejects it at save time, and what is under test here is what the ENGINE does if such a pattern
    // ever reaches it. The @AfterEach resetCustomPatterns prevents any bleed.
    @Test
    fun oversizeBodyFailsClosed() {
        Redaction.setCustomPatterns(listOf("(a+)+\$"))

        val oversizeBody = ("a".repeat(2_000) + "!\n").repeat(600)
        assertTrue(
            oversizeBody.length > Defaults.MAX_REDACTION_BODY_CHARS,
            "The fixture must exceed the window width or no windowing happens",
        )

        val policy = RedactionPolicy.fromMode(PrivacyMode.STRICT)
        val start = System.currentTimeMillis()
        val output = Redaction.apply(oversizeBody, policy, stableHostSalt = "salt")
        val elapsed = System.currentTimeMillis() - start

        assertTrue(
            output.contains("REDACTION INCOMPLETE") || output.contains("REDACTION BUDGET EXCEEDED"),
            "A window that could not be fully scanned must be dropped behind a marker, not passed through",
        )
        // (PRIV-06) WR-05 — WHY THE PREVIOUS ASSERTION WAS REPLACED, recorded so the strengthening
        // reads as deliberate rather than as churn. This test used to assert only that the WHOLE
        // body did not survive verbatim beside the marker. That form is satisfied by *any*
        // single-character modification to the input: inserting one marker anywhere already makes
        // a whole-body containment check false, so it proved nothing at all about the property under
        // test. A mutation that emitted three windows unscanned and marked only the fourth would
        // have kept this test green while the fail-OPEN this phase exists to kill was back in place.
        //
        // The two replacements are EXACT rather than approximate, and that is a property of this
        // fixture specifically: it consists of nothing but 2 000-character 'a' runs and '!', every
        // window in it must be dropped, and a 2 000-'a' run can therefore appear in the output only
        // if some window was emitted UNSCANNED. The length bound is the second half of the same
        // statement — a body that collapsed to markers is orders of magnitude shorter than half its
        // input, while a body that passed through is longer than it.
        assertFalse(
            output.contains("a".repeat(2_000)),
            "No unscanned window may reach the output; only markers may remain",
        )
        assertTrue(
            output.length < oversizeBody.length / 2,
            "A wholly-unscannable body must collapse to markers, not pass through",
        )
        // Generous so a slow machine cannot make this flaky, tight enough to fail if it hangs.
        assertTrue(elapsed < 30_000, "The total budget must bound a pathological pattern; took ${elapsed}ms")
    }

    // (PRIV-06) SC4 / D-02 / D-14 / T-21-03: the fail-closed guarantee holds BELOW the window
    // width too, not only above it.
    //
    // The sibling above covers oversized input. This one covers the single-pass path, which plan
    // 21-06 shipped assigning the return value of the since-deleted SafeRegex.replaceAllSafe façade
    // (WR-03): that value was replaceAllSafeReporting's .text, which on timeout is the input
    // unchanged, byte-identical to "the pattern matched nothing", so a rule that overran its per-rule
    // bound was silently skipped and its unredacted content passed straight through. That is fail-OPEN, one size class below the defect the phase exists to remove, and
    // it is what this test pins shut. The fix discards the partial result and re-scans the ORIGINAL
    // input through the windowed path, which already drops unscannable content behind a marker.
    //
    // FIXTURE STRENGTH (the 21-05 lesson: a test another rule also satisfies is vacuous). Two
    // properties make this reachable ONLY by the path under test:
    //   - the body is 800 800 characters, strictly BELOW MAX_REDACTION_BODY_CHARS, so the windowed
    //     path is not entered directly and the single-pass loop is what must fail closed. The
    //     assertion below pins that, so a future change to the constant cannot silently turn this
    //     into a duplicate of oversizeBodyFailsClosed;
    //   - the content is nothing but 'a' runs and '!' — no '=', no sensitive key name, no cookie
    //     section, no bearer/basic prefix, no "eyJ" and no host header. Not one built-in rule can
    //     match it, in either stage, so the marker asserted below can only have been produced by
    //     the fail-closed fallthrough. Verified by mutation, not by inspection.
    @Test
    fun subWindowBodyFailsClosed() {
        Redaction.setCustomPatterns(listOf("(a+)+\$"))

        // 400 lines of 2 000 'a' plus "!\n" is 800 800 characters — under the 1 MB window width.
        val body = ("a".repeat(2_000) + "!\n").repeat(400)
        assertTrue(
            body.length <= Defaults.MAX_REDACTION_BODY_CHARS,
            "The fixture must stay BELOW the window width or this test duplicates oversizeBodyFailsClosed",
        )

        val policy = RedactionPolicy.fromMode(PrivacyMode.STRICT)
        val start = System.currentTimeMillis()
        val output = Redaction.apply(body, policy, stableHostSalt = "salt")
        val elapsed = System.currentTimeMillis() - start

        assertTrue(
            output.contains("REDACTION INCOMPLETE") || output.contains("REDACTION BUDGET EXCEEDED"),
            "A sub-window body whose rule timed out must be dropped behind a marker, never passed through",
        )
        // (PRIV-06) WR-05 — the same strengthening as the sibling above, for the same reason. The
        // previous assertion checked only that the WHOLE body did not survive verbatim, which any
        // single-character modification satisfies, so a mutation emitting most of the input
        // unscanned and marking only the tail would have left this test green. This fixture is also
        // nothing but 2 000-character 'a' runs and '!', so the run-absence check below is exact:
        // there is no window in it that can legitimately be emitted.
        assertFalse(
            output.contains("a".repeat(2_000)),
            "No unscanned window may reach the output; only markers may remain",
        )
        assertTrue(
            output.length < body.length / 2,
            "A wholly-unscannable body must collapse to markers, not pass through",
        )
        // Bounds the documented composition: one single-pass sweep plus one full windowed budget.
        assertTrue(elapsed < 30_000, "The single-pass fallthrough must stay bounded; took ${elapsed}ms")
    }

    // (PRIV-06) CR-04 / T-21-33: splitPoint must be able to cut a window that has no newline in it
    // at all. THIS is the defect, reduced to a pure function.
    //
    // Returning 0 here is not a neutral "cannot split" answer: dropOrRetry's guard is
    // `if (cut <= 0 || cut >= window.length)`, so 0 routes straight into the total drop and the
    // whole window is replaced by a marker. A newline-free body is one window at any size, so that
    // single return value is what destroys a minified-JSON payload in its entirety.
    //
    // WHY A SEAM RATHER THAN ONLY THE END-TO-END TEST. Reaching this branch through
    // Redaction.apply requires a rule to genuinely exhaust its access budget, which the built-in
    // rules never do, so it needs a pathological custom pattern or an injected budget.
    // The defect itself is a pure function of one string. Asserting it directly makes the core of
    // CR-04 deterministic and hardware-independent, and leaves the end-to-end sibling below to prove
    // the wiring rather than the arithmetic.
    @Test
    fun splitPointCutsNewlineFreeWindowsInsteadOfRefusing() {
        val window = "x".repeat(1_000)

        val cut = Redaction.testSplitPoint(window)

        assertTrue(
            cut > 0,
            "A newline-free window must be splittable; a 0 here is what makes dropOrRetry discard the whole window",
        )
        assertTrue(
            cut < window.length,
            "The cut must leave a non-empty second half, or dropOrRetry drops on its `cut >= window.length` limb",
        )
    }

    // (PRIV-06) CR-04: the line-boundary rule is UNCHANGED wherever a line boundary exists.
    //
    // GREEN BEFORE AND AFTER, BY DESIGN — this is a regression guard on the (?m)^ protection, not a
    // test of new behaviour, and Pitfall 1 says such a test must say so out loud. Its purpose is to
    // prove the character cut was added as a FALLBACK rather than as a replacement: the trap
    // 21-RESEARCH.md "Decision 3" proved in both directions — a mid-line cut can create a match at
    // an artificial line start and can truncate a match spanning the cut — is still avoided
    // everywhere a '\n' is available to cut on. If this test ever goes red, the fallback has
    // escaped its branch and the fix has traded the protection away rather than extending it.
    @Test
    fun splitPointStillCutsAtALineBoundaryWhenOneExists() {
        val window = SAFE_CUT_LINE_FIXTURE.repeat(SAFE_CUT_LINE_REPEATS)
        // ANTI-VACUITY GUARD — see SAFE_CUT_LINE_FIXTURE. Unless a NON-newline terminator sits
        // between the midpoint and the next line break, this test cannot tell a line-boundary cut
        // from a character cut that happened to land on a newline, and it would stay green against a
        // splitPoint whose line branches had been deleted outright.
        val firstTerminatorAtOrAfterMid =
            (window.length / 2 until window.length).first { isSafeCutTerminatorForTest(window[it]) }
        assertFalse(
            window[firstTerminatorAtOrAfterMid] == '\n',
            "The fixture must carry a non-newline terminator between its midpoint and the next line break",
        )

        val cut = Redaction.testSplitPoint(window)

        assertTrue(cut > 0, "A window full of line boundaries must be splittable")
        assertEquals(
            '\n',
            window[cut - 1],
            "The cut must land immediately after a newline, so both halves stay line-aligned and (?m)^ keeps its meaning",
        )
    }

    // (PRIV-06) CR-04 / T-21-34: on the dominant oversized shape, the character cut lands where no
    // built-in body rule's match can span it.
    //
    // The straddle residual is real and is recorded in ADR-14 rather than solved — D-01 AMENDED's
    // overlap clause stays dropped, because measured single matches of the built-in rules reach
    // 200 006 characters and no finite overlap constant is therefore sound. What CAN be done, and is
    // what this test pins, is to prefer a cut position that the built-in value classes cannot cross:
    // [^&\s"'<>]+ cannot span '&' or whitespace, and a JSON value is either '"'-delimited or a
    // scalar immediately followed by ',', '}' or ']' in minified JSON. Cutting just after one of
    // those therefore lands OUTSIDE any built-in match for exactly the payload shape CR-04 is about.
    @Test
    fun splitPointPrefersASafeCutBoundaryInMinifiedJson() {
        val window = SAFE_CUT_JSON_FRAGMENT.repeat(SAFE_CUT_JSON_REPEATS)
        assertFalse(
            window.contains('\n'),
            "The fixture must have no line boundary, or splitPoint never reaches the safe-cut branch",
        )
        // ANTI-VACUITY GUARD — see SAFE_CUT_JSON_FRAGMENT. If the exact midpoint were itself already
        // a safe cut, this test would pass against a splitPoint that never searched at all, which is
        // precisely what the first version of this fixture did.
        assertFalse(
            isSafeCutTerminatorForTest(window[window.length / 2 - 1]),
            "The fixture must be MISALIGNED with the midpoint, or the assertion below proves nothing",
        )

        val cut = Redaction.testSplitPoint(window)

        assertTrue(cut > 0, "A newline-free minified-JSON window must be splittable")
        assertTrue(cut < window.length, "The cut must leave a non-empty second half")
        val cutAfter = window[cut - 1]
        assertTrue(
            cutAfter in SAFE_CUT_TERMINATORS || cutAfter.isWhitespace(),
            "The cut must land just after a value-terminating character so it cannot fall inside a " +
                "built-in match; it landed after '$cutAfter'",
        )
    }

    // (PRIV-06) CR-04 / T-21-33: a newline-free body above the window width must be SCANNED in
    // pieces, not replaced in its entirety by a drop marker.
    //
    // THE DEFECT. windowEnd deliberately makes an over-width line its own window, so a body with no
    // '\n' is one window whatever its size. splitPoint then returned 0 for any window with no
    // interior newline, and dropOrRetry's `if (cut <= 0 …)` turned that into a total drop — so the
    // WINDOW_RETRY_MAX_DEPTH ladder, justified in source as existing so a 2-3x slower machine would
    // not lose content that ships today, was structurally inapplicable to the single most common
    // oversized payload shape there is.
    //
    // WHY THAT SHAPE IS THE COMMON ONE, not a corner case: McpToolContext.redactIfNeeded receives
    // serialized tool output capped at maxBodyBytes (default 2 MiB) and toolJson.encodeToString(...)
    // emits MINIFIED, newline-free JSON. A default-configuration 2 MiB tool response therefore
    // reached the model as "[REDACTION INCOMPLETE - 2097156 CHARS DROPPED AND NOT SENT]" and
    // nothing else. That is fail-CLOSED, so it is a capability regression rather than a leak — but
    // it is one this phase introduced, and an empty analysis for a default input is incorrect
    // behaviour, not a safe one.
    //
    // WHICH ASSERTION IS THE GATE. Secret-absence alone would be VACUOUS here, and in the most
    // deceptive way available: the pre-fix behaviour removes the secret too, by destroying the
    // entire body. A test asserting only that the secret is gone would have passed against the
    // defect it exists to catch. The two marker-absence assertions are what separate "scanned" from
    // "dropped behind a marker", the length bound is what states that failure in bytes, and the
    // surviving-key assertion is what proves the pair was redacted in place rather than removed
    // wholesale — the same shape as the CR-02 sweeps below, one leg stronger.
    //
    // FIXTURE REACHABILITY (the 21-05 lesson: a test some OTHER rule also satisfies proves nothing).
    // SC4-NEWLINE-SECRET-9 is reachable by jsonSecretKeyRegex and by nothing else, and the seam makes
    // that AIRTIGHT rather than merely argued — the same strengthening testRedactCookieSections gave
    // cookieSectionDeadlineFailsClosed:
    //   - Redaction.testWindowedBodyStage bypasses Redaction.apply entirely, so the HEADER STAGE
    //     never runs at all. urlTokenParamRegex, bearerRegex, basicAuthRegex, jwtRegex, the two
    //     header rules, the cookie-section rule and the typed-parameter rule are all structurally
    //     out of reach, rather than merely unable to match this fixture. Only bodyRules runs;
    //   - within bodyRules, the fixture contains no '=' anywhere, so formBodyParamRegex cannot reach
    //     the pair either, leaving jsonSecretKeyRegex as the sole rule that can;
    //   - no custom pattern is registered, and @AfterEach resetCustomPatterns guarantees no bleed
    //     from oversizeBodyFailsClosed / subWindowBodyFailsClosed, which both install "(a+)+$".
    //     A leaked "(a+)+$" would matter here: bodyRules would carry a third, pathological rule.
    // Established by mutation, not by inspection.
    //
    // WHY THIS DRIVES A SEAM RATHER THAN Redaction.apply (W-04 / T-21-52), recorded because it is a
    // deliberate weakening of one dimension to remove a race in another.
    //
    // Through Redaction.apply this test was RED on every isolated run: measured 2.196 / 2.290 / 2.345
    // / 2.246 s against a 2 000 ms budget on Apple Silicon / JDK 21 with the JaCoCo agent attached,
    // and green in a full-suite run only because 600+ preceding tests had warmed the JIT. The failure
    // presented as the capability assertion below going red while the secret-absence assertion stayed
    // green — the window was dropped fail-closed, so it was never a leak, but it was an indefinitely
    // red security test, and a red security test is one contributor away from being @Disabled.
    //
    // TWO INDEPENDENT CAUSES, both now removed. Recorded in full because a fix aimed at only the
    // first would have left this test red:
    //   1. a TOTAL-BUDGET race. The stage ran at 97-101 % of MAX_REDACTION_BUDGET_MS, and the
    //      reviewer bisected the break point at roughly a 1 000 ms effective budget, the ordinary
    //      speed of a GitHub-hosted runner for single-threaded regex work before instrumentation.
    //      That is what NEWLINE_FREE_INJECTED_BUDGET_MS removes.
    //   2. a PER-RULE BOUND cliff. The per-rule bound was a wall clock, so whether the ladder engaged,
    //      and whether its deepest pieces (fixture/2^WINDOW_RETRY_MAX_DEPTH) then scanned, depended
    //      on the machine. It is now a deterministic access budget, and this test injects it: 0 above
    //      NEWLINE_FREE_LADDER_EXHAUST_ABOVE, the shipped budget below. Depths 0 and 1 exhaust and
    //      depth 2 scans, on any machine. newlineFreeOversizeBodyCollapsesWhenNoLadderPieceCanScan
    //      is the anti-vacuity twin that proves the injection reaches scanWindow.
    //
    // The shipped 2 s budget stays exactly as it is: it is a product decision, not a dial, and
    // raising it to make an assertion pass would be tuning the product to the test. What is injected
    // instead, through Redaction.testWindowedBodyStage, is a generous total budget and a ladder-forcing
    // per-rule budget, so this assertion measures SCANNING BEHAVIOUR rather than machine speed. With
    // the shipped per-rule budget the built-in rules never exhaust, the body scans in one pass, and
    // the ladder this test exists to carry would go untested.
    //
    // WHAT IS GIVEN UP, stated plainly: this test no longer exercises Redaction.apply -> bodyStage ->
    // windowedScan end to end. That wiring is still covered, by five tests that all drive
    // Redaction.apply on a body above the window width and were all verified green alongside this
    // change:
    //   - oversizeBodySecretDoesNotSurvive (1 000 100 chars, secret past the old cut-off, redacted);
    //   - oversizeBodyFailsClosed (1 201 200 chars, every window dropped behind a marker);
    //   - subWindowBodyFailsClosed (800 800 chars — BELOW the window width, so it additionally covers
    //     the single-pass timeout FALLTHROUGH into windowedScan, which none of the others reach);
    //   - windowedScanRedactsJsonPairAcrossEveryBoundaryAlignment,
    //     jsonPairWithBlankLineBetweenKeyAndValueIsRedacted and
    //     windowedScanRedactsJsonPairWhoseValueStraddlesTheCut (24 alignments each, > 1 MB per
    //     alignment, asserting successful redaction AND the absence of both markers).
    // So bodyStage's dispatch into windowedScan is asserted six ways over; what this test uniquely
    // carries is the newline-free RETRY LADDER, and that is what the seam preserves.
    //
    // TIMING EXPOSURE, rewritten to describe what ships. There is none left in this test: the total
    // budget is injected far above the measured run of the stage, the per-rule bound counts accesses,
    // and no assertion below reads a clock. A RED RUN HERE IS A GENUINE CR-04 REGRESSION, not timing
    // pressure under instrumentation - that diagnosis applied to the previous form of this test and no longer
    // applies to this one. Check splitPointCutsNewlineFreeWindowsInsteadOfRefusing first: it asserts
    // the same defect as pure arithmetic in 0 ms, so if it is red too, splitPoint itself has
    // regressed; if it is green while this is red, the ladder's wiring has broken downstream of
    // splitPoint — in dropOrRetry, scanWindow or windowedScan's append path.
    @Test
    fun newlineFreeOversizeBodyIsScannedNotDestroyed() {
        val target = Defaults.MAX_REDACTION_BODY_CHARS * NEWLINE_FREE_WINDOW_MULTIPLIER
        val body =
            buildString {
                while (length < target / 2) append(NEWLINE_FREE_FRAGMENT)
                append(NEWLINE_FREE_SECRET_PAIR)
                while (length < target) append(NEWLINE_FREE_FRAGMENT)
            }
        // Both fixture properties are load-bearing and are asserted so a later edit cannot defuse
        // this test silently. The '\n' guard is unchanged in force: one newline anywhere would hand
        // splitPoint the line boundary whose ABSENCE is the whole defect. The width guard's ROLE has
        // changed and is stated rather than left stale — the seam calls windowedScan directly, so
        // this guard no longer CAUSES the windowing; it pins that the fixture is one production
        // bodyStage would route to windowedScan rather than through its single-pass branch, which is
        // what keeps the seam's input representative of the shipped path.
        assertTrue(
            body.length > Defaults.MAX_REDACTION_BODY_CHARS,
            "The fixture must exceed the window width, or bodyStage would take its single-pass branch " +
                "in production and this seam would no longer stand in for the shipped path",
        )
        assertFalse(
            body.contains('\n'),
            "The fixture must contain NO newline, or splitPoint takes its line-boundary branch and CR-04 is not exercised",
        )

        val start = System.currentTimeMillis()
        val output =
            Redaction.testWindowedBodyStage(
                body,
                budgetMs = NEWLINE_FREE_INJECTED_BUDGET_MS,
                accessBudget = { len -> if (len > NEWLINE_FREE_LADDER_EXHAUST_ABOVE) 0L else SafeRegex.accessBudgetFor(len) },
            )
        // MEASURED, NEVER ASSERTED ON. The previous form of this test carried an
        // `assertTrue(elapsed < 30_000)` crash guard, and it is deliberately gone rather than
        // retightened, for two independent reasons. First, it could not do the job it was named for:
        // it runs AFTER the call returns, so it cannot catch a hang — only a slow-but-correct run,
        // which is precisely the flake being removed here. Second, the injected budget already bounds
        // this stage far more tightly and more informatively than any millisecond literal could: if
        // the budget were ever reached, windowedScan emits a marker and breaks, and the marker
        // assertion below then fails with the exact shape and character count rather than with a
        // stopwatch reading. The number is still captured and still reported in the failure messages,
        // because a red run is much easier to diagnose with it than without it.
        val elapsed = System.currentTimeMillis() - start

        // "BUILT-INS ENABLED" rather than "STRICT", deliberately: the seam pins
        // bodyRules(builtinsEnabled = true), which is the rule list BOTH STRICT and BALANCED produce,
        // and no RedactionPolicy is consulted on this path. Saying STRICT here would name a mode the
        // call does not read.
        assertFalse(
            output.contains("SC4-NEWLINE-SECRET-9"),
            "BUILT-INS ENABLED: a secret in a newline-free oversize body must not survive the body stage",
        )
        assertTrue(
            output.contains("\"api_key\":\"[REDACTED]\""),
            "BUILT-INS ENABLED: the pair must be redacted IN PLACE, keeping its key — not removed wholesale " +
                "(stage took ${elapsed}ms of a ${NEWLINE_FREE_INJECTED_BUDGET_MS}ms injected budget)",
        )
        // STRENGTHENED under the injected budget, and only affordable because of it. Under the
        // shipped 2 s budget a marker was a legitimate outcome on a slow machine, so the strongest
        // available statement was the half-length bound below. With budget exhaustion unreachable,
        // NEITHER marker shape may appear ANYWHERE: every one of the ~1 MB must be scanned and
        // appended, so any marker at all means the ladder failed to produce a scannable piece.
        assertFalse(
            output.contains("REDACTION INCOMPLETE"),
            "No window may be dropped when the budget cannot be exhausted; a drop marker here means the " +
                "retry ladder failed to produce a scannable piece (stage took ${elapsed}ms of " +
                "${NEWLINE_FREE_INJECTED_BUDGET_MS}ms)",
        )
        assertFalse(
            output.contains("REDACTION BUDGET EXCEEDED"),
            "The injected budget is ~150x the measured cost of this stage; a budget marker here means " +
                "the seam is not honouring its budgetMs parameter (stage took ${elapsed}ms of " +
                "${NEWLINE_FREE_INJECTED_BUDGET_MS}ms)",
        )
        // KEPT alongside the two marker assertions, not replaced by them: this is the assertion that
        // names the failure IN BYTES when it goes red. CR-04's pre-fix output was 59 characters
        // against a 4 000 005-character input, and that number is what made the defect legible.
        assertTrue(
            output.length > body.length / 2,
            "A newline-free body must be SCANNED, not collapsed behind a drop marker; " +
                "output was ${output.length} chars against a ${body.length}-char input",
        )
    }

    // ANTI-VACUITY TWIN of newlineFreeOversizeBodyIsScannedNotDestroyed: the same body under a
    // per-rule access budget of 0 EVERYWHERE, so no ladder depth can scan. It must collapse behind
    // drop markers with the secret gone. Without this twin, a seam that ignored its accessBudget
    // parameter would leave the sibling green (the shipped budget scans the body in one pass) while
    // the ladder it claims to exercise never ran.
    @Test
    fun newlineFreeOversizeBodyCollapsesWhenNoLadderPieceCanScan() {
        val target = Defaults.MAX_REDACTION_BODY_CHARS * NEWLINE_FREE_WINDOW_MULTIPLIER
        val body =
            buildString {
                while (length < target / 2) append(NEWLINE_FREE_FRAGMENT)
                append(NEWLINE_FREE_SECRET_PAIR)
                while (length < target) append(NEWLINE_FREE_FRAGMENT)
            }

        val output = Redaction.testWindowedBodyStage(body, budgetMs = NEWLINE_FREE_INJECTED_BUDGET_MS, accessBudget = { 0L })

        assertTrue(
            output.contains("REDACTION INCOMPLETE"),
            "With a zero access budget at every depth the ladder cannot produce a scannable piece, so the body " +
                "must be dropped behind markers",
        )
        assertTrue(
            output.length < body.length / 2,
            "A body no piece of which can scan must collapse to markers; output was ${output.length} chars " +
                "against a ${body.length}-char input",
        )
        assertFalse(output.contains("SC4-NEWLINE-SECRET-9"), "A dropped body must not carry the secret")
    }

    // HEADROOM PIN for SafeRegex.ACCESS_BUDGET_PER_CHAR. The worst measured built-in shapes are
    // degenerate 1 MB bodies: only '&' or only newlines through formBodyParamRegex (30.0 accesses per
    // char) and only '"' through jsonSecretKeyRegex (29.0). Each must pass the windowed body stage
    // UNCHANGED under HALF the shipped budget (32.5 per char at this size), so the shipped budget
    // keeps a factor of at least 2 over them. A cost regression in either built-in rule then trips
    // here deterministically, on any machine, instead of dropping content behind markers in use.
    @Test
    fun builtinBodyRulesFitInHalfTheAccessBudgetOnDegenerateBodies() {
        val shapes = listOf("'&'" to '&', "newline" to '\n', "'\"'" to '"')
        for ((label, c) in shapes) {
            val body = c.toString().repeat(Defaults.MAX_REDACTION_BODY_CHARS)

            val output =
                Redaction.testWindowedBodyStage(body, NEWLINE_FREE_INJECTED_BUDGET_MS) { SafeRegex.accessBudgetFor(it) / 2 }

            assertTrue(
                output == body,
                "$label x ${body.length}: the built-in body rules must scan this body unchanged under HALF the access " +
                    "budget, or ACCESS_BUDGET_PER_CHAR no longer keeps its 2x safety factor over the worst built-in " +
                    "shape (output ${output.length} chars, drop marker=${output.contains("REDACTION INCOMPLETE")})",
            )
        }
    }

    // (PRIV-06) CR-02 / WR-06 / D-01 AMENDED: the windowing invariant D-01 always CLAIMED and never
    // asserted.
    //
    // D-01's central claim was that line-boundary cutting is equivalent to whole-document
    // processing. Nothing in the committed suite ever swept a fixture across a window cut, and that
    // is precisely the gap CR-02 fell through: windowEnd mitigated its own documented hazard by
    // pulling in exactly ONE following line and never re-checking, so a key/colon/value pair spread
    // over three lines was cut in half. The reviewer reproduced it at shift 7 —
    // "windowedLeak=true singlePassLeak=false", a secret the single-pass path redacts surviving the
    // windowed path. Response bodies are attacker-controlled and window boundaries are deterministic
    // given a known prefix length, so the alignment is craftable rather than accidental.
    //
    // THE ANTI-VACUITY ASSERTION IS LOAD-BEARING, not decoration. A DROPPED window also removes the
    // secret, so "the secret is absent" on its own would be satisfied by the fail-closed path and
    // this sweep would degrade into a second oversizeBodyFailsClosed — passing for entirely the
    // wrong reason while proving nothing about equivalence. Asserting that no drop marker was
    // emitted is what forces the pair to have been REDACTED. The surviving key is the third leg: it
    // proves the region was redacted in place rather than removed wholesale.
    //
    // FIXTURE STRENGTH (the 21-05 lesson: a test that some OTHER rule also satisfies is vacuous).
    // BOUNDARY-SECRET-7 is reachable by jsonSecretKeyRegex and by nothing else in either stage:
    //   - it contains no '=', so formBodyParamRegex cannot reach it, and urlTokenParamRegex — which
    //     runs unbounded in the header stage and would otherwise mask the defect — additionally
    //     requires a leading '?' or '&';
    //   - the value is not Bearer- or Basic-prefixed and does not begin "eyJ", so bearerRegex,
    //     basicAuthRegex and jwtRegex cannot match it;
    //   - there is no "Cookie:" or "Set-Cookie:" header, no "=== COOKIES ===" section and no
    //     " (COOKIE)" type suffix, so neither cookie rule can reach it;
    //   - no custom pattern is registered, and @AfterEach resetCustomPatterns guarantees no bleed
    //     from a sibling test.
    // If the JSON rule does not match across the cut, the value survives verbatim. Established by
    // mutation, not by inspection.
    @Test
    fun windowedScanRedactsJsonPairAcrossEveryBoundaryAlignment() {
        // Key, colon and value on three separate lines — the exact shape windowEnd's own comment
        // cited as the hazard and then failed to handle.
        val pair = "  \"token\"\n  :\n  \"BOUNDARY-SECRET-7\"\n"

        for (shift in 0 until BOUNDARY_SWEEP_SHIFTS) {
            val body = boundarySweepBody(shift, pair)
            assertTrue(
                body.length > Defaults.MAX_REDACTION_BODY_CHARS,
                "shift=$shift: the fixture must exceed the window width, or this sweeps the single-pass path",
            )

            val policy = RedactionPolicy.fromMode(PrivacyMode.STRICT)
            val output = Redaction.apply(body, policy, stableHostSalt = "salt")

            assertFalse(
                output.contains("BOUNDARY-SECRET-7"),
                "shift=$shift: a JSON pair straddling a window boundary must still be redacted",
            )
            assertFalse(
                output.contains("REDACTION INCOMPLETE") || output.contains("REDACTION BUDGET EXCEEDED"),
                "shift=$shift: the sweep must prove the pair was REDACTED, not that the window was DROPPED",
            )
            assertTrue(
                output.contains("\"token\""),
                "shift=$shift: the key must survive, so the pair was redacted in place, not removed wholesale",
            )
        }
    }

    // (PRIV-06) CR-02, second half: a whitespace-only line between the colon and the value must not
    // let the pair slip through.
    //
    // jsonSecretKeyRegex's \s* spans newlines, so "key" / ':' / blank / "value" is a single match on
    // the single-pass path — confirmed against the real pattern before this test was written, so it
    // asserts a property the engine genuinely has rather than one contorted into existence for it.
    // A loop that stops extending the window the moment it meets a blank line therefore still cuts
    // this shape in half, which is why isJsonPairBoundaryContinuation treats a blank line as a
    // continuation of risk while isJsonPairBoundaryRisk does not START one on it.
    //
    // Same three assertions and the same fixture-strength argument as the sibling above:
    // BLANK-GAP-SECRET-3 carries no '=', no bearer/basic prefix, no "eyJ" and no cookie context, so
    // only the JSON rule can reach it.
    @Test
    fun jsonPairWithBlankLineBetweenKeyAndValueIsRedacted() {
        val pair = "  \"token\"\n  :\n\n  \"BLANK-GAP-SECRET-3\"\n"

        for (shift in 0 until BOUNDARY_SWEEP_SHIFTS) {
            val body = boundarySweepBody(shift, pair)
            assertTrue(
                body.length > Defaults.MAX_REDACTION_BODY_CHARS,
                "shift=$shift: the fixture must exceed the window width, or this sweeps the single-pass path",
            )

            val policy = RedactionPolicy.fromMode(PrivacyMode.STRICT)
            val output = Redaction.apply(body, policy, stableHostSalt = "salt")

            assertFalse(
                output.contains("BLANK-GAP-SECRET-3"),
                "shift=$shift: a blank line between key and value must not carry the pair past a window cut",
            )
            assertFalse(
                output.contains("REDACTION INCOMPLETE") || output.contains("REDACTION BUDGET EXCEEDED"),
                "shift=$shift: the sweep must prove the pair was REDACTED, not that the window was DROPPED",
            )
            assertTrue(
                output.contains("\"token\""),
                "shift=$shift: the key must survive, so the pair was redacted in place, not removed wholesale",
            )
        }
    }

    // (PRIV-06) CR-02, third shape / 21-REVIEW-2 CR-01: the cut landing INSIDE AN OPEN QUOTED VALUE.
    //
    // The two sweeps above cover cuts that land in the whitespace AROUND THE COLON, and that is the
    // only state the original two-clause isJsonPairBoundaryRisk could see: it asked whether the
    // window's last line ends with ':' or '"'. jsonSecretKeyRegex's value alternative is "[^"]*",
    // and [^"] matches a newline, so the pair has a SECOND in-flight state — the value's opening
    // quote on one line and its closing quote on the next. There the window's last line ends with an
    // ordinary value character ('K' below), the risk check returns false, no extension is started,
    // MAX_JSON_BOUNDARY_LOOKAHEAD_LINES is never consulted, and the pair is cut in half. Neither
    // half matches, so the value is emitted VERBATIM — a leak, not a fail-closed drop.
    //
    // WHY THE TWO SIBLING SWEEPS STRUCTURALLY CANNOT REACH IT: in both of their fixtures every line
    // of the pair ends on ':' or '"', which is precisely the state the old predicate already
    // detected. No shift of either fixture can produce a line ending mid-value. This is one fixture
    // family covering one of two states, which is why CR-02 was reported closed while still leaking.
    //
    // FIXTURE GEOMETRY IS LOAD-BEARING AND WAS MEASURED, NOT ASSUMED. boundarySweepBody places the
    // pair at a position that is PERIODIC in PAD_LINE_CHARS: across every shift the pair starts in
    // [999981, 1000000], so the cut can only fall after the pair's FIRST line when that line is at
    // most 19 characters. The first line here is 16. A longer first line does not weaken the test,
    // it VACATES it: 21-REVIEW-2's literally-suggested fixture, whose first line is 31 characters,
    // was driven through this builder over 40 alignments and leaked 0 times pre-fix, because the cut
    // always landed at the pair's start and handed the whole pair to the next window. Do not
    // "simplify" the value split below without re-measuring; the sentinel must also stay whole on
    // ONE line, since a sentinel spanning the cut would be absent from the output for the trivial
    // reason that it contains a newline.
    //
    // THE ANTI-VACUITY ASSERTION IS LOAD-BEARING, exactly as in the two siblings: a DROPPED window
    // also removes the sentinel, so "the sentinel is absent" alone would be satisfied by the
    // fail-closed path. Asserting no drop marker is what forces the pair to have been REDACTED, and
    // it is what makes this test reproduce the reviewer's measured shape — leak with
    // dropMarker=false — rather than a fail-closed drop.
    //
    // FIXTURE STRENGTH. STRADDLE-SECRET-2 is reachable by jsonSecretKeyRegex and by nothing else in
    // either stage:
    //   - the pair carries no '=' anywhere, so formBodyParamRegex cannot reach it, and
    //     urlTokenParamRegex — which runs UNBOUNDED in the header stage and would otherwise mask
    //     this defect entirely — additionally requires a leading '?' or '&';
    //   - the value is neither Bearer- nor Basic-prefixed and does not begin "eyJ", so bearerRegex,
    //     basicAuthRegex and jwtRegex cannot match it;
    //   - there is no "Cookie:"/"Set-Cookie:" header, no "=== COOKIES ===" section and no
    //     " (COOKIE)" type suffix, so neither cookie rule — including 21-08's section rule — reaches
    //     it;
    //   - the padding is 'y' and 'z' only, so it cannot manufacture a "[REDACTED]" and create a
    //     false positive on the surviving-key leg;
    //   - no custom pattern is registered, and @AfterEach resetCustomPatterns prevents bleed from
    //     oversizeBodyFailsClosed / subWindowBodyFailsClosed, which both install "(a+)+$".
    // So only jsonSecretKeyRegex can reach the sentinel. Established by mutation M1, not by
    // inspection.
    @Test
    fun windowedScanRedactsJsonPairWhoseValueStraddlesTheCut() {
        // Key, colon, the value's opening quote and two value characters on the first line; the
        // value's remainder and its closing quote on the second. The trailing "AK" is what makes the
        // line end on an ordinary value character instead of on the quote the old predicate saw.
        val pair = "  \"api_key\": \"AK\nSTRADDLE-SECRET-2\"\n"

        for (shift in 0 until BOUNDARY_SWEEP_SHIFTS) {
            val body = boundarySweepBody(shift, pair)
            assertTrue(
                body.length > Defaults.MAX_REDACTION_BODY_CHARS,
                "shift=$shift: the fixture must exceed the window width, or this sweeps the single-pass path",
            )

            val policy = RedactionPolicy.fromMode(PrivacyMode.STRICT)
            val output = Redaction.apply(body, policy, stableHostSalt = "salt")

            assertFalse(
                output.contains("STRADDLE-SECRET-2"),
                "shift=$shift: a quoted value straddling a window boundary must still be redacted",
            )
            assertFalse(
                output.contains("REDACTION INCOMPLETE") || output.contains("REDACTION BUDGET EXCEEDED"),
                "shift=$shift: the sweep must prove the pair was REDACTED, not that the window was DROPPED",
            )
            assertTrue(
                output.contains("\"api_key\""),
                "shift=$shift: the key must survive, so the pair was redacted in place, not removed wholesale",
            )
        }
    }

    // DETERMINISM PIN: the same input redacts byte-identically on two consecutive runs. Under the
    // former per-rule wall clock this sweep fixture was marked at shift=18 on a loaded Windows
    // runner, and every shift under 3x CPU oversubscription; no per-rule outcome reads a clock now.
    // The straddle pair at shifts 0, 7 and 18, with no marker in either output.
    @Test
    fun boundarySweepRedactionIsIdenticalAcrossRepeatedRuns() {
        val pair = "  \"api_key\": \"AK\nSTRADDLE-SECRET-2\"\n"
        val policy = RedactionPolicy.fromMode(PrivacyMode.STRICT)

        for (shift in listOf(0, 7, 18)) {
            val body = boundarySweepBody(shift, pair)

            val first = Redaction.apply(body, policy, stableHostSalt = "salt")
            val second = Redaction.apply(body, policy, stableHostSalt = "salt")

            assertTrue(first == second, "shift=$shift: two runs over the same input must redact byte-identically")
            assertFalse(
                first.contains("REDACTION INCOMPLETE") || first.contains("REDACTION BUDGET EXCEEDED"),
                "shift=$shift: the sweep fixture must scan without a marker",
            )
            assertFalse(first.contains("STRADDLE-SECRET-2"), "shift=$shift: the straddling secret must be redacted")
        }
    }

    // (PRIV-06) CR-02 / IN-03 / T-21-54: reaching MAX_JSON_BOUNDARY_LOOKAHEAD_LINES had no test.
    //
    // The cap is documented as a deliberate residual and it behaves as documented, but NOTHING
    // asserted either half of it: not that the loop stops at eight, and not that the window stays
    // line-aligned once it does. A change to the cap, or to isJsonPairBoundaryContinuation, would move
    // the boundary silently — and this round WIDENED that predicate (endsInsideOpenQuotedValue), which
    // is what turns a theoretical gap into a live one.
    //
    // WHY A SEAM RATHER THAN AN END-TO-END FIXTURE. Reaching the cap through Redaction.apply takes a
    // multi-megabyte body, slow to build and to scan, for a property that is not about scanning at
    // all. Where the loop stops is a pure function, so it is asserted as one. Same reasoning, and the same answer, as testSplitPoint.
    //
    // THE FIXTURE'S ANTI-VACUITY PROPERTIES ARE ASSERTED, NOT DESCRIBED — plan 21-11 shipped two seam
    // tests in this very file that were vacuous by numeric coincidence, so a comment claiming a
    // fixture is sound is worth nothing here. Three guards, each closing a different way this test
    // could pass while proving nothing:
    //   1. the fixture supplies MORE continuing lines than the cap, so the loop is stopped by the CAP
    //      and not by running out of continuing content (which is a different branch);
    //   2. a CONTROL fixture, identical except that the line before the boundary is ordinary filler,
    //      must return the natural cut EXACTLY. That simultaneously proves the natural-cut arithmetic
    //      below is right and that an extension is genuinely required in the real fixture — without
    //      it, a windowEnd that never extended at all would satisfy nothing here but would also not
    //      be detected;
    //   3. the returned index is asserted line-aligned, which is the half of the cap's contract that
    //      says the window stays cuttable at a line boundary even when the lookahead is truncated.
    // Verified by mutation M3 (cap lowered to 4: this test fails by exactly four lines) rather than by
    // inspection.
    @Test
    fun windowEndStopsAtTheJsonBoundaryLookaheadCap() {
        assertTrue(
            LOOKAHEAD_CONTINUING_LINES > LOOKAHEAD_CAP_MIRROR,
            "The fixture must offer MORE continuing lines ($LOOKAHEAD_CONTINUING_LINES) than the cap " +
                "($LOOKAHEAD_CAP_MIRROR), or the loop could stop for lack of input instead of at the cap " +
                "and this test would pin the wrong branch",
        )

        // Lead filler, then ONE risk-starting line, then more continuing lines than the cap allows,
        // then plain filler so the loop always has a next line to consider.
        val body =
            LOOKAHEAD_FILLER_LINE.repeat(LOOKAHEAD_LEAD_LINES) +
                LOOKAHEAD_RISKY_LINE +
                LOOKAHEAD_RISKY_LINE.repeat(LOOKAHEAD_CONTINUING_LINES) +
                LOOKAHEAD_FILLER_LINE.repeat(LOOKAHEAD_TRAIL_LINES)
        // The same fixture with the risk-starting line replaced by ordinary filler. Everything after
        // it is byte-identical, so the ONLY difference between the two results is whether an
        // extension started at all.
        val control =
            LOOKAHEAD_FILLER_LINE.repeat(LOOKAHEAD_LEAD_LINES) +
                LOOKAHEAD_FILLER_LINE +
                LOOKAHEAD_RISKY_LINE.repeat(LOOKAHEAD_CONTINUING_LINES) +
                LOOKAHEAD_FILLER_LINE.repeat(LOOKAHEAD_TRAIL_LINES)

        // The boundary windowEnd would take with no extension: just past the newline that ends the
        // risk-starting line. Computed from the fixture's own geometry rather than hard-coded.
        val naturalCut = LOOKAHEAD_LINE_CHARS * (LOOKAHEAD_LEAD_LINES + 1)
        // Half a line past that newline, so lastIndexOf('\n', start + width) lands on it. Any width
        // from naturalCut - 1 to the next newline inclusive selects the same boundary.
        val width = naturalCut + LOOKAHEAD_LINE_CHARS / 2

        assertEquals(
            naturalCut,
            Redaction.testWindowEnd(control, 0, width),
            "ANTI-VACUITY: with an ordinary line before the boundary, windowEnd must return the natural " +
                "cut untouched. If this is wrong the natural-cut arithmetic below is wrong too, and the " +
                "cap assertion would be measuring nothing",
        )

        val end = Redaction.testWindowEnd(body, 0, width)

        assertEquals(
            naturalCut + LOOKAHEAD_CAP_MIRROR * LOOKAHEAD_LINE_CHARS,
            end,
            "The lookahead must stop at exactly MAX_JSON_BOUNDARY_LOOKAHEAD_LINES ($LOOKAHEAD_CAP_MIRROR) " +
                "lines past the natural cut — not one more, and not the end of the input, both of which " +
                "are reachable branches of this loop",
        )
        assertEquals(
            '\n',
            body[end - 1],
            "At the cap the window must still be LINE-ALIGNED: only the boundary moved. A mid-line " +
                "boundary here would hand the next window an artificial (?m)^ anchor",
        )
    }

    // (PRIV-06) CR-02 / WR-06: one oversize body whose JSON [pair] sits [shift] characters past the
    // natural PAD_LINE_CHARS alignment. Sweeping [shift] walks the pair across the deterministic
    // window cut one character at a time, which is the whole technique: the defect is invisible at
    // most alignments and only appears when the cut lands between the key and its value.
    private fun boundarySweepBody(
        shift: Int,
        pair: String,
    ): String =
        buildString {
            val pad = "y".repeat(PAD_LINE_CHARS - 1) + "\n"
            while (length < Defaults.MAX_REDACTION_BODY_CHARS - PAD_LINE_CHARS - shift) append(pad)
            append("z".repeat(shift)).append('\n')
            append(pair)
            while (length < Defaults.MAX_REDACTION_BODY_CHARS + SWEEP_TAIL_CHARS) append(pad)
        }
}
