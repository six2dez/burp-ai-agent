package com.six2dez.burp.aiagent.mcp.tools

import burp.api.montoya.MontoyaApi
import burp.api.montoya.core.BurpSuiteEdition
import burp.api.montoya.http.message.params.HttpParameterType
import burp.api.montoya.http.message.params.ParsedHttpParameter
import com.six2dez.burp.aiagent.mcp.McpRequestLimiter
import com.six2dez.burp.aiagent.mcp.McpToolContext
import com.six2dez.burp.aiagent.redact.PrivacyMode
import com.six2dez.burp.aiagent.redact.Redaction
import com.six2dez.burp.aiagent.redact.RedactionPolicy
import kotlinx.serialization.encodeToString
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.mockito.Answers
import org.mockito.kotlin.mock
import org.mockito.kotlin.whenever
import java.io.File

/**
 * (PRIV-05) Phase 27 plan 27-07 — the THIRD carrier of the same cookie bytes: COOKIE-typed HTTP
 * parameters.
 *
 * WHAT THIS FILE ASSERTS ON, and why it is a different shape from both `RedactionTest`'s cookie
 * fixtures and `SerializedEmissionRedactionTest`'s raw-message carrier: Burp parses the `Cookie:`
 * header into `HttpParameterType.COOKIE` parameters, and `HttpRequest.parameters()` hands those
 * VALUES to four live MCP producers — `request_parse` and `params_extract`, once per executor. In
 * `request_parse` the leak sat inside the same JSON object as its own control: `headers` was
 * cookie-stripped by `sanitizeHeaders` while `parameters` returned the identical value verbatim.
 *
 * THE CONTROL UNDER TEST IS TYPE-KEYED, NOT SHAPE-KEYED. Every probe here drives the REAL
 * [sanitizeParameters] and the REAL [toolJson] serializer — never a reimplementation of either. A
 * gate that does not exercise the code it guards is the second anti-pattern this phase paid for:
 * `Redaction.cookieTypedParamRegex` is keyed to the passive scanner's `name=value (COOKIE)`
 * rendering, was verified green at the site it was written for, and is measurably blind to both MCP
 * shapes.
 *
 * SCOPE OF THE CLAIM THIS FILE SUPPORTS: the MCP parameter carrier, and the cookie TYPE class.
 * Nothing here says PRIV-05 is closed, and nothing here is evidence about a URL- or BODY-typed
 * parameter whose VALUE carries a token — that is D-27-20's deliberate pass-through, measured by
 * plan 27-08 task 3, not asserted either way here.
 *
 * TWO CONTROLS LIVE IN THIS FILE, AND THEY ARE NOT INTERCHANGEABLE (added by plan 27-08 task 1).
 * The `promptPath…` methods below the "the PROMPT PATH, preserved" banner are the ONLY ones that
 * drive `Redaction.apply`; they pin the passive scanner's `name=value (TYPE)` rendering, which
 * `Redaction.cookieTypedParamRegex` owns and which already worked. Every other method drives
 * [sanitizeParameters], which owns the two MCP renderings the regex cannot reach. Neither group is
 * evidence for the other's path, and deleting one because the other exists reopens a different half.
 *
 * SENTINEL DISCIPLINE (the reason an absence assertion here cannot pass for some other rule's
 * reason). Every sentinel is a bare lowercase alphabetic word:
 *  - it contains no `=`, so `formBodyParamRegex`, `urlTokenParamRegex` and `cookieTypedParamRegex`
 *    cannot claim it;
 *  - it carries no `Bearer ` / `Basic ` prefix and no dotted `eyJ` segment, so `bearerRegex`,
 *    `basicAuthRegex` and `jwtRegex` cannot claim it;
 *  - the enclosing JSON key is the literal `value`, which is not in `SENSITIVE_WORDS`, so
 *    `jsonSecretKeyRegex` cannot claim it;
 *  - no `=== COOKIES ===` section is ever built, so `redactCookieSections` never runs.
 *
 * These probes additionally do NOT call `redactIfNeeded` at all — the control is at the PRODUCER,
 * so a pass here is attributable to [sanitizeParameters] and to nothing else in the rule set.
 *
 * FLAT, not `@Nested`, DELIBERATELY. JUnit writes each `@Nested` inner class to its OWN
 * `TEST-<outer>$<Inner>.xml`, so this plan's acceptance gate — "every test method present BY NAME in
 * `TEST-…ParameterCarrierRedactionTest.xml`" — would be unsatisfiable against a nested layout no
 * matter how green the suite was. That is the `WINDOWS.md` 11/13/14/15 class exactly: a criterion
 * that counts a population the artifact does not contain. One class, one XML, one decidable gate.
 */
class ParameterCarrierRedactionTest {
    @BeforeEach
    fun clearCustomPatterns() {
        // Redaction is a singleton object: custom patterns left behind by another test class in the
        // same JVM could remove a sentinel for the wrong reason and let an absence assertion pass
        // without this control doing anything. Precedent: SerializedEmissionRedactionTest.
        Redaction.setCustomPatterns(emptyList())
    }

    @Test
    fun everySentinelInThisFileIsDistinct() {
        // Distinctness asserted IN KOTLIN over the list the fixtures actually draw from, so a
        // copy-paste collision fails rather than flatters. The substring half is load-bearing in its
        // own right: every gate below is an `assertFalse(output.contains(sentinel))`, and a sentinel
        // that is a SUBSTRING of another defeats that gate exactly as a duplicate does.
        assertEquals(
            ALL_SENTINELS.size,
            ALL_SENTINELS.toSet().size,
            "sentinels must be distinct, or one probe's success masks another's failure: $ALL_SENTINELS",
        )
        for (a in ALL_SENTINELS) {
            for (b in ALL_SENTINELS) {
                if (a === b) continue
                assertFalse(
                    b.contains(a),
                    "'$a' is a substring of '$b' — an absence assertion on '$a' could then pass while '$b' leaks",
                )
            }
        }
    }

    // ── the sanitizer itself: type-keyed, order-preserving, policy-driven ────────────────

    @Test
    fun cookieTypedParameterValueIsStrippedUnderStrict() {
        val sanitized =
            sanitizeParameters(
                listOf(cookieParam("wibble", Sentinel.COOKIE_STRICT.value)),
                contextWith(PrivacyMode.STRICT, "param-strict-salt"),
            )

        assertEquals(1, sanitized.size, "arity must be preserved")
        assertEquals(STRIPPED_MARKER, sanitized[0].value, "a COOKIE-typed value must not survive STRICT")
        assertEquals("wibble", sanitized[0].name, "the parameter NAME is not the secret and must survive verbatim")
        assertEquals("COOKIE", sanitized[0].type, "the type label must survive verbatim")
    }

    @Test
    fun cookieTypedParameterValueIsStrippedUnderBalanced() {
        val sanitized =
            sanitizeParameters(
                listOf(cookieParam("wibble", Sentinel.COOKIE_BALANCED.value)),
                contextWith(PrivacyMode.BALANCED, "param-balanced-salt"),
            )

        assertEquals(STRIPPED_MARKER, sanitized[0].value, "BALANCED carries stripCookies too")
    }

    @Test
    fun cookieTypedParameterValuePassesThroughUnderOff() {
        // The OFF control. Its whole job is to prove this is a MEASUREMENT OF THE POLICY and not a
        // blanket strip — an absence assertion that would also pass with the value hard-coded away is
        // not evidence. Note the assertion is on pass-through under a NON-redacting policy:
        // 26-SECURITY.md records that a green assertion of SURVIVAL under STRICT is the artifact the
        // threat register exists to stop producing.
        val sanitized =
            sanitizeParameters(
                listOf(cookieParam("wibble", Sentinel.COOKIE_OFF.value)),
                contextWith(PrivacyMode.OFF, "param-off-salt"),
            )

        assertEquals(Sentinel.COOKIE_OFF.value, sanitized[0].value, "OFF must be OFF")
    }

    @Test
    fun urlTypedParameterValueIsUntouchedInEveryMode() {
        // Proves the key is the TYPE. A URL-typed parameter is byte-identical in all three modes,
        // including the two that strip cookies.
        for (mode in listOf(PrivacyMode.STRICT, PrivacyMode.BALANCED, PrivacyMode.OFF)) {
            val sanitized =
                sanitizeParameters(
                    listOf(paramOfType(HttpParameterType.URL, "search", Sentinel.URL_CONTROL.value)),
                    contextWith(mode, "param-url-salt-$mode"),
                )

            assertEquals(
                Sentinel.URL_CONTROL.value,
                sanitized[0].value,
                "a URL-typed parameter is outside PRIV-05's cookie wording (D-27-20) and must be untouched in $mode",
            )
        }
    }

    @Test
    fun bodyTypedParameterValueIsUntouchedInEveryMode() {
        for (mode in listOf(PrivacyMode.STRICT, PrivacyMode.BALANCED, PrivacyMode.OFF)) {
            val sanitized =
                sanitizeParameters(
                    listOf(paramOfType(HttpParameterType.BODY, "comment", Sentinel.BODY_CONTROL.value)),
                    contextWith(mode, "param-body-salt-$mode"),
                )

            assertEquals(Sentinel.BODY_CONTROL.value, sanitized[0].value, "a BODY-typed parameter must be untouched in $mode")
        }
    }

    @Test
    fun orderAndArityArePreservedAcrossMixedTypes() {
        val input =
            listOf(
                paramOfType(HttpParameterType.URL, "a", Sentinel.ORDER_URL.value),
                cookieParam("b", Sentinel.ORDER_COOKIE.value),
                paramOfType(HttpParameterType.BODY, "c", Sentinel.ORDER_BODY.value),
            )

        val sanitized = sanitizeParameters(input, contextWith(PrivacyMode.STRICT, "param-order-salt"))

        assertEquals(3, sanitized.size, "N parameters in, N out")
        assertEquals(listOf("a", "b", "c"), sanitized.map { it.name }, "sequence must be preserved")
        assertEquals(
            listOf(Sentinel.ORDER_URL.value, STRIPPED_MARKER, Sentinel.ORDER_BODY.value),
            sanitized.map { it.value },
            "only the cookie-typed entry may change, and only in place",
        )
    }

    // ── carrier 1: the request_parse serialized shape, through the REAL toolJson ─────────

    @Test
    fun cookieSentinelDoesNotSurviveTheSerializedRequestParseShapeUnderStrict() {
        val serialized = toolJson.encodeToString(parsedRequestFrom(PrivacyMode.STRICT, "rp-strict-salt", Sentinel.SERIALIZED_STRICT.value))

        assertFalse(
            serialized.contains(Sentinel.SERIALIZED_STRICT.value),
            "the cookie value reached the serialized tool result: $serialized",
        )
        assertTrue(serialized.contains(STRIPPED_MARKER), "the marker must be present in its place: $serialized")
    }

    @Test
    fun cookieSentinelDoesNotSurviveTheSerializedRequestParseShapeUnderBalanced() {
        val serialized =
            toolJson.encodeToString(parsedRequestFrom(PrivacyMode.BALANCED, "rp-balanced-salt", Sentinel.SERIALIZED_BALANCED.value))

        assertFalse(
            serialized.contains(Sentinel.SERIALIZED_BALANCED.value),
            "the cookie value reached the serialized tool result: $serialized",
        )
    }

    @Test
    fun cookieSentinelDoesSurviveTheSerializedRequestParseShapeUnderOff() {
        val serialized = toolJson.encodeToString(parsedRequestFrom(PrivacyMode.OFF, "rp-off-salt", Sentinel.SERIALIZED_OFF.value))

        assertTrue(
            serialized.contains(Sentinel.SERIALIZED_OFF.value),
            "OFF must leave the serialized shape untouched, or the two probes above prove nothing: $serialized",
        )
    }

    @Test
    fun theSerializedFieldSetIsUnchangedByThisControl() {
        // D-27-18: ParsedParam.value stays a non-null String and no field is added, removed or
        // reordered, so no MCP client's schema breaks. Asserted on the REAL serializer output.
        val stripped = toolJson.encodeToString(parsedRequestFrom(PrivacyMode.STRICT, "rp-shape-salt", Sentinel.SHAPE_STRICT.value))
        val passthrough = toolJson.encodeToString(parsedRequestFrom(PrivacyMode.OFF, "rp-shape-salt", Sentinel.SHAPE_STRICT.value))

        assertEquals(
            passthrough.replace(Sentinel.SHAPE_STRICT.value, STRIPPED_MARKER),
            stripped,
            "the only permitted difference between the two modes is the value substitution itself",
        )
    }

    // ── carrier 2: the params_extract line shape ────────────────────────────────────────

    @Test
    fun cookieSentinelDoesNotSurviveTheParamsExtractLineShapeUnderStrict() {
        val line = paramsExtractLines(PrivacyMode.STRICT, "px-strict-salt", cookieParam("wibble", Sentinel.LINE_STRICT.value))

        assertFalse(line.contains(Sentinel.LINE_STRICT.value), "the cookie value reached the params_extract line: $line")
        assertEquals("type=COOKIE name=wibble value=$STRIPPED_MARKER", line, "the line shape must be preserved around the marker")
    }

    @Test
    fun cookieSentinelDoesNotSurviveTheParamsExtractLineShapeUnderBalanced() {
        val line = paramsExtractLines(PrivacyMode.BALANCED, "px-balanced-salt", cookieParam("wibble", Sentinel.LINE_BALANCED.value))

        assertFalse(line.contains(Sentinel.LINE_BALANCED.value), "the cookie value reached the params_extract line: $line")
    }

    @Test
    fun cookieSentinelDoesSurviveTheParamsExtractLineShapeUnderOff() {
        val line = paramsExtractLines(PrivacyMode.OFF, "px-off-salt", cookieParam("wibble", Sentinel.LINE_OFF.value))

        assertEquals(
            "type=COOKIE name=wibble value=${Sentinel.LINE_OFF.value}",
            line,
            "OFF must leave the line shape untouched, or the two probes above prove nothing",
        )
    }

    @Test
    fun nonCookieParamsExtractLinesAreUnchangedInEveryMode() {
        for (mode in listOf(PrivacyMode.STRICT, PrivacyMode.BALANCED, PrivacyMode.OFF)) {
            val line =
                paramsExtractLines(
                    mode,
                    "px-noncookie-salt-$mode",
                    paramOfType(HttpParameterType.URL, "search", Sentinel.LINE_URL_CONTROL.value),
                )

            assertEquals(
                "type=URL name=search value=${Sentinel.LINE_URL_CONTROL.value}",
                line,
                "a URL-typed parameter's rendered line must be byte-identical in $mode",
            )
        }
    }

    @Test
    fun everyHttpParameterTypeRendersTheSameTokenThroughNameAsThroughToString() {
        // THE PRESERVATION PROOF FOR THIS REFACTOR, and the reason it exists rather than being
        // asserted in prose. Both params_extract producers used to render the type token via the
        // Montoya enum's `toString()`; they now render `ParsedParam.type`, which is
        // `HttpParameterType.name`. Those are the same token ONLY while no constant overrides
        // `toString()`. WINDOWS.md records what a format change costs when no fixture pins the OLD
        // correct behaviour — a quote-terminated tail that leaked on RFC 6265 DQUOTE-wrapped values
        // and would have shipped green.
        //
        // IF THIS GOES RED, DO NOT WEAKEN IT. A Montoya constant that overrides toString() is a real
        // behaviour difference in the emitted line: keep the original accessor at the affected site
        // and record the finding.
        assertTrue(HttpParameterType.entries.isNotEmpty(), "the enum walk found no constants — the fixture is vacuous")
        HttpParameterType.entries.forEach { type ->
            assertEquals(
                type.name,
                type.toString(),
                "HttpParameterType.$type overrides toString(), so switching the params_extract type " +
                    "token from toString() to name() is NOT shape-preserving for this constant",
            )
        }
    }

    // ── 27-08 task 1: the PROMPT PATH, preserved ────────────────────────────────────────
    //
    // EVERYTHING BELOW THIS LINE GUARDS A DIFFERENT PATH FROM EVERYTHING ABOVE IT. The probes above
    // drive `sanitizeParameters`, the type-keyed control that owns the two MCP renderings. The
    // probes below drive the REAL `Redaction.apply` over the PASSIVE SCANNER's `name=value (TYPE)`
    // rendering — the one shape `Redaction.cookieTypedParamRegex` matches, produced by
    // `formatParamLine` (scanner/PassiveAiScannerPrompts.kt) from
    // `PassiveAiScannerAnalysis.kt`'s parameters() mapping. Two carriers, two controls, two
    // mechanisms; they are neighbours in this file so nobody deletes one believing the other covers
    // it.
    //
    // WHY THESE ARE HERE AND NOT IN A `@Nested` CLASS, as plan 27-08 task 1's action text suggests.
    // JUnit writes each `@Nested` inner class to its OWN `TEST-<outer>$<Inner>.xml`. The same task's
    // acceptance criterion 2 requires all five fixture groups present BY NAME in
    // `TEST-…ParameterCarrierRedactionTest.xml`, which a nested layout makes unsatisfiable no matter
    // how green the suite is — the identical conflict 27-07 recorded as its own deviation 1 and the
    // `WINDOWS.md` 11/13/14/15 class. The grouping is carried by the method-name prefix
    // `promptPath…` and by this banner instead.
    //
    // WHY THESE FIXTURES ARE MANDATORY RATHER THAN DECORATIVE. `WINDOWS.md` records a
    // quote-terminated tail in this phase that leaked on RFC 6265 DQUOTE-wrapped cookie values and
    // would have SHIPPED GREEN, because no fixture in the suite carried a quote. Group (iii) below
    // is that fixture. It asserts on the FULL output string, not merely on the sentinel's absence,
    // so a mangled tail fails it too.
    //
    // ATTRIBUTION. Every parameter NAME below is drawn from outside `Redaction.SENSITIVE_WORDS`
    // (`abtestbucket`, `layoutpref`, `themechoice`), so `formBodyParamRegex` — whose `(^|[?&])`
    // anchor does reach a bare line — cannot claim any of these lines. Group (iv) is the live
    // control for that: the identical shape under a non-COOKIE label must survive STRICT untouched.
    // A pass in groups (i)/(iii)/(v) is therefore attributable to `cookieTypedParamRegex` and to
    // nothing else in the rule set.

    @Test
    fun promptPathCanonicalCookieParamLineIsRedactedUnderStrict() {
        // Group (i), STRICT. The name and the trailing type label survive; only the value changes.
        assertEquals(
            "layoutpref=$REDACTED_MARKER (COOKIE)",
            redactPromptText("layoutpref=${Sentinel.PROMPT_CANONICAL_STRICT.value} (COOKIE)", PrivacyMode.STRICT),
            "the passive scanner's canonical COOKIE parameter line must be redacted under STRICT, " +
                "with name and type label written back verbatim",
        )
    }

    @Test
    fun promptPathCanonicalCookieParamLineIsRedactedUnderBalanced() {
        // Group (i), BALANCED. BALANCED strips cookies too; only host anonymisation differs.
        assertEquals(
            "layoutpref=$REDACTED_MARKER (COOKIE)",
            redactPromptText("layoutpref=${Sentinel.PROMPT_CANONICAL_BALANCED.value} (COOKIE)", PrivacyMode.BALANCED),
            "the passive scanner's canonical COOKIE parameter line must be redacted under BALANCED",
        )
    }

    @Test
    fun promptPathCanonicalCookieParamLineIsUntouchedUnderOff() {
        // Group (ii). This is what makes the two assertions above measurements of the POLICY rather
        // than of some unconditional rewrite: the identical input is byte-identical out under OFF.
        val input = "layoutpref=${Sentinel.PROMPT_CANONICAL_OFF.value} (COOKIE)"
        assertEquals(
            input,
            redactPromptText(input, PrivacyMode.OFF),
            "OFF must not strip cookies, or groups (i) and (iii) prove nothing about the policy",
        )
    }

    @Test
    fun promptPathDquoteWrappedCookieValueIsRedactedUnderStrict() {
        // Group (iii), STRICT — THE REGRESSION CLASS WINDOWS.md RECORDS. RFC 6265 permits a
        // DQUOTE-wrapped cookie-value, so `layoutpref="value" (COOKIE)` is a legal rendering. The
        // assertion is on the WHOLE string: a rule that swallowed the closing quote, or left it
        // stranded after the marker, fails here even though the sentinel would be absent either way.
        assertEquals(
            "layoutpref=$REDACTED_MARKER (COOKIE)",
            redactPromptText(
                "layoutpref=\"${Sentinel.PROMPT_QUOTED_STRICT.value}\" (COOKIE)",
                PrivacyMode.STRICT,
            ),
            "an RFC 6265 DQUOTE-wrapped cookie value must be redacted whole under STRICT, leaving no " +
                "stranded quote in the output",
        )
    }

    @Test
    fun promptPathDquoteWrappedCookieValueIsRedactedUnderBalanced() {
        // Group (iii), BALANCED.
        assertEquals(
            "layoutpref=$REDACTED_MARKER (COOKIE)",
            redactPromptText(
                "layoutpref=\"${Sentinel.PROMPT_QUOTED_BALANCED.value}\" (COOKIE)",
                PrivacyMode.BALANCED,
            ),
            "an RFC 6265 DQUOTE-wrapped cookie value must be redacted whole under BALANCED",
        )
    }

    @Test
    fun promptPathNonCookieTypeLabelIsUntouchedInEveryMode() {
        // Group (iv), and the ATTRIBUTION CONTROL for the whole prompt-path block. The shape is
        // identical to group (i) in every respect but the type label. If this ever goes red, the
        // rule has become a blanket line strip and groups (i)/(iii)/(v) stop being evidence about a
        // COOKIE-keyed control.
        val input = "abtestbucket=${Sentinel.PROMPT_NON_COOKIE_LABEL.value} (URL)"
        for (mode in listOf(PrivacyMode.STRICT, PrivacyMode.BALANCED, PrivacyMode.OFF)) {
            assertEquals(
                input,
                redactPromptText(input, mode),
                "cookieTypedParamRegex is keyed on the COOKIE label: a URL-typed line must be " +
                    "byte-identical in $mode",
            )
        }
    }

    @Test
    fun promptPathMultiParameterBlockRedactsOnlyTheCookieLineAndPreservesOrder() {
        // Group (v). The real emitted blob is many lines, so the single-line fixtures above do not
        // by themselves show that the (?m) anchors bind per line rather than swallowing neighbours.
        val input =
            listOf(
                "abtestbucket=${Sentinel.PROMPT_MULTI_URL.value} (URL)",
                "layoutpref=${Sentinel.PROMPT_MULTI_COOKIE.value} (COOKIE)",
                "themechoice=${Sentinel.PROMPT_MULTI_BODY.value} (BODY)",
            ).joinToString(separator = "\n")

        val expected =
            listOf(
                "abtestbucket=${Sentinel.PROMPT_MULTI_URL.value} (URL)",
                "layoutpref=$REDACTED_MARKER (COOKIE)",
                "themechoice=${Sentinel.PROMPT_MULTI_BODY.value} (BODY)",
            ).joinToString(separator = "\n")

        assertEquals(
            expected,
            redactPromptText(input, PrivacyMode.STRICT),
            "only the COOKIE-typed line may change, and the three lines must keep their order",
        )
    }

    /**
     * The prompt path's redacting call, driven exactly as `PassiveAiScannerPrompts.redactScanMetadata`
     * drives it: the REAL [Redaction.apply] with [RedactionPolicy.fromMode], never a copy of the
     * pattern. `recordMapping` is left at its production default so nothing about the fixture is
     * softer than the shipped call.
     */
    private fun redactPromptText(
        text: String,
        mode: PrivacyMode,
    ): String = Redaction.apply(text, RedactionPolicy.fromMode(mode), stableHostSalt = "px-prompt-path-salt-$mode")

    // ── the producer pin: the behavioural probes above cannot reach the branch ───────────

    @Test
    fun theProducerInventoryIsExactlyFourAndEveryOneRoutesThroughTheSanitizer() {
        // WHY THIS IS A SOURCE SCAN AND NOT AN END-TO-END CALL. Every one of the four producers
        // begins `HttpRequest.httpRequest(content)`, a Montoya STATIC FACTORY that needs Burp's
        // internal ObjectFactory and cannot run in a pure-JVM test — `McpToolScopeEnforcementTest`
        // records the same constraint at its own site. So the probes above prove the SANITIZER, and
        // this pin proves the PRODUCERS are wired to it. Without this assertion the suite would stay
        // green with `sanitizeParameters` correct and never called, which is precisely the
        // "verified at the site it was written for" failure this phase exists to repair.
        //
        // ── THE BOUND OF THIS PIN, stated where a reader meets it ──
        //
        // It sees ONE CALL SHAPE (`sanitizeParameters(`) in TWO NAMED FILES. A fifth producer written
        // in a different shape, or in a third file, is INVISIBLE to it and leaves it GREEN. It is a
        // tripwire over a measured inventory, not a proof of coverage — plan 27-08 builds the wider
        // mechanism and states its own, different bound.
        //
        // THE WORKED EXAMPLE of that blindness, named rather than left abstract so a reader can go
        // and look at it. THE PREVIOUS EXAMPLE HAS BEEN CONVERTED: it was
        // `scanner/InjectionPointExtractor.kt:29`, which wrote its own `it.type().name == "COOKIE"`
        // cookie-parameter test in a THIRD file — measured by baseline B9, deliberately left
        // unconverted by D-27-17 while the issue-detail route it fed was uncontrolled, and invisible
        // to this pin. Phase 28 controlled that route (plan 28-01) and then routed the predicate
        // through `Redaction.isCookieParameterType` (plan 28-02). THE PIN'S BLINDNESS IS UNCHANGED BY
        // THAT — the conversion removed an instance, not the gap; this pin still sees one call shape
        // in two named files and nothing else.
        //
        // THE REPLACEMENT LIVE EXAMPLE, which does exist: `prompts/bountyprompt/
        // BountyPromptTagResolver.kt` (buildRequestParameters) renders `name=value (TYPE)` for prompt
        // tags and applies its OWN inline cookie control — `Redaction.isCookieParameterType(...) ->
        // "[STRIPPED]"` — in a THIRD file, without ever calling `sanitizeParameters`. This pin cannot
        // see it. The resolver is LIVE: it is constructed in production by `ui/UiActions.kt`
        // (bountyPromptResolver) and reached from the right-click BountyPrompt menu. An earlier
        // measurement that called it uninstantiated was invalidated by a raw NUL byte in that file,
        // which made grep skip it as binary (corrected in quick task 261008-jx2). A bound stated with
        // a live example is a bound; a bound stated abstractly is the sentence three prior rounds of
        // this phase also wrote.
        val perFile = PRODUCER_FILES.associateWith { path -> codeLines(path).count { it.text.contains(SANITIZER_CALL) } }

        perFile.forEach { (path, count) ->
            assertEquals(
                EXPECTED_PRODUCERS_PER_EXECUTOR,
                count,
                "$path carries $count `$SANITIZER_CALL` calls, not $EXPECTED_PRODUCERS_PER_EXECUTOR. Each executor " +
                    "registers exactly the tools in $PARAMETER_PRODUCER_TOOL_NAMES, and each must route its " +
                    "parameter values through the sanitizer. A missing call is a live cookie leak; an extra " +
                    "one means a new producer that this inventory has not been re-measured against.",
            )
        }
        assertEquals(
            EXPECTED_PRODUCERS,
            perFile.values.sum(),
            "the measured parameter-producer inventory has drifted from the pinned total. Per file: $perFile",
        )

        // The split is asserted against the tool-name set rather than restated as a second literal,
        // so the count and the names cannot disagree with each other.
        assertEquals(
            EXPECTED_PRODUCERS,
            PARAMETER_PRODUCER_TOOL_NAMES.size * PRODUCER_FILES.size,
            "the producer count and the producer tool-name set disagree: " +
                "${PARAMETER_PRODUCER_TOOL_NAMES.size} names across ${PRODUCER_FILES.size} executors",
        )
        PRODUCER_FILES.forEach { path ->
            PARAMETER_PRODUCER_TOOL_NAMES.forEach { tool ->
                assertTrue(
                    codeLines(path).any { it.text.contains("\"$tool\"") },
                    "$path no longer registers the `$tool` tool, so the pinned inventory of " +
                        "$EXPECTED_PRODUCERS no longer describes the tree",
                )
            }
        }

        // What makes the sanitizer the SOLE producer rather than merely a popular one.
        PRODUCER_FILES.forEach { path ->
            assertEquals(
                0,
                codeLines(path).count { it.text.contains(PARSED_PARAM_CONSTRUCTION) },
                "$path constructs `$PARSED_PARAM_CONSTRUCTION` itself. `sanitizeParameters` is the sole " +
                    "producer of ParsedParam by design (D-27-17); a second producer is how the control " +
                    "gets bypassed without anyone editing the sanitizer.",
            )
        }
        assertEquals(
            1,
            codeLines(HELPERS_FILE).count { it.text.contains(PARSED_PARAM_CONSTRUCTION) },
            "$HELPERS_FILE must hold exactly one `$PARSED_PARAM_CONSTRUCTION` construction — the one inside " +
                "sanitizeParameters. Zero means the sanitizer stopped producing; more than one means it " +
                "grew a second, unguarded path.",
        )

        // The two surviving direct readers of a Montoya parameter value, classified. `find_reflected`
        // emits name, type and an occurrence count — the value is a search needle and is never
        // rendered — which is why it is outside this control rather than a hole in it (T-27-07-07).
        val directReaders = PRODUCER_FILES.associateWith { path -> codeLines(path).count { it.text.contains(RAW_VALUE_READ) } }
        assertEquals(
            EXPECTED_DIRECT_VALUE_READERS_PER_EXECUTOR,
            directReaders.values.toSet().singleOrNull(),
            "each executor must retain exactly $EXPECTED_DIRECT_VALUE_READERS_PER_EXECUTOR direct `$RAW_VALUE_READ` " +
                "read — the find_reflected needle. Measured: $directReaders. More means a producer slipped " +
                "back past the sanitizer.",
        )
    }

    @Test
    fun theProducerScanIsNonVacuous() {
        // Copied from CookieHeaderRuleOwnershipTest.theOwnershipScanIsNonVacuous. A repository-state
        // test that goes green when it cannot find the repository is worse than the grep it replaced.
        // Note mainSourceRoot() THROWS rather than returning null, so resolving the root is itself
        // the first assertion.
        (PRODUCER_FILES + HELPERS_FILE).forEach { path ->
            val lines = codeLines(path)
            assertTrue(
                lines.size >= MIN_EXPECTED_LINES.getValue(path),
                "the scan read only ${lines.size} code lines from $path, below the floor of " +
                    "${MIN_EXPECTED_LINES.getValue(path)} — it is looking at the wrong file, or the file it " +
                    "pins has been gutted, so the pin above proves nothing",
            )
        }

        // Comment stripping proven live: this file's own KDoc and comments name every symbol the scan
        // looks for, and an unfiltered scan would count that prose as evidence.
        assertTrue(isCommentOnly("    // $SANITIZER_CALL"), "the comment filter no longer recognises a line comment")
        assertTrue(isCommentOnly("     * $SANITIZER_CALL"), "the comment filter no longer recognises a KDoc body line")
        assertTrue(
            PRODUCER_FILES.none { path -> codeLines(path).any { isCommentOnly(it.text) } },
            "a comment-only line reached the producer scan",
        )

        // Every needle proven live against a known positive, so a count of zero cannot pass as
        // agreement with a pinned zero.
        assertTrue(
            "parameters = sanitizeParameters(request.parameters(), context),".contains(SANITIZER_CALL),
            "the scan needle `$SANITIZER_CALL` no longer matches its own known-positive fixture",
        )
        assertTrue(
            "ParsedParam(type = typeName, name = param.name(), value = value)".contains(PARSED_PARAM_CONSTRUCTION),
            "the scan needle `$PARSED_PARAM_CONSTRUCTION` no longer matches its own known-positive fixture",
        )
        assertTrue(
            "val value = param.value()".contains(RAW_VALUE_READ),
            "the scan needle `$RAW_VALUE_READ` no longer matches its own known-positive fixture",
        )
    }

    // ── the scans ───────────────────────────────────────────────────────────────────────

    private data class SourceLine(
        val number: Int,
        val text: String,
    ) {
        override fun toString(): String = "$number:${text.trim()}"
    }

    /** Non-comment lines of [relPath], 1-based, so prose about a symbol never counts as the symbol. */
    private fun codeLines(relPath: String): List<SourceLine> =
        sourceFile(relPath)
            .readLines()
            .mapIndexed { index, text -> SourceLine(index + 1, text) }
            .filterNot { isCommentOnly(it.text) }

    private fun isCommentOnly(line: String): Boolean {
        val trimmed = line.trimStart()
        return trimmed.startsWith("//") || trimmed.startsWith("*") || trimmed.startsWith("/*")
    }

    private fun sourceFile(relPath: String): File = File(mainSourceRoot(), relPath)

    /** Resolved by walking up from the Gradle test working directory. FAILS rather than skips. */
    private fun mainSourceRoot(): File {
        var candidate: File? = File(System.getProperty("user.dir")).absoluteFile
        while (candidate != null) {
            val root = File(candidate, MAIN_SOURCE_ROOT)
            if (root.isDirectory) return root
            candidate = candidate.parentFile
        }
        throw AssertionError(
            "could not resolve $MAIN_SOURCE_ROOT from user.dir=${System.getProperty("user.dir")}. " +
                "Resolve the path rather than weakening this test into a skip.",
        )
    }

    // ── shared fixtures ─────────────────────────────────────────────────────────────────

    private fun parsedRequestFrom(
        mode: PrivacyMode,
        salt: String,
        sentinel: String,
    ): ParsedRequest =
        ParsedRequest(
            method = "GET",
            path = "/a",
            url = "http://example.com/a",
            headers = mapOf("Host" to "example.com"),
            parameters = sanitizeParameters(listOf(cookieParam("wibble", sentinel)), contextWith(mode, salt)),
            body = null,
            bodyLength = 0,
        )

    /**
     * The `params_extract` line shape, built by the SAME expression both producers use so the probe
     * moves with the format instead of asserting against a shape that is no longer emitted. The
     * expression is duplicated here rather than extracted into production code on purpose: an
     * extracted formatter would make this test assert that a function equals itself.
     */
    private fun paramsExtractLines(
        mode: PrivacyMode,
        salt: String,
        vararg parameters: ParsedHttpParameter,
    ): String =
        sanitizeParameters(parameters.toList(), contextWith(mode, salt)).joinToString(separator = "\n") { param ->
            "type=${param.type} name=${param.name} value=${param.value}"
        }

    private fun cookieParam(
        name: String,
        value: String,
    ): ParsedHttpParameter = paramOfType(HttpParameterType.COOKIE, name, value)

    private fun paramOfType(
        type: HttpParameterType,
        name: String,
        value: String,
    ): ParsedHttpParameter {
        val param = mock<ParsedHttpParameter>()
        whenever(param.type()).thenReturn(type)
        whenever(param.name()).thenReturn(name)
        whenever(param.value()).thenReturn(value)
        return param
    }

    private fun contextWith(
        mode: PrivacyMode,
        salt: String,
    ): McpToolContext {
        val api = mock<MontoyaApi>(defaultAnswer = Answers.RETURNS_DEEP_STUBS)
        return McpToolContext(
            api = api,
            privacyMode = mode,
            determinismMode = false,
            hostSalt = salt,
            toolToggles = emptyMap(),
            unsafeEnabled = false,
            unsafeTools = emptySet(),
            enabledUnsafeTools = emptySet(),
            limiter = McpRequestLimiter(4),
            edition = BurpSuiteEdition.PROFESSIONAL,
            maxBodyBytes = 1024,
        )
    }

    /**
     * Every fixture value this file uses, declared ONCE. [ALL_SENTINELS] is derived from `entries`,
     * so the distinctness gate cannot drift from the fixtures: a new value has to be an entry here
     * to be usable at all.
     */
    private enum class Sentinel(
        val value: String,
    ) {
        COOKIE_STRICT("paramalfa"),
        COOKIE_BALANCED("parambravo"),
        COOKIE_OFF("paramcharlie"),
        URL_CONTROL("paramdelta"),
        BODY_CONTROL("paramecho"),
        ORDER_URL("paramfoxtrot"),
        ORDER_COOKIE("paramgolf"),
        ORDER_BODY("paramhotel"),
        SERIALIZED_STRICT("paramindia"),
        SERIALIZED_BALANCED("paramjuliett"),
        SERIALIZED_OFF("paramkilo"),
        SHAPE_STRICT("paramlima"),

        // 27-07 task 2 — the params_extract line carrier.
        LINE_STRICT("parammike"),
        LINE_BALANCED("paramnovember"),
        LINE_OFF("paramoscar"),
        LINE_URL_CONTROL("parampapa"),

        // 27-08 task 1 — the PROMPT PATH preservation group. A distinct `prompt` stem rather than
        // `param`, so a reader of a failure message can tell instantly which of the two carriers,
        // and therefore which of the two controls, the probe was measuring.
        PROMPT_CANONICAL_STRICT("promptalfa"),
        PROMPT_CANONICAL_BALANCED("promptbravo"),
        PROMPT_CANONICAL_OFF("promptcharlie"),
        PROMPT_QUOTED_STRICT("promptdelta"),
        PROMPT_QUOTED_BALANCED("promptecho"),
        PROMPT_NON_COOKIE_LABEL("promptfoxtrot"),
        PROMPT_MULTI_COOKIE("promptgolf"),
        PROMPT_MULTI_URL("prompthotel"),
        PROMPT_MULTI_BODY("promptindia"),
    }

    private companion object {
        val ALL_SENTINELS: List<String> = Sentinel.entries.map { it.value }

        // The same literal sanitizeHeaders writes for a stripped cookie HEADER (D-27-18): one
        // vocabulary across both fields of one request_parse result.
        const val STRIPPED_MARKER = "[STRIPPED]"

        // The DIFFERENT literal `cookieTypedParamRegex` writes on the prompt path. The two markers
        // are deliberately not unified: `[STRIPPED]` means "the producer never emitted this value"
        // and `[REDACTED]` means "the value was emitted and then rewritten at the choke point".
        // Collapsing them would erase which control acted.
        const val REDACTED_MARKER = "[REDACTED]"

        const val MAIN_SOURCE_ROOT = "src/main/kotlin"
        const val TOOLS_PACKAGE = "com/six2dez/burp/aiagent/mcp/tools"
        const val MODERN_EXECUTOR = "$TOOLS_PACKAGE/McpToolExecutorImpl.kt"
        const val LEGACY_EXECUTOR = "$TOOLS_PACKAGE/McpToolLegacy.kt"
        const val HELPERS_FILE = "$TOOLS_PACKAGE/McpToolHelpers.kt"

        /**
         * The two executor files that carry every measured parameter producer. Keyed by PATH and
         * COUNT, never by line number, so the pin does not rot the first time a file above one of
         * these sites is reformatted (WINDOWS.md 11/13/14/15).
         */
        val PRODUCER_FILES = listOf(MODERN_EXECUTOR, LEGACY_EXECUTOR)

        /**
         * MEASURED, not assumed. Before this plan:
         *   grep -c 'param.value()' McpToolExecutorImpl.kt McpToolLegacy.kt  ->  3 + 3 = 6
         *   grep -c 'ParsedParam('  McpToolExecutorImpl.kt McpToolLegacy.kt  ->  1 + 1 = 2
         * Two tools per executor read a parameter VALUE for rendering: request_parse and
         * params_extract. find_reflected is the third reader in each file and is NOT a producer —
         * it emits name, type and an occurrence count, never the value (T-27-07-07).
         */
        const val EXPECTED_PRODUCERS = 4
        const val EXPECTED_PRODUCERS_PER_EXECUTOR = 2
        const val EXPECTED_DIRECT_VALUE_READERS_PER_EXECUTOR = 1

        val PARAMETER_PRODUCER_TOOL_NAMES = setOf("request_parse", "params_extract")

        /** Floors catch a walk that reaches nothing or a gutted file — not drift. */
        val MIN_EXPECTED_LINES =
            mapOf(
                MODERN_EXECUTOR to 600,
                LEGACY_EXECUTOR to 400,
                HELPERS_FILE to 300,
            )

        const val SANITIZER_CALL = "sanitizeParameters("
        const val PARSED_PARAM_CONSTRUCTION = "ParsedParam("
        const val RAW_VALUE_READ = "param.value()"
    }
}
