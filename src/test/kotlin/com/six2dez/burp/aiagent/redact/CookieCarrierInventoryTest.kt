package com.six2dez.burp.aiagent.redact

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import java.io.File

/**
 * (PRIV-05) Phase 27 plan 27-08 / D-27-22 — the CARRIER inventory.
 *
 * WHAT THIS IS FOR.
 *
 * PRIV-05 has been refuted on three axes in this phase. Waves 1-3 found header NAMES the control did
 * not spell. Waves 4-6 found emission PATHS the control never reached. `27-VERIFICATION-2.md` found a
 * field TYPE — `HttpParameterType.COOKIE` — that no prior mechanism could see. Each round built a
 * rigorous mechanism for the axis it was looking along and was structurally blind to the next,
 * because each keyed on a RENDERING of the data: `CookieHeaderRuleOwnershipTest` keys on how a
 * matcher is SPELLED, `SerializedEmissionSiteInventoryTest` on how an emission is SHAPED,
 * `Redaction.cookieTypedParamRegex` on how a parameter is FORMATTED. A rendering-keyed mechanism can
 * only see renderings it already knows.
 *
 * This file keys one axis up: on the SOURCE of the bytes. A cookie byte can only enter this extension
 * through a Montoya call that returns it. So enumerate those calls, and require every site that makes
 * one to be either ROUTED through a named control or CLASSIFIED non-carrying with a reason read from
 * that site's own CONSUMER. Adding a call site anywhere in `src/main/kotlin` fails a test until
 * somebody classifies it.
 *
 * ── THE BOUND, STATED FIRST AND NOT AS A FOOTNOTE ──
 *
 * THIS IS A TRIPWIRE OVER A MEASURED ACCESSOR SET. IT IS NOT A PROOF OF COVERAGE. Anyone who quotes
 * this test as evidence that no cookie value can reach an AI backend reproduces, one iteration
 * smaller, the defect this whole phase exists to repair: a record wider than the control it
 * describes. Four things it CANNOT see, named here so nobody has to discover them as round five:
 *
 *  1. A COOKIE BYTE THAT NEVER PASSES A MONTOYA ACCESSOR. Operator-pasted text in the chat box; a
 *     model echoing a cookie back into the transcript; a cookie this extension itself persisted to
 *     settings or a cache and later emitted. No accessor-keyed mechanism reaches any of these.
 *
 *  2. `bodyToString()`, DELIBERATELY EXCLUDED — with the reason that actually holds. Measured at 32
 *     call sites across 8 files, comment-stripped, 2026-08-25. The exclusion is NOT because an entity
 *     body cannot contain cookie bytes. It can: a body can carry a pasted raw HTTP message, a
 *     forwarded webhook envelope, or a proxied upstream request, and any of those carries a `Cookie:`
 *     header inside the body text. Writing the exclusion as "an entity body does not contain the
 *     Cookie header" would be an absolute that one pasted request falsifies — a premise authored to
 *     be refuted in round five. THE REASON THAT DOES HOLD: a body of that shape reaching a backend
 *     passes `Redaction.apply` at the `redactIfNeeded` choke point, and there the logical-line cookie
 *     rules DO fire, because such a body carries a REAL newline before the `Cookie:` token — exactly
 *     the boundary waves 4-6 taught those rules to see. The carrier is covered by an EXISTING control
 *     on a DIFFERENT axis, so enumerating its 32 sites here would add churn without adding coverage.
 *     Two contingencies travel with that reason, because it is contingent where the old one pretended
 *     to be absolute: (a) the exclusion FAILS for any body that reaches a backend on a path bypassing
 *     `Redaction.apply`, and an accessor-keyed inventory cannot see such a path — that is axis 1, one
 *     step out; and (b) a session token duplicated into a body FIELD (a JSON value, a form parameter)
 *     carries no header line and no newline discriminator, so it is the TOKEN class (PRIV-02),
 *     reachable by different rules and NOT covered here either.
 *
 *  3. TRANSITIVE CARRIERS, where a cookie byte is copied into a field whose accessor is not on the
 *     list. `AuditIssue.detail()` is the worked example, surfaced by the `InjectionPointExtractor` and
 *     `ResponseAnalyzer` entries below and carried in [ISSUE_DETAIL_CARRIER_DISPOSITION]. This
 *     inventory can point at the FIRST hop; it cannot follow a value through arbitrary copies.
 *
 *     READ THE EXAMPLE AS AN EXAMPLE, NOT AS AN OPEN FINDING. Phase 28 CONTROLLED the
 *     `AuditIssue.detail()` route at its write sites — PLURAL, corrected 2026-08-27 by plan 28-06,
 *     because the sentence here previously said "at its write site" and was true of ONE write site
 *     in ONE file when it was written. THERE ARE TWO PRODUCERS OF THESE DETAIL LINES:
 *     `ScannerIssueSupport.buildActiveIssueDetailLines`, whose `Original Value:` and `Payload Used:`
 *     lines are gated by `sanitizeInjectionPointValue` (plan 28-01) and `sanitizeRenderedPayload`
 *     (plan 28-04); and `AiScanCheck.buildDetail`, a SECOND producer that read no privacy mode at
 *     all until plan 28-05 gated both of its lines through `sanitizeCookiePointText`.
 *     [ISSUE_DETAIL_CARRIER_DISPOSITION] carries the original measurement and both dated
 *     supersessions. The example is kept precisely BECAUSE it was walked to the end: it is the one
 *     case where this axis's blindness was traced end to end and shown to be real — twice, since the
 *     second producer was found by a verifier and not by this inventory. THE AXIS ITSELF IS STILL
 *     OPEN, and that is the sentence to keep: controlling one transitive carrier does not teach this
 *     inventory to follow the next one, a reader who reads the control as closing the axis has
 *     narrowed the bound, and NO repository-wide detail-producer gate exists to catch a third
 *     producer (D-28-06 records building one as considered and NOT taken; `WR-01` stays open).
 *
 *  4. A NEW MONTOYA ACCESSOR added by a future API version that returns cookie data under a name not
 *     in [COOKIE_BYTE_ACCESSORS]. The set is additive-only and a reader adding one must extend it.
 *
 *     THIS AXIS HAS ALREADY COST SOMETHING, recorded 2026-08-27 by plan 28-06 rather than left as a
 *     hypothetical. `AuditInsertionPoint.baseValue()` was NOT a future accessor — it was in the tree
 *     the whole time, returning the raw cookie value for a `PARAM_COOKIE` point, and its absence from
 *     this set is why `AR-27-08`'s route 2 in `AiScanCheck.kt` survived three phase-28 plans and had
 *     to be found by hand in `28-VERIFICATION.md`. It is now in the set as
 *     [INSERTION_POINT_BASE_VALUE]. THE AXIS IS CLOSED FOR THAT ONE ACCESSOR AND OPEN FOR EVERY
 *     OTHER: adding one accessor teaches this file nothing about the next, and nothing in this
 *     repository enumerates the accessors that are still missing.
 *
 * ── A FIFTH, WEAKER BOUND, ON THE GRANULARITY OF THE CLASSIFICATION ITSELF ──
 *
 * Separated from the four above rather than averaged into them, because it is a limit of the
 * BOOKKEEPING and not of the axis. A registry key is a (file, accessor) PAIR, not an individual call.
 * Where the calls behind one pair split — `McpToolExecutorImpl`'s three `parameters()` calls are two
 * `sanitizeParameters` producers plus one non-carrying `find_reflected` reader — the pair sits in
 * [ROUTED_THROUGH] and its reason enumerates the split by line. That prose is NOT machine-checked.
 * What IS machine-checked is the COUNT: adding a fourth `parameters()` call to that file turns
 * [theMeasuredPerFilePerAccessorCountsArePinned] red and forces the split to be re-read. The tripwire
 * property survives; the per-call attribution is a human record inside it.
 */
class CookieCarrierInventoryTest {
    @Test
    fun everyCookieByteCarrierSiteIsRoutedOrClassified() {
        val measured = scanCarrierSites().keys
        val declared = ROUTED_THROUGH.keys + CLASSIFIED_NON_CARRYING.keys

        val overlap = ROUTED_THROUGH.keys intersect CLASSIFIED_NON_CARRYING.keys
        assertTrue(
            overlap.isEmpty(),
            "a site cannot be both routed through a control and classified non-carrying — pick one " +
                "and say why: $overlap",
        )

        assertEquals(
            declared,
            measured,
            "the set of cookie-byte carrier sites has changed.\n" +
                "  NEW (route it through a named control, or classify it in CLASSIFIED_NON_CARRYING " +
                "with the reason you read from its CONSUMER — not from the call site): " +
                "${measured - declared}\n" +
                "  STALE (declared here but no longer measured — remove the entry so the registry " +
                "cannot accumulate dead keys): ${declared - measured}",
        )
    }

    @Test
    fun theMeasuredPerFilePerAccessorCountsArePinned() {
        val measured = scanCarrierSites()
        val measuredPerFile = measured.entries.groupBy({ it.key.path }, { it.key.accessor to it.value })

        MEASURED_CARRIER_SITES.forEach { (path, expectedPerAccessor) ->
            val actualPerAccessor = measuredPerFile[path].orEmpty().toMap()
            assertEquals(
                expectedPerAccessor,
                actualPerAccessor,
                "$path no longer carries the pinned accessor counts. The WHOLE per-file map is " +
                    "printed so a drift is diagnosable without re-running the scan by hand.\n" +
                    "  pinned:   $expectedPerAccessor\n" +
                    "  measured: $actualPerAccessor\n" +
                    "If the change is deliberate, re-read the new site's CONSUMER, classify it, and " +
                    "update this count in the same edit — never one without the other.",
            )
        }

        assertEquals(
            MEASURED_CARRIER_SITES.keys,
            measuredPerFile.keys,
            "the set of FILES carrying a measured accessor has changed. Per-file measured counts: " +
                "${measuredPerFile.mapValues { it.value.toMap() }}",
        )

        assertEquals(
            EXPECTED_TOTAL_CARRIER_SITES,
            measured.values.sum(),
            "the total measured carrier-site count has drifted. Per site: $measured",
        )
        assertEquals(
            EXPECTED_TOTAL_CARRIER_SITES,
            MEASURED_CARRIER_SITES.values.sumOf { it.values.sum() },
            "the pinned per-file map and the pinned total disagree with each other, so one of the " +
                "two was edited alone",
        )
    }

    @Test
    fun theHeaderValueArgumentMultisetIsPinned() {
        // A count alone is defeatable by a simultaneous add and remove. The ARGUMENT is the data that
        // matters for this accessor: `headerValue("Cookie")` returns cookie bytes and
        // `headerValue("Content-Type")` cannot, so a new cookie-named argument must fail here even
        // when the per-file count is unchanged.
        val measured =
            mainSourceFiles()
                .flatMap { file -> codeLines(file).flatMap { HEADER_VALUE_ARGUMENT.findAll(it).map { m -> m.groupValues[1] } } }
                .groupingBy { it }
                .eachCount()

        assertEquals(
            MEASURED_HEADER_VALUE_ARGUMENTS,
            measured,
            "the `.headerValue(\"…\")` argument multiset has changed. A NEW cookie-named argument is " +
                "a new carrier site even if the per-file count did not move.\n" +
                "  pinned:   $MEASURED_HEADER_VALUE_ARGUMENTS\n" +
                "  measured: $measured",
        )
        assertEquals(
            MEASURED_CARRIER_SITES.values.sumOf { it[SINGLE_HEADER_LOOKUP] ?: 0 },
            measured.values.sum(),
            "the argument multiset and the per-file SINGLE_HEADER_LOOKUP counts disagree, which means " +
                "a call passes something this scan cannot read as a string literal",
        )
    }

    @Test
    fun theCarrierScanIsNonVacuous() {
        // A repository-state test that goes green when it cannot find the repository is worse than
        // the grep it replaced. Both halves below FAIL rather than skip.
        val files = mainSourceFiles()
        assertTrue(
            files.size >= MIN_EXPECTED_MAIN_FILES,
            "the walk found only ${files.size} .kt files under $MAIN_SOURCE_ROOT — the scan is not " +
                "reaching the repository, so every other assertion here proves nothing",
        )

        COOKIE_BYTE_ACCESSORS.forEach { (accessor, spec) ->
            assertTrue(
                spec.pattern.containsMatchIn(spec.positiveFixture),
                "accessor '$accessor' has a pattern that matches none of its own declared positive " +
                    "fixture [${spec.positiveFixture}] — it can no longer detect the call it exists " +
                    "to detect, and every count it contributes is vacuously correct",
            )
        }
        assertTrue(
            HEADER_VALUE_ARGUMENT.containsMatchIn("""val cookieHeader = request.headerValue("Cookie")"""),
            "the headerValue argument pattern matches no known positive fixture",
        )

        assertEquals(
            MEASURED_CARRIER_SITES.size,
            MEASURED_CARRIER_SITES.keys.count { path -> sourceFile(path).isFile },
            "a pinned carrier file does not exist on disk, so its zero counts would read as agreement: " +
                "${MEASURED_CARRIER_SITES.keys.filterNot { sourceFile(it).isFile }}",
        )
    }

    // ── the scan ─────────────────────────────────────────────────────────────────────────

    private fun scanCarrierSites(): Map<CarrierSite, Int> {
        val out = mutableMapOf<CarrierSite, Int>()
        mainSourceFiles().forEach { file ->
            val lines = codeLines(file)
            COOKIE_BYTE_ACCESSORS.forEach { (accessor, spec) ->
                val count = lines.sumOf { spec.pattern.findAll(it).count() }
                if (count > 0) out[CarrierSite(relativePath(file), accessor)] = count
            }
        }
        return out
    }

    /** Non-comment lines only, so prose ABOUT an accessor can never count as a call to it. */
    private fun codeLines(file: File): List<String> = file.readLines().filterNot { isCommentOnly(it) }

    private fun isCommentOnly(line: String): Boolean {
        val trimmed = line.trimStart()
        return trimmed.startsWith("//") || trimmed.startsWith("/*") || isBlockCommentContinuation(trimmed)
    }

    /**
     * A KDoc / block-comment continuation line, NARROWED 2026-08-27 by plan 28-06 — and the narrowing
     * is a measured bug fix, not tidying.
     *
     * The previous rule was `trimmed.startsWith("*")`, which also swallowed any line of a Kotlin RAW
     * STRING beginning with a markdown bold marker. `AiScanCheck.kt:388` is exactly such a line: the
     * rendered `Original Value` heading, in markdown bold, interpolating
     * `sanitizeCookiePointText(insertionPoint, policy, insertionPoint.baseValue(), …)` — the CARRIER
     * for `AR-27-08`'s route 2. Under the old rule the scan saw the NON-CARRYING `baseValue()` call at
     * `:116` and was blind to the carrying one, so adding [INSERTION_POINT_BASE_VALUE] to the accessor
     * set would have produced a registry entry whose count silently excluded the site it exists to
     * watch. A tripwire that cannot see the line it was added for is the failure mode this whole file
     * is a response to, so the heuristic was narrowed rather than the count pinned around it.
     *
     * A genuine continuation is a bare asterisk, an asterisk followed by whitespace, or the block
     * terminator. A line opening with a DOUBLED asterisk is markdown, not KDoc.
     */
    private fun isBlockCommentContinuation(trimmed: String): Boolean = trimmed == "*" || trimmed.startsWith("* ") || trimmed.startsWith("*\t") || trimmed.startsWith("*/")

    private fun mainSourceFiles(): List<File> =
        mainSourceRoot()
            .walkTopDown()
            .filter { it.isFile && it.extension == "kt" }
            .toList()

    private fun sourceFile(relativePath: String): File = File(mainSourceRoot(), relativePath)

    private fun relativePath(file: File): String = file.relativeTo(mainSourceRoot()).invariantSeparatorsPath

    // Resolved from the Gradle test working directory, then by walking up. If it cannot be found the
    // test FAILS — it is never weakened into a skip.
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

    /** One measured call site class: a file plus the accessor it calls. */
    private data class CarrierSite(
        val path: String,
        val accessor: String,
    ) {
        override fun toString(): String = "$path[$accessor]"
    }

    /** An accessor, its detection pattern, WHY it can return cookie bytes, and a positive fixture. */
    private data class AccessorSpec(
        val pattern: Regex,
        val whyItCarriesCookieBytes: String,
        val positiveFixture: String,
    )

    private companion object {
        const val MAIN_SOURCE_ROOT = "src/main/kotlin"

        // Measured at 172 .kt files when CookieHeaderRuleOwnershipTest was written; re-measured above
        // that here. The floor catches a walk that reaches nothing, not the file count.
        const val MIN_EXPECTED_MAIN_FILES = 150

        const val HEADER_LIST = "headerList"
        const val PARAMETER_LIST = "parameterList"
        const val SINGLE_HEADER_LOOKUP = "singleHeaderLookup"
        const val RAW_MESSAGE = "rawMessage"
        const val COOKIE_JAR = "cookieJar"

        // Added by plan 28-06 (phase 28). This is axis 4 of the class KDoc — the accessor set is
        // additive-only and a reader adding a cookie-returning accessor must extend it — closed FOR
        // THIS ACCESSOR ONLY. Its absence is what let AR-27-08's route 2 exist unseen until
        // 28-VERIFICATION.md found it by hand. The axis itself stays open.
        const val INSERTION_POINT_BASE_VALUE = "insertionPointBaseValue"

        /**
         * THE MEASURED ACCESSOR SET. Every entry states WHY that call can return cookie bytes, because
         * an inventory whose membership rule is unstated cannot be extended correctly by the next
         * reader. `bodyToString()` is excluded on the reasoning in this class's KDoc, axis 2 — read it
         * before adding it.
         */
        val COOKIE_BYTE_ACCESSORS: Map<String, AccessorSpec> =
            mapOf(
                HEADER_LIST to
                    AccessorSpec(
                        pattern = Regex("""\.headers\(\)"""),
                        whyItCarriesCookieBytes =
                            "the header list contains `Cookie` on a request and `Set-Cookie` on a response",
                        positiveFixture = """val requestHeaders = sanitizeHeadersForPrompt(request.headers(), isRequest = true)""",
                    ),
                PARAMETER_LIST to
                    AccessorSpec(
                        pattern = Regex("""\.parameters\("""),
                        whyItCarriesCookieBytes =
                            "Burp parses the `Cookie` header into HttpParameterType.COOKIE entries, so the " +
                                "parameter list carries the same bytes under a different type",
                        // Mirrors the tree as of phase 28: the extractor's hand-written
                        // `it.type().name == "COOKIE"` was converted to the shared predicate by plan
                        // 28-02. The pattern above keys on the ACCESSOR CALL, not on the predicate, so
                        // this fixture matched before and after — which is precisely why it had to be
                        // updated by hand. A fixture quoting a line that no longer exists stays GREEN
                        // while it rots, the stale-but-green drift this class's own KDoc warns about.
                        positiveFixture = """request.parameters().filter { Redaction.isCookieParameterType(it.type().name) }.forEach { param ->""",
                    ),
                SINGLE_HEADER_LOOKUP to
                    AccessorSpec(
                        pattern = Regex("""\.headerValue\("""),
                        whyItCarriesCookieBytes =
                            "it returns the raw value of one named header, which is the whole cookie string " +
                                "when the argument names a cookie header",
                        positiveFixture = """val cookieHeader = request.headerValue("Cookie")""",
                    ),
                RAW_MESSAGE to
                    AccessorSpec(
                        pattern = Regex("""(request|response)\(\)\??\.toString\(\)"""),
                        whyItCarriesCookieBytes =
                            "the serialized message contains the whole header block, cookie headers included",
                        positiveFixture = """request = request()?.toString() ?: "<no request>",""",
                    ),
                COOKIE_JAR to
                    AccessorSpec(
                        pattern = Regex("""cookieJar\(\)"""),
                        whyItCarriesCookieBytes =
                            "Burp's cookie jar IS the bytes. Measured on this tree, every `.cookies()` call " +
                                "is chained onto `cookieJar()` on the same line, so this one pattern is a " +
                                "complete detector for the jar accessor here",
                        positiveFixture = """val cookies = api.http().cookieJar().cookies()""",
                    ),
                INSERTION_POINT_BASE_VALUE to
                    AccessorSpec(
                        pattern = Regex("""\.baseValue\(\)"""),
                        whyItCarriesCookieBytes =
                            "Burp DERIVES a PARAM_COOKIE insertion point from the request's `Cookie` header, so " +
                                "for a point of that type the base value IS the cookie value — the operator's " +
                                "raw proxied session token, under a name that says nothing about cookies. That " +
                                "is why an accessor-keyed inventory missed it: no spelling, shape or format " +
                                "rule on this call reveals what it returns; only the point's TYPE does",
                        // Quoted from AiScanCheck.kt as it stands AFTER plan 28-05 — the controlled
                        // carrier line itself, not the pre-28-05 bare interpolation. A fixture that
                        // quotes a line no longer in the tree stays GREEN while it rots, which is the
                        // drift this class's own KDoc warns about, so it is re-read on every edit.
                        positiveFixture =
                            "**Original Value:** \${sanitizeCookiePointText(insertionPoint, policy, " +
                                "insertionPoint.baseValue(), ScannerIssueSupport.ORIGINAL_VALUE_MAX_CHARS)}",
                    ),
            )

        /** The string-literal argument of a `.headerValue("…")` call. */
        val HEADER_VALUE_ARGUMENT = Regex("""\.headerValue\("([^"]*)"\)""")

        const val EXECUTOR_MODERN = "com/six2dez/burp/aiagent/mcp/tools/McpToolExecutorImpl.kt"
        const val EXECUTOR_LEGACY = "com/six2dez/burp/aiagent/mcp/tools/McpToolLegacy.kt"
        const val SERIALIZATION = "com/six2dez/burp/aiagent/mcp/schema/Serialization.kt"
        const val CONTEXT_COLLECTOR = "com/six2dez/burp/aiagent/context/ContextCollector.kt"
        const val BOUNTY_TAG_RESOLVER = "com/six2dez/burp/aiagent/prompts/bountyprompt/BountyPromptTagResolver.kt"
        const val ACTIVE_SCANNER = "com/six2dez/burp/aiagent/scanner/ActiveAiScanner.kt"
        const val PASSIVE_HEURISTICS = "com/six2dez/burp/aiagent/scanner/PassiveAiScannerHeuristics.kt"
        const val PASSIVE_ANALYSIS = "com/six2dez/burp/aiagent/scanner/PassiveAiScannerAnalysis.kt"
        const val PASSIVE_FILTERS = "com/six2dez/burp/aiagent/scanner/PassiveAiScannerFilters.kt"
        const val INJECTION_EXTRACTOR = "com/six2dez/burp/aiagent/scanner/InjectionPointExtractor.kt"
        const val RESPONSE_ANALYZER = "com/six2dez/burp/aiagent/scanner/ResponseAnalyzer.kt"
        const val AI_SCAN_CHECK = "com/six2dez/burp/aiagent/scanner/AiScanCheck.kt"

        /**
         * RE-MEASURED at execution time on this tree, NOT copied from plan 27-08's baseline table.
         * Totals per accessor: headerList 25, parameterList 15, singleHeaderLookup 11, rawMessage 19,
         * cookieJar 2, insertionPointBaseValue 2 — 74 sites across 12 files, which is what makes this
         * registry tractable rather than open-ended.
         *
         * RE-MEASURED AGAIN 2026-08-27 by plan 28-06, on the tree as it stands after plans 28-04 and
         * 28-05: the twelfth file and the two new sites are `AiScanCheck.kt`'s `baseValue()` calls,
         * which entered this map on the same edit that added the accessor to [COOKIE_BYTE_ACCESSORS].
         * The two must move together — declaring a route without extending the accessor set turns
         * [everyCookieByteCarrierSiteIsRoutedOrClassified] red, and moving either without
         * [EXPECTED_TOTAL_CARRIER_SITES] turns [theMeasuredPerFilePerAccessorCountsArePinned] red.
         */
        val MEASURED_CARRIER_SITES: Map<String, Map<String, Int>> =
            mapOf(
                EXECUTOR_MODERN to mapOf(HEADER_LIST to 2, PARAMETER_LIST to 3, RAW_MESSAGE to 5, COOKIE_JAR to 1),
                EXECUTOR_LEGACY to mapOf(HEADER_LIST to 2, PARAMETER_LIST to 3, RAW_MESSAGE to 5, COOKIE_JAR to 1),
                SERIALIZATION to mapOf(RAW_MESSAGE to 5),
                CONTEXT_COLLECTOR to mapOf(RAW_MESSAGE to 2),
                BOUNTY_TAG_RESOLVER to mapOf(PARAMETER_LIST to 1, RAW_MESSAGE to 2),
                ACTIVE_SCANNER to mapOf(HEADER_LIST to 5, SINGLE_HEADER_LOOKUP to 2),
                PASSIVE_HEURISTICS to mapOf(HEADER_LIST to 5, PARAMETER_LIST to 2, SINGLE_HEADER_LOOKUP to 5),
                PASSIVE_ANALYSIS to mapOf(HEADER_LIST to 5, PARAMETER_LIST to 1, SINGLE_HEADER_LOOKUP to 2),
                PASSIVE_FILTERS to mapOf(HEADER_LIST to 2, PARAMETER_LIST to 1),
                INJECTION_EXTRACTOR to mapOf(HEADER_LIST to 2, PARAMETER_LIST to 4, SINGLE_HEADER_LOOKUP to 2),
                RESPONSE_ANALYZER to mapOf(HEADER_LIST to 2),
                AI_SCAN_CHECK to mapOf(INSERTION_POINT_BASE_VALUE to 2),
            )

        const val EXPECTED_TOTAL_CARRIER_SITES = 74

        /** Measured 2026-08-25. `Cookie` ×3 is the population that matters; the rest are the control. */
        val MEASURED_HEADER_VALUE_ARGUMENTS: Map<String, Int> =
            mapOf(
                "Content-Type" to 6,
                "Cookie" to 3,
                "Origin" to 1,
                "Referer" to 1,
            )

        /**
         * Sites whose bytes reach a named control. The value names that control and, where the calls
         * behind one (file, accessor) pair do not share a disposition, enumerates the split by line —
         * see the fifth bound in the class KDoc for why that prose is not machine-checked.
         */
        val ROUTED_THROUGH: Map<CarrierSite, String> =
            mapOf(
                CarrierSite(EXECUTOR_MODERN, HEADER_LIST) to
                    "McpToolHelpers.sanitizeHeaders. Consumer read: :376 and :395 pass the list straight " +
                    "into it as ParsedRequest.headers / ParsedResponse.headers.",
                CarrierSite(EXECUTOR_LEGACY, HEADER_LIST) to
                    "McpToolHelpers.sanitizeHeaders. Consumer read: :184 and :207, the same two shapes.",
                CarrierSite(EXECUTOR_MODERN, PARAMETER_LIST) to
                    "McpToolHelpers.sanitizeParameters at :360 (params_extract) and :381 (request_parse). " +
                    "THE THIRD CALL, :406, IS NON-CARRYING: consumer read at :406-411, find_reflected " +
                    "uses the value only as a needle for countOccurrences and emits " +
                    "`name=… type=… count=…`, never the value itself.",
                CarrierSite(EXECUTOR_LEGACY, PARAMETER_LIST) to
                    "McpToolHelpers.sanitizeParameters at :160 (params_extract) and :189 (request_parse). " +
                    "THE THIRD CALL, :222, IS NON-CARRYING for the same reason: consumer read at " +
                    ":222-227, find_reflected emits name, type and an occurrence count only.",
                CarrierSite(INJECTION_EXTRACTOR, PARAMETER_LIST) to
                    "TWO CONSUMERS, BOTH READ, AND BOTH NOW CONTROLLED — BY DIFFERENT MECHANISMS, which is " +
                    "precisely the kind of thing this inventory exists to surface. MOVED HERE FROM " +
                    "CLASSIFIED_NON_CARRYING BY PHASE 28: the old reason said this entry was CLASSIFIED " +
                    "rather than ROUTED 'because a route with an uncontrolled consumer is not a route', " +
                    "and that reason expired when plan 28-01 controlled consumer 2. The producers — :22 " +
                    "(URL), :26 (BODY), :37 (COOKIE) and :170 — all build InjectionPoint.originalValue, " +
                    "which stays RAW on purpose (D-28-02): the control belongs at each consumer, because " +
                    "redacting in the producer would hit consumer 1 a second time with a foreign marker " +
                    "vocabulary. CONSUMER 1, the AI-facing one: AdaptivePayloadEngine.kt:52 substitutes " +
                    "`[REDACTED_VALUE]` for the value under ANY non-OFF privacy mode before it reaches a " +
                    "prompt. CONSUMER 2: ActiveAiScanner writes `Original Value: <originalValue>` into an " +
                    "AuditIssue detail, and that value is now stripped at the WRITE SITE by " +
                    "ScannerIssueSupport.sanitizeInjectionPointValue under any stripCookies policy — see " +
                    "ISSUE_DETAIL_CARRIER_DISPOSITION for the measurement and its supersession. The " +
                    "COOKIE producer's own cookie-type test is no longer hand-written either: plan 28-02 " +
                    "routed it through Redaction.isCookieParameterType, so the type question and the " +
                    "value question now each have exactly one owner. Both controls are held by committed " +
                    "probes: CookieRouteDispositionTest (no double redaction, one marker vocabulary per " +
                    "route) and IssueDetailCookieCarrierTest (the write-site strip)." +
                    " AMENDED 2026-08-27 by plan 28-06 — 'BOTH NOW CONTROLLED' WAS TRUE OF ONE LINE " +
                    "AND FALSE OF THE BLOCK, and the reason above is kept verbatim rather than " +
                    "rewritten because it is the record of what was believed. 28-VERIFICATION.md " +
                    "measured the gap. THE THIRD CONSUMER THIS ENTRY NEVER NAMED: " +
                    "payloadGenerator.generateContextAwarePayloads, called at ActiveAiScanner.kt:512 " +
                    "and :707, whose output RE-ENTERS THE SAME DETAIL BLOB on the `Payload Used:` " +
                    "line — and for a COOKIE point that payload is DERIVED FROM the cookie value " +
                    "(PayloadGenerator.kt interpolates originalValue), so the line consumer 2's " +
                    "control had just stripped was re-emitted one line below it. IT IS NOW " +
                    "CONTROLLED by ScannerIssueSupport.sanitizeRenderedPayload (plan 28-04), a " +
                    "type-keyed WHOLESALE strip of the rendered payload keyed on the same " +
                    "InjectionType.COOKIE and the same stripCookies policy, writing the same " +
                    "INJECTION_VALUE_STRIPPED_MARKER, held by the same committed probe " +
                    "IssueDetailCookieCarrierTest. CONSUMER 1'S DISPOSITION IS UNCHANGED and is " +
                    "restated here as unchanged so no reader infers it moved: " +
                    "AdaptivePayloadEngine.kt:52 substitutes its own `[REDACTED_VALUE]` marker under " +
                    "any non-OFF mode and is deliberately NOT double-redacted, because a second pass " +
                    "with a foreign marker vocabulary produces a misleading prompt " +
                    "(CookieRouteDispositionTest pins exactly that). WHAT THIS AMENDMENT STILL DOES " +
                    "NOT COVER: the `Evidence:` line of the same blob (AR-28-01, MEDIUM, accepted as " +
                    "a shipping residual by maintainer decision at 28-03's checkpoint), and there is " +
                    "no gate anywhere in this repository that would catch a THIRD detail producer — " +
                    "D-28-06 records building one as considered and NOT taken.",
                CarrierSite(EXECUTOR_MODERN, RAW_MESSAGE) to
                    "Redaction.apply at the redactIfNeeded choke point. Consumer read: all five sites " +
                    "(:592, :593, :732, :761, :811) sit inside the dispatch `when` whose result is " +
                    "wrapped at McpToolExecutorImpl.kt:1045. The logical-line cookie header rules fire " +
                    "there; SerializedEmissionSiteInventoryTest pins the same choke point.",
                CarrierSite(EXECUTOR_LEGACY, RAW_MESSAGE) to
                    "Redaction.apply at the redactIfNeeded choke point. Consumer read: all five sites " +
                    "(:460, :461, :622, :640, :690) sit inside mcpTool/mcpPaginatedTool registrations " +
                    "whose handler wraps output at McpTool.kt:45 and :78.",
                CarrierSite(SERIALIZATION, RAW_MESSAGE) to
                    "Redaction.apply at the redactIfNeeded choke point. Consumer read: :44, :45, :50, :59 " +
                    "and :82 build HttpRequestResponse / SiteMapEntry carriers, which only the two " +
                    "executors serialize, and those emissions are wrapped at the choke point above. " +
                    "This file emits nothing itself.",
                CarrierSite(CONTEXT_COLLECTOR, RAW_MESSAGE) to
                    "Redaction.apply, called directly. Consumer read: :41 and :45 are truncated and then " +
                    "passed to Redaction.apply at :65 and :67 and, in STRICT, to " +
                    "UrlRedaction.anonymizeHostOccurrences with the item's own host; only those strings " +
                    "reach HttpItem. HttpItem.url is built by UrlRedaction.redact (:72). The earlier " +
                    "wording of this record was false for the url field, which was serialized raw until " +
                    "quick task 261008-jx2; the committed probes are ContextCollectorPrivacyTest and " +
                    "UrlRedactionTest.",
                CarrierSite(BOUNTY_TAG_RESOLVER, RAW_MESSAGE) to
                    "Redaction.apply, called directly. Consumer read: :77 and :78 are redacted at :92 and " +
                    ":93 into requestRedacted / responseRedacted, followed in STRICT by the " +
                    "UrlRedaction.anonymizeHostOccurrences own-host pass, and every tag branch below " +
                    "reads only those.",
                CarrierSite(BOUNTY_TAG_RESOLVER, PARAMETER_LIST) to
                    "Redaction.isCookieParameterType plus Redaction.apply (quick task 261008-jx2). " +
                    "Consumer read: buildRequestParameters at :152 renders `name=value (TYPE)`. The " +
                    "cookie TYPE gate writes [STRIPPED] for a COOKIE-typed value under any stripCookies " +
                    "policy, the NAME filter writes [REDACTED] for a sensitive-looking name, and every " +
                    "other line passes Redaction.apply in every mode (tokens, JWTs, custom patterns) " +
                    "before truncation; STRICT then aliases the own host over the whole block. Held by " +
                    "BountyPromptTagResolverTest.",
                CarrierSite(PASSIVE_ANALYSIS, HEADER_LIST) to
                    "Redaction.apply, via redactScanMetadata. Consumer read: :257 and :258 go through " +
                    "sanitizeHeadersForPrompt; :266 selects Cookie header values for cookieSectionLines " +
                    "and the `=== COOKIES ===` span rule; :274 collects auth headers; :286 reduces " +
                    "response headers to tech hints. All five feed buildScanMetadataText at :360, whose " +
                    "output is redacted at :380 before leaving the machine.",
                CarrierSite(PASSIVE_ANALYSIS, PARAMETER_LIST) to
                    "Redaction.cookieTypedParamRegex, via redactScanMetadata. Consumer read: :248 maps each " +
                    "parameter through formatParamLine (PassiveAiScannerPrompts.kt:34) into the " +
                    "`name=value (TYPE)` shape, which the rule matches at Redaction.kt:724 after :380's " +
                    "redactScanMetadata call. This is the ONE rendered shape that rule reaches; plan " +
                    "27-08 task 1 narrowed the rule's comment to say so and pinned the behaviour.",
                CarrierSite(AI_SCAN_CHECK, INSERTION_POINT_BASE_VALUE) to
                    "AiScanCheck.sanitizeCookiePointText (plan 28-05). THE PAIR COVERS TWO CALLS WITH " +
                    "DIFFERENT DISPOSITIONS, enumerated by line the way McpToolExecutorImpl's split " +
                    "parameters() calls are — and, as the fifth bound in the class KDoc says, this " +
                    "attribution is PROSE; what is machine-checked is the COUNT of 2, so a third " +
                    "baseValue() call in this file turns theMeasuredPerFilePerAccessorCountsArePinned " +
                    "red and forces the split to be re-read. :116 IS NON-CARRYING: consumer read at " +
                    ":116-160, determineVulnClasses binds the value only as a regex subject " +
                    "(a digits-only match and a UUID shape) to decide whether to add " +
                    "VulnClass.IDOR, and it is " +
                    "never appended to any emitted string. :388 IS THE CARRIER and is CONTROLLED: it " +
                    "builds the `**Original Value:**` line of buildDetail, the SECOND producer of " +
                    "active-scan issue-detail lines, and the value now passes " +
                    "sanitizeCookiePointText, which keys on isCookieInsertionPoint — an identity " +
                    "compare against AuditInsertionPointType.PARAM_COOKIE, a member of a DIFFERENT " +
                    "closed Montoya enum from route 1's InjectionType, which is exactly why the " +
                    "shared predicate did not already cover it — and substitutes " +
                    "ScannerIssueSupport.INJECTION_VALUE_STRIPPED_MARKER under any stripCookies " +
                    "policy. COMMITTED PROBES: AiScanCheckDetailCookieCarrierTest (the strip, under " +
                    "STRICT and BALANCED, with survival under OFF and a PARAM_URL attribution " +
                    "control) and CookieRouteDispositionTest." +
                    "exactlyOneInsertionPointCookieTypePredicateExistsInMainSource (the predicate " +
                    "population). WHY THIS ENTRY EXISTS AT ALL: this accessor was NOT in the set " +
                    "until plan 28-06, and its absence is the whole reason route 2 stayed invisible " +
                    "through three phase-28 plans — see ISSUE_DETAIL_CARRIER_DISPOSITION.",
            )

        /**
         * Sites whose bytes do NOT cross the process boundary, each with the reason read from that
         * site's own CONSUMER rather than from the call. `26-SECURITY.md` standing rule (i): presence
         * is not width, and a classification asserted from the call site alone is not a classification.
         */
        val CLASSIFIED_NON_CARRYING: Map<CarrierSite, String> =
            mapOf(
                CarrierSite(EXECUTOR_MODERN, COOKIE_JAR) to
                    "MODE-GATED AT THE FIELD. Consumer read: :476 reads the jar, and the map at :502-523 " +
                    "emits cookie.value() ONLY when `includeValues && privacyMode == OFF`, writing " +
                    "[REDACTED] otherwise; the domain is additionally anonymised under STRICT. Under " +
                    "every redacting policy the value never enters CookieEntry.",
                CarrierSite(EXECUTOR_LEGACY, COOKIE_JAR) to
                    "MODE-GATED AT THE FIELD, byte-identical logic. Consumer read: :316 reads the jar and " +
                    ":348-353 applies the same `includeValues && privacyMode == OFF` gate.",
                CarrierSite(ACTIVE_SCANNER, HEADER_LIST) to
                    "LOCAL ANALYSIS and TARGET-BOUND MUTATION, no AI-facing emission. Consumers read: :933 " +
                    "hasAuthContext reduces to a Boolean; :943 stripAuthHeaders REMOVES the matched " +
                    "headers and the Cookie header outright; :995 buildFullResponse is used only for " +
                    "`.contains(payload.value)` tests at :873-884; :1025 responseHeaderValue serves " +
                    "isCacheable / isCacheHit Booleans; :1387 rebuilds a request sent to the TARGET, " +
                    "not to a backend.",
                CarrierSite(ACTIVE_SCANNER, SINGLE_HEADER_LOOKUP) to
                    "BOTH ARE `headerValue(\"Cookie\")` AND BOTH ARE NON-EMITTING. Consumers read: :936 " +
                    "feeds `authCookieHint.containsMatchIn(...)`, a Boolean; :1411 rewrites the cookie " +
                    "string and sends it to the TARGET via withAddedHeader. This pair is why the " +
                    "argument multiset is pinned separately: they are the only cookie-named lookups in " +
                    "the tree that a count alone would not distinguish from a new one.",
                CarrierSite(PASSIVE_HEURISTICS, HEADER_LIST) to
                    "LOCAL ANALYSIS producing LocalFinding objects with FIXED detail strings. Consumers " +
                    "read: :66 detectRequestSmuggling compares Content-Length / Transfer-Encoding " +
                    "values; :101 and :107 reduce to Booleans; :116 reduces Set-Cookie values to a " +
                    "sameSiteSecure Boolean; :186 reduces a Location header to a filename containment " +
                    "test. No header value reaches a LocalFinding.detail.",
                CarrierSite(PASSIVE_HEURISTICS, PARAMETER_LIST) to
                    "LOCAL ANALYSIS. Consumers read: :106 tests parameter NAMES against csrfTokenRegex; " +
                    ":139 tests a name and a value prefix (`rO0AB` / `aced0005`) and returns a fixed " +
                    "detail string. Neither emits a value.",
                CarrierSite(PASSIVE_HEURISTICS, SINGLE_HEADER_LOOKUP) to
                    "LOCAL ANALYSIS. Consumers read: :102 `headerValue(\"Cookie\")` reduces to " +
                    "`authCookieHint.containsMatchIn`, a Boolean; :110 and :111 (Origin, Referer) are " +
                    "null/blank tests; :149 and :173 (Content-Type) are containment tests. The one " +
                    "cookie-named lookup here never leaves the function as text.",
                CarrierSite(PASSIVE_ANALYSIS, SINGLE_HEADER_LOOKUP) to
                    "NON-CARRYING BY ARGUMENT. Consumer read: :356 and :357 both pass \"Content-Type\", " +
                    "feeding buildCompactRequestBody / buildCompactResponseBody, which select a body " +
                    "formatter. A Content-Type value cannot be a cookie.",
                CarrierSite(PASSIVE_FILTERS, HEADER_LIST) to
                    "ADMISSION AND HASHING. Consumers read: :80 hasInterestingResponseHeaders tests header " +
                    "NAMES against an allowlist and returns a Boolean; :147 buildResponseFingerprint " +
                    "passes the sanitized list into sha256Hex at :159, so only a digest survives as a " +
                    "dedup cache key. Neither emits a header value.",
                CarrierSite(PASSIVE_FILTERS, PARAMETER_LIST) to
                    "ARITY ONLY. Consumer read: :60 calls `.isNotEmpty()` inside shouldSkipAiAnalysis; the " +
                    "parameter objects are discarded.",
                CarrierSite(INJECTION_EXTRACTOR, HEADER_LIST) to
                    "ALLOWLISTED INJECTION POINTS, and the allowlist cannot admit a cookie header on the " +
                    "AI-facing path. Consumers read: :33 admits a header only when headerAllowlist " +
                    "contains its lowercased name; :185 matches a header by raw-byte offset for a " +
                    "user selection. Both produce InjectionPoint values, which share the disposition " +
                    "recorded for this file's PARAMETER_LIST entry — which phase 28 MOVED into " +
                    "ROUTED_THROUGH, so it is no longer 'below' in this map.",
                CarrierSite(INJECTION_EXTRACTOR, SINGLE_HEADER_LOOKUP) to
                    "NON-CARRYING BY ARGUMENT. Consumer read: :45 and :207 both pass \"Content-Type\" and " +
                    "use it to choose a JSON or XML field extractor.",
                CarrierSite(RESPONSE_ANALYZER, HEADER_LIST) to
                    "PATTERN MATCHING, with one narrow transitive tail recorded rather than waved off. " +
                    "Consumer read: :616 and :623 build modifiedHeaders / originalHeaders, which are " +
                    "concatenated with the body and consumed by isFalsePositive, analyzeErrorBased, " +
                    "analyzeReflection and analyzeContentBased — all `containsMatchIn` / `find` tests " +
                    "against per-vuln-class error and success signatures. THE TAIL: a MATCHED substring " +
                    "of such a signature can be written into VulnConfirmation.evidence, which " +
                    "ActiveAiScanner.kt:1242 passes into buildActiveIssueDetailLines, putting it in " +
                    "the same AuditIssue detail as consumer 2 above. It is the same transitive route, " +
                    "reachable only by a cookie value that matches a vuln-class error signature. " +
                    "THE CAP IS NOT ONE NUMBER — corrected 2026-08-27 by plan 28-06. This entry " +
                    "previously stated the cap as a SINGLE value of 80 characters; the tree has " +
                    "THREE construction sites and their caps are the multiset {60, 80, 80}. The " +
                    "singular wording is retired rather than quoted, because a stale bound left " +
                    "in the text is the thing a future reader greps and believes. Do not read a " +
                    "number from this prose either: " +
                    "EvidenceTailReachTest.theEvidenceTailCapsAreMeasuredNotAssumed DERIVES the caps " +
                    "from ResponseAnalyzer.kt at test time and pins the multiset, so it is the source " +
                    "of truth and this sentence cannot drift ahead of it. That tail is AR-28-01 " +
                    "(MEDIUM), still OPEN by maintainer decision at 28-03's checkpoint.",
            )

        /**
         * The disposition of the transitive issue-detail carrier, recorded HERE because this is where a
         * reader of the InjectionPointExtractor classification needs it.
         *
         * MEASURED by plan 27-08 task 3, not inferred. The probe itself is deliberately NOT committed:
         * a green assertion under `src/` that a sensitive value survives STRICT is the artifact
         * `26-SECURITY.md` exists to stop producing. Its full source, exact commands and verbatim
         * output for all three modes are in `27-08-SUMMARY.md`, so the measurement stays re-runnable
         * without living in the tree.
         *
         * NOT FIXED HERE, and that is a decision rather than an oversight: a fix without its own red
         * probe is the same-day closure pattern that has failed three times in this phase. Plan 27-09
         * files it and opens a named successor.
         *
         * SUPERSEDED — 2026-08-27, phase 28. The named successor ran. The measurement text below is
         * KEPT BYTE-EXACT as the leading prefix of this constant and the supersession is APPENDED to
         * it, because the measurement is the EVIDENCE THE CONTROL WAS NEEDED: delete it and a later
         * reader sees a control with no stated reason to exist, which is how a control gets removed
         * as redundant. The register's discipline is supersession, never deletion.
         *
         * SUPERSEDED AGAIN — 2026-08-27, phase 28, plan 28-06. THIS CONSTANT NOW CARRIES TWO
         * SUPERSESSIONS AND ONE MEASUREMENT, in that order, and the second supersession withdraws the
         * FIRST SUPERSESSION rather than the measurement: plan 28-01's block described the route as
         * controlled when one line of one of the TWO producers was gated. Read all three blocks top to
         * bottom; none replaces what came before. `AR-27-08` itself STAYS OPEN in `26-SECURITY.md`,
         * narrowed to a named residual by a human maintainer decision on 2026-08-27, so nothing in
         * this file may be quoted as closing it.
         *
         * THIRD SUPERSESSION APPENDED — 2026-08-28, phase 28, plan 28-08. The marker-count
         * sentence in the 2026-08-27 (plan 28-06) paragraph above was true at that plan's commit
         * and is stale from this commit onward. It is amended here rather than rewritten, because
         * rewriting prior text is the practice this constant exists to record against. THE CONSTANT
         * NOW CARRIES THREE SUPERSESSIONS AND ONE MEASUREMENT, in that order. The third one
         * WITHDRAWS NOTHING — it EXTENDS the STILL OPEN clause of the 2026-08-27 (plan 28-06) block
         * with the write-time/read-time bound, its human disposition, and the two claims round 3
         * had to repair. Read all four blocks top to bottom; none replaces what came before.
         */
        const val ISSUE_DETAIL_CARRIER_DISPOSITION =
            "UNCONTROLLED, MEASURED 2026-08-25 (AR-27-08, severity MEDIUM). A cookie sentinel in the " +
                "`Original Value:` line SURVIVES Redaction.apply on the serialized IssueDetails shape " +
                "under STRICT and BALANCED alike. The POSITIVE CONTROL fired on the same payload — a " +
                "`Cookie:` header inside requestResponses[0].request became `Cookie: [STRIPPED]` in the " +
                "same output — so the null result is attributable to REACH, not to a broken probe. " +
                "MECHANISM: IssueUtils.formatIssueDetailHtml joins detailLines with `<br>`, so the blob " +
                "carries NO newline for the logical-line cookie rules to key on, and its shape is " +
                "`Original Value: <v>`, not `name=<v> (COOKIE)`, so cookieTypedParamRegex cannot key on " +
                "it either. The enclosing JSON key is `detail`, which is not in SENSITIVE_WORDS. " +
                "REACHABILITY, cited at source: ActiveAiScanner.kt:1239 writes the value with NO " +
                "privacy-mode gate; handleResult at :1174 calls it only when `confirmation.confirmed`, " +
                "so the route is CONFIRMED-FINDING-ONLY; active AI scanning is opt-in and defaults off " +
                "(AgentSettings.kt:127); a COOKIE-typed point DOES reach it, because :232-246 turns " +
                "every InjectionPoint from InjectionPointExtractor.extract into a target with no filter " +
                "on point.type. SEVERITY REASONING: aggravating — it carries BURP-HELD proxied traffic " +
                "rather than caller-echoed content, and it defeats STRICT outright; mitigating — it is " +
                "LATENT behind an opt-in feature, a confirmed finding, and a scanner_issues call. " +
                "Medium, not high, because it is unreachable in the default posture; not low, because " +
                "when reachable it puts a real session cookie past STRICT." +
                " SUPERSEDED 2026-08-27 (phase 28, plan 28-01) — THE ROUTE IS NOW CONTROLLED. " +
                "Everything above this sentence is the 2026-08-25 measurement, preserved byte-exact " +
                "and NOT rewritten: it is why the control exists. CONTROL SYMBOL: " +
                "ScannerIssueSupport.sanitizeInjectionPointValue, applied at the WRITE SITE where the " +
                "`Original Value:` line is built, so the value never enters the detail blob rather " +
                "than being chased through it afterwards — which is the reason the MECHANISM analysis " +
                "above showed no downstream rule could key on it. A COOKIE-typed point's value is " +
                "replaced with ScannerIssueSupport.INJECTION_VALUE_STRIPPED_MARKER under any " +
                "stripCookies policy. COMMITTED PROBE: IssueDetailCookieCarrierTest — this REPLACES " +
                "the deliberately-uncommitted 27-08 probe, and it is committable for the reason the " +
                "old one was not: it asserts the value is ABSENT, so a green run is evidence of a " +
                "working control rather than a green assertion that a secret survives STRICT. RED " +
                "PROBE: recorded in `28-01-SUMMARY.md` — the control was verified to fail before it " +
                "was verified to pass, so the closure is not the same-day pattern this phase has " +
                "failed on three times. The PRODUCER side was collected separately by plan 28-02, " +
                "which routed InjectionPointExtractor's cookie-type test through " +
                "Redaction.isCookieParameterType WITHOUT moving any value control into the producer " +
                "(D-28-02) — see this file's ROUTED_THROUGH entry for INJECTION_EXTRACTOR/" +
                "PARAMETER_LIST, which moved out of CLASSIFIED_NON_CARRYING on the same commit." +
                " SUPERSEDED AGAIN 2026-08-27 (phase 28, plan 28-06) — THE 28-01 SUPERSESSION " +
                "IMMEDIATELY ABOVE WAS TOO NARROW, AND IT IS THAT SUPERSESSION THIS ONE WITHDRAWS, " +
                "NOT THE 2026-08-25 MEASUREMENT, WHICH STANDS. Both prior blocks are kept " +
                "byte-exact for the same reason the first one gave: they are the evidence the " +
                "controls were needed. THERE ARE TWO PRODUCERS OF THESE DETAIL LINES, NOT ONE. The " +
                "28-01 control covered ONE line of ONE of them, and this constant then described " +
                "the route as controlled. FOUR LINES ARE CONTROLLED NOW: (1) " +
                "ScannerIssueSupport.sanitizeInjectionPointValue on `Original Value:` (28-01); (2) " +
                "ScannerIssueSupport.sanitizeRenderedPayload on `Payload Used:` (28-04), the line " +
                "that re-leaked what (1) had just stripped, because for a COOKIE point the payload " +
                "is derived from the cookie value; (3) and (4) " +
                "AiScanCheck.sanitizeCookiePointText on BOTH detail lines of the SECOND producer, " +
                "AiScanCheck.buildDetail (28-05), keyed on an identity compare against " +
                "AuditInsertionPointType.PARAM_COOKIE. COMMITTED PROBES: " +
                "IssueDetailCookieCarrierTest for (1) and (2), AiScanCheckDetailCookieCarrierTest " +
                "for (3) and (4), with CookieRouteDispositionTest holding the predicate " +
                "populations. THREE OF THE FOUR ARE MEASURED CARRIERS AND ONE IS NOT: route 2's " +
                "payload line is controlled as DEFENCE IN DEPTH ONLY, because AiScanCheck sources " +
                "payloads from the static getQuickPayloads table and interpolates no insertion " +
                "point value, so it is not a carrier at HEAD. Recording it as a closed leak would " +
                "be this constant's own error repeated. STILL OPEN, NAMED SO NOBODY READS THIS AS " +
                "A CLOSURE: the `Evidence:` line of the same blob is AR-28-01 (MEDIUM), accepted as " +
                "a shipping residual by maintainer decision at 28-03's blocking checkpoint; and " +
                "AR-27-08 itself STAYS OPEN in 26-SECURITY.md, narrowed rather than closed, by a " +
                "human maintainer decision recorded there on 2026-08-27. NO REPOSITORY-WIDE " +
                "DETAIL-PRODUCER GATE EXISTS: WR-01 measured the one this file's own gate implied " +
                "as structurally unable to see another file, and D-28-06 records building a " +
                "repository-wide one as CONSIDERED AND NOT TAKEN. Two producers are controlled and " +
                "a third would be caught by nothing." +
                " SUPERSEDED A THIRD TIME 2026-08-28 (phase 28, plan 28-08) — THIS BLOCK " +
                "WITHDRAWS NOTHING. It EXTENDS the STILL OPEN clause of the 2026-08-27 (plan " +
                "28-06) block immediately above; the 2026-08-25 measurement and both prior " +
                "supersessions stand byte-exact, kept for the reason the first one gave — they " +
                "are the evidence the controls were needed. ROUND 3 ADDED NO CONTROL and changed " +
                "no runtime behaviour; a reader who takes this block as evidence of a new control " +
                "has misread it. " +
                "(a) THE WRITE-TIME/READ-TIME BOUND, NAMED. All four controlled lines decide " +
                "ONCE, at issue construction, and bake the result into AuditIssue.detail() — an " +
                "immutable string Burp stores and the scanner_issues MCP tool replays. A " +
                "read-time redaction pass DOES run over that blob: McpTool.kt:45 and :78 wrap " +
                "every tool result in McpToolContext.redactIfNeeded, which calls " +
                "Redaction.apply(raw, RedactionPolicy.fromMode(privacyMode)) unconditionally, " +
                "under the CURRENT mode. What does NOT run again is the TYPE-KEYED gate — the " +
                "AuditInsertionPointType is gone by serialization time — and the redactor's three " +
                "cookie rules each bind to framing a detail line does not carry: a Cookie:-style " +
                "logical-line header name, a === COOKIES === span, or a trailing ' (COOKIE)' " +
                "marker. An issue built while privacyMode was OFF therefore still emits that " +
                "cookie value on a later STRICT read UNLESS some generic, non-cookie rule happens " +
                "to match the value's own shape. AiScanCheck.consolidateIssues " +
                "returns KEEP_EXISTING on a matching canonical name and normalized URL, so a " +
                "re-scan under STRICT does not repair the site map; and plan 28-05's own red " +
                "probe recorded DETAIL_SENTINEL surviving STRICT redaction verbatim whenever the " +
                "write gate does not fire — a sentinel whose own KDoc records it was shaped with " +
                "no digits, no '=' and no metacharacters so that ONLY the type gate could remove " +
                "it, which bounds the type-keyed question and leaves the residual's width for a " +
                "JWT or base64 session value UNMEASURED. " +
                "(b) THE DISPOSITION AND ITS AUTHORITY. ACCEPTED AS A NAMED RESIDUAL by a HUMAN " +
                "maintainer answer on 2026-08-28 (D-28-09, recorded in 28-CONTEXT.md) — the " +
                "question was put at the verify_phase_goal gate and answered, not defaulted by " +
                "auto-advance. THE REASON THE MAINTAINER GAVE, recorded so it is not " +
                "re-litigated: every issue PRODUCED under STRICT or BALANCED — the entire default " +
                "posture, AgentSettings.kt:493 defaults to BALANCED — is measurably clean across " +
                "all four detail lines of both producers, and the residual requires a deliberate " +
                "OFF scan followed by a mode switch, the same latent, opt-in reachability profile " +
                "that put AR-27-08 at MEDIUM rather than high. A read-time fix is new " +
                "architecture on the emission path and belongs to its own phase. " +
                "(c) WHERE THE BOUND IS NOW NAMED, by identifier, because D-28-10 made the " +
                "acceptance CONDITIONAL on exactly this: AiScanCheck.consolidateIssues's KDoc " +
                "and SettingsPanelInit's PRIVACY_MODE_TOOLTIP (both plan 28-07), 26-SECURITY.md " +
                "row 315 clause (d) (plan 28-08), and here. " +
                "(d) THE PROBE CLAIM FOR DETAIL LINE (4) WAS FALSE WHEN THIS CONSTANT MADE IT, " +
                "AND IS TRUE NOW. The 28-06 block above names AiScanCheckDetailCookieCarrierTest " +
                "as the committed probe for line (4), the rendered payload line; at that commit a " +
                "grep for that line's literal prefix on that file returned 0, KDoc included — " +
                "the class asserted nothing about it. That was prose written ahead of the tree, " +
                "and naming it precisely is worth more than softening it. Plan 28-07 supplied " +
                "the assertions: cookiePayloadLineIsStrippedUnderStrict, " +
                "cookiePayloadLineIsStrippedUnderBalanced, cookiePayloadLineSurvivesUnderOff and " +
                "urlParamPayloadLineSurvivesStrict_attributionControl. THE ASYMMETRY IS " +
                "UNCHANGED BY THE REPAIR: line (4) on route 2 remains DEFENCE IN DEPTH and not a " +
                "measured carrier, because AiScanCheck sources payloads from the static " +
                "getQuickPayloads table and interpolates no insertion-point value. Adding " +
                "assertions made a claim TRUE; it did not close a leak. " +
                "(e) THE ROUTE-2 GATE'S FAIL-OPEN SET, PREVIOUSLY UNRECORDED (D-28-11). " +
                "AiScanCheck.isCookieInsertionPoint is an identity compare against " +
                "AuditInsertionPointType.PARAM_COOKIE, and FOUR members of that 17-member enum " +
                "can carry a cookie value while not being PARAM_COOKIE: HEADER, USER_PROVIDED, " +
                "EXTENSION_PROVIDED and UNKNOWN. For those four the gate is fail-OPEN today. " +
                "Contrast route 1, whose InjectionType has exactly ONE cookie-capable member and " +
                "it IS COOKIE — the property that made D-28-01's pass-through safe BY " +
                "CONSTRUCTION, and which this enum lacks. WIDENING WAS CONSIDERED AND NOT TAKEN, " +
                "for plan 28-07's four recorded reasons: it would strip the original-value line " +
                "on every header-typed, user-provided, extension-provided and unknown insertion " +
                "point, a product behaviour change nobody asked for; it contradicts D-28-01's " +
                "deliberate pass-through discipline that route 2 copied on purpose; it would " +
                "move CookieRouteDispositionTest's two pinned predicate populations and would " +
                "need its own red probe and its own reachability measurement; and plan 28-07 was " +
                "chartered as RECORD REPAIR, so shipping a behaviour change inside it would " +
                "leave the register describing code that no longer exists. THE RESIDUAL IS " +
                "PINNED by " +
                "AiScanCheckDetailCookieCarrierTest.theRouteTwoGateIsFailOpenForTheseCookieCapableTypes, " +
                "whose GREEN run records the residual's width and is NOT evidence of correct " +
                "behaviour, and bounded by that file's " +
                "theInsertionPointTypeEnumPopulationIsTheOneTheResidualWasMeasuredAgainst, so a " +
                "Burp release that adds a member turns the pin RED instead of widening the " +
                "residual in silence. THE CORRECTED KDoc PREMISE: the claim that a real Burp " +
                "implementation may return null from type() was FALSE against the shipped jar — " +
                "javap on montoya-api-2026.2.jar shows a DEFAULT method whose entire body is " +
                "`getstatic AuditInsertionPointType.EXTENSION_PROVIDED; areturn`. " +
                "(f) WHAT IS STILL OPEN AFTER THIS ROUND, so this constant cannot be read as a " +
                "closure: AR-28-01, the `Evidence:` line of the same blob (MEDIUM), " +
                "maintainer-accepted at 28-03's blocking checkpoint and deliberately not " +
                "reopened; AR-27-08 itself, which STAYS OPEN in 26-SECURITY.md; the " +
                "write-time/read-time bound of (a), now a named residual; the route-2 fail-open " +
                "set of (e); and the continued absence of any repository-wide detail-producer " +
                "gate — WR-01 is not closed by anything written here and D-28-06 records " +
                "building one as CONSIDERED AND NOT TAKEN. Two producers are controlled and a " +
                "third would still be caught by nothing." +
                " NARROWED 2026-08-28 (phase 28, plan 28-09) — THIS BLOCK WITHDRAWS NOTHING AND " +
                "ADDS NO CONTROL. It narrows two claims the plan 28-08 block above stated " +
                "absolutely: that no read-time redaction pass ran over the detail blob at all, " +
                "and that the 28-05 red probe PROVED the redactor could never rescue the value " +
                "downstream. The round-3 code review found both overstated (28-REVIEW-3.md, " +
                "WR-02 and WR-03) and the tree confirmed it: the pass exists — McpTool.kt:45 " +
                "and :78 wrap every tool result in McpToolContext.redactIfNeeded, which calls " +
                "Redaction.apply under the CURRENT mode — but it is not type-keyed; and the " +
                "probe's sentinel was built to be invisible to every generic rule, so it bounds " +
                "the type-keyed question ONLY. Clause (a) above is rewritten accordingly. Every " +
                "other clause, the DISPOSITION and its AUTHORITY in (b), and AR-27-08's OPEN " +
                "status in 26-SECURITY.md are UNTOUCHED — narrowing an overclaim about the " +
                "redactor's reach makes this residual's naming MORE accurate, not weaker, and " +
                "D-28-09 and D-28-10 stand exactly as recorded. The retired phrases are " +
                "deliberately not quoted anywhere in this file: the greps that enforce their " +
                "retirement are literal."
    }
}
