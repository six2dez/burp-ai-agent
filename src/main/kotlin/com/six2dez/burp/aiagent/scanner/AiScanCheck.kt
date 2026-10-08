package com.six2dez.burp.aiagent.scanner

import burp.api.montoya.MontoyaApi
import burp.api.montoya.http.Http
import burp.api.montoya.http.message.HttpRequestResponse
import burp.api.montoya.scanner.AuditResult
import burp.api.montoya.scanner.ConsolidationAction
import burp.api.montoya.scanner.audit.insertionpoint.AuditInsertionPoint
import burp.api.montoya.scanner.audit.insertionpoint.AuditInsertionPointType
import burp.api.montoya.scanner.audit.issues.AuditIssue
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence
import burp.api.montoya.scanner.scancheck.ActiveScanCheck
import com.six2dez.burp.aiagent.config.AgentSettings
import com.six2dez.burp.aiagent.redact.RedactionPolicy
import com.six2dez.burp.aiagent.util.IssueUtils

/**
 * Burp Scanner API integration (Option A - Burp Pro only)
 *
 * This integrates with Burp's native scanner to perform AI-powered active testing
 * at each insertion point discovered by Burp's crawler.
 */
class AiScanCheck(
    private val api: MontoyaApi,
    private val getSettings: () -> AgentSettings,
) : ActiveScanCheck {
    private val payloadGenerator = PayloadGenerator()
    private val responseAnalyzer = ResponseAnalyzer()

    override fun checkName(): String = "AI Active Security Analysis"

    /**
     * Called by Burp Scanner for each insertion point.
     * We test relevant payloads based on the insertion point context.
     */
    override fun doCheck(
        baseRequestResponse: HttpRequestResponse,
        insertionPoint: AuditInsertionPoint,
        http: Http,
    ): AuditResult {
        val settings = getSettings()

        // Check if active scanning is enabled
        if (!settings.activeAiEnabled) {
            return AuditResult.auditResult(emptyList())
        }

        // Check scope
        if (settings.activeAiScopeOnly && !api.scope().isInScope(baseRequestResponse.request().url())) {
            return AuditResult.auditResult(emptyList())
        }

        val maxRisk = settings.activeAiMaxRiskLevel
        val issues = mutableListOf<AuditIssue>()

        // Determine which vulnerability classes to test based on insertion point
        val vulnClasses = determineVulnClasses(insertionPoint)

        // Rate-limit pacing: timestamp when the last request finished, so we sleep only the
        // remaining interval before the next request instead of the full delay on top of the
        // round-trip (avoids idling a Burp scanner thread longer than necessary).
        var lastRequestEndMs = 0L

        for (vulnClass in vulnClasses) {
            val payloads =
                payloadGenerator
                    .getQuickPayloads(vulnClass, maxRisk)
                    .take(settings.activeAiMaxPayloadsPerPoint)

            for (payload in payloads) {
                try {
                    // Rate limiting: honour a minimum interval between requests, counting the
                    // request round-trip toward that interval rather than sleeping the full
                    // delay on top of it (keeps the scanner thread from idling unnecessarily).
                    val delayMs = settings.activeAiRequestDelayMs.toLong()
                    if (delayMs > 0 && lastRequestEndMs > 0L) {
                        val remaining = delayMs - (System.currentTimeMillis() - lastRequestEndMs)
                        if (remaining > 0L) Thread.sleep(remaining)
                    }

                    val issue = testPayload(baseRequestResponse, insertionPoint, payload, vulnClass)
                    lastRequestEndMs = System.currentTimeMillis()
                    if (issue != null) {
                        issues.add(issue)
                        // Found a confirmed vuln for this class, move to next
                        break
                    }
                } catch (e: Exception) {
                    api.logging().logToError("[AiScanCheck] Error testing payload: ${e.message}")
                }
            }
        }

        return AuditResult.auditResult(issues)
    }

    /**
     * Consolidate duplicate issues.
     *
     * WRITE-TIME/READ-TIME BOUND — THIS PARAGRAPH IS A NOTE, NOT A CONTROL. Nothing below changes
     * what this function returns. It is here because this function is the mechanism that makes a
     * stale finding stick, and a residual whose mechanism is undocumented gets re-derived wrongly.
     *
     * BOTH COOKIE CONTROLS DECIDE ONCE, AT WRITE TIME. Route 1
     * (`ScannerIssueSupport.sanitizeInjectionPointValue`) and route 2 ([buildDetail] through
     * [sanitizeCookiePointText]) both run at issue CONSTRUCTION and bake their result into
     * `AuditIssue.detail()` — an immutable string Burp stores and the `scanner_issues` MCP tool
     * replays verbatim.
     *
     * A READ-TIME REDACTION PASS DOES RUN OVER IT — WHAT IS MISSING IS A TYPE-KEYED ONE.
     * `mcp/tools/McpTool.kt:45` and `:78` wrap every tool result in
     * `McpToolContext.redactIfNeeded` (`mcp/McpToolContext.kt:59`), which calls
     * `Redaction.apply(raw, RedactionPolicy.fromMode(privacyMode), stableHostSalt = hostSalt)`
     * UNCONDITIONALLY, under the CURRENT mode. So the `scanner_issues` blob carrying this detail
     * string IS redacted on the way out. What that pass cannot do is re-apply the cookie gate the
     * two write-time routes above apply, because the `AuditInsertionPointType` those routes key on
     * is gone by serialization time — and the redactor's three cookie rules each key on framing a
     * detail line does not carry: `cookieHeaderRegex`/`setCookieHeaderRegex` need a logical-line
     * `Cookie:`-style header name, `redactCookieSections` needs a `=== COOKIES ===` span, and
     * `cookieTypedParamRegex` needs a trailing ` (COOKIE)` marker. [buildDetail] emits a bare
     * `**Original Value:** <value>` markdown line, which carries none of the three. An issue built
     * while `privacyMode` was `OFF` therefore still emits that cookie value on a later STRICT read
     * UNLESS one of the generic, non-cookie rules happens to match the value's own shape. That
     * conditional is the honest form of this residual, and the width of the condition is unmeasured
     * — see the next paragraph.
     *
     * AND THIS FUNCTION IS WHY THAT IS NOT SELF-HEALING. On a matching canonical name AND a
     * matching normalized URL it returns [ConsolidationAction.KEEP_EXISTING], so a re-scan under
     * STRICT does not replace the stale issue in the site map. The operator's later, stricter
     * intent cannot reach the already-recorded detail string through this path.
     *
     * WHAT THE REDACTOR WAS MEASURED NOT TO RESCUE, AND FOR WHICH SHAPE. Plan 28-05's red probe
     * recorded `DETAIL_SENTINEL = "cedar-anchor-marble-feather"` surviving STRICT redaction VERBATIM
     * whenever the write gate does not fire. Read that result at its actual reach: the sentinel's
     * own KDoc (`AiScanCheckDetailCookieCarrierTest`) records that it was SHAPED for the measurement
     * — "no digits, no `=`, no metacharacters, so only the new type gate can plausibly remove it",
     * and deliberately free of the token `cookie` so no header-name rule could bind. The probe
     * therefore establishes the absence of a TYPE-KEYED read-time control, which is exactly what it
     * was built to establish. It does NOT establish the residual's width for a realistic
     * high-entropy cookie value — a JWT or a base64 session id is the opposite shape, is what the
     * generic STRICT rules target, and was NOT measured.
     *
     * DISPOSITION: ACCEPTED as a named residual by maintainer answer on 2026-08-28 (`D-28-09`),
     * conditional (`D-28-10`) on it being named in four places — here, at the privacy-mode selector
     * (`PRIVACY_MODE_TOOLTIP` in `ui/SettingsPanelInit.kt`), in `ISSUE_DETAIL_CARRIER_DISPOSITION`
     * and in `26-SECURITY.md` row 315. THE REASON FOR THE ACCEPTANCE, stated so a reader does not
     * re-litigate it from scratch: a read-time fix is NEW ARCHITECTURE on the emission path and
     * belongs to its own phase, not to a record-repair round.
     *
     * RECORDED AS A CORRECTION, NOT A SILENT EDIT. Round 3 (plan 28-08) committed the two claims
     * above in an ABSOLUTE form: it denied that ANY read-time pass ran over the detail string, and
     * it called the red probe's result a PROOF that the redactor never stands between that string
     * and its reader. Round 4 (plan 28-09) narrowed both to the conditional forms written above,
     * after the round-3 code review (`28-REVIEW-3.md`, WR-02 and WR-03) found them overstated and
     * the tree confirmed it. Neither retired phrase is quoted here, deliberately — the greps that
     * enforce their retirement are literal, and a quotation would keep tripping them forever. The
     * disposition is UNCHANGED: `AR-27-08` stays OPEN and `D-28-09` stands. Only the account of the
     * redactor's reach was wrong, and narrowing it makes the residual's naming more accurate, not
     * weaker.
     */
    override fun consolidateIssues(
        newIssue: AuditIssue,
        existingIssue: AuditIssue,
    ): ConsolidationAction {
        // Use canonical name (strips AI prefixes) + normalized URL for cross-scanner dedup
        val sameName = IssueUtils.canonicalIssueName(newIssue.name()) == IssueUtils.canonicalIssueName(existingIssue.name())
        val sameUrl = IssueUtils.normalizeUrl(newIssue.baseUrl()) == IssueUtils.normalizeUrl(existingIssue.baseUrl())
        if (sameName && sameUrl) {
            return ConsolidationAction.KEEP_EXISTING
        }
        return ConsolidationAction.KEEP_BOTH
    }

    private fun determineVulnClasses(insertionPoint: AuditInsertionPoint): List<VulnClass> {
        val name = insertionPoint.name().lowercase()
        val baseValue = insertionPoint.baseValue()

        // Always test these
        val classes =
            mutableListOf(
                VulnClass.XSS_REFLECTED,
                VulnClass.SQLI,
            )

        // Context-specific additions
        when {
            // URL/file parameters
            name.contains("file") ||
                name.contains("path") ||
                name.contains("page") ||
                name.contains("url") ||
                name.contains("src") ||
                name.contains("dest") ||
                name.contains("redirect") ||
                name.contains("return") ||
                name.contains("next") -> {
                classes.addAll(listOf(VulnClass.LFI, VulnClass.PATH_TRAVERSAL, VulnClass.SSRF, VulnClass.OPEN_REDIRECT))
            }

            // ID parameters (IDOR)
            name.contains("id") ||
                name.contains("uid") ||
                name.contains("user") ||
                name.endsWith("_id") ||
                baseValue.matches(Regex("^\\d+$")) ||
                baseValue.matches(Regex("^[a-f0-9-]{36}$", RegexOption.IGNORE_CASE)) -> {
                classes.add(VulnClass.IDOR)
            }

            // Command execution contexts
            name.contains("cmd") ||
                name.contains("exec") ||
                name.contains("command") ||
                name.contains("ping") ||
                name.contains("host") ||
                name.contains("ip") -> {
                classes.add(VulnClass.CMDI)
            }

            // Template contexts
            name.contains("template") ||
                name.contains("view") ||
                name.contains("render") ||
                name.contains("email") ||
                name.contains("message") -> {
                classes.add(VulnClass.SSTI)
            }
        }

        val filtered = classes.distinct().filterNot { it in ScanPolicy.PASSIVE_ONLY_VULN_CLASSES }
        val mode = getSettings().activeAiScanMode
        return filtered.filter { ScanPolicy.isAllowedForMode(mode, it) }
    }

    private fun testPayload(
        baseRequestResponse: HttpRequestResponse,
        insertionPoint: AuditInsertionPoint,
        payload: Payload,
        vulnClass: VulnClass,
    ): AuditIssue? {
        val settings = getSettings()

        // Build request with payload using Burp's ByteArray
        val payloadBytes =
            burp.api.montoya.core.ByteArray
                .byteArray(payload.value)
        val baseService = baseRequestResponse.httpService()
        val attackRequestBase = insertionPoint.buildHttpRequestWithPayload(payloadBytes)
        val attackRequest =
            if (attackRequestBase.httpService() == null) {
                attackRequestBase.withService(baseService)
            } else {
                attackRequestBase
            }
        if (attackRequest.httpService() == null) {
            api.logging().logToError("[AiScanCheck] Cannot send request: HTTP service is null for insertion point ${insertionPoint.name()}")
            return null
        }

        // Measure baseline if needed for time-based
        val baselineTime =
            if (payload.detectionMethod == DetectionMethod.BLIND_TIME) {
                val start = System.currentTimeMillis()
                api.http().sendRequest(baseRequestResponse.request())
                System.currentTimeMillis() - start
            } else {
                0L
            }

        // Send attack request
        val startTime = System.currentTimeMillis()
        val attackResponse = api.http().sendRequest(attackRequest)
        val responseTime = System.currentTimeMillis() - startTime

        val attackRequestResponse = HttpRequestResponse.httpRequestResponse(attackRequest, attackResponse.response())

        // Analyze response
        val confirmed =
            when (payload.detectionMethod) {
                DetectionMethod.BLIND_TIME -> {
                    val expectedDelay = payload.timeDelayMs ?: 3000
                    responseAnalyzer.analyzeTimeBased(baselineTime, responseTime, expectedDelay)
                }
                else -> {
                    val confirmation =
                        responseAnalyzer.analyze(
                            baseRequestResponse,
                            attackRequestResponse,
                            payload,
                            vulnClass,
                        )
                    confirmation?.confirmed == true
                }
            }

        if (!confirmed) return null

        // Build evidence
        val evidence = buildEvidence(baseRequestResponse, attackRequestResponse, payload, vulnClass, responseTime, baselineTime)

        // Add markers to highlight payload in request and evidence in response
        val markedAttack =
            IssueMarkerSupport
                .markRequestPayload(
                    attackRequestResponse,
                    payload.value,
                ).let { IssueMarkerSupport.markResponseEvidence(it, evidence) }

        // Create Burp issue
        return AuditIssue.auditIssue(
            "[AI Active] ${vulnClass.name} (Burp Scanner)",
            buildDetail(insertionPoint, payload, evidence),
            ScannerIssueSupport.remediation(vulnClass),
            baseRequestResponse.request().url(),
            ScannerIssueSupport.mapSeverity(vulnClass),
            mapConfidence(payload),
            null, // background
            null, // remediationBackground
            ScannerIssueSupport.mapSeverity(vulnClass),
            listOf(baseRequestResponse, markedAttack),
        )
    }

    private fun buildEvidence(
        original: HttpRequestResponse,
        attack: HttpRequestResponse,
        payload: Payload,
        vulnClass: VulnClass,
        responseTime: Long,
        baselineTime: Long,
    ): String =
        when (payload.detectionMethod) {
            DetectionMethod.BLIND_TIME ->
                "Time-based detection: baseline=${baselineTime}ms, attack=${responseTime}ms (expected delay: ${payload.timeDelayMs ?: 3000}ms)"
            DetectionMethod.ERROR_BASED -> {
                val body = attack.response()?.bodyToString() ?: ""
                val errorMatch = findErrorPattern(body, vulnClass)
                "Error pattern detected: $errorMatch"
            }
            DetectionMethod.REFLECTION ->
                "Payload reflected unencoded in response"
            DetectionMethod.CONTENT_BASED ->
                "Expected content found in response: ${payload.expectedEvidence}"
            DetectionMethod.BLIND_BOOLEAN -> {
                val diff =
                    responseAnalyzer.calculateDifference(
                        original.response()?.bodyToString() ?: "",
                        attack.response()?.bodyToString() ?: "",
                    )
                "Boolean-based: response similarity ${(diff.similarity * 100).toInt()}%"
            }
            DetectionMethod.OUT_OF_BAND ->
                "Out-of-band interaction detected"
        }

    private fun findErrorPattern(
        body: String,
        vulnClass: VulnClass,
    ): String {
        val patterns =
            when (vulnClass) {
                VulnClass.SQLI ->
                    listOf(
                        Regex("SQL syntax.*MySQL", RegexOption.IGNORE_CASE),
                        Regex("ORA-[0-9]+", RegexOption.IGNORE_CASE),
                        Regex("PostgreSQL.*ERROR", RegexOption.IGNORE_CASE),
                        Regex("SQLServer", RegexOption.IGNORE_CASE),
                    )
                VulnClass.LFI ->
                    listOf(
                        Regex("root:.*:0:0:"),
                        Regex("\\[fonts\\]", RegexOption.IGNORE_CASE),
                    )
                else -> emptyList()
            }

        for (pattern in patterns) {
            val match = pattern.find(body)
            if (match != null) return match.value.take(100)
        }
        return "Pattern matched"
    }

    /**
     * (PRIV-05) 28-05 / `CR-02` — the SECOND producer of active-scan issue-detail lines.
     *
     * `AR-27-08` is defined as the cookie-value -> `scanner_issues` -> `AuditIssue.detail()`
     * carrier. This function is that carrier by a second route: it is live-registered
     * `PER_INSERTION_POINT` at `App.kt:214-215`, its output reaches the tool result through
     * `api.siteMap()`, and before plan 28-05 it read NO privacy mode at all — it rendered
     * identically under STRICT, BALANCED and OFF.
     *
     * THE TWO CONTROLLED LINES ARE NOT SYMMETRIC, and recording that is the point of this
     * paragraph. The `**Original Value:**` line IS a measured carrier: `baseValue()` on a
     * `PARAM_COOKIE` insertion point is the operator's raw cookie value, taken by Burp from proxied
     * traffic. The `**Payload Used:**` line is NOT a carrier at HEAD: this class sources payloads
     * from `payloadGenerator.getQuickPayloads(...)`, which returns entries from a STATIC table and
     * interpolates no value (`PayloadGenerator.kt:633-639`) — unlike `ActiveAiScanner`'s
     * context-aware route, which is what made route 1's payload line a real leak. It is controlled
     * here as DEFENCE IN DEPTH and for vocabulary parity with route 1. Calling it a measured leak
     * closure would be exactly the overclaim phase 28 exists to correct.
     *
     * WHY `internal` AND NOT `private`. `AuditIssue.auditIssue(...)` routes through Burp's
     * `ObjectFactoryLocator.FACTORY`, which is null outside the Burp runtime, so no unit test can
     * reach this function through its only caller, [testPayload] (the plan named that caller
     * `createIssue`; the issue-construction code lives inline in [testPayload] and there is no
     * function by that name in this class). `internal` is module-scoped and is the same visibility
     * `ScannerIssueSupport`'s controlled functions already use; it creates no external surface on a
     * single fat-JAR artifact.
     *
     * The `listOf(baseRequestResponse, markedAttack)` argument at that call site is
     * deliberately UNTOUCHED by this control: the operator keeps the raw attack request
     * byte-for-byte in the same issue's Burp evidence pane, which Burp renders directly and never
     * passes through `Redaction.apply`. That is the same accepted trade route 1 records.
     */
    internal fun buildDetail(
        insertionPoint: AuditInsertionPoint,
        payload: Payload,
        evidence: String,
    ): String {
        val settings = getSettings()
        val policy = RedactionPolicy.fromMode(settings.privacyMode)
        val backendId = settings.preferredBackendId
        val metadataSection =
            buildString {
                appendLine("---")
                appendLine()
                appendLine("### AI Analysis Metadata")
                appendLine()
                appendLine("**Backend:** $backendId (via Burp Scanner)")
                appendLine("**Scan Type:** Active (Burp Scanner Integration)")
                appendLine("**Detection:** ${payload.detectionMethod}")
                val timestamp =
                    java.time.Instant
                        .now()
                        .toString()
                        .replace('T', ' ')
                        .substringBefore('.')
                appendLine("**Scan Date:** $timestamp UTC")
                appendLine()
                appendLine("---")
            }

        return """
**AI-Confirmed Vulnerability via Burp Scanner**

**Insertion Point:** ${insertionPoint.name()} (${insertionPoint.type()})
**Original Value:** ${sanitizeCookiePointText(insertionPoint, policy, insertionPoint.baseValue(), ScannerIssueSupport.ORIGINAL_VALUE_MAX_CHARS)}

**Payload Used:**
```
${sanitizeCookiePointText(insertionPoint, policy, payload.value, ScannerIssueSupport.PAYLOAD_VALUE_MAX_CHARS)}
```

**Detection Method:** ${payload.detectionMethod}
**Evidence:** $evidence

**Risk Level:** ${payload.risk}

$metadataSection

_(Confirmed via active exploitation testing integrated with Burp Scanner)_
        """.trim()
    }

    private fun mapConfidence(payload: Payload): AuditIssueConfidence =
        when (payload.detectionMethod) {
            DetectionMethod.ERROR_BASED -> AuditIssueConfidence.CERTAIN
            DetectionMethod.REFLECTION -> AuditIssueConfidence.FIRM
            DetectionMethod.CONTENT_BASED -> AuditIssueConfidence.FIRM
            DetectionMethod.BLIND_TIME -> AuditIssueConfidence.TENTATIVE
            DetectionMethod.BLIND_BOOLEAN -> AuditIssueConfidence.TENTATIVE
            DetectionMethod.OUT_OF_BAND -> AuditIssueConfidence.FIRM
        }

    /**
     * (PRIV-05) 28-05 / `CR-02` — route 2's cookie control, held as companion members.
     *
     * WHY A COMPANION AND NOT TWO MORE INSTANCE METHODS, recorded because it is a deviation from
     * this plan's literal shape. Adding both as instance methods took `AiScanCheck` to eleven
     * functions and turned detekt's `TooManyFunctions` red (default `thresholdInClasses` is 11; the
     * rule is not configured in `detekt.yml` and this class has no baseline entry for it). The two
     * ways to silence that in place were both forbidden here: growing `detekt-baseline.xml` is
     * banned by QUAL-07 and by this plan's own acceptance criteria, and raising the threshold would
     * weaken a repository-wide quality gate to land a two-function change. Both functions are pure
     * — they read no instance state, only their arguments — so a companion is where they already
     * belonged. The identity compare still lives in this file, which is what
     * `CookieRouteDispositionTest.exactlyOneInsertionPointCookieTypePredicateExistsInMainSource`
     * asserts, and both remain `internal`.
     */
    companion object {
        /**
         * (PRIV-05) 28-05 / `CR-02` / `AR-27-08` route 2 — is this insertion point the cookie carrier?
         *
         * THE MEASUREMENT BEHIND THE SPELLING, written down because assuming it is how this control
         * ships dead. The shared predicate in `Redaction` answers the cookie-type question for the
         * PARAMETER carriers: it trims a parameter-type NAME, upper-cases it, and compares it
         * against the literal `COOKIE`. The constant this class actually holds is a member of a
         * DIFFERENT closed enum — Montoya's `AuditInsertionPointType`, whose cookie member is named
         * `PARAM_COOKIE`. That name is not `COOKIE`, so the shared predicate returns FALSE here.
         * Reusing it would compile, read as correct, and ship a control that never fires. That is
         * not inferred by inspection: it is pinned by `AiScanCheckDetailCookieCarrierTest`'s
         * `theSharedStringNamePredicateDoesNotRecogniseTheInsertionPointCookieConstant`.
         * <!-- planner-discipline-allow: isCookieParameterType -->
         *
         * THE ALTERNATIVE THAT WAS NOT TAKEN. Widening the shared predicate to accept
         * `PARAM_COOKIE` too was considered and rejected for two reasons. It would move
         * `CookieRouteDispositionTest.exactlyOneCookieTypePredicateExistsInMainSource`, which counts
         * a DIFFERENT population — `HttpParameterType` NAME comparisons — and whose count is
         * evidence for a different claim. And merging two unrelated Montoya enums under one
         * predicate makes that predicate's own contract ambiguous: a reader asking "what does this
         * key on" would get two answers. The new spelling class instead gets its OWN tripwire,
         * `CookieRouteDispositionTest.exactlyOneInsertionPointCookieTypePredicateExistsInMainSource`.
         *
         * D-28-07's discipline is preserved rather than restated: the decision is taken on a member
         * of a CLOSED enum, never on a rendered string, so no reformatting of the detail line can
         * defeat it.
         *
         * THE OTHER ALTERNATIVE NOT TAKEN, AND THE RESIDUAL IT LEAVES NAMED (28-07, `D-28-11`). The
         * paragraph above answers "should the two ENUMS share one predicate". This one answers a
         * DIFFERENT question — "should this gate accept more members of ITS OWN enum" — and the two
         * must not be read as one question answered twice.
         *
         * THE MEASURED POPULATION. `AuditInsertionPointType` carries SEVENTEEN members, and FOUR of
         * them can carry a cookie value while not being `PARAM_COOKIE`: `HEADER` (a `Cookie:` request
         * header presented as a header insertion point), `USER_PROVIDED`, `EXTENSION_PROVIDED` — which
         * is also what `AuditInsertionPoint.type()`'s DEFAULT body returns, so it is what a real
         * implementation that does not override `type()` reports — and `UNKNOWN`. For those four
         * members this gate is fail-OPEN today.
         *
         * WHY THAT IS A REAL GAP AND NOT A FORMALITY. Route 1's `InjectionType` has exactly ONE
         * cookie-capable member and it IS `COOKIE`, which is what made D-28-01's pass-through for
         * every other member safe BY CONSTRUCTION. This enum has no such property, so copying that
         * pass-through SHAPE here does not inherit its safety.
         *
         * THE DECISION: NAME THE RESIDUAL, DO NOT WIDEN THE PREDICATE. Four reasons, written down so
         * the choice is not silently re-taken by inference:
         *  1. Widening would strip `**Original Value:**` on EVERY header-typed, user-provided,
         *     extension-provided and unknown insertion point — removing the operator's own value from
         *     every non-cookie header finding. That is a product behaviour change nobody asked for.
         *  2. It contradicts D-28-01's deliberate pass-through discipline for non-cookie types, which
         *     route 2 copied on purpose so a reader meets ONE control applied twice rather than two
         *     mechanisms.
         *  3. It would move `CookieRouteDispositionTest`'s two pinned predicate populations, which are
         *     evidence for a different claim, and it would need its own red probe and its own
         *     reachability measurement — the very thing plan 27-08's TRANSFER disposition insists on.
         *  4. Plan 28-07 is chartered as RECORD REPAIR. Shipping a behaviour change inside it would
         *     leave the register describing code that no longer exists, in the opposite direction from
         *     the drift the round is fixing.
         *
         * WHERE THE RESIDUAL IS PINNED AND RECORDED. Pinned by
         * `AiScanCheckDetailCookieCarrierTest.theRouteTwoGateIsFailOpenForTheseCookieCapableTypes`,
         * whose GREEN run records the residual's exact width and is NOT evidence of correct
         * behaviour; bounded by that file's
         * `theInsertionPointTypeEnumPopulationIsTheOneTheResidualWasMeasuredAgainst`, so a Burp
         * release that adds a member turns the pin RED instead of widening the residual in silence.
         * Carried into `ISSUE_DETAIL_CARRIER_DISPOSITION` and `26-SECURITY.md` row 315 by plan 28-08.
         */
        internal fun isCookieInsertionPoint(insertionPoint: AuditInsertionPoint): Boolean = insertionPoint.type() == AuditInsertionPointType.PARAM_COOKIE

        /**
         * (PRIV-05) 28-05 / `CR-02` — the single gate BOTH controlled detail lines call.
         *
         * Shaped as the two-arm `when` of [ScannerIssueSupport.sanitizeInjectionPointValue] so a
         * reader meets ONE control applied twice across two producers rather than two mechanisms.
         * There is deliberately no emptiness guard, for the sibling's reason: a cookie point whose
         * value is the empty string must still render the marker, or the point's TYPE becomes
         * observable as a difference in the rendered line.
         *
         * The marker is [ScannerIssueSupport.INJECTION_VALUE_STRIPPED_MARKER], REFERENCED and never
         * retyped — D-28-05's one-vocabulary rule forbids a second marker constant, and a second
         * marker LITERAL in this file is the named failure mode.
         */
        internal fun sanitizeCookiePointText(
            insertionPoint: AuditInsertionPoint,
            policy: RedactionPolicy,
            raw: String,
            maxChars: Int,
        ): String =
            when {
                // The cookie carrier. Same marker every other cookie control in the product writes.
                policy.stripCookies && isCookieInsertionPoint(insertionPoint) -> ScannerIssueSupport.INJECTION_VALUE_STRIPPED_MARKER
                // Every other insertion-point type passes through, truncated exactly as before this
                // gate existed. Deliberate, and the same pass-through D-28-01 chose for route 1.
                else -> raw.take(maxChars)
            }
    }
}
