package com.six2dez.burp.aiagent.mcp

import com.six2dez.burp.aiagent.audit.AuditLogger
import com.six2dez.burp.aiagent.audit.Hashing
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNotEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import java.util.concurrent.CopyOnWriteArrayList

/** A real catalog ID, so the "known tool" path is exercised with a name the extension actually ships. */
private const val KNOWN_TOOL = "http1_request"

/** Extension-derived, so it stays plaintext in both sinks. Deliberately not 64 hex characters. */
private const val TRACE_ID = "trace-22-05"

/** Not 1, so a hardcoded first step would be visible instead of accidentally correct. */
private const val CHAIN_STEP = 3

/** Distinctive enough that its absence from the payload is provable by marker rather than by eye. */
private const val ARGS_JSON = """{"url":"http://evil.example/SECRETMARKER"}"""

/**
 * `sanitizeInline`'s default cap, restated here because `INLINE_MAX_LENGTH` is file-private to
 * `ToolApprovalGate.kt`. The number is what the fixtures below are built around: it is the boundary the
 * args digest used to be taken at, so a test that differs only past it is the one that can see the bug.
 */
private const val INLINE_CAP = 120

/**
 * The opening of a real `http1_request` argument object, padded past [INLINE_CAP]. Everything that
 * constitutes the security question — method, path, headers, body — lives after this prefix, which is
 * exactly the shape that made a prefix digest useless.
 */
private val LONG_ARGS_PREFIX =
    """{"targetHostname":"example.com","targetPort":443,"usesHttps":true,"content":"""" + "x".repeat(80)

/** The same idea for a tool name the catalog cannot resolve. */
private const val UNRESOLVABLE_TOOL = "pretend_tool_MARKER"

/**
 * An unresolvable tool name padded past [INLINE_CAP], so two variants of it can differ only where a
 * capped digest cannot see.
 *
 * This is the tool-name analogue of [LONG_ARGS_PREFIX], and the branch it exercises is the one where
 * the digest matters MOST: when the catalog cannot resolve a name, the plaintext `toolName` is replaced
 * by the constant `"unknown"`, so `toolNameSha256` is the ONLY record in the durable payload of what the
 * model actually asked for. A model that wants two different requests to be indistinguishable in the
 * audit trail only has to keep the first 120 characters the same.
 */
private val LONG_UNRESOLVABLE_PREFIX = "pretend_tool_" + "z".repeat(INLINE_CAP)

/**
 * A name the extension currently treats as RECOGNISED — `ChatPanel.isKnownTool` accepts any `ext:`
 * prefix and `McpToolExecutor.canonicalToolId` returns unmatched names verbatim — carrying the newline
 * and the second `[SEC-06]` record that a model would use to forge an approval in the Output tab.
 */
private const val FORGED_EXT_TOOL = "ext:demo:a\r\n[SEC-06] decision=approve_once"

/** [FORGED_EXT_TOOL] with its control characters removed, which is the only form either sink may carry. */
private const val FORGED_EXT_TOOL_SANITIZED = "ext:demo:a[SEC-06] decision=approve_once"

/** Any lowercase 64-hex run — what a SHA-256 looks like. The Output tab must never carry one. */
private val sha256Shaped = Regex("[0-9a-f]{64}")

/**
 * SC3 coverage for the SEC-06 decision record: the payload's key set and ORDER, the hash-by-default
 * rule, `status = denied`, `secTier` on every event, and the single-line sanitized Output line.
 *
 * Nothing here binds a port, touches a clock or constructs a Swing component — the Output sink is a
 * lambda and the audit sink is the global emitter seam, so every assertion is exact.
 */
class ToolDecisionReporterTest {
    private val lines = CopyOnWriteArrayList<String>()

    // The emitter fires on the caller's thread and is read from the JUnit thread, so the capture list
    // must be concurrent. The payload type is `Any`, not `Map<String, Any?>` — AuditLogger.kt:20
    // declares `((String, Any) -> Unit)?`.
    private val captured = CopyOnWriteArrayList<Pair<String, Any>>()

    @BeforeEach
    fun registerCapturingEmitter() {
        lines.clear()
        captured.clear()
        AuditLogger.registerGlobalEmitter { type, payload -> captured += type to payload }
    }

    @AfterEach
    fun clearGlobalEmitter() {
        // globalEmitter is a @Volatile companion field — leaving it registered leaks into other
        // test classes running in the same JVM.
        AuditLogger.registerGlobalEmitter(null)
    }

    // ---------------------------------------------------------------------------------------
    // D-06 — one event, one Output line, one metadata map, all from a single construction
    // ---------------------------------------------------------------------------------------

    @Test
    fun reportEmitsExactlyOneAuditEventPerInvocation() {
        report()

        assertEquals(1, captured.size, "SC3 requires exactly one decision event per decision")
        assertEquals(1, lines.size, "the Output tab gets exactly one line per decision")
        // A NEW type constant. Filing this under an existing tool event would put records whose keys
        // mean different things under one type.
        assertEquals("mcp_tool_decision", captured[0].first)
    }

    @Test
    fun payloadKeyOrderIsPinnedForAKnownApprovedTool() {
        report(
            decision = ToolDecision.APPROVE_ONCE,
            argsJson = ARGS_JSON,
            resultChars = RESULT_CHARS,
        )

        // The first six keys are what MCP_TOOL_CALL already emits, in their existing order; the rest
        // are SEC-06's additions. Pinning the list is what stops the shape drifting one field at a
        // time until two records of the "same" event no longer describe the same thing.
        assertEquals(
            listOf("operation", "status", "traceId", "step", "toolName", "secTier", "decision", "argsSha256", "resultChars"),
            payloadAt(0).keys.toList(),
        )
        assertEquals("tool_chain", payloadAt(0)["operation"])
        assertEquals(KNOWN_TOOL, payloadAt(0)["toolName"])
        assertEquals(CHAIN_STEP.toString(), payloadAt(0)["step"])
        assertEquals(TRACE_ID, payloadAt(0)["traceId"])
    }

    @Test
    fun returnedMetadataMapIsTheSameConstructionAsTheAuditPayload() {
        val metadata = report(argsJson = ARGS_JSON, resultChars = RESULT_CHARS)

        // T-22-09: the audit event and the AI Activity record are derived from ONE map, so they cannot
        // drift into disagreeing about what was decided. A call site that assembled its own second map
        // is the defect this assertion exists to catch.
        assertEquals(payloadAt(0).filterValues { it != null }, metadata)
        // AiRequestLogger.log takes Map<String, String>, so null-valued keys are dropped rather than
        // written as empty strings — "key absent" and "key present but empty" stay distinguishable.
        assertFalse(metadata.containsValue(""), "an absent value was flattened into an empty string")
    }

    // ---------------------------------------------------------------------------------------
    // D-12 / Pitfall 5 — a denial is a POLICY outcome, not a malfunction
    // ---------------------------------------------------------------------------------------

    @Test
    fun deniedDecisionUsesDeniedStatusAndOmitsResultChars() {
        val denials =
            listOf(
                ToolDecision.DENY,
                ToolDecision.DENY_SESSION,
                ToolDecision.SESSION_DENIED,
                ToolDecision.IMPLICIT_DENY,
            )

        denials.forEachIndexed { index, decision ->
            // resultChars is supplied deliberately: the reporter must drop it, because a record
            // reading "denied" alongside a result length is self-contradictory and an auditor cannot
            // tell which half to believe.
            report(decision = decision, resultChars = RESULT_CHARS, runStatus = "ok")

            assertEquals("denied", payloadAt(index)["status"], "$decision must not be recorded as anything else")
            // An audit log that cannot distinguish a deliberate refusal from a crash is exactly the
            // corruption D-12 was written to prevent, so "error" is asserted against by name.
            assertNotEquals("error", payloadAt(index)["status"])
            assertFalse(payloadAt(index).containsKey("resultChars"), "a denial has no result: $decision")
        }
    }

    @Test
    fun runStatusIsPreservedForACallThatActuallyRan() {
        reporter().report(
            rawToolName = KNOWN_TOOL,
            canonicalId = KNOWN_TOOL,
            knownTool = true,
            tier = SecTier.CONFIRM,
            decision = ToolDecision.APPROVE_ONCE,
            argsJson = null,
            traceId = TRACE_ID,
            chainStep = CHAIN_STEP,
            runStatus = "error",
        )

        // The third status value is ADDITIVE. An approved call that then failed keeps the caller's
        // existing derivation, so "the tool broke" stays distinguishable from "policy refused it".
        assertEquals("error", payloadAt(0)["status"])
    }

    // ---------------------------------------------------------------------------------------
    // Implicit denial carries its cause; nothing else carries the key
    // ---------------------------------------------------------------------------------------

    @Test
    fun implicitDenyCarriesItsReasonAndOthersDoNot() {
        report(
            decision = ToolDecision.IMPLICIT_DENY,
            implicitDenyReason = ImplicitDenyReason.PROJECT_CHANGED,
        )
        // The reason is passed on the approval too: the key must be gated on the DECISION, not on
        // whether the caller happened to supply a reason.
        report(
            decision = ToolDecision.APPROVE_ONCE,
            implicitDenyReason = ImplicitDenyReason.PROJECT_CHANGED,
        )

        assertEquals("project_changed", payloadAt(0)["implicitDenyReason"])
        assertFalse(payloadAt(1).containsKey("implicitDenyReason"), "an approval gained an implicit-denial cause")
    }

    // ---------------------------------------------------------------------------------------
    // D-10 / T-22-23 — model-supplied values are hashed by default
    // ---------------------------------------------------------------------------------------

    @Test
    fun argsAreHashedByDefault() {
        report(argsJson = ARGS_JSON)

        assertEquals(Hashing.sha256Hex(ARGS_JSON), payloadAt(0)["argsSha256"])
        // Marker absence, not inspection: the args are attacker-influenceable, so no fragment of them
        // may reach the durable record while the verbose seam is off.
        assertFalse(payloadAt(0).toString().contains("SECRETMARKER"), "raw args reached the audit payload")
        assertFalse(lines.single().contains("SECRETMARKER"), "raw args reached the Output tab")
    }

    @Test
    fun argsArePlaintextOnlyUnderTheVerboseSeam() {
        val metadata = report(reporter = verboseReporter(), argsJson = ARGS_JSON)

        // Quick 261008-sqa: `argsSha256` is a digest in BOTH modes; verbose ADDS the body under its own
        // key, right after the digest, instead of writing plaintext under a key named for a hash.
        assertEquals(Hashing.sha256Hex(ARGS_JSON), payloadAt(0)["argsSha256"])
        assertEquals(ARGS_JSON, payloadAt(0)["args"])
        val keys = payloadAt(0).keys.toList()
        assertEquals(keys.indexOf("argsSha256") + 1, keys.indexOf("args"), "`args` must follow `argsSha256`: $keys")
        // The returned map becomes AI Activity metadata, which reaches the AI request log and
        // `ai_audit_query`; verbose must not widen what those sinks hold.
        assertFalse(metadata.containsKey("args"), "verbose args leaked into the AI Activity metadata")
        assertFalse(metadata.values.any { it.contains("SECRETMARKER") }, "raw args reached the AI Activity metadata")
    }

    @Test
    fun theVerboseSupplierIsReadPerReport() {
        var verbose = false
        val reporter = ToolDecisionReporter(logToOutput = { line -> lines += line }, verboseAudit = { verbose })
        report(reporter = reporter, argsJson = ARGS_JSON)
        verbose = true
        report(reporter = reporter, argsJson = ARGS_JSON)

        assertFalse(payloadAt(0).containsKey("args"), "the first report ran with verbose off")
        assertEquals(ARGS_JSON, payloadAt(1)["args"], "the second report must see the flipped setting")
        assertEquals(payloadAt(0)["argsSha256"], payloadAt(1)["argsSha256"], "the digest does not depend on the mode")
    }

    @Test
    fun theDefaultReporterWritesNoArgsKey() {
        val metadata = report(argsJson = ARGS_JSON)

        assertFalse(payloadAt(0).containsKey("args"), "the default reporter must not write the args body")
        assertFalse(metadata.containsKey("args"))
        assertEquals(Hashing.sha256Hex(ARGS_JSON), payloadAt(0)["argsSha256"])
    }

    @Test
    fun argsDigestDistinguishesPayloadsThatDifferPastTheInlineCap() {
        report(argsJson = LONG_ARGS_PREFIX + """benign"}""")
        report(argsJson = LONG_ARGS_PREFIX + """malicious"}""")

        // The digest used to be taken over sanitizeInline's 120-character prefix, so two http1_request
        // calls differing only in the request body hashed identically — and per D-07 the args are
        // exactly where exfiltration hides. An attacker only had to keep the first 120 characters
        // constant, which the argument key order makes trivial.
        assertTrue(LONG_ARGS_PREFIX.length > INLINE_CAP, "the fixture must differ only PAST the old cap")
        assertNotEquals(
            payloadAt(0)["argsSha256"],
            payloadAt(1)["argsSha256"],
            "two payloads differing only past character $INLINE_CAP produced the same digest",
        )
    }

    @Test
    fun argsDigestCoversTheWholeArgumentStringNotAPrefixOfIt() {
        val args = LONG_ARGS_PREFIX + """benign"}"""
        report(argsJson = args)

        // Exact, so a future truncation, trim or whitespace collapse anywhere in the audit path is red
        // rather than merely different. ARGS_JSON cannot catch that: it is 42 clean characters, which
        // every one of those transformations returns unchanged.
        assertEquals(Hashing.sha256Hex(args), payloadAt(0)["argsSha256"])
        assertNotEquals(Hashing.sha256Hex(sanitizeInline(args).orEmpty()), payloadAt(0)["argsSha256"])
    }

    @Test
    fun verboseArgsKeepTheirJsonStructureRatherThanBeingFlattenedToOneCappedLine() {
        val args = "{\n  \"content\": \"GET /x HTTP/1.1\",\n  \"marker\": \"" + "y".repeat(INLINE_CAP) + "\"\n}"
        report(reporter = verboseReporter(), argsJson = args)

        // The verbose body is the only form that is ever rendered, so it is the only one that is
        // sanitized — with the BLOCK form, because the inline form flattens JSON into one unreadable
        // line, which is the opposite of D-07's rule that the full args are shown.
        assertEquals(args, payloadAt(0)["args"])
        assertEquals(Hashing.sha256Hex(args), payloadAt(0)["argsSha256"])
        val keys = payloadAt(0).keys.toList()
        assertEquals(keys.indexOf("argsSha256") + 1, keys.indexOf("args"), "`args` must follow `argsSha256`: $keys")
    }

    @Test
    fun blankArgsAreOmittedRatherThanHashedAsTheEmptyString() {
        report(argsJson = "   ")

        // "no args" and "empty args" must stay distinguishable; hashing "" would collapse them.
        assertFalse(payloadAt(0).containsKey("argsSha256"))
        assertFalse(payloadAt(0).containsValue(Hashing.sha256Hex("")))
    }

    @Test
    fun unknownToolNameIsHashedNotWrittenPlaintext() {
        report(rawToolName = UNRESOLVABLE_TOOL, knownTool = false, tier = SecTier.CONFIRM_EACH)

        assertEquals("unknown", payloadAt(0)["toolName"])
        assertEquals(Hashing.sha256Hex(UNRESOLVABLE_TOOL), payloadAt(0)["toolNameSha256"])
        assertFalse(payloadAt(0).toString().contains("pretend_tool_MARKER"), "a model-authored name reached the audit payload")
        // The conditional key's ORDERED POSITION is part of the shape, not an append.
        assertEquals(
            listOf("operation", "status", "traceId", "step", "toolName", "toolNameSha256", "secTier", "decision"),
            payloadAt(0).keys.toList(),
        )
    }

    @Test
    fun toolNameDigestDistinguishesUnresolvableNamesThatDifferPastTheInlineCap() {
        report(rawToolName = LONG_UNRESOLVABLE_PREFIX + "_benign", knownTool = false, tier = SecTier.CONFIRM_EACH)
        report(rawToolName = LONG_UNRESOLVABLE_PREFIX + "_exfiltrate", knownTool = false, tier = SecTier.CONFIRM_EACH)

        // The same defect CR-03 fixed for argsSha256, on the narrower !knownTool branch: the digest was
        // taken over sanitizeInline's 120-character prefix, so two unresolvable names sharing that
        // prefix recorded identically — on the one branch where the hash is the whole record, because
        // the plaintext name is replaced by the constant "unknown".
        assertTrue(LONG_UNRESOLVABLE_PREFIX.length > INLINE_CAP, "the fixture must differ only PAST the old cap")
        assertEquals("unknown", payloadAt(0)["toolName"], "the plaintext name must still be withheld")
        assertNotEquals(
            payloadAt(0)["toolNameSha256"],
            payloadAt(1)["toolNameSha256"],
            "two unresolvable tool names differing only past character $INLINE_CAP produced the same " +
                "digest, so the audit trail cannot say which one the model asked for",
        )
    }

    @Test
    fun toolNameDigestCoversTheWholeNameNotAPrefixOfIt() {
        val name = LONG_UNRESOLVABLE_PREFIX + "_benign"
        report(rawToolName = name, knownTool = false, tier = SecTier.CONFIRM_EACH)

        // Exact, so a future truncation, trim or whitespace collapse anywhere on this path is red rather
        // than merely different. UNRESOLVABLE_TOOL cannot catch it: it is 19 clean characters, which
        // every one of those transformations returns unchanged.
        assertEquals(Hashing.sha256Hex(name), payloadAt(0)["toolNameSha256"])
        assertNotEquals(Hashing.sha256Hex(sanitizeInline(name).orEmpty()), payloadAt(0)["toolNameSha256"])
        // Dropping the sanitizer must not become a way for the raw name to reach the durable record:
        // a hex digest is safe by construction, and the plaintext name stays behind the placeholder.
        assertFalse(payloadAt(0).toString().contains("pretend_tool"), "a model-authored name reached the audit payload")
    }

    @Test
    fun payloadNamesTheCanonicalToolNotTheAliasTheModelWrote() {
        reporter().report(
            rawToolName = "history",
            canonicalId = "site_map",
            knownTool = true,
            tier = SecTier.CONFIRM,
            decision = ToolDecision.APPROVE_ONCE,
            argsJson = null,
            traceId = TRACE_ID,
            chainStep = CHAIN_STEP,
        )

        // T-22-12 reaching the record: the audit trail must name the tool that actually EXECUTED, not
        // the alias the model happened to type, or the log points at a tool that never ran.
        assertEquals("site_map", payloadAt(0)["toolName"])
        assertTrue(lines.single().contains("tool=site_map"), lines.single())
    }

    // ---------------------------------------------------------------------------------------
    // T-22-24 — secTier on EVERY event, including AUTO
    // ---------------------------------------------------------------------------------------

    @Test
    fun secTierIsPresentOnAnAutoEvent() {
        report(tier = SecTier.AUTO, decision = ToolDecision.AUTO, resultChars = RESULT_CHARS)

        // Without this field, a call that ran under the AUTO tier and a pre-SEC-06 call that ran with
        // no decision at all are indistinguishable in a historical log.
        assertEquals("auto", payloadAt(0)["secTier"])
        assertEquals("auto", payloadAt(0)["decision"])
        assertEquals("ok", payloadAt(0)["status"])
    }

    // ---------------------------------------------------------------------------------------
    // T-22-06 / CWE-117 — the Output line is one line, sanitized, and plaintext
    // ---------------------------------------------------------------------------------------

    @Test
    fun outputLineIsSingleLineAndSanitized() {
        report(rawToolName = "a\r\nInjected: line", knownTool = false, tier = SecTier.CONFIRM_EACH)

        val line = lines.single()
        assertFalse(line.contains('\r'), "CR survived into the Output tab: $line")
        assertFalse(line.contains('\n'), "LF survived into the Output tab: $line")
        // REMOVED, not replaced — a forged second Output line is impossible.
        assertTrue(line.contains("tool=aInjected: line"), line)
        assertTrue(line.contains("[SEC-06]"), line)
        // The Output tab is where a human diagnoses, so it carries sanitized plaintext; the hash
        // belongs in the durable record, where the plaintext must not go.
        assertFalse(sha256Shaped.containsMatchIn(line), "a digest leaked into the Output tab: $line")
    }

    @Test
    fun aRecognisedExtToolNameIsSanitizedBeforeReachingEitherSink() {
        // The mirror of the test above, on the branch that carried the defect. `knownTool = true` was
        // the branch that wrote the name VERBATIM, on the reasoning that a recognised name is a catalog
        // ID — which is false for `ext:` names, where it is raw model output. Every decision branch
        // reports, so this was reachable on approve, on deny and on implicit deny alike.
        report(rawToolName = FORGED_EXT_TOOL, knownTool = true, tier = SecTier.CONFIRM_EACH, decision = ToolDecision.DENY)

        val line = lines.single()
        assertFalse(line.contains('\r'), "CR survived into the Output tab on the knownTool branch: $line")
        assertFalse(line.contains('\n'), "a model-authored newline forged a second [SEC-06] Output line: $line")
        // Exact, not `contains`: the whole property is that the forged text stays INSIDE the single line
        // this decision is allowed to write, so it cannot be read as a second record.
        assertEquals(
            "[SEC-06] decision=deny tier=confirm_each tool=$FORGED_EXT_TOOL_SANITIZED step=$CHAIN_STEP trace=$TRACE_ID",
            line,
        )
        // The durable half of the record is model-authored on this branch too, so it is bounded and
        // control-character-free as well — an `ext:` name is not a catalog entry.
        assertEquals(FORGED_EXT_TOOL_SANITIZED, payloadAt(0)["toolName"])
    }

    @Test
    fun outputLineCarriesTheDecisionTierStepAndTrace() {
        report(tier = SecTier.CONFIRM, decision = ToolDecision.APPROVE_SESSION, argsJson = ARGS_JSON)

        assertEquals(
            "[SEC-06] decision=approve_session tier=confirm tool=$KNOWN_TOOL step=$CHAIN_STEP trace=$TRACE_ID",
            lines.single(),
        )
    }

    // ---------------------------------------------------------------------------------------
    // Helpers
    // ---------------------------------------------------------------------------------------

    /**
     * Deliberately does NOT pass `verboseAudit`. The production default is the thing CLAUDE.md
     * constrains ("hashes only unless verbose is on"), so flipping that default must turn
     * [argsAreHashedByDefault] red — which it cannot do if this helper re-states `false` here.
     */
    private fun reporter(): ToolDecisionReporter = ToolDecisionReporter(logToOutput = { line -> lines += line })

    private fun verboseReporter(): ToolDecisionReporter = ToolDecisionReporter(logToOutput = { line -> lines += line }, verboseAudit = { true })

    /**
     * Ten parameters would reach detekt's `LongParameterList` functionThreshold of 10, so the canonical
     * ID is not one of them: every test that uses this helper has a name that canonicalises to itself.
     * The alias case, where the two genuinely differ, calls `report` directly.
     */
    private fun report(
        reporter: ToolDecisionReporter = reporter(),
        rawToolName: String = KNOWN_TOOL,
        knownTool: Boolean = true,
        tier: SecTier = SecTier.CONFIRM,
        decision: ToolDecision = ToolDecision.APPROVE_ONCE,
        argsJson: String? = null,
        implicitDenyReason: ImplicitDenyReason? = null,
        resultChars: Int? = null,
        runStatus: String? = null,
    ): Map<String, String> =
        reporter.report(
            rawToolName = rawToolName,
            canonicalId = rawToolName,
            knownTool = knownTool,
            tier = tier,
            decision = decision,
            argsJson = argsJson,
            traceId = TRACE_ID,
            chainStep = CHAIN_STEP,
            implicitDenyReason = implicitDenyReason,
            resultChars = resultChars,
            runStatus = runStatus,
        )

    @Suppress("UNCHECKED_CAST")
    private fun payloadAt(index: Int): Map<String, Any?> = captured[index].second as Map<String, Any?>

    private companion object {
        /** Any non-null length; its presence or absence is what the assertions are about. */
        const val RESULT_CHARS = 1500
    }
}
