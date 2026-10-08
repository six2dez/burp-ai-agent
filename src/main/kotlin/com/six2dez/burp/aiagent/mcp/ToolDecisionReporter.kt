package com.six2dez.burp.aiagent.mcp

import com.six2dez.burp.aiagent.audit.AuditLogger
import com.six2dez.burp.aiagent.audit.Hashing
import com.six2dez.burp.aiagent.config.Defaults

// SEC-06 / SC3 / ADR-15: the RECORD half of the tool-call trust boundary. ToolApprovalGate decides;
// this file writes the decision down and nothing else.
//
// The split is the repo's own established shape for a security gate — mcp/McpAccessControlDecision.kt
// decides and mcp/McpBlockedRequestReporter.kt reports — and it is what keeps the tier table and the
// decision state machine assertable with no audit sink, no clock and no Swing harness. Everything here
// is `internal` so ToolDecisionReporterTest reaches it without reflection, the same test-seam
// convention as redact/Redaction.kt:215-228 and mcp/McpAccessControlDecision.kt:10-11.

/**
 * The audit type constant for a resolved SEC-06 decision.
 *
 * **New**, and deliberately NOT a reuse of either tool-scoped constant already declared in
 * `mcp/tools/McpTool.kt` — the one meaning "the enable / unsafe gates refused this call" or the one
 * meaning "this call finished". Both are file-private there and unreachable from here anyway, but the
 * substantive reason is that they describe DIFFERENT events with a different key set (`tool`,
 * `toolType`, `hasArgs`, `reason`). Filing a decision under either name would put records whose keys
 * mean different things under one type and corrupt downstream analysis of tool telemetry. That reason
 * is recorded verbatim at mcp/McpBlockedRequestReporter.kt:8-14; this is its second application.
 */
private const val MCP_TOOL_DECISION_EVENT = "mcp_tool_decision"

/** Unchanged from today's `MCP_TOOL_CALL` metadata (ChatPanel.kt): this event is one step of a tool chain. */
private const val OPERATION_TOOL_CHAIN = "tool_chain"

/**
 * D-12 reaching telemetry: a refusal is a POLICY outcome, so it gets a THIRD status value rather than
 * reusing `"error"`. A log in which a deliberate denial is indistinguishable from a malfunction cannot
 * answer "did the extension refuse this, or did it break?" — exactly the corruption D-12 was written to
 * prevent. Adding a value (rather than changing one) is also why no existing consumer breaks: the AI
 * Activity view and `ai_audit_query` render `detail` and `type`, neither switches on `status`.
 */
private const val STATUS_DENIED = "denied"

/** The caller's existing "the tool ran and did not error" derivation. Used when no `runStatus` is supplied. */
private const val STATUS_OK = "ok"

/** Written in place of a tool name the catalog could not resolve. The raw name is hashed alongside it. */
private const val UNKNOWN_TOOL_NAME = "unknown"

/** Output-tab placeholder for a name that sanitized away to nothing, following the analog's convention. */
private const val OUTPUT_NONE = "none"

/**
 * Turns one resolved SEC-06 decision into a durable record. It performs **no policy**: it never
 * decides, never consults session memory and never calls [ToolApprovalGate]. The caller invokes it from
 * an already-resolved branch, in the same order the analog uses — record first, act second.
 *
 * **Three destinations, per Phase 20 D-06.** Audit logging is disabled by default in this project, so a
 * decision written only to the audit file would be invisible to almost every user. One invocation
 * therefore produces:
 *
 * 1. one ordered [AuditLogger.emitGlobal] event — the durable record;
 * 2. one Burp Output-tab line — the human-visible one, which is the only one most users ever see;
 * 3. the returned metadata map, which the caller merges into its existing `MCP_TOOL_CALL` emission.
 *
 * **Returning the map is the mechanism, not a convenience.** Both the audit payload and the AI Activity
 * metadata are derived from ONE construction in [buildPayload], so the two sinks cannot drift into
 * disagreeing about what was decided. Assembling a second, hand-written map at the call site is exactly
 * the defect this shape prevents — the same instinct as the single canonicalisation function in
 * `McpToolExecutor.canonicalToolId`.
 *
 * **Output sink is a lambda, not the Burp API handle.** The caller passes
 * `{ line -> api.logging().logToOutput(line) }`; tests capture into a list. That keeps this class
 * testable with no Mockito deep stub and no display, and it is why the import list above carries no
 * Burp type, no Swing type and no AWT type — only the audit seam, the digest and a constants holder.
 *
 * **D-10 / [verboseAudit].** `AgentSettings` has `auditEnabled` but there is still no verbose-audit flag
 * anywhere in the repo (verified again this phase), so [verboseAudit] is a constructor seam that callers
 * wire to `false`. Hashing model-supplied values is therefore the effective default, which is what
 * CLAUDE.md's "hashes only unless verbose is on" requires. **Adding a user-facing verbose toggle is
 * explicitly out of scope for SEC-06** and Phase 20 already declined it; do not add one here. The split
 * is by provenance, not by convenience: the canonical tool ID, the tier, the decision, the trace ID and
 * the chain step are all extension-derived and stay plaintext, because a hashed decision would make the
 * record useless. Only the values the model authored — the args JSON, and a tool name the catalog could
 * not resolve — are hashed.
 *
 * **Phase 20 D-09 aggregation is deliberately NOT applied**, and saying so is better than leaving the
 * omission unexamined. The flood vector D-09 answers was a remote, unauthenticated peer able to generate
 * blocks at will. Here the emitter is the local model loop, whose ceiling is
 * `MAX_AUTO_TOOL_ITERATIONS = 8` per chain and whose counter D-13 keeps monotone. Eight events per chain
 * does not need coalescing, and coalescing them would hide exactly the repetition a user needs to see.
 */
internal class ToolDecisionReporter(
    private val logToOutput: (String) -> Unit,
    private val verboseAudit: () -> Boolean = { false },
) {
    /**
     * The only entry point. Emits both sinks and returns the metadata map for the third.
     *
     * @param rawToolName the name exactly as the model emitted it — attacker-influenceable, never
     *   written to either sink unsanitized, and never written to the audit payload in plaintext.
     * @param canonicalId the result of `McpToolExecutor.canonicalToolId(rawToolName)`. **Not
     *   necessarily extension-derived, even when [knownTool] is true**: `canonicalToolId` returns the
     *   model's string verbatim for anything its alias table does not rewrite, so an `ext:<server>:<tool>`
     *   name is model-authored text that merely carries a recognised prefix. It is therefore sanitized
     *   on every path out of this class, on both branches of [knownTool] — see [outputToolName].
     * @param knownTool whether [canonicalId] resolved to something the extension recognises. False
     *   flips the tool name to a hash: an unresolvable name is model-controlled text.
     * @param tier the resolved [SecTier]. Emitted on EVERY event, including `AUTO`.
     * @param decision what was decided. Emitted on every event.
     * @param argsJson the model-supplied arguments. Hashed unless [verboseAudit] is on.
     * @param traceId extension-derived correlation ID, plaintext, so a decision can be joined to the
     *   `MCP_TOOL_CALL` record and the backend turn it came from.
     * @param chainStep the 1-based step within the tool chain (SC3's "chain step").
     * @param implicitDenyReason which teardown path resolved the call; recorded only for
     *   [ToolDecision.IMPLICIT_DENY], where "nobody answered" is otherwise unattributable.
     * @param resultChars length of the tool result, when there was one. Dropped for a denial.
     * @param runStatus the caller's existing `"ok"` / `"error"` derivation for a call that actually ran.
     *   Ignored for a denial, which is always [STATUS_DENIED].
     *
     * The 11 parameters reach detekt's `LongParameterList` functionThreshold of 10. Suppressed on the
     * declaration (precedent: PassiveAiScannerPrompts.kt:73-76) rather than added to
     * detekt-baseline.xml, which QUAL-07 forbids from growing; a data-class holder would trip
     * constructorThreshold 10 as well.
     */
    @Suppress("LongParameterList")
    internal fun report(
        rawToolName: String,
        canonicalId: String,
        knownTool: Boolean,
        tier: SecTier,
        decision: ToolDecision,
        argsJson: String?,
        traceId: String,
        chainStep: Int,
        implicitDenyReason: ImplicitDenyReason? = null,
        resultChars: Int? = null,
        runStatus: String? = null,
    ): Map<String, String> {
        val payload =
            buildPayload(
                rawToolName = rawToolName,
                canonicalId = canonicalId,
                knownTool = knownTool,
                tier = tier,
                decision = decision,
                argsJson = argsJson,
                traceId = traceId,
                chainStep = chainStep,
                implicitDenyReason = implicitDenyReason,
                resultChars = resultChars,
                runStatus = runStatus,
            )
        AuditLogger.emitGlobal(MCP_TOOL_DECISION_EVENT, payload)
        logToOutput(outputLine(rawToolName, canonicalId, knownTool, tier, decision, chainStep, traceId))
        // Null values are dropped rather than emitted as empty strings: AiRequestLogger.log takes
        // Map<String, String>, and "key absent" and "key present but empty" must stay distinguishable
        // in the AI Activity record for the same reason they do in the audit payload.
        return payload.mapNotNull { (key, value) -> value?.let { key to it } }.toMap()
    }

    /**
     * The SC3 payload, in an insertion-ordered map because the key ORDER is a pinned property rather
     * than an accident of construction — `ToolDecisionReporterTest` asserts the exact list.
     *
     * The first six keys are the ones `MCP_TOOL_CALL` already emits today, unchanged and in their
     * existing order; this event EXTENDS that shape rather than inventing one. Every value is typed
     * `String?` rather than `Any?`, which is what makes the returned metadata map a mechanical
     * null-filter with no cast — including `resultChars`, which the existing metadata map already
     * stringifies, so the two records agree field for field.
     *
     * Conditional keys are inserted at their ordered position rather than appended, so a payload never
     * carries a key whose meaning does not apply: `toolNameSha256` only for an unresolved name,
     * `implicitDenyReason` only for an implicit denial, `argsSha256` only when there were args, and
     * `resultChars` only when a tool actually produced a result.
     */
    @Suppress("LongParameterList")
    private fun buildPayload(
        rawToolName: String,
        canonicalId: String,
        knownTool: Boolean,
        tier: SecTier,
        decision: ToolDecision,
        argsJson: String?,
        traceId: String,
        chainStep: Int,
        implicitDenyReason: ImplicitDenyReason?,
        resultChars: Int?,
        runStatus: String?,
    ): Map<String, String?> {
        val denied = isDenial(decision)
        return linkedMapOf<String, String?>(
            "operation" to OPERATION_TOOL_CHAIN,
            "status" to if (denied) STATUS_DENIED else runStatus ?: STATUS_OK,
            "traceId" to traceId,
            "step" to chainStep.toString(),
            // A recognised name is written in plaintext, because a hashed tool name would make the
            // record useless — but it is SANITIZED first, and unconditionally. `canonicalToolId` is not
            // a validator: it returns the model's string unchanged for every name its alias table does
            // not rewrite, so a "known" `ext:<server>:<tool>` name is model-authored text of unbounded
            // length. [sanitizeInline] caps it and strips control characters; for a catalog ID it is the
            // identity. An unresolvable name is replaced by a placeholder and hashed below.
            "toolName" to
                if (knownTool) {
                    sanitizeInline(canonicalId).orEmpty().ifBlank { UNKNOWN_TOOL_NAME }
                } else {
                    UNKNOWN_TOOL_NAME
                },
        ).apply {
            if (!knownTool) {
                // D-10, and the SAME rule [auditValue] applies to the args: digest the WHOLE value.
                //
                // This used to run through [sanitizeInline], whose cap is 120 characters, so the digest
                // identified a whitespace-collapsed PREFIX of the name rather than the name — two
                // unresolvable names sharing a 120-character prefix recorded identically. It is a
                // narrower instance of the defect fixed for `argsSha256`, but it lands on the branch
                // where the hash carries the most: `toolName` above is the constant placeholder here, so
                // this digest is the ONLY record in the durable payload of what the model asked for.
                //
                // Dropping the sanitizer costs nothing that was not already guaranteed elsewhere. A hex
                // digest is 64 characters of `[0-9a-f]` by construction, so no model-authored character
                // survives it and no forged record line is possible; and the only form of this name that
                // is ever RENDERED is the Output line, which [outputToolName] sanitizes unconditionally
                // on both branches of `knownTool`.
                put("toolNameSha256", Hashing.sha256Hex(rawToolName))
            }
            // On EVERY event, including AUTO. Without it, a call that ran under the AUTO tier and a
            // pre-SEC-06 call that ran with no decision at all are indistinguishable in a historical
            // log — which makes "which tool calls ran without a decision?" unanswerable.
            put("secTier", tier.wireValue)
            put("decision", decision.wireValue)
            if (decision == ToolDecision.IMPLICIT_DENY) {
                put("implicitDenyReason", implicitDenyReason?.wireValue)
            }
            argsJson?.takeIf { it.isNotBlank() }?.let { put("argsSha256", auditValue(it)) }
            // A denial has no result, so the key is dropped even if a caller supplies one. Enforced
            // here rather than trusted to the call site: a record reading "denied" alongside a result
            // length is self-contradictory, and an auditor cannot tell which half to believe.
            if (!denied && resultChars != null) {
                put("resultChars", resultChars.toString())
            }
        }
    }

    /**
     * D-10: hash the WHOLE value, or write the whole value under the verbose seam. Null in, null out —
     * the caller drops blank args before calling, so "args absent" and "args empty" stay distinguishable
     * without hashing the empty string.
     *
     * **The digest is taken over the value as given, and nothing is discarded first.** It used to run
     * through [sanitizeInline], whose default cap is 120 characters, so `argsSha256` identified a
     * whitespace-collapsed 120-character PREFIX of the arguments rather than the arguments. Two
     * `http1_request` calls differing only in the request body — the method, path, headers and body all
     * live past character 120 in the argument order the executor uses — produced a byte-identical
     * digest, so an exfiltration request was indistinguishable in the audit trail from a benign one by
     * keeping the prefix constant. Per D-07 the args are exactly where exfiltration hides, which makes a
     * prefix digest worse than no digest: it looks like an answer to "which arguments ran?".
     *
     * Sanitization is applied only to the form that is actually RENDERED. A hex digest is safe by
     * construction — 64 characters of `[0-9a-f]`, nothing model-authored survives it — so the default
     * path needs no sanitizer at all. The verbose path does, and it uses [sanitizeBlock] rather than
     * [sanitizeInline] for the reason [sanitizeInline]'s own KDoc gives: `\p{Cntrl}` includes `\n` and
     * `\t`, so the inline form flattens JSON into one unreadable line. The cap is the extension's
     * established ceiling for model-supplied context, the same one the approval card uses for its full
     * args stage, so the record can hold everything the card could have shown. Neither form ever reaches
     * [outputLine] — the Output tab carries no arguments at all — and both audit sinks are Jackson-
     * serialized, so a preserved newline cannot forge a record line.
     *
     * This hash is still not required to equal the one `McpTool.runTool` records under the same key
     * name: that one digests the *trimmed* string, and the executor may normalise args before it. The
     * key name is shared so an analyst reads both fields as "a digest of the arguments"; byte equality
     * across the two records is not claimed.
     */
    private fun auditValue(value: String?): String? =
        value?.let {
            if (verboseAudit()) {
                sanitizeBlock(it, maxChars = Defaults.MAX_CONTEXT_TOTAL_CHARS, maxLines = Int.MAX_VALUE)
            } else {
                Hashing.sha256Hex(it)
            }
        }

    /**
     * Exactly one line per invocation, carrying **sanitized plaintext and never a hash** — the Output tab
     * is where a human diagnoses, and a digest diagnoses nothing.
     *
     * Every field but the tool name is extension-derived. The tool name is not, on EITHER branch of
     * `knownTool`, so it goes through [sanitizeInline] unconditionally: control characters are REMOVED,
     * whitespace is collapsed and the value is capped, which is what makes a model-authored newline
     * unable to forge a second Output line (CWE-117). The args JSON is never interpolated here at all.
     */
    @Suppress("LongParameterList")
    private fun outputLine(
        rawToolName: String,
        canonicalId: String,
        knownTool: Boolean,
        tier: SecTier,
        decision: ToolDecision,
        chainStep: Int,
        traceId: String,
    ): String =
        "[SEC-06] decision=${decision.wireValue} tier=${tier.wireValue} " +
            "tool=${outputToolName(rawToolName, canonicalId, knownTool)} step=$chainStep trace=$traceId"

    /**
     * The tool name as it appears on the Output line: sanitized on BOTH branches, never one of them.
     *
     * The earlier shape returned `canonicalId` verbatim when [knownTool] was true, on the reasoning that
     * a recognised name is a catalog ID. That reasoning does not hold: `ChatPanel.isKnownTool` accepts
     * any `ext:`-prefixed string and `McpToolExecutor.canonicalToolId` passes unmatched names through
     * untouched, so `"ext:x\n[SEC-06] decision=approve_once …"` was a recognised name whose newline
     * forged a second `[SEC-06]` line in Burp's Output tab (CWE-117) — on approve, on deny and on
     * implicit deny alike, because every decision branch reports.
     *
     * Sanitizing unconditionally is the narrow fix: it costs nothing for a catalog ID, which
     * [sanitizeInline] returns unchanged, and it removes the class of bug rather than one entry point
     * into it. It does not depend on `isKnownTool` being right, which is what makes it the control.
     */
    private fun outputToolName(
        rawToolName: String,
        canonicalId: String,
        knownTool: Boolean,
    ): String = sanitizeInline(if (knownTool) canonicalId else rawToolName).orEmpty().ifBlank { OUTPUT_NONE }

    /**
     * Which decisions refused the call. An exhaustive `when` over the enum rather than a boolean
     * predicate, and the difference is load-bearing: a ninth [ToolDecision] constant is a COMPILE ERROR
     * here, so a future denial-shaped decision cannot silently be recorded as a success. That is the same
     * control D-03 applies at the catalog site — the compile error is the mechanism.
     */
    private fun isDenial(decision: ToolDecision): Boolean =
        when (decision) {
            ToolDecision.DENY,
            ToolDecision.DENY_SESSION,
            ToolDecision.SESSION_DENIED,
            ToolDecision.IMPLICIT_DENY,
            -> true

            ToolDecision.APPROVE_ONCE,
            ToolDecision.APPROVE_SESSION,
            ToolDecision.AUTO,
            ToolDecision.SESSION_APPROVED,
            -> false
        }
}
