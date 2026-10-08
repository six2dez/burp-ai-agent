package com.six2dez.burp.aiagent.mcp

import com.six2dez.burp.aiagent.mcp.tools.McpToolExecutor

// SEC-06 / ADR-15: the pure decision half of the tool-call trust boundary.
//
// Everything in this file is `internal` rather than `private` so ToolApprovalGateTest and
// SecTierResolutionTest can reach it without reflection — the same test-seam convention used by
// redact/Redaction.kt:215-228 and mcp/McpAccessControlDecision.kt:10-11.
//
// No Swing type and no AWT type is imported here — the import list above is the whole proof, and it
// is what keeps every SEC-06 decision provable in a unit test with no Swing harness and no display.
//
// ToolCallOrigin and ToolApprovalGate live in ONE file on purpose, against the two-file sketch in
// 22-PATTERNS.md, and the reason is load-bearing: Kotlin's `internal` is MODULE-WIDE (the whole main
// source set), so an `internal` factory would let any file in the module mint a model origin. The only
// compile-time mechanism that binds minting to the gate is FILE-PRIVATE visibility, and that requires
// the origin implementation and the gate to be declared in the same file. Splitting this file back
// into two would silently downgrade the SC5 control to a comment.
//
// State the control at the strength the COMPILER actually enforces, because a claim the compiler does
// not check is worse than a weaker accurate one. Two boundaries, not one:
//
//   1. MINTING is file-scoped, and this is enforced. `ModelApproved` is top-level `private`, so no
//      other file can name or construct it, and `ToolApprovalGate.approvedOrigin` is `private` to the
//      object, so no other file can call it either. It was `internal` until this was measured: any file
//      in the main source set could write `ToolApprovalGate.approvedOrigin(SecTier.AUTO,
//      ToolDecision.AUTO)` and hand the result to `executeTool` with no card and no audit record, which
//      made the file-private class decorative. Verified by compiling a probe file in this package: the
//      call is now rejected with "Cannot access 'fun approvedOrigin': it is private".
//   2. IMPLEMENTING `ToolCallOrigin` is PACKAGE-scoped, and this is a real residual. Kotlin seals a
//      `sealed interface` to the same package AND module, never to a file, so a NEW FILE under
//      `com.six2dez.burp.aiagent.mcp` can declare `object X : ToolCallOrigin { override val wireValue =
//      "model_approved" }` and pass it to `executeTool`. Also verified by compiling a probe, which
//      succeeded. There is no idiomatic file-scoped seal in Kotlin: an unnameable marker member
//      (`val seal: PrivateInFileType`) does close it, but only behind three `@Suppress`ed
//      EXPOSED_PROPERTY_TYPE compiler ERRORS, which trades a checked property for a suppressed
//      diagnostic that a future Kotlin release can change under us. It was tried and rejected.
//
// So the honest SC5 statement is: an ACCIDENTAL bypass is impossible — a new parse-and-execute call
// site cannot compile without an origin, and cannot obtain the model one without going through
// `evaluate` or `resolve`. A DELIBERATE bypass by someone editing package `mcp` is not prevented by
// the type system; nothing in a single-module Kotlin codebase could prevent it, and the controls
// against it are code review and the audit record.

/** Cap for [sanitizeInline]. A named constant because MagicNumber is active and QUAL-07 forbids growing detekt-baseline.xml. */
private const val INLINE_MAX_LENGTH = 120

/** Default truncation marker. [McpBlockedRequestReporter] overrides it to keep the Output line it has always written. */
private const val INLINE_ELLIPSIS = "\u2026"

/**
 * C0 controls and DEL via `\p{Cntrl}`, plus the C1 range spelled out — Java's `\p{Cntrl}` covers only
 * `\x00-\x1F` and `\x7F` unless UNICODE_CHARACTER_CLASS is set.
 *
 * This is the ONE copy in the package. It used to be a deliberate duplicate of the identical regex in
 * mcp/McpBlockedRequestReporter.kt, on the reasoning that copying kept the two from drifting — which is
 * exactly backwards, and they had already drifted on the truncation marker by the time it was noticed
 * (WR-05). The reporter now calls [sanitizeInline] and supplies its own marker as an argument.
 */
private val inlineControlCharRegex = Regex("[\\p{Cntrl}\\u0080-\\u009F]")

/**
 * The same character set MINUS `\n` and `\t`, which the block form must preserve. `&&` is Java's
 * character-class intersection; the C1 range is a separate alternative because it is not part of
 * `\p{Cntrl}` at all.
 */
private val blockControlCharRegex = Regex("[\\p{Cntrl}&&[^\\n\\t]]|[\\u0080-\\u009F]")

/** Collapses runs of whitespace for the inline form only. The block form must keep its line structure. */
private val inlineWhitespaceRegex = Regex("\\s+")

/**
 * What was decided about one model-emitted tool call. The wire string is defined once, here, and
 * nowhere else — both the SC3 audit payload and the approval card read [wireValue], so the two sinks
 * cannot disagree (the BlockReason convention from mcp/McpAccessControlDecision.kt:62-75).
 *
 * The pair that matters to an auditor is [APPROVE_ONCE] versus [SESSION_APPROVED]. [APPROVE_ONCE]
 * means a human clicked *for this specific call*; [SESSION_APPROVED] means an earlier click was
 * applied to this call without asking anyone. Collapsing the two into a single "approved" token would
 * make "did a human authorise this particular invocation?" unanswerable from the log — which is the
 * one question an audit trail exists to answer. The same split applies to [DENY] and [SESSION_DENIED].
 */
internal enum class ToolDecision(
    val wireValue: String,
) {
    /** A human clicked approve for this call, and only this call. */
    APPROVE_ONCE("approve_once"),

    /** A human clicked approve and extended it to this tool for the rest of the session (CONFIRM only). */
    APPROVE_SESSION("approve_session"),

    /** A human clicked deny for this call. */
    DENY("deny"),

    /** A human clicked deny and extended it to this tool for the rest of the session (CONFIRM only). */
    DENY_SESSION("deny_session"),

    /** The tool's tier is [SecTier.AUTO]; it ran with no user decision at all (D-02). */
    AUTO("auto"),

    /** An EARLIER click was applied to this call. No human saw this invocation. */
    SESSION_APPROVED("session_approved"),

    /** An earlier denial was applied to this call. No human saw this invocation. */
    SESSION_DENIED("session_denied"),

    /** No human ever answered: the card was destroyed by a teardown path. See [ImplicitDenyReason]. */
    IMPLICIT_DENY("implicit_deny"),
}

/**
 * Why a pending decision was resolved as [ToolDecision.IMPLICIT_DENY] without anyone clicking.
 *
 * Research measured **five** teardown paths that destroy a pending card, not the three D-08 lists;
 * plan 22-08 wires all five. The enum is declared here, before the wiring exists, so the audit shape
 * is fixed once rather than grown one string at a time as each path is discovered.
 */
internal enum class ImplicitDenyReason(
    val wireValue: String,
) {
    /** The user typed a new message instead of answering (D-08). */
    NEW_MESSAGE("new_message"),

    /** The chat session holding the card was deleted (D-08). */
    SESSION_DELETED("session_deleted"),

    /** The current chat was cleared, which destroys the card. Not in D-08's list. */
    CHAT_CLEARED("chat_cleared"),

    /** The Burp project changed, clearing in-memory session state. Not in D-08's list. */
    PROJECT_CHANGED("project_changed"),

    /** The extension was unloaded (D-08). */
    UNLOAD("unload"),
}

/**
 * Where a tool invocation came from, as a type the compiler checks rather than a comment.
 *
 * SC5, and the property is worth stating in plain English: **a hypothetical fourth parse-and-execute
 * call site cannot compile without obtaining a model origin from [ToolApprovalGate], which means going
 * through the decision.** A plain enum would let that call site write `origin = MODEL` and silently
 * reopen SEC-06 — the maintainer's standard is that a control a future edit can silently undo is not a
 * control.
 *
 * The two user-originated variants are public because a user who picked the tool and typed the args
 * themselves has already authorised it; there is nothing for the gate to decide. The model-originated
 * variant is deliberately NOT declared here — it is a file-private class, unnameable and
 * unconstructible outside this file, and minted only by the object-private `approvedOrigin`, which
 * `evaluate` and `resolve` are the only code that can call.
 *
 * **The seal is a PACKAGE boundary, not a file boundary, and the difference is written down here
 * rather than glossed.** Kotlin permits an implementation of a `sealed interface` in any file of the
 * same package and module, so a new file under `com.six2dez.burp.aiagent.mcp` can declare its own
 * `ToolCallOrigin` — including one whose `wireValue` reads `"model_approved"`. That is a deliberate
 * act, not an accident, and it is the residual the file header explains; do not read "sealed" as
 * "only this file".
 */
internal sealed interface ToolCallOrigin {
    val wireValue: String

    /** The user picked the tool and typed the args in ToolInvocationDialog (`ChatPanel.openToolDialog`). */
    data object UserDialog : ToolCallOrigin {
        override val wireValue: String = "user_dialog"
    }

    /** The user typed the `/tool <name> <json>` slash command (`ChatPanel.handleToolCommand`). */
    data object UserSlashCommand : ToolCallOrigin {
        override val wireValue: String = "user_slash_command"
    }
}

/**
 * Parsed from model output AND authorised by the SEC-06 gate.
 *
 * Top-level `private`, which in Kotlin means FILE-private: no other file in the module can construct
 * this class or even name its type. That is HALF the SC5 mechanism (T-22-11); the other half is that
 * [ToolApprovalGate.approvedOrigin], the only thing that constructs it, is object-private. Either half
 * alone is decorative — the class was file-private from the first commit while the factory was
 * `internal`, and a module-wide factory for a file-private type is simply a module-wide factory.
 *
 * It carries the proof of the decision that produced it — the resolved [tier] and the [decision] a
 * human (or the AUTO rule) reached — so an audit record can be written from the origin alone.
 *
 * `internal` would NOT work here: Kotlin's `internal` is module-wide, so every file in the main source
 * set could mint one. Do not widen this to `internal` and do not move it to its own file.
 */
private class ModelApproved(
    val tier: SecTier,
    val decision: ToolDecision,
) : ToolCallOrigin {
    override val wireValue: String = "model_approved"
}

/**
 * Per-chat-session approve/deny memory (D-10), plus the FLAG-22-01 repeat counter.
 *
 * "Session" means the **chat session**, not the Burp session and not the current auto-chain. The
 * decisive case, and the reason this is a per-chat holder rather than anything wider: an approval
 * granted while reviewing target A must not silently apply when the user opens a new chat about
 * target B. The memory dies with the chat session because the holder does — plan 22-07 stores one of
 * these as `ChatPanel.ToolSessionState.approvalMemory`, beside `toolsMode` and `wire`,
 * which is why this class must stay constructible with no arguments and hold only plain collections.
 *
 * Measured fact worth recording so a future contributor does not "fix" it: approvals do **not** survive
 * a Burp restart. `ChatPanel.restoreSessions` builds a fresh `ToolSessionState`, and that
 * holder is in-memory only, so a chat session restored from disk comes back with no approvals. That is
 * stricter than D-10 requires and is deliberate — do not persist the sets.
 *
 * All three fields are private, reached only through the narrow accessors below, so no caller can
 * splice an entry in ad hoc. Every key is a **canonical** tool ID, never the raw model string
 * (T-22-12): a gate that remembered `history` and an executor that ran `proxy_http_history` would
 * disagree about what the user approved.
 */
internal class ToolApprovalMemory {
    private val approvedForSession = mutableSetOf<String>()
    private val deniedForSession = mutableSetOf<String>()
    private val requestCounts = mutableMapOf<String, Int>()

    /** True if an earlier `Approve for session` click covers this tool. CONFIRM tools only. */
    internal fun isApprovedForSession(canonicalId: String): Boolean = key(canonicalId) in approvedForSession

    /** True if an earlier `Deny for session` click covers this tool. CONFIRM tools only. */
    internal fun isDeniedForSession(canonicalId: String): Boolean = key(canonicalId) in deniedForSession

    /** Immutable view, for assertions and for any future "what has this chat granted?" surface. */
    internal fun approvedSnapshot(): Set<String> = approvedForSession.toSet()

    /** Immutable view, for assertions and for any future "what has this chat refused?" surface. */
    internal fun deniedSnapshot(): Set<String> = deniedForSession.toSet()

    /** Extends approval to the rest of the chat session. Called only from [ToolApprovalGate.resolve]. */
    internal fun approveForSession(canonicalId: String) {
        approvedForSession += key(canonicalId)
    }

    /** Extends denial to the rest of the chat session. Called only from [ToolApprovalGate.resolve]. */
    internal fun denyForSession(canonicalId: String) {
        deniedForSession += key(canonicalId)
    }

    /**
     * Records one request for this tool and returns the 1-based count for this chat session.
     *
     * The anti-habituation signal the approval card needs (22-UI-SPEC.md mechanism B): without it the
     * caption could only ever read "1st", and a user cannot see that the model is asking for the same
     * capability for the fourth time. The only mutating method the UI calls directly.
     */
    internal fun recordRequest(canonicalId: String): Int {
        val id = key(canonicalId)
        val next = (requestCounts[id] ?: 0) + 1
        requestCounts[id] = next
        return next
    }

    /**
     * Re-canonicalises every key through the executor's own function.
     *
     * The parameter is named for what the gate passes — [ToolApprovalGate.evaluate] and
     * [ToolApprovalGate.resolve] both canonicalise first — but a UI caller holding the raw model string
     * must not be able to open a second entry for the same tool. [McpToolExecutor.canonicalToolId] is
     * idempotent for an already-canonical ID, so the normal path is unchanged and this costs nothing.
     */
    private fun key(canonicalId: String): String = McpToolExecutor.canonicalToolId(canonicalId)
}

/**
 * What the gate decided about one model-emitted tool call, in the shape of
 * mcp/McpAccessControlDecision.kt:93-101's [GateDecision]: a closed set of outcomes the caller must
 * branch on, so no call site can forget a case.
 *
 * Rich enough to drive 22-UI-SPEC.md states 2-5 without the UI recomputing any policy. The card reads
 * these fields; it must never re-derive them from the tier.
 */
internal sealed interface ToolApprovalOutcome {
    /**
     * Proceed. [origin] is the minted, unforgeable model-approved token — the only thing that will
     * satisfy plan 22-07's `executeTool` origin parameter — and [decision] records whether a human
     * clicked for *this* call or an earlier click was applied to it.
     */
    data class Run(
        val origin: ToolCallOrigin,
        val tier: SecTier,
        val decision: ToolDecision,
    ) : ToolApprovalOutcome

    /**
     * A human decision is required; render the card.
     *
     * [offersSessionActions] is D-11's four-buttons-versus-two rule, computed **here** rather than in
     * the card: `true` for [SecTier.CONFIRM], `false` for [SecTier.CONFIRM_EACH]. Two surfaces deriving
     * the same rule from the tier is exactly how one of them ends up offering a session grant for a
     * tool that must never have one (T-22-18).
     */
    data class Ask(
        val tier: SecTier,
        val canonicalId: String,
        val offersSessionActions: Boolean,
    ) : ToolApprovalOutcome

    /** Refuse. [result] is always [ToolApprovalGate.DENIAL_RESULT] — the one D-12 constant. */
    data class Denied(
        val tier: SecTier,
        val decision: ToolDecision,
        val result: String,
    ) : ToolApprovalOutcome
}

/**
 * The pure SEC-06 decision core.
 *
 * Pure by contract, in the shape of mcp/McpAccessControlDecision.kt:103-114: no logging, no audit
 * events, no I/O. Audit emission is a separate call the ChatPanel caller
 * makes from the resolved branch (plan 22-05's ToolDecisionReporter) — never from inside this object.
 * That separation is what makes every row of the tier matrix assertable with no Swing harness.
 *
 * The single exception to "no side effects" is [resolve] writing D-10's session memory, and it is
 * confined to the two session-scoped actions on a [ToolApprovalMemory] the caller owns and passes in.
 * The gate holds no state of its own, so two chat sessions cannot leak into one another through it.
 *
 * **Phase 20 D-09 aggregation-based rate limiting is deliberately NOT applied here**, and saying so is
 * better than leaving the omission unexamined. The flood vector D-09 answers was a remote,
 * unauthenticated peer able to generate blocks at will. Here the caller is the local model loop, whose
 * ceiling is `ChatPanel.MAX_AUTO_TOOL_ITERATIONS` (8) per chain and whose counter D-13 makes
 * monotone. Eight cards per chain does not need coalescing, and coalescing them would hide exactly the
 * repetition a user needs to see.
 */
internal object ToolApprovalGate {
    /**
     * The one string a refused tool call returns to the model. Fixed, neutral, deterministic (D-12).
     *
     * **Deliberately not `Error:`-prefixed.** The tool-chain telemetry in `ChatPanel.executeApprovedToolCall` derives
     * `status = "error"` from that prefix, and a refusal is a *policy outcome*, not a malfunction.
     * Conflating the two tells the model something broke, which invites a retry with different args —
     * the exact loop SEC-06 exists to bound — and it corrupts the audit record, which would then show
     * a tool failure where a human actually made a decision (T-22-19).
     *
     * **Deterministic on purpose.** Stable templates are a shipped feature of this extension, so the
     * refusal text has to be reproducible rather than composed per call. That is also why the user is
     * not offered a free-text reason: user-authored text on a security path breaks determinism, leaks
     * whatever the user types into the model's context, and turns a two-second decision into a writing
     * task.
     *
     * One constant, four decisions. [ToolDecision.DENY], [ToolDecision.DENY_SESSION],
     * [ToolDecision.SESSION_DENIED] and [ToolDecision.IMPLICIT_DENY] all return exactly this — the
     * model must not be able to tell from the text whether the user clicked, an earlier click was
     * applied, or nobody answered at all.
     */
    internal const val DENIAL_RESULT: String =
        "This tool call was not authorised by the user. Do not retry it; continue with the information you already have."

    /**
     * Resolves the SEC-06 tier for a model-supplied tool name. Total: every input resolves, and no
     * input throws.
     *
     * Canonicalisation comes FIRST and comes from [McpToolExecutor.canonicalToolId] — the executor's
     * own function, called rather than copied. That ordering reproduces `executeToolResult` exactly:
     * canonicalise, then test the external namespace, then look the catalog up. If this gate grew its
     * own alias table, an aliased call would be labelled "unknown tool" on the card while the executor
     * ran it as a known one, and the audit record would name a tool that never executed (T-22-12).
     */
    internal fun tierFor(rawToolName: String): SecTier {
        val canonical = McpToolExecutor.canonicalToolId(rawToolName)
        // D-04: DERIVED from the namespace prefix, never declared per tool. An external server's tools
        // are not in the catalog and are untrusted by ADR-11, so every one of them prompts every time —
        // including `ext:<server>:scope_check`, which must not inherit the built-in's AUTO tier.
        if (canonical.startsWith("ext:")) return SecTier.CONFIRM_EACH
        val descriptor = McpToolCatalog.all().firstOrNull { it.id == canonical }
        // Fail closed. D-03 removes the AUTHORING default; this is the RUNTIME fallback it does not
        // cover. An unrecognised name must never resolve to AUTO.
        return descriptor?.secTier ?: SecTier.CONFIRM_EACH
    }

    /**
     * Mints the model origin. **Object-private**: [evaluate] and [resolve] are the only callers that
     * can exist, because no code outside this object body can name this function at all.
     *
     * `private`, not `internal`, and the distinction is the control rather than a style preference.
     * Kotlin's `internal` is module-wide, so an `internal` factory let any file in the main source set
     * write `ToolApprovalGate.approvedOrigin(SecTier.AUTO, ToolDecision.AUTO)` and hand the result
     * straight to `McpToolExecutor.executeTool` — no card, no session-memory consultation, no audit
     * record. Making the *class* file-private bought nothing while the *factory* was module-visible.
     * Do not widen this back to `internal` to make a test reach it: a test that needs a model origin
     * should obtain one the way production does, from [evaluate] or [resolve].
     *
     * Returns the [ToolCallOrigin] interface, never the implementing type, so callers pass the value on
     * without ever being able to name — or reconstruct — what they are holding.
     */
    private fun approvedOrigin(
        tier: SecTier,
        decision: ToolDecision,
    ): ToolCallOrigin = ModelApproved(tier, decision)

    /**
     * The pre-card branch: decides whether this call runs, is refused outright, or needs a human.
     *
     * **These two parameters are the whole signature, and the omissions are the control.** There is no
     * settings object, no on/off flag and no bypass argument, because D-09 ships neither an opt-out nor
     * a tier downgrade — and a parameter that does not exist cannot be passed `false` by a future edit,
     * a malicious settings import, or a call site that just wants the tests to go green (T-22-21). The
     * absence of the parameter is what keeps ADR-15 a rule rather than a default. The escape hatch
     * already exists and is the correct one: `ToolSessionState.toolsMode` stops the model calling tools
     * at all, rather than un-gating the ones it calls.
     *
     * Order is fixed: canonicalise, resolve the tier, then consult memory — never the reverse. Session
     * memory is only ever read for [SecTier.CONFIRM].
     */
    internal fun evaluate(
        rawToolName: String,
        memory: ToolApprovalMemory,
    ): ToolApprovalOutcome {
        val canonical = McpToolExecutor.canonicalToolId(rawToolName)
        val tier = tierFor(rawToolName)
        // One `when`, so the branch order below IS the evaluation order: a later branch cannot run
        // unless every earlier one was false. That is what makes "CONFIRM_EACH touches no session set"
        // a structural property of this function rather than a claim about it.
        return when {
            // D-02: AUTO runs with no decision and no record of one. D-05 makes it read-only AND
            // bounded-output, so there is nothing for a human to weigh.
            tier == SecTier.AUTO ->
                ToolApprovalOutcome.Run(approvedOrigin(tier, ToolDecision.AUTO), tier, ToolDecision.AUTO)
            // D-02: this tier consults NEITHER session set and writes to NEITHER, which is the whole
            // reason a third tier exists. One click must not hand the model unlimited http1_request /
            // http2_request / intruder / scan_audit_start for a whole chat (T-22-18). It also means an
            // unrecognised name — which plan 22-03's fail-closed fallback lands here — can never enter
            // either set.
            tier == SecTier.CONFIRM_EACH ->
                ToolApprovalOutcome.Ask(tier, canonical, offersSessionActions = false)
            // Denied is checked BEFORE approved so a tool that somehow reached both sets fails closed.
            memory.isDeniedForSession(canonical) ->
                ToolApprovalOutcome.Denied(tier, ToolDecision.SESSION_DENIED, DENIAL_RESULT)
            // SESSION_APPROVED, not APPROVE_ONCE: no human saw this invocation, and the audit record
            // has to be able to say so.
            memory.isApprovedForSession(canonical) ->
                ToolApprovalOutcome.Run(approvedOrigin(tier, ToolDecision.SESSION_APPROVED), tier, ToolDecision.SESSION_APPROVED)
            else -> ToolApprovalOutcome.Ask(tier, canonical, offersSessionActions = true)
        }
    }

    /**
     * Applies one user click (D-11's four actions) or a teardown-driven implicit denial.
     *
     * Accepts only what a human can actually cause. [ToolDecision.AUTO], [ToolDecision.SESSION_APPROVED]
     * and [ToolDecision.SESSION_DENIED] are gate-derived outcomes, never clickable, so passing one is a
     * caller bug the gate surfaces rather than absorbs.
     *
     * Session memory is written for exactly two of the five actions. `Approve once` and `Deny` are
     * per-call by definition, and an implicit denial means nobody answered — inferring a lasting
     * preference from silence is the opposite of consent.
     */
    internal fun resolve(
        rawToolName: String,
        memory: ToolApprovalMemory,
        action: ToolDecision,
    ): ToolApprovalOutcome {
        require(action != ToolDecision.AUTO && action != ToolDecision.SESSION_APPROVED && action != ToolDecision.SESSION_DENIED) {
            "$action is derived by the gate, not clickable; resolve() accepts only the four D-11 actions plus IMPLICIT_DENY."
        }
        val canonical = McpToolExecutor.canonicalToolId(rawToolName)
        val tier = tierFor(rawToolName)
        // The card never offers a session action for this tier, so a caller that passes one has already
        // gone wrong somewhere the gate cannot see. Throwing keeps D-02's third tier un-short-circuitable.
        require(tier != SecTier.CONFIRM_EACH || (action != ToolDecision.APPROVE_SESSION && action != ToolDecision.DENY_SESSION)) {
            "$canonical is CONFIRM_EACH and has no session memory in either direction (D-02); $action must never be offered for it."
        }
        return when (action) {
            ToolDecision.APPROVE_ONCE ->
                ToolApprovalOutcome.Run(approvedOrigin(tier, action), tier, action)
            ToolDecision.APPROVE_SESSION -> {
                memory.approveForSession(canonical)
                ToolApprovalOutcome.Run(approvedOrigin(tier, action), tier, action)
            }
            ToolDecision.DENY ->
                ToolApprovalOutcome.Denied(tier, action, DENIAL_RESULT)
            ToolDecision.DENY_SESSION -> {
                memory.denyForSession(canonical)
                ToolApprovalOutcome.Denied(tier, action, DENIAL_RESULT)
            }
            ToolDecision.IMPLICIT_DENY ->
                ToolApprovalOutcome.Denied(tier, action, DENIAL_RESULT)
            // Exhaustive rather than `else`, so adding a ninth ToolDecision fails the build here instead
            // of silently falling into a default. Unreachable: the first require above rejects all three.
            ToolDecision.AUTO, ToolDecision.SESSION_APPROVED, ToolDecision.SESSION_DENIED ->
                error("Unreachable: $action was rejected by the clickable-action precondition.")
        }
    }

    /**
     * The iteration budget after this tool call, whatever the user clicked (D-13).
     *
     * Reproduces the arithmetic already in `ChatPanel.denyToolCall` and `ChatPanel.executeApprovedToolCall`,
     * each of which hands `toolIterationsLeft` to its followup `sendMessage`, so the denial branch and the
     * success branch
     * provably share ONE decrement. That is the entire proof that `MAX_AUTO_TOOL_ITERATIONS = 8` holds:
     * the counter is monotone, so eight steps reach zero with no case analysis over what was clicked.
     *
     * Free denials were rejected, and the reason is not thrift: if refusing cost nothing, injected
     * traffic could walk the model through 59 *different* tools and produce 59 cards — a user-facing
     * denial of service delivered through the safety control itself (T-22-08).
     *
     * Claim only what ships: a session-denied tool still resolves instantly and still sends a followup
     * turn, so a model that re-emits it can burn up to seven further backend round-trips with no card
     * and no user interaction. Deny-for-session bounds the *prompting*, not the *token cost*.
     */
    internal fun nextIterationBudget(remaining: Int): Int = (remaining - 1).coerceAtLeast(0)

    /** Whether the next turn may still call a tool. Mirrors the `allowToolCalls` argument both of those followup call sites pass, for the same reason. */
    internal fun allowsFurtherToolCalls(remaining: Int): Boolean = remaining > 1
}

/**
 * Makes a model-supplied value safe to render on one line and to write into an audit payload.
 *
 * Control characters are **REMOVED, never replaced**, so `"a\r\nInjected: line"` collapses to
 * `"aInjected: line"` and a forged second log line is impossible (CWE-117,
 * mcp/McpBlockedRequestReporter.kt:220-233). Stripping ESC also neuters ANSI sequences.
 *
 * **One implementation, two callers.** [McpBlockedRequestReporter] used to carry a line-for-line copy of
 * this function — same regex, same remove-then-collapse-then-trim-then-cap sequence — differing only in
 * the cap and in the truncation marker. Two copies is how the CWE-117 rule ends up fixed in one place
 * and not the other, so the marker and the cap are parameters and the copy is gone (WR-05).
 *
 * Applied to the model-supplied TOOL ID on the card, in the accessible description and in the audit
 * payload. It is the wrong tool for the args JSON: `\p{Cntrl}` includes `\n` and `\t`, so this would
 * flatten JSON into one unreadable line — the opposite of D-07's rule that the full args are shown
 * because the args are where exfiltration hides. Use [sanitizeBlock] there.
 */
internal fun sanitizeInline(
    value: String?,
    maxLength: Int = INLINE_MAX_LENGTH,
    ellipsis: String = INLINE_ELLIPSIS,
): String? =
    value?.let { raw ->
        val cleaned =
            inlineControlCharRegex
                .replace(raw, "")
                .replace(inlineWhitespaceRegex, " ")
                .trim()
        if (cleaned.length > maxLength) cleaned.take(maxLength).trimEnd() + ellipsis else cleaned
    }

/**
 * Makes a model-supplied value safe to render as a multi-line block, preserving `\n` and `\t`.
 *
 * Same CWE-117 rule as [sanitizeInline] — control characters are REMOVED, never replaced — but `\n`
 * and `\t` survive, because this is what renders the args JSON in the card's expandable preview and
 * unreadable args defeat the point of showing them. Truncates by whichever of [maxChars] and
 * [maxLines] bites first, appending `…` so a truncated preview never looks complete.
 *
 * It is the wrong tool for a tool ID: a name like `"scope_check\n\n✔ Approved"` would occupy several
 * lines and imitate an outcome row. Use [sanitizeInline] there.
 */
internal fun sanitizeBlock(
    value: String?,
    maxChars: Int,
    maxLines: Int,
): String {
    val cleaned = blockControlCharRegex.replace(value.orEmpty(), "")
    val lines = cleaned.lines()
    val lineTruncated = lines.size > maxLines
    val lineCapped = lines.take(maxLines).joinToString("\n")
    val charTruncated = lineCapped.length > maxChars
    val capped = if (charTruncated) lineCapped.take(maxChars) else lineCapped
    return if (lineTruncated || charTruncated) "$capped…" else capped
}
