package com.six2dez.burp.aiagent.mcp

import com.six2dez.burp.aiagent.audit.AuditLogger
import com.six2dez.burp.aiagent.audit.Hashing
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicLong

/**
 * D-06 mandates the SHAPE (a flat map with a `reason` key), not a literal constant. It deliberately
 * does NOT reuse `mcp_tool_blocked`: that constant is a file-private `const` in
 * `mcp/tools/McpTool.kt` and unreachable from here, and its payload keys (`tool`, `toolType`,
 * `hasArgs`, `argsSha256`) have no transport-level meaning — emitting them with a different key set
 * would corrupt downstream analysis of tool telemetry.
 */
private const val MCP_TRANSPORT_EVENT_BLOCKED = "mcp_transport_blocked"

private const val MAX_HEADER_VALUE_LENGTH = 200

private const val BLOCK_LOG_WINDOW_MS = 60_000L

/**
 * The truncation marker this class has always written into the Output tab. Three ASCII dots rather than
 * U+2026, which is [sanitizeInline]'s default — kept as-is so a Phase-20 log line does not change shape
 * for a Phase-22 refactor, and passed as an argument rather than justifying a second implementation.
 */
private const val TRUNCATION_MARKER = "..."

/**
 * Turns a [GateDecision.Deny] into observability. Two sinks: an audit event, and a Burp Output-tab
 * line that is rate-limited per reason with an aggregate count (D-09). Per D-06 as amended by
 * **ADR-13**, the audit event fires on EVERY occurrence for the four local-mode reasons, and is
 * coalesced into one event per per-reason window carrying a `suppressed` count for the two
 * pre-authentication reasons (`UNAUTHORIZED`, `BLANK_TOKEN`). The access-control decision itself
 * stays pure — this class is invoked by the caller from the `Deny` branch, never from inside
 * `evaluate`.
 *
 * **Output sink is a lambda, not a `MontoyaApi`.** The caller passes
 * `{ line -> api.logging().logToOutput(line) }`; tests capture into a list. That keeps this class
 * testable without a Mockito deep stub.
 *
 * **D-10 / [verboseAudit].** A user-facing Verbose audit setting (`AgentSettings.auditVerbose`) exists
 * since quick 261008-sqa and is deliberately NOT wired here: the four reflected values are header values
 * sent by a remote, possibly unauthenticated peer, and header values are never written in plaintext in
 * either audit mode. [verboseAudit] therefore stays `false` at every call site, and the reflected header
 * values are always hashed. `method` and `path` are sanitized but not hashed: they are not reflected
 * header values, and a hashed request path would make a blocked route undiagnosable.
 *
 * **T-20-12, residual risk, stated for the audit-ENABLED case.** `App.kt:69` registers the
 * `AuditLogger` global emitter unconditionally at startup — the `enabled` short-circuit lives one
 * level deeper, in `AuditLogger.logEvent`. So when the user has turned audit logging ON, an audit
 * event means one synchronous append to audit.jsonl per emission, on a Netty event-loop thread.
 *
 * In EXTERNAL mode every route except `/__mcp/health` answers `401` to an unauthenticated peer, and
 * each of those is an `UNAUTHORIZED` or `BLANK_TOKEN` denial, so per-occurrence emission for those
 * two reasons was a REMOTE UNAUTHENTICATED append primitive against `~/.burp-ai-agent/audit.jsonl`
 * (CWE-400 resource exhaustion / CWE-779 excessive logging — the flood also buries genuine records
 * under attacker-chosen noise). **ADR-13** resolves that by coalescing those two reasons to one
 * event per window with a `suppressed` count; see [consumeAuditWindow]. The four local-mode reasons
 * stay per-occurrence because triggering them requires local code execution, and they are the
 * diagnosable ones.
 *
 * What remains accepted: no size cap or rotation was added to the shared `AuditLogger`, so a local
 * process able to loop local-mode denials can still grow the file. That is a deliberate scope
 * boundary — `AuditLogger` is shared infrastructure every phase depends on — not an oversight, and
 * it is recorded as the residual in ADR-13. Async hand-off to a writer thread still has no in-repo
 * precedent, so the volume ceiling is the mitigation actually applied.
 */
internal class McpBlockedRequestReporter(
    private val logToOutput: (String) -> Unit,
    private val verboseAudit: Boolean = false,
) {
    private data class ReasonWindow(
        val lastLoggedAtMs: AtomicLong = AtomicLong(0L),
        val suppressedCount: AtomicLong = AtomicLong(0L),
    )

    /** D-09's Output-tab windows. Owned exclusively by [maybeLogBlocked]. */
    private val windows: MutableMap<BlockReason, ReasonWindow> = ConcurrentHashMap()

    /**
     * ADR-13's audit-sink windows. A SEPARATE map holding distinct [ReasonWindow] instances from
     * [windows]: both sinks consume their suppression counter with `getAndSet(0L)`, so sharing an
     * instance would let whichever sink ran first steal the other's count and report a wrong number.
     * The window LENGTH is shared ([BLOCK_LOG_WINDOW_MS]) so the two sinks cannot drift apart.
     */
    private val auditWindows: MutableMap<BlockReason, ReasonWindow> = ConcurrentHashMap()

    /**
     * The only entry point. Decides the audit emission first, then attempts the rate-limited Output
     * line.
     *
     * [nowMs] is injected by the caller rather than read from the system clock inside this class — the
     * same convention as `PassiveAiScannerAnalysis.maybeLogBackoff(nowMs, untilMs)` — so the D-09
     * window is assertable without sleeping.
     */
    internal fun report(
        deny: GateDecision.Deny,
        externalMode: Boolean,
        nowMs: Long,
    ) {
        // ADR-13: `UNAUTHORIZED` and `BLANK_TOKEN` are the only reasons an unauthenticated remote
        // peer can trigger, so they are the flood-capable ones and their audit event is coalesced.
        // A boolean predicate over the existing reasons rather than an exhaustive `when`, so adding
        // a `BlockReason` cannot silently opt it into coalescing.
        val floodCapable = deny.reason == BlockReason.UNAUTHORIZED || deny.reason == BlockReason.BLANK_TOKEN
        if (!floodCapable) {
            emitTransportTelemetry(MCP_TRANSPORT_EVENT_BLOCKED, buildPayload(deny, externalMode))
        } else {
            // `Map.plus` keeps insertion order, so `suppressed` lands after the eight D-06 keys and
            // never appears on a non-coalesced payload.
            consumeAuditWindow(deny.reason, nowMs)?.let { suppressed ->
                emitTransportTelemetry(MCP_TRANSPORT_EVENT_BLOCKED, buildPayload(deny, externalMode) + ("suppressed" to suppressed))
            }
        }
        maybeLogBlocked(deny, nowMs)
    }

    /**
     * ADR-13 limiter for the audit sink, using the same lock-free read-then-CAS idiom as
     * [maybeLogBlocked] over [auditWindows].
     *
     * Returns the number of occurrences suppressed SINCE THE PREVIOUS EMISSION when the window has
     * elapsed — the same meaning [aggregateLine] gives it, so the first event of a burst always
     * carries `0L` and the emitted occurrence is not counted in its own total. Returns `null` while
     * the window is still open, meaning "count this one and emit nothing". A `Long`, not an `Int`,
     * because the payload's value type is `Any?` and an `Int` would not compare equal to a `Long`.
     */
    private fun consumeAuditWindow(
        reason: BlockReason,
        nowMs: Long,
    ): Long? {
        val window = auditWindows.computeIfAbsent(reason) { ReasonWindow() }
        val prev = window.lastLoggedAtMs.get()
        val windowElapsed = prev == 0L || nowMs - prev >= BLOCK_LOG_WINDOW_MS
        return if (!windowElapsed || !window.lastLoggedAtMs.compareAndSet(prev, nowMs)) {
            window.suppressedCount.incrementAndGet()
            null
        } else {
            window.suppressedCount.getAndSet(0L)
        }
    }

    /**
     * Builds the D-06 audit payload.
     *
     * Deliberately ABSENT: the raw, attacker-controlled header values. Every value is D-07 sanitized,
     * and the four reflected header values are SHA-256 hashed in both audit modes, because the
     * [verboseAudit] seam is never wired to the Verbose audit setting (D-10, quick 261008-sqa), so
     * an attacker cannot use a blocked request to write chosen plaintext — a session cookie echoed in
     * a `Referer`, a bearer token misplaced into `Origin` — into `~/.burp-ai-agent/audit.jsonl`.
     * Also absent: any request body, any response detail, and the configured token itself.
     *
     * A null header stays null through both steps; it is never hashed into the SHA-256 of the empty
     * string, which would otherwise make "header absent" indistinguishable from "header empty".
     */
    private fun buildPayload(
        deny: GateDecision.Deny,
        externalMode: Boolean,
    ): Map<String, Any?> =
        linkedMapOf(
            "reason" to deny.reason.wireValue,
            "mode" to if (externalMode) "external" else "local",
            "method" to sanitize(deny.facts.method),
            "path" to sanitize(deny.facts.path),
            "origin" to auditValue(deny.facts.origin),
            "host" to auditValue(deny.facts.host),
            "referer" to auditValue(deny.facts.referer),
            "userAgent" to auditValue(deny.facts.userAgent),
        )

    /** D-10: sanitize, then hash unless the caller opted into plaintext. Null in, null out. */
    private fun auditValue(value: String?): String? = sanitize(value)?.let { if (verboseAudit) it else Hashing.sha256Hex(it) }

    private fun emitTransportTelemetry(
        type: String,
        payload: Map<String, Any?>,
    ) {
        AuditLogger.emitGlobal(type, payload)
    }

    /**
     * D-09 limiter. Lock-free read-then-CAS: this runs on Netty event-loop threads, so there is no
     * monitor lock and no scheduled executor anywhere in this class. Windows expire lazily on the next
     * block for the same reason rather than being swept by a cleaner thread.
     *
     * `0L` means "never logged", so the first block for a reason always prints — computing
     * `nowMs - Long.MIN_VALUE` would overflow instead.
     */
    private fun maybeLogBlocked(
        deny: GateDecision.Deny,
        nowMs: Long,
    ) {
        val window = windows.computeIfAbsent(deny.reason) { ReasonWindow() }
        val prev = window.lastLoggedAtMs.get()
        val windowElapsed = prev == 0L || nowMs - prev >= BLOCK_LOG_WINDOW_MS
        // Short-circuits so the CAS is only attempted when the window has actually elapsed. Losing
        // the CAS means a concurrent thread printed for this reason, so this block is a suppression.
        if (!windowElapsed || !window.lastLoggedAtMs.compareAndSet(prev, nowMs)) {
            window.suppressedCount.incrementAndGet()
        } else {
            val suppressed = window.suppressedCount.getAndSet(0L)
            logToOutput(if (suppressed > 0L) aggregateLine(deny, suppressed) else blockedLine(deny))
        }
    }

    private fun blockedLine(deny: GateDecision.Deny): String =
        "[McpAccessControl] Blocked MCP request: reason=${deny.reason.wireValue} " +
            "method=${outputValue(deny.facts.method)} path=${outputValue(deny.facts.path)} " +
            "origin=${outputValue(deny.facts.origin)} host=${outputValue(deny.facts.host)} " +
            "referer=${outputValue(deny.facts.referer)} ua=${outputValue(deny.facts.userAgent)}"

    private fun aggregateLine(
        deny: GateDecision.Deny,
        suppressed: Long,
    ): String = "[McpAccessControl] $suppressed further blocks for ${deny.reason.wireValue} in the last 60s"

    /** The Output tab carries sanitized plaintext, never a hash — it is where a human diagnoses. */
    private fun outputValue(value: String?): String = sanitize(value) ?: "none"

    /**
     * D-07: make an attacker-controlled value safe to write into a log line. Control characters are
     * REMOVED rather than replaced, so `"a\r\nInjected: line"` collapses to `"aInjected: line"` and a
     * forged second log line is impossible (CWE-117).
     *
     * Binds this class's cap and marker to the package's one implementation. It used to BE that
     * implementation, duplicated character for character in `mcp/ToolApprovalGate.kt` — with a comment
     * claiming the copy was what kept the two from drifting, by which time they had already drifted on
     * the marker (WR-05). One regex, one remove-then-collapse-then-trim-then-cap sequence, and the two
     * things that genuinely differ passed as arguments.
     */
    private fun sanitize(value: String?): String? = sanitizeInline(value, MAX_HEADER_VALUE_LENGTH, TRUNCATION_MARKER)
}
