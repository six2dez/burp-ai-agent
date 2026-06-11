package com.six2dez.burp.aiagent.redact

/**
 * Pre-send secret tripwire (PRIV-03, Phase 15). AWT-free — MUST NOT import `java.awt.*` or
 * `javax.swing.*`. The scanner and MCP paths reuse this object headless (same contract as
 * [SecretShapes] and [SafeRegex]).
 *
 * ### Design
 * Orchestrates two complementary detectors into a single [ScanResult]:
 * 1. **Shape detector** — [SecretShapes.findSurviving] for known-prefix secrets (AWS, GitHub,
 *    OpenAI, JWT, …). Never re-implemented here; single source of truth keeps interactive and
 *    non-interactive paths in sync (SC4).
 * 2. **Entropy heuristic** — [Entropy.maxQualifyingTokenEntropy] for unprefixed high-entropy
 *    tokens (e.g. raw base64-encoded keys) that [SecretShapes] does not cover.
 *
 * ### No-leak discipline (CLAUDE.md / AGENTS.md non-negotiable)
 * [ScanResult] carries ONLY [ScanResult.shapeCategories] (human-readable category names from
 * [SecretShapes.findSurviving]) and [ScanResult.maxEntropyBitsPerChar] (a numeric score).
 * The raw matched token is NEVER a field and NEVER interpolated into any result or log.
 * [SecretTripwireTest] SC3 asserts this property at the type level.
 *
 * ### Usage
 * Call [scan] on the FINAL post-redaction payload at every outbound hook point. Do NOT re-run
 * redaction inside this object — the payload is already final at the call site (RESEARCH G8).
 */
object SecretTripwire {

    /**
     * Result of a tripwire scan.
     *
     * @param matched True if any shape or high-entropy token was found — triggers the
     *   warn-with-confirmation gate (interactive path) or audit-log-and-proceed (non-interactive).
     * @param shapeCategories Human-readable category names from [SecretShapes.findSurviving]
     *   (e.g. "AWS access key"). Empty if detection was entropy-only. Never contains the raw value.
     * @param maxEntropyBitsPerChar Maximum qualifying token entropy in bits/char, or 0.0 if no
     *   high-entropy token was found. Used by [Entropy.truncatedScore] for the SC3 audit score.
     */
    data class ScanResult(
        val matched: Boolean,
        val shapeCategories: Set<String>,
        val maxEntropyBitsPerChar: Double,
    )

    /**
     * Pure gate-decision record for the interactive confirmation gate (SC5).
     * AWT-free — consumed by [ContextPreviewDialog] to drive banner level + button label,
     * and exercised directly in [SecretTripwireGateTest] without any Swing instantiation.
     *
     * @param bannerRisk True when the [SubtleNotice] banner should escalate to [Level.RISK] (red).
     *   False when the clean state applies (banner hidden) or no match is present.
     * @param affirmativeLabel The label for the "send" action in [JOptionPane.showOptionDialog].
     *   "Send anyway" when [bannerRisk] is true; "Send" on the clean path.
     * @param cancelIsDefault Always true — Cancel ([options[1]]) is the [showOptionDialog] initialValue
     *   so Enter never silently sends past a suspected secret (G5 / Pitfall 5 / UI-SPEC Delta 2).
     */
    data class GateDecision(
        val bannerRisk: Boolean,
        val affirmativeLabel: String,
        val cancelIsDefault: Boolean = true,
    )

    /**
     * Derives the pure gate-decision from a [ScanResult].
     *
     * - When [ScanResult.matched] is true: [GateDecision.bannerRisk] = true,
     *   [GateDecision.affirmativeLabel] = "Send anyway".
     * - When [ScanResult.matched] is false (clean path): [GateDecision.bannerRisk] = false,
     *   [GateDecision.affirmativeLabel] = "Send".
     * - [GateDecision.cancelIsDefault] is always true (never the affirmative — G5).
     *
     * This helper is AWT-free and unit-tested in [SecretTripwireGateTest] without Swing
     * (SC5 branch picks RISK + "Send anyway" + Cancel-default when matched).
     */
    fun gateDecision(scan: ScanResult): GateDecision =
        GateDecision(
            bannerRisk = scan.matched,
            affirmativeLabel = if (scan.matched) "Send anyway" else "Send",
            cancelIsDefault = true,
        )

    /**
     * The single SC3 audit-payload builder shared by every emit site (interactive allow event +
     * the non-interactive detect events). Centralising here is the single source of truth for the
     * payload shape so the no-leak contract and the key set cannot drift between paths (WR-03).
     *
     * The map always carries:
     * - `"path"` — `"chat"`, `"passive_scanner"`, or `"mcp"` (identifies the outbound hook)
     * - `"sessionId"` — the resolved session id, or `"none"` when null
     * - `"shapeCategories"` — sorted list of category names from [ScanResult.shapeCategories]
     *   (names only — NEVER the raw matched value, CLAUDE.md / AGENTS.md non-negotiable)
     * - `"entropyScore"` — one-decimal-place string from [Entropy.truncatedScore] (a number —
     *   NEVER the token)
     *
     * The raw matched token is NEVER a key or value here (SC3 no-leak).
     */
    private fun buildAuditPayload(
        scan: ScanResult,
        path: String,
        sessionId: String?,
    ): Map<String, Any?> =
        buildMap {
            put("path", path)
            put("sessionId", sessionId ?: "none")
            put("shapeCategories", scan.shapeCategories.toList().sorted())
            put("entropyScore", Entropy.truncatedScore(scan.maxEntropyBitsPerChar))
        }

    /**
     * Builds the audit payload map for a `secret_tripwire_allow` event (SC3).
     *
     * Delegates to the single [buildAuditPayload] builder with `path = "chat"` (the interactive
     * chat send path). The map carries `"path"`, `"sessionId"`, a sorted `"shapeCategories"` name
     * list, and `"entropyScore"`. The raw matched value is NEVER present (CLAUDE.md / AGENTS.md
     * non-negotiable).
     *
     * Consumed by [ChatPanel.startSessionFromContext] after [createSession] so the event carries
     * a real session id (RESEARCH Open Q1 Option b / G3).
     */
    fun buildAllowAuditPayload(
        scan: ScanResult,
        sessionId: String,
    ): Map<String, Any?> = buildAuditPayload(scan, path = "chat", sessionId = sessionId)

    /**
     * Builds the audit payload map for a `secret_tripwire_detect` event on the non-interactive
     * paths (PassiveAiScanner and McpToolContext). Delegates to the single [buildAuditPayload]
     * builder. This is the SC3 payload: it carries only category names + sessionId + a truncated
     * numeric entropy score — NEVER the raw matched token (CLAUDE.md / AGENTS.md non-negotiable).
     *
     * @param scan The [ScanResult] from [scan] on the FINAL post-redaction payload.
     * @param path One of `"passive_scanner"` or `"mcp"` — identifies the outbound hook.
     * @param sessionId The caller's `supervisor.currentSessionId() ?: "none"` (or null, in which
     *   case `"none"` is substituted). Null-safe: a null value is stored as `"none"`.
     */
    fun buildDetectAuditPayload(
        scan: ScanResult,
        path: String,
        sessionId: String?,
    ): Map<String, Any?> = buildAuditPayload(scan, path = path, sessionId = sessionId)

    /**
     * Convenience helper for non-interactive hook bodies: scans [payload] and, when matched,
     * returns the audit payload map (suitable for passing to `AuditLogger.emitGlobal`). Returns
     * `null` when the scan does not match (no event should be emitted).
     *
     * The caller MUST proceed regardless of the return value — a non-null result means "emit the
     * event" but NEVER means "block the send" (SC2).
     *
     * @param payload The FINAL post-redaction string to scan (G1/G8 — never raw/pre-redaction).
     * @param path One of `"passive_scanner"` or `"mcp"`.
     * @param sessionId `supervisor.currentSessionId() ?: "none"`, or null (falls back to `"none"`).
     * @return A detect-payload map when [ScanResult.matched] is true; null otherwise.
     */
    fun detectAndBuild(
        payload: String,
        path: String,
        sessionId: String?,
    ): Map<String, Any?>? {
        val tw = scan(payload)
        return if (tw.matched) buildDetectAuditPayload(tw, path, sessionId) else null
    }

    /**
     * Scans the FINAL post-redaction [payload] for secrets that may have survived the redaction
     * pipeline.
     *
     * Delegates to [SecretShapes.findSurviving] for the shape half and
     * [Entropy.maxQualifyingTokenEntropy] for the entropy half. [ScanResult.matched] is true if
     * either detector fires. Never echoes a matched value.
     */
    fun scan(payload: String): ScanResult {
        val categories = SecretShapes.findSurviving(payload)
        val maxEntropy = Entropy.maxQualifyingTokenEntropy(payload)
        return ScanResult(
            matched = categories.isNotEmpty() || maxEntropy > 0.0,
            shapeCategories = categories,
            maxEntropyBitsPerChar = maxEntropy,
        )
    }
}
