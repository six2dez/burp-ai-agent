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
