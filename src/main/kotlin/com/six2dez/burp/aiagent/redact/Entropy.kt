package com.six2dez.burp.aiagent.redact

import java.util.Locale
import kotlin.math.ln

/**
 * AWT-free Shannon entropy helper for the PRIV-03 pre-send secret tripwire (Phase 15).
 *
 * ### Purpose
 * Detects unknown high-entropy tokens that have no recognised secret prefix (e.g. unprefixed
 * base64-encoded keys) and that [SecretShapes] therefore does not cover. The hex path
 * (≥ 3.0 bits/char) harmlessly overlaps [SecretShapes]' broad `high-entropy hex key` shape;
 * the entropy path's real contribution is base64 tokens with no known prefix. (RESEARCH Open Q3.)
 *
 * ### AWT-free contract
 * This file MUST NOT import `java.awt.*` or `javax.swing.*`. The Phase 15 tripwire runs in a
 * non-UI context (scanner + MCP paths) and must be headless-testable without dragging in AWT.
 * Mirrors the contract documented in [SecretShapes] lines 17-19 and [SafeRegex] lines 21-22.
 *
 * ### Thresholds
 * [BASE64_THRESHOLD] and [HEX_THRESHOLD] match the truffleHog / detect-secrets canonical defaults
 * (base64 ≥ 4.5 bits/char, hex ≥ 3.0 bits/char, token length ≥ 20). These are corroborated by two
 * independent sources (RESEARCH A1). They are private `const`s — tunable in one place, not
 * user-facing, following the [SecretShapes] "no user-facing tuning" precedent (RESEARCH Open Q2).
 *
 * ### SC3 audit discipline
 * [truncatedScore] returns a one-decimal string from a bits/char Double. It is the ONLY
 * entropy-derived value that appears in audit events or the UI — never the token itself.
 */
object Entropy {

    // Minimum token length to be considered for entropy qualification (inclusive).
    // Tokens shorter than this are skipped to avoid false-positives on short identifiers.
    private const val MIN_TOKEN_LEN = 20

    // Shannon entropy threshold for base64-charset tokens (bits/char).
    // Canonical default from truffleHog and detect-secrets. (RESEARCH A1)
    private const val BASE64_THRESHOLD = 4.5

    // Shannon entropy threshold for hex-charset tokens (bits/char).
    // Canonical default from truffleHog and detect-secrets. (RESEARCH A1)
    private const val HEX_THRESHOLD = 3.0

    // Characters that make up a valid base64-encoded value (standard alphabet + padding).
    private val BASE64_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=".toSet()

    // Characters that make up a hex-encoded value (lowercase and uppercase).
    private val HEX_CHARS = "0123456789abcdefABCDEF".toSet()

    // Splits on any character that is NOT a typical secret/token character.
    // The character class [^A-Za-z0-9+/=_-] is linear and ReDoS-safe — no backtracking
    // patterns are introduced, so no SafeRegex deadline wrapper is required. (RESEARCH G6)
    private val TOKEN_SPLIT = Regex("[^A-Za-z0-9+/=_-]+")

    /**
     * Shannon entropy of [s] in bits per character.
     *
     * Computes H = -Σ p(c)·log2(p(c)) where p(c) is the relative frequency of character c.
     * Returns 0.0 for an empty string.
     */
    fun shannon(s: String): Double {
        if (s.isEmpty()) return 0.0
        val counts = HashMap<Char, Int>()
        for (c in s) counts[c] = (counts[c] ?: 0) + 1
        val n = s.length.toDouble()
        var h = 0.0
        for (count in counts.values) {
            val p = count / n
            h -= p * (ln(p) / ln(2.0))
        }
        return h
    }

    /**
     * Returns the maximum entropy (bits/char) among all tokens in [text] that QUALIFY as suspect:
     * - length ≥ [MIN_TOKEN_LEN] (= 20), AND
     * - the token's charset is entirely hex ([HEX_CHARS]) with entropy ≥ [HEX_THRESHOLD] (3.0), OR
     * - the token's charset is entirely base64 ([BASE64_CHARS]) with entropy ≥ [BASE64_THRESHOLD] (4.5).
     *
     * Returns 0.0 if no token qualifies. Used by [SecretTripwire.scan] as the entropy half of
     * the pre-send tripwire detector.
     */
    fun maxQualifyingTokenEntropy(text: String): Double {
        var max = 0.0
        for (token in text.split(TOKEN_SPLIT)) {
            if (token.length < MIN_TOKEN_LEN) continue
            val h = shannon(token)
            val isHex = token.all { it in HEX_CHARS }
            val isB64 = token.all { it in BASE64_CHARS }
            val qualifies = (isHex && h >= HEX_THRESHOLD) || (isB64 && h >= BASE64_THRESHOLD)
            if (qualifies && h > max) max = h
        }
        return max
    }

    /**
     * Formats [bitsPerChar] as a one-decimal-place string for audit logging (SC3).
     *
     * This is the ONLY entropy-derived value that may appear in audit events or the UI.
     * The matched token itself is NEVER exposed — only this numeric score and the shape
     * category names from [SecretShapes.findSurviving]. (CLAUDE.md / AGENTS.md non-negotiable.)
     */
    fun truncatedScore(bitsPerChar: Double): String = "%.1f".format(Locale.ROOT, bitsPerChar)
}
