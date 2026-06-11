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
    // NOTE: this splitter treats '.' as a delimiter, so dot-delimited runs are evaluated
    // segment-by-segment. The dot-aware second pass below ([DOTTED_SPLIT]) recovers the
    // case where the individual segments are each < MIN_TOKEN_LEN but the dot-joined run is
    // a single high-entropy secret (a raw JWT body/signature or a dot-delimited base64url key).
    private val TOKEN_SPLIT = Regex("[^A-Za-z0-9+/=_-]+")

    // WR-01 dot-aware splitter: like [TOKEN_SPLIT] but ALSO keeps '.' inside the candidate so a
    // run such as `aaaa.bbbb.cccc` survives whole. Used only to recover dot-delimited base64url
    // secrets whose segments are individually below the length gate. The charset gate below still
    // requires the dots-removed payload to be entirely base64url AND clear BASE64_THRESHOLD (4.5),
    // so ordinary dotted prose (hostnames, IPs, version strings, package names) does NOT qualify:
    // those either fall short of MIN_TOKEN_LEN once dots are removed, or stay well under 4.5
    // bits/char. Linear and ReDoS-safe (no backtracking) — no SafeRegex wrapper required. (G6)
    private val DOTTED_SPLIT = Regex("[^A-Za-z0-9+/=_.\\-]+")

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
     * Entropy (bits/char) of [token] if it QUALIFIES as a suspect token, else 0.0. A token
     * qualifies when:
     * - length ≥ [MIN_TOKEN_LEN] (= 20), AND
     * - its charset is entirely hex ([HEX_CHARS]) with entropy ≥ [HEX_THRESHOLD] (3.0), OR
     * - its charset is entirely base64 ([BASE64_CHARS]) with entropy ≥ [BASE64_THRESHOLD] (4.5).
     *
     * The entropy is measured on [token] exactly as supplied. Callers that want to evaluate a
     * dot-delimited run as a single secret pass the dots-removed payload (see [maxQualifyingTokenEntropy]).
     */
    private fun qualifyingEntropy(token: String): Double {
        if (token.length < MIN_TOKEN_LEN) return 0.0
        val h = shannon(token)
        val isHex = token.all { it in HEX_CHARS }
        val isB64 = token.all { it in BASE64_CHARS }
        val qualifies = (isHex && h >= HEX_THRESHOLD) || (isB64 && h >= BASE64_THRESHOLD)
        return if (qualifies) h else 0.0
    }

    /**
     * Returns the maximum entropy (bits/char) among all tokens in [text] that QUALIFY as suspect
     * (see [qualifyingEntropy] for the per-token gate). Returns 0.0 if no token qualifies. Used by
     * [SecretTripwire.scan] as the entropy half of the pre-send tripwire detector.
     *
     * Two complementary passes run:
     * 1. **Segment pass** — split on [TOKEN_SPLIT] (`.` is a delimiter) and gate each segment.
     *    This is the original behaviour: it catches a single contiguous high-entropy run.
     * 2. **Dot-joined pass (WR-01)** — split on [DOTTED_SPLIT] (`.` kept in-token); for any
     *    candidate that contains a `.`, gate the dots-removed payload. This recovers dot-delimited
     *    base64url secrets (e.g. a raw JWT body/signature `aaaa.bbbb.cccc`) whose individual
     *    segments are each below [MIN_TOKEN_LEN] but whose joined payload is one high-entropy
     *    secret. The [BASE64_THRESHOLD] (4.5) charset/entropy gate keeps ordinary dotted prose
     *    (hostnames, IPs, version strings, dotted identifiers) from qualifying.
     *
     * The dot-joined pass is strictly additive: it can only raise the reported maximum, never
     * suppress a detection the segment pass already made.
     */
    fun maxQualifyingTokenEntropy(text: String): Double {
        var max = 0.0
        // Pass 1: original segment-wise gate (unchanged behaviour).
        for (token in text.split(TOKEN_SPLIT)) {
            val h = qualifyingEntropy(token)
            if (h > max) max = h
        }
        // Pass 2 (WR-01): dot-joined candidates — evaluate the dots-removed payload so a
        // dot-delimited base64url secret with sub-MIN_TOKEN_LEN segments is still detected.
        // Restricted to the BASE64 path (>= 4.5 bits/char) ONLY: pure hex maxes out at 4.0
        // bits/char, so requiring 4.5 excludes dotted-hex runs (MAC addresses, hex-octet
        // sequences) that would otherwise be audit noise here — a contiguous high-entropy hex
        // secret is already covered by Pass 1 and SecretShapes' broad hex-key shape.
        for (candidate in text.split(DOTTED_SPLIT)) {
            if (!candidate.contains('.')) continue // pass 1 already covered dot-free runs
            val joined = candidate.replace(".", "")
            if (joined.length < MIN_TOKEN_LEN) continue
            if (!joined.all { it in BASE64_CHARS }) continue
            val h = shannon(joined)
            if (h >= BASE64_THRESHOLD && h > max) max = h
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
