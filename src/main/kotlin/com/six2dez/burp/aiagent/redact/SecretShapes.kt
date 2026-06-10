package com.six2dez.burp.aiagent.redact

/**
 * Shared, AWT-free curated set of high-confidence secret shapes.
 *
 * Prefixes verified against multiple secret-scanning pattern corpora (gitleaks-class /
 * trufflehog-class patterns) plus the authoritative provider documentation for AWS, GitHub, and
 * Google. Source: 13-RESEARCH.md Pattern 4 (2026-06-10). [VERIFIED: secret-scanning corpora]
 *
 * ### Purpose
 * - **PRIV-04 (Phase 13):** the [ContextPreviewDialog] calls [findSurviving] on the
 *   post-redaction context to surface a non-blocking WARN banner when a known secret shape
 *   escaped the pipeline.
 * - **Phase 15 tripwire (future):** the pre-send scanner reuses this same object as the single
 *   source of truth so the two detection paths stay in sync.
 *
 * ### AWT-free contract
 * This file MUST NOT import `java.awt.*` or `javax.swing.*`. The Phase 15 tripwire runs in a
 * non-UI context and must be able to depend on [SecretShapes] without dragging in AWT.
 *
 * ### Shape ordering note
 * The broad `high-entropy hex key` shape (`[0-9a-fA-F]{32,}`) is intentionally placed LAST.
 * It can match MD5/SHA digests and other benign hex, producing false-positive WARN banners.
 * Because the banner is informational and non-blocking, a false positive only adds an advisory
 * (T-13-11 disposition: accept). Users who find it noisy can treat it as an additional prompt
 * to review their context — the harm is desensitisation at worst, not a security regression.
 * (Open Question 3, 13-RESEARCH.md lines 654-656.)
 */
object SecretShapes {

    /**
     * A (category, regex) pair. [category] is the human-readable name shown in the UI banner;
     * [regex] is the detection pattern — never echoed to the user.
     */
    data class Shape(val category: String, val regex: Regex)

    /**
     * Ordered list of curated high-confidence secret shapes.
     *
     * The OpenAI regex covers both legacy (`sk-<48+>`) and modern (`sk-proj-` / `sk-svcacct-` /
     * `sk-admin-` prefixed) key forms. The suffix floor `{20,}` is generous to avoid false
     * negatives while keeping the word-boundary anchors tight.
     *
     * AWS AKIA keys are exactly 20 characters (AKIA + 16 uppercase alphanumerics).
     * GitHub tokens use two-letter type prefixes (gh[pousr]_) followed by 36+ alphanum chars.
     * The fine-grained PAT format (`github_pat_<22+>`) is a separate shape.
     * Google API keys are exactly AIza + 35 URL-safe chars.
     * Slack tokens use the xox[baprs]- prefix family.
     * JWTs are three base64url segments separated by dots — the `eyJ` prefix identifies the header.
     * The broad high-entropy hex shape is placed last (see ordering note above).
     */
    val shapes: List<Shape> = listOf(
        // OpenAI: legacy sk-<48+> AND modern sk-proj-/svcacct-/admin- forms
        Shape("OpenAI key", Regex("""\bsk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_-]{20,}\b""")),

        // AWS access key ID: AKIA + 16 uppercase alphanumerics (exact format per AWS docs)
        Shape("AWS access key", Regex("""\bAKIA[0-9A-Z]{16}\b""")),

        // GitHub personal access tokens: ghp_ / gho_ / ghu_ / ghs_ / ghr_ + 36+ chars
        Shape("GitHub token", Regex("""\bgh[pousr]_[A-Za-z0-9]{36,}\b""")),

        // GitHub fine-grained PAT (newer format introduced 2022)
        Shape("GitHub fine-grained PAT", Regex("""\bgithub_pat_[A-Za-z0-9_]{22,}\b""")),

        // Google API key: AIza + 35 URL-safe chars (exact per Google Cloud docs)
        Shape("Google API key", Regex("""\bAIza[0-9A-Za-z_-]{35}\b""")),

        // Slack tokens: xoxb- (bot), xoxa- (app), xoxp- (user), xoxr- (refresh), xoxs- (service)
        Shape("Slack token", Regex("""\bxox[baprs]-[0-9A-Za-z-]{10,}\b""")),

        // JWT: three base64url segments separated by dots; header always starts eyJ
        // Note: Redaction.kt's jwtRegex *redacts* JWTs; this shape *detects* survivors.
        // The patterns are intentionally similar — duplicating the literal here avoids
        // a coupling between the redaction and detection layers.
        Shape("JWT", Regex("""\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b""")),

        // Broad high-entropy hex key (32+ hex chars) — placed LAST to minimise false-positive
        // desensitisation. Matches MD5/SHA digests and other benign hex; acceptable because the
        // banner is non-blocking (T-13-11: accept). Include to catch keys with no recognisable
        // prefix (e.g. database passwords stored as raw hex).
        Shape("high-entropy hex key", Regex("""\b[0-9a-fA-F]{32,}\b""")),
    )

    /**
     * Returns the set of [Shape.category] names whose regex appears in [text].
     *
     * Scans [text] (typically the post-redaction context JSON as it will be sent to the AI
     * backend) and returns every category whose pattern has at least one match. The matched
     * values themselves are never included in the result — only the category names.
     *
     * An empty set means no known secret shape survived redaction (clean context).
     */
    fun findSurviving(text: String): Set<String> =
        shapes.filter { it.regex.containsMatchIn(text) }.map { it.category }.toSet()
}
