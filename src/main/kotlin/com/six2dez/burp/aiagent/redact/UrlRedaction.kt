package com.six2dez.burp.aiagent.redact

import java.net.URI
import java.net.URISyntaxException
import java.util.Locale

/**
 * The one shared, fail-closed redactor for a bare URL string and for the item's own hostname in
 * free text (quick task 261008-jx2).
 *
 * A bare URL has no `Host:` line, so [Redaction.apply] alone never anonymizes its host, and the
 * old per-site helpers returned the raw URL whenever `java.net.URI` refused to parse it. This
 * object closes both gaps:
 *
 * - [redact] rewrites the authority (userinfo dropped when tokens are redacted, host aliased when
 *   hosts are anonymized, port kept), redacts the fragment with the same `[?&]key=` rule as the
 *   query, aliases the own host wherever else it appears in the URL, and finally runs the
 *   host-less [Redaction.apply] so token, JWT and user custom-pattern rules apply uniformly. When
 *   the URL does not parse it still rewrites the `scheme://authority` prefix it can find, and it
 *   never skips the final apply.
 * - [anonymizeHostOccurrences] aliases one known hostname wherever it appears in text, including
 *   inside percent-encoded URLs, and must run AFTER [Redaction.apply] so the `Host:` line is not
 *   aliased twice.
 */
object UrlRedaction {
    private val aliasShape = Regex("^host-[0-9a-f]{12}\\.local$", RegexOption.IGNORE_CASE)
    private val authorityPrefix = Regex("^[A-Za-z][A-Za-z0-9+.-]*://([^/?#]*)")
    private const val REDACTED_USERINFO = "[REDACTED]"

    // A host occurrence starts after a character that cannot belong to a DNS label, or right after
    // a percent-escape (%XX, or the double-encoded %25XX): in https%3A%2F%2Fhost the character in
    // front of the host is the alphanumeric 'F' of %2F, which the plain rule would reject.
    private const val HOST_BOUNDARY_BEFORE =
        "(?:(?<![A-Za-z0-9-])|(?<=%[0-9A-Fa-f]{2})|(?<=%25[0-9A-Fa-f]{2}))"
    private const val HOST_BOUNDARY_AFTER = "(?![A-Za-z0-9-])"

    /**
     * Returns the stable alias for [host]. A host that already has the alias shape is returned
     * unchanged, because [Redaction.anonymizeHost] is not idempotent and an alias-of-alias breaks
     * the reverse mapping MCP tools rely on. The host is lowercased first: DNS names are
     * case-insensitive and Burp reports hosts in lowercase, so the alias normally agrees with the
     * one [Redaction.apply] writes on the `Host:` line.
     */
    fun aliasHost(
        host: String,
        salt: String,
    ): String = if (aliasShape.matches(host)) host else Redaction.anonymizeHost(host.lowercase(Locale.ROOT), salt)

    /**
     * The host of an absolute URL: the `java.net.URI` host when it parses, otherwise the host part
     * of the `scheme://authority` prefix (userinfo and port removed, a bracketed IPv6 literal kept
     * whole). Null when neither yields a host.
     */
    fun hostOf(rawUrl: String?): String? {
        if (rawUrl.isNullOrBlank()) return null
        return parseOrNull(rawUrl)?.host?.ifEmpty { null } ?: prefixAuthority(rawUrl)?.let { (_, authority) ->
            authority.host.ifEmpty { null }
        }
    }

    /**
     * Redacts [rawUrl] under [policy]. OFF (no token redaction, no host anonymization) only runs the
     * user custom patterns, so its output is byte-identical to the input when none match. Every
     * other policy fails closed: the result never carries the raw userinfo, raw host (when hosts
     * are anonymized) or a sensitive parameter value, even when the URL does not parse.
     */
    fun redact(
        rawUrl: String,
        policy: RedactionPolicy,
        hostSalt: String,
    ): String {
        // A bare URL has no Host: line, so the Host-line rule is meaningless here; the authority
        // rewrite below is what anonymizes the host.
        val hostless = policy.copy(anonymizeHosts = false)
        if (!policy.redactTokens && !policy.anonymizeHosts) {
            return Redaction.apply(rawUrl, hostless, hostSalt)
        }
        val (rebuilt, realHost) = rewriteUrl(rawUrl, policy, hostSalt)
        val fragmentSafe = redactFragment(rebuilt, hostless, hostSalt)
        val hostSafe =
            if (policy.anonymizeHosts && realHost != null) {
                anonymizeHostOccurrences(fragmentSafe, realHost, hostSalt)
            } else {
                fragmentSafe
            }
        return Redaction.apply(hostSafe, hostless, hostSalt)
    }

    /**
     * Replaces every occurrence of [host] in [text] with its alias, case-insensitively and only on
     * label boundaries: `myapi.realcorp.com` and `api.realcorp.company` are left alone for host
     * `api.realcorp.com`, while `www.api.realcorp.com`, `api.realcorp.com:443` and the
     * percent-encoded `%2F%2Fapi.realcorp.com` are aliased. A blank or alias-shaped [host] returns
     * [text] unchanged. The pattern is a quoted literal between fixed-width lookarounds, so it runs
     * in linear time on target-controlled text.
     */
    fun anonymizeHostOccurrences(
        text: String,
        host: String,
        salt: String,
    ): String {
        if (host.isBlank() || aliasShape.matches(host)) return text
        val pattern = Regex(HOST_BOUNDARY_BEFORE + Regex.escape(host) + HOST_BOUNDARY_AFTER, RegexOption.IGNORE_CASE)
        val alias = aliasHost(host, salt)
        return text.replace(pattern) { alias }
    }

    private fun parseOrNull(rawUrl: String): URI? =
        try {
            URI(rawUrl)
        } catch (_: URISyntaxException) {
            null
        }

    // Rebuilds the URL with a rewritten authority and returns it with the real host it found.
    // The parsed path concatenates the RAW components: the multi-arg URI constructor re-encodes
    // them, which would change percent-encoded paths and queries byte-for-byte.
    private fun rewriteUrl(
        rawUrl: String,
        policy: RedactionPolicy,
        hostSalt: String,
    ): Pair<String, String?> {
        val uri = parseOrNull(rawUrl)
        val host = uri?.host
        if (uri == null || !uri.isAbsolute || host == null) return rewriteUnparsedUrl(rawUrl, policy, hostSalt)
        val port = if (uri.port >= 0) ":${uri.port}" else null
        val rebuilt =
            buildString {
                append(uri.scheme).append("://")
                append(Authority(uri.rawUserInfo, host, port).rewritten(policy, hostSalt))
                append(uri.rawPath.orEmpty())
                uri.rawQuery?.let { append('?').append(it) }
                uri.rawFragment?.let { append('#').append(it) }
            }
        return rebuilt to host
    }

    // FAIL CLOSED: rewrite the authority of the scheme://authority prefix and keep the rest
    // verbatim. Without such a prefix there is no host to rewrite; the caller's final
    // Redaction.apply still runs.
    private fun rewriteUnparsedUrl(
        rawUrl: String,
        policy: RedactionPolicy,
        hostSalt: String,
    ): Pair<String, String?> {
        val (range, authority) = prefixAuthority(rawUrl) ?: return rawUrl to null
        val rebuilt =
            rawUrl.substring(0, range.first) +
                authority.rewritten(policy, hostSalt) +
                rawUrl.substring(range.last + 1)
        return rebuilt to authority.host.ifEmpty { null }
    }

    // The authority of the scheme://authority prefix, with its character range in [rawUrl].
    private fun prefixAuthority(rawUrl: String): Pair<IntRange, Authority>? {
        val group = authorityPrefix.find(rawUrl)?.groups?.get(1) ?: return null
        return group.range to Authority.parse(group.value)
    }

    // The fragment meets the same [?&]key= rule as the query: an OAuth implicit-flow fragment
    // (#access_token=...&token_type=bearer) is prefixed with '?' for the apply and the prefix is
    // removed afterwards. A fragment with nothing sensitive comes back verbatim. The authority
    // cannot contain '#', so the first '#' always starts the fragment.
    private fun redactFragment(
        url: String,
        hostless: RedactionPolicy,
        hostSalt: String,
    ): String {
        val hash = url.indexOf('#')
        if (hash < 0) return url
        val fragment = url.substring(hash + 1)
        val redacted = Redaction.apply("?$fragment", hostless, hostSalt).removePrefix("?")
        return url.substring(0, hash + 1) + redacted
    }

    // userinfo, host and the raw ":port" suffix of an authority, plus the rewrite shared by the
    // parsed and the fail-closed paths.
    private data class Authority(
        val userInfo: String?,
        val host: String,
        val portSuffix: String?,
    ) {
        // userinfo becomes [REDACTED] when tokens are redacted, the host becomes its alias when hosts
        // are anonymized, and the port is kept.
        fun rewritten(
            policy: RedactionPolicy,
            hostSalt: String,
        ): String =
            buildString {
                userInfo?.let { append(if (policy.redactTokens) REDACTED_USERINFO else it).append('@') }
                append(if (policy.anonymizeHosts && host.isNotEmpty()) aliasHost(host, hostSalt) else host)
                portSuffix?.let { append(it) }
            }

        companion object {
            // Splits at the LAST '@' (an unencoded '@' inside userinfo stays in the userinfo), keeps
            // a bracketed IPv6 literal whole and treats the last ':' outside it as the port separator.
            fun parse(authority: String): Authority {
                val at = authority.lastIndexOf('@')
                val userInfo = if (at >= 0) authority.substring(0, at) else null
                val hostPort = authority.substring(at + 1)
                val close = if (hostPort.startsWith("[")) hostPort.indexOf(']') else -1
                val hostEnd =
                    when {
                        close >= 0 -> close + 1
                        hostPort.startsWith("[") -> hostPort.length
                        hostPort.contains(':') -> hostPort.lastIndexOf(':')
                        else -> hostPort.length
                    }
                return Authority(userInfo, hostPort.substring(0, hostEnd), hostPort.substring(hostEnd).ifEmpty { null })
            }
        }
    }
}
