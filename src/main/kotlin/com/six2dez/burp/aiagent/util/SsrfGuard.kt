package com.six2dez.burp.aiagent.util

import java.net.InetAddress
import java.net.URI

/**
 * Pure, network-free classifier for backend base-URLs (SEC-03 / A6).
 *
 * [isPrivateOrLinkLocal] returns true when a URL's host is a literal IP address in a private
 * (RFC-1918), link-local (169.254.0.0/16, fe80::/10), or cloud-metadata (169.254.169.254) range.
 * Loopback is explicitly EXCLUDED (Ollama/LM Studio local use is legitimate).
 *
 * Constraints (per D-01 "classify by address range inspection only"):
 * - No DNS resolution: only literal IP hosts are classified. Hostname-format hosts return false.
 * - No network calls; never throws on malformed/blank input.
 *
 * The result is advisory only — the caller shows a non-blocking inline warning and proceeds.
 */
object SsrfGuard {
    // Conservative literal-IP detectors. A dotted-quad is IPv4; anything with a ':' that is all
    // hex/colon is treated as a literal IPv6 candidate. These guards keep getByName from doing any
    // reverse/forward DNS for hostnames.
    private val IPV4_REGEX = Regex("""^\d{1,3}(\.\d{1,3}){3}$""")
    private val IPV6_REGEX = Regex("""^[0-9a-fA-F:]+$""")

    fun isPrivateOrLinkLocal(url: String): Boolean {
        if (url.isBlank()) return false

        val rawHost =
            try {
                URI(url).host
            } catch (e: Exception) {
                null
            }
        // URI(...).host is null for IPv6 hosts that are not bracketed (e.g. http://fe80::1) and for
        // some malformed inputs. Fall back to a manual authority parse so unbracketed IPv6 literals
        // are still classified.
        val host = (rawHost ?: extractAuthorityHost(url))?.trim()?.removeSurrounding("[", "]")
        if (host.isNullOrBlank()) return false

        // Only classify literal IPs — never resolve hostnames.
        val isIpv4 = IPV4_REGEX.matches(host)
        val isIpv6 = host.contains(':') && IPV6_REGEX.matches(host)
        if (!isIpv4 && !isIpv6) return false

        val addr =
            try {
                InetAddress.getByName(host)
            } catch (e: Exception) {
                return false
            }

        return when {
            addr.isLoopbackAddress -> false // loopback excluded per D-01
            addr.isSiteLocalAddress -> true // RFC-1918: 10.x, 172.16-31.x, 192.168.x
            addr.isLinkLocalAddress -> true // 169.254.x.x and fe80::/10
            addr.hostAddress == "169.254.169.254" -> true // cloud metadata (also link-local; explicit)
            else -> false
        }
    }

    /**
     * Best-effort extraction of the host portion from a URL authority for inputs that
     * [URI.getHost] cannot parse (e.g. unbracketed IPv6 literals). Returns null when no authority
     * is present. Performs no DNS — pure string parsing.
     */
    private fun extractAuthorityHost(url: String): String? {
        val schemeIdx = url.indexOf("://")
        if (schemeIdx < 0) return null
        var authority = url.substring(schemeIdx + 3)
        // Strip path/query/fragment.
        authority = authority.substringBefore('/').substringBefore('?').substringBefore('#')
        // Strip userinfo.
        authority = authority.substringAfterLast('@')
        if (authority.isBlank()) return null
        // Bracketed IPv6 with optional :port — return the inside of the brackets.
        if (authority.startsWith("[")) {
            val close = authority.indexOf(']')
            if (close > 0) return authority.substring(1, close)
        }
        // Unbracketed IPv6 literal: more than one ':' means it is not host:port.
        if (authority.count { it == ':' } > 1) return authority
        // host:port (IPv4 or hostname).
        return authority.substringBefore(':')
    }
}
