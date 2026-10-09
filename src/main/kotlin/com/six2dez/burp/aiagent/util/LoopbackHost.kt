package com.six2dez.burp.aiagent.util

import java.net.URI

private const val IPV6_GROUP_COUNT = 8
private const val IPV6_MAX_GROUP_CHARS = 4
private const val IPV6_HEX_RADIX = 16
private const val IPV4_MAPPED_MARKER_INDEX = 5
private const val IPV4_MAPPED_MARKER = 0xffff
private const val LOOPBACK_FIRST_OCTET: Byte = 127

/**
 * Decides whether a configured backend URL points at this machine's loopback interface.
 *
 * **No DNS, ever.** The decision is made from the URL's literal host text only: `localhost`, an
 * IPv4 literal in 127.0.0.0/8 (via [Ipv4Literal], which never resolves), or the IPv6 loopback
 * `::1` in its compressed, fully expanded or IPv4-mapped (`::ffff:127.x.x.x`) spelling. No
 * `java.net` address type is used, so nothing here can trigger name resolution. A hostname that
 * merely resolves to 127.0.0.1 therefore counts as remote — the safe default, because remote
 * backends are only health-checked on demand and never on a timer.
 */
object LoopbackHost {
    fun isLoopbackUrl(url: String): Boolean {
        val host =
            runCatching { URI(url.trim()).host }
                .getOrNull()
                ?.removePrefix("[")
                ?.removeSuffix("]")
                ?.removeSuffix(".")
                ?.lowercase()
        return when {
            host.isNullOrBlank() -> false
            host == "localhost" -> true
            ':' in host -> isIpv6Loopback(host)
            else -> isIpv4Loopback(host)
        }
    }

    private fun isIpv4Loopback(host: String): Boolean = Ipv4Literal.parse(host)?.firstOrNull() == LOOPBACK_FIRST_OCTET

    private fun isIpv6Loopback(host: String): Boolean {
        val embeddedIpv4 = host.substringAfterLast(':').takeIf { '.' in it }
        // An embedded dotted IPv4 tail occupies the last two 16-bit groups; stand in zeros for them.
        val hexText = if (embeddedIpv4 != null) host.dropLast(embeddedIpv4.length) + "0:0" else host
        val groups = expandIpv6(hexText) ?: return false
        return if (embeddedIpv4 != null) {
            groups.take(IPV4_MAPPED_MARKER_INDEX).all { it == 0 } &&
                groups[IPV4_MAPPED_MARKER_INDEX] == IPV4_MAPPED_MARKER &&
                isIpv4Loopback(embeddedIpv4)
        } else {
            groups.dropLast(1).all { it == 0 } && groups.last() == 1
        }
    }

    /** Expands a (possibly `::`-compressed) IPv6 literal to its eight 16-bit groups, or null. */
    private fun expandIpv6(text: String): List<Int>? {
        val halves = text.split("::")
        val head = parseGroups(halves[0])
        val tail = if (halves.size == 2) parseGroups(halves[1]) else emptyList()
        if (halves.size > 2 || head == null || tail == null) return null
        val missing = IPV6_GROUP_COUNT - head.size - tail.size
        val valid = if (halves.size == 2) missing >= 1 else missing == 0
        return if (valid) head + List(missing) { 0 } + tail else null
    }

    private fun parseGroups(text: String): List<Int>? {
        if (text.isEmpty()) return emptyList()
        val groups =
            text.split(':').map { group ->
                group
                    .takeIf { it.length in 1..IPV6_MAX_GROUP_CHARS && it.all(::isHexDigit) }
                    ?.toInt(IPV6_HEX_RADIX)
            }
        return if (groups.any { it == null }) null else groups.filterNotNull()
    }

    private fun isHexDigit(c: Char): Boolean = c in '0'..'9' || c in 'a'..'f'
}
