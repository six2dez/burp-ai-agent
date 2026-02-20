package com.six2dez.burp.aiagent.redact

import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.util.Collections
import java.util.LinkedHashMap
import java.util.concurrent.ConcurrentHashMap

data class RedactionPolicy(
    val stripCookies: Boolean,
    val redactTokens: Boolean,
    val anonymizeHosts: Boolean
) {
    companion object {
        fun default() = RedactionPolicy(
            stripCookies = true,
            redactTokens = true,
            anonymizeHosts = true
        )

        fun fromMode(mode: PrivacyMode): RedactionPolicy {
            return when (mode) {
                PrivacyMode.STRICT -> RedactionPolicy(
                    stripCookies = true,
                    redactTokens = true,
                    anonymizeHosts = true
                )
                PrivacyMode.BALANCED -> RedactionPolicy(
                    stripCookies = true,
                    redactTokens = true,
                    anonymizeHosts = false
                )
                PrivacyMode.OFF -> RedactionPolicy(
                    stripCookies = false,
                    redactTokens = false,
                    anonymizeHosts = false
                )
            }
        }
    }
}

enum class PrivacyMode {
    STRICT,
    BALANCED,
    OFF;

    companion object {
        fun fromString(raw: String?): PrivacyMode {
            return entries.firstOrNull { it.name.equals(raw, ignoreCase = true) } ?: OFF
        }
    }
}

object Redaction {

    private val authHeaderRegex = Regex("(?im)^(authorization|x-api-key|api-key|proxy-authorization):\\s*.+$")
    private val bearerRegex = Regex("(?i)bearer\\s+[A-Za-z0-9\\-\\._~\\+\\/]+=*")
    private val cookieHeaderRegex = Regex("(?im)^cookie:\\s*.+$")
    private val setCookieHeaderRegex = Regex("(?im)^set-cookie:\\s*.+$")

    // very generic JWT-like pattern (not perfect by design)
    private val jwtRegex = Regex("\\beyJ[A-Za-z0-9_\\-]+\\.[A-Za-z0-9_\\-]+\\.[A-Za-z0-9_\\-]+\\b")

    private val hostHeaderRegex = Regex("(?im)^host:\\s*([^\\s]+)\\s*$")

    private const val MAX_HOST_ENTRIES = 10_000

    private fun <K, V> boundedSynchronizedMap(maxSize: Int): MutableMap<K, V> {
        return Collections.synchronizedMap(object : LinkedHashMap<K, V>(16, 0.75f, true) {
            override fun removeEldestEntry(eldest: MutableMap.MutableEntry<K, V>?): Boolean {
                return size > maxSize
            }
        })
    }

    private val hostForwardMap = ConcurrentHashMap<String, MutableMap<String, String>>()
    private val hostReverseMap = ConcurrentHashMap<String, MutableMap<String, String>>()

    fun apply(raw: String, policy: RedactionPolicy, stableHostSalt: String, recordMapping: Boolean = true): String {
        var out = raw

        if (policy.stripCookies) {
            out = out.replace(cookieHeaderRegex, "Cookie: [STRIPPED]")
            out = out.replace(setCookieHeaderRegex, "Set-Cookie: [STRIPPED]")
        }

        if (policy.redactTokens) {
            out = out.replace(authHeaderRegex) { m ->
                val header = m.value.substringBefore(":")
                "$header: [REDACTED]"
            }
            out = out.replace(bearerRegex, "Bearer [REDACTED]")
            out = out.replace(jwtRegex, "[JWT_REDACTED]")
        }

        if (policy.anonymizeHosts) {
            out = out.replace(hostHeaderRegex) { m ->
                val host = m.groupValues[1]
                val anon = anonymizeHost(host, stableHostSalt, recordMapping)
                "Host: $anon"
            }
        }

        return out
    }

    fun anonymizeHost(host: String, salt: String, recordMapping: Boolean = true): String {
        val digest = MessageDigest.getInstance("SHA-256")
            .digest((salt + ":" + host).toByteArray(StandardCharsets.UTF_8))
        val short = digest.take(6).joinToString("") { "%02x".format(it) }
        val anon = "host-$short.local"
        if (recordMapping) {
            hostForwardMap.computeIfAbsent(salt) { boundedSynchronizedMap(MAX_HOST_ENTRIES) }[host] = anon
            hostReverseMap.computeIfAbsent(salt) { boundedSynchronizedMap(MAX_HOST_ENTRIES) }[anon] = host
        }
        return anon
    }

    fun deAnonymizeHost(host: String, salt: String): String? {
        return hostReverseMap[salt]?.get(host)
    }
}
