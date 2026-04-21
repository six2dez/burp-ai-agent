package com.six2dez.burp.aiagent.redact

import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.util.concurrent.ConcurrentHashMap

data class RedactionPolicy(
    val stripCookies: Boolean,
    val redactTokens: Boolean,
    val anonymizeHosts: Boolean,
) {
    companion object {
        fun default() =
            RedactionPolicy(
                stripCookies = true,
                redactTokens = true,
                anonymizeHosts = true,
            )

        fun fromMode(mode: PrivacyMode): RedactionPolicy =
            when (mode) {
                PrivacyMode.STRICT ->
                    RedactionPolicy(
                        stripCookies = true,
                        redactTokens = true,
                        anonymizeHosts = true,
                    )
                PrivacyMode.BALANCED ->
                    RedactionPolicy(
                        stripCookies = true,
                        redactTokens = true,
                        anonymizeHosts = false,
                    )
                PrivacyMode.OFF ->
                    RedactionPolicy(
                        stripCookies = false,
                        redactTokens = false,
                        anonymizeHosts = false,
                    )
            }
    }
}

enum class PrivacyMode {
    STRICT,
    BALANCED,
    OFF,
    ;

    companion object {
        fun fromString(raw: String?): PrivacyMode = entries.firstOrNull { it.name.equals(raw, ignoreCase = true) } ?: BALANCED
    }
}

object Redaction {
    private val authHeaderRegex =
        Regex(
            "(?im)^(" +
                "authorization|proxy-authorization|" +
                "x-api-key|api-key|x-api-secret|api-secret|x-client-secret|" +
                "x-auth-token|auth-token|x-access-token|access-token|" +
                "x-session-token|session-token|x-csrf-token|csrf-token|x-xsrf-token" +
                "):\\s*.+$",
        )
    private val bearerRegex = Regex("(?i)bearer\\s+[A-Za-z0-9\\-\\._~\\+\\/]+=*")
    private val basicAuthRegex = Regex("(?i)basic\\s+[A-Za-z0-9\\+\\/=]+")
    private val cookieHeaderRegex = Regex("(?im)^cookie:\\s*.+$")
    private val setCookieHeaderRegex = Regex("(?im)^set-cookie:\\s*.+$")

    // very generic JWT-like pattern (not perfect by design)
    private val jwtRegex = Regex("\\beyJ[A-Za-z0-9_\\-]+\\.[A-Za-z0-9_\\-]+\\.[A-Za-z0-9_\\-]+\\b")

    // Tokens/secrets in URL query strings, e.g. ?access_token=xyz or &api_key=xyz
    private val urlTokenParamRegex =
        Regex(
            "(?i)([?&](access_token|api_key|apikey|auth|token|key|secret|password|pwd|session|sid|code)=)[^&\\s\"'<>]+",
        )

    private val hostHeaderRegex = Regex("(?im)^host:\\s*([^\\s]+)\\s*$")

    private val hostForwardMap = ConcurrentHashMap<String, ConcurrentHashMap<String, String>>()
    private val hostReverseMap = ConcurrentHashMap<String, ConcurrentHashMap<String, String>>()

    fun apply(
        raw: String,
        policy: RedactionPolicy,
        stableHostSalt: String,
        recordMapping: Boolean = true,
    ): String {
        var out = raw

        if (policy.stripCookies) {
            out = out.replace(cookieHeaderRegex, "Cookie: [STRIPPED]")
            out = out.replace(setCookieHeaderRegex, "Set-Cookie: [STRIPPED]")
        }

        if (policy.redactTokens) {
            out =
                out.replace(authHeaderRegex) { m ->
                    val header = m.value.substringBefore(":")
                    "$header: [REDACTED]"
                }
            out = out.replace(bearerRegex, "Bearer [REDACTED]")
            out = out.replace(basicAuthRegex, "Basic [REDACTED]")
            out = out.replace(jwtRegex, "[JWT_REDACTED]")
            out = out.replace(urlTokenParamRegex, "$1[REDACTED]")
        }

        if (policy.anonymizeHosts) {
            out =
                out.replace(hostHeaderRegex) { m ->
                    val host = m.groupValues[1]
                    val anon = anonymizeHost(host, stableHostSalt, recordMapping)
                    "Host: $anon"
                }
        }

        return out
    }

    fun anonymizeHost(
        host: String,
        salt: String,
        recordMapping: Boolean = true,
    ): String {
        val digest =
            MessageDigest
                .getInstance("SHA-256")
                .digest((salt + ":" + host).toByteArray(StandardCharsets.UTF_8))
        val short = digest.take(6).joinToString("") { "%02x".format(it) }
        val anon = "host-$short.local"
        if (recordMapping) {
            hostForwardMap.computeIfAbsent(salt) { ConcurrentHashMap() }[host] = anon
            hostReverseMap.computeIfAbsent(salt) { ConcurrentHashMap() }[anon] = host
        }
        return anon
    }

    fun deAnonymizeHost(
        host: String,
        salt: String,
    ): String? = hostReverseMap[salt]?.get(host)

    fun clearMappings(salt: String? = null) {
        if (salt == null) {
            hostForwardMap.clear()
            hostReverseMap.clear()
            return
        }
        hostForwardMap.remove(salt)
        hostReverseMap.remove(salt)
    }
}
