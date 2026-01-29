package com.six2dez.burp.aiagent.util

object HeaderParser {
    fun parse(raw: String): Map<String, String> {
        if (raw.isBlank()) return emptyMap()
        val out = LinkedHashMap<String, String>()
        raw.lineSequence().forEach { line ->
            val trimmed = line.trim()
            if (trimmed.isEmpty()) return@forEach
            val idx = trimmed.indexOf(':')
            if (idx <= 0 || idx == trimmed.length - 1) return@forEach
            val name = trimmed.substring(0, idx).trim()
            val value = trimmed.substring(idx + 1).trim()
            if (name.isNotEmpty() && value.isNotEmpty()) {
                out[name] = value
            }
        }
        return out
    }

    fun withBearerToken(apiKey: String, headers: Map<String, String>): Map<String, String> {
        if (apiKey.isBlank()) return headers
        val hasAuth = headers.keys.any { it.equals("authorization", ignoreCase = true) }
        if (hasAuth) return headers
        val merged = LinkedHashMap<String, String>()
        merged.putAll(headers)
        merged["Authorization"] = "Bearer ${apiKey.trim()}"
        return merged
    }
}
