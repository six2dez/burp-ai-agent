package com.six2dez.burp.aiagent.scanner

fun canonicalIssueName(name: String): String {
    return name
        .trim()
        .replace(Regex("^\\[(?:AI(?:\\s+(?:Passive|Active))?)\\]\\s*", RegexOption.IGNORE_CASE), "")
        .trim()
        .lowercase()
}

object ScannerUtils {
    val HEADER_INJECTION_ALLOWLIST: Set<String> = setOf(
        "host",
        "origin",
        "referer",
        "x-forwarded-host",
        "x-forwarded-for",
        "x-host",
        "x-original-host"
    )
}
