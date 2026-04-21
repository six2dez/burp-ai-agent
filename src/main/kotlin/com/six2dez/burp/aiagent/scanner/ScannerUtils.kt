package com.six2dez.burp.aiagent.scanner

object ScannerUtils {
    val HEADER_INJECTION_ALLOWLIST: Set<String> =
        setOf(
            "host",
            "origin",
            "referer",
            "x-forwarded-host",
            "x-forwarded-for",
            "x-host",
            "x-original-host",
        )
}
