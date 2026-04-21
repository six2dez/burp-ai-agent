package com.six2dez.burp.aiagent.audit

import java.nio.charset.StandardCharsets
import java.security.MessageDigest

object Hashing {
    fun sha256Hex(value: String): String {
        val d =
            MessageDigest
                .getInstance("SHA-256")
                .digest(value.toByteArray(StandardCharsets.UTF_8))
        return d.joinToString("") { "%02x".format(it) }
    }
}
