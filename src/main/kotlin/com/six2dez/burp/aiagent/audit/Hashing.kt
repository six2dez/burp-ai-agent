package com.six2dez.burp.aiagent.audit

import java.nio.charset.StandardCharsets
import java.security.MessageDigest

object Hashing {
    fun sha256Hex(value: String): String = sha256Hex(value.toByteArray(StandardCharsets.UTF_8))

    fun sha256Hex(bytes: ByteArray): String {
        val d =
            MessageDigest
                .getInstance("SHA-256")
                .digest(bytes)
        return d.joinToString("") { "%02x".format(it) }
    }
}
