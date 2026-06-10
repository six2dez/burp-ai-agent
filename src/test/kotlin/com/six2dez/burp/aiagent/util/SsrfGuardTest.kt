package com.six2dez.burp.aiagent.util

import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class SsrfGuardTest {
    @Test
    fun rfc1918_192_168_isFlagged() {
        assertTrue(SsrfGuard.isPrivateOrLinkLocal("http://192.168.1.10/api"))
    }

    @Test
    fun rfc1918_10_isFlagged() {
        assertTrue(SsrfGuard.isPrivateOrLinkLocal("http://10.0.0.1:8080"))
    }

    @Test
    fun rfc1918_172_16_isFlagged() {
        assertTrue(SsrfGuard.isPrivateOrLinkLocal("http://172.16.0.1"))
    }

    @Test
    fun cloudMetadata_169_254_169_254_isFlagged() {
        assertTrue(SsrfGuard.isPrivateOrLinkLocal("http://169.254.169.254/latest/meta-data/"))
    }

    @Test
    fun ipv6LinkLocal_fe80_isFlagged() {
        assertTrue(SsrfGuard.isPrivateOrLinkLocal("http://fe80::1"))
    }

    @Test
    fun loopback_127_isNotFlagged() {
        assertFalse(SsrfGuard.isPrivateOrLinkLocal("http://127.0.0.1:11434"))
    }

    @Test
    fun publicHost_isNotFlagged() {
        assertFalse(SsrfGuard.isPrivateOrLinkLocal("https://api.openai.com"))
    }

    @Test
    fun blankInput_isNotFlagged() {
        assertFalse(SsrfGuard.isPrivateOrLinkLocal(""))
    }

    @Test
    fun malformedInput_isNotFlagged_noException() {
        assertFalse(SsrfGuard.isPrivateOrLinkLocal("not-a-url"))
    }
}
