package com.six2dez.burp.aiagent.util

import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class LoopbackHostTest {
    @Test
    fun loopbackLiteralsAndLocalhostAreLoopback() {
        listOf(
            "http://localhost:11434",
            "http://LOCALHOST/",
            "http://127.0.0.1:1234",
            "http://127.8.9.10/v1",
            "http://[::1]:8000",
            "http://[0:0:0:0:0:0:0:1]/",
            "http://[::ffff:127.0.0.1]/",
        ).forEach { assertTrue(LoopbackHost.isLoopbackUrl(it), "expected loopback: $it") }
    }

    @Test
    fun lanPublicLookalikesAndGarbageAreNotLoopback() {
        listOf(
            "http://10.0.0.5:8000",
            "http://192.168.1.10",
            "https://api.perplexity.ai",
            "https://integrate.api.nvidia.com",
            "http://localhost.evil.com",
            "http://127.0.0.1.nip.io",
            "http://[::2]/",
            "",
            "   ",
            "not a url",
            "localhost:11434",
        ).forEach { assertFalse(LoopbackHost.isLoopbackUrl(it), "expected NOT loopback: '$it'") }
    }
}
