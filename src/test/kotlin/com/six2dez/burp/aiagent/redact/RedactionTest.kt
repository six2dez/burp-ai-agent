package com.six2dez.burp.aiagent.redact

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

// RFC 5869 Test Case 1 inputs/outputs for the HKDF vector test.
// Source: https://www.rfc-editor.org/rfc/rfc5869 Appendix A.1
private object Rfc5869TestCase1 {
    // IKM = 22 bytes of 0x0b
    val ikm: ByteArray = ByteArray(22) { 0x0b.toByte() }

    // salt = 0x000102...0c (13 bytes)
    val salt: ByteArray = ByteArray(13) { i -> i.toByte() }

    // info = 0xf0f1...f9 (10 bytes)
    val info: ByteArray = ByteArray(10) { i -> (0xf0 + i).toByte() }

    val l = 42

    // Expected PRK (HMAC-SHA256 of salt over IKM):
    // 077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5
    val expectedPrk: ByteArray = byteArrayOf(
        0x07, 0x77, 0x09, 0x36, 0x2c, 0x2e, 0x32, 0xdf.toByte(),
        0x0d, 0xdc.toByte(), 0x3f, 0x0d, 0xc4.toByte(), 0x7b, 0xba.toByte(), 0x63,
        0x90.toByte(), 0xb6.toByte(), 0xc7.toByte(), 0x3b, 0xb5.toByte(), 0x0f, 0x9c.toByte(), 0x31,
        0x22, 0xec.toByte(), 0x84.toByte(), 0x4a, 0xd7.toByte(), 0xc2.toByte(), 0xb3.toByte(), 0xe5.toByte(),
    )

    // Expected OKM (first 42 bytes):
    // 3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf
    // 34007208d5b887185865
    val expectedOkm: ByteArray = byteArrayOf(
        0x3c, 0xb2.toByte(), 0x5f, 0x25, 0xfa.toByte(), 0xac.toByte(), 0xd5.toByte(), 0x7a,
        0x90.toByte(), 0x43, 0x4f, 0x64, 0xd0.toByte(), 0x36, 0x2f, 0x2a,
        0x2d, 0x2d, 0x0a, 0x90.toByte(), 0xcf.toByte(), 0x1a, 0x5a, 0x4c,
        0x5d, 0xb0.toByte(), 0x2d, 0x56, 0xec.toByte(), 0xc4.toByte(), 0xc5.toByte(), 0xbf.toByte(),
        0x34, 0x00, 0x72, 0x08, 0xd5.toByte(), 0xb8.toByte(), 0x87.toByte(), 0x18,
        0x58, 0x65,
    )
}

class RedactionTest {
    @Test
    fun strictModeStripsCookiesTokensAndHosts() {
        val input =
            """
            GET / HTTP/1.1
            Host: example.com
            Cookie: a=b
            Authorization: Bearer abc.def.ghi

            """.trimIndent()

        val policy = RedactionPolicy.fromMode(PrivacyMode.STRICT)
        val output = Redaction.apply(input, policy, stableHostSalt = "salt")

        assertTrue(output.contains("Cookie: [STRIPPED]"))
        assertTrue(output.contains("Authorization: [REDACTED]"))
        assertTrue(output.contains("Host: host-"))
    }

    @Test
    fun hostAnonymizationIsStablePerSalt() {
        val a = Redaction.anonymizeHost("example.com", "salt-a")
        val b = Redaction.anonymizeHost("example.com", "salt-a")
        val c = Redaction.anonymizeHost("example.com", "salt-b")

        assertEquals(a, b)
        assertTrue(a != c)
    }

    @Test
    fun balancedModeRedactsCustomAuthHeaders() {
        val input =
            """
            GET / HTTP/1.1
            Host: example.com
            X-Auth-Token: abc123
            X-Access-Token: xyz789
            X-CSRF-Token: csrf123
            X-Api-Secret: secret!
            Authorization: Basic dXNlcjpwYXNz

            """.trimIndent()

        val policy = RedactionPolicy.fromMode(PrivacyMode.BALANCED)
        val output = Redaction.apply(input, policy, stableHostSalt = "salt")

        assertTrue(output.contains("X-Auth-Token: [REDACTED]"), "X-Auth-Token must be redacted")
        assertTrue(output.contains("X-Access-Token: [REDACTED]"), "X-Access-Token must be redacted")
        assertTrue(output.contains("X-CSRF-Token: [REDACTED]"), "X-CSRF-Token must be redacted")
        assertTrue(output.contains("X-Api-Secret: [REDACTED]"), "X-Api-Secret must be redacted")
        assertTrue(output.contains("Authorization: [REDACTED]"), "Authorization header must be redacted")
        assertTrue(!output.contains("abc123") && !output.contains("xyz789") && !output.contains("dXNlcjpwYXNz"))
    }

    @Test
    fun balancedModeRedactsUrlTokensInQueryStrings() {
        val input =
            """
            GET /api/user?api_key=secret123&token=xyz987&name=alice HTTP/1.1
            Host: example.com
            Referer: https://example.com/callback?access_token=ABC.DEF.GHI&state=open

            """.trimIndent()

        val policy = RedactionPolicy.fromMode(PrivacyMode.BALANCED)
        val output = Redaction.apply(input, policy, stableHostSalt = "salt")

        assertTrue(output.contains("api_key=[REDACTED]"), "api_key query param must be redacted")
        assertTrue(output.contains("token=[REDACTED]"), "token query param must be redacted")
        assertTrue(output.contains("access_token=[REDACTED]"), "access_token query param must be redacted")
        assertTrue(output.contains("name=alice"), "non-sensitive params must not be touched")
        assertTrue(!output.contains("secret123") && !output.contains("xyz987") && !output.contains("ABC.DEF.GHI"))
    }

    @Test
    fun offModePreservesAllTokens() {
        val input =
            """
            GET /api?api_key=secret123 HTTP/1.1
            Authorization: Bearer TOKEN
            X-Auth-Token: abc

            """.trimIndent()
        val policy = RedactionPolicy.fromMode(PrivacyMode.OFF)
        val output = Redaction.apply(input, policy, stableHostSalt = "salt")

        assertTrue(output.contains("api_key=secret123"))
        assertTrue(output.contains("Bearer TOKEN"))
        assertTrue(output.contains("X-Auth-Token: abc"))
    }

    @Test
    fun clearMappings_removesOnlyRequestedSaltOrAll() {
        val anonA = Redaction.anonymizeHost("a.example", "salt-a")
        val anonB = Redaction.anonymizeHost("b.example", "salt-b")
        assertEquals("a.example", Redaction.deAnonymizeHost(anonA, "salt-a"))
        assertEquals("b.example", Redaction.deAnonymizeHost(anonB, "salt-b"))

        Redaction.clearMappings("salt-a")
        assertEquals(null, Redaction.deAnonymizeHost(anonA, "salt-a"))
        assertEquals("b.example", Redaction.deAnonymizeHost(anonB, "salt-b"))

        Redaction.clearMappings()
        assertEquals(null, Redaction.deAnonymizeHost(anonB, "salt-b"))
    }

    // PRIV-01: output format test — added for HKDF swap (Task 1 Wave 0 RED)
    @Test
    fun hostAnonymizationFormatIsStable() {
        val result = Redaction.anonymizeHost("example.com", "salt")
        // Assert format only — never hardcode the hex value so the crypto can evolve.
        assertTrue(
            result.matches(Regex("^host-[0-9a-f]{12}\\.local$")),
            "Expected format host-<12hex>.local but got: $result",
        )
    }

    // PRIV-01: RFC 5869 Test Case 1 HKDF vector — proves the HMAC-SHA256 extract/expand
    // math is correct against a published reference vector.
    // Source: https://www.rfc-editor.org/rfc/rfc5869 Appendix A.1
    @Test
    fun hkdfMatchesRfc5869Vector() {
        // Access the internal HKDF helpers via the test-internal seam exposed on Redaction.
        val prk = Redaction.testHkdfExtract(Rfc5869TestCase1.salt, Rfc5869TestCase1.ikm)
        assertEquals(
            Rfc5869TestCase1.expectedPrk.toList(),
            prk.toList(),
            "PRK must match RFC 5869 Test Case 1",
        )

        val okm = Redaction.testHkdfExpand(prk, Rfc5869TestCase1.info, Rfc5869TestCase1.l)
        assertEquals(
            Rfc5869TestCase1.expectedOkm.toList(),
            okm.toList(),
            "OKM must match RFC 5869 Test Case 1",
        )
    }
}
