package com.six2dez.burp.aiagent.redact

import com.six2dez.burp.aiagent.config.Defaults
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
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
    @AfterEach
    fun resetCustomPatterns() {
        // Prevent custom-pattern bleed across tests: reset after each test.
        Redaction.setCustomPatterns(emptyList())
    }

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

    // PRIV-02: Leading x-www-form-urlencoded field (no leading ?/&) must be redacted in STRICT
    // and BALANCED. This is the documented gap: the old [?&]-only urlTokenParamRegex missed the
    // first field of a body like apikey=sk-abc123&user=bob.
    @Test
    fun bodyFormLeadingFieldRedacted() {
        val body = "apikey=sk-abc123&user=bob"

        for (mode in listOf(PrivacyMode.STRICT, PrivacyMode.BALANCED)) {
            val policy = RedactionPolicy.fromMode(mode)
            val output = Redaction.apply(body, policy, stableHostSalt = "salt")
            assertTrue(output.contains("apikey=[REDACTED]"), "$mode: leading form field apikey must be redacted")
            assertTrue(output.contains("user=bob"), "$mode: non-sensitive param user must NOT be touched")
            assertFalse(output.contains("sk-abc123"), "$mode: original secret value must not appear")
        }
    }

    // PRIV-02: Known-sensitive JSON keys must be redacted (key-scoped — only the value under
    // a sensitive key name is replaced). Non-sensitive keys must be left untouched.
    @Test
    fun bodyJsonSecretKeysRedacted() {
        val body = """{"api_key":"sk-xyz","name":"alice","token":"abc"}"""

        for (mode in listOf(PrivacyMode.STRICT, PrivacyMode.BALANCED)) {
            val policy = RedactionPolicy.fromMode(mode)
            val output = Redaction.apply(body, policy, stableHostSalt = "salt")
            assertTrue(output.contains("\"api_key\":\"[REDACTED]\""), "$mode: api_key JSON value must be redacted")
            assertTrue(output.contains("\"token\":\"[REDACTED]\""), "$mode: token JSON value must be redacted")
            assertTrue(output.contains("\"name\":\"alice\""), "$mode: non-sensitive name key must NOT be touched")
            assertFalse(output.contains("sk-xyz"), "$mode: original api_key value must not appear")
            assertFalse(output.contains("\"abc\""), "$mode: original token value must not appear")
        }
    }

    // PRIV-02: OFF mode must leave bodies completely untouched — no form-body or JSON redaction.
    @Test
    fun offModePreservesBodies() {
        val formBody = "apikey=sk-abc123&user=bob"
        val jsonBody = """{"api_key":"sk-xyz","name":"alice","token":"abc"}"""

        val policy = RedactionPolicy.fromMode(PrivacyMode.OFF)

        val formOutput = Redaction.apply(formBody, policy, stableHostSalt = "salt")
        assertEquals(formBody, formOutput, "OFF mode must not touch form body")

        val jsonOutput = Redaction.apply(jsonBody, policy, stableHostSalt = "salt")
        assertEquals(jsonBody, jsonOutput, "OFF mode must not touch JSON body")
    }

    // PRIV-02: User-supplied custom pattern applied in STRICT and BALANCED, inactive in OFF.
    // The test resets patterns in @AfterEach to avoid cross-test bleed.
    @Test
    fun customPatternRedactsInStrictAndBalanced() {
        Redaction.setCustomPatterns(listOf("\\bSECRET-\\d{4}\\b"))

        val input = "Content: SECRET-1234 is the value"

        for (mode in listOf(PrivacyMode.STRICT, PrivacyMode.BALANCED)) {
            val policy = RedactionPolicy.fromMode(mode)
            val output = Redaction.apply(input, policy, stableHostSalt = "salt")
            assertTrue(output.contains("[REDACTED]"), "$mode: custom pattern must redact SECRET-1234")
            assertFalse(output.contains("SECRET-1234"), "$mode: original value must not appear after redaction")
        }

        // OFF mode: custom patterns are in the redactTokens branch — inactive in OFF.
        val offPolicy = RedactionPolicy.fromMode(PrivacyMode.OFF)
        val offOutput = Redaction.apply(input, offPolicy, stableHostSalt = "salt")
        assertEquals(input, offOutput, "OFF mode must not apply custom patterns")
    }

    // PRIV-02 / CR-01: regression — custom patterns carried on a loaded settings object must
    // become active when seeded into the engine (the App.initialize startup step), NOT only
    // after a manual re-save. The previous bug was that App.initialize never called
    // setCustomPatterns(settings.customRedactionPatterns), so on every Burp launch the live
    // custom-pattern list silently reset to empty and configured secrets leaked to the backend.
    // This exercises the load -> seed -> apply contract that App.kt now relies on, using a
    // pattern sourced from a settings object rather than set directly inline.
    @Test
    fun customPatternsFromSettingsAreActiveAfterSeeding() {
        // Stands in for AgentSettings.customRedactionPatterns as returned by
        // AgentSettingsRepository.load() — the persisted, save-validated pattern list that
        // App.initialize must push into the engine at startup.
        val persistedPatterns = listOf("\\bINTERNAL-[A-Z0-9]{6}\\b")

        // Sanity: the engine starts with NO custom patterns active (simulating a fresh launch
        // before the seeding step). The pattern must NOT redact yet.
        Redaction.setCustomPatterns(emptyList())
        val input = "Leak check: INTERNAL-ABC123 must be stripped"
        val strict = RedactionPolicy.fromMode(PrivacyMode.STRICT)
        val beforeSeed = Redaction.apply(input, strict, stableHostSalt = "salt")
        assertTrue(beforeSeed.contains("INTERNAL-ABC123"), "Pre-seed: custom pattern must be inactive")

        // The App.initialize seeding step: push the loaded settings' patterns into the engine.
        // This is exactly Redaction.setCustomPatterns(settings.customRedactionPatterns).
        Redaction.setCustomPatterns(persistedPatterns)

        val afterSeed = Redaction.apply(input, strict, stableHostSalt = "salt")
        assertTrue(afterSeed.contains("[REDACTED]"), "Post-seed: loaded custom pattern must redact")
        assertFalse(afterSeed.contains("INTERNAL-ABC123"), "Post-seed: original secret must not appear")
    }

    // PRIV-02: A body larger than Defaults.MAX_REDACTION_BODY_CHARS must be short-circuited.
    // The body-stage redaction is skipped; the call must return promptly and not throw.
    // The over-cap secret may remain (documented size-cap behaviour).
    @Test
    fun oversizeBodySkippedSafely() {
        // Generate a body larger than the cap (cap is ~1 MB = 1_000_000 chars).
        val oversizeBody = "apikey=" + "x".repeat(Defaults.MAX_REDACTION_BODY_CHARS + 10)
        val policy = RedactionPolicy.fromMode(PrivacyMode.STRICT)

        // The primary assertion: the call must return without throwing or hanging.
        val start = System.currentTimeMillis()
        val output = Redaction.apply(oversizeBody, policy, stableHostSalt = "salt")
        val elapsed = System.currentTimeMillis() - start

        // Should return in well under a second (body stage is skipped entirely).
        assertTrue(elapsed < 5_000, "Oversize body must short-circuit quickly; took ${elapsed}ms")
        // The output must be a string (not null, not empty) — the call completed.
        assertTrue(output.isNotEmpty(), "Output must be non-empty even when oversize body is skipped")
    }
}
