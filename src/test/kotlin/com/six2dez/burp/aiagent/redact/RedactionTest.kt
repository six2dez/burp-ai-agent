package com.six2dez.burp.aiagent.redact

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

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
}
