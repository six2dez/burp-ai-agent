package com.six2dez.burp.aiagent.redact

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

/**
 * Mode matrix, fail-closed, boundary and alias round-trip tests for [UrlRedaction]
 * (quick task 261008-jx2).
 *
 * Survival-sweep discipline: functions naming a redacting mode assert absence or the exact
 * redacted string; pass-through assertions live in OFF-only functions.
 */
class UrlRedactionTest {
    private val strict = RedactionPolicy.fromMode(PrivacyMode.STRICT)
    private val balanced = RedactionPolicy.fromMode(PrivacyMode.BALANCED)
    private val alias get() = Redaction.anonymizeHost(HOST, SALT)

    @Test
    fun queryToken_isRedactedInBalancedAndStrict() {
        val url = "https://api.realcorp.com/api/v1/me?access_token=SECRETQ9&x=1"

        assertEquals(
            "https://api.realcorp.com/api/v1/me?access_token=[REDACTED]&x=1",
            UrlRedaction.redact(url, RedactionPolicy.fromMode(PrivacyMode.BALANCED), SALT),
        )
        assertEquals(
            "https://$alias/api/v1/me?access_token=[REDACTED]&x=1",
            UrlRedaction.redact(url, RedactionPolicy.fromMode(PrivacyMode.STRICT), SALT),
        )
    }

    @Test
    fun userinfo_isDroppedInBalancedAndStrict() {
        val url = "https://admin:S3cr3t@api.realcorp.com/x"

        assertEquals("https://[REDACTED]@api.realcorp.com/x", UrlRedaction.redact(url, balanced, SALT))
        assertEquals("https://[REDACTED]@$alias/x", UrlRedaction.redact(url, strict, SALT))
    }

    @Test
    fun nonDefaultPort_isKeptInStrict() {
        assertEquals(
            "https://$alias:8443/x?y=1",
            UrlRedaction.redact("https://api.realcorp.com:8443/x?y=1", strict, SALT),
        )
    }

    @Test
    fun upperCaseHost_getsTheLowercaseAliasInStrict() {
        val out = UrlRedaction.redact("https://API.RealCorp.COM/x", RedactionPolicy.fromMode(PrivacyMode.STRICT), SALT)

        assertEquals("https://$alias/x", out)
        assertFalse(out.contains("realcorp", ignoreCase = true), out)
    }

    @Test
    fun fragment_isPreservedWhenBenignAndRedactedWhenItCarriesATokenInBalanced() {
        val benign = "https://api.realcorp.com/x#section-2"
        assertEquals(benign, UrlRedaction.redact(benign, balanced, SALT))

        val implicitFlow = "https://api.realcorp.com/cb#access_token=SECRETF1&token_type=bearer"
        val out = UrlRedaction.redact(implicitFlow, RedactionPolicy.fromMode(PrivacyMode.BALANCED), SALT)
        assertFalse(out.contains("SECRETF1"), out)
        assertTrue(out.startsWith("https://api.realcorp.com/cb#access_token=[REDACTED]"), out)
    }

    @Test
    fun fragment_tokenIsRedactedInStrict() {
        val implicitFlow = "https://api.realcorp.com/cb#access_token=SECRETF1&token_type=bearer"
        val out = UrlRedaction.redact(implicitFlow, RedactionPolicy.fromMode(PrivacyMode.STRICT), SALT)

        assertFalse(out.contains("SECRETF1"), out)
        assertFalse(out.contains("realcorp", ignoreCase = true), out)
        assertTrue(out.startsWith("https://$alias/cb#access_token=[REDACTED]"), out)
    }

    @Test
    fun percentEncoding_isPreservedByteForByteInBalanced() {
        val url = "https://api.realcorp.com/a%20b/%2F?q=%41"

        assertEquals(url, UrlRedaction.redact(url, RedactionPolicy.fromMode(PrivacyMode.BALANCED), SALT))
    }

    @Test
    fun unparseableUrl_failsClosedInStrict() {
        val braces = "https://api.realcorp.com/search?q={x}&access_token=SECRETQ9"
        val braced = UrlRedaction.redact(braces, RedactionPolicy.fromMode(PrivacyMode.STRICT), SALT)
        assertEquals("https://$alias/search?q={x}&access_token=[REDACTED]", braced)

        val spaced = "https://admin:pw@api.realcorp.com:8443/a b?access_token=SECRETQ9"
        val out = UrlRedaction.redact(spaced, strict, SALT)
        assertFalse(out.contains("realcorp", ignoreCase = true), out)
        assertFalse(out.contains("SECRETQ9"), out)
        assertFalse(out.contains("admin:pw"), out)
        assertEquals("https://[REDACTED]@$alias:8443/a b?access_token=[REDACTED]", out)
    }

    @Test
    fun unparseableUrl_failsClosedInBalanced() {
        val spaced = "https://admin:pw@api.realcorp.com:8443/a b?access_token=SECRETQ9"
        val out = UrlRedaction.redact(spaced, RedactionPolicy.fromMode(PrivacyMode.BALANCED), SALT)

        assertFalse(out.contains("SECRETQ9"), out)
        assertFalse(out.contains("admin:pw"), out)
        assertEquals("https://[REDACTED]@api.realcorp.com:8443/a b?access_token=[REDACTED]", out)
    }

    @Test
    fun registryAuthorityWithoutUriHost_failsClosedInStrict() {
        // java.net.URI parses this but reports a null host (underscore in a registry authority).
        val url = "https://my_host.realcorp.com/x?token=SECRETQ9"
        val out = UrlRedaction.redact(url, RedactionPolicy.fromMode(PrivacyMode.STRICT), SALT)

        assertFalse(out.contains("realcorp", ignoreCase = true), out)
        assertFalse(out.contains("SECRETQ9"), out)
    }

    @Test
    fun ownHostInsideAnEncodedQueryValue_isAliasedInStrict() {
        val url = "https://api.realcorp.com/login?next=https%3A%2F%2Fapi.realcorp.com%2Fhome"
        val out = UrlRedaction.redact(url, RedactionPolicy.fromMode(PrivacyMode.STRICT), SALT)

        assertFalse(out.contains("realcorp", ignoreCase = true), out)
        assertEquals("https://$alias/login?next=https%3A%2F%2F$alias%2Fhome", out)
    }

    @Test
    fun strictRedaction_isIdempotent() {
        val policy = RedactionPolicy.fromMode(PrivacyMode.STRICT)
        for (url in listOf(
            "https://api.realcorp.com/api/v1/me?access_token=SECRETQ9&x=1",
            "https://admin:S3cr3t@api.realcorp.com:8443/x#access_token=SECRETF1",
            "https://api.realcorp.com/login?next=https%3A%2F%2Fapi.realcorp.com%2Fhome",
        )) {
            val once = UrlRedaction.redact(url, policy, SALT)
            assertEquals(once, UrlRedaction.redact(once, policy, SALT), url)
        }
    }

    @Test
    fun offMode_isByteIdenticalWithoutCustomPatterns() {
        val off = RedactionPolicy.fromMode(PrivacyMode.OFF)
        for (url in listOf(
            "https://admin:S3cr3t@api.realcorp.com:8443/api/v1/me?access_token=SECRETQ9&x=1#frag",
            "https://api.realcorp.com/search?q={x}",
            "not a url at all",
        )) {
            assertEquals(url, UrlRedaction.redact(url, off, SALT))
        }
    }

    @Test
    fun offMode_appliesCustomPatterns() {
        Redaction.setCustomPatterns(listOf("SECRETQ9"))
        try {
            val out =
                UrlRedaction.redact(
                    "https://api.realcorp.com/api/v1/me?access_token=SECRETQ9&x=1",
                    RedactionPolicy.fromMode(PrivacyMode.OFF),
                    SALT,
                )
            assertFalse(out.contains("SECRETQ9"), out)
            assertEquals("https://api.realcorp.com/api/v1/me?access_token=[REDACTED]&x=1", out)
        } finally {
            Redaction.setCustomPatterns(emptyList())
        }
    }

    @Test
    fun anonymizeHostOccurrences_respectsLabelBoundaries() {
        val a = alias
        assertEquals("myapi.realcorp.com", UrlRedaction.anonymizeHostOccurrences("myapi.realcorp.com", HOST, SALT))
        assertEquals("api.realcorp.company", UrlRedaction.anonymizeHostOccurrences("api.realcorp.company", HOST, SALT))
        assertEquals("www.$a", UrlRedaction.anonymizeHostOccurrences("www.api.realcorp.com", HOST, SALT))
        assertEquals("$a:443", UrlRedaction.anonymizeHostOccurrences("api.realcorp.com:443", HOST, SALT))
        assertEquals(a, UrlRedaction.anonymizeHostOccurrences("API.REALCORP.COM", HOST, SALT))
        assertEquals(
            "Referer: https://$a/hr/x\r\nOrigin: https://$a",
            UrlRedaction.anonymizeHostOccurrences("Referer: https://api.realcorp.com/hr/x\r\nOrigin: https://api.realcorp.com", HOST, SALT),
        )
    }

    @Test
    fun anonymizeHostOccurrences_catchesPercentEncodedUrls() {
        val encoded = UrlRedaction.anonymizeHostOccurrences("https%3A%2F%2Fapi.realcorp.com%2Fcb", HOST, SALT)
        assertTrue(encoded.contains(alias), encoded)
        assertFalse(encoded.contains("realcorp", ignoreCase = true), encoded)

        val doubleEncoded = UrlRedaction.anonymizeHostOccurrences("https%253A%252F%252Fapi.realcorp.com%252Fcb", HOST, SALT)
        assertFalse(doubleEncoded.contains("realcorp", ignoreCase = true), doubleEncoded)
    }

    @Test
    fun anonymizeHostOccurrences_leavesTextAloneForBlankOrAliasShapedHost() {
        val text = "Referer: https://api.realcorp.com/x"
        assertEquals(text, UrlRedaction.anonymizeHostOccurrences(text, "", SALT))
        assertEquals(text, UrlRedaction.anonymizeHostOccurrences(text, "  ", SALT))

        val a = alias
        val aliased = "Referer: https://$a/x"
        assertEquals(aliased, UrlRedaction.anonymizeHostOccurrences(aliased, a, SALT))
    }

    @Test
    fun aliasHost_roundTripsThroughTheReverseMapping() {
        val a = UrlRedaction.aliasHost(HOST, SALT)

        assertEquals(Redaction.anonymizeHost(HOST, SALT), a)
        assertEquals(HOST, Redaction.deAnonymizeHost(a, SALT))
        assertEquals(a, UrlRedaction.aliasHost(a, SALT))
        assertEquals(a, UrlRedaction.aliasHost("API.RealCorp.COM", SALT))
    }

    @Test
    fun hostOf_extractsTheHostOrReturnsNull() {
        assertEquals(HOST, UrlRedaction.hostOf("https://api.realcorp.com:8443/x?y=1"))
        assertEquals(HOST, UrlRedaction.hostOf("https://admin:pw@api.realcorp.com:8443/a b"))
        assertEquals("my_host.realcorp.com", UrlRedaction.hostOf("https://my_host.realcorp.com/x"))
        assertEquals("[::1]", UrlRedaction.hostOf("http://[::1]:8080/x"))
        assertNull(UrlRedaction.hostOf("/relative/path"))
        assertNull(UrlRedaction.hostOf(null))
        assertNull(UrlRedaction.hostOf(""))
    }

    private companion object {
        const val SALT = "jx2-url-salt"
        const val HOST = "api.realcorp.com"
    }
}
