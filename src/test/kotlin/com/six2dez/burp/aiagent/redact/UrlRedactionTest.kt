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
    fun schemeRelativeUrl_failsClosedInStrict() {
        // java.net.URI parses //host/... as a non-absolute network-path reference, so it takes the
        // fail-closed path, which must still find the //authority without a scheme.
        val parsed = UrlRedaction.redact("//admin:pw@api.realcorp.com:8443/x?access_token=SECRETQ9", strict, SALT)
        assertFalse(parsed.contains("realcorp", ignoreCase = true), parsed)
        assertFalse(parsed.contains("admin:pw"), parsed)
        assertFalse(parsed.contains("SECRETQ9"), parsed)
        assertEquals("//[REDACTED]@$alias:8443/x?access_token=[REDACTED]", parsed)
        assertEquals(parsed, UrlRedaction.redact(parsed, strict, SALT))

        val unparseable = UrlRedaction.redact("//api.realcorp.com/a b?access_token=SECRETQ9", strict, SALT)
        assertEquals("//$alias/a b?access_token=[REDACTED]", unparseable)
        assertEquals(unparseable, UrlRedaction.redact(unparseable, strict, SALT))
    }

    @Test
    fun schemeRelativeUrl_failsClosedInBalanced() {
        val url = "//admin:pw@api.realcorp.com:8443/x?access_token=SECRETQ9"
        val out = UrlRedaction.redact(url, RedactionPolicy.fromMode(PrivacyMode.BALANCED), SALT)

        assertFalse(out.contains("admin:pw"), out)
        assertFalse(out.contains("SECRETQ9"), out)
        assertEquals("//[REDACTED]@api.realcorp.com:8443/x?access_token=[REDACTED]", out)
    }

    @Test
    fun relativeUrlWithoutAuthority_losesItsTokenInStrictAndBalanced() {
        // No //authority, so there is no host to rewrite; the final apply still drops the token.
        for (policy in listOf(RedactionPolicy.fromMode(PrivacyMode.STRICT), balanced)) {
            val parsed = UrlRedaction.redact("/api/v1/me?access_token=SECRETQ9&x=1", policy, SALT)
            assertFalse(parsed.contains("SECRETQ9"), parsed)
            assertEquals("/api/v1/me?access_token=[REDACTED]&x=1", parsed)

            val unparseable = UrlRedaction.redact("/search?q={x}&access_token=SECRETQ9", policy, SALT)
            assertFalse(unparseable.contains("SECRETQ9"), unparseable)
            assertEquals("/search?q={x}&access_token=[REDACTED]", unparseable)
        }
    }

    @Test
    fun opaqueMailtoUri_hasNoHostToAliasAndLosesItsTokenInStrictAndBalanced() {
        // An opaque URI has no authority, so there is no URI host to alias. The address domain is
        // not a host under this redactor's model (Redaction.apply never aliases email domains
        // either), and the callers' own-host pass still aliases the item's own hostname.
        for (policy in listOf(RedactionPolicy.fromMode(PrivacyMode.STRICT), balanced)) {
            val out = UrlRedaction.redact("mailto:security@example.org?subject=hi&access_token=SECRETQ9", policy, SALT)
            assertFalse(out.contains("SECRETQ9"), out)
            assertEquals("mailto:security@example.org?subject=hi&access_token=[REDACTED]", out)
        }
    }

    @Test
    fun emptyHostAuthority_dropsUserinfoAndTokenInStrictAndBalanced() {
        // Unparseable (space in the path) with an empty host: the userinfo still goes, the port
        // stays, and there is no host to alias.
        for (policy in listOf(RedactionPolicy.fromMode(PrivacyMode.STRICT), balanced)) {
            val out = UrlRedaction.redact("http://admin:pw@:80/a b?access_token=SECRETQ9", policy, SALT)
            assertFalse(out.contains("admin:pw"), out)
            assertFalse(out.contains("SECRETQ9"), out)
            assertEquals("http://[REDACTED]@:80/a b?access_token=[REDACTED]", out)
        }
    }

    @Test
    fun unparsedIpv6Authority_isAliasedWholeInStrict() {
        val policy = RedactionPolicy.fromMode(PrivacyMode.STRICT)

        val closed = UrlRedaction.redact("http://admin:pw@[fd00::5]:8443/a b?access_token=SECRETQ9", policy, SALT)
        assertFalse(closed.contains("fd00"), closed)
        assertFalse(closed.contains("admin:pw"), closed)
        assertFalse(closed.contains("SECRETQ9"), closed)
        assertEquals(
            "http://[REDACTED]@" + Redaction.anonymizeHost("[fd00::5]", SALT) + ":8443/a b?access_token=[REDACTED]",
            closed,
        )

        // The whole malformed bracket run is one host, so no fragment of the address survives.
        val unclosed = UrlRedaction.redact("http://[fd00::5:8443/a b?access_token=SECRETQ9", policy, SALT)
        assertFalse(unclosed.contains("fd00"), unclosed)
        assertFalse(unclosed.contains("SECRETQ9"), unclosed)
        assertEquals(
            "http://" + Redaction.anonymizeHost("[fd00::5:8443", SALT) + "/a b?access_token=[REDACTED]",
            unclosed,
        )
    }

    @Test
    fun unparsedIpv6Authority_dropsUserinfoAndTokenInBalanced() {
        val policy = RedactionPolicy.fromMode(PrivacyMode.BALANCED)

        val closed = UrlRedaction.redact("http://admin:pw@[fd00::5]:8443/a b?access_token=SECRETQ9", policy, SALT)
        assertFalse(closed.contains("admin:pw"), closed)
        assertFalse(closed.contains("SECRETQ9"), closed)
        assertEquals("http://[REDACTED]@[fd00::5]:8443/a b?access_token=[REDACTED]", closed)

        val unclosed = UrlRedaction.redact("http://[fd00::5:8443/a b?access_token=SECRETQ9", policy, SALT)
        assertFalse(unclosed.contains("SECRETQ9"), unclosed)
        assertEquals("http://[fd00::5:8443/a b?access_token=[REDACTED]", unclosed)
    }

    @Test
    fun hostOnlyPolicy_aliasesEveryOwnHostOccurrenceAndLeavesUserinfoToTheTokenSwitch() {
        // No mode builds this policy; it isolates the host switch from the token switch. The own
        // host percent-encoded inside the kept userinfo is caught by the %XX boundary.
        val hostOnly = RedactionPolicy(stripCookies = true, redactTokens = false, anonymizeHosts = true)
        val out = UrlRedaction.redact("https://ops%40api.realcorp.com:pw@api.realcorp.com/x", hostOnly, SALT)

        assertFalse(out.contains("realcorp", ignoreCase = true), out)
        assertEquals("https://ops%40$alias:pw@$alias/x", out)
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
            "//admin:pw@api.realcorp.com:8443/x?access_token=SECRETQ9",
            "/api/v1/me?access_token=SECRETQ9&x=1",
            "/search?q={x}&access_token=SECRETQ9",
            "mailto:security@example.org?subject=hi&access_token=SECRETQ9",
            "http://admin:pw@:80/a b?access_token=SECRETQ9",
            "http://admin:pw@[fd00::5]:8443/a b?access_token=SECRETQ9",
            "http://[fd00::5:8443/a b?access_token=SECRETQ9",
            "https://ops%40api.realcorp.com:pw@api.realcorp.com/x",
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

    @Test
    fun hostOf_findsTheAuthorityOfASchemeRelativeUrl() {
        assertEquals(HOST, UrlRedaction.hostOf("//api.realcorp.com/a b"))
        assertEquals(HOST, UrlRedaction.hostOf("//admin:pw@api.realcorp.com:8443/x"))
    }

    @Test
    fun hostOf_failsClosedOnHostlessAndBracketedShapes() {
        assertNull(UrlRedaction.hostOf("mailto:security@example.org"))
        assertNull(UrlRedaction.hostOf("/search?q={x}"))
        // Parses with a null URI host; the prefix authority has an empty host.
        assertNull(UrlRedaction.hostOf("http://:80/a"))
        assertNull(UrlRedaction.hostOf("http://:80/a b"))
        assertEquals("[fd00::5]", UrlRedaction.hostOf("http://[fd00::5]:8443/a b"))
        assertEquals("[fd00::5:8443", UrlRedaction.hostOf("http://[fd00::5:8443/a b"))
    }

    private companion object {
        const val SALT = "jx2-url-salt"
        const val HOST = "api.realcorp.com"
    }
}
