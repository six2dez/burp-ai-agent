package com.six2dez.burp.aiagent.scanner

import com.six2dez.burp.aiagent.TestSettings
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test
import org.mockito.kotlin.argumentCaptor
import org.mockito.kotlin.atLeastOnce
import org.mockito.kotlin.mock
import org.mockito.kotlin.verify
import org.mockito.kotlin.verifyNoInteractions

/**
 * Quick 261009-d0i - short acronyms in a passive finding title match only as whole words ("ato" no
 * longer matches "Indicators", "rce" no longer matches "Source") and NoSQL is checked before SQL. The
 * class picked by `mapTitleToVulnClass` drives both the `[AI Passive]` issue name and what the AI
 * active scanner is auto-queued to test, so both are checked through the real code paths.
 */
class PassiveTitleClassifierTest {
    @Test
    fun shortTokensInsideOtherWordsNoLongerPickAClass() {
        PassiveScanCheckRig().use { rig ->
            assertEquals(emptyList<String>(), mismatches(rig, REGRESSION_ROWS))
        }
    }

    @Test
    fun titlesClassifiedCorrectlyTodayKeepTheirClass() {
        PassiveScanCheckRig().use { rig ->
            assertEquals(emptyList<String>(), mismatches(rig, KEEP_ROWS))
        }
    }

    @Test
    fun theFourLocalHeuristicTitlesMapToTheirOwnClass() {
        PassiveScanCheckRig().use { rig ->
            val smuggling = rig.pageGet("title-local-smuggling.example", smugglingIndicators = true)
            val csrf = rig.csrfPost("title-local-csrf.example")
            val smugglingTitle =
                rig.scanner
                    .localChecks(smuggling.request(), smuggling.response())
                    .single()
                    .title
            val csrfTitle =
                rig.scanner
                    .localChecks(csrf.request(), csrf.response())
                    .single()
                    .title
            val rows =
                listOf(
                    smugglingTitle to VulnClass.REQUEST_SMUGGLING,
                    csrfTitle to VulnClass.CSRF,
                    // Literal titles from PassiveAiScannerHeuristics.kt: the rig has no builder for these requests.
                    "Deserialization Surface Detected" to VulnClass.DESERIALIZATION,
                    "Unrestricted File Upload (Executable Extension)" to VulnClass.UNRESTRICTED_FILE_UPLOAD,
                )

            assertEquals(emptyList<String>(), mismatches(rig, rows))
        }
    }

    @Test
    fun theSmugglingFindingIsFiledUnderRequestSmuggling() {
        PassiveScanCheckRig().use { rig ->
            rig.scanner.setEnabled(true)

            rig.check.doCheck(rig.pageGet("title-smuggling.example", smugglingIndicators = true))
            rig.drain()

            assertEquals(listOf("[AI Passive] REQUEST_SMUGGLING"), rig.built.map { it.name })
            assertEquals("[AI Passive] SOURCEMAP_DISCLOSURE", rig.scanner.issueNameForPassive("JavaScript Source Map Exposed"))
            assertEquals("[AI Passive] NOSQL_INJECTION", rig.scanner.issueNameForPassive("NoSQL Injection"))
        }
    }

    @Test
    fun onlyTheRealClassIsAutoQueuedToTheActiveScanner() {
        val settings =
            TestSettings.baselineSettings().copy(
                passiveAiEnabled = true,
                passiveAiScopeOnly = false,
                activeAiEnabled = true,
                activeAiAutoFromPassive = true,
                activeAiScanMode = ScanMode.FULL,
            )
        PassiveScanCheckRig(settings).use { rig ->
            val active = mock<ActiveAiScanner>()
            rig.scanner.activeScanner = active
            val unrelated =
                listOf(
                    "HTTP Request Smuggling Indicators" to "queue-smuggling.example",
                    "JavaScript Source Map Exposed" to "queue-sourcemap.example",
                    "Missing Brute Force Protection" to "queue-bruteforce.example",
                )

            for ((title, host) in unrelated) {
                rig.scanner.queueToActiveScanner(rig.csrfPost(host), title, "Medium", "evidence", 90, rig.settings)
            }
            verifyNoInteractions(active)

            rig.scanner.queueToActiveScanner(rig.csrfPost("queue-sqli.example"), "SQL Injection", "Medium", "evidence", 90, rig.settings)
            val targets = argumentCaptor<ActiveScanTarget>()
            verify(active, atLeastOnce()).queueTarget(targets.capture())
            assertEquals(setOf(VulnClass.SQLI), targets.allValues.map { it.vulnHint.vulnClass }.toSet())
        }
    }

    private fun mismatches(
        rig: PassiveScanCheckRig,
        rows: List<Pair<String, VulnClass?>>,
    ): List<String> =
        rows.mapNotNull { (title, expected) ->
            val actual = rig.scanner.mapTitleToVulnClass(title)
            if (actual == expected) null else "$title -> $actual (expected $expected)"
        }

    private companion object {
        /** Titles where a short token sat inside another word, or NoSQL lost to SQL. */
        val REGRESSION_ROWS: List<Pair<String, VulnClass?>> =
            listOf(
                "Input Validator Bypass" to null,
                "Open Redirect via Locator Parameter" to VulnClass.OPEN_REDIRECT,
                "Authenticator Misconfiguration" to null,
                "Moderator Panel Exposed" to null,
                "Template Generator Disclosure" to null,
                "Spring Boot Actuator Exposed" to VulnClass.DEBUG_EXPOSURE,
                "JavaScript Source Map Exposed" to VulnClass.SOURCEMAP_DISCLOSURE,
                "Exposed Source Code" to null,
                "Insecure Resource Sharing" to null,
                "Cross-Origin Resource Sharing (CORS) Misconfiguration" to VulnClass.CORS_MISCONFIGURATION,
                "Missing Brute Force Protection" to null,
                "Weak Password Policy Enforcement" to null,
                "Ecommerce Cart Tampering" to null,
                "NoSQL Injection" to VulnClass.NOSQL_INJECTION,
                "MongoDB NoSQL Operator Injection" to VulnClass.NOSQL_INJECTION,
                "NoSQL Injection in Database Query" to VulnClass.NOSQL_INJECTION,
                "Associated Session Bypass" to null,
                "Corridor Access" to null,
            )

        /** Titles classified correctly before the fix; they guard plurals, `_` boundaries, SQLi, dialects and long words. */
        val KEEP_ROWS: List<Pair<String, VulnClass?>> =
            listOf(
                "Remote Code Execution (RCE)" to VulnClass.CMDI,
                "OS Command Injection" to VulnClass.CMDI,
                "Pre-auth RCE" to VulnClass.CMDI,
                "Account Takeover via Password Reset" to VulnClass.ACCOUNT_TAKEOVER,
                "ATO via Email Change" to VulnClass.ACCOUNT_TAKEOVER,
                "Single Sign-On (SSO) Bypass" to VulnClass.OAUTH_MISCONFIGURATION,
                "AWS S3 Bucket Exposed" to VulnClass.S3_MISCONFIGURATION,
                "Price Manipulation" to VulnClass.PRICE_MANIPULATION,
                "Self-Inflicted XSS" to VulnClass.XSS_REFLECTED,
                "Stored-XSS in Comments" to VulnClass.XSS_REFLECTED,
                "SQL Injection" to VulnClass.SQLI,
                "Time-based SQL-Injection" to VulnClass.SQLI,
                "Blind SQLi in Search Parameter" to VulnClass.SQLI,
                "Verbose Error Message (MySQL)" to VulnClass.SQLI,
                "PostgreSQL Error Disclosure" to VulnClass.SQLI,
                "MSSQL Error Message" to VulnClass.SQLI,
                "SQLite Error Disclosure" to VulnClass.SQLI,
                "LFI via Path Parameter" to VulnClass.LFI,
                "SSTI in Jinja2 Template" to VulnClass.SSTI,
                "Blind SSRF via Webhook" to VulnClass.SSRF,
                "XXE Injection" to VulnClass.XXE,
                "LDAP Injection" to VulnClass.LDAP_INJECTION,
                "BOLA on Orders API" to VulnClass.BOLA,
                "IDORs on Order Endpoints" to VulnClass.IDOR,
                "BFLA on Admin Endpoint" to VulnClass.BFLA,
                "2FA Bypass" to VulnClass.MFA_BYPASS,
                "MFA Bypass" to VulnClass.MFA_BYPASS,
                "JWTs Signed With None Algorithm" to VulnClass.JWT_WEAKNESS,
                "jwt_secret Exposed" to VulnClass.JWT_WEAKNESS,
                "Anti-CSRF Token Missing" to VulnClass.CSRF,
                "CRLF Injection" to VulnClass.HEADER_INJECTION,
                "CORS Misconfiguration" to VulnClass.CORS_MISCONFIGURATION,
                "TOCTOU Race in Checkout" to VulnClass.RACE_CONDITION_TOCTOU,
                "Debugging Enabled" to VulnClass.DEBUG_EXPOSURE,
                "Exposed .git Directory" to VulnClass.GIT_EXPOSURE,
                "Missing HSTS Header" to null,
                "Session Fixation" to null,
            )
    }
}
