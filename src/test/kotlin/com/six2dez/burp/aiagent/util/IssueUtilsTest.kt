package com.six2dez.burp.aiagent.util

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class IssueUtilsTest {
    @Test
    fun canonicalIssueName_stripsAiPrefixesAndNormalizesCase() {
        assertEquals("sql injection", IssueUtils.canonicalIssueName("[AI] SQL Injection"))
        assertEquals("sql injection", IssueUtils.canonicalIssueName("[AI Passive] sql injection"))
        assertEquals("idor", IssueUtils.canonicalIssueName("  [ai] IDOR  "))
    }

    @Test
    fun hasEquivalentIssue_matchesCanonicalNameOnSameBaseUrl() {
        val issues =
            listOf(
                "[AI Passive] SQL Injection" to "https://example.test/path",
                "Other issue" to "https://example.test/other",
            )

        assertTrue(IssueUtils.hasEquivalentIssue("[AI] sql injection", "https://example.test/path", issues))
        assertFalse(IssueUtils.hasEquivalentIssue("[AI] sql injection", "https://example.test/other", issues))
    }

    @Test
    fun formatIssueDetailHtml_escapesHtmlAndPreservesIndentedPrefix() {
        val html = IssueUtils.formatIssueDetailHtml(listOf("line<1>", "  indented & value"))
        assertTrue(html.contains("line&lt;1&gt;"))
        assertTrue(html.contains("&nbsp;&nbsp;indented &amp; value"))
    }
}
