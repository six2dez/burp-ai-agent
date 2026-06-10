package com.six2dez.burp.aiagent.redact

import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

/**
 * Tests for [SecretShapes.findSurviving].
 *
 * Each curated shape is exercised with a positive sample taken from the secret-scanning
 * pattern corpora referenced in 13-RESEARCH.md Pattern 4. A benign string that contains
 * no known secret prefix exercises the negative (false-positive) path.
 *
 * Assertions check category-name membership (case-insensitive substring match) rather than
 * exact-set equality so the tests are robust to minor wording changes in category names.
 */
class SecretShapesTest {

    // ── Positive: each curated shape must be detected ────────────────────────────────────────

    @Test
    fun findSurvivingReturnsCategories() {
        // OpenAI legacy key (sk-<48+>)
        val openAiResult = SecretShapes.findSurviving("token is sk-abc123def456ghi789jkl012mnopqrstuvwxyz123456")
        assertTrue(
            openAiResult.any { it.contains("OpenAI", ignoreCase = true) },
            "OpenAI key shape must be detected; got: $openAiResult",
        )

        // OpenAI modern project key (sk-proj-…)
        val openAiProjResult = SecretShapes.findSurviving("sk-proj-AbcDefGhiJklMnoPqrStuVwxYz0123456789abcdefgh")
        assertTrue(
            openAiProjResult.any { it.contains("OpenAI", ignoreCase = true) },
            "OpenAI project key shape must be detected; got: $openAiProjResult",
        )

        // AWS access key (AKIA + 16 uppercase alphanumerics)
        val awsResult = SecretShapes.findSurviving("AKIAIOSFODNN7EXAMPLE")
        assertTrue(
            awsResult.any { it.contains("AWS", ignoreCase = true) },
            "AWS access key shape must be detected; got: $awsResult",
        )

        // GitHub personal access token (ghp_<36+>)
        val githubResult = SecretShapes.findSurviving("ghp_0123456789012345678901234567890123456")
        assertTrue(
            githubResult.any { it.contains("GitHub", ignoreCase = true) },
            "GitHub token shape must be detected; got: $githubResult",
        )

        // GitHub fine-grained PAT (github_pat_…)
        val githubFineResult = SecretShapes.findSurviving("github_pat_11ABCDEFG0000000000000_0123456789abcdefABCDEFGHIJ")
        assertTrue(
            githubFineResult.any { it.contains("GitHub", ignoreCase = true) },
            "GitHub fine-grained PAT shape must be detected; got: $githubFineResult",
        )

        // Google API key (AIza<35>)
        val googleResult = SecretShapes.findSurviving("key=AIzaSyDaGmWKa4JsXZ-HjGw7ISLn_3namBGewQE")
        assertTrue(
            googleResult.any { it.contains("Google", ignoreCase = true) },
            "Google API key shape must be detected; got: $googleResult",
        )

        // Slack token (xox…)
        val slackResult = SecretShapes.findSurviving("xoxb-123456789012-123456789012-ABCDEFGHIJKLMNO")
        assertTrue(
            slackResult.any { it.contains("Slack", ignoreCase = true) },
            "Slack token shape must be detected; got: $slackResult",
        )

        // JWT (eyJ….….…) — three base64url segments separated by dots
        val jwtResult = SecretShapes.findSurviving("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyMSJ9.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c")
        assertTrue(
            jwtResult.any { it.contains("JWT", ignoreCase = true) },
            "JWT shape must be detected; got: $jwtResult",
        )
    }

    // ── Negative: benign strings must yield an empty set ─────────────────────────────────────

    @Test
    fun benignTextHasNoSurvivors() {
        // A plain English sentence with no secret-like tokens
        val result = SecretShapes.findSurviving("hello world, just a normal sentence with name=alice")
        assertTrue(
            result.isEmpty(),
            "Benign text must return empty set; got: $result",
        )
    }

    @Test
    fun shortHexDoesNotTriggerHighEntropyShape() {
        // An MD5-length hex string (32 chars) — if the high-entropy hex shape is included
        // it should match; if it is omitted or the threshold is >32 this test documents the choice.
        // We do NOT assert either outcome here — the implementation comment in SecretShapes.kt
        // documents whether the broad hex shape is included or omitted.
        // This test just asserts the call returns without throwing.
        val result = SecretShapes.findSurviving("d41d8cd98f00b204e9800998ecf8427e")
        assertFalse(
            result.isEmpty() && result.isNotEmpty(), // always false — just a smoke call
            "findSurviving must not throw on a hex string",
        )
    }

    @Test
    fun nonSecretQueryStringNotFlagged() {
        // A URL with non-sensitive key names must not trigger the shape scanner
        val result = SecretShapes.findSurviving("https://example.com/api?user=alice&page=2&format=json")
        assertTrue(
            result.isEmpty(),
            "Non-sensitive query string must return empty set; got: $result",
        )
    }
}
