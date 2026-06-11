package com.six2dez.burp.aiagent.redact

import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

// PRIV-03 / Phase 15: unit tests for SecretTripwire detector (SC1/SC2/SC3-no-leak).
// Tests run headless (no AWT) and reference SecretTripwire + Entropy, which are created in
// Tasks 2 and 3 (RED state until those implementations exist).
class SecretTripwireTest {
    // ── SC1: known-shape detection (AKIA AWS key via SecretShapes) ────────────────────────────

    @Test
    fun sc1_awsKeyPayloadIsMatched() {
        // AKIAIOSFODNN7EXAMPLE is the canonical AWS access key example (same token used in
        // SecretShapesTest to verify the curated shape set).
        val result = SecretTripwire.scan("Authorization: AKIAIOSFODNN7EXAMPLE")
        assertTrue(result.matched, "SC1: payload with AKIA key must be matched; result=$result")
    }

    @Test
    fun sc1_awsKeyPayloadHasAwsCategory() {
        val result = SecretTripwire.scan("Authorization: AKIAIOSFODNN7EXAMPLE")
        assertTrue(
            result.shapeCategories.any { it.contains("AWS", ignoreCase = true) },
            "SC1: shapeCategories must include an AWS category; got=${result.shapeCategories}",
        )
    }

    // ── SC1 / SC2: entropy-only detection (synthetic high-entropy base64, no known prefix) ──

    @Test
    fun sc1_syntheticHighEntropyBase64IsMatched() {
        // A 44-char base64-alphabet token with no known secret prefix — the entropy half must fire.
        // Base64 alphabet; entropy ~5.9 bits/char for a well-distributed token.
        val syntheticToken = "xK8mN2pQrT5vWyZ1aB3cD6eFgHiJkLmNoPqRsT7uV"
        val result = SecretTripwire.scan(syntheticToken)
        assertTrue(result.matched, "SC1: high-entropy base64 token must be matched via entropy; result=$result")
        assertTrue(
            result.maxEntropyBitsPerChar > 0.0,
            "SC1: maxEntropyBitsPerChar must be > 0.0 for entropy-only match; got=${result.maxEntropyBitsPerChar}",
        )
    }

    // ── SC2: legitimate base64 fuzz payload fires the gate (by design — high-entropy) ────────

    @Test
    fun sc2_legitimateBase64FuzzPayloadIsMatched() {
        // A legitimate base64 fuzz token (>= 20 chars, entropy >= 4.5). The tripwire is designed
        // to fire on this — the UX provides a "Send anyway" option (warn-with-confirmation).
        // This test asserts the detector is never silently silent on such payloads.
        val fuzzToken = "dGVzdC1meXp6aW5nLXBheWxvYWQtZm9yLXRlc3Rpbmc=" // base64 of test fuzz string
        val result = SecretTripwire.scan(fuzzToken)
        assertTrue(result.matched, "SC2: legit base64 fuzz token must be matched (warn-with-confirm by design); result=$result")
    }

    // ── SC2: low-entropy clean prose must NOT fire ───────────────────────────────────────────

    @Test
    fun sc2_lowEntropyProseIsNotMatched() {
        val result = SecretTripwire.scan("hello world this is fine")
        assertFalse(result.matched, "SC2: low-entropy prose must not be matched; result=$result")
    }

    // ── SC3: no-leak — ScanResult string forms must NOT contain the raw input token ──────────

    @Test
    fun sc3_noLeakScanResultDoesNotContainRawToken() {
        // Hold the raw token in a val and assert the result's string forms do not contain it.
        // The result must carry only category names + a numeric score, never the secret itself.
        val rawToken = "AKIAIOSFODNN7EXAMPLE"
        val result = SecretTripwire.scan("The token is $rawToken end.")

        val resultStr = result.toString()
        val categoriesStr = result.shapeCategories.joinToString(",")
        val entropyStr = Entropy.truncatedScore(result.maxEntropyBitsPerChar)

        assertFalse(
            resultStr.contains(rawToken),
            "SC3: ScanResult.toString() must NOT contain the raw token; got: $resultStr",
        )
        assertFalse(
            categoriesStr.contains(rawToken),
            "SC3: shapeCategories joined must NOT contain the raw token; got: $categoriesStr",
        )
        // entropyStr is a one-decimal number — cannot contain a 20-char key.
        assertFalse(
            entropyStr.contains(rawToken),
            "SC3: truncatedScore output must NOT contain the raw token; got: $entropyStr",
        )
    }

    @Test
    fun sc3_noLeakHighEntropyResultDoesNotContainRawToken() {
        // Same no-leak assertion for the entropy-only path.
        val rawToken = "xK8mN2pQrT5vWyZ1aB3cD6eFgHiJkLmNoPqRsT7uV"
        val result = SecretTripwire.scan(rawToken)

        val resultStr = result.toString()
        val categoriesStr = result.shapeCategories.joinToString(",")

        assertFalse(
            resultStr.contains(rawToken),
            "SC3 entropy path: ScanResult.toString() must NOT contain the raw token; got: $resultStr",
        )
        assertFalse(
            categoriesStr.contains(rawToken),
            "SC3 entropy path: shapeCategories joined must NOT contain the raw token; got: $categoriesStr",
        )
    }
}
