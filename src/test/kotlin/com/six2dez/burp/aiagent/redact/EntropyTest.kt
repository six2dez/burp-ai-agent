package com.six2dez.burp.aiagent.redact

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

// PRIV-03 / Phase 15: unit tests for Entropy — Shannon bits/char, qualifying-token scan,
// and truncatedScore format. All tests run headless (no AWT) and reference the not-yet-created
// Entropy object (RED state until Task 2 creates the implementation).
class EntropyTest {

    // A string of 32 identical characters has zero entropy (only one symbol, no uncertainty).
    @Test
    fun shannonOfConstantStringIsZero() {
        val h = Entropy.shannon("a".repeat(32))
        assertEquals(0.0, h, 0.001, "A constant string must have entropy ~0.0; got $h")
    }

    // A token containing exactly 16 distinct hex characters each appearing once has entropy
    // log2(16) == 4.0 bits/char. Use "0123456789abcdef" as the uniform sample.
    @Test
    fun shannonOfUniform16CharHexApproximates4Bits() {
        val h = Entropy.shannon("0123456789abcdef")
        assertEquals(4.0, h, 0.1, "Uniform 16-distinct-char hex token must have entropy ~4.0 bits/char; got $h")
    }

    // Empty string must return 0.0 without throwing.
    @Test
    fun shannonOfEmptyStringIsZero() {
        val h = Entropy.shannon("")
        assertEquals(0.0, h, 0.001, "Empty string must return 0.0; got $h")
    }

    // MIN_TOKEN_LEN gate: a 19-char token that is otherwise high-entropy must NOT qualify
    // (length < MIN_TOKEN_LEN=20), so maxQualifyingTokenEntropy returns 0.0.
    @Test
    fun tokenShorterThanMinLenDoesNotQualify() {
        // 19 base64 chars with reasonable entropy — below the min-length gate.
        val shortToken = "ABCDEFGHIJKLMNOPQRs" // length 19
        assertEquals(19, shortToken.length)
        val result = Entropy.maxQualifyingTokenEntropy(shortToken)
        assertEquals(0.0, result, 0.001, "A 19-char token must not qualify (< MIN_TOKEN_LEN); got $result")
    }

    // A 20-char token that meets or exceeds the base64 threshold must qualify (> 0.0).
    @Test
    fun tokenAtMinLenQualifiesWhenHighEntropy() {
        // 20-char base64 alphabet token with good spread — should clear the base64 threshold.
        val longToken = "ABCDEFGHIJKLMNOPQRst" // 20 chars, base64 alphabet
        assertEquals(20, longToken.length)
        val result = Entropy.maxQualifyingTokenEntropy(longToken)
        assertTrue(result > 0.0, "A 20-char high-entropy base64 token must qualify; got $result")
    }

    // A long hex token (all hex chars, >= 20) with good entropy must clear the hex threshold.
    @Test
    fun longHexTokenClearsHexThreshold() {
        // 32 hex chars — uniform spread of 0-9a-f → entropy near 4.0 bits/char, well above hex 3.0.
        val hexToken = "0123456789abcdef0123456789abcdef"
        assertEquals(32, hexToken.length)
        val result = Entropy.maxQualifyingTokenEntropy(hexToken)
        assertTrue(result > 0.0, "A 32-char uniform hex token must clear the hex threshold; got $result")
    }

    // A long base64 token with random-looking chars must clear the base64 threshold.
    @Test
    fun longBase64TokenClearsBase64Threshold() {
        // A 44-char base64 token with good character spread.
        val b64Token = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnop"
        assertEquals(44, b64Token.length)
        val result = Entropy.maxQualifyingTokenEntropy(b64Token)
        assertTrue(result > 0.0, "A 44-char diverse base64 token must clear the base64 threshold; got $result")
    }

    // SC3: truncatedScore must format to exactly one decimal place regardless of locale.
    @Test
    fun truncatedScoreFormatsToOneDecimal() {
        assertEquals("4.7", Entropy.truncatedScore(4.73), "truncatedScore(4.73) must == \"4.7\"")
        assertEquals("0.0", Entropy.truncatedScore(0.0), "truncatedScore(0.0) must == \"0.0\"")
        assertEquals("3.0", Entropy.truncatedScore(3.0), "truncatedScore(3.0) must == \"3.0\"")
        assertEquals("4.5", Entropy.truncatedScore(4.50), "truncatedScore(4.50) must == \"4.5\"")
    }
}
