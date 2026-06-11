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

    // A 20-char token passes the length gate; use the hex threshold (3.0) which is reachable
    // with a good 20-char hex token (4+ distinct hex chars each appearing ~5 times gives entropy
    // > 3.0). Verify the gate: 19-char does NOT qualify, 20-char does qualify (hex path).
    @Test
    fun tokenAtMinLenQualifiesViaHexThreshold() {
        // 20-char hex token with uniform spread across 16 hex symbols → entropy ~4.0, well above 3.0.
        val hexToken = "0123456789abcdef0123" // 20 chars, all hex, good entropy
        assertEquals(20, hexToken.length)
        val result = Entropy.maxQualifyingTokenEntropy(hexToken)
        assertTrue(result > 0.0, "A 20-char high-entropy hex token must qualify via hex threshold (>=3.0); got $result")
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

    // A long base64 token with diverse characters must clear the base64 threshold (4.5).
    @Test
    fun longBase64TokenClearsBase64Threshold() {
        // 48-char base64 token with good character spread across uppercase, lowercase, digits.
        // Entropy of a 48-char token with 48 distinct base64 chars approaches log2(48) ~5.6 bits/char.
        val b64Token = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuv"
        assertEquals(48, b64Token.length)
        val result = Entropy.maxQualifyingTokenEntropy(b64Token)
        assertTrue(result > 0.0, "A 48-char diverse base64 token must clear the base64 threshold (>=4.5); got $result")
    }

    // SC3: truncatedScore must format to exactly one decimal place regardless of locale.
    @Test
    fun truncatedScoreFormatsToOneDecimal() {
        assertEquals("4.7", Entropy.truncatedScore(4.73), "truncatedScore(4.73) must == \"4.7\"")
        assertEquals("0.0", Entropy.truncatedScore(0.0), "truncatedScore(0.0) must == \"0.0\"")
        assertEquals("3.0", Entropy.truncatedScore(3.0), "truncatedScore(3.0) must == \"3.0\"")
        assertEquals("4.5", Entropy.truncatedScore(4.50), "truncatedScore(4.50) must == \"4.5\"")
    }

    // ── WR-01: dot-delimited high-entropy tokens are now detected via the dot-joined pass ──────

    // A dot-delimited base64url secret (e.g. a raw JWT body/signature, or a `a.b.c` API key)
    // whose individual segments are each below MIN_TOKEN_LEN=20. Under the old single-pass
    // tokenizer every segment was fragmented below the length gate, so this evaded the entropy
    // detector entirely (silent false negative). The dot-joined pass evaluates the dots-removed
    // payload (the same 41-char high-entropy base64url string used elsewhere in this suite), which
    // clears the base64 threshold (>=4.5).
    @Test
    fun dottedHighEntropyBase64urlTokenIsDetected() {
        // Segments are 12 / 11 / 18 chars — all < 20, so the segment pass cannot catch them.
        val dotted = "xK8mN2pQrT5v.WyZ1aB3cD6e.FgHiJkLmNoPqRsT7uV"
        assertTrue(
            dotted.split(".").all { it.length < 20 },
            "Pre-condition: every dot segment must be < MIN_TOKEN_LEN so only the dot-joined pass can fire",
        )
        val result = Entropy.maxQualifyingTokenEntropy(dotted)
        assertTrue(
            result >= 4.5,
            "WR-01: a dot-delimited high-entropy base64url token must be detected via the dot-joined pass; got $result",
        )
    }

    // FP guard: a dotted IPv4 address must NOT qualify (dots-removed length < MIN_TOKEN_LEN).
    @Test
    fun dottedIpv4AddressIsNotDetected() {
        val result = Entropy.maxQualifyingTokenEntropy("connect to 192.168.100.200 now")
        assertEquals(0.0, result, 0.001, "FP guard: an IPv4 address must not be detected; got $result")
    }

    // FP guard: a short dotted hostname must NOT qualify (dots-removed length < MIN_TOKEN_LEN).
    @Test
    fun shortDottedHostnameIsNotDetected() {
        val result = Entropy.maxQualifyingTokenEntropy("see www.example.com for details")
        assertEquals(0.0, result, 0.001, "FP guard: a short hostname must not be detected; got $result")
    }

    // FP guard: a LONG dotted hostname (dots-removed >= MIN_TOKEN_LEN) must still NOT qualify —
    // natural-language letter distributions stay well under the base64 threshold (4.5 bits/char).
    @Test
    fun longDottedHostnameIsNotDetected() {
        val host = "subdomain.example.organization.company.com" // dots-removed = 38 chars, all letters
        assertTrue(host.replace(".", "").length >= 20, "Pre-condition: dots-removed must clear the length gate")
        val result = Entropy.maxQualifyingTokenEntropy(host)
        assertEquals(
            0.0,
            result,
            0.001,
            "FP guard: a long natural-language dotted hostname must stay below 4.5 bits/char; got $result",
        )
    }

    // FP guard: a long dotted package/identifier path must NOT qualify (low entropy, repeated letters).
    @Test
    fun longDottedIdentifierPathIsNotDetected() {
        val pkg = "com.example.service.controller.internal.handler" // dots-removed = 42 chars
        assertTrue(pkg.replace(".", "").length >= 20)
        val result = Entropy.maxQualifyingTokenEntropy(pkg)
        assertEquals(0.0, result, 0.001, "FP guard: a dotted identifier path must not be detected; got $result")
    }

    // Regression: the dot-joined pass is ADDITIVE — a plain (dot-free) high-entropy base64 token
    // detected by the original segment pass is still detected (and the dotted pass does not lower it).
    @Test
    fun dotFreeHighEntropyTokenStillDetectedAfterDotPass() {
        val token = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuv" // 48 chars, no dots
        val result = Entropy.maxQualifyingTokenEntropy(token)
        assertTrue(result > 0.0, "Regression: dot-free high-entropy base64 token must remain detected; got $result")
    }
}
