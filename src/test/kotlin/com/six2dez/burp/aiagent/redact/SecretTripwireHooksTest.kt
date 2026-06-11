package com.six2dez.burp.aiagent.redact

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

/**
 * SC4 / SC3 — per-path detect-payload + proceed assertions for the two non-interactive hooks.
 *
 * Tests [SecretTripwire.buildDetectAuditPayload] and [SecretTripwire.detectAndBuild]:
 *  - Payload shape: path, sessionId, shapeCategories (sorted), entropyScore — for both
 *    "passive_scanner" and "mcp" path values.
 *  - No-leak: the payload string form does NOT contain the raw input token (SC3).
 *  - sessionId fallback: null sessionId → "none" in the payload.
 *  - emit-only-on-match: [SecretTripwire.detectAndBuild] returns null when scan.matched == false,
 *    non-null when matched == true — proving the hook never emits on a clean payload while the
 *    caller still proceeds regardless.
 *
 * These are headless pure-unit tests — no AWT, no mocks needed (payload builder has no deps).
 */
class SecretTripwireHooksTest {
    // A well-known AWS access key format that SecretShapes covers.
    private val awsToken = "AKIAIOSFODNN7EXAMPLE"

    // A high-entropy base64 string (≥ 20 chars, entropy ≥ 4.5) that trips the Entropy heuristic.
    // Uses 48 distinct base64 chars → entropy ~log2(48) ≈ 5.6 bits/char, well above the 4.5 threshold.
    private val highEntropyB64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuv" // len=48, all-base64, high entropy

    // A plain innocuous payload that should not match any detector.
    private val cleanPayload = "GET /api/users HTTP/1.1\nHost: example.com"

    // -------------------------------------------------------------------------
    // buildDetectAuditPayload — passive_scanner path
    // -------------------------------------------------------------------------

    @Test
    fun `buildDetectAuditPayload for passive_scanner contains required keys`() {
        val scan = SecretTripwire.scan(awsToken)
        val payload = SecretTripwire.buildDetectAuditPayload(scan, path = "passive_scanner", sessionId = "sess-1")

        assertEquals("passive_scanner", payload["path"], "path must match the supplied value")
        assertEquals("sess-1", payload["sessionId"], "sessionId must match the supplied value")
        assertNotNull(payload["shapeCategories"], "shapeCategories must be present")
        // WR-02: awsToken is a shape-only match (no qualifying high-entropy token), so the entropy
        // half did NOT contribute and entropyScore must be OMITTED — never a misleading "0.0".
        assertFalse(
            payload.containsKey("entropyScore"),
            "entropyScore must be absent on a shape-only match (WR-02 — no misleading 0.0)",
        )
    }

    @Test
    fun `buildDetectAuditPayload for passive_scanner shapeCategories is sorted list of names`() {
        val scan = SecretTripwire.scan(awsToken)
        val payload = SecretTripwire.buildDetectAuditPayload(scan, path = "passive_scanner", sessionId = "sess-1")

        @Suppress("UNCHECKED_CAST")
        val categories = payload["shapeCategories"] as List<String>
        assertTrue(categories.isNotEmpty(), "AWS token must produce at least one category")
        // Must be a sorted list (verifiable by comparing to manually sorted copy)
        assertEquals(categories.sorted(), categories, "shapeCategories must be sorted")
    }

    // -------------------------------------------------------------------------
    // buildDetectAuditPayload — mcp path
    // -------------------------------------------------------------------------

    @Test
    fun `buildDetectAuditPayload for mcp path contains required keys`() {
        val scan = SecretTripwire.scan(awsToken)
        val payload = SecretTripwire.buildDetectAuditPayload(scan, path = "mcp", sessionId = "sess-2")

        assertEquals("mcp", payload["path"])
        assertEquals("sess-2", payload["sessionId"])
        assertNotNull(payload["shapeCategories"])
        // WR-02: shape-only AWS match → entropyScore omitted (not a misleading "0.0").
        assertFalse(payload.containsKey("entropyScore"), "entropyScore must be absent on a shape-only match")
    }

    // -------------------------------------------------------------------------
    // WR-02: entropyScore presence is honest — omitted on shape-only matches,
    // present (and a numeric decimal) when the entropy half contributed.
    // -------------------------------------------------------------------------

    @Test
    fun `buildDetectAuditPayload omits entropyScore on a shape-only match`() {
        // awsToken trips SecretShapes but has no qualifying high-entropy token (maxEntropy == 0.0).
        val scan = SecretTripwire.scan(awsToken)
        assertEquals(0.0, scan.maxEntropyBitsPerChar, 0.0001, "Pre-condition: AWS key is shape-only")
        val payload = SecretTripwire.buildDetectAuditPayload(scan, path = "passive_scanner", sessionId = "s")

        assertFalse(
            payload.containsKey("entropyScore"),
            "WR-02: a 0.0 entropy contribution must omit the key, not record a misleading \"0.0\"",
        )
        // The remaining required keys are still present.
        assertNotNull(payload["path"])
        assertNotNull(payload["sessionId"])
        assertNotNull(payload["shapeCategories"])
    }

    @Test
    fun `buildDetectAuditPayload includes entropyScore when the entropy half contributed`() {
        // highEntropyB64 has no known shape prefix — the entropy half is what fires here.
        val scan = SecretTripwire.scan(highEntropyB64)
        assertTrue(scan.maxEntropyBitsPerChar > 0.0, "Pre-condition: entropy half contributed")
        val payload = SecretTripwire.buildDetectAuditPayload(scan, path = "mcp", sessionId = "s")

        assertTrue(
            payload.containsKey("entropyScore"),
            "WR-02: entropyScore must be present when the entropy half actually contributed",
        )
        val score = payload["entropyScore"] as String
        assertTrue(score.matches(Regex("\\d+\\.\\d")), "entropyScore must be a one-decimal string; got: $score")
    }

    // -------------------------------------------------------------------------
    // sessionId fallback: null → "none"
    // -------------------------------------------------------------------------

    @Test
    fun `buildDetectAuditPayload uses 'none' when sessionId is null`() {
        val scan = SecretTripwire.scan(awsToken)
        val payload = SecretTripwire.buildDetectAuditPayload(scan, path = "passive_scanner", sessionId = null)

        assertEquals("none", payload["sessionId"], "null sessionId must fall back to 'none'")
    }

    @Test
    fun `buildDetectAuditPayload uses 'none' for mcp path with null sessionId`() {
        val scan = SecretTripwire.scan(awsToken)
        val payload = SecretTripwire.buildDetectAuditPayload(scan, path = "mcp", sessionId = null)

        assertEquals("none", payload["sessionId"])
    }

    // -------------------------------------------------------------------------
    // No-leak: raw token must not appear in payload (SC3)
    // -------------------------------------------------------------------------

    @Test
    fun `buildDetectAuditPayload does not leak the raw token into the payload for AWS key`() {
        val scan = SecretTripwire.scan(awsToken)
        val payload = SecretTripwire.buildDetectAuditPayload(scan, path = "passive_scanner", sessionId = "sess-3")

        // Convert the entire payload to string and assert the input token is absent
        val payloadStr = payload.toString()
        assertFalse(
            payloadStr.contains(awsToken),
            "Audit payload must NEVER contain the raw input token (SC3 no-leak)",
        )
    }

    @Test
    fun `buildDetectAuditPayload does not leak the raw token for high-entropy base64`() {
        val scan = SecretTripwire.scan(highEntropyB64)
        val payload = SecretTripwire.buildDetectAuditPayload(scan, path = "mcp", sessionId = "sess-4")

        val payloadStr = payload.toString()
        assertFalse(
            payloadStr.contains(highEntropyB64),
            "Audit payload must NEVER contain the raw input high-entropy token (SC3 no-leak)",
        )
    }

    // -------------------------------------------------------------------------
    // detectAndBuild: returns null on non-match, non-null on match
    // -------------------------------------------------------------------------

    @Test
    fun `detectAndBuild returns null for a clean payload (no emit signal)`() {
        val result = SecretTripwire.detectAndBuild(cleanPayload, path = "passive_scanner", sessionId = "sess-5")

        assertNull(result, "detectAndBuild must return null when the scan does not match — no event to emit")
    }

    @Test
    fun `detectAndBuild returns non-null payload for a matching token`() {
        val result = SecretTripwire.detectAndBuild(awsToken, path = "passive_scanner", sessionId = "sess-6")

        assertNotNull(result, "detectAndBuild must return a payload map when the scan matches")
        assertEquals("passive_scanner", result!!["path"])
        assertEquals("sess-6", result["sessionId"])
    }

    @Test
    fun `detectAndBuild returns non-null for high-entropy base64 on mcp path`() {
        val result = SecretTripwire.detectAndBuild(highEntropyB64, path = "mcp", sessionId = null)

        assertNotNull(result, "High-entropy token must produce a non-null detectAndBuild result")
        assertEquals("mcp", result!!["path"])
        assertEquals("none", result["sessionId"])
    }

    // -------------------------------------------------------------------------
    // Payload contains only safe types (score is a numeric string, not the token)
    // -------------------------------------------------------------------------

    @Test
    fun `entropyScore in payload is a numeric decimal string`() {
        val scan = SecretTripwire.scan(highEntropyB64)
        val payload = SecretTripwire.buildDetectAuditPayload(scan, path = "passive_scanner", sessionId = "s")

        val score = payload["entropyScore"] as String
        // Must match the pattern "X.Y" (one decimal place)
        assertTrue(
            score.matches(Regex("\\d+\\.\\d")),
            "entropyScore must be a one-decimal-place numeric string, got: $score",
        )
        // And the raw high-entropy token must not be in it
        assertFalse(score.contains(highEntropyB64))
    }
}
