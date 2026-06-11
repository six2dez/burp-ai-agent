package com.six2dez.burp.aiagent.redact

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

// PRIV-03 / Phase 15 (15-02): pure gate-decision and allow-payload shape tests.
// All tests run headless (no AWT) — no JOptionPane / JPanel / Swing instantiated here.
// References: 15-UI-SPEC Delta 1+2, 15-VALIDATION SC5+SC3, 15-02-PLAN Task 1.
class SecretTripwireGateTest {
    // ── SC5: gate decision when ScanResult.matched == true ──────────────────────────────────

    @Test
    fun sc5_matchedScan_gateDecisionHasBannerRisk() {
        // A payload with a surviving AWS key — scan.matched == true.
        val scan = SecretTripwire.scan("Authorization: AKIAIOSFODNN7EXAMPLE")
        assertTrue(scan.matched, "Pre-condition: scan must be matched for gate test")

        val gate = SecretTripwire.gateDecision(scan)
        assertTrue(
            gate.bannerRisk,
            "SC5: bannerRisk must be true when scan.matched; gate=$gate",
        )
    }

    @Test
    fun sc5_matchedScan_gateDecisionAffirmativeLabelIsSendAnyway() {
        // When a tripwire match is present the affirmative MUST be relabeled to "Send anyway" (UI-SPEC Delta 2).
        val scan = SecretTripwire.scan("Authorization: AKIAIOSFODNN7EXAMPLE")
        assertTrue(scan.matched, "Pre-condition: scan must be matched")

        val gate = SecretTripwire.gateDecision(scan)
        assertEquals(
            "Send anyway",
            gate.affirmativeLabel,
            "SC5: affirmativeLabel must be 'Send anyway' when scan.matched",
        )
    }

    @Test
    fun sc5_matchedScan_gateDecisionCancelIsDefault() {
        // Cancel MUST be the default focus (options[1] initialValue) — Enter must never silently send
        // past a detected secret (UI-SPEC Delta 2 / G5 / Pitfall 5).
        val scan = SecretTripwire.scan("Authorization: AKIAIOSFODNN7EXAMPLE")
        assertTrue(scan.matched, "Pre-condition: scan must be matched")

        val gate = SecretTripwire.gateDecision(scan)
        assertTrue(
            gate.cancelIsDefault,
            "SC5: cancelIsDefault must be true when scan.matched (never affirmative default)",
        )
    }

    @Test
    fun sc5_matchedEntropyOnlyScan_gateDecisionHasBannerRisk() {
        // Same contract for the entropy-only path (no known shape, but high-entropy token fires).
        val syntheticToken = "xK8mN2pQrT5vWyZ1aB3cD6eFgHiJkLmNoPqRsT7uV"
        val scan = SecretTripwire.scan(syntheticToken)
        assertTrue(scan.matched, "Pre-condition: high-entropy token must be matched")

        val gate = SecretTripwire.gateDecision(scan)
        assertTrue(gate.bannerRisk, "SC5 entropy path: bannerRisk must be true")
        assertEquals("Send anyway", gate.affirmativeLabel, "SC5 entropy path: label must be 'Send anyway'")
        assertTrue(gate.cancelIsDefault, "SC5 entropy path: cancelIsDefault must be true")
    }

    // ── SC5: gate decision when ScanResult.matched == false (clean path unchanged) ──────────

    @Test
    fun sc5_cleanScan_gateDecisionHasNoBannerRisk() {
        val scan = SecretTripwire.scan("hello world this is fine")
        assertFalse(scan.matched, "Pre-condition: clean prose must not be matched")

        val gate = SecretTripwire.gateDecision(scan)
        assertFalse(
            gate.bannerRisk,
            "SC5 clean path: bannerRisk must be false when not matched",
        )
    }

    @Test
    fun sc5_cleanScan_gateDecisionAffirmativeLabelIsSend() {
        val scan = SecretTripwire.scan("hello world this is fine")
        assertFalse(scan.matched, "Pre-condition: clean prose must not be matched")

        val gate = SecretTripwire.gateDecision(scan)
        assertEquals(
            "Send",
            gate.affirmativeLabel,
            "SC5 clean path: affirmativeLabel must be 'Send' when not matched",
        )
    }

    @Test
    fun sc5_cleanScan_gateDecisionCancelIsDefault() {
        // Cancel stays default on the clean path too (existing behaviour, options[1] = initialValue).
        val scan = SecretTripwire.scan("hello world this is fine")
        assertFalse(scan.matched, "Pre-condition: clean prose must not be matched")

        val gate = SecretTripwire.gateDecision(scan)
        assertTrue(
            gate.cancelIsDefault,
            "SC5 clean path: cancelIsDefault must be true even when not matched",
        )
    }

    // ── SC3: allow-payload builder — keys present, no raw secret ────────────────────────────

    @Test
    fun sc3_allowPayloadContainsRequiredKeys() {
        // When a user clicks "Send anyway", buildAllowAuditPayload produces the SC3-compliant map.
        val scan = SecretTripwire.scan("Authorization: AKIAIOSFODNN7EXAMPLE")
        assertTrue(scan.matched, "Pre-condition: scan must be matched")

        val sessionId = "sess-test-001"
        val payload = SecretTripwire.buildAllowAuditPayload(scan, sessionId)

        assertTrue(payload.containsKey("path"), "SC3: payload must contain key 'path'")
        assertTrue(payload.containsKey("sessionId"), "SC3: payload must contain key 'sessionId'")
        assertTrue(payload.containsKey("shapeCategories"), "SC3: payload must contain key 'shapeCategories'")
        // WR-02: the AWS key is a shape-only match (entropy half did not contribute), so
        // entropyScore is OMITTED rather than recorded as a misleading "0.0".
        assertFalse(
            payload.containsKey("entropyScore"),
            "WR-02: entropyScore must be absent on a shape-only allow event (no misleading 0.0)",
        )
    }

    @Test
    fun sc3_allowPayloadIncludesEntropyScoreWhenEntropyContributed() {
        // An entropy-only match (no known shape prefix) must carry the entropyScore key.
        val syntheticToken = "xK8mN2pQrT5vWyZ1aB3cD6eFgHiJkLmNoPqRsT7uV"
        val scan = SecretTripwire.scan(syntheticToken)
        assertTrue(scan.maxEntropyBitsPerChar > 0.0, "Pre-condition: entropy half contributed")

        val payload = SecretTripwire.buildAllowAuditPayload(scan, "sess-entropy")
        assertTrue(
            payload.containsKey("entropyScore"),
            "WR-02: entropyScore must be present when the entropy half contributed",
        )
    }

    @Test
    fun sc3_allowPayloadPathIsChatForChatAllowEvent() {
        val scan = SecretTripwire.scan("Authorization: AKIAIOSFODNN7EXAMPLE")
        val payload = SecretTripwire.buildAllowAuditPayload(scan, "sess-abc")

        assertEquals("chat", payload["path"], "SC3: path must be 'chat' for the interactive chat allow event")
    }

    @Test
    fun sc3_allowPayloadSessionIdMatches() {
        val scan = SecretTripwire.scan("Authorization: AKIAIOSFODNN7EXAMPLE")
        val sessionId = "sess-xyz-789"
        val payload = SecretTripwire.buildAllowAuditPayload(scan, sessionId)

        assertEquals(sessionId, payload["sessionId"], "SC3: sessionId in payload must match the provided session id")
    }

    @Test
    fun sc3_allowPayloadShapeCategoriesAreSortedList() {
        val scan = SecretTripwire.scan("Authorization: AKIAIOSFODNN7EXAMPLE")
        val payload = SecretTripwire.buildAllowAuditPayload(scan, "sess-1")

        val categories = payload["shapeCategories"]
        assertTrue(
            categories is List<*>,
            "SC3: shapeCategories in payload must be a List; got=${categories?.javaClass}",
        )
        @Suppress("UNCHECKED_CAST")
        val categoryList = categories as List<String>
        assertEquals(
            categoryList.sorted(),
            categoryList,
            "SC3: shapeCategories must be sorted",
        )
    }

    @Test
    fun sc3_allowPayloadEntropyScoreIsFormattedString() {
        val syntheticToken = "xK8mN2pQrT5vWyZ1aB3cD6eFgHiJkLmNoPqRsT7uV"
        val scan = SecretTripwire.scan(syntheticToken)
        val payload = SecretTripwire.buildAllowAuditPayload(scan, "sess-2")

        val score = payload["entropyScore"]
        assertTrue(
            score is String,
            "SC3: entropyScore in payload must be a String; got=${score?.javaClass}",
        )
        val scoreStr = score as String
        // Must match the one-decimal format from Entropy.truncatedScore.
        assertTrue(
            scoreStr.matches(Regex("-?\\d+\\.\\d")),
            "SC3: entropyScore must be a one-decimal number like '4.7'; got='$scoreStr'",
        )
    }

    @Test
    fun sc3_allowPayloadDoesNotContainRawSecret() {
        // The audit map's string representation MUST NOT contain the raw matched token (CLAUDE.md / AGENTS.md).
        val rawToken = "AKIAIOSFODNN7EXAMPLE"
        val scan = SecretTripwire.scan("Authorization: $rawToken end.")
        val payload = SecretTripwire.buildAllowAuditPayload(scan, "sess-3")

        val payloadStr = payload.toString()
        assertFalse(
            payloadStr.contains(rawToken),
            "SC3 no-leak: the allow-payload string form must NOT contain the raw token; got: $payloadStr",
        )
    }

    @Test
    fun sc3_allowPayloadDoesNotContainRawEntropyToken() {
        // Same no-leak assertion for the entropy-only path.
        val rawToken = "xK8mN2pQrT5vWyZ1aB3cD6eFgHiJkLmNoPqRsT7uV"
        val scan = SecretTripwire.scan(rawToken)
        assertTrue(scan.matched, "Pre-condition: entropy-only token must be matched")

        val payload = SecretTripwire.buildAllowAuditPayload(scan, "sess-4")
        val payloadStr = payload.toString()

        assertFalse(
            payloadStr.contains(rawToken),
            "SC3 entropy no-leak: the allow-payload string form must NOT contain the raw token; got: $payloadStr",
        )
    }
}
