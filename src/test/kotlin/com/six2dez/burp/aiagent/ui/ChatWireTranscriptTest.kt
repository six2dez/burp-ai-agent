package com.six2dez.burp.aiagent.ui

import com.six2dez.burp.aiagent.backends.ChatMessage
import com.six2dez.burp.aiagent.redact.PrivacyMode
import com.six2dez.burp.aiagent.ui.ChatWireTranscript.Tag
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

/**
 * Quick 261008-ph4 — the guard matrix of [ChatWireTranscript] at unit level (Q-261008-ph4-GUARD,
 * -LATCH). [ChatWireHistoryTest] samples this matrix through the real panel; these tests pin every
 * cell of it on the real class.
 */
class ChatWireTranscriptTest {
    private val bal = Tag(PrivacyMode.BALANCED, "ollama")
    private val strict = Tag(PrivacyMode.STRICT, "ollama")
    private val off = Tag(PrivacyMode.OFF, "ollama")
    private val otherBackend = Tag(PrivacyMode.BALANCED, "lmstudio")

    /** U1 — a delivered turn is resent as sent only to the same backend under a no less strict mode. */
    @Test
    fun aDeliveredTurnIsResentAsSentOnlyForTheSameBackendUnderANoLessStrictMode() {
        val t = ChatWireTranscript()
        t.recordDelivered(t.planTurn(bal), "WIRE", "typed", "reply", carriedCatalog = false)

        val asSent = listOf(ChatMessage("user", "WIRE"), ChatMessage("assistant", "reply"))
        val asTyped = listOf(ChatMessage("user", "typed"), ChatMessage("assistant", "reply"))
        assertEquals(asSent, t.planTurn(bal).history)
        assertEquals(asSent, t.planTurn(off).history)
        assertEquals(asTyped, t.planTurn(strict).history)
        assertEquals(asTyped, t.planTurn(otherBackend).history)

        val loose = ChatWireTranscript()
        loose.recordDelivered(loose.planTurn(off), "WIRE", "typed", "reply", carriedCatalog = false)
        assertEquals(asTyped, loose.planTurn(bal).history, "A turn delivered under OFF is sent as typed under BALANCED")
    }

    /** U2 — follow-ups and dialog tool results have no safe fallback and are omitted; plain turns are sent as shown. */
    @Test
    fun turnsWithoutASafeFallbackAreOmittedAndPlainTurnsAreSentAsShown() {
        val t = ChatWireTranscript()
        t.recordPlain("user", "/tool x {}")
        t.recordToolResult("Tool result (x):\nRESULT", bal)
        t.recordDelivered(t.planTurn(bal), "FOLLOWUP WIRE", null, "final", carriedCatalog = false)

        assertEquals(
            listOf(
                ChatMessage("user", "/tool x {}"),
                ChatMessage("assistant", "Tool result (x):\nRESULT"),
                ChatMessage("user", "FOLLOWUP WIRE"),
                ChatMessage("assistant", "final"),
            ),
            t.planTurn(bal).history,
        )
        val guarded = listOf(ChatMessage("user", "/tool x {}"), ChatMessage("assistant", "final"))
        assertEquals(guarded, t.planTurn(strict).history)
        assertEquals(guarded, t.planTurn(otherBackend).history)
    }

    /** U3 — a context is offered once, sent until delivered, and dropped for good when the guard fails. */
    @Test
    fun aPendingContextIsOfferedOnceSentUntilDeliveredAndDroppedForGoodWhenTheGuardFails() {
        val t = ChatWireTranscript()
        t.offerContext("CTX-1", bal)
        t.offerContext("CTX-2", bal)
        assertEquals("CTX-1", t.planTurn(bal).contextJson, "A second offer is ignored")

        t.recordUndelivered("typed")
        val retry = t.planTurn(bal)
        assertEquals("CTX-1", retry.contextJson, "An undelivered context stays pending")
        assertFalse(retry.contextWithheld)
        assertEquals(listOf(ChatMessage("user", "typed")), retry.history)

        val tightened = t.planTurn(strict)
        assertNull(tightened.contextJson)
        assertTrue(tightened.contextWithheld, "The guard drops the pending context and says so")
        val later = t.planTurn(bal)
        assertNull(later.contextJson, "A dropped context is gone for good")
        assertFalse(later.contextWithheld)

        val delivered = ChatWireTranscript()
        delivered.offerContext("CTX-1", bal)
        delivered.recordDelivered(delivered.planTurn(bal), "wire", "typed", "reply", carriedCatalog = true)
        assertNull(delivered.planTurn(bal).contextJson, "A delivered context is never sent again")
        delivered.offerContext("CTX-3", bal)
        assertNull(delivered.planTurn(bal).contextJson, "A later offer is ignored")
    }

    /** U4 — the catalog is included until a turn the guard lets this send resend has carried it. */
    @Test
    fun theCatalogIsIncludedUntilAResendableTurnCarriesIt() {
        val t = ChatWireTranscript()
        assertTrue(t.planTurn(bal).includeCatalog, "An empty transcript needs the catalog")
        t.recordUndelivered("typed")
        assertTrue(t.planTurn(bal).includeCatalog, "An undelivered send carried nothing")

        t.recordDelivered(t.planTurn(bal), "wire with catalog", "typed", "reply", carriedCatalog = true)
        assertFalse(t.planTurn(bal).includeCatalog)
        assertFalse(t.planTurn(off).includeCatalog)
        assertTrue(t.planTurn(strict).includeCatalog, "A stricter mode cannot resend the turn that carried it")
        assertTrue(t.planTurn(otherBackend).includeCatalog, "Another backend never received it")
    }
}
