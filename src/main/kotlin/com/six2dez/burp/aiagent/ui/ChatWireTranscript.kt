package com.six2dez.burp.aiagent.ui

import com.six2dez.burp.aiagent.backends.ChatMessage
import com.six2dez.burp.aiagent.redact.PrivacyMode

/**
 * One chat session's conversation as it was actually sent to and received from the model, in order
 * (quick 261008-ph4, review finding C4).
 *
 * The display messages are what the user sees and what `saveSessions` persists: the typed text and the
 * replies. The model received more than that — the tool preamble with the catalog, the captured
 * request/response context, the tool results of a chain — and every backend that rebuilds its
 * conversation from the chat history needs those turns back in the form it saw them. This transcript
 * is where that form lives, and `ChatPanel.sendMessage` builds every turn's history from it.
 *
 * **In memory only.** It is never written to the Burp preferences, the project file, the Markdown
 * export or any other disk path (orchestrator decision): a wire turn can carry captured traffic, and the
 * display messages are the only thing a saved session keeps. A restored session therefore starts from
 * its display text.
 *
 * **Privacy guard (brief item c, review H8).** Every turn is tagged with the privacy mode and the
 * backend id of the send that produced it. A turn is resent as sent only to the same backend under a
 * mode no less strict; otherwise its typed text is sent instead (or nothing, when it has none), and a
 * captured context that has not been delivered yet is dropped for good. History is never re-redacted:
 * `Redaction.anonymizeHost` is not idempotent and several salts exist, so a second pass would corrupt
 * rather than protect. The guard chooses what to send instead.
 *
 * Internally synchronized: a send is planned on the EDT and settled from the backend's completion
 * thread.
 */
internal class ChatWireTranscript {
    /** The settings a turn was produced under. */
    data class Tag(
        val privacyMode: PrivacyMode,
        val backendId: String,
    )

    /**
     * What one send carries: the [history] to pass to the backend, the captured context to attach (if
     * any), whether the full tool catalog must be sent, and whether a pending context was just dropped
     * by the guard ([contextWithheld]). [tag] is the send's own settings.
     */
    class TurnPlan(
        val history: List<ChatMessage>,
        val contextJson: String?,
        val includeCatalog: Boolean,
        val contextWithheld: Boolean,
        val tag: Tag,
    )

    private class Entry(
        val role: String,
        val wireText: String?,
        val fallbackText: String?,
        val tag: Tag?,
        val carriesCatalog: Boolean,
    )

    private class PendingContext(
        val json: String,
        val tag: Tag,
    )

    private val lock = Any()
    private val entries = mutableListOf<Entry>()
    private var pending: PendingContext? = null
    private var contextOffered = false

    /**
     * Captures the context the session was launched with. Only the first offer counts: the context is
     * pending from then on until a delivered send carries it, or until the guard drops it.
     */
    fun offerContext(
        contextJson: String,
        tag: Tag,
    ) {
        synchronized(lock) {
            if (contextOffered) return
            contextOffered = true
            pending = PendingContext(contextJson, tag)
        }
    }

    /** Plans the next send under [tag]. A pending context the guard rejects is dropped for good. */
    fun planTurn(tag: Tag): TurnPlan =
        synchronized(lock) {
            val history =
                entries.mapNotNull { entry ->
                    val text = if (allows(entry.tag, tag)) entry.wireText else entry.fallbackText
                    text?.takeIf { it.isNotBlank() }?.let { ChatMessage(entry.role, it) }
                }
            val context = pending
            val contextPasses = context != null && allows(context.tag, tag)
            val withheld = context != null && !contextPasses
            if (withheld) pending = null
            TurnPlan(
                history = history,
                contextJson = if (contextPasses) context?.json else null,
                includeCatalog = entries.none { it.carriesCatalog && allows(it.tag, tag) },
                contextWithheld = withheld,
                tag = tag,
            )
        }

    /**
     * Settles a delivered send: the user turn as it was sent ([wireText]) with its typed form
     * ([fallbackText], null for a follow-up the user never typed) and the [reply]. A context the plan
     * carried has now been delivered and is never sent again.
     */
    fun recordDelivered(
        plan: TurnPlan,
        wireText: String,
        fallbackText: String?,
        reply: String,
        carriedCatalog: Boolean,
    ) {
        synchronized(lock) {
            entries += Entry("user", wireText, fallbackText, plan.tag, carriedCatalog)
            entries += Entry("assistant", reply, reply, plan.tag, carriesCatalog = false)
            if (plan.contextJson != null) pending = null
        }
    }

    /**
     * Settles a failed or cancelled send. Nothing it carried counts as delivered: the context stays
     * pending and the catalog undelivered. Its typed text, when it has one, stays in the conversation.
     */
    fun recordUndelivered(fallbackText: String?) {
        synchronized(lock) {
            if (fallbackText != null) {
                entries += Entry("user", wireText = null, fallbackText = fallbackText, tag = null, carriesCatalog = false)
            }
        }
    }

    /**
     * An entry whose sent form is its display form: a typed slash command, the tool dialog's command
     * preview, a restored display message. Untagged, so it is always sent as shown, as before.
     */
    fun recordPlain(
        role: String,
        text: String,
    ) {
        synchronized(lock) {
            entries += Entry(role, wireText = text, fallbackText = text, tag = null, carriesCatalog = false)
        }
    }

    /**
     * A tool result the user ran from the tool dialog, which reaches the model with the next turn. It has
     * no typed form, so the guard omits it once the mode tightens or the backend changes.
     */
    fun recordToolResult(
        text: String,
        tag: Tag,
    ) {
        synchronized(lock) {
            entries += Entry("assistant", wireText = text, fallbackText = null, tag = tag, carriesCatalog = false)
        }
    }

    /**
     * The privacy guard (brief item c, review H8): a turn produced under [entryTag] may be resent as sent
     * under [current] only for the same backend and when its mode is at least as strict as the current
     * one. An untagged entry never passes; its fallback text is what it always was. A mode missing from
     * [LEAST_TO_MOST_STRICT] fails closed.
     */
    private fun allows(
        entryTag: Tag?,
        current: Tag,
    ): Boolean =
        entryTag != null &&
            entryTag.backendId == current.backendId &&
            current.privacyMode in LEAST_TO_MOST_STRICT &&
            LEAST_TO_MOST_STRICT.indexOf(entryTag.privacyMode) >= LEAST_TO_MOST_STRICT.indexOf(current.privacyMode)

    private companion object {
        /** Privacy modes ordered by strictness, so the guard never depends on the enum's declaration order. */
        val LEAST_TO_MOST_STRICT = listOf(PrivacyMode.OFF, PrivacyMode.BALANCED, PrivacyMode.STRICT)
    }
}
