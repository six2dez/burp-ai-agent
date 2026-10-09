package com.six2dez.burp.aiagent.ui

import burp.api.montoya.persistence.PersistedObject
import com.six2dez.burp.aiagent.TestSettings
import com.six2dez.burp.aiagent.backends.AgentConnection
import com.six2dez.burp.aiagent.backends.ChatMessage
import com.six2dez.burp.aiagent.config.AgentSettings
import com.six2dez.burp.aiagent.context.ContextCapture
import com.six2dez.burp.aiagent.redact.PrivacyMode
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.mockito.kotlin.any
import org.mockito.kotlin.anyOrNull
import org.mockito.kotlin.doAnswer
import org.mockito.kotlin.mock
import org.mockito.kotlin.whenever
import java.util.concurrent.ConcurrentLinkedQueue
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.atomic.AtomicReference
import javax.swing.SwingUtilities

/**
 * Quick 261008-ph4 — the conversation a backend receives is the conversation it actually had.
 *
 * Drives a REAL [ChatPanel] through [ChatPanelTestHarness] and stubs only `AgentSupervisor.sendChat`,
 * re-stubbed locally per test with a script of outcomes, so every assertion reads the arguments the
 * production code really passed: the text, the history, the context JSON, the backend and the mode.
 */
class ChatWireHistoryTest {
    @BeforeEach
    fun installObserver() {
        ChatPanelTestHarness.installSettledObserver()
    }

    @AfterEach
    fun releaseObserver() {
        ChatPanelTestHarness.releaseSettledObserver()
    }

    /**
     * A — Q-261008-ph4-WIRE: turn 2's history carries turn 1 exactly as it was sent (tool preamble with
     * the full catalog, the prompt and the context JSON), and turn 2 sends neither again. The display
     * messages still hold only the typed prompt.
     */
    @Test
    fun turnTwoCarriesTurnOneAsSentIncludingTheCapturedContext() {
        val f = fixture(Outcome.Reply("Reply one."), Outcome.Reply("Reply two."))
        launch(f)
        ChatPanelTestHarness.sendUserMessage(f.h, "second question")
        ChatPanelTestHarness.drainEdt()

        val first = f.sent[0]
        assertTrue(first.text.contains(CONTEXT_MARKER), "Turn 1 must carry the context: ${first.text}")
        assertTrue(first.text.contains(CATALOG_MARKER), "Turn 1 must carry the catalog: ${first.text}")
        assertEquals(CONTEXT_JSON, first.contextJson)
        assertTrue(first.history.isEmpty(), "Turn 1 has no history: ${first.history}")

        val second = f.sent[1]
        assertEquals(
            listOf(ChatMessage("user", first.text), ChatMessage("assistant", "Reply one.")),
            second.history,
            "Turn 2's history must be turn 1 as it was sent",
        )
        assertFalse(second.text.contains(CONTEXT_MARKER), "Turn 2 must not resend the context: ${second.text}")
        assertFalse(second.text.contains(CATALOG_MARKER), "Turn 2 must not resend the catalog: ${second.text}")
        assertNull(second.contextJson)
    }

    /**
     * B — Q-261008-ph4-LATCH: a first send that failed did not deliver the context or the catalog, so
     * the next send carries both; once a send carrying the context is delivered, no later send does.
     */
    @Test
    fun aFailedFirstSendKeepsTheContextAndCatalogPendingUntilASendIsDelivered() {
        val f =
            fixture(
                Outcome.Fail("backend down"),
                Outcome.Reply("Reply after retry."),
                Outcome.Reply("Reply three."),
            )
        launch(f)
        ChatPanelTestHarness.sendUserMessage(f.h, "retry please")
        ChatPanelTestHarness.drainEdt()
        ChatPanelTestHarness.sendUserMessage(f.h, "third")
        ChatPanelTestHarness.drainEdt()

        val retry = f.sent[1]
        assertTrue(retry.text.contains(CONTEXT_MARKER), "The retry must carry the undelivered context: ${retry.text}")
        assertTrue(retry.text.contains(CATALOG_MARKER), "The retry must carry the undelivered catalog: ${retry.text}")
        assertEquals(CONTEXT_JSON, retry.contextJson)
        assertEquals(listOf(ChatMessage("user", PROMPT)), retry.history, "The failed turn is history only as typed")

        val third = f.sent[2]
        assertFalse(third.text.contains(CONTEXT_MARKER), "A delivered context is never sent twice: ${third.text}")
        assertNull(third.contextJson)
    }

    /**
     * D — Q-261008-ph4-GUARD: after the privacy mode tightens, earlier turns are resent only as typed and
     * replied, the context is not resent, and the catalog is sent again because no resendable turn
     * carries it. No redaction is applied to history; the guard chooses what to send instead.
     */
    @Test
    fun afterThePrivacyModeTightensNoEarlierWirePayloadIsResent() {
        val f = fixture(Outcome.Reply("Reply one."), Outcome.Reply("Reply two."))
        launch(f)
        f.settings.set(f.settings.get().copy(privacyMode = PrivacyMode.STRICT))
        ChatPanelTestHarness.sendUserMessage(f.h, "second question")
        ChatPanelTestHarness.drainEdt()

        val second = f.sent[1]
        assertEquals(PrivacyMode.STRICT, second.privacyMode)
        assertNoEarlierWirePayload(second)
        assertTrue(second.text.contains(CATALOG_MARKER), "No resendable turn carries the catalog, so it is sent again")
    }

    /** D2 — Q-261008-ph4-GUARD: the same guard when the backend changes and the mode stays the same. */
    @Test
    fun afterTheBackendChangesNoEarlierWirePayloadIsResent() {
        val f = fixture(Outcome.Reply("Reply one."), Outcome.Reply("Reply two."))
        launch(f)
        f.settings.set(f.settings.get().copy(preferredBackendId = "lmstudio"))
        ChatPanelTestHarness.sendUserMessage(f.h, "second question")
        ChatPanelTestHarness.drainEdt()

        val second = f.sent[1]
        assertEquals("lmstudio", second.backendId)
        assertNoEarlierWirePayload(second)
        assertTrue(second.text.contains(CATALOG_MARKER), "No resendable turn carries the catalog, so it is sent again")
    }

    /**
     * E — Q-261008-ph4-TOOLS / -GUARD: a chained tool follow-up is history exactly as sent, between the
     * tool-call reply and the final reply; once the mode tightens it is omitted (it has no typed form).
     */
    @Test
    fun toolResultTurnsAreKeptAsSentAndOmittedOnceThePrivacyModeTightens() {
        val toolCallReply = toolCall("scope_check", """{"url":"https://target.example/"}""")
        val f =
            fixture(
                Outcome.Reply(toolCallReply),
                Outcome.Reply("Final one."),
                Outcome.Reply("Reply two."),
                Outcome.Reply("Reply three."),
            )
        ChatPanelTestHarness.sendUserMessage(f.h, "check the scope")
        ChatPanelTestHarness.awaitToolSettled(label = requireNotNull(f.sent[0].traceId), count = 1)
        ChatPanelTestHarness.sendUserMessage(f.h, "next question")
        ChatPanelTestHarness.drainEdt()

        assertTrue(f.sent[1].text.contains("Tool result for scope_check:"), "sent[1] is the follow-up: ${f.sent[1].text}")
        assertEquals(
            listOf(
                ChatMessage("user", f.sent[0].text),
                ChatMessage("assistant", toolCallReply),
                ChatMessage("user", f.sent[1].text),
                ChatMessage("assistant", "Final one."),
            ),
            f.sent[2].history,
            "The follow-up turn must be history exactly as it was sent",
        )

        f.settings.set(f.settings.get().copy(privacyMode = PrivacyMode.STRICT))
        ChatPanelTestHarness.sendUserMessage(f.h, "third question")
        ChatPanelTestHarness.drainEdt()
        val strict = f.sent[3].history
        assertEquals(
            listOf(
                ChatMessage("user", "check the scope"),
                ChatMessage("assistant", toolCallReply),
                ChatMessage("assistant", "Final one."),
                ChatMessage("user", "next question"),
                ChatMessage("assistant", "Reply two."),
            ),
            strict,
        )
        assertTrue(strict.none { it.content.contains("Tool result for") }, "No tool result under a stricter mode: $strict")
    }

    /**
     * H — Q-261008-ph4-TOOLS / -LATCH: `/tools` and `/tool` send nothing to the model, so they never
     * mark the catalog as delivered; the typed `/tool` command still reaches the model as typed.
     */
    @Test
    fun userOriginatedToolCommandsNeverMarkTheCatalogAsDelivered() {
        val f = fixture(Outcome.Reply("Reply one."))
        val command = """/tool scope_check {"url":"https://target.example/"}"""
        ChatPanelTestHarness.sendUserMessage(f.h, "/tools")
        ChatPanelTestHarness.sendUserMessage(f.h, command)
        ChatPanelTestHarness.awaitToolSettled(label = ChatPanelTestHarness.slashToolLabel(), count = 1)
        assertTrue(f.sent.isEmpty(), "Neither tool command sends anything to the model: ${f.sent}")

        ChatPanelTestHarness.sendUserMessage(f.h, "hello")
        ChatPanelTestHarness.drainEdt()

        assertTrue(f.sent[0].text.contains(CATALOG_MARKER), "The model never received the catalog: ${f.sent[0].text}")
        assertEquals(listOf(ChatMessage("user", command)), f.sent[0].history)
    }

    /**
     * C — Q-261008-ph4-LATCH: a send the Cancel button cancelled is not delivered even when its backend
     * still answers afterwards, so the next send carries the context and the catalog again.
     */
    @Test
    fun aCancelledSendIsNotDeliveredEvenWhenItsResponseArrivesLate() {
        val f = fixture(Outcome.Park, Outcome.Reply("Reply after retry."))
        launch(f)
        SwingUtilities.invokeAndWait { assertTrue(f.h.panel.cancelInFlightRequest(), "A send was in flight") }
        fireParked(f, "Late reply.")
        ChatPanelTestHarness.sendUserMessage(f.h, "retry please")
        ChatPanelTestHarness.drainEdt()

        val retry = f.sent[1]
        assertTrue(retry.text.contains(CONTEXT_MARKER), "The cancelled send delivered nothing: ${retry.text}")
        assertTrue(retry.text.contains(CATALOG_MARKER), "The cancelled send delivered no catalog: ${retry.text}")
        assertEquals(CONTEXT_JSON, retry.contextJson)
        assertEquals(listOf(ChatMessage("user", PROMPT)), retry.history, "The cancelled turn is history only as typed")
    }

    /**
     * G — Q-261008-ph4-MEMORY: a send in flight while Clear Chat runs settles into the transcript it
     * started with, so the cleared conversation's next send has an empty history and the full catalog.
     */
    @Test
    fun aSendInFlightDuringClearChatCannotWriteIntoTheClearedConversation() {
        val f = fixture(Outcome.Park, Outcome.Reply("Fresh reply."))
        ChatPanelTestHarness.sendUserMessage(f.h, "first question")
        SwingUtilities.invokeAndWait { f.h.panel.clearChatState() }
        fireParked(f, "Stale reply.")
        ChatPanelTestHarness.sendUserMessage(f.h, "fresh question")
        ChatPanelTestHarness.drainEdt()

        val fresh = f.sent[1]
        assertTrue(fresh.history.isEmpty(), "The cleared conversation must start empty: ${fresh.history}")
        assertTrue(fresh.text.contains(CATALOG_MARKER), "A cleared conversation needs the catalog again: ${fresh.text}")
    }

    /**
     * F1 — Q-261008-ph4-MEMORY: saving sessions writes the display messages only, never a wire payload
     * (the context JSON, the tool preamble or the catalog).
     */
    @Test
    fun savingSessionsNeverWritesAWirePayload() {
        val f = fixture(Outcome.Reply("Reply one."))
        val stored = mutableMapOf<String, String>()
        useInMemoryExtensionData(f, stored)
        launch(f)
        SwingUtilities.invokeAndWait { f.h.panel.saveSessions() }

        assertTrue(stored.values.any { it.contains(PROMPT) }, "Anti-vacuity: the typed prompt was saved: $stored")
        for (marker in listOf(CONTEXT_MARKER, PREAMBLE_MARKER, CATALOG_MARKER)) {
            assertTrue(stored.values.none { it.contains(marker) }, "A saved value carries `$marker`: $stored")
        }
    }

    /**
     * F2 — Q-261008-ph4-MEMORY: a restored session sends its display text as history and never its
     * original context; the catalog is sent again because no restored turn carries it.
     */
    @Test
    fun aRestoredSessionSendsItsDisplayTextAndNeverItsOriginalContext() {
        val stored = mutableMapOf<String, String>()
        val before = fixture(Outcome.Reply("Reply one."))
        useInMemoryExtensionData(before, stored)
        launch(before)
        SwingUtilities.invokeAndWait { before.h.panel.saveSessions() }

        val after = fixture(Outcome.Reply("Reply two."))
        useInMemoryExtensionData(after, stored)
        SwingUtilities.invokeAndWait { after.h.panel.restoreSessions() }
        ChatPanelTestHarness.sendUserMessage(after.h, "continue")
        ChatPanelTestHarness.drainEdt()

        val resumed = after.sent[0]
        assertEquals(listOf(ChatMessage("user", PROMPT), ChatMessage("assistant", "Reply one.")), resumed.history)
        assertFalse(resumed.text.contains(CONTEXT_MARKER), "The original context is never resent: ${resumed.text}")
        assertNull(resumed.contextJson)
        assertTrue(resumed.text.contains(CATALOG_MARKER), "No restored turn carries the catalog: ${resumed.text}")
    }

    // ── Fixture ──────────────────────────────────────────────────────────────────────────────────

    /** A backend that answers after the panel moved on: fires the parked callbacks from the test thread. */
    private fun fireParked(
        f: Fixture,
        reply: String,
    ) {
        val onChunk = checkNotNull(f.parked.onChunk) { "No send was parked" }
        val onComplete = checkNotNull(f.parked.onComplete) { "No send was parked" }
        onChunk(reply)
        onComplete(null)
        ChatPanelTestHarness.drainEdt()
    }

    /**
     * Points the panel's project store at [strings], an in-memory map (the answer shape of
     * SettingsSingleSourceOfTruthTest's `inMemoryPreferences`). Two panels given the same map share it.
     */
    private fun useInMemoryExtensionData(
        f: Fixture,
        strings: MutableMap<String, String>,
    ) {
        val booleans = mutableMapOf<String, Boolean>()
        val store = mock<PersistedObject>()
        whenever(store.getString(any())).thenAnswer { strings[it.getArgument<String>(0)] }
        whenever(store.setString(any(), any())).thenAnswer {
            strings[it.getArgument<String>(0)] = it.getArgument(1)
            null
        }
        whenever(store.deleteString(any())).thenAnswer {
            strings.remove(it.getArgument<String>(0))
            null
        }
        whenever(store.getBoolean(any())).thenAnswer { booleans[it.getArgument<String>(0)] }
        whenever(store.setBoolean(any(), any())).thenAnswer {
            booleans[it.getArgument<String>(0)] = it.getArgument(1)
            null
        }
        whenever(
            f.h.api
                .persistence()
                .extensionData(),
        ).thenReturn(store)
    }

    /** One captured `sendChat` call. */
    private data class SentChat(
        val backendId: String,
        val text: String,
        val history: List<ChatMessage>,
        val contextJson: String?,
        val privacyMode: PrivacyMode,
        val traceId: String?,
    )

    /** What the scripted backend does with the next `sendChat` call. */
    private sealed interface Outcome {
        /** Streams [text], then completes without error. */
        data class Reply(
            val text: String,
        ) : Outcome

        /** Completes with an error carrying [message]. */
        data class Fail(
            val message: String,
        ) : Outcome

        /** Keeps the callbacks for the test to fire later and returns a live connection. */
        data object Park : Outcome
    }

    /** The callbacks of a [Outcome.Park]ed send. */
    private class Parked {
        @Volatile var onChunk: ((String) -> Unit)? = null

        @Volatile var onComplete: ((Throwable?) -> Unit)? = null
    }

    private class Fixture(
        val h: ChatPanelTestHarness.Harness,
        val settings: AtomicReference<AgentSettings>,
        val sent: CopyOnWriteArrayList<SentChat>,
        val parked: Parked,
    )

    private fun fixture(vararg script: Outcome): Fixture {
        val settings = AtomicReference(TestSettings.baselineSettings("ollama").copy(privacyMode = PrivacyMode.BALANCED))
        val h =
            ChatPanelTestHarness.create(
                modelResponse = "unused: replies are scripted per test",
                getSettings = { settings.get() },
            )
        val sent = CopyOnWriteArrayList<SentChat>()
        val parked = Parked()
        val queue = ConcurrentLinkedQueue(script.toList())
        // doAnswer form: `whenever(mock.call())` would run the harness's own answer while stubbing.
        doAnswer { invocation ->
            val args = invocation.arguments

            @Suppress("UNCHECKED_CAST")
            val history = (args[HISTORY_INDEX] as List<ChatMessage>?).orEmpty().toList()
            sent.add(
                SentChat(
                    backendId = args[BACKEND_INDEX] as String,
                    text = args[TEXT_INDEX] as String,
                    history = history,
                    contextJson = args[CONTEXT_INDEX] as String?,
                    privacyMode = args[PRIVACY_INDEX] as PrivacyMode,
                    traceId = args[TRACE_ID_INDEX] as String?,
                ),
            )

            @Suppress("UNCHECKED_CAST")
            val onChunk = args[ON_CHUNK_INDEX] as (String) -> Unit

            @Suppress("UNCHECKED_CAST")
            val onComplete = args[ON_COMPLETE_INDEX] as (Throwable?) -> Unit
            when (val next = queue.poll() ?: error("sendChat call ${sent.size} ran past the script")) {
                is Outcome.Reply -> {
                    onChunk(next.text)
                    onComplete(null)
                    null
                }
                is Outcome.Fail -> {
                    onComplete(IllegalStateException(next.message))
                    null
                }
                Outcome.Park -> {
                    parked.onChunk = onChunk
                    parked.onComplete = onComplete
                    mock<AgentConnection>()
                }
            }
        }.whenever(h.supervisor).sendChat(
            any(),
            any(),
            any(),
            anyOrNull(),
            anyOrNull(),
            any(),
            any(),
            any(),
            any(),
            anyOrNull(),
            anyOrNull(),
            anyOrNull(),
            anyOrNull(),
        )
        return Fixture(h, settings, sent, parked)
    }

    /** "Send to AI" after the user confirmed the context preview. */
    private fun launch(f: Fixture) {
        SwingUtilities.invokeAndWait {
            f.h.panel.startConfirmedSessionFromContext(
                ContextCapture(contextJson = CONTEXT_JSON, previewText = "Kind: HTTP selection"),
                PromptLaunchSpec(
                    promptText = PROMPT,
                    actionName = "Analyze this request",
                    source = PromptSource.FIXED,
                    contextKind = ContextKind.HTTP_SELECTION,
                ),
            )
        }
        ChatPanelTestHarness.drainEdt()
    }

    /** The privacy half of D and D2: earlier turns as typed and replied, no wire payload, no context. */
    private fun assertNoEarlierWirePayload(second: SentChat) {
        assertEquals(
            listOf(ChatMessage("user", PROMPT), ChatMessage("assistant", "Reply one.")),
            second.history,
            "Earlier turns are resent only as typed and as replied",
        )
        for (entry in second.history) {
            for (marker in listOf(CONTEXT_MARKER, PREAMBLE_MARKER, CATALOG_MARKER)) {
                assertFalse(entry.content.contains(marker), "History entry resends `$marker`: ${entry.content}")
            }
        }
        assertFalse(second.text.contains(CONTEXT_MARKER), "The context must not be resent: ${second.text}")
        assertNull(second.contextJson)
    }

    /** The fenced tool-call shape, copied from ChatPanelEdtConfinementTest's private `toolCall` helper. */
    private fun toolCall(
        tool: String,
        argsJson: String,
    ): String =
        """
        ```json
        {"tool":"$tool","args":$argsJson}
        ```
        """.trimIndent()

    private companion object {
        /*
         * Zero-based argument indices of AgentSupervisor.sendChat, in its parameter order: 0 chatSessionId,
         * 1 backendId, 2 text, 3 history, 4 contextJson, 5 privacyMode, 6 determinismMode, 7 onChunk,
         * 8 onComplete, 9 traceId, 10 systemPrompt, 11 maxOutputTokens, 12 launchMetadata.
         */

        /** `backendId` in AgentSupervisor.sendChat. */
        const val BACKEND_INDEX = 1

        /** `text` in AgentSupervisor.sendChat. */
        const val TEXT_INDEX = 2

        /** `history` in AgentSupervisor.sendChat. */
        const val HISTORY_INDEX = 3

        /** `contextJson` in AgentSupervisor.sendChat. */
        const val CONTEXT_INDEX = 4

        /** `privacyMode` in AgentSupervisor.sendChat. */
        const val PRIVACY_INDEX = 5

        /** `onChunk` in AgentSupervisor.sendChat. */
        const val ON_CHUNK_INDEX = 7

        /** `onComplete` in AgentSupervisor.sendChat. */
        const val ON_COMPLETE_INDEX = 8

        /**
         * `traceId: String?` in AgentSupervisor.sendChat.
         *
         * Verified against the real signature at AgentSupervisor.kt:430-444: `traceId` is the 10th
         * parameter, at :440. Recorded here because this fixture replaces the harness's sendChat stub,
         * so the harness's own trace id record never sees these calls.
         */
        const val TRACE_ID_INDEX = 9

        const val PROMPT = "Find the authorization flaw in this request."
        const val CONTEXT_MARKER = "CTX-WIRE-7F3A"
        const val PREAMBLE_MARKER = "You have access to MCP tools via a text-based protocol"
        const val CATALOG_MARKER = "Enabled MCP tools:"
        const val CONTEXT_JSON =
            """{"items":[{"url":"https://target.example/account","method":"GET",""" +
                """"request":"GET /account?probe=$CONTEXT_MARKER HTTP/1.1","response":null}]}"""
    }
}
