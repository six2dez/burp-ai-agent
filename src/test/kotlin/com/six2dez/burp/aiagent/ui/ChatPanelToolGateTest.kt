package com.six2dez.burp.aiagent.ui

import burp.api.montoya.proxy.ProxyHttpRequestResponse
import com.six2dez.burp.aiagent.audit.AuditLogger
import com.six2dez.burp.aiagent.audit.Hashing
import com.six2dez.burp.aiagent.mcp.ToolApprovalGate
import com.six2dez.burp.aiagent.mcp.ToolDecision
import com.six2dez.burp.aiagent.ui.components.ToolApprovalCard
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertTimeoutPreemptively
import org.mockito.Mockito
import org.mockito.kotlin.any
import org.mockito.kotlin.anyOrNull
import org.mockito.kotlin.argumentCaptor
import org.mockito.kotlin.atLeast
import org.mockito.kotlin.never
import org.mockito.kotlin.times
import org.mockito.kotlin.verify
import org.mockito.kotlin.whenever
import java.awt.Component
import java.awt.Container
import java.io.File
import java.time.Duration
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicReference
import javax.swing.AbstractButton
import javax.swing.JButton
import javax.swing.JLabel
import javax.swing.JList
import javax.swing.ListCellRenderer
import javax.swing.SwingUtilities

/**
 * SEC-06 / SC4 — the agent tool-call trust boundary, asserted against the real production path.
 *
 * **This file drives a REAL [ChatPanel] through its REAL Send button.** It is not a model of the
 * chat flow: [ChatPanelTestHarness] constructs the production ten-parameter panel from deep-stub
 * mocks and clicks the same button a user clicks in Burp. Nothing here simulates
 * `maybeExecuteToolCall` — it is executed.
 *
 * **This file is now the SC4 acceptance gate, landed in plan 22-07.** The gate assertion is
 * [confirmToolDoesNotReachBurpBeforeADecision]: a model-emitted `proxy_http_history` call — `CONFIRM`
 * in 22-02's locked tier table — must not reach `api.proxy().history()` before a click, and must raise
 * an approval card instead. Both halves are red against the pre-gate commit and green after, which is
 * what makes the gate non-vacuous under the Phase 20 SC4 / Phase 21 rule: *a test that passes both
 * before and after the change has not tested the defect.*
 *
 * **22-01's baseline assertion is NOT inverted and NOT deleted.** It survives as
 * [autoToolStillRunsWithNoCard]: `scope_check` is `SecTier.AUTO`, so it still runs silently by design
 * after the gate ships. Inverting that line to `never()` would assert the opposite of the shipped
 * behaviour and go red forever. It passes both before and after **on purpose** — it is the `AUTO`
 * companion, never the gate.
 *
 * **Naming constraint (hard).** The class must stay `ChatPanelToolGateTest`. Renaming it to
 * `*IntegrationTest` (or `*ConcurrencyTest`, `*BackpressureTest`, `*RestartPolicyTest`,
 * `*SupervisionTest`) would make `-PexcludeHeavyTests=true` skip it — silently disabling the SC4
 * gate on exactly the PR gate where it matters most.
 */
class ChatPanelToolGateTest {
    // ── The SC4 acceptance gate ──────────────────────────────────────────────────────────

    @Test
    fun confirmToolDoesNotReachBurpBeforeADecision() {
        val h = ChatPanelTestHarness.create(modelResponse = toolCall("proxy_http_history", """{"count":5}"""))

        ChatPanelTestHarness.sendUserMessage(h, "summarise the proxy history")
        ChatPanelTestHarness.drainEdt()

        // THE ORDER OF THESE TWO ASSERTIONS IS LOAD-BEARING, NOT STYLISTIC.
        // JUnit stops at the first failure, and the red-before-green proof requires the never()
        // verification to be the assertion that fails at the pre-gate commit — a Mockito
        // NeverWantedButInvoked proving the tool DID reach Burp with nobody asked. Written the other
        // way round, a harness that never reached Burp at all would pass the never() check and fail
        // only on the card, which is trivially red pre-gate (no card type is wired in there at all)
        // and says nothing whatever about the defect.
        verify(h.api.proxy(), never()).history()
        // REL-05 — THE HALF THE never() STOPPED WATCHING THE MOMENT THE DISPATCH BECAME ASYNCHRONOUS.
        // A bare never() now passes VACUOUSLY, and passes faster: the failure it exists to catch is a
        // worker that was dispatched and has not reached Burp yet, which is exactly the state in which
        // it goes green. This clause catches that — an un-decided call that started a worker anyway.
        // It reads the DISPATCH record, never the SETTLE record, and the distinction is the whole
        // clause. The settle record is written from the worker's EDT tail, so a worker that started and
        // has not finished is absent from it too — a clause read off it would inherit the very blindness
        // it repairs. The dispatch record is written synchronously with the dispatch statement, so a
        // started worker is visible the instant it exists and its absence is a real claim.
        // Selected by THIS chain's trace id, never by "the log is empty" — panels built by earlier tests
        // in this class are still alive and still draining on this test's drains.
        assertFalse(
            ChatPanelTestHarness.dispatchedLabels().contains(pendingTraceId(h)),
            "SEC-06: no tool worker may be started before a decision is reached.",
        )
        assertNotNull(
            ChatPanelTestHarness.findApprovalCard(h.panel.root),
            "A CONFIRM-tier model-emitted tool call must raise an approval card instead of running.",
        )
    }

    // ── The AUTO companion, kept verbatim from plan 22-01 ────────────────────────────────

    @Test
    fun autoToolStillRunsWithNoCard() {
        // The exact fenced payload research measured reaching Burp. ToolCallParser.extractFirst
        // resolves the "tool" and "args" keys directly (ToolCallParser.kt:80-108).
        val h = ChatPanelTestHarness.create(modelResponse = toolCall("scope_check", """{"url":"http://evil.example/"}"""))

        ChatPanelTestHarness.sendUserMessage(h, "check scope please")
        val traceId = ChatPanelTestHarness.chainTraceId(h)
        // REL-05: the AUTO call is dispatched to a daemon worker, so a bare drain would run the assertion
        // below in the window between dispatch and the worker's EDT tail. The AUTO chain then runs to its
        // budget with nobody asked, and waiting for the whole of it is what stops its workers settling
        // inside later tests (measured: 7 of 8 outlived this test and satisfied the next two tests' awaits).
        ChatPanelTestHarness.awaitToolSettled(label = traceId, count = ChatPanel.MAX_AUTO_TOOL_ITERATIONS)

        // D-02: scope_check is SecTier.AUTO, so the gate returns Run and the call still reaches Burp.
        // Unchanged behaviour is the CORRECT result here, not a sign the gate is inert. Do not invert.
        verify(h.api.scope(), Mockito.atLeastOnce()).isInScope("http://evil.example/")
        assertNull(
            ChatPanelTestHarness.findApprovalCard(h.panel.root),
            "An AUTO tool is read-only and bounded-output; there is nothing for a human to weigh (D-02).",
        )
    }

    // ── The four D-11 actions ────────────────────────────────────────────────────────────

    @Test
    fun approveOnceExecutesTheCall() {
        val h = ChatPanelTestHarness.create(modelResponse = toolCall("proxy_http_history", """{"count":5}"""))
        ChatPanelTestHarness.sendUserMessage(h, "summarise the proxy history")
        ChatPanelTestHarness.drainEdt()
        val card = requireNotNull(ChatPanelTestHarness.findApprovalCard(h.panel.root)) { NO_CARD }
        val traceId = pendingTraceId(h)

        click(card, "Approve once")
        // REL-05: replaces the post-click drain, which cannot see a daemon worker (see @BeforeEach).
        ChatPanelTestHarness.awaitToolSettled(label = traceId, count = 1)

        verify(h.api.proxy(), times(1)).history()
        assertEquals(
            0,
            decisionButtons(card).size,
            "Approve once is per-call: the card that was clicked becomes a record, buttons removed.",
        )
    }

    /**
     * T-22-31 — the failure twin of [approveOnceExecutesTheCall].
     *
     * A human clicked `Approve once`, the tool then blew up, and `reportFailedToolCall` stopped the
     * chain without sending a followup turn. Nothing downstream is carrying `onCompleted` any more, so
     * if the resolution path does not discharge it here the caller that supplied it waits forever —
     * the register's "parked continuation that is never discharged".
     *
     * The un-asked path has always handled this: `sendMessage`'s completion block reads the outcome and
     * invokes `onCompleted` on `NOT_CHAINED`. This asserts the resolved-click path now does the same.
     */
    @Test
    fun anApprovedToolThatThrowsStillDischargesTheParkedContinuation() {
        val h = ChatPanelTestHarness.create(modelResponse = toolCall("proxy_http_history", """{"count":5}"""))
        // Must be an Error, not an Exception. `McpTool.runTool` catches SerializationException and
        // Exception and turns both into an error RESULT, which executeApprovedToolCall reports as a
        // run with status "error" and then CHAINS — the branch that is not the defect. Only a Throwable
        // runTool does not catch escapes McpToolExecutor.executeTool into the runCatching in
        // executeApprovedToolCall, which is the reportFailedToolCall / NOT_CHAINED branch under test.
        whenever(h.api.proxy().history()).thenThrow(InjectedToolFailure("proxy history exploded"))

        ChatPanelTestHarness.sendUserMessage(h, "summarise the proxy history")
        ChatPanelTestHarness.drainEdt()
        val card = requireNotNull(liveApprovalCard(h.panel.root)) { NO_CARD }
        val discharges = CopyOnWriteArrayList<Pair<String, Throwable?>>()
        val traceId = parkContinuation(h) { text, error -> discharges += text to error }

        click(card, "Approve once")
        // REL-05: added BESIDE the explicit drain, not in place of it — the drain's count is load-bearing
        // for chain continuation (one invokeLater per chained turn) and the await is what proves the
        // worker's EDT tail has run. Over-draining an empty EDT queue is free.
        ChatPanelTestHarness.awaitToolSettled(label = traceId, count = 1)
        ChatPanelTestHarness.drainEdt(times = LONG_DRAIN)

        // NON-VACUITY FIRST, AND THAT ORDERING IS THE POINT. The claim below is "the continuation was
        // discharged on the failure branch"; it says nothing at all unless the approved tool really ran
        // and really threw. A harness that raised no card, or a click that did nothing, would leave
        // `discharges` empty too — and would fail here instead, naming the actual breakage.
        verify(h.api.proxy(), times(1)).history()
        // Exactly the one turn the user's own message started. A second would mean the tool did NOT
        // throw and executeApprovedToolCall chained a followup carrying onCompleted with it, in which
        // case this test is exercising the success path and proves nothing about T-22-31.
        verifySendChatCount(h, 1)
        // SC3 is not allowed to be the price of the fix: the approved-then-threw branch still owes a
        // record, and it is the easiest one in the file to lose while restructuring returns.
        //
        // Selected by THIS chain's trace id, not by position or by tool name. `AuditLogger`'s emitter is
        // a global singleton, and an earlier test's panel is still alive with queued `invokeLater` work
        // that this test's drain runs — measured: the `scope_check` AUTO chain lands three more
        // `mcp_tool_decision` events in here. The trace id is the one field that is this chain's alone.
        val decision =
            auditEvents.single { it.first == "mcp_tool_decision" && it.second["traceId"] == traceId }.second
        assertEquals("approve_once", decision["decision"], "A human clicked Approve once; the record must say so.")
        assertEquals("error", decision["status"], "The run status is the failure's, not the decision's.")

        assertEquals(
            1,
            discharges.size,
            "An approved tool that throws must discharge the parked continuation EXACTLY once, or the " +
                "'Send to AI' caller that supplied it hangs forever (T-22-31). Discharges: $discharges",
        )
        assertNull(
            discharges.single().second,
            "The throwable was already recorded by reportFailedToolCall's SC3 event; the continuation " +
                "is a resume hook, not a second audit sink.",
        )
    }

    @Test
    fun approveForSessionSuppressesTheNextCard() {
        val h = ChatPanelTestHarness.create(modelResponse = toolCall("proxy_http_history", """{"count":5}"""))
        ChatPanelTestHarness.sendUserMessage(h, "summarise the proxy history")
        ChatPanelTestHarness.drainEdt()
        val card = requireNotNull(ChatPanelTestHarness.findApprovalCard(h.panel.root)) { NO_CARD }
        val traceId = pendingTraceId(h)

        click(card, "Approve for session")
        // REL-05, and N = 2 for the same reason the verification below is atLeast(2): the claim is that
        // a SECOND call ran without a second decision, so two of this chain's own workers must have
        // settled before it is read. Added beside the explicit drain, which stays; see
        // anApprovedToolThatThrows... above.
        ChatPanelTestHarness.awaitToolSettled(label = traceId, count = 2)
        ChatPanelTestHarness.drainEdt(times = LONG_DRAIN)

        // The grant is applied to every later call in this chat with nobody asked, so the model's
        // repeat of the same tool runs straight through. `atLeast(2)` rather than a literal: the chain
        // keeps going until the monotone budget stops it, so the exact count is the budget's business,
        // not this test's. What matters is that a SECOND call ran without a second decision.
        verify(h.api.proxy(), atLeast(2)).history()
        assertTrue(
            decisionButtons(h.panel.root).isEmpty(),
            "A session grant must suppress the CARD, not just the prompt: no decision button may remain.",
        )
    }

    @Test
    fun denyReturnsAResultThatLetsTheConversationContinue() {
        val h = ChatPanelTestHarness.create(modelResponse = toolCall("proxy_http_history", """{"count":5}"""))
        ChatPanelTestHarness.sendUserMessage(h, "summarise the proxy history")
        ChatPanelTestHarness.drainEdt()
        val card = requireNotNull(ChatPanelTestHarness.findApprovalCard(h.panel.root)) { NO_CARD }
        // Captured while exactly one decision is parked; a chain's trace id is threaded through every
        // followup turn, so this one capture covers the whole chain.
        val traceId = pendingTraceId(h)

        click(card, "Deny")
        ChatPanelTestHarness.drainEdt()

        verify(h.api.proxy(), never()).history()
        // REL-05: what a denial must produce is not merely "Burp not reached yet" but "no worker was
        // ever started". ToolApprovalOutcome.Denied routes to denyToolCall and never to
        // executeApprovedToolCall, so an entry here would mean the gate leaked.
        assertFalse(
            ChatPanelTestHarness.dispatchedLabels().contains(traceId),
            "SEC-06: a denied call must start no tool worker at all.",
        )
        val prompts = sentPrompts(h)
        // SC2: the session continues rather than erroring — a further backend turn was issued.
        assertTrue(prompts.size >= 2, "A denial must continue the conversation, not end the session. Turns: ${prompts.size}")
        assertTrue(
            prompts.any { it.contains(ToolApprovalGate.DENIAL_RESULT) },
            "The followup must carry the one D-12 denial constant verbatim.",
        )
        // D-12 / T-22-19: nothing ran, so there is no tool result. Pointing the model at one that does
        // not exist is how a refusal turns into a retry with different arguments.
        assertTrue(
            prompts.none { it.contains(SUCCESS_CLOSING_LINE) },
            "The denial followup must not reuse the success branch's closing line.",
        )
    }

    @Test
    fun denyForSessionResolvesLaterCallsWithNoCard() {
        val h = ChatPanelTestHarness.create(modelResponse = toolCall("proxy_http_history", """{"count":5}"""))
        ChatPanelTestHarness.sendUserMessage(h, "summarise the proxy history")
        ChatPanelTestHarness.drainEdt()
        val card = requireNotNull(ChatPanelTestHarness.findApprovalCard(h.panel.root)) { NO_CARD }
        val traceId = pendingTraceId(h)

        click(card, "Deny for session")
        ChatPanelTestHarness.drainEdt(times = LONG_DRAIN)

        // ASSERT NON-VACUITY FIRST — the discipline this class documents at the eight-denials test and
        // the one place in the file that did not follow it. Both claims below pass vacuously on a chain
        // that never got started; only the resolution milestone fails loudly when it did not.
        assertTrue(
            decisionButtons(h.panel.root).isEmpty(),
            "A session denial must resolve later calls instantly — re-asking is the habituation D-11 avoids.",
        )
        // REL-05: no worker was ever started for this chain (see confirmToolDoesNotReachBurpBeforeADecision
        // for why the settle record cannot answer this and the dispatch record can).
        assertFalse(
            ChatPanelTestHarness.dispatchedLabels().contains(traceId),
            "SEC-06: a session-denied chain must start no tool worker at all.",
        )
        verify(h.api.proxy(), never()).history()
    }

    @Test
    fun confirmEachOffersOnlyTwoActions() {
        // http1_request is SecTier.CONFIRM_EACH: one click must never hand the model unlimited
        // traffic-generating capability for a whole chat (T-22-18).
        val h = ChatPanelTestHarness.create(modelResponse = toolCall("http1_request", """{"content":"GET / HTTP/1.1"}"""))
        ChatPanelTestHarness.sendUserMessage(h, "send that request")
        ChatPanelTestHarness.drainEdt()
        val card = requireNotNull(ChatPanelTestHarness.findApprovalCard(h.panel.root)) { NO_CARD }

        assertEquals(
            listOf("Deny", "Approve once"),
            decisionButtons(card).map { it.text },
            "CONFIRM_EACH offers exactly Deny and Approve once — no session-wide action, in safe-first order.",
        )
    }

    /**
     * WR-02: a decision the gate REFUSES must leave the card exactly as it was, not destroy the record
     * behind it.
     *
     * `ToolApprovalGate.resolve` carries two `require` blocks that reject a gate/card disagreement, and
     * `resolveToolDecision` used to take the pending record out of the map before calling it. A throw
     * therefore left a card with live buttons, no record behind them and a parked continuation nobody
     * could discharge — and the user's second click hit `?: return` and did nothing at all. That is the
     * permanently dead card T-22-10 exists to eliminate, reached through the fail-closed path itself.
     *
     * The disagreement is injected by reflection because the card deliberately renders no button that
     * can produce it: what is under test is what happens to the record when the gate refuses, not how
     * the two came to disagree.
     */
    @Test
    fun anActionTheGateRefusesLeavesTheCardUsable() {
        // http1_request is CONFIRM_EACH, which has no session memory in either direction — so
        // APPROVE_SESSION is exactly the caller bug resolve()'s second `require` rejects.
        val h = ChatPanelTestHarness.create(modelResponse = toolCall("http1_request", """{"content":"GET / HTTP/1.1"}"""))
        ChatPanelTestHarness.sendUserMessage(h, "send that request")
        ChatPanelTestHarness.drainEdt()
        val card = requireNotNull(liveApprovalCard(h.panel.root)) { NO_CARD }
        assertEquals(
            listOf("Deny", "Approve once"),
            decisionButtons(card).map { it.text },
            "Setup: the tier under test must be the one whose session actions the gate refuses.",
        )

        invokeResolveToolDecision(h, ToolDecision.APPROVE_SESSION)

        assertEquals(
            1,
            pendingDecisionCount(h),
            "A refused action decided nothing, so the record must survive. Destroying it strands the " +
                "parked continuation and makes every later click a silent no-op (WR-02).",
        )
        assertEquals(
            listOf("Deny", "Approve once"),
            decisionButtons(card).map { it.text },
            "The card must still be answerable. Deny trips neither precondition, so the fail-closed " +
                "action stays one click away.",
        )

        // And it really is answerable: the SAME card, not a replacement raised by a later turn.
        click(card, "Deny")
        ChatPanelTestHarness.drainEdt(times = LONG_DRAIN)

        assertTrue(
            decisionButtons(card).isEmpty(),
            "The originally-parked card must resolve normally after the refusal — otherwise the " +
                "refusal left it dead after all.",
        )
    }

    // ── SC5: user-originated calls are not double-prompted ───────────────────────────────

    @Test
    fun userDialogPathIsNotDoublePrompted() {
        // ToolInvocationDialog extends JDialog with APPLICATION_MODAL, so constructing it under
        // `-Djava.awt.headless=true` throws HeadlessException and the dialog path cannot be driven
        // headlessly. Rather than weaken the claim, assert the equivalent property directly on the
        // call site, exactly as plan 22-07 prescribes for this case.
        val body = functionBody("fun openToolDialog()")

        assertTrue(
            body.contains("McpToolExecutor.executeTool("),
            "openToolDialog must still execute the tool the user picked.",
        )
        assertTrue(
            body.contains("ToolCallOrigin.UserDialog"),
            "SC5: the dialog call site must DECLARE its origin, so the three call sites are distinguishable.",
        )
        assertTrue(
            !body.contains("ToolApprovalGate") && !body.contains("ToolApprovalCard"),
            "SC5 / T-22-32: the user picked the tool and typed the args. Asking again trains click-through.",
        )
    }

    @Test
    fun slashCommandPathIsNotDoublePrompted() {
        // Deliberately a CONFIRM tool rather than an AUTO one: an AUTO tool raises no card either way,
        // so it could not tell a gated slash path from an ungated one.
        val h = ChatPanelTestHarness.create(modelResponse = toolCall("proxy_http_history", """{"count":5}"""))

        ChatPanelTestHarness.sendUserMessage(h, """/tool proxy_http_history {"count":5}""")
        // The `/tool` branch dispatches to a daemon worker (REL-05), and the window this closes is
        // narrow and specific: between the worker returning and its marshalled EDT tail running. A bare
        // EDT drain cannot see that window at all — it drains the EDT queue and knows nothing about a
        // thread it did not queue — so the verification below would run against a call that has not
        // happened yet, and fail intermittently rather than honestly.
        ChatPanelTestHarness.awaitToolSettled(label = ChatPanelTestHarness.slashToolLabel(), count = 1)

        verify(h.api.proxy(), times(1)).history()
        assertNull(
            ChatPanelTestHarness.findApprovalCard(h.panel.root),
            "SC5 / T-22-32: the user typed this call themselves; it must not be gated.",
        )
    }

    // ── SC4's ChatPanel-side monotone budget ─────────────────────────────────────────────

    @Test
    fun eightConsecutiveDenialsTerminateTheChainWithNoNinthTurn() {
        assertEquals(
            8,
            ChatPanel.MAX_AUTO_TOOL_ITERATIONS,
            "This test's NAME says eight. If the budget ever changes, rename the test — do not relax it.",
        )
        val expectedTurns = expectedTurnsForAFullyDeniedChain()
        val h = ChatPanelTestHarness.create(modelResponse = toolCall("proxy_http_history", """{"count":5}"""))

        // assertTimeoutPreemptively runs its block on a SEPARATE thread, so the trace id crosses back
        // through an AtomicReference rather than a captured local.
        val traceIdRef = AtomicReference<String>()
        // A non-monotone budget would loop forever; fail the suite instead of stalling CI.
        assertTimeoutPreemptively(Duration.ofSeconds(30)) {
            ChatPanelTestHarness.sendUserMessage(h, "summarise the proxy history")
            ChatPanelTestHarness.drainEdt()
            val card = requireNotNull(ChatPanelTestHarness.findApprovalCard(h.panel.root)) { NO_CARD }
            traceIdRef.set(pendingTraceId(h))
            // One click; every later turn is auto-denied with no further interaction.
            click(card, "Deny for session")
            // Drain EXPLICITLY. drainEdt's default of 4 was measured sufficient for ONE turn, and each
            // chained turn sits behind exactly one invokeLater, so a bare drainEdt() would stop this
            // chain around turn 5. Over-draining is free: invokeAndWait on an empty queue is a no-op.
            ChatPanelTestHarness.drainEdt(times = ChatPanel.MAX_AUTO_TOOL_ITERATIONS * 2 + 4)
        }

        // ASSERT (b) FIRST, AND THAT IS THE POINT. Clauses (a) and (c) pass VACUOUSLY on an
        // under-drained chain: a chain stopped at turn 5 by too few drains also "terminates" and also
        // never reached Burp. Only the turn count fails loudly when the drain is short, so it is the
        // clause that licenses the other two. A future maintainer who sees this fail must fix the
        // drain or the budget — never relax the expected count.
        verifySendChatCount(h, expectedTurns)

        // (a) The chain really has terminated: draining further produces no further backend turn.
        ChatPanelTestHarness.drainEdt(times = LONG_DRAIN)
        verifySendChatCount(h, expectedTurns)

        // (c) Not one of the denied calls reached Burp.
        verify(h.api.proxy(), never()).history()
        // REL-05: and not one of them started a worker either — the half of (c) that an asynchronous
        // dispatch would otherwise satisfy for free.
        assertFalse(
            ChatPanelTestHarness.dispatchedLabels().contains(traceIdRef.get()),
            "SEC-06: eight consecutive denials must start zero tool workers.",
        )
    }

    /**
     * REL-05 / AI-SPEC E6 — cancelling a running tool REFUNDS NO CHAIN ITERATION.
     *
     * The cancel variant of the eight-denial budget test above, and the threat it closes is the same
     * monotone-budget one approached from the other direction: if a superseded step handed
     * its iteration back and re-issued the turn, a user could hold an auto-chain open indefinitely by
     * cancelling it — the unbounded chain D-13's counter exists to make impossible.
     *
     * **The measured shape of "no refund" is "no followup turn at all", and it is stronger than a
     * budget that merely fails to grow.** `discardSupersededToolResult` sends nothing, so the chain
     * stops dead at the cancelled step: the turn count stays at the ONE turn the user's own message
     * started. A refund would show up here as a second turn.
     *
     * `Approve for session` rather than `Approve once` on purpose: with a session grant live, every
     * later step would run with no card at all, so the chain demonstrably COULD have continued. Under
     * `Approve once` a stopped chain proves nothing — the next card would simply have gone unanswered.
     *
     * **The turn count is asserted FIRST, for the reason the denial test above states:** the other
     * clauses pass vacuously on a chain that stopped early for the wrong reason.
     */
    @Test
    fun cancellingARunningToolRefundsNoChainIterationAndSendsNoFurtherTurn() {
        val entered = CountDownLatch(1)
        val release = CountDownLatch(1)
        val h = ChatPanelTestHarness.create(modelResponse = toolCall("proxy_http_history", """{"count":5}"""))
        whenever(h.api.proxy().history()).thenAnswer {
            entered.countDown()
            check(release.await(SUPERSEDE_FAILSAFE_SECONDS, TimeUnit.SECONDS)) {
                "The test never released the blocked tool — the cancel window was never opened."
            }
            emptyList<ProxyHttpRequestResponse>()
        }

        assertTimeoutPreemptively(Duration.ofSeconds(30)) {
            ChatPanelTestHarness.sendUserMessage(h, "summarise the proxy history")
            ChatPanelTestHarness.drainEdt()
            // A session grant, so nothing downstream is waiting on a click.
            val traceId = pendingTraceId(h)
            click(requireNotNull(ChatPanelTestHarness.findApprovalCard(h.panel.root)) { NO_CARD }, "Approve for session")
            assertTrue(
                entered.await(SUPERSEDE_FAILSAFE_SECONDS, TimeUnit.SECONDS),
                "The tool worker never started, so there was nothing to cancel.",
            )
            SwingUtilities.invokeAndWait { cancelButton(h).doClick() }
            release.countDown()
            ChatPanelTestHarness.awaitToolSettled(label = traceId, count = 1)
        }

        // FIRST. Exactly the turn the user typed, and no other.
        verifySendChatCount(h, 1)
        // Drained far past the point a refunded iteration's followup would have landed.
        ChatPanelTestHarness.drainEdt(times = LONG_DRAIN)
        verifySendChatCount(h, 1)
        // And the chain really did stop: one call reached Burp, not a second under the live grant.
        verify(h.api.proxy(), times(1)).history()
    }

    /**
     * REL-05 / AI-SPEC E6 — the same anti-refund rule for a supersede NOBODY CLICKED CANCEL for.
     *
     * The twin of the cancel variant above, and worth having separately: the anti-refund property has
     * to belong to the SUPERSEDE TOKEN rather than to the Cancel button's action listener. Here the
     * token is taken by a `/tool` command the user typed while the chain's step was still in flight —
     * a different entry point that never goes near `cancelInFlightRequest` — and the budget must come
     * out identical.
     *
     * **A `/tool` supersede rather than the project-change one this variant was first written
     * against, and the reason was measured, not preferred.** `clearInMemorySessionState` clears
     * `sessionPanels`, and `sendMessage` returns early when a session's panel is gone — so with the
     * supersede REMOVED that variant still produced no second turn and went green against the defect.
     * `/tool` leaves the panel alive, so the un-superseded tail really does reach `sendChat` and the
     * turn count really does move. Verified by reverting `finishApprovedToolCall`'s
     * `clearIfMatches` check to a constant `false`: this test fails, the earlier form did not.
     *
     * The `/tool` command contributes NO backend turn of its own (`handleToolCommand` returns before
     * `sendMessage`), so the expected count stays at the one turn the user's chat message started.
     *
     * Turn count first, for the reason the two tests above both state.
     */
    @Test
    fun aToolSupersededByASlashCommandRefundsNoChainIterationEither() {
        val entered = CountDownLatch(1)
        val release = CountDownLatch(1)
        val h = ChatPanelTestHarness.create(modelResponse = toolCall("proxy_http_history", """{"count":5}"""))
        whenever(h.api.proxy().history()).thenAnswer {
            entered.countDown()
            check(release.await(SUPERSEDE_FAILSAFE_SECONDS, TimeUnit.SECONDS)) {
                "The test never released the blocked tool — the supersede window was never opened."
            }
            emptyList<ProxyHttpRequestResponse>()
        }

        assertTimeoutPreemptively(Duration.ofSeconds(30)) {
            ChatPanelTestHarness.sendUserMessage(h, "summarise the proxy history")
            ChatPanelTestHarness.drainEdt()
            val chainLabel = pendingTraceId(h)
            click(requireNotNull(ChatPanelTestHarness.findApprovalCard(h.panel.root)) { NO_CARD }, "Approve for session")
            assertTrue(
                entered.await(SUPERSEDE_FAILSAFE_SECONDS, TimeUnit.SECONDS),
                "The tool worker never started, so there was nothing to supersede.",
            )
            // Mints its own running-tool token on the EDT, which is the supersede. Synchronous, so by
            // the time this returns the chain's token is already the loser of the compare-and-set.
            ChatPanelTestHarness.sendUserMessage(h, "/tool status {}")
            val slashLabel = ChatPanelTestHarness.slashToolLabel()
            release.countDown()
            // Two workers, each awaited under its own label: the superseding /tool one and the
            // superseded chain one.
            ChatPanelTestHarness.awaitToolSettled(label = slashLabel, count = 1)
            ChatPanelTestHarness.awaitToolSettled(label = chainLabel, count = 1)
        }

        verifySendChatCount(h, 1)
        ChatPanelTestHarness.drainEdt(times = LONG_DRAIN)
        verifySendChatCount(h, 1)
        // The chain stopped at the superseded step rather than continuing under the live grant.
        verify(h.api.proxy(), times(1)).history()
    }

    // ── The pending-decision lifecycle (D-08's five teardown paths) ──────────────────────

    @Test
    fun newMessageInTheSessionImplicitlyDeniesThePendingCard() {
        val h = ChatPanelTestHarness.create(modelResponse = toolCall("proxy_http_history", """{"count":5}"""))
        ChatPanelTestHarness.sendUserMessage(h, "summarise the proxy history")
        ChatPanelTestHarness.drainEdt()
        val card = requireNotNull(ChatPanelTestHarness.findApprovalCard(h.panel.root)) { NO_CARD }

        // Captured while exactly one decision is parked — the second message below retires it.
        val traceId = pendingTraceId(h)

        // The user answers by moving on. Teardown path 1 of 5.
        ChatPanelTestHarness.sendUserMessage(h, "never mind, just summarise what you have")
        ChatPanelTestHarness.drainEdt()

        assertEquals(
            0,
            decisionButtons(card).size,
            "A new message retires the pending card: its buttons become an outcome row (T-22-10).",
        )
        verify(h.api.proxy(), never()).history()
        // REL-05: an implicit denial must start no worker either, for the same reason an explicit one
        // must not — it is the same SEC-06 boundary, reached without a click.
        assertFalse(
            ChatPanelTestHarness.dispatchedLabels().contains(traceId),
            "SEC-06: an implicitly denied call must start no tool worker at all.",
        )
        // EXACTLY two turns, and the count is the assertion. One for each message the USER sent. A
        // third would mean the implicit denial dispatched a D-12 followup of its own — running
        // concurrently with the turn the user just started, which is what clobbers inFlightConnection
        // (T-22-33). The user's own message IS the continuation; there is nothing to add to it.
        verifySendChatCount(h, 2)
    }

    @Test
    fun clearChatResolvesThePendingCardAndClearsApprovalMemory() {
        val h = ChatPanelTestHarness.create(modelResponse = toolCall("proxy_http_history", """{"count":5}"""))
        ChatPanelTestHarness.sendUserMessage(h, "summarise the proxy history")
        ChatPanelTestHarness.drainEdt()
        val granted = requireNotNull(ChatPanelTestHarness.findApprovalCard(h.panel.root)) { NO_CARD }
        click(granted, "Approve for session")
        ChatPanelTestHarness.drainEdt(times = LONG_DRAIN)
        // Precondition, asserted rather than assumed: the grant really is live, so a later card
        // appearing proves the CLEAR removed it rather than the grant never having been recorded.
        assertTrue(
            decisionButtons(h.panel.root).isEmpty(),
            "Approve for session must suppress later cards — otherwise this test proves nothing below.",
        )

        SwingUtilities.invokeAndWait { h.panel.clearChatState() }
        ChatPanelTestHarness.sendUserMessage(h, "have another look")
        ChatPanelTestHarness.drainEdt()

        // T-22-34: Clear Chat is the user declaring a new task. A session grant that outlived it would
        // run a tool against the new task that was approved for the old one, with nobody asked.
        val afterClear =
            requireNotNull(liveApprovalCard(h.panel.root)) {
                "Clear Chat must clear the D-10 approval memory: the tool has to be asked about again."
            }
        assertEquals(
            DECISION_LABELS.size,
            decisionButtons(afterClear).size,
            "The re-asked call is a live CONFIRM card offering all four D-11 actions, not a receipt.",
        )

        // Now the other half — clearing while a decision is genuinely pending. Without the
        // resolvePending call, clearMessages() below takes the card out of the transcript and leaves
        // the record with no UI able to answer it: permanently stuck, continuation never fired.
        SwingUtilities.invokeAndWait { h.panel.clearChatState() }
        assertEquals(
            0,
            decisionButtons(afterClear).size,
            "Clear Chat must resolve the pending decision, not orphan it (T-22-10).",
        )
        assertNull(
            liveApprovalCard(h.panel.root),
            "No decision may survive a Clear Chat: the transcript that could answer it is gone.",
        )
    }

    @Test
    fun shutdownResolvesAllPendingDecisionsWithoutSendingATurn() {
        val h = ChatPanelTestHarness.create(modelResponse = toolCall("proxy_http_history", """{"count":5}"""))
        ChatPanelTestHarness.sendUserMessage(h, "summarise the proxy history")
        ChatPanelTestHarness.drainEdt()
        SwingUtilities.invokeAndWait { h.panel.createNewSession() }
        ChatPanelTestHarness.sendUserMessage(h, "and check this other one")
        ChatPanelTestHarness.drainEdt()
        // Two sessions, two pending cards. CardLayout keeps every session panel in the component tree,
        // so both cards are reachable from the root even though only one is showing.
        assertEquals(
            DECISION_LABELS.size * 2,
            decisionButtons(h.panel.root).size,
            "Setup: one live CONFIRM card in each of two sessions.",
        )
        val turnsBeforeUnload = 2

        h.panel.shutdown()

        assertTrue(
            decisionButtons(h.panel.root).isEmpty(),
            "Unload must retire EVERY pending decision, not just the active session's (T-22-10).",
        )
        // The whole point of the implicit-denial rule: no backend request is dispatched while Burp is
        // tearing down the extension classloader (T-22-33).
        verifySendChatCount(h, turnsBeforeUnload)

        // The parked continuation is the one claim this suite cannot drive headlessly: the only way to
        // park an `onCompleted` is startSessionFromContext, which goes through ContextPreviewDialog ->
        // JOptionPane.showOptionDialog and throws HeadlessException. Asserted structurally instead, on
        // the single shared line every teardown path routes through — the same sanctioned fallback
        // userDialogPathIsNotDoublePrompted uses, and for the same reason.
        val body = functionBody("private fun resolvePending(")
        assertTrue(
            body.contains("onCompleted?.invoke(ToolApprovalGate.DENIAL_RESULT, null)"),
            "Every implicit denial must discharge the parked continuation, or the caller hangs (T-22-31).",
        )
        assertTrue(
            !body.contains("sendMessage("),
            "An implicit denial terminates the chain; only an explicit Deny click sends the D-12 followup.",
        )
    }

    // ── SC3: every decision leaves a durable record ──────────────────────────────────────

    @Test
    fun everyDecisionEmitsTheSc3Metadata() {
        val h = ChatPanelTestHarness.create(modelResponse = toolCall("proxy_http_history", """{"count":5}"""))
        ChatPanelTestHarness.sendUserMessage(h, "summarise the proxy history")
        ChatPanelTestHarness.drainEdt()
        // Captured before the first click and used as the SELECTOR below. This used to filter on the
        // event type alone and read the results positionally, which is only sound while no other panel
        // is emitting — and `AuditLogger.registerGlobalEmitter` is a process-global hook, panels built
        // by earlier tests in this class are never shut down, and their queued `invokeLater` chains run
        // on this test's drains. It survived by draining 4 times rather than 24; raising the drain or
        // reordering the class turns it red, or green for the wrong reason. A chain's trace id is
        // threaded through every followup turn, so both decisions below share this one and nothing else
        // does.
        val traceId = pendingTraceId(h)

        click(requireNotNull(liveApprovalCard(h.panel.root)) { NO_CARD }, "Approve once")
        // REL-05: the approval dispatches a worker, and the next card only exists once that worker's EDT
        // tail has chained the followup turn. The later Deny click needs no await — a denial starts no
        // worker at all, so waiting on one would hang for the full failsafe and then fail.
        ChatPanelTestHarness.awaitToolSettled(label = traceId, count = 1)
        ChatPanelTestHarness.drainEdt()
        // Approve once writes no session memory, so the model's next identical call raises a new card.
        click(requireNotNull(liveApprovalCard(h.panel.root)) { NO_CARD }, "Deny")
        ChatPanelTestHarness.drainEdt(times = LONG_DRAIN)

        val decisions = auditEvents.filter { it.first == "mcp_tool_decision" && it.second["traceId"] == traceId }.map { it.second }
        assertEquals(
            listOf("approve_once", "deny"),
            decisions.map { it["decision"] },
            "SC3: one event per decision, in the order the user made them — an approval and a refusal.",
        )
        decisions.forEach { payload ->
            // The four fields SC3 names. secTier rides on every event, which is the field that makes
            // "which calls ran with no decision at all?" answerable from a historical log.
            assertEquals("proxy_http_history", payload["toolName"], "The record names the CANONICAL tool that ran.")
            assertEquals("confirm", payload["secTier"], "The resolved tier is part of every decision record.")
            assertNotNull(payload["step"], "SC3 requires the chain step on every decision.")
        }
        // D-12 / Pitfall 5: a refusal is a policy outcome, not a malfunction. An audit log that files
        // it as an error cannot distinguish a decision from a broken tool.
        assertEquals("denied", decisions[1]["status"], "A denial is a third status value, never an error.")
    }

    /**
     * WR-04 / UF-1: an `ext:` name is "known" only if a configured server actually exposes it.
     *
     * `isKnownTool` used to return `true` for any string starting with `ext:`, so a name no server
     * exposes was filed as recognised: `toolName` took the model's own string and `toolNameSha256` was
     * omitted entirely — the whole-name digest bypassed for exactly the class of names where it is the
     * only record of what was asked for, while the executor rejects the call outright. The gate is
     * unaffected either way (the prefix still derives CONFIRM_EACH), so this is a claim about the
     * DURABLE RECORD, and it is asserted on the record.
     */
    @Test
    fun anExtNameNoConfiguredServerExposesIsRecordedAsUnknown() {
        val extName = "ext:demo:definitely_not_configured"
        val h = ChatPanelTestHarness.create(modelResponse = toolCall(extName, """{"x":1}"""))
        ChatPanelTestHarness.sendUserMessage(h, "call that external tool")
        ChatPanelTestHarness.drainEdt()
        val card = requireNotNull(liveApprovalCard(h.panel.root)) { NO_CARD }
        assertEquals(
            listOf("Deny", "Approve once"),
            decisionButtons(card).map { it.text },
            "Setup: the ext: prefix still derives CONFIRM_EACH, so the gate still asks. This test is " +
                "about what the record says, not about whether the call is gated.",
        )
        val traceId = pendingTraceId(h)

        click(card, "Deny")
        ChatPanelTestHarness.drainEdt(times = LONG_DRAIN)

        // Selected by THIS chain's trace id: AuditLogger's emitter is a process-global singleton and
        // panels from earlier tests are still alive with queued invokeLater work that this drain runs.
        val decision = auditEvents.single { it.first == "mcp_tool_decision" && it.second["traceId"] == traceId }.second
        assertEquals(
            "unknown",
            decision["toolName"],
            "No configured server exposes this name and the executor would refuse it, so the record " +
                "must not file it as a recognised tool.",
        )
        assertEquals(
            Hashing.sha256Hex(extName),
            decision["toolNameSha256"],
            "The unresolved branch is the one that carries the whole-name digest, and it is the only " +
                "record of what the model asked for. Filing the name as known dropped it entirely.",
        )
    }

    @Test
    fun sessionRowMarksAPendingDecisionAndClearsItOnResolution() {
        val h = ChatPanelTestHarness.create(modelResponse = toolCall("proxy_http_history", """{"count":5}"""))
        assertFalse(
            sessionRowLabels(h).contains(PENDING_MARKER),
            "A session with nothing outstanding must not claim to be awaiting anything.",
        )

        ChatPanelTestHarness.sendUserMessage(h, "summarise the proxy history")
        ChatPanelTestHarness.drainEdt()

        // T-22-35: the marker is the only signal that a background session has parked a chain. Without
        // it the user sees a session that simply stopped talking and concludes the model gave up.
        assertTrue(
            sessionRowLabels(h).contains(PENDING_MARKER),
            "A session holding a pending decision must say so on its row.",
        )

        // Deny FOR SESSION, not a bare Deny. A bare denial sends the D-12 followup, the model re-emits
        // the same call and a fresh card is raised — so the marker correctly stays up and the test
        // would be asserting the wrong thing. A session denial resolves every later call with no card,
        // which is the only way to reach "this session is waiting on nothing" inside one chain.
        click(requireNotNull(liveApprovalCard(h.panel.root)) { NO_CARD }, "Deny for session")
        ChatPanelTestHarness.drainEdt(times = LONG_DRAIN)

        assertFalse(
            sessionRowLabels(h).contains(PENDING_MARKER),
            "The marker must clear when the decision is retired, or it becomes noise nobody reads.",
        )
    }

    // ── Audit capture plumbing ───────────────────────────────────────────────────────────

    private val auditEvents = CopyOnWriteArrayList<Pair<String, Map<*, *>>>()

    @BeforeEach
    fun captureAuditEvents() {
        auditEvents.clear()
        AuditLogger.registerGlobalEmitter { type, payload ->
            if (payload is Map<*, *>) auditEvents += type to payload
        }
        // REL-05: an approved tool call is now dispatched to a daemon worker, so drainEdt() alone no
        // longer proves the call reached Burp — it drains the EDT queue and knows nothing about a
        // worker. The observers make the worker's start and its finish both observable.
        ChatPanelTestHarness.installSettledObserver()
    }

    @AfterEach
    fun releaseAuditEmitter() {
        // Both are global singleton hooks. Leaving either registered would have this class capturing
        // — and holding — events emitted by every test class that runs after it.
        AuditLogger.registerGlobalEmitter(null)
        ChatPanelTestHarness.releaseSettledObserver()
    }
}

// ── Helpers ──────────────────────────────────────────────────────────────────────────────

private const val NO_CARD = "No ToolApprovalCard in the transcript — the SEC-06 gate did not raise a decision."

/** The success-branch closing line the denial variant must never reuse (ChatPanel.executeApprovedToolCall). */
private const val SUCCESS_CLOSING_LINE = "Provide the final response using the tool result"

/** Comfortably longer than any chain this suite drives; over-draining an empty EDT queue is free. */
private const val LONG_DRAIN = 24

/**
 * Deadlock failsafe for the two supersede budget variants, in seconds.
 *
 * A bound on a hang, never a threshold the work is measured against — the same discipline, and the
 * same number, as `ChatPanelTestHarness.awaitToolSettled`'s own failsafe.
 */
private const val SUPERSEDE_FAILSAFE_SECONDS = 10L

/** The panel's real Cancel button — the affordance a supersede variant has to press. */
private fun cancelButton(h: ChatPanelTestHarness.Harness): JButton =
    requireNotNull(ChatPanelTestHarness.find(h.panel.root, JButton::class.java) { it.text == "Cancel" }) {
        "No JButton labelled 'Cancel' under ChatPanel.root — UI-SPEC Rule C-1 pins that label, so a " +
            "miss here means it was renamed."
    }

/** The four D-11 labels, defined once so "is this a decision button?" is asked one way. */
private val DECISION_LABELS = setOf("Deny", "Deny for session", "Approve once", "Approve for session")

/** The session-list pending marker, verbatim from the UI-SPEC copywriting contract. */
private const val PENDING_MARKER = "Awaiting approval"

/**
 * Every label the sessions-list renderer produces for the first session row.
 *
 * The renderer is invoked directly rather than waiting for a paint: a headless `JList` never paints,
 * so the marker would otherwise be unassertable — and an unasserted UI affordance is exactly the kind
 * of claim this phase is meant to stop making. This is the same production renderer the list uses,
 * reached through `cellRenderer`, so nothing about it is modelled.
 *
 * Searched from `sessionsComponent()` rather than `root`: the sessions list is a SIBLING of the chat
 * transcript, handed to `MainTab` separately, so it is not under `ChatPanel.root` at all.
 */
@Suppress("UNCHECKED_CAST")
private fun sessionRowLabels(h: ChatPanelTestHarness.Harness): List<String> {
    val list =
        requireNotNull(ChatPanelTestHarness.find(h.panel.sessionsComponent(), JList::class.java)) {
            "No JList under ChatPanel.sessionsComponent() — the sessions-list lookup is stale."
        } as JList<Any?>
    val renderer = list.cellRenderer as ListCellRenderer<Any?>
    val row = renderer.getListCellRendererComponent(list, list.model.getElementAt(0), 0, false, false)
    return allDescendants(row as Container).filterIsInstance<JLabel>().map { it.text }
}

/** The fenced payload shape `ToolCallParser.extractFirst` resolves (ToolCallParser.kt:80-108). */
private fun toolCall(
    tool: String,
    argsJson: String,
): String =
    """
    ```json
    {"tool":"$tool","args":$argsJson}
    ```
    """.trimIndent()

private fun allDescendants(root: Container): List<Component> =
    root.components.flatMap { child ->
        listOf(child) + if (child is Container) allDescendants(child) else emptyList()
    }

/**
 * Every live decision button under [root], in render order.
 *
 * A count, not a first match, because the properties that carry the security claim here are
 * exhaustive ones: "exactly two actions", "no button remains anywhere in the transcript".
 */
private fun decisionButtons(root: Container): List<AbstractButton> = allDescendants(root).filterIsInstance<AbstractButton>().filter { it.text in DECISION_LABELS }

/**
 * The card still awaiting a decision, or `null` if nothing is pending.
 *
 * [ChatPanelTestHarness.findApprovalCard] returns the FIRST card in the transcript, which is the right
 * answer for "did a card appear at all?" and the wrong one once a chain has produced several: the
 * earlier ones are resolved records whose buttons have been removed, so clicking on them is impossible
 * and asserting on them is misleading.
 */
private fun liveApprovalCard(root: Container): ToolApprovalCard? = allDescendants(root).filterIsInstance<ToolApprovalCard>().lastOrNull { decisionButtons(it).isNotEmpty() }

/** Clicks a decision button on the EDT, exactly as the AWT event pump would dispatch it. */
private fun click(
    card: Container,
    label: String,
) {
    val button =
        requireNotNull(decisionButtons(card).firstOrNull { it.text == label }) {
            "No '$label' button on the card. Present: ${decisionButtons(card).map { it.text }}"
        }
    SwingUtilities.invokeAndWait { button.doClick() }
}

/**
 * Every prompt string handed to the backend, in order.
 *
 * `text` is the third parameter of `AgentSupervisor.sendChat`; the other twelve are matched
 * positionally so the captor lines up with it.
 */
private fun sentPrompts(h: ChatPanelTestHarness.Harness): List<String> {
    val prompt = argumentCaptor<String>()
    verify(h.supervisor, atLeast(1)).sendChat(
        any(),
        any(),
        prompt.capture(),
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
    return prompt.allValues
}

private fun verifySendChatCount(
    h: ChatPanelTestHarness.Harness,
    expected: Int,
) {
    verify(h.supervisor, times(expected)).sendChat(
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
}

/**
 * How many backend turns a chain of nothing but denials may produce, DERIVED rather than written out.
 *
 * Walks the real budget with the real helpers — `ChatPanel.MAX_AUTO_TOOL_ITERATIONS` (widened to
 * `internal` for exactly this), `ToolApprovalGate.allowsFurtherToolCalls` and
 * `ToolApprovalGate.nextIterationBudget` — so raising the budget or changing either helper moves this
 * expectation with it instead of leaving a stale literal quietly passing.
 *
 * One initial user turn, plus one followup per denial. D-13 makes a denial cost the same as an
 * approval, so the walk terminates.
 */
private fun expectedTurnsForAFullyDeniedChain(): Int {
    var remaining = ChatPanel.MAX_AUTO_TOOL_ITERATIONS
    var turns = 1
    while (remaining > 0) {
        turns++
        if (!ToolApprovalGate.allowsFurtherToolCalls(remaining)) break
        remaining = ToolApprovalGate.nextIterationBudget(remaining)
    }
    return turns
}

/**
 * The trace id of the single parked decision.
 *
 * Every audit assertion in this file needs it: `AuditLogger.registerGlobalEmitter` is a process-global
 * singleton, panels built by earlier tests are never shut down, and their queued `invokeLater` chains
 * run on this test's drains — so a positional or by-tool-name filter over [auditEvents] silently reads
 * another test's events. The trace id is the one field that is this chain's alone.
 */
private fun pendingTraceId(h: ChatPanelTestHarness.Harness): String {
    lateinit var traceId: String
    SwingUtilities.invokeAndWait {
        val field = ChatPanel::class.java.getDeclaredField("pendingDecisions")
        field.isAccessible = true
        val pending = field.get(h.panel) as Map<*, *>
        val record = requireNotNull(pending.values.singleOrNull()) { "Expected exactly one parked decision; found ${pending.keys}." }
        val slot = record.javaClass.getDeclaredField("traceId").also { it.isAccessible = true }
        traceId = slot.get(record) as String
    }
    return traceId
}

/**
 * Calls `ChatPanel.resolveToolDecision` for the single parked session, on the EDT.
 *
 * Reflection for the same reason [parkContinuation] uses it: the production path cannot be made to
 * produce this argument — the card renders no session button for a CONFIRM_EACH tool — and the
 * property under test is the gate/card disagreement handling, which is reached no other way.
 */
private fun invokeResolveToolDecision(
    h: ChatPanelTestHarness.Harness,
    decision: ToolDecision,
) {
    SwingUtilities.invokeAndWait {
        val sessionId = requireNotNull(pendingSessionIds(h).singleOrNull()) { "Expected exactly one parked decision; found ${pendingSessionIds(h)}." }
        val method =
            ChatPanel::class.java.getDeclaredMethod(
                "resolveToolDecision",
                String::class.java,
                ToolDecision::class.java,
            )
        method.isAccessible = true
        method.invoke(h.panel, sessionId, decision)
    }
}

/** How many sessions currently hold a parked decision. */
private fun pendingDecisionCount(h: ChatPanelTestHarness.Harness): Int = pendingSessionIds(h).size

private fun pendingSessionIds(h: ChatPanelTestHarness.Harness): Set<*> {
    val field = ChatPanel::class.java.getDeclaredField("pendingDecisions")
    field.isAccessible = true
    return (field.get(h.panel) as Map<*, *>).keys
}

/** Declared as a `tasks.test` input in `build.gradle.kts`; the two must stay in step. */
private const val CHAT_PANEL_SOURCE = "src/main/kotlin/com/six2dez/burp/aiagent/ui/ChatPanel.kt"

/**
 * The source text of one `ChatPanel` function, brace-matched from its declaration.
 *
 * Reading source is the sanctioned fallback for [ChatPanelToolGateTest.userDialogPathIsNotDoublePrompted]
 * only, where the production path is a modal `JDialog` and cannot be constructed headlessly at all.
 * Every other test in this file asserts on executed behaviour.
 */
private fun functionBody(declaration: String): String {
    val file = File(CHAT_PANEL_SOURCE)
    // Named, resolved and asserted rather than left to surface as a bare FileNotFoundException, which
    // is what a build-layout change would otherwise produce here (DecisionsAdrTest.readProjectFile does
    // the same, for the same reason). `build.gradle.kts` declares this path as a `tasks.test` input, so
    // an edit to it invalidates the cache and these structural assertions actually re-run.
    assertTrue(
        file.isFile,
        "Expected to find `$CHAT_PANEL_SOURCE` relative to the test working directory " +
            "`${System.getProperty("user.dir")}`, resolved as `${file.absolutePath}`. If the build " +
            "layout changed, fix the path here and in the matching `tasks.test` input declaration.",
    )
    val source = file.readText()
    val start = source.indexOf(declaration)
    require(start >= 0) { "No '$declaration' in ChatPanel.kt — this structural assertion is stale." }
    val open = source.indexOf('{', start)
    var depth = 0
    var index = open
    while (index < source.length) {
        if (source[index] == '{') depth++
        if (source[index] == '}') {
            depth--
            if (depth == 0) break
        }
        index++
    }
    return source.substring(open, index + 1)
}

/**
 * The failure injected into an APPROVED tool call.
 *
 * An [Error] on purpose — see the comment at the injection site. Named rather than reusing
 * [AssertionError] so that if it ever surfaces in a stack trace it says why it exists, and so it can
 * never be confused with a JUnit assertion failing for real.
 */
private class InjectedToolFailure(
    message: String,
) : Error(message)

/**
 * Substitutes [onCompleted] into the LIVE pending record the production path just parked.
 *
 * Reflection, and deliberately narrow about it: the only producer of a non-null `onCompleted` is
 * `MainTab.openChatWithContext`, which has no callers yet, and the only route to it —
 * `startSessionFromContext` — blocks on `ContextPreviewDialog.confirm`, an application-modal dialog
 * that cannot be driven under `-Djava.awt.headless=true`. So the record is built by the real gate on
 * the real Send path and ONLY its callback slot is swapped; everything before and after is production
 * code. The alternative — asserting on source text — is what this suite exists not to do.
 *
 * Runs on the EDT because `pendingDecisions` is EDT-confined (REL-01). Mutating it from the JUnit
 * thread would make this fixture a worse offender than the code it guards.
 *
 * @return the parked chain's trace id, which is the only field that identifies this chain's audit
 *   events among those of every other still-live panel the global emitter also sees.
 */
private fun parkContinuation(
    h: ChatPanelTestHarness.Harness,
    onCompleted: (String, Throwable?) -> Unit,
): String {
    lateinit var traceId: String
    SwingUtilities.invokeAndWait {
        val field = ChatPanel::class.java.getDeclaredField("pendingDecisions")
        field.isAccessible = true

        @Suppress("UNCHECKED_CAST")
        val pending = field.get(h.panel) as MutableMap<String, Any>
        val sessionId =
            requireNotNull(pending.keys.singleOrNull()) {
                "Expected exactly one parked decision to substitute a continuation into; found ${pending.keys}."
            }
        val record = pending.getValue(sessionId)
        val type = record.javaClass
        val constructor =
            requireNotNull(type.declaredConstructors.singleOrNull()) {
                "PendingToolDecision no longer has exactly one constructor — this fixture is stale."
            }
        constructor.isAccessible = true

        fun slot(name: String): Any? = type.getDeclaredField(name).also { it.isAccessible = true }.get(record)

        traceId = slot("traceId") as String
        pending[sessionId] =
            constructor.newInstance(
                slot("sessionId"),
                slot("userText"),
                slot("call"),
                slot("context"),
                slot("remainingToolIterations"),
                traceId,
                onCompleted,
                slot("card"),
            )
    }
    return traceId
}
