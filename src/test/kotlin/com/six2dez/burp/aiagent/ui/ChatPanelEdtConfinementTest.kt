package com.six2dez.burp.aiagent.ui

import burp.api.montoya.proxy.ProxyHttpRequestResponse
import com.six2dez.burp.aiagent.TestSettings
import com.six2dez.burp.aiagent.audit.ActivityType
import com.six2dez.burp.aiagent.audit.AuditLogger
import com.six2dez.burp.aiagent.config.AgentSettings
import com.six2dez.burp.aiagent.mcp.ToolApprovalGate
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNotEquals
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertTimeoutPreemptively
import org.mockito.Mockito.mockingDetails
import org.mockito.kotlin.any
import org.mockito.kotlin.anyOrNull
import org.mockito.kotlin.argumentCaptor
import org.mockito.kotlin.atLeast
import org.mockito.kotlin.doAnswer
import org.mockito.kotlin.never
import org.mockito.kotlin.times
import org.mockito.kotlin.verify
import org.mockito.kotlin.whenever
import java.awt.CardLayout
import java.awt.Component
import java.awt.Container
import java.io.File
import java.time.Duration
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicReference
import javax.swing.AbstractButton
import javax.swing.JButton
import javax.swing.JEditorPane
import javax.swing.JList
import javax.swing.JTextArea
import javax.swing.SwingUtilities

/**
 * REL-05 / SC1 · SC2 · SC3 — an approved tool call runs OFF the AWT Event Dispatch Thread.
 *
 * **This file drives a REAL [ChatPanel] through its REAL Send button and its REAL approval card**, via
 * [ChatPanelTestHarness]. Nothing about the dispatch path is modelled: the assertions read a `Thread`
 * the production code actually created, captured inside the deep-stub `MontoyaApi` at the moment the
 * tool body ran.
 *
 * **Naming constraint (hard), inherited from [ChatPanelTestHarness]'s own KDoc.** The PR gate runs
 * `./gradlew test -PexcludeHeavyTests=true` (`.github/workflows/build.yml:47`) and
 * `build.gradle.kts:206-213` excludes `*IntegrationTest`, `*ConcurrencyTest`, `*BackpressureTest`,
 * `*RestartPolicyTest` and `*SupervisionTest` under that flag. `ChatPanelConcurrencyTest` already sits
 * in the excluded set, which makes `*ConcurrencyTest` the natural — and silently fatal — name to reach
 * for here. `ChatPanelEdtConfinementTest` is the approved one. Do not rename this class.
 *
 * **No assertion in this file compares an elapsed duration to a threshold.** Every timeout present is a
 * deadlock failsafe whose margin over the work is four orders of magnitude — categorically unlike the
 * `RedactionTest` wall-clock flake, where a 50 ms deadline bounds work of the same order.
 *
 * **`LargeClass` is suppressed inline, and the alternatives are worse rather than merely harder.**
 * detekt's threshold is a real signal on production code and a poor one here: this class is 17
 * acceptance scenarios for one requirement, each carrying the KDoc that records what its assertion
 * measures and why the obvious cheaper form would pass vacuously. Splitting it would mint a second
 * suite name, and the naming constraint above is exactly why that is not a free move — a new suite
 * that lands on one of the five excluded suffixes never runs on the cross-platform matrix at all.
 * A baseline entry is also unavailable: `detekt-baseline.xml` is pinned at 1096 entries as the
 * v0.10.0 milestone metric Phase 26 improves against, so adding one moves the metric the wrong way to
 * silence a finding about a test file. The inline suppression with its reason attached follows the
 * same convention `ExternalMcpClientManager` and plan 23-03's two-layer `finally` already use.
 */
@Suppress("LargeClass")
class ChatPanelEdtConfinementTest {
    /**
     * S-01 / SC1 / SC2 / AI-SPEC E2 + E9 — the tool body runs on a named daemon thread that is not the
     * EDT, proven from a captured `Thread` rather than inferred after the fact.
     *
     * Capturing the `Thread` itself rather than a `Boolean` satisfies three separate claims from one
     * observation — not the EDT (E2), daemon (E9's unload clause), named (E9's thread-dump clause) —
     * and it means the assertions read a RECORDED thread. Re-deriving thread identity after the drive
     * would answer about the test's own thread, which is never the question.
     *
     * The deep-stub `MontoyaApi` is the only tool-body seam that exists: `McpToolExecutor` is an
     * `object` singleton (`McpToolExecutorImpl.kt:45`) referenced statically at every call site, so
     * there is no executor double to put a probe in.
     */
    @Test
    fun anApprovedChainToolExecutesOnANamedDaemonThread() {
        val toolThread = AtomicReference<Thread?>(null)
        val h = ChatPanelTestHarness.create(modelResponse = toolCall("proxy_http_history", """{"count":5}"""))
        whenever(h.api.proxy().history()).thenAnswer {
            toolThread.set(Thread.currentThread())
            emptyList<ProxyHttpRequestResponse>()
        }

        // A deadlock failsafe, matching ChatPanelToolGateTest.kt:377 — if the dispatch never completes
        // the suite fails instead of stalling CI. Nothing here is timed against it.
        assertTimeoutPreemptively(Duration.ofSeconds(30)) {
            ChatPanelTestHarness.sendUserMessage(h, "summarise the proxy history")
            ChatPanelTestHarness.drainEdt()
            val traceId = pendingTraceId(h)
            click(requireNotNull(ChatPanelTestHarness.findApprovalCard(h.panel.root)) { NO_CARD }, "Approve once")
            ChatPanelTestHarness.awaitToolSettled(label = traceId, count = 1)
        }

        val captured = requireNotNull(toolThread.get()) { "The tool body never ran — nothing was dispatched." }
        assertNotEquals(
            EDT_THREAD_NAME,
            captured.name,
            "SC1/SC2: an approved tool call must not execute on the EDT. Burp refuses HTTP from the EDT " +
                "and the whole Burp UI freezes for as long as the call runs there.",
        )
        assertTrue(captured.isDaemon, "E9/D-08: a non-daemon worker can hold extension unload open.")
        assertTrue(
            captured.name.startsWith("burp-ai-tool"),
            "E9: a stuck worker must be identifiable in a thread dump. Thread name was '${captured.name}'.",
        )
    }

    /**
     * S-02 / SC2 — a Montoya double that refuses the EDT is never called on the EDT.
     *
     * **The double's message is a claim about THIS TEST, not about Burp's runtime.** Research assumption
     * A1 records that Burp's *"Extensions should not make HTTP requests in the Swing event dispatch
     * thread"* exception is corroborated — by this repo's own `MontoyaHttpTransport` workaround for #80
     * and by third-party reports — but not live-confirmed here. Constructing the refusal ourselves is
     * what closes that gap: the test pins *"we do not call Burp's API from the EDT"* against a double we
     * control, so it holds regardless of what a live Burp actually does. Live confirmation is a UAT item
     * routed by plan 23-05. Do not read the message below as evidence of Burp's behaviour.
     *
     * The tool is asserted to have completed **normally** rather than merely to have run: `McpTool.runTool`
     * catches `Exception` and turns it into an error RESULT, so a call that did hit the EDT would still
     * produce a transcript row — and only the recorded run status tells the two apart.
     *
     * **`proxy_http_history` rather than the `http1_request` this scenario was drafted against, and the
     * reason is measured rather than assumed.** Driven headlessly, `http1_request` records
     * `status=error` with a 112-character error result before any EDT question arises: its body reaches
     * Montoya's `HttpRequest.httpRequest` static factory, which `McpScopeFilter.deriveScopeUrl`'s own
     * KDoc already records as *"unavailable in pure-JVM unit tests"*. The assertion would then be red
     * for a reason that has nothing to do with the EDT, which is the one thing a red-before-green gate
     * must never be. `proxy_http_history` is the same trust boundary through a seam that works.
     */
    @Test
    fun aToolThatRefusesTheEdtCompletesNormally() {
        val h = ChatPanelTestHarness.create(modelResponse = toolCall("proxy_http_history", """{"count":5}"""))
        whenever(h.api.proxy().history()).thenAnswer {
            check(!SwingUtilities.isEventDispatchThread()) { BURP_EDT_REFUSAL }
            emptyList<ProxyHttpRequestResponse>()
        }

        // assertTimeoutPreemptively runs its block on a SEPARATE thread, so the trace id crosses back
        // through an AtomicReference rather than a captured local.
        val traceIdRef = AtomicReference<String>()
        assertTimeoutPreemptively(Duration.ofSeconds(30)) {
            ChatPanelTestHarness.sendUserMessage(h, "summarise the proxy history")
            ChatPanelTestHarness.drainEdt()
            val card = requireNotNull(ChatPanelTestHarness.findApprovalCard(h.panel.root)) { NO_CARD }
            traceIdRef.set(pendingTraceId(h))
            click(card, "Approve once")
            ChatPanelTestHarness.awaitToolSettled(label = traceIdRef.get(), count = 1)
        }

        val record = decisionsFor(traceIdRef.get()).single()
        assertEquals(
            "ok",
            record["status"],
            "SC2: the tool ran to completion, so it was never entered from the EDT. A status of 'error' " +
                "here means the double's EDT refusal fired — i.e. the call WAS made on the EDT.",
        )
    }

    /**
     * S-01 / SC3 / AI-SPEC E3 — the EDT runs queued work WHILE a tool call is mid-flight.
     *
     * **A mutual latch handshake, not a stopwatch.** The tool double counts down [ToolLatches.entered]
     * and then waits on [ToolLatches.probeRan], which the test counts down from a runnable it queues to
     * the EDT *after* the tool has been entered. A free EDT therefore runs that runnable and the tool
     * returns; a blocked EDT **deadlocks**, and a deadlock is a categorical failure
     * `assertTimeoutPreemptively` reports.
     *
     * **Neither timeout is a wall-clock assertion, and the distinction is not a technicality.** Nothing
     * here is compared against the duration of the work: the inner failsafe bounds a deadlock and the
     * outer one stops CI stalling, exactly as `ChatPanelToolGateTest.kt:377` already does for a
     * non-monotone chain budget. The margin over the work — which settles in microseconds once the
     * handshake resolves — is four orders of magnitude. That is what separates this from the
     * `RedactionTest` flake, where a 50 ms deadline bounds work of the same order and fails under load.
     *
     * The inner failsafe is 10 seconds and not 60 for a budgeted reason: a red-before-green run against
     * the pre-fix tree pays it in full, once, and ten seconds is what that demonstration is worth.
     */
    @Test
    fun theEdtRunsQueuedWorkWhileAToolCallIsMidFlight() {
        val latches = ToolLatches()
        val h = ChatPanelTestHarness.create(modelResponse = toolCall("proxy_http_history", """{"count":5}"""))
        whenever(h.api.proxy().history()).thenAnswer {
            latches.entered.countDown()
            // The tool waits on the EDT. This is what makes a FREE EDT a precondition for the tool
            // returning, and therefore what makes a blocked one a deadlock rather than a slow path.
            check(latches.probeRan.await(HANDSHAKE_FAILSAFE_SECONDS, TimeUnit.SECONDS)) {
                "The EDT never ran a queued runnable while the tool was mid-call — it was blocked inside it."
            }
            emptyList<ProxyHttpRequestResponse>()
        }

        val traceIdRef = AtomicReference<String>()
        assertTimeoutPreemptively(Duration.ofSeconds(30)) {
            ChatPanelTestHarness.sendUserMessage(h, "summarise the proxy history")
            ChatPanelTestHarness.drainEdt()
            val card = requireNotNull(ChatPanelTestHarness.findApprovalCard(h.panel.root)) { NO_CARD }
            traceIdRef.set(pendingTraceId(h))
            click(card, "Approve once")

            assertTrue(
                latches.entered.await(HANDSHAKE_FAILSAFE_SECONDS, TimeUnit.SECONDS),
                "The tool worker never started, so the handshake below would prove nothing.",
            )
            // Queued WHILE the tool is mid-call. On a blocked EDT this never runs and the tool's own
            // await above expires; on a free one it runs and releases the tool.
            SwingUtilities.invokeLater { latches.probeRan.countDown() }
            ChatPanelTestHarness.awaitToolSettled(label = traceIdRef.get(), count = 1)
        }

        // THE RUN STATUS IS THE CLAUSE THAT FAILS LOUDLY, AND IT IS ASSERTED FIRST FOR THAT REASON.
        // The latch count below is NOT sufficient on its own and would pass VACUOUSLY against the
        // pre-fix tree: with the tool running on the EDT, the click blocks until the tool's own await
        // expires, the tool returns an error, the click returns — and only THEN does the queued runnable
        // finally run, leaving the latch at zero and the assertion green with the defect fully present.
        // Completing NORMALLY is the property only a free EDT can produce, because the tool returns
        // normally only if the runnable ran while it was still inside its call.
        assertEquals(
            "ok",
            decisionsFor(traceIdRef.get()).single()["status"],
            "SC3/E3: the tool returned normally, which is possible only if the EDT ran the queued " +
                "runnable while the tool was still mid-call. An 'error' status means the tool's own " +
                "await expired — the EDT was blocked inside the call.",
        )
        assertEquals(
            0L,
            latches.probeRan.count,
            "Corroborates the above: the queued runnable really did execute.",
        )
    }

    /**
     * SC3 / AI-SPEC E3 — a full auto-approved chain produces eight results in submission order.
     *
     * **Selected by trace id, never by list position** (Phase 22 commit `ab55ff5`). `AuditLogger`'s
     * emitter is a process-global hook and panels built by earlier tests in this class are never shut
     * down, so a positional read over the collected events silently mixes in another test's chain. A
     * chain threads ONE trace id through every followup turn, which is what makes it the correct
     * selector — and the `step` field, not the list index, is what carries the ordering claim.
     *
     * [ChatPanelTestHarness.awaitToolSettled] with this chain's own label and a count of eight is the
     * primary synchronisation rather than a raised drain count: a chain of eight daemon workers is
     * precisely what draining the EDT queue is blind to. The chain is selected by the trace id the
     * harness recorded from `sendChat`, because the settle record is process-global and panels from
     * earlier tests may still be settling their own chains.
     */
    @Test
    fun aFullAutoChainProducesEightResultsInSubmissionOrder() {
        // FIRST, AND IN ITS OWN ASSERTION. If the budget ever changes, this fails by name and the test
        // gets renamed — the alternative is a derived expectation that silently relaxes.
        assertEquals(
            8,
            ChatPanel.MAX_AUTO_TOOL_ITERATIONS,
            "This test's name says eight. If the budget changes, rename the test — do not relax it.",
        )
        val h = ChatPanelTestHarness.create(modelResponse = toolCall("scope_check", """{"url":"http://evil.example/"}"""))

        assertTimeoutPreemptively(Duration.ofSeconds(60)) {
            ChatPanelTestHarness.sendUserMessage(h, "check scope repeatedly")
            val chainLabel = ChatPanelTestHarness.chainTraceId(h)
            ChatPanelTestHarness.awaitToolSettled(label = chainLabel, count = ChatPanel.MAX_AUTO_TOOL_ITERATIONS)
        }

        // The chain's identity, taken from the trace ids THIS panel passed to sendChat rather than
        // guessed from the audit log. Re-read after every followup turn: that it still collapses to
        // exactly one value is itself the claim that one chain ran.
        val chainTraceId = ChatPanelTestHarness.chainTraceId(h)
        // LICENSES THE ORDERING CLAIM BELOW, so it is asserted first. A short chain would also produce a
        // correctly ORDERED prefix; only the count fails loudly when the chain stopped early.
        assertEquals(
            ChatPanel.MAX_AUTO_TOOL_ITERATIONS,
            ChatPanelTestHarness.settledLabels().count { it == chainTraceId },
            "Eight tool workers must have settled — one per chain step.",
        )
        assertEquals(
            (1..ChatPanel.MAX_AUTO_TOOL_ITERATIONS).map { it.toString() },
            decisionsFor(chainTraceId).map { it["step"] },
            "SC3: eight results, each recorded at its own chain step, in submission order.",
        )
        // The busy state is cleared exactly once per call: the chain ends in S0.
        assertTrue(sendButton(h).isVisible, "The panel must finish the chain in S0 with Send visible.")
        assertTrue(inputArea(h).isEnabled, "The panel must finish the chain in S0 with the input enabled.")
    }

    /**
     * S-04 / D-07 / UI-SPEC Rules S-5 and C-1 — Cancel is a live affordance while a tool is running,
     * and it tells the user the truth about what happened to their request.
     *
     * The five things Cancel must do in state S3 are asserted together, because each of them is a way
     * the others could be satisfied dishonestly: the panel returns to S0 **immediately** (not when the
     * worker finishes), the transcript says the request was already sent rather than cancelled, the
     * result is discarded with no followup turn, no chain iteration is refunded — and the call is
     * **still audited**, which is D-07's load-bearing corollary. A cancelled call that became an
     * unlogged call would put a hole in the SEC-06 record at exactly the point a user interrupted
     * something.
     *
     * The worker is never interrupted and this test does not check for an interrupt: Montoya's
     * `sendRequest` takes no cancellation token, so an interrupt would work for one transport and
     * silently no-op for Burp's. A cancel that works sometimes is worse than one that states its limits.
     */
    @Test
    fun cancellingARunningToolDiscardsItsResultAndStillAuditsTheCall() {
        val latches = ToolLatches()
        val h = ChatPanelTestHarness.create(modelResponse = toolCall("proxy_http_history", """{"count":5}"""))
        whenever(h.api.proxy().history()).thenAnswer {
            latches.entered.countDown()
            check(latches.probeRan.await(HANDSHAKE_FAILSAFE_SECONDS, TimeUnit.SECONDS)) {
                "The test never released the blocked tool — the cancel window was never opened."
            }
            emptyList<ProxyHttpRequestResponse>()
        }

        val traceIdRef = AtomicReference<String>()
        assertTimeoutPreemptively(Duration.ofSeconds(30)) {
            ChatPanelTestHarness.sendUserMessage(h, "summarise the proxy history")
            ChatPanelTestHarness.drainEdt()
            val card = requireNotNull(ChatPanelTestHarness.findApprovalCard(h.panel.root)) { NO_CARD }
            traceIdRef.set(pendingTraceId(h))
            click(card, "Approve once")
            assertTrue(
                latches.entered.await(HANDSHAKE_FAILSAFE_SECONDS, TimeUnit.SECONDS),
                "The tool worker never started, so there was nothing to cancel.",
            )

            // The real Cancel button, clicked on the EDT exactly as the AWT pump would dispatch it,
            // WHILE the tool is still blocked inside its call.
            SwingUtilities.invokeAndWait { cancelButton(h).doClick() }

            // ASSERTED BEFORE THE LATCH IS RELEASED, and that ordering is the claim. "The panel returns
            // to S0 immediately" is only meaningful while the worker is demonstrably still running —
            // read after the release it would also pass on an implementation that made the user wait.
            assertTrue(sendButton(h).isVisible, "UI-SPEC S-5: Cancel returns the panel to S0 at once.")
            assertTrue(inputArea(h).isEnabled, "UI-SPEC S-5: the input is usable again at once.")

            latches.probeRan.countDown()
            ChatPanelTestHarness.awaitToolSettled(label = traceIdRef.get(), count = 1)
        }

        val transcript = transcriptText(h)
        assertTrue(
            transcript.contains("was already sent to Burp and will finish"),
            "UI-SPEC C-1: the user must be told the request really was sent. Transcript: $transcript",
        )
        assertFalse(
            transcript.contains("Request cancelled."),
            "UI-SPEC C-1: the backend-turn line is FALSE on the tool path — the request was not cancelled.",
        )
        assertFalse(
            transcript.contains(EMPTY_HISTORY_ROW),
            "UI-SPEC S4: a superseded run renders no transcript row for its discarded result.",
        )
        // D-07's corollary: the call reached Burp and cannot be recalled, so it stays in the record.
        val record = decisionsFor(traceIdRef.get()).single()
        assertEquals(
            ChatPanel.SUPERSEDED_RUN_STATUS,
            record["status"],
            "The cancelled call must be audited, with the cancellation recorded rather than filed as a " +
                "malfunction or as a policy refusal.",
        )
        assertEquals("approve_once", record["decision"], "The decision the user really made is unchanged by the cancel.")
        // No followup turn: exactly the one turn the user's own message started. A second would mean the
        // discarded result was fed back to the model anyway.
        verifySendChatCount(h, 1)
    }

    /**
     * S-03 / SC1 / AI-SPEC E1 — a Deny executes nothing and STARTS nothing, and the model is still told.
     *
     * **The dispatch record is the load-bearing selector, and reading the settle record instead would
     * make this test pass vacuously.** A settle event is written from the EDT tail's `finally`, so in
     * precisely the world this assertion exists to catch — a denial that dispatched a worker anyway —
     * that worker has not finished when the assertion runs and its label is missing from the settle
     * record too. The dispatch record is written synchronously with the dispatch statement itself
     * (`OffEdtDispatch.kt`), so absence there is a claim about what happened rather than about timing.
     *
     * The captured `Thread` is the same argument one layer down: `never()` on the Montoya double proves
     * Burp was not reached, and a null capture proves no worker got far enough to reach for it.
     *
     * **This is AI-SPEC E1's PASS clause.** Phase 23 changes WHERE an approved call runs; it must never
     * change WHETHER a call runs. The SEC-06 trust boundary is still evaluated on the EDT, before any
     * dispatch, and a refusal still refuses.
     */
    @Test
    fun aDeniedToolCallStartsNoWorkerAndStillContinuesTheConversation() {
        val toolThread = AtomicReference<Thread?>(null)
        // A CONFIRM-tier tool, deliberately: an AUTO-tier one raises no card at all, so it could not
        // tell a working gate from a missing one.
        val h = ChatPanelTestHarness.create(modelResponse = toolCall("proxy_http_history", """{"count":5}"""))
        whenever(h.api.proxy().history()).thenAnswer {
            toolThread.set(Thread.currentThread())
            emptyList<ProxyHttpRequestResponse>()
        }

        val traceIdRef = AtomicReference<String>()
        assertTimeoutPreemptively(Duration.ofSeconds(30)) {
            ChatPanelTestHarness.sendUserMessage(h, "summarise the proxy history")
            ChatPanelTestHarness.drainEdt()
            val card = requireNotNull(ChatPanelTestHarness.findApprovalCard(h.panel.root)) { NO_CARD }
            // Captured while exactly one decision is parked, before the click resolves it.
            traceIdRef.set(pendingTraceId(h))
            click(card, "Deny")
            ChatPanelTestHarness.drainEdt(times = LONG_DRAIN)
        }

        verify(h.api.proxy(), never()).history()
        assertNull(
            toolThread.get(),
            "SEC-06 / E1: the tool body ran on ${toolThread.get()?.name} after a Deny. A refusal that " +
                "still reaches Burp is the whole failure this gate exists to prevent.",
        )
        assertFalse(
            ChatPanelTestHarness.dispatchedLabels().contains(traceIdRef.get()),
            "REL-05 / E1: a denied call must start NO worker. Read from the dispatch record, which is " +
                "written synchronously with the dispatch — an unfinished worker is absent from the " +
                "settle record too, so that record could not tell these two worlds apart. " +
                "Dispatched: ${ChatPanelTestHarness.dispatchedLabels()}.",
        )
        val prompts = sentPrompts(h)
        assertTrue(
            prompts.size >= 2,
            "D-12: a refusal must be answerable — the model gets the denial back and the session " +
                "continues. Turns: ${prompts.size}.",
        )
        assertTrue(
            prompts.any { it.contains(ToolApprovalGate.DENIAL_RESULT) },
            "The followup must carry the one D-12 denial constant verbatim, so the model is told the " +
                "call was refused rather than left to infer it from silence.",
        )
    }

    /**
     * S-05 / D-08 — deleting a session supersedes the tool worker its chain left running.
     *
     * **This scenario is the whole reason plan 23-04's Task 1 exists, and it is written so that
     * removing that one line turns it red.** Session delete is the ONE teardown exit of four that does
     * not route through `cancelInFlightRequest`, so it inherited nothing from plan 23-01's supersede
     * cell (research F-5). Without the explicit `runningTool.take()` in `deleteConfirmedSession` the
     * returning worker finds its token still current, takes the SUCCESS branch, files an `"ok"` run
     * for a session that no longer exists, and sends a followup turn continuing that dead chain.
     *
     * **Two clauses are loud and two are not, and which is which was MEASURED against the reverted
     * tree rather than assumed.** Loud: the recorded run status (`"ok"` with the defect present), and
     * the `supersedeReason` key, which only the superseded exit merges onto the pair. Corroboration
     * only:
     * - the missing transcript row — `ToolCallCapture` freezes the `SessionPanel` OBJECT before
     *   dispatch, and a deleted session's panel is DETACHED rather than destroyed, so the row really
     *   is written on the un-superseded tree, into a panel [transcriptText] can no longer reach;
     * - the turn count — `sendMessage` returns early when `sessionPanels[sessionId]` is null
     *   (`ChatPanel.kt`), and a session delete removes exactly that entry, so the followup the success
     *   branch asks for is refused one layer further down whether or not the supersede happened.
     *
     * Both stay, because both are the claim for a supersede whose panel SURVIVES — the unload exit
     * below is one — and neither may ever be promoted to carry this test on its own.
     *
     * **`deleteConfirmedSession` rather than `deleteSession`, and the modal was not deleted to get
     * here.** `deleteSession` opens `JOptionPane.showConfirmDialog`, which constructs a `JDialog` and
     * throws `HeadlessException` under `-Djava.awt.headless=true`; every line of the teardown sits
     * below it. Production keeps the confirmation in one function and the teardown in another, so
     * this drives the real teardown while real users still meet the real modal.
     */
    @Test
    fun deletingASessionSupersedesItsRunningToolAndStillAuditsTheCall() {
        val latches = ToolLatches()
        val discharged = CountDownLatch(1)
        val h = ChatPanelTestHarness.create(modelResponse = toolCall("proxy_http_history", """{"count":5}"""))
        whenever(h.api.proxy().history()).thenAnswer {
            latches.entered.countDown()
            check(latches.probeRan.await(HANDSHAKE_FAILSAFE_SECONDS, TimeUnit.SECONDS)) {
                "The test never released the blocked tool — the delete window was never opened."
            }
            emptyList<ProxyHttpRequestResponse>()
        }

        val traceIdRef = AtomicReference<String>()
        assertTimeoutPreemptively(Duration.ofSeconds(30)) {
            ChatPanelTestHarness.sendUserMessage(h, "summarise the proxy history")
            ChatPanelTestHarness.drainEdt()
            val card = requireNotNull(ChatPanelTestHarness.findApprovalCard(h.panel.root)) { NO_CARD }
            // Substitutes a continuation into the record the REAL gate just parked, so T-22-31's
            // "discharged rather than dropped" clause is assertable on this exit too.
            traceIdRef.set(parkContinuation(h) { _, _ -> discharged.countDown() })
            click(card, "Approve once")
            assertTrue(
                latches.entered.await(HANDSHAKE_FAILSAFE_SECONDS, TimeUnit.SECONDS),
                "The tool worker never started, so there was nothing for the delete to supersede.",
            )

            // The user deletes the session out from under the running call. On the EDT, exactly as the
            // popup-menu action listener would reach it once the modal has been answered.
            SwingUtilities.invokeAndWait { h.panel.deleteConfirmedSession(onlySession(h)) }

            latches.probeRan.countDown()
            ChatPanelTestHarness.awaitToolSettled(label = traceIdRef.get(), count = 1)
        }

        // LOUD CLAUSE 1. On a tree without the explicit supersede this reads "ok": the worker's token
        // still matched, so the tail applied a result belonging to a session that was already gone.
        val record = decisionsFor(traceIdRef.get()).single()
        assertEquals(
            ChatPanel.SUPERSEDED_RUN_STATUS,
            record["status"],
            "D-08: a session delete must supersede the tool worker its chain left running. This exit " +
                "does not route through the in-flight cancel, so it inherits nothing and needs its own take().",
        )
        // LOUD CLAUSE 2, and independent of the first: only the superseded exit merges a
        // supersedeReason onto the pair, so this fails on the un-superseded tree even if some later
        // change made "ok" and "cancelled" agree. E4's ordering claim rides in the same assertion.
        assertOrderedAuditPair(h, record, traceIdRef.get(), extraKeys = setOf(SUPERSEDE_REASON_KEY))
        // CORROBORATION. See the KDoc: sendMessage refuses a followup for a session whose panel is
        // gone, so this clause is satisfied by the defect too. It is the real claim only where the
        // panel survives the supersede.
        verifySendChatCount(h, 1)
        assertTrue(
            discharged.await(HANDSHAKE_FAILSAFE_SECONDS, TimeUnit.SECONDS),
            "T-22-31: the parked continuation must be discharged on the superseded exit, not dropped — " +
                "no followup turn is carrying it any more.",
        )
        // CORROBORATION ONLY. See the KDoc: the deleted panel is detached, not destroyed, so this
        // clause is also satisfied by the defect. It is here to fail alongside the two above, never
        // instead of them.
        assertFalse(
            transcriptText(h).contains(EMPTY_HISTORY_ROW),
            "UI-SPEC S4: a superseded run renders no transcript row.",
        )
    }

    /**
     * S-06 / D-08 / AI-SPEC E5 — a Burp project change supersedes every running tool worker.
     *
     * Unlike a session delete this exit inherits its supersede: `clearInMemorySessionState` calls the
     * in-flight cancel, which takes the running-tool token. So this test is a REGRESSION guard rather
     * than a red-before-green demonstration, and it is worth having for exactly that reason — the
     * coverage is invisible in the source of `clearInMemorySessionState`, which mentions no worker.
     *
     * The E5 clause is asserted on the map state AFTER the worker has settled: a tail that wrote
     * anything back into the session maps would resurrect a session the project change destroyed, and
     * the user would be looking at a chat belonging to a Burp project they had already left.
     *
     * **Loud clauses: the run status and the `supersedeReason` key.** The turn count is corroboration
     * on this exit for the same measured reason it is on the session-delete one — a project change
     * clears `sessionPanels`, and `sendMessage` refuses a followup when the session's panel is gone,
     * so no second turn appears whether or not the worker was superseded.
     */
    @Test
    fun aProjectChangeSupersedesTheRunningToolAndNoWriteReachesTheDisposedPanel() {
        val latches = ToolLatches()
        val discharged = CountDownLatch(1)
        val h = ChatPanelTestHarness.create(modelResponse = toolCall("proxy_http_history", """{"count":5}"""))
        whenever(h.api.proxy().history()).thenAnswer {
            latches.entered.countDown()
            check(latches.probeRan.await(HANDSHAKE_FAILSAFE_SECONDS, TimeUnit.SECONDS)) {
                "The test never released the blocked tool — the project-change window was never opened."
            }
            emptyList<ProxyHttpRequestResponse>()
        }

        val traceIdRef = AtomicReference<String>()
        assertTimeoutPreemptively(Duration.ofSeconds(30)) {
            ChatPanelTestHarness.sendUserMessage(h, "summarise the proxy history")
            ChatPanelTestHarness.drainEdt()
            val card = requireNotNull(ChatPanelTestHarness.findApprovalCard(h.panel.root)) { NO_CARD }
            traceIdRef.set(parkContinuation(h) { _, _ -> discharged.countDown() })
            click(card, "Approve once")
            assertTrue(
                latches.entered.await(HANDSHAKE_FAILSAFE_SECONDS, TimeUnit.SECONDS),
                "The tool worker never started, so there was nothing for the project change to supersede.",
            )

            // MainTab.onProjectChanged()'s whole body, reached on the EDT.
            SwingUtilities.invokeAndWait { h.panel.clearInMemorySessionState() }
            assertEquals(0, sessionCount(h), "Setup: the project change really did clear every session.")

            latches.probeRan.countDown()
            ChatPanelTestHarness.awaitToolSettled(label = traceIdRef.get(), count = 1)
        }

        val record = decisionsFor(traceIdRef.get()).single()
        assertEquals(
            ChatPanel.SUPERSEDED_RUN_STATUS,
            record["status"],
            "D-08: a project change must supersede the running tool worker.",
        )
        assertOrderedAuditPair(h, record, traceIdRef.get(), extraKeys = setOf(SUPERSEDE_REASON_KEY))
        // Corroboration on THIS exit — see the KDoc. Loud on the unload exit, where the panel lives.
        verifySendChatCount(h, 1)
        assertTrue(
            discharged.await(HANDSHAKE_FAILSAFE_SECONDS, TimeUnit.SECONDS),
            "T-22-31: the parked continuation must be discharged when the project changes under it.",
        )
        // E5, read after the worker has finished its tail: nothing the returning worker did put a
        // session back. Read before the settle this would be a claim about the project change alone.
        assertEquals(
            0,
            sessionCount(h),
            "AI-SPEC E5: no write from the returning worker may reach the disposed panel — a resurrected " +
                "session belongs to the Burp project the user already left.",
        )
    }

    /**
     * S-07 / SC6 / D-08 — extension unload supersedes the worker and does NOT wait for it.
     *
     * **The non-blocking claim is proved as a deadlock, not as a duration.** `shutdown()` is called
     * from a non-EDT thread while the tool double is still blocked inside its call. If unload joined
     * the worker, nothing would ever release the tool's latch — the release below happens only after
     * `shutdown()` returns — and `assertTimeoutPreemptively` reports that categorically. Nothing here
     * is compared against elapsed time; this file contains no wall-clock reading at all.
     *
     * **What this scenario cannot catch, stated rather than implied:** a BOUNDED wait
     * (`future.get(10, SECONDS)`), which would expire and let `shutdown()` return late instead of
     * hanging. That shape is D-08's actual named counter-example, and the guard against it is the
     * structural one in plan 23-04's Task 1 — `shutdown()`'s body contains no `.get(` or `.join(`.
     * Two guards, because one covers the hang and the other covers the timeout.
     *
     * The daemon assertion is the other half of why not waiting is safe: a non-daemon worker would
     * hold the JVM open past unload even with nobody waiting on it.
     */
    @Test
    fun unloadSupersedesTheRunningToolWithoutWaitingForIt() {
        val latches = ToolLatches()
        val discharged = CountDownLatch(1)
        val toolThread = AtomicReference<Thread?>(null)
        val toolReturned = AtomicBoolean(false)
        val h = ChatPanelTestHarness.create(modelResponse = toolCall("proxy_http_history", """{"count":5}"""))
        whenever(h.api.proxy().history()).thenAnswer {
            toolThread.set(Thread.currentThread())
            latches.entered.countDown()
            check(latches.probeRan.await(HANDSHAKE_FAILSAFE_SECONDS, TimeUnit.SECONDS)) {
                "The test never released the blocked tool — shutdown() must have waited for it."
            }
            toolReturned.set(true)
            emptyList<ProxyHttpRequestResponse>()
        }

        val traceIdRef = AtomicReference<String>()
        assertTimeoutPreemptively(Duration.ofSeconds(30)) {
            ChatPanelTestHarness.sendUserMessage(h, "summarise the proxy history")
            ChatPanelTestHarness.drainEdt()
            val card = requireNotNull(ChatPanelTestHarness.findApprovalCard(h.panel.root)) { NO_CARD }
            traceIdRef.set(parkContinuation(h) { _, _ -> discharged.countDown() })
            click(card, "Approve once")
            assertTrue(
                latches.entered.await(HANDSHAKE_FAILSAFE_SECONDS, TimeUnit.SECONDS),
                "The tool worker never started, so there was nothing for unload to supersede.",
            )

            // Burp's unload handler calls this from a Montoya thread, not the EDT — which is the case
            // shutdown()'s own invokeAndWait exists for. Returning from here at all, with the worker
            // demonstrably still inside its call, IS the SC6 claim.
            h.panel.shutdown()
            assertFalse(
                toolReturned.get(),
                "SC6 / D-08: unload returned only after the worker finished, so it waited for it. " +
                    "A tool call has no cancellation token; waiting is how unload becomes a hang.",
            )

            latches.probeRan.countDown()
            ChatPanelTestHarness.awaitToolSettled(label = traceIdRef.get(), count = 1)
        }

        val record = decisionsFor(traceIdRef.get()).single()
        assertEquals(
            ChatPanel.SUPERSEDED_RUN_STATUS,
            record["status"],
            "D-08: unload must supersede the running tool worker, so its result is never applied to a " +
                "panel whose classloader Burp is tearing down.",
        )
        // LOUD ON THIS EXIT, unlike on the session-delete and project-change ones. Unload leaves
        // sessionPanels intact, so sendMessage's own null-panel refusal does not stand in for the
        // supersede here: an un-superseded tail really does dispatch a backend request into a Burp
        // that is tearing the extension classloader down (T-22-33).
        verifySendChatCount(h, 1)
        assertOrderedAuditPair(h, record, traceIdRef.get(), extraKeys = setOf(SUPERSEDE_REASON_KEY))
        assertTrue(
            discharged.await(HANDSHAKE_FAILSAFE_SECONDS, TimeUnit.SECONDS),
            "T-22-31: the parked continuation must be discharged at unload, not dropped.",
        )
        assertTrue(
            requireNotNull(toolThread.get()) { "The tool body never ran." }.isDaemon,
            "E9 / T-23-12: unload does not join the worker, so the daemon flag is what stops a stuck " +
                "one holding the JVM open. Without it, 'we do not wait' becomes 'Burp does not exit'.",
        )
    }

    /**
     * S-09 / CFM 2 / T-23-10 — an approved call that is superseded mid-flight executes EXACTLY ONCE.
     *
     * The supersede is a compare-and-set with exactly one winner: whoever takes the token wins, and
     * the returning worker's `clearIfMatches` loses and discards. The failure this rules out is the
     * one that would matter most on a security tool — the resolution path and the worker both
     * proceeding, so a single human `Approve once` click puts two requests on the wire.
     *
     * **A genuine `CONFIRM_EACH` tool, not a `CONFIRM` one approved once.** The two behave alike for a
     * single call, so substituting would have quietly turned a tier-specific claim into a generic one.
     * `scope_include` is the one CONFIRM_EACH tool that both reaches a stubbable Montoya seam and
     * completes headlessly: `http1_request` / `http2_request` die in `HttpRequest.httpRequest`, which
     * `McpScopeFilter.deriveScopeUrl`'s KDoc records as unavailable in pure-JVM unit tests; every
     * `scan_*` one is Professional-only; `ai_analyze` and `ai_passive_scan` need runtime AI
     * dependencies the chat context does not carry. Reaching it costs the settings override below,
     * which is a real user configuration rather than a test hook.
     *
     * The two-button assertion is a SETUP assertion: it fails if `scope_include` ever stops being
     * CONFIRM_EACH, rather than letting this test silently become the CONFIRM case.
     */
    @Test
    fun aSupersededConfirmEachCallReachesBurpExactlyOnce() {
        val latches = ToolLatches()
        val h =
            ChatPanelTestHarness.create(
                modelResponse = toolCall("scope_include", """{"url":"http://s09.example/"}"""),
                settings = settingsEnabling("scope_include"),
            )
        // Resolved to a local FIRST. `includeInScope` returns void, so the stub has to be written
        // `doAnswer {}.whenever(mock)`, and leaving the deep-stub `h.api.scope()` call inside the
        // `whenever(...)` argument makes Mockito read THAT call as the one being stubbed —
        // UnfinishedStubbingException, measured.
        val scope = h.api.scope()
        doAnswer {
            latches.entered.countDown()
            check(latches.probeRan.await(HANDSHAKE_FAILSAFE_SECONDS, TimeUnit.SECONDS)) {
                "The test never released the blocked tool — the supersede window was never opened."
            }
            null
        }.whenever(scope).includeInScope(any<String>())

        val traceIdRef = AtomicReference<String>()
        assertTimeoutPreemptively(Duration.ofSeconds(30)) {
            ChatPanelTestHarness.sendUserMessage(h, "add that host to scope")
            ChatPanelTestHarness.drainEdt()
            val card = requireNotNull(ChatPanelTestHarness.findApprovalCard(h.panel.root)) { NO_CARD }
            assertEquals(
                listOf("Deny", "Approve once"),
                decisionButtons(card).map { it.text },
                "Setup: this scenario is about CONFIRM_EACH. Two actions is what that tier offers; four " +
                    "would mean the tool was re-tiered and this test now proves something else.",
            )
            traceIdRef.set(pendingTraceId(h))
            click(card, "Approve once")
            assertTrue(
                latches.entered.await(HANDSHAKE_FAILSAFE_SECONDS, TimeUnit.SECONDS),
                "The tool worker never started, so there was nothing to supersede.",
            )

            SwingUtilities.invokeAndWait { cancelButton(h).doClick() }

            latches.probeRan.countDown()
            ChatPanelTestHarness.awaitToolSettled(label = traceIdRef.get(), count = 1)
        }

        // THE CLAIM. One click, one call on the wire — read from the Montoya double the tool body
        // actually reached, not from a counter this test keeps.
        verify(scope, times(1)).includeInScope(any<String>())
        // And the loser of the compare-and-set does not re-enter later: drained well past the point a
        // second dispatch would have landed.
        ChatPanelTestHarness.drainEdt(times = LONG_DRAIN)
        verify(scope, times(1)).includeInScope(any<String>())

        val record = decisionsFor(traceIdRef.get()).single()
        assertEquals(
            ChatPanel.SUPERSEDED_RUN_STATUS,
            record["status"],
            "The superseded call is still audited — it reached Burp and cannot be recalled (D-07).",
        )
        assertEquals("approve_once", record["decision"], "The decision the human really made is unchanged by the supersede.")
        assertOrderedAuditPair(h, record, traceIdRef.get(), extraKeys = setOf(SUPERSEDE_REASON_KEY))
    }

    /**
     * S-12 / AI-SPEC E9 — a tool body that throws produces a row, a record and a `logToError` line,
     * and leaves the panel usable. Silence is the failure mode being ruled out.
     *
     * **Burp does not catch or report exceptions thrown on threads an extension created**, so a
     * throwable that escaped this worker would vanish: no Burp error-log entry, no transcript row, and
     * a panel stuck in UI-SPEC state S3 with nothing running. Every clause below is one half of that
     * silence closed.
     *
     * **The failure is an [Error], not an [Exception], and that is measured rather than stylistic.**
     * `McpTool.runTool` catches `SerializationException` and `Exception` and converts both into an
     * error RESULT, which the tail reports as a run with status `"error"` and then CHAINS — a
     * different branch entirely. Only a `Throwable` `runTool` does not catch escapes
     * `McpToolExecutor.executeTool` into `OffEdtDispatch`'s `runCatching`, which is the
     * `reportFailedToolCall` branch this scenario is about. `ChatPanelToolGateTest` reached the same
     * conclusion independently and injects the same shape.
     *
     * **`errorClass` is read off the AI-ACTIVITY metadata, not the audit event.**
     * `reportFailedToolCall` merges the key onto the map the reporter RETURNED, after the reporter has
     * already emitted its own payload — so the audit event never carries it and an assertion there
     * would be red for the wrong reason. That the value is the real exception's `simpleName` is the
     * evidence that the `Throwable` crossed the thread boundary intact instead of as text.
     */
    @Test
    fun aThrowingToolBodyIsReportedRatherThanSwallowed() {
        val h = ChatPanelTestHarness.create(modelResponse = toolCall("proxy_http_history", """{"count":5}"""))
        whenever(h.api.proxy().history()).thenThrow(InjectedWorkerFailure(INJECTED_FAILURE_MESSAGE))

        val escaped = AtomicReference<Throwable?>(null)
        val previousHandler = Thread.getDefaultUncaughtExceptionHandler()
        Thread.setDefaultUncaughtExceptionHandler { _, thrown -> escaped.set(thrown) }
        val traceIdRef = AtomicReference<String>()
        try {
            assertTimeoutPreemptively(Duration.ofSeconds(30)) {
                ChatPanelTestHarness.sendUserMessage(h, "summarise the proxy history")
                ChatPanelTestHarness.drainEdt()
                val card = requireNotNull(ChatPanelTestHarness.findApprovalCard(h.panel.root)) { NO_CARD }
                traceIdRef.set(pendingTraceId(h))
                click(card, "Approve once")
                // Reaching this at all is half the claim: the settle observer fires from the EDT tail's
                // `finally`, so a worker whose throw had taken its tail down with it would never settle
                // and this would time out instead of failing an assertion.
                ChatPanelTestHarness.awaitToolSettled(label = traceIdRef.get(), count = 1)
            }
        } finally {
            Thread.setDefaultUncaughtExceptionHandler(previousHandler)
        }

        val record = decisionsFor(traceIdRef.get()).single()
        assertEquals("error", record["status"], "An approved call that threw is recorded as a failed run, not as 'ok'.")
        val logged = loggedMetadataFor(h, traceIdRef.get())
        assertEquals(
            InjectedWorkerFailure::class.java.simpleName,
            logged["errorClass"],
            "E9: the Throwable must cross the worker/EDT boundary INTACT. A stringified failure would " +
                "still produce a row and a record, but 'which class blew up?' — the one question a " +
                "maintainer reading the audit log has — would be unanswerable.",
        )
        assertOrderedAuditPair(h, record, traceIdRef.get(), extraKeys = setOf("errorClass"))
        // Burp reports nothing itself for a thread it did not create, so this line is the ONLY place a
        // background failure becomes visible to the user at all.
        assertTrue(
            loggedErrors(h).any { it.contains(InjectedWorkerFailure::class.java.simpleName) },
            "E9: the failure must reach Burp's error log naming its class. Logged: ${loggedErrors(h)}.",
        )
        assertTrue(
            transcriptText(h).contains("Error: "),
            "The user asked for this answer in the transcript, so the failure belongs there too — not " +
                "only in a log they have no reason to open. Transcript: ${transcriptText(h)}",
        )
        // UI-SPEC S0. The chain STOPS at a failure with no followup turn, so nothing downstream would
        // clear the busy state; without an explicit clear the Send button stays hidden forever.
        assertTrue(sendButton(h).isVisible, "A failed tool must leave the panel usable: Send is back.")
        assertTrue(inputArea(h).isEnabled, "A failed tool must leave the panel usable: the input is live.")
        assertNull(
            escaped.get(),
            "Nothing may escape the worker: `OffEdtDispatch` wraps both the body and its EDT tail. " +
                "An escaped throwable reached the default handler: ${escaped.get()}",
        )
    }

    /**
     * S-08 / AI-SPEC E10 — a `/tool` fired while a chain step is in flight never reports limiter
     * exhaustion, because each chat call site mints its OWN [McpRequestLimiter].
     *
     * **A NEGATIVE dimension, and it is worth reading twice before deciding it tests nothing.** The
     * premise E10 was drafted on — that per-call workers make limiter contention newly reachable —
     * was verified FALSE at source: `ChatPanel.buildToolContext` constructs a fresh limiter on every
     * call, and the MCP-server path holds a separate instance minted once per runtime context in
     * `McpRuntimeContextFactory`. Two chat calls can therefore never contend today. The dimension
     * exists to catch the FUTURE refactor that hoists that construction out of `buildToolContext` "to
     * avoid an allocation" and silently couples two independent user actions. If the string below ever
     * reaches a chat transcript, a limiter became shared and it is a real defect.
     *
     * **`maxConcurrentRequests = 1` is what gives the negative clause teeth.** The baseline is 4, and
     * two concurrent calls would fit inside a SHARED limiter of 4 without complaint — so against the
     * baseline this test would pass under the very refactor it exists to catch. With one permit, a
     * shared limiter refuses the second call after its 250 ms `tryAcquire` and writes the exhaustion
     * string into the transcript.
     *
     * **What this scenario does NOT claim, measured rather than glossed:** that the chain survives.
     * The running-tool supersede cell is panel-wide by design, so the `/tool` command takes the token
     * and the chain's in-flight step lands in state S4 — no row, no followup, chain over. That is
     * correct behaviour, asserted below rather than worked around. It is also barely reachable by a
     * real user: the panel is in state S3 while a tool runs, with Send hidden and the input disabled,
     * so only this harness can type into it. The paired structural guard is
     * [theChatToolLimiterIsConstructedPerCall], which does not depend on any of that.
     */
    @Test
    fun aSlashCommandRacingAChainStepNeverReportsLimiterExhaustion() {
        val latches = ToolLatches()
        val chainThread = AtomicReference<Thread?>(null)
        val slashThread = AtomicReference<Thread?>(null)
        val h =
            ChatPanelTestHarness.create(
                modelResponse = toolCall("scope_check", """{"url":"http://e10.example/"}"""),
                settings = settingsWithSingleMcpPermit(),
            )
        whenever(h.api.scope().isInScope(any<String>())).thenAnswer {
            chainThread.set(Thread.currentThread())
            latches.entered.countDown()
            check(latches.probeRan.await(HANDSHAKE_FAILSAFE_SECONDS, TimeUnit.SECONDS)) {
                "The test never released the blocked chain step — the race window was never opened."
            }
            false
        }
        whenever(h.api.proxy().history()).thenAnswer {
            slashThread.set(Thread.currentThread())
            emptyList<ProxyHttpRequestResponse>()
        }

        val slashLabelRef = AtomicReference<String>()
        val chainLabelRef = AtomicReference<String>()
        assertTimeoutPreemptively(Duration.ofSeconds(30)) {
            // AUTO tier: no card, so the chain's first step is dispatched and blocked straight away.
            ChatPanelTestHarness.sendUserMessage(h, "check scope repeatedly")
            assertTrue(
                latches.entered.await(HANDSHAKE_FAILSAFE_SECONDS, TimeUnit.SECONDS),
                "The chain worker never started, so there was no in-flight call to race.",
            )
            // The second user action, fired while the first is demonstrably still inside its call and
            // still holding its own limiter permit.
            ChatPanelTestHarness.sendUserMessage(h, """/tool proxy_http_history {"count":5}""")
            val slashLabel = ChatPanelTestHarness.slashToolLabel()
            slashLabelRef.set(slashLabel)
            // WAIT FOR THE /tool WORKER TO FINISH BEFORE RELEASING THE CHAIN, and the ordering is the
            // whole of the negative clause. Releasing first lets the chain drop its permit inside the
            // second call's 250 ms tryAcquire window, so a SHARED limiter would often acquire anyway
            // and the assertion would be green against the defect: measured, by hoisting the limiter
            // to a panel field and watching this test stay green. The await is on the /tool worker's
            // own label, so the release-after-settle ordering no longer depends on which worker in the
            // process settles first.
            ChatPanelTestHarness.awaitToolSettled(label = slashLabel, count = 1)
            latches.probeRan.countDown()
            val chainLabel = ChatPanelTestHarness.chainTraceId(h)
            chainLabelRef.set(chainLabel)
            ChatPanelTestHarness.awaitToolSettled(label = chainLabel, count = 1)
        }
        val slashLabel = slashLabelRef.get()
        val chainLabel = chainLabelRef.get()

        // THE NEGATIVE CLAUSE. `finishUserOriginatedToolCall` renders whatever the executor returned,
        // so a refused acquisition arrives as a visible transcript row rather than as an exception.
        val transcript = transcriptText(h)
        assertFalse(
            transcript.contains(LIMITER_EXHAUSTED),
            "E10: each chat call site mints its own McpRequestLimiter, so two user actions can never " +
                "contend. This string in a chat transcript means the construction was hoisted out of " +
                "buildToolContext and two independent actions are now coupled. Transcript: $transcript",
        )
        // Both really executed — the negative clause above is worthless if neither call ran.
        verify(h.api.proxy(), times(1)).history()
        assertTrue(
            transcript.contains(EMPTY_HISTORY_ROW),
            "The /tool call must have produced its own result row. Transcript: $transcript",
        )
        // Both off the EDT, read from Threads the production code created.
        listOf("chain" to chainThread, "/tool" to slashThread).forEach { (name, captured) ->
            val thread = requireNotNull(captured.get()) { "The $name tool body never ran." }
            assertNotEquals(EDT_THREAD_NAME, thread.name, "SC1: the $name call must not execute on the EDT.")
            assertTrue(thread.isDaemon, "E9: the $name worker must be a daemon.")
        }
        assertEquals(
            listOf(chainLabel, slashLabel),
            ChatPanelTestHarness.dispatchedLabels().filter { it == chainLabel || it.startsWith(CHAT_TOOL_LABEL_PREFIX) },
            "Exactly two workers were dispatched: the chain step, then the /tool call.",
        )
        // The measured consequence, asserted rather than avoided: the /tool minted a new running-tool
        // token, so the chain's step lost the compare-and-set and landed in UI-SPEC state S4.
        assertEquals(
            ChatPanel.SUPERSEDED_RUN_STATUS,
            decisionsFor(chainLabel).single()["status"],
            "The /tool command takes the panel-wide running-tool token, so the chain step it raced is " +
                "superseded. Correct, and documented in this test's KDoc rather than designed around.",
        )
    }

    /**
     * S-08 / AI-SPEC E10, structural half — the limiter is constructed INSIDE `buildToolContext`.
     *
     * The guard the behavioural test above cannot be: a hoisted limiter only shows up as a defect when
     * two calls overlap, and overlapping them at all takes a harness that types into a disabled input.
     * This one fails the moment the construction moves, with no timing involved.
     *
     * `ChatPanel.kt` is already declared a `tasks.test` input in `build.gradle.kts`, so an edit that
     * changes only this source text still invalidates the cache and this assertion actually re-runs —
     * the 22-09 defect, and the reason no new declaration is needed here.
     */
    @Test
    fun theChatToolLimiterIsConstructedPerCall() {
        assertTrue(
            functionBody("private fun buildToolContext(").contains("McpRequestLimiter("),
            "E10: every chat tool call must mint its OWN McpRequestLimiter. Hoisting the construction " +
                "to a field or a singleton — the obvious 'avoid an allocation' refactor — would make a " +
                "/tool command and an auto-chain step share one semaphore, so one user action could " +
                "make another fail with 'Too many concurrent MCP requests.' They are independent, and " +
                "this is what keeps them that way.",
        )
    }

    // ── SC5 — the REL-01 confinement contract did NOT regress (plan 23-05) ───────────────

    /**
     * SC5 / AI-SPEC E5, first half — `assertEdt()` is exactly as Phase 17 left it.
     *
     * **This test exists because SC5 is an ABSENCE claim, and an absence claim stated only in a
     * summary is worth nothing.** Phase 23 moved the *work* off the EDT; REL-01's guarantee is that the
     * five `@GuardedBy("EDT")` session maps stay confined to it. The cheapest and most direct evidence
     * that the guarantee did not move with the work is that the method encoding it is untouched —
     * exactly the evidence Phase 22 produced for the same contract (`22-07-SUMMARY.md`). Phase 26 /
     * QUAL-07 owns upgrading `assertEdt()` from the JVM assertion facility to something that fires in
     * shipped Burp; this phase deliberately leaves it alone and adds its inverse check at a different
     * seam instead — the throwing door guard on `McpToolExecutor.executeToolResult` (plan 23-02).
     *
     * **The mention count is 6, and that number is a MEASUREMENT rather than a description.** Its six
     * occurrences are one declaration, one comment that names the method, and four invocations. Earlier
     * Phase 23 artifacts call all six "call sites"; they are not, and stating it precisely here costs
     * nothing and stops the next reader hunting for two invocations that do not exist. What makes 6
     * evidence is that it is *unmoved from HEAD*: plan 23-01 had to rewrite two of its own KDoc
     * sentences after prose alone pushed this counter to 7, so the number is only meaningful while
     * every mention is accounted for.
     *
     * `ChatPanel.kt` is already a declared `tasks.test` input (`build.gradle.kts`), so this assertion
     * really does re-run when the source text changes even if the bytecode does not — the 22-09
     * stale-cache defect. No new declaration is needed, and adding a read of any OTHER main file here
     * would need one.
     */
    @Test
    fun theEdtConfinementAssertionIsByteIdenticalAndStillHasSixMentions() {
        val body = functionBody("private fun assertEdt()")
        assertTrue(
            body.contains("assert(SwingUtilities.isEventDispatchThread())"),
            "REL-01 / SC5: assertEdt() must still test EDT-ness. Body was:\n$body",
        )
        assertTrue(
            body.contains(REL_01_DATA_RACE_MESSAGE),
            "REL-01 / SC5: assertEdt()'s message is the contract in prose — it is what tells whoever " +
                "meets the failure that an off-EDT map touch is a silent data race rather than a style " +
                "nit. Phase 23 moved work off the EDT and must not have softened it. Body was:\n$body",
        )
        assertEquals(
            CHAT_PANEL_ASSERT_EDT_MENTIONS,
            occurrencesOf("assertEdt()", chatPanelSource()),
            "SC5: the number of assertEdt() mentions in ChatPanel.kt must be unmoved from the measured " +
                "HEAD baseline of $CHAT_PANEL_ASSERT_EDT_MENTIONS. FEWER means a confinement point was " +
                "deleted while the work around it went asynchronous — the regression SC5 exists to " +
                "catch. MORE means this phase added an EDT assertion, which would make the number stop " +
                "being evidence of an unchanged contract. If you are legitimately changing this, change " +
                "the constant and say why in its KDoc.",
        )
    }

    /**
     * SC5, second half — every marshalling point in `ChatPanel.kt` is accounted for.
     *
     * A bare count is not evidence; a count with a per-addition reason attached is. See
     * [CHAT_PANEL_INVOKE_LATER_SITES] for the ledger this asserts against.
     */
    @Test
    fun everyMarshallingPointInChatPanelIsAccountedFor() {
        assertEquals(
            CHAT_PANEL_INVOKE_LATER_SITES,
            occurrencesOf("SwingUtilities.invokeLater", chatPanelSource()),
            "SC5: ChatPanel.kt's marshalling-point count moved. Every one is a place where work hops " +
                "onto the EDT, so an unexplained addition is an unexplained new interleaving. The " +
                "justification ledger is the KDoc on CHAT_PANEL_INVOKE_LATER_SITES — add your line " +
                "there and move the constant, or remove the marshalling point.",
        )
    }

    /**
     * SC5 / AI-SPEC E5, structural half — no off-EDT worker body names a `@GuardedBy("EDT")` map.
     *
     * Scoped to the `work =` argument of each [OffEdtDispatch] dispatch, which is the only code in
     * `ChatPanel.kt` that runs off the EDT. It is deliberately NOT a file-wide grep: `shutdown()`'s own
     * `work` lambda reads `sessionPanels`, and it is *supposed* to — that block is marshalled onto the
     * EDT with `invokeAndWait` before it runs.
     *
     * **The site count is asserted first, and that is the part that stops this test being vacuous.**
     * A `none { … }` over an empty list passes; if a refactor renamed the parameter or moved the
     * dispatch, this would silently become an assertion about nothing.
     *
     * Paired with the behavioural half below, because a source assertion alone survives a renamed
     * field and a behavioural assertion alone can pass by luck of timing.
     */
    @Test
    fun noOffEdtWorkerLambdaTouchesAGuardedSessionMap() {
        val lambdas = dispatchedWorkLambdas()
        assertEquals(
            OFF_EDT_DISPATCH_SITES,
            lambdas.size,
            "Expected $OFF_EDT_DISPATCH_SITES OffEdtDispatch.run call sites in ChatPanel.kt (the " +
                "auto-chain step, the tool dialog and the /tool command). Finding a different number " +
                "means either a new off-EDT path exists that this assertion has not inspected, or the " +
                "extraction is stale and the assertion below is inspecting nothing.",
        )
        for (lambda in lambdas) {
            for (map in GUARDED_SESSION_MAPS) {
                assertFalse(
                    lambda.contains(map),
                    "REL-01 / E5: an off-EDT worker body references `$map`, which is @GuardedBy(\"EDT\"). " +
                        "An off-EDT read of one of these maps is the data race REL-01 exists to " +
                        "prevent, and it corrupts silently rather than failing loudly. Everything the " +
                        "worker needs is frozen into ToolCallCapture on the EDT before dispatch; " +
                        "everything the TAIL needs it may read, because the tail runs on the EDT. " +
                        "Offending lambda:\n$lambda",
                )
            }
        }
    }

    /**
     * SC5 / AI-SPEC E5, behavioural half — the tail writes into its CAPTURED panel, not a live lookup.
     *
     * The source assertion above says the worker names no guarded map. This one says the same thing
     * about the values that actually reach the transcript, and it is written so that resolving the
     * panel from a map instead of from [ChatPanel.ToolCallCapture] turns it red.
     *
     * **How the trap is set.** While the tool worker is blocked mid-call, the user clicks *New
     * Session*. `createSession` writes `sessionsById`, `sessionPanels`, `sessionStates` and
     * `sessionDrafts`, moves `activeSessionId` and flips the card layout — so from that instant every
     * live map lookup answers *session 2* while the capture still says *session 1*. The two worlds are
     * now distinguishable, which they are not at any other moment in the run. Then the worker is
     * released, and the question is simply which transcript the result row landed in.
     *
     * **Why New Session and not one of the teardown paths.** Session delete, project change, unload and
     * Cancel all supersede the running worker (plans 23-01 and 23-04), so its tail renders nothing at
     * all and there would be no row to locate. Creating a session mutates every guarded map and
     * supersedes nothing, which is exactly the window this claim needs.
     *
     * The two-card assertion is the anti-vacuity clause: without it, a run in which the click silently
     * did nothing would leave one card holding both strings and pass.
     */
    @Test
    fun theToolTailWritesIntoItsCapturedPanelWhileTheGuardedMapsMoveUnderneathIt() {
        val latches = ToolLatches()
        val h = ChatPanelTestHarness.create(modelResponse = toolCall("proxy_http_history", """{"count":5}"""))
        whenever(h.api.proxy().history()).thenAnswer {
            latches.entered.countDown()
            check(latches.probeRan.await(HANDSHAKE_FAILSAFE_SECONDS, TimeUnit.SECONDS)) {
                "The test never released the blocked tool — the map-mutation window was never opened."
            }
            emptyList<ProxyHttpRequestResponse>()
        }

        assertTimeoutPreemptively(Duration.ofSeconds(30)) {
            ChatPanelTestHarness.sendUserMessage(h, E5_QUESTION)
            ChatPanelTestHarness.drainEdt()
            val traceId = pendingTraceId(h)
            click(requireNotNull(ChatPanelTestHarness.findApprovalCard(h.panel.root)) { NO_CARD }, "Approve once")
            assertTrue(
                latches.entered.await(HANDSHAKE_FAILSAFE_SECONDS, TimeUnit.SECONDS),
                "The tool worker never started, so the guarded maps were never moved underneath it.",
            )
            // The real button, on the EDT, exactly as the AWT event pump would deliver the click.
            SwingUtilities.invokeAndWait { newSessionButton(h).doClick() }
            latches.probeRan.countDown()
            ChatPanelTestHarness.awaitToolSettled(label = traceId, count = 1)
            ChatPanelTestHarness.drainEdt(times = LONG_DRAIN)
        }

        val cards = sessionCards(h).map { transcriptTextOf(it) }
        // ANTI-VACUITY. If the click did nothing there is only one transcript, the capture and the live
        // lookup agree, and every clause below passes without having distinguished anything.
        assertEquals(
            2,
            cards.size,
            "The New Session click did not create a second session card, so the guarded maps never " +
                "moved and this test distinguished nothing. Cards: ${cards.size}.",
        )
        val asked = cards.filter { it.contains(E5_QUESTION) }
        assertEquals(
            1,
            asked.size,
            "Expected the original question in exactly one transcript; found it in ${asked.size}.",
        )
        assertTrue(
            asked.single().contains(EMPTY_HISTORY_ROW),
            "REL-01 / E5: the tool result landed somewhere other than the session that asked for it. " +
                "finishApprovedToolCall must render through `captured.panel` — the SessionPanel frozen " +
                "into ToolCallCapture on the EDT before dispatch — and never through a live " +
                "sessionPanels lookup, whose answer changed the moment the user made a new session.",
        )
        assertTrue(
            cards.none { !it.contains(E5_QUESTION) && it.contains(EMPTY_HISTORY_ROW) },
            "REL-01 / E5: a tool result appeared in a transcript that never asked for it — the row " +
                "followed the CURRENT session rather than the captured one.",
        )
    }

    /**
     * CR-05 / UI-SPEC Rule S-1 — the entry guard, which is the CONTROL rather than the affordance.
     *
     * This is the assertion that makes 23-01's must-have truth *"S3 is global to `ChatPanel`, so a
     * second dispatch cannot be started from the UI while the first is live"* true rather than merely
     * claimed. Against the tree as committed at `2a0c703` `openToolDialog` has no re-entrancy check of
     * any kind: it would create a session, build the catalog and reach `ToolInvocationDialog`, whose
     * construction throws `HeadlessException` here — and in Burp would open a real dialog whose token
     * overwrites the running one and destroys the first call's result with no surface indication.
     *
     * **The dispatch record is the load-bearing selector, never the settle record.** A settle event is
     * written from the EDT tail's `finally`, so in exactly the world this test exists to catch — a
     * re-entrant call that dispatched a second worker — that worker has not finished at assert time
     * and its label is missing from the settle record too. `dispatchedLabels()` is written
     * synchronously with the dispatch statement, so absence there is a claim about what happened.
     *
     * The blocked tool is released and awaited before the test returns: `OffEdtDispatch` is an object
     * singleton and a worker still parked on a latch would follow the JVM into the next suite (WR-08).
     */
    @Test
    fun aSecondToolCannotBeStartedWhileOneIsRunning() {
        val latches = ToolLatches()
        val h = harnessForUserOriginatedTool(latches)

        assertTimeoutPreemptively(Duration.ofSeconds(30)) {
            ChatPanelTestHarness.sendUserMessage(h, SLASH_TOOL_COMMAND)
            val slashLabel = ChatPanelTestHarness.slashToolLabel()
            assertTrue(
                latches.entered.await(HANDSHAKE_FAILSAFE_SECONDS, TimeUnit.SECONDS),
                "The /tool worker never started, so there was no running call to re-enter.",
            )
            val dispatchedBefore = ChatPanelTestHarness.dispatchedLabels().count { it.startsWith(CHAT_TOOL_LABEL_PREFIX) }
            assertEquals(1, dispatchedBefore, "Expected exactly the one /tool worker to be in flight.")

            // The real entry point the Tools button reaches, called on the EDT exactly as the AWT pump
            // would dispatch its action listener.
            SwingUtilities.invokeAndWait { h.panel.openToolDialog() }

            assertEquals(
                listOf(BUSY_REFUSAL),
                h.shownErrors.toList(),
                "UI-SPEC Rule S-1: a re-entrant openToolDialog must refuse, and must say so. Shown: ${h.shownErrors}",
            )
            assertEquals(
                dispatchedBefore,
                ChatPanelTestHarness.dispatchedLabels().count { it.startsWith(CHAT_TOOL_LABEL_PREFIX) },
                "CR-05: the refused call must start NO second worker. The guard has to be the function's " +
                    "first statement — below the session lookup it has already created a session, and " +
                    "below the dialog it has already minted a token over the running one.",
            )

            latches.probeRan.countDown()
            ChatPanelTestHarness.awaitToolSettled(label = slashLabel, count = 1)
        }
    }

    /**
     * CR-05 / UI-SPEC Rule S-1 — the affordance limb: `toolsBtn` is inert for the WHOLE tool run.
     *
     * Asserted mid-flight, before the latch is released, because "the button is disabled while a tool
     * runs" is only a claim while a tool demonstrably still runs. Read after the settle it would also
     * pass against a panel that never disabled the button at all.
     *
     * Deliberately independent of [aStatusRefreshMidRunDoesNotRestoreTheIdleAffordances]: that one
     * covers `updateChatAvailability`, this one covers `setSendingState`. One clause standing in for
     * both would hide a regression in either — confirmed by driving each limb red on its own.
     */
    @Test
    fun theToolsButtonIsInertForTheWholeToolRun() {
        val latches = ToolLatches()
        val h = harnessForUserOriginatedTool(latches)

        assertTimeoutPreemptively(Duration.ofSeconds(30)) {
            assertTrue(toolsButton(h).isEnabled, "UI-SPEC S0: the Tools button starts live.")
            ChatPanelTestHarness.sendUserMessage(h, SLASH_TOOL_COMMAND)
            val slashLabel = ChatPanelTestHarness.slashToolLabel()
            assertTrue(
                latches.entered.await(HANDSHAKE_FAILSAFE_SECONDS, TimeUnit.SECONDS),
                "The /tool worker never started, so the panel was never in S3.",
            )

            assertFalse(
                toolsButton(h).isEnabled,
                "UI-SPEC Rule S-1: setSendingState must take the Tools button down with the rest of the " +
                    "busy seam, so the second door is not merely uncontrolled but not even offered.",
            )

            latches.probeRan.countDown()
            ChatPanelTestHarness.awaitToolSettled(label = slashLabel, count = 1)
        }

        assertTrue(toolsButton(h).isEnabled, "UI-SPEC S0: the Tools button is live again once the run settles.")
    }

    /**
     * CR-05's timer limb — a status refresh mid-run must not hand back the idle affordances.
     *
     * **This is the scenario that goes red against the code as committed with no second dialog
     * involved, and it is live today rather than hypothetical.** `MainTab.mcpStatusTimer`
     * (`MainTab.kt:81-88`) fires `updateMcpControls()` every 1000 ms, which calls
     * `chatPanel.setMcpAvailable(running)` (`MainTab.kt:583`) and so reaches
     * `updateChatAvailability()`. Before this plan that function wrote `inputArea.isEnabled` and
     * `toolsBtn.isEnabled` from `mcpAvailable` alone, so one second into ANY tool run the S3 disabled
     * input area and tool button were both silently re-enabled by a timer. Plan 23-06 moved
     * `MainTab.renderStatus()` into an asynchronous tail, which adds a second arrival moment for the
     * same call.
     *
     * `setMcpAvailable(true)` on the EDT IS the timer tick: it is the production entry point, called
     * with the value a running server produces.
     *
     * Both limbs are asserted, because they are two separate writes and the review names the input
     * area as the one a user would notice first.
     */
    @Test
    fun aStatusRefreshMidRunDoesNotRestoreTheIdleAffordances() {
        val latches = ToolLatches()
        val h = harnessForUserOriginatedTool(latches)

        assertTimeoutPreemptively(Duration.ofSeconds(30)) {
            ChatPanelTestHarness.sendUserMessage(h, SLASH_TOOL_COMMAND)
            val slashLabel = ChatPanelTestHarness.slashToolLabel()
            assertTrue(
                latches.entered.await(HANDSHAKE_FAILSAFE_SECONDS, TimeUnit.SECONDS),
                "The /tool worker never started, so the panel was never in S3.",
            )

            // One mcpStatusTimer tick, on the EDT, through the production entry point.
            SwingUtilities.invokeAndWait { h.panel.setMcpAvailable(true) }

            assertFalse(
                ChatPanelTestHarness.inputTextArea(h).isEnabled,
                "UI-SPEC Rule S-3: a 1 Hz status tick must not return the input area to S0 while a tool " +
                    "worker is still in flight. updateChatAvailability has to respect isSending.",
            )
            assertFalse(
                toolsButton(h).isEnabled,
                "UI-SPEC Rule S-1: the same tick must not re-open the second door either.",
            )

            latches.probeRan.countDown()
            ChatPanelTestHarness.awaitToolSettled(label = slashLabel, count = 1)
        }
    }

    /**
     * WR-04 / D-07's load-bearing corollary — a superseded user-originated call is still audited.
     *
     * Against the tree as committed at `2a0c703` the supersede branch is a bare
     * `if (!runningTool.clearIfMatches(token)) return`: the call reached Burp and hit a real target,
     * and then vanished from every surface. The chain path's `discardSupersededToolResult` has emitted
     * a record for exactly this case since 23-04, on the stated grounds that suppressing it would put
     * a hole in the SEC-06 audit log at the precise point a user interrupted something.
     *
     * **Asserted on the `aiRequestLogger` record, never on transcript text.** `ChatMessagePanel`
     * renders every non-user role as the literal `"AI"`, so a `contains("Tool result: …")` clause is
     * false by construction and its negative form can never fail. The record is the only surface on
     * which this claim is falsifiable at all — by design, since S4 renders nothing.
     *
     * **Superseded through Cancel rather than through a session delete**, and the choice is what makes
     * the sibling row-count test real: `deleteConfirmedSession` removes the panel from `sessionPanels`
     * and from the card layout, so a wrongly-rendered row would land in a detached transcript that no
     * assertion can see. Cancel is a first-class user-originated supersede (UI-SPEC Rule S-5) and the
     * panel survives it.
     */
    @Test
    fun aSupersededUserOriginatedToolCallIsStillAudited() {
        val latches = ToolLatches()
        val h = harnessForUserOriginatedTool(latches)

        assertTimeoutPreemptively(Duration.ofSeconds(30)) {
            ChatPanelTestHarness.sendUserMessage(h, SLASH_TOOL_COMMAND)
            val slashLabel = ChatPanelTestHarness.slashToolLabel()
            assertTrue(
                latches.entered.await(HANDSHAKE_FAILSAFE_SECONDS, TimeUnit.SECONDS),
                "The /tool worker never started, so there was nothing to supersede.",
            )
            SwingUtilities.invokeAndWait { cancelButton(h).doClick() }
            latches.probeRan.countDown()
            ChatPanelTestHarness.awaitToolSettled(label = slashLabel, count = 1)
        }

        val record =
            requireNotNull(toolCallRecords(h).singleOrNull()) {
                "Expected exactly one MCP_TOOL_CALL activity record for the discarded /tool call; " +
                    "captured ${toolCallRecords(h)}."
            }
        assertEquals(
            "result discarded before it was applied",
            record.metadata[SUPERSEDE_REASON_KEY],
            "WR-04: the discarded user-originated call must name WHY it was discarded, in the same " +
                "words discardSupersededToolResult uses for a discarded chain step.",
        )
        assertEquals(
            ChatPanel.SUPERSEDED_RUN_STATUS,
            record.metadata["runStatus"],
            "The run status must distinguish a discarded call from one that completed normally — the " +
                "distinction the audit log could not make before.",
        )
        assertEquals("proxy_http_history", record.metadata["tool"], "The record must name the tool that was discarded.")
        assertTrue(
            record.detail.contains("proxy_http_history"),
            "An operator reading the detail line must be able to say which tool it was. Detail: ${record.detail}",
        )
    }

    /**
     * UI-SPEC S4 — the superseded run stays invisible in the transcript and leaves S0 alone.
     *
     * **The clause is a row COUNT, and that is the whole design of this test.** The obvious form —
     * `assertFalse(transcript.contains("Tool result: proxy_http_history"))` — is false by construction,
     * because `ChatMessagePanel` renders every non-user role as the literal `"AI"` and the role string
     * never reaches a component. 23-04 shipped exactly that shape and caught it only when the POSITIVE
     * form failed against a row that was demonstrably on screen. A count changes if and only if a row
     * was really added, whatever text it carries.
     *
     * The busy-state clause is the second half of the S4 contract: the tail must not re-enter S3 and
     * must not clear a state Cancel already returned to S0, because whatever superseded this run may
     * have started something since.
     */
    @Test
    fun aSupersededUserOriginatedToolCallRendersNoResultRow() {
        val latches = ToolLatches()
        val h = harnessForUserOriginatedTool(latches)
        val rowsAfterCancel = AtomicInteger()

        assertTimeoutPreemptively(Duration.ofSeconds(30)) {
            ChatPanelTestHarness.sendUserMessage(h, SLASH_TOOL_COMMAND)
            val slashLabel = ChatPanelTestHarness.slashToolLabel()
            assertTrue(
                latches.entered.await(HANDSHAKE_FAILSAFE_SECONDS, TimeUnit.SECONDS),
                "The /tool worker never started, so there was nothing to supersede.",
            )
            SwingUtilities.invokeAndWait { cancelButton(h).doClick() }
            // SNAPSHOT TAKEN AFTER THE CANCEL and BEFORE the release: the Rule C-1 line Cancel appends
            // is part of the baseline, so the only thing that can move this number afterwards is the
            // superseded worker rendering a row it must not render.
            rowsAfterCancel.set(transcriptRowCount(h))
            latches.probeRan.countDown()
            ChatPanelTestHarness.awaitToolSettled(label = slashLabel, count = 1)
        }

        assertEquals(
            rowsAfterCancel.get(),
            transcriptRowCount(h),
            "UI-SPEC S4: a superseded run must add no transcript row. Counting rows rather than " +
                "matching row TEXT is deliberate — the role a tool result carries never reaches a " +
                "component, so a text clause here could not fail.",
        )
        assertTrue(
            sendButton(h).isVisible,
            "UI-SPEC S4: the superseded tail must leave the busy state alone. Cancel already returned " +
                "the panel to S0 and may have started something since.",
        )
    }

    /**
     * The negative control for [aSupersededUserOriginatedToolCallIsStillAudited].
     *
     * Without it, that test passes just as happily against an implementation that emits a supersede
     * record on EVERY completion — which would make the audit log unable to tell a discarded call from
     * a normal one in the opposite direction, and would be a worse defect than the one being fixed.
     * Driven red by moving the emission above the `clearIfMatches` check.
     */
    @Test
    fun anUnsupersededUserOriginatedToolCallEmitsNoSupersedeRecord() {
        val h =
            ChatPanelTestHarness.create(
                modelResponse = "no tool call here",
                settings = settingsEnabling("proxy_http_history"),
            )
        whenever(h.api.proxy().history()).thenReturn(emptyList<ProxyHttpRequestResponse>())

        assertTimeoutPreemptively(Duration.ofSeconds(30)) {
            ChatPanelTestHarness.sendUserMessage(h, SLASH_TOOL_COMMAND)
            val slashLabel = ChatPanelTestHarness.slashToolLabel()
            ChatPanelTestHarness.awaitToolSettled(label = slashLabel, count = 1)
        }

        assertTrue(
            transcriptText(h).contains(EMPTY_HISTORY_ROW),
            "Precondition: this control is only meaningful if the call really did run to completion " +
                "and render its result. Transcript: ${transcriptText(h)}",
        )
        assertEquals(
            emptyList<Map<String, String>>(),
            toolCallRecords(h).filter { it.metadata.containsKey(SUPERSEDE_REASON_KEY) }.map { it.metadata },
            "A call that completed normally must emit NO supersede record. An unconditional emission " +
                "would pass the positive test while making the audit log wrong in the other direction.",
        )
    }

    // ── UI-SPEC Rules S-4 and S-3 — source order on both user-originated tool paths ───────

    /**
     * UI-SPEC Rule S-4 on the `/tool` slash path: the typed command is echoed into the existing `"You"`
     * channel BEFORE the call is handed to a worker thread.
     *
     * Rule S-4 exists because `sendFromInput` clears the input area and returns without echoing on this
     * branch. While the call still blocked the EDT the typed text survived on screen by accident; once
     * plan 23-02 made it asynchronous, an echo emitted after the dispatch could land after the result
     * row — a transcript showing an answer with no visible question, in a tool whose users have to be
     * able to say what they just ran. The ORDER, not the mere presence, is therefore the contract.
     *
     * **The edit that turns this red:** move `panel.addMessage("You", trimmed)` below the
     * `OffEdtDispatch.run(` call inside `handleToolCommand`, or delete it. The first fails the index
     * comparison; the second fails the exactly-once precondition in [assertPrecedesWithin], which is
     * there precisely so that deleting the echo cannot pass as success.
     *
     * Asserted by index within the extracted `handleToolCommand` body, never by absolute line number:
     * line citations in this repo have rotted twice (WINDOWS.md entry 34), and a body-relative index
     * survives every edit that does not actually move the call.
     */
    @Test
    fun theSlashToolPathEchoesTheTypedCommandBeforeItGoesAsync() {
        assertPrecedesWithin(
            declaration = HANDLE_TOOL_COMMAND_DECLARATION,
            earlier = SLASH_PATH_ECHO,
            later = OFF_EDT_DISPATCH_CALL,
            rule = "UI-SPEC Rule S-4 (slash path)",
            why =
                "the /tool echo must be emitted before the work leaves the EDT, or the transcript can " +
                    "show a `Tool result:` row with no visible request above it",
        )
    }

    /**
     * UI-SPEC Rule S-4 on the tool-dialog path: the same relation, in its own function.
     *
     * The dialog path is the path Rule S-4 tells the slash path to imitate, so it is asserted here too
     * rather than assumed. Symmetry that is only checked on one side is not symmetry, and nothing else
     * in this suite would notice if the dialog echo drifted below its own dispatch.
     *
     * **The edit that turns this red:** move `panel.addMessage("You", commandPreview)` below the
     * `OffEdtDispatch.run(` call inside `openToolDialog`, or delete it — the same two failure modes,
     * caught by the same exactly-once guard.
     */
    @Test
    fun theDialogToolPathEchoesTheCommandPreviewBeforeItGoesAsync() {
        assertPrecedesWithin(
            declaration = OPEN_TOOL_DIALOG_DECLARATION,
            earlier = DIALOG_PATH_ECHO,
            later = OFF_EDT_DISPATCH_CALL,
            rule = "UI-SPEC Rule S-4 (dialog path)",
            why =
                "the dialog path is the reference implementation Rule S-4 makes the slash path match; " +
                    "if its own echo drifts below the dispatch the rule has no reference left",
        )
    }

    /**
     * UI-SPEC Rule S-3 on the `/tool` slash path: the panel enters the busy state BEFORE the dispatch.
     *
     * Rule S-3 is what removes the idle flash. Once the call no longer blocks the EDT, a panel left
     * idle-and-live across the dispatch is a window in which the user can fire `/tool` and then press
     * Send a millisecond later — the concurrent-worker case D-05 accepts only as "one chain plus one
     * manual invocation", never as fan-out. `setSendingState(true)` after the dispatch would still
     * *eventually* disable Send while leaving exactly that window open, which is why this is an
     * ordering assertion and not a presence one.
     *
     * **The edit that turns this red:** move `setSendingState(true)` below the `OffEdtDispatch.run(`
     * call inside `handleToolCommand`, or drop it and rely on the shared teardown to re-enable the
     * controls. Deletion fails the exactly-once precondition in [assertPrecedesWithin] rather than
     * silently passing.
     */
    @Test
    fun theSlashToolPathEntersTheBusyStateBeforeItGoesAsync() {
        assertPrecedesWithin(
            declaration = HANDLE_TOOL_COMMAND_DECLARATION,
            earlier = BUSY_STATE_ENTRY,
            later = OFF_EDT_DISPATCH_CALL,
            rule = "UI-SPEC Rule S-3 (slash path)",
            why =
                "between the dispatch and a later busy-state entry the panel is idle and live, and a " +
                    "Send pressed in that window fans out a second worker",
        )
    }

    /**
     * UI-SPEC Rule S-3 on the tool-dialog path: the same relation, in its own function.
     *
     * The dialog path additionally mints the supersede token immediately after entering the busy state,
     * so that a Cancel pressed while the tool runs has something to take (Rule S-5). That ordering hangs
     * off this one: a busy state entered after the dispatch would leave Cancel inert for the window in
     * between.
     *
     * **The edit that turns this red:** move `setSendingState(true)` below the `OffEdtDispatch.run(`
     * call inside `openToolDialog`, or delete it.
     */
    @Test
    fun theDialogToolPathEntersTheBusyStateBeforeItGoesAsync() {
        assertPrecedesWithin(
            declaration = OPEN_TOOL_DIALOG_DECLARATION,
            earlier = BUSY_STATE_ENTRY,
            later = OFF_EDT_DISPATCH_CALL,
            rule = "UI-SPEC Rule S-3 (dialog path)",
            why =
                "the supersede token is minted on the EDT right after this call so Cancel is never " +
                    "inert while the tool runs (Rule S-5), and that ordering depends on this one",
        )
    }

    /**
     * Rule S-3, whole-file half — every busy-state entry in `ChatPanel.kt` is accounted for.
     *
     * A bare count is not evidence; a count with a per-site reason attached is. The ledger this asserts
     * against is the KDoc on [CHAT_PANEL_BUSY_STATE_ENTRIES]. Same discipline as
     * [CHAT_PANEL_INVOKE_LATER_SITES], and for the same reason: the two ordering tests above only see
     * the two paths they name, so a THIRD asynchronous send path added without a busy-state entry
     * would be invisible to them. This is the assertion that notices.
     */
    @Test
    fun everyBusyStateEntryInChatPanelIsAccountedFor() {
        assertEquals(
            CHAT_PANEL_BUSY_STATE_ENTRIES,
            occurrencesOf(BUSY_STATE_ENTRY, chatPanelSource()),
            "Rule S-3: ChatPanel.kt's busy-state entry count moved. FEWER means a send path stopped " +
                "entering the busy state while its work went asynchronous — the idle-flash regression " +
                "S-3 exists to prevent. MORE means a new dispatch site appeared, and it needs its line " +
                "in the CHAT_PANEL_BUSY_STATE_ENTRIES ledger plus an ordering assertion of its own. " +
                "Note that this counts occurrences in the SOURCE TEXT, so a comment that spells the " +
                "call out verbatim also moves it — prose alone pushed the assertEdt() counter to 7 in " +
                "plan 23-01. Change the constant and say why in its KDoc, or put the entry back.",
        )
    }

    // ── Audit + worker capture plumbing ──────────────────────────────────────────────────

    private val auditEvents = CopyOnWriteArrayList<Pair<String, Map<*, *>>>()

    /**
     * Every SC3 decision record belonging to [traceId], in emission order.
     *
     * The trace id is the ONLY sound selector here: `AuditLogger.registerGlobalEmitter` is a
     * process-global hook, panels built by earlier tests in this class are never shut down, and their
     * queued `invokeLater` chains run on this test's drains. Filtering by tool name or reading
     * positionally would silently fold in another chain's events.
     */
    private fun decisionsFor(traceId: String): List<Map<*, *>> = auditEvents.filter { it.first == TOOL_DECISION_EVENT && it.second["traceId"] == traceId }.map { it.second }

    @BeforeEach
    fun installObservers() {
        auditEvents.clear()
        AuditLogger.registerGlobalEmitter { type, payload ->
            if (payload is Map<*, *>) auditEvents += type to payload
        }
        ChatPanelTestHarness.installSettledObserver()
    }

    @AfterEach
    fun releaseObservers() {
        // Both are process-global singleton hooks. Left registered, this class would capture — and hold
        // — events emitted by every test class that runs after it. Same discipline as
        // ChatPanelToolGateTest.kt:649-654, and for the same reason.
        AuditLogger.registerGlobalEmitter(null)
        ChatPanelTestHarness.releaseSettledObserver()
    }
}

// ── Helpers ──────────────────────────────────────────────────────────────────────────────

private const val NO_CARD = "No ToolApprovalCard in the transcript — the SEC-06 gate did not raise a decision."

/**
 * Comfortably longer than any followup this suite drives after a decision click; over-draining an
 * empty EDT queue is free, and under-draining would leave the denial's followup turn unsent.
 */
private const val LONG_DRAIN = 24

/** The AWT Event Dispatch Thread's name, which is what "not the EDT" is asserted against. */
private const val EDT_THREAD_NAME = "AWT-EventQueue-0"

/** The `AuditLogger` event type every SC3 decision record is emitted under. */
private const val TOOL_DECISION_EVENT = "mcp_tool_decision"

/**
 * Burp's refusal text, reproduced in a double THIS SUITE controls.
 *
 * It is not evidence of Burp's runtime behaviour — see [ChatPanelEdtConfinementTest] S-02 — and the
 * live confirmation is a UAT item. It reads as Burp's message so a maintainer meeting the failure
 * recognises which real-world constraint the test encodes.
 */
private const val BURP_EDT_REFUSAL = "Extensions should not make HTTP requests in the Swing event dispatch thread"

/**
 * Deadlock failsafe for the SC3 handshake, in seconds.
 *
 * A bound on a hang, never a threshold the work is measured against: nothing compares an elapsed
 * duration to it. Ten and not sixty because a red-before-green run against the pre-fix tree pays it in
 * full, once, and ten seconds is the budgeted price of that demonstration.
 */
private const val HANDSHAKE_FAILSAFE_SECONDS = 10L

/** The two halves of the SC3 mutual handshake, named so the test body reads as the protocol it is. */
private class ToolLatches {
    /** Counted down by the tool double the instant its body is entered. */
    val entered = CountDownLatch(1)

    /** Counted down from a runnable the test queues to the EDT; the tool double waits on it. */
    val probeRan = CountDownLatch(1)
}

/**
 * The trace id of the single parked decision, read reflectively off the live panel.
 *
 * Same helper, and the same reason, as `ChatPanelToolGateTest.kt:818`: every audit assertion needs a
 * selector that is this chain's alone, and the trace id is the only field that qualifies.
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

/** The panel's real Send button — one half of the UI-SPEC S0 assertion. */
private fun sendButton(h: ChatPanelTestHarness.Harness): JButton =
    requireNotNull(ChatPanelTestHarness.find(h.panel.root, JButton::class.java) { it.text == "Send" }) {
        "No JButton labelled 'Send' under ChatPanel.root — the button lookup is stale."
    }

/** The panel's real input area, found by the same `isEditable` rule the harness documents. */
private fun inputArea(h: ChatPanelTestHarness.Harness): JTextArea =
    requireNotNull(ChatPanelTestHarness.find(h.panel.root, JTextArea::class.java) { it.isEditable }) {
        "No editable JTextArea under ChatPanel.root — the input area lookup is stale."
    }

/** The panel's real Cancel button — the affordance UI-SPEC Rule S-5 says must not be inert in S3. */
private fun cancelButton(h: ChatPanelTestHarness.Harness): JButton =
    requireNotNull(ChatPanelTestHarness.find(h.panel.root, JButton::class.java) { it.text == "Cancel" }) {
        "No JButton labelled 'Cancel' under ChatPanel.root — Rule C-1 pins that label, so a miss here " +
            "means it was renamed."
    }

/**
 * The transcript's rendered text, tags stripped.
 *
 * Read through the `HTMLDocument` rather than off `JEditorPane.text`: the transcript renders through
 * `MarkdownRenderer.toHtml`, so the raw property is markup in which a sentence can be split by tags,
 * and a `contains` over it would be a claim about the renderer instead of about the copy.
 */
private fun transcriptText(h: ChatPanelTestHarness.Harness): String =
    allDescendants(h.panel.root)
        .filterIsInstance<JEditorPane>()
        .joinToString(" ") { pane -> pane.document.getText(0, pane.document.length) }

/**
 * Asserts the exact number of backend turns.
 *
 * `sendChat` takes 13 parameters; all are matched positionally so the verification lines up.
 */

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
 * Every prompt handed to the backend, in turn order.
 *
 * `sendChat` takes 13 parameters; all are matched positionally so the captor lines up with the third.
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

/**
 * The extra metadata key `discardSupersededToolResult` merges onto the reporter's map.
 *
 * Named here so [assertOrderedAuditPair] can subtract it before comparing the two records, rather
 * than having each caller restate the string.
 */
private const val SUPERSEDE_REASON_KEY = "supersedeReason"

/**
 * AI-SPEC E4 — the audit PAIR for one call, asserted as the DATA DEPENDENCY it actually is.
 *
 * `toolDecisionReporter.report` emits the `mcp_tool_decision` event AND returns the null-filtered copy
 * of that same payload; `supervisor.aiRequestLogger?.log` then consumes what it returned. So "report
 * ran first" is not a convention to be checked by call order — it is provable from the data, and this
 * checks it there: the AI-activity metadata must BE the decision payload, minus its null values and
 * plus [extraKeys]. A `log` call that assembled its own map, or one made with a stale one, fails this
 * and would pass an ordering check.
 *
 * Both sides are selected by trace id and never by list position: `AuditLogger`'s emitter is
 * process-global and panels built by earlier tests in this class are still alive.
 */
private fun assertOrderedAuditPair(
    h: ChatPanelTestHarness.Harness,
    decision: Map<*, *>,
    traceId: String,
    extraKeys: Set<String>,
) {
    val logged = loggedMetadataFor(h, traceId)
    val reported = decision.entries.filter { it.value != null }.associate { it.key.toString() to it.value.toString() }
    assertEquals(
        reported,
        logged - extraKeys,
        "E4: the AI-activity record must be exactly what the decision reporter returned. A record that " +
            "merely LOOKS right but was built separately would drift from the audit event the first time " +
            "either shape changed, and the two sinks would then disagree about the same call.",
    )
    extraKeys.forEach { key ->
        assertTrue(
            logged.containsKey(key),
            "The '$key' key must ride along on the AI-activity record; the pair carried ${logged.keys}.",
        )
    }
}

/**
 * The metadata map handed to `AiRequestLogger.log` for [traceId].
 *
 * `log` takes ten parameters and every one is matched positionally, so the captor lines up with the
 * last. `singleOrNull` is itself an assertion: exactly one AI-activity record per call is the other
 * half of "exactly one audit pair per exit".
 */
private fun loggedMetadataFor(
    h: ChatPanelTestHarness.Harness,
    traceId: String,
): Map<String, String> {
    val metadata = argumentCaptor<Map<String, String>>()
    verify(requireNotNull(h.supervisor.aiRequestLogger) { "No AiRequestLogger on the supervisor double." }, atLeast(1)).log(
        any(),
        any(),
        any(),
        any(),
        anyOrNull(),
        anyOrNull(),
        anyOrNull(),
        anyOrNull(),
        anyOrNull(),
        metadata.capture(),
    )
    return requireNotNull(metadata.allValues.singleOrNull { it["traceId"] == traceId }) {
        "Expected exactly one AI-activity record for trace $traceId; captured ${metadata.allValues.map { it["traceId"] }}."
    }
}

/**
 * Substitutes [onCompleted] into the LIVE pending record the production path just parked.
 *
 * Ported verbatim in intent from `ChatPanelToolGateTest`, and narrow for the same reason: the only
 * producer of a non-null `onCompleted` is `MainTab.openChatWithContext`, whose only route in blocks on
 * an application-modal `ContextPreviewDialog` that cannot be driven under `-Djava.awt.headless=true`.
 * So the record is built by the real gate on the real Send path and ONLY its callback slot is swapped.
 *
 * Runs on the EDT because `pendingDecisions` is EDT-confined (REL-01).
 *
 * @return the parked chain's trace id — the only field that identifies this chain's audit events
 *   among those of every other still-live panel the global emitter also sees.
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

/**
 * Every session the panel currently holds, read off the production sessions-list model.
 *
 * The list is a SIBLING of the transcript — `MainTab` is handed it separately — so it is not under
 * `ChatPanel.root` and has to be searched from `sessionsComponent()`.
 */
@Suppress("UNCHECKED_CAST")
private fun sessions(h: ChatPanelTestHarness.Harness): List<ChatPanel.ChatSession> {
    val list =
        requireNotNull(ChatPanelTestHarness.find(h.panel.sessionsComponent(), JList::class.java)) {
            "No JList under ChatPanel.sessionsComponent() — the sessions-list lookup is stale."
        } as JList<Any?>
    return (0 until list.model.size).map { list.model.getElementAt(it) as ChatPanel.ChatSession }
}

private fun sessionCount(h: ChatPanelTestHarness.Harness): Int = sessions(h).size

/** The single session a freshly built harness holds — asserted to be single, never assumed. */
private fun onlySession(h: ChatPanelTestHarness.Harness): ChatPanel.ChatSession =
    requireNotNull(sessions(h).singleOrNull()) {
        "Expected exactly one session on the panel; found ${sessions(h).map { it.title }}."
    }

/**
 * Baseline settings with [toolIds] switched on, unsafe mode included.
 *
 * A real user configuration rather than a test hook: every `CONFIRM_EACH` tool that both completes
 * headlessly and touches a stubbable Montoya seam is `unsafeOnly` and off by default, so reaching that
 * tier at all requires the same two toggles a user would set in the MCP settings tab.
 */
private fun settingsEnabling(vararg toolIds: String): AgentSettings {
    val base = TestSettings.baselineSettings()
    return base.copy(
        mcpSettings =
            base.mcpSettings.copy(
                unsafeEnabled = true,
                toolToggles = toolIds.associateWith { true },
            ),
    )
}

/**
 * Baseline settings with the MCP concurrency cap at ONE permit.
 *
 * The baseline is four, which is enough for two overlapping calls to fit inside a SHARED limiter
 * without complaint — so the E10 negative clause would pass under the exact refactor it exists to
 * catch. One permit is the smallest configuration in which a shared limiter is observably shared.
 */
private fun settingsWithSingleMcpPermit(): AgentSettings {
    val base = TestSettings.baselineSettings()
    return base.copy(mcpSettings = base.mcpSettings.copy(maxConcurrentRequests = 1))
}

/**
 * The BODY text a `proxy_http_history` call produces against an empty-history double.
 *
 * **Transcript rows are identified by their body here, never by their header, and that is a measured
 * constraint rather than a preference.** `ChatMessagePanel` renders every non-user role as the
 * literal string `"AI"` (`ChatPanel.kt`), so the role handed to `addMessage` — `"Tool result:
 * proxy_http_history"` — reaches no component at all and appears in no transcript. A
 * `contains("Tool result: ...")` is therefore FALSE BY CONSTRUCTION, which makes the negative form of
 * it an assertion that cannot fail: it passes just as happily against a superseded run that DID
 * render its row. Found by measurement, not review — the positive form of the same assertion failed
 * in S-08 against a row that was demonstrably on screen.
 *
 * This string is the tool's own output, so it appears if and only if the row was really rendered.
 */
private const val EMPTY_HISTORY_ROW = "Tool executed: proxy_http_history"

/** The exhaustion message `McpTool.runTool` writes when a limiter permit cannot be acquired. */
private const val LIMITER_EXHAUSTED = "Too many concurrent MCP requests."

/** The message carried by the injected tool failure, so the assertion and the throw cannot drift. */
private const val INJECTED_FAILURE_MESSAGE = "proxy history exploded"

/**
 * The failure injected into an APPROVED tool call.
 *
 * An [Error] on purpose — see the comment at the injection site — and named rather than reusing
 * [AssertionError] so it can never be confused with a JUnit assertion failing for real.
 *
 * Distinct from `ChatPanelToolGateTest`'s equivalent rather than shared: a file-private top-level
 * CLASS still produces a real JVM class in this package, so two of the same name in one package are a
 * redeclaration error — unlike the file-private consts and functions both suites already duplicate.
 */
private class InjectedWorkerFailure(
    message: String,
) : Error(message)

/** Every string Burp's error log received, in order. */
private fun loggedErrors(h: ChatPanelTestHarness.Harness): List<String> {
    val message = argumentCaptor<String>()
    verify(h.api.logging(), atLeast(1)).logToError(message.capture())
    return message.allValues
}

/** Declared as a `tasks.test` input in `build.gradle.kts`; the two must stay in step. */
private const val CHAT_PANEL_SOURCE = "src/main/kotlin/com/six2dez/burp/aiagent/ui/ChatPanel.kt"

/**
 * The source text of one `ChatPanel` function, brace-matched from its declaration.
 *
 * Reading source is the sanctioned fallback for a claim no headless drive can make — here, that a
 * construction stays lexically inside one function. Every other assertion in this file reads executed
 * behaviour.
 */
private fun functionBody(declaration: String): String {
    val source = chatPanelSource()
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
 * `ChatPanel.kt`'s source text.
 *
 * One reader for every structural assertion in this file, so the "does the file exist?" diagnostic is
 * written once. Named and asserted rather than left to surface as a bare `FileNotFoundException`,
 * which is what a build-layout change would otherwise produce here.
 */
private fun chatPanelSource(): String {
    val file = File(CHAT_PANEL_SOURCE)
    assertTrue(
        file.isFile,
        "Expected to find `$CHAT_PANEL_SOURCE` relative to the test working directory " +
            "`${System.getProperty("user.dir")}`, resolved as `${file.absolutePath}`. If the build " +
            "layout changed, fix the path here and in the matching `tasks.test` input declaration.",
    )
    return file.readText()
}

/** Literal (not regex) occurrences of [needle] in [source] — occurrences, never matching lines. */
private fun occurrencesOf(
    needle: String,
    source: String,
): Int {
    var count = 0
    var index = source.indexOf(needle)
    while (index >= 0) {
        count++
        index = source.indexOf(needle, index + needle.length)
    }
    return count
}

/**
 * The measured number of `assertEdt()` mentions in `ChatPanel.kt` — SC5's frozen counter.
 *
 * Six, and its composition is: the declaration, one comment that names the method, and four
 * invocations. Unmoved across all five Phase 23 plans. Every one of those mentions is accounted for,
 * which is what stops the number drifting on prose — plan 23-01 rewrote two of its own KDoc sentences
 * after they alone pushed this counter to 7.
 */
private const val CHAT_PANEL_ASSERT_EDT_MENTIONS = 6

/** The REL-01 contract, in the words `assertEdt()` itself uses. */
private const val REL_01_DATA_RACE_MESSAGE = "off-EDT access is a data race (REL-01)"

/**
 * The number of `SwingUtilities.invokeLater` marshalling points in `ChatPanel.kt`, and the ledger of
 * why each addition above the baseline exists.
 *
 * **HEAD baseline before Phase 23: 11** — measured at lines 647, 658, 673, 715, 723, 741, 1909, 1926,
 * 2190, 2268 and 2283 of the pre-phase file.
 *
 * **Additions made by Phase 23: none.** That is not an omission, it is the design. Plan 23-01 put the
 * phase's single marshalling point inside [OffEdtDispatch], which owns one `invokeLater` for the whole
 * phase; every later plan — the two user-originated call sites in 23-02, the Settings save in 23-03,
 * the teardown supersedes in 23-04 — marshalled back through that one seam rather than queueing its
 * own. So there is no per-addition line to write here, and if a future change adds one, this KDoc is
 * where its reason goes:
 *
 * - `12`: _reason for the twelfth marshalling point_
 *
 * A bare number with no reason is not evidence. A number that fails loudly when someone adds an
 * unexplained marshalling point is.
 */
private const val CHAT_PANEL_INVOKE_LATER_SITES = 11

/** `handleToolCommand` owns the `/tool` slash branch — the first of the two user-originated tool paths. */
private const val HANDLE_TOOL_COMMAND_DECLARATION = "private fun handleToolCommand("

/** `openToolDialog` owns the tool-dialog branch — the second user-originated tool path. */
private const val OPEN_TOOL_DIALOG_DECLARATION = "fun openToolDialog()"

/** Rule S-4's echo on the slash path: the trimmed command the user typed. */
private const val SLASH_PATH_ECHO = """panel.addMessage("You", trimmed)"""

/** Rule S-4's echo on the dialog path: the `/tool {id} {args}` line the dialog reconstructs. */
private const val DIALOG_PATH_ECHO = """panel.addMessage("You", commandPreview)"""

/** Rule S-3's busy-state entry: the call that disables Send and arms Cancel for the run's duration. */
private const val BUSY_STATE_ENTRY = "setSendingState(true)"

/**
 * The number of busy-state entries in `ChatPanel.kt`, and the ledger of what each one is for.
 *
 * **Four, measured at source, and every one is accounted for:**
 *
 * - `sendMessage` — the ordinary chat send. The panel goes busy for the model request itself.
 * - `openToolDialog` — user-originated tool invocation via the dialog. Rule S-3, dialog path; the
 *   supersede token is minted immediately after so Cancel is not inert (Rule S-5).
 * - `handleToolCommand` (`/tool` branch) — user-originated tool invocation by typed command. Rule S-3,
 *   slash path; symmetric with the dialog path by Rule S-4's mandate.
 * - `executeApprovedToolCall` — the chain step's approved / auto-approved tool dispatch. This is the
 *   site Rule S-3 was written about: it is the last EDT read of guarded state before the work leaves
 *   the thread, and entering the busy state here is what stops an idle flash between a chain step and
 *   the tool it triggers.
 *
 * Sites are named by FUNCTION, not by line: line citations in this repo have rotted twice (WINDOWS.md
 * entry 34), and a function name survives every edit that does not actually move the call.
 *
 * A bare number with no reason is not evidence. A number that fails loudly when someone adds an
 * unexplained send path is. If a fifth appears, its line goes here:
 *
 * - `5`: _which function, and why that path needs its own busy-state entry_
 */
private const val CHAT_PANEL_BUSY_STATE_ENTRIES = 4

/**
 * Asserts [earlier] precedes [later] in the body of [declaration], and that each occurs exactly once.
 *
 * **The exactly-once half is what stops this being vacuous, and it is not belt-and-braces.**
 * `String.indexOf` returns `-1` for an absent needle, and `-1` compares as "before" everything — so a
 * bare order assertion would go GREEN the moment the call it guards was deleted, which is the loudest
 * form of the very regression these tests exist to catch. Requiring exactly one occurrence turns both
 * "moved below the dispatch" and "removed entirely" into failures.
 *
 * Order is compared by index WITHIN one brace-matched function body, never by absolute line number.
 * Line citations in this repo have rotted twice (WINDOWS.md entry 34); a body-relative index cannot,
 * because it is recomputed from the source text on every run.
 */
private fun assertPrecedesWithin(
    declaration: String,
    earlier: String,
    later: String,
    rule: String,
    why: String,
) {
    val body = functionBody(declaration)
    assertEquals(
        1,
        occurrencesOf(earlier, body),
        "$rule: expected exactly one `$earlier` inside `$declaration`. ZERO means the guarded call was " +
            "deleted — the regression this test exists to catch, and the case a bare ordering check " +
            "would have passed. MORE than one means the order below is ambiguous and this assertion " +
            "stopped meaning what it says. Because $why. Body was:\n$body",
    )
    assertEquals(
        1,
        occurrencesOf(later, body),
        "$rule: expected exactly one `$later` inside `$declaration` — the dispatch this ordering is " +
            "measured against. If it moved or multiplied, re-derive the relation rather than relaxing " +
            "it. Body was:\n$body",
    )
    assertTrue(
        body.indexOf(earlier) < body.indexOf(later),
        "$rule: `$earlier` must appear BEFORE `$later` inside `$declaration`, because $why. It now " +
            "appears after it. Body was:\n$body",
    )
}

/** The five `@GuardedBy("EDT")` session maps REL-01 confines to the EDT. */
private val GUARDED_SESSION_MAPS =
    listOf("sessionPanels", "sessionStates", "sessionsById", "sessionDrafts", "pendingDecisions")

/** The auto-chain step, the tool dialog and the `/tool` command — D-01's three call sites. */
private const val OFF_EDT_DISPATCH_SITES = 3

/**
 * The `work = { … }` argument of every `OffEdtDispatch.run(…)` call in `ChatPanel.kt`.
 *
 * Scoped to the dispatch's own argument list rather than grepped file-wide, because `shutdown()` also
 * declares a local named `work` and that one legitimately reads `sessionPanels` — it is handed to
 * `SwingUtilities.invokeAndWait`, so it runs ON the EDT. A file-wide scan would report it as a
 * violation and this assertion would be deleted as a false alarm.
 */
private fun dispatchedWorkLambdas(): List<String> {
    val source = chatPanelSource()
    val lambdas = mutableListOf<String>()
    var at = source.indexOf(OFF_EDT_DISPATCH_CALL)
    while (at >= 0) {
        val callEnd = matchingCloser(source, source.indexOf('(', at), '(', ')')
        val workAt = source.indexOf(WORK_ARGUMENT, at)
        if (workAt in (at + 1) until callEnd) {
            val open = source.indexOf('{', workAt)
            lambdas += source.substring(open, matchingCloser(source, open, '{', '}') + 1)
        }
        at = source.indexOf(OFF_EDT_DISPATCH_CALL, at + OFF_EDT_DISPATCH_CALL.length)
    }
    return lambdas
}

private const val OFF_EDT_DISPATCH_CALL = "OffEdtDispatch.run("

private const val WORK_ARGUMENT = "work = {"

/** The index of the delimiter closing the one opened at [open]; [open] must hold [opener]. */
private fun matchingCloser(
    source: String,
    open: Int,
    opener: Char,
    closer: Char,
): Int {
    require(open >= 0 && source[open] == opener) { "Expected '$opener' at $open — the extraction is stale." }
    var depth = 0
    var index = open
    while (index < source.length) {
        if (source[index] == opener) depth++
        if (source[index] == closer) {
            depth--
            if (depth == 0) return index
        }
        index++
    }
    error("Unbalanced '$opener' from offset $open in ChatPanel.kt — the extraction is stale.")
}

/** The question the E5 behavioural scenario asks, used to identify the transcript that asked it. */
private const val E5_QUESTION = "summarise the proxy history for the E5 capture check"

/** The panel's real New Session button — the mutation E5's behavioural half drives the maps with. */
private fun newSessionButton(h: ChatPanelTestHarness.Harness): JButton =
    requireNotNull(ChatPanelTestHarness.find(h.panel.sessionsComponent(), JButton::class.java) { it.text == "New Session" }) {
        "No JButton labelled 'New Session' under ChatPanel.sessionsComponent() — the lookup is stale."
    }

/**
 * One [Container] per session transcript, in the order the cards were added.
 *
 * [transcriptText] joins every `JEditorPane` under `ChatPanel.root` into one string, which is the
 * right shape for a single-session drive and the wrong one for a claim about WHICH transcript a row
 * landed in. The session cards are the children of the `CardLayout` panel, so grouping by card is the
 * only way to ask that question.
 */
private fun sessionCards(h: ChatPanelTestHarness.Harness): List<Container> {
    val cards =
        requireNotNull(
            allDescendants(h.panel.root).filterIsInstance<Container>().firstOrNull { it.layout is CardLayout },
        ) { "No CardLayout container under ChatPanel.root — the session-card lookup is stale." }
    return cards.components.filterIsInstance<Container>()
}

/** One session card's rendered transcript, read through the `HTMLDocument` as [transcriptText] is. */
private fun transcriptTextOf(card: Container): String =
    allDescendants(card)
        .filterIsInstance<JEditorPane>()
        .joinToString(" ") { pane -> pane.document.getText(0, pane.document.length) }

/** The four D-11 labels, defined once so "is this a decision button?" is asked one way. */
private val DECISION_LABELS = setOf("Deny", "Deny for session", "Approve once", "Approve for session")

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

private fun decisionButtons(root: Container): List<AbstractButton> = allDescendants(root).filterIsInstance<AbstractButton>().filter { it.text in DECISION_LABELS }

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

/** The exact copy CR-05's entry guard emits, pinned so the test and the string cannot drift apart. */
private const val BUSY_REFUSAL = "A request is already running. Cancel it first."

/**
 * The `/tool` command the CR-05 scenarios drive.
 *
 * `proxy_http_history` because it is the one tool in the catalog that both completes headlessly and
 * reaches a stubbable Montoya seam, which is what lets the double block the worker mid-flight.
 */
private const val SLASH_TOOL_COMMAND = "/tool proxy_http_history {\"count\":5}"

/** The label prefix `OffEdtDispatch` receives for BOTH user-originated tool paths. */
private const val CHAT_TOOL_LABEL_PREFIX = "chat-tool-"

/**
 * A harness whose `proxy_http_history` double blocks until [latches] is released.
 *
 * Shared by the CR-05 and WR-04 scenarios, all of which need the same thing: a user-originated tool
 * call parked mid-flight so the panel is demonstrably in state S3 while the assertion runs. The tool
 * is enabled through [settingsEnabling], i.e. through the same two toggles a real user would set.
 *
 * `modelResponse` is deliberately not a tool call: these scenarios drive the `/tool` slash path, and a
 * chain step arriving as well would put a second worker in the dispatch record the assertions count.
 */
private fun harnessForUserOriginatedTool(latches: ToolLatches): ChatPanelTestHarness.Harness {
    val h =
        ChatPanelTestHarness.create(
            modelResponse = "no tool call here",
            settings = settingsEnabling("proxy_http_history"),
        )
    whenever(h.api.proxy().history()).thenAnswer {
        latches.entered.countDown()
        check(latches.probeRan.await(HANDSHAKE_FAILSAFE_SECONDS, TimeUnit.SECONDS)) {
            "The test never released the blocked tool — the mid-flight window was never opened."
        }
        emptyList<ProxyHttpRequestResponse>()
    }
    return h
}

/**
 * The panel's real Tools button, through the harness's single-match finder.
 *
 * Not [ChatPanelTestHarness.find]: a lookup that returns the first of several would make a
 * button-state assertion vacuous the moment a second `JButton` carried the same label.
 */
private fun toolsButton(h: ChatPanelTestHarness.Harness): JButton = ChatPanelTestHarness.toolsButton(h)

/**
 * One `AiRequestLogger.log` call, reduced to the three fields the WR-04 assertions read.
 *
 * A named shape rather than a raw argument array, so a signature change fails at compile time in one
 * place instead of silently shifting every positional index.
 */
private data class ActivityRecord(
    val type: ActivityType,
    val detail: String,
    val metadata: Map<String, String>,
)

/**
 * Every `MCP_TOOL_CALL` activity record the panel emitted, in emission order.
 *
 * Read off the mock's own invocation list rather than through `verify(..., atLeast(1))`, because the
 * negative control asserts a count of ZERO — and a captor-based verification of a mock that was never
 * called fails for the wrong reason, turning "no record was emitted" into an error rather than a pass.
 *
 * `log` takes ten parameters; the three read here are positional, which is what [ActivityRecord]
 * exists to state once.
 */
private fun toolCallRecords(h: ChatPanelTestHarness.Harness): List<ActivityRecord> {
    val logger = requireNotNull(h.supervisor.aiRequestLogger) { "No AiRequestLogger on the supervisor double." }
    return mockingDetails(logger)
        .invocations
        .filter { it.method.name == "log" }
        .map { invocation ->
            @Suppress("UNCHECKED_CAST")
            ActivityRecord(
                type = invocation.arguments[0] as ActivityType,
                detail = invocation.arguments[3] as String,
                metadata = invocation.arguments[9] as Map<String, String>,
            )
        }.filter { it.type == ActivityType.MCP_TOOL_CALL }
}

/**
 * The number of message rows on screen, counted as rendered transcript panes.
 *
 * The falsifiable form of "no result row appeared". See
 * [ChatPanelEdtConfinementTest.aSupersededUserOriginatedToolCallRendersNoResultRow] for why the
 * text-matching form of that claim cannot fail.
 */
private fun transcriptRowCount(h: ChatPanelTestHarness.Harness): Int = allDescendants(h.panel.root).filterIsInstance<JEditorPane>().size
