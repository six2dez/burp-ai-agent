package com.six2dez.burp.aiagent.ui

import burp.api.montoya.MontoyaApi
import burp.api.montoya.core.BurpSuiteEdition
import com.six2dez.burp.aiagent.TestSettings
import com.six2dez.burp.aiagent.config.AgentSettings
import com.six2dez.burp.aiagent.supervisor.AgentSupervisor
import com.six2dez.burp.aiagent.ui.components.ToolApprovalCard
import org.mockito.Answers
import org.mockito.kotlin.any
import org.mockito.kotlin.anyOrNull
import org.mockito.kotlin.mock
import org.mockito.kotlin.whenever
import java.awt.Container
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.TimeUnit
import java.util.concurrent.locks.ReentrantLock
import javax.swing.JButton
import javax.swing.JComponent
import javax.swing.JTextArea
import javax.swing.SwingUtilities
import kotlin.concurrent.withLock

/**
 * Shared headless fixture that builds a **real** [ChatPanel] and drives its **real** Send button.
 *
 * This is deliberately not a model of the chat flow. It constructs the production ten-parameter
 * [ChatPanel] from deep-stub mocks, so assertions written against it exercise the same code path a
 * user drives in Burp. That is what makes the SEC-06 / SC4 acceptance gate in [ChatPanelToolGateTest]
 * non-vacuous.
 *
 * It is enabled by two things that landed with it in Phase 22 Wave 0:
 * - the `ChatPanel.kt` headless guard on `Toolkit.getDefaultToolkit().menuShortcutKeyMaskEx`, the one
 *   headless-hostile call in the whole construction path;
 * - `-Djava.awt.headless=true` in `tasks.test`, so a developer Mac and `ubuntu-latest` agree.
 *
 * Note for anyone reading `ChatPanelConcurrencyTest`: its KDoc claims a real `ChatPanel` "requires
 * Swing + UiTheme and throws HeadlessException in CI". That premise was measured false — the entire
 * cost was the one-call guard above. Do not copy the modelled approach from that file into new tests.
 *
 * **Naming constraint (hard).** `build.gradle.kts` excludes `*IntegrationTest`, `*ConcurrencyTest`,
 * `*BackpressureTest`, `*RestartPolicyTest` and `*SupervisionTest` under `-PexcludeHeavyTests=true`,
 * which is exactly what the PR gate passes. This object, and every test built on it, must avoid those
 * suffixes or the gate silently stops running them.
 *
 * This object declares no annotated test functions at all by design — it is a fixture, not a suite,
 * so no JUnit runner picks it up.
 */
object ChatPanelTestHarness {
    /**
     * Zero-based index of the `onChunk: (String) -> Unit` callback in `AgentSupervisor.sendChat`.
     *
     * Verified against the real signature at `AgentSupervisor.kt:435-449` rather than trusted from
     * research: the function takes 13 parameters and `onChunk` is the 8th of them.
     */
    private const val ON_CHUNK_INDEX = 7

    /** Zero-based index of `onComplete: (Throwable?) -> Unit` — `AgentSupervisor.kt:444`. */
    private const val ON_COMPLETE_INDEX = 8

    /**
     * Zero-based index of `traceId: String?` in `AgentSupervisor.sendChat`.
     *
     * Verified against the real signature at AgentSupervisor.kt:430-444: `traceId` is the 10th
     * parameter, at :440.
     */
    private const val TRACE_ID_INDEX = 9

    /** The label prefix ChatPanel's `/tool` branch dispatches its worker under. */
    private const val SLASH_TOOL_LABEL_PREFIX = "chat-tool-slash-"

    /**
     * Measured-sufficient number of EDT drains for the send -> response -> tool-call chain.
     *
     * Exposed as a parameter on [drainEdt] so a later plan can raise it in one place instead of
     * editing every call site.
     */
    private const val DEFAULT_EDT_DRAINS = 4

    /** Holder giving a test access to the mocks after it has driven the real UI. */
    data class Harness(
        val panel: ChatPanel,
        val api: MontoyaApi,
        val supervisor: AgentSupervisor,
        /**
         * Every message the panel passed to its `showError` sink, in emission order.
         *
         * The production sink is a modal (`MainTab` routes it to a `JOptionPane`), which cannot be
         * driven under `-Djava.awt.headless=true`. `ChatPanel` takes it as a constructor lambda, so
         * capturing it here reads the real call the real code made rather than modelling one.
         *
         * `CopyOnWriteArrayList` because a refusal can be reported from a worker's EDT tail while the
         * test thread reads the list.
         */
        val shownErrors: CopyOnWriteArrayList<String>,
        /**
         * Every non-null trace id this panel passed to `sendChat`, in call order.
         *
         * Written by the `sendChat` stub in [create]. A test that replaces that stub with `doAnswer`
         * records nothing here and must record the trace id itself.
         */
        val sentTraceIds: CopyOnWriteArrayList<String>,
    )

    /**
     * Builds a real [ChatPanel] whose backend answers every chat turn with [modelResponse].
     *
     * `sendChat` is stubbed to invoke the response callback and then the completion callback
     * synchronously on the calling thread. That is what makes the whole flow deterministic without
     * sleeping on a timer.
     */
    fun create(
        // Deliberately has NO default value, matching the ContextPreviewDialog.kt:21-23 convention:
        // a default is how a future test silently asserts against the wrong model output.
        modelResponse: String,
        settings: AgentSettings = TestSettings.baselineSettings(),
        // Quick 261008-n0c: a test that composes the chat the way MainTab does passes MainTab's provider.
        getSettings: (() -> AgentSettings)? = null,
    ): Harness {
        val api: MontoyaApi = mock(defaultAnswer = Answers.RETURNS_DEEP_STUBS)
        whenever(api.burpSuite().version().edition()).thenReturn(BurpSuiteEdition.COMMUNITY_EDITION)

        val supervisor: AgentSupervisor = mock(defaultAnswer = Answers.RETURNS_DEEP_STUBS)
        whenever(supervisor.requiresBurpAiAndDisabled(any())).thenReturn(false)
        val sentTraceIds = CopyOnWriteArrayList<String>()
        whenever(
            // 13 matchers, one per parameter of AgentSupervisor.sendChat; nullable parameters use
            // anyOrNull() so an omitted optional argument still matches.
            supervisor.sendChat(
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
            ),
        ).thenAnswer { invocation ->
            @Suppress("UNCHECKED_CAST")
            val onChunk = invocation.arguments[ON_CHUNK_INDEX] as (String) -> Unit

            @Suppress("UNCHECKED_CAST")
            val onComplete = invocation.arguments[ON_COMPLETE_INDEX] as (Throwable?) -> Unit
            (invocation.arguments[TRACE_ID_INDEX] as String?)?.let { sentTraceIds.add(it) }
            onChunk(modelResponse)
            onComplete(null)
            null
        }

        val shownErrors = CopyOnWriteArrayList<String>()
        val panel =
            ChatPanel(
                api = api,
                supervisor = supervisor,
                getSettings = getSettings ?: { settings },
                validateBackend = { null },
                ensureBackendReady = { true },
                showError = { message -> shownErrors.add(message) },
                onStatusChanged = { },
                onResponseReady = { },
                passiveScanner = null,
            )
        panel.createNewSession()
        return Harness(panel, api, supervisor, shownErrors, sentTraceIds)
    }

    /**
     * The trace id of the one chain [h]'s panel ran, read from what it passed to `sendChat`.
     *
     * One chain threads one trace id through every followup turn, and that id is the label
     * `OffEdtDispatch.run` settles every chain tool worker under. That the record collapses to one
     * distinct value is itself the claim that exactly one chain ran in this panel.
     */
    fun chainTraceId(h: Harness): String {
        val distinct = h.sentTraceIds.distinct()
        return requireNotNull(distinct.singleOrNull()) {
            "Expected exactly one distinct trace id passed to sendChat; recorded ${h.sentTraceIds.toList()}. " +
                "A test that replaced the sendChat stub with doAnswer records nothing here."
        }
    }

    /**
     * The label of the single `/tool` worker dispatched since [installSettledObserver].
     *
     * Fails with the dispatched list when there is not exactly one, so a second `/tool` call cannot
     * silently bind an await to the wrong worker.
     */
    fun slashToolLabel(): String {
        val dispatched = dispatchedLabels()
        val slash = dispatched.filter { it.startsWith(SLASH_TOOL_LABEL_PREFIX) }
        check(slash.size == 1) {
            "Expected exactly one dispatched label starting with $SLASH_TOOL_LABEL_PREFIX; dispatched: $dispatched"
        }
        return slash.single()
    }

    /**
     * Depth-first search of the Swing component tree under [root] for the first component of [type]
     * satisfying [predicate].
     *
     * Kept generic on purpose: later plans reuse it to locate the tool-call approval card and its
     * buttons, not just the input area and Send.
     */
    fun <T : JComponent> find(
        root: Container,
        type: Class<T>,
        predicate: (T) -> Boolean = { true },
    ): T? {
        root.components.forEach { child ->
            val self = if (type.isInstance(child)) type.cast(child).takeIf(predicate) else null
            val match = self ?: (child as? Container)?.let { find(it, type, predicate) }
            if (match != null) return match
        }
        return null
    }

    /**
     * Every component of [type] under [root] satisfying [predicate], in depth-first order.
     *
     * The counting sibling of [find]. [find] answers "is there one?", which is the right question for
     * a card that may legitimately be absent and the WRONG one for a component the panel owns exactly
     * one of: a lookup by type alone silently binds to a sibling — `ToolApprovalCard` renders its
     * arguments into a read-only [JTextArea], so "the [JTextArea] under the panel" stops being unique
     * the moment a decision is on screen. Assertions built on the first of several are how a component
     * claim goes vacuous.
     */
    fun <T : JComponent> findAll(
        root: Container,
        type: Class<T>,
        predicate: (T) -> Boolean = { true },
    ): List<T> =
        root.components.flatMap { child ->
            val self = if (type.isInstance(child)) listOfNotNull(type.cast(child).takeIf(predicate)) else emptyList()
            self + ((child as? Container)?.let { findAll(it, type, predicate) } ?: emptyList())
        }

    /**
     * The single component of [type] under [root] satisfying [predicate], asserted to be single.
     *
     * [what] names what was searched for, so a miss reads as a stale lookup rather than as a null
     * dereference three frames later.
     */
    private fun <T : JComponent> findExactlyOne(
        root: Container,
        type: Class<T>,
        what: String,
        predicate: (T) -> Boolean,
    ): T {
        val matches = findAll(root, type, predicate)
        check(matches.size == 1) {
            "Expected exactly one $what under the searched container; found ${matches.size}. " +
                "A finder that returned the first of several would make every assertion on it vacuous."
        }
        return matches.single()
    }

    /**
     * The panel's real Tools button — the UI-SPEC Rule S-1 affordance that must go inert in state S3.
     *
     * Asserted to match exactly one component: the label is what identifies it, and a second button
     * carrying it would mean the assertion had stopped being about the one the user clicks.
     */
    fun toolsButton(h: Harness): JButton = findExactlyOne(h.panel.root, JButton::class.java, "JButton labelled 'Tools'") { it.text == "Tools" }

    /**
     * The panel's real input area, identified by its constructed geometry (`JTextArea(3, 24)`).
     *
     * Rows-and-columns rather than `isEditable`, because this finder is used to assert the input is
     * DISABLED — and a disabled `JTextArea` is still editable, so the `isEditable` rule that
     * [sendUserMessage] relies on would keep matching the `ToolApprovalCard` argument box too.
     * Asserted to match exactly one component for the reason [findExactlyOne] states.
     */
    fun inputTextArea(h: Harness): JTextArea =
        findExactlyOne(h.panel.root, JTextArea::class.java, "JTextArea(rows = 3, columns = 24) input area") {
            it.rows == 3 && it.columns == 24
        }

    /**
     * The first SEC-06 [ToolApprovalCard] in the transcript under [root], or `null` if none was added.
     *
     * A thin wrapper over [find] rather than a second traversal, so "is a decision on screen?" is asked
     * exactly one way across the suite. `null` is the meaningful answer for the two cases that must
     * NEVER produce a card: an `AUTO`-tier call, and a call the user originated themselves.
     */
    internal fun findApprovalCard(root: Container): ToolApprovalCard? = find(root, ToolApprovalCard::class.java)

    /**
     * Types [text] into the panel's real input area and clicks its real Send button on the EDT.
     *
     * **The `isEditable` predicate is load-bearing, not defensive.** It used to be true that the input
     * area was the only [JTextArea] under the panel — the transcript renders into a `JEditorPane` — but
     * `ToolApprovalCard` renders the model-supplied arguments into a read-only [JTextArea] as part of
     * its anti-spoofing rule, and the transcript is added to the layout BEFORE the input panel
     * (`chatContainer.add(chatCards, CENTER)` then `add(inputPanel(), SOUTH)`). A depth-first search
     * for any `JTextArea` therefore returns the CARD's argument box the moment a decision is on screen,
     * so a second `sendUserMessage` would type into the card and click Send on an empty input — a
     * silent no-op that makes every lifecycle assertion pass vacuously. The input area is the only
     * EDITABLE one, which is a property of what it is for rather than of where it sits in the tree.
     *
     * **The WHOLE interaction runs on the EDT, tree walk included, and that is not tidiness.** Assigning
     * `input.text` fires the input area's `DocumentListener`, which calls `ChatPanel.syncDraftFromInput`
     * and writes `sessionDrafts` — a `@GuardedBy("EDT")` map. Only the click used to be dispatched, so
     * the harness that exists to assert the production path was itself breaking the confinement REL-01
     * established, and `syncDraftFromInput` had no `assertEdt()` to catch it under `-ea` (WR-10). It has
     * one now, so this ordering is enforced rather than remembered. A fixture is a template as much as a
     * tool: every later test built on this one inherits whichever discipline it shows.
     *
     * The two `requireNotNull` messages surface through `InvocationTargetException.cause`, which JUnit
     * prints — worth less than running the lookups off-thread would cost.
     */
    fun sendUserMessage(
        h: Harness,
        text: String,
    ) {
        SwingUtilities.invokeAndWait {
            val input =
                requireNotNull(find(h.panel.root, JTextArea::class.java) { it.isEditable }) {
                    "No editable JTextArea found under ChatPanel.root — the input area lookup is stale."
                }
            val send =
                requireNotNull(find(h.panel.root, JButton::class.java) { it.text == "Send" }) {
                    "No JButton labelled 'Send' found under ChatPanel.root — the button lookup is stale."
                }
            input.text = text
            send.doClick()
        }
    }

    /**
     * Drains the nested `invokeLater` blocks the send chain schedules, so assertions run after the
     * response and any tool call have been processed.
     */
    fun drainEdt(times: Int = DEFAULT_EDT_DRAINS) {
        repeat(times) { SwingUtilities.invokeAndWait { } }
    }

    /**
     * Default failsafe for [awaitToolSettled], in seconds.
     *
     * Ten, not sixty, and the number has a budget behind it: a red-before-green demonstration against
     * the pre-fix tree pays this failsafe once per waiting test, and ten seconds is what that
     * demonstration is worth. It is a **deadlock failsafe, never a wall-clock assertion** — nothing
     * compares it against the work, which settles in microseconds once the dispatch is correct.
     */
    private const val DEFAULT_SETTLE_FAILSAFE_SECONDS = 10L

    /** Guards [settledCounts]; [settledChanged] is signalled on every settle. */
    private val settleLock = ReentrantLock()

    private val settledChanged = settleLock.newCondition()

    /**
     * Settles per label since [installSettledObserver], read by [awaitToolSettled].
     *
     * Cumulative and never consumed: a second await on the same label sees the same total, and no
     * await can take a settle that belongs to another label. Guarded by [settleLock].
     */
    private val settledCounts = HashMap<String, Int>()

    /**
     * The ordered record of the same settle events, for assertions that need to inspect what finished
     * and in which order. Written under [settleLock] together with [settledCounts].
     */
    private val settledLog = CopyOnWriteArrayList<String>()

    /**
     * The record of workers STARTED, a different moment from the two above, and the one a test must
     * read when its claim is that no worker ran at all.
     *
     * A settle record is written from the worker's EDT tail, i.e. at settle. So in the buggy world such
     * a test exists to catch (a denied or un-decided call that dispatched a worker anyway), that worker
     * has not finished at assert time and its label is missing from [settledLog] too, so the assertion
     * passes while the bug is present. `OffEdtDispatch.run` writes THIS log as its first statement,
     * synchronous with the dispatch, so a started worker is visible the moment it exists and its absence
     * is a real claim rather than a timing artefact.
     */
    private val dispatchedLog = CopyOnWriteArrayList<String>()

    /**
     * Installs both `OffEdtDispatch` hooks and clears the three records.
     *
     * **One lifecycle pair, not two, even though it installs two hooks.** The pair is pinned to a count
     * of exactly one by acceptance criteria in plans 23-01 and 23-02: these are process-global hooks,
     * so one left registered captures events from every test class that runs after this one, and a
     * second lifecycle pair is one more thing to forget to clear. Same install/clear discipline as
     * `AuditLogger.registerGlobalEmitter`.
     */
    fun installSettledObserver() {
        settleLock.withLock {
            settledCounts.clear()
            settledLog.clear()
            dispatchedLog.clear()
        }
        OffEdtDispatch.registerSettledObserver { label ->
            settleLock.withLock {
                settledCounts[label] = (settledCounts[label] ?: 0) + 1
                settledLog.add(label)
                settledChanged.signalAll()
            }
        }
        OffEdtDispatch.registerDispatchedObserver { label -> dispatchedLog.add(label) }
    }

    /** Clears both hooks. See [installSettledObserver] for why they share one lifecycle pair. */
    fun releaseSettledObserver() {
        OffEdtDispatch.registerSettledObserver(null)
        OffEdtDispatch.registerDispatchedObserver(null)
    }

    /**
     * Blocks until [count] tool workers dispatched under [label] have finished their marshalled EDT
     * tail, then drains the EDT.
     *
     * **[label] is mandatory because the settle stream is process-global.** `OffEdtDispatch` is an
     * `object`, panels built by earlier tests stay alive after those tests end, and their chains keep
     * settling under their own trace ids. An await that accepted any label once returned on exactly
     * those: the eight-step AUTO chain of `autoToolStillRunsWithNoCard` satisfied the awaits of the next
     * two tests while their own workers were still running, which left only the EDT drain as a disguised
     * wall-clock wait. Callers pass their own chain's trace id or their own `/tool` worker's label.
     *
     * **Counts are cumulative since [installSettledObserver] and are never consumed**, so a second await
     * on the same label sees the same total and asks for the new one.
     *
     * **[drainEdt] alone cannot do this and the gap is structural, not a matter of draining harder.**
     * It drains the EDT QUEUE and knows nothing about a daemon worker, so an assertion placed straight
     * after it runs in the window between the dispatch and the worker's tail. The settle observer fires
     * from that tail's `finally`, so a successful await means the tail has ALREADY run on the EDT.
     *
     * [failsafeSeconds] is one overall deadline that bounds a deadlock; it is not a measurement. Past it
     * the await fails with an IllegalStateException naming the label, the counts and both logs.
     */
    fun awaitToolSettled(
        label: String,
        count: Int,
        failsafeSeconds: Long = DEFAULT_SETTLE_FAILSAFE_SECONDS,
    ) {
        require(count >= 1) { "count must be at least 1; was $count" }
        val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(failsafeSeconds)
        settleLock.withLock {
            while ((settledCounts[label] ?: 0) < count) {
                val remaining = deadline - System.nanoTime()
                if (remaining <= 0L) {
                    error(
                        "Tool worker(s) under label $label did not settle $count time(s) within ${failsafeSeconds}s " +
                            "(observed ${settledCounts[label] ?: 0}). The async dispatch or its EDT tail is broken, " +
                            "or the label is not this test's own. Settled so far: ${settledLabels()}; dispatched: ${dispatchedLabels()}.",
                    )
                }
                settledChanged.awaitNanos(remaining)
            }
        }
        drainEdt()
    }

    /** Snapshot of every worker that has FINISHED, in settle order. Non-draining. */
    fun settledLabels(): List<String> = settledLog.toList()

    /** Snapshot of every worker that has STARTED, in dispatch order. See [dispatchedLog]. */
    fun dispatchedLabels(): List<String> = dispatchedLog.toList()
}
