package com.six2dez.burp.aiagent.ui

import burp.api.montoya.MontoyaApi
import com.six2dez.burp.aiagent.config.AgentSettings
import com.six2dez.burp.aiagent.config.AgentSettingsRepository
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertTimeoutPreemptively
import org.mockito.Answers
import org.mockito.kotlin.mock
import java.io.File
import java.time.Duration
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import javax.swing.SwingUtilities

/**
 * REL-05 / SC4 / CR-02 — the behavioural acceptance suite for [SettingsPersistQueue].
 *
 * **Naming constraint (hard).** `build.gradle.kts` excludes `*IntegrationTest`, `*ConcurrencyTest`,
 * `*BackpressureTest`, `*RestartPolicyTest` and `*SupervisionTest` under `-PexcludeHeavyTests=true`,
 * which is exactly what `.github/workflows/build.yml` passes. `SettingsPersistQueueTest` is the
 * approved name; `SettingsPersistConcurrencyTest` would have been the natural one and would have made
 * this suite silently stop running on the PR gate.
 *
 * **No test here compares an elapsed duration to a threshold.** Blocking is proved by mutual latches
 * whose failure mode is a deadlock [assertTimeoutPreemptively] reports categorically, and by the
 * recorded outcome of the handshake rather than by a latch count alone.
 *
 * **The overlap assertion is an entry-time detector, never a snapshot-field comparison.**
 * `AgentSettings` is a `data class`, an immutable value handed to `apply` by reference, so a single
 * invocation cannot receive a mixture of two snapshots under ANY implementation, lock or no lock. A
 * "no torn fields" assertion would be false by construction and could never fail — and this test is
 * the only asserted mitigation for threats `T-23-06-01` and `T-23-06-02`, both `high`.
 */
class SettingsPersistQueueTest {
    /** Labels recorded from [OffEdtDispatch]'s settle observer — one per completed dispatch. */
    private val settled = CopyOnWriteArrayList<String>()
    private lateinit var settledSignal: CountDownLatch

    /** Snapshot ids recorded on ENTRY to each apply body, in the order the bodies actually ran. */
    private val appliedIds = CopyOnWriteArrayList<String>()

    private val errors = CopyOnWriteArrayList<String>()

    @BeforeEach
    fun installObservers() {
        settled.clear()
        appliedIds.clear()
        errors.clear()
        settledSignal = CountDownLatch(1)
        OffEdtDispatch.registerSettledObserver { label ->
            settled.add(label)
            settledSignal.countDown()
        }
    }

    @AfterEach
    fun releaseObservers() {
        OffEdtDispatch.registerSettledObserver(null)
        OffEdtDispatch.registerDispatchedObserver(null)
    }

    /**
     * T-23-06-04 / SC4 — the submitting thread returns while the apply body is still blocked.
     *
     * The apply body stands in for the real path's reach into `KtorMcpServerManager.stop()`'s bounded
     * `future.get(10, TimeUnit.SECONDS)`: it blocks until a runnable the test queues to the EDT *after*
     * the submit has already returned. If the persist body were still on the EDT that runnable could
     * never run, and the handshake records a categorical failure rather than a slow path a timer has to
     * guess at.
     */
    @Test
    fun theSubmittingThreadReturnsWhileTheApplyIsStillBlocked() {
        assertTimeoutPreemptively(Duration.ofSeconds(30)) {
            val queue = SettingsPersistQueue { errors.add(it) }
            val applyEntered = CountDownLatch(1)
            val probeRan = CountDownLatch(1)
            val edtWasFree = AtomicBoolean(false)
            val workerThread = CopyOnWriteArrayList<String>()

            SwingUtilities.invokeAndWait {
                queue.submit(
                    label = "handshake",
                    supersedeKey = SAME_FIELD,
                    payload = snapshot("only"),
                    apply = {
                        workerThread.add(Thread.currentThread().name)
                        applyEntered.countDown()
                        edtWasFree.set(probeRan.await(20, TimeUnit.SECONDS))
                    },
                    onSettled = { },
                )
            }

            assertTrue(applyEntered.await(20, TimeUnit.SECONDS), "SC4: the submit never reached the apply body.")
            SwingUtilities.invokeLater { probeRan.countDown() }
            assertTrue(settledSignal.await(25, TimeUnit.SECONDS), "SC4: the write never settled.")

            // The LOUD clause, asserted first: the handshake's own recorded outcome. A bare
            // `probeRan.count == 0` would also read zero after a synchronous apply finally returned and
            // the EDT drained its queue — green with the defect fully present.
            assertTrue(
                edtWasFree.get(),
                "SC4/T-23-06-04: the EDT must run queued work while a settings write is mid-flight. A " +
                    "false here means submit() applied inline on the calling thread, so the click paid " +
                    "the whole bounded ten-second MCP stop on the EDT.",
            )
            assertEquals(
                listOf("burp-ai-settings-sync"),
                workerThread.toList(),
                "SC4: the persist body must run on the named daemon worker, not the caller's thread.",
            )
        }
    }

    /**
     * T-23-06-01 / T-23-06-02 (both `high`) — two apply bodies never overlap, and run in submission
     * order.
     *
     * The detector is entry-time mutual exclusion, not field identity: the body flips an
     * `inApply` flag on the way in and records whether it was ALREADY set. Removing `lock.withLock`
     * from `applyIfCurrent` turns `overlapSeen` true — which is the red probe this assertion is
     * accepted on.
     */
    @Test
    fun twoApplyBodiesNeverOverlapAndRunInSubmissionOrder() {
        assertTimeoutPreemptively(Duration.ofSeconds(60)) {
            val queue = SettingsPersistQueue { errors.add(it) }
            val inApply = AtomicBoolean(false)
            val overlapSeen = AtomicBoolean(false)
            val firstEntered = CountDownLatch(1)
            val bothEntered = CountDownLatch(2)
            val release = CountDownLatch(1)
            settledSignal = CountDownLatch(2)

            val body: (AgentSettings) -> Unit = { snapshot ->
                if (inApply.getAndSet(true)) {
                    overlapSeen.set(true)
                }
                appliedIds.add(snapshot.preferredBackendId)
                firstEntered.countDown()
                bothEntered.countDown()
                release.await(20, TimeUnit.SECONDS)
                inApply.set(false)
            }

            SwingUtilities.invokeAndWait {
                queue.submit("write", SAME_FIELD, snapshot("alpha"), body) { }
            }
            assertTrue(firstEntered.await(20, TimeUnit.SECONDS), "The first write never reached the apply body.")
            SwingUtilities.invokeAndWait {
                queue.submit("write", SAME_FIELD, snapshot("beta"), body) { }
            }

            // A bounded window for the second write to overlap the first. Under the lock it cannot,
            // so this await times out and the wait costs three seconds; without the lock the second
            // worker enters immediately and the detector above fires. Not asserted on directly — the
            // recorded `overlapSeen` is the claim.
            bothEntered.await(3, TimeUnit.SECONDS)
            release.countDown()
            assertTrue(settledSignal.await(30, TimeUnit.SECONDS), "Both writes never settled.")

            assertFalse(
                overlapSeen.get(),
                "T-23-06-01/T-23-06-02: two apply bodies were inside the persist body at once. " +
                    "SettingsPersistQueue.applyIfCurrent must run each apply to completion under its " +
                    "single ReentrantLock, so two header MCP writes never overlap their bounded MCP " +
                    "stop/start. (AgentSettingsRepository's write lock is what keeps save() whole for " +
                    "every writer, quick 261008-o97.)",
            )
            assertEquals(
                listOf("alpha", "beta"),
                appliedIds.toList(),
                "The apply bodies must run in submission order, which is click order.",
            )
        }
    }

    /**
     * T-23-06-03 — an older generation that reaches the lock late is dropped, never applied over a
     * newer one.
     *
     * Driven deterministically through [OffEdtDispatch]'s dispatched observer, which fires on the
     * CALLING thread before the worker is started: parking the older submitter there holds generation 1
     * outside `applyIfCurrent` entirely while generation 2 runs to completion. Without that seam the
     * out-of-order arrival this guard exists for is a scheduler race a test cannot force.
     */
    @Test
    fun anOlderGenerationIsDroppedRatherThanAppliedOverANewerOne() {
        assertTimeoutPreemptively(Duration.ofSeconds(30)) {
            val queue = SettingsPersistQueue { errors.add(it) }
            val olderParked = CountDownLatch(1)
            val releaseOlder = CountDownLatch(1)
            val body: (AgentSettings) -> Unit = { snapshot -> appliedIds.add(snapshot.preferredBackendId) }

            OffEdtDispatch.registerDispatchedObserver { label ->
                if (label.startsWith("older-")) {
                    olderParked.countDown()
                    releaseOlder.await(20, TimeUnit.SECONDS)
                }
            }

            val olderSubmitter =
                Thread({ queue.submit("older", SAME_FIELD, snapshot("stale"), body) { } }, "older-submitter")
            olderSubmitter.isDaemon = true
            olderSubmitter.start()
            assertTrue(olderParked.await(20, TimeUnit.SECONDS), "The older submitter never reached the dispatch hook.")

            // Generation 2 is minted and applied while generation 1 is still parked before its worker
            // has even been started.
            SwingUtilities.invokeAndWait {
                queue.submit("newer", SAME_FIELD, snapshot("current"), body) { }
            }
            assertTrue(settledSignal.await(25, TimeUnit.SECONDS), "The newer write never settled.")

            settledSignal = CountDownLatch(1)
            releaseOlder.countDown()
            assertTrue(settledSignal.await(25, TimeUnit.SECONDS), "The older write never settled.")
            olderSubmitter.join(TimeUnit.SECONDS.toMillis(20))

            assertEquals(
                listOf("current"),
                appliedIds.toList(),
                "T-23-06-03: generation 1 reached applyIfCurrent after generation 2 had already begun " +
                    "applying, so it must be dropped. Seeing \"stale\" here means the older snapshot was " +
                    "written over the newer one the user actually chose last.",
            )
            assertEquals(2, settled.size, "Both writes must settle, including the dropped one.")
        }
    }

    /**
     * Q-261008-o97-R1 (T-o97-05) — writes to different fields never supersede each other.
     *
     * Each header write now carries ONE field, so dropping an older write because a newer write to a
     * DIFFERENT field began first would silently lose a toggle the header still shows as changed. The
     * same dispatched-observer parking as the test above: the older write (key "passive") is held before
     * its worker starts while the newer one (key "active") runs to completion.
     */
    @Test
    fun writesToDifferentFieldsNeverSupersedeEachOther() {
        assertTimeoutPreemptively(Duration.ofSeconds(30)) {
            val queue = SettingsPersistQueue { errors.add(it) }
            val olderParked = CountDownLatch(1)
            val releaseOlder = CountDownLatch(1)
            val body: (AgentSettings) -> Unit = { snapshot -> appliedIds.add(snapshot.preferredBackendId) }

            OffEdtDispatch.registerDispatchedObserver { label ->
                if (label.startsWith("older-")) {
                    olderParked.countDown()
                    releaseOlder.await(20, TimeUnit.SECONDS)
                }
            }

            val olderSubmitter =
                Thread({ queue.submit("older", "passive", snapshot("passive"), body) { } }, "older-submitter")
            olderSubmitter.isDaemon = true
            olderSubmitter.start()
            assertTrue(olderParked.await(20, TimeUnit.SECONDS), "The older submitter never reached the dispatch hook.")

            SwingUtilities.invokeAndWait {
                queue.submit("newer", "active", snapshot("active"), body) { }
            }
            assertTrue(settledSignal.await(25, TimeUnit.SECONDS), "The newer write never settled.")

            settledSignal = CountDownLatch(1)
            releaseOlder.countDown()
            assertTrue(settledSignal.await(25, TimeUnit.SECONDS), "The older write never settled.")
            olderSubmitter.join(TimeUnit.SECONDS.toMillis(20))

            assertEquals(
                listOf("active", "passive"),
                appliedIds.toList(),
                "Q-261008-o97-R1: a write to one field must never drop a write to another field. Each " +
                    "header write sets one field of the saved snapshot, so the supersede rule is per " +
                    "field; a missing \"passive\" means a passive toggle was silently never saved.",
            )
            assertEquals(2, settled.size, "Both writes must settle.")
        }
    }

    /**
     * T-23-06-05 — `dispose()` stops new work and never blocks its caller.
     *
     * `MainTab.shutdown()` calls it from the EDT while a worker may be inside a bounded ten-second
     * `mcpSupervisor.applySettings`. A `dispose()` that took the queue's lock would block there for the
     * whole wait, reintroducing at unload the exact freeze this class removes — and would fail this
     * test as a deadlock rather than as an assertion.
     */
    @Test
    fun disposeStopsNewWorkAndDoesNotBlockTheCaller() {
        assertTimeoutPreemptively(Duration.ofSeconds(30)) {
            val queue = SettingsPersistQueue { errors.add(it) }
            val inApply = AtomicBoolean(false)
            val heldEntered = CountDownLatch(1)
            val release = CountDownLatch(1)

            SwingUtilities.invokeAndWait {
                queue.submit(
                    label = "held",
                    supersedeKey = SAME_FIELD,
                    payload = snapshot("held"),
                    apply = { s ->
                        appliedIds.add(s.preferredBackendId)
                        inApply.set(true)
                        heldEntered.countDown()
                        release.await(20, TimeUnit.SECONDS)
                        inApply.set(false)
                    },
                    onSettled = { },
                )
            }
            assertTrue(heldEntered.await(20, TimeUnit.SECONDS), "The held write never reached the apply body.")

            queue.dispose()
            assertTrue(
                inApply.get(),
                "T-23-06-05: dispose() returned only after the in-flight apply finished, i.e. it took " +
                    "the worker's lock. It must set its flag and return.",
            )

            release.countDown()
            assertTrue(settledSignal.await(25, TimeUnit.SECONDS), "The held write never settled.")

            settledSignal = CountDownLatch(1)
            SwingUtilities.invokeAndWait {
                queue.submit("after-dispose", SAME_FIELD, snapshot("after"), { s: AgentSettings -> appliedIds.add(s.preferredBackendId) }) { }
            }
            assertTrue(settledSignal.await(25, TimeUnit.SECONDS), "The post-dispose write never settled.")

            assertEquals(
                listOf("held"),
                appliedIds.toList(),
                "T-23-06-05: a write submitted after dispose() must never reach its apply body, so no " +
                    "settings write can start after MainTab.shutdown() has run.",
            )
        }
    }

    /**
     * CR-02 / REL-05 / quick 261008-n0c — every enumerated `MainTab` settings write goes through the
     * persist queue, and the chat neither saves nor applies settings.
     *
     * A structural gate, because the alternative is unreachable: driving a real `MainTab` headlessly
     * would need the whole Burp `MontoyaApi` surface plus a live `ChatPanel`. It reads `MainTab.kt`
     * from disk and asserts the eight counts pinned in the KDoc ledger above `persistSettings`, as
     * EQUALITIES — "greater than zero" would pass with an eighth inline write site added.
     *
     * **Comment lines are stripped, block comments included.** The ledger deliberately reproduces the
     * very tokens counted here, so a `//`-only filter would read one high on every token against a
     * CORRECT implementation. `build.gradle.kts` declares `MainTab.kt` as a `tasks.test` input, so an
     * edit to it re-runs this assertion instead of serving it from cache — the measured 22-09 defect.
     */
    @Test
    fun everyMainTabSettingsWriteGoesThroughThePersistQueue() {
        val code = codeLinesOf(MAIN_TAB_SOURCE)

        assertEquals(
            6,
            code.count { it.contains("persistSettings(") },
            "MainTab ledger: `persistSettings(` must be 1 declaration + 5 call sites (backend picker, " +
                "passive/active host callbacks, passive/active header toggles). A different count means " +
                "a site was added, removed, or regressed to an inline settingsRepo.save on the EDT.",
        )
        assertEquals(
            3,
            code.count { it.contains("persistSettingsAndApplyMcp(") },
            "MainTab ledger: `persistSettingsAndApplyMcp(` must be 1 declaration + 2 call sites (the MCP " +
                "host callback and the header mcpToggle) — the only two sites allowed to reach " +
                "McpSupervisor.stop().",
        )
        assertEquals(
            0,
            code.count { it.contains("settingsRepo.save(") },
            "MainTab ledger: `settingsRepo.save(` must be 0. Header writes save through " +
                "persistHeaderChange / persistHeaderChangeAndApplyMcp, which apply one field to the saved " +
                "snapshot under the repository write lock (quick 261008-o97). A save here would persist " +
                "a whole snapshot again, unsaved Settings edits included, or the chat saves settings " +
                "again (quick 261008-n0c, H10).",
        )
        assertEquals(
            0,
            code.count { it.contains("mcpSupervisor.applySettings(") },
            "MainTab ledger: `mcpSupervisor.applySettings(` must be 0. The only MCP apply of a header " +
                "write is inside persistHeaderChangeAndApplyMcp, built from what was saved; one here " +
                "would apply unsaved MCP edits, or let a passive/active toggle reach McpSupervisor.stop() " +
                "and drop live scanner tasks (T-23-06-07).",
        )
        assertEquals(
            1,
            code.count { it.contains("persistHeaderChange(") },
            "MainTab ledger: `persistHeaderChange(` must be 1, persistSettings' apply lambda.",
        )
        assertEquals(
            1,
            code.count { it.contains("persistHeaderChangeAndApplyMcp(") },
            "MainTab ledger: `persistHeaderChangeAndApplyMcp(` must be 1, persistSettingsAndApplyMcp's " +
                "apply lambda.",
        )
        assertEquals(
            0,
            code.count { it.contains("supervisor.applySettings(") },
            "MainTab ledger: `supervisor.applySettings(` must be 0. MainTab never pushes settings into " +
                "AgentSupervisor; App's mirrorAppliedSettingsInto does it inside every successful save, " +
                "so a MainTab call would be a second, unordered writer. The token is lowercase and does " +
                "not match the MCP one.",
        )
        assertEquals(
            1,
            code.count { it.contains("getSettings = { settingsRepo.load() }") },
            "MainTab ledger: `getSettings = { settingsRepo.load() }` must be 1, the ChatPanel " +
                "construction. ChatPanel reads the applied snapshot and nothing else (quick 261008-n0c).",
        )
    }

    /**
     * Q-261008-o97-ATOMIC / -MCP — the header-write worker bodies save only through the atomic
     * `AgentSettingsRepository.update`, and only the MCP body applies MCP settings.
     *
     * Equalities on comment-stripped `SettingsPersistQueue.kt`: two `update(` calls (one per worker
     * body), no `save(` (a whole-snapshot save would bypass the read-modify-write under the repository
     * lock), and one MCP apply (only the McpEnabled body may reach McpSupervisor.stop(), T-23-06-07).
     */
    @Test
    fun headerWriteWorkerBodiesSaveOnlyThroughTheAtomicUpdate() {
        val code = codeLinesOf(PERSIST_QUEUE_SOURCE)

        assertEquals(
            2,
            code.count { it.contains("settingsRepo.update(") },
            "Worker bodies: `settingsRepo.update(` must be 1 in persistHeaderChange + 1 in " +
                "persistHeaderChangeAndApplyMcp.",
        )
        assertEquals(
            0,
            code.count { it.contains("settingsRepo.save(") },
            "Worker bodies: `settingsRepo.save(` must be 0. A header write saves one field onto the " +
                "saved snapshot through update(), never a snapshot read at click time.",
        )
        assertEquals(
            1,
            code.count { it.contains("mcpSupervisor.applySettings(") },
            "Worker bodies: `mcpSupervisor.applySettings(` must be 1, in persistHeaderChangeAndApplyMcp, " +
                "built from what update() saved (T-23-06-07).",
        )
    }

    // ---------------------------------------------------------------------------------------------
    // Fixture
    // ---------------------------------------------------------------------------------------------

    /**
     * A default [AgentSettings] tagged with [id] in `preferredBackendId`, which is the field every
     * assertion here reads back. `AgentSettings` has no defaulted constructor parameters, so the
     * repository's own factory is the only honest way to build one.
     */
    private fun snapshot(id: String): AgentSettings {
        val api: MontoyaApi = mock(defaultAnswer = Answers.RETURNS_DEEP_STUBS)
        return AgentSettingsRepository(api).defaultSettings().copy(preferredBackendId = id)
    }

    /**
     * The non-comment lines of [path], read from disk.
     *
     * Named, resolved and asserted rather than left to surface as a bare `FileNotFoundException`, which
     * is what a build-layout change would otherwise produce here — the shape
     * `SettingsSaveAsyncTest.restoreDefaultsSource` uses. A line counts as a comment when its first
     * non-space characters are a line-comment marker, a continuation asterisk, or a block-comment
     * opener; stripping BLOCK comments is what makes it safe for the counted tokens to be named in the
     * ledger KDoc that documents them. (The three markers are written out longhand here rather than
     * quoted, because Kotlin block comments nest — a literal opener inside this KDoc would open a
     * nested comment and swallow the rest of the file.)
     */
    private fun codeLinesOf(path: String): List<String> {
        val file = File(path)
        assertTrue(
            file.isFile,
            "Expected to find `$path` relative to the test working directory " +
                "`${System.getProperty("user.dir")}`, resolved as `${file.absolutePath}`. If the build " +
                "layout changed, fix the path here and in the matching `tasks.test` input declaration.",
        )
        return file
            .readLines()
            .filterNot { line ->
                val trimmed = line.trimStart()
                trimmed.startsWith("//") || trimmed.startsWith("*") || trimmed.startsWith("/*")
            }
    }

    private companion object {
        const val MAIN_TAB_SOURCE = "src/main/kotlin/com/six2dez/burp/aiagent/ui/MainTab.kt"
        const val PERSIST_QUEUE_SOURCE = "src/main/kotlin/com/six2dez/burp/aiagent/ui/SettingsPersistQueue.kt"

        /** One supersede key shared by the tests that model writes to the same field. */
        const val SAME_FIELD = "same-field"
    }
}
