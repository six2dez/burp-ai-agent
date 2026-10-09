package com.six2dez.burp.aiagent.ui

import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicReference

/**
 * Pins that the harness's tool-settle await returns only on the caller's own label.
 *
 * The settle stream is process-global: `OffEdtDispatch` is an `object`, and its settle observer sees
 * every worker in the JVM. Panels built by earlier tests stay alive after those tests end, and their
 * chains keep settling under their own trace ids while later tests run. An await that accepts any label
 * returns on those foreign settles while the caller's own worker is still running, which leaves only the
 * EDT drain that follows it as a disguised wall-clock wait.
 *
 * These probes drive `OffEdtDispatch.run` directly, with no panel: a foreign label settles first, the
 * test's own worker is held on a latch, and the await must not return until that latch is released.
 *
 * **Naming constraint (hard).** The class name carries none of the heavy suffixes `build.gradle.kts`
 * excludes from the fast gate, so these probes run on every PR.
 */
class AwaitScopeProbeTest {
    @BeforeEach
    fun install() {
        ChatPanelTestHarness.installSettledObserver()
    }

    @AfterEach
    fun release() {
        ChatPanelTestHarness.releaseSettledObserver()
    }

    @Test
    fun anotherChainsSettleDoesNotSatisfyTheAwait() {
        val stale = "await-scope-a-stale"
        val own = "await-scope-a-own"
        dispatch(stale) { }
        awaitLogged(stale, 1)

        val release = CountDownLatch(1)
        dispatch(own) { check(release.await(FAILSAFE_SECONDS, TimeUnit.SECONDS)) }
        val waiter = startWaiter { ChatPanelTestHarness.awaitToolSettled(count = 1) }

        val returnedEarly: Boolean
        try {
            waiter.thread.join(OBSERVATION_WINDOW_MS)
            returnedEarly = waiter.returned.get()
        } finally {
            release.countDown()
            waiter.thread.join(TimeUnit.SECONDS.toMillis(FAILSAFE_SECONDS))
        }

        assertFalse(
            returnedEarly,
            "The await returned on a foreign settle: label $stale had settled, but this test's own worker " +
                "($own) was still running on its latch. Settled: ${ChatPanelTestHarness.settledLabels()}",
        )
        assertTrue(
            waiter.returned.get(),
            "The await must return once this test's own worker settled. Failure: ${waiter.failure.get()}",
        )
    }

    @Test
    fun aCountOfTwoCountsOnlyTheCallersOwnSettles() {
        val stale = "await-scope-b-stale"
        val own = "await-scope-b-own"
        dispatch(stale) { }
        dispatch(stale) { }
        awaitLogged(stale, 2)
        dispatch(own) { }
        awaitLogged(own, 1)

        val release = CountDownLatch(1)
        dispatch(own) { check(release.await(FAILSAFE_SECONDS, TimeUnit.SECONDS)) }
        val waiter = startWaiter { ChatPanelTestHarness.awaitToolSettled(count = 2) }

        val returnedEarly: Boolean
        try {
            waiter.thread.join(OBSERVATION_WINDOW_MS)
            returnedEarly = waiter.returned.get()
        } finally {
            release.countDown()
            waiter.thread.join(TimeUnit.SECONDS.toMillis(FAILSAFE_SECONDS))
        }

        assertFalse(
            returnedEarly,
            "The await returned on a foreign settle: two settles of $stale and one of $own were counted as " +
                "two of this test's own, while its second worker was still running on its latch. " +
                "Settled: ${ChatPanelTestHarness.settledLabels()}",
        )
        assertTrue(
            waiter.returned.get(),
            "The await must return once this test's own second worker settled. Failure: ${waiter.failure.get()}",
        )
    }
}

// -- Helpers ----------------------------------------------------------------------------------

/**
 * How long a probe watches the waiter before releasing the held worker, in milliseconds.
 *
 * An observation window, not a correctness timeout: a scoped await cannot return before the release
 * whatever this value is. It only gives a defective await time to show itself.
 */
private const val OBSERVATION_WINDOW_MS = 200L

/** Deadlock failsafe, in seconds. A bound on a hang, never a threshold the work is measured against. */
private const val FAILSAFE_SECONDS = 10L

/** The worker thread name these probes dispatch under; distinct from production's so a thread dump is unambiguous. */
private const val PROBE_THREAD_NAME = "burp-ai-dispatch-probe"

/** A waiter thread with the two outcomes a probe reads after joining it. */
private class Waiter(
    val thread: Thread,
    val returned: AtomicBoolean,
    val failure: AtomicReference<Throwable?>,
)

private fun dispatch(
    label: String,
    work: () -> Unit,
) {
    OffEdtDispatch.run(
        threadName = PROBE_THREAD_NAME,
        label = label,
        logError = { },
        work = work,
        onEdt = { },
    )
}

/** Waits until the harness's settle log holds [label] [times] times; fails with the log after the failsafe. */
private fun awaitLogged(
    label: String,
    times: Int,
) {
    val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(FAILSAFE_SECONDS)
    while (ChatPanelTestHarness.settledLabels().count { it == label } < times) {
        check(System.nanoTime() < deadline) {
            "Label $label did not settle $times time(s) within ${FAILSAFE_SECONDS}s. Settled: ${ChatPanelTestHarness.settledLabels()}"
        }
        Thread.sleep(1)
    }
}

/** Starts a daemon thread running [block]; records whether it returned and any throwable it raised. */
private fun startWaiter(block: () -> Unit): Waiter {
    val returned = AtomicBoolean(false)
    val failure = AtomicReference<Throwable?>(null)
    val thread =
        Thread({
            try {
                block()
                returned.set(true)
            } catch (t: Throwable) {
                failure.set(t)
            }
        }, "await-scope-waiter").apply { isDaemon = true }
    thread.start()
    return Waiter(thread, returned, failure)
}
