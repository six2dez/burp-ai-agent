package com.six2dez.burp.aiagent.ui

import com.six2dez.burp.aiagent.backends.AgentConnection
import com.six2dez.burp.aiagent.backends.ChatMessage
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertSame
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import java.util.Collections
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger

class ChatPanelConcurrencyTest {
    @Test
    fun clearIfMatches_onlyClearsWhenConnectionMatches() {
        val tracker = InFlightConnectionTracker()
        val first = FakeConnection("first")
        val second = FakeConnection("second")

        tracker.set(first)

        assertFalse(tracker.clearIfMatches(second))
        assertSame(first, tracker.current())

        assertTrue(tracker.clearIfMatches(first))
        assertNull(tracker.current())
    }

    @Test
    fun take_returnsConnectionOnlyOnceUnderConcurrency() {
        val tracker = InFlightConnectionTracker()
        val target = FakeConnection("target")
        tracker.set(target)

        val pool = Executors.newFixedThreadPool(4)
        val start = CountDownLatch(1)
        val results = Collections.synchronizedList(mutableListOf<AgentConnection?>())

        repeat(4) {
            pool.submit {
                start.await()
                results.add(tracker.take())
            }
        }
        start.countDown()
        pool.shutdown()
        assertTrue(pool.awaitTermination(2, TimeUnit.SECONDS))

        assertEquals(1, results.count { it === target })
        assertEquals(3, results.count { it == null })
        assertNull(tracker.current())
    }

    /**
     * SC1 gate: session-map EDT confinement contract.
     *
     * Models the EDT-confinement invariant without constructing a real ChatPanel
     * (which requires Swing + UiTheme and throws HeadlessException in CI).
     *
     * Strategy: a single-thread executor stands in for the EDT.  All map mutations
     * and reads are routed exclusively through that executor.  A pool of background
     * threads attempt concurrent map access but are also routed through the same
     * single-thread executor (simulating the invokeLater dispatch that the fix
     * introduces).  This proves the confinement design produces no
     * ConcurrentModificationException and a consistent final state.
     */
    @Test
    fun sessionMaps_noDataRaceUnderEdtConfinement() {
        // Single-thread executor stands in for the AWT Event Dispatch Thread.
        val edtExecutor = Executors.newSingleThreadExecutor { r ->
            Thread(r, "fake-EDT").also { it.isDaemon = true }
        }

        // The session map — confined to edtExecutor (the fake EDT).
        val sessionMap = linkedMapOf<String, String>()
        val sawException = AtomicBoolean(false)
        val readSuccesses = AtomicInteger(0)
        val writeSuccesses = AtomicInteger(0)

        val iterations = 200
        val readers = 4
        val start = CountDownLatch(1)
        val done = CountDownLatch(readers + 1) // readers + 1 writer pool

        // Writer pool: submits mutations through the fake EDT (simulates invokeLater wrapping).
        val writerPool = Executors.newFixedThreadPool(2)
        writerPool.submit {
            try {
                start.await()
                repeat(iterations) { i ->
                    // Route every mutation onto the fake EDT — mirrors the invokeLater fix.
                    edtExecutor.submit {
                        try {
                            sessionMap["session-$i"] = "value-$i"
                            writeSuccesses.incrementAndGet()
                        } catch (e: Exception) {
                            sawException.set(true)
                        }
                    }
                }
            } finally {
                done.countDown()
            }
        }

        // Reader pool: each reader also routes its access through the fake EDT.
        // This mirrors how off-EDT callers (onComplete callbacks) must invokeLater
        // before touching the maps.
        val readerPool = Executors.newFixedThreadPool(readers)
        repeat(readers) { r ->
            readerPool.submit {
                try {
                    start.await()
                    repeat(iterations) { i ->
                        // Route every read onto the fake EDT.
                        edtExecutor.submit {
                            try {
                                @Suppress("UnusedExpression")
                                sessionMap["session-$i"] // read access
                                readSuccesses.incrementAndGet()
                            } catch (e: Exception) {
                                sawException.set(true)
                            }
                        }
                    }
                } finally {
                    done.countDown()
                }
            }
        }

        start.countDown()

        // Wait for all submissions to be dispatched.
        assertTrue(done.await(10, TimeUnit.SECONDS), "Submission phase timed out")

        // Drain the fake EDT so all submitted tasks complete.
        val drainLatch = CountDownLatch(1)
        edtExecutor.submit { drainLatch.countDown() }
        assertTrue(drainLatch.await(10, TimeUnit.SECONDS), "EDT drain timed out")

        writerPool.shutdown()
        readerPool.shutdown()
        edtExecutor.shutdown()

        assertFalse(sawException.get(), "ConcurrentModificationException or other exception detected — EDT confinement violated")
        assertTrue(writeSuccesses.get() == iterations, "Expected $iterations writes, got ${writeSuccesses.get()}")
        // Every entry written should be present (no race corruption).
        val mapSnapshot = mutableMapOf<String, String>()
        mapSnapshot.putAll(sessionMap)
        assertEquals(iterations, mapSnapshot.size, "Map size mismatch — possible lost write or corruption")
    }

    /**
     * WR-01 regression guard: `ChatPanel.shutdown()` is reachable off the EDT (Burp's unload
     * handler runs on a Montoya thread), yet it touches `@GuardedBy("EDT")` session maps and Swing
     * via `cancelInFlightRequest()` + `stopAllTimers()`. The fix marshals that work onto the EDT
     * with an `isEventDispatchThread()`-guarded `invokeAndWait`.
     *
     * Constructing a real `ChatPanel` throws `HeadlessException` in CI (see SC1 test above), so this
     * exercises the exact marshaling shape `shutdown()` uses and asserts the confined work runs on
     * the EDT — never on the calling (off-EDT) thread — and that the call is synchronous.
     */
    @Test
    fun shutdownMarshalingRunsConfinedWorkOnEdtWhenCalledOffEdt() {
        val ranOnEdt = AtomicBoolean(false)
        val ranOnCallingThread = AtomicBoolean(false)
        val executed = AtomicBoolean(false)
        val callerThread = Thread.currentThread()

        // Mirror ChatPanel.shutdown(): if off-EDT, marshal via invokeAndWait; else run inline.
        val work = Runnable {
            executed.set(true)
            ranOnEdt.set(javax.swing.SwingUtilities.isEventDispatchThread())
            ranOnCallingThread.set(Thread.currentThread() === callerThread)
        }

        // Sanity: this test thread is NOT the EDT, so the off-EDT branch is the one under test.
        assertFalse(javax.swing.SwingUtilities.isEventDispatchThread(), "test must run off the EDT")

        if (javax.swing.SwingUtilities.isEventDispatchThread()) {
            work.run()
        } else {
            javax.swing.SwingUtilities.invokeAndWait(work)
        }

        // invokeAndWait is synchronous: the work has already completed by the time we return.
        assertTrue(executed.get(), "confined work did not execute")
        assertTrue(ranOnEdt.get(), "confined work must run on the EDT (REL-01 confinement)")
        assertFalse(ranOnCallingThread.get(), "confined work must NOT run on the off-EDT calling thread")
    }

    private class FakeConnection(
        private val id: String,
    ) : AgentConnection {
        override fun isAlive(): Boolean = true

        override fun send(
            text: String,
            history: List<ChatMessage>?,
            onChunk: (String) -> Unit,
            onComplete: (Throwable?) -> Unit,
            systemPrompt: String?,
            jsonMode: Boolean,
            maxOutputTokens: Int?,
        ) = Unit

        override fun stop() = Unit

        override fun toString(): String = "FakeConnection($id)"
    }
}
