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

    private class FakeConnection(private val id: String) : AgentConnection {
        override fun isAlive(): Boolean = true

        override fun send(
            text: String,
            history: List<ChatMessage>?,
            onChunk: (String) -> Unit,
            onComplete: (Throwable?) -> Unit,
            systemPrompt: String?
        ) = Unit

        override fun stop() = Unit

        override fun toString(): String = "FakeConnection($id)"
    }
}
