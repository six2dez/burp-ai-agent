package com.six2dez.burp.aiagent.backends.http

import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class ConversationHistoryTest {
    @Test
    fun trimsToConfiguredMaximum() {
        val history = ConversationHistory(maxMessages = 3)
        history.addUser("u1")
        history.addAssistant("a1")
        history.addUser("u2")
        history.addAssistant("a2")

        val snapshot = history.snapshot()
        assertEquals(3, snapshot.size)
        assertEquals("assistant", snapshot[0]["role"])
        assertEquals("a1", snapshot[0]["content"])
        assertEquals("user", snapshot[1]["role"])
        assertEquals("u2", snapshot[1]["content"])
        assertEquals("assistant", snapshot[2]["role"])
        assertEquals("a2", snapshot[2]["content"])
    }

    @Test
    fun supportsConcurrentWritesWithoutGrowingBeyondLimit() {
        val history = ConversationHistory(maxMessages = 20)
        val pool = Executors.newFixedThreadPool(8)
        val done = CountDownLatch(100)

        repeat(100) { index ->
            pool.submit {
                try {
                    if (index % 2 == 0) {
                        history.addUser("u$index")
                    } else {
                        history.addAssistant("a$index")
                    }
                } finally {
                    done.countDown()
                }
            }
        }

        assertTrue(done.await(5, TimeUnit.SECONDS))
        pool.shutdownNow()

        val snapshot = history.snapshot()
        assertTrue(snapshot.size <= 20)
        assertTrue(snapshot.all { it["role"] == "user" || it["role"] == "assistant" })
        assertTrue(snapshot.all { !it["content"].isNullOrBlank() })
    }

    @Test
    fun trimsByTotalCharsWhileKeepingRecentExchange() {
        val history = ConversationHistory(maxMessages = 20, maxTotalChars = 30)
        history.addUser("x".repeat(100))
        history.addAssistant("ok")
        history.addUser("ok")

        val snapshot = history.snapshot()
        assertEquals(2, snapshot.size)
        assertEquals("assistant", snapshot[0]["role"])
        assertEquals("ok", snapshot[0]["content"])
        assertEquals("user", snapshot[1]["role"])
        assertEquals("ok", snapshot[1]["content"])
    }
}
