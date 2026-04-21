package com.six2dez.burp.aiagent.audit

import com.six2dez.burp.aiagent.backends.TokenUsage
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import java.nio.file.Files
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger

class AiRequestLoggerTest {
    private lateinit var logger: AiRequestLogger

    @BeforeEach
    fun setup() {
        logger = AiRequestLogger(maxEntries = 100)
    }

    @Test
    fun `test circular buffer enforcement`() {
        // Add 150 entries, expect only the last 100 to remain
        for (i in 1..150) {
            logger.log(
                type = ActivityType.PROMPT_SENT,
                source = "test",
                backendId = "test-backend",
                detail = "Entry $i",
            )
        }

        val entries = logger.entries()
        assertEquals(100, entries.size)
        // First entry should be the 51st added
        assertEquals("Entry 51", entries.first().detail)
        // Last entry should be the 150th added
        assertEquals("Entry 150", entries.last().detail)
    }

    @Test
    fun `test listener notification`() {
        val count = AtomicInteger(0)
        var lastEntry: AiActivityEntry? = null

        val listener = { entry: AiActivityEntry ->
            count.incrementAndGet()
            lastEntry = entry
            Unit
        }

        logger.addListener(listener)

        logger.log(
            type = ActivityType.MCP_TOOL_CALL,
            source = "mcp",
            backendId = "test",
            detail = "Tool execution",
        )

        assertEquals(1, count.get())
        assertNotNull(lastEntry)
        assertEquals(ActivityType.MCP_TOOL_CALL, lastEntry?.type)
        assertEquals("mcp", lastEntry?.source)
    }

    @Test
    fun `test filtering`() {
        logger.log(ActivityType.PROMPT_SENT, "agent", "b1", "Prompt 1")
        logger.log(ActivityType.RESPONSE_COMPLETE, "agent", "b1", "Response 1")
        logger.log(ActivityType.MCP_TOOL_CALL, "mcp", "b1", "Tool 1")
        logger.log(ActivityType.ERROR, "agent", "b1", "Error 1")

        val prompts = logger.entries(ActivityType.PROMPT_SENT)
        assertEquals(1, prompts.size)
        assertEquals(ActivityType.PROMPT_SENT, prompts.first().type)

        val mcpCalls = logger.entries(ActivityType.MCP_TOOL_CALL)
        assertEquals(1, mcpCalls.size)
        assertEquals(ActivityType.MCP_TOOL_CALL, mcpCalls.first().type)
    }

    @Test
    fun `test concurrent writes are thread-safe`() {
        val numThreads = 10
        val writesPerThread = 100
        val maxTarget = numThreads * writesPerThread
        logger.maxEntries = maxTarget // Allow all to fit

        val executor = Executors.newFixedThreadPool(numThreads)
        val latch = CountDownLatch(numThreads)

        for (i in 0 until numThreads) {
            executor.submit {
                for (j in 0 until writesPerThread) {
                    logger.log(ActivityType.PROMPT_SENT, "test", "b1", "Concurrent detail")
                }
                latch.countDown()
            }
        }

        latch.await(5, TimeUnit.SECONDS)
        executor.shutdown()

        assertEquals(numThreads * writesPerThread, logger.size())
    }

    @Test
    fun `test export to JSON format`() {
        logger.log(
            type = ActivityType.PROMPT_SENT,
            source = "chat",
            backendId = "test-backend",
            detail = "Hello",
            sessionId = "s1",
            durationMs = 150,
            tokenUsage = TokenUsage(10, 20),
            metadata = mapOf("custom" to "val"),
        )

        val exported = logger.exportAsMapList()
        assertEquals(1, exported.size)

        val map = exported.first()
        assertEquals(ActivityType.PROMPT_SENT.name, map["type"])
        assertEquals("chat", map["source"])
        assertEquals("test-backend", map["backendId"])
        assertEquals("s1", map["sessionId"])
        assertEquals(150L, map["durationMs"])
        assertEquals(10, map["inputTokens"])
        assertEquals(20, map["outputTokens"])

        @Suppress("UNCHECKED_CAST")
        val meta = map["metadata"] as Map<String, String>
        assertEquals("val", meta["custom"])
    }

    @Test
    fun `test rolling persistence writes jsonl`() {
        val tempDir = Files.createTempDirectory("ai-logger-jsonl")
        try {
            logger.configureRollingPersistence(
                RollingLogConfig(
                    directory = tempDir,
                    maxFileBytes = 1_000_000,
                    maxFiles = 3,
                ),
            )

            logger.log(ActivityType.PROMPT_SENT, "chat", "b1", "First entry")
            logger.log(ActivityType.RESPONSE_COMPLETE, "chat", "b1", "Second entry")

            val activeFile = tempDir.resolve("ai-request-log.jsonl")
            assertTrue(Files.exists(activeFile))
            val lines = Files.readAllLines(activeFile)
            assertEquals(2, lines.size)
            assertTrue(lines[0].contains("\"detail\":\"First entry\""))
            assertTrue(lines[1].contains("\"detail\":\"Second entry\""))
        } finally {
            tempDir.toFile().deleteRecursively()
        }
    }

    @Test
    fun `test rolling persistence rotates files`() {
        val tempDir = Files.createTempDirectory("ai-logger-rotation")
        try {
            logger.configureRollingPersistence(
                RollingLogConfig(
                    directory = tempDir,
                    maxFileBytes = AiRequestLogger.MIN_ROLLING_FILE_BYTES,
                    maxFiles = 2,
                ),
            )

            repeat(8) { index ->
                logger.log(
                    type = ActivityType.PROMPT_SENT,
                    source = "chat",
                    backendId = "b1",
                    detail = "Entry $index " + "x".repeat(3000),
                )
            }

            assertTrue(Files.exists(tempDir.resolve("ai-request-log.jsonl")))
            assertTrue(Files.exists(tempDir.resolve("ai-request-log.1.jsonl")))
        } finally {
            tempDir.toFile().deleteRecursively()
        }
    }

    @Test
    fun `test clear and disabled state`() {
        logger.log(ActivityType.PROMPT_SENT, "test", "test", "test")
        assertEquals(1, logger.size())

        logger.clear()
        assertEquals(0, logger.size())

        logger.enabled = false
        logger.log(ActivityType.PROMPT_SENT, "test", "test", "test")
        assertEquals(0, logger.size())
    }
}
