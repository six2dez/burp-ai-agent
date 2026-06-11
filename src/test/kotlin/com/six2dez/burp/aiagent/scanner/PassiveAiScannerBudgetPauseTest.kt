package com.six2dez.burp.aiagent.scanner

import burp.api.montoya.MontoyaApi
import burp.api.montoya.http.message.HttpRequestResponse
import burp.api.montoya.http.message.requests.HttpRequest
import com.six2dez.burp.aiagent.TestSettings
import com.six2dez.burp.aiagent.audit.AuditLogger
import com.six2dez.burp.aiagent.supervisor.AgentSupervisor
import com.six2dez.burp.aiagent.util.BudgetGuard
import com.six2dez.burp.aiagent.util.TokenTracker
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.mockito.Answers
import org.mockito.kotlin.mock
import org.mockito.kotlin.whenever
import java.lang.reflect.Field

/**
 * SC4b: The budget pause gate is a no-op on enqueueForScanCheck that does NOT
 *       clear ScanKnowledgeBase and does NOT flip isEnabled().
 *
 * Pitfall 3 guard: pause MUST use a separate budgetPaused AtomicBoolean, NOT setEnabled(false)
 * which would clear the knowledge base and change the user's visible toggle.
 */
class PassiveAiScannerBudgetPauseTest {
    @AfterEach
    fun clearTokenTracker() {
        // TokenTracker is a process-wide singleton; reset its counters so per-session token sums
        // do not bleed across tests (the budget tests below assert on currentSessionTokens()).
        val countersField = TokenTracker::class.java.getDeclaredField("counters")
        countersField.isAccessible = true
        (countersField.get(TokenTracker) as java.util.concurrent.ConcurrentHashMap<*, *>).clear()
    }

    private fun makeScanner(): PassiveAiScanner =
        PassiveAiScanner(
            api = mock<MontoyaApi>(defaultAnswer = Answers.RETURNS_DEEP_STUBS),
            supervisor =
                mock<AgentSupervisor>().also { sup ->
                    whenever(sup.isBlockedByBurpAiGate()).thenReturn(false)
                },
            audit = mock<AuditLogger>(),
        ) { TestSettings.baselineSettings() }

    private fun mockRequestResponse(): HttpRequestResponse {
        val request = mock<HttpRequest>()
        whenever(request.url()).thenReturn("http://example.com/test")
        whenever(request.parameters()).thenReturn(emptyList())
        whenever(request.headers()).thenReturn(emptyList())
        whenever(request.headerValue("Content-Type")).thenReturn(null)
        whenever(request.bodyToString()).thenReturn("")
        return mock<HttpRequestResponse>().also {
            whenever(it.request()).thenReturn(request)
        }
    }

    /** Read the private executor field to inspect submission count via task count. */
    private fun executorSubmitCount(scanner: PassiveAiScanner): Int {
        // Access the underlying executor's task count via the thread pool interface
        val field: Field = scanner.javaClass.getDeclaredField("executor")
        field.isAccessible = true
        val executor = field.get(scanner) as java.util.concurrent.ExecutorService
        // Cast to thread pool executor to inspect task count
        if (executor is java.util.concurrent.ThreadPoolExecutor) {
            return executor.taskCount.toInt()
        }
        return -1
    }

    @Test
    fun budgetPaused_enqueueIsNoOp_executorNotSubmitted() {
        val scanner = makeScanner()
        scanner.setEnabled(true) // scanner is active

        // Capture task count before pause
        val countBefore = executorSubmitCount(scanner)

        scanner.setBudgetPaused(true)
        scanner.enqueueForScanCheck(mockRequestResponse())

        val countAfter = executorSubmitCount(scanner)
        // No task should have been submitted while paused
        if (countBefore >= 0 && countAfter >= 0) {
            assertTrue(
                countAfter == countBefore,
                "No executor task should be submitted when budget is paused (before=$countBefore, after=$countAfter)",
            )
        }
        // Also verify via isBudgetPaused
        assertTrue(scanner.isBudgetPaused(), "isBudgetPaused() must return true after setBudgetPaused(true)")
    }

    @Test
    fun budgetPaused_doesNotClearScanKnowledgeBase() {
        val scanner = makeScanner()
        scanner.setEnabled(true)

        // Populate the ScanKnowledgeBase with a tech-stack entry via reflection
        // (it is a package-level singleton; we just verify its size doesn't drop to 0 after pausing)
        // ScanKnowledgeBase is cleared by setEnabled(false). We assert pause does NOT call clear.
        // Record an entry so KB is non-empty.
        ScanKnowledgeBase.recordTechStack("budget-test.example.com", setOf("nginx", "php"))
        val kbSizeBefore = getScanKnowledgeBaseSize()
        assertTrue(kbSizeBefore > 0, "ScanKnowledgeBase should be non-empty before pause")

        scanner.setBudgetPaused(true)
        scanner.enqueueForScanCheck(mockRequestResponse())

        val kbSizeAfter = getScanKnowledgeBaseSize()
        assertTrue(
            kbSizeAfter > 0,
            "ScanKnowledgeBase must NOT be cleared by budget pause (Pitfall 3 guard)",
        )
        assertTrue(
            kbSizeAfter >= kbSizeBefore,
            "ScanKnowledgeBase must not shrink due to budget pause",
        )
    }

    @Test
    fun budgetPaused_doesNotFlipIsEnabled() {
        val scanner = makeScanner()
        scanner.setEnabled(true) // user set scanner ON

        scanner.setBudgetPaused(true)

        assertTrue(
            scanner.isEnabled(),
            "isEnabled() must remain true after budget pause — pause is separate from the user's toggle (Pitfall 3)",
        )
    }

    @Test
    fun budgetPaused_false_enqueueProceeds() {
        val scanner = makeScanner()
        scanner.setEnabled(true)
        scanner.setBudgetPaused(false) // explicitly not paused

        val countBefore = executorSubmitCount(scanner)
        scanner.enqueueForScanCheck(mockRequestResponse())
        val countAfter = executorSubmitCount(scanner)

        if (countBefore >= 0 && countAfter >= 0) {
            assertTrue(
                countAfter > countBefore,
                "When not paused, enqueueForScanCheck SHOULD submit to the executor",
            )
        }
        assertFalse(scanner.isBudgetPaused(), "isBudgetPaused() must return false")
    }

    @Test
    fun isBudgetPaused_initialState_returnsFalse() {
        val scanner = makeScanner()
        assertFalse(scanner.isBudgetPaused(), "budgetPaused must start false (per-process reset by design)")
    }

    // --- WR-01: scanner self-pauses when its OWN recorded tokens cross the hard cap ---

    @Test
    fun reconcileBudget_scannerOwnTokensCrossCap_selfPauses() {
        val scanner = makeScanner()
        scanner.setEnabled(true)
        // hard cap of 100 tokens. Record scanner consumption that crosses it: 800 input chars ≈ 200
        // input tokens estimated (>= 100 cap). This simulates a scanner-only run with no chat turn.
        TokenTracker.record(flow = "passive_scanner", backendId = "test-backend", inputChars = 800, outputChars = 0)
        val settings = TestSettings.baselineSettings().copy(tokenBudgetWarnThreshold = 0, tokenBudgetHardCap = 100)

        val state = scanner.reconcileBudget(settings)

        assertEquals(BudgetGuard.State.CAP, state, "Scanner-recorded tokens over the cap must evaluate to CAP")
        assertTrue(
            scanner.isBudgetPaused(),
            "WR-01: passive scanner must self-pause once its own recorded tokens cross the hard cap, " +
                "even with no chat turn",
        )
    }

    @Test
    fun reconcileBudget_belowCap_doesNotPause() {
        val scanner = makeScanner()
        scanner.setEnabled(true)
        // 40 input chars ≈ 10 estimated tokens, well below the 100 cap.
        TokenTracker.record(flow = "passive_scanner", backendId = "test-backend", inputChars = 40, outputChars = 0)
        val settings = TestSettings.baselineSettings().copy(tokenBudgetWarnThreshold = 0, tokenBudgetHardCap = 100)

        val state = scanner.reconcileBudget(settings)

        assertEquals(BudgetGuard.State.OFF, state, "Below both thresholds should evaluate OFF")
        assertFalse(scanner.isBudgetPaused(), "Scanner must NOT pause while under the cap")
    }

    // --- WR-02: the pause is reversible (not a one-way latch) ---

    @Test
    fun reconcileBudget_capRaisedAboveUsage_releasesPause() {
        val scanner = makeScanner()
        scanner.setEnabled(true)
        // Cross a cap of 100 → paused.
        TokenTracker.record(flow = "passive_scanner", backendId = "test-backend", inputChars = 800, outputChars = 0)
        scanner.reconcileBudget(TestSettings.baselineSettings().copy(tokenBudgetHardCap = 100))
        assertTrue(scanner.isBudgetPaused(), "precondition: scanner is paused after crossing the cap")

        // Operator raises the cap well above current usage; re-evaluation must RESUME.
        val state = scanner.reconcileBudget(TestSettings.baselineSettings().copy(tokenBudgetHardCap = 1_000_000))

        assertEquals(BudgetGuard.State.OFF, state, "Usage now below the raised cap should evaluate OFF")
        assertFalse(scanner.isBudgetPaused(), "WR-02: raising the cap above usage must release the pause")
    }

    @Test
    fun reconcileBudget_capClearedToUnlimited_releasesPause() {
        val scanner = makeScanner()
        scanner.setEnabled(true)
        TokenTracker.record(flow = "passive_scanner", backendId = "test-backend", inputChars = 800, outputChars = 0)
        scanner.reconcileBudget(TestSettings.baselineSettings().copy(tokenBudgetHardCap = 100))
        assertTrue(scanner.isBudgetPaused(), "precondition: scanner is paused after crossing the cap")

        // Operator clears the cap (0 = unlimited / off); re-evaluation must RESUME.
        val state = scanner.reconcileBudget(TestSettings.baselineSettings().copy(tokenBudgetHardCap = 0))

        assertEquals(BudgetGuard.State.OFF, state, "Cap=0 means unlimited; must evaluate OFF")
        assertFalse(scanner.isBudgetPaused(), "WR-02: clearing the cap (unlimited) must release the pause")
    }

    @Test
    fun reconcileBudget_warnState_doesNotPauseAndResumesFromCap() {
        val scanner = makeScanner()
        scanner.setEnabled(true)
        // 800 chars ≈ 200 tokens. warn=100, cap=300 → WARN (over warn, under cap).
        TokenTracker.record(flow = "passive_scanner", backendId = "test-backend", inputChars = 800, outputChars = 0)
        // Start paused to prove WARN releases an existing pause.
        scanner.setBudgetPaused(true)

        val state =
            scanner.reconcileBudget(
                TestSettings.baselineSettings().copy(tokenBudgetWarnThreshold = 100, tokenBudgetHardCap = 300),
            )

        assertEquals(BudgetGuard.State.WARN, state, "Between warn and cap should evaluate WARN")
        assertFalse(scanner.isBudgetPaused(), "WARN must not keep the scanner paused")
    }

    // --- WR-01 (iter 2): manual passive scan also respects the budget pause gate ---

    @Test
    fun manualScan_whenBudgetPaused_isNoOpAndReturnsZero() {
        val scanner = makeScanner()
        scanner.setEnabled(true)
        scanner.setBudgetPaused(true)

        val countBefore = executorSubmitCount(scanner)
        val queued = scanner.manualScan(listOf(mockRequestResponse(), mockRequestResponse()))
        val countAfter = executorSubmitCount(scanner)

        assertEquals(
            0,
            queued,
            "WR-01: manualScan must queue nothing and return 0 when the budget hard cap is paused",
        )
        if (countBefore >= 0 && countAfter >= 0) {
            assertTrue(
                countAfter == countBefore,
                "WR-01: no executor task should be submitted by manualScan while paused " +
                    "(before=$countBefore, after=$countAfter)",
            )
        }
        // Pause must not have touched the user's enabled toggle.
        assertTrue(scanner.isEnabled(), "manualScan pause must not flip isEnabled()")
    }

    @Test
    fun manualScan_whenNotPaused_queuesRequests() {
        val scanner = makeScanner()
        scanner.setEnabled(true)
        scanner.setBudgetPaused(false)

        val queued = scanner.manualScan(listOf(mockRequestResponse(), mockRequestResponse()))

        assertEquals(2, queued, "When not paused, manualScan must queue all supplied requests")
    }

    /** Reflectively read the size of ScanKnowledgeBase's tech stack map. */
    private fun getScanKnowledgeBaseSize(): Int {
        // ScanKnowledgeBase is an object; look for the techStack or hostData map
        return try {
            val cls = ScanKnowledgeBase::class.java
            val mapField =
                cls.declaredFields.firstOrNull { f ->
                    f.name.contains("tech", ignoreCase = true) ||
                        f.name.contains("host", ignoreCase = true) ||
                        f.name.contains("data", ignoreCase = true) ||
                        java.util.Map::class.java.isAssignableFrom(f.type)
                }
            mapField?.let {
                it.isAccessible = true
                (it.get(ScanKnowledgeBase) as? Map<*, *>)?.size ?: 0
            } ?: -1
        } catch (_: Exception) {
            -1 // If reflection fails, skip size assertion
        }
    }
}
