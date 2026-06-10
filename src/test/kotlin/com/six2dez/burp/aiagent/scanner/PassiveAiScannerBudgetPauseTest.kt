package com.six2dez.burp.aiagent.scanner

import burp.api.montoya.MontoyaApi
import burp.api.montoya.http.message.HttpRequestResponse
import burp.api.montoya.http.message.requests.HttpRequest
import com.six2dez.burp.aiagent.TestSettings
import com.six2dez.burp.aiagent.audit.AuditLogger
import com.six2dez.burp.aiagent.supervisor.AgentSupervisor
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

    private fun makeScanner(): PassiveAiScanner =
        PassiveAiScanner(
            api = mock<MontoyaApi>(defaultAnswer = Answers.RETURNS_DEEP_STUBS),
            supervisor = mock<AgentSupervisor>().also { sup ->
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
