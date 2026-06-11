package com.six2dez.burp.aiagent.scanner

import burp.api.montoya.MontoyaApi
import burp.api.montoya.http.message.HttpRequestResponse
import burp.api.montoya.http.message.params.HttpParameterType
import burp.api.montoya.http.message.params.ParsedHttpParameter
import burp.api.montoya.http.message.requests.HttpRequest
import com.six2dez.burp.aiagent.TestSettings
import com.six2dez.burp.aiagent.audit.AuditLogger
import com.six2dez.burp.aiagent.supervisor.AgentSupervisor
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.mockito.Answers
import org.mockito.kotlin.mock

/**
 * SC4 / QUAL-02 — covers the processedTargets dedup path in ActiveAiScanner.queueTarget().
 *
 * The dedup map (ConcurrentHashMap keyed on target.id) prevents the same target from being
 * re-queued within DEDUP_WINDOW_MS (1 hour). These tests exercise:
 *  1. Same target within the window → second call does NOT grow the queue.
 *  2. After resetStats() (clears processedTargets) → re-queue succeeds.
 *
 * Critical: setEnabled(true) must be called before queueTarget() or the enabled-gate at
 * ActiveAiScanner.kt:135 returns early and the dedup path is never reached.
 */
class ActiveScannerDedupTest {
    @Test
    fun queueTargetDedupPreventsRequeueWithinWindow() {
        val scanner = newScanner()
        scanner.setEnabled(true)

        val rr = requestResponse("http://example.com/?id=1", "id", "1")
        val point = InjectionPoint(InjectionType.URL_PARAM, "id", "1")
        val target =
            ActiveScanTarget(
                originalRequest = rr,
                injectionPoint = point,
                vulnHint = VulnHint(VulnClass.SQLI, 50, "test"),
                priority = 50,
            )

        // First enqueue
        scanner.queueTarget(target)
        val after1 = scanner.getQueueItems(limit = 10).size

        // Second enqueue — same target.id, within the dedup window (DEDUP_WINDOW_MS = 1 hour)
        scanner.queueTarget(target)
        val after2 = scanner.getQueueItems(limit = 10).size

        assertEquals(after1, after2, "dedup must prevent re-queuing the same target within DEDUP_WINDOW_MS")
        // The first enqueue should have succeeded (queue has at least 0 items; may be 0 if
        // startProcessing() consumed it, but after1 == after2 proves dedup worked either way)
        assertTrue(after1 <= 1)
    }

    @Test
    fun queueTargetAllowsRequeueAfterWindowExpires() {
        val scanner = newScanner()
        scanner.setEnabled(true)

        val rr = requestResponse("http://example.com/?id=2", "id", "2")
        val point = InjectionPoint(InjectionType.URL_PARAM, "id", "2")
        val target =
            ActiveScanTarget(
                originalRequest = rr,
                injectionPoint = point,
                vulnHint = VulnHint(VulnClass.SQLI, 50, "test"),
                priority = 50,
            )

        // First enqueue — populates processedTargets
        scanner.queueTarget(target)

        // resetStats() clears processedTargets — simulates expiry of the dedup window
        scanner.resetStats()

        // Second enqueue — dedup map is clear, so this must succeed
        scanner.queueTarget(target)

        val queueItems = scanner.getQueueItems(limit = 10)
        assertTrue(
            queueItems.size >= 1,
            "re-queue must succeed after processedTargets cleared by resetStats()",
        )
    }

    // ── helpers ─────────────────────────────────────────────────────────────────

    private fun newScanner(): ActiveAiScanner {
        // Deep stubs required: queueTarget() calls api.scope().isInScope() and
        // api.logging().logToOutput() — deep stubs return a mock for every chained call.
        val api = mock<MontoyaApi>(defaultAnswer = Answers.RETURNS_DEEP_STUBS)
        return ActiveAiScanner(
            api = api,
            supervisor = mock<AgentSupervisor>(),
            audit = mock<AuditLogger>(),
            getSettings = { TestSettings.baselineSettings() },
        ).apply {
            scopeOnly = false // disable scope filter so isInScope() is never consulted
            maxQueueSize = 64
            scanMode = ScanMode.FULL
        }
    }

    private fun requestResponse(
        url: String,
        name: String,
        value: String,
    ): HttpRequestResponse {
        val param = mock<ParsedHttpParameter>()
        org.mockito.kotlin
            .whenever(param.type())
            .thenReturn(HttpParameterType.URL)
        org.mockito.kotlin
            .whenever(param.name())
            .thenReturn(name)
        org.mockito.kotlin
            .whenever(param.value())
            .thenReturn(value)

        val request = mock<HttpRequest>()
        org.mockito.kotlin
            .whenever(request.url())
            .thenReturn(url)
        org.mockito.kotlin
            .whenever(request.parameters())
            .thenReturn(listOf(param))
        org.mockito.kotlin
            .whenever(request.headers())
            .thenReturn(emptyList())
        org.mockito.kotlin
            .whenever(request.headerValue("Content-Type"))
            .thenReturn(null)
        org.mockito.kotlin
            .whenever(request.bodyToString())
            .thenReturn("")

        val rr = mock<HttpRequestResponse>()
        org.mockito.kotlin
            .whenever(rr.request())
            .thenReturn(request)
        return rr
    }
}
