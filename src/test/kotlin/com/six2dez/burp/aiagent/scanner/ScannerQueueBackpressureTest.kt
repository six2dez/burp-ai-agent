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
import org.mockito.kotlin.whenever

class ScannerQueueBackpressureTest {
    @Test
    fun queueDropsTargetsAfterMaxQueueSize() {
        val scanner =
            ActiveAiScanner(
                api = mock<MontoyaApi>(defaultAnswer = Answers.RETURNS_DEEP_STUBS),
                supervisor = mock<AgentSupervisor>(),
                audit = mock<AuditLogger>(),
            ) { TestSettings.baselineSettings() }
        scanner.scopeOnly = false
        scanner.maxQueueSize = 3
        scanner.scanMode = ScanMode.FULL

        val requests =
            (1..6).map { idx ->
                requestResponse("http://example.com/?id=$idx", "id", idx.toString())
            }
        val queued = scanner.manualScan(requests, vulnClasses = listOf(VulnClass.SQLI))

        assertEquals(3, queued)
        assertEquals(3, scanner.getStatus().queueSize)
        assertTrue(scanner.getQueueItems(limit = 10).all { it.status == "QUEUED" })

        val extraQueued =
            scanner.manualScan(
                requests = listOf(requestResponse("http://example.com/?id=999", "id", "999")),
                vulnClasses = listOf(VulnClass.SQLI),
            )
        assertEquals(0, extraQueued)
        assertEquals(3, scanner.getStatus().queueSize)
    }

    private fun requestResponse(
        url: String,
        name: String,
        value: String,
    ): HttpRequestResponse {
        val param = mock<ParsedHttpParameter>()
        whenever(param.type()).thenReturn(HttpParameterType.URL)
        whenever(param.name()).thenReturn(name)
        whenever(param.value()).thenReturn(value)

        val request = mock<HttpRequest>()
        whenever(request.url()).thenReturn(url)
        whenever(request.parameters()).thenReturn(listOf(param))
        whenever(request.headers()).thenReturn(emptyList())
        whenever(request.headerValue("Content-Type")).thenReturn(null)
        whenever(request.bodyToString()).thenReturn("")

        return mock<HttpRequestResponse>().also {
            whenever(it.request()).thenReturn(request)
        }
    }
}
