package com.six2dez.burp.aiagent.scanner

import burp.api.montoya.scanner.ConsolidationAction
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity
import com.six2dez.burp.aiagent.audit.AuditLogger
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.mockito.kotlin.any
import org.mockito.kotlin.never
import org.mockito.kotlin.verify

/**
 * Quick 261009-1ao - with the AI passive scanner on, each local finding is filed ONCE: by the Burp
 * Scanner passive check, under the name the AI passive scanner gives it (`issueNameForPassive`), with
 * every other side effect (audit record, counter, knowledge-base signal, findings buffer, auto-queue)
 * recorded before `doCheck` returns. The AI half no longer files local findings for scan-check
 * requests but still uses them to skip the AI call. The right-click manual analysis keeps filing them.
 */
class AiPassiveScanCheckFilingTest {
    @Test
    fun aLocalFindingIsFiledOnceUnderTheAiPassiveNameWhenBurpFilesFirst() {
        PassiveScanCheckRig().use { rig ->
            rig.scanner.setEnabled(true)
            val rr = rig.csrfPost("once-burp-first.example")

            val result = rig.check.doCheck(rr)
            rig.fileLikeBurp(result)
            rig.drain()

            val names = result.auditIssues().map { it.name() }
            assertEquals(listOf("[AI Passive] CSRF"), names, "the scan check files the finding under the AI passive name")
            assertEquals(rig.scanner.issueNameForPassive("Potential CSRF (Missing Token)"), names.single())
            val filed = rig.built.single()
            assertEquals(
                rig.scanner
                    .localChecks(rr.request(), rr.response())
                    .single()
                    .detail,
                filed.detail,
            )
            assertEquals("Verify the finding manually or use AI Active Scanner for confirmation.", filed.remediation)
            assertEquals(rr.request().url(), filed.baseUrl)
            assertEquals(AuditIssueSeverity.LOW, filed.severity)
            assertEquals(AuditIssueSeverity.LOW, filed.typicalSeverity)
            assertEquals(AuditIssueConfidence.TENTATIVE, filed.confidence)
            assertEquals(listOf(rr), filed.requestResponses)
            assertEquals(emptyList<Any>(), rig.extensionAdds, "the AI half files no second issue")
            assertEquals(1, rig.siteMap.size, "one issue in the site map")
        }
    }

    @Test
    fun theAiHalfFilesNoLocalIssueWhenItRunsBeforeBurpFiles() {
        PassiveScanCheckRig().use { rig ->
            rig.scanner.setEnabled(true)

            val result = rig.check.doCheck(rig.csrfPost("once-ai-first.example"))
            rig.drain()
            rig.fileLikeBurp(result)

            assertEquals(
                emptyList<String>(),
                rig.extensionAdds.map { it.name() },
                "the AI half files no local issue for a scan-check request",
            )
            assertEquals(listOf("[AI Passive] CSRF"), rig.built.map { it.name }, "exactly one issue is built")
        }
    }

    @Test
    fun aFiledFindingKeepsItsSideEffectsOnceAndRepeatsConsolidate() {
        PassiveScanCheckRig().use { rig ->
            rig.scanner.setEnabled(true)
            val rr = rig.csrfPost("sidefx.example")
            val url = rr.request().url()
            val first = rig.check.doCheck(rr)
            rig.fileLikeBurp(first)
            rig.drain()

            val event = rig.passiveIssueEvents().single()
            assertEquals("local", event["source"])
            assertEquals("Potential CSRF (Missing Token)", event["title"])
            assertEquals(AuditLogger.endpointOf(url), event["url"])
            assertEquals(1, rig.scanner.getStatus().issuesFound)
            val buffered = rig.scanner.getLastFindings(10).single()
            assertEquals(Triple("Potential CSRF (Missing Token)", "local", true), Triple(buffered.title, buffered.source, buffered.issueCreated))
            val signal = ScanKnowledgeBase.getVulnSignals(url).single()
            assertEquals("Potential CSRF (Missing Token)" to "local", signal.vulnClass to signal.source)

            val second = rig.check.doCheck(rig.csrfPost("sidefx.example"))
            rig.fileLikeBurp(second)
            rig.drain()

            assertEquals(1, second.auditIssues().size)
            assertEquals(
                ConsolidationAction.KEEP_EXISTING,
                rig.check.consolidateIssues(second.auditIssues().single(), first.auditIssues().single()),
            )
            assertEquals(1, rig.passiveIssueEvents().size, "a repeat writes no second audit event")
            assertEquals(1, rig.scanner.getStatus().issuesFound, "a repeat is not counted again")
            val findings = rig.scanner.getLastFindings(10)
            assertEquals(2, findings.size, "every finding is buffered")
            assertTrue(findings[1].issueCreated, "a consolidated repeat is buffered with issueCreated true")
            assertEquals(
                1,
                rig.output.count { it.contains("Consolidated duplicate issue: [AI Passive] CSRF") },
                "one consolidation line for the repeat",
            )
        }
    }

    @Test
    fun theSideEffectsAreRecordedBeforeTheCheckReturns() {
        PassiveScanCheckRig().use { rig ->
            rig.scanner.setEnabled(true)
            val latch = rig.blockExecutor()
            val rr = rig.csrfPost("sync.example")

            val result = rig.check.doCheck(rr)

            assertEquals(1, rig.passiveIssueEvents().size, "the audit event is written before doCheck returns")
            assertEquals(1, rig.scanner.getStatus().issuesFound, "the issue is counted before doCheck returns")
            assertEquals(1, rig.scanner.getLastFindings(10).size, "the finding is buffered before doCheck returns")
            assertEquals(1, ScanKnowledgeBase.getVulnSignals(rr.request().url()).size, "the signal is recorded before doCheck returns")
            latch.countDown()
            rig.fileLikeBurp(result)
            rig.drain()
            assertEquals(1, rig.passiveIssueEvents().size, "the AI half records no second event")
            assertEquals(emptyList<Any>(), rig.extensionAdds, "the AI half files no second issue")
        }
    }

    @Test
    fun theAiHalfStillSkipsTheAiCallBecauseOfALocalFinding() {
        PassiveScanCheckRig().use { rig ->
            rig.scanner.setEnabled(true)

            val result = rig.check.doCheck(rig.pageGet("skip.example", smugglingIndicators = true))
            rig.fileLikeBurp(result)

            assertEquals(1, result.auditIssues().size, "the smuggling finding is filed by the scan check")
            assertEquals(1, rig.analyzed(), "the request is analyzed and ends at the local-findings skip")
            verify(rig.supervisor, never()).startOrAttach(any())
            assertEquals(emptyList<String>(), rig.extensionAdds.map { it.name() }, "the AI half files no second issue")
        }
    }

    @Test
    fun withoutALocalFindingTheSameRequestReachesTheBackendStep() {
        PassiveScanCheckRig().use { rig ->
            rig.scanner.setEnabled(true)

            val result = rig.check.doCheck(rig.pageGet("skip-control.example", smugglingIndicators = false))

            assertEquals(0, result.auditIssues().size, "no local finding")
            assertEquals(0, rig.analyzed(), "no skip filter counts it: the analysis reaches the backend step")
            verify(rig.supervisor).startOrAttach(any())
        }
    }

    @Test
    fun theManualAnalysisStillFilesItsLocalFindings() {
        PassiveScanCheckRig().use { rig ->
            assertEquals(1, rig.scanner.manualScan(listOf(rig.csrfPost("manual.example"))))
            rig.drain()

            val added = rig.extensionAdds.single()
            assertEquals("[AI Passive] CSRF", added.name())
            assertEquals(AuditIssueConfidence.FIRM, added.confidence())
            assertEquals(listOf("local"), rig.passiveIssueEvents().map { it["source"] })
            assertEquals(emptyList<String>(), rig.errors.filter { it.contains("Failed to create issue") })
        }
    }
}
