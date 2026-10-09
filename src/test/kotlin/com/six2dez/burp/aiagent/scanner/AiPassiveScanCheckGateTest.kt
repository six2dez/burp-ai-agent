package com.six2dez.burp.aiagent.scanner

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

/**
 * Quick 261009-1ao - the Burp Scanner passive check ([AiPassiveScanCheck]) acts only while the AI
 * passive scanner is on. It reads the same runtime switch the AI half reads
 * ([PassiveAiScanner.isEnabled]) on every check, so with the scanner off it files no issue, records no
 * side effect and enqueues no analysis, whatever the saved settings say. The token-budget pause gates
 * only the AI half and the side effects, not the filing.
 */
class AiPassiveScanCheckGateTest {
    @Test
    fun nothingIsFiledOrEnqueuedWhileThePassiveScannerIsOff() {
        PassiveScanCheckRig().use { rig ->
            assertTrue(rig.settings.passiveAiEnabled, "the saved settings say on; only the runtime switch is off")
            val rr = rig.csrfPost("gate-off.example")

            val result = rig.check.doCheck(rr)

            assertEquals(emptyList<String>(), result.auditIssues().map { it.name() }, "no issue while the scanner is off")
            assertEquals(emptyList<FiledIssue>(), rig.built, "no AuditIssue is built while the scanner is off")
            assertEquals(0, rig.analyzed(), "no analysis is enqueued while the scanner is off")
            assertEquals(emptyList<Pair<String, Any>>(), rig.auditEvents, "no audit event while the scanner is off")
            assertEquals(emptyList<PassiveAiFinding>(), rig.scanner.getLastFindings(10), "no buffered finding")
            assertEquals(
                emptyList<ScanKnowledgeBase.VulnSignal>(),
                ScanKnowledgeBase.getVulnSignals(rr.request().url()),
                "no knowledge-base signal",
            )
            assertEquals(emptyList<Any>(), rig.extensionAdds, "nothing added to the site map by the extension")
        }
    }

    @Test
    fun turningTheSwitchOffStopsTheNextCheck() {
        PassiveScanCheckRig().use { rig ->
            rig.scanner.setEnabled(true)
            val first = rig.check.doCheck(rig.csrfPost("gate-on.example"))
            assertEquals(1, first.auditIssues().size, "the check files its local finding while the scanner is on")
            assertEquals(1, rig.analyzed(), "the request was enqueued while the scanner is on")

            rig.scanner.setEnabled(false)
            val second = rig.check.doCheck(rig.csrfPost("gate-later.example"))

            assertEquals(
                emptyList<String>(),
                second.auditIssues().map { it.name() },
                "the switch is read on every check: nothing is filed once it is off",
            )
            assertEquals(1, rig.analyzed(), "nothing more is enqueued once the switch is off")
        }
    }

    @Test
    fun aPausedBudgetStillFilesTheIssueButRecordsAndEnqueuesNothing() {
        PassiveScanCheckRig().use { rig ->
            rig.scanner.setEnabled(true)
            rig.scanner.setBudgetPaused(true)

            val result = rig.check.doCheck(rig.csrfPost("gate-paused.example"))

            assertEquals(1, result.auditIssues().size, "the budget pause does not gate the local filing")
            assertEquals(0, rig.analyzed(), "the budget pause still gates the AI analysis")
            assertEquals(emptyList<Map<*, *>>(), rig.passiveIssueEvents(), "no passive_ai_issue event while paused")
            assertEquals(0, rig.scanner.getStatus().issuesFound, "no issue counted while paused")
            assertEquals(emptyList<PassiveAiFinding>(), rig.scanner.getLastFindings(10), "no buffered finding while paused")
        }
    }
}
