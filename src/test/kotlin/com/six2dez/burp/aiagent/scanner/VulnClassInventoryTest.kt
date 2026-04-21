package com.six2dez.burp.aiagent.scanner

import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Test

/**
 * Locks the shape of the public vulnerability catalogue. A failure here means someone added
 * or removed a VulnClass without updating README, remediation text, or severity mapping.
 * Update all three together, then bump EXPECTED_COUNT.
 */
class VulnClassInventoryTest {
    companion object {
        private const val EXPECTED_COUNT = 62
    }

    @Test
    fun enumCountMatchesPublicClaim() {
        assertEquals(
            EXPECTED_COUNT,
            VulnClass.entries.size,
            "VulnClass count must match the number advertised in README.md (\"$EXPECTED_COUNT Vulnerability Classes\"). " +
                "Adjust EXPECTED_COUNT and README together when classes change.",
        )
    }

    @Test
    fun everyVulnClassHasSeverityMapping() {
        VulnClass.entries.forEach { vc ->
            val severity = ScannerIssueSupport.mapSeverity(vc)
            assertNotNull(severity, "Missing severity mapping for $vc")
            // Kotlin enum switch is exhaustive; this also ensures the when branch covers it.
            assertEquals(true, severity in AuditIssueSeverity.entries)
        }
    }

    @Test
    fun everyVulnClassHasRemediationText() {
        VulnClass.entries.forEach { vc ->
            val text = ScannerIssueSupport.remediation(vc)
            assertNotNull(text, "Missing remediation text for $vc")
            assertEquals(true, text.isNotBlank(), "Empty remediation text for $vc")
        }
    }
}
