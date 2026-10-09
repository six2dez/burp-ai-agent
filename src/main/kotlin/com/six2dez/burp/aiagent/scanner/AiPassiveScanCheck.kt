package com.six2dez.burp.aiagent.scanner

import burp.api.montoya.MontoyaApi
import burp.api.montoya.http.message.HttpRequestResponse
import burp.api.montoya.scanner.AuditResult
import burp.api.montoya.scanner.ConsolidationAction
import burp.api.montoya.scanner.audit.issues.AuditIssue
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity
import burp.api.montoya.scanner.scancheck.PassiveScanCheck
import com.six2dez.burp.aiagent.config.AgentSettings
import com.six2dez.burp.aiagent.util.IssueUtils

/**
 * Implements the modern PassiveScanCheck interface (Montoya API 2026.2+).
 *
 * BApp Store requirement: passive scanning must use PassiveScanCheck.doCheck()
 * rather than ProxyResponseHandler. Registration is Pro-only — Community edition
 * registration is silently caught in App.kt.
 *
 * Contract:
 *  - With the AI passive scanner off (PassiveAiScanner.isEnabled() false) doCheck() does nothing:
 *    no local heuristics, no issue, no enqueued analysis. Both halves of the passive scanner share
 *    that one runtime switch, which is read on every check.
 *  - doCheck() returns synchronously after running fast local heuristics
 *  - Async AI deep-analysis is enqueued to PassiveAiScanner.executor
 *  - AI findings surface later via api.siteMap().add() inside PassiveAiScanner
 */
class AiPassiveScanCheck(
    private val api: MontoyaApi,
    private val passiveScanner: PassiveAiScanner,
    private val getSettings: () -> AgentSettings,
) : PassiveScanCheck {
    override fun checkName(): String = "AI Passive Security Analysis"

    /**
     * Synchronous per-request passive check.
     *
     * Steps:
     *  1. Skip when the AI passive scanner is off (checked first, so the off path does no scope
     *     lookup) or when the request is out of scope while scope-only is set.
     *  2. Run fast local heuristics via passiveScanner.localChecks().
     *  3. Convert LocalFinding list to AuditIssue list and return immediately.
     *  4. Enqueue async AI deep-analysis via passiveScanner.enqueueForScanCheck().
     *
     * MUST NOT call supervisor.send() or any blocking AI operation.
     */
    override fun doCheck(httpRequestResponse: HttpRequestResponse): AuditResult {
        val settings = getSettings()

        // Switch first (the same runtime flag the AI half reads), then the scope check — mirror of
        // AiScanCheck.activeAudit lines 44-46.
        if (!passiveScanner.isEnabled() ||
            settings.passiveAiScopeOnly &&
            !api.scope().isInScope(httpRequestResponse.request().url())
        ) {
            return AuditResult.auditResult(emptyList())
        }

        val request = httpRequestResponse.request()
        val response = httpRequestResponse.response()

        // Synchronous local heuristics
        val localFindings = passiveScanner.localChecks(request, response)

        // Convert LocalFinding → AuditIssue
        val localIssues =
            localFindings.map { finding ->
                AuditIssue.auditIssue(
                    "[AI Passive] ${finding.title}",
                    finding.detail,
                    "Verify the finding manually or use AI Active Scanner for confirmation.",
                    request.url(),
                    mapSeverity(finding.severity),
                    AuditIssueConfidence.TENTATIVE,
                    null,
                    null,
                    mapSeverity(finding.severity),
                    listOf(httpRequestResponse),
                )
            }

        // Enqueue async AI deep-analysis (returns immediately; findings surface via siteMap().add())
        passiveScanner.enqueueForScanCheck(httpRequestResponse)

        return AuditResult.auditResult(localIssues)
    }

    /**
     * Deduplication — copy verbatim from AiScanCheck.kt:94-105.
     * Uses canonical issue name + normalized URL to prevent flooding.
     */
    override fun consolidateIssues(
        newIssue: AuditIssue,
        existingIssue: AuditIssue,
    ): ConsolidationAction {
        val sameName =
            IssueUtils.canonicalIssueName(newIssue.name()) == IssueUtils.canonicalIssueName(existingIssue.name())
        val sameUrl = IssueUtils.normalizeUrl(newIssue.baseUrl()) == IssueUtils.normalizeUrl(existingIssue.baseUrl())
        if (sameName && sameUrl) return ConsolidationAction.KEEP_EXISTING
        return ConsolidationAction.KEEP_BOTH
    }

    private fun mapSeverity(rawSeverity: String): AuditIssueSeverity =
        when (rawSeverity.uppercase()) {
            "HIGH", "CRITICAL" -> AuditIssueSeverity.HIGH
            "MEDIUM" -> AuditIssueSeverity.MEDIUM
            "LOW", "INFO", "INFORMATIONAL" -> AuditIssueSeverity.LOW
            else -> AuditIssueSeverity.LOW
        }
}
