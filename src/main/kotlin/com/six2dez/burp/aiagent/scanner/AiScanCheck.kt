package com.six2dez.burp.aiagent.scanner

import burp.api.montoya.MontoyaApi
import burp.api.montoya.http.message.HttpRequestResponse
import burp.api.montoya.scanner.AuditResult
import burp.api.montoya.scanner.ConsolidationAction
import burp.api.montoya.scanner.ScanCheck
import burp.api.montoya.scanner.audit.insertionpoint.AuditInsertionPoint
import burp.api.montoya.scanner.audit.issues.AuditIssue
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity
import com.six2dez.burp.aiagent.config.AgentSettings
import com.six2dez.burp.aiagent.util.IssueUtils

/**
 * Burp Scanner API integration (Option A - Burp Pro only)
 * 
 * This integrates with Burp's native scanner to perform AI-powered active testing
 * at each insertion point discovered by Burp's crawler.
 */
class AiScanCheck(
    private val api: MontoyaApi,
    private val getSettings: () -> AgentSettings
) : ScanCheck {

    private val payloadGenerator = PayloadGenerator()
    private val responseAnalyzer = ResponseAnalyzer()

    /**
     * Called by Burp Scanner for each insertion point.
     * We test relevant payloads based on the insertion point context.
     */
    override fun activeAudit(baseRequestResponse: HttpRequestResponse, insertionPoint: AuditInsertionPoint): AuditResult {
        val settings = getSettings()
        
        // Check if active scanning is enabled
        if (!settings.activeAiEnabled) {
            return AuditResult.auditResult(emptyList())
        }
        
        // Check scope
        if (settings.activeAiScopeOnly && !api.scope().isInScope(baseRequestResponse.request().url())) {
            return AuditResult.auditResult(emptyList())
        }
        
        val maxRisk = settings.activeAiMaxRiskLevel
        val issues = mutableListOf<AuditIssue>()
        
        // Determine which vulnerability classes to test based on insertion point
        val vulnClasses = determineVulnClasses(insertionPoint)
        
        for (vulnClass in vulnClasses) {
            val payloads = payloadGenerator.getQuickPayloads(vulnClass, maxRisk)
                .take(settings.activeAiMaxPayloadsPerPoint)
            
            for (payload in payloads) {
                try {
                    val issue = testPayload(baseRequestResponse, insertionPoint, payload, vulnClass)
                    if (issue != null) {
                        issues.add(issue)
                        // Found a confirmed vuln for this class, move to next
                        break
                    }
                    
                    // Rate limiting
                    if (settings.activeAiRequestDelayMs > 0) {
                        Thread.sleep(settings.activeAiRequestDelayMs.toLong())
                    }
                } catch (e: Exception) {
                    api.logging().logToError("[AiScanCheck] Error testing payload: ${e.message}")
                }
            }
        }
        
        return AuditResult.auditResult(issues)
    }

    /**
     * Passive audit - analyze response without sending requests
     */
    override fun passiveAudit(baseRequestResponse: HttpRequestResponse): AuditResult {
        // Passive scanning is handled by PassiveAiScanner
        // Return empty here to avoid duplication
        return AuditResult.auditResult(emptyList())
    }

    /**
     * Consolidate duplicate issues
     */
    override fun consolidateIssues(newIssue: AuditIssue, existingIssue: AuditIssue): ConsolidationAction {
        // Use canonical name (strips AI prefixes) + normalized URL for cross-scanner dedup
        val sameName = IssueUtils.canonicalIssueName(newIssue.name()) == IssueUtils.canonicalIssueName(existingIssue.name())
        val sameUrl = IssueUtils.normalizeUrl(newIssue.baseUrl()) == IssueUtils.normalizeUrl(existingIssue.baseUrl())
        if (sameName && sameUrl) {
            return ConsolidationAction.KEEP_EXISTING
        }
        return ConsolidationAction.KEEP_BOTH
    }

    private fun determineVulnClasses(insertionPoint: AuditInsertionPoint): List<VulnClass> {
        val name = insertionPoint.name().lowercase()
        val baseValue = insertionPoint.baseValue()
        
        // Always test these
        val classes = mutableListOf(
            VulnClass.XSS_REFLECTED,
            VulnClass.SQLI
        )
        
        // Context-specific additions
        when {
            // URL/file parameters
            name.contains("file") || name.contains("path") || name.contains("page") || 
            name.contains("url") || name.contains("src") || name.contains("dest") ||
            name.contains("redirect") || name.contains("return") || name.contains("next") -> {
                classes.addAll(listOf(VulnClass.LFI, VulnClass.PATH_TRAVERSAL, VulnClass.SSRF, VulnClass.OPEN_REDIRECT))
            }
            
            // ID parameters (IDOR)
            name.contains("id") || name.contains("uid") || name.contains("user") ||
            name.endsWith("_id") || baseValue.matches(Regex("^\\d+$")) ||
            baseValue.matches(Regex("^[a-f0-9-]{36}$", RegexOption.IGNORE_CASE)) -> {
                classes.add(VulnClass.IDOR)
            }
            
            // Command execution contexts
            name.contains("cmd") || name.contains("exec") || name.contains("command") ||
            name.contains("ping") || name.contains("host") || name.contains("ip") -> {
                classes.add(VulnClass.CMDI)
            }
            
            // Template contexts
            name.contains("template") || name.contains("view") || name.contains("render") ||
            name.contains("email") || name.contains("message") -> {
                classes.add(VulnClass.SSTI)
            }
        }
        
        val filtered = classes.distinct().filterNot { it in ScanPolicy.PASSIVE_ONLY_VULN_CLASSES }
        val mode = getSettings().activeAiScanMode
        return filtered.filter { ScanPolicy.isAllowedForMode(mode, it) }
    }

    private fun testPayload(
        baseRequestResponse: HttpRequestResponse,
        insertionPoint: AuditInsertionPoint,
        payload: Payload,
        vulnClass: VulnClass
    ): AuditIssue? {
        val settings = getSettings()
        
        // Build request with payload using Burp's ByteArray
        val payloadBytes = burp.api.montoya.core.ByteArray.byteArray(payload.value)
        val baseService = baseRequestResponse.httpService()
        val attackRequestBase = insertionPoint.buildHttpRequestWithPayload(payloadBytes)
        val attackRequest = if (attackRequestBase.httpService() == null) {
            attackRequestBase.withService(baseService)
        } else {
            attackRequestBase
        }
        if (attackRequest.httpService() == null) {
            api.logging().logToError("[AiScanCheck] Cannot send request: HTTP service is null for insertion point ${insertionPoint.name()}")
            return null
        }
        
        // Measure baseline if needed for time-based
        val baselineTime = if (payload.detectionMethod == DetectionMethod.BLIND_TIME) {
            val start = System.currentTimeMillis()
            api.http().sendRequest(baseRequestResponse.request())
            System.currentTimeMillis() - start
        } else 0L
        
        // Send attack request
        val startTime = System.currentTimeMillis()
        val attackResponse = api.http().sendRequest(attackRequest)
        val responseTime = System.currentTimeMillis() - startTime
        
        val attackRequestResponse = HttpRequestResponse.httpRequestResponse(attackRequest, attackResponse.response())
        
        // Analyze response
        val confirmed = when (payload.detectionMethod) {
            DetectionMethod.BLIND_TIME -> {
                val expectedDelay = payload.timeDelayMs ?: 3000
                responseAnalyzer.analyzeTimeBased(baselineTime, responseTime, expectedDelay)
            }
            else -> {
                val confirmation = responseAnalyzer.analyze(
                    baseRequestResponse,
                    attackRequestResponse,
                    payload,
                    vulnClass
                )
                confirmation?.confirmed == true
            }
        }
        
        if (!confirmed) return null
        
        // Build evidence
        val evidence = buildEvidence(baseRequestResponse, attackRequestResponse, payload, vulnClass, responseTime, baselineTime)
        
        // Create Burp issue
        return AuditIssue.auditIssue(
            "[AI Active] ${vulnClass.name} (Burp Scanner)",
            buildDetail(insertionPoint, payload, evidence, vulnClass),
            ScannerIssueSupport.remediation(vulnClass),
            baseRequestResponse.request().url(),
            ScannerIssueSupport.mapSeverity(vulnClass),
            mapConfidence(payload),
            null,  // background
            null,  // remediationBackground  
            ScannerIssueSupport.mapSeverity(vulnClass),
            listOf(baseRequestResponse, attackRequestResponse)
        )
    }

    private fun buildEvidence(
        original: HttpRequestResponse,
        attack: HttpRequestResponse,
        payload: Payload,
        vulnClass: VulnClass,
        responseTime: Long,
        baselineTime: Long
    ): String {
        return when (payload.detectionMethod) {
            DetectionMethod.BLIND_TIME -> 
                "Time-based detection: baseline=${baselineTime}ms, attack=${responseTime}ms (expected delay: ${payload.timeDelayMs ?: 3000}ms)"
            DetectionMethod.ERROR_BASED -> {
                val body = attack.response()?.bodyToString() ?: ""
                val errorMatch = findErrorPattern(body, vulnClass)
                "Error pattern detected: $errorMatch"
            }
            DetectionMethod.REFLECTION ->
                "Payload reflected unencoded in response"
            DetectionMethod.CONTENT_BASED ->
                "Expected content found in response: ${payload.expectedEvidence}"
            DetectionMethod.BLIND_BOOLEAN -> {
                val diff = responseAnalyzer.calculateDifference(
                    original.response()?.bodyToString() ?: "",
                    attack.response()?.bodyToString() ?: ""
                )
                "Boolean-based: response similarity ${(diff.similarity * 100).toInt()}%"
            }
            DetectionMethod.OUT_OF_BAND ->
                "Out-of-band interaction detected"
        }
    }

    private fun findErrorPattern(body: String, vulnClass: VulnClass): String {
        val patterns = when (vulnClass) {
            VulnClass.SQLI -> listOf(
                Regex("SQL syntax.*MySQL", RegexOption.IGNORE_CASE),
                Regex("ORA-[0-9]+", RegexOption.IGNORE_CASE),
                Regex("PostgreSQL.*ERROR", RegexOption.IGNORE_CASE),
                Regex("SQLServer", RegexOption.IGNORE_CASE)
            )
            VulnClass.LFI -> listOf(
                Regex("root:.*:0:0:"),
                Regex("\\[fonts\\]", RegexOption.IGNORE_CASE)
            )
            else -> emptyList()
        }
        
        for (pattern in patterns) {
            val match = pattern.find(body)
            if (match != null) return match.value.take(100)
        }
        return "Pattern matched"
    }

    private fun buildDetail(insertionPoint: AuditInsertionPoint, payload: Payload, evidence: String, vulnClass: VulnClass): String {
        val settings = getSettings()
        val backendId = settings.preferredBackendId
        val metadataSection = buildString {
            appendLine("---")
            appendLine()
            appendLine("### AI Analysis Metadata")
            appendLine()
            appendLine("**Backend:** $backendId (via Burp Scanner)")
            appendLine("**Scan Type:** Active (Burp Scanner Integration)")
            appendLine("**Detection:** ${payload.detectionMethod}")
            val timestamp = java.time.Instant.now().toString().replace('T', ' ').substringBefore('.')
            appendLine("**Scan Date:** $timestamp UTC")
            appendLine()
            appendLine("---")
        }
        
        return """
**AI-Confirmed Vulnerability via Burp Scanner**

**Insertion Point:** ${insertionPoint.name()} (${insertionPoint.type()})
**Original Value:** ${insertionPoint.baseValue().take(100)}

**Payload Used:**
```
${payload.value.take(500)}
```

**Detection Method:** ${payload.detectionMethod}
**Evidence:** $evidence

**Risk Level:** ${payload.risk}

$metadataSection

_(Confirmed via active exploitation testing integrated with Burp Scanner)_
        """.trim()
    }

    private fun mapConfidence(payload: Payload): AuditIssueConfidence {
        return when (payload.detectionMethod) {
            DetectionMethod.ERROR_BASED -> AuditIssueConfidence.CERTAIN
            DetectionMethod.REFLECTION -> AuditIssueConfidence.FIRM
            DetectionMethod.CONTENT_BASED -> AuditIssueConfidence.FIRM
            DetectionMethod.BLIND_TIME -> AuditIssueConfidence.TENTATIVE
            DetectionMethod.BLIND_BOOLEAN -> AuditIssueConfidence.TENTATIVE
            DetectionMethod.OUT_OF_BAND -> AuditIssueConfidence.FIRM
        }
    }

}
