package com.six2dez.burp.aiagent.scanner

import burp.api.montoya.http.message.HttpRequestResponse
import burp.api.montoya.scanner.audit.issues.AuditIssue
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity
import com.six2dez.burp.aiagent.config.AgentSettings
import com.six2dez.burp.aiagent.config.Defaults
import com.six2dez.burp.aiagent.supervisor.AgentSupervisor
import com.six2dez.burp.aiagent.util.IssueText
import com.six2dez.burp.aiagent.util.IssueUtils

// AWT-free contract: MUST NOT import java.awt.* or javax.swing.*

private val headerInjectionAllowlist = ScannerUtils.HEADER_INJECTION_ALLOWLIST

// ---- finding handlers ----

internal fun PassiveAiScanner.handleAiResponse(
    aiText: String,
    requestResponse: HttpRequestResponse,
    minSeverity: String,
) {
    val issues = parseIssuesFromAiResponse(aiText, api)
    handleParsedAiIssues(issues, requestResponse, minSeverity)
}

internal fun PassiveAiScanner.handleParsedAiIssues(
    issues: List<AiIssueItem>,
    requestResponse: HttpRequestResponse,
    minSeverity: String,
) {
    if (issues.isEmpty()) return
    val settings = getSettings()

    for (item in issues) {
        val confidence = item.confidence ?: 0
        val title = (item.title ?: "AI Potential Issue").take(120)
        val rawSeverity = item.severity ?: "Information"
        val reasoning = item.reasoning ?: ""
        val detail =
            buildString {
                if (reasoning.isNotBlank()) {
                    appendLine("Analysis Reasoning")
                    reasoning.trim().lines().forEach { line ->
                        if (line.isNotBlank()) {
                            appendLine("  $line")
                        } else {
                            appendLine()
                        }
                    }
                    appendLine()
                }
                appendLine((item.detail ?: "No detail from AI").trim())
            }.trim()

        handleFinding(requestResponse, title, rawSeverity, detail, confidence, minSeverity, settings, "ai")
    }
}

internal fun PassiveAiScanner.handleFinding(
    requestResponse: HttpRequestResponse,
    title: String,
    rawSeverity: String,
    detail: String,
    confidence: Int,
    minSeverity: String,
    settings: AgentSettings,
    source: String,
) {
    val minSeverityLevel = severityLevel(minSeverity)
    val severityLevel = severityLevel(rawSeverity)
    val shouldCreate = confidence >= 85 && severityLevel >= minSeverityLevel

    if (source == "ai" && confidence < 85) {
        return
    }

    val issueCreated =
        if (shouldCreate) {
            try {
                val severity = mapSeverity(rawSeverity)
                val burpConfidence =
                    when {
                        confidence >= 95 -> AuditIssueConfidence.CERTAIN
                        confidence >= 85 -> AuditIssueConfidence.FIRM
                        else -> AuditIssueConfidence.TENTATIVE
                    }
                val issueName = issueNameForPassive(title)
                if (hasExistingIssue(issueName, requestResponse.request().url())) {
                    api.logging().logToOutput("[PassiveAiScanner] Consolidated duplicate issue: $issueName")
                    true
                } else {
                    val sanitizedDetail = IssueText.sanitize(detail)

                    // Get backend info for metadata
                    val backendInfo = supervisor.getCurrentBackendInfo()
                    val metadataSection =
                        buildMetadataSectionPlain(
                            backendInfo,
                            "Passive",
                            confidence,
                            "AI passive analysis - may need active confirmation for verification.",
                        )

                    // Build well-formatted detail
                    val fullDetailLines = mutableListOf<String>()
                    fullDetailLines.addAll(sanitizedDetail.split("\n"))
                    fullDetailLines.add("")
                    fullDetailLines.addAll(metadataSection.split("\r\n"))
                    val fullDetail = IssueUtils.formatIssueDetailHtml(fullDetailLines)

                    // Add markers to highlight evidence in response
                    val markedReqResp = IssueMarkerSupport.markResponseFromDetail(requestResponse, sanitizedDetail)

                    val issue =
                        AuditIssue.auditIssue(
                            issueName,
                            fullDetail,
                            "Verify the finding manually or use AI Active Scanner for confirmation.",
                            requestResponse.request().url(),
                            severity,
                            burpConfidence,
                            null,
                            null,
                            severity,
                            listOf(markedReqResp),
                        )
                    api.siteMap().add(issue)
                    issuesFound.incrementAndGet()
                    api.logging().logToOutput("[PassiveAiScanner] Issue: $title | $rawSeverity | $confidence%")

                    // Record finding in knowledge base
                    ScanKnowledgeBase.recordVulnSignal(
                        ScanKnowledgeBase.VulnSignal(
                            endpoint = requestResponse.request().url(),
                            vulnClass = title,
                            severity = rawSeverity,
                            confidence = confidence,
                            source = source,
                            evidence = detail.take(200),
                        ),
                    )

                    // Auto-queue to active scanner if enabled
                    queueToActiveScanner(requestResponse, title, rawSeverity, detail, confidence, settings)

                    audit.logEvent(
                        "passive_ai_issue",
                        mapOf(
                            "title" to title,
                            "severity" to rawSeverity,
                            "confidence" to confidence.toString(),
                            "url" to requestResponse.request().url(),
                            "source" to source,
                        ),
                    )
                    true
                }
            } catch (e: Exception) {
                api.logging().logToError("[PassiveAiScanner] Failed to create issue: ${e.message}")
                false
            }
        } else {
            false
        }

    recordFinding(requestResponse, title, rawSeverity, detail, confidence, source, issueCreated)
}

internal fun PassiveAiScanner.recordFinding(
    requestResponse: HttpRequestResponse,
    title: String,
    rawSeverity: String,
    detail: String,
    confidence: Int,
    source: String,
    issueCreated: Boolean,
) {
    val finding =
        PassiveAiFinding(
            timestamp = System.currentTimeMillis(),
            url = requestResponse.request().url(),
            title = title,
            severity = rawSeverity,
            detail = detail,
            confidence = confidence,
            source = source,
            issueCreated = issueCreated,
        )
    synchronized(findings) {
        if (findings.size >= Defaults.FINDINGS_BUFFER_SIZE) findings.removeFirst()
        findings.addLast(finding)
    }
}

internal fun PassiveAiScanner.issueNameForPassive(title: String): String {
    val vulnClass = mapTitleToVulnClass(title)
    return if (vulnClass != null) {
        "[AI Passive] ${vulnClass.name}"
    } else {
        "[AI Passive] ${IssueText.sanitize(title)}"
    }
}

internal fun PassiveAiScanner.hasExistingIssue(
    name: String,
    baseUrl: String,
): Boolean =
    IssueUtils.hasEquivalentIssue(
        name = name,
        baseUrl = baseUrl,
        issues = api.siteMap().issues().map { issue -> issue.name() to issue.baseUrl() },
    )

internal fun PassiveAiScanner.queueToActiveScanner(
    requestResponse: HttpRequestResponse,
    title: String,
    severity: String,
    detail: String,
    confidence: Int,
    settings: AgentSettings,
) {
    val scanner = activeScanner ?: return
    if (!settings.activeAiEnabled || !settings.activeAiAutoFromPassive) return

    // Map title to VulnClass
    val vulnClass = mapTitleToVulnClass(title) ?: return
    if (vulnClass in ScanPolicy.PASSIVE_ONLY_VULN_CLASSES) return
    if (!ScanPolicy.isAllowedForMode(settings.activeAiScanMode, vulnClass)) return

    // Extract injection points from the request
    val injectionPoints = extractInjectionPoints(requestResponse)
    if (injectionPoints.isEmpty()) return

    // Queue each injection point for active testing
    for (point in injectionPoints) {
        val hint =
            VulnHint(
                vulnClass = vulnClass,
                confidence = confidence,
                evidence = detail.take(200),
            )
        val target =
            ActiveScanTarget(
                originalRequest = requestResponse,
                injectionPoint = point,
                vulnHint = hint,
                priority =
                    when (severity.uppercase()) {
                        "CRITICAL" -> 100
                        "HIGH" -> 80
                        "MEDIUM" -> 60
                        else -> 40
                    },
            )
        scanner.queueTarget(target)
    }

    api.logging().logToOutput("[PassiveAiScanner] Queued to Active Scanner: $title")
}

internal fun PassiveAiScanner.mapTitleToVulnClass(title: String): VulnClass? {
    val lowerTitle = title.lowercase()
    return when {
        // Injection vulnerabilities
        lowerTitle.contains("sql") || lowerTitle.contains("injection") && lowerTitle.contains("database") -> VulnClass.SQLI
        lowerTitle.contains(
            "xss",
        ) ||
            lowerTitle.contains("cross-site scripting") ||
            lowerTitle.contains("script injection") -> VulnClass.XSS_REFLECTED
        lowerTitle.contains("lfi") || lowerTitle.contains("local file") || lowerTitle.contains("file inclusion") -> VulnClass.LFI
        lowerTitle.contains("path traversal") || lowerTitle.contains("directory traversal") -> VulnClass.PATH_TRAVERSAL
        lowerTitle.contains("command") || lowerTitle.contains("rce") || lowerTitle.contains("os injection") -> VulnClass.CMDI
        lowerTitle.contains("ssti") || lowerTitle.contains("template injection") -> VulnClass.SSTI
        lowerTitle.contains("ssrf") || lowerTitle.contains("server-side request") -> VulnClass.SSRF
        lowerTitle.contains("xxe") || lowerTitle.contains("xml external") -> VulnClass.XXE
        lowerTitle.contains("nosql") -> VulnClass.NOSQL_INJECTION
        lowerTitle.contains("ldap") -> VulnClass.LDAP_INJECTION

        // Access control
        lowerTitle.contains("bola") || lowerTitle.contains("object level authorization") -> VulnClass.BOLA
        lowerTitle.contains("idor") || lowerTitle.contains("insecure direct") -> VulnClass.IDOR
        lowerTitle.contains("bfla") || lowerTitle.contains("function level") -> VulnClass.BFLA
        lowerTitle.contains("horizontal") && lowerTitle.contains("privilege") -> VulnClass.BAC_HORIZONTAL
        lowerTitle.contains("vertical") && lowerTitle.contains("privilege") -> VulnClass.BAC_VERTICAL
        lowerTitle.contains("privilege escalation") -> VulnClass.BAC_VERTICAL
        lowerTitle.contains("authorization bypass") ||
            (lowerTitle.contains("access control") && lowerTitle.contains("bypass")) ||
            lowerTitle.contains("broken access control") -> VulnClass.AUTH_BYPASS
        lowerTitle.contains("mass assignment") -> VulnClass.MASS_ASSIGNMENT

        // Authentication/Authorization (NEW)
        lowerTitle.contains(
            "account takeover",
        ) ||
            lowerTitle.contains("ato") ||
            lowerTitle.contains("password reset") -> VulnClass.ACCOUNT_TAKEOVER
        lowerTitle.contains("oauth") || lowerTitle.contains("sso") && lowerTitle.contains("bypass") -> VulnClass.OAUTH_MISCONFIGURATION
        lowerTitle.contains("2fa") || lowerTitle.contains("mfa") || lowerTitle.contains("two-factor") -> VulnClass.MFA_BYPASS
        lowerTitle.contains("jwt") || lowerTitle.contains("json web token") -> VulnClass.JWT_WEAKNESS
        lowerTitle.contains("csrf") || lowerTitle.contains("cross-site request forgery") -> VulnClass.CSRF
        lowerTitle.contains("deserialization") || lowerTitle.contains("serialized object") -> VulnClass.DESERIALIZATION

        // Host/Header injection (NEW)
        lowerTitle.contains("host header") -> VulnClass.HOST_HEADER_INJECTION
        lowerTitle.contains("email header") || lowerTitle.contains("mail injection") -> VulnClass.EMAIL_HEADER_INJECTION
        lowerTitle.contains("crlf") || lowerTitle.contains("header injection") -> VulnClass.HEADER_INJECTION

        // Cache attacks (NEW)
        lowerTitle.contains("cache poison") -> VulnClass.CACHE_POISONING
        lowerTitle.contains("cache deception") -> VulnClass.CACHE_DECEPTION
        lowerTitle.contains("request smuggling") ||
            lowerTitle.contains("cl.te") ||
            lowerTitle.contains("transfer-encoding") &&
            lowerTitle.contains("content-length") -> VulnClass.REQUEST_SMUGGLING
        lowerTitle.contains("file upload") ||
            lowerTitle.contains("unrestricted upload") ||
            lowerTitle.contains("upload") &&
            lowerTitle.contains("executable") -> VulnClass.UNRESTRICTED_FILE_UPLOAD

        // Information disclosure (NEW)
        lowerTitle.contains("source map") || lowerTitle.contains("sourcemap") -> VulnClass.SOURCEMAP_DISCLOSURE
        lowerTitle.contains(
            ".git",
        ) ||
            lowerTitle.contains("git exposure") ||
            lowerTitle.contains("git repository") -> VulnClass.GIT_EXPOSURE
        lowerTitle.contains("backup") || lowerTitle.contains(".bak") || lowerTitle.contains(".old file") -> VulnClass.BACKUP_DISCLOSURE
        lowerTitle.contains("debug") || lowerTitle.contains("actuator") || lowerTitle.contains("profiler") -> VulnClass.DEBUG_EXPOSURE
        lowerTitle.contains("stack trace") || lowerTitle.contains("error leak") -> VulnClass.STACK_TRACE_EXPOSURE

        // Cloud/Infrastructure (NEW)
        lowerTitle.contains("s3") || lowerTitle.contains("bucket") && lowerTitle.contains("public") -> VulnClass.S3_MISCONFIGURATION
        lowerTitle.contains("subdomain takeover") || lowerTitle.contains("dangling") -> VulnClass.SUBDOMAIN_TAKEOVER

        // Business logic (NEW)
        lowerTitle.contains(
            "price",
        ) ||
            lowerTitle.contains("quantity") &&
            lowerTitle.contains("manipulation") -> VulnClass.PRICE_MANIPULATION
        lowerTitle.contains("race condition") || lowerTitle.contains("toctou") -> VulnClass.RACE_CONDITION_TOCTOU

        // API security (NEW)
        lowerTitle.contains("api version") || lowerTitle.contains("deprecated api") -> VulnClass.API_VERSION_BYPASS
        lowerTitle.contains("graphql") -> VulnClass.GRAPHQL_INJECTION

        // Other
        lowerTitle.contains("redirect") || lowerTitle.contains("open redirect") -> VulnClass.OPEN_REDIRECT
        lowerTitle.contains("cors") -> VulnClass.CORS_MISCONFIGURATION
        lowerTitle.contains("directory listing") -> VulnClass.DIRECTORY_LISTING
        lowerTitle.contains(
            "403 bypass",
        ) ||
            lowerTitle.contains("access control bypass") ||
            lowerTitle.contains("forbidden bypass") -> VulnClass.ACCESS_CONTROL_BYPASS

        else -> null
    }
}

internal fun PassiveAiScanner.extractInjectionPoints(requestResponse: HttpRequestResponse): List<InjectionPoint> =
    InjectionPointExtractor.extract(requestResponse.request(), headerInjectionAllowlist)

internal fun PassiveAiScanner.severityLevel(severity: String): Int =
    when (severity.uppercase()) {
        "CRITICAL" -> 4
        "HIGH" -> 3
        "MEDIUM" -> 2
        "LOW" -> 1
        else -> 0
    }

internal fun PassiveAiScanner.mapSeverity(raw: String): AuditIssueSeverity =
    when (raw.lowercase()) {
        "critical", "high" -> AuditIssueSeverity.HIGH
        "medium" -> AuditIssueSeverity.MEDIUM
        "low" -> AuditIssueSeverity.LOW
        else -> AuditIssueSeverity.INFORMATION
    }

internal fun PassiveAiScanner.buildMetadataSection(
    backendInfo: AgentSupervisor.BackendInfo?,
    scanType: String,
    confidence: Int,
): String =
    buildString {
        appendLine("---")
        appendLine()
        appendLine("### AI Analysis Metadata")
        appendLine()
        if (backendInfo != null) {
            appendLine("**Backend:** ${backendInfo.displayName}")
            if (backendInfo.model != null) {
                appendLine("**Model:** ${backendInfo.model}")
            }
        } else {
            appendLine("**Backend:** Unknown")
        }
        appendLine("**Scan Type:** $scanType")
        appendLine("**Confidence:** $confidence%")

        val timestamp =
            java.time.Instant
                .now()
                .toString()
                .replace('T', ' ')
                .substringBefore('.')
        appendLine("**Scan Date:** $timestamp UTC")
        appendLine()
        appendLine("---")
    }
