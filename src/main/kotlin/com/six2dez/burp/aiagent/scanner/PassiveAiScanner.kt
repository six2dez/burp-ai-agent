package com.six2dez.burp.aiagent.scanner

import burp.api.montoya.MontoyaApi
import burp.api.montoya.http.message.HttpRequestResponse
import burp.api.montoya.proxy.http.InterceptedResponse
import burp.api.montoya.proxy.http.ProxyResponseHandler
import burp.api.montoya.proxy.http.ProxyResponseReceivedAction
import burp.api.montoya.proxy.http.ProxyResponseToBeSentAction
import burp.api.montoya.scanner.audit.issues.AuditIssue
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity
import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.module.kotlin.registerKotlinModule
import com.six2dez.burp.aiagent.audit.AuditLogger
import com.six2dez.burp.aiagent.config.AgentSettings
import com.six2dez.burp.aiagent.config.Defaults
import com.six2dez.burp.aiagent.redact.Redaction
import com.six2dez.burp.aiagent.redact.RedactionPolicy
import com.six2dez.burp.aiagent.supervisor.AgentSupervisor
import com.six2dez.burp.aiagent.util.IssueText
import java.net.URI
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicLong
import java.util.concurrent.atomic.AtomicReference

data class PassiveAiFinding(
    val timestamp: Long,
    val url: String,
    val title: String,
    val severity: String,
    val detail: String,
    val confidence: Int,
    val source: String = "ai",
    val issueCreated: Boolean = true
)

data class PassiveAiScannerStatus(
    val enabled: Boolean,
    val requestsAnalyzed: Int,
    val issuesFound: Int,
    val lastAnalysisTime: Long,
    val queueSize: Int
)

class PassiveAiScanner(
    private val api: MontoyaApi,
    private val supervisor: AgentSupervisor,
    private val audit: AuditLogger,
    private val getSettings: () -> AgentSettings
) {
    private val enabled = AtomicBoolean(false)
    private val requestsAnalyzed = AtomicInteger(0)
    private val issuesFound = AtomicInteger(0)
    private val lastAnalysisTime = AtomicLong(0)
    private val lastRequestTime = AtomicLong(0)
    private val executor = Executors.newSingleThreadExecutor { r ->
        Thread(r, "PassiveAiScanner").apply { isDaemon = true }
    }
    private val findings = ArrayDeque<PassiveAiFinding>(Defaults.FINDINGS_BUFFER_SIZE)
    private val registered = AtomicBoolean(false)
    private val jsonMapper = ObjectMapper().registerKotlinModule()
    
    // Reference to active scanner for auto-queueing
    var activeScanner: ActiveAiScanner? = null

    // Configurable settings with defaults
    var rateLimitSeconds: Int = 5
    var scopeOnly: Boolean = true
    var maxSizeKb: Int = 96

    private val allowedMimeTypes = setOf(
        "html", "json", "javascript", "xml", "text", "unknown", "script"
    )
    private val headerInjectionAllowlist = ScannerUtils.HEADER_INJECTION_ALLOWLIST
    private val csrfTokenRegex = Regex(
        "(csrf|xsrf|anti_csrf|csrfmiddlewaretoken|__requestverificationtoken|token)",
        RegexOption.IGNORE_CASE
    )
    private val dangerousUploadExtensions = setOf(
        "php", "phtml", "php5", "asp", "aspx", "jsp", "jspx",
        "cgi", "pl", "py", "rb", "jar", "war", "ear", "exe", "dll"
    )
    private val authHeaderNames = setOf(
        "authorization",
        "x-api-key",
        "x-auth-token",
        "x-access-token"
    )
    private val authCookieHint = Regex("(session|auth|token|sid|jwt|remember)", RegexOption.IGNORE_CASE)

    private val handler = object : ProxyResponseHandler {
        override fun handleResponseReceived(response: InterceptedResponse): ProxyResponseReceivedAction {
            if (!enabled.get()) {
                return ProxyResponseReceivedAction.continueWith(response)
            }

            // Check scope
            if (scopeOnly && !api.scope().isInScope(response.initiatingRequest().url())) {
                return ProxyResponseReceivedAction.continueWith(response)
            }

            // Check size
            val responseBytes = response.toByteArray().length()
            if (responseBytes > maxSizeKb * 1024) {
                return ProxyResponseReceivedAction.continueWith(response)
            }

            // Check MIME type
            val mime = response.statedMimeType().name.lowercase()
            val inferredMime = response.inferredMimeType().name.lowercase()
            if (mime !in allowedMimeTypes && inferredMime !in allowedMimeTypes) {
                return ProxyResponseReceivedAction.continueWith(response)
            }

            // Rate limiting - skip if too recent
            val now = System.currentTimeMillis()
            if (now - lastRequestTime.get() < rateLimitSeconds * 1000) {
                return ProxyResponseReceivedAction.continueWith(response)
            }

            lastRequestTime.set(now)

            // Queue for analysis
            val requestResponse = HttpRequestResponse.httpRequestResponse(
                response.initiatingRequest(),
                response
            )
            
            executor.submit {
                analyzeInBackground(requestResponse)
            }

            return ProxyResponseReceivedAction.continueWith(response)
        }

        override fun handleResponseToBeSent(response: InterceptedResponse): ProxyResponseToBeSentAction {
            return ProxyResponseToBeSentAction.continueWith(response)
        }
    }

    fun setEnabled(on: Boolean) {
        enabled.set(on)
        if (on && registered.compareAndSet(false, true)) {
            api.proxy().registerResponseHandler(handler)
            api.logging().logToOutput("[PassiveAiScanner] Enabled - analyzing proxy traffic")
        } else if (!on) {
            api.logging().logToOutput("[PassiveAiScanner] Disabled")
        }
    }

    fun isEnabled(): Boolean = enabled.get()
    
    private val backendStartAttempted = AtomicBoolean(false)
    
    private fun ensureBackendRunning(settings: AgentSettings): Boolean {
        // Check if supervisor has an active session
        if (supervisor.currentSessionId() != null) {
            return true
        }
        
        // Try to start the preferred backend (only once per scan batch)
        if (backendStartAttempted.compareAndSet(false, true)) {
            api.logging().logToOutput("[PassiveAiScanner] Starting backend: ${settings.preferredBackendId}")
            val started = supervisor.startOrAttach(settings.preferredBackendId)
            if (started) {
                val ready = waitForBackendSession(maxWaitMs = 10_000L, pollMs = 200L)
                if (ready) {
                    api.logging().logToOutput("[PassiveAiScanner] Backend started successfully")
                    return true
                }
                api.logging().logToError("[PassiveAiScanner] Backend started but session did not become ready in time")
            } else {
                val error = supervisor.lastStartError()
                api.logging().logToError("[PassiveAiScanner] Failed to start backend: $error")
            }
        }
        
        return supervisor.currentSessionId() != null
    }

    private fun waitForBackendSession(maxWaitMs: Long, pollMs: Long): Boolean {
        val deadline = System.currentTimeMillis() + maxWaitMs.coerceAtLeast(0L)
        while (System.currentTimeMillis() < deadline) {
            if (supervisor.currentSessionId() != null) {
                return true
            }
            try {
                Thread.sleep(pollMs.coerceAtLeast(1L))
            } catch (_: InterruptedException) {
                Thread.currentThread().interrupt()
                return false
            }
        }
        return supervisor.currentSessionId() != null
    }

    fun getStatus(): PassiveAiScannerStatus {
        return PassiveAiScannerStatus(
            enabled = enabled.get(),
            requestsAnalyzed = requestsAnalyzed.get(),
            issuesFound = issuesFound.get(),
            lastAnalysisTime = lastAnalysisTime.get(),
            queueSize = 0 // Single-threaded executor
        )
    }

    fun getLastFindings(n: Int): List<PassiveAiFinding> {
        if (n <= 0) return emptyList()
        synchronized(findings) {
            return if (findings.size <= n) findings.toList() else findings.takeLast(n)
        }
    }

    fun shutdown() {
        enabled.set(false)
        executor.shutdown()
        try {
            if (!executor.awaitTermination(3, java.util.concurrent.TimeUnit.SECONDS)) {
                executor.shutdownNow()
            }
        } catch (_: InterruptedException) {
            executor.shutdownNow()
        }
    }

    fun resetStats() {
        requestsAnalyzed.set(0)
        issuesFound.set(0)
        synchronized(findings) { findings.clear() }
    }

    // Manual scan tracking
    private val manualScanTotal = AtomicInteger(0)
    private val manualScanCompleted = AtomicInteger(0)
    private val manualScanInProgress = AtomicBoolean(false)

    fun getManualScanProgress(): Triple<Boolean, Int, Int> {
        return Triple(manualScanInProgress.get(), manualScanCompleted.get(), manualScanTotal.get())
    }

    /**
     * Manually scan a list of requests (from context menu).
     * Does not require the passive scanner to be enabled.
     * Returns the number of requests queued for analysis.
     */
    fun manualScan(requests: List<HttpRequestResponse>, onProgress: (Int, Int) -> Unit = { _, _ -> }): Int {
        if (requests.isEmpty()) return 0
        
        val total = requests.size
        manualScanTotal.set(total)
        manualScanCompleted.set(0)
        manualScanInProgress.set(true)
        backendStartAttempted.set(false)  // Reset so we try to start backend for this scan
        
        api.logging().logToOutput("[PassiveAiScanner] Manual scan started: $total requests queued")
        
        requests.forEachIndexed { index, reqRes ->
            executor.submit {
                val url = try { reqRes.request().url() } catch (_: Exception) { "unknown" }
                val shortUrl = if (url.length > 80) url.take(80) + "..." else url
                
                api.logging().logToOutput("[PassiveAiScanner] Analyzing [${index + 1}/$total]: $shortUrl")
                
                try {
                    analyzeManually(reqRes)
                } finally {
                    val completed = manualScanCompleted.incrementAndGet()
                    onProgress(completed, total)
                    
                    if (completed >= total) {
                        manualScanInProgress.set(false)
                        val issuesCreated = issuesFound.get()
                        api.logging().logToOutput("[PassiveAiScanner] Manual scan complete: $total requests analyzed, $issuesCreated issues found")
                    }
                }
            }
        }
        
        return total
    }

    private fun analyzeManually(requestResponse: HttpRequestResponse) {
        try {
            doAnalysis(requestResponse)
        } catch (e: Exception) {
            api.logging().logToError("[PassiveAiScanner] Manual scan error: ${e.message}")
        }
    }

    private fun analyzeInBackground(requestResponse: HttpRequestResponse) {
        try {
            doAnalysis(requestResponse)
        } catch (e: Exception) {
            api.logging().logToError("[PassiveAiScanner] Error: ${e.message}")
        }
    }

    private fun doAnalysis(requestResponse: HttpRequestResponse) {
        try {
            val settings = getSettings()
            val request = requestResponse.request()
            val response = requestResponse.response()

            // Extract request body (truncated)
            val requestBody = try {
                val bodyStr = request.bodyToString()
                if (bodyStr.length > 3000) bodyStr.take(3000) + "..." else bodyStr
            } catch (_: Exception) { "" }

            // Extract response body (truncated for AI analysis)
            val responseBody = try {
                val bodyStr = response?.bodyToString() ?: ""
                if (bodyStr.length > 6000) bodyStr.take(6000) + "..." else bodyStr
            } catch (_: Exception) { "" }

            // Local passive checks (independent of AI backend availability)
            val localFindings = runLocalChecks(request, response, requestBody, responseBody)
            for (finding in localFindings) {
                handleFinding(
                    requestResponse,
                    finding.title,
                    finding.severity,
                    finding.detail,
                    finding.confidence,
                    settings.passiveAiMinSeverity.name,
                    settings,
                    "local"
                )
            }

            // Ensure backend is running for AI analysis
            if (!ensureBackendRunning(settings)) {
                api.logging().logToError("[PassiveAiScanner] No AI backend available - skipping analysis")
                return
            }

            // Build params sample with more detail
            val params = request.parameters().take(20).map { p ->
                val value = if (p.value().length > 300) p.value().take(300) + "..." else p.value()
                mapOf(
                    "name" to p.name(),
                    "value" to value,
                    "type" to p.type().name
                )
            }

            // Extract ALL headers for security analysis
            val requestHeaders = request.headers().map { h ->
                "${h.name()}: ${if (h.value().length > 150) h.value().take(150) + "..." else h.value()}"
            }
            val responseHeaders = response?.headers()?.map { h ->
                "${h.name()}: ${if (h.value().length > 150) h.value().take(150) + "..." else h.value()}"
            } ?: emptyList()

            // Extract cookies separately for auth analysis
            val cookies = request.headers()
                .filter { it.name().equals("Cookie", ignoreCase = true) }
                .flatMap { it.value().split(";").map { c -> c.trim() } }
                .take(10)

            // Check for auth headers
            val authHeaders = request.headers()
                .filter { h ->
                    h.name().equals("Authorization", ignoreCase = true) ||
                        h.name().equals("X-API-Key", ignoreCase = true) ||
                        h.name().equals("X-Auth-Token", ignoreCase = true)
                }
                .map { "${it.name()}: ${it.value().take(50)}..." }

            // Extract path segments for IDOR/BOLA analysis
            val urlPath = try {
                java.net.URI(request.url()).path ?: ""
            } catch (_: Exception) { "" }

            // Look for potential object IDs in URL
            val potentialIds = Regex("\\b([0-9]+|[a-f0-9-]{36}|[a-f0-9]{24})\\b", RegexOption.IGNORE_CASE)
                .findAll(urlPath + "?" + params.joinToString("&") { "${it["name"]}=${it["value"]}" })
                .map { it.value }
                .distinct()
                .take(10)
                .toList()

            val redactionPolicy = RedactionPolicy.fromMode(settings.privacyMode)
            val displayUrl = redactUrlForPrompt(request.url(), redactionPolicy, settings.hostAnonymizationSalt)

            // Build simple text-based metadata
            val metadataText = buildString {
                appendLine("URL: $displayUrl")
                appendLine("Path: $urlPath")
                appendLine("Method: ${request.method()}")
                appendLine("Status: ${response?.statusCode() ?: 0}")
                appendLine("MIME Type: ${response?.statedMimeType()?.name ?: "unknown"}")
                appendLine()
                if (potentialIds.isNotEmpty()) {
                    appendLine("Potential Object IDs: ${potentialIds.joinToString(", ")}")
                }
                appendLine()
                appendLine("=== REQUEST HEADERS ===")
                requestHeaders.forEach { appendLine(it) }
                appendLine()
                appendLine("=== RESPONSE HEADERS ===")
                responseHeaders.forEach { appendLine(it) }
                appendLine()
                if (authHeaders.isNotEmpty()) {
                    appendLine("=== AUTH HEADERS ===")
                    authHeaders.forEach { appendLine(it) }
                    appendLine()
                }
                if (cookies.isNotEmpty()) {
                    appendLine("=== COOKIES ===")
                    cookies.forEach { appendLine(it) }
                    appendLine()
                }
                if (params.isNotEmpty()) {
                    appendLine("=== PARAMETERS ===")
                    params.forEach { p ->
                        appendLine("${p["name"]} (${p["type"]}): ${p["value"]}")
                    }
                    appendLine()
                }
                if (requestBody.isNotEmpty()) {
                    appendLine("=== REQUEST BODY ===")
                    appendLine(requestBody)
                    appendLine()
                }
                if (responseBody.isNotEmpty()) {
                    appendLine("=== RESPONSE BODY ===")
                    appendLine(responseBody)
                }
            }

            val safeMetadataText = if (settings.privacyMode == com.six2dez.burp.aiagent.redact.PrivacyMode.OFF) {
                metadataText
            } else {
                Redaction.apply(
                    metadataText,
                    redactionPolicy,
                    stableHostSalt = settings.hostAnonymizationSalt
                )
            }

            val prompt = buildAnalysisPrompt(safeMetadataText, settings.passiveAiMinSeverity.name)

            // Send to AI backend
            val responseBuffer = StringBuilder()
            val completionLatch = CountDownLatch(1)
            val errorRef = AtomicReference<String?>(null)

            supervisor.send(
                text = prompt,
                contextJson = null,
                privacyMode = settings.privacyMode,
                determinismMode = settings.determinismMode,
                onChunk = { chunk -> responseBuffer.append(chunk) },
                onComplete = { err ->
                    errorRef.set(err?.message)
                    completionLatch.countDown()
                }
            )

            val completed = completionLatch.await(Defaults.PASSIVE_SCAN_TIMEOUT_MS, TimeUnit.MILLISECONDS)

            requestsAnalyzed.incrementAndGet()
            lastAnalysisTime.set(System.currentTimeMillis())

            if (!completed) {
                api.logging().logToError("[PassiveAiScanner] Timeout for: ${request.url().take(60)}")
            } else if (errorRef.get() != null) {
                api.logging().logToError("[PassiveAiScanner] AI error: ${errorRef.get()}")
            } else if (responseBuffer.isNotEmpty()) {
                handleAiResponse(responseBuffer.toString(), requestResponse, settings.passiveAiMinSeverity.name)
            }

            audit.logEvent("passive_ai_scan", mapOf(
                "url" to request.url(),
                "method" to request.method(),
                "status" to (response?.statusCode() ?: 0).toString()
            ))
        } catch (e: Exception) {
            api.logging().logToError("[PassiveAiScanner] Error: ${e.javaClass.simpleName}: ${e.message}")
        }
    }

    private fun buildAnalysisPrompt(metadata: String, minSeverity: String): String {
        val severityInstruction = when (minSeverity) {
            "CRITICAL" -> "Only report CRITICAL severity findings."
            "HIGH" -> "Only report HIGH or CRITICAL severity findings."
            "MEDIUM" -> "Only report MEDIUM, HIGH or CRITICAL severity findings."
            else -> "Report all findings (LOW, MEDIUM, HIGH, CRITICAL)."
        }
        
        return """
### ROLE
You are a senior security researcher analyzing HTTP traffic.
Response Language: English.

### TASK
Analyze the provided HTTP data for vulnerabilities and misconfigurations.
$severityInstruction

### SCOPE
1. **Injection**: XSS (Reflected/DOM/Stored), SQLi, CMDI, SSTI, LDAP/XPath.
2. **Auth & Access**: IDOR, BOLA, BAC (Horizontal/Vertical), Mass Assignment, Broken Auth, JWT Issues, CSRF.
3. **Info Disclosure**: Sensitive Data (PII, Secrets), Debug Info, Source Code, Git/Backup Files.
4. **Config**: Missing Headers, CORS, Open Redirect, SSRF, Deserialization, XXE.
5. **High Value**: Account Takeover, Host/Email Header Injection, OAuth Misconfig, MFA Bypass, Cache Poisoning/Deception, Request Smuggling, Prototype Pollution.
6. **API**: Version Bypass, GraphQL Introspection.

### RULES
1. **Evidence First**: ONLY report findings with CONCRETE EVIDENCE in the provided data.
2. **Quality**: Confidence 95-100 (Certain), 85-94 (Firm), <85 (Ignore).
3. **No Speculation**: Do not report theoretical issues without proof in this specific traffic.
4. **JSON Output**: Output ONLY a JSON array. If no issues found, output [].

### OUTPUT FORMAT
[
  {
    "reasoning": "Step-by-step logic explaining why this is a vulnerability",
    "title": "Short descriptive title",
    "severity": "High|Medium|Low|Information",
    "detail": "Technical description with evidence quotes",
    "confidence": 0-100
  }
]

### HTTP DATA
$metadata
""".trim()
    }

    private fun handleAiResponse(aiText: String, requestResponse: HttpRequestResponse, minSeverity: String) {
        val cleaned = cleanJsonResponse(aiText)
        if (cleaned.isBlank() || cleaned == "[]") return

        try {
            // Parse JSON manually to avoid Jackson classloader issues
            val issues = parseIssuesJson(cleaned)
            if (issues.isEmpty()) return
            val settings = getSettings()

            for (item in issues) {
                val confidence = item.confidence ?: 0
                val title = (item.title ?: "AI Potential Issue").take(120)
                val rawSeverity = item.severity ?: "Information"
                val reasoning = item.reasoning ?: ""
                val detail = buildString {
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
        } catch (e: Exception) {
            api.logging().logToError("[PassiveAiScanner] Failed to parse AI response: ${e.message}")
        }
    }

    private fun handleFinding(
        requestResponse: HttpRequestResponse,
        title: String,
        rawSeverity: String,
        detail: String,
        confidence: Int,
        minSeverity: String,
        settings: AgentSettings,
        source: String
    ) {
        val minSeverityLevel = severityLevel(minSeverity)
        val severityLevel = severityLevel(rawSeverity)
        val shouldCreate = confidence >= 85 && severityLevel >= minSeverityLevel

        if (source == "ai" && confidence < 85) {
            return
        }

        val issueCreated = if (shouldCreate) {
            try {
                val severity = mapSeverity(rawSeverity)
                val burpConfidence = when {
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
                    val metadataSection = buildMetadataSectionPlain(
                        backendInfo,
                        "Passive",
                        confidence,
                        "AI passive analysis - may need active confirmation for verification."
                    )

                    // Build well-formatted detail
                    val fullDetailLines = mutableListOf<String>()
                    fullDetailLines.addAll(sanitizedDetail.split("\n"))
                    fullDetailLines.add("")
                    fullDetailLines.addAll(metadataSection.split("\r\n"))
                    val fullDetail = formatIssueDetailHtml(fullDetailLines)
                    
                    val issue = AuditIssue.auditIssue(
                        issueName,
                        fullDetail,
                        "Verify the finding manually or use AI Active Scanner for confirmation.",
                        requestResponse.request().url(),
                        severity,
                        burpConfidence,
                        null,
                        null,
                        severity,
                        listOf(requestResponse)
                    )
                    api.siteMap().add(issue)
                    issuesFound.incrementAndGet()
                    api.logging().logToOutput("[PassiveAiScanner] Issue: $title | $rawSeverity | $confidence%")

                    // Auto-queue to active scanner if enabled
                    queueToActiveScanner(requestResponse, title, rawSeverity, detail, confidence, settings)

                    audit.logEvent("passive_ai_issue", mapOf(
                        "title" to title,
                        "severity" to rawSeverity,
                        "confidence" to confidence.toString(),
                        "url" to requestResponse.request().url(),
                        "source" to source
                    ))
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

    private fun recordFinding(
        requestResponse: HttpRequestResponse,
        title: String,
        rawSeverity: String,
        detail: String,
        confidence: Int,
        source: String,
        issueCreated: Boolean
    ) {
        val finding = PassiveAiFinding(
            timestamp = System.currentTimeMillis(),
            url = requestResponse.request().url(),
            title = title,
            severity = rawSeverity,
            detail = detail,
            confidence = confidence,
            source = source,
            issueCreated = issueCreated
        )
        synchronized(findings) {
            if (findings.size >= Defaults.FINDINGS_BUFFER_SIZE) findings.removeFirst()
            findings.addLast(finding)
        }
    }

    private fun issueNameForPassive(title: String): String {
        val vulnClass = mapTitleToVulnClass(title)
        return if (vulnClass != null) {
            "[AI Passive] ${vulnClass.name}"
        } else {
            "[AI Passive] ${IssueText.sanitize(title)}"
        }
    }

    private fun hasExistingIssue(name: String, baseUrl: String): Boolean {
        return api.siteMap().issues().any { it.name() == name && it.baseUrl() == baseUrl }
    }
    
    private fun queueToActiveScanner(
        requestResponse: HttpRequestResponse,
        title: String,
        severity: String,
        detail: String,
        confidence: Int,
        settings: AgentSettings
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
            val hint = VulnHint(
                vulnClass = vulnClass,
                confidence = confidence,
                evidence = detail.take(200)
            )
            val target = ActiveScanTarget(
                originalRequest = requestResponse,
                injectionPoint = point,
                vulnHint = hint,
                priority = when (severity.uppercase()) {
                    "CRITICAL" -> 100
                    "HIGH" -> 80
                    "MEDIUM" -> 60
                    else -> 40
                }
            )
            scanner.queueTarget(target)
        }
        
        api.logging().logToOutput("[PassiveAiScanner] Queued to Active Scanner: $title")
    }
    
    private fun mapTitleToVulnClass(title: String): VulnClass? {
        val lowerTitle = title.lowercase()
        return when {
            // Injection vulnerabilities
            lowerTitle.contains("sql") || lowerTitle.contains("injection") && lowerTitle.contains("database") -> VulnClass.SQLI
            lowerTitle.contains("xss") || lowerTitle.contains("cross-site scripting") || lowerTitle.contains("script injection") -> VulnClass.XSS_REFLECTED
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
            lowerTitle.contains("account takeover") || lowerTitle.contains("ato") || lowerTitle.contains("password reset") -> VulnClass.ACCOUNT_TAKEOVER
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
            lowerTitle.contains("request smuggling") || lowerTitle.contains("cl.te") || lowerTitle.contains("transfer-encoding") && lowerTitle.contains("content-length") -> VulnClass.REQUEST_SMUGGLING
            lowerTitle.contains("file upload") || lowerTitle.contains("unrestricted upload") || lowerTitle.contains("upload") && lowerTitle.contains("executable") -> VulnClass.UNRESTRICTED_FILE_UPLOAD

            // Information disclosure (NEW)
            lowerTitle.contains("source map") || lowerTitle.contains("sourcemap") -> VulnClass.SOURCEMAP_DISCLOSURE
            lowerTitle.contains(".git") || lowerTitle.contains("git exposure") || lowerTitle.contains("git repository") -> VulnClass.GIT_EXPOSURE
            lowerTitle.contains("backup") || lowerTitle.contains(".bak") || lowerTitle.contains(".old file") -> VulnClass.BACKUP_DISCLOSURE
            lowerTitle.contains("debug") || lowerTitle.contains("actuator") || lowerTitle.contains("profiler") -> VulnClass.DEBUG_EXPOSURE
            lowerTitle.contains("stack trace") || lowerTitle.contains("error leak") -> VulnClass.STACK_TRACE_EXPOSURE

            // Cloud/Infrastructure (NEW)
            lowerTitle.contains("s3") || lowerTitle.contains("bucket") && lowerTitle.contains("public") -> VulnClass.S3_MISCONFIGURATION
            lowerTitle.contains("subdomain takeover") || lowerTitle.contains("dangling") -> VulnClass.SUBDOMAIN_TAKEOVER

            // Business logic (NEW)
            lowerTitle.contains("price") || lowerTitle.contains("quantity") && lowerTitle.contains("manipulation") -> VulnClass.PRICE_MANIPULATION
            lowerTitle.contains("race condition") || lowerTitle.contains("toctou") -> VulnClass.RACE_CONDITION_TOCTOU

            // API security (NEW)
            lowerTitle.contains("api version") || lowerTitle.contains("deprecated api") -> VulnClass.API_VERSION_BYPASS
            lowerTitle.contains("graphql") -> VulnClass.GRAPHQL_INJECTION

            // Other
            lowerTitle.contains("redirect") || lowerTitle.contains("open redirect") -> VulnClass.OPEN_REDIRECT
            lowerTitle.contains("cors") -> VulnClass.CORS_MISCONFIGURATION
            lowerTitle.contains("directory listing") -> VulnClass.DIRECTORY_LISTING

            else -> null
        }
    }
    
    private fun extractInjectionPoints(requestResponse: HttpRequestResponse): List<InjectionPoint> {
        return InjectionPointExtractor.extract(requestResponse.request(), headerInjectionAllowlist)
    }
    
    private fun severityLevel(severity: String): Int {
        return when (severity.uppercase()) {
            "CRITICAL" -> 4
            "HIGH" -> 3
            "MEDIUM" -> 2
            "LOW" -> 1
            else -> 0
        }
    }

    private data class LocalFinding(
        val title: String,
        val severity: String,
        val detail: String,
        val confidence: Int
    )

    private fun runLocalChecks(
        request: burp.api.montoya.http.message.requests.HttpRequest,
        response: burp.api.montoya.http.message.responses.HttpResponse?,
        requestBody: String,
        responseBody: String
    ): List<LocalFinding> {
        val findings = mutableListOf<LocalFinding>()
        detectRequestSmuggling(request)?.let { findings.add(it) }
        detectCsrf(request, response)?.let { findings.add(it) }
        detectDeserialization(request, requestBody)?.let { findings.add(it) }
        detectUnrestrictedFileUpload(request, response, requestBody, responseBody)?.let { findings.add(it) }
        return findings
    }

    private fun detectRequestSmuggling(
        request: burp.api.montoya.http.message.requests.HttpRequest
    ): LocalFinding? {
        val headers = request.headers()
        val contentLengths = headers.filter { it.name().equals("Content-Length", ignoreCase = true) }
        val transferEncodings = headers.filter { it.name().equals("Transfer-Encoding", ignoreCase = true) }
        val distinctCl = contentLengths.map { it.value().trim() }.distinct()
        val hasClTe = transferEncodings.any { it.value().contains("chunked", ignoreCase = true) } && contentLengths.isNotEmpty()
        val hasDuplicateCl = contentLengths.size > 1 && distinctCl.size > 1

        if (!hasClTe && !hasDuplicateCl) return null

        val detail = buildString {
            appendLine("Potential request smuggling conditions detected in request headers.")
            if (hasClTe) {
                appendLine("Content-Length present with Transfer-Encoding: chunked.")
            }
            if (hasDuplicateCl) {
                appendLine("Multiple Content-Length headers with different values: ${distinctCl.joinToString(", ")}.")
            }
        }.trim()

        return LocalFinding(
            title = "HTTP Request Smuggling Indicators",
            severity = "Medium",
            detail = detail,
            confidence = 90
        )
    }

    private fun detectCsrf(
        request: burp.api.montoya.http.message.requests.HttpRequest,
        response: burp.api.montoya.http.message.responses.HttpResponse?
    ): LocalFinding? {
        val method = request.method().uppercase()
        if (method !in setOf("POST", "PUT", "PATCH", "DELETE")) return null

        val hasAuthHeader = request.headers().any { authHeaderNames.contains(it.name().lowercase()) }
        val cookieHeader = request.headerValue("Cookie") ?: ""
        if (hasAuthHeader || cookieHeader.isBlank()) return null
        if (!authCookieHint.containsMatchIn(cookieHeader)) return null

        val hasTokenParam = request.parameters().any { csrfTokenRegex.containsMatchIn(it.name()) }
        val hasTokenHeader = request.headers().any { csrfTokenRegex.containsMatchIn(it.name()) }
        if (hasTokenParam || hasTokenHeader) return null

        val origin = request.headerValue("Origin")
        val referer = request.headerValue("Referer")
        if (!origin.isNullOrBlank() || !referer.isNullOrBlank()) return null

        val sameSiteSecure = response?.headers()
            ?.filter { it.name().equals("Set-Cookie", ignoreCase = true) }
            ?.any { header ->
                val value = header.value()
                authCookieHint.containsMatchIn(value) &&
                    value.contains("samesite", ignoreCase = true) &&
                    (value.contains("strict", ignoreCase = true) || value.contains("lax", ignoreCase = true))
            } ?: false
        if (sameSiteSecure) return null

        return LocalFinding(
            title = "Potential CSRF (Missing Token)",
            severity = "Low",
            detail = "State-changing request with cookie-based auth and no CSRF token; Origin/Referer not present; SameSite not strict.",
            confidence = 85
        )
    }

    private fun detectDeserialization(
        request: burp.api.montoya.http.message.requests.HttpRequest,
        requestBody: String
    ): LocalFinding? {
        val serializedParam = request.parameters().firstOrNull { param ->
            val nameMatch = Regex("(data|payload|serialized|object|state|viewstate)", RegexOption.IGNORE_CASE)
                .containsMatchIn(param.name())
            val value = param.value()
            if (!nameMatch || value.length < 100) return@firstOrNull false
            value.startsWith("rO0AB") ||
                value.contains("aced0005", ignoreCase = true)
        }

        val contentType = request.headerValue("Content-Type") ?: ""
        val bodyMatch = (contentType.contains("java-serialized", ignoreCase = true) ||
            contentType.contains("octet-stream", ignoreCase = true)) &&
            (requestBody.contains("rO0AB") || requestBody.contains("aced0005", ignoreCase = true))

        if (serializedParam == null && !bodyMatch) return null

        return LocalFinding(
            title = "Deserialization Surface Detected",
            severity = "Information",
            detail = "Serialized data detected in request (potential deserialization sink).",
            confidence = 90
        )
    }

    private fun detectUnrestrictedFileUpload(
        request: burp.api.montoya.http.message.requests.HttpRequest,
        response: burp.api.montoya.http.message.responses.HttpResponse?,
        requestBody: String,
        responseBody: String
    ): LocalFinding? {
        val contentType = request.headerValue("Content-Type") ?: return null
        if (!contentType.contains("multipart/form-data", ignoreCase = true)) return null

        val filenameMatch = Regex("filename=\"([^\"]+)\"").find(requestBody) ?: return null
        val filename = filenameMatch.groupValues[1]
        val ext = filename.substringAfterLast('.', "")
        if (ext.isBlank() || !dangerousUploadExtensions.contains(ext.lowercase())) return null

        val status = response?.statusCode() ?: 0
        if (status !in 200..299) return null

        val location = response?.headers()
            ?.firstOrNull { it.name().equals("Location", ignoreCase = true) }
            ?.value()
            ?.lowercase()
            ?: ""
        val bodyLower = responseBody.lowercase()
        if (!location.contains(filename.lowercase()) && !bodyLower.contains(filename.lowercase())) return null

        return LocalFinding(
            title = "Unrestricted File Upload (Executable Extension)",
            severity = "Medium",
            detail = "Upload accepted for '$filename' and response references the uploaded filename.",
            confidence = 90
        )
    }
    
    internal data class AiIssueItem(
        val reasoning: String? = null,
        val title: String? = null,
        val severity: String? = null,
        val detail: String? = null,
        val confidence: Int? = null
    )

    internal fun parseIssuesJson(json: String): List<AiIssueItem> {
        val root = jsonMapper.readTree(json)
        if (!root.isArray) return emptyList()
        return root.mapNotNull { node ->
            runCatching {
                AiIssueItem(
                    reasoning = node.path("reasoning").takeIf { !it.isMissingNode && !it.isNull }?.asText(),
                    title = node.path("title").takeIf { !it.isMissingNode && !it.isNull }?.asText(),
                    severity = node.path("severity").takeIf { !it.isMissingNode && !it.isNull }?.asText(),
                    detail = node.path("detail").takeIf { !it.isMissingNode && !it.isNull }?.asText(),
                    confidence = node.path("confidence").takeIf { !it.isMissingNode && !it.isNull }?.asInt()
                )
            }.getOrNull()
        }
    }

    internal fun cleanJsonResponse(text: String): String {
        if (text.isBlank()) return ""
        var cleaned = text.trim()
        // Remove markdown code blocks
        cleaned = cleaned.replace(Regex("^```json\\s*", RegexOption.IGNORE_CASE), "")
        cleaned = cleaned.replace(Regex("```\\s*$"), "")
        cleaned = cleaned.replace(Regex("^```\\s*"), "")
        // Extract JSON array
        val match = Regex("\\[.*]", RegexOption.DOT_MATCHES_ALL).find(cleaned)
        return match?.value ?: ""
    }

    private fun mapSeverity(raw: String): AuditIssueSeverity {
        return when (raw.lowercase()) {
            "high" -> AuditIssueSeverity.HIGH
            "medium" -> AuditIssueSeverity.MEDIUM
            "low" -> AuditIssueSeverity.LOW
            else -> AuditIssueSeverity.INFORMATION
        }
    }

    private fun redactUrlForPrompt(rawUrl: String, policy: RedactionPolicy, hostSalt: String): String {
        return try {
            val uri = URI(rawUrl)
            val safeHost = if (!uri.host.isNullOrBlank() && policy.anonymizeHosts) {
                Redaction.anonymizeHost(uri.host, hostSalt)
            } else {
                uri.host
            }
            val safeQuery = if (uri.query.isNullOrBlank()) {
                uri.query
            } else if (policy.redactTokens) {
                redactSensitiveQuery(uri.query)
            } else {
                uri.query
            }
            URI(
                uri.scheme,
                uri.userInfo,
                safeHost,
                uri.port,
                uri.path,
                safeQuery,
                uri.fragment
            ).toString()
        } catch (_: Exception) {
            rawUrl
        }
    }

    private fun redactSensitiveQuery(query: String): String {
        val sensitiveKey = Regex("(token|key|auth|session|jwt|cookie|password|secret)", RegexOption.IGNORE_CASE)
        return query.split("&").joinToString("&") { pair ->
            val separator = pair.indexOf('=')
            if (separator <= 0) {
                pair
            } else {
                val key = pair.substring(0, separator)
                if (sensitiveKey.containsMatchIn(key)) "$key=[REDACTED]" else pair
            }
        }
    }

    private fun buildMetadataSection(backendInfo: AgentSupervisor.BackendInfo?, scanType: String, confidence: Int): String {
        return buildString {
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
            
            val timestamp = java.time.Instant.now().toString().replace('T', ' ').substringBefore('.')
            appendLine("**Scan Date:** $timestamp UTC")
            appendLine()
            appendLine("---")
        }
    }

    private fun buildMetadataSectionPlain(
        backendInfo: AgentSupervisor.BackendInfo?,
        scanType: String,
        confidence: Int,
        note: String
    ): String {
        val lines = mutableListOf<String>()
        lines.add("AI Analysis Metadata")
        if (backendInfo != null) {
            lines.add("  Backend: ${backendInfo.displayName}")
            if (backendInfo.model != null) {
                lines.add("  Model: ${backendInfo.model}")
            }
        } else {
            lines.add("  Backend: Unknown")
        }
        lines.add("  Scan Type: $scanType")
        lines.add("  Confidence: $confidence%")

        val timestamp = java.time.Instant.now().toString().replace('T', ' ').substringBefore('.')
        lines.add("  Scan Date: $timestamp UTC")
        lines.add("  Note: $note")
        return lines.joinToString("\r\n")
    }

    private fun formatIssueDetailHtml(lines: List<String>): String {
        return lines.joinToString("<br>") { line ->
            val escaped = line
                .replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;")
            if (escaped.startsWith("  ")) {
                "&nbsp;&nbsp;" + escaped.drop(2)
            } else {
                escaped
            }
        }
    }
}
