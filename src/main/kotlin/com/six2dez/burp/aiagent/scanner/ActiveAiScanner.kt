package com.six2dez.burp.aiagent.scanner

import burp.api.montoya.MontoyaApi
import burp.api.montoya.http.message.HttpRequestResponse
import burp.api.montoya.http.message.requests.HttpRequest
import burp.api.montoya.scanner.audit.issues.AuditIssue
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity
import com.six2dez.burp.aiagent.audit.AuditLogger
import com.six2dez.burp.aiagent.config.AgentSettings
import com.six2dez.burp.aiagent.config.Defaults
import com.six2dez.burp.aiagent.redact.PrivacyMode
import com.six2dez.burp.aiagent.supervisor.AgentSupervisor
import com.six2dez.burp.aiagent.util.IssueText
import java.util.concurrent.*
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicReference
import kotlin.math.abs

data class ActiveAiFinding(
    val timestamp: Long,
    val url: String,
    val title: String,
    val severity: String,
    val detail: String,
    val confidence: Int
)

/**
 * AI-powered Active Scanner that confirms vulnerabilities by sending test payloads
 */
class ActiveAiScanner(
    private val api: MontoyaApi,
    private val supervisor: AgentSupervisor,
    private val audit: AuditLogger,
    private val getSettings: () -> AgentSettings
) {
    private val enabled = AtomicBoolean(false)
    private val scanning = AtomicBoolean(false)
    private val scanQueue = ConcurrentLinkedQueue<ActiveScanTarget>()
    private val processedTargets = ConcurrentHashMap<String, Long>()  // Dedup
    private val scansCompleted = AtomicInteger(0)
    private val vulnsConfirmed = AtomicInteger(0)
    private val currentTarget = AtomicReference<String?>(null)
    private val confirmations = ArrayDeque<ActiveAiFinding>(Defaults.FINDINGS_BUFFER_SIZE)
    
    private val payloadGenerator = PayloadGenerator()
    private val responseAnalyzer = ResponseAnalyzer()
    private val requestExecutor = Executors.newCachedThreadPool()

    private val headerInjectionAllowlist = ScannerUtils.HEADER_INJECTION_ALLOWLIST
    private val authHeaderNames = setOf(
        "authorization",
        "x-api-key",
        "x-auth-token",
        "x-access-token",
        "x-csrf-token"
    )
    private val authCookieHint = Regex("(session|auth|token|sid|jwt|remember)", RegexOption.IGNORE_CASE)
    private val authErrorRegex = Regex(
        "(unauthorized|forbidden|access denied|not authorized|login|sign\\s?in|signin)",
        RegexOption.IGNORE_CASE
    )
    private val sensitiveDataRegex = Regex(
        "email.*@|password|credit.*card|ssn|api.*key",
        RegexOption.IGNORE_CASE
    )
    private val staticAssetRegex = Regex(
        "\\.(css|js|png|jpg|jpeg|gif|svg|woff2?|ico|map)(\\?|$)",
        RegexOption.IGNORE_CASE
    )
    
    private var executor: ExecutorService? = null
    private var scheduledExecutor: ScheduledExecutorService? = null
    
    // Configurable limits
    var maxConcurrent: Int = 3
    var maxPayloadsPerPoint: Int = 10
    var timeoutSeconds: Int = 30
    var requestDelayMs: Long = 100
    var maxRiskLevel: PayloadRisk = PayloadRisk.SAFE
    var scopeOnly: Boolean = true
    var scanMode: ScanMode = ScanMode.FULL
    var useCollaborator: Boolean = false
    var maxQueueSize: Int = Defaults.ACTIVE_SCAN_MAX_QUEUE_SIZE

    fun setEnabled(value: Boolean) {
        enabled.set(value)
        if (value) {
            startProcessing()
        } else {
            stopProcessing()
        }
    }

    fun isEnabled(): Boolean = enabled.get()

    fun getStatus(): ActiveScannerStatus {
        return ActiveScannerStatus(
            enabled = enabled.get(),
            queueSize = scanQueue.size,
            scanning = scanning.get(),
            scansCompleted = scansCompleted.get(),
            vulnsConfirmed = vulnsConfirmed.get(),
            currentTarget = currentTarget.get()
        )
    }

    fun getRecentConfirmations(n: Int): List<ActiveAiFinding> {
        if (n <= 0) return emptyList()
        synchronized(confirmations) {
            return if (confirmations.size <= n) confirmations.toList() else confirmations.takeLast(n)
        }
    }

    /**
     * Queue a target for active scanning
     * Called by PassiveAiScanner when it detects a potential vulnerability
     */
    fun queueTarget(target: ActiveScanTarget) {
        if (!enabled.get()) return
        if (target.vulnHint.vulnClass in ScanPolicy.PASSIVE_ONLY_VULN_CLASSES) return
        if (!ScanPolicy.isAllowedForMode(scanMode, target.vulnHint.vulnClass)) return
        
        // Check scope
        if (scopeOnly && !api.scope().isInScope(target.originalRequest.request().url())) {
            return
        }
        
        // Dedup - don't scan same target twice within 1 hour
        val now = System.currentTimeMillis()
        val lastScan = processedTargets[target.id]
        if (lastScan != null && (now - lastScan) < Defaults.DEDUP_WINDOW_MS) {
            return
        }
        
        if (!offerIfQueueNotFull(target)) return
        api.logging().logToOutput("[ActiveAiScanner] Queued: ${target.vulnHint.vulnClass} in ${target.injectionPoint.name}")
    }

    /**
     * Manually trigger active scan on specific requests
     */
    fun manualScan(requests: List<HttpRequestResponse>, vulnClasses: List<VulnClass> = VulnClass.values().toList()): Int {
        var queued = 0
        val filteredClasses = vulnClasses.filterNot { it in ScanPolicy.PASSIVE_ONLY_VULN_CLASSES }
            .filter { ScanPolicy.isAllowedForMode(scanMode, it) }
        
        for (request in requests) {
            val injectionPoints = extractInjectionPoints(request)
            for (point in injectionPoints) {
                for (vulnClass in filteredClasses) {
                    val target = ActiveScanTarget(
                        originalRequest = request,
                        injectionPoint = point,
                        vulnHint = VulnHint(vulnClass, 50, "Manual scan"),
                        priority = 50
                    )
                    if (scopeOnly && !api.scope().isInScope(request.request().url())) {
                        continue
                    }
                    if (offerIfQueueNotFull(target)) {
                        queued++
                    }
                }
            }
        }
        
        if (queued > 0) {
            api.logging().logToOutput("[ActiveAiScanner] Manual active scan: $queued targets queued")
            if (!scanning.get() && enabled.get()) {
                startProcessing()
            }
        }
        
        return queued
    }

    private fun offerIfQueueNotFull(target: ActiveScanTarget): Boolean {
        if (scanQueue.size >= maxQueueSize.coerceAtLeast(1)) {
            api.logging().logToError("[ActiveAiScanner] Queue limit reached ($maxQueueSize). Dropping target: ${target.id}")
            return false
        }
        scanQueue.offer(target)
        return true
    }

    fun clearQueue() {
        scanQueue.clear()
        api.logging().logToOutput("[ActiveAiScanner] Queue cleared")
    }

    fun resetStats() {
        scansCompleted.set(0)
        vulnsConfirmed.set(0)
        processedTargets.clear()
    }

    private fun startProcessing() {
        if (scanning.getAndSet(true)) return  // Already running
        
        executor = Executors.newFixedThreadPool(maxConcurrent)
        scheduledExecutor = Executors.newSingleThreadScheduledExecutor()
        
        scheduledExecutor?.scheduleWithFixedDelay({
            processQueue()
        }, 0, 500, TimeUnit.MILLISECONDS)
    }

    private fun stopProcessing() {
        scanning.set(false)
        executor?.shutdownNow()
        scheduledExecutor?.shutdownNow()
        try {
            executor?.awaitTermination(5, TimeUnit.SECONDS)
            scheduledExecutor?.awaitTermination(5, TimeUnit.SECONDS)
        } catch (_: InterruptedException) {
            Thread.currentThread().interrupt()
        }
        executor = null
        scheduledExecutor = null
        currentTarget.set(null)
    }

    private fun processQueue() {
        if (!enabled.get() || !scanning.get()) return
        
        val exec = executor ?: return
        
        // Process up to maxConcurrent targets
        repeat(maxConcurrent) {
            val target = scanQueue.poll() ?: return@repeat
            
            exec.submit {
                try {
                    currentTarget.set("${target.vulnHint.vulnClass}: ${target.originalRequest.request().url().take(50)}")
                    val result = executeScan(target)
                    handleResult(result)
                } catch (e: Exception) {
                    api.logging().logToError("[ActiveAiScanner] Error: ${e.message}")
                } finally {
                    scansCompleted.incrementAndGet()
                    processedTargets[target.id] = System.currentTimeMillis()
                }
            }
        }
        
        if (scanQueue.isEmpty()) {
            currentTarget.set(null)
        }
    }

    private fun executeScan(target: ActiveScanTarget): ActiveScanResult {
        val settings = getSettings()
        val vulnClass = target.vulnHint.vulnClass

        if (vulnClass in ScanPolicy.PASSIVE_ONLY_VULN_CLASSES) {
            return ActiveScanResult(target, 0, null, "Passive-only vulnerability class")
        }
        if (!ScanPolicy.isAllowedForMode(scanMode, vulnClass)) {
            return ActiveScanResult(target, 0, null, "Vulnerability class not enabled for scan mode")
        }

        // Measure baseline response time
        val baselineStart = System.currentTimeMillis()
        val baselineResponse = sendRequestWithTimeout(target.originalRequest.request())
            ?: return ActiveScanResult(target, 0, null, "Failed to send baseline request (timeout)")
        val baselineTime = System.currentTimeMillis() - baselineStart
        val baselineRequestResponse = HttpRequestResponse.httpRequestResponse(
            target.originalRequest.request(),
            baselineResponse.response()
        )

        val authzConfirmation = if (vulnClass in ScanPolicy.AUTHZ_BYPASS_CLASSES) {
            executeAuthzBypassCheck(target, baselineRequestResponse)
        } else null
        if (authzConfirmation != null) {
            return ActiveScanResult(target, 0, authzConfirmation)
        }
        if (vulnClass in ScanPolicy.IDOR_CLASSES) {
            return executeIdorScan(target, baselineRequestResponse)
        }
        
        // Get payloads for this vulnerability class
        val quickPayloads = payloadGenerator.getQuickPayloads(vulnClass, maxRiskLevel)
        val contextPayloads = payloadGenerator.generateContextAwarePayloads(
            vulnClass, 
            target.injectionPoint.originalValue,
            5
        )
        
        val allPayloads = (quickPayloads + contextPayloads)
            .distinctBy { it.value }
            .take(maxPayloadsPerPoint)
        
        if (allPayloads.isEmpty()) {
            return ActiveScanResult(target, 0, null, "No payloads available for ${vulnClass}")
        }
        
        // Group Boolean-based payloads for dual confirmation testing
        val booleanPayloadPairs = mutableListOf<Pair<Payload, Payload>>()
        val truePayloads = allPayloads.filter {
            it.detectionMethod == DetectionMethod.BLIND_BOOLEAN &&
            (it.value.contains("1=1") || it.value.contains("1'='1") || it.expectedEvidence.contains("Same", ignoreCase = true))
        }
        val falsePayloads = allPayloads.filter {
            it.detectionMethod == DetectionMethod.BLIND_BOOLEAN &&
            (it.value.contains("1=2") || it.value.contains("1'='2") || it.expectedEvidence.contains("Different", ignoreCase = true))
        }

        // Pair TRUE and FALSE payloads for dual confirmation
        for (truePayload in truePayloads) {
            // Find matching FALSE payload (same quote style)
            val matchingFalse = falsePayloads.find { fp ->
                (truePayload.value.contains("'") && fp.value.contains("'")) ||
                (!truePayload.value.contains("'") && !fp.value.contains("'"))
            }
            if (matchingFalse != null) {
                booleanPayloadPairs.add(Pair(truePayload, matchingFalse))
            }
        }

        // Test Boolean-based payloads with DUAL CONFIRMATION
        for ((truePayload, falsePayload) in booleanPayloadPairs) {
            try {
                // Test TRUE condition
                val trueRequest = injectPayload(target.originalRequest.request(), target.injectionPoint, truePayload.value)
                val trueResponse = sendRequestWithTimeout(trueRequest) ?: continue
                val trueRequestResponse = HttpRequestResponse.httpRequestResponse(trueRequest, trueResponse.response())

                Thread.sleep(requestDelayMs)

                // Test FALSE condition
                val falseRequest = injectPayload(target.originalRequest.request(), target.injectionPoint, falsePayload.value)
                val falseResponse = sendRequestWithTimeout(falseRequest) ?: continue
                val falseRequestResponse = HttpRequestResponse.httpRequestResponse(falseRequest, falseResponse.response())

                // Perform dual confirmation
                val confirmation = responseAnalyzer.analyzeBooleanBasedDual(
                    target.originalRequest,
                    trueRequestResponse,
                    falseRequestResponse,
                    truePayload,
                    falsePayload,
                    vulnClass
                )?.copy(target = target)

                if (confirmation != null && confirmation.confirmed) {
                    return ActiveScanResult(target, allPayloads.indexOf(falsePayload) + 1, confirmation)
                }

                Thread.sleep(requestDelayMs)

            } catch (e: Exception) {
                api.logging().logToError("[ActiveAiScanner] Boolean dual test error: ${e.message}")
            }
        }

        // Test non-Boolean payloads normally
        val nonBooleanPayloads = allPayloads.filter { it.detectionMethod != DetectionMethod.BLIND_BOOLEAN }
        for (payload in nonBooleanPayloads) {
            try {
                // Build modified request with payload
                val modifiedRequest = injectPayload(
                    target.originalRequest.request(),
                    target.injectionPoint,
                    payload.value
                )

                // Send request with timeout
                val startTime = System.currentTimeMillis()
                val response = sendRequestWithTimeout(modifiedRequest) ?: continue
                val responseTime = System.currentTimeMillis() - startTime

                // Create HttpRequestResponse for analysis
                val modifiedRequestResponse = HttpRequestResponse.httpRequestResponse(modifiedRequest, response.response())

                // Analyze response
                val confirmation = when {
                    vulnClass in ScanPolicy.CACHE_CLASSES -> confirmCacheIssue(
                        target,
                        baselineRequestResponse,
                        modifiedRequestResponse,
                        payload
                    )
                    payload.detectionMethod == DetectionMethod.BLIND_TIME -> {
                        val expectedDelay = payload.timeDelayMs ?: 3000
                        if (responseAnalyzer.analyzeTimeBased(baselineTime, responseTime, expectedDelay)) {
                            VulnConfirmation(
                                target = target,
                                payload = payload,
                                originalResponse = target.originalRequest,
                                exploitResponse = modifiedRequestResponse,
                                confidence = 85,
                                evidence = "Time-based detection: baseline=${baselineTime}ms, payload=${responseTime}ms (expected delay: ${expectedDelay}ms)",
                                confirmed = true
                            )
                        } else null
                    }
                    else -> {
                        responseAnalyzer.analyze(
                            target.originalRequest,
                            modifiedRequestResponse,
                            payload,
                            vulnClass
                        )?.copy(target = target)
                    }
                }

                if (confirmation != null && confirmation.confirmed) {
                    return ActiveScanResult(target, allPayloads.indexOf(payload) + 1, confirmation)
                }

                // Rate limiting
                Thread.sleep(requestDelayMs)

            } catch (e: Exception) {
                api.logging().logToError("[ActiveAiScanner] Payload error: ${e.message}")
            }
        }

        if (vulnClass == VulnClass.SSRF) {
            val oastConfirmation = confirmSsrfoob(target, baselineRequestResponse, settings)
            if (oastConfirmation != null && oastConfirmation.confirmed) {
                return ActiveScanResult(target, allPayloads.size, oastConfirmation)
            }
        }
        
        return ActiveScanResult(target, allPayloads.size, null)
    }

    private fun executeIdorScan(
        target: ActiveScanTarget,
        baseline: HttpRequestResponse
    ): ActiveScanResult {
        if (target.injectionPoint.type !in setOf(
                InjectionType.URL_PARAM,
                InjectionType.BODY_PARAM,
                InjectionType.PATH_SEGMENT,
                InjectionType.JSON_FIELD
            )
        ) {
            return ActiveScanResult(target, 0, null, "Unsupported injection point for IDOR/BOLA")
        }
        val payloads = payloadGenerator.generateContextAwarePayloads(
            target.vulnHint.vulnClass,
            target.injectionPoint.originalValue,
            5
        )
        if (payloads.isEmpty()) {
            return ActiveScanResult(target, 0, null, "No IDOR payloads available")
        }

        val baselineStatus = baseline.response()?.statusCode() ?: 0
        if (baselineStatus !in 200..299) {
            return ActiveScanResult(target, 0, null, "Baseline response not successful")
        }

        for ((index, payload) in payloads.withIndex()) {
            try {
                val modifiedRequest = injectPayload(
                    target.originalRequest.request(),
                    target.injectionPoint,
                    payload.value
                )
                val response = sendRequestWithTimeout(modifiedRequest) ?: continue
                val modifiedRequestResponse = HttpRequestResponse.httpRequestResponse(
                    modifiedRequest,
                    response.response()
                )

                val confirmation = analyzeIdor(
                    target,
                    baseline,
                    modifiedRequestResponse,
                    payload
                )

                if (confirmation != null && confirmation.confirmed) {
                    return ActiveScanResult(target, index + 1, confirmation)
                }

                Thread.sleep(requestDelayMs)
            } catch (e: Exception) {
                api.logging().logToError("[ActiveAiScanner] IDOR test error: ${e.message}")
            }
        }

        return ActiveScanResult(target, payloads.size, null)
    }

    private fun analyzeIdor(
        target: ActiveScanTarget,
        baseline: HttpRequestResponse,
        modified: HttpRequestResponse,
        payload: Payload
    ): VulnConfirmation? {
        val baselineBody = baseline.response()?.bodyToString() ?: ""
        val modifiedBody = modified.response()?.bodyToString() ?: ""
        val baselineStatus = baseline.response()?.statusCode() ?: 0
        val modifiedStatus = modified.response()?.statusCode() ?: 0

        if (baselineStatus !in 200..299 || modifiedStatus !in 200..299) return null
        if (baselineBody.isBlank() || modifiedBody.isBlank()) return null
        if (baselineBody == modifiedBody) return null
        if (!containsIdToken(baselineBody, target.injectionPoint.originalValue)) return null
        if (!containsIdToken(modifiedBody, payload.value)) return null
        if (containsIdToken(modifiedBody, target.injectionPoint.originalValue)) return null
        if (isAuthError(modified)) return null

        val lengthDiff = abs(baselineBody.length - modifiedBody.length)
        val lengthDiffPercent = if (baselineBody.isNotEmpty()) lengthDiff.toDouble() / baselineBody.length else 1.0
        if (lengthDiffPercent > 0.2) return null

        val isJson = isJsonResponse(baseline, baselineBody) && isJsonResponse(modified, modifiedBody)
        val confidence = if (isJson) {
            val baselineKeys = extractJsonKeys(baselineBody)
            val modifiedKeys = extractJsonKeys(modifiedBody)
            val common = baselineKeys.intersect(modifiedKeys).size
            val union = baselineKeys.union(modifiedKeys).size
            val keyOverlap = if (union > 0) common.toDouble() / union else 0.0
            if (common < 5 || keyOverlap < 0.7) return null
            if (keyOverlap > 0.85) 95 else 90
        } else {
            val diff = responseAnalyzer.calculateDifference(baselineBody, modifiedBody)
            if (diff.similarity < 0.85) return null
            90
        }

        return VulnConfirmation(
            target = target,
            payload = payload,
            originalResponse = baseline,
            exploitResponse = modified,
            confidence = confidence,
            evidence = "IDOR/BOLA confirmed: ${target.injectionPoint.originalValue} -> ${payload.value} with similar response structure",
            confirmed = true
        )
    }

    private fun executeAuthzBypassCheck(
        target: ActiveScanTarget,
        baseline: HttpRequestResponse
    ): VulnConfirmation? {
        val request = target.originalRequest.request()
        if (!hasAuthContext(request)) return null

        val strippedRequest = stripAuthHeaders(request)
        val response = sendRequestWithTimeout(strippedRequest) ?: return null
        val strippedRequestResponse = HttpRequestResponse.httpRequestResponse(
            strippedRequest,
            response.response()
        )

        val baselineStatus = baseline.response()?.statusCode() ?: 0
        val strippedStatus = strippedRequestResponse.response()?.statusCode() ?: 0
        if (baselineStatus !in 200..299 || strippedStatus !in 200..299) return null
        if (isAuthError(strippedRequestResponse)) return null

        val baselineBody = baseline.response()?.bodyToString() ?: ""
        val strippedBody = strippedRequestResponse.response()?.bodyToString() ?: ""
        if (baselineBody.isBlank() || strippedBody.isBlank()) return null

        val diff = responseAnalyzer.calculateDifference(baselineBody, strippedBody)
        val lengthDiff = abs(baselineBody.length - strippedBody.length)
        val lengthDiffPercent = if (baselineBody.isNotEmpty()) lengthDiff.toDouble() / baselineBody.length else 1.0
        if (diff.similarity < 0.85 || lengthDiffPercent > 0.15) return null

        val payload = Payload(
            value = "(auth stripped)",
            vulnClass = target.vulnHint.vulnClass,
            detectionMethod = DetectionMethod.CONTENT_BASED,
            risk = PayloadRisk.SAFE,
            expectedEvidence = "Unauthenticated response matches baseline"
        )

        return VulnConfirmation(
            target = target,
            payload = payload,
            originalResponse = baseline,
            exploitResponse = strippedRequestResponse,
            confidence = 90,
            evidence = "Authorization bypass: unauthenticated response matched baseline (similarity ${(diff.similarity * 100).toInt()}%)",
            confirmed = true
        )
    }

    private fun confirmCacheIssue(
        target: ActiveScanTarget,
        baseline: HttpRequestResponse,
        modified: HttpRequestResponse,
        payload: Payload
    ): VulnConfirmation? {
        return when (target.vulnHint.vulnClass) {
            VulnClass.CACHE_POISONING -> confirmCachePoisoning(target, baseline, modified, payload)
            VulnClass.CACHE_DECEPTION -> confirmCacheDeception(target, modified, payload)
            else -> null
        }
    }

    private fun confirmCachePoisoning(
        target: ActiveScanTarget,
        baseline: HttpRequestResponse,
        modified: HttpRequestResponse,
        payload: Payload
    ): VulnConfirmation? {
        val modifiedFull = buildFullResponse(modified)
        if (!modifiedFull.contains(payload.value)) return null
        if (buildFullResponse(baseline).contains(payload.value)) return null
        if (!isCacheable(modified)) return null

        val followUpResponse = sendRequestWithTimeout(target.originalRequest.request()) ?: return null
        val followUp = HttpRequestResponse.httpRequestResponse(
            target.originalRequest.request(),
            followUpResponse.response()
        )
        val followUpFull = buildFullResponse(followUp)
        if (!followUpFull.contains(payload.value)) return null
        if (!isCacheHit(followUp)) return null

        return VulnConfirmation(
            target = target,
            payload = payload,
            originalResponse = baseline,
            exploitResponse = modified,
            confidence = 90,
            evidence = "Cache poisoning confirmed: marker persisted and cache hit detected",
            confirmed = true
        )
    }

    private fun confirmCacheDeception(
        target: ActiveScanTarget,
        modified: HttpRequestResponse,
        payload: Payload
    ): VulnConfirmation? {
        val modifiedBody = modified.response()?.bodyToString() ?: ""
        val path = modified.request().path()
        if (!staticAssetRegex.containsMatchIn(path)) return null
        if (!sensitiveDataRegex.containsMatchIn(modifiedBody)) return null
        if (!isCacheable(modified)) return null

        val followUpResponse = sendRequestWithTimeout(target.originalRequest.request()) ?: return null
        val followUp = HttpRequestResponse.httpRequestResponse(
            target.originalRequest.request(),
            followUpResponse.response()
        )
        val followUpBody = followUp.response()?.bodyToString() ?: ""
        if (!sensitiveDataRegex.containsMatchIn(followUpBody)) return null
        if (!isCacheHit(followUp)) return null

        return VulnConfirmation(
            target = target,
            payload = payload,
            originalResponse = modified,
            exploitResponse = followUp,
            confidence = 90,
            evidence = "Cache deception confirmed: sensitive data served from cache on static-looking path",
            confirmed = true
        )
    }

    private fun hasAuthContext(request: HttpRequest): Boolean {
        val hasAuthHeader = request.headers().any { header ->
            authHeaderNames.contains(header.name().lowercase())
        }
        val cookieHeader = request.headerValue("Cookie") ?: ""
        val hasAuthCookie = authCookieHint.containsMatchIn(cookieHeader)
        return hasAuthHeader || hasAuthCookie
    }

    private fun stripAuthHeaders(request: HttpRequest): HttpRequest {
        var stripped = request
        request.headers().forEach { header ->
            if (authHeaderNames.contains(header.name().lowercase())) {
                stripped = stripped.withRemovedHeader(header.name())
            }
        }
        stripped = stripped.withRemovedHeader("Cookie")
        return stripped
    }

    private fun isAuthError(response: HttpRequestResponse): Boolean {
        val status = response.response()?.statusCode()?.toInt() ?: 0
        if (status == 401 || status == 403) return true
        val location = responseHeaderValue(response, "Location")?.lowercase()
        if (location != null && (location.contains("login") || location.contains("signin"))) return true
        val wwwAuth = responseHeaderValue(response, "WWW-Authenticate")
        if (!wwwAuth.isNullOrBlank()) return true
        val body = response.response()?.bodyToString() ?: ""
        return authErrorRegex.containsMatchIn(body)
    }

    private fun isJsonResponse(response: HttpRequestResponse, body: String): Boolean {
        val contentType = responseHeaderValue(response, "Content-Type")?.lowercase() ?: ""
        if (contentType.contains("json")) return true
        val trimmed = body.trimStart()
        return trimmed.startsWith("{") || trimmed.startsWith("[")
    }

    private fun extractJsonKeys(body: String): Set<String> {
        val keys = mutableSetOf<String>()
        val pattern = Regex("\"([A-Za-z0-9_\\-]+)\"\\s*:")
        pattern.findAll(body).forEach { match ->
            keys.add(match.groupValues[1])
        }
        return keys
    }

    private fun containsIdToken(body: String, value: String): Boolean {
        val escaped = Regex.escape(value)
        val pattern = Regex("(?<![A-Za-z0-9])$escaped(?![A-Za-z0-9])")
        return pattern.containsMatchIn(body)
    }

    private fun buildFullResponse(response: HttpRequestResponse): String {
        val headers = response.response()?.headers()
            ?.joinToString("\n") { "${it.name()}: ${it.value()}" }
            ?: ""
        val body = response.response()?.bodyToString() ?: ""
        return headers + "\n\n" + body
    }

    private fun isCacheable(response: HttpRequestResponse): Boolean {
        val cacheControl = responseHeaderValue(response, "Cache-Control")?.lowercase() ?: return false
        if (cacheControl.contains("no-store") || cacheControl.contains("no-cache") || cacheControl.contains("private")) {
            return false
        }
        return cacheControl.contains("max-age") || cacheControl.contains("s-maxage") || cacheControl.contains("public")
    }

    private fun isCacheHit(response: HttpRequestResponse): Boolean {
        val xCache = responseHeaderValue(response, "X-Cache")?.lowercase()
        if (xCache != null && xCache.contains("hit")) return true
        val cfCache = responseHeaderValue(response, "CF-Cache-Status")?.lowercase()
        if (cfCache != null && cfCache.contains("hit")) return true
        val age = responseHeaderValue(response, "Age")?.toIntOrNull()
        return age != null && age > 0
    }

    private fun responseHeaderValue(response: HttpRequestResponse, name: String): String? {
        return response.response()?.headers()
            ?.firstOrNull { it.name().equals(name, ignoreCase = true) }
            ?.value()
    }

    private fun confirmSsrfoob(
        target: ActiveScanTarget,
        baseline: HttpRequestResponse,
        settings: AgentSettings
    ): VulnConfirmation? {
        if (!useCollaborator) return null
        if (settings.privacyMode != PrivacyMode.OFF) return null
        if (target.injectionPoint.type !in setOf(
                InjectionType.URL_PARAM,
                InjectionType.BODY_PARAM,
                InjectionType.JSON_FIELD,
                InjectionType.HEADER,
                InjectionType.PATH_SEGMENT
            )
        ) {
            return null
        }

        val client = try {
            api.collaborator().createClient()
        } catch (e: Exception) {
            api.logging().logToError("[ActiveAiScanner] Collaborator unavailable: ${e.message}")
            return null
        }

        val collaboratorPayload = try {
            client.generatePayload()
        } catch (e: Exception) {
            api.logging().logToError("[ActiveAiScanner] Collaborator payload error: ${e.message}")
            return null
        }

        val oastUrl = "http://${collaboratorPayload.toString()}"
        val oastRequest = injectPayload(
            target.originalRequest.request(),
            target.injectionPoint,
            oastUrl
        )
        val oastResponse = sendRequestWithTimeout(oastRequest) ?: return null
        val oastRequestResponse = HttpRequestResponse.httpRequestResponse(oastRequest, oastResponse.response())

        val timeoutMs = maxOf(5000L, timeoutSeconds.toLong() * 1000L)
        val start = System.currentTimeMillis()
        while (System.currentTimeMillis() - start < timeoutMs) {
            val interactions = client.getAllInteractions()
            if (interactions.isNotEmpty()) {
                val types = interactions.joinToString(", ") { it.type().toString() }
                val payload = Payload(
                    value = oastUrl,
                    vulnClass = VulnClass.SSRF,
                    detectionMethod = DetectionMethod.OUT_OF_BAND,
                    risk = PayloadRisk.SAFE,
                    expectedEvidence = "Collaborator interaction"
                )
                return VulnConfirmation(
                    target = target,
                    payload = payload,
                    originalResponse = baseline,
                    exploitResponse = oastRequestResponse,
                    confidence = 95,
                    evidence = "Collaborator interaction received ($types) for $oastUrl",
                    confirmed = true
                )
            }
            Thread.sleep(500)
        }

        return null
    }

    private fun sendRequestWithTimeout(request: HttpRequest): HttpRequestResponse? {
        val timeout = timeoutSeconds.coerceAtLeast(5).toLong()
        val future = requestExecutor.submit(Callable { api.http().sendRequest(request) })
        return try {
            future.get(timeout, TimeUnit.SECONDS)
        } catch (e: TimeoutException) {
            future.cancel(true)
            api.logging().logToError("[ActiveAiScanner] Request timeout after ${timeout}s for ${request.url().take(80)}")
            null
        } catch (e: Exception) {
            future.cancel(true)
            api.logging().logToError("[ActiveAiScanner] Request error: ${e.message}")
            null
        }
    }

    private fun handleResult(result: ActiveScanResult) {
        val confirmation = result.confirmation
        if (confirmation != null && confirmation.confirmed) {
            vulnsConfirmed.incrementAndGet()
            createConfirmedIssue(confirmation)
            
            audit.logEvent("active_scan_confirmed", mapOf(
                "vuln_class" to confirmation.target.vulnHint.vulnClass.name,
                "url" to confirmation.target.originalRequest.request().url(),
                "payload" to confirmation.payload.value.take(100),
                "confidence" to confirmation.confidence.toString()
            ))
        }
    }

    private fun createConfirmedIssue(confirmation: VulnConfirmation) {
        val target = confirmation.target
        val payload = confirmation.payload
        
        val title = "[AI Active] ${target.vulnHint.vulnClass.name}"
        
        // Get backend info for metadata
        val backendInfo = supervisor.getCurrentBackendInfo()
        val metadataSection = buildMetadataSectionPlain(backendInfo, "Active", confirmation.confidence, "Confirmed via AI active exploitation testing.")
        
        val detailLines = mutableListOf<String>()
        detailLines.add("Vulnerability confirmed via active testing")
        detailLines.add("")
        detailLines.add("Type:")
        detailLines.add("  ${target.vulnHint.vulnClass.name}")
        detailLines.add("  Injection Point: ${target.injectionPoint.type} - ${target.injectionPoint.name}")
        detailLines.add("  Original Value: ${target.injectionPoint.originalValue.take(100)}")
        detailLines.add("  Payload Used: ${payload.value.take(500)}")
        detailLines.add("  Detection Method: ${payload.detectionMethod}")
        detailLines.add("  Evidence: ${confirmation.evidence}")
        detailLines.add("")
        detailLines.addAll(metadataSection.split("\r\n"))
        val detail = formatIssueDetailHtml(detailLines)
        
        val severity = ScannerIssueSupport.mapSeverity(target.vulnHint.vulnClass)
        val confidence = when {
            confirmation.confidence >= 95 -> AuditIssueConfidence.CERTAIN
            confirmation.confidence >= 80 -> AuditIssueConfidence.FIRM
            else -> AuditIssueConfidence.TENTATIVE
        }
        
        try {
            if (hasExistingIssue(title, target.originalRequest.request().url())) {
                api.logging().logToOutput("[ActiveAiScanner] Consolidated duplicate issue: $title")
                return
            }
            val issue = AuditIssue.auditIssue(
                title,
                detail,
                ScannerIssueSupport.remediation(target.vulnHint.vulnClass),
                target.originalRequest.request().url(),
                severity,
                confidence,
                null,
                null,
                severity,
                listOf(target.originalRequest, confirmation.exploitResponse)
            )
            
            api.siteMap().add(issue)
            api.logging().logToOutput("[ActiveAiScanner] CONFIRMED: ${target.vulnHint.vulnClass.name} in '${target.injectionPoint.name}' (${confirmation.confidence}%)")

            val finding = ActiveAiFinding(
                timestamp = System.currentTimeMillis(),
                url = target.originalRequest.request().url(),
                title = title,
                severity = ScannerIssueSupport.mapSeverity(target.vulnHint.vulnClass).name,
                detail = confirmation.evidence,
                confidence = confirmation.confidence
            )
            synchronized(confirmations) {
            if (confirmations.size >= Defaults.FINDINGS_BUFFER_SIZE) confirmations.removeFirst()
                confirmations.addLast(finding)
            }
            
        } catch (e: Exception) {
            api.logging().logToError("[ActiveAiScanner] Failed to create issue: ${e.message}")
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

    private fun hasExistingIssue(name: String, baseUrl: String): Boolean {
        return api.siteMap().issues().any { it.name() == name && it.baseUrl() == baseUrl }
    }

    private fun injectPayload(request: HttpRequest, point: InjectionPoint, payload: String): HttpRequest {
        return when (point.type) {
            InjectionType.URL_PARAM -> {
                val url = request.url()
                val newUrl = url.replace(
                    "${point.name}=${java.net.URLEncoder.encode(point.originalValue, "UTF-8")}",
                    "${point.name}=${java.net.URLEncoder.encode(payload, "UTF-8")}"
                ).replace(
                    "${point.name}=${point.originalValue}",
                    "${point.name}=${java.net.URLEncoder.encode(payload, "UTF-8")}"
                )
                request.withPath(newUrl.substringAfter(request.httpService().host()).substringBefore("?").ifEmpty { "/" })
                    .let { req ->
                        val query = newUrl.substringAfter("?", "")
                        if (query.isNotEmpty()) {
                            HttpRequest.httpRequest(req.httpService(), "${req.method()} ${req.path()}?$query ${req.httpVersion()}\r\n${req.headers().joinToString("\r\n") { "${it.name()}: ${it.value()}" }}\r\n\r\n${req.bodyToString()}")
                        } else req
                    }
            }
            InjectionType.BODY_PARAM -> {
                val body = request.bodyToString()
                val newBody = body.replace(
                    "${point.name}=${point.originalValue}",
                    "${point.name}=${java.net.URLEncoder.encode(payload, "UTF-8")}"
                )
                request.withBody(newBody)
            }
            InjectionType.HEADER -> {
                request.withRemovedHeader(point.name)
                    .withAddedHeader(point.name, payload)
            }
            InjectionType.COOKIE -> {
                val cookies = request.headerValue("Cookie") ?: ""
                val newCookies = cookies.replace(
                    "${point.name}=${point.originalValue}",
                    "${point.name}=$payload"
                )
                request.withRemovedHeader("Cookie").withAddedHeader("Cookie", newCookies)
            }
            InjectionType.PATH_SEGMENT -> {
                val path = request.path()
                val newPath = path.replace(point.originalValue, payload)
                request.withPath(newPath)
            }
            InjectionType.JSON_FIELD -> {
                val body = request.bodyToString()
                val numericPattern = Regex("-?\\d+(?:\\.\\d+)?")
                val isNumericOriginal = numericPattern.matches(point.originalValue)
                val isNumericPayload = numericPattern.matches(payload)
                val replacementValue = if (isNumericOriginal && isNumericPayload) payload else "\"$payload\""
                val fieldPattern = Regex(
                    "\"${Regex.escape(point.name)}\"\\s*:\\s*\"?${Regex.escape(point.originalValue)}\"?"
                )
                val newBody = fieldPattern.replace(
                    body,
                    "\"${point.name}\":$replacementValue"
                )
                request.withBody(newBody)
            }
            InjectionType.XML_ELEMENT -> {
                val body = request.bodyToString()
                val newBody = body.replace(
                    "<${point.name}>${point.originalValue}</${point.name}>",
                    "<${point.name}>$payload</${point.name}>"
                )
                request.withBody(newBody)
            }
        }
    }

    private fun extractInjectionPoints(requestResponse: HttpRequestResponse): List<InjectionPoint> {
        return InjectionPointExtractor.extract(requestResponse.request(), headerInjectionAllowlist)
    }

    fun shutdown() {
        enabled.set(false)
        stopProcessing()
        executor?.shutdownNow()
        scheduledExecutor?.shutdownNow()
        requestExecutor.shutdown()
        try {
            if (!requestExecutor.awaitTermination(3, TimeUnit.SECONDS)) {
                requestExecutor.shutdownNow()
            }
        } catch (_: InterruptedException) {
            requestExecutor.shutdownNow()
        }
    }
}
