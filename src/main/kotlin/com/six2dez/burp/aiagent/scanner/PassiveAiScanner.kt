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
import com.fasterxml.jackson.databind.JsonNode
import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.module.kotlin.registerKotlinModule
import com.six2dez.burp.aiagent.audit.ActivityType
import com.six2dez.burp.aiagent.audit.AiRequestLogger
import com.six2dez.burp.aiagent.audit.AuditLogger
import com.six2dez.burp.aiagent.config.AgentSettings
import com.six2dez.burp.aiagent.config.Defaults
import com.six2dez.burp.aiagent.redact.Redaction
import com.six2dez.burp.aiagent.redact.RedactionPolicy
import com.six2dez.burp.aiagent.supervisor.AgentSupervisor
import com.six2dez.burp.aiagent.audit.Hashing
import com.six2dez.burp.aiagent.util.IssueUtils
import com.six2dez.burp.aiagent.util.IssueText
import com.six2dez.burp.aiagent.util.SecurityExcerpts
import com.six2dez.burp.aiagent.util.TokenTracker
import java.net.URI
import java.util.LinkedHashMap
import java.util.UUID
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
    var aiRequestLogger: AiRequestLogger? = null

    private val enabled = AtomicBoolean(false)
    private val requestsAnalyzed = AtomicInteger(0)
    private val issuesFound = AtomicInteger(0)
    private val lastAnalysisTime = AtomicLong(0)
    private val lastRequestTime = AtomicLong(0)
    private val aiBackoffUntilMs = AtomicLong(0)
    private val lastBackoffLogTime = AtomicLong(0)
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
    @Volatile
    var endpointDedupMinutes: Int = DEFAULT_ENDPOINT_DEDUP_MINUTES
        set(value) {
            field = value.coerceIn(MIN_DEDUP_TTL_MINUTES, MAX_DEDUP_TTL_MINUTES)
        }
    @Volatile
    var responseFingerprintDedupMinutes: Int = DEFAULT_RESPONSE_FINGERPRINT_DEDUP_MINUTES
        set(value) {
            field = value.coerceIn(MIN_DEDUP_TTL_MINUTES, MAX_DEDUP_TTL_MINUTES)
        }
    @Volatile
    var promptCacheTtlMinutes: Int = DEFAULT_PROMPT_CACHE_TTL_MINUTES
        set(value) {
            field = value.coerceIn(MIN_DEDUP_TTL_MINUTES, MAX_DEDUP_TTL_MINUTES)
        }
    @Volatile
    var endpointCacheEntries: Int = DEFAULT_ENDPOINT_CACHE_MAX_ENTRIES
        set(value) {
            field = value.coerceIn(MIN_ENDPOINT_CACHE_ENTRIES, MAX_ENDPOINT_CACHE_ENTRIES)
            synchronized(endpointRecentCache) {
                trimLruCache(endpointRecentCache, field)
            }
        }
    @Volatile
    var responseFingerprintCacheEntries: Int = DEFAULT_RESPONSE_FINGERPRINT_CACHE_MAX_ENTRIES
        set(value) {
            field = value.coerceIn(MIN_RESPONSE_FINGERPRINT_CACHE_ENTRIES, MAX_RESPONSE_FINGERPRINT_CACHE_ENTRIES)
            synchronized(responseFingerprintCache) {
                trimLruCache(responseFingerprintCache, field)
            }
        }
    @Volatile
    var promptCacheEntries: Int = DEFAULT_PROMPT_RESULT_CACHE_MAX_ENTRIES
        set(value) {
            field = value.coerceIn(MIN_PROMPT_RESULT_CACHE_ENTRIES, MAX_PROMPT_RESULT_CACHE_ENTRIES)
            synchronized(promptResultCache) {
                trimLruCache(promptResultCache, field)
            }
        }
    @Volatile
    var requestBodyPromptMaxChars: Int = DEFAULT_REQUEST_BODY_PROMPT_MAX_CHARS
        set(value) {
            field = value.coerceIn(MIN_REQUEST_BODY_PROMPT_MAX_CHARS, MAX_REQUEST_BODY_PROMPT_MAX_CHARS)
        }
    @Volatile
    var responseBodyPromptMaxChars: Int = DEFAULT_RESPONSE_BODY_PROMPT_MAX_CHARS
        set(value) {
            field = value.coerceIn(MIN_RESPONSE_BODY_PROMPT_MAX_CHARS, MAX_RESPONSE_BODY_PROMPT_MAX_CHARS)
        }
    @Volatile
    var headerMaxCount: Int = DEFAULT_HEADERS_MAX_COUNT
        set(value) {
            field = value.coerceIn(MIN_HEADERS_MAX_COUNT, MAX_HEADERS_MAX_COUNT)
        }
    @Volatile
    var paramMaxCount: Int = DEFAULT_PARAMS_MAX_COUNT
        set(value) {
            field = value.coerceIn(MIN_PARAMS_MAX_COUNT, MAX_PARAMS_MAX_COUNT)
        }

    @Volatile
    var excludedExtensions: Set<String> = DEFAULT_EXCLUDED_EXTENSIONS
        set(value) {
            field = value.map { it.lowercase().removePrefix(".") }.toSet()
        }

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
    private val cacheBustingParamRegex = Regex("^(?:_|t|ts|timestamp|cachebust|cb|rnd|nonce)$", RegexOption.IGNORE_CASE)
    private val dynamicValueStripRegex = Regex(
        listOf(
            """\b[a-f0-9]{8}-[a-f0-9]{4}-[1-5][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}\b""",  // UUID
            """\b[a-f0-9]{24}\b""",                                                                 // MongoDB ObjectId
            """\b\d{10,13}\b""",                                                                    // Unix timestamps (sec/ms)
            """\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}[^\s"',}\]]*""",                               // ISO 8601
            """(?<=[":=])\s*"?[A-Za-z0-9_\-]{20,}"?""",                                            // Long tokens/nonces
        ).joinToString("|"),
        RegexOption.IGNORE_CASE
    )
    private val staticAssetPathRegex = Regex(
        "\\.(?:css|js|map|png|jpg|jpeg|gif|svg|ico|woff2?|ttf|eot)(?:\\?|$)",
        RegexOption.IGNORE_CASE
    )
    private val requestHeaderAllowlist = setOf(
        "authorization",
        "cookie",
        "x-api-key",
        "x-auth-token",
        "x-access-token",
        "content-type",
        "origin",
        "referer",
        "host",
        "x-forwarded-for",
        "x-forwarded-host",
        "x-requested-with"
    )
    private val responseHeaderAllowlist = setOf(
        "set-cookie",
        "www-authenticate",
        "x-frame-options",
        "content-security-policy",
        "content-security-policy-report-only",
        "strict-transport-security",
        "x-content-type-options",
        "x-xss-protection",
        "location",
        "content-type",
        "content-disposition",
        "server",
        "x-powered-by",
        "access-control-allow-origin",
        "access-control-allow-credentials",
        "access-control-allow-methods",
        "access-control-allow-headers",
        "access-control-expose-headers"
    )
    private val headerNoiseDenylist = setOf(
        "accept-encoding",
        "accept-language",
        "connection",
        "keep-alive",
        "date",
        "etag",
        "last-modified",
        "vary",
        "transfer-encoding",
        "content-length",
        "accept-ranges",
        "age",
        "via"
    )

    private data class CachedAiIssues(val createdAtMs: Long, val issues: List<AiIssueItem>)

    private val endpointRecentCache = object : LinkedHashMap<String, Long>(1024, 0.75f, true) {
        override fun removeEldestEntry(eldest: MutableMap.MutableEntry<String, Long>?): Boolean {
            return size > endpointCacheEntries
        }
    }
    private val responseFingerprintCache = object : LinkedHashMap<String, Long>(2048, 0.75f, true) {
        override fun removeEldestEntry(eldest: MutableMap.MutableEntry<String, Long>?): Boolean {
            return size > responseFingerprintCacheEntries
        }
    }
    private val promptResultCache = object : LinkedHashMap<String, CachedAiIssues>(512, 0.75f, true) {
        override fun removeEldestEntry(eldest: MutableMap.MutableEntry<String, CachedAiIssues>?): Boolean {
            return size > promptCacheEntries
        }
    }

    private val batchQueue = BatchAnalysisQueue()
    private var persistentCache: com.six2dez.burp.aiagent.cache.PersistentPromptCache? = null

    private val handler = object : ProxyResponseHandler {
        override fun handleResponseReceived(response: InterceptedResponse): ProxyResponseReceivedAction {
            if (!enabled.get() || !supervisor.isAiEnabled()) {
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

            // Check excluded file extensions
            if (hasExcludedExtension(response.initiatingRequest().url())) {
                return ProxyResponseReceivedAction.continueWith(response)
            }

            // Skip streaming/upgrade endpoints that are noisy and frequently time out.
            if (isStreamingOrRealtimeEndpoint(response)) {
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
        val wasEnabled = enabled.getAndSet(on)
        if (on && registered.compareAndSet(false, true)) {
            api.proxy().registerResponseHandler(handler)
            api.logging().logToOutput("[PassiveAiScanner] Enabled - analyzing proxy traffic")
        } else if (!on && wasEnabled) {
            // Clear accumulated knowledge to prevent cross-scope contamination
            ScanKnowledgeBase.clear()
            api.logging().logToOutput("[PassiveAiScanner] Disabled — knowledge base cleared")
        }
    }

    fun isEnabled(): Boolean = enabled.get()

    fun applyOptimizationSettings(settings: AgentSettings) {
        if (endpointDedupMinutes != settings.passiveAiEndpointDedupMinutes) {
            endpointDedupMinutes = settings.passiveAiEndpointDedupMinutes
        }
        if (responseFingerprintDedupMinutes != settings.passiveAiResponseFingerprintDedupMinutes) {
            responseFingerprintDedupMinutes = settings.passiveAiResponseFingerprintDedupMinutes
        }
        if (promptCacheTtlMinutes != settings.passiveAiPromptCacheTtlMinutes) {
            promptCacheTtlMinutes = settings.passiveAiPromptCacheTtlMinutes
        }
        if (endpointCacheEntries != settings.passiveAiEndpointCacheEntries) {
            endpointCacheEntries = settings.passiveAiEndpointCacheEntries
        }
        if (responseFingerprintCacheEntries != settings.passiveAiResponseFingerprintCacheEntries) {
            responseFingerprintCacheEntries = settings.passiveAiResponseFingerprintCacheEntries
        }
        if (promptCacheEntries != settings.passiveAiPromptCacheEntries) {
            promptCacheEntries = settings.passiveAiPromptCacheEntries
        }
        if (requestBodyPromptMaxChars != settings.passiveAiRequestBodyMaxChars) {
            requestBodyPromptMaxChars = settings.passiveAiRequestBodyMaxChars
        }
        if (responseBodyPromptMaxChars != settings.passiveAiResponseBodyMaxChars) {
            responseBodyPromptMaxChars = settings.passiveAiResponseBodyMaxChars
        }
        if (headerMaxCount != settings.passiveAiHeaderMaxCount) {
            headerMaxCount = settings.passiveAiHeaderMaxCount
        }
        if (paramMaxCount != settings.passiveAiParamMaxCount) {
            paramMaxCount = settings.passiveAiParamMaxCount
        }
        val newExcluded = settings.passiveAiExcludedExtensions
            .split(",")
            .map { it.trim().lowercase().removePrefix(".") }
            .filter { it.isNotEmpty() }
            .toSet()
        if (excludedExtensions != newExcluded) {
            excludedExtensions = newExcluded
        }
        // Apply batch size
        val newBatchSize = settings.passiveAiBatchSize.coerceIn(1, 5)
        if (batchQueue.maxBatchSize != newBatchSize) {
            batchQueue.maxBatchSize = newBatchSize
        }
        // Initialize or update persistent cache (project-namespaced)
        if (settings.passiveAiPersistentCacheEnabled) {
            val wantMaxBytes = settings.passiveAiPersistentCacheMaxMb.toLong() * 1024 * 1024
            val wantTtlMs = settings.passiveAiPersistentCacheTtlHours.toLong() * 60 * 60 * 1000
            val current = persistentCache
            if (current == null || current.maxDiskBytes != wantMaxBytes || current.ttlMs != wantTtlMs) {
                val projectSlug = try { api.project().id().take(8) } catch (_: Exception) { "default" }
                val cacheDir = java.io.File(System.getProperty("user.home"), ".burp-ai-agent/cache/$projectSlug")
                persistentCache = com.six2dez.burp.aiagent.cache.PersistentPromptCache(
                    cacheDir = cacheDir,
                    maxDiskBytes = wantMaxBytes,
                    ttlMs = wantTtlMs
                )
            }
        } else {
            persistentCache = null
        }
    }
    
    private fun ensureBackendRunning(settings: AgentSettings): Boolean {
        val targetBackend = settings.preferredBackendId
        val currentStatus = supervisor.status()
        val currentSessionId = supervisor.currentSessionId()
        val currentBackend = currentStatus.backendId

        // Reuse only when the running backend matches the scanner target backend.
        if (currentSessionId != null && currentBackend == targetBackend) {
            return true
        }

        val action = if (currentSessionId == null) "Starting" else "Switching"
        api.logging().logToOutput("[PassiveAiScanner] $action backend: $targetBackend (current=${currentBackend ?: "none"})")
        val started = supervisor.startOrAttach(targetBackend)
        if (started) {
            val ready = waitForBackendSession(maxWaitMs = 10_000L, pollMs = 200L)
            if (ready) {
                api.logging().logToOutput("[PassiveAiScanner] Backend ready: $targetBackend")
                return true
            }
            api.logging().logToError("[PassiveAiScanner] Backend started but session did not become ready in time")
        } else {
            val error = supervisor.lastStartError()
            api.logging().logToError("[PassiveAiScanner] Failed to start backend: $error")
        }

        return supervisor.currentSessionId() != null && supervisor.status().backendId == targetBackend
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
        try { flushBatch(getSettings()) } catch (_: Exception) {}
        batchQueue.clear()
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
            // Flush batch if timeout expired (handles case where no new requests arrive)
            if (batchQueue.shouldFlush()) {
                flushBatch(getSettings())
            }
        } catch (e: Exception) {
            api.logging().logToError("[PassiveAiScanner] Error: ${e.message}")
        }
    }

    private fun doAnalysis(requestResponse: HttpRequestResponse) {
        try {
            val settings = getSettings()
            applyOptimizationSettings(settings)
            val request = requestResponse.request()
            val response = requestResponse.response()

            val requestBodyRaw = runCatching { request.bodyToString() }.getOrDefault("")
            val responseBodyRaw = runCatching { response?.bodyToString().orEmpty() }.getOrDefault("")
            val requestBodyForLocalChecks = truncateWithEllipsis(requestBodyRaw, REQUEST_BODY_LOCAL_CHECK_MAX_CHARS)
            val responseBodyForLocalChecks = truncateWithEllipsis(responseBodyRaw, RESPONSE_BODY_LOCAL_CHECK_MAX_CHARS)

            // Local passive checks (independent of AI backend availability)
            val localFindings = runLocalChecks(request, response, requestBodyForLocalChecks, responseBodyForLocalChecks)
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

            if (shouldSkipAiAfterLocalFindings(localFindings, request, requestBodyRaw)) {
                requestsAnalyzed.incrementAndGet()
                lastAnalysisTime.set(System.currentTimeMillis())
                return
            }
            if (shouldSkipUninterestingTraffic(request, response, responseBodyRaw)) {
                requestsAnalyzed.incrementAndGet()
                lastAnalysisTime.set(System.currentTimeMillis())
                return
            }
            if (shouldSkipRecentlyAnalyzedEndpoint(request)) {
                requestsAnalyzed.incrementAndGet()
                lastAnalysisTime.set(System.currentTimeMillis())
                return
            }
            if (shouldSkipKnownResponseFingerprint(request, response, responseBodyRaw)) {
                requestsAnalyzed.incrementAndGet()
                lastAnalysisTime.set(System.currentTimeMillis())
                return
            }

            // Ensure backend is running for AI analysis
            if (!ensureBackendRunning(settings)) {
                api.logging().logToError("[PassiveAiScanner] No AI backend available - skipping analysis")
                return
            }

            val nowMs = System.currentTimeMillis()
            val backoffUntil = aiBackoffUntilMs.get()
            if (backoffUntil > nowMs) {
                maybeLogBackoff(nowMs, backoffUntil)
                return
            }

            val params = request.parameters()
                .asSequence()
                .filterNot { cacheBustingParamRegex.matches(it.name().trim()) }
                .take(paramMaxCount)
                .map { p ->
                    val value = truncateWithEllipsis(p.value(), PARAM_VALUE_MAX_CHARS)
                    "${p.name()}=$value (${p.type().name})"
                }
                .toList()

            val requestHeaders = sanitizeHeadersForPrompt(request.headers(), isRequest = true)
            val responseHeaders = sanitizeHeadersForPrompt(response?.headers().orEmpty(), isRequest = false)

            // Extract cookies separately for auth analysis
            val cookies = request.headers()
                .filter { it.name().equals("Cookie", ignoreCase = true) }
                .flatMap { it.value().split(";").map { c -> c.trim() } }
                .take(COOKIES_MAX_COUNT)

            // Check for auth headers
            val authHeaders = request.headers()
                .filter { h ->
                    h.name().equals("Authorization", ignoreCase = true) ||
                        h.name().equals("X-API-Key", ignoreCase = true) ||
                        h.name().equals("X-Auth-Token", ignoreCase = true)
                }
                .map { "${it.name()}: ${it.value().take(50)}..." }

            // Parse URI once for host and path extraction
            val parsedUri = runCatching { java.net.URI(request.url()) }.getOrNull()
            val host = parsedUri?.host.orEmpty()
            if (host.isNotBlank() && response != null) {
                val techHints = mutableSetOf<String>()
                response.headers().forEach { h ->
                    val name = h.name().lowercase()
                    val value = h.value().trim()
                    when (name) {
                        "server" -> if (value.isNotBlank()) techHints.add(value.split("/").first().trim())
                        "x-powered-by" -> if (value.isNotBlank()) techHints.add(value.split("/").first().trim())
                        "x-aspnet-version" -> techHints.add("ASP.NET")
                        "x-generator" -> if (value.isNotBlank()) techHints.add(value.split(" ").first().trim())
                    }
                }
                if (techHints.isNotEmpty()) ScanKnowledgeBase.recordTechStack(host, techHints)

                val authCookieNames = cookies
                    .mapNotNull { it.split("=").firstOrNull()?.trim() }
                    .filter { authCookieHint.containsMatchIn(it) }
                    .toSet()
                if (authHeaders.isNotEmpty() || authCookieNames.isNotEmpty()) {
                    ScanKnowledgeBase.recordAuthInfo(host, ScanKnowledgeBase.AuthInfo(
                        hasSessionCookies = authCookieNames.isNotEmpty(),
                        hasAuthHeader = authHeaders.any { it.startsWith("Authorization:", ignoreCase = true) },
                        hasApiKey = authHeaders.any { it.contains("API-Key", ignoreCase = true) || it.contains("X-API", ignoreCase = true) },
                        authCookieNames = authCookieNames
                    ))
                }
            }

            // Extract path segments for IDOR/BOLA analysis
            val urlPath = parsedUri?.path.orEmpty()

            // Look for potential object IDs in URL
            val potentialIds = POTENTIAL_IDS_REGEX
                .findAll(urlPath + "?" + params.joinToString("&"))
                .map { it.value }
                .distinct()
                .take(POTENTIAL_IDS_MAX_COUNT)
                .toList()

            // Extract JS endpoints from JavaScript responses
            val mime = response?.statedMimeType()?.name?.lowercase().orEmpty()
            val inferredMime = response?.inferredMimeType()?.name?.lowercase().orEmpty()
            val isJsResponse = mime == "javascript" || mime == "script" || inferredMime == "javascript" || inferredMime == "script"
            if (isJsResponse) {
                extractAndLogJsEndpoints(request, responseBodyRaw)
                // Skip AI analysis for JS assets — endpoint extraction is sufficient
                requestsAnalyzed.incrementAndGet()
                lastAnalysisTime.set(System.currentTimeMillis())
                return
            }

            val redactionPolicy = RedactionPolicy.fromMode(settings.privacyMode)
            val displayUrl = redactUrlForPrompt(request.url(), redactionPolicy, settings.hostAnonymizationSalt)
            val requestBody = buildCompactRequestBody(requestBodyRaw, request.headerValue("Content-Type").orEmpty())
            val responseBody = buildCompactResponseBody(responseBodyRaw, response?.headerValue("Content-Type").orEmpty())

            val metadataText = buildString {
                // Include knowledge base context if available
                val kbSummary = ScanKnowledgeBase.buildContextSummary(host)
                if (!kbSummary.isNullOrBlank()) {
                    appendLine("=== PRIOR KNOWLEDGE ===")
                    appendLine(kbSummary)
                    appendLine()
                }
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
                    params.forEach { appendLine(it) }
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

            // Single-item prompt cache check
            val singlePrompt = buildAnalysisPrompt(safeMetadataText, settings.passiveAiMinSeverity.name)
            val singlePromptHash = sha256Hex(singlePrompt)
            val cachedIssues = promptResultCacheValue(singlePromptHash)
            if (cachedIssues != null) {
                handleParsedAiIssues(cachedIssues, requestResponse, settings.passiveAiMinSeverity.name)
                requestsAnalyzed.incrementAndGet()
                lastAnalysisTime.set(System.currentTimeMillis())
                TokenTracker.record(
                    flow = "passive_scanner",
                    backendId = settings.preferredBackendId,
                    inputChars = singlePrompt.length,
                    outputChars = 0,
                    cacheHit = true
                )
                audit.logEvent(
                    "passive_ai_scan_cache_hit",
                    mapOf(
                        "url" to request.url(),
                        "method" to request.method(),
                        "status" to (response?.statusCode() ?: 0).toString(),
                        "promptChars" to singlePrompt.length.toString(),
                        "issues" to cachedIssues.size.toString()
                    )
                )
                return
            }

            // Batch mode: enqueue and flush when ready
            val batchSize = settings.passiveAiBatchSize.coerceIn(1, 5)
            if (batchSize > 1) {
                batchQueue.enqueue(PendingAnalysis(
                    metadata = safeMetadataText,
                    requestResponse = requestResponse,
                    minSeverity = settings.passiveAiMinSeverity.name,
                    host = host.lowercase()
                ))
                if (batchQueue.shouldFlush()) {
                    flushBatch(settings)
                }
                return
            }

            // Single-request mode: send directly to AI backend
            val responseBuffer = StringBuilder()
            val completionLatch = CountDownLatch(1)
            val errorRef = AtomicReference<String?>(null)
            val traceId = "scanner-job-" + UUID.randomUUID().toString()
            val sendStartMs = System.currentTimeMillis()

            supervisor.send(
                text = singlePrompt,
                history = emptyList(),
                contextJson = null,
                privacyMode = settings.privacyMode,
                determinismMode = settings.determinismMode,
                onChunk = { chunk -> responseBuffer.append(chunk) },
                onComplete = { err ->
                    errorRef.set(err?.message)
                    completionLatch.countDown()
                },
                traceId = traceId,
                jsonMode = true,
                maxOutputTokens = Defaults.SCANNER_MAX_OUTPUT_TOKENS
            )

            aiRequestLogger?.log(
                type = ActivityType.SCANNER_SEND,
                source = "passive_scanner",
                backendId = settings.preferredBackendId,
                detail = "Passive scan: ${request.method()} ${request.url().take(80)}",
                promptChars = singlePrompt.length,
                metadata = mapOf(
                    "operation" to "scanner_job",
                    "status" to "sent",
                    "traceId" to traceId,
                    "url" to request.url().take(200),
                    "method" to request.method()
                )
            )

            val completed = completionLatch.await(Defaults.PASSIVE_SCAN_TIMEOUT_MS, TimeUnit.MILLISECONDS)
            val durationMs = System.currentTimeMillis() - sendStartMs

            requestsAnalyzed.incrementAndGet()
            lastAnalysisTime.set(System.currentTimeMillis())

            if (!completed) {
                api.logging().logToError("[PassiveAiScanner] Timeout for: ${request.url().take(60)}")
                aiRequestLogger?.log(
                    type = ActivityType.ERROR,
                    source = "passive_scanner",
                    backendId = settings.preferredBackendId,
                    detail = "Passive scan timeout: ${request.method()} ${request.url().take(80)}",
                    durationMs = durationMs,
                    promptChars = singlePrompt.length,
                    metadata = mapOf(
                        "operation" to "scanner_job",
                        "status" to "timeout",
                        "traceId" to traceId,
                        "url" to request.url().take(200),
                        "method" to request.method()
                    )
                )
            } else if (errorRef.get() != null) {
                val err = errorRef.get().orEmpty()
                if (isGeminiCapacityError(err)) {
                    val until = System.currentTimeMillis() + GEMINI_CAPACITY_BACKOFF_MS
                    aiBackoffUntilMs.set(until)
                    maybeLogBackoff(System.currentTimeMillis(), until)
                }
                api.logging().logToError("[PassiveAiScanner] AI error: $err")
                aiRequestLogger?.log(
                    type = ActivityType.ERROR,
                    source = "passive_scanner",
                    backendId = settings.preferredBackendId,
                    detail = "Passive scan error: ${err.take(200)}",
                    durationMs = durationMs,
                    promptChars = singlePrompt.length,
                    metadata = mapOf(
                        "operation" to "scanner_job",
                        "status" to "error",
                        "traceId" to traceId,
                        "url" to request.url().take(200),
                        "method" to request.method()
                    )
                )
            } else if (responseBuffer.isNotEmpty()) {
                val issues = parseIssuesFromAiResponse(responseBuffer.toString())
                putPromptResultCacheValue(singlePromptHash, issues)
                handleParsedAiIssues(issues, requestResponse, settings.passiveAiMinSeverity.name)
                aiRequestLogger?.log(
                    type = ActivityType.RESPONSE_COMPLETE,
                    source = "passive_scanner",
                    backendId = settings.preferredBackendId,
                    detail = "Passive scan completed with ${issues.size} issue(s)",
                    durationMs = durationMs,
                    promptChars = singlePrompt.length,
                    responseChars = responseBuffer.length,
                    metadata = mapOf(
                        "operation" to "scanner_job",
                        "status" to "ok",
                        "traceId" to traceId,
                        "issues" to issues.size.toString(),
                        "url" to request.url().take(200),
                        "method" to request.method()
                    )
                )
            }

            TokenTracker.record(
                flow = "passive_scanner",
                backendId = settings.preferredBackendId,
                inputChars = singlePrompt.length,
                outputChars = responseBuffer.length
            )

            audit.logEvent("passive_ai_scan", mapOf(
                "url" to request.url(),
                "method" to request.method(),
                "status" to (response?.statusCode() ?: 0).toString(),
                "promptChars" to singlePrompt.length.toString(),
                "responseChars" to responseBuffer.length.toString()
            ))
        } catch (e: Exception) {
            api.logging().logToError("[PassiveAiScanner] Error: ${e.javaClass.simpleName}: ${e.message}")
        }
    }

    // JS endpoint discovery cache (track already-discovered endpoints to avoid duplicate logging)
    private val discoveredJsEndpoints = object : LinkedHashMap<String, Long>(512, 0.75f, true) {
        override fun removeEldestEntry(eldest: MutableMap.MutableEntry<String, Long>?): Boolean {
            return size > JS_ENDPOINTS_CACHE_MAX
        }
    }

    private fun extractAndLogJsEndpoints(
        request: burp.api.montoya.http.message.requests.HttpRequest,
        jsBody: String
    ) {
        if (jsBody.length < JS_MIN_BODY_FOR_EXTRACTION) return

        val endpoints = JsEndpointExtractor.extract(jsBody)
        if (endpoints.isEmpty()) return

        val resolved = JsEndpointExtractor.resolveEndpoints(endpoints, request.url())
        val newEndpoints = mutableListOf<String>()

        synchronized(discoveredJsEndpoints) {
            val now = System.currentTimeMillis()
            for (ep in resolved) {
                val prev = discoveredJsEndpoints[ep]
                if (prev == null || now - prev > endpointDedupWindowMs()) {
                    discoveredJsEndpoints[ep] = now
                    newEndpoints.add(ep)
                }
            }
        }

        if (newEndpoints.isEmpty()) return

        val jsUrl = request.url().take(80)
        api.logging().logToOutput("[PassiveAiScanner] JS endpoints discovered from $jsUrl: ${newEndpoints.size} new endpoint(s)")
        for (ep in newEndpoints.take(JS_ENDPOINTS_LOG_MAX)) {
            api.logging().logToOutput("[PassiveAiScanner]   -> $ep")
        }
        if (newEndpoints.size > JS_ENDPOINTS_LOG_MAX) {
            api.logging().logToOutput("[PassiveAiScanner]   ... and ${newEndpoints.size - JS_ENDPOINTS_LOG_MAX} more")
        }

        aiRequestLogger?.log(
            type = com.six2dez.burp.aiagent.audit.ActivityType.SCANNER_SEND,
            source = "js_endpoint_discovery",
            backendId = "local",
            detail = "Discovered ${newEndpoints.size} endpoint(s) from JS: $jsUrl",
            metadata = mapOf(
                "operation" to "js_discovery",
                "jsUrl" to jsUrl,
                "endpoints" to newEndpoints.take(20).joinToString(", ")
            )
        )
    }

    private fun truncateWithEllipsis(text: String, maxChars: Int): String {
        if (text.length <= maxChars) return text
        return text.take(maxChars) + "..."
    }

    private fun endpointDedupWindowMs(): Long {
        return endpointDedupMinutes.toLong().coerceAtLeast(1L) * 60_000L
    }

    private fun responseFingerprintDedupWindowMs(): Long {
        return responseFingerprintDedupMinutes.toLong().coerceAtLeast(1L) * 60_000L
    }

    private fun promptCacheTtlMs(): Long {
        return promptCacheTtlMinutes.toLong().coerceAtLeast(1L) * 60_000L
    }

    private fun <K, V> trimLruCache(cache: LinkedHashMap<K, V>, maxEntries: Int) {
        while (cache.size > maxEntries) {
            val iterator = cache.entries.iterator()
            if (!iterator.hasNext()) return
            iterator.next()
            iterator.remove()
        }
    }

    private fun shouldSkipAiAfterLocalFindings(
        localFindings: List<LocalFinding>,
        request: burp.api.montoya.http.message.requests.HttpRequest,
        requestBody: String
    ): Boolean {
        if (localFindings.isEmpty()) return false
        val hasHighConfidenceLocal = localFindings.any { it.confidence >= LOCAL_FINDING_SKIP_CONFIDENCE }
        if (!hasHighConfidenceLocal) return false
        val hasInterestingInput = request.parameters().isNotEmpty() ||
            requestBody.length > MIN_BODY_SIZE_FOR_AI ||
            request.method().uppercase() in setOf("POST", "PUT", "PATCH", "DELETE")
        return !hasInterestingInput
    }

    private fun shouldSkipUninterestingTraffic(
        request: burp.api.montoya.http.message.requests.HttpRequest,
        response: burp.api.montoya.http.message.responses.HttpResponse?,
        responseBody: String
    ): Boolean {
        val status = response?.statusCode() ?: return false
        if (status == 204.toShort() || status == 304.toShort()) return true
        val path = runCatching { URI(request.url()).path.orEmpty().lowercase() }.getOrDefault("")
        if (path.isNotBlank() && staticAssetPathRegex.containsMatchIn(path)) return true
        if (responseBody.length < MIN_RESPONSE_BODY_CHARS && !hasInterestingResponseHeaders(response)) return true
        return false
    }

    private fun hasInterestingResponseHeaders(response: burp.api.montoya.http.message.responses.HttpResponse): Boolean {
        return response.headers().any { header ->
            val name = header.name().lowercase()
            responseHeaderAllowlist.contains(name) || name.startsWith("x-")
        }
    }

    private fun shouldSkipRecentlyAnalyzedEndpoint(
        request: burp.api.montoya.http.message.requests.HttpRequest
    ): Boolean {
        val key = buildEndpointCacheKey(request)
        val now = System.currentTimeMillis()
        synchronized(endpointRecentCache) {
            val previous = endpointRecentCache[key]
            if (previous != null && now - previous < endpointDedupWindowMs()) {
                return true
            }
            endpointRecentCache[key] = now
        }
        return false
    }

    private fun buildEndpointCacheKey(request: burp.api.montoya.http.message.requests.HttpRequest): String {
        val method = request.method().uppercase()
        val uri = runCatching { URI(request.url()) }.getOrNull()
        val normalizedPath = runCatching {
            normalizePathSegments(uri?.path.orEmpty())
        }.getOrElse { normalizePathSegments(request.url()) }
        val host = uri?.host.orEmpty().lowercase()
        val sortedParamNames = uri?.query.orEmpty()
            .split('&')
            .mapNotNull { it.split('=').firstOrNull()?.lowercase()?.ifBlank { null } }
            .filter { !cacheBustingParamRegex.matches(it) }
            .sorted()
            .joinToString(",")
        return "$method:$host:$normalizedPath:$sortedParamNames"
    }

    private fun normalizePathSegments(path: String): String {
        return IssueUtils.normalizePathSegments(path)
    }

    private fun shouldSkipKnownResponseFingerprint(
        request: burp.api.montoya.http.message.requests.HttpRequest,
        response: burp.api.montoya.http.message.responses.HttpResponse?,
        responseBody: String
    ): Boolean {
        val fingerprint = buildResponseFingerprint(request, response, responseBody) ?: return false
        val now = System.currentTimeMillis()
        synchronized(responseFingerprintCache) {
            val previous = responseFingerprintCache[fingerprint]
            if (previous != null && now - previous < responseFingerprintDedupWindowMs()) {
                return true
            }
            responseFingerprintCache[fingerprint] = now
        }
        return false
    }

    private fun buildResponseFingerprint(
        request: burp.api.montoya.http.message.requests.HttpRequest,
        response: burp.api.montoya.http.message.responses.HttpResponse?,
        responseBody: String
    ): String? {
        if (response == null) return null
        val headers = sanitizeHeadersForPrompt(response.headers(), isRequest = false)
            .take(10)
            .joinToString("\n")
        val bodyPrefix = stripDynamicValues(responseBody.take(RESPONSE_FINGERPRINT_BODY_PREFIX_CHARS))
        val raw = buildString {
            append(request.method()).append('\n')
            append(IssueUtils.normalizeUrl(request.url())).append('\n')
            append(response.statusCode()).append('\n')
            append(headers).append('\n')
            append(bodyPrefix)
        }
        return sha256Hex(raw)
    }

    private fun stripDynamicValues(text: String): String {
        return dynamicValueStripRegex.replace(text, "{DYN}")
    }

    private fun sanitizeHeadersForPrompt(
        headers: List<burp.api.montoya.http.message.HttpHeader>,
        isRequest: Boolean
    ): List<String> {
        return headers.asSequence()
            .filter { header ->
                val name = header.name().lowercase()
                if (name in headerNoiseDenylist) return@filter false
                if (name.startsWith("x-")) return@filter true
                if (name.contains("auth") || name.contains("token") || name.contains("cookie")) return@filter true
                if (isRequest) {
                    name in requestHeaderAllowlist
                } else {
                    name in responseHeaderAllowlist
                }
            }
            .take(headerMaxCount)
            .map { header ->
                val value = truncateWithEllipsis(header.value(), HEADER_VALUE_MAX_CHARS)
                "${header.name()}: $value"
            }
            .toList()
    }

    private fun buildCompactRequestBody(body: String, contentType: String): String {
        if (body.isBlank()) return ""
        return if (looksLikeJson(contentType, body)) {
            compactJsonBody(body, requestBodyPromptMaxChars)
        } else {
            truncateWithEllipsis(body, requestBodyPromptMaxChars)
        }
    }

    private fun buildCompactResponseBody(body: String, contentType: String): String {
        if (body.isBlank()) return ""
        val base = if (looksLikeJson(contentType, body)) {
            compactJsonBody(body, responseBodyPromptMaxChars)
        } else if (contentType.contains("html", ignoreCase = true) || body.contains("<html", ignoreCase = true)) {
            compactHtmlBody(body, responseBodyPromptMaxChars)
        } else {
            truncateWithEllipsis(body, responseBodyPromptMaxChars)
        }
        // Append security-relevant excerpts from deeper in the response that truncation may have cut off
        val excerpts = SecurityExcerpts.extract(body, base.length)
        return if (excerpts.isNullOrBlank()) base else "$base\n\n=== SECURITY-RELEVANT EXCERPTS ===\n$excerpts"
    }

    private fun looksLikeJson(contentType: String, body: String): Boolean {
        val trimmed = body.trimStart()
        return contentType.contains("json", ignoreCase = true) ||
            trimmed.startsWith("{") ||
            trimmed.startsWith("[")
    }

    private fun compactJsonBody(body: String, maxChars: Int): String {
        val node = runCatching { jsonMapper.readTree(body) }.getOrNull()
        if (node == null) return truncateWithEllipsis(body, maxChars)
        if (node.isArray && node.size() > JSON_ARRAY_SAMPLE_SIZE) {
            val sample = jsonMapper.createArrayNode()
            val iterator = node.elements()
            var added = 0
            while (iterator.hasNext() && added < JSON_ARRAY_SAMPLE_SIZE) {
                sample.add(iterator.next())
                added++
            }
            val summarized = buildString {
                append(sample.toString())
                append("\n...[array truncated: ")
                append(node.size() - JSON_ARRAY_SAMPLE_SIZE)
                append(" more item(s)]...")
            }
            return truncateWithEllipsis(summarized, maxChars)
        }
        return truncateWithEllipsis(node.toString(), maxChars)
    }

    private fun compactHtmlBody(body: String, maxChars: Int): String {
        val head = Regex("(?is)<head[^>]*>(.*?)</head>").find(body)?.groupValues?.getOrNull(1).orEmpty().trim()
        val forms = Regex("(?is)<form\\b[^>]*>.*?</form>").findAll(body)
            .map { it.value.trim() }
            .take(HTML_FORMS_SAMPLE_MAX)
            .toList()
        val scripts = Regex("(?is)<script(?![^>]*\\bsrc=)[^>]*>.*?</script>").findAll(body)
            .map { it.value.trim() }
            .take(HTML_INLINE_SCRIPTS_SAMPLE_MAX)
            .toList()
        if (head.isBlank() && forms.isEmpty() && scripts.isEmpty()) {
            return truncateWithEllipsis(body, maxChars)
        }
        val summarized = buildString {
            if (head.isNotBlank()) {
                appendLine("HEAD:")
                appendLine(truncateWithEllipsis(head, 1200))
                appendLine()
            }
            if (forms.isNotEmpty()) {
                appendLine("FORMS:")
                forms.forEachIndexed { index, form ->
                    appendLine("[$index] ${truncateWithEllipsis(form, 1200)}")
                }
                appendLine()
            }
            if (scripts.isNotEmpty()) {
                appendLine("INLINE_SCRIPTS:")
                scripts.forEachIndexed { index, script ->
                    appendLine("[$index] ${truncateWithEllipsis(script, 1200)}")
                }
            }
        }.trim()
        return truncateWithEllipsis(summarized, maxChars)
    }

    private fun promptResultCacheValue(promptHash: String): List<AiIssueItem>? {
        val now = System.currentTimeMillis()
        // Check in-memory cache first
        synchronized(promptResultCache) {
            val cached = promptResultCache[promptHash]
            if (cached != null) {
                if (now - cached.createdAtMs > promptCacheTtlMs()) {
                    promptResultCache.remove(promptHash)
                } else {
                    return cached.issues
                }
            }
        }
        // Fall back to persistent cache
        val diskEntry = persistentCache?.get(promptHash) ?: return null
        val issues = diskEntry.issues.map { ci ->
            AiIssueItem(
                reasoning = ci.reasoning,
                title = ci.title,
                severity = ci.severity,
                detail = ci.detail,
                confidence = ci.confidence,
                requestIndex = ci.requestIndex
            )
        }
        // Promote to in-memory cache
        synchronized(promptResultCache) {
            promptResultCache[promptHash] = CachedAiIssues(
                createdAtMs = diskEntry.createdAtMs,
                issues = issues
            )
        }
        return issues
    }

    private fun putPromptResultCacheValue(promptHash: String, issues: List<AiIssueItem>) {
        val now = System.currentTimeMillis()
        synchronized(promptResultCache) {
            promptResultCache[promptHash] = CachedAiIssues(
                createdAtMs = now,
                issues = issues
            )
        }
        // Write to persistent cache
        persistentCache?.put(promptHash, com.six2dez.burp.aiagent.cache.CachedEntry(
            createdAtMs = now,
            issues = issues.map { ai ->
                com.six2dez.burp.aiagent.cache.CachedIssue(
                    reasoning = ai.reasoning,
                    title = ai.title,
                    severity = ai.severity,
                    detail = ai.detail,
                    confidence = ai.confidence,
                    requestIndex = ai.requestIndex
                )
            }
        ))
    }

    private fun sha256Hex(text: String): String = Hashing.sha256Hex(text)

    private fun buildAnalysisPrompt(metadata: String, minSeverity: String): String {
        val severityInstruction = when (minSeverity) {
            "CRITICAL" -> "Severity filter: only CRITICAL."
            "HIGH" -> "Severity filter: HIGH or CRITICAL."
            "MEDIUM" -> "Severity filter: MEDIUM/HIGH/CRITICAL."
            else -> "Severity filter: LOW/MEDIUM/HIGH/CRITICAL."
        }

        return """
You are a security researcher. Analyze this HTTP traffic for real vulnerabilities.
$severityInstruction

SEVERITY DEFINITIONS:
- Critical: RCE, authentication bypass, full account takeover
- High: SQLi, stored XSS, SSRF with internal access, deserialization
- Medium: Reflected XSS, IDOR/BOLA, CSRF on sensitive actions, open redirect
- Low: Information disclosure, verbose errors, minor misconfigurations

CHECK: Injection (XSS/SQLi/CMDI/SSTI/SSRF/XXE/NoSQL), Auth (IDOR/BOLA/BAC/CSRF/JWT), Info disclosure (secrets/debug/source), Config (CORS/open redirect), High-value (ATO/cache poison/smuggling/host-header), API (version bypass/GraphQL).

DO NOT REPORT:
- Missing security headers (CSP, X-Frame-Options, HSTS, X-Content-Type-Options) as standalone findings
- "Potential" issues without concrete evidence in the request/response
- Generic reflection without XSS context (e.g., parameter echoed in non-executable context)
- Absence of rate limiting as a vulnerability

RULES: Evidence required — provide step-by-step evidence chain in reasoning. No speculation. Confidence >=85 only. Output JSON array only.
Output schema: [{"reasoning":"step-by-step evidence chain","title":"...","severity":"Critical|High|Medium|Low|Information","detail":"...with evidence","confidence":0-100}]
Return [] when no supported issue exists.

HTTP DATA:
$metadata
""".trim()
    }

    private fun buildBatchAnalysisPrompt(items: List<PendingAnalysis>): String {
        val severityInstruction = when (items.first().minSeverity) {
            "CRITICAL" -> "Severity filter: only CRITICAL."
            "HIGH" -> "Severity filter: HIGH or CRITICAL."
            "MEDIUM" -> "Severity filter: MEDIUM/HIGH/CRITICAL."
            else -> "Severity filter: LOW/MEDIUM/HIGH/CRITICAL."
        }

        val batchMetadata = items.mapIndexed { index, item ->
            "=== REQUEST #${index + 1} ===\n${item.metadata}"
        }.joinToString("\n\n")

        return """
You are a security researcher. Analyze these ${items.size} HTTP requests for real vulnerabilities.
$severityInstruction

SEVERITY DEFINITIONS:
- Critical: RCE, authentication bypass, full account takeover
- High: SQLi, stored XSS, SSRF with internal access, deserialization
- Medium: Reflected XSS, IDOR/BOLA, CSRF on sensitive actions, open redirect
- Low: Information disclosure, verbose errors, minor misconfigurations

CHECK: Injection (XSS/SQLi/CMDI/SSTI/SSRF/XXE/NoSQL), Auth (IDOR/BOLA/BAC/CSRF/JWT), Info disclosure (secrets/debug/source), Config (CORS/open redirect), High-value (ATO/cache poison/smuggling/host-header), API (version bypass/GraphQL).
Also CHECK cross-request issues: IDOR by comparing endpoints, BAC by comparing access patterns, inconsistent auth.

DO NOT REPORT:
- Missing security headers (CSP, X-Frame-Options, HSTS, X-Content-Type-Options) as standalone findings
- "Potential" issues without concrete evidence in the request/response
- Generic reflection without XSS context (e.g., parameter echoed in non-executable context)
- Absence of rate limiting as a vulnerability

RULES: Evidence required — provide step-by-step evidence chain in reasoning. No speculation. Confidence >=85 only. Output JSON array only.
Output schema: [{"request_index":1,"reasoning":"step-by-step evidence chain","title":"...","severity":"Critical|High|Medium|Low|Information","detail":"...with evidence","confidence":0-100}]
The request_index field (1-based) indicates which request the finding belongs to.
Return [] when no supported issue exists.

HTTP DATA:
$batchMetadata
""".trim()
    }

    private fun flushBatch(settings: com.six2dez.burp.aiagent.config.AgentSettings) {
        val batch = batchQueue.drain()
        if (batch.isEmpty()) return

        if (batch.size == 1) {
            // Single item: use standard analysis path
            val item = batch.first()
            val prompt = buildAnalysisPrompt(item.metadata, item.minSeverity)
            sendSingleAnalysis(prompt, item.requestResponse, item.minSeverity, settings)
            return
        }

        val prompt = buildBatchAnalysisPrompt(batch)
        val promptHash = sha256Hex(prompt)

        if (!ensureBackendRunning(settings)) {
            // Backend unavailable: fall back to individual analysis when it recovers
            api.logging().logToError("[PassiveAiScanner] Batch backend unavailable, falling back to individual analysis (${batch.size} items)")
            fallbackToIndividualAnalysis(batch, settings)
            return
        }

        val responseBuffer = StringBuilder()
        val completionLatch = CountDownLatch(1)
        val errorRef = AtomicReference<String?>(null)
        val traceId = "scanner-batch-" + UUID.randomUUID().toString()
        val sendStartMs = System.currentTimeMillis()

        supervisor.send(
            text = prompt,
            history = emptyList(),
            contextJson = null,
            privacyMode = settings.privacyMode,
            determinismMode = settings.determinismMode,
            onChunk = { chunk -> responseBuffer.append(chunk) },
            onComplete = { err ->
                errorRef.set(err?.message)
                completionLatch.countDown()
            },
            traceId = traceId,
            jsonMode = true,
            maxOutputTokens = Defaults.SCANNER_BATCH_MAX_OUTPUT_TOKENS
        )

        val completed = completionLatch.await(Defaults.PASSIVE_SCAN_TIMEOUT_MS, TimeUnit.MILLISECONDS)
        val durationMs = System.currentTimeMillis() - sendStartMs

        if (!completed) {
            api.logging().logToError("[PassiveAiScanner] Batch timeout (${batch.size} items), falling back to individual analysis")
            fallbackToIndividualAnalysis(batch, settings)
        } else if (errorRef.get() != null) {
            val err = errorRef.get().orEmpty()
            if (isGeminiCapacityError(err)) {
                val until = System.currentTimeMillis() + GEMINI_CAPACITY_BACKOFF_MS
                aiBackoffUntilMs.set(until)
            }
            api.logging().logToError("[PassiveAiScanner] Batch AI error: $err, falling back to individual analysis")
            fallbackToIndividualAnalysis(batch, settings)
        } else {
            batch.forEach { _ -> requestsAnalyzed.incrementAndGet() }
            lastAnalysisTime.set(System.currentTimeMillis())

            if (responseBuffer.isNotEmpty()) {
                val allIssues = parseIssuesFromAiResponse(responseBuffer.toString())
                putPromptResultCacheValue(promptHash, allIssues)

                // Dispatch issues to their respective requests by request_index
                for (issue in allIssues) {
                    val idx = (issue.requestIndex ?: 1).coerceIn(1, batch.size) - 1
                    handleParsedAiIssues(listOf(issue), batch[idx].requestResponse, batch[idx].minSeverity)
                }

                api.logging().logToOutput("[PassiveAiScanner] Batch completed: ${batch.size} requests, ${allIssues.size} issue(s)")
            }

            TokenTracker.record(
                flow = "passive_scanner",
                backendId = settings.preferredBackendId,
                inputChars = prompt.length,
                outputChars = responseBuffer.length
            )
        }
    }

    private fun fallbackToIndividualAnalysis(
        batch: List<PendingAnalysis>,
        settings: com.six2dez.burp.aiagent.config.AgentSettings
    ) {
        for (item in batch) {
            try {
                val prompt = buildAnalysisPrompt(item.metadata, item.minSeverity)
                sendSingleAnalysis(prompt, item.requestResponse, item.minSeverity, settings)
            } catch (e: Exception) {
                api.logging().logToError("[PassiveAiScanner] Individual fallback failed for ${item.host}: ${e.message}")
                requestsAnalyzed.incrementAndGet()
            }
        }
    }

    private fun sendSingleAnalysis(
        prompt: String,
        requestResponse: HttpRequestResponse,
        minSeverity: String,
        settings: com.six2dez.burp.aiagent.config.AgentSettings
    ) {
        if (!ensureBackendRunning(settings)) return

        val promptHash = sha256Hex(prompt)
        val responseBuffer = StringBuilder()
        val completionLatch = CountDownLatch(1)
        val errorRef = AtomicReference<String?>(null)

        supervisor.send(
            text = prompt,
            history = emptyList(),
            contextJson = null,
            privacyMode = settings.privacyMode,
            determinismMode = settings.determinismMode,
            onChunk = { chunk -> responseBuffer.append(chunk) },
            onComplete = { err ->
                errorRef.set(err?.message)
                completionLatch.countDown()
            },
            traceId = "scanner-job-" + UUID.randomUUID().toString(),
            jsonMode = true,
            maxOutputTokens = Defaults.SCANNER_MAX_OUTPUT_TOKENS
        )

        val completed = completionLatch.await(Defaults.PASSIVE_SCAN_TIMEOUT_MS, TimeUnit.MILLISECONDS)
        requestsAnalyzed.incrementAndGet()
        lastAnalysisTime.set(System.currentTimeMillis())

        if (completed && errorRef.get() == null && responseBuffer.isNotEmpty()) {
            val issues = parseIssuesFromAiResponse(responseBuffer.toString())
            putPromptResultCacheValue(promptHash, issues)
            handleParsedAiIssues(issues, requestResponse, minSeverity)
        }
    }

    private fun handleAiResponse(aiText: String, requestResponse: HttpRequestResponse, minSeverity: String) {
        val issues = parseIssuesFromAiResponse(aiText)
        handleParsedAiIssues(issues, requestResponse, minSeverity)
    }

    private fun handleParsedAiIssues(
        issues: List<AiIssueItem>,
        requestResponse: HttpRequestResponse,
        minSeverity: String
    ) {
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
                    val fullDetail = IssueUtils.formatIssueDetailHtml(fullDetailLines)
                    
                    // Add markers to highlight evidence in response
                    val markedReqResp = IssueMarkerSupport.markResponseFromDetail(requestResponse, sanitizedDetail)

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
                        listOf(markedReqResp)
                    )
                    api.siteMap().add(issue)
                    issuesFound.incrementAndGet()
                    api.logging().logToOutput("[PassiveAiScanner] Issue: $title | $rawSeverity | $confidence%")

                    // Record finding in knowledge base
                    ScanKnowledgeBase.recordVulnSignal(ScanKnowledgeBase.VulnSignal(
                        endpoint = requestResponse.request().url(),
                        vulnClass = title,
                        severity = rawSeverity,
                        confidence = confidence,
                        source = source,
                        evidence = detail.take(200)
                    ))

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
        return IssueUtils.hasEquivalentIssue(
            name = name,
            baseUrl = baseUrl,
            issues = api.siteMap().issues().map { issue -> issue.name() to issue.baseUrl() }
        )
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
            lowerTitle.contains("403 bypass") || lowerTitle.contains("access control bypass") || lowerTitle.contains("forbidden bypass") -> VulnClass.ACCESS_CONTROL_BYPASS

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
            val nameMatch = SERIALIZED_NAME_REGEX
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
        val confidence: Int? = null,
        val requestIndex: Int? = null
    )

    internal fun parseIssuesJson(json: String): List<AiIssueItem> {
        val root = jsonMapper.readTree(json)
        return parseIssuesNode(root)
    }

    internal fun parseIssuesFromAiResponse(text: String): List<AiIssueItem> {
        if (text.isBlank()) return emptyList()
        val cleaned = cleanJsonResponse(text)
        if (cleaned.isBlank() || cleaned == "[]") return emptyList()
        return try {
            parseIssuesJson(cleaned)
        } catch (e: Exception) {
            val preview = text.replace(Regex("\\s+"), " ").take(160)
            api.logging().logToError("[PassiveAiScanner] Failed to parse AI response after cleanup: ${e.message} | preview=$preview")
            emptyList()
        }
    }

    internal fun cleanJsonResponse(text: String): String {
        if (text.isBlank()) return ""
        val cleaned = stripCodeFences(text.trim())
        if (cleaned.isBlank()) return ""

        // Fast path: whole payload is already valid JSON.
        parseNodeIfValid(cleaned)?.let { node ->
            return when {
                node.isArray -> cleaned
                node.isObject && (node.has("issues") || node.has("findings") || node.has("results")) -> cleaned
                else -> ""
            }
        }

        // Fallback: extract the first balanced JSON array/object from mixed CLI output.
        for (candidate in extractBalancedJsonCandidates(cleaned)) {
            val node = parseNodeIfValid(candidate) ?: continue
            if (node.isArray) return candidate
            if (node.isObject && (node.has("issues") || node.has("findings") || node.has("results"))) return candidate
        }
        return ""
    }

    private fun parseIssuesNode(root: JsonNode): List<AiIssueItem> {
        val issueArray = when {
            root.isArray -> root
            root.isObject && root.path("issues").isArray -> root.path("issues")
            root.isObject && root.path("findings").isArray -> root.path("findings")
            root.isObject && root.path("results").isArray -> root.path("results")
            else -> return emptyList()
        }
        return issueArray.mapNotNull { node ->
            runCatching {
                AiIssueItem(
                    reasoning = node.path("reasoning").takeIf { !it.isMissingNode && !it.isNull }?.asText(),
                    title = node.path("title").takeIf { !it.isMissingNode && !it.isNull }?.asText(),
                    severity = node.path("severity").takeIf { !it.isMissingNode && !it.isNull }?.asText(),
                    detail = node.path("detail").takeIf { !it.isMissingNode && !it.isNull }?.asText(),
                    confidence = node.path("confidence").takeIf { !it.isMissingNode && !it.isNull }?.asInt(),
                    requestIndex = node.path("request_index").takeIf { !it.isMissingNode && !it.isNull }?.asInt()
                )
            }.getOrNull()
        }
    }

    private fun parseNodeIfValid(candidate: String): JsonNode? {
        return runCatching { jsonMapper.readTree(candidate) }.getOrNull()
    }

    private fun stripCodeFences(text: String): String {
        return text
            .replace(Regex("^```(?:json)?\\s*", setOf(RegexOption.IGNORE_CASE, RegexOption.MULTILINE)), "")
            .replace(CODE_FENCE_END_REGEX, "")
            .trim()
    }

    private fun extractBalancedJsonCandidates(text: String): Sequence<String> = sequence {
        val openers = setOf('[', '{')
        var start = -1
        var stack = ArrayDeque<Char>()
        var inString = false
        var escaped = false

        for (i in text.indices) {
            val ch = text[i]
            if (inString) {
                if (escaped) {
                    escaped = false
                    continue
                }
                if (ch == '\\') {
                    escaped = true
                    continue
                }
                if (ch == '"') {
                    inString = false
                }
                continue
            }

            if (ch == '"') {
                inString = true
                continue
            }

            if (start < 0 && ch in openers) {
                start = i
                stack = ArrayDeque()
                stack.addLast(ch)
                continue
            }

            if (start >= 0) {
                when (ch) {
                    '[', '{' -> stack.addLast(ch)
                    ']' -> {
                        if (stack.isNotEmpty() && stack.last() == '[') {
                            stack.removeLast()
                        } else {
                            start = -1
                            stack.clear()
                        }
                    }
                    '}' -> {
                        if (stack.isNotEmpty() && stack.last() == '{') {
                            stack.removeLast()
                        } else {
                            start = -1
                            stack.clear()
                        }
                    }
                }
                if (start >= 0 && stack.isEmpty()) {
                    yield(text.substring(start, i + 1).trim())
                    start = -1
                }
            }
        }
    }

    private fun mapSeverity(raw: String): AuditIssueSeverity {
        return when (raw.lowercase()) {
            "critical", "high" -> AuditIssueSeverity.HIGH
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
        val sensitiveKey = SENSITIVE_KEY_REGEX
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

    private fun hasExcludedExtension(url: String): Boolean {
        if (excludedExtensions.isEmpty()) return false
        val path = try { URI(url).path.orEmpty() } catch (_: Exception) { url }
        val lastSegment = path.substringAfterLast('/')
        val ext = lastSegment.substringAfterLast('.', "").lowercase()
        return ext.isNotEmpty() && ext in excludedExtensions
    }

    private fun isStreamingOrRealtimeEndpoint(response: InterceptedResponse): Boolean {
        val request = response.initiatingRequest()
        val reqAccept = request.headerValue("Accept").orEmpty().lowercase()
        if (reqAccept.contains("text/event-stream")) return true

        val reqUpgrade = request.headerValue("Upgrade").orEmpty().lowercase()
        if (reqUpgrade.contains("websocket")) return true

        val respContentType = response.headerValue("Content-Type").orEmpty().lowercase()
        if (respContentType.contains("text/event-stream")) return true

        val respUpgrade = response.headerValue("Upgrade").orEmpty().lowercase()
        if (respUpgrade.contains("websocket")) return true

        val path = try { URI(request.url()).path.orEmpty().lowercase() } catch (_: Exception) { "" }
        if (path.contains("/_ws/") || path.startsWith("/ws") || path.contains("/socket")) return true

        return false
    }

    private fun isGeminiCapacityError(error: String): Boolean {
        val lower = error.lowercase()
        return lower.contains("resource_exhausted") ||
            lower.contains("model_capacity_exhausted") ||
            (lower.contains("status 429") && lower.contains("gemini")) ||
            lower.contains("no capacity available for model")
    }

    private fun maybeLogBackoff(nowMs: Long, untilMs: Long) {
        val prev = lastBackoffLogTime.get()
        if (nowMs - prev < BACKOFF_LOG_INTERVAL_MS) return
        if (lastBackoffLogTime.compareAndSet(prev, nowMs)) {
            val seconds = ((untilMs - nowMs).coerceAtLeast(0L) / 1000L)
            api.logging().logToOutput("[PassiveAiScanner] AI backend backoff active (${seconds}s remaining)")
        }
    }

    private companion object {
        private const val GEMINI_CAPACITY_BACKOFF_MS = 60_000L
        private const val BACKOFF_LOG_INTERVAL_MS = 10_000L
        private const val MIN_DEDUP_TTL_MINUTES = 1
        private const val MAX_DEDUP_TTL_MINUTES = 240
        private const val DEFAULT_ENDPOINT_DEDUP_MINUTES = 30
        private const val DEFAULT_RESPONSE_FINGERPRINT_DEDUP_MINUTES = 30
        private const val DEFAULT_PROMPT_CACHE_TTL_MINUTES = 30
        private const val MIN_ENDPOINT_CACHE_ENTRIES = 100
        private const val MAX_ENDPOINT_CACHE_ENTRIES = 50_000
        private const val DEFAULT_ENDPOINT_CACHE_MAX_ENTRIES = 5_000
        private const val MIN_RESPONSE_FINGERPRINT_CACHE_ENTRIES = 100
        private const val MAX_RESPONSE_FINGERPRINT_CACHE_ENTRIES = 50_000
        private const val DEFAULT_RESPONSE_FINGERPRINT_CACHE_MAX_ENTRIES = 5_000
        private const val MIN_PROMPT_RESULT_CACHE_ENTRIES = 50
        private const val MAX_PROMPT_RESULT_CACHE_ENTRIES = 5_000
        private const val DEFAULT_PROMPT_RESULT_CACHE_MAX_ENTRIES = 500
        private const val RESPONSE_FINGERPRINT_BODY_PREFIX_CHARS = 2_000
        private const val REQUEST_BODY_LOCAL_CHECK_MAX_CHARS = 3_000
        private const val RESPONSE_BODY_LOCAL_CHECK_MAX_CHARS = 6_000
        private const val MIN_REQUEST_BODY_PROMPT_MAX_CHARS = 256
        private const val MAX_REQUEST_BODY_PROMPT_MAX_CHARS = 20_000
        private const val DEFAULT_REQUEST_BODY_PROMPT_MAX_CHARS = 2_000
        private const val MIN_RESPONSE_BODY_PROMPT_MAX_CHARS = 512
        private const val MAX_RESPONSE_BODY_PROMPT_MAX_CHARS = 40_000
        private const val DEFAULT_RESPONSE_BODY_PROMPT_MAX_CHARS = 4_000
        private const val MIN_RESPONSE_BODY_CHARS = 50
        private const val LOCAL_FINDING_SKIP_CONFIDENCE = 90
        private const val MIN_BODY_SIZE_FOR_AI = 80
        private const val MIN_PARAMS_MAX_COUNT = 5
        private const val MAX_PARAMS_MAX_COUNT = 100
        private const val DEFAULT_PARAMS_MAX_COUNT = 15
        private const val PARAM_VALUE_MAX_CHARS = 200
        private const val POTENTIAL_IDS_MAX_COUNT = 10
        private const val MIN_HEADERS_MAX_COUNT = 5
        private const val MAX_HEADERS_MAX_COUNT = 120
        private const val DEFAULT_HEADERS_MAX_COUNT = 40
        private const val HEADER_VALUE_MAX_CHARS = 120
        private const val COOKIES_MAX_COUNT = 6
        private const val JSON_ARRAY_SAMPLE_SIZE = 3
        private const val HTML_FORMS_SAMPLE_MAX = 3
        private const val HTML_INLINE_SCRIPTS_SAMPLE_MAX = 3

        private const val JS_ENDPOINTS_CACHE_MAX = 2_000
        private const val JS_ENDPOINTS_LOG_MAX = 10
        private const val JS_MIN_BODY_FOR_EXTRACTION = 100

        val DEFAULT_EXCLUDED_EXTENSIONS = Defaults.DEFAULT_EXCLUDED_EXTENSIONS

        // Pre-compiled Regex patterns (avoid recompilation in hot paths)
        val POTENTIAL_IDS_REGEX = Regex("\\b([0-9]+|[a-f0-9-]{36}|[a-f0-9]{24})\\b", RegexOption.IGNORE_CASE)
        val SERIALIZED_NAME_REGEX = Regex("(data|payload|serialized|object|state|viewstate)", RegexOption.IGNORE_CASE)
        val CODE_FENCE_END_REGEX = Regex("\\s*```$", RegexOption.MULTILINE)
        val SENSITIVE_KEY_REGEX = Regex("(token|key|auth|session|jwt|cookie|password|secret)", RegexOption.IGNORE_CASE)
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

}
