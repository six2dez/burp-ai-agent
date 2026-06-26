package com.six2dez.burp.aiagent.scanner

import burp.api.montoya.MontoyaApi
import burp.api.montoya.http.message.HttpRequestResponse
import com.six2dez.burp.aiagent.audit.AiRequestLogger
import com.six2dez.burp.aiagent.audit.AuditLogger
import com.six2dez.burp.aiagent.config.AgentSettings
import com.six2dez.burp.aiagent.config.Defaults
import com.six2dez.burp.aiagent.supervisor.AgentSupervisor
import com.six2dez.burp.aiagent.util.BudgetGuard
import java.util.LinkedHashMap
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicLong

class PassiveAiScanner(
    internal val api: MontoyaApi,
    internal val supervisor: AgentSupervisor,
    internal val audit: AuditLogger,
    internal val getSettings: () -> AgentSettings,
) {
    var aiRequestLogger: AiRequestLogger? = null

    private val enabled = AtomicBoolean(false)

    /** CAP-04: per-process budget pause gate. Starts false each Burp run (reversible). */
    private val budgetPaused = AtomicBoolean(false)

    fun setBudgetPaused(on: Boolean) {
        budgetPaused.set(on)
    }

    fun isBudgetPaused(): Boolean = budgetPaused.get()

    /**
     * CAP-04 single budget-consultation point (RESEARCH Open-Q2): evaluate the per-session token
     * budget against the live session totals and drive the pause gate in BOTH directions.
     *
     * - [BudgetGuard.State.CAP] → [setBudgetPaused] `true` (pause passive scanning).
     * - [BudgetGuard.State.WARN] / [BudgetGuard.State.OFF] → [setBudgetPaused] `false` (resume),
     *   which makes the gate genuinely reversible (its KDoc contract) once the cap is raised,
     *   cleared, or usage drops back below it.
     *
     * Called from the scanner's own token-record sites (so a scanner-only run trips the cap —
     * WR-01) and from the chat / settings-apply paths so chat and scanner share ONE evaluation.
     * Returns the resulting [BudgetGuard.State] so EDT callers can refresh their banner from the
     * same decision without re-evaluating. Stays AWT-free: no Swing access here.
     */
    fun reconcileBudget(settings: AgentSettings): BudgetGuard.State {
        val state =
            BudgetGuard.evaluate(
                BudgetGuard.currentSessionTokens(),
                settings.tokenBudgetWarnThreshold,
                settings.tokenBudgetHardCap,
            )
        setBudgetPaused(state == BudgetGuard.State.CAP)
        return state
    }

    internal val requestsAnalyzed = AtomicInteger(0)
    internal val issuesFound = AtomicInteger(0)
    internal val lastAnalysisTime = AtomicLong(0)
    private val lastRequestTime = AtomicLong(0)
    internal val aiBackoffUntilMs = AtomicLong(0)
    internal val lastBackoffLogTime = AtomicLong(0)
    internal val executor =
        Executors.newSingleThreadExecutor { r ->
            Thread(r, "PassiveAiScanner").apply { isDaemon = true }
        }
    internal val findings = ArrayDeque<PassiveAiFinding>(Defaults.FINDINGS_BUFFER_SIZE)

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

    internal val cacheBustingParamRegex = Regex("^(?:_|t|ts|timestamp|cachebust|cb|rnd|nonce)$", RegexOption.IGNORE_CASE)
    internal val dynamicValueStripRegex =
        Regex(
            listOf(
                """\b[a-f0-9]{8}-[a-f0-9]{4}-[1-5][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}\b""", // UUID
                """\b[a-f0-9]{24}\b""", // MongoDB ObjectId
                """\b\d{10,13}\b""", // Unix timestamps (sec/ms)
                """\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}[^\s"',}\]]*""", // ISO 8601
                """(?<=[":=])\s*"?[A-Za-z0-9_\-]{20,}"?""", // Long tokens/nonces
            ).joinToString("|"),
            RegexOption.IGNORE_CASE,
        )
    internal val staticAssetPathRegex =
        Regex(
            "\\.(?:css|js|map|png|jpg|jpeg|gif|svg|ico|woff2?|ttf|eot)(?:\\?|$)",
            RegexOption.IGNORE_CASE,
        )
    internal val requestHeaderAllowlist =
        setOf(
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
            "x-requested-with",
        )
    internal val responseHeaderAllowlist =
        setOf(
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
            "access-control-expose-headers",
        )
    internal val headerNoiseDenylist =
        setOf(
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
            "via",
        )

    internal val endpointRecentCache =
        object : LinkedHashMap<String, Long>(1024, 0.75f, true) {
            override fun removeEldestEntry(eldest: MutableMap.MutableEntry<String, Long>?): Boolean = size > endpointCacheEntries
        }
    internal val responseFingerprintCache =
        object : LinkedHashMap<String, Long>(2048, 0.75f, true) {
            override fun removeEldestEntry(eldest: MutableMap.MutableEntry<String, Long>?): Boolean = size > responseFingerprintCacheEntries
        }
    internal val promptResultCache =
        object : LinkedHashMap<String, CachedAiIssues>(512, 0.75f, true) {
            override fun removeEldestEntry(eldest: MutableMap.MutableEntry<String, CachedAiIssues>?): Boolean = size > promptCacheEntries
        }

    internal val batchQueue = BatchAnalysisQueue()
    internal var persistentCache: com.six2dez.burp.aiagent.cache.PersistentPromptCache? = null

    fun setEnabled(on: Boolean) {
        val wasEnabled = enabled.getAndSet(on)
        if (on) {
            api.logging().logToOutput("[PassiveAiScanner] Enabled - Burp Scanner passive check active (Pro only)")
        } else if (wasEnabled) {
            // Clear accumulated knowledge to prevent cross-scope contamination
            ScanKnowledgeBase.clear()
            api.logging().logToOutput("[PassiveAiScanner] Disabled — knowledge base cleared")
        }
    }

    /**
     * Enqueues a request/response for asynchronous AI deep-analysis.
     * Called by AiPassiveScanCheck.doCheck() after local heuristics run synchronously.
     * Returns immediately — AI findings surface later via api.siteMap().add().
     */
    fun enqueueForScanCheck(requestResponse: HttpRequestResponse) {
        if (!enabled.get()) return
        if (budgetPaused.get()) return // CAP-04: no-op when paused (does NOT clear KB or flip enabled)
        if (supervisor.isBlockedByBurpAiGate()) return
        executor.submit { analyzeManually(requestResponse) }
    }

    /**
     * Package-internal wrapper for the private runLocalChecks() method.
     * Called by AiPassiveScanCheck.doCheck() synchronously to get fast heuristic findings.
     */
    internal fun localChecks(
        request: burp.api.montoya.http.message.requests.HttpRequest,
        response: burp.api.montoya.http.message.responses.HttpResponse?,
    ): List<LocalFinding> =
        runLocalChecks(
            request,
            response,
            request.bodyToString().take(REQUEST_BODY_LOCAL_CHECK_MAX_CHARS),
            response?.bodyToString().orEmpty().take(RESPONSE_BODY_LOCAL_CHECK_MAX_CHARS),
        )

    // applyOptimizationSettings is a public extension function in PassiveAiScannerFilters.kt.

    fun isEnabled(): Boolean = enabled.get()

    fun getStatus(): PassiveAiScannerStatus =
        PassiveAiScannerStatus(
            enabled = enabled.get(),
            requestsAnalyzed = requestsAnalyzed.get(),
            issuesFound = issuesFound.get(),
            lastAnalysisTime = lastAnalysisTime.get(),
            queueSize = 0, // Single-threaded executor
        )

    fun getLastFindings(n: Int): List<PassiveAiFinding> {
        if (n <= 0) return emptyList()
        synchronized(findings) {
            return if (findings.size <= n) findings.toList() else findings.takeLast(n)
        }
    }

    fun shutdown() {
        enabled.set(false)
        try {
            flushBatch(getSettings())
        } catch (_: Exception) {
        }
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

    fun getManualScanProgress(): Triple<Boolean, Int, Int> = Triple(manualScanInProgress.get(), manualScanCompleted.get(), manualScanTotal.get())

    /**
     * Manually scan a list of requests (from context menu).
     * Does not require the passive scanner to be enabled.
     * Returns the number of requests queued for analysis.
     */
    fun manualScan(
        requests: List<HttpRequestResponse>,
        onProgress: (Int, Int) -> Unit = { _, _ -> },
    ): Int {
        if (requests.isEmpty()) return 0
        // CAP-04 / WR-01: manual passive scan is scanner work that enqueues AI analysis, so it must
        // respect the hard-cap pause just like enqueueForScanCheck (line ~356). When paused, queue
        // nothing and return 0 (callers already handle a 0 count) so the advertised spend ceiling is
        // a real ceiling. Does NOT clear the KB or flip the user's enabled toggle. Chat stays usable.
        if (budgetPaused.get()) {
            api.logging().logToOutput("[PassiveAiScanner] Manual scan skipped — token hard cap reached")
            return 0
        }

        val total = requests.size
        manualScanTotal.set(total)
        manualScanCompleted.set(0)
        manualScanInProgress.set(true)

        api.logging().logToOutput("[PassiveAiScanner] Manual scan started: $total requests queued")

        requests.forEachIndexed { index, reqRes ->
            executor.submit {
                val url =
                    try {
                        reqRes.request().url()
                    } catch (_: Exception) {
                        "unknown"
                    }
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
                        api.logging().logToOutput(
                            "[PassiveAiScanner] Manual scan complete: $total requests analyzed, $issuesCreated issues found",
                        )
                    }
                }
            }
        }

        return total
    }

    // doAnalysis, analyzeManually, analyzeInBackground, flushBatch,
    // fallbackToIndividualAnalysis, sendSingleAnalysis, ensureBackendRunning,
    // waitForBackendSession, redactUrlForPrompt, redactSensitiveQuery, hasExcludedExtension,
    // isGeminiCapacityError, maybeLogBackoff, extractAndLogJsEndpoints, reconcileBudgetAndLog
    // are internal extension functions in PassiveAiScannerAnalysis.kt.

    // JS endpoint discovery cache — map is owned here; extension functions access it by name.
    internal val discoveredJsEndpointsMap =
        object : java.util.LinkedHashMap<String, Long>(512, 0.75f, true) {
            override fun removeEldestEntry(eldest: MutableMap.MutableEntry<String, Long>?): Boolean = size > JS_ENDPOINTS_CACHE_MAX
        }

    private companion object {
        // Dedup TTL limits (used by @Volatile property setters)
        private const val MIN_DEDUP_TTL_MINUTES = 1
        private const val MAX_DEDUP_TTL_MINUTES = 240
        private const val DEFAULT_ENDPOINT_DEDUP_MINUTES = 30
        private const val DEFAULT_RESPONSE_FINGERPRINT_DEDUP_MINUTES = 30
        private const val DEFAULT_PROMPT_CACHE_TTL_MINUTES = 30

        // Cache entry limits
        private const val MIN_ENDPOINT_CACHE_ENTRIES = 100
        private const val MAX_ENDPOINT_CACHE_ENTRIES = 50_000
        private const val DEFAULT_ENDPOINT_CACHE_MAX_ENTRIES = 5_000
        private const val MIN_RESPONSE_FINGERPRINT_CACHE_ENTRIES = 100
        private const val MAX_RESPONSE_FINGERPRINT_CACHE_ENTRIES = 50_000
        private const val DEFAULT_RESPONSE_FINGERPRINT_CACHE_MAX_ENTRIES = 5_000
        private const val MIN_PROMPT_RESULT_CACHE_ENTRIES = 50
        private const val MAX_PROMPT_RESULT_CACHE_ENTRIES = 5_000
        private const val DEFAULT_PROMPT_RESULT_CACHE_MAX_ENTRIES = 500

        // Body truncation for localChecks() (called from class body)
        private const val REQUEST_BODY_LOCAL_CHECK_MAX_CHARS = 3_000
        private const val RESPONSE_BODY_LOCAL_CHECK_MAX_CHARS = 6_000

        // Prompt size limits
        private const val MIN_REQUEST_BODY_PROMPT_MAX_CHARS = 256
        private const val MAX_REQUEST_BODY_PROMPT_MAX_CHARS = 20_000
        private const val DEFAULT_REQUEST_BODY_PROMPT_MAX_CHARS = 2_000
        private const val MIN_RESPONSE_BODY_PROMPT_MAX_CHARS = 512
        private const val MAX_RESPONSE_BODY_PROMPT_MAX_CHARS = 40_000
        private const val DEFAULT_RESPONSE_BODY_PROMPT_MAX_CHARS = 4_000

        // Header/param count limits
        private const val MIN_PARAMS_MAX_COUNT = 5
        private const val MAX_PARAMS_MAX_COUNT = 100
        private const val DEFAULT_PARAMS_MAX_COUNT = 15
        private const val MIN_HEADERS_MAX_COUNT = 5
        private const val MAX_HEADERS_MAX_COUNT = 120
        private const val DEFAULT_HEADERS_MAX_COUNT = 40

        // JS endpoint discovery cache size (used by discoveredJsEndpointsMap field init)
        private const val JS_ENDPOINTS_CACHE_MAX = 2_000

        val DEFAULT_EXCLUDED_EXTENSIONS = Defaults.DEFAULT_EXCLUDED_EXTENSIONS
    }
}
