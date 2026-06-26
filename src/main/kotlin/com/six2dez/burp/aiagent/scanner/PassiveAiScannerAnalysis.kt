package com.six2dez.burp.aiagent.scanner

import burp.api.montoya.http.message.HttpRequestResponse
import com.six2dez.burp.aiagent.audit.ActivityType
import com.six2dez.burp.aiagent.audit.AuditLogger
import com.six2dez.burp.aiagent.config.AgentSettings
import com.six2dez.burp.aiagent.config.Defaults
import com.six2dez.burp.aiagent.redact.PrivacyMode
import com.six2dez.burp.aiagent.redact.Redaction
import com.six2dez.burp.aiagent.redact.RedactionPolicy
import com.six2dez.burp.aiagent.redact.SecretTripwire
import com.six2dez.burp.aiagent.util.BudgetGuard
import com.six2dez.burp.aiagent.util.TokenTracker
import java.net.URI
import java.util.UUID
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicReference

// AWT-free contract: MUST NOT import java.awt.* or javax.swing.*

// Redeclared from PassiveAiScanner companion (private there, needed here for extension functions)
private const val GEMINI_CAPACITY_BACKOFF_MS = 60_000L
private const val BACKOFF_LOG_INTERVAL_MS = 10_000L
private const val POTENTIAL_IDS_MAX_COUNT = 10
private const val PARAM_VALUE_MAX_CHARS = 200
private const val COOKIES_MAX_COUNT = 6
private const val REQUEST_BODY_LOCAL_CHECK_MAX_CHARS = 3_000
private const val RESPONSE_BODY_LOCAL_CHECK_MAX_CHARS = 6_000

// JS discovery limits (companion-private; redeclared for extension use)
private const val JS_MIN_BODY_FOR_EXTRACTION = 100
private const val JS_ENDPOINTS_LOG_MAX = 10

private val POTENTIAL_IDS_REGEX = Regex("\\b([0-9]+|[a-f0-9-]{36}|[a-f0-9]{24})\\b", RegexOption.IGNORE_CASE)
private val SENSITIVE_KEY_REGEX = Regex("(token|key|auth|session|jwt|cookie|password|secret)", RegexOption.IGNORE_CASE)

// ---- budget helpers ----

internal fun PassiveAiScanner.reconcileBudgetAndLog(settings: AgentSettings) {
    val wasPaused = isBudgetPaused()
    val state = reconcileBudget(settings)
    if (state == BudgetGuard.State.CAP && !wasPaused) {
        api.logging().logToOutput("[PassiveAiScanner] Token hard cap reached — pausing passive scanning")
    }
}

// ---- backend lifecycle ----

internal fun PassiveAiScanner.ensureBackendRunning(settings: AgentSettings): Boolean {
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

internal fun PassiveAiScanner.waitForBackendSession(
    maxWaitMs: Long,
    pollMs: Long,
): Boolean {
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

// ---- JS endpoint extraction ----

internal fun PassiveAiScanner.extractAndLogJsEndpoints(
    request: burp.api.montoya.http.message.requests.HttpRequest,
    jsBody: String,
) {
    if (jsBody.length < JS_MIN_BODY_FOR_EXTRACTION) return

    val endpoints = JsEndpointExtractor.extract(jsBody)
    if (endpoints.isEmpty()) return

    val resolved = JsEndpointExtractor.resolveEndpoints(endpoints, request.url())
    val newEndpoints = mutableListOf<String>()

    synchronized(discoveredJsEndpointsMap) {
        val now = System.currentTimeMillis()
        for (ep in resolved) {
            val prev = discoveredJsEndpointsMap[ep]
            if (prev == null || now - prev > endpointDedupWindowMs()) {
                discoveredJsEndpointsMap[ep] = now
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
        type = ActivityType.SCANNER_SEND,
        source = "js_endpoint_discovery",
        backendId = "local",
        detail = "Discovered ${newEndpoints.size} endpoint(s) from JS: $jsUrl",
        metadata =
            mapOf(
                "operation" to "js_discovery",
                "jsUrl" to jsUrl,
                "endpoints" to newEndpoints.take(20).joinToString(", "),
            ),
    )
}

// ---- analysis flow ----

internal fun PassiveAiScanner.analyzeManually(requestResponse: HttpRequestResponse) {
    try {
        doAnalysis(requestResponse)
    } catch (e: Exception) {
        api.logging().logToError("[PassiveAiScanner] Manual scan error: ${e.message}")
    }
}

internal fun PassiveAiScanner.analyzeInBackground(requestResponse: HttpRequestResponse) {
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

@Suppress("CyclomaticComplexMethod", "LongMethod")
internal fun PassiveAiScanner.doAnalysis(requestResponse: HttpRequestResponse) {
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
                "local",
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

        val params =
            request
                .parameters()
                .asSequence()
                .filterNot { cacheBustingParamRegex.matches(it.name().trim()) }
                .take(paramMaxCount)
                .map { p ->
                    val value = truncateWithEllipsis(p.value(), PARAM_VALUE_MAX_CHARS)
                    "${p.name()}=$value (${p.type().name})"
                }.toList()

        val requestHeaders = sanitizeHeadersForPrompt(request.headers(), isRequest = true)
        val responseHeaders = sanitizeHeadersForPrompt(response?.headers().orEmpty(), isRequest = false)

        // Extract cookies separately for auth analysis
        val cookies =
            request
                .headers()
                .filter { it.name().equals("Cookie", ignoreCase = true) }
                .flatMap { it.value().split(";").map { c -> c.trim() } }
                .take(COOKIES_MAX_COUNT)

        // Check for auth headers
        val authHeaders =
            request
                .headers()
                .filter { h ->
                    h.name().equals("Authorization", ignoreCase = true) ||
                        h.name().equals("X-API-Key", ignoreCase = true) ||
                        h.name().equals("X-Auth-Token", ignoreCase = true)
                }.map { "${it.name()}: ${it.value().take(50)}..." }

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

            val authCookieNames =
                cookies
                    .mapNotNull { it.split("=").firstOrNull()?.trim() }
                    .filter { authCookieHint.containsMatchIn(it) }
                    .toSet()
            if (authHeaders.isNotEmpty() || authCookieNames.isNotEmpty()) {
                ScanKnowledgeBase.recordAuthInfo(
                    host,
                    ScanKnowledgeBase.AuthInfo(
                        hasSessionCookies = authCookieNames.isNotEmpty(),
                        hasAuthHeader = authHeaders.any { it.startsWith("Authorization:", ignoreCase = true) },
                        hasApiKey =
                            authHeaders.any {
                                it.contains("API-Key", ignoreCase = true) ||
                                    it.contains("X-API", ignoreCase = true)
                            },
                        authCookieNames = authCookieNames,
                    ),
                )
            }
        }

        // Extract path segments for IDOR/BOLA analysis
        val urlPath = parsedUri?.path.orEmpty()

        // Look for potential object IDs in URL
        val potentialIds =
            POTENTIAL_IDS_REGEX
                .findAll(urlPath + "?" + params.joinToString("&"))
                .map { it.value }
                .distinct()
                .take(POTENTIAL_IDS_MAX_COUNT)
                .toList()

        // Extract JS endpoints from JavaScript responses
        val mime =
            response
                ?.statedMimeType()
                ?.name
                ?.lowercase()
                .orEmpty()
        val inferredMime =
            response
                ?.inferredMimeType()
                ?.name
                ?.lowercase()
                .orEmpty()
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
        val requestBody = buildCompactRequestBody(requestBodyRaw, request.headerValue("Content-Type").orEmpty(), requestBodyPromptMaxChars)
        val responseBody = buildCompactResponseBody(responseBodyRaw, response?.headerValue("Content-Type").orEmpty(), responseBodyPromptMaxChars)

        val metadataText =
            buildString {
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

        val safeMetadataText =
            if (settings.privacyMode == PrivacyMode.OFF) {
                metadataText
            } else {
                Redaction.apply(
                    metadataText,
                    redactionPolicy,
                    stableHostSalt = settings.hostAnonymizationSalt,
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
                cacheHit = true,
            )
            // CAP-04 (WR-01): self-pause when the scanner's own consumption crosses the cap.
            reconcileBudgetAndLog(settings)
            audit.logEvent(
                "passive_ai_scan_cache_hit",
                mapOf(
                    "url" to request.url(),
                    "method" to request.method(),
                    "status" to (response?.statusCode() ?: 0).toString(),
                    "promptChars" to singlePrompt.length.toString(),
                    "issues" to cachedIssues.size.toString(),
                ),
            )
            return
        }

        // Batch mode: enqueue and flush when ready
        val batchSize = settings.passiveAiBatchSize.coerceIn(1, 5)
        if (batchSize > 1) {
            batchQueue.enqueue(
                PendingAnalysis(
                    metadata = safeMetadataText,
                    requestResponse = requestResponse,
                    minSeverity = settings.passiveAiMinSeverity.name,
                    host = host.lowercase(),
                ),
            )
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

        // PRIV-03 (Phase 15): tripwire scan on the FINAL post-redaction prompt (G1/G8).
        // Detect + audit-log on match via the single SecretTripwire helper (WR-03 — one
        // payload shape across all hooks); NEVER block — fall through to supervisor.send (SC2).
        SecretTripwire
            .detectAndBuild(singlePrompt, path = "passive_scanner", sessionId = supervisor.currentSessionId())
            ?.let { AuditLogger.emitGlobal("secret_tripwire_detect", it) }
        // NO blocking — fall through to supervisor.send (SC2 / non-interactive path).

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
            maxOutputTokens = Defaults.SCANNER_MAX_OUTPUT_TOKENS,
        )

        aiRequestLogger?.log(
            type = ActivityType.SCANNER_SEND,
            source = "passive_scanner",
            backendId = settings.preferredBackendId,
            detail = "Passive scan: ${request.method()} ${request.url().take(80)}",
            promptChars = singlePrompt.length,
            metadata =
                mapOf(
                    "operation" to "scanner_job",
                    "status" to "sent",
                    "traceId" to traceId,
                    "url" to request.url().take(200),
                    "method" to request.method(),
                ),
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
                metadata =
                    mapOf(
                        "operation" to "scanner_job",
                        "status" to "timeout",
                        "traceId" to traceId,
                        "url" to request.url().take(200),
                        "method" to request.method(),
                    ),
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
                metadata =
                    mapOf(
                        "operation" to "scanner_job",
                        "status" to "error",
                        "traceId" to traceId,
                        "url" to request.url().take(200),
                        "method" to request.method(),
                    ),
            )
        } else if (responseBuffer.isNotEmpty()) {
            val issues = parseIssuesFromAiResponse(responseBuffer.toString(), api)
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
                metadata =
                    mapOf(
                        "operation" to "scanner_job",
                        "status" to "ok",
                        "traceId" to traceId,
                        "issues" to issues.size.toString(),
                        "url" to request.url().take(200),
                        "method" to request.method(),
                    ),
            )
        }

        TokenTracker.record(
            flow = "passive_scanner",
            backendId = settings.preferredBackendId,
            inputChars = singlePrompt.length,
            outputChars = responseBuffer.length,
        )
        // CAP-04 (WR-01): self-pause when the scanner's own consumption crosses the cap.
        reconcileBudgetAndLog(settings)

        audit.logEvent(
            "passive_ai_scan",
            mapOf(
                "url" to request.url(),
                "method" to request.method(),
                "status" to (response?.statusCode() ?: 0).toString(),
                "promptChars" to singlePrompt.length.toString(),
                "responseChars" to responseBuffer.length.toString(),
            ),
        )
    } catch (e: Exception) {
        api.logging().logToError("[PassiveAiScanner] Error: ${e.javaClass.simpleName}: ${e.message}")
    }
}

// ---- batch + single-send ----

internal fun PassiveAiScanner.flushBatch(settings: AgentSettings) {
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
        api.logging().logToError(
            "[PassiveAiScanner] Batch backend unavailable, falling back to individual analysis (${batch.size} items)",
        )
        fallbackToIndividualAnalysis(batch, settings)
        return
    }

    val responseBuffer = StringBuilder()
    val completionLatch = CountDownLatch(1)
    val errorRef = AtomicReference<String?>(null)
    val traceId = "scanner-batch-" + UUID.randomUUID().toString()
    val sendStartMs = System.currentTimeMillis()

    // PRIV-03 (Phase 15): tripwire scan on the FINAL post-redaction batch prompt (G1/G8).
    // Detect + audit-log on match via the single SecretTripwire helper (WR-03 — one payload
    // shape across all hooks); NEVER block — fall through to supervisor.send (SC2).
    SecretTripwire
        .detectAndBuild(prompt, path = "passive_scanner", sessionId = supervisor.currentSessionId())
        ?.let { AuditLogger.emitGlobal("secret_tripwire_detect", it) }
    // NO blocking — fall through to supervisor.send (SC2 / non-interactive path).

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
        maxOutputTokens = Defaults.SCANNER_BATCH_MAX_OUTPUT_TOKENS,
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
            val allIssues = parseIssuesFromAiResponse(responseBuffer.toString(), api)
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
            outputChars = responseBuffer.length,
        )
        // CAP-04 (WR-01): self-pause when the scanner's own consumption crosses the cap.
        reconcileBudgetAndLog(settings)
    }
}

internal fun PassiveAiScanner.fallbackToIndividualAnalysis(
    batch: List<PendingAnalysis>,
    settings: AgentSettings,
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

internal fun PassiveAiScanner.sendSingleAnalysis(
    prompt: String,
    requestResponse: HttpRequestResponse,
    minSeverity: String,
    settings: AgentSettings,
) {
    if (!ensureBackendRunning(settings)) return

    val promptHash = sha256Hex(prompt)
    val responseBuffer = StringBuilder()
    val completionLatch = CountDownLatch(1)
    val errorRef = AtomicReference<String?>(null)

    // PRIV-03 (Phase 15): tripwire scan on the FINAL post-redaction prompt (G1/G8).
    // Detect + audit-log on match via the single SecretTripwire helper (WR-03 — one payload
    // shape across all hooks); NEVER block — fall through to supervisor.send (SC2).
    SecretTripwire
        .detectAndBuild(prompt, path = "passive_scanner", sessionId = supervisor.currentSessionId())
        ?.let { AuditLogger.emitGlobal("secret_tripwire_detect", it) }
    // NO blocking — fall through to supervisor.send (SC2 / non-interactive path).

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
        maxOutputTokens = Defaults.SCANNER_MAX_OUTPUT_TOKENS,
    )

    val completed = completionLatch.await(Defaults.PASSIVE_SCAN_TIMEOUT_MS, TimeUnit.MILLISECONDS)
    requestsAnalyzed.incrementAndGet()
    lastAnalysisTime.set(System.currentTimeMillis())

    if (completed && errorRef.get() == null && responseBuffer.isNotEmpty()) {
        val issues = parseIssuesFromAiResponse(responseBuffer.toString(), api)
        putPromptResultCacheValue(promptHash, issues)
        handleParsedAiIssues(issues, requestResponse, minSeverity)
    }
}

// ---- redaction helpers ----

internal fun PassiveAiScanner.redactUrlForPrompt(
    rawUrl: String,
    policy: RedactionPolicy,
    hostSalt: String,
): String =
    try {
        val uri = URI(rawUrl)
        val safeHost =
            if (!uri.host.isNullOrBlank() && policy.anonymizeHosts) {
                Redaction.anonymizeHost(uri.host, hostSalt)
            } else {
                uri.host
            }
        val safeQuery =
            if (uri.query.isNullOrBlank()) {
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
            uri.fragment,
        ).toString()
    } catch (_: Exception) {
        rawUrl
    }

internal fun PassiveAiScanner.redactSensitiveQuery(query: String): String {
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

internal fun PassiveAiScanner.hasExcludedExtension(url: String): Boolean {
    if (excludedExtensions.isEmpty()) return false
    val path =
        try {
            URI(url).path.orEmpty()
        } catch (_: Exception) {
            url
        }
    val lastSegment = path.substringAfterLast('/')
    val ext = lastSegment.substringAfterLast('.', "").lowercase()
    return ext.isNotEmpty() && ext in excludedExtensions
}

internal fun PassiveAiScanner.isGeminiCapacityError(error: String): Boolean {
    val lower = error.lowercase()
    return lower.contains("resource_exhausted") ||
        lower.contains("model_capacity_exhausted") ||
        (lower.contains("status 429") && lower.contains("gemini")) ||
        lower.contains("no capacity available for model")
}

internal fun PassiveAiScanner.maybeLogBackoff(
    nowMs: Long,
    untilMs: Long,
) {
    val prev = lastBackoffLogTime.get()
    if (nowMs - prev < BACKOFF_LOG_INTERVAL_MS) return
    if (lastBackoffLogTime.compareAndSet(prev, nowMs)) {
        val seconds = ((untilMs - nowMs).coerceAtLeast(0L) / 1000L)
        api.logging().logToOutput("[PassiveAiScanner] AI backend backoff active (${seconds}s remaining)")
    }
}
