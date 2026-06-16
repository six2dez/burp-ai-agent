package com.six2dez.burp.aiagent.scanner

import burp.api.montoya.http.message.HttpHeader
import burp.api.montoya.http.message.requests.HttpRequest
import burp.api.montoya.http.message.responses.HttpResponse
import com.six2dez.burp.aiagent.cache.CachedEntry
import com.six2dez.burp.aiagent.cache.CachedIssue
import com.six2dez.burp.aiagent.util.IssueUtils
import java.net.URI
import java.util.LinkedHashMap

// AWT-free contract: MUST NOT import java.awt.* or javax.swing.*

private const val RESPONSE_FINGERPRINT_BODY_PREFIX_CHARS = 2_000
private const val HEADER_VALUE_MAX_CHARS = 120
private const val MIN_RESPONSE_BODY_CHARS = 50

// Redeclared from PassiveAiScanner companion (private there, copied here for extension functions)
private const val LOCAL_FINDING_SKIP_CONFIDENCE = 90
private const val MIN_BODY_SIZE_FOR_AI = 80

// ---- time-window helpers ----

internal fun PassiveAiScanner.endpointDedupWindowMs(): Long =
    endpointDedupMinutes.toLong().coerceAtLeast(1L) * 60_000L

internal fun PassiveAiScanner.responseFingerprintDedupWindowMs(): Long =
    responseFingerprintDedupMinutes.toLong().coerceAtLeast(1L) * 60_000L

internal fun PassiveAiScanner.promptCacheTtlMs(): Long =
    promptCacheTtlMinutes.toLong().coerceAtLeast(1L) * 60_000L

// ---- LRU trim helper ----

internal fun <K, V> PassiveAiScanner.trimLruCache(
    cache: LinkedHashMap<K, V>,
    maxEntries: Int,
) {
    while (cache.size > maxEntries) {
        val iterator = cache.entries.iterator()
        if (!iterator.hasNext()) return
        iterator.next()
        iterator.remove()
    }
}

// ---- skip-decision helpers ----

internal fun PassiveAiScanner.shouldSkipAiAfterLocalFindings(
    localFindings: List<LocalFinding>,
    request: HttpRequest,
    requestBody: String,
): Boolean {
    if (localFindings.isEmpty()) return false
    val hasHighConfidenceLocal = localFindings.any { it.confidence >= LOCAL_FINDING_SKIP_CONFIDENCE }
    if (!hasHighConfidenceLocal) return false
    val hasInterestingInput =
        request.parameters().isNotEmpty() ||
            requestBody.length > MIN_BODY_SIZE_FOR_AI ||
            request.method().uppercase() in setOf("POST", "PUT", "PATCH", "DELETE")
    return !hasInterestingInput
}

internal fun PassiveAiScanner.shouldSkipUninterestingTraffic(
    request: HttpRequest,
    response: HttpResponse?,
    responseBody: String,
): Boolean {
    val status = response?.statusCode() ?: return false
    if (status == 204.toShort() || status == 304.toShort()) return true
    val path = runCatching { URI(request.url()).path.orEmpty().lowercase() }.getOrDefault("")
    if (path.isNotBlank() && staticAssetPathRegex.containsMatchIn(path)) return true
    if (responseBody.length < MIN_RESPONSE_BODY_CHARS && !hasInterestingResponseHeaders(response)) return true
    return false
}

internal fun PassiveAiScanner.hasInterestingResponseHeaders(response: HttpResponse): Boolean =
    response.headers().any { header ->
        val name = header.name().lowercase()
        responseHeaderAllowlist.contains(name) || name.startsWith("x-")
    }

internal fun PassiveAiScanner.shouldSkipRecentlyAnalyzedEndpoint(request: HttpRequest): Boolean {
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

internal fun PassiveAiScanner.buildEndpointCacheKey(request: HttpRequest): String {
    val method = request.method().uppercase()
    val uri = runCatching { URI(request.url()) }.getOrNull()
    val normalizedPath =
        runCatching {
            IssueUtils.normalizePathSegments(uri?.path.orEmpty())
        }.getOrElse { IssueUtils.normalizePathSegments(request.url()) }
    val host = uri?.host.orEmpty().lowercase()
    val sortedParamNames =
        uri
            ?.query
            .orEmpty()
            .split('&')
            .mapNotNull {
                it
                    .split('=')
                    .firstOrNull()
                    ?.lowercase()
                    ?.ifBlank { null }
            }.filter { !cacheBustingParamRegex.matches(it) }
            .sorted()
            .joinToString(",")
    return "$method:$host:$normalizedPath:$sortedParamNames"
}

internal fun PassiveAiScanner.shouldSkipKnownResponseFingerprint(
    request: HttpRequest,
    response: HttpResponse?,
    responseBody: String,
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

internal fun PassiveAiScanner.buildResponseFingerprint(
    request: HttpRequest,
    response: HttpResponse?,
    responseBody: String,
): String? {
    if (response == null) return null
    val headers =
        sanitizeHeadersForPrompt(response.headers(), isRequest = false)
            .take(10)
            .joinToString("\n")
    val bodyPrefix = stripDynamicValues(responseBody.take(RESPONSE_FINGERPRINT_BODY_PREFIX_CHARS))
    val raw =
        buildString {
            append(request.method()).append('\n')
            append(IssueUtils.normalizeUrl(request.url())).append('\n')
            append(response.statusCode()).append('\n')
            append(headers).append('\n')
            append(bodyPrefix)
        }
    return sha256Hex(raw)
}

internal fun PassiveAiScanner.stripDynamicValues(text: String): String =
    dynamicValueStripRegex.replace(text, "{DYN}")

internal fun PassiveAiScanner.sanitizeHeadersForPrompt(
    headers: List<HttpHeader>,
    isRequest: Boolean,
): List<String> =
    headers
        .asSequence()
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
        }.take(headerMaxCount)
        .map { header ->
            val value = truncateWithEllipsis(header.value(), HEADER_VALUE_MAX_CHARS)
            "${header.name()}: $value"
        }.toList()

// ---- in-memory + persistent prompt-result cache ----

internal fun PassiveAiScanner.promptResultCacheValue(promptHash: String): List<AiIssueItem>? {
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
    val issues =
        diskEntry.issues.map { ci ->
            AiIssueItem(
                reasoning = ci.reasoning,
                title = ci.title,
                severity = ci.severity,
                detail = ci.detail,
                confidence = ci.confidence,
                requestIndex = ci.requestIndex,
            )
        }
    // Promote to in-memory cache
    synchronized(promptResultCache) {
        promptResultCache[promptHash] =
            CachedAiIssues(
                createdAtMs = diskEntry.createdAtMs,
                issues = issues,
            )
    }
    return issues
}

internal fun PassiveAiScanner.putPromptResultCacheValue(
    promptHash: String,
    issues: List<AiIssueItem>,
) {
    val now = System.currentTimeMillis()
    synchronized(promptResultCache) {
        promptResultCache[promptHash] =
            CachedAiIssues(
                createdAtMs = now,
                issues = issues,
            )
    }
    // Write to persistent cache
    persistentCache?.put(
        promptHash,
        CachedEntry(
            createdAtMs = now,
            issues =
                issues.map { ai ->
                    CachedIssue(
                        reasoning = ai.reasoning,
                        title = ai.title,
                        severity = ai.severity,
                        detail = ai.detail,
                        confidence = ai.confidence,
                        requestIndex = ai.requestIndex,
                    )
                },
        ),
    )
}

