package com.six2dez.burp.aiagent.mcp.tools

// AWT-free contract: MUST NOT import java.awt.* or javax.swing.*
// Note: getActiveEditor imports javax.swing.JTextArea via the MontoyaApi — that function
// is NOT AWT-free by nature and must only be called on the Swing EDT. All other functions
// in this file are pure transforms with no AWT/Swing dependency.

import burp.api.montoya.MontoyaApi
import burp.api.montoya.core.HighlightColor
import burp.api.montoya.http.message.HttpHeader
import burp.api.montoya.http.message.requests.HttpRequest
import burp.api.montoya.scanner.BuiltInAuditConfiguration
import com.six2dez.burp.aiagent.mcp.McpToolContext
import com.six2dez.burp.aiagent.redact.Redaction
import com.six2dez.burp.aiagent.redact.RedactionPolicy
import com.six2dez.burp.aiagent.util.IssueText
import com.six2dez.burp.aiagent.util.IssueUtils
import kotlinx.serialization.json.Json
import java.awt.KeyboardFocusManager
import java.net.URI
import java.util.Base64
import javax.swing.JTextArea

internal val toolJson = Json { encodeDefaults = true }

internal fun executeIssueCreate(
    input: CreateAuditIssue,
    api: MontoyaApi,
    context: McpToolContext,
): String {
    val severityEnum =
        try {
            burp.api.montoya.scanner.audit.issues.AuditIssueSeverity
                .valueOf(input.severity.uppercase())
        } catch (_: Exception) {
            return "Invalid severity: ${input.severity}. Use: HIGH, MEDIUM, LOW, INFORMATION"
        }
    val confidenceEnum =
        try {
            burp.api.montoya.scanner.audit.issues.AuditIssueConfidence
                .valueOf(input.confidence.uppercase())
        } catch (_: Exception) {
            return "Invalid confidence: ${input.confidence}. Use: CERTAIN, FIRM, TENTATIVE"
        }
    val typicalSeverityEnum =
        try {
            burp.api.montoya.scanner.audit.issues.AuditIssueSeverity
                .valueOf((input.typicalSeverity ?: input.severity).uppercase())
        } catch (_: Exception) {
            severityEnum
        }

    val requestResponseList =
        if (input.httpRequest != null) {
            val service =
                input.toMontoyaServiceOrNull(context::resolveHost)
                    ?: return "Error: targetHostname/targetPort/usesHttps required when providing httpRequest"
            val fixedRequest = input.httpRequest.replace("\r", "").replace("\n", "\r\n")
            val request = HttpRequest.httpRequest(service, fixedRequest)
            val httpResponse =
                if (input.httpResponseContent != null) {
                    val fixedResponse = input.httpResponseContent.replace("\r", "").replace("\n", "\r\n")
                    burp.api.montoya.http.message.responses.HttpResponse
                        .httpResponse(fixedResponse)
                } else {
                    null
                }
            val rr =
                if (httpResponse != null) {
                    burp.api.montoya.http.message.HttpRequestResponse
                        .httpRequestResponse(request, httpResponse)
                } else {
                    burp.api.montoya.http.message.HttpRequestResponse
                        .httpRequestResponse(request, null)
                }
            listOf(rr)
        } else {
            findProxyHistoryMatch(api, input.baseUrl)
        }

    val issueNameWithPrefix = withAiIssuePrefix(input.name)
    if (hasEquivalentIssue(api, issueNameWithPrefix, input.baseUrl)) {
        return "Issue already exists: $issueNameWithPrefix"
    }
    val sanitizedDetail = IssueText.sanitize(input.detail)
    val sanitizedRemediation = IssueText.sanitize(input.remediation ?: "")
    val sanitizedBackground = IssueText.sanitize(input.background ?: "")
    val sanitizedRemediationBackground = IssueText.sanitize(input.remediationBackground ?: "")

    val issue =
        burp.api.montoya.scanner.audit.issues.AuditIssue.auditIssue(
            issueNameWithPrefix,
            sanitizedDetail,
            sanitizedRemediation,
            input.baseUrl,
            severityEnum,
            confidenceEnum,
            sanitizedBackground,
            sanitizedRemediationBackground,
            typicalSeverityEnum,
            requestResponseList,
        )

    api.siteMap().add(issue)
    return "Issue created: $issueNameWithPrefix (Severity: ${input.severity}, Confidence: ${input.confidence})"
}

internal fun findProxyHistoryMatch(
    api: MontoyaApi,
    baseUrl: String,
): List<burp.api.montoya.http.message.HttpRequestResponse> {
    return runCatching {
        val baseUri = java.net.URI(baseUrl)
        val baseScheme = baseUri.scheme?.lowercase()
        val baseHost = baseUri.host?.lowercase() ?: return@runCatching emptyList()
        val basePort = baseUri.port
        val basePath = baseUri.path.orEmpty()

        api
            .proxy()
            .history()
            .firstOrNull { entry ->
                val entryUrl = entry.request()?.url() ?: return@firstOrNull false
                val entryUri = runCatching { java.net.URI(entryUrl) }.getOrNull() ?: return@firstOrNull false
                entryUri.scheme?.lowercase() == baseScheme &&
                    entryUri.host?.lowercase() == baseHost &&
                    (basePort < 0 || entryUri.port == basePort) &&
                    entryUri.path.orEmpty().startsWith(basePath)
            }?.let { proxy ->
                listOf(
                    burp.api.montoya.http.message.HttpRequestResponse.httpRequestResponse(
                        proxy.request(),
                        proxy.response(),
                    ),
                )
            } ?: emptyList()
    }.getOrDefault(emptyList())
}

internal fun withAiIssuePrefix(rawName: String): String {
    val trimmed = rawName.trim()
    if (trimmed.startsWith("[AI]", ignoreCase = true)) return trimmed
    if (trimmed.startsWith("[AI Passive]", ignoreCase = true)) return trimmed
    return "[AI] $trimmed"
}

internal fun hasEquivalentIssue(
    api: MontoyaApi,
    name: String,
    baseUrl: String,
): Boolean =
    IssueUtils.hasEquivalentIssue(
        name = name,
        baseUrl = baseUrl,
        issues = api.siteMap().issues().map { issue -> issue.name() to issue.baseUrl() },
    )

/**
 * Normalizes HTTP request line endings and updates Content-Length header.
 *
 * When MCP clients send requests, they may use LF-only line endings which get
 * converted to CRLF. This changes the body byte length, but the original
 * Content-Length header value remains unchanged, causing the server to receive
 * a truncated body. This function recalculates Content-Length after normalization.
 */
internal fun normalizeHttpRequest(content: String): String {
    // Normalize line endings to CRLF
    val normalized = content.replace("\r\n", "\n").replace("\r", "\n").replace("\n", "\r\n")

    // Find the header/body separator
    val separatorIndex = normalized.indexOf("\r\n\r\n")
    if (separatorIndex < 0) return normalized

    val headerSection = normalized.substring(0, separatorIndex)
    val body = normalized.substring(separatorIndex + 4)

    // If no body, no need to update Content-Length
    if (body.isEmpty()) return normalized

    // Calculate actual body length in bytes
    val bodyBytes = body.toByteArray(Charsets.UTF_8)
    val bodyLength = bodyBytes.size

    // Update or add Content-Length header
    val lines = headerSection.split("\r\n").toMutableList()
    val contentLengthIndex = lines.indexOfFirst { it.startsWith("Content-Length:", ignoreCase = true) }

    if (contentLengthIndex >= 0) {
        lines[contentLengthIndex] = "Content-Length: $bodyLength"
    }
    // If no Content-Length and body exists, the server may not need it (e.g., chunked encoding)
    // so we only update existing headers, not add new ones

    return lines.joinToString("\r\n") + "\r\n\r\n" + body
}

internal fun truncateIfNeeded(
    serialized: String,
    maxBodyBytes: Int,
): String {
    val limit = maxBodyBytes.coerceAtLeast(1)
    val bytes = serialized.toByteArray(Charsets.UTF_8)
    if (bytes.size <= limit) return serialized
    val truncated = String(bytes, 0, limit, Charsets.UTF_8)
    return "$truncated... (truncated ${bytes.size} bytes to $limit bytes)"
}

internal fun ensureAllowedProxyHistoryCount(
    requestedCount: Int,
    maxAllowedCount: Int,
) {
    if (requestedCount <= maxAllowedCount) return
    throw IllegalArgumentException(
        "Requested count $requestedCount exceeds MCP proxy history limit $maxAllowedCount. " +
            "Reduce count.",
    )
}

internal fun <T> orderedProxyHistory(
    items: List<T>,
    context: McpToolContext,
    deterministicKey: (T) -> String,
): Sequence<T> =
    if (context.determinismMode) {
        items.sortedBy(deterministicKey).asSequence()
    } else {
        if (context.proxyHistoryNewestFirst) items.asReversed().asSequence() else items.asSequence()
    }

internal fun decodeJwt(token: String): String {
    val parts = token.split(".")
    if (parts.size < 2) return "Invalid JWT: expected header.payload.signature"
    val decoder = Base64.getUrlDecoder()
    val header = runCatching { String(decoder.decode(parts[0]), Charsets.UTF_8) }.getOrNull() ?: "<invalid header>"
    val payload = runCatching { String(decoder.decode(parts[1]), Charsets.UTF_8) }.getOrNull() ?: "<invalid payload>"
    val signature = if (parts.size > 2) parts[2] else ""
    return buildString {
        appendLine("header=$header")
        appendLine("payload=$payload")
        appendLine("signature=$signature")
    }.trim()
}

internal fun normalizeHashAlgorithm(raw: String): String {
    val algo = raw.trim().uppercase()
    return when (algo) {
        "SHA1" -> "SHA-1"
        "SHA256" -> "SHA-256"
        "SHA512" -> "SHA-512"
        else -> algo
    }
}

internal fun diffLines(
    a: String,
    b: String,
): String {
    val left = a.replace("\r", "").split("\n")
    val right = b.replace("\r", "").split("\n")
    val max = maxOf(left.size, right.size)
    return buildString {
        appendLine("--- request_a")
        appendLine("+++ request_b")
        for (i in 0 until max) {
            val l = left.getOrNull(i)
            val r = right.getOrNull(i)
            if (l == r) {
                if (l != null) appendLine(" $l")
            } else {
                if (l != null) appendLine("-$l")
                if (r != null) appendLine("+$r")
            }
        }
    }.trim()
}

internal fun countOccurrences(
    haystack: String,
    needle: String,
): Int {
    if (needle.isEmpty()) return 0
    var count = 0
    var idx = 0
    while (true) {
        val found = haystack.indexOf(needle, idx)
        if (found == -1) return count
        count++
        idx = found + needle.length
    }
}

internal fun parseHighlightColor(raw: String?): HighlightColor? {
    val name = raw?.trim().orEmpty()
    if (name.isBlank()) return null
    return try {
        HighlightColor.valueOf(name.uppercase())
    } catch (_: Exception) {
        null
    }
}

internal fun sanitizeHeaders(
    headers: List<HttpHeader>,
    context: McpToolContext,
): Map<String, String> {
    val policy = RedactionPolicy.fromMode(context.privacyMode)
    val tokenHeaders = setOf("authorization", "proxy-authorization", "x-api-key", "api-key")
    val sanitized = LinkedHashMap<String, String>()
    headers.forEach { header ->
        val name = header.name()
        val lowered = name.lowercase()
        var value = header.value()
        if (policy.stripCookies && (lowered == "cookie" || lowered == "set-cookie")) {
            value = "[STRIPPED]"
        }
        if (policy.redactTokens && tokenHeaders.contains(lowered)) {
            value = "[REDACTED]"
        }
        if (policy.anonymizeHosts && lowered == "host") {
            value = Redaction.anonymizeHost(value, context.hostSalt)
        }
        sanitized[name] = value
    }
    return sanitized
}

internal fun maybeAnonymizeUrl(
    rawUrl: String,
    context: McpToolContext,
): String {
    if (context.privacyMode != com.six2dez.burp.aiagent.redact.PrivacyMode.STRICT) return rawUrl
    return try {
        val uri = URI(rawUrl)
        val host = uri.host ?: return rawUrl
        val anonHost = Redaction.anonymizeHost(host, context.hostSalt)
        URI(
            uri.scheme,
            uri.userInfo,
            anonHost,
            uri.port,
            uri.path,
            uri.query,
            uri.fragment,
        ).toString()
    } catch (_: Exception) {
        rawUrl
    }
}

internal fun resolveReportPath(raw: String): java.nio.file.Path {
    val trimmed = raw.trim()
    if (trimmed.isBlank()) {
        throw IllegalArgumentException("Report path is empty")
    }
    val rawPath =
        java.nio.file.Path
            .of(trimmed)
    val home =
        java.nio.file.Path
            .of(System.getProperty("user.home"))
            .normalize()
    val resolved =
        if (rawPath.isAbsolute) {
            rawPath.normalize()
        } else {
            home.resolve(rawPath).normalize()
        }
    if (!resolved.startsWith(home)) {
        throw IllegalArgumentException("Report path must be under $home")
    }
    return resolved
}

internal fun applyReplacements(
    content: String,
    replacements: Map<String, String>,
): String {
    if (replacements.isEmpty()) return content
    var output = content
    replacements.forEach { (key, value) ->
        output = output.replace(key, value)
    }
    return output
}

internal fun resolveAuditConfig(mode: String): BuiltInAuditConfiguration =
    when (mode.trim().lowercase()) {
        "active", "active_checks", "legacy_active" -> BuiltInAuditConfiguration.LEGACY_ACTIVE_AUDIT_CHECKS
        "passive", "passive_checks", "legacy_passive" -> BuiltInAuditConfiguration.LEGACY_PASSIVE_AUDIT_CHECKS
        else -> BuiltInAuditConfiguration.valueOf(mode.trim().uppercase())
    }

fun getActiveEditor(api: MontoyaApi): JTextArea? {
    val frame = api.userInterface().swingUtils().suiteFrame()
    val focusManager = KeyboardFocusManager.getCurrentKeyboardFocusManager()
    val permanentFocusOwner = focusManager.permanentFocusOwner
    val isInBurpWindow = generateSequence(permanentFocusOwner) { it.parent }.any { it == frame }
    return if (isInBurpWindow && permanentFocusOwner is JTextArea) {
        permanentFocusOwner
    } else {
        null
    }
}
