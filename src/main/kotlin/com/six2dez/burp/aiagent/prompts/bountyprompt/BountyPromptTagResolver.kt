package com.six2dez.burp.aiagent.prompts.bountyprompt

import burp.api.montoya.http.message.HttpRequestResponse
import com.six2dez.burp.aiagent.context.ContextOptions
import com.six2dez.burp.aiagent.redact.Redaction
import com.six2dez.burp.aiagent.redact.RedactionPolicy
import java.net.URI

class BountyPromptTagResolver {

    private val maxChunkChars = 6_000
    private val maxTagChars = 28_000
    private val sensitiveParamName = Regex(
        "(token|key|auth|session|jwt|cookie|password|secret|api_key|apikey)",
        RegexOption.IGNORE_CASE
    )

    fun resolve(
        definition: BountyPromptDefinition,
        requestResponses: List<HttpRequestResponse>,
        options: ContextOptions
    ): ResolvedBountyPrompt {
        val policy = RedactionPolicy.fromMode(options.privacyMode)
        val tagValues = definition.tagsUsed.associateWith { tag ->
            buildTagValue(tag, requestResponses, policy, options.hostSalt)
        }

        var resolved = definition.userPrompt
        for ((tag, value) in tagValues) {
            resolved = resolved.replace(tag.token, value)
        }
        // Remove any unknown HTTP_* tokens left in the prompt.
        resolved = resolved.replace(Regex("\\[HTTP_[^\\]]+\\]"), "").trim()

        val preview = buildString {
            appendLine("Kind: BountyPrompt selection")
            appendLine("Items: ${requestResponses.size}")
            appendLine("Prompt ID: ${definition.id}")
            appendLine("Prompt Type: ${definition.outputType.name}")
            appendLine("Category: ${definition.category.name}")
            appendLine("Tags used: ${if (definition.tagsUsed.isEmpty()) "none" else definition.tagsUsed.joinToString { it.token }}")
            appendLine("Selective context: true")
            appendLine("Redaction:")
            appendLine("  - Cookie stripping: ${policy.stripCookies}")
            appendLine("  - Token redaction: ${policy.redactTokens}")
            appendLine("  - Host anonymization: ${policy.anonymizeHosts}")
            appendLine("Deterministic: ${options.deterministic}")
        }.trimIndent()

        return ResolvedBountyPrompt(
            resolvedUserPrompt = resolved,
            previewText = preview
        )
    }

    private fun buildTagValue(
        tag: BountyPromptTag,
        requestResponses: List<HttpRequestResponse>,
        policy: RedactionPolicy,
        hostSalt: String
    ): String {
        if (requestResponses.isEmpty()) return "<no request/response selected>"
        val sections = mutableListOf<String>()
        for ((index, rr) in requestResponses.withIndex()) {
            val requestRaw = rr.request().toString()
            val responseRaw = rr.response()?.toString()
            val requestRedacted = Redaction.apply(requestRaw, policy, stableHostSalt = hostSalt)
            val responseRedacted = responseRaw?.let { Redaction.apply(it, policy, stableHostSalt = hostSalt) }
            val safeUrl = redactUrl(rr.request().url(), policy, hostSalt)
            val label = "[${index + 1}] ${rr.request().method()} $safeUrl"

            val value = when (tag) {
                BountyPromptTag.HTTP_REQUESTS -> truncateChunk(requestRedacted)
                BountyPromptTag.HTTP_REQUESTS_HEADERS -> truncateChunk(extractHeaders(requestRedacted))
                BountyPromptTag.HTTP_REQUESTS_PARAMETERS -> truncateChunk(
                    buildRequestParameters(rr, policy, hostSalt)
                )
                BountyPromptTag.HTTP_REQUEST_BODY -> truncateChunk(extractBody(requestRedacted))
                BountyPromptTag.HTTP_RESPONSES -> truncateChunk(responseRedacted ?: "<no response>")
                BountyPromptTag.HTTP_RESPONSE_HEADERS -> truncateChunk(
                    responseRedacted?.let { extractHeaders(it) } ?: "<no response>"
                )
                BountyPromptTag.HTTP_RESPONSE_BODY -> truncateChunk(
                    responseRedacted?.let { extractBody(it) } ?: "<no response>"
                )
                BountyPromptTag.HTTP_STATUS_CODE -> rr.response()?.statusCode()?.toString() ?: "<no response>"
                BountyPromptTag.HTTP_COOKIES -> truncateChunk(extractCookies(requestRedacted, responseRedacted))
            }
            sections.add("$label\n$value")
        }
        return truncateTag(sections.joinToString("\n\n----------------------------------------------------------------\n\n"))
    }

    private fun buildRequestParameters(
        rr: HttpRequestResponse,
        policy: RedactionPolicy,
        hostSalt: String
    ): String {
        val params = rr.request().parameters().take(80).joinToString("\n") { param ->
            val rawValue = param.value().take(500)
            val safeValue = if (policy.redactTokens && sensitiveParamName.containsMatchIn(param.name())) {
                "[REDACTED]"
            } else {
                rawValue
            }
            "${param.name()}=${safeValue} (${param.type().name})"
        }
        val safeUrl = redactUrl(rr.request().url(), policy, hostSalt)
        return buildString {
            appendLine("URL: $safeUrl")
            appendLine("Parameters:")
            append(if (params.isBlank()) "<none>" else params)
        }.trim()
    }

    private fun extractCookies(requestText: String, responseText: String?): String {
        val requestCookies = requestText.lineSequence()
            .filter { it.startsWith("Cookie:", ignoreCase = true) }
            .toList()
        val responseCookies = responseText.orEmpty()
            .lineSequence()
            .filter { it.startsWith("Set-Cookie:", ignoreCase = true) }
            .toList()
        val lines = mutableListOf<String>()
        if (requestCookies.isNotEmpty()) {
            lines.add("Request Cookies:")
            lines.addAll(requestCookies)
        }
        if (responseCookies.isNotEmpty()) {
            if (lines.isNotEmpty()) lines.add("")
            lines.add("Response Cookies:")
            lines.addAll(responseCookies)
        }
        return lines.joinToString("\n").ifBlank { "<none>" }
    }

    private fun extractHeaders(raw: String): String {
        val idx = raw.indexOf("\r\n\r\n").takeIf { it >= 0 } ?: raw.indexOf("\n\n")
        return if (idx >= 0) raw.substring(0, idx) else raw
    }

    private fun extractBody(raw: String): String {
        val idxRr = raw.indexOf("\r\n\r\n")
        if (idxRr >= 0 && idxRr + 4 <= raw.length) return raw.substring(idxRr + 4)
        val idxNn = raw.indexOf("\n\n")
        return if (idxNn >= 0 && idxNn + 2 <= raw.length) raw.substring(idxNn + 2) else ""
    }

    private fun truncateChunk(text: String): String {
        if (text.length <= maxChunkChars) return text
        return text.take(maxChunkChars) + "\n...[truncated]..."
    }

    private fun truncateTag(text: String): String {
        if (text.length <= maxTagChars) return text
        return text.take(maxTagChars) + "\n...[tag content truncated]..."
    }

    private fun redactUrl(rawUrl: String, policy: RedactionPolicy, hostSalt: String): String {
        return try {
            val uri = URI(rawUrl)
            val safeHost = if (!uri.host.isNullOrBlank() && policy.anonymizeHosts) {
                Redaction.anonymizeHost(uri.host, hostSalt)
            } else {
                uri.host
            }
            val safeQuery = when {
                uri.query.isNullOrBlank() -> uri.query
                !policy.redactTokens -> uri.query
                else -> redactSensitiveQuery(uri.query)
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
        return query.split("&").joinToString("&") { pair ->
            val idx = pair.indexOf('=')
            if (idx <= 0) return@joinToString pair
            val key = pair.substring(0, idx)
            val value = pair.substring(idx + 1)
            if (sensitiveParamName.containsMatchIn(key)) {
                "$key=[REDACTED]"
            } else {
                "$key=$value"
            }
        }
    }
}
