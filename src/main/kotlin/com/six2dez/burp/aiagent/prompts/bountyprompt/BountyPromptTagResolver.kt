package com.six2dez.burp.aiagent.prompts.bountyprompt

import burp.api.montoya.http.message.HttpRequestResponse
import com.six2dez.burp.aiagent.context.ContextOptions
import com.six2dez.burp.aiagent.redact.Redaction
import com.six2dez.burp.aiagent.redact.RedactionPolicy
import com.six2dez.burp.aiagent.redact.UrlRedaction

class BountyPromptTagResolver {
    private val defaultMaxChunkChars = 3_000
    private val defaultMaxTagChars = 12_000
    private val sensitiveParamName =
        Regex(
            "(token|key|auth|session|jwt|cookie|password|secret|api_key|apikey)",
            RegexOption.IGNORE_CASE,
        )

    fun resolve(
        definition: BountyPromptDefinition,
        requestResponses: List<HttpRequestResponse>,
        options: ContextOptions,
    ): ResolvedBountyPrompt {
        val policy = RedactionPolicy.fromMode(options.privacyMode)
        val limits = limitsForCategory(definition.category)
        val tagValues =
            definition.tagsUsed.associateWith { tag ->
                buildTagValue(
                    tag = tag,
                    requestResponses = requestResponses,
                    policy = policy,
                    hostSalt = options.hostSalt,
                    maxChunkChars = limits.first,
                    maxTagChars = limits.second,
                )
            }

        var resolved = definition.userPrompt
        for ((tag, value) in tagValues) {
            resolved = resolved.replace(tag.token, value)
        }
        // Remove any unknown HTTP_* tokens left in the prompt.
        resolved = resolved.replace(Regex("\\[HTTP_[^\\]]+\\]"), "").trim()

        val preview =
            buildString {
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
            previewText = preview,
        )
    }

    private fun buildTagValue(
        tag: BountyPromptTag,
        requestResponses: List<HttpRequestResponse>,
        policy: RedactionPolicy,
        hostSalt: String,
        maxChunkChars: Int,
        maxTagChars: Int,
    ): String {
        if (requestResponses.isEmpty()) return "<no request/response selected>"
        val sections = mutableListOf<String>()
        for ((index, rr) in requestResponses.withIndex()) {
            val requestRaw = rr.request().toString()
            val responseRaw = rr.response()?.toString()
            val rawUrl: String? = rr.request().url()
            val safeUrl = rawUrl?.let { UrlRedaction.redact(it, policy, hostSalt) }
            val ownHost = rr.httpService()?.host() ?: UrlRedaction.hostOf(rawUrl)
            // Redaction.apply first (it aliases the whole Host: value), then the STRICT own-host pass
            // for Referer / Origin / Location / absolute URLs in bodies. The reverse order would
            // alias the alias on the Host: line.
            val ownHostPass: (String) -> String = { text ->
                if (policy.anonymizeHosts && ownHost != null) {
                    UrlRedaction.anonymizeHostOccurrences(text, ownHost, hostSalt)
                } else {
                    text
                }
            }
            val requestRedacted = ownHostPass(Redaction.apply(requestRaw, policy, stableHostSalt = hostSalt))
            val responseRedacted = responseRaw?.let { ownHostPass(Redaction.apply(it, policy, stableHostSalt = hostSalt)) }
            val label = "[${index + 1}] ${rr.request().method()} ${ownHostPass(safeUrl.orEmpty())}"

            val value =
                when (tag) {
                    BountyPromptTag.HTTP_REQUESTS -> truncateChunk(requestRedacted, maxChunkChars)
                    BountyPromptTag.HTTP_REQUESTS_HEADERS -> truncateChunk(extractHeaders(requestRedacted), maxChunkChars)
                    BountyPromptTag.HTTP_REQUESTS_PARAMETERS ->
                        truncateChunk(
                            ownHostPass(buildRequestParameters(rr, safeUrl.orEmpty(), policy, hostSalt)),
                            maxChunkChars,
                        )
                    BountyPromptTag.HTTP_REQUEST_BODY -> truncateChunk(extractBody(requestRedacted), maxChunkChars)
                    BountyPromptTag.HTTP_RESPONSES -> truncateChunk(responseRedacted ?: "<no response>", maxChunkChars)
                    BountyPromptTag.HTTP_RESPONSE_HEADERS ->
                        truncateChunk(
                            responseRedacted?.let { extractHeaders(it) } ?: "<no response>",
                            maxChunkChars,
                        )
                    BountyPromptTag.HTTP_RESPONSE_BODY ->
                        truncateChunk(
                            responseRedacted?.let { extractBody(it) } ?: "<no response>",
                            maxChunkChars,
                        )
                    BountyPromptTag.HTTP_STATUS_CODE -> rr.response()?.statusCode()?.toString() ?: "<no response>"
                    BountyPromptTag.HTTP_COOKIES -> truncateChunk(extractCookies(requestRedacted, responseRedacted), maxChunkChars)
                }
            sections.add("$label\n$value")
        }
        return truncateTag(sections.joinToString("\n\n----------------------------------------------------------------\n\n"), maxTagChars)
    }

    /**
     * Renders the `[HTTP_Requests_Parameters]` block: a `URL:` line carrying [safeUrl] (already
     * built by [UrlRedaction.redact]) and one `name=value (TYPE)` line per parameter, capped at 80.
     *
     * - Cookie TYPE gate (when cookies are stripped): the value is written as `[STRIPPED]` and the
     *   line deliberately bypasses the pipeline, because the session-key vocabulary and
     *   `cookieTypedParamRegex` would rewrite that marker to `[REDACTED]` and break the
     *   `PHPSESSID=[STRIPPED] (COOKIE)` shape the MCP carriers share.
     * - NAME filter (when tokens are redacted): a value whose parameter NAME looks sensitive is
     *   replaced with `[REDACTED]` before anything else sees it.
     * - Every other line goes through [Redaction.apply] in EVERY mode, so JWTs, bearer tokens,
     *   sensitive keys and user custom patterns are redacted in the VALUE, not only by name.
     * - Redact before truncate: the value is cut to [PARAM_VALUE_MAX_CHARS] only after the apply,
     *   because a JWT cut mid-payload no longer has three segments and the JWT rule would miss it.
     * - The caller runs the STRICT own-host pass over the whole block.
     *
     * This class IS constructed in production by `ui/UiActions.kt` (bountyPromptResolver); an
     * earlier measurement that found no instantiation was invalidated by a raw NUL byte in that
     * file, which made grep treat it as binary.
     */
    private fun buildRequestParameters(
        rr: HttpRequestResponse,
        safeUrl: String,
        policy: RedactionPolicy,
        hostSalt: String,
    ): String {
        val params =
            rr.request().parameters().take(80).joinToString("\n") { param ->
                val name = param.name()
                val type = param.type().name
                if (policy.stripCookies && Redaction.isCookieParameterType(type)) {
                    "${Redaction.apply(name, policy, stableHostSalt = hostSalt)}=[STRIPPED] ($type)"
                } else {
                    val value =
                        if (policy.redactTokens && sensitiveParamName.containsMatchIn(name)) "[REDACTED]" else param.value()
                    val head = Redaction.apply("$name=$value", policy, stableHostSalt = hostSalt)
                    "${head.take(name.length + 1 + PARAM_VALUE_MAX_CHARS)} ($type)"
                }
            }
        return buildString {
            appendLine("URL: $safeUrl")
            appendLine("Parameters:")
            append(if (params.isBlank()) "<none>" else params)
        }.trim()
    }

    private fun extractCookies(
        requestText: String,
        responseText: String?,
    ): String {
        val requestCookies =
            requestText
                .lineSequence()
                .filter { it.startsWith("Cookie:", ignoreCase = true) }
                .toList()
        val responseCookies =
            responseText
                .orEmpty()
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

    private fun truncateChunk(
        text: String,
        maxChunkChars: Int,
    ): String {
        if (text.length <= maxChunkChars) return text
        return text.take(maxChunkChars) + "\n...[truncated]..."
    }

    private fun truncateTag(
        text: String,
        maxTagChars: Int,
    ): String {
        if (text.length <= maxTagChars) return text
        return text.take(maxTagChars) + "\n...[tag content truncated]..."
    }

    private fun limitsForCategory(category: BountyPromptCategory): Pair<Int, Int> =
        when (category) {
            BountyPromptCategory.DETECTION -> 2_500 to 10_000
            BountyPromptCategory.RECON -> 3_500 to 14_000
            BountyPromptCategory.ADVISORY -> defaultMaxChunkChars to defaultMaxTagChars
        }

    private companion object {
        // Upper bound on a rendered parameter value, applied AFTER redaction.
        const val PARAM_VALUE_MAX_CHARS = 500
    }
}
