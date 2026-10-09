package com.six2dez.burp.aiagent.context

import burp.api.montoya.MontoyaApi
import burp.api.montoya.http.message.HttpRequestResponse
import burp.api.montoya.scanner.audit.issues.AuditIssue
import com.fasterxml.jackson.databind.MapperFeature
import com.fasterxml.jackson.databind.SerializationFeature
import com.fasterxml.jackson.databind.json.JsonMapper
import com.fasterxml.jackson.module.kotlin.registerKotlinModule
import com.six2dez.burp.aiagent.config.Defaults
import com.six2dez.burp.aiagent.redact.Redaction
import com.six2dez.burp.aiagent.redact.RedactionPolicy
import com.six2dez.burp.aiagent.redact.UrlRedaction
import com.six2dez.burp.aiagent.util.SecurityExcerpts
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.util.logging.Logger

class ContextCollector(
    private val api: MontoyaApi,
) {
    private val log = Logger.getLogger(ContextCollector::class.java.name)
    private val mapper =
        JsonMapper
            .builder()
            .enable(MapperFeature.SORT_PROPERTIES_ALPHABETICALLY)
            .enable(SerializationFeature.ORDER_MAP_ENTRIES_BY_KEYS)
            .build()
            .registerKotlinModule()

    fun fromRequestResponses(
        rr: List<HttpRequestResponse>,
        options: ContextOptions,
    ): ContextCapture {
        val policy = RedactionPolicy.fromMode(options.privacyMode)
        val items =
            rr
                .map { item ->
                    val req =
                        truncateHttpMessageBody(
                            item.request().toString(),
                            options.maxRequestBodyChars ?: DEFAULT_REQUEST_BODY_MAX_CHARS,
                        )
                    val resp =
                        item.response()?.toString()?.let {
                            truncateHttpMessageBody(
                                it,
                                options.maxResponseBodyChars ?: DEFAULT_RESPONSE_BODY_MAX_CHARS,
                            )
                        }

                    // Order is mandatory: Redaction.apply aliases the whole Host: value first, then the
                    // own-host pass aliases the item's hostname everywhere else (Referer, Origin,
                    // Location, absolute URLs in bodies). The reverse order would leave an alias on the
                    // Host: line for Redaction.apply to alias again.
                    val rawUrl: String? = item.request().url()
                    val ownHost = item.httpService()?.host() ?: UrlRedaction.hostOf(rawUrl)
                    val ownHostPass: (String) -> String = { text ->
                        if (policy.anonymizeHosts && ownHost != null) {
                            UrlRedaction.anonymizeHostOccurrences(text, ownHost, options.hostSalt)
                        } else {
                            text
                        }
                    }
                    val redactedReq = ownHostPass(Redaction.apply(req, policy, stableHostSalt = options.hostSalt))
                    val redactedResp =
                        resp?.let { ownHostPass(Redaction.apply(it, policy, stableHostSalt = options.hostSalt)) }

                    rawUrl to
                        HttpItem(
                            tool = null,
                            url = rawUrl?.let { ownHostPass(UrlRedaction.redact(it, policy, options.hostSalt)) },
                            method = item.request().method(),
                            request = redactedReq,
                            response = redactedResp,
                        )
                }.let { list ->
                    // The sort key uses the RAW url so the deterministic order does not depend on the
                    // host salt (an alias would reshuffle items whenever the salt rotates). Only the
                    // order is derived from it; the raw url itself is never emitted.
                    if (options.deterministic) list.sortedBy { (rawUrl, item) -> stableKey(rawUrl, item) } else list
                }.map { it.second }

        // Global context cap: drop trailing items if total serialized size exceeds limit
        val cappedItems = capItemsBySize(items)

        val env =
            BurpContextEnvelope(
                capturedAtEpochMs = System.currentTimeMillis(),
                items = cappedItems,
            )

        val json = toJson(env, options.compactJson)
        val preview = buildHttpPreview(cappedItems, policy, options)

        return ContextCapture(contextJson = json, previewText = preview)
    }

    fun fromAuditIssues(
        issues: List<AuditIssue>,
        options: ContextOptions,
    ): ContextCapture {
        val policy = RedactionPolicy.fromMode(options.privacyMode)
        val items =
            issues
                .map { i ->
                    val host: String? = i.httpService()?.host()
                    // Same apply-then-own-host order as the HTTP capture: Redaction.apply handles
                    // tokens, JWTs and custom patterns in every mode, then STRICT aliases the issue's
                    // own host wherever the scanner wrote it into the text.
                    val redactText: (String) -> String = { text ->
                        val applied = Redaction.apply(text, policy, stableHostSalt = options.hostSalt)
                        if (policy.anonymizeHosts && host != null) {
                            UrlRedaction.anonymizeHostOccurrences(applied, host, options.hostSalt)
                        } else {
                            applied
                        }
                    }
                    val name: String? = i.name()
                    val detail: String? = i.detail()
                    val remediation: String? = i.remediation()
                    AuditIssueItem(
                        name = redactText(name.orEmpty()),
                        severity = i.severity()?.name,
                        confidence = i.confidence()?.name,
                        detail = detail?.let(redactText),
                        remediation = remediation?.let(redactText),
                        affectedHost =
                            host?.let {
                                if (policy.anonymizeHosts) UrlRedaction.aliasHost(it, options.hostSalt) else it
                            },
                    )
                }.let { list ->
                    if (options.deterministic) list.sortedBy { stableKey(it) } else list
                }

        val env =
            BurpContextEnvelope(
                capturedAtEpochMs = System.currentTimeMillis(),
                items = items,
            )

        val json = toJson(env, options.compactJson)
        val preview = buildIssuePreview(items, policy, options)

        return ContextCapture(contextJson = json, previewText = preview)
    }

    private fun toJson(
        env: BurpContextEnvelope,
        compact: Boolean,
    ): String =
        if (compact) {
            mapper.writeValueAsString(env)
        } else {
            mapper.writerWithDefaultPrettyPrinter().writeValueAsString(env)
        }

    private fun buildHttpPreview(
        items: List<HttpItem>,
        policy: RedactionPolicy,
        options: ContextOptions,
    ): String {
        // item.url already holds the redacted string that is sent; printing it as-is keeps the
        // preview truthful, and re-redacting it would alias the alias.
        val sampleLines =
            items.take(PREVIEW_MAX_ITEMS).map { item ->
                val sentUrl = item.url?.ifBlank { null } ?: "-"
                "${item.method ?: "?"} $sentUrl"
            }
        return buildPreview(
            count = items.size,
            kind = "HTTP selection",
            policy = policy,
            deterministic = options.deterministic,
            sampleLines = sampleLines,
        )
    }

    private fun buildIssuePreview(
        items: List<AuditIssueItem>,
        policy: RedactionPolicy,
        options: ContextOptions,
    ): String {
        val sampleLines =
            items.take(PREVIEW_MAX_ITEMS).map { item ->
                val host = item.affectedHost ?: "-"
                "[${item.severity ?: "UNKNOWN"}] ${item.name} @ $host"
            }
        return buildPreview(
            count = items.size,
            kind = "Scanner findings",
            policy = policy,
            deterministic = options.deterministic,
            sampleLines = sampleLines,
        )
    }

    private fun buildPreview(
        count: Int,
        kind: String,
        policy: RedactionPolicy,
        deterministic: Boolean,
        sampleLines: List<String>,
    ): String =
        """
            Kind: $kind
            Items: $count
            Redaction:
              - Cookie stripping: ${policy.stripCookies}
              - Token redaction: ${policy.redactTokens}
              - Host anonymization: ${policy.anonymizeHosts}
            Deterministic: $deterministic
            Sample:
${sampleLines.ifEmpty { listOf("- (none)") }.joinToString(separator = "\n") { "  - $it" }}
        """.trimIndent()

    private fun stableKey(
        rawUrl: String?,
        item: HttpItem,
    ): String {
        val base = listOf(rawUrl, item.method, hashOf(item.request)).joinToString("|")
        return base
    }

    private fun stableKey(item: AuditIssueItem): String {
        val base = listOf(item.name, item.severity, item.affectedHost, hashOf(item.detail ?: "")).joinToString("|")
        return base
    }

    private fun hashOf(value: String): String {
        val digest =
            MessageDigest
                .getInstance("SHA-256")
                .digest(value.toByteArray(StandardCharsets.UTF_8))
        return digest.take(8).joinToString("") { "%02x".format(it) }
    }

    private fun truncateHttpMessageBody(
        raw: String,
        maxBodyChars: Int,
    ): String {
        if (maxBodyChars <= 0) return raw
        val crlfIndex = raw.indexOf("\r\n\r\n")
        val splitIndex = if (crlfIndex >= 0) crlfIndex else raw.indexOf("\n\n")
        if (splitIndex < 0) return raw
        val delimiterLength = if (crlfIndex >= 0) 4 else 2
        val bodyStart = splitIndex + delimiterLength
        if (bodyStart >= raw.length) return raw
        val body = raw.substring(bodyStart)
        if (body.length <= maxBodyChars) return raw
        val truncated = body.take(maxBodyChars)
        val excerpts = SecurityExcerpts.extract(body, truncated.length)
        val suffix =
            if (excerpts.isNullOrBlank()) {
                "\n...[body truncated]..."
            } else {
                "\n...[body truncated]...\n\n=== SECURITY-RELEVANT EXCERPTS ===\n$excerpts"
            }
        return raw.substring(0, bodyStart) + truncated + suffix
    }

    private fun <T> capItemsBySize(items: List<T>): List<T> {
        if (items.size <= 1) return items
        var totalChars = 0
        val result = mutableListOf<T>()
        for (item in items) {
            val itemJson = mapper.writeValueAsString(item)
            if (totalChars + itemJson.length > Defaults.MAX_CONTEXT_TOTAL_CHARS && result.isNotEmpty()) {
                log.warning(
                    "[ContextCollector] Context cap reached at ${result.size}/${items.size} items ($totalChars chars). Dropping ${items.size - result.size} trailing item(s).",
                )
                break
            }
            totalChars += itemJson.length
            result.add(item)
        }
        return result
    }

    private companion object {
        private const val DEFAULT_REQUEST_BODY_MAX_CHARS = 4_000
        private const val DEFAULT_RESPONSE_BODY_MAX_CHARS = 8_000
        private const val PREVIEW_MAX_ITEMS = 3
    }
}
