package com.six2dez.burp.aiagent.context

data class ContextCapture(
    val contextJson: String,
    val previewText: String,
)

data class ContextOptions(
    val privacyMode: com.six2dez.burp.aiagent.redact.PrivacyMode,
    val deterministic: Boolean,
    val hostSalt: String,
    val maxRequestBodyChars: Int? = null,
    val maxResponseBodyChars: Int? = null,
    val compactJson: Boolean = true,
)

data class BurpContextEnvelope(
    val schemaVersion: Int = 1,
    val capturedAtEpochMs: Long,
    val items: List<BurpContextItem>,
)

sealed interface BurpContextItem

data class HttpItem(
    val tool: String?,
    val url: String?,
    val method: String?,
    val request: String,
    val response: String?,
) : BurpContextItem

data class AuditIssueItem(
    val name: String,
    val severity: String?,
    val confidence: String?,
    val detail: String?,
    val remediation: String?,
    val affectedHost: String?,
) : BurpContextItem
