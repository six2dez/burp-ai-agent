package com.six2dez.burp.aiagent.audit

data class PromptBundle(
    val createdAtEpochMs: Long,
    val sessionId: String,
    val backendId: String,
    val backendConfig: com.six2dez.burp.aiagent.backends.BackendLaunchConfig,
    val promptText: String,
    val promptSha256: String,
    val contextJson: String?,
    val contextSha256: String?,
    val privacyMode: String,
    val determinismMode: Boolean,
    val promptSource: String? = null,
    val promptId: String? = null,
    val promptTitle: String? = null,
    val contextKind: String? = null,
)
