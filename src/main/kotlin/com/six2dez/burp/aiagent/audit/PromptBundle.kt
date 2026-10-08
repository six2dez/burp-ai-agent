package com.six2dez.burp.aiagent.audit

import com.six2dez.burp.aiagent.backends.BackendLaunchConfig

/**
 * One prompt as the audit trail records it (quick 261008-sqa). The digest pair
 * (`promptSha256` + `promptUtf8Bytes`, `contextSha256` + `contextUtf8Bytes`) is always present and
 * identifies the bodies; `promptText` and `contextJson` are attached only when the bundle was built
 * with verbose audit on, and are null otherwise.
 */
data class PromptBundle(
    val createdAtEpochMs: Long,
    val sessionId: String,
    val backendId: String,
    val backendConfig: AuditBackendConfig,
    val verbose: Boolean,
    val promptText: String?,
    val promptSha256: String,
    val promptUtf8Bytes: Int,
    val contextJson: String?,
    val contextSha256: String?,
    val contextUtf8Bytes: Int?,
    val privacyMode: String,
    val determinismMode: Boolean,
    val promptSource: String? = null,
    val promptId: String? = null,
    val promptTitle: String? = null,
    val contextKind: String? = null,
)

/**
 * The allowlisted part of a [BackendLaunchConfig] that an audit record may carry. Header values and
 * environment values (the MCP token among them) are never copied, only their names; `baseUrl` is
 * reduced to its endpoint form without userinfo, query or fragment; `command` is dropped because its
 * arguments (or an inline `VAR=value` first token) can carry keys; `cliSessionId` is dropped because it
 * is the resume handle of the CLI's stored conversation; `sessionId` duplicates the record's own field
 * and `transport` is a runtime object.
 */
data class AuditBackendConfig(
    val backendId: String,
    val displayName: String,
    val model: String?,
    val baseUrl: String?,
    val embeddedMode: Boolean,
    val determinismMode: Boolean,
    val requestTimeoutSeconds: Long?,
    val cliTimeoutSeconds: Int?,
    val contextWindow: Int?,
    val headerNames: List<String>,
    val envKeys: List<String>,
) {
    companion object {
        fun from(config: BackendLaunchConfig): AuditBackendConfig =
            AuditBackendConfig(
                backendId = config.backendId,
                displayName = config.displayName,
                model = config.model,
                baseUrl = AuditLogger.endpointOf(config.baseUrl),
                embeddedMode = config.embeddedMode,
                determinismMode = config.determinismMode,
                requestTimeoutSeconds = config.requestTimeoutSeconds,
                cliTimeoutSeconds = config.cliTimeoutSeconds,
                contextWindow = config.contextWindow,
                headerNames = config.headers.keys.sorted(),
                envKeys = config.env.keys.sorted(),
            )
    }
}
