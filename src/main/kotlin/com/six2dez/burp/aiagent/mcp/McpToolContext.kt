package com.six2dez.burp.aiagent.mcp

import burp.api.montoya.MontoyaApi
import burp.api.montoya.core.BurpSuiteEdition
import com.six2dez.burp.aiagent.audit.AiRequestLogger
import com.six2dez.burp.aiagent.audit.AuditLogger
import com.six2dez.burp.aiagent.backends.BackendRegistry
import com.six2dez.burp.aiagent.config.Defaults
import com.six2dez.burp.aiagent.mcp.external.ExternalMcpClientManager
import com.six2dez.burp.aiagent.mcp.tools.LimitedStringBuilder
import com.six2dez.burp.aiagent.mcp.tools.ResponsePreprocessorSettings
import com.six2dez.burp.aiagent.redact.PrivacyMode
import com.six2dez.burp.aiagent.redact.Redaction
import com.six2dez.burp.aiagent.redact.RedactionPolicy
import com.six2dez.burp.aiagent.redact.SecretTripwire
import com.six2dez.burp.aiagent.scanner.PassiveAiScanner
import com.six2dez.burp.aiagent.supervisor.AgentSupervisor

data class McpToolContext(
    val api: MontoyaApi,
    val privacyMode: PrivacyMode,
    val determinismMode: Boolean,
    val hostSalt: String,
    val toolToggles: Map<String, Boolean>,
    val unsafeEnabled: Boolean,
    val unsafeTools: Set<String>,
    val enabledUnsafeTools: Set<String>,
    val limiter: McpRequestLimiter,
    val edition: BurpSuiteEdition,
    val maxBodyBytes: Int,
    val proxyHistoryMaxItemsPerRequest: Int = Defaults.MCP_PROXY_HISTORY_MAX_ITEMS_PER_REQUEST,
    val proxyHistoryNewestFirst: Boolean = Defaults.MCP_PROXY_HISTORY_NEWEST_FIRST,
    val allowUnpreprocessedProxyHistory: Boolean = Defaults.MCP_ALLOW_UNPREPROCESSED_PROXY_HISTORY,
    val preprocessProxyHistory: Boolean = Defaults.PREPROCESS_PROXY_HISTORY_ENABLED,
    val preprocessMaxResponseSizeKb: Int = Defaults.PREPROCESS_MAX_RESPONSE_SIZE_KB,
    val preprocessFilterBinaryContent: Boolean = Defaults.PREPROCESS_FILTER_BINARY_CONTENT,
    val preprocessAllowedContentTypes: Set<String> = Defaults.PREPROCESS_ALLOWED_CONTENT_TYPES,
    val aiRequestLogger: AiRequestLogger? = null,
    val supervisor: AgentSupervisor? = null,
    val passiveScanner: PassiveAiScanner? = null,
    val backendRegistry: BackendRegistry? = null,
    // 07-03 D-03: when true, McpScopeFilter restricts every scope-aware MCP tool to
    // in-scope hosts. Default false preserves bytewise behaviour for legacy call sites.
    val scopeOnly: Boolean = false,
    // Phase 16 (CAP-02): optional external MCP client manager. Null when no external servers
    // are configured. Defaults to null so all existing construction sites compile unchanged.
    val externalClientManager: ExternalMcpClientManager? = null,
) {
    fun isToolEnabled(name: String): Boolean = toolToggles[name] ?: false

    fun isUnsafeTool(name: String): Boolean = unsafeTools.contains(name)

    fun isUnsafeToolAllowed(name: String): Boolean {
        if (!isUnsafeTool(name)) return true
        if (unsafeEnabled) return true
        return enabledUnsafeTools.contains(name)
    }

    fun redactIfNeeded(raw: String): String {
        // Compute the FINAL post-redaction string (two existing branches preserved).
        val finalText =
            if (privacyMode == PrivacyMode.OFF) {
                raw
            } else {
                Redaction.apply(raw, RedactionPolicy.fromMode(privacyMode), stableHostSalt = hostSalt)
            }
        // PRIV-03 (Phase 15): tripwire scan on the FINAL redacted MCP output (G1/G8).
        // Detect + audit-log on match via the single SecretTripwire helper (WR-03 — one payload
        // shape across all hooks); NEVER block — return finalText regardless (SC2).
        SecretTripwire
            .detectAndBuild(finalText, path = "mcp", sessionId = supervisor?.currentSessionId())
            ?.let { AuditLogger.emitGlobal("secret_tripwire_detect", it) }
        // NO blocking — return finalText (SC2 / non-interactive path).
        return finalText
    }

    fun resolveHost(host: String): String = Redaction.deAnonymizeHost(host, hostSalt) ?: host

    fun limitOutput(raw: String): String {
        val limit = maxBodyBytes.coerceAtLeast(1)
        val bytes = raw.toByteArray(Charsets.UTF_8)
        if (bytes.size <= limit) return raw
        val truncated = String(bytes, 0, limit, Charsets.UTF_8)
        return "$truncated... (truncated ${bytes.size} bytes to $limit bytes)"
    }

    fun limitedJoin(
        items: Sequence<String>,
        separator: String = "\n\n",
    ): String {
        val builder = LimitedStringBuilder(maxBodyBytes.coerceAtLeast(1))
        var first = true
        for (item in items) {
            if (!first) {
                if (!builder.append(separator)) break
            }
            if (!builder.append(item)) break
            first = false
        }
        return builder.build()
    }

    fun responsePreprocessorSettings(): ResponsePreprocessorSettings =
        ResponsePreprocessorSettings(
            preprocessProxyHistory = preprocessProxyHistory,
            preprocessMaxResponseSizeKb = preprocessMaxResponseSizeKb,
            preprocessFilterBinaryContent = preprocessFilterBinaryContent,
            preprocessAllowedContentTypes = preprocessAllowedContentTypes,
        )
}
