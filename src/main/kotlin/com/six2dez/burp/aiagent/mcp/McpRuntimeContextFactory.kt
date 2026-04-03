package com.six2dez.burp.aiagent.mcp

import burp.api.montoya.MontoyaApi
import com.six2dez.burp.aiagent.audit.AiRequestLogger
import com.six2dez.burp.aiagent.config.McpSettings
import com.six2dez.burp.aiagent.mcp.tools.ResponsePreprocessorSettings
import com.six2dez.burp.aiagent.redact.PrivacyMode

class McpRuntimeContextFactory(private val api: MontoyaApi) {

    var aiRequestLogger: AiRequestLogger? = null

    fun create(
        settings: McpSettings,
        privacyMode: PrivacyMode,
        determinismMode: Boolean,
        preprocessSettings: ResponsePreprocessorSettings
    ): McpToolContext {
        val tools = McpToolCatalog.mergeWithDefaults(settings.toolToggles)
        val unsafeTools = McpToolCatalog.unsafeToolIds()
        val limiter = McpRequestLimiter(settings.maxConcurrentRequests)
        val hostSalt = "mcp-${settings.token.take(12)}"

        return McpToolContext(
            api = api,
            privacyMode = privacyMode,
            determinismMode = determinismMode,
            hostSalt = hostSalt,
            toolToggles = tools,
            unsafeEnabled = settings.unsafeEnabled,
            unsafeTools = unsafeTools,
            enabledUnsafeTools = settings.enabledUnsafeTools,
            limiter = limiter,
            edition = api.burpSuite().version().edition(),
            maxBodyBytes = settings.maxBodyBytes,
            proxyHistoryMaxItemsPerRequest = settings.proxyHistoryMaxItemsPerRequest,
            proxyHistoryNewestFirst = settings.proxyHistoryNewestFirst,
            allowUnpreprocessedProxyHistory = settings.allowUnpreprocessedProxyHistory,
            preprocessProxyHistory = preprocessSettings.preprocessProxyHistory,
            preprocessMaxResponseSizeKb = preprocessSettings.preprocessMaxResponseSizeKb,
            preprocessFilterBinaryContent = preprocessSettings.preprocessFilterBinaryContent,
            preprocessAllowedContentTypes = preprocessSettings.preprocessAllowedContentTypes,
            aiRequestLogger = aiRequestLogger
        )
    }
}
