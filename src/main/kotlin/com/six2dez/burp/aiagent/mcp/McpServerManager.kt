package com.six2dez.burp.aiagent.mcp

import com.six2dez.burp.aiagent.audit.AiRequestLogger
import com.six2dez.burp.aiagent.config.McpSettings
import com.six2dez.burp.aiagent.redact.PrivacyMode

interface McpServerManager {
    fun setAiRequestLogger(logger: AiRequestLogger)
    fun start(settings: McpSettings, privacyMode: PrivacyMode, determinismMode: Boolean, callback: (McpServerState) -> Unit)
    fun stop(callback: (McpServerState) -> Unit)
    fun shutdown()
}
