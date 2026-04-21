package com.six2dez.burp.aiagent.backends.cli

import com.six2dez.burp.aiagent.backends.AiBackend
import com.six2dez.burp.aiagent.backends.AiBackendFactory

class ClaudeCliBackendFactory : AiBackendFactory {
    override fun create(): AiBackend =
        CliBackend(
            id = "claude-cli",
            displayName = "Claude Code",
        )
}
