package com.six2dez.burp.aiagent.backends.cli

import com.six2dez.burp.aiagent.backends.AiBackend
import com.six2dez.burp.aiagent.backends.AiBackendFactory

class CodexCliBackendFactory : AiBackendFactory {
    override fun create(): AiBackend =
        CliBackend(
            id = "codex-cli",
            displayName = "Codex CLI",
        )
}
