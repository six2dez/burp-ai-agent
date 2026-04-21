package com.six2dez.burp.aiagent.backends.cli

import com.six2dez.burp.aiagent.backends.AiBackend
import com.six2dez.burp.aiagent.backends.AiBackendFactory

class GeminiCliBackendFactory : AiBackendFactory {
    override fun create(): AiBackend =
        CliBackend(
            id = "gemini-cli",
            displayName = "Gemini CLI",
        )
}
