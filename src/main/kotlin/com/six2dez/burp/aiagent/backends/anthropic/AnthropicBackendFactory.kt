package com.six2dez.burp.aiagent.backends.anthropic

import com.six2dez.burp.aiagent.backends.AiBackend
import com.six2dez.burp.aiagent.backends.AiBackendFactory

class AnthropicBackendFactory : AiBackendFactory {
    override fun create(): AiBackend = AnthropicBackend()
}
