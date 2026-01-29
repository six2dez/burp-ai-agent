package com.six2dez.burp.aiagent.backends.openai

import com.six2dez.burp.aiagent.backends.AiBackend
import com.six2dez.burp.aiagent.backends.AiBackendFactory

class OpenAiCompatibleBackendFactory : AiBackendFactory {
    override fun create(): AiBackend = OpenAiCompatibleBackend()
}
