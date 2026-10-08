package com.six2dez.burp.aiagent.backends.openai

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test

class OpenAiModelsUrlTest {
    @Test
    fun bareHostsGetTheV1ModelsPath() {
        assertEquals("https://integrate.api.nvidia.com/v1/models", OpenAiModelsUrl.versioned("https://integrate.api.nvidia.com"))
        assertEquals("https://api.perplexity.ai/v1/models", OpenAiModelsUrl.versioned("https://api.perplexity.ai"))
        assertEquals("https://api.perplexity.ai/v1/models", OpenAiModelsUrl.versioned("  https://api.perplexity.ai/  "))
    }

    @Test
    fun versionedBasesAppendModels() {
        assertEquals("https://x/v1/models", OpenAiModelsUrl.versioned("https://x/v1"))
        assertEquals("https://x/v1/models", OpenAiModelsUrl.versioned("https://x/v1/"))
        assertEquals("https://x/v2/models", OpenAiModelsUrl.versioned("https://x/v2"))
    }

    @Test
    fun chatCompletionsSuffixIsStripped() {
        assertEquals("https://api.perplexity.ai/v1/models", OpenAiModelsUrl.versioned("https://api.perplexity.ai/chat/completions"))
        assertEquals("https://x/v1/models", OpenAiModelsUrl.versioned("https://x/v1/chat/completions"))
        assertEquals("https://x/V1/models", OpenAiModelsUrl.versioned("https://x/V1/Chat/Completions"))
    }

    @Test
    fun modelsUrlIsReturnedUnchanged() {
        assertEquals("https://x/v1/models", OpenAiModelsUrl.versioned("https://x/v1/models"))
    }
}
