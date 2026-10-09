package com.six2dez.burp.aiagent.backends.openai

private val versionedBaseRegex = Regex(".*/v\\d+$", RegexOption.IGNORE_CASE)

private const val CHAT_COMPLETIONS_SUFFIX = "/chat/completions"
private const val MODELS_SUFFIX = "/models"

/**
 * Builds the versioned `/v1/models` URL used by the NVIDIA NIM and Perplexity health checks.
 *
 * A `GET /v1/models` is free, whereas the previous health check sent a billable chat completion.
 * Unlike the generic backend's models URL (which maps `…/chat/completions` to `…/models` for
 * self-hosted servers), a bare host here always gets the `/v1` prefix: both providers serve their
 * model catalog at `/v1/models` even though Perplexity's chat endpoint has no `/v1` prefix.
 */
internal object OpenAiModelsUrl {
    fun versioned(baseUrl: String): String {
        var trimmed = baseUrl.trim().trimEnd('/')
        if (trimmed.endsWith(CHAT_COMPLETIONS_SUFFIX, ignoreCase = true)) {
            trimmed = trimmed.dropLast(CHAT_COMPLETIONS_SUFFIX.length).trimEnd('/')
        }
        return when {
            trimmed.endsWith(MODELS_SUFFIX, ignoreCase = true) -> trimmed
            versionedBaseRegex.matches(trimmed) -> "$trimmed$MODELS_SUFFIX"
            else -> "$trimmed/v1$MODELS_SUFFIX"
        }
    }
}
