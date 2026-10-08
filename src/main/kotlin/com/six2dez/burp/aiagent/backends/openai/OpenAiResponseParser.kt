package com.six2dez.burp.aiagent.backends.openai

import com.fasterxml.jackson.databind.JsonNode
import com.fasterxml.jackson.databind.ObjectMapper
import com.six2dez.burp.aiagent.backends.TokenUsage

/** Assistant text and token usage extracted from one chat-completions response body. */
internal data class ParsedCompletion(
    val content: String,
    val usage: TokenUsage?,
)

/**
 * Parses a buffered OpenAI-style chat-completions response body.
 *
 * Two shapes are accepted:
 * - a single JSON document (`choices[0].message.content`), the normal answer to a
 *   `"stream":false` request. Malformed JSON propagates Jackson's exception unchanged.
 * - a Server-Sent Events body (`data:` lines terminated by `data: [DONE]`). Some
 *   OpenAI-compatible servers stream regardless of the request flag; the transport buffers the
 *   whole body, so the `choices[0].delta.content` fragments are concatenated here. Malformed
 *   `data:` lines are skipped and only textual content nodes are appended (a JSON null delta must
 *   never become the literal text "null"). `event:`, `id:`, `retry:` and comment lines are ignored.
 *
 * The body is untrusted provider input: it is only read into a [JsonNode] tree (no polymorphic
 * binding), and blank content is reported by the caller with its existing error message.
 */
internal object OpenAiResponseParser {
    private const val SSE_DATA_PREFIX = "data:"
    private const val SSE_DONE_SENTINEL = "[DONE]"

    fun parse(
        mapper: ObjectMapper,
        body: String,
    ): ParsedCompletion {
        val leading = body.trimStart()
        if (leading.startsWith(SSE_DATA_PREFIX) || leading.startsWith("event:") || leading.startsWith(":")) {
            return parseSse(mapper, body)
        }
        val node = mapper.readTree(body)
        val content =
            node
                .path("choices")
                .path(0)
                .path("message")
                .path("content")
                .asText()
        return ParsedCompletion(content = content, usage = extractUsage(node))
    }

    /** Returns null when the node carries neither `prompt_tokens` nor `completion_tokens`. */
    fun extractUsage(node: JsonNode): TokenUsage? {
        val usageNode = node.path("usage")
        val promptTokens = usageNode.path("prompt_tokens").asInt(-1)
        val completionTokens = usageNode.path("completion_tokens").asInt(-1)
        if (promptTokens < 0 && completionTokens < 0) return null
        return TokenUsage(
            inputTokens = promptTokens.coerceAtLeast(0),
            outputTokens = completionTokens.coerceAtLeast(0),
        )
    }

    private fun parseSse(
        mapper: ObjectMapper,
        body: String,
    ): ParsedCompletion {
        val content = StringBuilder()
        var usage: TokenUsage? = null
        for (rawLine in body.lineSequence()) {
            val chunk = parseDataLine(mapper, rawLine.trim()) ?: continue
            val choice = chunk.path("choices").path(0)
            val delta = choice.path("delta").path("content")
            val message = choice.path("message").path("content")
            when {
                delta.isTextual -> content.append(delta.asText())
                message.isTextual -> content.append(message.asText())
            }
            val usageNode = chunk.get("usage")
            if (usageNode != null && usageNode.isObject) {
                extractUsage(chunk)?.let { usage = it }
            }
        }
        return ParsedCompletion(content = content.toString(), usage = usage)
    }

    private fun parseDataLine(
        mapper: ObjectMapper,
        line: String,
    ): JsonNode? {
        val payload = if (line.startsWith(SSE_DATA_PREFIX)) line.removePrefix(SSE_DATA_PREFIX).trim() else ""
        if (payload.isEmpty() || payload == SSE_DONE_SENTINEL) return null
        // A malformed chunk is skipped; the remaining chunks still carry the answer.
        return runCatching { mapper.readTree(payload) }.getOrNull()
    }
}
