package com.six2dez.burp.aiagent.scanner

import burp.api.montoya.MontoyaApi
import com.fasterxml.jackson.databind.JsonNode
import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.module.kotlin.registerKotlinModule
import com.six2dez.burp.aiagent.audit.Hashing

// AWT-free contract: MUST NOT import java.awt.* or javax.swing.*

/** Shared ObjectMapper for parsing and compact-body serialization. Declared internal so
 *  PassiveAiScannerPrompts.kt (same package) can reference it without a second instance. */
internal val jsonMapper = ObjectMapper().registerKotlinModule()

private val CODE_FENCE_END_REGEX = Regex("\\s*```$", RegexOption.MULTILINE)

internal fun parseIssuesJson(json: String): List<AiIssueItem> {
    val root = jsonMapper.readTree(json)
    return parseIssuesNode(root)
}

internal fun parseIssuesFromAiResponse(
    text: String,
    api: MontoyaApi,
): List<AiIssueItem> {
    if (text.isBlank()) return emptyList()
    val cleaned = cleanJsonResponse(text)
    if (cleaned.isBlank() || cleaned == "[]") return emptyList()
    return try {
        parseIssuesJson(cleaned)
    } catch (e: Exception) {
        val preview = text.replace(Regex("\\s+"), " ").take(160)
        api.logging().logToError("[PassiveAiScanner] Failed to parse AI response after cleanup: ${e.message} | preview=$preview")
        emptyList()
    }
}

internal fun cleanJsonResponse(text: String): String {
    if (text.isBlank()) return ""
    val cleaned = stripCodeFences(text.trim())
    if (cleaned.isBlank()) return ""

    // Fast path: whole payload is already valid JSON.
    parseNodeIfValid(cleaned)?.let { node ->
        return when {
            node.isArray -> cleaned
            node.isObject && (node.has("issues") || node.has("findings") || node.has("results")) -> cleaned
            else -> ""
        }
    }

    // Fallback: extract the first balanced JSON array/object from mixed CLI output.
    for (candidate in extractBalancedJsonCandidates(cleaned)) {
        val node = parseNodeIfValid(candidate) ?: continue
        if (node.isArray) return candidate
        if (node.isObject && (node.has("issues") || node.has("findings") || node.has("results"))) return candidate
    }
    return ""
}

private fun parseIssuesNode(root: JsonNode): List<AiIssueItem> {
    val issueArray =
        when {
            root.isArray -> root
            root.isObject && root.path("issues").isArray -> root.path("issues")
            root.isObject && root.path("findings").isArray -> root.path("findings")
            root.isObject && root.path("results").isArray -> root.path("results")
            else -> return emptyList()
        }
    return issueArray.mapNotNull { node ->
        runCatching {
            AiIssueItem(
                reasoning = node.path("reasoning").takeIf { !it.isMissingNode && !it.isNull }?.asText(),
                title = node.path("title").takeIf { !it.isMissingNode && !it.isNull }?.asText(),
                severity = node.path("severity").takeIf { !it.isMissingNode && !it.isNull }?.asText(),
                detail = node.path("detail").takeIf { !it.isMissingNode && !it.isNull }?.asText(),
                confidence = node.path("confidence").takeIf { !it.isMissingNode && !it.isNull }?.asInt(),
                requestIndex = node.path("request_index").takeIf { !it.isMissingNode && !it.isNull }?.asInt(),
            )
        }.getOrNull()
    }
}

private fun parseNodeIfValid(candidate: String): JsonNode? = runCatching { jsonMapper.readTree(candidate) }.getOrNull()

private fun stripCodeFences(text: String): String =
    text
        .replace(Regex("^```(?:json)?\\s*", setOf(RegexOption.IGNORE_CASE, RegexOption.MULTILINE)), "")
        .replace(CODE_FENCE_END_REGEX, "")
        .trim()

private fun extractBalancedJsonCandidates(text: String): Sequence<String> =
    sequence {
        val openers = setOf('[', '{')
        var start = -1
        var stack = ArrayDeque<Char>()
        var inString = false
        var escaped = false

        for (i in text.indices) {
            val ch = text[i]
            if (inString) {
                if (escaped) {
                    escaped = false
                    continue
                }
                if (ch == '\\') {
                    escaped = true
                    continue
                }
                if (ch == '"') {
                    inString = false
                }
                continue
            }

            if (ch == '"') {
                inString = true
                continue
            }

            if (start < 0 && ch in openers) {
                start = i
                stack = ArrayDeque()
                stack.addLast(ch)
                continue
            }

            if (start >= 0) {
                when (ch) {
                    '[', '{' -> stack.addLast(ch)
                    ']' -> {
                        if (stack.isNotEmpty() && stack.last() == '[') {
                            stack.removeLast()
                        } else {
                            start = -1
                            stack.clear()
                        }
                    }
                    '}' -> {
                        if (stack.isNotEmpty() && stack.last() == '{') {
                            stack.removeLast()
                        } else {
                            start = -1
                            stack.clear()
                        }
                    }
                }
                if (start >= 0 && stack.isEmpty()) {
                    yield(text.substring(start, i + 1).trim())
                    start = -1
                }
            }
        }
    }

internal fun sha256Hex(text: String): String = Hashing.sha256Hex(text)
