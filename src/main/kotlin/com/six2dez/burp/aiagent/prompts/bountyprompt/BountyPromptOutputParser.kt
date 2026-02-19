package com.six2dez.burp.aiagent.prompts.bountyprompt

import com.fasterxml.jackson.databind.JsonNode
import com.fasterxml.jackson.databind.MapperFeature
import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.databind.SerializationFeature
import com.fasterxml.jackson.databind.json.JsonMapper
import com.fasterxml.jackson.module.kotlin.registerKotlinModule

class BountyPromptOutputParser(
    private val mapper: ObjectMapper = JsonMapper.builder()
        .enable(MapperFeature.SORT_PROPERTIES_ALPHABETICALLY)
        .enable(SerializationFeature.ORDER_MAP_ENTRIES_BY_KEYS)
        .build()
        .registerKotlinModule()
) {

    fun parse(
        outputText: String,
        definition: BountyPromptDefinition
    ): List<BountyPromptFinding> {
        if (outputText.isBlank()) return emptyList()
        if (Regex("\\bNONE\\b", RegexOption.IGNORE_CASE).containsMatchIn(outputText)) {
            return emptyList()
        }

        val fromJson = parseFromJson(outputText, definition)
        if (fromJson.isNotEmpty()) return fromJson

        val fallbackDetail = outputText.trim().take(12_000)
        return listOf(
            BountyPromptFinding(
                title = definition.title,
                detail = fallbackDetail,
                severity = definition.severity,
                confidence = definition.confidence.score
            )
        )
    }

    private fun parseFromJson(
        outputText: String,
        definition: BountyPromptDefinition
    ): List<BountyPromptFinding> {
        val candidates = extractJsonCandidates(outputText)
        for (candidate in candidates) {
            val root = runCatching { mapper.readTree(candidate) }.getOrNull() ?: continue
            val nodes = extractFindingNodes(root)
            if (nodes.isEmpty()) continue
            return nodes.map { node ->
                BountyPromptFinding(
                    title = node.textAny("title", "name").ifBlank { definition.title }.take(140),
                    detail = node.textAny("detail", "description", "evidence")
                        .ifBlank { node.toString() }
                        .take(12_000),
                    severity = normalizeSeverity(node.textAny("severity").ifBlank { definition.severity }),
                    confidence = parseConfidence(node, definition.confidence.score)
                )
            }
        }
        return emptyList()
    }

    private fun extractFindingNodes(root: JsonNode): List<JsonNode> {
        return when {
            root.isArray -> root.toList()
            root.isObject && root.path("issues").isArray -> root.path("issues").toList()
            root.isObject && root.path("findings").isArray -> root.path("findings").toList()
            root.isObject && root.path("results").isArray -> root.path("results").toList()
            root.isObject -> listOf(root)
            else -> emptyList()
        }
    }

    private fun parseConfidence(node: JsonNode, fallback: Int): Int {
        val intVal = node.path("confidence").takeIf { !it.isMissingNode && !it.isNull }?.asInt()
        if (intVal != null && intVal > 0) return intVal.coerceIn(0, 100)

        val textVal = node.textAny("confidence")
        if (textVal.isNotBlank()) {
            return when (textVal.trim().lowercase()) {
                "certain" -> BountyPromptConfidence.CERTAIN.score
                "firm" -> BountyPromptConfidence.FIRM.score
                "tentative" -> BountyPromptConfidence.TENTATIVE.score
                else -> textVal.toIntOrNull()?.coerceIn(0, 100) ?: fallback
            }
        }
        return fallback
    }

    private fun normalizeSeverity(raw: String): String {
        return when (raw.trim().lowercase()) {
            "high" -> "High"
            "medium" -> "Medium"
            "low" -> "Low"
            else -> "Information"
        }
    }

    private fun JsonNode.textAny(vararg names: String): String {
        for (name in names) {
            val node = this.path(name)
            if (!node.isMissingNode && !node.isNull) {
                val text = node.asText("").trim()
                if (text.isNotBlank()) return text
            }
        }
        return ""
    }

    private fun extractJsonCandidates(text: String): List<String> {
        val trimmed = stripCodeFences(text.trim())
        if (trimmed.isBlank()) return emptyList()
        val out = mutableListOf<String>()

        if (runCatching { mapper.readTree(trimmed) }.isSuccess) {
            out.add(trimmed)
        }
        out.addAll(extractBalancedJsonCandidates(trimmed))
        return out.distinct()
    }

    private fun stripCodeFences(text: String): String {
        return text
            .replace(Regex("^```(?:json)?\\s*", setOf(RegexOption.IGNORE_CASE, RegexOption.MULTILINE)), "")
            .replace(Regex("\\s*```$", RegexOption.MULTILINE), "")
            .trim()
    }

    private fun extractBalancedJsonCandidates(text: String): List<String> {
        val results = mutableListOf<String>()
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
                if (ch == '"') inString = false
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
                    ']' -> if (stack.isNotEmpty() && stack.last() == '[') stack.removeLast() else {
                        start = -1
                        stack.clear()
                    }
                    '}' -> if (stack.isNotEmpty() && stack.last() == '{') stack.removeLast() else {
                        start = -1
                        stack.clear()
                    }
                }
                if (start >= 0 && stack.isEmpty()) {
                    results.add(text.substring(start, i + 1).trim())
                    start = -1
                }
            }
        }
        return results
    }
}
