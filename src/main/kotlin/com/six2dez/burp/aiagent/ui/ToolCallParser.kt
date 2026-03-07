package com.six2dez.burp.aiagent.ui

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive

internal data class ParsedToolCall(val tool: String, val argsJson: String?)

internal object ToolCallParser {
    private const val MAX_JSON_CANDIDATES = 12

    fun extractFirst(text: String): ParsedToolCall? {
        val candidates = linkedSetOf<String>()
        candidates.addAll(extractFencedJsonCandidates(text))
        val trimmed = text.trim()
        if (trimmed.startsWith("{") && trimmed.endsWith("}")) {
            candidates.add(trimmed)
        }
        candidates.addAll(extractJsonObjectCandidates(text))
        for (candidate in candidates) {
            val parsed = parseToolJson(candidate)
            if (parsed != null) return parsed
        }
        return null
    }

    private fun parseToolJson(jsonText: String): ParsedToolCall? {
        val rootObject = runCatching {
            Json.parseToJsonElement(jsonText).jsonObject
        }.getOrNull() ?: return null
        return parseToolCallObject(rootObject)
    }

    private fun parseToolCallObject(obj: JsonObject): ParsedToolCall? {
        val direct = buildToolCall(obj)
        if (direct != null) return direct
        val nested = firstNestedToolCallObject(obj) ?: return null
        return buildToolCall(nested)
    }

    private fun buildToolCall(obj: JsonObject): ParsedToolCall? {
        val tool = resolveToolName(obj) ?: return null
        val args = resolveToolArgs(obj)
        return ParsedToolCall(tool = tool, argsJson = args)
    }

    private fun firstNestedToolCallObject(obj: JsonObject): JsonObject? {
        firstToolCallObject(obj["tool_calls"].asArrayOrNull())?.let { return it }

        val messageObj = obj["message"].asObjectOrNull()
        firstToolCallObject(messageObj?.get("tool_calls").asArrayOrNull())?.let { return it }

        val responseObj = obj["response"].asObjectOrNull()
        firstToolCallObject(responseObj?.get("tool_calls").asArrayOrNull())?.let { return it }

        val firstChoice = obj["choices"].asArrayOrNull()
            ?.firstOrNull()
            .asObjectOrNull()
        if (firstChoice != null) {
            firstToolCallObject(firstChoice["tool_calls"].asArrayOrNull())?.let { return it }
            val choiceMessage = firstChoice["message"].asObjectOrNull()
            firstToolCallObject(choiceMessage?.get("tool_calls").asArrayOrNull())?.let { return it }
        }
        return null
    }

    private fun firstToolCallObject(array: JsonArray?): JsonObject? {
        return array?.firstOrNull().asObjectOrNull()
    }

    private fun resolveToolName(obj: JsonObject): String? {
        val directTool = obj["tool"].asStringOrNull()?.trim()
        if (!directTool.isNullOrBlank()) return directTool

        val directName = obj["name"].asStringOrNull()?.trim()
        if (!directName.isNullOrBlank()) return directName

        val functionName = obj["function"]
            .asObjectOrNull()
            ?.get("name")
            .asStringOrNull()
            ?.trim()
        if (!functionName.isNullOrBlank()) return functionName

        val functionCallName = obj["function_call"]
            .asObjectOrNull()
            ?.get("name")
            .asStringOrNull()
            ?.trim()
        if (!functionCallName.isNullOrBlank()) return functionCallName

        return null
    }

    private fun resolveToolArgs(obj: JsonObject): String? {
        val directArgs = obj["args"]
        if (directArgs != null) return normalizeArgsJson(directArgs)

        val arguments = obj["arguments"]
        if (arguments != null) return normalizeArgsJson(arguments)

        val input = obj["input"]
        if (input != null) return normalizeArgsJson(input)

        val functionArgs = obj["function"]
            .asObjectOrNull()
            ?.get("arguments")
        if (functionArgs != null) return normalizeArgsJson(functionArgs)

        val functionCallArgs = obj["function_call"]
            .asObjectOrNull()
            ?.get("arguments")
        return normalizeArgsJson(functionCallArgs)
    }

    private fun normalizeArgsJson(value: JsonElement?): String? {
        if (value == null) return null
        val primitive = runCatching { value.jsonPrimitive }.getOrNull()
        if (primitive != null && primitive.isString) {
            val raw = primitive.contentOrNull?.trim().orEmpty()
            return raw.ifBlank { null }
        }
        return value.toString()
    }

    private fun extractFencedJsonCandidates(text: String): List<String> {
        val regex = Regex("```(?:tool|json)\\s*([\\s\\S]*?)\\s*```", RegexOption.IGNORE_CASE)
        return regex.findAll(text)
            .mapNotNull { match ->
                val payload = match.groupValues.getOrNull(1)?.trim().orEmpty()
                if (payload.startsWith("{") && payload.endsWith("}")) payload else null
            }
            .take(MAX_JSON_CANDIDATES)
            .toList()
    }

    private fun extractJsonObjectCandidates(text: String): List<String> {
        val out = mutableListOf<String>()
        var start = -1
        var depth = 0
        var inString = false
        var escaped = false
        for (i in text.indices) {
            val ch = text[i]
            if (start < 0) {
                if (ch == '{') {
                    start = i
                    depth = 1
                    inString = false
                    escaped = false
                }
                continue
            }
            if (inString) {
                when {
                    escaped -> escaped = false
                    ch == '\\' -> escaped = true
                    ch == '"' -> inString = false
                }
                continue
            }
            when (ch) {
                '"' -> inString = true
                '{' -> depth++
                '}' -> {
                    depth--
                    if (depth == 0) {
                        out.add(text.substring(start, i + 1))
                        if (out.size >= MAX_JSON_CANDIDATES) break
                        start = -1
                    }
                }
            }
        }
        return out
    }

    private fun JsonElement?.asObjectOrNull(): JsonObject? {
        return runCatching { this?.jsonObject }.getOrNull()
    }

    private fun JsonElement?.asArrayOrNull(): JsonArray? {
        return runCatching { this?.jsonArray }.getOrNull()
    }

    private fun JsonElement?.asStringOrNull(): String? {
        return runCatching { this?.jsonPrimitive?.contentOrNull }.getOrNull()
    }
}
