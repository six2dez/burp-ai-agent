package com.six2dez.burp.aiagent.prompts.bountyprompt

import com.fasterxml.jackson.databind.JsonNode
import com.fasterxml.jackson.databind.MapperFeature
import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.databind.SerializationFeature
import com.fasterxml.jackson.databind.json.JsonMapper
import com.fasterxml.jackson.module.kotlin.registerKotlinModule
import java.io.File

class BountyPromptLoader(
    private val mapper: ObjectMapper = JsonMapper.builder()
        .enable(MapperFeature.SORT_PROPERTIES_ALPHABETICALLY)
        .enable(SerializationFeature.ORDER_MAP_ENTRIES_BY_KEYS)
        .build()
        .registerKotlinModule()
) {

    fun loadFromDirectory(
        directoryPath: String,
        enabledPromptIds: Set<String>
    ): LoadedBountyPrompts {
        val dir = File(directoryPath.trim())
        if (!dir.exists() || !dir.isDirectory) {
            return LoadedBountyPrompts(
                prompts = emptyList(),
                errors = listOf("BountyPrompt directory not found or not a directory: ${dir.absolutePath}")
            )
        }

        val jsonFiles = dir.listFiles { f -> f.isFile && f.name.lowercase().endsWith(".json") }
            ?.sortedBy { it.name.lowercase() }
            ?: return LoadedBountyPrompts(
                prompts = emptyList(),
                errors = listOf("Unable to list prompt files from: ${dir.absolutePath}")
            )

        val allowed = if (enabledPromptIds.isEmpty()) {
            BountyPromptCatalog.defaultEnabledPromptIds()
        } else {
            enabledPromptIds
        }

        val prompts = mutableListOf<BountyPromptDefinition>()
        val errors = mutableListOf<String>()

        for (file in jsonFiles) {
            val id = file.nameWithoutExtension

            if (id !in BountyPromptCatalog.curatedPromptIds) continue
            if (id !in allowed) continue

            val loaded = loadPromptFile(file, id)
            if (loaded == null) {
                errors.add("Skipping malformed prompt file: ${file.name}")
                continue
            }
            prompts.add(loaded)
        }

        val sorted = prompts.sortedWith(
            compareBy<BountyPromptDefinition> { it.category.name }.thenBy { it.title.lowercase() }
        )

        return LoadedBountyPrompts(prompts = sorted, errors = errors)
    }

    private fun loadPromptFile(file: File, id: String): BountyPromptDefinition? {
        return runCatching {
            val node = mapper.readTree(file)
            parsePromptNode(node, id)
        }.getOrNull()
    }

    private fun parsePromptNode(node: JsonNode, id: String): BountyPromptDefinition? {
        val systemPrompt = node.path("systemPrompt").asText("").trim()
        val userPrompt = node.path("userPrompt").asText("").trim()
        if (systemPrompt.isBlank() || userPrompt.isBlank()) return null

        val title = node.path("title").asText("").trim().ifBlank {
            BountyPromptCatalog.humanizedTitle(id)
        }
        val outputType = BountyPromptOutputType.fromString(node.path("outputType").asText(""))
        val severity = normalizeSeverity(node.path("severity").asText(""))
        val confidence = BountyPromptConfidence.fromString(node.path("confidence").asText(""))
        val tagsUsed = BountyPromptTag.extractFrom(userPrompt)

        return BountyPromptDefinition(
            id = id,
            title = title,
            category = BountyPromptCatalog.categoryFor(id),
            outputType = outputType,
            systemPrompt = systemPrompt,
            userPrompt = userPrompt,
            severity = severity,
            confidence = confidence,
            tagsUsed = tagsUsed
        )
    }

    private fun normalizeSeverity(raw: String): String {
        return when (raw.trim().lowercase()) {
            "high" -> "High"
            "medium" -> "Medium"
            "low" -> "Low"
            "information", "informational", "info" -> "Information"
            else -> "Information"
        }
    }
}
