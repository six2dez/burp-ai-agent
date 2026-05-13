package com.six2dez.burp.aiagent.config

import com.fasterxml.jackson.annotation.JsonIgnoreProperties
import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.module.kotlin.registerKotlinModule

enum class CustomPromptTag { HTTP_SELECTION, SCANNER_ISSUE }

@JsonIgnoreProperties(ignoreUnknown = true)
data class CustomPromptDefinition(
    val id: String,
    val title: String,
    val promptText: String,
    val tags: Set<CustomPromptTag>,
    val showInContextMenu: Boolean = true,
    val isFavorite: Boolean = false,
) {
    fun isValid(): Boolean = id.isNotBlank() && title.isNotBlank() && promptText.isNotBlank() && tags.isNotEmpty()

    companion object {
        fun filterForMenu(
            library: List<CustomPromptDefinition>,
            tag: CustomPromptTag,
        ): List<CustomPromptDefinition> = library.filter { tag in it.tags && it.showInContextMenu }

        /**
         * Filter the library by a free-form query against title and prompt text. Empty/blank query
         * returns the library unchanged. Match is case-insensitive substring.
         */
        fun searchFilter(
            library: List<CustomPromptDefinition>,
            query: String,
        ): List<CustomPromptDefinition> {
            val q = query.trim()
            if (q.isEmpty()) return library
            val needle = q.lowercase()
            return library.filter { entry ->
                entry.title.lowercase().contains(needle) || entry.promptText.lowercase().contains(needle)
            }
        }

        /**
         * Stable sort that places favorites first, preserving relative order within each group.
         */
        fun sortFavoritesFirst(library: List<CustomPromptDefinition>): List<CustomPromptDefinition> {
            val favorites = library.filter { it.isFavorite }
            val others = library.filterNot { it.isFavorite }
            return favorites + others
        }

        /**
         * Parse a JSON string produced by the export handler into a list of valid prompt definitions.
         * Returns an empty list on blank input or any parse error. Filters entries by [isValid] to
         * drop malformed objects that Jackson deserialised but that fail business-level validation.
         */
        fun parseLibraryJson(text: String): List<CustomPromptDefinition> {
            if (text.isBlank()) return emptyList()
            return try {
                ObjectMapper()
                    .registerKotlinModule()
                    .readValue(text, Array<CustomPromptDefinition>::class.java)
                    .toList()
                    .filter { it.isValid() }
            } catch (e: Exception) {
                emptyList()
            }
        }

        /**
         * Merge [incoming] entries into [existing] by id.
         *
         * Input-side deduplication uses [associateBy] (last-occurrence-wins per D-02 — intentional
         * semantic correction from the prior `distinctBy` first-wins behaviour). Matching ids replace
         * existing entries in their original positions; new ids are appended in incoming order.
         * The [incoming] list is expected to be validity-filtered before calling this method
         * (e.g. via [parseLibraryJson]); no additional [isValid] check is applied here.
         */
        fun mergeById(
            existing: List<CustomPromptDefinition>,
            incoming: List<CustomPromptDefinition>,
        ): List<CustomPromptDefinition> {
            // Input dedup: last occurrence wins.
            val deduped = incoming.associateBy { it.id }.values.toList()
            val incomingById = deduped.associateBy { it.id }
            // Replace matching ids in-place, preserving existing order.
            val result = existing.map { incomingById[it.id] ?: it }.toMutableList()
            val existingIds = existing.map { it.id }.toSet()
            // Append new ids in incoming order.
            result.addAll(deduped.filter { it.id !in existingIds })
            return result
        }

        /**
         * Adjacent-swap move within a favorites/non-favorites group.
         *
         * Returns the original list unchanged when: (a) [index] is out of bounds, (b) [index] +
         * [delta] is out of bounds, or (c) the move would cross the favorites/non-favorites boundary.
         * Per D-05: reject semantics, not clamp.
         */
        fun applyMove(
            library: List<CustomPromptDefinition>,
            index: Int,
            delta: Int,
        ): List<CustomPromptDefinition> {
            if (index !in library.indices) return library
            val target = index + delta
            if (target !in library.indices) return library
            if (library[index].isFavorite != library[target].isFavorite) return library
            val result = library.toMutableList()
            val moved = result.removeAt(index)
            result.add(target, moved)
            return result
        }
    }
}
