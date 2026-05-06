package com.six2dez.burp.aiagent.config

import com.fasterxml.jackson.annotation.JsonIgnoreProperties

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
    }
}
