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
) {
    fun isValid(): Boolean = id.isNotBlank() && title.isNotBlank() && promptText.isNotBlank() && tags.isNotEmpty()

    companion object {
        fun filterForMenu(
            library: List<CustomPromptDefinition>,
            tag: CustomPromptTag,
        ): List<CustomPromptDefinition> = library.filter { tag in it.tags && it.showInContextMenu }
    }
}
