package com.six2dez.burp.aiagent.ui

enum class PromptSource { FIXED, CUSTOM_SAVED, CUSTOM_AD_HOC }

enum class ContextKind { HTTP_SELECTION, SCANNER_ISSUE }

data class PromptLaunchSpec(
    val promptText: String,
    val actionName: String,
    val source: PromptSource,
    val contextKind: ContextKind,
    val customPromptId: String? = null,
    val customPromptTitle: String? = null,
) {
    fun toMetadataMap(): Map<String, String> =
        buildMap {
            put("promptSource", source.name)
            put("contextKind", contextKind.name)
            customPromptId?.let { put("promptId", it) }
            customPromptTitle?.let { put("promptTitle", it) }
        }
}
