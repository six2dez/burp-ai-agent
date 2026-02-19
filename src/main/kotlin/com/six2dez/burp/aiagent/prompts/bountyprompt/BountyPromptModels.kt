package com.six2dez.burp.aiagent.prompts.bountyprompt

enum class BountyPromptCategory {
    DETECTION,
    RECON,
    ADVISORY
}

enum class BountyPromptOutputType {
    ISSUE,
    PROMPT_OUTPUT;

    companion object {
        fun fromString(raw: String?): BountyPromptOutputType {
            return when (raw?.trim()?.lowercase()) {
                "issue" -> ISSUE
                "prompt output" -> PROMPT_OUTPUT
                else -> ISSUE
            }
        }
    }
}

enum class BountyPromptConfidence(val score: Int) {
    CERTAIN(95),
    FIRM(90),
    TENTATIVE(80);

    companion object {
        fun fromString(raw: String?): BountyPromptConfidence {
            return when (raw?.trim()?.lowercase()) {
                "certain" -> CERTAIN
                "firm" -> FIRM
                "tentative" -> TENTATIVE
                else -> FIRM
            }
        }
    }
}

enum class BountyPromptTag(val token: String) {
    HTTP_REQUESTS("[HTTP_Requests]"),
    HTTP_REQUESTS_HEADERS("[HTTP_Requests_Headers]"),
    HTTP_REQUESTS_PARAMETERS("[HTTP_Requests_Parameters]"),
    HTTP_REQUEST_BODY("[HTTP_Request_Body]"),
    HTTP_RESPONSES("[HTTP_Responses]"),
    HTTP_RESPONSE_HEADERS("[HTTP_Response_Headers]"),
    HTTP_RESPONSE_BODY("[HTTP_Response_Body]"),
    HTTP_STATUS_CODE("[HTTP_Status_Code]"),
    HTTP_COOKIES("[HTTP_Cookies]");

    companion object {
        private val byToken = entries.associateBy { it.token }
        private val regex = Regex("\\[HTTP_[^\\]]+]")

        fun extractFrom(text: String): Set<BountyPromptTag> {
            if (text.isBlank()) return emptySet()
            return regex.findAll(text)
                .mapNotNull { match -> byToken[match.value] }
                .toCollection(LinkedHashSet())
        }
    }
}

data class BountyPromptDefinition(
    val id: String,
    val title: String,
    val category: BountyPromptCategory,
    val outputType: BountyPromptOutputType,
    val systemPrompt: String,
    val userPrompt: String,
    val severity: String,
    val confidence: BountyPromptConfidence,
    val tagsUsed: Set<BountyPromptTag>
)

data class LoadedBountyPrompts(
    val prompts: List<BountyPromptDefinition>,
    val errors: List<String>
)

data class ResolvedBountyPrompt(
    val resolvedUserPrompt: String,
    val previewText: String
)

data class BountyPromptFinding(
    val title: String,
    val detail: String,
    val severity: String,
    val confidence: Int
)
