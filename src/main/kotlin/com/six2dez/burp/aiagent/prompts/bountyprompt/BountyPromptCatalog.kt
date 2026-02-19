package com.six2dez.burp.aiagent.prompts.bountyprompt

object BountyPromptCatalog {

    val curatedPromptIds: Set<String> = linkedSetOf(
        "API_Keys_Exposure_Detection",
        "CSRF_Vulnerability_Assessment",
        "Security_Headers_Analysis",
        "Vulnerable_Software_Detection",
        "Extract_Endpoints",
        "Vulnerable_File_Upload_Endpoint_Detection",
        "Web_Attack_Suggestions",
        "Sensitive_Error_Messages_Detection"
    )

    private val categoryById: Map<String, BountyPromptCategory> = mapOf(
        "API_Keys_Exposure_Detection" to BountyPromptCategory.DETECTION,
        "CSRF_Vulnerability_Assessment" to BountyPromptCategory.DETECTION,
        "Security_Headers_Analysis" to BountyPromptCategory.DETECTION,
        "Vulnerable_Software_Detection" to BountyPromptCategory.DETECTION,
        "Vulnerable_File_Upload_Endpoint_Detection" to BountyPromptCategory.DETECTION,
        "Sensitive_Error_Messages_Detection" to BountyPromptCategory.DETECTION,
        "Extract_Endpoints" to BountyPromptCategory.RECON,
        "Web_Attack_Suggestions" to BountyPromptCategory.ADVISORY
    )

    fun categoryFor(id: String): BountyPromptCategory {
        return categoryById[id] ?: BountyPromptCategory.ADVISORY
    }

    fun humanizedTitle(id: String): String {
        if (id.isBlank()) return "Untitled Prompt"
        return id.split('_')
            .filter { it.isNotBlank() }
            .joinToString(" ") { token ->
                token.lowercase().replaceFirstChar { it.uppercase() }
            }
    }

    fun defaultEnabledPromptIds(): Set<String> = curatedPromptIds
}
