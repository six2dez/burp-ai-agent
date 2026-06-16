package com.six2dez.burp.aiagent.scanner

data class PassiveAiFinding(
    val timestamp: Long,
    val url: String,
    val title: String,
    val severity: String,
    val detail: String,
    val confidence: Int,
    val source: String = "ai",
    val issueCreated: Boolean = true,
)

data class PassiveAiScannerStatus(
    val enabled: Boolean,
    val requestsAnalyzed: Int,
    val issuesFound: Int,
    val lastAnalysisTime: Long,
    val queueSize: Int,
)

internal data class LocalFinding(
    val title: String,
    val severity: String,
    val detail: String,
    val confidence: Int,
)

internal data class AiIssueItem(
    val reasoning: String? = null,
    val title: String? = null,
    val severity: String? = null,
    val detail: String? = null,
    val confidence: Int? = null,
    val requestIndex: Int? = null,
)

internal data class CachedAiIssues(
    val createdAtMs: Long,
    val issues: List<AiIssueItem>,
)
