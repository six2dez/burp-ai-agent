package com.six2dez.burp.aiagent.config

import burp.api.montoya.MontoyaApi
import burp.api.montoya.persistence.Preferences
import com.six2dez.burp.aiagent.prompts.bountyprompt.BountyPromptCatalog
import com.six2dez.burp.aiagent.redact.PrivacyMode
import com.six2dez.burp.aiagent.scanner.PayloadRisk
import com.six2dez.burp.aiagent.scanner.ScanMode

enum class SeverityLevel {
    LOW,
    MEDIUM,
    HIGH,
    CRITICAL;

    companion object {
        fun fromString(raw: String?): SeverityLevel {
            return entries.firstOrNull { it.name.equals(raw, ignoreCase = true) } ?: LOW
        }
    }
}

data class AgentSettings(
    val codexCmd: String,
    val geminiCmd: String,
    val opencodeCmd: String,
    val claudeCmd: String,
    val agentProfile: String,
    val ollamaCliCmd: String,
    val ollamaModel: String,
    val ollamaUrl: String,
    val ollamaServeCmd: String,
    val ollamaAutoStart: Boolean,
    val ollamaApiKey: String,
    val ollamaHeaders: String,
    val ollamaTimeoutSeconds: Int,
    val ollamaContextWindow: Int,
    val lmStudioUrl: String,
    val lmStudioModel: String,
    val lmStudioTimeoutSeconds: Int,
    val lmStudioServerCmd: String,
    val lmStudioAutoStart: Boolean,
    val lmStudioApiKey: String,
    val lmStudioHeaders: String,
    val openAiCompatibleUrl: String,
    val openAiCompatibleModel: String,
    val openAiCompatibleApiKey: String,
    val openAiCompatibleHeaders: String,
    val openAiCompatibleTimeoutSeconds: Int,
    val nvidiaNimUrl: String = "https://integrate.api.nvidia.com",
    val nvidiaNimModel: String = "",
    val nvidiaNimApiKey: String = "",
    val nvidiaNimHeaders: String = "",
    val nvidiaNimTimeoutSeconds: Int = 60,
    val copilotCmd: String = "",
    val requestPromptTemplate: String,
    val issuePromptTemplate: String,
    val issueAnalyzePrompt: String,
    val issuePocPrompt: String,
    val issueImpactPrompt: String,
    val requestSummaryPrompt: String,
    val explainJsPrompt: String,
    val accessControlPrompt: String,
    val loginSequencePrompt: String,
    val hostAnonymizationSalt: String,
    val preferredBackendId: String,
    val privacyMode: PrivacyMode,
    val determinismMode: Boolean,
    val autoRestart: Boolean,
    val auditEnabled: Boolean,
    val mcpSettings: McpSettings,
    // Passive AI Scanner settings
    val passiveAiEnabled: Boolean = false,
    val passiveAiRateSeconds: Int = 5,
    val passiveAiScopeOnly: Boolean = true,
    val passiveAiMaxSizeKb: Int = 96,
    val passiveAiMinSeverity: SeverityLevel = SeverityLevel.LOW,
    val passiveAiEndpointDedupMinutes: Int = 30,
    val passiveAiResponseFingerprintDedupMinutes: Int = 30,
    val passiveAiPromptCacheTtlMinutes: Int = 30,
    val passiveAiEndpointCacheEntries: Int = 5_000,
    val passiveAiResponseFingerprintCacheEntries: Int = 5_000,
    val passiveAiPromptCacheEntries: Int = 500,
    val passiveAiRequestBodyMaxChars: Int = 2_000,
    val passiveAiResponseBodyMaxChars: Int = 4_000,
    val passiveAiHeaderMaxCount: Int = 40,
    val passiveAiParamMaxCount: Int = 15,
    val passiveAiExcludedExtensions: String = Defaults.DEFAULT_EXCLUDED_EXTENSIONS_CSV,
    val passiveAiBatchSize: Int = 3,
    val passiveAiPersistentCacheEnabled: Boolean = true,
    val passiveAiPersistentCacheTtlHours: Int = 24,
    val passiveAiPersistentCacheMaxMb: Int = 50,
    val contextRequestBodyMaxChars: Int = 4_000,
    val contextResponseBodyMaxChars: Int = 8_000,
    val contextCompactJson: Boolean = true,
    // Active AI Scanner settings
    val activeAiEnabled: Boolean = false,
    val activeAiMaxConcurrent: Int = 3,
    val activeAiMaxPayloadsPerPoint: Int = 10,
    val activeAiTimeoutSeconds: Int = 30,
    val activeAiRequestDelayMs: Int = 100,
    val activeAiMaxRiskLevel: PayloadRisk = PayloadRisk.SAFE,
    val activeAiScopeOnly: Boolean = true,
    val activeAiAutoFromPassive: Boolean = true,  // Auto-queue passive findings
    val activeAiScanMode: ScanMode = ScanMode.FULL,
    val activeAiUseCollaborator: Boolean = false,  // SSRF OAST confirmation
    val activeAiAdaptivePayloads: Boolean = false,
    // BountyPrompt integration settings
    val bountyPromptEnabled: Boolean = false,
    val bountyPromptDir: String = "",
    val bountyPromptAutoCreateIssues: Boolean = true,
    val bountyPromptIssueConfidenceThreshold: Int = 90,
    val bountyPromptEnabledPromptIds: Set<String> = emptySet(),
    // AI Request Logger settings
    val aiRequestLoggerEnabled: Boolean = true,
    val aiRequestLoggerMaxEntries: Int = 500
)

class AgentSettingsRepository(api: MontoyaApi) {
    private val prefs: Preferences = api.persistence().preferences()
    /** Thread-safe cached settings snapshot. Updated atomically on save(). */
    private val cachedSettings = java.util.concurrent.atomic.AtomicReference<AgentSettings?>(null)

    fun load(): AgentSettings {
        // Return cached snapshot if available (thread-safe immutable data class)
        cachedSettings.get()?.let { return it }
        migrateIfNeeded()
        val privacy = PrivacyMode.fromString(prefs.getString(KEY_PRIVACY_MODE))
        val mcpSettings = loadMcpSettings()
        val rawGeminiCmd = prefs.getString(KEY_GEMINI_CMD).orEmpty().trim()
        return AgentSettings(
            codexCmd = prefs.getString(KEY_CODEX_CMD).orEmpty().trim().ifBlank { defaultCodexCmd() },
            geminiCmd = normalizeLegacyGeminiCmd(rawGeminiCmd).ifBlank { defaultGeminiCmd() },
            opencodeCmd = prefs.getString(KEY_OPENCODE_CMD).orEmpty().trim().ifBlank { defaultOpenCodeCmd() },
            claudeCmd = prefs.getString(KEY_CLAUDE_CMD).orEmpty().trim().ifBlank { defaultClaudeCmd() },
            agentProfile = prefs.getString(KEY_AGENT_PROFILE).orEmpty().trim().ifBlank { defaultAgentProfile() },
            ollamaCliCmd = prefs.getString(KEY_OLLAMA_CLI_CMD).orEmpty().trim().ifBlank { defaultOllamaCliCmd() },
            ollamaModel = prefs.getString(KEY_OLLAMA_MODEL).orEmpty().trim().ifBlank { defaultOllamaModel() },
            ollamaUrl = (prefs.getString(KEY_OLLAMA_URL) ?: "http://127.0.0.1:11434").trim(),
            ollamaServeCmd = prefs.getString(KEY_OLLAMA_SERVE_CMD).orEmpty().trim().ifBlank { defaultOllamaServeCmd() },
            ollamaAutoStart = prefs.getBoolean(KEY_OLLAMA_AUTOSTART) ?: true,
            ollamaApiKey = prefs.getString(KEY_OLLAMA_API_KEY).orEmpty().trim(),
            ollamaHeaders = prefs.getString(KEY_OLLAMA_HEADERS).orEmpty(),
            ollamaTimeoutSeconds = (prefs.getInteger(KEY_OLLAMA_TIMEOUT) ?: defaultOllamaTimeoutSeconds())
                .coerceIn(30, 3600),
            ollamaContextWindow = (prefs.getInteger(KEY_OLLAMA_CONTEXT_WINDOW) ?: defaultOllamaContextWindow())
                .coerceIn(2048, 256000),
            lmStudioUrl = (prefs.getString(KEY_LMSTUDIO_URL) ?: "http://127.0.0.1:1234").trim(),
            lmStudioModel = prefs.getString(KEY_LMSTUDIO_MODEL).orEmpty().trim().ifBlank { defaultLmStudioModel() },
            lmStudioTimeoutSeconds = (prefs.getInteger(KEY_LMSTUDIO_TIMEOUT) ?: defaultLmStudioTimeoutSeconds())
                .coerceIn(30, 3600),
            lmStudioServerCmd = prefs.getString(KEY_LMSTUDIO_SERVER_CMD).orEmpty().trim().ifBlank { defaultLmStudioServerCmd() },
            lmStudioAutoStart = prefs.getBoolean(KEY_LMSTUDIO_AUTOSTART) ?: true,
            lmStudioApiKey = prefs.getString(KEY_LMSTUDIO_API_KEY).orEmpty().trim(),
            lmStudioHeaders = prefs.getString(KEY_LMSTUDIO_HEADERS).orEmpty(),
            openAiCompatibleUrl = prefs.getString(KEY_OPENAI_COMPAT_URL).orEmpty().trim(),
            openAiCompatibleModel = prefs.getString(KEY_OPENAI_COMPAT_MODEL).orEmpty().trim(),
            openAiCompatibleApiKey = prefs.getString(KEY_OPENAI_COMPAT_API_KEY).orEmpty().trim(),
            openAiCompatibleHeaders = prefs.getString(KEY_OPENAI_COMPAT_HEADERS).orEmpty(),
            openAiCompatibleTimeoutSeconds = (prefs.getInteger(KEY_OPENAI_COMPAT_TIMEOUT) ?: defaultOpenAiCompatTimeoutSeconds())
                .coerceIn(30, 3600),
            nvidiaNimUrl = (prefs.getString(KEY_NVIDIA_NIM_URL) ?: defaultNvidiaNimUrl()).trim().ifBlank {
                defaultNvidiaNimUrl()
            },
            nvidiaNimModel = prefs.getString(KEY_NVIDIA_NIM_MODEL).orEmpty().trim(),
            nvidiaNimApiKey = prefs.getString(KEY_NVIDIA_NIM_API_KEY).orEmpty().trim(),
            nvidiaNimHeaders = prefs.getString(KEY_NVIDIA_NIM_HEADERS).orEmpty(),
            nvidiaNimTimeoutSeconds = (prefs.getInteger(KEY_NVIDIA_NIM_TIMEOUT) ?: defaultNvidiaNimTimeoutSeconds())
                .coerceIn(30, 3600),
            copilotCmd = prefs.getString(KEY_COPILOT_CMD).orEmpty().trim().ifBlank { defaultCopilotCmd() },
            requestPromptTemplate = prefs.getString(KEY_PROMPT_FIND_VULNS).orEmpty().ifBlank { defaultRequestPrompt() },
            issuePromptTemplate = prefs.getString(KEY_PROMPT_FULL_REPORT).orEmpty().ifBlank { defaultIssuePrompt() },
            issueAnalyzePrompt = prefs.getString(KEY_PROMPT_ISSUE_ANALYZE).orEmpty().ifBlank { defaultIssueAnalyzePrompt() },
            issuePocPrompt = prefs.getString(KEY_PROMPT_ISSUE_POC).orEmpty().ifBlank { defaultIssuePocPrompt() },
            issueImpactPrompt = prefs.getString(KEY_PROMPT_ISSUE_IMPACT).orEmpty().ifBlank { defaultIssueImpactPrompt() },
            requestSummaryPrompt = prefs.getString(KEY_PROMPT_QUICK_RECON).orEmpty().ifBlank { defaultRequestSummaryPrompt() },
            explainJsPrompt = prefs.getString(KEY_PROMPT_EXPLAIN_JS).orEmpty().ifBlank { defaultExplainJsPrompt() },
            accessControlPrompt = prefs.getString(KEY_PROMPT_ACCESS_CONTROL).orEmpty().ifBlank { defaultAccessControlPrompt() },
            loginSequencePrompt = prefs.getString(KEY_PROMPT_LOGIN_SEQUENCE).orEmpty().ifBlank { defaultLoginSequencePrompt() },
            hostAnonymizationSalt = prefs.getString(KEY_HOST_SALT).orEmpty().ifBlank {
                val generated = McpSettings.generateToken() // Reuse token generator for salt
                prefs.setString(KEY_HOST_SALT, generated)
                generated
            },
            preferredBackendId = (prefs.getString(KEY_PREFERRED_BACKEND) ?: "burp-ai").trim(),
            privacyMode = privacy,
            determinismMode = prefs.getBoolean(KEY_DETERMINISM) ?: false,
            autoRestart = prefs.getBoolean(KEY_AUTORESTART) ?: true,
            auditEnabled = prefs.getBoolean(KEY_AUDIT_ENABLED) ?: false,
            mcpSettings = mcpSettings,
            passiveAiEnabled = prefs.getBoolean(KEY_PASSIVE_AI_ENABLED) ?: false,
            passiveAiRateSeconds = (prefs.getInteger(KEY_PASSIVE_AI_RATE) ?: 5).coerceIn(1, 60),
            passiveAiScopeOnly = prefs.getBoolean(KEY_PASSIVE_AI_SCOPE_ONLY) ?: true,
            passiveAiMaxSizeKb = (prefs.getInteger(KEY_PASSIVE_AI_MAX_SIZE) ?: 96).coerceIn(16, 1024),
            passiveAiMinSeverity = SeverityLevel.fromString(prefs.getString(KEY_PASSIVE_AI_MIN_SEVERITY)),
            passiveAiEndpointDedupMinutes = (prefs.getInteger(KEY_PASSIVE_AI_ENDPOINT_DEDUP_MINUTES) ?: 30).coerceIn(1, 240),
            passiveAiResponseFingerprintDedupMinutes = (prefs.getInteger(KEY_PASSIVE_AI_FINGERPRINT_DEDUP_MINUTES) ?: 30).coerceIn(1, 240),
            passiveAiPromptCacheTtlMinutes = (prefs.getInteger(KEY_PASSIVE_AI_PROMPT_CACHE_TTL_MINUTES) ?: 30).coerceIn(1, 240),
            passiveAiEndpointCacheEntries = (prefs.getInteger(KEY_PASSIVE_AI_ENDPOINT_CACHE_ENTRIES) ?: 5_000).coerceIn(100, 50_000),
            passiveAiResponseFingerprintCacheEntries = (prefs.getInteger(KEY_PASSIVE_AI_FINGERPRINT_CACHE_ENTRIES) ?: 5_000).coerceIn(100, 50_000),
            passiveAiPromptCacheEntries = (prefs.getInteger(KEY_PASSIVE_AI_PROMPT_CACHE_ENTRIES) ?: 500).coerceIn(50, 5_000),
            passiveAiRequestBodyMaxChars = (prefs.getInteger(KEY_PASSIVE_AI_REQUEST_BODY_MAX_CHARS) ?: 2_000).coerceIn(256, 20_000),
            passiveAiResponseBodyMaxChars = (prefs.getInteger(KEY_PASSIVE_AI_RESPONSE_BODY_MAX_CHARS) ?: 4_000).coerceIn(512, 40_000),
            passiveAiHeaderMaxCount = (prefs.getInteger(KEY_PASSIVE_AI_HEADER_MAX_COUNT) ?: 40).coerceIn(5, 120),
            passiveAiParamMaxCount = (prefs.getInteger(KEY_PASSIVE_AI_PARAM_MAX_COUNT) ?: 15).coerceIn(5, 100),
            passiveAiExcludedExtensions = prefs.getString(KEY_PASSIVE_AI_EXCLUDED_EXTENSIONS).orEmpty().ifBlank {
                Defaults.DEFAULT_EXCLUDED_EXTENSIONS_CSV
            },
            passiveAiBatchSize = (prefs.getInteger(KEY_PASSIVE_AI_BATCH_SIZE) ?: 3).coerceIn(1, 5),
            passiveAiPersistentCacheEnabled = prefs.getBoolean(KEY_PASSIVE_AI_PERSISTENT_CACHE_ENABLED) ?: true,
            passiveAiPersistentCacheTtlHours = (prefs.getInteger(KEY_PASSIVE_AI_PERSISTENT_CACHE_TTL_HOURS) ?: 24).coerceIn(1, 168),
            passiveAiPersistentCacheMaxMb = (prefs.getInteger(KEY_PASSIVE_AI_PERSISTENT_CACHE_MAX_MB) ?: 50).coerceIn(10, 500),
            contextRequestBodyMaxChars = (prefs.getInteger(KEY_CONTEXT_REQUEST_BODY_MAX_CHARS) ?: 4_000).coerceIn(256, 40_000),
            contextResponseBodyMaxChars = (prefs.getInteger(KEY_CONTEXT_RESPONSE_BODY_MAX_CHARS) ?: 8_000).coerceIn(512, 80_000),
            contextCompactJson = prefs.getBoolean(KEY_CONTEXT_COMPACT_JSON) ?: true,
            activeAiEnabled = prefs.getBoolean(KEY_ACTIVE_AI_ENABLED) ?: false,
            activeAiMaxConcurrent = (prefs.getInteger(KEY_ACTIVE_AI_MAX_CONCURRENT) ?: 3).coerceIn(1, 10),
            activeAiMaxPayloadsPerPoint = (prefs.getInteger(KEY_ACTIVE_AI_MAX_PAYLOADS) ?: 10).coerceIn(1, 50),
            activeAiTimeoutSeconds = (prefs.getInteger(KEY_ACTIVE_AI_TIMEOUT) ?: 30).coerceIn(5, 120),
            activeAiRequestDelayMs = (prefs.getInteger(KEY_ACTIVE_AI_DELAY) ?: 100).coerceIn(0, 5000),
            activeAiMaxRiskLevel = PayloadRisk.fromString(prefs.getString(KEY_ACTIVE_AI_RISK_LEVEL)),
            activeAiScopeOnly = prefs.getBoolean(KEY_ACTIVE_AI_SCOPE_ONLY) ?: true,
            activeAiAutoFromPassive = prefs.getBoolean(KEY_ACTIVE_AI_AUTO_PASSIVE) ?: true,
            activeAiScanMode = ScanMode.fromString(prefs.getString(KEY_ACTIVE_AI_SCAN_MODE)),
            activeAiUseCollaborator = prefs.getBoolean(KEY_ACTIVE_AI_USE_COLLABORATOR) ?: false,
            activeAiAdaptivePayloads = prefs.getBoolean(KEY_ACTIVE_AI_ADAPTIVE_PAYLOADS) ?: false,
            bountyPromptEnabled = prefs.getBoolean(KEY_BOUNTY_PROMPT_ENABLED) ?: false,
            bountyPromptDir = prefs.getString(KEY_BOUNTY_PROMPT_DIR).orEmpty().trim().ifBlank { defaultBountyPromptDir() },
            bountyPromptAutoCreateIssues = prefs.getBoolean(KEY_BOUNTY_PROMPT_AUTO_CREATE_ISSUES) ?: true,
            bountyPromptIssueConfidenceThreshold = (prefs.getInteger(KEY_BOUNTY_PROMPT_CONFIDENCE_THRESHOLD) ?: 90)
                .coerceIn(0, 100),
            bountyPromptEnabledPromptIds = parseIdSet(
                prefs.getString(KEY_BOUNTY_PROMPT_ENABLED_IDS),
                BountyPromptCatalog.defaultEnabledPromptIds()
            ),
            aiRequestLoggerEnabled = prefs.getBoolean(KEY_AI_LOGGER_ENABLED) ?: true,
            aiRequestLoggerMaxEntries = (prefs.getInteger(KEY_AI_LOGGER_MAX_ENTRIES) ?: 500).coerceIn(50, 5_000)
        ).also { cachedSettings.set(it) }
    }

    fun defaultSettings(): AgentSettings {
        return AgentSettings(
            codexCmd = defaultCodexCmd(),
            geminiCmd = defaultGeminiCmd(),
            opencodeCmd = defaultOpenCodeCmd(),
            claudeCmd = defaultClaudeCmd(),
            agentProfile = defaultAgentProfile(),
            ollamaCliCmd = defaultOllamaCliCmd(),
            ollamaModel = defaultOllamaModel(),
            ollamaUrl = "http://127.0.0.1:11434",
            ollamaServeCmd = defaultOllamaServeCmd(),
            ollamaAutoStart = true,
            ollamaApiKey = "",
            ollamaHeaders = "",
            ollamaTimeoutSeconds = defaultOllamaTimeoutSeconds(),
            ollamaContextWindow = defaultOllamaContextWindow(),
            lmStudioUrl = "http://127.0.0.1:1234",
            lmStudioModel = defaultLmStudioModel(),
            lmStudioTimeoutSeconds = defaultLmStudioTimeoutSeconds(),
            lmStudioServerCmd = defaultLmStudioServerCmd(),
            lmStudioAutoStart = true,
            lmStudioApiKey = "",
            lmStudioHeaders = "",
            openAiCompatibleUrl = "",
            openAiCompatibleModel = "",
            openAiCompatibleApiKey = "",
            openAiCompatibleHeaders = "",
            openAiCompatibleTimeoutSeconds = defaultOpenAiCompatTimeoutSeconds(),
            nvidiaNimUrl = defaultNvidiaNimUrl(),
            nvidiaNimModel = "",
            nvidiaNimApiKey = "",
            nvidiaNimHeaders = "",
            nvidiaNimTimeoutSeconds = defaultNvidiaNimTimeoutSeconds(),
            copilotCmd = defaultCopilotCmd(),
            requestPromptTemplate = defaultRequestPrompt(),
            issuePromptTemplate = defaultIssuePrompt(),
            issueAnalyzePrompt = defaultIssueAnalyzePrompt(),
            issuePocPrompt = defaultIssuePocPrompt(),
            issueImpactPrompt = defaultIssueImpactPrompt(),
            requestSummaryPrompt = defaultRequestSummaryPrompt(),
            explainJsPrompt = defaultExplainJsPrompt(),
            accessControlPrompt = defaultAccessControlPrompt(),
            loginSequencePrompt = defaultLoginSequencePrompt(),
            hostAnonymizationSalt = McpSettings.generateToken(),
            preferredBackendId = "burp-ai",
            privacyMode = PrivacyMode.OFF,
            determinismMode = false,
            autoRestart = true,
            auditEnabled = false,
            mcpSettings = defaultMcpSettings(),
            passiveAiEnabled = false,
            passiveAiRateSeconds = 5,
            passiveAiScopeOnly = true,
            passiveAiMaxSizeKb = 96,
            passiveAiMinSeverity = SeverityLevel.LOW,
            passiveAiEndpointDedupMinutes = 30,
            passiveAiResponseFingerprintDedupMinutes = 30,
            passiveAiPromptCacheTtlMinutes = 30,
            passiveAiEndpointCacheEntries = 5_000,
            passiveAiResponseFingerprintCacheEntries = 5_000,
            passiveAiPromptCacheEntries = 500,
            passiveAiRequestBodyMaxChars = 2_000,
            passiveAiResponseBodyMaxChars = 4_000,
            passiveAiHeaderMaxCount = 40,
            passiveAiParamMaxCount = 15,
            contextRequestBodyMaxChars = 4_000,
            contextResponseBodyMaxChars = 8_000,
            contextCompactJson = true,
            activeAiEnabled = false,
            activeAiMaxConcurrent = 3,
            activeAiMaxPayloadsPerPoint = 10,
            activeAiTimeoutSeconds = 30,
            activeAiRequestDelayMs = 100,
            activeAiMaxRiskLevel = PayloadRisk.SAFE,
            activeAiScopeOnly = true,
            activeAiAutoFromPassive = true,
            activeAiScanMode = ScanMode.FULL,
            activeAiUseCollaborator = false,
            bountyPromptEnabled = false,
            bountyPromptDir = defaultBountyPromptDir(),
            bountyPromptAutoCreateIssues = true,
            bountyPromptIssueConfidenceThreshold = 90,
            bountyPromptEnabledPromptIds = BountyPromptCatalog.defaultEnabledPromptIds(),
            aiRequestLoggerEnabled = true,
            aiRequestLoggerMaxEntries = 500
        )
    }

    fun save(settings: AgentSettings) {
        // Atomically update the cached snapshot before persisting to disk
        cachedSettings.set(settings)
        prefs.setString(KEY_CODEX_CMD, settings.codexCmd)
        prefs.setString(KEY_GEMINI_CMD, settings.geminiCmd)
        prefs.setString(KEY_OPENCODE_CMD, settings.opencodeCmd)
        prefs.setString(KEY_CLAUDE_CMD, settings.claudeCmd)
        prefs.setString(KEY_AGENT_PROFILE, settings.agentProfile)
        prefs.setString(KEY_OLLAMA_CLI_CMD, settings.ollamaCliCmd)
        prefs.setString(KEY_OLLAMA_MODEL, settings.ollamaModel)
        prefs.setString(KEY_OLLAMA_URL, settings.ollamaUrl)
        prefs.setString(KEY_OLLAMA_SERVE_CMD, settings.ollamaServeCmd)
        prefs.setBoolean(KEY_OLLAMA_AUTOSTART, settings.ollamaAutoStart)
        prefs.setString(KEY_OLLAMA_API_KEY, settings.ollamaApiKey)
        prefs.setString(KEY_OLLAMA_HEADERS, settings.ollamaHeaders)
        prefs.setInteger(KEY_OLLAMA_TIMEOUT, settings.ollamaTimeoutSeconds.coerceIn(30, 3600))
        prefs.setInteger(KEY_OLLAMA_CONTEXT_WINDOW, settings.ollamaContextWindow.coerceIn(2048, 128000))
        prefs.setString(KEY_LMSTUDIO_URL, settings.lmStudioUrl)
        prefs.setString(KEY_LMSTUDIO_MODEL, settings.lmStudioModel)
        prefs.setInteger(KEY_LMSTUDIO_TIMEOUT, settings.lmStudioTimeoutSeconds.coerceIn(30, 3600))
        prefs.setString(KEY_LMSTUDIO_SERVER_CMD, settings.lmStudioServerCmd)
        prefs.setBoolean(KEY_LMSTUDIO_AUTOSTART, settings.lmStudioAutoStart)
        prefs.setString(KEY_LMSTUDIO_API_KEY, settings.lmStudioApiKey)
        prefs.setString(KEY_LMSTUDIO_HEADERS, settings.lmStudioHeaders)
        prefs.setString(KEY_OPENAI_COMPAT_URL, settings.openAiCompatibleUrl)
        prefs.setString(KEY_OPENAI_COMPAT_MODEL, settings.openAiCompatibleModel)
        prefs.setString(KEY_OPENAI_COMPAT_API_KEY, settings.openAiCompatibleApiKey)
        prefs.setString(KEY_OPENAI_COMPAT_HEADERS, settings.openAiCompatibleHeaders)
        prefs.setInteger(KEY_OPENAI_COMPAT_TIMEOUT, settings.openAiCompatibleTimeoutSeconds.coerceIn(30, 3600))
        prefs.setString(KEY_NVIDIA_NIM_URL, settings.nvidiaNimUrl)
        prefs.setString(KEY_NVIDIA_NIM_MODEL, settings.nvidiaNimModel)
        prefs.setString(KEY_NVIDIA_NIM_API_KEY, settings.nvidiaNimApiKey)
        prefs.setString(KEY_NVIDIA_NIM_HEADERS, settings.nvidiaNimHeaders)
        prefs.setInteger(KEY_NVIDIA_NIM_TIMEOUT, settings.nvidiaNimTimeoutSeconds.coerceIn(30, 3600))
        prefs.setString(KEY_COPILOT_CMD, settings.copilotCmd)
        prefs.setString(KEY_PROMPT_FIND_VULNS, settings.requestPromptTemplate)
        prefs.setString(KEY_PROMPT_FULL_REPORT, settings.issuePromptTemplate)
        prefs.setString(KEY_PROMPT_ISSUE_ANALYZE, settings.issueAnalyzePrompt)
        prefs.setString(KEY_PROMPT_ISSUE_POC, settings.issuePocPrompt)
        prefs.setString(KEY_PROMPT_ISSUE_IMPACT, settings.issueImpactPrompt)
        prefs.setString(KEY_PROMPT_QUICK_RECON, settings.requestSummaryPrompt)
        prefs.setString(KEY_PROMPT_EXPLAIN_JS, settings.explainJsPrompt)
        prefs.setString(KEY_PROMPT_ACCESS_CONTROL, settings.accessControlPrompt)
        prefs.setString(KEY_PROMPT_LOGIN_SEQUENCE, settings.loginSequencePrompt)
        prefs.setString(KEY_HOST_SALT, settings.hostAnonymizationSalt)
        prefs.setString(KEY_PREFERRED_BACKEND, settings.preferredBackendId)
        prefs.setString(KEY_PRIVACY_MODE, settings.privacyMode.name)
        prefs.setBoolean(KEY_DETERMINISM, settings.determinismMode)
        prefs.setBoolean(KEY_AUTORESTART, settings.autoRestart)
        prefs.setBoolean(KEY_AUDIT_ENABLED, settings.auditEnabled)
        saveMcpSettings(settings.mcpSettings)
        prefs.setBoolean(KEY_PASSIVE_AI_ENABLED, settings.passiveAiEnabled)
        prefs.setInteger(KEY_PASSIVE_AI_RATE, settings.passiveAiRateSeconds)
        prefs.setBoolean(KEY_PASSIVE_AI_SCOPE_ONLY, settings.passiveAiScopeOnly)
        prefs.setInteger(KEY_PASSIVE_AI_MAX_SIZE, settings.passiveAiMaxSizeKb)
        prefs.setString(KEY_PASSIVE_AI_MIN_SEVERITY, settings.passiveAiMinSeverity.name)
        prefs.setInteger(KEY_PASSIVE_AI_ENDPOINT_DEDUP_MINUTES, settings.passiveAiEndpointDedupMinutes.coerceIn(1, 240))
        prefs.setInteger(
            KEY_PASSIVE_AI_FINGERPRINT_DEDUP_MINUTES,
            settings.passiveAiResponseFingerprintDedupMinutes.coerceIn(1, 240)
        )
        prefs.setInteger(
            KEY_PASSIVE_AI_PROMPT_CACHE_TTL_MINUTES,
            settings.passiveAiPromptCacheTtlMinutes.coerceIn(1, 240)
        )
        prefs.setInteger(
            KEY_PASSIVE_AI_ENDPOINT_CACHE_ENTRIES,
            settings.passiveAiEndpointCacheEntries.coerceIn(100, 50_000)
        )
        prefs.setInteger(
            KEY_PASSIVE_AI_FINGERPRINT_CACHE_ENTRIES,
            settings.passiveAiResponseFingerprintCacheEntries.coerceIn(100, 50_000)
        )
        prefs.setInteger(
            KEY_PASSIVE_AI_PROMPT_CACHE_ENTRIES,
            settings.passiveAiPromptCacheEntries.coerceIn(50, 5_000)
        )
        prefs.setInteger(
            KEY_PASSIVE_AI_REQUEST_BODY_MAX_CHARS,
            settings.passiveAiRequestBodyMaxChars.coerceIn(256, 20_000)
        )
        prefs.setInteger(
            KEY_PASSIVE_AI_RESPONSE_BODY_MAX_CHARS,
            settings.passiveAiResponseBodyMaxChars.coerceIn(512, 40_000)
        )
        prefs.setInteger(
            KEY_PASSIVE_AI_HEADER_MAX_COUNT,
            settings.passiveAiHeaderMaxCount.coerceIn(5, 120)
        )
        prefs.setInteger(
            KEY_PASSIVE_AI_PARAM_MAX_COUNT,
            settings.passiveAiParamMaxCount.coerceIn(5, 100)
        )
        prefs.setString(KEY_PASSIVE_AI_EXCLUDED_EXTENSIONS, settings.passiveAiExcludedExtensions)
        prefs.setInteger(KEY_PASSIVE_AI_BATCH_SIZE, settings.passiveAiBatchSize)
        prefs.setBoolean(KEY_PASSIVE_AI_PERSISTENT_CACHE_ENABLED, settings.passiveAiPersistentCacheEnabled)
        prefs.setInteger(KEY_PASSIVE_AI_PERSISTENT_CACHE_TTL_HOURS, settings.passiveAiPersistentCacheTtlHours)
        prefs.setInteger(KEY_PASSIVE_AI_PERSISTENT_CACHE_MAX_MB, settings.passiveAiPersistentCacheMaxMb)
        prefs.setInteger(
            KEY_CONTEXT_REQUEST_BODY_MAX_CHARS,
            settings.contextRequestBodyMaxChars.coerceIn(256, 40_000)
        )
        prefs.setInteger(
            KEY_CONTEXT_RESPONSE_BODY_MAX_CHARS,
            settings.contextResponseBodyMaxChars.coerceIn(512, 80_000)
        )
        prefs.setBoolean(KEY_CONTEXT_COMPACT_JSON, settings.contextCompactJson)
        prefs.setBoolean(KEY_ACTIVE_AI_ENABLED, settings.activeAiEnabled)
        prefs.setInteger(KEY_ACTIVE_AI_MAX_CONCURRENT, settings.activeAiMaxConcurrent)
        prefs.setInteger(KEY_ACTIVE_AI_MAX_PAYLOADS, settings.activeAiMaxPayloadsPerPoint)
        prefs.setInteger(KEY_ACTIVE_AI_TIMEOUT, settings.activeAiTimeoutSeconds)
        prefs.setInteger(KEY_ACTIVE_AI_DELAY, settings.activeAiRequestDelayMs)
        prefs.setString(KEY_ACTIVE_AI_RISK_LEVEL, settings.activeAiMaxRiskLevel.name)
        prefs.setBoolean(KEY_ACTIVE_AI_SCOPE_ONLY, settings.activeAiScopeOnly)
        prefs.setBoolean(KEY_ACTIVE_AI_AUTO_PASSIVE, settings.activeAiAutoFromPassive)
        prefs.setString(KEY_ACTIVE_AI_SCAN_MODE, settings.activeAiScanMode.name)
        prefs.setBoolean(KEY_ACTIVE_AI_USE_COLLABORATOR, settings.activeAiUseCollaborator)
        prefs.setBoolean(KEY_ACTIVE_AI_ADAPTIVE_PAYLOADS, settings.activeAiAdaptivePayloads)
        prefs.setBoolean(KEY_BOUNTY_PROMPT_ENABLED, settings.bountyPromptEnabled)
        prefs.setString(KEY_BOUNTY_PROMPT_DIR, settings.bountyPromptDir)
        prefs.setBoolean(KEY_BOUNTY_PROMPT_AUTO_CREATE_ISSUES, settings.bountyPromptAutoCreateIssues)
        prefs.setInteger(
            KEY_BOUNTY_PROMPT_CONFIDENCE_THRESHOLD,
            settings.bountyPromptIssueConfidenceThreshold.coerceIn(0, 100)
        )
        prefs.setString(
            KEY_BOUNTY_PROMPT_ENABLED_IDS,
            serializeIdSet(settings.bountyPromptEnabledPromptIds)
        )
        prefs.setBoolean(KEY_AI_LOGGER_ENABLED, settings.aiRequestLoggerEnabled)
        prefs.setInteger(KEY_AI_LOGGER_MAX_ENTRIES, settings.aiRequestLoggerMaxEntries.coerceIn(50, 5_000))
        prefs.setInteger(KEY_SETTINGS_SCHEMA_VERSION, CURRENT_SETTINGS_SCHEMA_VERSION)
    }

    private fun migrateIfNeeded() {
        val storedVersion = prefs.getInteger(KEY_SETTINGS_SCHEMA_VERSION) ?: 1
        var effectiveVersion = storedVersion.coerceAtLeast(1)

        if (effectiveVersion < 2) {
            migrateToSchemaV2()
            effectiveVersion = 2
        }

        if (storedVersion != effectiveVersion) {
            prefs.setInteger(KEY_SETTINGS_SCHEMA_VERSION, effectiveVersion)
        }
    }

    private fun migrateToSchemaV2() {
        val rawOrigins = prefs.getString(KEY_MCP_ALLOWED_ORIGINS).orEmpty()
        val normalizedOrigins = McpSettings.serializeAllowedOrigins(McpSettings.parseAllowedOrigins(rawOrigins))
        if (rawOrigins != normalizedOrigins) {
            prefs.setString(KEY_MCP_ALLOWED_ORIGINS, normalizedOrigins)
        }

        val rawGeminiCmd = prefs.getString(KEY_GEMINI_CMD).orEmpty().trim()
        val legacyDefault = "gemini --output-format text --model gemini-2.5-flash"
        if (rawGeminiCmd == legacyDefault) {
            prefs.setString(KEY_GEMINI_CMD, defaultGeminiCmd())
        }
    }

    companion object {
        private const val KEY_CODEX_CMD = "codex.cmd"
        private const val KEY_GEMINI_CMD = "gemini.cmd"
        private const val KEY_OPENCODE_CMD = "opencode.cmd"
        private const val KEY_CLAUDE_CMD = "claude.cmd"
        private const val KEY_AGENT_PROFILE = "agent.profile"
        private const val KEY_OLLAMA_URL = "ollama.url"
        private const val KEY_OLLAMA_CLI_CMD = "ollama.cli.cmd"
        private const val KEY_OLLAMA_MODEL = "ollama.model"
        private const val KEY_OLLAMA_SERVE_CMD = "ollama.serve.cmd"
        private const val KEY_OLLAMA_AUTOSTART = "ollama.autostart"
        private const val KEY_OLLAMA_API_KEY = "ollama.apiKey"
        private const val KEY_OLLAMA_HEADERS = "ollama.headers"
        private const val KEY_OLLAMA_TIMEOUT = "ollama.timeoutSeconds"
        private const val KEY_OLLAMA_CONTEXT_WINDOW = "ollama.contextWindow"
        private const val KEY_LMSTUDIO_URL = "lmstudio.url"
        private const val KEY_LMSTUDIO_MODEL = "lmstudio.model"
        private const val KEY_LMSTUDIO_TIMEOUT = "lmstudio.timeoutSeconds"
        private const val KEY_LMSTUDIO_SERVER_CMD = "lmstudio.server.cmd"
        private const val KEY_LMSTUDIO_AUTOSTART = "lmstudio.autostart"
        private const val KEY_LMSTUDIO_API_KEY = "lmstudio.apiKey"
        private const val KEY_LMSTUDIO_HEADERS = "lmstudio.headers"
        private const val KEY_OPENAI_COMPAT_URL = "openai.compat.url"
        private const val KEY_OPENAI_COMPAT_MODEL = "openai.compat.model"
        private const val KEY_OPENAI_COMPAT_API_KEY = "openai.compat.apiKey"
        private const val KEY_OPENAI_COMPAT_HEADERS = "openai.compat.headers"
        private const val KEY_OPENAI_COMPAT_TIMEOUT = "openai.compat.timeoutSeconds"
        private const val KEY_NVIDIA_NIM_URL = "nvidia.nim.url"
        private const val KEY_NVIDIA_NIM_MODEL = "nvidia.nim.model"
        private const val KEY_NVIDIA_NIM_API_KEY = "nvidia.nim.apiKey"
        private const val KEY_NVIDIA_NIM_HEADERS = "nvidia.nim.headers"
        private const val KEY_NVIDIA_NIM_TIMEOUT = "nvidia.nim.timeoutSeconds"
        private const val KEY_COPILOT_CMD = "copilot.cmd"
        private const val KEY_PROMPT_FIND_VULNS = "prompt.find_vulns"
        private const val KEY_PROMPT_QUICK_RECON = "prompt.quick_recon"
        private const val KEY_PROMPT_EXPLAIN_JS = "prompt.explain_js"
        private const val KEY_PROMPT_FULL_REPORT = "prompt.full_report"
        private const val KEY_PROMPT_ISSUE_ANALYZE = "prompt.issue_analyze"
        private const val KEY_PROMPT_ISSUE_POC = "prompt.issue_poc_validate"
        private const val KEY_PROMPT_ISSUE_IMPACT = "prompt.issue_impact_severity"
        private const val KEY_PROMPT_ACCESS_CONTROL = "prompt.access_control"
        private const val KEY_PROMPT_LOGIN_SEQUENCE = "prompt.login_sequence"
        private const val KEY_HOST_SALT = "privacy.host_salt"
        private const val KEY_PREFERRED_BACKEND = "backend.preferred"
        private const val KEY_PRIVACY_MODE = "privacy.mode"
        private const val KEY_DETERMINISM = "determinism.enabled"
        private const val KEY_AUTORESTART = "agent.autorestart"
        private const val KEY_AUDIT_ENABLED = "audit.enabled"
        private const val KEY_MCP_ENABLED = "mcp.enabled"
        private const val KEY_MCP_HOST = "mcp.host"
        private const val KEY_MCP_PORT = "mcp.port"
        private const val KEY_MCP_EXTERNAL = "mcp.external.enabled"
        private const val KEY_MCP_STDIO = "mcp.stdio.enabled"
        private const val KEY_MCP_TOKEN = "mcp.token"
        private const val KEY_MCP_ALLOWED_ORIGINS = "mcp.allowed.origins"
        private const val KEY_MCP_TLS_ENABLED = "mcp.tls.enabled"
        private const val KEY_MCP_TLS_AUTO = "mcp.tls.auto"
        private const val KEY_MCP_TLS_KEYSTORE = "mcp.tls.keystore.path"
        private const val KEY_MCP_TLS_PASSWORD = "mcp.tls.keystore.password"
        private const val KEY_MCP_SCAN_TASK_TTL_MINUTES = "mcp.scan.task.ttl.minutes"
        private const val KEY_MCP_COLLABORATOR_TTL_MINUTES = "mcp.collaborator.ttl.minutes"
        private const val KEY_MCP_MAX_CONCURRENT = "mcp.max.concurrent"
        private const val KEY_MCP_MAX_BODY_BYTES = "mcp.max.body.bytes"
        private const val KEY_MCP_TOOL_TOGGLES = "mcp.tools.toggles"
        private const val KEY_MCP_UNSAFE_TOOLS = "mcp.unsafe.tools"
        private const val KEY_MCP_UNSAFE = "mcp.unsafe.enabled"
        private const val KEY_PASSIVE_AI_ENABLED = "passive.ai.enabled"
        private const val KEY_PASSIVE_AI_RATE = "passive.ai.rate.seconds"
        private const val KEY_PASSIVE_AI_SCOPE_ONLY = "passive.ai.scope.only"
        private const val KEY_PASSIVE_AI_MAX_SIZE = "passive.ai.max.size.kb"
        private const val KEY_PASSIVE_AI_MIN_SEVERITY = "passive.ai.min.severity"
        private const val KEY_PASSIVE_AI_ENDPOINT_DEDUP_MINUTES = "passive.ai.endpoint.dedup.minutes"
        private const val KEY_PASSIVE_AI_FINGERPRINT_DEDUP_MINUTES = "passive.ai.fingerprint.dedup.minutes"
        private const val KEY_PASSIVE_AI_PROMPT_CACHE_TTL_MINUTES = "passive.ai.prompt.cache.ttl.minutes"
        private const val KEY_PASSIVE_AI_ENDPOINT_CACHE_ENTRIES = "passive.ai.endpoint.cache.entries"
        private const val KEY_PASSIVE_AI_FINGERPRINT_CACHE_ENTRIES = "passive.ai.fingerprint.cache.entries"
        private const val KEY_PASSIVE_AI_PROMPT_CACHE_ENTRIES = "passive.ai.prompt.cache.entries"
        private const val KEY_PASSIVE_AI_REQUEST_BODY_MAX_CHARS = "passive.ai.request.body.max.chars"
        private const val KEY_PASSIVE_AI_RESPONSE_BODY_MAX_CHARS = "passive.ai.response.body.max.chars"
        private const val KEY_PASSIVE_AI_HEADER_MAX_COUNT = "passive.ai.header.max.count"
        private const val KEY_PASSIVE_AI_PARAM_MAX_COUNT = "passive.ai.param.max.count"
        private const val KEY_PASSIVE_AI_EXCLUDED_EXTENSIONS = "passive.ai.excluded.extensions"
        private const val KEY_PASSIVE_AI_BATCH_SIZE = "passive.ai.batch.size"
        private const val KEY_PASSIVE_AI_PERSISTENT_CACHE_ENABLED = "passive.ai.persistent.cache.enabled"
        private const val KEY_PASSIVE_AI_PERSISTENT_CACHE_TTL_HOURS = "passive.ai.persistent.cache.ttl.hours"
        private const val KEY_PASSIVE_AI_PERSISTENT_CACHE_MAX_MB = "passive.ai.persistent.cache.max.mb"
        private const val KEY_CONTEXT_REQUEST_BODY_MAX_CHARS = "context.request.body.max.chars"
        private const val KEY_CONTEXT_RESPONSE_BODY_MAX_CHARS = "context.response.body.max.chars"
        private const val KEY_CONTEXT_COMPACT_JSON = "context.compact.json"
        private const val KEY_ACTIVE_AI_ENABLED = "active.ai.enabled"
        private const val KEY_ACTIVE_AI_MAX_CONCURRENT = "active.ai.max.concurrent"
        private const val KEY_ACTIVE_AI_MAX_PAYLOADS = "active.ai.max.payloads"
        private const val KEY_ACTIVE_AI_TIMEOUT = "active.ai.timeout"
        private const val KEY_ACTIVE_AI_DELAY = "active.ai.delay"
        private const val KEY_ACTIVE_AI_RISK_LEVEL = "active.ai.risk.level"
        private const val KEY_ACTIVE_AI_SCOPE_ONLY = "active.ai.scope.only"
        private const val KEY_ACTIVE_AI_AUTO_PASSIVE = "active.ai.auto.passive"
        private const val KEY_ACTIVE_AI_SCAN_MODE = "active.ai.scan.mode"
        private const val KEY_ACTIVE_AI_USE_COLLABORATOR = "active.ai.use.collaborator"
        private const val KEY_ACTIVE_AI_ADAPTIVE_PAYLOADS = "active.ai.adaptive.payloads"
        private const val KEY_BOUNTY_PROMPT_ENABLED = "bountyprompt.enabled"
        private const val KEY_BOUNTY_PROMPT_DIR = "bountyprompt.dir"
        private const val KEY_BOUNTY_PROMPT_AUTO_CREATE_ISSUES = "bountyprompt.auto.issue"
        private const val KEY_BOUNTY_PROMPT_CONFIDENCE_THRESHOLD = "bountyprompt.issue.threshold"
        private const val KEY_BOUNTY_PROMPT_ENABLED_IDS = "bountyprompt.enabled.ids"
        private const val KEY_AI_LOGGER_ENABLED = "ai.logger.enabled"
        private const val KEY_AI_LOGGER_MAX_ENTRIES = "ai.logger.max.entries"
        private const val KEY_SETTINGS_SCHEMA_VERSION = "settings.schema.version"
        private const val CURRENT_SETTINGS_SCHEMA_VERSION = 2

        private fun defaultCodexCmd(): String {
            return "codex chat"
        }

        private fun defaultGeminiCmd(): String {
            return "gemini --output-format text --model gemini-2.5-flash --yolo"
        }

        private fun normalizeLegacyGeminiCmd(raw: String): String {
            if (raw.isBlank()) return raw
            val legacyDefault = "gemini --output-format text --model gemini-2.5-flash"
            return if (raw == legacyDefault) {
                defaultGeminiCmd()
            } else {
                raw
            }
        }

        private fun defaultOpenCodeCmd(): String {
            return "opencode"
        }

        private fun defaultClaudeCmd(): String {
            return "claude"
        }

        private fun defaultAgentProfile(): String {
            return "pentester"
        }

        private fun defaultOllamaCliCmd(): String {
            return "ollama run llama3.1"
        }

        private fun defaultOllamaModel(): String {
            return "llama3.1"
        }

        private fun defaultOllamaServeCmd(): String {
            return "ollama serve"
        }

        private fun defaultOllamaTimeoutSeconds(): Int {
            return Defaults.CLI_PROCESS_TIMEOUT_SECONDS
        }

        private fun defaultOllamaContextWindow(): Int {
            return 8192
        }

        private fun defaultLmStudioModel(): String {
            return "lmstudio"
        }

        private fun defaultLmStudioTimeoutSeconds(): Int {
            return Defaults.CLI_PROCESS_TIMEOUT_SECONDS
        }

        private fun defaultLmStudioServerCmd(): String {
            return "lms server start"
        }

        private fun defaultOpenAiCompatTimeoutSeconds(): Int {
            return Defaults.CLI_PROCESS_TIMEOUT_SECONDS
        }

        private fun defaultNvidiaNimUrl(): String {
            return "https://integrate.api.nvidia.com"
        }

        private fun defaultNvidiaNimTimeoutSeconds(): Int {
            return Defaults.CLI_PROCESS_TIMEOUT_SECONDS
        }

        private fun defaultCopilotCmd(): String {
            return "copilot"
        }

        private fun defaultBountyPromptDir(): String {
            return java.io.File(
                System.getProperty("user.home"),
                "Tools/BountyPrompt/prompts"
            ).absolutePath
        }

        private fun defaultRequestPrompt(): String {
            return """
### ROLE
Analyze the provided HTTP traffic as a Senior Security Researcher.
Response Language: English.

### TASK
Identify security vulnerabilities, architectural flaws, and business logic issues.

### SCOPE
- **Injections**: SQLi, XSS, Command, Template (SSTI), SSRF, XXE, NoSQL.
- **Auth & Access**: IDOR/BOLA, Broken Authentication, JWT issues, CSRF.
- **Exposure**: PII, Secrets, Debug Info, Source Code leaks.
- **Logic**: Mass Assignment, Race Conditions, Price/Quantity manipulation.

### OUTPUT FORMAT
For each finding, provide:
1. **Type**: Vulnerability category.
2. **Evidence**: Quote the specific code, parameter, or header.
3. **Severity**: CVSS-based (Low, Medium, High, Critical).
4. **Impact**: Potential consequences.
5. **Remediation**: Actionable fix.
""".trim()
        }

        private fun defaultIssuePrompt(): String {
            return """
### ROLE
Write a professional security vulnerability report.
Response Language: English.

### STRUCTURE
1. **Summary**: Concise overview of the finding.
2. **Root Cause**: Why does this happen? (e.g., lack of sanitization).
3. **Evidence**: Describe the exact request/response behavior.
4. **Impact**: Describe the business and technical risk.
5. **PoC**: Step-by-step reproduction instructions.
6. **Remediation**: Detailed fix recommendation.
""".trim()
        }

        private fun defaultIssueAnalyzePrompt(): String {
            return """
### TASK
Analyze the provided security finding in depth.
Response Language: English.

### REQUIREMENTS
- Explain the **vulnerability mechanics** clearly.
- Identify the **root cause** in the application logic.
- Cite **concrete evidence** from the data provided.
- Provide a list of **manual validation steps** for a researcher.
""".trim()
        }

        private fun defaultIssuePocPrompt(): String {
            return """
### TASK
Generate a step-by-step Proof of Concept (PoC) for validation.
Response Language: English.

### REQUIREMENTS
1. provide exact **HTTP requests** (curl where possible).
2. document the **expected response** indicating success.
3. define **safe validation criteria** to avoid production impact.
""".trim()
        }

        private fun defaultIssueImpactPrompt(): String {
            return """
### TASK
Assess the impact and overall risk of this finding.
Response Language: English.

### CRITERIA
- **CIA Impact**: Confidentiality, Integrity, Availability.
- **Exploitability**: Skill level and preconditions required.
- **Business Risk**: Financial, reputational, or operational.
- **CVSS Vector**: Provide a suggested CVSS v3.1 vector.
""".trim()
        }

        private fun defaultRequestSummaryPrompt(): String {
            return """
### TASK
Summarize the security profile of this endpoint.
Response Language: English.

### FORMAT (5-7 bullets)
- **Endpoint**: Method and Path purpose.
- **Authentication**: Mechanism used (JWT, Session, API Key).
- **Inputs**: Notable query, body, or header parameters.
- **Data Flow**: Type of data returned and its sensitivity.
- **Security Observations**: Any immediate red flags or good practices noted.
""".trim()
        }

        private fun defaultExplainJsPrompt(): String {
            return """
### TASK
Analyze the provided JavaScript code for security relevance.
Response Language: English.

### OUTPUT
- **Behavior**: Concise summary of what the code does.
- **Sinks**: Identify usage of dangerous functions (eval, innerHTML, etc.).
- **Sensitive Data**: Identify hardcoded keys, endpoints, or patterns.
- **Risk Note**: One-sentence summary of the security risk.
""".trim()
        }

        private fun defaultAccessControlPrompt(): String {
            return """
### TASK
Design a systematic access control test plan for this request.
Response Language: English.

### TEST MATRIX
1. **Horizontal Escalation**: Accessing same-role data (e.g., `userId=B` instead of `A`).
2. **Vertical Escalation**: Regular user accessing admin functions.
3. **Authentication Bypass**: Request without session/tokens.
4. **Parameter Pollution**: Testing if roles/permissions can be overwritten.

For each test, provide:
- **Modification**: What to change in the request.
- **Expected Outcome**: What behavior would indicate a vulnerability.
""".trim()
        }

        private fun defaultLoginSequencePrompt(): String {
            return """
### TASK
Map the authentication flow based on the provided traffic.
Response Language: English.

### OUTPUT
- **Step-by-Step Flow**: Sequence of requests to complete login.
- **Session Keys**: Tokens/Headers to capture for persistence.
- **Failure Indicators**: How to detect session expiration.
""".trim()
        }

        private fun defaultMcpSettings(): McpSettings {
            val defaultPath = java.io.File(System.getProperty("user.home"), ".burp-ai-agent/certs/mcp-keystore.p12")
            return McpSettings(
                enabled = false,
                host = "127.0.0.1",
                port = 9876,
                externalEnabled = false,
                stdioEnabled = false,
                token = McpSettings.generateToken(),
                allowedOrigins = emptyList(),
                tlsEnabled = false,
                tlsAutoGenerate = true,
                tlsKeystorePath = defaultPath.absolutePath,
                tlsKeystorePassword = McpSettings.generatePassword(),
                scanTaskTtlMinutes = 120,
                collaboratorClientTtlMinutes = 60,
                maxConcurrentRequests = 4,
                maxBodyBytes = 2 * 1024 * 1024,
                toolToggles = emptyMap(),
                enabledUnsafeTools = emptySet(),
                unsafeEnabled = false
            )
        }

        private fun parseIdSet(raw: String?, fallback: Set<String>): Set<String> {
            val parsed = raw.orEmpty()
                .split(',')
                .map { it.trim() }
                .filter { it.isNotBlank() }
                .toSet()
            return if (parsed.isEmpty()) fallback else parsed
        }

        private fun serializeIdSet(ids: Set<String>): String {
            return ids
                .map { it.trim() }
                .filter { it.isNotBlank() }
                .toSortedSet()
                .joinToString(",")
        }
    }

    private fun loadMcpSettings(): McpSettings {
        val token = (prefs.getString(KEY_MCP_TOKEN) ?: "").trim().ifBlank {
            val generated = McpSettings.generateToken()
            prefs.setString(KEY_MCP_TOKEN, generated)
            generated
        }
        val tlsAuto = prefs.getBoolean(KEY_MCP_TLS_AUTO) ?: true
        val keystorePath = prefs.getString(KEY_MCP_TLS_KEYSTORE).orEmpty().trim()
        val resolvedKeystorePath = if (tlsAuto && keystorePath.isBlank()) {
            val defaultPath = java.io.File(System.getProperty("user.home"), ".burp-ai-agent/certs/mcp-keystore.p12")
            prefs.setString(KEY_MCP_TLS_KEYSTORE, defaultPath.absolutePath)
            defaultPath.absolutePath
        } else {
            keystorePath
        }
        val tlsPassword = prefs.getString(KEY_MCP_TLS_PASSWORD).orEmpty().trim().ifBlank {
            val generated = McpSettings.generatePassword()
            prefs.setString(KEY_MCP_TLS_PASSWORD, generated)
            generated
        }
        val toolToggles = McpSettings.parseToolToggles(prefs.getString(KEY_MCP_TOOL_TOGGLES))
        val enabledUnsafeTools = McpSettings.parseUnsafeToolSet(prefs.getString(KEY_MCP_UNSAFE_TOOLS))
        val allowedOrigins = McpSettings.parseAllowedOrigins(prefs.getString(KEY_MCP_ALLOWED_ORIGINS))
        val externalEnabled = prefs.getBoolean(KEY_MCP_EXTERNAL) ?: false
        val tlsEnabledRaw = prefs.getBoolean(KEY_MCP_TLS_ENABLED) ?: false
        val tlsEnabled = if (externalEnabled) true else tlsEnabledRaw
        if (externalEnabled && !tlsEnabledRaw) {
            prefs.setBoolean(KEY_MCP_TLS_ENABLED, true)
        }
        return McpSettings(
            enabled = prefs.getBoolean(KEY_MCP_ENABLED) ?: false,
            host = (prefs.getString(KEY_MCP_HOST) ?: "127.0.0.1").trim().ifBlank { "127.0.0.1" },
            port = (prefs.getInteger(KEY_MCP_PORT) ?: 9876).coerceIn(1, 65535),
            externalEnabled = externalEnabled,
            stdioEnabled = prefs.getBoolean(KEY_MCP_STDIO) ?: false,
            token = token,
            allowedOrigins = allowedOrigins,
            tlsEnabled = tlsEnabled,
            tlsAutoGenerate = tlsAuto,
            tlsKeystorePath = resolvedKeystorePath,
            tlsKeystorePassword = tlsPassword,
            scanTaskTtlMinutes = (prefs.getInteger(KEY_MCP_SCAN_TASK_TTL_MINUTES) ?: 120).coerceIn(5, 24 * 60),
            collaboratorClientTtlMinutes = (prefs.getInteger(KEY_MCP_COLLABORATOR_TTL_MINUTES) ?: 60)
                .coerceIn(5, 24 * 60),
            maxConcurrentRequests = (prefs.getInteger(KEY_MCP_MAX_CONCURRENT) ?: 4).coerceIn(1, 64),
            maxBodyBytes = (prefs.getInteger(KEY_MCP_MAX_BODY_BYTES) ?: 2 * 1024 * 1024)
                .coerceIn(256 * 1024, 100 * 1024 * 1024),
            toolToggles = toolToggles,
            enabledUnsafeTools = enabledUnsafeTools,
            unsafeEnabled = prefs.getBoolean(KEY_MCP_UNSAFE) ?: false
        )
    }

    private fun saveMcpSettings(settings: McpSettings) {
        prefs.setBoolean(KEY_MCP_ENABLED, settings.enabled)
        prefs.setString(KEY_MCP_HOST, settings.host)
        prefs.setInteger(KEY_MCP_PORT, settings.port)
        prefs.setBoolean(KEY_MCP_EXTERNAL, settings.externalEnabled)
        prefs.setBoolean(KEY_MCP_STDIO, settings.stdioEnabled)
        prefs.setString(KEY_MCP_TOKEN, settings.token)
        prefs.setString(KEY_MCP_ALLOWED_ORIGINS, McpSettings.serializeAllowedOrigins(settings.allowedOrigins))
        prefs.setBoolean(KEY_MCP_TLS_ENABLED, settings.tlsEnabled)
        prefs.setBoolean(KEY_MCP_TLS_AUTO, settings.tlsAutoGenerate)
        prefs.setString(KEY_MCP_TLS_KEYSTORE, settings.tlsKeystorePath)
        prefs.setString(KEY_MCP_TLS_PASSWORD, settings.tlsKeystorePassword)
        prefs.setInteger(KEY_MCP_SCAN_TASK_TTL_MINUTES, settings.scanTaskTtlMinutes.coerceIn(5, 24 * 60))
        prefs.setInteger(
            KEY_MCP_COLLABORATOR_TTL_MINUTES,
            settings.collaboratorClientTtlMinutes.coerceIn(5, 24 * 60)
        )
        prefs.setInteger(KEY_MCP_MAX_CONCURRENT, settings.maxConcurrentRequests)
        prefs.setInteger(KEY_MCP_MAX_BODY_BYTES, settings.maxBodyBytes)
        prefs.setString(KEY_MCP_TOOL_TOGGLES, McpSettings.serializeToolToggles(settings.toolToggles))
        prefs.setString(KEY_MCP_UNSAFE_TOOLS, McpSettings.serializeUnsafeToolSet(settings.enabledUnsafeTools))
        prefs.setBoolean(KEY_MCP_UNSAFE, settings.unsafeEnabled)
    }
}
