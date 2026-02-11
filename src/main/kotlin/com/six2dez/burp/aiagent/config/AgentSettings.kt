package com.six2dez.burp.aiagent.config

import burp.api.montoya.MontoyaApi
import burp.api.montoya.persistence.Preferences
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
    val activeAiUseCollaborator: Boolean = false  // SSRF OAST confirmation
)

class AgentSettingsRepository(api: MontoyaApi) {
    private val prefs: Preferences = api.persistence().preferences()

    fun load(): AgentSettings {
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
                .coerceIn(2048, 128000),
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
            preferredBackendId = (prefs.getString(KEY_PREFERRED_BACKEND) ?: "codex-cli").trim(),
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
            activeAiEnabled = prefs.getBoolean(KEY_ACTIVE_AI_ENABLED) ?: false,
            activeAiMaxConcurrent = (prefs.getInteger(KEY_ACTIVE_AI_MAX_CONCURRENT) ?: 3).coerceIn(1, 10),
            activeAiMaxPayloadsPerPoint = (prefs.getInteger(KEY_ACTIVE_AI_MAX_PAYLOADS) ?: 10).coerceIn(1, 50),
            activeAiTimeoutSeconds = (prefs.getInteger(KEY_ACTIVE_AI_TIMEOUT) ?: 30).coerceIn(5, 120),
            activeAiRequestDelayMs = (prefs.getInteger(KEY_ACTIVE_AI_DELAY) ?: 100).coerceIn(0, 5000),
            activeAiMaxRiskLevel = PayloadRisk.fromString(prefs.getString(KEY_ACTIVE_AI_RISK_LEVEL)),
            activeAiScopeOnly = prefs.getBoolean(KEY_ACTIVE_AI_SCOPE_ONLY) ?: true,
            activeAiAutoFromPassive = prefs.getBoolean(KEY_ACTIVE_AI_AUTO_PASSIVE) ?: true,
            activeAiScanMode = ScanMode.fromString(prefs.getString(KEY_ACTIVE_AI_SCAN_MODE)),
            activeAiUseCollaborator = prefs.getBoolean(KEY_ACTIVE_AI_USE_COLLABORATOR) ?: false
        )
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
            preferredBackendId = "codex-cli",
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
            activeAiEnabled = false,
            activeAiMaxConcurrent = 3,
            activeAiMaxPayloadsPerPoint = 10,
            activeAiTimeoutSeconds = 30,
            activeAiRequestDelayMs = 100,
            activeAiMaxRiskLevel = PayloadRisk.SAFE,
            activeAiScopeOnly = true,
            activeAiAutoFromPassive = true,
            activeAiScanMode = ScanMode.FULL,
            activeAiUseCollaborator = false
        )
    }

    fun save(settings: AgentSettings) {
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
        private const val KEY_MCP_TLS_ENABLED = "mcp.tls.enabled"
        private const val KEY_MCP_TLS_AUTO = "mcp.tls.auto"
        private const val KEY_MCP_TLS_KEYSTORE = "mcp.tls.keystore.path"
        private const val KEY_MCP_TLS_PASSWORD = "mcp.tls.keystore.password"
        private const val KEY_MCP_MAX_CONCURRENT = "mcp.max.concurrent"
        private const val KEY_MCP_MAX_BODY_BYTES = "mcp.max.body.bytes"
        private const val KEY_MCP_TOOL_TOGGLES = "mcp.tools.toggles"
        private const val KEY_MCP_UNSAFE = "mcp.unsafe.enabled"
        private const val KEY_PASSIVE_AI_ENABLED = "passive.ai.enabled"
        private const val KEY_PASSIVE_AI_RATE = "passive.ai.rate.seconds"
        private const val KEY_PASSIVE_AI_SCOPE_ONLY = "passive.ai.scope.only"
        private const val KEY_PASSIVE_AI_MAX_SIZE = "passive.ai.max.size.kb"
        private const val KEY_PASSIVE_AI_MIN_SEVERITY = "passive.ai.min.severity"
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
                enabled = true,
                host = "127.0.0.1",
                port = 9876,
                externalEnabled = false,
                stdioEnabled = false,
                token = McpSettings.generateToken(),
                tlsEnabled = false,
                tlsAutoGenerate = true,
                tlsKeystorePath = defaultPath.absolutePath,
                tlsKeystorePassword = McpSettings.generatePassword(),
                maxConcurrentRequests = 4,
                maxBodyBytes = 2 * 1024 * 1024,
                toolToggles = emptyMap(),
                unsafeEnabled = false
            )
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
        val externalEnabled = prefs.getBoolean(KEY_MCP_EXTERNAL) ?: false
        val tlsEnabledRaw = prefs.getBoolean(KEY_MCP_TLS_ENABLED) ?: false
        val tlsEnabled = if (externalEnabled) true else tlsEnabledRaw
        if (externalEnabled && !tlsEnabledRaw) {
            prefs.setBoolean(KEY_MCP_TLS_ENABLED, true)
        }
        return McpSettings(
            enabled = prefs.getBoolean(KEY_MCP_ENABLED) ?: true,
            host = (prefs.getString(KEY_MCP_HOST) ?: "127.0.0.1").trim().ifBlank { "127.0.0.1" },
            port = (prefs.getInteger(KEY_MCP_PORT) ?: 9876).coerceIn(1, 65535),
            externalEnabled = externalEnabled,
            stdioEnabled = prefs.getBoolean(KEY_MCP_STDIO) ?: false,
            token = token,
            tlsEnabled = tlsEnabled,
            tlsAutoGenerate = tlsAuto,
            tlsKeystorePath = resolvedKeystorePath,
            tlsKeystorePassword = tlsPassword,
            maxConcurrentRequests = (prefs.getInteger(KEY_MCP_MAX_CONCURRENT) ?: 4).coerceIn(1, 64),
            maxBodyBytes = (prefs.getInteger(KEY_MCP_MAX_BODY_BYTES) ?: 2 * 1024 * 1024)
                .coerceIn(256 * 1024, 100 * 1024 * 1024),
            toolToggles = toolToggles,
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
        prefs.setBoolean(KEY_MCP_TLS_ENABLED, settings.tlsEnabled)
        prefs.setBoolean(KEY_MCP_TLS_AUTO, settings.tlsAutoGenerate)
        prefs.setString(KEY_MCP_TLS_KEYSTORE, settings.tlsKeystorePath)
        prefs.setString(KEY_MCP_TLS_PASSWORD, settings.tlsKeystorePassword)
        prefs.setInteger(KEY_MCP_MAX_CONCURRENT, settings.maxConcurrentRequests)
        prefs.setInteger(KEY_MCP_MAX_BODY_BYTES, settings.maxBodyBytes)
        prefs.setString(KEY_MCP_TOOL_TOGGLES, McpSettings.serializeToolToggles(settings.toolToggles))
        prefs.setBoolean(KEY_MCP_UNSAFE, settings.unsafeEnabled)
    }
}
