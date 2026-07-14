package com.six2dez.burp.aiagent.ui

import com.six2dez.burp.aiagent.agents.AgentProfileLoader
import com.six2dez.burp.aiagent.config.AgentSettings
import com.six2dez.burp.aiagent.config.Defaults
import com.six2dez.burp.aiagent.config.McpSettings
import com.six2dez.burp.aiagent.config.SeverityLevel
import com.six2dez.burp.aiagent.config.toPreprocessorSettings
import com.six2dez.burp.aiagent.prompts.bountyprompt.BountyPromptCatalog
import com.six2dez.burp.aiagent.redact.PrivacyMode
import com.six2dez.burp.aiagent.scanner.PayloadRisk
import com.six2dez.burp.aiagent.scanner.ScanMode
import com.six2dez.burp.aiagent.scanner.applyOptimizationSettings
import com.six2dez.burp.aiagent.ui.design.DesignTokens
import com.six2dez.burp.aiagent.ui.panels.BackendConfigState

internal fun SettingsPanel.currentSettings(): AgentSettings {
    val mcpSettings =
        McpSettings(
            enabled = mcpEnabled.isSelected,
            host = mcpHost.text.trim().ifBlank { "127.0.0.1" },
            port = (mcpPort.value as? Int) ?: 9876,
            externalEnabled = mcpExternal.isSelected,
            stdioEnabled = mcpStdio.isSelected,
            token = mcpToken.text.trim(),
            allowedOrigins = parseAllowedOriginsInput(mcpAllowedOrigins.text),
            tlsEnabled = mcpTlsEnabled.isSelected,
            tlsAutoGenerate = mcpTlsAuto.isSelected,
            tlsKeystorePath = mcpKeystorePath.text.trim(),
            tlsKeystorePassword = String(mcpKeystorePassword.password),
            scanTaskTtlMinutes = settings.mcpSettings.scanTaskTtlMinutes,
            collaboratorClientTtlMinutes = settings.mcpSettings.collaboratorClientTtlMinutes,
            maxConcurrentRequests = (mcpMaxConcurrent.value as? Int) ?: 4,
            // 07-02 D-02: spinner is denominated in KB; convert to bytes for persistence.
            // Floor of 32 KB matches AgentSettings.loadMcpSettings coerceIn lower bound.
            maxBodyBytes = ((mcpMaxBodyKb.value as? Int) ?: 2048).coerceAtLeast(32) * 1024,
            proxyHistoryMaxItemsPerRequest =
                (mcpProxyHistoryMaxItems.value as? Int)
                    ?.coerceIn(1, 500)
                    ?: Defaults.MCP_PROXY_HISTORY_MAX_ITEMS_PER_REQUEST,
            proxyHistoryNewestFirst =
                (mcpProxyHistorySortOrder.selectedItem as? String) != "Oldest first",
            allowUnpreprocessedProxyHistory = mcpAllowUnpreprocessedProxyHistory.isSelected,
            toolToggles = collectMcpToolToggles(),
            enabledUnsafeTools = collectEnabledUnsafeTools(),
            unsafeEnabled = mcpUnsafe.isSelected,
            // 07-03 D-03: persist the global MCP scope toggle on the McpSettings sub-object.
            scopeOnly = mcpScopeOnly.isSelected,
            // Phase 16-05: external server list; bearerToken values are PLAINTEXT here —
            // AgentSettingsRepository.saveExternalMcpServers() encrypts per-field at persist time.
            externalMcpServers = externalServersPanel.getServers(),
        )
    val backendState = backendConfigPanel.currentBackendSettings()
    val ollamaTimeoutSeconds =
        parseTimeoutSeconds(
            backendState.ollamaTimeoutSeconds,
            settings.ollamaTimeoutSeconds,
        )
    val lmStudioTimeoutSeconds =
        parseTimeoutSeconds(
            backendState.lmStudioTimeoutSeconds,
            settings.lmStudioTimeoutSeconds,
        )
    val openAiCompatTimeoutSeconds =
        parseTimeoutSeconds(
            backendState.openAiCompatTimeoutSeconds,
            settings.openAiCompatibleTimeoutSeconds,
        )
    val nvidiaNimTimeoutSeconds =
        parseTimeoutSeconds(
            backendState.nvidiaNimTimeoutSeconds,
            settings.nvidiaNimTimeoutSeconds,
        )
    val perplexityTimeoutSeconds =
        parseTimeoutSeconds(
            backendState.perplexityTimeoutSeconds,
            settings.perplexityTimeoutSeconds,
        )
    return AgentSettings(
        codexCmd = backendState.codexCmd,
        geminiCmd = backendState.geminiCmd,
        opencodeCmd = backendState.opencodeCmd,
        claudeCmd = backendState.claudeCmd,
        agentProfile = profilePicker.selectedItem as? String ?: "pentester",
        ollamaCliCmd = backendState.ollamaCliCmd,
        ollamaModel = backendState.ollamaModel,
        ollamaUrl = backendState.ollamaUrl,
        ollamaServeCmd = backendState.ollamaServeCmd,
        ollamaAutoStart = backendState.ollamaAutoStart,
        ollamaApiKey = backendState.ollamaApiKey,
        ollamaHeaders = backendState.ollamaHeaders,
        ollamaTimeoutSeconds = ollamaTimeoutSeconds,
        ollamaContextWindow = settings.ollamaContextWindow,
        lmStudioUrl = backendState.lmStudioUrl,
        lmStudioModel = backendState.lmStudioModel,
        lmStudioTimeoutSeconds = lmStudioTimeoutSeconds,
        lmStudioServerCmd = backendState.lmStudioServerCmd,
        lmStudioAutoStart = backendState.lmStudioAutoStart,
        lmStudioApiKey = backendState.lmStudioApiKey,
        lmStudioHeaders = backendState.lmStudioHeaders,
        openAiCompatibleUrl = backendState.openAiCompatUrl,
        openAiCompatibleModel = backendState.openAiCompatModel,
        openAiCompatibleApiKey = backendState.openAiCompatApiKey,
        openAiCompatibleHeaders = backendState.openAiCompatHeaders,
        openAiCompatibleTimeoutSeconds = openAiCompatTimeoutSeconds,
        nvidiaNimUrl = backendState.nvidiaNimUrl,
        nvidiaNimModel = backendState.nvidiaNimModel,
        nvidiaNimApiKey = backendState.nvidiaNimApiKey,
        nvidiaNimHeaders = backendState.nvidiaNimHeaders,
        nvidiaNimTimeoutSeconds = nvidiaNimTimeoutSeconds,
        perplexityUrl = backendState.perplexityUrl,
        perplexityModel = backendState.perplexityModel,
        perplexityApiKey = backendState.perplexityApiKey,
        perplexityHeaders = backendState.perplexityHeaders,
        perplexityTimeoutSeconds = perplexityTimeoutSeconds,
        anthropicModel = backendState.anthropicModel,
        anthropicApiKey = backendState.anthropicApiKey,
        tokenBudgetWarnThreshold =
            tokenBudgetWarnField.text
                .trim()
                .toIntOrNull()
                ?.coerceAtLeast(0) ?: 0,
        tokenBudgetHardCap =
            tokenBudgetHardCapField.text
                .trim()
                .toIntOrNull()
                ?.coerceAtLeast(0) ?: 0,
        copilotCmd = backendState.copilotCmd,
        requestPromptTemplate = promptRequest.text.trim(),
        issuePromptTemplate = promptIssueFull.text.trim(),
        issueAnalyzePrompt = promptIssueAnalyze.text.trim(),
        issuePocPrompt = promptIssuePoc.text.trim(),
        issueImpactPrompt = promptIssueImpact.text.trim(),
        requestSummaryPrompt = promptSummary.text.trim(),
        explainJsPrompt = promptJs.text.trim(),
        accessControlPrompt = promptAccessControl.text.trim(),
        loginSequencePrompt = promptLoginSequence.text.trim(),
        hostAnonymizationSalt = settings.hostAnonymizationSalt,
        preferredBackendId = preferredBackendId(),
        privacyMode = privacyMode.selectedItem as? PrivacyMode ?: PrivacyMode.STRICT,
        determinismMode = determinism.isSelected,
        autoRestart = autoRestart.isSelected,
        auditEnabled = auditEnabled.isSelected,
        mcpSettings = mcpSettings,
        preprocessProxyHistory = preprocessProxyHistory.isSelected,
        preprocessMaxResponseSizeKb =
            (preprocessMaxResponseSizeKb.value as? Int)
                ?: Defaults.PREPROCESS_MAX_RESPONSE_SIZE_KB,
        preprocessFilterBinaryContent = preprocessFilterBinaryContent.isSelected,
        preprocessAllowedContentTypes =
            parseContentTypePrefixesInput(
                preprocessAllowedContentTypes.text,
                Defaults.PREPROCESS_ALLOWED_CONTENT_TYPES,
            ),
        passiveAiEnabled = passiveAiEnabled.isSelected,
        passiveAiRateSeconds = (passiveAiRateSpinner.value as? Int) ?: 5,
        passiveAiScopeOnly = passiveAiScopeOnly.isSelected,
        passiveAiMaxSizeKb = (passiveAiMaxSizeSpinner.value as? Int) ?: 96,
        passiveAiMinSeverity = SeverityLevel.fromString(passiveAiMinSeverityCombo.selectedItem as? String),
        passiveAiEndpointDedupMinutes = (passiveAiEndpointDedupSpinner.value as? Int) ?: 30,
        passiveAiResponseFingerprintDedupMinutes = (passiveAiFingerprintDedupSpinner.value as? Int) ?: 30,
        passiveAiPromptCacheTtlMinutes = (passiveAiPromptCacheTtlSpinner.value as? Int) ?: 30,
        passiveAiEndpointCacheEntries = (passiveAiEndpointCacheEntriesSpinner.value as? Int) ?: 5_000,
        passiveAiResponseFingerprintCacheEntries = (passiveAiFingerprintCacheEntriesSpinner.value as? Int) ?: 5_000,
        passiveAiPromptCacheEntries = (passiveAiPromptCacheEntriesSpinner.value as? Int) ?: 500,
        passiveAiRequestBodyMaxChars = (passiveAiRequestBodyMaxCharsSpinner.value as? Int) ?: 2_000,
        passiveAiResponseBodyMaxChars = (passiveAiResponseBodyMaxCharsSpinner.value as? Int) ?: 4_000,
        passiveAiHeaderMaxCount = (passiveAiHeaderMaxCountSpinner.value as? Int) ?: 40,
        passiveAiParamMaxCount = (passiveAiParamMaxCountSpinner.value as? Int) ?: 15,
        passiveAiExcludedExtensions = passiveAiExcludedExtensionsField.text.trim(),
        passiveAiBatchSize = (passiveAiBatchSizeSpinner.value as? Int) ?: 3,
        passiveAiPersistentCacheEnabled = passiveAiPersistentCacheEnabled.isSelected,
        passiveAiPersistentCacheTtlHours = (passiveAiPersistentCacheTtlSpinner.value as? Int) ?: 24,
        passiveAiPersistentCacheMaxMb = (passiveAiPersistentCacheMaxMbSpinner.value as? Int) ?: 50,
        contextRequestBodyMaxChars = (contextRequestBodyMaxCharsSpinner.value as? Int) ?: 4_000,
        contextResponseBodyMaxChars = (contextResponseBodyMaxCharsSpinner.value as? Int) ?: 8_000,
        contextCompactJson = contextCompactJson.isSelected,
        activeAiEnabled = activeAiEnabled.isSelected,
        activeAiMaxConcurrent = (activeAiMaxConcurrentSpinner.value as? Int) ?: 3,
        activeAiMaxPayloadsPerPoint = (activeAiMaxPayloadsSpinner.value as? Int) ?: 10,
        activeAiTimeoutSeconds = (activeAiTimeoutSpinner.value as? Int) ?: 30,
        activeAiRequestDelayMs = (activeAiDelaySpinner.value as? Int) ?: 100,
        activeAiMaxRiskLevel = PayloadRisk.fromString(activeAiRiskLevelCombo.selectedItem as? String),
        activeAiScopeOnly = activeAiScopeOnly.isSelected,
        activeAiAutoFromPassive = activeAiAutoFromPassive.isSelected,
        activeAiScanMode = ScanMode.fromString(activeAiScanModeCombo.selectedItem as? String),
        activeAiUseCollaborator = activeAiUseCollaborator.isSelected,
        activeAiAdaptivePayloads = activeAiAdaptivePayloads.isSelected,
        bountyPromptEnabled = bountyPromptEnabled.isSelected,
        bountyPromptDir = bountyPromptDir.text.trim(),
        bountyPromptAutoCreateIssues = bountyPromptAutoCreateIssues.isSelected,
        bountyPromptIssueConfidenceThreshold = (bountyPromptIssueThreshold.value as? Int) ?: 90,
        bountyPromptEnabledPromptIds =
            parseIdSetInput(
                bountyPromptEnabledIds.text,
                BountyPromptCatalog.defaultEnabledPromptIds(),
            ),
        aiRequestLoggerEnabled = aiLoggerEnabled.isSelected,
        aiRequestLoggerMaxEntries = (aiLoggerMaxEntries.value as? Int) ?: 500,
        customPromptLibrary = customPromptLibraryEditor.snapshot(),
        // 07-02 D-02: ToggleSwitch.isSelected is inherited from JToggleButton and returns
        // kotlin.Boolean — verified at compile time by this AgentSettings constructor call.
        smallModelMode = chatSmallModelMode.isSelected,
        // PRIV-02: validate each non-blank pattern line via SafeRegex.isPatternSafe.
        // Invalid/slow lines are dropped (not persisted); feedback label shows outcome.
        customRedactionPatterns = validateAndCollectCustomPatterns(),
    )
}

/**
 * Splits the custom-patterns text area by newline, validates each non-blank line via
 * SafeRegex.isPatternSafe (regex compile + 50 ms ReDoS probe), and updates the
 * patternsFeedbackLabel with statusError / statusSuccess accordingly.
 *
 * Valid lines are returned; invalid/slow lines are dropped (not persisted).
 * The feedback label is hidden when the area is empty.
 */
internal fun SettingsPanel.validateAndCollectCustomPatterns(): List<String> {
    val lines =
        customPatternsArea.text
            .split('\n')
            .map { it.trim() }
            .filter { it.isNotBlank() }

    if (lines.isEmpty()) {
        patternsFeedbackLabel.isVisible = false
        return emptyList()
    }

    val rejected = mutableListOf<String>()
    val valid = mutableListOf<String>()
    for (line in lines) {
        if (com.six2dez.burp.aiagent.redact.SafeRegex
                .isPatternSafe(line)
        ) {
            valid.add(line)
        } else {
            rejected.add(line)
        }
    }

    // Update the feedback label — re-read tokens each time (UI-SPEC Light/dark rule 4).
    if (rejected.isNotEmpty()) {
        val msg =
            if (rejected.size == 1) {
                "Pattern rejected: invalid regex, matches empty string, or too slow (ReDoS guard). Fix it and save again."
            } else {
                "${rejected.size} patterns rejected: invalid regex, match empty string, or too slow. Fix the highlighted lines and save again."
            }
        patternsFeedbackLabel.text = msg
        patternsFeedbackLabel.foreground = DesignTokens.Colors.statusError
        patternsFeedbackLabel.isVisible = true
    } else {
        patternsFeedbackLabel.text = "Custom patterns saved."
        patternsFeedbackLabel.foreground = DesignTokens.Colors.statusSuccess
        patternsFeedbackLabel.isVisible = true
    }

    return valid
}

internal fun SettingsPanel.applySettingsToUi(updated: AgentSettings) {
    preferredBackend.selectedItem = updated.preferredBackendId
    backendConfigPanel.applyState(
        BackendConfigState(
            codexCmd = updated.codexCmd,
            geminiCmd = updated.geminiCmd,
            opencodeCmd = updated.opencodeCmd,
            claudeCmd = updated.claudeCmd,
            ollamaCliCmd = updated.ollamaCliCmd,
            ollamaModel = updated.ollamaModel,
            ollamaUrl = updated.ollamaUrl,
            ollamaServeCmd = updated.ollamaServeCmd,
            ollamaAutoStart = updated.ollamaAutoStart,
            ollamaApiKey = updated.ollamaApiKey,
            ollamaHeaders = updated.ollamaHeaders,
            ollamaTimeoutSeconds = updated.ollamaTimeoutSeconds.toString(),
            lmStudioUrl = updated.lmStudioUrl,
            lmStudioModel = updated.lmStudioModel,
            lmStudioTimeoutSeconds = updated.lmStudioTimeoutSeconds.toString(),
            lmStudioServerCmd = updated.lmStudioServerCmd,
            lmStudioAutoStart = updated.lmStudioAutoStart,
            lmStudioApiKey = updated.lmStudioApiKey,
            lmStudioHeaders = updated.lmStudioHeaders,
            openAiCompatUrl = updated.openAiCompatibleUrl,
            openAiCompatModel = updated.openAiCompatibleModel,
            openAiCompatApiKey = updated.openAiCompatibleApiKey,
            openAiCompatHeaders = updated.openAiCompatibleHeaders,
            openAiCompatTimeoutSeconds = updated.openAiCompatibleTimeoutSeconds.toString(),
            nvidiaNimUrl = updated.nvidiaNimUrl,
            nvidiaNimModel = updated.nvidiaNimModel,
            nvidiaNimApiKey = updated.nvidiaNimApiKey,
            nvidiaNimHeaders = updated.nvidiaNimHeaders,
            nvidiaNimTimeoutSeconds = updated.nvidiaNimTimeoutSeconds.toString(),
            perplexityUrl = updated.perplexityUrl,
            perplexityModel = updated.perplexityModel,
            perplexityApiKey = updated.perplexityApiKey,
            perplexityHeaders = updated.perplexityHeaders,
            perplexityTimeoutSeconds = updated.perplexityTimeoutSeconds.toString(),
            anthropicModel = updated.anthropicModel,
            anthropicApiKey = updated.anthropicApiKey,
            copilotCmd = updated.copilotCmd,
        ),
    )
    profilePicker.selectedItem = updated.agentProfile
    privacyMode.selectedItem = updated.privacyMode
    determinism.isSelected = updated.determinismMode
    autoRestart.isSelected = updated.autoRestart
    auditEnabled.isSelected = updated.auditEnabled
    // 07-02 D-02: keep the small-model-mode toggle in sync with persisted state.
    chatSmallModelMode.isSelected = updated.smallModelMode
    promptRequest.text = updated.requestPromptTemplate
    promptIssueFull.text = updated.issuePromptTemplate
    promptIssueAnalyze.text = updated.issueAnalyzePrompt
    promptIssuePoc.text = updated.issuePocPrompt
    promptIssueImpact.text = updated.issueImpactPrompt
    promptSummary.text = updated.requestSummaryPrompt
    promptJs.text = updated.explainJsPrompt
    promptAccessControl.text = updated.accessControlPrompt
    promptLoginSequence.text = updated.loginSequencePrompt
    bountyPromptEnabled.isSelected = updated.bountyPromptEnabled
    bountyPromptDir.text = updated.bountyPromptDir
    bountyPromptAutoCreateIssues.isSelected = updated.bountyPromptAutoCreateIssues
    customPromptLibraryEditor.load(updated.customPromptLibrary)
    // PRIV-02: reload custom patterns into the text area; clear validation feedback on reload.
    customPatternsArea.text = updated.customRedactionPatterns.joinToString("\n")
    patternsFeedbackLabel.isVisible = false
    bountyPromptIssueThreshold.value = updated.bountyPromptIssueConfidenceThreshold
    bountyPromptEnabledIds.text = updated.bountyPromptEnabledPromptIds.joinToString(",")
    aiLoggerEnabled.isSelected = updated.aiRequestLoggerEnabled
    aiLoggerMaxEntries.value = updated.aiRequestLoggerMaxEntries

    mcpEnabled.isSelected = updated.mcpSettings.enabled
    mcpHost.text = updated.mcpSettings.host
    mcpPort.value = updated.mcpSettings.port
    mcpExternal.isSelected = updated.mcpSettings.externalEnabled
    mcpStdio.isSelected = updated.mcpSettings.stdioEnabled
    mcpToken.text = updated.mcpSettings.token
    mcpAllowedOrigins.text = updated.mcpSettings.allowedOrigins.joinToString("\n")
    mcpTlsEnabled.isSelected = updated.mcpSettings.tlsEnabled
    mcpTlsAuto.isSelected = updated.mcpSettings.tlsAutoGenerate
    mcpKeystorePath.text = updated.mcpSettings.tlsKeystorePath
    mcpKeystorePassword.text = updated.mcpSettings.tlsKeystorePassword
    mcpMaxConcurrent.value = updated.mcpSettings.maxConcurrentRequests
    // 07-02 D-02: spinner is denominated in KB; clamp to the 32 KB floor on refresh too.
    mcpMaxBodyKb.value = (updated.mcpSettings.maxBodyBytes / 1024).coerceAtLeast(32)
    mcpProxyHistoryMaxItems.value = updated.mcpSettings.proxyHistoryMaxItemsPerRequest
    mcpProxyHistorySortOrder.selectedItem =
        if (updated.mcpSettings.proxyHistoryNewestFirst) "Newest first" else "Oldest first"
    mcpAllowUnpreprocessedProxyHistory.isSelected = updated.mcpSettings.allowUnpreprocessedProxyHistory
    mcpUnsafe.isSelected = updated.mcpSettings.unsafeEnabled
    // 07-03 D-03: keep the scope-only toggle in sync with persisted state.
    mcpScopeOnly.isSelected = updated.mcpSettings.scopeOnly
    // Phase 16-05: refresh external server list; bearerToken values are PLAINTEXT (decrypted
    // by AgentSettingsRepository.loadExternalMcpServers() before reaching here).
    externalServersPanel.setServers(updated.mcpSettings.externalMcpServers)
    preprocessProxyHistory.isSelected = updated.preprocessProxyHistory
    preprocessMaxResponseSizeKb.value = updated.preprocessMaxResponseSizeKb
    preprocessFilterBinaryContent.isSelected = updated.preprocessFilterBinaryContent
    preprocessAllowedContentTypes.text = updated.preprocessAllowedContentTypes.joinToString(",")
    applyMcpToolToggles(updated.mcpSettings.toolToggles)
    applyUnsafeToolApprovals(updated.mcpSettings.enabledUnsafeTools)

    // Privacy advisory now lives in `privacyNotice` (SubtleNotice); the next call routes
    // through `refreshPrivacyNotice()` which decides level + visibility from current state.
    updatePrivacyWarnings()
    backendConfigPanel.setBackend(preferredBackendId())
    updateMcpTlsState()
    updateMcpCorsWarning()
    updateUnsafeToolStates()
    updateRiskWarnings()

    // Passive AI Scanner settings
    passiveAiEnabled.isSelected = updated.passiveAiEnabled
    passiveAiScopeOnly.isSelected = updated.passiveAiScopeOnly
    passiveAiRateSpinner.value = updated.passiveAiRateSeconds
    passiveAiMaxSizeSpinner.value = updated.passiveAiMaxSizeKb
    passiveAiMinSeverityCombo.selectedItem = updated.passiveAiMinSeverity.name
    passiveAiEndpointDedupSpinner.value = updated.passiveAiEndpointDedupMinutes
    passiveAiFingerprintDedupSpinner.value = updated.passiveAiResponseFingerprintDedupMinutes
    passiveAiPromptCacheTtlSpinner.value = updated.passiveAiPromptCacheTtlMinutes
    passiveAiEndpointCacheEntriesSpinner.value = updated.passiveAiEndpointCacheEntries
    passiveAiFingerprintCacheEntriesSpinner.value = updated.passiveAiResponseFingerprintCacheEntries
    passiveAiPromptCacheEntriesSpinner.value = updated.passiveAiPromptCacheEntries
    passiveAiRequestBodyMaxCharsSpinner.value = updated.passiveAiRequestBodyMaxChars
    passiveAiResponseBodyMaxCharsSpinner.value = updated.passiveAiResponseBodyMaxChars
    passiveAiHeaderMaxCountSpinner.value = updated.passiveAiHeaderMaxCount
    passiveAiParamMaxCountSpinner.value = updated.passiveAiParamMaxCount
    passiveAiExcludedExtensionsField.text = updated.passiveAiExcludedExtensions
    passiveAiBatchSizeSpinner.value = updated.passiveAiBatchSize
    passiveAiPersistentCacheEnabled.isSelected = updated.passiveAiPersistentCacheEnabled
    passiveAiPersistentCacheTtlSpinner.value = updated.passiveAiPersistentCacheTtlHours
    passiveAiPersistentCacheMaxMbSpinner.value = updated.passiveAiPersistentCacheMaxMb
    contextRequestBodyMaxCharsSpinner.value = updated.contextRequestBodyMaxChars
    contextResponseBodyMaxCharsSpinner.value = updated.contextResponseBodyMaxChars
    contextCompactJson.isSelected = updated.contextCompactJson
    // CAP-04: token-budget thresholds (show blank when 0 = off)
    tokenBudgetWarnField.text = if (updated.tokenBudgetWarnThreshold > 0) updated.tokenBudgetWarnThreshold.toString() else ""
    tokenBudgetHardCapField.text = if (updated.tokenBudgetHardCap > 0) updated.tokenBudgetHardCap.toString() else ""
    refreshPassiveAiStatus()

    // Active AI Scanner settings
    activeAiEnabled.isSelected = updated.activeAiEnabled
    activeAiScopeOnly.isSelected = updated.activeAiScopeOnly
    activeAiAutoFromPassive.isSelected = updated.activeAiAutoFromPassive
    activeAiMaxConcurrentSpinner.value = updated.activeAiMaxConcurrent
    activeAiMaxPayloadsSpinner.value = updated.activeAiMaxPayloadsPerPoint
    activeAiTimeoutSpinner.value = updated.activeAiTimeoutSeconds
    activeAiDelaySpinner.value = updated.activeAiRequestDelayMs
    activeAiRiskLevelCombo.selectedItem = updated.activeAiMaxRiskLevel.name
    activeAiScanModeCombo.selectedItem = updated.activeAiScanMode.name
    activeAiUseCollaborator.isSelected = updated.activeAiUseCollaborator
    activeAiAdaptivePayloads.isSelected = updated.activeAiAdaptivePayloads
    updateActiveRiskDescription()
    refreshActiveAiStatus()
    onMcpEnabledChanged?.invoke(updated.mcpSettings.enabled)
    onPassiveAiEnabledChanged?.invoke(updated.passiveAiEnabled)
    onActiveAiEnabledChanged?.invoke(updated.activeAiEnabled)
}

internal fun SettingsPanel.parseTimeoutSeconds(
    raw: String,
    fallback: Int,
): Int {
    val parsed = raw.trim().toIntOrNull() ?: return fallback.coerceIn(30, 3600)
    return parsed.coerceIn(30, 3600)
}

internal fun SettingsPanel.parseIdSetInput(
    raw: String,
    fallback: Set<String>,
): Set<String> {
    val parsed =
        raw
            .split(',')
            .map { it.trim() }
            .filter { it.isNotBlank() }
            .toSet()
    return if (parsed.isEmpty()) fallback else parsed
}

internal fun SettingsPanel.parseContentTypePrefixesInput(
    raw: String,
    fallback: Set<String>,
): Set<String> {
    val parsed =
        raw
            .split('\n', ',', ';')
            .asSequence()
            .map { it.trim().lowercase() }
            .filter { it.isNotBlank() }
            .toSet()
    return if (parsed.isEmpty()) fallback else parsed
}

internal fun SettingsPanel.applyAndSaveSettings(updated: AgentSettings) {
    settings = updated
    settingsRepo.save(updated)
    // Re-prime the BountyPrompt cache off-thread so menu builds never touch disk (BApp #231, finding 2).
    UiActions.refreshBountyPromptCache(updated)
    AgentProfileLoader.setActiveProfile(updated.agentProfile)
    backends.reload()
    supervisor.applySettings(updated)
    audit.setEnabled(updated.auditEnabled)
    mcpSupervisor.applySettings(
        updated.mcpSettings,
        updated.privacyMode,
        updated.determinismMode,
        updated.toPreprocessorSettings(),
    )

    // PRIV-02: push validated custom patterns into the live redaction pipeline so edits
    // take effect without a restart (per 13-RESEARCH A7 / Open Question 1).
    com.six2dez.burp.aiagent.redact.Redaction
        .setCustomPatterns(updated.customRedactionPatterns)

    // Apply passive AI scanner settings
    passiveAiScanner.rateLimitSeconds = updated.passiveAiRateSeconds
    passiveAiScanner.scopeOnly = updated.passiveAiScopeOnly
    passiveAiScanner.maxSizeKb = updated.passiveAiMaxSizeKb
    passiveAiScanner.applyOptimizationSettings(updated)
    passiveAiScanner.setEnabled(updated.passiveAiEnabled)
    // CAP-04 (WR-02): re-evaluate against the freshly-applied warn/cap so raising, clearing
    // (cap=0 → unlimited), or otherwise dropping below the cap RELEASES the pause gate. Without
    // this, once the hard cap fires the scanner stays paused for the whole Burp run.
    passiveAiScanner.reconcileBudget(updated)

    // Apply active AI scanner settings
    activeAiScanner.maxConcurrent = updated.activeAiMaxConcurrent
    activeAiScanner.maxPayloadsPerPoint = updated.activeAiMaxPayloadsPerPoint
    activeAiScanner.timeoutSeconds = updated.activeAiTimeoutSeconds
    activeAiScanner.requestDelayMs = updated.activeAiRequestDelayMs.toLong()
    activeAiScanner.maxRiskLevel = updated.activeAiMaxRiskLevel
    activeAiScanner.scopeOnly = updated.activeAiScopeOnly
    activeAiScanner.scanMode = updated.activeAiScanMode
    activeAiScanner.useCollaborator = updated.activeAiUseCollaborator
    activeAiScanner.setEnabled(updated.activeAiEnabled)

    api.logging().logToOutput("AI Agent settings saved.")
    onSettingsChanged?.invoke(updated)
    refreshPassiveAiStatus()
    refreshActiveAiStatus()
    updateProfileWarnings()
    updateRiskWarnings()
}

internal fun parseAllowedOriginsInput(raw: String): List<String> =
    raw
        .split('\n', ',', ';')
        .asSequence()
        .map { it.trim() }
        .filter { it.isNotBlank() }
        .distinct()
        .toList()
