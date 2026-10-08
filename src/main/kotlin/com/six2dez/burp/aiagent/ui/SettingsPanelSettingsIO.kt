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
import java.util.concurrent.atomic.AtomicBoolean
import javax.swing.SwingUtilities

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
        auditVerbose = auditVerbose.isSelected,
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

/**
 * Writes [updated] into the Settings tab's Swing components, and — only when [notifyHosts] — tells the
 * host about the three enable flags.
 *
 * **Why a flag rather than firing the three callbacks from `applyAndSaveSettingsAsync`'s EDT tail.**
 * The verifier offered both. Moving them to the tail would fire them for BOTH callers, and on the
 * `saveSettings()` path `onMcpEnabledChanged` reaches `MainTab`'s `persistHeaderChangeAndApplyMcp` (a
 * save plus `mcpSupervisor.applySettings(...)`) immediately after the worker's
 * [applyAndSaveSettingsBody] has already done exactly those two things — a second disk write and a
 * second bounded MCP stop/start on every save. The flag confines the change to the single caller that
 * has the problem.
 *
 * On the restore-defaults path the three callbacks are pure duplication already: one line later
 * [applyAndSaveSettingsBody] performs `settingsRepo.save`, `mcpSupervisor.applySettings`,
 * `passiveAiScanner.setEnabled` and `activeAiScanner.setEnabled` itself, on a worker. Firing them from
 * the EDT first is what made `Restore defaults` pay `KtorMcpServerManager`'s bounded
 * `future.get(10, TimeUnit.SECONDS)` on the EDT (REL-05 / SC4).
 *
 * Every component write below stays exactly where it is, on the EDT, per UI-SPEC Rule T-3. Only the
 * three host notifications are suppressible.
 *
 * **`@Suppress("LongMethod")` rather than a regenerated baseline.** This function was already carried
 * by `detekt-baseline.xml` as `LongMethod`, but the baseline keys on the full signature, so adding the
 * [notifyHosts] parameter orphaned that entry and the finding re-fired at 145 lines against the
 * threshold of 80. `detekt-baseline.xml` is a v0.10.0 milestone metric held at 1096 entries and must
 * not be regenerated (23-03 and 23-05 answered their own new findings the same way). Splitting the
 * function is not free either: it is one flat sequence of component writes whose ONLY structure is
 * "assign every field", and the surrounding phase asserts that those writes stay contiguous on the EDT
 * ahead of the dispatch (Rule T-3).
 */
@Suppress("LongMethod")
internal fun SettingsPanel.applySettingsToUi(
    updated: AgentSettings,
    notifyHosts: Boolean = true,
) {
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
    auditVerbose.isSelected = updated.auditVerbose
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
    if (notifyHosts) {
        onMcpEnabledChanged?.invoke(updated.mcpSettings.enabled)
        onPassiveAiEnabledChanged?.invoke(updated.passiveAiEnabled)
        onActiveAiEnabledChanged?.invoke(updated.activeAiEnabled)
    }
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

/**
 * The synchronous body of a Settings save. Runs on the `burp-ai-settings-save` worker, never the EDT.
 *
 * REL-05 / SC4: this reaches `McpSupervisor.applySettings` → `McpSupervisor.stop()` →
 * `KtorMcpServerManager.stop()`'s bounded `future.get(10, TimeUnit.SECONDS)`, and it also does
 * `settingsRepo.save()` (disk) and `backends.reload()`. All three are why the whole body is off the
 * EDT. `KtorMcpServerManager.stop()` itself stays blocking (D-14): `McpSupervisor.stop()` resets its
 * attempt counters, stops the stdio bridge and clears the registries only after `serverManager.stop`
 * has completed, and that callback fires on the calling thread.
 *
 * It touches no Swing component. The snapshot it applies was read off the components by
 * `currentSettings()` on the EDT before dispatch; the Swing tail lives in
 * [applyAndSaveSettingsAsync]'s `onEdt`.
 *
 * `settings = updated` moves with the body rather than staying on the EDT: the snapshot has already
 * been taken before dispatch, and splitting that field write from the ten mutations that depend on it
 * would put two rules in one function.
 *
 * **[isCurrent] is CR-01's supersede check.** It is re-tested immediately before each of the three
 * externally visible mutations that outlive this panel — `mcpSupervisor.applySettings` and the two
 * scanner `setEnabled` calls — so a `SettingsPanel.shutdown()` landing mid-body cannot leave an MCP
 * listener on `127.0.0.1` owned by an unloaded extension's classloader, or re-arm a scanner
 * `App.shutdown()` has already disabled and torn down. The default `{ true }` keeps every existing call
 * shape valid and keeps this function independently testable; a predicate rather than a raw generation
 * value, so the body never has to know what a generation is.
 *
 * **The ordering consequence, stated rather than hidden.** A supersede detected mid-body abandons the
 * remaining mutations, including `audit.setEnabled` and `Redaction.setCustomPatterns`. That is correct
 * during teardown — `App.shutdown()` calls `Redaction.clearMappings()` immediately afterwards and the
 * audit sink is being torn down anyway — and it is unreachable outside teardown, because D-10 disables
 * both Save settings and Restore defaults for the whole flight, so there is no second concurrent save
 * to supersede this one.
 *
 * **Why `ReturnCount` is suppressed inline rather than baselined.** The three returns ARE the fix: one
 * supersede check immediately before each externally visible mutation that can outlive this panel.
 * Collapsing them into a single guarded block would re-open the mid-body window they exist to close,
 * because the supersede can land between any two of them. `detekt-baseline.xml` is never regenerated to
 * answer a finding this phase introduced.
 */
@Suppress("ReturnCount")
internal fun SettingsPanel.applyAndSaveSettingsBody(
    updated: AgentSettings,
    isCurrent: () -> Boolean = { true },
) {
    settings = updated
    settingsRepo.save(updated)
    // Re-prime the BountyPrompt cache off-thread so menu builds never touch disk (BApp #231, finding 2).
    // Called from this worker it starts a second, nested daemon thread. That nesting is harmless and
    // deliberate: the cache refresh is fire-and-forget, this worker never reads its result, and the
    // same call is made from App.initialize on the startup thread, where a synchronous form would
    // block extension load on a directory listing and a JSON parse per definition.
    UiActions.refreshBountyPromptCache(updated)
    AgentProfileLoader.setActiveProfile(updated.agentProfile)
    backends.reload()
    supervisor.applySettings(updated)
    // CR-01, guard 1 of 3. The mutation below is the one whose loss CR-01 names first and the only one
    // that can leave a socket LISTENING after the extension is gone.
    if (!isCurrent()) return
    mcpSupervisor.applySettings(
        updated.mcpSettings,
        updated.privacyMode,
        updated.determinismMode,
        updated.toPreprocessorSettings(),
    )

    // E8: the two privacy-relevant global writes are kept contiguous so the window a concurrent tool
    // worker can observe is one readable block rather than scattered across ten mutations. A tool
    // worker running during a save redacts under the privacy mode captured in its own immutable
    // McpToolContext snapshot, taken on the EDT before its dispatch, and against whichever custom
    // pattern list is current when it reads. Both halves are always fully published: setCustomPatterns
    // assigns a whole new List<Pattern> to a @Volatile field, and audit.setEnabled flips a @Volatile
    // boolean. There is no state in which a call is redacted under no rules, and no state in which a
    // partially compiled pattern list is readable. `audit.verbose` (quick 261008-sqa) is a @Volatile
    // boolean too, written right after the switch it qualifies.
    audit.setEnabled(updated.auditEnabled)
    audit.verbose = updated.auditVerbose
    // PRIV-02: push validated custom patterns into the live redaction pipeline so edits
    // take effect without a restart (per 13-RESEARCH A7 / Open Question 1).
    com.six2dez.burp.aiagent.redact.Redaction
        .setCustomPatterns(updated.customRedactionPatterns)

    // Apply passive AI scanner settings
    passiveAiScanner.rateLimitSeconds = updated.passiveAiRateSeconds
    passiveAiScanner.scopeOnly = updated.passiveAiScopeOnly
    passiveAiScanner.maxSizeKb = updated.passiveAiMaxSizeKb
    passiveAiScanner.applyOptimizationSettings(updated)
    // CR-01, guard 2 of 3. The plain field writes above are deliberately NOT guarded: they are
    // process-local assignments on an object App.shutdown() is about to discard, and a guard per
    // assignment would bury the three that matter in noise. setEnabled is different — it re-arms
    // background analysis that sends observed traffic to an AI backend.
    if (!isCurrent()) return
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
    // CR-01, guard 3 of 3. Same selectivity as guard 2, and asserted independently of it: a supersede
    // landing between the two setEnabled calls must still stop this one.
    if (!isCurrent()) return
    activeAiScanner.setEnabled(updated.activeAiEnabled)

    api.logging().logToOutput("AI Agent settings saved.")
}

/**
 * Applies [updated] on the `burp-ai-settings-save` worker and reports the outcome to [onDone] on the EDT.
 *
 * Call this from the EDT with a snapshot already read off the Swing components. It returns as soon as
 * the worker is started; nothing after the dispatch waits on it (REL-05 / SC4).
 *
 * **The busy seam and its two `finally` layers (UI-SPEC Rule T-1, FLAG-23-06).** The seam is raised
 * here, before dispatch, and lowered exactly once — `lowered` is a compare-and-set, so both layers can
 * fire and the listener still sees one `false`. The inner layer is the `finally` around the EDT tail,
 * covering a completion callback that throws. The outer layer runs on the worker and posts the
 * lowering itself, covering a worker that dies on the way out before its tail can be posted. A path
 * that returns without lowering leaves the Settings tab permanently unsaveable, with no error and no
 * way back short of reloading the extension.
 *
 * The `Throwable` catch cannot be narrowed: the seam must lower for ANY throwable the worker produces,
 * and the one the worker is least able to survive — an `Error` — is exactly the one that would
 * otherwise leave Settings permanently unsaveable. It is rethrown, never swallowed.
 */
@Suppress("TooGenericExceptionCaught")
internal fun SettingsPanel.applyAndSaveSettingsAsync(
    updated: AgentSettings,
    onDone: (Result<Unit>) -> Unit,
) {
    // CR-01: a save submitted AFTER unload is refused outright rather than superseded mid-body.
    // The consequence, stated precisely: onDone is never invoked and the busy seam is never raised,
    // so there is nothing left to lower. That is correct at teardown — the panel is gone and no
    // listener remains to inform — and it is unreachable otherwise, because SettingsPanel.shutdown()
    // is called only from MainTab.shutdown().
    if (disposed) return
    // Minted FIRST, on the calling thread, before the seam is raised and before anything is dispatched.
    // Same placement rule and same reason as OffEdtDispatch's dispatchedObserver and
    // SettingsPersistQueue.submit: the generation must be the CLICK's, not the thread-start's.
    val generation = saveGeneration.incrementAndGet()
    // Quick 261008-n0c: the rendering of the applied settings, for the Unsaved changes marker. It is
    // captured at dispatch, not re-read at completion, so an edit made during the flight stays marked
    // unsaved. On Restore defaults it is the rendering of the defaults applySettingsToUi just wrote,
    // which is why it is not `updated`. The working copy is installed first, on the EDT, because the
    // fields with no component (salt, TTLs, context window) are read from it and the body installs the
    // same value on the worker; without this a restore, whose defaults carry a fresh salt, would leave
    // a false marker. For a plain Save `updated` was read from that same working copy, so it is a no-op.
    // Quick 261008-o97: a header write that waited on the repository lock and landed after this save is
    // carried onto this dispatch-time rendering by markSaveApplied. That works because this save's own
    // listener post always runs on the EDT before this tail (same worker, FIFO).
    settings = updated
    val onScreenAtDispatch = currentSettings()
    val lowered = AtomicBoolean(false)
    val lowerBusy = {
        if (lowered.compareAndSet(false, true)) {
            busyListener?.invoke(false)
        }
    }
    busyListener?.invoke(true)
    OffEdtDispatch.run(
        // Named so a stuck save is identifiable in a thread dump; the label identifies this unit of
        // work in OffEdtDispatch's two observers and in the error log.
        threadName = "burp-ai-settings-save",
        label = "settings-save",
        logError = { api.logging().logToError(it) },
        work = {
            try {
                applyAndSaveSettingsBody(
                    updated,
                    isCurrent = { saveGeneration.get() == generation && !disposed },
                )
            } catch (failure: Throwable) {
                // Outer layer. The dispatcher posts its EDT tail after routing this throwable to
                // logError; a sink that throws on the way out would leave the seam raised forever.
                SwingUtilities.invokeLater(lowerBusy)
                throw failure
            }
        },
        onEdt = { result ->
            try {
                result.onSuccess {
                    onSettingsChanged?.invoke(updated)
                    markSaveApplied(updated, onScreenAtDispatch)
                    refreshPassiveAiStatus()
                    refreshActiveAiStatus()
                    updateProfileWarnings()
                    updateRiskWarnings()
                }
                onDone(result)
            } finally {
                // Inner layer, covering a completion callback that throws.
                lowerBusy()
            }
        },
    )
}

internal fun parseAllowedOriginsInput(raw: String): List<String> =
    raw
        .split('\n', ',', ';')
        .asSequence()
        .map { it.trim() }
        .filter { it.isNotBlank() }
        .distinct()
        .toList()
