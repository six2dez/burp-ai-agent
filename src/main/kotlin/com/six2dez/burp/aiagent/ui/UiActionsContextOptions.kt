package com.six2dez.burp.aiagent.ui

import com.six2dez.burp.aiagent.config.AgentSettings
import com.six2dez.burp.aiagent.context.ContextOptions

/**
 * Builds [ContextOptions] from [AgentSettings], applying the small-model-mode caps
 * (1500 request chars / 750 response chars) per 07-CONTEXT.md D-02 when
 * [AgentSettings.smallModelMode] is true.
 *
 * Extracted from `UiActions.contextOptionsFromSettings` so unit tests can exercise the
 * branch without instantiating a full UiActions (which depends on Burp's MontoyaApi).
 */
internal fun buildContextOptionsFromSettings(settings: AgentSettings): ContextOptions =
    ContextOptions(
        privacyMode = settings.privacyMode,
        deterministic = settings.determinismMode,
        hostSalt = settings.hostAnonymizationSalt,
        maxRequestBodyChars =
            if (settings.smallModelMode) SMALL_MODEL_REQUEST_BODY_MAX_CHARS else settings.contextRequestBodyMaxChars,
        maxResponseBodyChars =
            if (settings.smallModelMode) SMALL_MODEL_RESPONSE_BODY_MAX_CHARS else settings.contextResponseBodyMaxChars,
        compactJson = settings.contextCompactJson,
    )

// 07-02 D-02 caps for 1278-token-class local models. Calibrated so request+response per
// item fit comfortably below 2_500 chars (~625 tokens) with the rest of the envelope.
private const val SMALL_MODEL_REQUEST_BODY_MAX_CHARS = 1_500
private const val SMALL_MODEL_RESPONSE_BODY_MAX_CHARS = 750
