package com.six2dez.burp.aiagent.ui.panels

import com.six2dez.burp.aiagent.ui.components.AccordionPanel
import com.six2dez.burp.aiagent.ui.design.DesignTokens
import com.six2dez.burp.aiagent.ui.design.addRowFull
import com.six2dez.burp.aiagent.ui.design.addRowPair
import com.six2dez.burp.aiagent.ui.design.addSpacerRow
import com.six2dez.burp.aiagent.ui.design.applyFieldStyle
import com.six2dez.burp.aiagent.ui.design.formGrid
import java.awt.Dimension
import javax.swing.Box
import javax.swing.BoxLayout
import javax.swing.JButton
import javax.swing.JCheckBox
import javax.swing.JComboBox
import javax.swing.JComponent
import javax.swing.JLabel
import javax.swing.JPanel
import javax.swing.JSpinner
import javax.swing.JTextField
import javax.swing.border.EmptyBorder
import javax.swing.border.LineBorder

class PassiveScanConfigPanel(
    private val passiveAiEnabled: JComponent,
    private val passiveAiScopeOnly: JCheckBox,
    private val passiveAiRateSpinner: JSpinner,
    private val passiveAiMaxSizeSpinner: JSpinner,
    private val passiveAiMinSeverityCombo: JComboBox<*>,
    private val passiveAiEndpointDedupSpinner: JSpinner,
    private val passiveAiFingerprintDedupSpinner: JSpinner,
    private val passiveAiPromptCacheTtlSpinner: JSpinner,
    private val passiveAiEndpointCacheEntriesSpinner: JSpinner,
    private val passiveAiFingerprintCacheEntriesSpinner: JSpinner,
    private val passiveAiPromptCacheEntriesSpinner: JSpinner,
    private val passiveAiRequestBodyMaxCharsSpinner: JSpinner,
    private val passiveAiResponseBodyMaxCharsSpinner: JSpinner,
    private val passiveAiHeaderMaxCountSpinner: JSpinner,
    private val passiveAiParamMaxCountSpinner: JSpinner,
    private val passiveAiExcludedExtensionsField: JTextField,
    private val passiveAiBatchSizeSpinner: JSpinner,
    private val passiveAiPersistentCacheEnabled: JCheckBox,
    private val passiveAiPersistentCacheTtlSpinner: JSpinner,
    private val passiveAiPersistentCacheMaxMbSpinner: JSpinner,
    private val contextRequestBodyMaxCharsSpinner: JSpinner,
    private val contextResponseBodyMaxCharsSpinner: JSpinner,
    private val contextCompactJson: JCheckBox,
    private val passiveAiStatusLabel: JLabel,
    private val passiveAiViewFindings: JButton,
    private val scannerTriageButton: JButton,
    private val passiveAiResetStats: JButton,
    // CAP-04: token-budget threshold fields (0 = unlimited / off)
    private val tokenBudgetWarnField: JTextField,
    private val tokenBudgetHardCapField: JTextField,
) : ConfigPanel {
    override fun build(): JPanel {
        passiveAiEnabled.font = DesignTokens.Typography.body
        passiveAiEnabled.background = DesignTokens.Colors.surface
        passiveAiEnabled.foreground = DesignTokens.Colors.onSurface
        passiveAiEnabled.toolTipText = "Automatically analyze proxy traffic using AI and create Burp issues for findings."

        passiveAiScopeOnly.font = DesignTokens.Typography.body
        passiveAiScopeOnly.background = DesignTokens.Colors.surface
        passiveAiScopeOnly.foreground = DesignTokens.Colors.onSurface
        passiveAiScopeOnly.toolTipText = "Only analyze requests that are in the defined target scope."

        passiveAiMinSeverityCombo.font = DesignTokens.Typography.body
        passiveAiMinSeverityCombo.background = DesignTokens.Colors.surface
        passiveAiMinSeverityCombo.toolTipText = "Only report findings at or above this severity level."

        passiveAiStatusLabel.font = DesignTokens.Typography.body
        passiveAiStatusLabel.foreground = DesignTokens.Colors.onSurfaceVariant

        passiveAiViewFindings.font = DesignTokens.Typography.label
        passiveAiViewFindings.background = DesignTokens.Colors.surface
        passiveAiViewFindings.foreground = DesignTokens.Colors.primary
        passiveAiViewFindings.border = LineBorder(DesignTokens.Colors.border, 1, true)
        passiveAiViewFindings.isFocusPainted = false

        scannerTriageButton.font = DesignTokens.Typography.label
        scannerTriageButton.background = DesignTokens.Colors.surface
        scannerTriageButton.foreground = DesignTokens.Colors.primary
        scannerTriageButton.border = LineBorder(DesignTokens.Colors.border, 1, true)
        scannerTriageButton.isFocusPainted = false

        passiveAiResetStats.font = DesignTokens.Typography.label
        passiveAiResetStats.background = DesignTokens.Colors.surface
        passiveAiResetStats.foreground = DesignTokens.Colors.primary
        passiveAiResetStats.border = LineBorder(DesignTokens.Colors.border, 1, true)
        passiveAiResetStats.isFocusPainted = false

        passiveAiRateSpinner.font = DesignTokens.Typography.body
        passiveAiRateSpinner.toolTipText = "Minimum seconds between AI analyses (rate limiting)."

        passiveAiMaxSizeSpinner.font = DesignTokens.Typography.body
        passiveAiMaxSizeSpinner.toolTipText = "Maximum response size in KB to analyze."

        passiveAiRequestBodyMaxCharsSpinner.font = DesignTokens.Typography.body
        passiveAiRequestBodyMaxCharsSpinner.toolTipText = "Max request body characters sent to AI."

        passiveAiResponseBodyMaxCharsSpinner.font = DesignTokens.Typography.body
        passiveAiResponseBodyMaxCharsSpinner.toolTipText = "Max response body characters sent to AI."

        passiveAiHeaderMaxCountSpinner.font = DesignTokens.Typography.body
        passiveAiHeaderMaxCountSpinner.toolTipText = "Max filtered headers included in prompt metadata."

        passiveAiParamMaxCountSpinner.font = DesignTokens.Typography.body
        passiveAiParamMaxCountSpinner.toolTipText = "Max parameters included in prompt metadata."

        passiveAiExcludedExtensionsField.font = DesignTokens.Typography.body
        passiveAiExcludedExtensionsField.toolTipText =
            "Comma-separated file extensions to skip (e.g. css,js,png,woff,ico). Leave empty to disable."

        passiveAiBatchSizeSpinner.font = DesignTokens.Typography.body
        passiveAiBatchSizeSpinner.toolTipText = "Group N requests per AI call (1 = disabled). Reduces API calls by 60-70%."

        passiveAiEndpointDedupSpinner.font = DesignTokens.Typography.body
        passiveAiEndpointDedupSpinner.toolTipText = "Skip repeated endpoint analysis within this number of minutes."

        passiveAiFingerprintDedupSpinner.font = DesignTokens.Typography.body
        passiveAiFingerprintDedupSpinner.toolTipText = "Skip repeated response fingerprints within this number of minutes."

        passiveAiPromptCacheTtlSpinner.font = DesignTokens.Typography.body
        passiveAiPromptCacheTtlSpinner.toolTipText = "Reuse previous AI results for identical prompts within this time window."

        passiveAiEndpointCacheEntriesSpinner.font = DesignTokens.Typography.body
        passiveAiEndpointCacheEntriesSpinner.toolTipText = "Maximum endpoint dedup cache entries."

        passiveAiFingerprintCacheEntriesSpinner.font = DesignTokens.Typography.body
        passiveAiFingerprintCacheEntriesSpinner.toolTipText = "Maximum response fingerprint cache entries."

        passiveAiPromptCacheEntriesSpinner.font = DesignTokens.Typography.body
        passiveAiPromptCacheEntriesSpinner.toolTipText = "Maximum prompt-result cache entries."

        passiveAiPersistentCacheEnabled.font = DesignTokens.Typography.body
        passiveAiPersistentCacheEnabled.background = DesignTokens.Colors.surface
        passiveAiPersistentCacheEnabled.foreground = DesignTokens.Colors.onSurface
        passiveAiPersistentCacheEnabled.toolTipText = "Cache AI results to disk for reuse across Burp sessions."

        passiveAiPersistentCacheTtlSpinner.font = DesignTokens.Typography.body
        passiveAiPersistentCacheTtlSpinner.toolTipText = "Hours before persistent cache entries expire (1-168)."

        passiveAiPersistentCacheMaxMbSpinner.font = DesignTokens.Typography.body
        passiveAiPersistentCacheMaxMbSpinner.toolTipText = "Maximum disk space for persistent cache in MB."

        contextRequestBodyMaxCharsSpinner.font = DesignTokens.Typography.body
        contextRequestBodyMaxCharsSpinner.toolTipText = "Max request body characters in manual context actions."

        contextResponseBodyMaxCharsSpinner.font = DesignTokens.Typography.body
        contextResponseBodyMaxCharsSpinner.toolTipText = "Max response body characters in manual context actions."

        contextCompactJson.font = DesignTokens.Typography.body
        contextCompactJson.background = DesignTokens.Colors.surface
        contextCompactJson.foreground = DesignTokens.Colors.onSurface
        contextCompactJson.toolTipText = "Serialize manual context payloads as compact JSON to reduce tokens."

        // --- Section A: Scanner control ---
        val actionsCluster =
            JPanel().apply {
                layout = BoxLayout(this, BoxLayout.X_AXIS)
                background = DesignTokens.Colors.surface
                add(passiveAiViewFindings)
                add(Box.createRigidArea(Dimension(DesignTokens.Spacing.sm, 0)))
                add(scannerTriageButton)
                add(Box.createRigidArea(Dimension(DesignTokens.Spacing.sm, 0)))
                add(passiveAiResetStats)
            }
        val statusBar =
            JPanel(java.awt.BorderLayout(DesignTokens.Spacing.sm, 0)).apply {
                background = DesignTokens.Colors.surface
                add(passiveAiStatusLabel, java.awt.BorderLayout.CENTER)
                add(actionsCluster, java.awt.BorderLayout.EAST)
            }

        val gridA = formGrid()
        addRowFull(gridA, "Enable scanner", passiveAiEnabled)
        addSpacerRow(gridA, DesignTokens.Spacing.xs)
        addRowFull(gridA, "In-scope only", passiveAiScopeOnly)
        addSpacerRow(gridA, DesignTokens.Spacing.xs)
        addRowFull(gridA, "Min severity", passiveAiMinSeverityCombo)
        addSpacerRow(gridA, DesignTokens.Spacing.xs)
        addRowFull(gridA, "Status", statusBar)
        addSpacerRow(gridA, DesignTokens.Spacing.xs)
        addRowFull(gridA, "Batch size (1=off)", passiveAiBatchSizeSpinner)
        val sectionA =
            AccordionPanel(
                "Scanner control",
                "Enable passive AI scanning and scope settings",
                gridA,
                initiallyExpanded = true,
            )

        // --- Section B: Rate limiting & body caps ---
        val gridB = formGrid()
        addRowPair(gridB, "Rate limit (s)", passiveAiRateSpinner, "Max size (KB)", passiveAiMaxSizeSpinner)
        addSpacerRow(gridB, DesignTokens.Spacing.xs)
        addRowPair(
            gridB,
            "Req body chars (AI)",
            passiveAiRequestBodyMaxCharsSpinner,
            "Resp body chars (AI)",
            passiveAiResponseBodyMaxCharsSpinner,
        )
        addSpacerRow(gridB, DesignTokens.Spacing.xs)
        addRowPair(
            gridB,
            "Max headers",
            passiveAiHeaderMaxCountSpinner,
            "Max params",
            passiveAiParamMaxCountSpinner,
        )
        addSpacerRow(gridB, DesignTokens.Spacing.xs)
        addRowFull(gridB, "Excluded extensions", passiveAiExcludedExtensionsField)
        val sectionB =
            AccordionPanel(
                "Rate limiting & body caps",
                "Control scan frequency and context size sent to AI",
                gridB,
                initiallyExpanded = true,
            )

        // --- Section C: Dedup & prompt cache ---
        val gridC = formGrid()
        addRowPair(
            gridC,
            "Endpoint dedup (min)",
            passiveAiEndpointDedupSpinner,
            "Response dedup (min)",
            passiveAiFingerprintDedupSpinner,
        )
        addSpacerRow(gridC, DesignTokens.Spacing.xs)
        addRowPair(
            gridC,
            "Prompt cache TTL (min)",
            passiveAiPromptCacheTtlSpinner,
            "Prompt cache entries",
            passiveAiPromptCacheEntriesSpinner,
        )
        addSpacerRow(gridC, DesignTokens.Spacing.xs)
        addRowPair(
            gridC,
            "Endpoint cache entries",
            passiveAiEndpointCacheEntriesSpinner,
            "Fingerprint cache entries",
            passiveAiFingerprintCacheEntriesSpinner,
        )
        val sectionC =
            AccordionPanel(
                "Dedup & prompt cache",
                "Avoid redundant analyses across endpoints and requests",
                gridC,
                initiallyExpanded = false,
            )

        // --- Section D: Persistent cache ---
        val gridD = formGrid()
        addRowFull(gridD, "Persistent cache", passiveAiPersistentCacheEnabled)
        addSpacerRow(gridD, DesignTokens.Spacing.xs)
        addRowPair(
            gridD,
            "Persistent TTL (hrs)",
            passiveAiPersistentCacheTtlSpinner,
            "Persistent max (MB)",
            passiveAiPersistentCacheMaxMbSpinner,
        )
        val sectionD =
            AccordionPanel(
                "Persistent cache",
                "Cache AI results to disk between Burp sessions",
                gridD,
                initiallyExpanded = false,
            )

        // --- Section E: Context builder ---
        val gridContext = formGrid()
        addRowPair(
            gridContext,
            "Req body chars (manual)",
            contextRequestBodyMaxCharsSpinner,
            "Resp body chars (manual)",
            contextResponseBodyMaxCharsSpinner,
        )
        addSpacerRow(gridContext, DesignTokens.Spacing.xs)
        addRowFull(gridContext, "Manual context JSON", contextCompactJson)
        val sectionContext =
            AccordionPanel(
                "Context builder",
                "Cap request/response chars and JSON compaction for prompts",
                gridContext,
                initiallyExpanded = false,
            )

        // --- Section F: Token budget ---
        applyFieldStyle(tokenBudgetWarnField)
        applyFieldStyle(tokenBudgetHardCapField)
        tokenBudgetWarnField.toolTipText = "Show a chat banner when session tokens exceed this value. 0 = unlimited (off)."
        tokenBudgetHardCapField.toolTipText = "Pause passive scanning when session tokens exceed this value. 0 = unlimited (off)."
        val gridF = formGrid()
        addRowFull(
            gridF,
            "Warn threshold (tokens)",
            tokenBudgetWarnField,
        )
        addSpacerRow(gridF, DesignTokens.Spacing.xs)
        addRowFull(
            gridF,
            "Hard cap (tokens)",
            tokenBudgetHardCapField,
        )
        addSpacerRow(gridF, DesignTokens.Spacing.xs)
        addRowFull(
            gridF,
            "",
            JLabel("Warn shows a chat banner. The hard cap pauses passive scanning; chat stays usable.").apply {
                font = DesignTokens.Typography.caption
                foreground = DesignTokens.Colors.onSurfaceVariant
            },
        )
        val sectionF =
            AccordionPanel(
                "Token budget",
                "Optional per-session limits. 0 means unlimited (off).",
                gridF,
                initiallyExpanded = false,
            )

        val body =
            JPanel().apply {
                layout = BoxLayout(this, BoxLayout.Y_AXIS)
                background = DesignTokens.Colors.surface
                border = EmptyBorder(DesignTokens.Spacing.sectionPad, DesignTokens.Spacing.sectionPad, DesignTokens.Spacing.sectionPad, DesignTokens.Spacing.sectionPad)
                add(sectionA)
                add(Box.createRigidArea(Dimension(0, DesignTokens.Spacing.sm)))
                add(sectionB)
                add(Box.createRigidArea(Dimension(0, DesignTokens.Spacing.sm)))
                add(sectionC)
                add(Box.createRigidArea(Dimension(0, DesignTokens.Spacing.sm)))
                add(sectionD)
                add(Box.createRigidArea(Dimension(0, DesignTokens.Spacing.sm)))
                add(sectionContext)
                add(Box.createRigidArea(Dimension(0, DesignTokens.Spacing.sm)))
                add(sectionF)
            }
        return body
    }
}
