package com.six2dez.burp.aiagent.ui.components

import com.six2dez.burp.aiagent.ui.UiTheme
import javax.swing.JLabel
import javax.swing.border.EmptyBorder

/**
 * Compact, theme-aware safety indicator that replaces the old full-width red "safety strip" in
 * the main tab header. Renders as a small labelled pill matching the surrounding "MCP: Running"
 * and "AI: OK" status pills — colored background reflects the safety level, the text spells out
 * the state so the indicator self-describes without relying on color alone. The full textual
 * breakdown stays available via the HTML tooltip.
 *
 * Three levels — OK / WARN / RISK — map to `UiTheme.Colors.statusRunning / statusTerminal /
 * statusCrashed`. Colors are re-read on every [updateUI] so Burp's theme switch propagates
 * without a plugin reload.
 */
class SafetyIndicator : JLabel("Safety: OK") {
    enum class Level { OK, WARN, RISK }

    private var level: Level = Level.OK

    // `JLabel.<init>` invokes `updateUI()` BEFORE the Kotlin field initialiser for `level` runs,
    // so any access to `level` from inside that callback would NPE. The flag is zero-initialised
    // to `false` by the JVM (so the guard short-circuits during super-construction) and flipped
    // to `true` only after our own `init {}` block has finished.
    private var initialized = false

    init {
        isOpaque = true
        font = UiTheme.Typography.body
        initialized = true
        applyStyle()
    }

    /**
     * Update the indicator's level and tooltip. The [tooltipHtml] should already be wrapped in
     * `<html>...</html>` for multi-line wrapping (Swing renders HTML tooltips natively).
     */
    fun setSummary(
        level: Level,
        tooltipHtml: String,
    ) {
        this.level = level
        text = "Safety: ${labelFor(level)}"
        toolTipText = tooltipHtml
        applyStyle()
    }

    override fun updateUI() {
        super.updateUI()
        // Re-apply colors / font / border after a Burp theme switch so the pill follows the new
        // palette. Guarded against the super-construction callback (see [initialized]).
        if (initialized) {
            applyStyle()
        }
    }

    private fun applyStyle() {
        background =
            when (level) {
                Level.OK -> UiTheme.Colors.statusRunning
                Level.WARN -> UiTheme.Colors.statusTerminal
                Level.RISK -> UiTheme.Colors.statusCrashed
            }
        foreground = UiTheme.Colors.onPrimary
        border = EmptyBorder(4, 8, 4, 8)
        font = UiTheme.Typography.body
    }

    private fun labelFor(level: Level): String =
        when (level) {
            Level.OK -> "OK"
            Level.WARN -> "Warn"
            Level.RISK -> "Risk"
        }
}
