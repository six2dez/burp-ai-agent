package com.six2dez.burp.aiagent.ui.components

import com.six2dez.burp.aiagent.ui.UiTheme
import java.awt.Color
import java.awt.Dimension
import java.awt.Graphics
import java.awt.Graphics2D
import java.awt.RenderingHints
import javax.swing.JComponent
import javax.swing.border.LineBorder

/**
 * Compact, theme-aware safety indicator that replaces the old full-width red "safety strip" in the
 * main tab header. Renders as a small bordered pill with a centered filled circle whose color
 * conveys the safety level. The full textual breakdown is exposed via the HTML tooltip so the
 * information is still discoverable on hover.
 *
 * Three levels — OK / WARN / RISK — map to `UiTheme.Colors.statusRunning / statusTerminal /
 * statusCrashed`. The dot is drawn directly with `Graphics2D.fillOval` rather than relying on a
 * Unicode glyph because some headless JRE / Burp font combinations fall back to a tofu box for
 * the U+25CF "●" character. Colors are re-read on every [updateUI] so Burp's theme switch
 * propagates without a plugin reload.
 */
class SafetyIndicator : JComponent() {
    enum class Level { OK, WARN, RISK }

    private var level: Level = Level.OK

    init {
        isOpaque = true
        preferredSize = Dimension(28, 18)
        minimumSize = preferredSize
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
        toolTipText = tooltipHtml
        repaint()
    }

    override fun updateUI() {
        super.updateUI()
        // Re-apply colors / border after a Burp theme switch so the indicator follows the new palette.
        applyStyle()
    }

    override fun paintComponent(g: Graphics) {
        super.paintComponent(g)
        val g2 = g.create() as Graphics2D
        try {
            g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON)
            g2.color = background ?: UiTheme.Colors.surface
            g2.fillRect(0, 0, width, height)
            g2.color = dotColor()
            val diameter = (height - 6).coerceAtLeast(6)
            val cx = (width - diameter) / 2
            val cy = (height - diameter) / 2
            g2.fillOval(cx, cy, diameter, diameter)
        } finally {
            g2.dispose()
        }
    }

    private fun applyStyle() {
        background = UiTheme.Colors.surface
        border = LineBorder(UiTheme.Colors.outlineVariant, 1, true)
    }

    private fun dotColor(): Color =
        when (level) {
            Level.OK -> UiTheme.Colors.statusRunning
            Level.WARN -> UiTheme.Colors.statusTerminal
            Level.RISK -> UiTheme.Colors.statusCrashed
        }
}
