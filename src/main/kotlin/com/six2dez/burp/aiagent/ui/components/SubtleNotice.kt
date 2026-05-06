package com.six2dez.burp.aiagent.ui.components

import com.six2dez.burp.aiagent.ui.UiTheme
import java.awt.BorderLayout
import java.awt.Color
import java.awt.Dimension
import javax.swing.BorderFactory
import javax.swing.JPanel
import javax.swing.JTextPane

/**
 * A subtle, theme-aware advisory banner used to replace the previous "two stacked red labels"
 * pattern in Privacy & Logging and MCP Server. Renders as a soft-background panel with a colored
 * left-border accent strip; the message body uses an HTML-aware [JTextPane] so multi-line text
 * wraps reliably inside `GridBagLayout` rows (a `JLabel` with `<html>...</html>` tends to clip
 * lazily when the parent grid does not give it a wrapping width contract).
 *
 * Three levels — INFO / WARN / RISK — pick the accent color from `UiTheme.Colors`. Visibility is
 * managed by callers via [setMessage] / [hideNotice]; the component starts hidden.
 *
 * Theme switches in Burp are propagated via [updateUI] which re-applies all theme-aware colors
 * after the L&F reset.
 */
class SubtleNotice : JPanel(BorderLayout()) {
    enum class Level { INFO, WARN, RISK }

    /**
     * `JTextPane` subclass that asks the layout for its current width before computing its
     * preferred size, forcing the HTML view to flow at the actual rendered width and report a
     * correct wrapped height back to the parent `GridBagLayout`. Without this hint the pane
     * renders as a single long line on the first layout pass.
     */
    private inner class WrappingPane : JTextPane() {
        override fun getPreferredSize(): Dimension {
            val available = (parent?.width ?: 0) - (parent?.insets?.let { it.left + it.right } ?: 0)
            if (available > 0) {
                // setSize forces a re-layout of the HTML view at the constrained width.
                setSize(available, Short.MAX_VALUE.toInt())
            }
            return super.getPreferredSize()
        }
    }

    // `lateinit` so we can guard `updateUI()` against the L&F firing before the field is set
    // during super-constructor chain (`JPanel(BorderLayout)` → `JComponent` may call updateUI()).
    private lateinit var body: JTextPane

    private var level: Level = Level.INFO

    init {
        isOpaque = true
        isVisible = false
        body =
            WrappingPane().apply {
                isEditable = false
                isOpaque = false
                background = Color(0, 0, 0, 0)
                border = null
                contentType = "text/html"
            }
        add(body, BorderLayout.CENTER)
        applyStyle()
    }

    /**
     * Show the banner with [html] (will be wrapped in `<html>...</html>` automatically if not
     * already). Picks accent + background colors from [level].
     */
    fun setMessage(
        level: Level,
        html: String,
    ) {
        this.level = level
        val wrapped =
            if (html.trimStart().startsWith("<html", ignoreCase = true)) {
                html
            } else {
                "<html><body style='font-family:sans-serif'>$html</body></html>"
            }
        body.text = wrapped
        applyStyle()
        isVisible = true
        revalidate()
        repaint()
    }

    fun hideNotice() {
        isVisible = false
    }

    override fun updateUI() {
        super.updateUI()
        // Re-apply colors / borders after a Burp theme switch. Guarded because `super.updateUI()`
        // can fire during the super-constructor chain before our `body` field is initialised.
        if (::body.isInitialized) {
            applyStyle()
        }
    }

    private fun applyStyle() {
        background =
            when (level) {
                Level.INFO -> UiTheme.Colors.warningBannerBg
                Level.WARN -> UiTheme.Colors.subtleWarning
                Level.RISK -> UiTheme.Colors.subtleDanger
            }
        val accent: Color =
            when (level) {
                Level.INFO -> UiTheme.Colors.outlineVariant
                Level.WARN -> UiTheme.Colors.accentWarn
                Level.RISK -> UiTheme.Colors.accentDanger
            }
        border =
            BorderFactory.createCompoundBorder(
                BorderFactory.createCompoundBorder(
                    BorderFactory.createLineBorder(UiTheme.Colors.outlineVariant, 1, true),
                    BorderFactory.createMatteBorder(0, 3, 0, 0, accent),
                ),
                BorderFactory.createEmptyBorder(8, 12, 8, 12),
            )
        body.font = UiTheme.Typography.body
        body.foreground = UiTheme.Colors.warningBannerFg
        body.minimumSize = Dimension(0, 0)
    }
}
