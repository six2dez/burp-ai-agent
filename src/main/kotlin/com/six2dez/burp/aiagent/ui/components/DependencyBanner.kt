package com.six2dez.burp.aiagent.ui.components

import com.six2dez.burp.aiagent.ui.UiTheme
import java.awt.BorderLayout
import java.awt.Color
import javax.swing.JLabel
import javax.swing.JPanel
import javax.swing.border.EmptyBorder
import javax.swing.border.LineBorder

class DependencyBanner(message: String) : JPanel(BorderLayout()) {
    private val label = JLabel(message)

    init {
        background = UiTheme.Colors.warningBannerBg
        border = LineBorder(UiTheme.Colors.outlineVariant, 1, true)
        label.foreground = UiTheme.Colors.warningBannerFg
        label.font = UiTheme.Typography.body
        label.border = EmptyBorder(6, 10, 6, 10)
        add(label, BorderLayout.CENTER)
        isVisible = false
    }

    fun showBanner() {
        isVisible = true
    }

    fun hideBanner() {
        isVisible = false
    }
}
