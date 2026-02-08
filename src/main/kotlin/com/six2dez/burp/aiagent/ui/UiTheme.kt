package com.six2dez.burp.aiagent.ui

import java.awt.Color
import java.awt.Font
import javax.swing.UIManager

object UiTheme {
    val isDarkTheme: Boolean
        get() {
            val bg = Colors.surface
            // Simple luminance calculation
            val luminance = (0.299 * bg.red + 0.587 * bg.green + 0.114 * bg.blue) / 255
            return luminance < 0.5
        }

    object Colors {
        val primary: Color get() = UIManager.getColor("Burp.primaryButtonBackground") ?: Color(0xD86633)
        val onPrimary: Color get() = UIManager.getColor("Burp.primaryButtonForeground") ?: Color.WHITE
        val surface: Color get() = UIManager.getColor("Panel.background") ?: Color(0xFFFBFF)
        val onSurface: Color get() = UIManager.getColor("Label.foreground") ?: Color(0x1A1A1A)
        val onSurfaceVariant: Color get() = UIManager.getColor("Label.disabledForeground") ?: Color(0x666666)
        val outline: Color get() = UIManager.getColor("Component.borderColor") ?: Color(0xCCCCCC)
        val outlineVariant: Color get() = UIManager.getColor("Separator.foreground") ?: Color(0xE0E0E0)
        val statusRunning: Color get() = UIManager.getColor("Burp.successColor") ?: Color(0x1B9E5A)
        val statusCrashed: Color get() = UIManager.getColor("Burp.errorColor") ?: Color(0xB3261E)
        val statusTerminal: Color get() = UIManager.getColor("Burp.warningColor") ?: Color(0xF57C00)
        val inputBackground: Color get() = UIManager.getColor("TextField.background") ?: Color.WHITE
        val inputForeground: Color get() = UIManager.getColor("TextField.foreground") ?: Color(0x1A1A1A)
        val comboBackground: Color get() = UIManager.getColor("ComboBox.background") ?: Color.WHITE
        val comboForeground: Color get() = UIManager.getColor("ComboBox.foreground") ?: Color(0x1A1A1A)

        // Chat bubble colors
        val userBubble: Color get() = if (isDarkTheme) Color(0x1A3A2A) else Color(0xE8F5E9)
        val aiBubble: Color get() = if (isDarkTheme) Color(0x1E2A3A) else Color(0xE3F2FD)
        val userRole: Color get() = Color(0x2E7D32) // green
        val aiRole: Color get() = primary // orange

        // Banner
        val warningBannerBg: Color get() = if (isDarkTheme) Color(0x3E2723) else Color(0xFFF3CD)
        val warningBannerFg: Color get() = if (isDarkTheme) Color(0xFFCC80) else onSurface

        // Code blocks
        val codeBlockBg: Color get() = if (isDarkTheme) Color(0x2D2D2D) else Color(0xF0F0F0)
        val inlineCodeBg: Color get() = if (isDarkTheme) Color(0x3C3C3C) else Color(0xE0E0E0)
    }

    object Typography {
        private val baseFont: Font get() = UIManager.getFont("Label.font") ?: Font("SansSerif", Font.PLAIN, 14)
        private val baseSize: Int get() = baseFont.size

        val headline: Font get() = baseFont.deriveFont(Font.BOLD, (baseSize * 1.8f))
        val title: Font get() = baseFont.deriveFont(Font.BOLD, (baseSize * 1.2f))
        val body: Font get() = baseFont.deriveFont(Font.PLAIN, baseSize.toFloat())
        val label: Font get() = baseFont.deriveFont(Font.BOLD, baseSize.toFloat())
        val mono: Font get() = UIManager.getFont("TextArea.font") ?: Font("Monospaced", Font.PLAIN, baseSize)
    }
}
