package com.six2dez.burp.aiagent.ui.design

import java.awt.Color
import java.awt.Font
import java.awt.Insets
import javax.swing.UIManager

/**
 * Design token contract for the Burp AI Agent UI.
 *
 * All color and typography tokens are computed `get` properties that resolve from
 * `javax.swing.UIManager` at call time — never cached — so they automatically track
 * Burp's light/dark theme switch. Spacing values are Int constants (pixels).
 *
 * Canonical token names are defined here. `UiTheme.kt` is retained as a legacy shim
 * for callers not yet migrated to DesignTokens; Phase 11 will fully align the two.
 *
 * Contract reference: `.planning/phases/09-design-system-foundation/09-UI-SPEC.md`
 */
object DesignTokens {

    /**
     * Returns `true` when the active panel background has a luminance below 0.5 (dark theme).
     * Identical logic to `UiTheme.isDarkTheme`.
     */
    val isDarkTheme: Boolean
        get() {
            val bg = Colors.surface
            val luminance = (0.299 * bg.red + 0.587 * bg.green + 0.114 * bg.blue) / 255
            return luminance < 0.5
        }

    // -----------------------------------------------------------------------------------------
    // Spacing — all values are Int constants (pixels); multiples of 4.
    // -----------------------------------------------------------------------------------------

    /**
     * Pixel spacing constants for the design system.
     * All values are multiples of 4 to maintain a consistent 4-pixel grid.
     */
    object Spacing {
        /** 4 px — icon/text gaps; accordion toggle padding; minimum spacer height. */
        val xs = 4

        /** 8 px — row insets (vertical); button gap in button rows; section inter-spacing. */
        val sm = 8

        /** 12 px — label-to-field insets inside form grid rows (horizontal). */
        val md = 12

        /** 16 px — tab content outer padding (horizontal); section header bottom gap. */
        val lg = 16

        /** 24 px — major section break between accordion panels. */
        val xl = 24

        /** 8 px — outer border for section panels (rounds EmptyBorder(6,8,8,8) to 8). */
        val sectionPad = 8

        /** 8 px — bottom border for form grids (rounds EmptyBorder(2,0,6,0) up to 4-grid). */
        val formGridPad = 8

        // Row inset constants (4-value Insets: top, left, bottom, right).

        /** Insets(4, 8, 4, 8) — label cell in addRowFull / addRowPair. */
        val rowInsets: Insets get() = Insets(4, 8, 4, 8)

        /** Insets(4, 0, 4, 8) — field cell in addRowFull. */
        val fieldInsets: Insets get() = Insets(4, 0, 4, 8)

        /** Insets(4, 0, 4, 12) — left field cell in addRowPair. */
        val fieldPairInsets: Insets get() = Insets(4, 0, 4, 12)

        /** Insets(8, 0, 4, 0) — toggle-switch field cell; extra top gap. */
        val toggleRowInsets: Insets get() = Insets(8, 0, 4, 0)
    }

    // -----------------------------------------------------------------------------------------
    // Typography — all computed get properties; no cached values.
    // -----------------------------------------------------------------------------------------

    /**
     * Typography roles derived from the UIManager base font.
     * All properties are computed at call time so they reflect runtime L&F changes.
     *
     * Maximum declared roles: sectionTitle, body, caption, label, mono (5 total).
     * Phases 10 and 11 must not introduce additional font derivations outside this set.
     *
     * Headless fallback size is 14 (matches UiTheme.kt:55) to prevent font-size drift.
     */
    object Typography {
        private val baseFont: Font
            get() = UIManager.getFont("Label.font") ?: Font("SansSerif", Font.PLAIN, 14)

        private val baseSize: Int
            get() = baseFont.size

        /** Section header labels; accordion title. Bold, ~1.2× base size. */
        val sectionTitle: Font get() = baseFont.deriveFont(Font.BOLD, baseSize * 1.2f)

        /** Row labels; checkbox text; description text; button labels. Plain, base size. */
        val body: Font get() = baseFont.deriveFont(Font.PLAIN, baseSize.toFloat())

        /** Help/description labels under fields; badge text. Plain, ~0.9× base size. */
        val caption: Font get() = baseFont.deriveFont(Font.PLAIN, baseSize * 0.9f)

        /** Inline labels that need visual weight. Bold, base size. */
        val label: Font get() = baseFont.deriveFont(Font.BOLD, baseSize.toFloat())

        /** JTextField/JTextArea with code/config content; password fields; URL fields. */
        val mono: Font
            get() = UIManager.getFont("TextArea.font") ?: Font("Monospaced", Font.PLAIN, baseSize)
    }

    // -----------------------------------------------------------------------------------------
    // Colors — all computed get properties; UIManager resolved at call time.
    // Fallbacks (after ?:) are acceptable Color literals; none appear in primary resolution paths.
    // FLAG-01: badgeNative has no UIManager key — isDarkTheme branching is the documented approach.
    // FLAG-02: cardSurface falls back to a derived value when Table.background is absent.
    // -----------------------------------------------------------------------------------------

    /**
     * Color token roles for the design system.
     * All standard tokens resolve from UIManager keys; only badgeNative and badgeFull use
     * derived values because no Burp UIManager key maps to those roles.
     */
    object Colors {

        /** 60% dominant — panel and form backgrounds. */
        val surface: Color get() = UIManager.getColor("Panel.background") ?: Color(0xFFFBFF)

        /** Body text; row labels; checkbox text. */
        val onSurface: Color get() = UIManager.getColor("Label.foreground") ?: Color(0x1A1A1A)

        /** Subtitle/description labels; section subtitles. */
        val onSurfaceVariant: Color
            get() = UIManager.getColor("Label.disabledForeground") ?: Color(0x666666)

        /**
         * Badge background; tool-row alternate background; card borders.
         * FLAG-02: Prefers UIManager("Table.background"); derives from surface when absent.
         */
        val cardSurface: Color
            get() {
                val fromUi = UIManager.getColor("Table.background")
                if (fromUi != null) return fromUi
                val s = surface
                return Color(
                    (s.red - 10).coerceIn(0, 255),
                    (s.green - 10).coerceIn(0, 255),
                    (s.blue - 10).coerceIn(0, 255),
                )
            }

        /** Field borders; card outlines; 1 px separators. */
        val border: Color get() = UIManager.getColor("Component.borderColor") ?: Color(0xCCCCCC)

        /** Accordion divider line; section dividers. */
        val borderSubtle: Color
            get() = UIManager.getColor("Separator.foreground") ?: Color(0xE0E0E0)

        /** JTextField; JTextArea; JPasswordField backgrounds. */
        val inputBackground: Color
            get() = UIManager.getColor("TextField.background") ?: Color.WHITE

        /** Input text color. */
        val inputForeground: Color
            get() = UIManager.getColor("TextField.foreground") ?: Color(0x1A1A1A)

        /** Primary buttons; focus ring; toggle-on track. 10% accent. */
        val primary: Color
            get() = UIManager.getColor("Burp.primaryButtonBackground") ?: Color(0xD86633)

        /** Text on primary-colored surfaces. */
        val onPrimary: Color
            get() = UIManager.getColor("Burp.primaryButtonForeground") ?: Color.WHITE

        /** Running status; toggle-on state; store badge. */
        val statusSuccess: Color
            get() = UIManager.getColor("Burp.successColor") ?: Color(0x1B9E5A)

        /** Error state; risk advisory accent. */
        val statusError: Color
            get() = UIManager.getColor("Burp.errorColor") ?: Color(0xB3261E)

        /** Warning advisory accent. */
        val statusWarning: Color
            get() = UIManager.getColor("Burp.warningColor") ?: Color(0xF57C00)

        /**
         * AI-native tool badge background.
         * FLAG-01: No UIManager key; approximated as solid alpha-blended color because
         * Swing does not support CSS opacity on solid panel backgrounds.
         * Dark: Color(0x1E3A2C), Light: Color(0xE8F5EE).
         */
        val badgeNative: Color
            get() = if (isDarkTheme) Color(0x1E3A2C) else Color(0xE8F5EE)

        /** Full-build-only badge background — delegates to cardSurface. */
        val badgeFull: Color get() = cardSurface
    }
}
