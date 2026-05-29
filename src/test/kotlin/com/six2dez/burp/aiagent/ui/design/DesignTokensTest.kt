package com.six2dez.burp.aiagent.ui.design

import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import java.awt.Color
import javax.swing.UIManager

/**
 * Headless JUnit 5 tests for the DesignTokens contract.
 *
 * Coverage: spacing multiples-of-4 (T1), color-role resolution (T2), isDarkTheme light/dark
 * flip (T3, T4), computed-get re-resolution (T5), typography derivation (T6), headless
 * no-throw (T7).
 *
 * SC5 (formGrid() returns non-null) is intentionally NOT here — formGrid() lives in
 * Components.kt (Plan 02) and is covered by DesignComponentsTest.T1.
 */
class DesignTokensTest {

    // Saves Panel.background before each test that mutates UIManager; restored in @AfterEach.
    private var savedPanelBackground: Color? = null

    @AfterEach
    fun restoreUIManager() {
        savedPanelBackground?.let { UIManager.put("Panel.background", it) }
        savedPanelBackground = null
    }

    // -------------------------------------------------------------------------------------
    // T1 — Spacing constants are positive multiples of 4
    // -------------------------------------------------------------------------------------

    @Test
    fun spacingConstantsArePositiveMultiplesOf4() {
        val tokens = listOf(
            "xs" to DesignTokens.Spacing.xs,
            "sm" to DesignTokens.Spacing.sm,
            "md" to DesignTokens.Spacing.md,
            "lg" to DesignTokens.Spacing.lg,
            "xl" to DesignTokens.Spacing.xl,
            "sectionPad" to DesignTokens.Spacing.sectionPad,
            "formGridPad" to DesignTokens.Spacing.formGridPad,
        )
        tokens.forEach { (name, value) ->
            assertTrue(value > 0, "Spacing.$name must be positive; got $value")
            assertTrue(value % 4 == 0, "Spacing.$name must be a multiple of 4; got $value")
        }
    }

    // -------------------------------------------------------------------------------------
    // T2 — Color roles resolve non-null in the default UIManager (whatever JVM L&F is active)
    // -------------------------------------------------------------------------------------

    @Test
    fun colorRolesResolveNonNullInDefaultUIManager() {
        assertNotNull(DesignTokens.Colors.surface, "Colors.surface must not be null")
        assertNotNull(DesignTokens.Colors.onSurface, "Colors.onSurface must not be null")
        assertNotNull(DesignTokens.Colors.primary, "Colors.primary must not be null")
        assertNotNull(DesignTokens.Colors.statusSuccess, "Colors.statusSuccess must not be null")
        assertNotNull(DesignTokens.Colors.border, "Colors.border must not be null")
        assertNotNull(DesignTokens.Colors.inputBackground, "Colors.inputBackground must not be null")
    }

    // -------------------------------------------------------------------------------------
    // T3 — isDarkTheme is true when Panel.background is dark
    // -------------------------------------------------------------------------------------

    @Test
    fun isDarkTheme_trueWhenPanelBackgroundIsDark() {
        savedPanelBackground = UIManager.getColor("Panel.background")
        try {
            UIManager.put("Panel.background", Color(0x1E1E1E))
            assertTrue(DesignTokens.isDarkTheme, "isDarkTheme must be true for Panel.background #1E1E1E")
        } finally {
            UIManager.put("Panel.background", savedPanelBackground)
        }
    }

    // -------------------------------------------------------------------------------------
    // T4 — isDarkTheme is false when Panel.background is light
    // -------------------------------------------------------------------------------------

    @Test
    fun isDarkTheme_falseWhenPanelBackgroundIsLight() {
        savedPanelBackground = UIManager.getColor("Panel.background")
        try {
            UIManager.put("Panel.background", Color(0xF5F5F5))
            assertTrue(!DesignTokens.isDarkTheme, "isDarkTheme must be false for Panel.background #F5F5F5")
        } finally {
            UIManager.put("Panel.background", savedPanelBackground)
        }
    }

    // -------------------------------------------------------------------------------------
    // T5 — Colors.surface re-resolves after UIManager change (computed get, not cached)
    // -------------------------------------------------------------------------------------

    @Test
    fun colorRolesReResolveAfterUIManagerChange_surface() {
        savedPanelBackground = UIManager.getColor("Panel.background")
        try {
            UIManager.put("Panel.background", Color(0x2B2B2B))
            val dark = DesignTokens.Colors.surface
            assertTrue(dark.red < 100, "surface.red must be < 100 for dark background; got ${dark.red}")

            UIManager.put("Panel.background", Color(0xFFFFFF))
            val light = DesignTokens.Colors.surface
            assertTrue(light.red > 200, "surface.red must be > 200 for light background; got ${light.red}")
        } finally {
            UIManager.put("Panel.background", savedPanelBackground)
        }
    }

    // -------------------------------------------------------------------------------------
    // T6 — Typography roles derive from the base font with expected attributes
    // -------------------------------------------------------------------------------------

    @Test
    fun typographyRolesDeriveFromBaseFont() {
        val st = DesignTokens.Typography.sectionTitle
        val body = DesignTokens.Typography.body
        val caption = DesignTokens.Typography.caption

        assertNotNull(st, "Typography.sectionTitle must not be null")
        assertNotNull(body, "Typography.body must not be null")
        assertNotNull(caption, "Typography.caption must not be null")

        assertTrue(st.isBold, "Typography.sectionTitle must be bold")
        assertTrue(
            caption.size2D < body.size2D,
            "Typography.caption must be smaller than body; caption=${caption.size2D}, body=${body.size2D}",
        )
        assertTrue(
            st.size2D > body.size2D,
            "Typography.sectionTitle must be larger than body; title=${st.size2D}, body=${body.size2D}",
        )
    }

    // -------------------------------------------------------------------------------------
    // T7 — All tokens load without throwing in a headless environment
    // -------------------------------------------------------------------------------------

    @Test
    fun allTokensLoadWithoutThrowingHeadless() {
        val result = runCatching {
            DesignTokens.Colors.surface
            DesignTokens.Typography.body
            DesignTokens.Spacing.lg
        }
        assertTrue(result.isSuccess, "DesignTokens must not throw in a headless JVM; error: ${result.exceptionOrNull()}")
    }
}
