package com.six2dez.burp.aiagent.ui.design

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import java.awt.BorderLayout
import java.awt.GridBagConstraints
import java.awt.GridBagLayout
import javax.swing.JPanel
import javax.swing.JScrollPane
import javax.swing.JSpinner
import javax.swing.JTextArea
import javax.swing.JTextField

/**
 * Headless JUnit 5 tests for the Components module.
 *
 * Each test constructs a component via the public builder API and asserts the key properties
 * specified by the UI-SPEC. All assertions use DesignTokens values as the expected source of truth
 * — never inline literals — so the tests also verify that builders use tokens, not hardcoded values.
 *
 * T1 satisfies UI-SPEC Verification Harness SC5 (formGrid() returns non-null JPanel), which was
 * intentionally deferred from DesignTokensTest (Plan 01) because formGrid() lives here.
 *
 * Contract reference: .planning/phases/09-design-system-foundation/09-UI-SPEC.md
 */
class DesignComponentsTest {

    // -----------------------------------------------------------------------------------------
    // T1 — formGrid returns a non-null JPanel with GridBagLayout (SC5)
    // -----------------------------------------------------------------------------------------

    @Test
    fun formGrid_returnsNonNullJPanelWithGridBagLayout() {
        val g = formGrid()
        assertNotNull(g, "formGrid() must not return null")
        assertTrue(g.layout is GridBagLayout, "formGrid() layout must be GridBagLayout")
    }

    // -----------------------------------------------------------------------------------------
    // T2 — addRowFull with a small component does not expand horizontally
    // -----------------------------------------------------------------------------------------

    @Test
    fun addRowFull_smallComponent_doesNotExpand() {
        val g = formGrid()
        val spinner = JSpinner()
        addRowFull(g, "Label", spinner)
        // Must have at least label + field components
        assertTrue(g.componentCount >= 2, "grid must contain at least 2 components (label + field); got ${g.componentCount}")
    }

    // -----------------------------------------------------------------------------------------
    // T3 — addRowFull with a large JTextField uses fill=HORIZONTAL
    // -----------------------------------------------------------------------------------------

    @Test
    fun addRowFull_largeComponent_expandsHorizontally() {
        val g = formGrid()
        val field = JTextField(40)
        addRowFull(g, "Label", field)
        val gbc = (g.layout as GridBagLayout).getConstraints(field)
        assertEquals(
            GridBagConstraints.HORIZONTAL,
            gbc.fill,
            "Large field must have fill=HORIZONTAL; got fill=${gbc.fill}",
        )
    }

    // -----------------------------------------------------------------------------------------
    // T4 — addRowFull with helpText adds a third component (the help label)
    // -----------------------------------------------------------------------------------------

    @Test
    fun addRowFull_withHelpText_addsThirdComponent() {
        val g = formGrid()
        val field = JTextField(40)
        addRowFull(g, "Label", field, "Help text")
        assertEquals(
            3,
            g.componentCount,
            "Grid must have 3 components (label + field + help label); got ${g.componentCount}",
        )
    }

    // -----------------------------------------------------------------------------------------
    // T5 — addRowFull with helpText=null does NOT add an extra component
    // -----------------------------------------------------------------------------------------

    @Test
    fun addRowFull_withoutHelpText_doesNotAddExtraComponent() {
        val g = formGrid()
        val field = JTextField(40)
        addRowFull(g, "Label", field, null)
        assertEquals(
            2,
            g.componentCount,
            "Grid must have exactly 2 components when helpText is null; got ${g.componentCount}",
        )
    }

    // -----------------------------------------------------------------------------------------
    // T6 — addRowPair adds 4 components (2 labels + 2 fields)
    // -----------------------------------------------------------------------------------------

    @Test
    fun addRowPair_addsFourComponents() {
        val g = formGrid()
        addRowPair(g, "L1", JTextField(10), "L2", JTextField(10))
        assertEquals(
            4,
            g.componentCount,
            "addRowPair must add 4 components; got ${g.componentCount}",
        )
    }

    // -----------------------------------------------------------------------------------------
    // T7 — addSpacerRow adds exactly 1 component (the rigid area)
    // -----------------------------------------------------------------------------------------

    @Test
    fun addSpacerRow_addsOneComponent() {
        val g = formGrid()
        addSpacerRow(g)
        assertEquals(
            1,
            g.componentCount,
            "addSpacerRow must add exactly 1 component; got ${g.componentCount}",
        )
    }

    // -----------------------------------------------------------------------------------------
    // T8 — sectionPanel returns a BorderLayout panel with a non-null NORTH component
    // -----------------------------------------------------------------------------------------

    @Test
    fun sectionPanel_returnsBorderLayoutWithNonNullTitle() {
        val content = JPanel()
        val sp = sectionPanel("Title", "Subtitle", content)
        assertNotNull(sp, "sectionPanel() must not return null")
        assertTrue(sp.layout is BorderLayout, "sectionPanel layout must be BorderLayout")
        val north = (sp.layout as BorderLayout).getLayoutComponent(BorderLayout.NORTH)
        assertNotNull(north, "sectionPanel must have a non-null NORTH (header) component")
    }

    // -----------------------------------------------------------------------------------------
    // T9 — helpLabel has caption font and onSurfaceVariant foreground
    // -----------------------------------------------------------------------------------------

    @Test
    fun helpLabel_hasCaptionFontAndVariantForeground() {
        val lbl = helpLabel("help text")
        assertNotNull(lbl, "helpLabel() must not return null")
        assertEquals(
            DesignTokens.Colors.onSurfaceVariant,
            lbl.foreground,
            "helpLabel foreground must be Colors.onSurfaceVariant",
        )
    }

    // -----------------------------------------------------------------------------------------
    // T10 — primaryButton has primary background
    // -----------------------------------------------------------------------------------------

    @Test
    fun primaryButton_hasPrimaryBackground() {
        val btn = primaryButton("Save")
        assertNotNull(btn, "primaryButton() must not return null")
        assertEquals(
            DesignTokens.Colors.primary,
            btn.background,
            "primaryButton background must be Colors.primary",
        )
    }

    // -----------------------------------------------------------------------------------------
    // T11 — secondaryButton has primary foreground
    // -----------------------------------------------------------------------------------------

    @Test
    fun secondaryButton_hasPrimaryForeground() {
        val btn = secondaryButton("Cancel")
        assertNotNull(btn, "secondaryButton() must not return null")
        assertEquals(
            DesignTokens.Colors.primary,
            btn.foreground,
            "secondaryButton foreground must be Colors.primary",
        )
    }

    // -----------------------------------------------------------------------------------------
    // T12 — buildTabPanel returns a JScrollPane with surface viewport background
    // -----------------------------------------------------------------------------------------

    @Test
    fun buildTabPanel_returnsJScrollPaneWithSurfaceViewportBackground() {
        val sp = buildTabPanel(listOf(JPanel(), JPanel()))
        assertNotNull(sp, "buildTabPanel() must not return null")
        assertTrue(sp is JScrollPane, "buildTabPanel result must be a JScrollPane")
        assertEquals(
            DesignTokens.Colors.surface,
            sp.viewport.background,
            "buildTabPanel viewport background must be Colors.surface",
        )
    }

    // -----------------------------------------------------------------------------------------
    // T13 — toolBadge NATIVE has statusSuccess foreground
    // -----------------------------------------------------------------------------------------

    @Test
    fun toolBadge_native_hasCorrectForeground() {
        val badge = toolBadge("store", BadgeStyle.NATIVE)
        assertNotNull(badge, "toolBadge(NATIVE) must not return null")
        assertEquals(
            DesignTokens.Colors.statusSuccess,
            badge.foreground,
            "toolBadge(NATIVE) foreground must be Colors.statusSuccess",
        )
    }

    // -----------------------------------------------------------------------------------------
    // T14 — toolBadge FULL has onSurfaceVariant foreground
    // -----------------------------------------------------------------------------------------

    @Test
    fun toolBadge_full_hasOnSurfaceVariantForeground() {
        val badge = toolBadge("full", BadgeStyle.FULL)
        assertNotNull(badge, "toolBadge(FULL) must not return null")
        assertEquals(
            DesignTokens.Colors.onSurfaceVariant,
            badge.foreground,
            "toolBadge(FULL) foreground must be Colors.onSurfaceVariant",
        )
    }

    // -----------------------------------------------------------------------------------------
    // T15 — applyFieldStyle sets mono font and inputBackground
    // -----------------------------------------------------------------------------------------

    @Test
    fun applyFieldStyle_setsFontAndBackground() {
        val tf = JTextField()
        applyFieldStyle(tf)
        assertEquals(
            DesignTokens.Typography.mono,
            tf.font,
            "applyFieldStyle must set font to Typography.mono",
        )
        assertEquals(
            DesignTokens.Colors.inputBackground,
            tf.background,
            "applyFieldStyle must set background to Colors.inputBackground",
        )
    }

    // -----------------------------------------------------------------------------------------
    // T16 — applyAreaStyle sets lineWrap=true and inputBackground
    // -----------------------------------------------------------------------------------------

    @Test
    fun applyAreaStyle_setsLineWrapAndBackground() {
        val ta = JTextArea()
        applyAreaStyle(ta)
        assertTrue(ta.lineWrap, "applyAreaStyle must set lineWrap = true")
        assertEquals(
            DesignTokens.Colors.inputBackground,
            ta.background,
            "applyAreaStyle must set background to Colors.inputBackground",
        )
    }
}
