package com.six2dez.burp.aiagent.ui.design

import com.six2dez.burp.aiagent.ui.components.ToggleSwitch
import java.awt.BorderLayout
import java.awt.Dimension
import java.awt.Graphics
import java.awt.Graphics2D
import java.awt.GridBagConstraints
import java.awt.GridBagLayout
import java.awt.Insets
import java.awt.RenderingHints
import javax.swing.Box
import javax.swing.BoxLayout
import javax.swing.JButton
import javax.swing.JCheckBox
import javax.swing.JComboBox
import javax.swing.JComponent
import javax.swing.JLabel
import javax.swing.JPanel
import javax.swing.JScrollPane
import javax.swing.JSpinner
import javax.swing.JTextArea
import javax.swing.JTextField
import javax.swing.border.EmptyBorder
import javax.swing.border.LineBorder

/**
 * Public component builder API for the Burp AI Agent design system.
 *
 * All builders source colors from [DesignTokens.Colors], fonts from [DesignTokens.Typography],
 * and spacing from [DesignTokens.Spacing]. No inline Color() literals or Font() constructors
 * appear in builder bodies — all tokens are resolved at call time from UIManager.
 *
 * Contract reference: `.planning/phases/09-design-system-foundation/09-UI-SPEC.md`
 * Companion to: [DesignTokens]
 *
 * Phases 10 and 11 MUST import from this module rather than duplicating layout logic.
 */

// -------------------------------------------------------------------------------------------------
// Badge style enum
// -------------------------------------------------------------------------------------------------

/**
 * Visual style variants for [toolBadge].
 *
 * [NATIVE] — AI-native tool indicator: green-tinted background, success-colored text ("store").
 * [FULL]   — Full-build-only tool indicator: neutral background, variant-text color ("full").
 */
enum class BadgeStyle { NATIVE, FULL }

// -------------------------------------------------------------------------------------------------
// Internal row counter helper
// -------------------------------------------------------------------------------------------------

/** Increments the "row" client property on [grid] and returns the current row index. */
private fun nextRow(grid: JPanel): Int {
    val row = (grid.getClientProperty("row") as? Int) ?: 0
    grid.putClientProperty("row", row + 1)
    return row
}

// -------------------------------------------------------------------------------------------------
// Small-component predicate
// -------------------------------------------------------------------------------------------------

/**
 * Returns true for components that should not expand horizontally (anchor=WEST, fill=NONE).
 * JSpinner, JComboBox, JCheckBox, ToggleSwitch, and JTextField with <= 20 columns are "small".
 */
private fun isSmallComponent(field: JComponent): Boolean =
    field is JSpinner ||
        field is JComboBox<*> ||
        field is JCheckBox ||
        field is ToggleSwitch ||
        (field is JTextField && field.columns <= 20)

// -------------------------------------------------------------------------------------------------
// 1. formGrid
// -------------------------------------------------------------------------------------------------

/**
 * Returns a [JPanel] with [GridBagLayout] configured as a design-system form grid.
 *
 * Background: [DesignTokens.Colors.surface]. Border: EmptyBorder(0, 0, [DesignTokens.Spacing.formGridPad], 0).
 * Client property "row" starts at 0. Use [addRowFull], [addRowPair], and [addSpacerRow] to
 * populate the grid.
 */
fun formGrid(): JPanel {
    val grid = JPanel(GridBagLayout())
    grid.background = DesignTokens.Colors.surface
    grid.border = EmptyBorder(0, 0, DesignTokens.Spacing.formGridPad, 0)
    grid.putClientProperty("row", 0)
    return grid
}

// -------------------------------------------------------------------------------------------------
// 2. addRowFull
// -------------------------------------------------------------------------------------------------

/**
 * Appends a label + field row to [grid].
 *
 * Label style: [DesignTokens.Typography.body] font, [DesignTokens.Colors.onSurface] foreground.
 * Field insets: [DesignTokens.Spacing.fieldInsets]. Small components (JSpinner, JComboBox,
 * JCheckBox, ToggleSwitch, JTextField <= 20 cols) get anchor=WEST, fill=NONE; others get
 * fill=HORIZONTAL.
 *
 * If [helpText] is non-null, a [helpLabel] is added on the next grid row spanning columns 1–3
 * with top/bottom insets of [DesignTokens.Spacing.xs].
 */
fun addRowFull(
    grid: JPanel,
    labelText: String,
    field: JComponent,
    helpText: String? = null,
) {
    val row = nextRow(grid)

    // Label cell
    val labelGbc = GridBagConstraints().apply {
        gridx = 0
        gridy = row
        anchor = GridBagConstraints.WEST
        insets = DesignTokens.Spacing.rowInsets
    }
    val label = JLabel(labelText).apply {
        font = DesignTokens.Typography.body
        foreground = DesignTokens.Colors.onSurface
    }
    grid.add(label, labelGbc)

    // Field cell
    val fieldGbc = GridBagConstraints().apply {
        gridx = 1
        gridy = row
        gridwidth = 3
        weightx = 1.0
        insets = DesignTokens.Spacing.fieldInsets
        if (isSmallComponent(field)) {
            anchor = GridBagConstraints.WEST
            fill = GridBagConstraints.NONE
        } else {
            fill = GridBagConstraints.HORIZONTAL
        }
    }
    grid.add(field, fieldGbc)

    // Optional help text row
    if (helpText != null) {
        val helpRow = nextRow(grid)
        val helpGbc = GridBagConstraints().apply {
            gridx = 1
            gridy = helpRow
            gridwidth = 3
            weightx = 1.0
            insets = Insets(0, 0, DesignTokens.Spacing.xs, 0)
        }
        grid.add(helpLabel(helpText), helpGbc)
    }
}

// -------------------------------------------------------------------------------------------------
// 3. addRowPair
// -------------------------------------------------------------------------------------------------

/**
 * Appends two label + field pairs on the same grid row (4 columns).
 *
 * Left label/field occupy columns 0–1; right label/field occupy columns 2–3. Insets snap to
 * [DesignTokens.Spacing] constants. Small-component detection applies to each field independently.
 */
fun addRowPair(
    grid: JPanel,
    leftLabel: String,
    leftField: JComponent,
    rightLabel: String,
    rightField: JComponent,
) {
    val row = nextRow(grid)

    // Left label
    val leftLabelGbc = GridBagConstraints().apply {
        gridx = 0
        gridy = row
        anchor = GridBagConstraints.WEST
        insets = DesignTokens.Spacing.rowInsets
    }
    val leftLbl = JLabel(leftLabel).apply {
        font = DesignTokens.Typography.body
        foreground = DesignTokens.Colors.onSurface
    }
    grid.add(leftLbl, leftLabelGbc)

    // Left field
    val leftFieldGbc = GridBagConstraints().apply {
        gridx = 1
        gridy = row
        weightx = 0.5
        insets = DesignTokens.Spacing.fieldPairInsets
        if (isSmallComponent(leftField)) {
            anchor = GridBagConstraints.WEST
            fill = GridBagConstraints.NONE
        } else {
            fill = GridBagConstraints.HORIZONTAL
        }
    }
    grid.add(leftField, leftFieldGbc)

    // Right label
    val rightLabelGbc = GridBagConstraints().apply {
        gridx = 2
        gridy = row
        anchor = GridBagConstraints.WEST
        insets = DesignTokens.Spacing.rowInsets
    }
    val rightLbl = JLabel(rightLabel).apply {
        font = DesignTokens.Typography.body
        foreground = DesignTokens.Colors.onSurface
    }
    grid.add(rightLbl, rightLabelGbc)

    // Right field
    val rightFieldGbc = GridBagConstraints().apply {
        gridx = 3
        gridy = row
        weightx = 0.5
        insets = DesignTokens.Spacing.fieldInsets
        if (isSmallComponent(rightField)) {
            anchor = GridBagConstraints.WEST
            fill = GridBagConstraints.NONE
        } else {
            fill = GridBagConstraints.HORIZONTAL
        }
    }
    grid.add(rightField, rightFieldGbc)
}

// -------------------------------------------------------------------------------------------------
// 4. addSpacerRow
// -------------------------------------------------------------------------------------------------

/**
 * Inserts a rigid-area spacer row spanning all 4 columns. Default [height] = [DesignTokens.Spacing.xs] (4 px).
 */
fun addSpacerRow(grid: JPanel, height: Int = DesignTokens.Spacing.xs) {
    val row = nextRow(grid)
    val gbc = GridBagConstraints().apply {
        gridx = 0
        gridy = row
        gridwidth = 4
        weightx = 1.0
        fill = GridBagConstraints.HORIZONTAL
        insets = Insets(0, 0, 0, 0)
    }
    grid.add(Box.createRigidArea(Dimension(0, height)), gbc)
}

// -------------------------------------------------------------------------------------------------
// 5. sectionPanel
// -------------------------------------------------------------------------------------------------

/**
 * Returns a [BorderLayout] panel with a [BoxLayout] Y_AXIS header block and [content] in CENTER.
 *
 * Header: [title] in [DesignTokens.Typography.sectionTitle] + [DesignTokens.Colors.onSurface];
 * [subtitle] in [DesignTokens.Typography.body] + [DesignTokens.Colors.onSurfaceVariant];
 * [DesignTokens.Spacing.xs] gap between them. Outer border: EmptyBorder([DesignTokens.Spacing.sectionPad]).
 */
fun sectionPanel(title: String, subtitle: String, content: JComponent): JPanel {
    val header = JPanel().apply {
        layout = BoxLayout(this, BoxLayout.Y_AXIS)
        background = DesignTokens.Colors.surface
    }

    val titleLabel = JLabel(title).apply {
        font = DesignTokens.Typography.sectionTitle
        foreground = DesignTokens.Colors.onSurface
    }

    val subtitleLabel = JLabel(subtitle).apply {
        font = DesignTokens.Typography.body
        foreground = DesignTokens.Colors.onSurfaceVariant
    }

    header.add(titleLabel)
    header.add(Box.createRigidArea(Dimension(0, DesignTokens.Spacing.xs)))
    header.add(subtitleLabel)

    return JPanel(BorderLayout()).apply {
        background = DesignTokens.Colors.surface
        border = EmptyBorder(
            DesignTokens.Spacing.sectionPad,
            DesignTokens.Spacing.sectionPad,
            DesignTokens.Spacing.sectionPad,
            DesignTokens.Spacing.sectionPad,
        )
        add(header, BorderLayout.NORTH)
        add(content, BorderLayout.CENTER)
    }
}

// -------------------------------------------------------------------------------------------------
// 6. helpLabel
// -------------------------------------------------------------------------------------------------

/**
 * Returns a [JLabel] styled with [DesignTokens.Typography.caption] font and
 * [DesignTokens.Colors.onSurfaceVariant] foreground. For multi-line help text, use an `<html>`
 * prefix in [text].
 */
fun helpLabel(text: String): JLabel = JLabel(text).apply {
    font = DesignTokens.Typography.caption
    foreground = DesignTokens.Colors.onSurfaceVariant
}

// -------------------------------------------------------------------------------------------------
// 7. primaryButton
// -------------------------------------------------------------------------------------------------

/**
 * Returns a [JButton] styled as the primary action button.
 *
 * Background: [DesignTokens.Colors.primary]. Foreground: [DesignTokens.Colors.onPrimary].
 * Font: [DesignTokens.Typography.body]. No border paint; focus ring uses L&F default.
 */
fun primaryButton(label: String): JButton = JButton(label).apply {
    font = DesignTokens.Typography.body
    background = DesignTokens.Colors.primary
    foreground = DesignTokens.Colors.onPrimary
    isBorderPainted = false
    isFocusPainted = true
    isOpaque = true
}

// -------------------------------------------------------------------------------------------------
// 8. secondaryButton
// -------------------------------------------------------------------------------------------------

/**
 * Returns a [JButton] styled as a secondary / link-style button.
 *
 * Background: [DesignTokens.Colors.surface]. Foreground: [DesignTokens.Colors.primary].
 * Border: [LineBorder] with [DesignTokens.Colors.border] and 1 px rounded.
 */
fun secondaryButton(label: String): JButton = JButton(label).apply {
    font = DesignTokens.Typography.body
    background = DesignTokens.Colors.surface
    foreground = DesignTokens.Colors.primary
    border = LineBorder(DesignTokens.Colors.border, 1, true)
}

// -------------------------------------------------------------------------------------------------
// 9. buildTabPanel
// -------------------------------------------------------------------------------------------------

/**
 * Wraps [sections] in a vertical [BoxLayout] Y_AXIS panel inside a [JScrollPane].
 *
 * Scroll pane: no border, [DesignTokens.Colors.surface] viewport background.
 * Content panel: [EmptyBorder] of [DesignTokens.Spacing.lg] on all sides.
 * Sections are separated by 8 px ([DesignTokens.Spacing.sm]) rigid-area gaps.
 */
fun buildTabPanel(sections: List<JComponent>): JScrollPane {
    val content = JPanel().apply {
        layout = BoxLayout(this, BoxLayout.Y_AXIS)
        background = DesignTokens.Colors.surface
        border = EmptyBorder(
            DesignTokens.Spacing.lg,
            DesignTokens.Spacing.lg,
            DesignTokens.Spacing.lg,
            DesignTokens.Spacing.lg,
        )
    }

    sections.forEachIndexed { index, section ->
        content.add(section)
        if (index < sections.lastIndex) {
            content.add(Box.createRigidArea(Dimension(0, DesignTokens.Spacing.sm)))
        }
    }

    return JScrollPane(content).apply {
        border = EmptyBorder(0, 0, 0, 0)
        viewport.background = DesignTokens.Colors.surface
    }
}

// -------------------------------------------------------------------------------------------------
// 10. toolBadge
// -------------------------------------------------------------------------------------------------

/**
 * Returns a small [JLabel] rendered as a pill badge with rounded corners.
 *
 * [BadgeStyle.NATIVE]: [DesignTokens.Colors.badgeNative] background, [DesignTokens.Colors.statusSuccess] text.
 * [BadgeStyle.FULL]:   [DesignTokens.Colors.badgeFull] background, [DesignTokens.Colors.onSurfaceVariant] text.
 *
 * Rounded rect is painted in [JLabel.paintComponent] via [Graphics2D.fillRoundRect] with 6 px arc.
 * Font: [DesignTokens.Typography.caption]. Padding: EmptyBorder(2, 6, 2, 6).
 */
fun toolBadge(label: String, style: BadgeStyle): JLabel {
    val bgColor = when (style) {
        BadgeStyle.NATIVE -> DesignTokens.Colors.badgeNative
        BadgeStyle.FULL -> DesignTokens.Colors.badgeFull
    }
    val fgColor = when (style) {
        BadgeStyle.NATIVE -> DesignTokens.Colors.statusSuccess
        BadgeStyle.FULL -> DesignTokens.Colors.onSurfaceVariant
    }

    return object : JLabel(label) {
        override fun paintComponent(g: Graphics) {
            val g2d = g as Graphics2D
            g2d.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON)
            g2d.color = bgColor
            g2d.fillRoundRect(0, 0, width, height, 6, 6)
            super.paintComponent(g)
        }
    }.apply {
        isOpaque = false
        font = DesignTokens.Typography.caption
        foreground = fgColor
        border = EmptyBorder(2, 6, 2, 6)
    }
}

// -------------------------------------------------------------------------------------------------
// 11. applyFieldStyle / applyAreaStyle
// -------------------------------------------------------------------------------------------------

/**
 * Applies design-system styling to a [JTextField].
 *
 * Sets: [DesignTokens.Typography.mono] font, [LineBorder] with [DesignTokens.Colors.border],
 * [DesignTokens.Colors.inputBackground], [DesignTokens.Colors.inputForeground].
 */
fun applyFieldStyle(field: JTextField) {
    field.font = DesignTokens.Typography.mono
    field.border = LineBorder(DesignTokens.Colors.border, 1, true)
    field.background = DesignTokens.Colors.inputBackground
    field.foreground = DesignTokens.Colors.inputForeground
}

/**
 * Applies design-system styling to a [JTextArea].
 *
 * Sets: [DesignTokens.Typography.mono] font, [LineBorder] with [DesignTokens.Colors.border],
 * [DesignTokens.Colors.inputBackground], [DesignTokens.Colors.inputForeground],
 * lineWrap = true, wrapStyleWord = true.
 */
fun applyAreaStyle(area: JTextArea) {
    area.font = DesignTokens.Typography.mono
    area.border = LineBorder(DesignTokens.Colors.border, 1, true)
    area.background = DesignTokens.Colors.inputBackground
    area.foreground = DesignTokens.Colors.inputForeground
    area.lineWrap = true
    area.wrapStyleWord = true
}
