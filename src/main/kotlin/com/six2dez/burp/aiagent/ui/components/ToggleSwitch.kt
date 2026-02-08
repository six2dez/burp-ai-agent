package com.six2dez.burp.aiagent.ui.components

import com.six2dez.burp.aiagent.ui.UiTheme
import java.awt.Dimension
import java.awt.Graphics
import java.awt.Graphics2D
import java.awt.RenderingHints
import javax.swing.JToggleButton
import javax.swing.Timer

/**
 * Custom toggle switch component.
 * Extends JToggleButton so isSelected, addActionListener, and addItemListener work natively.
 * Track: 44x22px rounded, Thumb: 18px circle, animated ~150ms transition.
 */
class ToggleSwitch(selected: Boolean = false) : JToggleButton() {

    private val trackWidth = 44
    private val trackHeight = 22
    private val thumbDiameter = 18
    private val thumbPadding = 2

    private var thumbX: Float = if (selected) maxThumbX() else minThumbX()
    private val animTimer: Timer

    init {
        animTimer = Timer(15) {
            val target = if (isSelected) maxThumbX() else minThumbX()
            val delta = (maxThumbX() - minThumbX()) / 10f // ~150ms at 15ms interval
            if (thumbX < target) {
                thumbX = (thumbX + delta).coerceAtMost(target)
            } else if (thumbX > target) {
                thumbX = (thumbX - delta).coerceAtLeast(target)
            }
            repaint()
            if (thumbX == target) {
                animTimer.stop()
            }
        }

        isSelected = selected
        isOpaque = false
        isFocusPainted = false
        isContentAreaFilled = false
        isBorderPainted = false
        preferredSize = Dimension(trackWidth, trackHeight)
        minimumSize = Dimension(trackWidth, trackHeight)
        maximumSize = Dimension(trackWidth, trackHeight)
        text = ""

        addActionListener {
            animTimer.restart()
        }
    }

    private fun minThumbX(): Float = thumbPadding.toFloat()
    private fun maxThumbX(): Float = (trackWidth - thumbDiameter - thumbPadding).toFloat()

    override fun paintComponent(g: Graphics) {
        val g2 = g.create() as Graphics2D
        g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON)

        // Track
        val trackColor = if (isSelected) UiTheme.Colors.statusRunning else UiTheme.Colors.outlineVariant
        g2.color = if (isEnabled) trackColor else trackColor.let {
            java.awt.Color(it.red, it.green, it.blue, 100)
        }
        g2.fillRoundRect(0, 0, trackWidth, trackHeight, trackHeight, trackHeight)

        // Focus ring
        if (isFocusOwner) {
            g2.color = UiTheme.Colors.primary
            g2.drawRoundRect(-1, -1, trackWidth + 1, trackHeight + 1, trackHeight + 2, trackHeight + 2)
        }

        // Thumb
        val thumbY = (trackHeight - thumbDiameter) / 2f
        g2.color = if (isEnabled) java.awt.Color.WHITE else java.awt.Color(255, 255, 255, 180)
        g2.fillOval(thumbX.toInt(), thumbY.toInt(), thumbDiameter, thumbDiameter)

        g2.dispose()
    }

    override fun getPreferredSize(): Dimension = Dimension(trackWidth, trackHeight)
    override fun getMinimumSize(): Dimension = Dimension(trackWidth, trackHeight)
    override fun getMaximumSize(): Dimension = Dimension(trackWidth, trackHeight)

    override fun setSelected(selected: Boolean) {
        val wasSelected = isSelected
        super.setSelected(selected)
        if (wasSelected == selected) return
        if (!isShowing) {
            thumbX = if (selected) maxThumbX() else minThumbX()
            repaint()
            return
        }
        animTimer.restart()
    }
}
