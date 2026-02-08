package com.six2dez.burp.aiagent.ui

import java.awt.BorderLayout
import java.awt.FlowLayout
import javax.swing.JButton
import javax.swing.JComponent
import javax.swing.JPanel
import javax.swing.JTabbedPane
import javax.swing.border.EmptyBorder
import javax.swing.border.LineBorder

class BottomTabsPanel(private val settingsPanel: SettingsPanel) {
    val root: JComponent = JPanel(BorderLayout())

    private val tabbedPane = JTabbedPane()
    private val saveButton = JButton("Save settings")
    private val restoreButton = JButton("Restore defaults")
    private val collapseButton = JButton("\u25BC Settings") // ▼
    private val contentPanel = JPanel(BorderLayout())
    private var collapsed = false
    private var savedDividerLocation = -1

    init {
        root.background = UiTheme.Colors.surface

        // Collapse/expand toggle bar
        collapseButton.font = UiTheme.Typography.label
        collapseButton.isFocusPainted = false
        collapseButton.isOpaque = false
        collapseButton.border = javax.swing.border.EmptyBorder(4, 12, 4, 12)
        collapseButton.horizontalAlignment = javax.swing.SwingConstants.LEFT
        collapseButton.cursor = java.awt.Cursor.getPredefinedCursor(java.awt.Cursor.HAND_CURSOR)
        collapseButton.addActionListener { toggleCollapse() }

        val toggleBar = JPanel(BorderLayout())
        toggleBar.background = UiTheme.Colors.surface
        toggleBar.border = javax.swing.border.MatteBorder(1, 0, 0, 0, UiTheme.Colors.outline)
        toggleBar.add(collapseButton, BorderLayout.WEST)

        tabbedPane.background = UiTheme.Colors.surface
        tabbedPane.foreground = UiTheme.Colors.onSurface
        tabbedPane.border = EmptyBorder(0, 0, 0, 0)

        tabbedPane.addTab("AI Backend", settingsPanel.generalTabComponent())
        tabbedPane.addTab("AI Passive Scanner", settingsPanel.passiveScannerTabComponent())
        tabbedPane.addTab("AI Active Scanner", settingsPanel.activeScannerTabComponent())
        tabbedPane.addTab("MCP Server", settingsPanel.mcpTabComponent())
        tabbedPane.addTab("Burp Integration", settingsPanel.burpIntegrationTabComponent())
        tabbedPane.addTab("Prompt Templates", settingsPanel.promptsTabComponent())
        tabbedPane.addTab("Privacy & Logging", settingsPanel.privacyTabComponent())
        tabbedPane.addTab("Help", settingsPanel.helpTabComponent())

        saveButton.font = UiTheme.Typography.label
        saveButton.background = UiTheme.Colors.primary
        saveButton.foreground = UiTheme.Colors.onPrimary
        saveButton.isOpaque = true
        saveButton.border = EmptyBorder(8, 14, 8, 14)
        saveButton.isFocusPainted = false
        saveButton.addActionListener {
            settingsPanel.saveSettings()
        }

        restoreButton.font = UiTheme.Typography.label
        restoreButton.background = UiTheme.Colors.surface
        restoreButton.foreground = UiTheme.Colors.primary
        restoreButton.isOpaque = true
        restoreButton.border = LineBorder(UiTheme.Colors.outline, 1, true)
        restoreButton.isFocusPainted = false
        restoreButton.addActionListener {
            settingsPanel.restoreDefaultsWithConfirmation()
        }

        val buttonPanel = JPanel(FlowLayout(FlowLayout.RIGHT, 12, 6))
        buttonPanel.background = UiTheme.Colors.surface
        buttonPanel.border = EmptyBorder(4, 12, 8, 12)
        buttonPanel.add(restoreButton)
        buttonPanel.add(saveButton)

        contentPanel.background = UiTheme.Colors.surface
        contentPanel.add(tabbedPane, BorderLayout.CENTER)
        contentPanel.add(buttonPanel, BorderLayout.SOUTH)

        root.add(toggleBar, BorderLayout.NORTH)
        root.add(contentPanel, BorderLayout.CENTER)

        settingsPanel.setDialogParent(root)
    }

    /** Public API for keyboard shortcut (Escape key) */
    fun toggle() = toggleCollapse()

    private fun toggleCollapse() {
        val splitPane = root.parent as? javax.swing.JSplitPane ?: return
        collapsed = !collapsed
        if (collapsed) {
            savedDividerLocation = splitPane.dividerLocation
            contentPanel.isVisible = false
            root.minimumSize = java.awt.Dimension(0, 0)
            root.preferredSize = java.awt.Dimension(0, collapseButton.preferredSize.height + 6)
            splitPane.dividerLocation = splitPane.height - splitPane.dividerSize - collapseButton.preferredSize.height - 6
            collapseButton.text = "\u25B6 Settings"
        } else {
            contentPanel.isVisible = true
            root.minimumSize = java.awt.Dimension(0, 90)
            root.preferredSize = java.awt.Dimension(0, 240)
            if (savedDividerLocation > 0) {
                splitPane.dividerLocation = savedDividerLocation
            }
            collapseButton.text = "\u25BC Settings"
        }
        root.revalidate()
        root.repaint()
        splitPane.revalidate()
        splitPane.repaint()
    }
}
