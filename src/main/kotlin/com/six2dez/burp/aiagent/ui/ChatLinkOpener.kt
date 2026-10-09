package com.six2dez.burp.aiagent.ui

import java.awt.BorderLayout
import java.awt.Component
import java.awt.Desktop
import java.net.URI
import javax.swing.JComponent
import javax.swing.JLabel
import javax.swing.JOptionPane
import javax.swing.JPanel
import javax.swing.JScrollPane
import javax.swing.JTextArea
import javax.swing.event.HyperlinkEvent
import javax.swing.event.HyperlinkListener

/**
 * Quick 261009-do9: the one way a chat transcript opens a link.
 *
 * It is the second gate behind [MarkdownRenderer]: the clicked href goes through [ChatLinkPolicy]
 * again, so only an http/https URL with a host and no userinfo can ever be opened. The user then sees
 * the full URL as plain text and must press Open; Cancel is the initial option and closing the
 * dialog does not open anything.
 *
 * A rejected link does nothing. Nothing is logged because no logger is reachable from the transcript
 * message panel without widening its constructor, and since the renderer no longer emits an anchor
 * for a rejected link this path is defense in depth.
 *
 * [confirm] and [browse] are seams so tests drive the real policy and handler without a dialog or a
 * browser; `ChatLinkOpener()` is the production opener.
 */
internal class ChatLinkOpener(
    private val confirm: (parent: Component?, uri: URI) -> Boolean = ::confirmInDialog,
    private val browse: (uri: URI) -> Unit = ::browseWithDesktop,
) : HyperlinkListener {
    /** Hyperlink events arrive on the EDT, so the confirmation is shown synchronously. */
    override fun hyperlinkUpdate(e: HyperlinkEvent) {
        if (e.eventType != HyperlinkEvent.EventType.ACTIVATED) return
        val uri = ChatLinkPolicy.acceptedUri(e.description ?: e.url?.toString()) ?: return
        if (confirm(e.source as? Component, uri)) {
            browse(uri)
        }
    }

    companion object {
        private const val DIALOG_TITLE = "Open link"
        private const val PROMPT = "Open this link from the chat in your default browser?"
        private const val OPEN_LABEL = "Open"
        private const val CANCEL_LABEL = "Cancel"
        private const val OPEN_INDEX = 0
        private const val URL_ROWS = 3
        private const val URL_COLUMNS = 48

        /**
         * The confirmation body: a fixed prompt and the URL in a non-editable [JTextArea]. A
         * [JTextArea] never renders HTML, which is the plain-text guarantee for an attacker-chosen URL.
         */
        internal fun confirmationContent(uri: URI): JComponent {
            val area = JTextArea(uri.toString(), URL_ROWS, URL_COLUMNS)
            area.isEditable = false
            area.lineWrap = true
            val panel = JPanel(BorderLayout())
            panel.add(JLabel(PROMPT), BorderLayout.NORTH)
            panel.add(JScrollPane(area), BorderLayout.CENTER)
            return panel
        }

        private fun confirmInDialog(
            parent: Component?,
            uri: URI,
        ): Boolean {
            val choice =
                JOptionPane.showOptionDialog(
                    parent,
                    confirmationContent(uri),
                    DIALOG_TITLE,
                    JOptionPane.DEFAULT_OPTION,
                    JOptionPane.WARNING_MESSAGE,
                    null,
                    arrayOf(OPEN_LABEL, CANCEL_LABEL),
                    CANCEL_LABEL,
                )
            return choice == OPEN_INDEX
        }

        private fun browseWithDesktop(uri: URI) {
            try {
                if (Desktop.isDesktopSupported()) {
                    val desktop = Desktop.getDesktop()
                    if (desktop.isSupported(Desktop.Action.BROWSE)) desktop.browse(uri)
                }
            } catch (_: Exception) {
                // The OS refused or has no browser, and there is nothing to report from here.
            }
        }
    }
}
