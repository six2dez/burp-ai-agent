package com.six2dez.burp.aiagent.ui

import com.six2dez.burp.aiagent.ui.ChatLinkHrefRows.visible
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import java.awt.Component
import java.net.URI
import java.net.URL
import javax.swing.JEditorPane
import javax.swing.JLabel
import javax.swing.JTextArea
import javax.swing.SwingUtilities
import javax.swing.event.HyperlinkEvent
import javax.swing.plaf.basic.BasicHTML
import javax.swing.text.html.HTML
import javax.swing.text.html.HTMLDocument

/**
 * Quick 261009-do9. A chat link opens only through [ChatLinkPolicy] and only after the user confirms
 * with the URL shown as plain text; the seams replace the dialog and the browser.
 *
 * Every `hyperlinkUpdate` call and every Swing construction runs inside `SwingUtilities.invokeAndWait`,
 * as the AWT event pump would deliver it.
 */
class ChatLinkOpenerTest {
    @Test
    fun thePolicyAcceptsOnlyPlainHttpAndHttpsUrls() {
        val acceptedWrong =
            (ChatLinkHrefRows.ALLOWED + ChatLinkHrefRows.QUOTED).mapNotNull { href ->
                val uri = ChatLinkPolicy.acceptedUri(href)
                if (uri?.toString() == href) null else "${visible(href)} -> $uri"
            }
        val trimmed = ChatLinkPolicy.acceptedUri("  https://example.com/  ")?.toString()
        val trimWrong = if (trimmed == "https://example.com/") emptyList() else listOf("surrounding whitespace -> $trimmed")
        val rejectedWrong =
            (ChatLinkHrefRows.REJECTED + listOf(null, "", "   ")).mapNotNull { href ->
                val uri = ChatLinkPolicy.acceptedUri(href)
                if (uri == null) null else "${href?.let(::visible)} -> $uri"
            }
        assertEquals(emptyList<String>(), acceptedWrong + trimWrong + rejectedWrong)
    }

    @Test
    fun anAcceptedLinkIsOpenedOnlyAfterTheUserConfirms() {
        val pane = onEdt { JEditorPane() }
        val href = "https://example.com/a?b=1&c=2"

        val yes = ChatLinkOpenerRecorder(answer = true)
        fire(yes, pane, HyperlinkEvent.EventType.ACTIVATED, href, urlOf(href))
        assertEquals(listOf<Pair<Component?, URI>>(pane to URI(href)), yes.confirms)
        assertEquals(listOf(URI(href)), yes.browses)

        val no = ChatLinkOpenerRecorder(answer = false)
        fire(no, pane, HyperlinkEvent.EventType.ACTIVATED, href, urlOf(href))
        assertEquals(listOf<Pair<Component?, URI>>(pane to URI(href)), no.confirms)
        assertEquals(emptyList<URI>(), no.browses)

        val fallback = ChatLinkOpenerRecorder(answer = true)
        fire(fallback, pane, HyperlinkEvent.EventType.ACTIVATED, null, urlOf("https://example.com/"))
        assertEquals(listOf<Pair<Component?, URI>>(pane to URI("https://example.com/")), fallback.confirms)
    }

    @Test
    fun aRejectedOrNonActivationEventIsNeitherConfirmedNorOpened() {
        val pane = onEdt { JEditorPane() }
        val activated = HyperlinkEvent.EventType.ACTIVATED
        val rows =
            ChatLinkHrefRows.REJECTED.map { href -> Triple(activated, href, urlOf(href)) } +
                listOf(
                    Triple(activated, "javascript:alert(1)", null),
                    Triple(activated, "file://attacker/share", urlOf("https://example.com/")),
                    Triple(HyperlinkEvent.EventType.ENTERED, "https://example.com/", urlOf("https://example.com/")),
                    Triple(HyperlinkEvent.EventType.EXITED, "https://example.com/", urlOf("https://example.com/")),
                )
        val wrong =
            rows.mapNotNull { (type, description, url) ->
                val recorder = ChatLinkOpenerRecorder(answer = true)
                fire(recorder, pane, type, description, url)
                if (recorder.confirms.isEmpty() && recorder.browses.isEmpty()) {
                    null
                } else {
                    "$type ${visible(description)} url=$url -> confirms=${recorder.confirms} browses=${recorder.browses}"
                }
            }
        assertEquals(emptyList<String>(), wrong)
    }

    @Test
    fun theConfirmationShowsTheUrlAsPlainText() {
        val url = "https://example.com/x'onmouseover='alert"
        onEdt {
            val content = ChatLinkOpener.confirmationContent(URI(url))
            val areas = ChatPanelTestHarness.findAll(content, JTextArea::class.java)
            assertEquals(1, areas.size, "text areas in the confirmation")
            assertFalse(areas.single().isEditable, "the URL area must not be editable")
            assertEquals(url, areas.single().text)
            val badLabels =
                ChatPanelTestHarness
                    .findAll(content, JLabel::class.java)
                    .map { it.text.orEmpty() }
                    .filter { it.contains(url) || BasicHTML.isHTMLString(it) }
            assertEquals(emptyList<String>(), badLabels)
        }
    }

    @Test
    fun theRealTranscriptPaneOpensLinksThroughTheConfirmingOpener() {
        val h = ChatPanelTestHarness.create(modelResponse = "ok")
        ChatPanelTestHarness.sendUserMessage(h, "docs [safe](https://example.com/docs)")
        ChatPanelTestHarness.drainEdt()

        onEdt {
            val linkPanes =
                ChatPanelTestHarness.findAll(h.panel.root, JEditorPane::class.java) { pane ->
                    (pane.document as? HTMLDocument)?.getIterator(HTML.Tag.A)?.isValid == true
                }
            assertEquals(1, linkPanes.size, "transcript panes holding an anchor")
            val listeners = linkPanes.single().hyperlinkListeners
            assertEquals(1, listeners.size, "hyperlink listeners on the transcript pane")
            assertTrue(listeners.single() is ChatLinkOpener, "listener is ${listeners.single()}")
        }
    }

    private fun fire(
        recorder: ChatLinkOpenerRecorder,
        source: JEditorPane,
        type: HyperlinkEvent.EventType,
        description: String?,
        url: URL?,
    ) {
        onEdt<Unit> { recorder.opener.hyperlinkUpdate(HyperlinkEvent(source, type, url, description)) }
    }

    private fun urlOf(href: String): URL? = runCatching { URI(href).toURL() }.getOrNull()

    private fun <T> onEdt(block: () -> T): T {
        var result: Result<T>? = null
        SwingUtilities.invokeAndWait { result = runCatching(block) }
        return requireNotNull(result).getOrThrow()
    }
}

/** Builds a [ChatLinkOpener] whose seams record every call instead of showing a dialog or a browser. */
private class ChatLinkOpenerRecorder(
    answer: Boolean,
) {
    val confirms = mutableListOf<Pair<Component?, URI>>()
    val browses = mutableListOf<URI>()
    val opener: ChatLinkOpener =
        ChatLinkOpener(
            confirm = { parent: Component?, uri: URI ->
                confirms += parent to uri
                answer
            },
            browse = { uri: URI -> browses += uri },
        )
}
