package com.six2dez.burp.aiagent.ui

import com.six2dez.burp.aiagent.ui.ChatLinkHrefRows.visible
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import java.io.StringReader
import javax.swing.JEditorPane
import javax.swing.SwingUtilities
import javax.swing.text.Document
import javax.swing.text.html.HTML
import javax.swing.text.html.HTMLDocument
import javax.swing.text.html.HTMLEditorKit

/**
 * Quick 261009-do9. A chat link is an anchor only for a plain http/https URL, the href cannot be
 * broken by quotes, and every assertion reads the PARSED document, never the markup.
 *
 * The table tests collect one message per wrong row and compare the list with an empty one, so a
 * failure prints every wrong row at once.
 */
class ChatLinkRenderingTest {
    private data class Anchor(
        val href: String?,
        val attributeNames: Set<String>,
        val text: String,
    )

    @Test
    fun acceptedHrefsRenderOneAnchorCarryingExactlyThatHref() {
        val wrong =
            (ChatLinkHrefRows.ALLOWED + ChatLinkHrefRows.QUOTED).mapNotNull { href ->
                val anchors = anchorsOf(render("[label]($href)"))
                val expected = listOf(Anchor(href, setOf("href", "color"), "label"))
                if (anchors == expected) null else "${visible(href)} -> $anchors"
            }
        assertEquals(emptyList<String>(), wrong)
    }

    @Test
    fun rejectedHrefsRenderNoAnchor() {
        val wrong =
            ChatLinkHrefRows.REJECTED.mapNotNull { href ->
                val anchors = anchorsOf(render("[label]($href)"))
                if (anchors.isEmpty()) null else "${visible(href)} -> $anchors"
            }
        assertEquals(emptyList<String>(), wrong)
    }

    @Test
    fun aRejectedLinkStaysVisibleAsItsMarkdownText() {
        val rows =
            listOf(
                "before [click me](javascript:alert(1)) after" to "before [click me](javascript:alert(1)) after",
                "[share](file://attacker/share)" to "[share](file://attacker/share)",
            )
        val wrong =
            rows.mapNotNull { (markdown, visibleText) ->
                val doc = render(markdown)
                val anchors = anchorsOf(doc)
                val text = doc.getText(0, doc.length)
                if (anchors.isEmpty() && text.contains(visibleText)) null else "$markdown -> anchors=$anchors text='$text'"
            }
        assertEquals(emptyList<String>(), wrong)
    }

    /**
     * Tracer through a real [ChatPanel]. The user bubble is used because it renders synchronously
     * through the same `ChatMessagePanel.updateHtml` as AI replies, whose re-render runs on a 200 ms
     * coalescing timer.
     */
    @Test
    fun aRealChatTranscriptLinksOnlyHttpUrlsAndKeepsTheirHref() {
        val h = ChatPanelTestHarness.create(modelResponse = "ok")
        ChatPanelTestHarness.sendUserMessage(
            h,
            "docs [safe](https://example.com/docs) quote [q](https://example.com/x'onmouseover='alert) " +
                "share [s](file://attacker/share)",
        )
        ChatPanelTestHarness.drainEdt()

        var anchors: List<Anchor> = emptyList()
        var text = ""
        SwingUtilities.invokeAndWait {
            val panes = ChatPanelTestHarness.findAll(h.panel.root, JEditorPane::class.java)
            anchors = panes.flatMap { pane -> anchorsOf(pane.document) }
            text = panes.joinToString(" ") { pane -> pane.document.getText(0, pane.document.length) }
        }

        assertEquals(
            listOf("https://example.com/docs", "https://example.com/x'onmouseover='alert"),
            anchors.map { it.href },
        )
        assertEquals(
            emptyList<Anchor>(),
            anchors.filter { it.attributeNames != setOf("href", "color") },
        )
        assertTrue(text.contains("[s](file://attacker/share)"), "transcript text: $text")
    }

    private fun render(markdown: String): HTMLDocument {
        val html = MarkdownRenderer.toHtml(markdown, isDark = false)
        val kit = HTMLEditorKit()
        val doc = kit.createDefaultDocument() as HTMLDocument
        kit.read(StringReader(html), doc, 0)
        return doc
    }

    private fun anchorsOf(doc: Document): List<Anchor> {
        val html = doc as? HTMLDocument ?: return emptyList()
        val anchors = mutableListOf<Anchor>()
        val it = html.getIterator(HTML.Tag.A)
        while (it.isValid) {
            val attributes = it.attributes
            val names =
                attributes.attributeNames
                    .toList()
                    .map { name -> name.toString() }
                    .toSet()
            anchors +=
                Anchor(
                    href = attributes.getAttribute(HTML.Attribute.HREF) as? String,
                    attributeNames = names,
                    text = html.getText(it.startOffset, it.endOffset - it.startOffset),
                )
            it.next()
        }
        return anchors
    }
}
