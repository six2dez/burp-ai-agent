package com.six2dez.burp.aiagent.ui

import java.net.URI
import java.net.URISyntaxException

/**
 * Quick 261009-do9: the one link gate shared by [MarkdownRenderer] (which links become anchors) and
 * [ChatLinkOpener] (which links may open). Chat text includes AI replies and tool output that carry
 * target HTTP content, so every href reaching this gate is attacker-influenced.
 *
 * Rules, in order:
 * - trim surrounding whitespace and reject a blank result;
 * - reject any ISO control, whitespace or Unicode format character. Bidi overrides and zero-width
 *   characters could make the URL shown in the confirmation read differently from the one opened;
 *   java.net.URI already refuses control and space characters, so that part is a second layer;
 * - parse with java.net.URI only, rejecting on [URISyntaxException];
 * - require an absolute URI whose scheme is http or https (ignoring case), a non-empty host, and no
 *   userinfo at all, since an `https://bank.example@evil.example/` shape is phishing.
 *
 * It fails closed: anything java.net.URI does not parse as a server host (an underscore or a raw
 * non-ASCII host, an opaque `http:example.com`) has a null host and is rejected.
 */
internal object ChatLinkPolicy {
    private val ALLOWED_SCHEMES = setOf("http", "https")

    /** The parsed URI when [rawHref] is a link the chat may render and open, or null otherwise. */
    fun acceptedUri(rawHref: String?): URI? {
        val href = rawHref?.trim().orEmpty()
        val uri =
            if (href.isEmpty() || href.any(::isForbiddenChar)) {
                null
            } else {
                try {
                    URI(href)
                } catch (_: URISyntaxException) {
                    null
                }
            }
        return uri?.takeIf(::isAllowedTarget)
    }

    private fun isForbiddenChar(c: Char): Boolean = c.isISOControl() || c.isWhitespace() || c.category == CharCategory.FORMAT

    private fun isAllowedTarget(uri: URI): Boolean {
        val scheme = uri.scheme?.lowercase()
        return uri.isAbsolute &&
            scheme in ALLOWED_SCHEMES &&
            !uri.host.isNullOrEmpty() &&
            uri.rawUserInfo == null
    }
}
