package com.six2dez.burp.aiagent.util

import java.net.URI

object IssueUtils {
    private val aiPrefixRegex = Regex("^(?:\\[AI(?:[^\\]]*)?\\]\\s*)+", RegexOption.IGNORE_CASE)

    private val numericIdRegex = Regex("^\\d{2,}$")
    private val uuidLikeRegex = Regex("^[a-f0-9]{8}-[a-f0-9]{4}-[1-5][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$", RegexOption.IGNORE_CASE)
    private val objectIdLikeRegex = Regex("^[a-f0-9]{24}$", RegexOption.IGNORE_CASE)

    fun canonicalIssueName(name: String): String {
        return name
            .trim()
            .replace(aiPrefixRegex, "")
            .trim()
            .lowercase()
    }

    /**
     * Normalize a URL for dedup comparison:
     * - Strip query string
     * - Replace numeric IDs, UUIDs, and ObjectIDs in path segments with placeholders
     */
    fun normalizeUrl(url: String): String {
        if (url.isBlank()) return url
        return try {
            val uri = URI(url)
            val normalizedPath = normalizePathSegments(uri.path.orEmpty())
            URI(uri.scheme, uri.authority, normalizedPath, null, null).toString()
        } catch (_: Exception) {
            // Fallback: strip query string
            url.substringBefore('?')
        }
    }

    fun normalizePathSegments(path: String): String {
        if (path.isBlank()) return "/"
        return path.split('/')
            .joinToString("/") { segment ->
                when {
                    segment.isBlank() -> ""
                    numericIdRegex.matches(segment) -> "{id}"
                    uuidLikeRegex.matches(segment) -> "{uuid}"
                    objectIdLikeRegex.matches(segment) -> "{oid}"
                    else -> segment
                }
            }
            .ifBlank { "/" }
    }

    fun formatIssueDetailHtml(lines: List<String>): String {
        return lines.joinToString("<br>") { line ->
            val escaped = line
                .replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;")
            if (escaped.startsWith("  ")) {
                "&nbsp;&nbsp;" + escaped.drop(2)
            } else {
                escaped
            }
        }
    }

    fun hasEquivalentIssue(
        name: String,
        baseUrl: String,
        issues: Iterable<Pair<String, String>>
    ): Boolean {
        val canonicalName = canonicalIssueName(name)
        val normalizedUrl = normalizeUrl(baseUrl)
        return issues.any { issue ->
            normalizeUrl(issue.second) == normalizedUrl && canonicalIssueName(issue.first) == canonicalName
        }
    }

    fun hasExistingIssue(
        name: String,
        baseUrl: String,
        issues: Iterable<Pair<String, String>>,
        ignoreCase: Boolean = false
    ): Boolean {
        val normalizedUrl = normalizeUrl(baseUrl)
        return issues.any { issue ->
            val sameName = if (ignoreCase) {
                issue.first.equals(name, ignoreCase = true)
            } else {
                issue.first == name
            }
            sameName && normalizeUrl(issue.second) == normalizedUrl
        }
    }
}
