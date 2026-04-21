package com.six2dez.burp.aiagent.scanner

import java.net.URI

/**
 * Extracts API endpoints from JavaScript file content.
 * Discovers hidden API routes that may not appear in proxy traffic.
 */
object JsEndpointExtractor {
    private val patterns =
        listOf(
            // fetch("url") / fetch('url') / fetch(`url`)
            Regex("""fetch\s*\(\s*["'`]([^"'`\s]+)["'`]"""),
            // axios.get/post/put/delete/patch("url")
            Regex("""axios\.\w+\s*\(\s*["'`]([^"'`\s]+)["'`]"""),
            // $.ajax({ url: "..." })
            Regex("""\.\s*ajax\s*\(\s*\{[^}]*url\s*:\s*["'`]([^"'`\s]+)["'`]"""),
            // XMLHttpRequest.open("METHOD", "url")
            Regex("""\.open\s*\(\s*["'`]\w+["'`]\s*,\s*["'`]([^"'`\s]+)["'`]"""),
            // "/api/v1/..." or "/api/..."
            Regex("""["'`](/api/[^"'`\s]{2,})["'`]"""),
            // "/v1/..." "/v2/..." etc.
            Regex("""["'`](/v[0-9]+/[^"'`\s]{2,})["'`]"""),
            // endpoint/path assignment: endpoint: "/...", path = "/..."
            Regex("""(?:endpoint|api_?path|base_?url|url_?path)\s*[:=]\s*["'`](/[^"'`\s]+)["'`]""", RegexOption.IGNORE_CASE),
            // Multi-segment path strings: "/users/profile", "/admin/settings"
            Regex("""["'`](/[a-z_-]+/[a-z_-]+(?:/[a-z_-]+)*)["'`]"""),
        )

    // Paths to exclude (common non-API JS paths)
    private val excludePatterns =
        Regex(
            """^/(css|js|img|images|static|assets|fonts|media|public|favicon|manifest|sw|service-worker|workbox|webpack|node_modules|\.well-known)/""",
            RegexOption.IGNORE_CASE,
        )

    // File extensions to exclude
    private val excludeExtensions =
        Regex(
            """\.(js|css|map|png|jpg|jpeg|gif|svg|ico|woff2?|ttf|eot|pdf|zip|gz|tar|mp[34]|avi|mov|webm|webp|avif)$""",
            RegexOption.IGNORE_CASE,
        )

    // Min/max path length filters
    private const val MIN_PATH_LENGTH = 4
    private const val MAX_PATH_LENGTH = 200
    private const val MAX_ENDPOINTS_PER_FILE = 50

    /**
     * Extract API endpoint paths from JavaScript content.
     * Returns a set of unique path strings (e.g., "/api/v1/users").
     */
    fun extract(jsContent: String): Set<String> {
        if (jsContent.isBlank()) return emptySet()

        val endpoints = mutableSetOf<String>()

        for (pattern in patterns) {
            for (match in pattern.findAll(jsContent)) {
                val path = match.groupValues.last().trim()
                if (isValidEndpoint(path)) {
                    endpoints.add(normalizePath(path))
                }
                if (endpoints.size >= MAX_ENDPOINTS_PER_FILE) break
            }
            if (endpoints.size >= MAX_ENDPOINTS_PER_FILE) break
        }

        return endpoints
    }

    /**
     * Resolve relative paths to absolute URLs using the base URL of the JS file.
     */
    fun resolveEndpoints(
        endpoints: Set<String>,
        baseUrl: String,
    ): Set<String> {
        val resolved = mutableSetOf<String>()
        val base =
            try {
                URI(baseUrl)
            } catch (_: Exception) {
                return endpoints
            }
        val origin = "${base.scheme}://${base.host}${if (base.port > 0 && base.port != 443 && base.port != 80) ":${base.port}" else ""}"

        for (endpoint in endpoints) {
            val resolved_url =
                when {
                    endpoint.startsWith("http://") || endpoint.startsWith("https://") -> endpoint
                    endpoint.startsWith("/") -> "$origin$endpoint"
                    else -> "$origin/$endpoint"
                }
            resolved.add(resolved_url)
        }
        return resolved
    }

    private fun isValidEndpoint(path: String): Boolean {
        if (path.length < MIN_PATH_LENGTH || path.length > MAX_PATH_LENGTH) return false
        if (!path.startsWith("/") && !path.startsWith("http")) return false
        if (excludePatterns.containsMatchIn(path)) return false
        if (excludeExtensions.containsMatchIn(path)) return false
        // Must contain at least one letter (not purely numeric/symbolic)
        if (!path.any { it.isLetter() }) return false
        // Skip template literals with ${...}
        if (path.contains("\${")) return false
        return true
    }

    private fun normalizePath(path: String): String {
        // Remove trailing slashes, query strings, and fragments
        return path
            .substringBefore("?")
            .substringBefore("#")
            .trimEnd('/')
            .ifBlank { "/" }
    }
}
