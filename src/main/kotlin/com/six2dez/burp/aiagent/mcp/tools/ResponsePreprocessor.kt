package com.six2dez.burp.aiagent.mcp.tools

data class ResponsePreprocessorSettings(
    val preprocessProxyHistory: Boolean = true,
    val preprocessMaxResponseSizeKb: Int = 20,
    val preprocessFilterBinaryContent: Boolean = true,
    val preprocessAllowedContentTypes: Set<String> = setOf(
        "text/",
        "application/json",
        "application/xml",
        "application/javascript",
        "application/x-www-form-urlencoded",
        "multipart/form-data"
    )
)

/**
 * Preprocesses HTTP response data to reduce context window usage.
 * Filters out binary content and truncates large responses.
 */
object ResponsePreprocessor {

    /**
     * Binary content type prefixes that should be filtered out
     */
    private val BINARY_CONTENT_PREFIXES = setOf(
        "image/", "video/", "audio/", "font/",
        "application/octet-stream", "application/pdf",
        "application/zip", "application/gzip", "application/x-tar",
        "application/x-bzip2", "application/x-7z-compressed",
        "application/java-archive", "application/vnd.ms-excel",
        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        "application/msword", "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        "application/vnd.ms-powerpoint", "application/vnd.openxmlformats-officedocument.presentationml.presentation"
    )

    /**
     * Preprocesses a response string based on settings.
     * @param response The raw response string
     * @param settings Agent settings containing preprocessing configuration
     * @return Preprocessed response string
     */
    fun preprocessResponse(response: String, settings: ResponsePreprocessorSettings): String {
        if (!settings.preprocessProxyHistory) {
            return response
        }

        // Extract headers and body
        val (separator, headerEndIndex) = when {
            response.contains("\r\n\r\n") -> "\r\n\r\n" to response.indexOf("\r\n\r\n")
            response.contains("\n\n") -> "\n\n" to response.indexOf("\n\n")
            else -> "" to -1
        }
        if (headerEndIndex < 0) {
            // No body separator found, return as-is
            return response
        }

        val headers = response.substring(0, headerEndIndex)
        val body = response.substring(headerEndIndex + separator.length)

        // Check if content type should be filtered
        if (settings.preprocessFilterBinaryContent) {
            val contentType = extractContentType(headers)
            if (contentType != null && isBinaryContentType(contentType, settings.preprocessAllowedContentTypes)) {
                val originalSize = body.toByteArray(Charsets.UTF_8).size
                return "$headers$separator[Content-Type: $contentType - Binary content filtered out, original size: $originalSize bytes]"
            }
        }

        // Truncate large responses
        val maxSizeBytes = settings.preprocessMaxResponseSizeKb * 1024
        val bodyBytes = body.toByteArray(Charsets.UTF_8)
        if (bodyBytes.size > maxSizeBytes) {
            val truncatedBody = truncateResponse(body, maxSizeBytes)
            return "$headers$separator$truncatedBody"
        }

        return response
    }

    /**
     * Extracts Content-Type header value from response headers.
     */
    fun extractContentType(headers: String): String? {
        val lines = headers.split(Regex("\\r?\\n"))
        for (line in lines) {
            if (line.startsWith("content-type:", ignoreCase = true)) {
                val value = line.substringAfter(":", "").trim()
                // Extract just the MIME type (before any parameters like charset)
                return value.split(";")[0].trim().lowercase()
            }
        }
        return null
    }

    /**
     * Checks if a content type is binary and should be filtered.
     */
    fun isBinaryContentType(contentType: String, allowedTypes: Set<String>): Boolean {
        val lowerContentType = contentType.lowercase()

        // Check if it matches any allowed type prefix
        for (allowed in allowedTypes) {
            if (lowerContentType.startsWith(allowed.lowercase())) {
                return false
            }
        }

        // Check if it matches any binary type prefix
        for (binary in BINARY_CONTENT_PREFIXES) {
            if (lowerContentType.startsWith(binary)) {
                return true
            }
        }

        // Heuristic for vendor-specific textual content types
        if (lowerContentType.endsWith("+json") || lowerContentType.endsWith("+xml")) return false

        // Unknown application/* content is usually compressed/binary blobs.
        if (lowerContentType.startsWith("application/")) return true

        return false
    }

    /**
     * Truncates a response body, keeping first and last portions with SNIP placeholder.
     * @param body The body text to truncate
     * @param maxSizeBytes Maximum size in bytes
     * @return Truncated body with SNIP placeholder
     */
    fun truncateResponse(body: String, maxSizeBytes: Int): String {
        val bodyBytes = body.toByteArray(Charsets.UTF_8)
        if (bodyBytes.size <= maxSizeBytes) {
            return body
        }

        val normalizedMax = maxSizeBytes.coerceAtLeast(64)
        // Keep first 20% and last 10% of configured max response size
        val firstPortionSize = (normalizedMax * 0.2).toInt().coerceAtLeast(32)
        val lastPortionSize = (normalizedMax * 0.1).toInt().coerceAtLeast(16)

        val firstPortion = takeFirstBytesSafe(body, firstPortionSize)
        val lastPortion = takeLastBytesSafe(body, lastPortionSize)

        val keptBytes = firstPortion.toByteArray(Charsets.UTF_8).size + lastPortion.toByteArray(Charsets.UTF_8).size
        val truncatedBytes = (bodyBytes.size - keptBytes).coerceAtLeast(0)

        return "$firstPortion\n[SNIP - $truncatedBytes bytes truncated]\n$lastPortion"
    }

    private fun takeFirstBytesSafe(text: String, maxBytes: Int): String {
        if (maxBytes <= 0) return ""
        val out = StringBuilder()
        var used = 0
        for (ch in text) {
            val bytes = ch.toString().toByteArray(Charsets.UTF_8).size
            if (used + bytes > maxBytes) break
            out.append(ch)
            used += bytes
        }
        return out.toString()
    }

    private fun takeLastBytesSafe(text: String, maxBytes: Int): String {
        if (maxBytes <= 0) return ""
        val reversed = StringBuilder()
        var used = 0
        for (i in text.length - 1 downTo 0) {
            val ch = text[i]
            val bytes = ch.toString().toByteArray(Charsets.UTF_8).size
            if (used + bytes > maxBytes) break
            reversed.append(ch)
            used += bytes
        }
        return reversed.reverse().toString()
    }
}
