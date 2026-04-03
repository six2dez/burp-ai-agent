package com.six2dez.burp.aiagent.scanner

import burp.api.montoya.core.Marker
import burp.api.montoya.http.message.HttpRequestResponse

/**
 * Utility for adding request/response markers to audit issue evidence.
 * Markers highlight the affected portion of the request (payload) or
 * response (evidence) so Burp shows highlighted regions in finding details.
 */
object IssueMarkerSupport {

    private const val MAX_MARKERS = 5

    /**
     * Mark the payload location in the exploit request.
     * Searches for the payload value (raw and URL-encoded) in request bytes.
     */
    fun markRequestPayload(
        reqResp: HttpRequestResponse,
        payloadValue: String
    ): HttpRequestResponse {
        if (payloadValue.isBlank()) return reqResp
        val reqBytes = reqResp.request().toByteArray()
        val reqStr = String(reqBytes.bytes, Charsets.ISO_8859_1)
        val encoded = java.net.URLEncoder.encode(payloadValue, "UTF-8")
        // Try URL-encoded first (more specific), then raw
        val searchTerms = listOf(encoded, payloadValue).distinct()
        for (term in searchTerms) {
            val idx = reqStr.indexOf(term)
            if (idx >= 0) {
                return reqResp.withRequestMarkers(
                    Marker.marker(idx, idx + term.length)
                )
            }
        }
        return reqResp
    }

    /**
     * Mark evidence text in the response body.
     * Searches for the evidence string (or its beginning) in response bytes.
     */
    fun markResponseEvidence(
        reqResp: HttpRequestResponse,
        evidence: String
    ): HttpRequestResponse {
        val resp = reqResp.response() ?: return reqResp
        if (evidence.isBlank()) return reqResp
        val respBytes = resp.toByteArray()
        val respStr = String(respBytes.bytes, Charsets.ISO_8859_1)
        // Try full evidence first, then progressively shorter prefixes
        val prefixes = listOf(100, 60, 30).map { evidence.take(it) }
        var idx = -1
        var matchedLength = 0
        for (prefix in prefixes) {
            idx = respStr.indexOf(prefix)
            if (idx >= 0) { matchedLength = prefix.length; break }
        }
        if (idx < 0) return reqResp
        val endIdx = (idx + matchedLength).coerceAtMost(respBytes.length())
        return reqResp.withResponseMarkers(Marker.marker(idx, endIdx))
    }

    /**
     * Mark quoted snippets from the detail text that appear in the response.
     * Useful for passive scanner findings where AI describes what it found.
     */
    fun markResponseFromDetail(
        reqResp: HttpRequestResponse,
        detail: String
    ): HttpRequestResponse {
        val resp = reqResp.response() ?: return reqResp
        val respBytes = resp.toByteArray()
        val respStr = String(respBytes.bytes, Charsets.ISO_8859_1)
        // Extract quoted strings from the detail that might exist in the response
        val quotedPattern = Regex(""""([^"]{4,80})"""")
        val markers = mutableListOf<Marker>()
        for (match in quotedPattern.findAll(detail)) {
            val snippet = match.groupValues[1]
            val idx = respStr.indexOf(snippet)
            if (idx >= 0 && idx + snippet.length <= respBytes.length()) {
                markers.add(Marker.marker(idx, idx + snippet.length))
            }
            if (markers.size >= MAX_MARKERS) break
        }
        return if (markers.isNotEmpty()) reqResp.withResponseMarkers(markers) else reqResp
    }
}
