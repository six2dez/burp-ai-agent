package com.six2dez.burp.aiagent.scanner

import burp.api.montoya.http.message.requests.HttpRequest
import com.fasterxml.jackson.databind.ObjectMapper
import java.net.URI

object InjectionPointExtractor {
    private val jsonFieldPattern =
        Regex("\"([A-Za-z0-9_\\-]+)\"\\s*:\\s*(\"([^\"\\\\]*(?:\\\\.[^\"\\\\]*)*)\"|(-?\\d+(?:\\.\\d+)?)|(true|false|null))")
    private val xmlElementPattern = Regex("<([A-Za-z0-9_\\-]+)>([^<]{1,200})</\\1>")
    private val pathIdPattern = Regex("([0-9]+|[a-f0-9-]{36}|[a-f0-9]{24})", RegexOption.IGNORE_CASE)
    private val jsonMapper = ObjectMapper()

    fun extract(
        request: HttpRequest,
        headerAllowlist: Set<String>,
        maxFields: Int = 20,
    ): List<InjectionPoint> {
        val points = mutableListOf<InjectionPoint>()

        request.parameters().filter { it.type().name == "URL" }.forEach { param ->
            points.add(InjectionPoint(InjectionType.URL_PARAM, param.name(), param.value()))
        }

        request.parameters().filter { it.type().name == "BODY" }.forEach { param ->
            points.add(InjectionPoint(InjectionType.BODY_PARAM, param.name(), param.value()))
        }

        request.parameters().filter { it.type().name == "COOKIE" }.forEach { param ->
            points.add(InjectionPoint(InjectionType.COOKIE, param.name(), param.value()))
        }

        request.headers().forEach { header ->
            if (headerAllowlist.contains(header.name().lowercase())) {
                points.add(InjectionPoint(InjectionType.HEADER, header.name(), header.value()))
            }
        }

        val body =
            try {
                request.bodyToString()
            } catch (_: Exception) {
                ""
            }
        val contentType = request.headerValue("Content-Type")?.lowercase() ?: ""
        if (body.isNotBlank()) {
            if (contentType.contains("json") || body.trimStart().startsWith("{") || body.trimStart().startsWith("[")) {
                points.addAll(extractJsonFields(body, maxFields))
            }
            if (contentType.contains("xml") || body.trimStart().startsWith("<")) {
                points.addAll(extractXmlElements(body, maxFields))
            }
        }

        val path =
            try {
                URI(request.url()).path ?: ""
            } catch (_: Exception) {
                ""
            }
        pathIdPattern.findAll(path).forEach { match ->
            points.add(
                InjectionPoint(
                    type = InjectionType.PATH_SEGMENT,
                    name = "path_id",
                    originalValue = match.value,
                    position = match.range.first,
                ),
            )
        }

        return points
    }

    private fun extractJsonFields(
        body: String,
        maxFields: Int,
    ): List<InjectionPoint> {
        val results = mutableListOf<InjectionPoint>()
        try {
            val root = jsonMapper.readTree(body)
            if (root.isObject) {
                val fields = root.fields()
                while (fields.hasNext() && results.size < maxFields) {
                    val field = fields.next()
                    val valueNode = field.value
                    val value =
                        when {
                            valueNode.isTextual -> valueNode.asText()
                            valueNode.isNumber -> valueNode.numberValue().toString()
                            valueNode.isBoolean -> valueNode.booleanValue().toString()
                            valueNode.isNull -> "null"
                            else -> continue
                        }
                    results.add(InjectionPoint(InjectionType.JSON_FIELD, field.key, value))
                }
                if (results.isNotEmpty()) {
                    return results
                }
            }
        } catch (_: Exception) {
            // Fall back to regex extraction for partially malformed bodies.
        }
        for (match in jsonFieldPattern.findAll(body)) {
            val name = match.groupValues[1]
            val value =
                match.groupValues[3]
                    .ifEmpty { match.groupValues[4] }
                    .ifEmpty { match.groupValues[5] }
            results.add(InjectionPoint(InjectionType.JSON_FIELD, name, value))
            if (results.size >= maxFields) break
        }
        return results
    }

    private fun extractXmlElements(
        body: String,
        maxFields: Int,
    ): List<InjectionPoint> {
        val results = mutableListOf<InjectionPoint>()
        for (match in xmlElementPattern.findAll(body)) {
            val name = match.groupValues[1]
            val value = match.groupValues[2].trim()
            results.add(InjectionPoint(InjectionType.XML_ELEMENT, name, value))
            if (results.size >= maxFields) break
        }
        return results
    }

    /**
     * Match a byte-range selection inside the raw request to the closest insertion point. Used by
     * the "AI Scan on Selected Insertion Point" right-click action so the user can scope a single
     * scan to one parameter / header / JSON field instead of every extractable point.
     *
     * Returns the matched [InjectionPoint] or null when the selection does not overlap any
     * candidate. The match priority is: URL/BODY/COOKIE parameters (Montoya gives us exact
     * byte offsets via [burp.api.montoya.http.message.params.ParsedHttpParameter.valueOffsets]) →
     * headers (matched by line offset in the raw request bytes) → JSON / XML body fields
     * (best-effort substring match) → path segment IDs.
     *
     * Known limitations (acceptable for the current scope):
     * - Header and body fallback branches use `indexOf` on the raw bytes, so duplicate identical
     *   header lines or repeated identical JSON values will always resolve to the FIRST occurrence
     *   even if the selection overlaps a later one. Real-world requests rarely contain
     *   byte-for-byte duplicates in the same message.
     * - Selecting only a JSON / XML key (not the value) is treated as a non-match because the
     *   candidate offsets we synthesise here track values, not keys. The user can still trigger
     *   the regular AI Active Scan if they need full coverage of the field.
     * - The caller is expected to validate scope / queue capacity at queue time
     *   ([com.six2dez.burp.aiagent.scanner.ActiveAiScanner.manualScanInsertionPoint]).
     */
    fun matchInsertionPoint(
        request: HttpRequest,
        selectionStart: Int,
        selectionEnd: Int,
        headerAllowlist: Set<String> = emptySet(),
        maxFields: Int = 50,
    ): InjectionPoint? {
        if (selectionEnd <= selectionStart) return null

        // 1) Parsed parameters expose exact byte offsets — try those first.
        for (param in request.parameters()) {
            val value = param.valueOffsets() ?: continue
            if (rangesOverlap(value.startIndexInclusive(), value.endIndexExclusive(), selectionStart, selectionEnd)) {
                val type =
                    when (param.type().name) {
                        "URL" -> InjectionType.URL_PARAM
                        "BODY" -> InjectionType.BODY_PARAM
                        "COOKIE" -> InjectionType.COOKIE
                        else -> continue
                    }
                return InjectionPoint(type, param.name(), param.value(), value.startIndexInclusive())
            }
        }

        // 2) Headers — Montoya doesn't expose offsets, so we walk the raw request bytes ourselves.
        val raw =
            try {
                request.toByteArray()?.bytes?.toString(Charsets.UTF_8) ?: ""
            } catch (_: Exception) {
                ""
            }
        if (raw.isNotBlank()) {
            val headerMatch =
                request.headers().firstOrNull { header ->
                    if (headerAllowlist.isNotEmpty() && !headerAllowlist.contains(header.name().lowercase())) return@firstOrNull false
                    val needle = "${header.name()}: ${header.value()}"
                    val idx = raw.indexOf(needle)
                    idx >= 0 && rangesOverlap(idx, idx + needle.length, selectionStart, selectionEnd)
                }
            if (headerMatch != null) {
                return InjectionPoint(InjectionType.HEADER, headerMatch.name(), headerMatch.value())
            }
        }

        // 3) Body JSON / XML fields — match by substring of the value within the request body.
        val bodyOffset = request.bodyOffset()
        val body =
            try {
                request.bodyToString()
            } catch (_: Exception) {
                ""
            }
        if (body.isNotBlank() && selectionEnd > bodyOffset) {
            val bodySelectionStart = (selectionStart - bodyOffset).coerceAtLeast(0)
            val bodySelectionEnd = (selectionEnd - bodyOffset).coerceAtLeast(0)
            val contentType = request.headerValue("Content-Type")?.lowercase() ?: ""
            val candidates = mutableListOf<InjectionPoint>()
            if (contentType.contains("json") || body.trimStart().startsWith("{") || body.trimStart().startsWith("[")) {
                candidates.addAll(extractJsonFields(body, maxFields))
            }
            if (contentType.contains("xml") || body.trimStart().startsWith("<")) {
                candidates.addAll(extractXmlElements(body, maxFields))
            }
            val bodyMatch =
                candidates.firstOrNull { point ->
                    val needle = point.originalValue
                    if (needle.isBlank()) return@firstOrNull false
                    val idx = body.indexOf(needle)
                    idx >= 0 && rangesOverlap(idx, idx + needle.length, bodySelectionStart, bodySelectionEnd)
                }
            if (bodyMatch != null) return bodyMatch
        }

        // 4) Path segment IDs — fall back to position-tagged extraction.
        val path =
            try {
                java.net.URI(request.url()).path ?: ""
            } catch (_: Exception) {
                ""
            }
        if (path.isNotBlank()) {
            // Path lives inside the request line; raw `toString()` includes it. We re-locate it
            // and translate the in-path offset to absolute request bytes.
            val pathStart = raw.indexOf(path)
            if (pathStart >= 0) {
                pathIdPattern.findAll(path).forEach { match ->
                    val absStart = pathStart + match.range.first
                    val absEnd = pathStart + match.range.last + 1
                    if (rangesOverlap(absStart, absEnd, selectionStart, selectionEnd)) {
                        return InjectionPoint(InjectionType.PATH_SEGMENT, "path_id", match.value, match.range.first)
                    }
                }
            }
        }

        return null
    }

    private fun rangesOverlap(
        aStart: Int,
        aEnd: Int,
        bStart: Int,
        bEnd: Int,
    ): Boolean = aStart < bEnd && bStart < aEnd
}
