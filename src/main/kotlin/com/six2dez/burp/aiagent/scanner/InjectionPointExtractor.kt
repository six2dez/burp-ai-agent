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
}
