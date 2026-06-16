package com.six2dez.burp.aiagent.scanner

import burp.api.montoya.http.message.requests.HttpRequest
import burp.api.montoya.http.message.responses.HttpResponse

// AWT-free contract: MUST NOT import java.awt.* or javax.swing.*

private const val LOCAL_FINDING_SKIP_CONFIDENCE = 90
private const val REQUEST_BODY_LOCAL_CHECK_MAX_CHARS = 3_000
private const val RESPONSE_BODY_LOCAL_CHECK_MAX_CHARS = 6_000

private val SERIALIZED_NAME_REGEX = Regex("(data|payload|serialized|object|state|viewstate)", RegexOption.IGNORE_CASE)

private val csrfTokenRegex =
    Regex(
        "(csrf|xsrf|anti_csrf|csrfmiddlewaretoken|__requestverificationtoken|token)",
        RegexOption.IGNORE_CASE,
    )

private val dangerousUploadExtensions =
    setOf(
        "php",
        "phtml",
        "php5",
        "asp",
        "aspx",
        "jsp",
        "jspx",
        "cgi",
        "pl",
        "py",
        "rb",
        "jar",
        "war",
        "ear",
        "exe",
        "dll",
    )

private val authHeaderNames =
    setOf(
        "authorization",
        "x-api-key",
        "x-auth-token",
        "x-access-token",
    )

internal val authCookieHint = Regex("(session|auth|token|sid|jwt|remember)", RegexOption.IGNORE_CASE)

internal fun runLocalChecks(
    request: HttpRequest,
    response: HttpResponse?,
    requestBody: String,
    responseBody: String,
): List<LocalFinding> {
    val findings = mutableListOf<LocalFinding>()
    detectRequestSmuggling(request)?.let { findings.add(it) }
    detectCsrf(request, response)?.let { findings.add(it) }
    detectDeserialization(request, requestBody)?.let { findings.add(it) }
    detectUnrestrictedFileUpload(request, response, requestBody, responseBody)?.let { findings.add(it) }
    return findings
}

private fun detectRequestSmuggling(request: HttpRequest): LocalFinding? {
    val headers = request.headers()
    val contentLengths = headers.filter { it.name().equals("Content-Length", ignoreCase = true) }
    val transferEncodings = headers.filter { it.name().equals("Transfer-Encoding", ignoreCase = true) }
    val distinctCl = contentLengths.map { it.value().trim() }.distinct()
    val hasClTe = transferEncodings.any { it.value().contains("chunked", ignoreCase = true) } && contentLengths.isNotEmpty()
    val hasDuplicateCl = contentLengths.size > 1 && distinctCl.size > 1

    if (!hasClTe && !hasDuplicateCl) return null

    val detail =
        buildString {
            appendLine("Potential request smuggling conditions detected in request headers.")
            if (hasClTe) {
                appendLine("Content-Length present with Transfer-Encoding: chunked.")
            }
            if (hasDuplicateCl) {
                appendLine("Multiple Content-Length headers with different values: ${distinctCl.joinToString(", ")}.")
            }
        }.trim()

    return LocalFinding(
        title = "HTTP Request Smuggling Indicators",
        severity = "Medium",
        detail = detail,
        confidence = 90,
    )
}

private fun detectCsrf(
    request: HttpRequest,
    response: HttpResponse?,
): LocalFinding? {
    val method = request.method().uppercase()
    if (method !in setOf("POST", "PUT", "PATCH", "DELETE")) return null

    val hasAuthHeader = request.headers().any { authHeaderNames.contains(it.name().lowercase()) }
    val cookieHeader = request.headerValue("Cookie") ?: ""
    if (hasAuthHeader || cookieHeader.isBlank()) return null
    if (!authCookieHint.containsMatchIn(cookieHeader)) return null

    val hasTokenParam = request.parameters().any { csrfTokenRegex.containsMatchIn(it.name()) }
    val hasTokenHeader = request.headers().any { csrfTokenRegex.containsMatchIn(it.name()) }
    if (hasTokenParam || hasTokenHeader) return null

    val origin = request.headerValue("Origin")
    val referer = request.headerValue("Referer")
    if (!origin.isNullOrBlank() || !referer.isNullOrBlank()) return null

    val sameSiteSecure =
        response
            ?.headers()
            ?.filter { it.name().equals("Set-Cookie", ignoreCase = true) }
            ?.any { header ->
                val value = header.value()
                authCookieHint.containsMatchIn(value) &&
                    value.contains("samesite", ignoreCase = true) &&
                    (value.contains("strict", ignoreCase = true) || value.contains("lax", ignoreCase = true))
            } ?: false
    if (sameSiteSecure) return null

    return LocalFinding(
        title = "Potential CSRF (Missing Token)",
        severity = "Low",
        detail = "State-changing request with cookie-based auth and no CSRF token; Origin/Referer not present; SameSite not strict.",
        confidence = 85,
    )
}

private fun detectDeserialization(
    request: HttpRequest,
    requestBody: String,
): LocalFinding? {
    val serializedParam =
        request.parameters().firstOrNull { param ->
            val nameMatch =
                SERIALIZED_NAME_REGEX
                    .containsMatchIn(param.name())
            val value = param.value()
            if (!nameMatch || value.length < 100) return@firstOrNull false
            value.startsWith("rO0AB") ||
                value.contains("aced0005", ignoreCase = true)
        }

    val contentType = request.headerValue("Content-Type") ?: ""
    val bodyMatch =
        (
            contentType.contains("java-serialized", ignoreCase = true) ||
                contentType.contains("octet-stream", ignoreCase = true)
        ) &&
            (requestBody.contains("rO0AB") || requestBody.contains("aced0005", ignoreCase = true))

    if (serializedParam == null && !bodyMatch) return null

    return LocalFinding(
        title = "Deserialization Surface Detected",
        severity = "Information",
        detail = "Serialized data detected in request (potential deserialization sink).",
        confidence = 90,
    )
}

private fun detectUnrestrictedFileUpload(
    request: HttpRequest,
    response: HttpResponse?,
    requestBody: String,
    responseBody: String,
): LocalFinding? {
    val contentType = request.headerValue("Content-Type") ?: return null
    if (!contentType.contains("multipart/form-data", ignoreCase = true)) return null

    val filenameMatch = Regex("filename=\"([^\"]+)\"").find(requestBody) ?: return null
    val filename = filenameMatch.groupValues[1]
    val ext = filename.substringAfterLast('.', "")
    if (ext.isBlank() || !dangerousUploadExtensions.contains(ext.lowercase())) return null

    val status = response?.statusCode() ?: 0
    if (status !in 200..299) return null

    val location =
        response
            ?.headers()
            ?.firstOrNull { it.name().equals("Location", ignoreCase = true) }
            ?.value()
            ?.lowercase()
            ?: ""
    val bodyLower = responseBody.lowercase()
    if (!location.contains(filename.lowercase()) && !bodyLower.contains(filename.lowercase())) return null

    return LocalFinding(
        title = "Unrestricted File Upload (Executable Extension)",
        severity = "Medium",
        detail = "Upload accepted for '$filename' and response references the uploaded filename.",
        confidence = 90,
    )
}
