package com.six2dez.burp.aiagent.mcp.tools

import burp.api.montoya.MontoyaApi
import burp.api.montoya.burpsuite.TaskExecutionEngine.TaskExecutionEngineState.PAUSED
import burp.api.montoya.burpsuite.TaskExecutionEngine.TaskExecutionEngineState.RUNNING
import burp.api.montoya.core.BurpSuiteEdition
import burp.api.montoya.core.Range
import burp.api.montoya.http.HttpMode
import burp.api.montoya.http.RequestOptions
import burp.api.montoya.http.message.HttpHeader
import burp.api.montoya.http.message.requests.HttpRequest
import burp.api.montoya.intruder.HttpRequestTemplate
import burp.api.montoya.intruder.HttpRequestTemplateGenerationOptions
import burp.api.montoya.scanner.AuditConfiguration
import burp.api.montoya.scanner.BuiltInAuditConfiguration
import burp.api.montoya.scanner.ReportFormat
import burp.api.montoya.scanner.audit.Audit
import burp.api.montoya.utilities.CompressionType
import com.six2dez.burp.aiagent.mcp.McpToolContext
import com.six2dez.burp.aiagent.mcp.schema.toSerializableForm
import com.six2dez.burp.aiagent.mcp.schema.toSiteMapEntry
import com.six2dez.burp.aiagent.redact.PrivacyMode
import com.six2dez.burp.aiagent.redact.Redaction
import com.six2dez.burp.aiagent.util.IssueText
import com.six2dez.burp.aiagent.util.IssueUtils
import io.modelcontextprotocol.kotlin.sdk.server.Server
import kotlinx.serialization.encodeToString
import java.security.MessageDigest
import java.util.Base64
import java.util.regex.Pattern

@Suppress("UNUSED_PARAMETER")
fun Server.registerTools(
    api: MontoyaApi,
    context: McpToolContext,
) {
    registerUtilityTools(context)
    registerHistoryTools(context)
    registerSiteMapTools(context)
    registerRequestTools(context)
    registerScannerTools(context)
    registerConfigTools(context)
    registerEditorTools(context)
    registerCollaboratorTools(context)
    registerIssueTools(context)
    registerAiTools(context)
}

@Suppress("unused")
private fun Server.registerToolsLegacy(
    api: MontoyaApi,
    context: McpToolContext,
) {
    mcpTool("status", "Returns basic extension and Burp version status.", context) {
        val version = api.burpSuite().version()
        buildString {
            appendLine("extension=burp-ai-agent")
            appendLine("burp_version=${version.name()}")
            appendLine("burp_edition=${version.edition().name}")
        }.trim()
    }

    mcpTool<SendHttp1Request>(
        "Issues an HTTP/1.1 request and returns the response.",
        context,
        toolName = "http1_request",
    ) {
        api.logging().logToOutput("MCP HTTP/1.1 request: ${context.resolveHost(targetHostname)}:$targetPort")
        val fixedContent = normalizeHttpRequest(content)
        val request = HttpRequest.httpRequest(toMontoyaService(context::resolveHost), fixedContent)
        val response = api.http().sendRequest(request, RequestOptions.requestOptions().withUpstreamTLSVerification())
        response?.toString() ?: "<no response>"
    }

    mcpTool<SendHttp2Request>(
        "Issues an HTTP/2 request and returns the response. Do NOT pass headers to the body parameter.",
        context,
        toolName = "http2_request",
    ) {
        api.logging().logToOutput("MCP HTTP/2 request: ${context.resolveHost(targetHostname)}:$targetPort")

        val orderedPseudoHeaderNames = listOf(":scheme", ":method", ":path", ":authority")
        val fixedPseudoHeaders =
            LinkedHashMap<String, String>().apply {
                orderedPseudoHeaderNames.forEach { name ->
                    val value = pseudoHeaders[name.removePrefix(":")] ?: pseudoHeaders[name]
                    if (value != null) put(name, value)
                }
                pseudoHeaders.forEach { (key, value) ->
                    val properKey = if (key.startsWith(":")) key else ":$key"
                    if (!containsKey(properKey)) {
                        put(properKey, value)
                    }
                }
            }

        val headerList = (fixedPseudoHeaders + headers).map { HttpHeader.httpHeader(it.key.lowercase(), it.value) }
        val request = HttpRequest.http2Request(toMontoyaService(context::resolveHost), headerList, requestBody)
        val response =
            api.http().sendRequest(
                request,
                RequestOptions.requestOptions().withUpstreamTLSVerification().withHttpMode(HttpMode.HTTP_2),
            )

        response?.toString() ?: "<no response>"
    }

    mcpTool<CreateRepeaterTab>(
        "Creates a new Repeater tab with the specified HTTP request and optional tab name. Make sure to use carriage returns appropriately.",
        context,
        toolName = "repeater_tab",
    ) {
        val request = HttpRequest.httpRequest(toMontoyaService(context::resolveHost), content)
        api.repeater().sendToRepeater(request, tabName)
    }

    mcpTool<RepeaterTabWithPayload>(
        "Creates a Repeater tab after applying placeholder replacements to the request.",
        context,
        toolName = "repeater_tab_with_payload",
    ) {
        val rendered = applyReplacements(content, replacements)
        val request = HttpRequest.httpRequest(toMontoyaService(context::resolveHost), rendered)
        api.repeater().sendToRepeater(request, tabName)
    }

    mcpTool<SendToIntruder>(
        "Sends an HTTP request to Intruder with the specified HTTP request and optional tab name. Make sure to use carriage returns appropriately.",
        context,
        toolName = "intruder",
    ) {
        val request = HttpRequest.httpRequest(toMontoyaService(context::resolveHost), content)
        api.intruder().sendToIntruder(request, tabName)
    }

    mcpTool<IntruderPrepare>(
        "Creates an Intruder tab with explicit insertion points.",
        context,
        toolName = "intruder_prepare",
    ) {
        val fixed = content.replace("\r", "").replace("\n", "\r\n")
        val byteArray =
            burp.api.montoya.core.ByteArray
                .byteArray(fixed)
        val template =
            if (insertionPoints.isNotEmpty()) {
                val ranges = insertionPoints.map { Range.range(it.start, it.end) }
                HttpRequestTemplate.httpRequestTemplate(byteArray, ranges)
            } else {
                val option = HttpRequestTemplateGenerationOptions.valueOf(mode.trim().uppercase())
                HttpRequestTemplate.httpRequestTemplate(byteArray, option)
            }
        api.intruder().sendToIntruder(toMontoyaService(context::resolveHost), template, tabName)
        "Intruder tab created"
    }
    mcpTool<InsertionPoints>(
        "Lists insertion point offsets for a request.",
        context,
        toolName = "insertion_points",
    ) {
        val request = HttpRequest.httpRequest(content)
        val option = HttpRequestTemplateGenerationOptions.valueOf(mode.trim().uppercase())
        val template = HttpRequestTemplate.httpRequestTemplate(request, option)
        template.insertionPointOffsets().joinToString(separator = "\n") { range ->
            "start=${range.startIndexInclusive()} end=${range.endIndexExclusive()}"
        }
    }

    mcpTool<ExtractParams>(
        "Extracts parameters from a request.",
        context,
        toolName = "params_extract",
    ) {
        val request = HttpRequest.httpRequest(content)
        request.parameters().joinToString(separator = "\n") { param ->
            "type=${param.type()} name=${param.name()} value=${param.value()}"
        }
    }

    mcpTool<DiffRequests>(
        "Produces a line diff between two requests.",
        context,
        toolName = "diff_requests",
    ) {
        diffLines(requestA, requestB)
    }

    mcpTool<RequestParse>(
        "Parses a raw HTTP request into method, path, headers, parameters, and body.",
        context,
        toolName = "request_parse",
    ) {
        val request = HttpRequest.httpRequest(content)
        val parsed =
            ParsedRequest(
                method = request.method(),
                path = request.path(),
                url = maybeAnonymizeUrl(request.url(), context),
                headers = sanitizeHeaders(request.headers(), context),
                parameters =
                    request.parameters().map { param ->
                        ParsedParam(type = param.type().name, name = param.name(), value = param.value())
                    },
                body = if (includeBody) request.bodyToString() else null,
                bodyLength = request.body().length(),
            )
        toolJson.encodeToString(parsed)
    }

    mcpTool<ResponseParse>(
        "Parses a raw HTTP response into status, headers, and body.",
        context,
        toolName = "response_parse",
    ) {
        val response =
            burp.api.montoya.http.message.responses.HttpResponse
                .httpResponse(content)
        val parsed =
            ParsedResponse(
                statusCode = response.statusCode().toInt(),
                headers = sanitizeHeaders(response.headers(), context),
                body = if (includeBody) response.bodyToString() else null,
                bodyLength = response.body().length(),
            )
        toolJson.encodeToString(parsed)
    }

    mcpTool<FindReflected>(
        "Finds reflected parameter values in a response.",
        context,
        toolName = "find_reflected",
    ) {
        val request = HttpRequest.httpRequest(request)
        val responseText = response
        val hits =
            request.parameters().mapNotNull { param ->
                val value = param.value()
                if (value.isBlank()) return@mapNotNull null
                val count = countOccurrences(responseText, value)
                if (count > 0) "name=${param.name()} type=${param.type()} count=$count" else null
            }
        if (hits.isEmpty()) "No reflections found" else hits.joinToString(separator = "\n")
    }

    mcpTool<ComparerSend>(
        "Sends one or more items to Burp Comparer.",
        context,
        toolName = "comparer_send",
    ) {
        val byteArrays =
            items.map {
                burp.api.montoya.core.ByteArray
                    .byteArray(it)
            }
        api.comparer().sendToComparer(*byteArrays.toTypedArray())
        "Sent ${items.size} item(s) to Comparer"
    }

    mcpTool<UrlEncode>("URL encodes the input string", context, toolName = "url_encode") {
        api.utilities().urlUtils().encode(content)
    }

    mcpTool<UrlDecode>("URL decodes the input string", context, toolName = "url_decode") {
        api.utilities().urlUtils().decode(content)
    }

    mcpTool<Base64Encode>("Base64 encodes the input string", context, toolName = "base64_encode") {
        api.utilities().base64Utils().encodeToString(content)
    }

    mcpTool<Base64Decode>("Base64 decodes the input string", context, toolName = "base64_decode") {
        api
            .utilities()
            .base64Utils()
            .decode(content)
            .toString()
    }

    mcpTool<GenerateRandomString>(
        "Generates a random string of specified length and character set",
        context,
        toolName = "random_string",
    ) {
        api.utilities().randomUtils().randomString(length, characterSet)
    }

    mcpTool<HashCompute>(
        "Computes a hash for input text (MD5/SHA1/SHA256/SHA512).",
        context,
        toolName = "hash_compute",
    ) {
        val algo = normalizeHashAlgorithm(algorithm)
        val digest = MessageDigest.getInstance(algo)
        val bytes = digest.digest(content.toByteArray(Charsets.UTF_8))
        bytes.joinToString("") { "%02x".format(it) }
    }

    mcpTool<JwtDecode>(
        "Decodes JWT header/payload without verifying the signature.",
        context,
        toolName = "jwt_decode",
    ) {
        decodeJwt(token)
    }

    mcpTool<DecodeAs>(
        "Decodes base64 content using compression codecs (gzip/deflate/brotli).",
        context,
        toolName = "decode_as",
    ) {
        val decoded = api.utilities().base64Utils().decode(base64)
        val codec = encoding.trim().uppercase()
        if (codec == "IDENTITY" || codec == "RAW") {
            decoded.toString()
        } else {
            val type = CompressionType.valueOf(codec)
            api
                .utilities()
                .compressionUtils()
                .decompress(decoded, type)
                .toString()
        }
    }

    mcpTool<CookieJarGet>(
        "Returns cookies from Burp's cookie jar. Values are redacted unless privacy mode is OFF.",
        context,
        toolName = "cookie_jar_get",
    ) {
        val cookies = api.http().cookieJar().cookies()
        val domainFilter =
            domain
                ?.trim()
                .orEmpty()
                .removePrefix(".")
                .lowercase()
                .ifBlank { null }
        val results =
            cookies
                .asSequence()
                .filter { cookie ->
                    if (domainFilter == null) return@filter true
                    val cookieDomain = cookie.domain().removePrefix(".").lowercase()
                    if (includeSubdomains) {
                        cookieDomain == domainFilter || cookieDomain.endsWith(".$domainFilter")
                    } else {
                        cookieDomain == domainFilter
                    }
                }.filter { cookie ->
                    if (!scopeOnly) return@filter true
                    val cookieDomain = cookie.domain().removePrefix(".")
                    val httpUrl = "http://$cookieDomain/"
                    val httpsUrl = "https://$cookieDomain/"
                    api.scope().isInScope(httpUrl) || api.scope().isInScope(httpsUrl)
                }.map { cookie ->
                    val rawDomain = cookie.domain()
                    val safeDomain =
                        if (context.privacyMode == com.six2dez.burp.aiagent.redact.PrivacyMode.STRICT) {
                            Redaction.anonymizeHost(rawDomain.removePrefix("."), context.hostSalt)
                        } else {
                            rawDomain
                        }
                    val value =
                        if (includeValues && context.privacyMode == com.six2dez.burp.aiagent.redact.PrivacyMode.OFF) {
                            cookie.value()
                        } else {
                            "[REDACTED]"
                        }
                    CookieEntry(
                        name = cookie.name(),
                        value = value,
                        domain = safeDomain,
                        path = cookie.path(),
                        expiresAt = cookie.expiration().map { it.toString() }.orElse(null),
                    )
                }.toList()
        toolJson.encodeToString(results)
    }

    mcpTool(
        "project_options_get",
        "Outputs current project-level configuration in JSON format. You can use this to determine the schema for available config options.",
        context,
    ) {
        api.burpSuite().exportProjectOptionsAsJson()
    }

    mcpTool(
        "user_options_get",
        "Outputs current user-level configuration in JSON format. You can use this to determine the schema for available config options.",
        context,
    ) {
        api.burpSuite().exportUserOptionsAsJson()
    }

    mcpTool<SetProjectOptions>(
        "Sets project-level configuration in JSON format. This will be merged with existing configuration. Make sure to export before doing this, so you know what the schema is. Make sure the JSON has a top level 'user_options' object!",
        context,
        toolName = "project_options_set",
    ) {
        api.logging().logToOutput("Setting project-level configuration via MCP.")
        api.burpSuite().importProjectOptionsFromJson(json)
        "Project configuration has been applied"
    }

    mcpTool<SetUserOptions>(
        "Sets user-level configuration in JSON format. This will be merged with existing configuration. Make sure to export before doing this, so you know what the schema is. Make sure the JSON has a top level 'project_options' object!",
        context,
        toolName = "user_options_set",
    ) {
        api.logging().logToOutput("Setting user-level configuration via MCP.")
        api.burpSuite().importUserOptionsFromJson(json)
        "User configuration has been applied"
    }

    mcpTool<CollaboratorGenerate>(
        "Generates a Burp Collaborator payload.",
        context,
        toolName = "collaborator_generate",
    ) {
        val client = api.collaborator().createClient()
        val opts =
            options
                .mapNotNull { opt ->
                    runCatching {
                        burp.api.montoya.collaborator.PayloadOption
                            .valueOf(opt.trim().uppercase())
                    }.getOrNull()
                }.toTypedArray()
        val payload =
            if (customData.isNullOrBlank()) {
                client.generatePayload(*opts)
            } else {
                client.generatePayload(customData.trim(), *opts)
            }
        val secretKey = client.getSecretKey().toString()
        CollaboratorRegistry.put(secretKey, client)
        buildString {
            appendLine("payload=$payload")
            appendLine("interaction_id=${payload.id()}")
            appendLine("secret_key=$secretKey")
        }.trim()
    }

    mcpTool<CollaboratorPoll>(
        "Fetches interactions for a Collaborator secret key.",
        context,
        toolName = "collaborator_poll",
    ) {
        val key = secretKey.trim()
        val client =
            CollaboratorRegistry.get(key)
                ?: api.collaborator().restoreClient(
                    burp.api.montoya.collaborator.SecretKey
                        .secretKey(key),
                )
        val interactions = client.getAllInteractions()
        if (interactions.isEmpty()) return@mcpTool "No interactions"
        interactions.joinToString(separator = "\n\n") { interaction ->
            buildString {
                appendLine("id=${interaction.id()}")
                appendLine("type=${interaction.type()}")
                appendLine("time=${interaction.timeStamp()}")
                appendLine("client_ip=${interaction.clientIp().hostAddress}")
                appendLine("client_port=${interaction.clientPort()}")
                interaction.customData().ifPresent { appendLine("custom_data=$it") }
                interaction.dnsDetails().ifPresent { dns ->
                    appendLine("dns_type=${dns.queryType()}")
                    appendLine("dns_query=${dns.query()}")
                }
                if (includeHttp) {
                    interaction.httpDetails().ifPresent { http ->
                        val rr = http.requestResponse()
                        appendLine("http_request=${rr.request()?.toString().orEmpty()}")
                        appendLine("http_response=${rr.response()?.toString().orEmpty()}")
                    }
                }
                interaction.smtpDetails().ifPresent { smtp ->
                    appendLine("smtp=$smtp")
                }
            }.trim()
        }
    }

    if (context.edition == BurpSuiteEdition.PROFESSIONAL) {
        mcpPaginatedTool<GetScannerIssues>(
            "Displays information about issues identified by the scanner",
            context,
            toolName = "scanner_issues",
        ) {
            api
                .siteMap()
                .issues()
                .asSequence()
                .map { toolJson.encodeToString(it.toSerializableForm()) }
        }

        mcpTool<StartAudit>(
            "Starts a Burp Scanner audit using a built-in configuration",
            context,
            toolName = "scan_audit_start",
        ) {
            val cfg =
                AuditConfiguration.auditConfiguration(
                    BuiltInAuditConfiguration.valueOf(builtInConfiguration),
                )
            val audit = api.scanner().startAudit(cfg)
            val id = ScannerTaskRegistry.put(audit)
            "Started audit: id=$id status=${audit.statusMessage()}"
        }

        mcpTool<StartAuditMode>(
            "Starts a Burp Scanner audit in active or passive mode",
            context,
            toolName = "scan_audit_start_mode",
        ) {
            val cfg = AuditConfiguration.auditConfiguration(resolveAuditConfig(mode))
            val audit = api.scanner().startAudit(cfg)
            val service = toMontoyaServiceOrNull(context::resolveHost)
            if (requests.isNotEmpty() && service == null) {
                return@mcpTool "Error: targetHostname/targetPort required when providing requests"
            }
            for (raw in requests) {
                val fixed = raw.replace("\r", "").replace("\n", "\r\n")
                val req = HttpRequest.httpRequest(service ?: toMontoyaService(context::resolveHost), fixed)
                audit.addRequest(req)
            }
            val id = ScannerTaskRegistry.put(audit)
            if (requests.isEmpty()) {
                "Started audit: id=$id status=${audit.statusMessage()}"
            } else {
                "Started audit with requests: id=$id status=${audit.statusMessage()}"
            }
        }

        mcpTool<StartAuditWithRequests>(
            "Starts an audit and adds provided HTTP requests to it",
            context,
            toolName = "scan_audit_start_requests",
        ) {
            val cfg =
                AuditConfiguration.auditConfiguration(
                    BuiltInAuditConfiguration.valueOf(builtInConfiguration),
                )
            val audit = api.scanner().startAudit(cfg)
            val service = toMontoyaService(context::resolveHost)

            for (raw in requests) {
                val fixed = raw.replace("\r", "").replace("\n", "\r\n")
                val req = HttpRequest.httpRequest(service, fixed)
                audit.addRequest(req)
            }

            val id = ScannerTaskRegistry.put(audit)
            "Started audit with requests: id=$id status=${audit.statusMessage()}"
        }

        mcpTool<StartCrawl>(
            "Starts a Burp Scanner crawl with seed URLs",
            context,
            toolName = "scan_crawl_start",
        ) {
            val crawl =
                api.scanner().startCrawl(
                    burp.api.montoya.scanner.CrawlConfiguration
                        .crawlConfiguration(*seedUrls.toTypedArray()),
                )
            val id = ScannerTaskRegistry.put(crawl)
            "Started crawl: id=$id status=${crawl.statusMessage()}"
        }

        mcpTool<GetScanTaskStatus>(
            "Gets status for a crawl/audit task started via MCP",
            context,
            toolName = "scan_task_status",
        ) {
            val task = ScannerTaskRegistry.get(taskId) ?: return@mcpTool "Task not found: $taskId"
            val base = "status=${task.statusMessage()} requests=${task.requestCount()} errors=${task.errorCount()}"
            val audit = (task as? Audit)
            if (audit != null) {
                val count = audit.issues().size
                "$base issues=$count"
            } else {
                base
            }
        }

        mcpTool<DeleteScanTask>(
            "Deletes a crawl/audit task started via MCP",
            context,
            toolName = "scan_task_delete",
        ) {
            val task = ScannerTaskRegistry.remove(taskId) ?: return@mcpTool "Task not found: $taskId"
            task.delete()
            "Deleted task: $taskId"
        }

        mcpTool<GenerateScannerReport>(
            "Generates a scanner report for a task or all issues to a path",
            context,
            toolName = "scan_report",
        ) {
            val formatEnum = ReportFormat.valueOf(format)
            val pathObj =
                try {
                    resolveReportPath(path)
                } catch (e: IllegalArgumentException) {
                    return@mcpTool "Error: ${e.message}"
                }

            val issues =
                when {
                    taskId != null -> {
                        val task = ScannerTaskRegistry.get(taskId)
                        val audit = task as? Audit ?: return@mcpTool "Task not found or not an audit: $taskId"
                        audit.issues()
                    }
                    allIssues -> api.siteMap().issues()
                    else -> return@mcpTool "Provide taskId or set allIssues=true"
                }

            api.scanner().generateReport(issues, formatEnum, pathObj)
            "Report generated: $path"
        }
    }

    mcpPaginatedTool<GetProxyHttpHistory>(
        "Displays items within the proxy HTTP history",
        context,
        toolName = "proxy_http_history",
    ) {
        ensureAllowedProxyHistoryCount(count, context.proxyHistoryMaxItemsPerRequest)
        val includeRaw = context.allowUnpreprocessedProxyHistory && includeUnpreprocessedResponse
        val items = api.proxy().history()
        val seq =
            orderedProxyHistory(items, context) { it.request()?.toString().orEmpty() }
                .let { s -> if (listenerPort != null) s.filter { it.listenerPort() == listenerPort } else s }
        val preprocess =
            context.responsePreprocessorSettings().copy(
                preprocessProxyHistory = !includeRaw,
            )
        seq.map { truncateIfNeeded(toolJson.encodeToString(it.toSerializableForm(preprocess)), context.maxBodyBytes) }
    }

    mcpPaginatedTool<GetProxyHttpHistoryRegex>(
        "Displays items matching a specified regex within the proxy HTTP history",
        context,
        toolName = "proxy_http_history_regex",
    ) {
        ensureAllowedProxyHistoryCount(count, context.proxyHistoryMaxItemsPerRequest)
        val includeRaw = context.allowUnpreprocessedProxyHistory && includeUnpreprocessedResponse
        val compiledRegex = Pattern.compile(regex)
        val items = api.proxy().history { it.contains(compiledRegex) }
        val seq = orderedProxyHistory(items, context) { it.request()?.toString().orEmpty() }
        val preprocess =
            context.responsePreprocessorSettings().copy(
                preprocessProxyHistory = !includeRaw,
            )
        seq.map { truncateIfNeeded(toolJson.encodeToString(it.toSerializableForm(preprocess)), context.maxBodyBytes) }
    }

    mcpTool<ProxyHistoryAnnotate>(
        "Adds notes and optional highlight color to proxy history items matching a regex.",
        context,
        toolName = "proxy_history_annotate",
    ) {
        val compiledRegex = Pattern.compile(regex)
        val items = api.proxy().history { it.contains(compiledRegex) }
        val highlightColor = parseHighlightColor(highlight)
        val limitValue = limit.coerceAtLeast(1).coerceAtMost(500)
        val annotated = mutableListOf<String>()
        for (item in items) {
            val url = item.request()?.url() ?: continue
            if (scopeOnly && !api.scope().isInScope(url)) continue
            if (note.isNotBlank()) {
                item.annotations().setNotes(note)
            }
            if (highlightColor != null) {
                item.annotations().setHighlightColor(highlightColor)
            }
            annotated.add(maybeAnonymizeUrl(url, context))
            if (annotated.size >= limitValue) break
        }
        if (annotated.isEmpty()) {
            "No matching proxy history items"
        } else {
            buildString {
                appendLine("Annotated ${annotated.size} item(s):")
                annotated.forEach { appendLine("url=$it") }
            }.trim()
        }
    }

    mcpTool<ResponseBodySearch>(
        "Searches response bodies in proxy history for a regex and returns matches.",
        context,
        toolName = "response_body_search",
    ) {
        val compiledRegex = Pattern.compile(regex)
        val matches = mutableListOf<String>()
        api.proxy().history().forEach { item ->
            val url = item.request()?.url() ?: return@forEach
            if (scopeOnly && !api.scope().isInScope(url)) return@forEach
            val response = item.response()?.toString().orEmpty()
            if (response.isBlank()) return@forEach
            val body = response.substringAfter("\r\n\r\n", "")
            val matcher = compiledRegex.matcher(body)
            var count = 0
            while (matcher.find()) count++
            if (count > 0) {
                val safeUrl = maybeAnonymizeUrl(url, context)
                matches.add("url=$safeUrl matches=$count response_bytes=${body.toByteArray(Charsets.UTF_8).size}")
            }
        }
        val sorted = if (context.determinismMode) matches.sorted() else matches
        val slice = sorted.drop(offset.coerceAtLeast(0)).take(count.coerceAtLeast(1))
        if (slice.isEmpty()) "No matches found" else slice.joinToString(separator = "\n")
    }

    mcpPaginatedTool<GetProxyWebsocketHistory>(
        "Displays items within the proxy WebSocket history",
        context,
        toolName = "proxy_ws_history",
    ) {
        val items = api.proxy().webSocketHistory()
        val seq =
            if (context.determinismMode) {
                items.sortedBy { it.payload()?.toString().orEmpty() }.asSequence()
            } else {
                items.asSequence()
            }
        seq.map { truncateIfNeeded(toolJson.encodeToString(it.toSerializableForm()), context.maxBodyBytes) }
    }

    mcpPaginatedTool<GetProxyWebsocketHistoryRegex>(
        "Displays items matching a specified regex within the proxy WebSocket history",
        context,
        toolName = "proxy_ws_history_regex",
    ) {
        val compiledRegex = Pattern.compile(regex)
        val items = api.proxy().webSocketHistory { it.contains(compiledRegex) }
        val seq =
            if (context.determinismMode) {
                items.sortedBy { it.payload()?.toString().orEmpty() }.asSequence()
            } else {
                items.asSequence()
            }
        seq.map { truncateIfNeeded(toolJson.encodeToString(it.toSerializableForm()), context.maxBodyBytes) }
    }

    mcpPaginatedTool<GetSiteMap>(
        "Displays items within the Burp site map",
        context,
        toolName = "site_map",
    ) {
        val items = api.siteMap().requestResponses()
        val seq =
            if (context.determinismMode) {
                items.sortedBy { it.request()?.url().orEmpty() }.asSequence()
            } else {
                items.asSequence()
            }
        seq.map { truncateIfNeeded(toolJson.encodeToString(it.toSiteMapEntry()), context.maxBodyBytes) }
    }

    mcpPaginatedTool<GetSiteMapRegex>(
        "Displays site map items matching a regex",
        context,
        toolName = "site_map_regex",
    ) {
        val compiledRegex = Pattern.compile(regex)
        val filter =
            burp.api.montoya.sitemap.SiteMapFilter { node ->
                compiledRegex.matcher(node.url()).find()
            }
        val items = api.siteMap().requestResponses(filter)
        val seq =
            if (context.determinismMode) {
                items.sortedBy { it.request()?.url().orEmpty() }.asSequence()
            } else {
                items.asSequence()
            }
        seq.map { truncateIfNeeded(toolJson.encodeToString(it.toSiteMapEntry()), context.maxBodyBytes) }
    }

    mcpTool<ScopeCheck>(
        "Checks whether a URL is in scope.",
        context,
        toolName = "scope_check",
    ) {
        val inScope = api.scope().isInScope(url)
        "in_scope=$inScope"
    }

    mcpTool<ScopeUpdate>(
        "Includes a URL in scope.",
        context,
        toolName = "scope_include",
    ) {
        api.scope().includeInScope(url)
        "Scope include applied"
    }

    mcpTool<ScopeUpdate>(
        "Excludes a URL from scope.",
        context,
        toolName = "scope_exclude",
    ) {
        api.scope().excludeFromScope(url)
        "Scope exclude applied"
    }

    mcpTool<SetTaskExecutionEngineState>(
        "Sets the state of Burp's task execution engine (paused or unpaused)",
        context,
        toolName = "task_engine_state",
    ) {
        api.burpSuite().taskExecutionEngine().state = if (running) RUNNING else PAUSED
        "Task execution engine is now ${if (running) "running" else "paused"}"
    }

    mcpTool<SetProxyInterceptState>(
        "Enables or disables Burp Proxy Intercept",
        context,
        toolName = "proxy_intercept",
    ) {
        if (intercepting) {
            api.proxy().enableIntercept()
        } else {
            api.proxy().disableIntercept()
        }
        "Intercept has been ${if (intercepting) "enabled" else "disabled"}"
    }

    mcpTool("editor_get", "Outputs the contents of the user's active message editor", context) {
        getActiveEditor(api)?.text ?: "<No active editor>"
    }

    mcpTool<SetActiveEditorContents>(
        "Sets the content of the user's active message editor",
        context,
        toolName = "editor_set",
    ) {
        val editor = getActiveEditor(api) ?: return@mcpTool "<No active editor>"
        if (!editor.isEditable) {
            return@mcpTool "<Current editor is not editable>"
        }
        editor.text = text
        "Editor text has been set"
    }

    mcpTool<CreateAuditIssue>(
        "Creates a custom audit issue in Burp's issue list. Use this to report findings discovered by AI analysis.",
        context,
        toolName = "issue_create",
    ) {
        executeIssueCreate(this, api, context)
    }
}

