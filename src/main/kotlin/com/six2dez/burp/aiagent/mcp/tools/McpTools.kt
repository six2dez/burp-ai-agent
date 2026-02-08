package com.six2dez.burp.aiagent.mcp.tools

import burp.api.montoya.MontoyaApi
import burp.api.montoya.burpsuite.TaskExecutionEngine.TaskExecutionEngineState.PAUSED
import burp.api.montoya.burpsuite.TaskExecutionEngine.TaskExecutionEngineState.RUNNING
import burp.api.montoya.core.HighlightColor
import burp.api.montoya.core.BurpSuiteEdition
import burp.api.montoya.core.Range
import burp.api.montoya.http.HttpMode
import burp.api.montoya.http.HttpService
import burp.api.montoya.http.message.HttpHeader
import burp.api.montoya.http.message.requests.HttpRequest
import burp.api.montoya.intruder.HttpRequestTemplate
import burp.api.montoya.intruder.HttpRequestTemplateGenerationOptions
import burp.api.montoya.scanner.AuditConfiguration
import burp.api.montoya.scanner.BuiltInAuditConfiguration
import burp.api.montoya.scanner.ReportFormat
import burp.api.montoya.scanner.audit.Audit
import burp.api.montoya.utilities.CompressionType
import com.six2dez.burp.aiagent.mcp.McpToolCatalog
import com.six2dez.burp.aiagent.mcp.McpToolContext
import com.six2dez.burp.aiagent.mcp.schema.asInputSchema
import com.six2dez.burp.aiagent.mcp.schema.toSerializableForm
import com.six2dez.burp.aiagent.mcp.schema.toSiteMapEntry
import com.six2dez.burp.aiagent.redact.Redaction
import com.six2dez.burp.aiagent.redact.RedactionPolicy
import com.six2dez.burp.aiagent.util.IssueText
import io.modelcontextprotocol.kotlin.sdk.server.Server
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.decodeFromJsonElement
import kotlinx.serialization.encodeToString
import java.security.MessageDigest
import java.awt.KeyboardFocusManager
import java.util.Base64
import java.net.URI
import java.util.regex.Pattern
import javax.swing.JTextArea

private val toolJson = Json { encodeDefaults = true }

fun Server.registerTools(api: MontoyaApi, context: McpToolContext) {
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
        toolName = "http1_request"
    ) {
        api.logging().logToOutput("MCP HTTP/1.1 request: ${context.resolveHost(targetHostname)}:$targetPort")
        val fixedContent = normalizeHttpRequest(content)
        val request = HttpRequest.httpRequest(toMontoyaService(context::resolveHost), fixedContent)
        val response = api.http().sendRequest(request)
        response?.toString() ?: "<no response>"
    }

    mcpTool<SendHttp2Request>(
        "Issues an HTTP/2 request and returns the response. Do NOT pass headers to the body parameter.",
        context,
        toolName = "http2_request"
    ) {
        api.logging().logToOutput("MCP HTTP/2 request: ${context.resolveHost(targetHostname)}:$targetPort")

        val orderedPseudoHeaderNames = listOf(":scheme", ":method", ":path", ":authority")
        val fixedPseudoHeaders = LinkedHashMap<String, String>().apply {
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
        val response = api.http().sendRequest(request, HttpMode.HTTP_2)

        response?.toString() ?: "<no response>"
    }

    mcpTool<CreateRepeaterTab>(
        "Creates a new Repeater tab with the specified HTTP request and optional tab name. Make sure to use carriage returns appropriately.",
        context,
        toolName = "repeater_tab"
    ) {
        val request = HttpRequest.httpRequest(toMontoyaService(context::resolveHost), content)
        api.repeater().sendToRepeater(request, tabName)
    }

    mcpTool<RepeaterTabWithPayload>(
        "Creates a Repeater tab after applying placeholder replacements to the request.",
        context,
        toolName = "repeater_tab_with_payload"
    ) {
        val rendered = applyReplacements(content, replacements)
        val request = HttpRequest.httpRequest(toMontoyaService(context::resolveHost), rendered)
        api.repeater().sendToRepeater(request, tabName)
    }

    mcpTool<SendToIntruder>(
        "Sends an HTTP request to Intruder with the specified HTTP request and optional tab name. Make sure to use carriage returns appropriately.",
        context,
        toolName = "intruder"
    ) {
        val request = HttpRequest.httpRequest(toMontoyaService(context::resolveHost), content)
        api.intruder().sendToIntruder(request, tabName)
    }

    mcpTool<IntruderPrepare>(
        "Creates an Intruder tab with explicit insertion points.",
        context,
        toolName = "intruder_prepare"
    ) {
        val fixed = content.replace("\r", "").replace("\n", "\r\n")
        val byteArray = burp.api.montoya.core.ByteArray.byteArray(fixed)
        val template = if (insertionPoints.isNotEmpty()) {
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
        toolName = "insertion_points"
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
        toolName = "params_extract"
    ) {
        val request = HttpRequest.httpRequest(content)
        request.parameters().joinToString(separator = "\n") { param ->
            "type=${param.type()} name=${param.name()} value=${param.value()}"
        }
    }

    mcpTool<DiffRequests>(
        "Produces a line diff between two requests.",
        context,
        toolName = "diff_requests"
    ) {
        diffLines(requestA, requestB)
    }

    mcpTool<RequestParse>(
        "Parses a raw HTTP request into method, path, headers, parameters, and body.",
        context,
        toolName = "request_parse"
    ) {
        val request = HttpRequest.httpRequest(content)
        val parsed = ParsedRequest(
            method = request.method(),
            path = request.path(),
            url = maybeAnonymizeUrl(request.url(), context),
            headers = sanitizeHeaders(request.headers(), context),
            parameters = request.parameters().map { param ->
                ParsedParam(type = param.type().name, name = param.name(), value = param.value())
            },
            body = if (includeBody) request.bodyToString() else null,
            bodyLength = request.body().length()
        )
        toolJson.encodeToString(parsed)
    }

    mcpTool<ResponseParse>(
        "Parses a raw HTTP response into status, headers, and body.",
        context,
        toolName = "response_parse"
    ) {
        val response = burp.api.montoya.http.message.responses.HttpResponse.httpResponse(content)
        val parsed = ParsedResponse(
            statusCode = response.statusCode().toInt(),
            headers = sanitizeHeaders(response.headers(), context),
            body = if (includeBody) response.bodyToString() else null,
            bodyLength = response.body().length()
        )
        toolJson.encodeToString(parsed)
    }

    mcpTool<FindReflected>(
        "Finds reflected parameter values in a response.",
        context,
        toolName = "find_reflected"
    ) {
        val request = HttpRequest.httpRequest(request)
        val responseText = response
        val hits = request.parameters().mapNotNull { param ->
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
        toolName = "comparer_send"
    ) {
        val byteArrays = items.map { burp.api.montoya.core.ByteArray.byteArray(it) }
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
        api.utilities().base64Utils().decode(content).toString()
    }

    mcpTool<GenerateRandomString>(
        "Generates a random string of specified length and character set",
        context,
        toolName = "random_string"
    ) {
        api.utilities().randomUtils().randomString(length, characterSet)
    }

    mcpTool<HashCompute>(
        "Computes a hash for input text (MD5/SHA1/SHA256/SHA512).",
        context,
        toolName = "hash_compute"
    ) {
        val algo = normalizeHashAlgorithm(algorithm)
        val digest = MessageDigest.getInstance(algo)
        val bytes = digest.digest(content.toByteArray(Charsets.UTF_8))
        bytes.joinToString("") { "%02x".format(it) }
    }

    mcpTool<JwtDecode>(
        "Decodes JWT header/payload without verifying the signature.",
        context,
        toolName = "jwt_decode"
    ) {
        decodeJwt(token)
    }

    mcpTool<DecodeAs>(
        "Decodes base64 content using compression codecs (gzip/deflate/brotli).",
        context,
        toolName = "decode_as"
    ) {
        val decoded = api.utilities().base64Utils().decode(base64)
        val codec = encoding.trim().uppercase()
        if (codec == "IDENTITY" || codec == "RAW") {
            decoded.toString()
        } else {
            val type = CompressionType.valueOf(codec)
            api.utilities().compressionUtils().decompress(decoded, type).toString()
        }
    }

    mcpTool<CookieJarGet>(
        "Returns cookies from Burp's cookie jar. Values are redacted unless privacy mode is OFF.",
        context,
        toolName = "cookie_jar_get"
    ) {
        val cookies = api.http().cookieJar().cookies()
        val domainFilter = domain?.trim().orEmpty().removePrefix(".").lowercase().ifBlank { null }
        val results = cookies.asSequence()
            .filter { cookie ->
                if (domainFilter == null) return@filter true
                val cookieDomain = cookie.domain().removePrefix(".").lowercase()
                if (includeSubdomains) {
                    cookieDomain == domainFilter || cookieDomain.endsWith(".$domainFilter")
                } else {
                    cookieDomain == domainFilter
                }
            }
            .filter { cookie ->
                if (!scopeOnly) return@filter true
                val cookieDomain = cookie.domain().removePrefix(".")
                val httpUrl = "http://$cookieDomain/"
                val httpsUrl = "https://$cookieDomain/"
                api.scope().isInScope(httpUrl) || api.scope().isInScope(httpsUrl)
            }
            .map { cookie ->
                val rawDomain = cookie.domain()
                val safeDomain = if (context.privacyMode == com.six2dez.burp.aiagent.redact.PrivacyMode.STRICT) {
                    Redaction.anonymizeHost(rawDomain.removePrefix("."), context.hostSalt)
                } else {
                    rawDomain
                }
                val value = if (includeValues && context.privacyMode == com.six2dez.burp.aiagent.redact.PrivacyMode.OFF) {
                    cookie.value()
                } else {
                    "[REDACTED]"
                }
                CookieEntry(
                    name = cookie.name(),
                    value = value,
                    domain = safeDomain,
                    path = cookie.path(),
                    expiresAt = cookie.expiration().map { it.toString() }.orElse(null)
                )
            }
            .toList()
        toolJson.encodeToString(results)
    }

    mcpTool(
        "project_options_get",
        "Outputs current project-level configuration in JSON format. You can use this to determine the schema for available config options.",
        context
    ) {
        api.burpSuite().exportProjectOptionsAsJson()
    }

    mcpTool(
        "user_options_get",
        "Outputs current user-level configuration in JSON format. You can use this to determine the schema for available config options.",
        context
    ) {
        api.burpSuite().exportUserOptionsAsJson()
    }

    mcpTool<SetProjectOptions>(
        "Sets project-level configuration in JSON format. This will be merged with existing configuration. Make sure to export before doing this, so you know what the schema is. Make sure the JSON has a top level 'user_options' object!",
        context,
        toolName = "project_options_set"
    ) {
        api.logging().logToOutput("Setting project-level configuration via MCP.")
        api.burpSuite().importProjectOptionsFromJson(json)
        "Project configuration has been applied"
    }

    mcpTool<SetUserOptions>(
        "Sets user-level configuration in JSON format. This will be merged with existing configuration. Make sure to export before doing this, so you know what the schema is. Make sure the JSON has a top level 'project_options' object!",
        context,
        toolName = "user_options_set"
    ) {
        api.logging().logToOutput("Setting user-level configuration via MCP.")
        api.burpSuite().importUserOptionsFromJson(json)
        "User configuration has been applied"
    }

    mcpTool<CollaboratorGenerate>(
        "Generates a Burp Collaborator payload.",
        context,
        toolName = "collaborator_generate"
    ) {
        val client = api.collaborator().createClient()
        val opts = options.mapNotNull { opt ->
            runCatching { burp.api.montoya.collaborator.PayloadOption.valueOf(opt.trim().uppercase()) }.getOrNull()
        }.toTypedArray()
        val payload = if (customData.isNullOrBlank()) {
            client.generatePayload(*opts)
        } else {
            client.generatePayload(customData.trim(), *opts)
        }
        val secretKey = client.getSecretKey().toString()
        CollaboratorRegistry.put(secretKey, client)
        buildString {
            appendLine("payload=${payload.toString()}")
            appendLine("interaction_id=${payload.id().toString()}")
            appendLine("secret_key=$secretKey")
        }.trim()
    }

    mcpTool<CollaboratorPoll>(
        "Fetches interactions for a Collaborator secret key.",
        context,
        toolName = "collaborator_poll"
    ) {
        val key = secretKey.trim()
        val client = CollaboratorRegistry.get(key)
            ?: api.collaborator().restoreClient(burp.api.montoya.collaborator.SecretKey.secretKey(key))
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
                    appendLine("dns_query=${dns.query().toString()}")
                }
                if (includeHttp) {
                    interaction.httpDetails().ifPresent { http ->
                        val rr = http.requestResponse()
                        appendLine("http_request=${rr.request()?.toString().orEmpty()}")
                        appendLine("http_response=${rr.response()?.toString().orEmpty()}")
                    }
                }
                interaction.smtpDetails().ifPresent { smtp ->
                    appendLine("smtp=${smtp.toString()}")
                }
            }.trim()
        }
    }

    if (context.edition == BurpSuiteEdition.PROFESSIONAL) {
        mcpPaginatedTool<GetScannerIssues>(
            "Displays information about issues identified by the scanner",
            context,
            toolName = "scanner_issues"
        ) {
            api.siteMap().issues().asSequence().map { toolJson.encodeToString(it.toSerializableForm()) }
        }

        mcpTool<StartAudit>(
            "Starts a Burp Scanner audit using a built-in configuration",
            context,
            toolName = "scan_audit_start"
        ) {
            val cfg = AuditConfiguration.auditConfiguration(
                BuiltInAuditConfiguration.valueOf(builtInConfiguration)
            )
            val audit = api.scanner().startAudit(cfg)
            val id = ScannerTaskRegistry.put(audit)
            "Started audit: id=$id status=${audit.statusMessage()}"
        }

        mcpTool<StartAuditMode>(
            "Starts a Burp Scanner audit in active or passive mode",
            context,
            toolName = "scan_audit_start_mode"
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
            toolName = "scan_audit_start_requests"
        ) {
            val cfg = AuditConfiguration.auditConfiguration(
                BuiltInAuditConfiguration.valueOf(builtInConfiguration)
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
            toolName = "scan_crawl_start"
        ) {
            val crawl = api.scanner().startCrawl(
                burp.api.montoya.scanner.CrawlConfiguration.crawlConfiguration(*seedUrls.toTypedArray())
            )
            val id = ScannerTaskRegistry.put(crawl)
            "Started crawl: id=$id status=${crawl.statusMessage()}"
        }

        mcpTool<GetScanTaskStatus>(
            "Gets status for a crawl/audit task started via MCP",
            context,
            toolName = "scan_task_status"
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
            toolName = "scan_task_delete"
        ) {
            val task = ScannerTaskRegistry.remove(taskId) ?: return@mcpTool "Task not found: $taskId"
            task.delete()
            "Deleted task: $taskId"
        }

        mcpTool<GenerateScannerReport>(
            "Generates a scanner report for a task or all issues to a path",
            context,
            toolName = "scan_report"
        ) {
            val formatEnum = ReportFormat.valueOf(format)
            val pathObj = try {
                resolveReportPath(path)
            } catch (e: IllegalArgumentException) {
                return@mcpTool "Error: ${e.message}"
            }

            val issues = when {
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
        toolName = "proxy_http_history"
    ) {
        val items = api.proxy().history()
        val seq = if (context.determinismMode) {
            items.sortedBy { it.request()?.toString().orEmpty() }.asSequence()
        } else {
            items.asSequence()
        }
        seq.map { truncateIfNeeded(toolJson.encodeToString(it.toSerializableForm()), context.maxBodyBytes) }
    }

    mcpPaginatedTool<GetProxyHttpHistoryRegex>(
        "Displays items matching a specified regex within the proxy HTTP history",
        context,
        toolName = "proxy_http_history_regex"
    ) {
        val compiledRegex = Pattern.compile(regex)
        val items = api.proxy().history { it.contains(compiledRegex) }
        val seq = if (context.determinismMode) {
            items.sortedBy { it.request()?.toString().orEmpty() }.asSequence()
        } else {
            items.asSequence()
        }
        seq.map { truncateIfNeeded(toolJson.encodeToString(it.toSerializableForm()), context.maxBodyBytes) }
    }

    mcpTool<ProxyHistoryAnnotate>(
        "Adds notes and optional highlight color to proxy history items matching a regex.",
        context,
        toolName = "proxy_history_annotate"
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
        toolName = "response_body_search"
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
        toolName = "proxy_ws_history"
    ) {
        val items = api.proxy().webSocketHistory()
        val seq = if (context.determinismMode) {
            items.sortedBy { it.payload()?.toString().orEmpty() }.asSequence()
        } else {
            items.asSequence()
        }
        seq.map { truncateIfNeeded(toolJson.encodeToString(it.toSerializableForm()), context.maxBodyBytes) }
    }

    mcpPaginatedTool<GetProxyWebsocketHistoryRegex>(
        "Displays items matching a specified regex within the proxy WebSocket history",
        context,
        toolName = "proxy_ws_history_regex"
    ) {
        val compiledRegex = Pattern.compile(regex)
        val items = api.proxy().webSocketHistory { it.contains(compiledRegex) }
        val seq = if (context.determinismMode) {
            items.sortedBy { it.payload()?.toString().orEmpty() }.asSequence()
        } else {
            items.asSequence()
        }
        seq.map { truncateIfNeeded(toolJson.encodeToString(it.toSerializableForm()), context.maxBodyBytes) }
    }

    mcpPaginatedTool<GetSiteMap>(
        "Displays items within the Burp site map",
        context,
        toolName = "site_map"
    ) {
        val items = api.siteMap().requestResponses()
        val seq = if (context.determinismMode) {
            items.sortedBy { it.request()?.url().orEmpty() }.asSequence()
        } else {
            items.asSequence()
        }
        seq.map { truncateIfNeeded(toolJson.encodeToString(it.toSiteMapEntry()), context.maxBodyBytes) }
    }

    mcpPaginatedTool<GetSiteMapRegex>(
        "Displays site map items matching a regex",
        context,
        toolName = "site_map_regex"
    ) {
        val compiledRegex = Pattern.compile(regex)
        val filter = burp.api.montoya.sitemap.SiteMapFilter { node ->
            compiledRegex.matcher(node.url()).find()
        }
        val items = api.siteMap().requestResponses(filter)
        val seq = if (context.determinismMode) {
            items.sortedBy { it.request()?.url().orEmpty() }.asSequence()
        } else {
            items.asSequence()
        }
        seq.map { truncateIfNeeded(toolJson.encodeToString(it.toSiteMapEntry()), context.maxBodyBytes) }
    }

    mcpTool<ScopeCheck>(
        "Checks whether a URL is in scope.",
        context,
        toolName = "scope_check"
    ) {
        val inScope = api.scope().isInScope(url)
        "in_scope=$inScope"
    }

    mcpTool<ScopeUpdate>(
        "Includes a URL in scope.",
        context,
        toolName = "scope_include"
    ) {
        api.scope().includeInScope(url)
        "Scope include applied"
    }

    mcpTool<ScopeUpdate>(
        "Excludes a URL from scope.",
        context,
        toolName = "scope_exclude"
    ) {
        api.scope().excludeFromScope(url)
        "Scope exclude applied"
    }

    mcpTool<SetTaskExecutionEngineState>(
        "Sets the state of Burp's task execution engine (paused or unpaused)",
        context,
        toolName = "task_engine_state"
    ) {
        api.burpSuite().taskExecutionEngine().state = if (running) RUNNING else PAUSED
        "Task execution engine is now ${if (running) "running" else "paused"}"
    }

    mcpTool<SetProxyInterceptState>(
        "Enables or disables Burp Proxy Intercept",
        context,
        toolName = "proxy_intercept"
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
        toolName = "editor_set"
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
        toolName = "issue_create"
    ) {
        val severityEnum = try {
            burp.api.montoya.scanner.audit.issues.AuditIssueSeverity.valueOf(severity.uppercase())
        } catch (_: Exception) {
            return@mcpTool "Invalid severity: $severity. Use: HIGH, MEDIUM, LOW, INFORMATION"
        }
        val confidenceEnum = try {
            burp.api.montoya.scanner.audit.issues.AuditIssueConfidence.valueOf(confidence.uppercase())
        } catch (_: Exception) {
            return@mcpTool "Invalid confidence: $confidence. Use: CERTAIN, FIRM, TENTATIVE"
        }
        val typicalSeverityEnum = try {
            burp.api.montoya.scanner.audit.issues.AuditIssueSeverity.valueOf((typicalSeverity ?: severity).uppercase())
        } catch (_: Exception) {
            severityEnum
        }

        val requestResponseList = if (httpRequest != null) {
            val service = toMontoyaServiceOrNull(context::resolveHost)
            if (service == null) {
                return@mcpTool "Error: targetHostname/targetPort/usesHttps required when providing httpRequest"
            }
            val fixedRequest = httpRequest.replace("\r", "").replace("\n", "\r\n")
            val request = HttpRequest.httpRequest(service, fixedRequest)
            val httpResponse = if (httpResponseContent != null) {
                val fixedResponse = httpResponseContent.replace("\r", "").replace("\n", "\r\n")
                burp.api.montoya.http.message.responses.HttpResponse.httpResponse(fixedResponse)
            } else {
                null
            }
            val rr = if (httpResponse != null) {
                burp.api.montoya.http.message.HttpRequestResponse.httpRequestResponse(request, httpResponse)
            } else {
                burp.api.montoya.http.message.HttpRequestResponse.httpRequestResponse(request, null)
            }
            listOf(rr)
        } else {
            emptyList()
        }

        val issueNameWithPrefix = if (name.startsWith("[AI]")) name else "[AI] $name"
        val sanitizedDetail = IssueText.sanitize(detail)
        val sanitizedRemediation = IssueText.sanitize(remediation ?: "")
        val sanitizedBackground = IssueText.sanitize(background ?: "")
        val sanitizedRemediationBackground = IssueText.sanitize(remediationBackground ?: "")
        
        val issue = burp.api.montoya.scanner.audit.issues.AuditIssue.auditIssue(
            issueNameWithPrefix,
            sanitizedDetail,
            sanitizedRemediation,
            baseUrl,
            severityEnum,
            confidenceEnum,
            sanitizedBackground,
            sanitizedRemediationBackground,
            typicalSeverityEnum,
            requestResponseList
        )

        api.siteMap().add(issue)
        "Issue created: $issueNameWithPrefix (Severity: $severity, Confidence: $confidence)"
    }
}

/**
 * Normalizes HTTP request line endings and updates Content-Length header.
 * 
 * When MCP clients send requests, they may use LF-only line endings which get
 * converted to CRLF. This changes the body byte length, but the original
 * Content-Length header value remains unchanged, causing the server to receive
 * a truncated body. This function recalculates Content-Length after normalization.
 */
internal fun normalizeHttpRequest(content: String): String {
    // Normalize line endings to CRLF
    val normalized = content.replace("\r\n", "\n").replace("\r", "\n").replace("\n", "\r\n")
    
    // Find the header/body separator
    val separatorIndex = normalized.indexOf("\r\n\r\n")
    if (separatorIndex < 0) return normalized
    
    val headerSection = normalized.substring(0, separatorIndex)
    val body = normalized.substring(separatorIndex + 4)
    
    // If no body, no need to update Content-Length
    if (body.isEmpty()) return normalized
    
    // Calculate actual body length in bytes
    val bodyBytes = body.toByteArray(Charsets.UTF_8)
    val bodyLength = bodyBytes.size
    
    // Update or add Content-Length header
    val lines = headerSection.split("\r\n").toMutableList()
    val contentLengthIndex = lines.indexOfFirst { it.startsWith("Content-Length:", ignoreCase = true) }
    
    if (contentLengthIndex >= 0) {
        lines[contentLengthIndex] = "Content-Length: $bodyLength"
    }
    // If no Content-Length and body exists, the server may not need it (e.g., chunked encoding)
    // so we only update existing headers, not add new ones
    
    return lines.joinToString("\r\n") + "\r\n\r\n" + body
}

private fun truncateIfNeeded(serialized: String, maxBodyBytes: Int): String {
    val limit = maxBodyBytes.coerceAtLeast(1)
    val bytes = serialized.toByteArray(Charsets.UTF_8)
    if (bytes.size <= limit) return serialized
    val truncated = String(bytes, 0, limit, Charsets.UTF_8)
    return "$truncated... (truncated ${bytes.size} bytes to ${limit} bytes)"
}

private fun decodeJwt(token: String): String {
    val parts = token.split(".")
    if (parts.size < 2) return "Invalid JWT: expected header.payload.signature"
    val decoder = Base64.getUrlDecoder()
    val header = runCatching { String(decoder.decode(parts[0]), Charsets.UTF_8) }.getOrNull() ?: "<invalid header>"
    val payload = runCatching { String(decoder.decode(parts[1]), Charsets.UTF_8) }.getOrNull() ?: "<invalid payload>"
    val signature = if (parts.size > 2) parts[2] else ""
    return buildString {
        appendLine("header=$header")
        appendLine("payload=$payload")
        appendLine("signature=$signature")
    }.trim()
}

private fun normalizeHashAlgorithm(raw: String): String {
    val algo = raw.trim().uppercase()
    return when (algo) {
        "SHA1" -> "SHA-1"
        "SHA256" -> "SHA-256"
        "SHA512" -> "SHA-512"
        else -> algo
    }
}

private fun diffLines(a: String, b: String): String {
    val left = a.replace("\r", "").split("\n")
    val right = b.replace("\r", "").split("\n")
    val max = maxOf(left.size, right.size)
    return buildString {
        appendLine("--- request_a")
        appendLine("+++ request_b")
        for (i in 0 until max) {
            val l = left.getOrNull(i)
            val r = right.getOrNull(i)
            if (l == r) {
                if (l != null) appendLine(" $l")
            } else {
                if (l != null) appendLine("-$l")
                if (r != null) appendLine("+$r")
            }
        }
    }.trim()
}

private fun countOccurrences(haystack: String, needle: String): Int {
    if (needle.isEmpty()) return 0
    var count = 0
    var idx = 0
    while (true) {
        val found = haystack.indexOf(needle, idx)
        if (found == -1) return count
        count++
        idx = found + needle.length
    }
}

private fun parseHighlightColor(raw: String?): HighlightColor? {
    val name = raw?.trim().orEmpty()
    if (name.isBlank()) return null
    return try {
        HighlightColor.valueOf(name.uppercase())
    } catch (_: Exception) {
        null
    }
}

private fun sanitizeHeaders(headers: List<HttpHeader>, context: McpToolContext): Map<String, String> {
    val policy = RedactionPolicy.fromMode(context.privacyMode)
    val tokenHeaders = setOf("authorization", "proxy-authorization", "x-api-key", "api-key")
    val sanitized = LinkedHashMap<String, String>()
    headers.forEach { header ->
        val name = header.name()
        val lowered = name.lowercase()
        var value = header.value()
        if (policy.stripCookies && (lowered == "cookie" || lowered == "set-cookie")) {
            value = "[STRIPPED]"
        }
        if (policy.redactTokens && tokenHeaders.contains(lowered)) {
            value = "[REDACTED]"
        }
        if (policy.anonymizeHosts && lowered == "host") {
            value = Redaction.anonymizeHost(value, context.hostSalt)
        }
        sanitized[name] = value
    }
    return sanitized
}

private fun maybeAnonymizeUrl(rawUrl: String, context: McpToolContext): String {
    if (context.privacyMode != com.six2dez.burp.aiagent.redact.PrivacyMode.STRICT) return rawUrl
    return try {
        val uri = URI(rawUrl)
        val host = uri.host ?: return rawUrl
        val anonHost = Redaction.anonymizeHost(host, context.hostSalt)
        URI(
            uri.scheme,
            uri.userInfo,
            anonHost,
            uri.port,
            uri.path,
            uri.query,
            uri.fragment
        ).toString()
    } catch (_: Exception) {
        rawUrl
    }
}

private fun resolveReportPath(raw: String): java.nio.file.Path {
    val trimmed = raw.trim()
    if (trimmed.isBlank()) {
        throw IllegalArgumentException("Report path is empty")
    }
    val rawPath = java.nio.file.Path.of(trimmed)
    val home = java.nio.file.Path.of(System.getProperty("user.home")).normalize()
    val resolved = if (rawPath.isAbsolute) {
        rawPath.normalize()
    } else {
        home.resolve(rawPath).normalize()
    }
    if (!resolved.startsWith(home)) {
        throw IllegalArgumentException("Report path must be under $home")
    }
    return resolved
}

private fun applyReplacements(content: String, replacements: Map<String, String>): String {
    if (replacements.isEmpty()) return content
    var output = content
    replacements.forEach { (key, value) ->
        output = output.replace(key, value)
    }
    return output
}

private fun resolveAuditConfig(mode: String): BuiltInAuditConfiguration {
    return when (mode.trim().lowercase()) {
        "active", "active_checks", "legacy_active" -> BuiltInAuditConfiguration.LEGACY_ACTIVE_AUDIT_CHECKS
        "passive", "passive_checks", "legacy_passive" -> BuiltInAuditConfiguration.LEGACY_PASSIVE_AUDIT_CHECKS
        else -> BuiltInAuditConfiguration.valueOf(mode.trim().uppercase())
    }
}

fun getActiveEditor(api: MontoyaApi): JTextArea? {
    val frame = api.userInterface().swingUtils().suiteFrame()
    val focusManager = KeyboardFocusManager.getCurrentKeyboardFocusManager()
    val permanentFocusOwner = focusManager.permanentFocusOwner
    val isInBurpWindow = generateSequence(permanentFocusOwner) { it.parent }.any { it == frame }
    return if (isInBurpWindow && permanentFocusOwner is JTextArea) {
        permanentFocusOwner
    } else {
        null
    }
}

data class ToolSpec(
    val id: String,
    val description: String,
    val enabled: Boolean,
    val unsafeOnly: Boolean,
    val proOnly: Boolean,
    val argsSchema: String?
)

object McpToolExecutor {
    private val decodeJson = Json { ignoreUnknownKeys = true }

    fun describeTools(context: McpToolContext, includeSchemas: Boolean): String {
        val specs = McpToolCatalog.all().map { desc ->
            val enabled = context.isToolEnabled(desc.id) &&
                (!desc.unsafeOnly || context.unsafeEnabled) &&
                (!desc.proOnly || context.edition == BurpSuiteEdition.PROFESSIONAL)
            val schema = if (includeSchemas) schemaString(desc.id) else null
            ToolSpec(
                id = desc.id,
                description = desc.description,
                enabled = enabled,
                unsafeOnly = desc.unsafeOnly,
                proOnly = desc.proOnly,
                argsSchema = schema
            )
        }

        return buildString {
            appendLine("MCP tools (enabled based on your toggles and privacy mode):")
            for (spec in specs) {
                val status = if (spec.enabled) "enabled" else "disabled"
                append("- ").append(spec.id).append(": ").append(spec.description)
                append(" [").append(status).append("]")
                if (spec.unsafeOnly) append(" [unsafe]")
                if (spec.proOnly) append(" [pro]")
                val schema = spec.argsSchema
                if (!schema.isNullOrBlank()) {
                    append(" args_schema=").append(schema)
                }
                appendLine()
            }
        }.trim()
    }

    fun executeTool(name: String, argsJson: String?, context: McpToolContext): String {
        val resolvedName = resolveAlias(name)
        val descriptor = McpToolCatalog.all().firstOrNull { it.id == resolvedName }
            ?: return "Unknown tool: $name"
        if (descriptor.proOnly && context.edition != BurpSuiteEdition.PROFESSIONAL) {
            return "Tool requires Burp Suite Professional: $resolvedName"
        }

        val api = context.api
        val normalizedArgs = normalizeArgs(resolvedName, argsJson)
        val result = runTool(context, resolvedName) {
            val output = when (resolvedName) {
                "status" -> {
                    val version = api.burpSuite().version()
                    buildString {
                        appendLine("extension=burp-ai-agent")
                        appendLine("burp_version=${version.name()}")
                        appendLine("burp_edition=${version.edition().name}")
                    }.trim()
                }
                "http1_request" -> {
                    val input = decode<SendHttp1Request>(normalizedArgs)
                    api.logging().logToOutput("MCP HTTP/1.1 request: ${context.resolveHost(input.targetHostname)}:${input.targetPort}")
                    val fixedContent = normalizeHttpRequest(input.content)
                    val request = HttpRequest.httpRequest(input.toMontoyaService(context::resolveHost), fixedContent)
                    val response = api.http().sendRequest(request)
                    response?.toString() ?: "<no response>"
                }
                "http2_request" -> {
                    val input = decode<SendHttp2Request>(normalizedArgs)
                    api.logging().logToOutput("MCP HTTP/2 request: ${context.resolveHost(input.targetHostname)}:${input.targetPort}")

                    val orderedPseudoHeaderNames = listOf(":scheme", ":method", ":path", ":authority")
                    val fixedPseudoHeaders = LinkedHashMap<String, String>().apply {
                        orderedPseudoHeaderNames.forEach { pname ->
                            val value = input.pseudoHeaders[pname.removePrefix(":")] ?: input.pseudoHeaders[pname]
                            if (value != null) put(pname, value)
                        }
                        input.pseudoHeaders.forEach { (key, value) ->
                            val properKey = if (key.startsWith(":")) key else ":$key"
                            if (!containsKey(properKey)) put(properKey, value)
                        }
                    }

                    val headerList = (fixedPseudoHeaders + input.headers).map {
                        HttpHeader.httpHeader(it.key.lowercase(), it.value)
                    }
                    val request = HttpRequest.http2Request(input.toMontoyaService(context::resolveHost), headerList, input.requestBody)
                    val response = api.http().sendRequest(request, HttpMode.HTTP_2)
                    response?.toString() ?: "<no response>"
                }
                "repeater_tab" -> {
                    val input = decode<CreateRepeaterTab>(normalizedArgs)
                    val request = HttpRequest.httpRequest(input.toMontoyaService(context::resolveHost), input.content)
                    api.repeater().sendToRepeater(request, input.tabName)
                    "Repeater tab created"
                }
                "repeater_tab_with_payload" -> {
                    val input = decode<RepeaterTabWithPayload>(normalizedArgs)
                    val rendered = applyReplacements(input.content, input.replacements)
                    val request = HttpRequest.httpRequest(input.toMontoyaService(context::resolveHost), rendered)
                    api.repeater().sendToRepeater(request, input.tabName)
                    "Repeater tab created"
                }
                "intruder" -> {
                    val input = decode<SendToIntruder>(normalizedArgs)
                    val request = HttpRequest.httpRequest(input.toMontoyaService(context::resolveHost), input.content)
                    api.intruder().sendToIntruder(request, input.tabName)
                    "Sent to Intruder"
                }
                "intruder_prepare" -> {
                    val input = decode<IntruderPrepare>(normalizedArgs)
                    val fixed = input.content.replace("\r", "").replace("\n", "\r\n")
                    val byteArray = burp.api.montoya.core.ByteArray.byteArray(fixed)
                    val template = if (input.insertionPoints.isNotEmpty()) {
                        val ranges = input.insertionPoints.map { Range.range(it.start, it.end) }
                        HttpRequestTemplate.httpRequestTemplate(byteArray, ranges)
                    } else {
                        val option = HttpRequestTemplateGenerationOptions.valueOf(input.mode.trim().uppercase())
                        HttpRequestTemplate.httpRequestTemplate(byteArray, option)
                    }
                    api.intruder().sendToIntruder(input.toMontoyaService(context::resolveHost), template, input.tabName)
                    "Intruder tab created"
                }
                "insertion_points" -> {
                    val input = decode<InsertionPoints>(normalizedArgs)
                    val request = HttpRequest.httpRequest(input.content)
                    val option = HttpRequestTemplateGenerationOptions.valueOf(input.mode.trim().uppercase())
                    val template = HttpRequestTemplate.httpRequestTemplate(request, option)
                    template.insertionPointOffsets().joinToString(separator = "\n") { range ->
                        "start=${range.startIndexInclusive()} end=${range.endIndexExclusive()}"
                    }
                }
                "params_extract" -> {
                    val input = decode<ExtractParams>(normalizedArgs)
                    val request = HttpRequest.httpRequest(input.content)
                    request.parameters().joinToString(separator = "\n") { param ->
                        "type=${param.type()} name=${param.name()} value=${param.value()}"
                    }
                }
                "diff_requests" -> {
                    val input = decode<DiffRequests>(normalizedArgs)
                    diffLines(input.requestA, input.requestB)
                }
                "request_parse" -> {
                    val input = decode<RequestParse>(normalizedArgs)
                    val request = HttpRequest.httpRequest(input.content)
                    val parsed = ParsedRequest(
                        method = request.method(),
                        path = request.path(),
                        url = maybeAnonymizeUrl(request.url(), context),
                        headers = sanitizeHeaders(request.headers(), context),
                        parameters = request.parameters().map { param ->
                            ParsedParam(type = param.type().name, name = param.name(), value = param.value())
                        },
                        body = if (input.includeBody) request.bodyToString() else null,
                        bodyLength = request.body().length()
                    )
                    toolJson.encodeToString(parsed)
                }
                "response_parse" -> {
                    val input = decode<ResponseParse>(normalizedArgs)
                    val response = burp.api.montoya.http.message.responses.HttpResponse.httpResponse(input.content)
                    val parsed = ParsedResponse(
                        statusCode = response.statusCode().toInt(),
                        headers = sanitizeHeaders(response.headers(), context),
                        body = if (input.includeBody) response.bodyToString() else null,
                        bodyLength = response.body().length()
                    )
                    toolJson.encodeToString(parsed)
                }
                "find_reflected" -> {
                    val input = decode<FindReflected>(normalizedArgs)
                    val request = HttpRequest.httpRequest(input.request)
                    val responseText = input.response
                    val hits = request.parameters().mapNotNull { param ->
                        val value = param.value()
                        if (value.isBlank()) return@mapNotNull null
                        val count = countOccurrences(responseText, value)
                        if (count > 0) "name=${param.name()} type=${param.type()} count=$count" else null
                    }
                    if (hits.isEmpty()) "No reflections found" else hits.joinToString(separator = "\n")
                }
                "comparer_send" -> {
                    val input = decode<ComparerSend>(normalizedArgs)
                    val byteArrays = input.items.map { burp.api.montoya.core.ByteArray.byteArray(it) }
                    api.comparer().sendToComparer(*byteArrays.toTypedArray())
                    "Sent ${input.items.size} item(s) to Comparer"
                }
                "url_encode" -> {
                    val input = decode<UrlEncode>(normalizedArgs)
                    api.utilities().urlUtils().encode(input.content)
                }
                "url_decode" -> {
                    val input = decode<UrlDecode>(normalizedArgs)
                    api.utilities().urlUtils().decode(input.content)
                }
                "base64_encode" -> {
                    val input = decode<Base64Encode>(normalizedArgs)
                    api.utilities().base64Utils().encodeToString(input.content)
                }
                "base64_decode" -> {
                    val input = decode<Base64Decode>(normalizedArgs)
                    api.utilities().base64Utils().decode(input.content).toString()
                }
                "random_string" -> {
                    val input = decode<GenerateRandomString>(normalizedArgs)
                    api.utilities().randomUtils().randomString(input.length, input.characterSet)
                }
                "hash_compute" -> {
                    val input = decode<HashCompute>(normalizedArgs)
                    val algo = normalizeHashAlgorithm(input.algorithm)
                    val digest = MessageDigest.getInstance(algo)
                    val bytes = digest.digest(input.content.toByteArray(Charsets.UTF_8))
                    bytes.joinToString("") { "%02x".format(it) }
                }
                "jwt_decode" -> {
                    val input = decode<JwtDecode>(normalizedArgs)
                    decodeJwt(input.token)
                }
                "decode_as" -> {
                    val input = decode<DecodeAs>(normalizedArgs)
                    val decoded = api.utilities().base64Utils().decode(input.base64)
                    val codec = input.encoding.trim().uppercase()
                    if (codec == "IDENTITY" || codec == "RAW") {
                        decoded.toString()
                    } else {
                        val type = CompressionType.valueOf(codec)
                        api.utilities().compressionUtils().decompress(decoded, type).toString()
                    }
                }
                "cookie_jar_get" -> {
                    val input = decode<CookieJarGet>(normalizedArgs)
                    val cookies = api.http().cookieJar().cookies()
                    val domainFilter = input.domain?.trim().orEmpty().removePrefix(".").lowercase().ifBlank { null }
                    val results = cookies.asSequence()
                        .filter { cookie ->
                            if (domainFilter == null) return@filter true
                            val cookieDomain = cookie.domain().removePrefix(".").lowercase()
                            if (input.includeSubdomains) {
                                cookieDomain == domainFilter || cookieDomain.endsWith(".$domainFilter")
                            } else {
                                cookieDomain == domainFilter
                            }
                        }
                        .filter { cookie ->
                            if (!input.scopeOnly) return@filter true
                            val cookieDomain = cookie.domain().removePrefix(".")
                            val httpUrl = "http://$cookieDomain/"
                            val httpsUrl = "https://$cookieDomain/"
                            api.scope().isInScope(httpUrl) || api.scope().isInScope(httpsUrl)
                        }
                        .map { cookie ->
                            val rawDomain = cookie.domain()
                            val safeDomain = if (context.privacyMode == com.six2dez.burp.aiagent.redact.PrivacyMode.STRICT) {
                                Redaction.anonymizeHost(rawDomain.removePrefix("."), context.hostSalt)
                            } else {
                                rawDomain
                            }
                            val value = if (input.includeValues && context.privacyMode == com.six2dez.burp.aiagent.redact.PrivacyMode.OFF) {
                                cookie.value()
                            } else {
                                "[REDACTED]"
                            }
                            CookieEntry(
                                name = cookie.name(),
                                value = value,
                                domain = safeDomain,
                                path = cookie.path(),
                                expiresAt = cookie.expiration().map { it.toString() }.orElse(null)
                            )
                        }
                        .toList()
                    toolJson.encodeToString(results)
                }
                "project_options_get" -> api.burpSuite().exportProjectOptionsAsJson()
                "user_options_get" -> api.burpSuite().exportUserOptionsAsJson()
                "project_options_set" -> {
                    val input = decode<SetProjectOptions>(normalizedArgs)
                    api.logging().logToOutput("Setting project-level configuration via MCP.")
                    api.burpSuite().importProjectOptionsFromJson(input.json)
                    "Project configuration has been applied"
                }
                "user_options_set" -> {
                    val input = decode<SetUserOptions>(normalizedArgs)
                    api.logging().logToOutput("Setting user-level configuration via MCP.")
                    api.burpSuite().importUserOptionsFromJson(input.json)
                    "User configuration has been applied"
                }
                "collaborator_generate" -> {
                    val input = decode<CollaboratorGenerate>(normalizedArgs)
                    val client = api.collaborator().createClient()
                    val opts = input.options.mapNotNull { opt ->
                        runCatching { burp.api.montoya.collaborator.PayloadOption.valueOf(opt.trim().uppercase()) }.getOrNull()
                    }.toTypedArray()
                    val payload = if (input.customData.isNullOrBlank()) {
                        client.generatePayload(*opts)
                    } else {
                        client.generatePayload(input.customData.trim(), *opts)
                    }
                    val secretKey = client.getSecretKey().toString()
                    CollaboratorRegistry.put(secretKey, client)
                    buildString {
                        appendLine("payload=${payload.toString()}")
                        appendLine("interaction_id=${payload.id().toString()}")
                        appendLine("secret_key=$secretKey")
                    }.trim()
                }
                "collaborator_poll" -> {
                    val input = decode<CollaboratorPoll>(normalizedArgs)
                    val key = input.secretKey.trim()
                    val client = CollaboratorRegistry.get(key)
                        ?: api.collaborator().restoreClient(burp.api.montoya.collaborator.SecretKey.secretKey(key))
                    val interactions = client.getAllInteractions()
                    if (interactions.isEmpty()) return@runTool "No interactions"
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
                                appendLine("dns_query=${dns.query().toString()}")
                            }
                            if (input.includeHttp) {
                                interaction.httpDetails().ifPresent { http ->
                                    val rr = http.requestResponse()
                                    appendLine("http_request=${rr.request()?.toString().orEmpty()}")
                                    appendLine("http_response=${rr.response()?.toString().orEmpty()}")
                                }
                            }
                            interaction.smtpDetails().ifPresent { smtp ->
                                appendLine("smtp=${smtp.toString()}")
                            }
                        }.trim()
                    }
                }
                "scanner_issues" -> {
                    ensurePro(context, resolvedName)
                    val input = decode<GetScannerIssues>(normalizedArgs)
                    val issues = api.siteMap().issues()
                    val seq = if (context.determinismMode) {
                        issues.sortedBy { it.name() }.asSequence()
                    } else {
                        issues.asSequence()
                    }
                    seq.drop(input.offset).take(input.count).joinToString("\n\n") {
                        toolJson.encodeToString(it.toSerializableForm())
                    }
                }
                "scan_audit_start" -> {
                    ensurePro(context, resolvedName)
                    val input = decode<StartAudit>(normalizedArgs)
                    val cfg = AuditConfiguration.auditConfiguration(
                        BuiltInAuditConfiguration.valueOf(input.builtInConfiguration)
                    )
                    val audit = api.scanner().startAudit(cfg)
                    val id = ScannerTaskRegistry.put(audit)
                    "Started audit: id=$id status=${audit.statusMessage()}"
                }
                "scan_audit_start_mode" -> {
                    ensurePro(context, resolvedName)
                    val input = decode<StartAuditMode>(normalizedArgs)
                    val cfg = AuditConfiguration.auditConfiguration(resolveAuditConfig(input.mode))
                    val audit = api.scanner().startAudit(cfg)
                    val service = input.toMontoyaServiceOrNull(context::resolveHost)
                    if (input.requests.isNotEmpty() && service == null) {
                        return@runTool "Error: targetHostname/targetPort required when providing requests"
                    }
                    for (raw in input.requests) {
                        val fixed = raw.replace("\r", "").replace("\n", "\r\n")
                        val req = HttpRequest.httpRequest(service ?: input.toMontoyaService(context::resolveHost), fixed)
                        audit.addRequest(req)
                    }
                    val id = ScannerTaskRegistry.put(audit)
                    if (input.requests.isEmpty()) {
                        "Started audit: id=$id status=${audit.statusMessage()}"
                    } else {
                        "Started audit with requests: id=$id status=${audit.statusMessage()}"
                    }
                }
                "scan_audit_start_requests" -> {
                    ensurePro(context, resolvedName)
                    val input = decode<StartAuditWithRequests>(normalizedArgs)
                    val cfg = AuditConfiguration.auditConfiguration(
                        BuiltInAuditConfiguration.valueOf(input.builtInConfiguration)
                    )
                    val audit = api.scanner().startAudit(cfg)
                    val service = input.toMontoyaService(context::resolveHost)
                    for (raw in input.requests) {
                        val fixed = raw.replace("\r", "").replace("\n", "\r\n")
                        val req = HttpRequest.httpRequest(service, fixed)
                        audit.addRequest(req)
                    }
                    val id = ScannerTaskRegistry.put(audit)
                    "Started audit with requests: id=$id status=${audit.statusMessage()}"
                }
                "scan_crawl_start" -> {
                    ensurePro(context, resolvedName)
                    val input = decode<StartCrawl>(normalizedArgs)
                    val crawl = api.scanner().startCrawl(
                        burp.api.montoya.scanner.CrawlConfiguration.crawlConfiguration(*input.seedUrls.toTypedArray())
                    )
                    val id = ScannerTaskRegistry.put(crawl)
                    "Started crawl: id=$id status=${crawl.statusMessage()}"
                }
                "scan_task_status" -> {
                    ensurePro(context, resolvedName)
                    val input = decode<GetScanTaskStatus>(normalizedArgs)
                    val task = ScannerTaskRegistry.get(input.taskId) ?: return@runTool "Task not found: ${input.taskId}"
                    val base = "status=${task.statusMessage()} requests=${task.requestCount()} errors=${task.errorCount()}"
                    val audit = task as? Audit
                    if (audit != null) {
                        val count = audit.issues().size
                        "$base issues=$count"
                    } else {
                        base
                    }
                }
                "scan_task_delete" -> {
                    ensurePro(context, resolvedName)
                    val input = decode<DeleteScanTask>(normalizedArgs)
                    val task = ScannerTaskRegistry.remove(input.taskId) ?: return@runTool "Task not found: ${input.taskId}"
                    task.delete()
                    "Deleted task: ${input.taskId}"
                }
                "scan_report" -> {
                    ensurePro(context, resolvedName)
                    val input = decode<GenerateScannerReport>(normalizedArgs)
                    val formatEnum = ReportFormat.valueOf(input.format)
                    val pathObj = try {
                        resolveReportPath(input.path)
                    } catch (e: IllegalArgumentException) {
                        return@runTool "Error: ${e.message}"
                    }
                    val issues = when {
                        input.taskId != null -> {
                            val task = ScannerTaskRegistry.get(input.taskId)
                            val audit = task as? Audit ?: return@runTool "Task not found or not an audit: ${input.taskId}"
                            audit.issues()
                        }
                        input.allIssues -> api.siteMap().issues()
                        else -> return@runTool "Provide taskId or set allIssues=true"
                    }
                    api.scanner().generateReport(issues, formatEnum, pathObj)
                    "Report generated: ${input.path}"
                }
                "proxy_http_history" -> {
                    val input = decode<GetProxyHttpHistory>(normalizedArgs)
                    val items = api.proxy().history()
                    val seq = if (context.determinismMode) {
                        items.sortedBy { it.request()?.toString().orEmpty() }.asSequence()
                    } else {
                        items.asSequence()
                    }
                    seq.drop(input.offset).take(input.count).joinToString("\n\n") {
                        truncateIfNeeded(toolJson.encodeToString(it.toSerializableForm()), context.maxBodyBytes)
                    }
                }
                "proxy_http_history_regex" -> {
                    val input = decode<GetProxyHttpHistoryRegex>(normalizedArgs)
                    val compiledRegex = Pattern.compile(input.regex)
                    val items = api.proxy().history { it.contains(compiledRegex) }
                    val seq = if (context.determinismMode) {
                        items.sortedBy { it.request()?.toString().orEmpty() }.asSequence()
                    } else {
                        items.asSequence()
                    }
                    seq.drop(input.offset).take(input.count).joinToString("\n\n") {
                        truncateIfNeeded(toolJson.encodeToString(it.toSerializableForm()), context.maxBodyBytes)
                    }
                }
                "proxy_history_annotate" -> {
                    val input = decode<ProxyHistoryAnnotate>(normalizedArgs)
                    val compiledRegex = Pattern.compile(input.regex)
                    val items = api.proxy().history { it.contains(compiledRegex) }
                    val highlightColor = parseHighlightColor(input.highlight)
                    val limitValue = input.limit.coerceAtLeast(1).coerceAtMost(500)
                    val annotated = mutableListOf<String>()
                    for (item in items) {
                        val url = item.request()?.url() ?: continue
                        if (input.scopeOnly && !api.scope().isInScope(url)) continue
                        if (input.note.isNotBlank()) {
                            item.annotations().setNotes(input.note)
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
                "response_body_search" -> {
                    val input = decode<ResponseBodySearch>(normalizedArgs)
                    val compiledRegex = Pattern.compile(input.regex)
                    val matches = mutableListOf<String>()
                    api.proxy().history().forEach { item ->
                        val url = item.request()?.url() ?: return@forEach
                        if (input.scopeOnly && !api.scope().isInScope(url)) return@forEach
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
                    val slice = sorted.drop(input.offset.coerceAtLeast(0)).take(input.count.coerceAtLeast(1))
                    if (slice.isEmpty()) "No matches found" else slice.joinToString(separator = "\n")
                }
                "proxy_ws_history" -> {
                    val input = decode<GetProxyWebsocketHistory>(normalizedArgs)
                    val items = api.proxy().webSocketHistory()
                    val seq = if (context.determinismMode) {
                        items.sortedBy { it.payload()?.toString().orEmpty() }.asSequence()
                    } else {
                        items.asSequence()
                    }
                    seq.drop(input.offset).take(input.count).joinToString("\n\n") {
                        truncateIfNeeded(toolJson.encodeToString(it.toSerializableForm()), context.maxBodyBytes)
                    }
                }
                "proxy_ws_history_regex" -> {
                    val input = decode<GetProxyWebsocketHistoryRegex>(normalizedArgs)
                    val compiledRegex = Pattern.compile(input.regex)
                    val items = api.proxy().webSocketHistory { it.contains(compiledRegex) }
                    val seq = if (context.determinismMode) {
                        items.sortedBy { it.payload()?.toString().orEmpty() }.asSequence()
                    } else {
                        items.asSequence()
                    }
                    seq.drop(input.offset).take(input.count).joinToString("\n\n") {
                        truncateIfNeeded(toolJson.encodeToString(it.toSerializableForm()), context.maxBodyBytes)
                    }
                }
                "site_map" -> {
                    val input = decode<GetSiteMap>(normalizedArgs)
                    val items = api.siteMap().requestResponses()
                    val seq = if (context.determinismMode) {
                        items.sortedBy { it.request()?.url().orEmpty() }.asSequence()
                    } else {
                        items.asSequence()
                    }
                    seq.drop(input.offset).take(input.count).joinToString("\n\n") {
                        truncateIfNeeded(toolJson.encodeToString(it.toSiteMapEntry()), context.maxBodyBytes)
                    }
                }
                "site_map_regex" -> {
                    val input = decode<GetSiteMapRegex>(normalizedArgs)
                    val compiledRegex = Pattern.compile(input.regex)
                    val filter = burp.api.montoya.sitemap.SiteMapFilter { node ->
                        compiledRegex.matcher(node.url()).find()
                    }
                    val items = api.siteMap().requestResponses(filter)
                    val seq = if (context.determinismMode) {
                        items.sortedBy { it.request()?.url().orEmpty() }.asSequence()
                    } else {
                        items.asSequence()
                    }
                    seq.drop(input.offset).take(input.count).joinToString("\n\n") {
                        truncateIfNeeded(toolJson.encodeToString(it.toSiteMapEntry()), context.maxBodyBytes)
                    }
                }
                "scope_check" -> {
                    val input = decode<ScopeCheck>(normalizedArgs)
                    "in_scope=${api.scope().isInScope(input.url)}"
                }
                "scope_include" -> {
                    val input = decode<ScopeUpdate>(normalizedArgs)
                    api.scope().includeInScope(input.url)
                    "Scope include applied"
                }
                "scope_exclude" -> {
                    val input = decode<ScopeUpdate>(normalizedArgs)
                    api.scope().excludeFromScope(input.url)
                    "Scope exclude applied"
                }
                "task_engine_state" -> {
                    val input = decode<SetTaskExecutionEngineState>(normalizedArgs)
                    api.burpSuite().taskExecutionEngine().state = if (input.running) RUNNING else PAUSED
                    "Task execution engine is now ${if (input.running) "running" else "paused"}"
                }
                "proxy_intercept" -> {
                    val input = decode<SetProxyInterceptState>(normalizedArgs)
                    if (input.intercepting) api.proxy().enableIntercept() else api.proxy().disableIntercept()
                    "Intercept has been ${if (input.intercepting) "enabled" else "disabled"}"
                }
                "editor_get" -> getActiveEditor(api)?.text ?: "<No active editor>"
                "editor_set" -> {
                    val input = decode<SetActiveEditorContents>(normalizedArgs)
                    val editor = getActiveEditor(api) ?: return@runTool "<No active editor>"
                    if (!editor.isEditable) return@runTool "<Current editor is not editable>"
                    editor.text = input.text
                    "Editor text has been set"
                }
                else -> "Unknown tool: $name"
            }
            context.redactIfNeeded(output)
        }

        val text = result.content.filterIsInstance<io.modelcontextprotocol.kotlin.sdk.TextContent>()
            .map { it.text?.toString().orEmpty() }
            .joinToString("\n")
        val isError = result.isError == true
        return if (isError && text.isNotBlank()) {
            "Error: $text"
        } else {
            text.ifBlank { "Tool executed: $resolvedName" }
        }
    }

    private fun ensurePro(context: McpToolContext, name: String) {
        if (context.edition != BurpSuiteEdition.PROFESSIONAL) {
            throw IllegalStateException("Tool requires Burp Suite Professional: $name")
        }
    }

    private inline fun <reified T : Any> decode(raw: String?): T {
        val jsonText = raw?.trim().orEmpty().ifBlank { "{}" }
        val element = decodeJson.parseToJsonElement(jsonText)
        try {
            return decodeJson.decodeFromJsonElement(element)
        } catch (e: kotlinx.serialization.MissingFieldException) {
            throw IllegalArgumentException(
                "Missing required argument(s) for ${T::class.simpleName}: ${e.message}. " +
                "Please provide the required fields in the JSON arguments."
            )
        }
    }

    private fun resolveAlias(toolName: String): String {
        return when (toolName.trim().lowercase()) {
            "history", "proxy_history", "requests" -> "proxy_http_history"
            "history_regex", "proxy_history_regex" -> "proxy_http_history_regex"
            "ws_history", "websocket_history", "websocket" -> "proxy_ws_history"
            "sitemap", "site_map_history" -> "site_map"
            else -> toolName
        }
    }

    private fun normalizeArgs(toolName: String, rawArgs: String?): String? {
        val lowered = toolName.lowercase()
        val needsPaging = lowered in setOf(
            "proxy_http_history",
            "proxy_http_history_regex",
            "response_body_search",
            "proxy_ws_history",
            "proxy_ws_history_regex",
            "site_map",
            "site_map_regex",
            "scanner_issues"
        )
        if (!needsPaging) return rawArgs

        val obj = parseArgsObject(rawArgs)
        val count = obj["count"] ?: obj["limit"] ?: JsonPrimitive(5)
        val offset = obj["offset"] ?: JsonPrimitive(0)
        val merged = obj.toMutableMap().apply {
            put("count", count)
            put("offset", offset)
            remove("limit")
        }
        return JsonObject(merged).toString()
    }

    private fun parseArgsObject(rawArgs: String?): Map<String, JsonElement> {
        val text = rawArgs?.trim().orEmpty()
        if (text.isBlank()) return emptyMap()
        return try {
            val element = decodeJson.parseToJsonElement(text)
            val obj = element as? JsonObject ?: return emptyMap()
            obj
        } catch (_: Exception) {
            emptyMap()
        }
    }

    private fun schemaString(toolName: String): String {
        val input = when (toolName) {
            "status",
            "editor_get",
            "project_options_get",
            "user_options_get" -> io.modelcontextprotocol.kotlin.sdk.Tool.Input()
            "http1_request" -> SendHttp1Request::class.asInputSchema()
            "http2_request" -> SendHttp2Request::class.asInputSchema()
            "repeater_tab" -> CreateRepeaterTab::class.asInputSchema()
            "repeater_tab_with_payload" -> RepeaterTabWithPayload::class.asInputSchema()
            "intruder" -> SendToIntruder::class.asInputSchema()
            "intruder_prepare" -> IntruderPrepare::class.asInputSchema()
            "insertion_points" -> InsertionPoints::class.asInputSchema()
            "params_extract" -> ExtractParams::class.asInputSchema()
            "diff_requests" -> DiffRequests::class.asInputSchema()
            "request_parse" -> RequestParse::class.asInputSchema()
            "response_parse" -> ResponseParse::class.asInputSchema()
            "find_reflected" -> FindReflected::class.asInputSchema()
            "comparer_send" -> ComparerSend::class.asInputSchema()
            "url_encode" -> UrlEncode::class.asInputSchema()
            "url_decode" -> UrlDecode::class.asInputSchema()
            "base64_encode" -> Base64Encode::class.asInputSchema()
            "base64_decode" -> Base64Decode::class.asInputSchema()
            "random_string" -> GenerateRandomString::class.asInputSchema()
            "hash_compute" -> HashCompute::class.asInputSchema()
            "jwt_decode" -> JwtDecode::class.asInputSchema()
            "decode_as" -> DecodeAs::class.asInputSchema()
            "cookie_jar_get" -> CookieJarGet::class.asInputSchema()
            "project_options_set" -> SetProjectOptions::class.asInputSchema()
            "user_options_set" -> SetUserOptions::class.asInputSchema()
            "collaborator_generate" -> CollaboratorGenerate::class.asInputSchema()
            "collaborator_poll" -> CollaboratorPoll::class.asInputSchema()
            "scanner_issues" -> GetScannerIssues::class.asInputSchema()
            "scan_audit_start" -> StartAudit::class.asInputSchema()
            "scan_audit_start_mode" -> StartAuditMode::class.asInputSchema()
            "scan_audit_start_requests" -> StartAuditWithRequests::class.asInputSchema()
            "scan_crawl_start" -> StartCrawl::class.asInputSchema()
            "scan_task_status" -> GetScanTaskStatus::class.asInputSchema()
            "scan_task_delete" -> DeleteScanTask::class.asInputSchema()
            "scan_report" -> GenerateScannerReport::class.asInputSchema()
            "proxy_http_history" -> GetProxyHttpHistory::class.asInputSchema()
            "proxy_http_history_regex" -> GetProxyHttpHistoryRegex::class.asInputSchema()
            "proxy_history_annotate" -> ProxyHistoryAnnotate::class.asInputSchema()
            "response_body_search" -> ResponseBodySearch::class.asInputSchema()
            "proxy_ws_history" -> GetProxyWebsocketHistory::class.asInputSchema()
            "proxy_ws_history_regex" -> GetProxyWebsocketHistoryRegex::class.asInputSchema()
            "site_map" -> GetSiteMap::class.asInputSchema()
            "site_map_regex" -> GetSiteMapRegex::class.asInputSchema()
            "scope_check" -> ScopeCheck::class.asInputSchema()
            "scope_include" -> ScopeUpdate::class.asInputSchema()
            "scope_exclude" -> ScopeUpdate::class.asInputSchema()
            "task_engine_state" -> SetTaskExecutionEngineState::class.asInputSchema()
            "proxy_intercept" -> SetProxyInterceptState::class.asInputSchema()
            "editor_set" -> SetActiveEditorContents::class.asInputSchema()
            else -> io.modelcontextprotocol.kotlin.sdk.Tool.Input()
        }

        val props = input.properties.toString()
        val requiredList = input.required ?: emptyList()
        val required = if (requiredList.isEmpty()) "[]" else requiredList.joinToString(prefix = "[", postfix = "]") { "\"$it\"" }
        return "{\"properties\":$props,\"required\":$required}"
    }
}

interface HttpServiceParams {
    val targetHostname: String
    val targetPort: Int
    val usesHttps: Boolean

    fun toMontoyaService(resolveHost: (String) -> String = { it }): HttpService =
        HttpService.httpService(resolveHost(targetHostname), targetPort, usesHttps)

    fun toMontoyaServiceOrNull(resolveHost: (String) -> String = { it }): HttpService? {
        if (targetHostname.isBlank() || targetPort <= 0) return null
        return HttpService.httpService(resolveHost(targetHostname), targetPort, usesHttps)
    }
}

@Serializable
data class SendHttp1Request(
    val content: String,
    override val targetHostname: String,
    override val targetPort: Int,
    override val usesHttps: Boolean
) : HttpServiceParams

@Serializable
data class SendHttp2Request(
    val pseudoHeaders: Map<String, String>,
    val headers: Map<String, String>,
    val requestBody: String,
    override val targetHostname: String,
    override val targetPort: Int,
    override val usesHttps: Boolean
) : HttpServiceParams

@Serializable
data class CreateRepeaterTab(
    val tabName: String?,
    val content: String,
    override val targetHostname: String,
    override val targetPort: Int,
    override val usesHttps: Boolean
) : HttpServiceParams

@Serializable
data class RepeaterTabWithPayload(
    val tabName: String?,
    val content: String,
    val replacements: Map<String, String>,
    override val targetHostname: String,
    override val targetPort: Int,
    override val usesHttps: Boolean
) : HttpServiceParams

@Serializable
data class SendToIntruder(
    val tabName: String?,
    val content: String,
    override val targetHostname: String,
    override val targetPort: Int,
    override val usesHttps: Boolean
) : HttpServiceParams

@Serializable
data class IntruderPrepare(
    val tabName: String?,
    val content: String,
    val insertionPoints: List<InsertionPointRange> = emptyList(),
    val mode: String = "REPLACE_BASE_PARAMETER_VALUE_WITH_OFFSETS",
    override val targetHostname: String,
    override val targetPort: Int,
    override val usesHttps: Boolean
) : HttpServiceParams

@Serializable
data class InsertionPointRange(val start: Int, val end: Int)

@Serializable
data class InsertionPoints(val content: String, val mode: String = "REPLACE_BASE_PARAMETER_VALUE_WITH_OFFSETS")

@Serializable
data class ExtractParams(val content: String)

@Serializable
data class DiffRequests(val requestA: String, val requestB: String)

@Serializable
data class RequestParse(val content: String, val includeBody: Boolean = false)

@Serializable
data class ResponseParse(val content: String, val includeBody: Boolean = false)

@Serializable
data class ParsedParam(val type: String, val name: String, val value: String)

@Serializable
data class ParsedRequest(
    val method: String,
    val path: String,
    val url: String,
    val headers: Map<String, String>,
    val parameters: List<ParsedParam>,
    val body: String? = null,
    val bodyLength: Int
)

@Serializable
data class ParsedResponse(
    val statusCode: Int,
    val headers: Map<String, String>,
    val body: String? = null,
    val bodyLength: Int
)

@Serializable
data class FindReflected(val request: String, val response: String)

@Serializable
data class ComparerSend(val items: List<String>)

@Serializable
data class ProxyHistoryAnnotate(
    val regex: String,
    val note: String,
    val highlight: String? = null,
    val scopeOnly: Boolean = true,
    val limit: Int = 20
)

@Serializable
data class ResponseBodySearch(
    val regex: String,
    override val count: Int = 5,
    override val offset: Int = 0,
    val scopeOnly: Boolean = true
) : Paginated

@Serializable
data class CookieJarGet(
    val domain: String? = null,
    val includeSubdomains: Boolean = true,
    val scopeOnly: Boolean = true,
    val includeValues: Boolean = false
)

@Serializable
data class CookieEntry(
    val name: String,
    val value: String,
    val domain: String,
    val path: String,
    val expiresAt: String? = null
)

@Serializable
data class ScopeCheck(val url: String = "") {
    init { require(url.isNotBlank()) { "'url' is required for scope_check. Provide the URL to check." } }
}

@Serializable
data class ScopeUpdate(val url: String = "") {
    init { require(url.isNotBlank()) { "'url' is required for scope_include/scope_exclude. Provide the URL to modify." } }
}

@Serializable
data class CollaboratorGenerate(
    val customData: String? = null,
    val options: List<String> = emptyList()
)

@Serializable
data class CollaboratorPoll(
    val secretKey: String,
    val includeHttp: Boolean = false
)

@Serializable
data class UrlEncode(val content: String)

@Serializable
data class UrlDecode(val content: String)

@Serializable
data class Base64Encode(val content: String)

@Serializable
data class Base64Decode(val content: String)

@Serializable
data class GenerateRandomString(val length: Int, val characterSet: String)

@Serializable
data class HashCompute(val content: String, val algorithm: String)

@Serializable
data class JwtDecode(val token: String)

@Serializable
data class DecodeAs(val base64: String, val encoding: String)

@Serializable
data class SetProjectOptions(val json: String)

@Serializable
data class SetUserOptions(val json: String)

@Serializable
data class SetTaskExecutionEngineState(val running: Boolean)

@Serializable
data class SetProxyInterceptState(val intercepting: Boolean)

@Serializable
data class SetActiveEditorContents(val text: String)

@Serializable
data class CreateAuditIssue(
    val name: String,
    val detail: String,
    val baseUrl: String,
    val severity: String,
    val confidence: String,
    val remediation: String? = null,
    val background: String? = null,
    val remediationBackground: String? = null,
    val typicalSeverity: String? = null,
    val httpRequest: String? = null,
    val httpResponseContent: String? = null,
    override val targetHostname: String = "",
    override val targetPort: Int = 443,
    override val usesHttps: Boolean = true
) : HttpServiceParams {
    override fun toMontoyaServiceOrNull(resolveHost: (String) -> String): HttpService? {
        return if (targetHostname.isNotBlank()) {
            HttpService.httpService(resolveHost(targetHostname), targetPort, usesHttps)
        } else {
            null
        }
    }
}

@Serializable
data class GetScannerIssues(override val count: Int, override val offset: Int) : Paginated

@Serializable
data class StartAudit(val builtInConfiguration: String)

@Serializable
data class StartAuditMode(
    val mode: String,
    val requests: List<String> = emptyList(),
    override val targetHostname: String = "",
    override val targetPort: Int = 0,
    override val usesHttps: Boolean = true
) : HttpServiceParams

@Serializable
data class StartAuditWithRequests(
    val builtInConfiguration: String,
    val requests: List<String>,
    override val targetHostname: String,
    override val targetPort: Int,
    override val usesHttps: Boolean
) : HttpServiceParams

@Serializable
data class StartCrawl(val seedUrls: List<String>)

@Serializable
data class GetScanTaskStatus(val taskId: String)

@Serializable
data class DeleteScanTask(val taskId: String)

@Serializable
data class GenerateScannerReport(
    val taskId: String?,
    val allIssues: Boolean,
    val format: String,
    val path: String
)

@Serializable
data class GetProxyHttpHistory(override val count: Int, override val offset: Int) : Paginated

@Serializable
data class GetProxyHttpHistoryRegex(val regex: String, override val count: Int, override val offset: Int) : Paginated

@Serializable
data class GetProxyWebsocketHistory(override val count: Int, override val offset: Int) : Paginated

@Serializable
data class GetProxyWebsocketHistoryRegex(val regex: String, override val count: Int, override val offset: Int) :
    Paginated

@Serializable
data class GetSiteMap(override val count: Int, override val offset: Int) : Paginated

@Serializable
data class GetSiteMapRegex(val regex: String, override val count: Int, override val offset: Int) : Paginated
