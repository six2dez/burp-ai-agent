package com.six2dez.burp.aiagent.ui

import burp.api.montoya.MontoyaApi
import burp.api.montoya.http.message.HttpRequestResponse
import burp.api.montoya.scanner.audit.issues.AuditIssue
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity
import burp.api.montoya.ui.contextmenu.AuditIssueContextMenuEvent
import burp.api.montoya.ui.contextmenu.ContextMenuEvent
import burp.api.montoya.ui.contextmenu.InvocationType
import com.six2dez.burp.aiagent.audit.AuditLogger
import com.six2dez.burp.aiagent.config.AgentSettings
import com.six2dez.burp.aiagent.config.CustomPromptDefinition
import com.six2dez.burp.aiagent.config.CustomPromptTag
import com.six2dez.burp.aiagent.context.ContextCapture
import com.six2dez.burp.aiagent.context.ContextCollector
import com.six2dez.burp.aiagent.context.ContextOptions
import com.six2dez.burp.aiagent.mcp.McpServerState
import com.six2dez.burp.aiagent.mcp.McpSupervisor
import com.six2dez.burp.aiagent.prompts.bountyprompt.BountyPromptCategory
import com.six2dez.burp.aiagent.prompts.bountyprompt.BountyPromptDefinition
import com.six2dez.burp.aiagent.prompts.bountyprompt.BountyPromptLoader
import com.six2dez.burp.aiagent.prompts.bountyprompt.BountyPromptOutputParser
import com.six2dez.burp.aiagent.prompts.bountyprompt.BountyPromptOutputType
import com.six2dez.burp.aiagent.prompts.bountyprompt.BountyPromptTagResolver
import com.six2dez.burp.aiagent.scanner.ActiveAiScanner
import com.six2dez.burp.aiagent.scanner.JsEndpointExtractor
import com.six2dez.burp.aiagent.scanner.PassiveAiScanner
import com.six2dez.burp.aiagent.scanner.VulnClass
import com.six2dez.burp.aiagent.ui.components.CustomPromptDialog
import com.six2dez.burp.aiagent.util.IssueText
import com.six2dez.burp.aiagent.util.IssueUtils
import java.awt.BorderLayout
import java.awt.GridLayout
import javax.swing.BoxLayout
import javax.swing.JCheckBox
import javax.swing.JMenu
import javax.swing.JMenuItem
import javax.swing.JOptionPane
import javax.swing.JPanel
import javax.swing.JScrollPane
import javax.swing.JTextArea
import javax.swing.SwingUtilities

object UiActions {
    private val bountyPromptLoader = BountyPromptLoader()
    private val bountyPromptResolver = BountyPromptTagResolver()
    private val bountyPromptOutputParser = BountyPromptOutputParser()

    @Volatile
    private var contextPreviewEnabled = true

    fun requestResponseMenuItems(
        api: MontoyaApi,
        event: ContextMenuEvent,
        tab: MainTab,
        mcpSupervisor: McpSupervisor,
        passiveAiScanner: PassiveAiScanner,
        activeAiScanner: ActiveAiScanner? = null,
        audit: AuditLogger? = null,
    ): List<JMenuItem> {
        val selected = event.selectedRequestResponses()
        val editorSelection = event.messageEditorRequestResponse().map { it.requestResponse() }
        val targets: List<HttpRequestResponse>
        val siteMapFallback: Boolean

        if (event.isFrom(InvocationType.SITE_MAP_TREE)) {
            // Tree node selected — expand to all requests under the selected URL prefix(es)
            val prefixes =
                selected
                    .mapNotNull { rr ->
                        try {
                            rr.request()?.url()
                        } catch (_: Exception) {
                            null
                        }
                    }.filter { it.isNotBlank() }

            targets =
                if (prefixes.isNotEmpty()) {
                    val filter =
                        burp.api.montoya.sitemap.SiteMapFilter { node ->
                            val url = node.url()
                            prefixes.any { prefix -> url.startsWith(prefix) }
                        }
                    api.siteMap().requestResponses(filter).ifEmpty { selected }
                } else {
                    api.logging().logToOutput(
                        "[UiActions] SITE_MAP_TREE: no URL prefixes extracted from selection, skipping to avoid scanning entire site map.",
                    )
                    selected.ifEmpty { emptyList() }
                }
            siteMapFallback = targets.size > selected.size
        } else if (selected.isNotEmpty()) {
            targets = selected
            siteMapFallback = false
        } else if (editorSelection.isPresent) {
            targets = listOf(editorSelection.get())
            siteMapFallback = false
        } else {
            return emptyList()
        }
        if (targets.isEmpty()) return emptyList()

        val targetLabel = if (siteMapFallback) "site map - ${targets.size}" else "${targets.size}"

        // AI Vulnerability Scan option (Passive)
        val aiScan = JMenuItem("AI Passive Scan ($targetLabel)")
        aiScan.addActionListener {
            val count = passiveAiScanner.manualScan(targets)
            JOptionPane.showMessageDialog(
                tab.root,
                "Queued $count request(s) for AI passive analysis.\n\nFindings will appear in Target → Issues with [AI] prefix.",
                "AI Passive Scan Started",
                JOptionPane.INFORMATION_MESSAGE,
            )
        }

        // AI Active Scan option
        val aiActiveScan = JMenuItem("AI Active Scan ($targetLabel)")
        aiActiveScan.addActionListener {
            if (!ensureActiveScannerEnabled(tab, activeAiScanner)) return@addActionListener
            val scanner = activeAiScanner ?: return@addActionListener
            val validTargets = filterValidTargets(targets)
            if (validTargets.isEmpty()) {
                JOptionPane.showMessageDialog(
                    tab.root,
                    "No valid HTTP targets found for active scan.",
                    "AI Active Scan",
                    JOptionPane.WARNING_MESSAGE,
                )
                return@addActionListener
            }
            val preQueue = scanner.getStatus().queueSize
            val confirmed =
                JOptionPane.showConfirmDialog(
                    tab.root,
                    "This will send active test payloads to ${validTargets.size} target(s).\n" +
                        "Current queue: $preQueue\n\n" +
                        "Do you want to continue?",
                    "Confirm AI Active Scan",
                    JOptionPane.YES_NO_OPTION,
                    JOptionPane.WARNING_MESSAGE,
                )
            if (confirmed != JOptionPane.YES_OPTION) return@addActionListener
            // Queue all vuln classes for manual scan
            val count = scanner.manualScan(validTargets, VulnClass.values().toList())
            val postQueue = scanner.getStatus().queueSize
            if (count == 0) {
                JOptionPane.showMessageDialog(
                    tab.root,
                    "No targets were queued. The active scan queue may be full (max ${scanner.maxQueueSize}) or targets were filtered out.",
                    "AI Active Scan",
                    JOptionPane.WARNING_MESSAGE,
                )
                return@addActionListener
            }
            JOptionPane.showMessageDialog(
                tab.root,
                "Queued $count target(s) for AI active testing.\n\n" +
                    "Queue size: $preQueue -> $postQueue\n" +
                    "Queue max: ${scanner.maxQueueSize}\n" +
                    "This will send test payloads to the server.\n" +
                    "Confirmed findings will appear in Target → Issues with [AI] Confirmed prefix.",
                "AI Active Scan Started",
                JOptionPane.INFORMATION_MESSAGE,
            )
        }

        val targetedTestsMenu = buildTargetedTestsMenu(tab, targets, activeAiScanner, targetLabel)
        val bountyPromptMenu = buildBountyPromptMenu(api, tab, mcpSupervisor, targets, audit)

        val findVulns = JMenuItem("Find vulnerabilities")
        findVulns.addActionListener {
            if (!ensureMcpRunning(tab, mcpSupervisor)) return@addActionListener
            val collector = ContextCollector(api)
            val settings = tab.currentSettings()
            val ctx =
                collector.fromRequestResponses(
                    targets,
                    contextOptionsFromSettings(settings),
                )
            if (!confirmContextPreview(tab, "Find Vulnerabilities", ctx)) return@addActionListener
            tab.openChatWithContext(ctx, settings.requestPromptTemplate, "Find Vulnerabilities")
        }

        val analyzeRequest = JMenuItem("Analyze this request")
        analyzeRequest.addActionListener {
            if (!ensureMcpRunning(tab, mcpSupervisor)) return@addActionListener
            val collector = ContextCollector(api)
            val settings = tab.currentSettings()
            val ctx =
                collector.fromRequestResponses(
                    targets,
                    contextOptionsFromSettings(settings),
                )
            if (!confirmContextPreview(tab, "Analyze this request", ctx)) return@addActionListener
            tab.openChatWithContext(ctx, settings.requestSummaryPrompt, "Analyze this request")
        }

        val explainJs = JMenuItem("Explain JS")
        explainJs.addActionListener {
            if (!ensureMcpRunning(tab, mcpSupervisor)) return@addActionListener
            val collector = ContextCollector(api)
            val settings = tab.currentSettings()
            val ctx =
                collector.fromRequestResponses(
                    targets,
                    contextOptionsFromSettings(settings),
                )
            if (!confirmContextPreview(tab, "Explain JS", ctx)) return@addActionListener
            tab.openChatWithContext(ctx, settings.explainJsPrompt, "Explain JS")
        }

        val extractJsEndpoints = JMenuItem("Extract JS Endpoints ($targetLabel)")
        extractJsEndpoints.addActionListener {
            val allEndpoints = mutableSetOf<String>()
            for (target in targets) {
                val body = runCatching { target.response()?.bodyToString().orEmpty() }.getOrDefault("")
                if (body.isBlank()) continue
                val raw = JsEndpointExtractor.extract(body)
                if (raw.isNotEmpty()) {
                    allEndpoints.addAll(JsEndpointExtractor.resolveEndpoints(raw, target.request().url()))
                }
            }
            if (allEndpoints.isEmpty()) {
                JOptionPane.showMessageDialog(
                    tab.root,
                    "No API endpoints found in the selected response(s).",
                    "JS Endpoint Extraction",
                    JOptionPane.INFORMATION_MESSAGE,
                )
                return@addActionListener
            }
            val sorted = allEndpoints.sorted()
            val textArea = JTextArea(sorted.joinToString("\n"), 20, 60)
            textArea.isEditable = false
            val scrollPane = JScrollPane(textArea)
            JOptionPane.showMessageDialog(
                tab.root,
                scrollPane,
                "JS Endpoints Discovered (${sorted.size})",
                JOptionPane.INFORMATION_MESSAGE,
            )
            api.logging().logToOutput("[JsEndpointExtractor] Manual extraction: ${sorted.size} endpoint(s) found")
            sorted.take(20).forEach { api.logging().logToOutput("[JsEndpointExtractor]   -> $it") }
        }

        val test403Bypass = JMenuItem("Test 403 Bypass ($targetLabel)")
        test403Bypass.addActionListener {
            if (!ensureActiveScannerEnabled(tab, activeAiScanner)) return@addActionListener
            val scanner = activeAiScanner ?: return@addActionListener
            val forbidden = targets.filter { (it.response()?.statusCode()?.toInt() ?: 0) == 403 }
            if (forbidden.isEmpty()) {
                JOptionPane.showMessageDialog(
                    tab.root,
                    "No requests with 403 status found in the selection.\nSelect requests that returned HTTP 403.",
                    "Test 403 Bypass",
                    JOptionPane.WARNING_MESSAGE,
                )
                return@addActionListener
            }
            val confirmed =
                JOptionPane.showConfirmDialog(
                    tab.root,
                    "This will test ${forbidden.size} request(s) with 403 bypass techniques:\n" +
                        "- IP spoofing headers (X-Forwarded-For, X-Real-IP, etc.)\n" +
                        "- Path manipulation (/path/, /path/., ..;, case swap)\n" +
                        "- HTTP method switching\n\n" +
                        "Continue?",
                    "Confirm 403 Bypass Test",
                    JOptionPane.YES_NO_OPTION,
                    JOptionPane.WARNING_MESSAGE,
                )
            if (confirmed != JOptionPane.YES_OPTION) return@addActionListener
            val count = scanner.manualScan(forbidden, listOf(VulnClass.ACCESS_CONTROL_BYPASS))
            JOptionPane.showMessageDialog(
                tab.root,
                "Queued $count target(s) for 403 bypass testing.\nResults will appear in Target → Issues.",
                "403 Bypass Test Started",
                JOptionPane.INFORMATION_MESSAGE,
            )
        }

        val accessControl = JMenuItem("Access control")
        accessControl.addActionListener {
            if (!ensureMcpRunning(tab, mcpSupervisor)) return@addActionListener
            val collector = ContextCollector(api)
            val settings = tab.currentSettings()
            val ctx =
                collector.fromRequestResponses(
                    targets,
                    contextOptionsFromSettings(settings),
                )
            if (!confirmContextPreview(tab, "Access Control", ctx)) return@addActionListener
            tab.openChatWithContext(ctx, settings.accessControlPrompt, "Access Control")
        }

        val login = JMenuItem("Login sequence")
        login.addActionListener {
            if (!ensureMcpRunning(tab, mcpSupervisor)) return@addActionListener
            val collector = ContextCollector(api)
            val settings = tab.currentSettings()
            val ctx =
                collector.fromRequestResponses(
                    targets,
                    contextOptionsFromSettings(settings),
                )
            if (!confirmContextPreview(tab, "Login Sequence", ctx)) return@addActionListener
            tab.openChatWithContext(ctx, settings.loginSequencePrompt, "Login Sequence")
        }

        val customPromptsMenu = buildHttpCustomPromptsMenu(api, tab, mcpSupervisor, targets, targetLabel)

        return listOf(
            aiScan,
            aiActiveScan,
            targetedTestsMenu,
            bountyPromptMenu,
            findVulns,
            analyzeRequest,
            explainJs,
            extractJsEndpoints,
            test403Bypass,
            accessControl,
            login,
            customPromptsMenu,
        )
    }

    fun auditIssueMenuItems(
        api: MontoyaApi,
        event: AuditIssueContextMenuEvent,
        tab: MainTab,
        mcpSupervisor: McpSupervisor,
    ): List<JMenuItem> {
        val issues = event.selectedIssues()
        if (issues.isEmpty()) return emptyList()

        val analyze =
            cannedIssueMenuItem(
                api,
                tab,
                mcpSupervisor,
                issues,
                label = "Analyze this issue",
                actionName = "Issue Analysis",
            ) { it.issueAnalyzePrompt }
        val poc =
            cannedIssueMenuItem(
                api,
                tab,
                mcpSupervisor,
                issues,
                label = "Generate PoC & validate",
                actionName = "PoC & Validation",
            ) { it.issuePocPrompt }
        val impact =
            cannedIssueMenuItem(
                api,
                tab,
                mcpSupervisor,
                issues,
                label = "Impact & severity",
                actionName = "Impact & Severity",
            ) { it.issueImpactPrompt }
        val fullReport =
            cannedIssueMenuItem(
                api,
                tab,
                mcpSupervisor,
                issues,
                label = "Full report",
                actionName = "Full Vuln Report",
            ) { it.issuePromptTemplate }

        val customPromptsMenu = buildIssueCustomPromptsMenu(api, tab, mcpSupervisor, issues)
        return listOf(analyze, poc, impact, fullReport, customPromptsMenu)
    }

    /** Builds a canned scanner-issue menu item that stamps audit metadata with SCANNER_ISSUE. */
    private fun cannedIssueMenuItem(
        api: MontoyaApi,
        tab: MainTab,
        mcpSupervisor: McpSupervisor,
        issues: List<AuditIssue>,
        label: String,
        actionName: String,
        promptSelector: (AgentSettings) -> String,
    ): JMenuItem {
        val item = JMenuItem(label)
        item.addActionListener {
            if (!ensureMcpRunning(tab, mcpSupervisor)) return@addActionListener
            val collector = ContextCollector(api)
            val settings = tab.currentSettings()
            val ctx = collector.fromAuditIssues(issues, contextOptionsFromSettings(settings))
            if (!confirmContextPreview(tab, actionName, ctx)) return@addActionListener
            tab.openChatWithContext(
                ctx,
                PromptLaunchSpec(
                    promptText = promptSelector(settings),
                    actionName = actionName,
                    source = PromptSource.FIXED,
                    contextKind = ContextKind.SCANNER_ISSUE,
                ),
            )
        }
        return item
    }

    private fun buildHttpCustomPromptsMenu(
        api: MontoyaApi,
        tab: MainTab,
        mcpSupervisor: McpSupervisor,
        targets: List<HttpRequestResponse>,
        targetLabel: String,
    ): JMenu {
        val menu = JMenu("Custom prompts ($targetLabel)")
        val settings = tab.currentSettings()
        val relevant =
            CustomPromptDefinition.filterForMenu(
                settings.customPromptLibrary,
                CustomPromptTag.HTTP_SELECTION,
            )
        relevant.forEach { def ->
            val item = JMenuItem(truncateLabel(def.title, 50))
            item.addActionListener {
                runCustomPromptHttp(api, tab, mcpSupervisor, targets, def.promptText, def.id, def.title)
            }
            menu.add(item)
        }
        if (relevant.isNotEmpty()) menu.addSeparator()
        val custom = JMenuItem("Custom…")
        custom.addActionListener {
            val prompt = CustomPromptDialog.ask(tab.root, targetLabel, relevant) ?: return@addActionListener
            runCustomPromptHttp(api, tab, mcpSupervisor, targets, prompt, customId = null, customTitle = null)
        }
        menu.add(custom)
        return menu
    }

    private fun buildIssueCustomPromptsMenu(
        api: MontoyaApi,
        tab: MainTab,
        mcpSupervisor: McpSupervisor,
        issues: List<AuditIssue>,
    ): JMenu {
        val menu = JMenu("Custom prompts")
        val settings = tab.currentSettings()
        val relevant =
            CustomPromptDefinition.filterForMenu(
                settings.customPromptLibrary,
                CustomPromptTag.SCANNER_ISSUE,
            )
        relevant.forEach { def ->
            val item = JMenuItem(truncateLabel(def.title, 50))
            item.addActionListener {
                runCustomPromptIssue(api, tab, mcpSupervisor, issues, def.promptText, def.id, def.title)
            }
            menu.add(item)
        }
        if (relevant.isNotEmpty()) menu.addSeparator()
        val issueLabel = if (issues.size == 1) "1 issue" else "${issues.size} issues"
        val custom = JMenuItem("Custom…")
        custom.addActionListener {
            val prompt = CustomPromptDialog.ask(tab.root, issueLabel, relevant) ?: return@addActionListener
            runCustomPromptIssue(api, tab, mcpSupervisor, issues, prompt, customId = null, customTitle = null)
        }
        menu.add(custom)
        return menu
    }

    private fun runCustomPromptHttp(
        api: MontoyaApi,
        tab: MainTab,
        mcpSupervisor: McpSupervisor,
        targets: List<HttpRequestResponse>,
        promptText: String,
        customId: String?,
        customTitle: String?,
    ) {
        if (!ensureMcpRunning(tab, mcpSupervisor)) return
        val collector = ContextCollector(api)
        val settings = tab.currentSettings()
        val ctx = collector.fromRequestResponses(targets, contextOptionsFromSettings(settings))
        // No confirmContextPreview: the exact-send preview inside ChatPanel is authoritative.
        val actionName = if (customTitle != null) "Custom: $customTitle" else "Custom prompt"
        val source = if (customId != null) PromptSource.CUSTOM_SAVED else PromptSource.CUSTOM_AD_HOC
        tab.openChatWithContext(
            ctx,
            PromptLaunchSpec(
                promptText = promptText,
                actionName = actionName,
                source = source,
                contextKind = ContextKind.HTTP_SELECTION,
                customPromptId = customId,
                customPromptTitle = customTitle,
            ),
        )
    }

    private fun runCustomPromptIssue(
        api: MontoyaApi,
        tab: MainTab,
        mcpSupervisor: McpSupervisor,
        issues: List<AuditIssue>,
        promptText: String,
        customId: String?,
        customTitle: String?,
    ) {
        if (!ensureMcpRunning(tab, mcpSupervisor)) return
        val collector = ContextCollector(api)
        val settings = tab.currentSettings()
        val ctx = collector.fromAuditIssues(issues, contextOptionsFromSettings(settings))
        val actionName = if (customTitle != null) "Custom: $customTitle" else "Custom prompt"
        val source = if (customId != null) PromptSource.CUSTOM_SAVED else PromptSource.CUSTOM_AD_HOC
        tab.openChatWithContext(
            ctx,
            PromptLaunchSpec(
                promptText = promptText,
                actionName = actionName,
                source = source,
                contextKind = ContextKind.SCANNER_ISSUE,
                customPromptId = customId,
                customPromptTitle = customTitle,
            ),
        )
    }

    private fun truncateLabel(
        value: String,
        max: Int,
    ): String = if (value.length <= max) value else value.take(max - 1) + "…"

    private fun buildBountyPromptMenu(
        api: MontoyaApi,
        tab: MainTab,
        mcpSupervisor: McpSupervisor,
        targets: List<HttpRequestResponse>,
        audit: AuditLogger?,
    ): JMenu {
        val settings = tab.currentSettings()
        val menu = JMenu("BountyPrompt")

        if (!settings.bountyPromptEnabled) {
            menu.isEnabled = false
            menu.toolTipText = "Enable BountyPrompt integration in Settings → Prompt Templates."
            return menu
        }

        val loaded =
            bountyPromptLoader.loadFromDirectory(
                settings.bountyPromptDir,
                settings.bountyPromptEnabledPromptIds,
            )
        loaded.errors.forEach { error ->
            api.logging().logToError("[BountyPrompt] $error")
        }

        if (loaded.prompts.isEmpty()) {
            menu.isEnabled = false
            menu.toolTipText = "No curated prompts available from: ${settings.bountyPromptDir}"
            return menu
        }

        val categories = loaded.prompts.groupBy { it.category }
        for (category in BountyPromptCategory.entries) {
            val prompts = categories[category].orEmpty().sortedBy { it.title.lowercase() }
            if (prompts.isEmpty()) continue
            val categoryMenu = JMenu(categoryLabel(category))
            for (definition in prompts) {
                val item = JMenuItem("${definition.title} (${targets.size})")
                item.addActionListener {
                    if (!ensureMcpRunning(tab, mcpSupervisor)) return@addActionListener
                    val current = tab.currentSettings()
                    val resolved =
                        bountyPromptResolver.resolve(
                            definition,
                            targets,
                            contextOptionsFromSettings(current),
                        )
                    val composedPrompt = composeBountyPrompt(definition, resolved.resolvedUserPrompt)
                    val capture =
                        ContextCapture(
                            contextJson = "",
                            previewText = resolved.previewText,
                        )

                    audit?.logEvent(
                        "bountyprompt_action_invoked",
                        mapOf(
                            "promptId" to definition.id,
                            "promptTitle" to definition.title,
                            "targets" to targets.size.toString(),
                            "privacyMode" to current.privacyMode.name,
                            "backendId" to current.preferredBackendId,
                        ),
                    )

                    tab.openChatWithContext(
                        capture = capture,
                        promptTemplate = composedPrompt,
                        actionName = "BountyPrompt: ${definition.title}",
                        onCompleted = { response, error ->
                            if (error != null) {
                                audit?.logEvent(
                                    "bountyprompt_completion_error",
                                    mapOf(
                                        "promptId" to definition.id,
                                        "error" to (error.message ?: "unknown"),
                                    ),
                                )
                                return@openChatWithContext
                            }
                            handleBountyPromptCompletion(
                                api = api,
                                tab = tab,
                                definition = definition,
                                responseText = response,
                                targets = targets,
                                audit = audit,
                            )
                        },
                    )
                }
                categoryMenu.add(item)
            }
            menu.add(categoryMenu)
        }

        menu.toolTipText = "Curated BountyPrompt actions"
        return menu
    }

    private fun composeBountyPrompt(
        definition: BountyPromptDefinition,
        resolvedUserPrompt: String,
    ): String =
        """
System Instructions (highest priority):
${definition.systemPrompt}

User Task:
$resolvedUserPrompt
        """.trim()

    private fun handleBountyPromptCompletion(
        api: MontoyaApi,
        tab: MainTab,
        definition: BountyPromptDefinition,
        responseText: String,
        targets: List<HttpRequestResponse>,
        audit: AuditLogger?,
    ) {
        val settings = tab.currentSettings()

        if (definition.outputType != BountyPromptOutputType.ISSUE) {
            audit?.logEvent(
                "bountyprompt_completion_output_only",
                mapOf("promptId" to definition.id),
            )
            return
        }

        if (!settings.bountyPromptAutoCreateIssues) {
            audit?.logEvent(
                "bountyprompt_issue_creation_skipped",
                mapOf("promptId" to definition.id, "reason" to "auto-create disabled"),
            )
            return
        }

        val findings = bountyPromptOutputParser.parse(responseText, definition)
        if (findings.isEmpty()) {
            audit?.logEvent(
                "bountyprompt_issue_creation_skipped",
                mapOf("promptId" to definition.id, "reason" to "no findings"),
            )
            return
        }

        var created = 0
        var skippedByThreshold = 0
        val threshold = settings.bountyPromptIssueConfidenceThreshold.coerceIn(0, 100)
        val requestResponses = targets.take(20)
        if (requestResponses.isEmpty()) {
            api.logging().logToError("[BountyPrompt] No targets selected - skipping issue creation for ${definition.title}")
            return
        }

        for (finding in findings) {
            if (finding.confidence < threshold) {
                skippedByThreshold++
                continue
            }

            val issueName = "[AI][BountyPrompt] ${finding.title.ifBlank { definition.title }.take(140)}"
            val baseUrl =
                requestResponses
                    .firstOrNull()
                    ?.request()
                    ?.url()
                    .orEmpty()
            if (baseUrl.isNotBlank() && hasExistingIssue(api, issueName, baseUrl)) continue

            val issue =
                runCatching {
                    AuditIssue.auditIssue(
                        issueName,
                        buildIssueDetailHtml(definition, finding),
                        "Validate manually before reporting externally.",
                        baseUrl,
                        mapSeverity(finding.severity),
                        mapConfidence(finding.confidence),
                        null,
                        null,
                        mapSeverity(finding.severity),
                        requestResponses,
                    )
                }.getOrNull() ?: continue

            runCatching {
                api.siteMap().add(issue)
                created++
            }.onFailure { err ->
                api.logging().logToError("[BountyPrompt] Failed creating issue: ${err.message}")
            }
        }

        audit?.logEvent(
            "bountyprompt_issue_result",
            mapOf(
                "promptId" to definition.id,
                "created" to created.toString(),
                "skippedThreshold" to skippedByThreshold.toString(),
                "threshold" to threshold.toString(),
                "findings" to findings.size.toString(),
            ),
        )

        if (created == 0 && skippedByThreshold == 0) return

        SwingUtilities.invokeLater {
            val msg =
                buildString {
                    append("BountyPrompt completed for '${definition.title}'.\n")
                    append("Issues created: $created")
                    if (skippedByThreshold > 0) {
                        append("\nSkipped by confidence threshold ($threshold): $skippedByThreshold")
                    }
                }
            JOptionPane.showMessageDialog(
                tab.root,
                msg,
                "BountyPrompt",
                JOptionPane.INFORMATION_MESSAGE,
            )
        }
    }

    private fun buildIssueDetailHtml(
        definition: BountyPromptDefinition,
        finding: com.six2dez.burp.aiagent.prompts.bountyprompt.BountyPromptFinding,
    ): String {
        val detail = IssueText.sanitize(finding.detail)
        val lines = mutableListOf<String>()
        lines.addAll(detail.lines())
        lines.add("")
        lines.add("AI Analysis Metadata")
        lines.add("  Source: BountyPrompt")
        lines.add("  Prompt ID: ${definition.id}")
        lines.add("  Prompt Title: ${definition.title}")
        lines.add("  Configured Confidence: ${definition.confidence.name}")
        lines.add("  Parsed Confidence: ${finding.confidence}%")
        val timestamp =
            java.time.Instant
                .now()
                .toString()
                .replace('T', ' ')
                .substringBefore('.')
        lines.add("  Analysis Date: $timestamp UTC")

        return lines.joinToString("<br>") { line ->
            val escaped =
                line
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

    private fun mapSeverity(raw: String): AuditIssueSeverity =
        when (raw.trim().lowercase()) {
            "high" -> AuditIssueSeverity.HIGH
            "medium" -> AuditIssueSeverity.MEDIUM
            "low" -> AuditIssueSeverity.LOW
            else -> AuditIssueSeverity.INFORMATION
        }

    private fun mapConfidence(confidence: Int): AuditIssueConfidence =
        when {
            confidence >= 95 -> AuditIssueConfidence.CERTAIN
            confidence >= 90 -> AuditIssueConfidence.FIRM
            else -> AuditIssueConfidence.TENTATIVE
        }

    private fun hasExistingIssue(
        api: MontoyaApi,
        name: String,
        baseUrl: String,
    ): Boolean =
        IssueUtils.hasEquivalentIssue(
            name = name,
            baseUrl = baseUrl,
            issues = api.siteMap().issues().map { issue -> issue.name() to issue.baseUrl() },
        )

    private fun categoryLabel(category: BountyPromptCategory): String =
        when (category) {
            BountyPromptCategory.DETECTION -> "Detection"
            BountyPromptCategory.RECON -> "Recon"
            BountyPromptCategory.ADVISORY -> "Advisory"
        }

    private fun ensureMcpRunning(
        tab: MainTab,
        mcpSupervisor: McpSupervisor,
    ): Boolean {
        if (mcpSupervisor.status() is McpServerState.Running) return true
        JOptionPane.showMessageDialog(
            tab.root,
            "Enable MCP Server to use AI features.",
            "Custom AI Agent",
            JOptionPane.WARNING_MESSAGE,
        )
        return false
    }

    private fun confirmContextPreview(
        tab: MainTab,
        actionName: String,
        capture: ContextCapture,
    ): Boolean {
        if (!contextPreviewEnabled) return true
        val redactedExcerpt =
            capture.contextJson.trim().let { json ->
                if (json.isBlank()) {
                    "(empty context)"
                } else if (json.length <= 1200) {
                    json
                } else {
                    json.take(1200) + "\n...[truncated]..."
                }
            }
        val previewText =
            buildString {
                appendLine("Action: $actionName")
                appendLine()
                appendLine(capture.previewText.trim())
                appendLine()
                appendLine("Context JSON excerpt:")
                append(redactedExcerpt)
            }
        val previewArea =
            JTextArea(previewText, 20, 72).apply {
                isEditable = false
                lineWrap = true
                wrapStyleWord = true
                font = UiTheme.Typography.mono
                caretPosition = 0
            }
        val keepPreview = JCheckBox("Show preview before send", contextPreviewEnabled)
        val panel =
            JPanel(BorderLayout(0, 8)).apply {
                add(JScrollPane(previewArea), BorderLayout.CENTER)
                add(keepPreview, BorderLayout.SOUTH)
            }
        val decision =
            JOptionPane.showConfirmDialog(
                tab.root,
                panel,
                "Context Preview",
                JOptionPane.YES_NO_OPTION,
                JOptionPane.PLAIN_MESSAGE,
            )
        contextPreviewEnabled = keepPreview.isSelected
        return decision == JOptionPane.YES_OPTION
    }

    private fun contextOptionsFromSettings(settings: AgentSettings): ContextOptions =
        ContextOptions(
            privacyMode = settings.privacyMode,
            deterministic = settings.determinismMode,
            hostSalt = settings.hostAnonymizationSalt,
            maxRequestBodyChars = settings.contextRequestBodyMaxChars,
            maxResponseBodyChars = settings.contextResponseBodyMaxChars,
            compactJson = settings.contextCompactJson,
        )

    private fun ensureActiveScannerEnabled(
        tab: MainTab,
        activeAiScanner: ActiveAiScanner?,
    ): Boolean {
        if (activeAiScanner == null) {
            JOptionPane.showMessageDialog(tab.root, "Active Scanner not available.", "Custom AI Agent", JOptionPane.WARNING_MESSAGE)
            return false
        }
        if (!activeAiScanner.isEnabled()) {
            val enable =
                JOptionPane.showConfirmDialog(
                    tab.root,
                    "Active Scanner is disabled. Enable it now?",
                    "Custom AI Agent",
                    JOptionPane.YES_NO_OPTION,
                )
            if (enable == JOptionPane.YES_OPTION) {
                activeAiScanner.setEnabled(true)
            } else {
                return false
            }
        }
        return true
    }

    private fun buildTargetedTestsMenu(
        tab: MainTab,
        targets: List<HttpRequestResponse>,
        activeAiScanner: ActiveAiScanner?,
        targetLabel: String = "${targets.size}",
    ): JMenu {
        val menu = JMenu("Targeted tests")

        val definitions =
            listOf(
                "SQLi" to listOf(VulnClass.SQLI),
                "XSS (Reflected)" to listOf(VulnClass.XSS_REFLECTED),
                "XSS (Stored)" to listOf(VulnClass.XSS_STORED),
                "XSS (DOM)" to listOf(VulnClass.XSS_DOM),
                "SSRF" to listOf(VulnClass.SSRF),
                "IDOR / BOLA" to listOf(VulnClass.IDOR, VulnClass.BOLA),
                "Path Traversal / LFI" to listOf(VulnClass.PATH_TRAVERSAL, VulnClass.LFI),
                "Command Injection" to listOf(VulnClass.CMDI),
                "SSTI" to listOf(VulnClass.SSTI),
                "XXE" to listOf(VulnClass.XXE),
                "Open Redirect" to listOf(VulnClass.OPEN_REDIRECT),
            )

        for ((label, classes) in definitions) {
            val item = JMenuItem("$label ($targetLabel)")
            item.addActionListener {
                if (!ensureActiveScannerEnabled(tab, activeAiScanner)) return@addActionListener
                val scanner = activeAiScanner ?: return@addActionListener
                val validTargets = filterValidTargets(targets)
                if (validTargets.isEmpty()) {
                    JOptionPane.showMessageDialog(
                        tab.root,
                        "No valid HTTP targets found for active scan.",
                        "AI Targeted Test",
                        JOptionPane.WARNING_MESSAGE,
                    )
                    return@addActionListener
                }
                val preQueue = scanner.getStatus().queueSize
                val confirmed =
                    JOptionPane.showConfirmDialog(
                        tab.root,
                        "This will run '$label' active tests on ${validTargets.size} target(s).\n" +
                            "Current queue: $preQueue\n\n" +
                            "Do you want to continue?",
                        "Confirm Targeted Active Test",
                        JOptionPane.YES_NO_OPTION,
                        JOptionPane.WARNING_MESSAGE,
                    )
                if (confirmed != JOptionPane.YES_OPTION) return@addActionListener
                val count = scanner.manualScan(validTargets, classes)
                val postQueue = scanner.getStatus().queueSize
                if (count == 0) {
                    JOptionPane.showMessageDialog(
                        tab.root,
                        "No targets were queued. The active scan queue may be full (max ${scanner.maxQueueSize}) or targets were filtered out.",
                        "AI Targeted Test",
                        JOptionPane.WARNING_MESSAGE,
                    )
                    return@addActionListener
                }
                JOptionPane.showMessageDialog(
                    tab.root,
                    "Queued $count target(s) for AI active testing: $label.\n\n" +
                        "Queue size: $preQueue -> $postQueue\n" +
                        "Queue max: ${scanner.maxQueueSize}\n" +
                        "This will send test payloads to the server.\n" +
                        "Confirmed findings will appear in Target → Issues with [AI] Confirmed prefix.",
                    "AI Targeted Test Started",
                    JOptionPane.INFORMATION_MESSAGE,
                )
            }
            menu.add(item)
        }

        menu.addSeparator()

        val customItem = JMenuItem("Custom... ($targetLabel)")
        customItem.addActionListener {
            if (!ensureActiveScannerEnabled(tab, activeAiScanner)) return@addActionListener
            val scanner = activeAiScanner ?: return@addActionListener
            val validTargets = filterValidTargets(targets)
            if (validTargets.isEmpty()) {
                JOptionPane.showMessageDialog(tab.root, "No valid HTTP targets found.", "AI Targeted Test", JOptionPane.WARNING_MESSAGE)
                return@addActionListener
            }
            val selected = showVulnClassSelectionDialog(tab) ?: return@addActionListener
            if (selected.isEmpty()) return@addActionListener
            val label = if (selected.size <= 3) selected.joinToString(", ") { it.name } else "${selected.size} vulnerability classes"
            val preQueue = scanner.getStatus().queueSize
            val confirmed =
                JOptionPane.showConfirmDialog(
                    tab.root,
                    "This will run custom active tests ($label) on ${validTargets.size} target(s).\nCurrent queue: $preQueue\n\nDo you want to continue?",
                    "Confirm Custom Targeted Test",
                    JOptionPane.YES_NO_OPTION,
                    JOptionPane.WARNING_MESSAGE,
                )
            if (confirmed != JOptionPane.YES_OPTION) return@addActionListener
            val count = scanner.manualScan(validTargets, selected)
            if (count == 0) {
                JOptionPane.showMessageDialog(tab.root, "No targets were queued.", "AI Targeted Test", JOptionPane.WARNING_MESSAGE)
                return@addActionListener
            }
            JOptionPane.showMessageDialog(
                tab.root,
                "Queued $count target(s) for custom AI active testing.\nQueue size: $preQueue -> ${scanner.getStatus().queueSize}",
                "AI Targeted Test Started",
                JOptionPane.INFORMATION_MESSAGE,
            )
        }
        menu.add(customItem)

        return menu
    }

    private fun showVulnClassSelectionDialog(tab: MainTab): List<VulnClass>? {
        val checkboxes =
            VulnClass.entries.map { vc ->
                JCheckBox(
                    vc.name
                        .replace('_', ' ')
                        .lowercase()
                        .replaceFirstChar { it.uppercase() },
                ).apply {
                    actionCommand = vc.name
                    font = UiTheme.Typography.body
                }
            }
        val panel = JPanel(BorderLayout())
        val grid = JPanel(GridLayout(0, 3, 4, 2))
        checkboxes.forEach { grid.add(it) }
        val scroll = JScrollPane(grid)
        scroll.preferredSize = java.awt.Dimension(600, 400)
        panel.add(scroll, BorderLayout.CENTER)

        val selectPanel = JPanel()
        selectPanel.layout = BoxLayout(selectPanel, BoxLayout.X_AXIS)
        val selectAll = javax.swing.JButton("Select All")
        val deselectAll = javax.swing.JButton("Deselect All")
        selectAll.addActionListener { checkboxes.forEach { it.isSelected = true } }
        deselectAll.addActionListener { checkboxes.forEach { it.isSelected = false } }
        selectPanel.add(selectAll)
        selectPanel.add(javax.swing.Box.createRigidArea(java.awt.Dimension(8, 0)))
        selectPanel.add(deselectAll)
        panel.add(selectPanel, BorderLayout.SOUTH)

        val result =
            JOptionPane.showConfirmDialog(
                tab.root,
                panel,
                "Select vulnerability classes to test",
                JOptionPane.OK_CANCEL_OPTION,
                JOptionPane.PLAIN_MESSAGE,
            )
        if (result != JOptionPane.OK_OPTION) return null
        return checkboxes.filter { it.isSelected }.map { VulnClass.valueOf(it.actionCommand) }
    }

    private fun filterValidTargets(targets: List<HttpRequestResponse>): List<HttpRequestResponse> =
        targets.filter { rr ->
            try {
                rr.request().url().isNotBlank()
            } catch (_: Exception) {
                false
            }
        }
}
