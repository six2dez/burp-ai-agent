package com.six2dez.burp.aiagent.ui

import burp.api.montoya.MontoyaApi
import burp.api.montoya.http.message.HttpRequestResponse
import burp.api.montoya.scanner.audit.issues.AuditIssue
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity
import burp.api.montoya.ui.contextmenu.AuditIssueContextMenuEvent
import burp.api.montoya.ui.contextmenu.ContextMenuEvent
import com.six2dez.burp.aiagent.audit.AuditLogger
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
import com.six2dez.burp.aiagent.scanner.PassiveAiScanner
import com.six2dez.burp.aiagent.scanner.VulnClass
import com.six2dez.burp.aiagent.util.IssueText
import javax.swing.JMenu
import javax.swing.JMenuItem
import javax.swing.JOptionPane
import javax.swing.SwingUtilities

object UiActions {

    private val bountyPromptLoader = BountyPromptLoader()
    private val bountyPromptResolver = BountyPromptTagResolver()
    private val bountyPromptOutputParser = BountyPromptOutputParser()

    fun requestResponseMenuItems(
        api: MontoyaApi,
        event: ContextMenuEvent,
        tab: MainTab,
        mcpSupervisor: McpSupervisor,
        passiveAiScanner: PassiveAiScanner,
        activeAiScanner: ActiveAiScanner? = null,
        audit: AuditLogger? = null
    ): List<JMenuItem> {
        val selected = event.selectedRequestResponses()
        val editorSelection = event.messageEditorRequestResponse().map { it.requestResponse() }
        val targets = if (selected.isNotEmpty()) {
            selected
        } else {
            editorSelection.map { listOf(it) }.orElse(emptyList())
        }
        if (targets.isEmpty()) return emptyList()

        // AI Vulnerability Scan option (Passive)
        val aiScan = JMenuItem("🔍 AI Passive Scan (${targets.size})")
        aiScan.addActionListener {
            val count = passiveAiScanner.manualScan(targets)
            JOptionPane.showMessageDialog(
                tab.root,
                "Queued $count request(s) for AI passive analysis.\n\nFindings will appear in Target → Issues with [AI] prefix.",
                "AI Passive Scan Started",
                JOptionPane.INFORMATION_MESSAGE
            )
        }

        // AI Active Scan option
        val aiActiveScan = JMenuItem("⚡ AI Active Scan (${targets.size})")
        aiActiveScan.addActionListener {
            if (!ensureActiveScannerEnabled(tab, activeAiScanner)) return@addActionListener
            val scanner = activeAiScanner ?: return@addActionListener
            val validTargets = filterValidTargets(targets)
            if (validTargets.isEmpty()) {
                JOptionPane.showMessageDialog(
                    tab.root,
                    "No valid HTTP targets found for active scan.",
                    "AI Active Scan",
                    JOptionPane.WARNING_MESSAGE
                )
                return@addActionListener
            }
            val preQueue = scanner.getStatus().queueSize
            val confirmed = JOptionPane.showConfirmDialog(
                tab.root,
                "This will send active test payloads to ${validTargets.size} target(s).\n" +
                    "Current queue: $preQueue\n\n" +
                    "Do you want to continue?",
                "Confirm AI Active Scan",
                JOptionPane.YES_NO_OPTION,
                JOptionPane.WARNING_MESSAGE
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
                    JOptionPane.WARNING_MESSAGE
                )
                return@addActionListener
            }
            JOptionPane.showMessageDialog(
                tab.root,
                "Queued $count target(s) for AI active testing.\n\n" +
                    "Queue size: $preQueue -> $postQueue\n" +
                    "Queue max: ${scanner.maxQueueSize}\n" +
                    "⚠️ This will send test payloads to the server.\n" +
                    "Confirmed findings will appear in Target → Issues with [AI] Confirmed prefix.",
                "AI Active Scan Started",
                JOptionPane.INFORMATION_MESSAGE
            )
        }

        val targetedTestsMenu = buildTargetedTestsMenu(tab, targets, activeAiScanner)
        val bountyPromptMenu = buildBountyPromptMenu(api, tab, mcpSupervisor, targets, audit)

        val findVulns = JMenuItem("Find vulnerabilities")
        findVulns.addActionListener {
            if (!ensureMcpRunning(tab, mcpSupervisor)) return@addActionListener
            val collector = ContextCollector(api)
            val settings = tab.currentSettings()
            val ctx = collector.fromRequestResponses(
                targets,
                ContextOptions(
                    privacyMode = settings.privacyMode,
                    deterministic = settings.determinismMode,
                    hostSalt = settings.hostAnonymizationSalt
                )
            )
            tab.openChatWithContext(ctx, settings.requestPromptTemplate, "Find Vulnerabilities")
        }

        val analyzeRequest = JMenuItem("Analyze this request")
        analyzeRequest.addActionListener {
            if (!ensureMcpRunning(tab, mcpSupervisor)) return@addActionListener
            val collector = ContextCollector(api)
            val settings = tab.currentSettings()
            val ctx = collector.fromRequestResponses(
                targets,
                ContextOptions(
                    privacyMode = settings.privacyMode,
                    deterministic = settings.determinismMode,
                    hostSalt = settings.hostAnonymizationSalt
                )
            )
            tab.openChatWithContext(ctx, settings.requestSummaryPrompt, "Analyze this request")
        }

        val explainJs = JMenuItem("Explain JS")
        explainJs.addActionListener {
            if (!ensureMcpRunning(tab, mcpSupervisor)) return@addActionListener
            val collector = ContextCollector(api)
            val settings = tab.currentSettings()
            val ctx = collector.fromRequestResponses(
                targets,
                ContextOptions(
                    privacyMode = settings.privacyMode,
                    deterministic = settings.determinismMode,
                    hostSalt = settings.hostAnonymizationSalt
                )
            )
            tab.openChatWithContext(ctx, settings.explainJsPrompt, "Explain JS")
        }

        val accessControl = JMenuItem("Access control")
        accessControl.addActionListener {
            if (!ensureMcpRunning(tab, mcpSupervisor)) return@addActionListener
            val collector = ContextCollector(api)
            val settings = tab.currentSettings()
            val ctx = collector.fromRequestResponses(
                targets,
                ContextOptions(
                    privacyMode = settings.privacyMode,
                    deterministic = settings.determinismMode,
                    hostSalt = settings.hostAnonymizationSalt
                )
            )
            tab.openChatWithContext(ctx, settings.accessControlPrompt, "Access Control")
        }

        val login = JMenuItem("Login sequence")
        login.addActionListener {
            if (!ensureMcpRunning(tab, mcpSupervisor)) return@addActionListener
            val collector = ContextCollector(api)
            val settings = tab.currentSettings()
            val ctx = collector.fromRequestResponses(
                targets,
                ContextOptions(
                    privacyMode = settings.privacyMode,
                    deterministic = settings.determinismMode,
                    hostSalt = settings.hostAnonymizationSalt
                )
            )
            tab.openChatWithContext(ctx, settings.loginSequencePrompt, "Login Sequence")
        }

        return listOf(
            aiScan,
            aiActiveScan,
            targetedTestsMenu,
            bountyPromptMenu,
            findVulns,
            analyzeRequest,
            explainJs,
            accessControl,
            login
        )
    }

    fun auditIssueMenuItems(
        api: MontoyaApi,
        event: AuditIssueContextMenuEvent,
        tab: MainTab,
        mcpSupervisor: McpSupervisor
    ): List<JMenuItem> {
        val issues = event.selectedIssues()
        if (issues.isEmpty()) return emptyList()

        val analyze = JMenuItem("Analyze this issue")
        analyze.addActionListener {
            if (!ensureMcpRunning(tab, mcpSupervisor)) return@addActionListener
            val collector = ContextCollector(api)
            val settings = tab.currentSettings()
            val ctx = collector.fromAuditIssues(
                issues,
                ContextOptions(
                    privacyMode = settings.privacyMode,
                    deterministic = settings.determinismMode,
                    hostSalt = settings.hostAnonymizationSalt
                )
            )
            tab.openChatWithContext(ctx, settings.issueAnalyzePrompt, "Issue Analysis")
        }

        val poc = JMenuItem("Generate PoC & validate")
        poc.addActionListener {
            if (!ensureMcpRunning(tab, mcpSupervisor)) return@addActionListener
            val collector = ContextCollector(api)
            val settings = tab.currentSettings()
            val ctx = collector.fromAuditIssues(
                issues,
                ContextOptions(
                    privacyMode = settings.privacyMode,
                    deterministic = settings.determinismMode,
                    hostSalt = settings.hostAnonymizationSalt
                )
            )
            tab.openChatWithContext(ctx, settings.issuePocPrompt, "PoC & Validation")
        }

        val impact = JMenuItem("Impact & severity")
        impact.addActionListener {
            if (!ensureMcpRunning(tab, mcpSupervisor)) return@addActionListener
            val collector = ContextCollector(api)
            val settings = tab.currentSettings()
            val ctx = collector.fromAuditIssues(
                issues,
                ContextOptions(
                    privacyMode = settings.privacyMode,
                    deterministic = settings.determinismMode,
                    hostSalt = settings.hostAnonymizationSalt
                )
            )
            tab.openChatWithContext(ctx, settings.issueImpactPrompt, "Impact & Severity")
        }

        val fullReport = JMenuItem("Full report")
        fullReport.addActionListener {
            if (!ensureMcpRunning(tab, mcpSupervisor)) return@addActionListener
            val collector = ContextCollector(api)
            val settings = tab.currentSettings()
            val ctx = collector.fromAuditIssues(
                issues,
                ContextOptions(
                    privacyMode = settings.privacyMode,
                    deterministic = settings.determinismMode,
                    hostSalt = settings.hostAnonymizationSalt
                )
            )
            tab.openChatWithContext(ctx, settings.issuePromptTemplate, "Full Vuln Report")
        }

        return listOf(analyze, poc, impact, fullReport)
    }

    private fun buildBountyPromptMenu(
        api: MontoyaApi,
        tab: MainTab,
        mcpSupervisor: McpSupervisor,
        targets: List<HttpRequestResponse>,
        audit: AuditLogger?
    ): JMenu {
        val settings = tab.currentSettings()
        val menu = JMenu("BountyPrompt")

        if (!settings.bountyPromptEnabled) {
            menu.isEnabled = false
            menu.toolTipText = "Enable BountyPrompt integration in Settings → Prompt Templates."
            return menu
        }

        val loaded = bountyPromptLoader.loadFromDirectory(
            settings.bountyPromptDir,
            settings.bountyPromptEnabledPromptIds
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
                    val resolved = bountyPromptResolver.resolve(
                        definition,
                        targets,
                        ContextOptions(
                            privacyMode = current.privacyMode,
                            deterministic = current.determinismMode,
                            hostSalt = current.hostAnonymizationSalt
                        )
                    )
                    val composedPrompt = composeBountyPrompt(definition, resolved.resolvedUserPrompt)
                    val capture = ContextCapture(
                        contextJson = "",
                        previewText = resolved.previewText
                    )

                    audit?.logEvent(
                        "bountyprompt_action_invoked",
                        mapOf(
                            "promptId" to definition.id,
                            "promptTitle" to definition.title,
                            "targets" to targets.size.toString(),
                            "privacyMode" to current.privacyMode.name,
                            "backendId" to current.preferredBackendId
                        )
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
                                        "error" to (error.message ?: "unknown")
                                    )
                                )
                                return@openChatWithContext
                            }
                            handleBountyPromptCompletion(
                                api = api,
                                tab = tab,
                                definition = definition,
                                responseText = response,
                                targets = targets,
                                audit = audit
                            )
                        }
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
        resolvedUserPrompt: String
    ): String {
        return """
System Instructions (highest priority):
${definition.systemPrompt}

User Task:
$resolvedUserPrompt
        """.trim()
    }

    private fun handleBountyPromptCompletion(
        api: MontoyaApi,
        tab: MainTab,
        definition: BountyPromptDefinition,
        responseText: String,
        targets: List<HttpRequestResponse>,
        audit: AuditLogger?
    ) {
        val settings = tab.currentSettings()

        if (definition.outputType != BountyPromptOutputType.ISSUE) {
            audit?.logEvent(
                "bountyprompt_completion_output_only",
                mapOf("promptId" to definition.id)
            )
            return
        }

        if (!settings.bountyPromptAutoCreateIssues) {
            audit?.logEvent(
                "bountyprompt_issue_creation_skipped",
                mapOf("promptId" to definition.id, "reason" to "auto-create disabled")
            )
            return
        }

        val findings = bountyPromptOutputParser.parse(responseText, definition)
        if (findings.isEmpty()) {
            audit?.logEvent(
                "bountyprompt_issue_creation_skipped",
                mapOf("promptId" to definition.id, "reason" to "no findings")
            )
            return
        }

        var created = 0
        var skippedByThreshold = 0
        val threshold = settings.bountyPromptIssueConfidenceThreshold.coerceIn(0, 100)
        val requestResponses = targets.take(20)

        for (finding in findings) {
            if (finding.confidence < threshold) {
                skippedByThreshold++
                continue
            }

            val issueName = "[AI][BountyPrompt] ${finding.title.ifBlank { definition.title }.take(140)}"
            val baseUrl = requestResponses.firstOrNull()?.request()?.url().orEmpty()
            if (baseUrl.isNotBlank() && hasExistingIssue(api, issueName, baseUrl)) continue

            val issue = runCatching {
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
                    requestResponses
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
                "findings" to findings.size.toString()
            )
        )

        if (created == 0 && skippedByThreshold == 0) return

        SwingUtilities.invokeLater {
            val msg = buildString {
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
                JOptionPane.INFORMATION_MESSAGE
            )
        }
    }

    private fun buildIssueDetailHtml(
        definition: BountyPromptDefinition,
        finding: com.six2dez.burp.aiagent.prompts.bountyprompt.BountyPromptFinding
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
        val timestamp = java.time.Instant.now().toString().replace('T', ' ').substringBefore('.')
        lines.add("  Analysis Date: $timestamp UTC")

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

    private fun mapSeverity(raw: String): AuditIssueSeverity {
        return when (raw.trim().lowercase()) {
            "high" -> AuditIssueSeverity.HIGH
            "medium" -> AuditIssueSeverity.MEDIUM
            "low" -> AuditIssueSeverity.LOW
            else -> AuditIssueSeverity.INFORMATION
        }
    }

    private fun mapConfidence(confidence: Int): AuditIssueConfidence {
        return when {
            confidence >= 95 -> AuditIssueConfidence.CERTAIN
            confidence >= 90 -> AuditIssueConfidence.FIRM
            else -> AuditIssueConfidence.TENTATIVE
        }
    }

    private fun hasExistingIssue(api: MontoyaApi, name: String, baseUrl: String): Boolean {
        return api.siteMap().issues().any { issue ->
            issue.baseUrl() == baseUrl && issue.name().equals(name, ignoreCase = true)
        }
    }

    private fun categoryLabel(category: BountyPromptCategory): String {
        return when (category) {
            BountyPromptCategory.DETECTION -> "Detection"
            BountyPromptCategory.RECON -> "Recon"
            BountyPromptCategory.ADVISORY -> "Advisory"
        }
    }

    private fun ensureMcpRunning(tab: MainTab, mcpSupervisor: McpSupervisor): Boolean {
        if (mcpSupervisor.status() is McpServerState.Running) return true
        JOptionPane.showMessageDialog(
            tab.root,
            "Enable MCP Server to use AI features.",
            "AI Agent",
            JOptionPane.WARNING_MESSAGE
        )
        return false
    }

    private fun ensureActiveScannerEnabled(tab: MainTab, activeAiScanner: ActiveAiScanner?): Boolean {
        if (activeAiScanner == null) {
            JOptionPane.showMessageDialog(tab.root, "Active Scanner not available.", "AI Agent", JOptionPane.WARNING_MESSAGE)
            return false
        }
        if (!activeAiScanner.isEnabled()) {
            val enable = JOptionPane.showConfirmDialog(
                tab.root,
                "Active Scanner is disabled. Enable it now?",
                "AI Agent",
                JOptionPane.YES_NO_OPTION
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
        activeAiScanner: ActiveAiScanner?
    ): JMenu {
        val menu = JMenu("Targeted tests")

        val definitions = listOf(
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
            "Open Redirect" to listOf(VulnClass.OPEN_REDIRECT)
        )

        for ((label, classes) in definitions) {
            val item = JMenuItem("⚡ $label (${targets.size})")
            item.addActionListener {
                if (!ensureActiveScannerEnabled(tab, activeAiScanner)) return@addActionListener
                val scanner = activeAiScanner ?: return@addActionListener
                val validTargets = filterValidTargets(targets)
                if (validTargets.isEmpty()) {
                    JOptionPane.showMessageDialog(
                        tab.root,
                        "No valid HTTP targets found for active scan.",
                        "AI Targeted Test",
                        JOptionPane.WARNING_MESSAGE
                    )
                    return@addActionListener
                }
                val preQueue = scanner.getStatus().queueSize
                val confirmed = JOptionPane.showConfirmDialog(
                    tab.root,
                    "This will run '$label' active tests on ${validTargets.size} target(s).\n" +
                        "Current queue: $preQueue\n\n" +
                        "Do you want to continue?",
                    "Confirm Targeted Active Test",
                    JOptionPane.YES_NO_OPTION,
                    JOptionPane.WARNING_MESSAGE
                )
                if (confirmed != JOptionPane.YES_OPTION) return@addActionListener
                val count = scanner.manualScan(validTargets, classes)
                val postQueue = scanner.getStatus().queueSize
                if (count == 0) {
                    JOptionPane.showMessageDialog(
                        tab.root,
                        "No targets were queued. The active scan queue may be full (max ${scanner.maxQueueSize}) or targets were filtered out.",
                        "AI Targeted Test",
                        JOptionPane.WARNING_MESSAGE
                    )
                    return@addActionListener
                }
                JOptionPane.showMessageDialog(
                    tab.root,
                    "Queued $count target(s) for AI active testing: $label.\n\n" +
                        "Queue size: $preQueue -> $postQueue\n" +
                        "Queue max: ${scanner.maxQueueSize}\n" +
                        "⚠️ This will send test payloads to the server.\n" +
                        "Confirmed findings will appear in Target → Issues with [AI] Confirmed prefix.",
                    "AI Targeted Test Started",
                    JOptionPane.INFORMATION_MESSAGE
                )
            }
            menu.add(item)
        }

        return menu
    }

    private fun filterValidTargets(targets: List<HttpRequestResponse>): List<HttpRequestResponse> {
        return targets.filter { rr ->
            try {
                rr.request().url().isNotBlank()
            } catch (_: Exception) {
                false
            }
        }
    }
}
