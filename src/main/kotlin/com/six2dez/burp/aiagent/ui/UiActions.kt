package com.six2dez.burp.aiagent.ui

import burp.api.montoya.MontoyaApi
import burp.api.montoya.ui.contextmenu.AuditIssueContextMenuEvent
import burp.api.montoya.ui.contextmenu.ContextMenuEvent
import com.six2dez.burp.aiagent.context.ContextCollector
import com.six2dez.burp.aiagent.context.ContextOptions
import com.six2dez.burp.aiagent.mcp.McpServerState
import com.six2dez.burp.aiagent.mcp.McpSupervisor
import com.six2dez.burp.aiagent.scanner.ActiveAiScanner
import com.six2dez.burp.aiagent.scanner.PassiveAiScanner
import com.six2dez.burp.aiagent.scanner.VulnClass
import javax.swing.JOptionPane
import javax.swing.JMenu
import javax.swing.JMenuItem

object UiActions {

    fun requestResponseMenuItems(
        api: MontoyaApi,
        event: ContextMenuEvent,
        tab: MainTab,
        mcpSupervisor: McpSupervisor,
        passiveAiScanner: PassiveAiScanner,
        activeAiScanner: ActiveAiScanner? = null
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
            if (!ensureMcpRunning(tab, mcpSupervisor)) return@addActionListener
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
            // Queue all vuln classes for manual scan
            val count = scanner.manualScan(targets, VulnClass.values().toList())
            JOptionPane.showMessageDialog(
                tab.root,
                "Queued $count target(s) for AI active testing.\n\n" +
                "⚠️ This will send test payloads to the server.\n" +
                "Confirmed findings will appear in Target → Issues with [AI] Confirmed prefix.",
                "AI Active Scan Started",
                JOptionPane.INFORMATION_MESSAGE
            )
        }

        val targetedTestsMenu = buildTargetedTestsMenu(tab, targets, activeAiScanner)

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

        return listOf(aiScan, aiActiveScan, targetedTestsMenu, findVulns, analyzeRequest, explainJs, accessControl, login)
    }

    fun auditIssueMenuItems(
        api: MontoyaApi,
        event: AuditIssueContextMenuEvent,
        tab: MainTab,
        mcpSupervisor: McpSupervisor
    ): List<JMenuItem> {
        val issues = event.selectedIssues() //  [oai_citation:6‡portswigger.github.io](https://portswigger.github.io/burp-extensions-montoya-api/javadoc/burp/api/montoya/ui/contextmenu/AuditIssueContextMenuEvent.html)
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
        targets: List<burp.api.montoya.http.message.HttpRequestResponse>,
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
                val count = scanner.manualScan(targets, classes)
                JOptionPane.showMessageDialog(
                    tab.root,
                    "Queued $count target(s) for AI active testing: $label.\n\n" +
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
}
