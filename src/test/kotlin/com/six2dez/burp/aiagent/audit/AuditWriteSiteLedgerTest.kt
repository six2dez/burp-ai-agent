package com.six2dez.burp.aiagent.audit

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import java.io.File

/**
 * Quick 261008-sqa — every audit write site in `src/main/kotlin`, pinned.
 *
 * Field classes: C = credential (never written, in either mode); B = body (digest pair
 * `<name>Sha256` + `<name>Utf8Bytes` always, the body only under Verbose audit); M = metadata (always).
 *
 * - AgentSupervisor `session_start` / `session_stop`: backendId, sessionId, model, displayName, note: M.
 * - AgentSupervisor `prompt` (audit.jsonl) + bundles/ (send, sendChat): ids, modes, promptSource, promptId,
 *   promptTitle, contextKind, verbose: M; promptText, contextJson: B; backendConfig is the
 *   AuditBackendConfig allowlist (header values, env values, baseUrl userinfo / query / fragment,
 *   command, cliSessionId: C).
 * - AgentSupervisor `agent_chunk`: backendId: M; chunk: B.
 * - AgentSupervisor `prompt_complete`: backendId, status, errorClass: M; error: B.
 * - PassiveAiScannerAnalysis `passive_ai_scan_cache_hit`, `passive_ai_scan`: url in endpoint form (its
 *   query is a C carrier); method, status, promptChars, issues, responseChars: M.
 * - PassiveAiScannerFinding `passive_ai_issue`: title, severity, confidence, source: M; url in endpoint form.
 * - ActiveAiScanner `active_scan_confirmed`: vuln_class, confidence: M; url in endpoint form; payload: B.
 * - UiActions `bountyprompt_action_invoked`, `_output_only`, `_issue_creation_skipped`, `_issue_result`:
 *   ids, targets, privacyMode, backendId, counts, constant reasons: M.
 * - UiActions `bountyprompt_completion_error`: promptId, errorClass: M; error: B.
 * - ChatPanel, PassiveAiScannerAnalysis, McpToolContext `secret_tripwire_allow` / `_detect`: path,
 *   sessionId, shapeCategories, entropyScore: M (the matched value is never present).
 * - ExternalMcpClientManager `external_mcp_call`: server, tool, status, errorClass: M; error: B.
 * - McpTool `mcp_tool_blocked` / `_start` / `_end`: tool, toolType, hasArgs, argsSha256 (a digest), reason,
 *   outcome, errorType, durationMs, outputChars: M.
 * - McpBlockedRequestReporter `mcp_transport_blocked`: reason, mode, method, path, suppressed: M; origin,
 *   host, referer, userAgent: remote header values, SHA-256 in both modes.
 * - ToolDecisionReporter `mcp_tool_decision`: decision metadata: M; args: B, in the audit event only.
 * - App: the global emitter routing to AuditLogger.logEvent (routing only).
 * - AuditLogger: the two declarations, plus the uncalled contexts/ and bundle zip writers (contextJson: B,
 *   written only with audit logging and verbose on).
 *
 * A new audit write site turns [everyAuditWriteSiteIsInTheLedger] red. Its author must classify every
 * field of the new record in the table above before raising the count.
 */
class AuditWriteSiteLedgerTest {
    @Test
    fun everyAuditWriteSiteIsInTheLedger() {
        val root = File(MAIN_SOURCE_ROOT)
        assertTrue(root.isDirectory, "Expected `$MAIN_SOURCE_ROOT` under `${System.getProperty("user.dir")}`.")
        val measured =
            root
                .walkTopDown()
                .filter { it.isFile && it.extension == "kt" }
                .associate { file ->
                    val code = codeLinesOf(file)
                    file.relativeTo(root).invariantSeparatorsPath to
                        Pair(occurrences(code, "logEvent("), occurrences(code, "emitGlobal("))
                }.filterValues { it != Pair(0, 0) }
        assertEquals(EXPECTED_WRITE_SITES, measured.toSortedMap())
    }

    @Test
    fun scannerTargetUrlsGoThroughEndpointOf() {
        val measured =
            ENDPOINT_ROUTING.mapValues { (path, _) ->
                occurrences(codeLinesOf(File(MAIN_SOURCE_ROOT, path)), "AuditLogger.endpointOf(")
            }
        assertEquals(ENDPOINT_ROUTING, measured, "AuditLogger.endpointOf( call sites per scanner file")
    }

    @Test
    fun bodiesAndErrorsGoThroughTheVerboseHelpers() {
        val measured =
            BODY_ROUTING.mapValues { (site, _) ->
                occurrences(codeLinesOf(File(MAIN_SOURCE_ROOT, site.first)), site.second)
            }
        assertEquals(BODY_ROUTING, measured, "verbose-helper call sites per (file, token)")
    }

    private fun occurrences(
        lines: List<String>,
        token: String,
    ): Int = lines.sumOf { line -> line.windowed(token.length).count { it == token } }

    /** Non-comment lines: a line-comment marker, a continuation asterisk or a block opener first. */
    private fun codeLinesOf(file: File): List<String> =
        file.readText(Charsets.UTF_8).lines().filterNot { line ->
            val trimmed = line.trimStart()
            trimmed.startsWith("//") || trimmed.startsWith("*") || trimmed.startsWith("/*")
        }

    private companion object {
        const val MAIN_SOURCE_ROOT = "src/main/kotlin"
        const val PKG = "com/six2dez/burp/aiagent"

        /** (logEvent call sites, emitGlobal call sites) per file; AuditLogger's are its declarations. */
        val EXPECTED_WRITE_SITES =
            sortedMapOf(
                "$PKG/App.kt" to Pair(1, 0),
                "$PKG/audit/AuditLogger.kt" to Pair(1, 1),
                "$PKG/mcp/McpBlockedRequestReporter.kt" to Pair(0, 1),
                "$PKG/mcp/McpToolContext.kt" to Pair(0, 1),
                "$PKG/mcp/ToolDecisionReporter.kt" to Pair(0, 1),
                "$PKG/mcp/external/ExternalMcpClientManager.kt" to Pair(0, 2),
                "$PKG/mcp/tools/McpTool.kt" to Pair(0, 1),
                "$PKG/scanner/ActiveAiScanner.kt" to Pair(1, 0),
                "$PKG/scanner/PassiveAiScannerAnalysis.kt" to Pair(2, 3),
                "$PKG/scanner/PassiveAiScannerFinding.kt" to Pair(1, 0),
                "$PKG/supervisor/AgentSupervisor.kt" to Pair(9, 0),
                "$PKG/ui/ChatPanel.kt" to Pair(0, 1),
                "$PKG/ui/UiActions.kt" to Pair(6, 0),
            )

        val ENDPOINT_ROUTING =
            mapOf(
                "$PKG/scanner/PassiveAiScannerAnalysis.kt" to 2,
                "$PKG/scanner/PassiveAiScannerFinding.kt" to 1,
                "$PKG/scanner/ActiveAiScanner.kt" to 1,
            )

        val BODY_ROUTING =
            mapOf(
                Pair("$PKG/scanner/ActiveAiScanner.kt", "bodyFields(\"payload\"") to 1,
                Pair("$PKG/supervisor/AgentSupervisor.kt", "bodyFields(\"chunk\"") to 2,
                Pair("$PKG/supervisor/AgentSupervisor.kt", "errorFields(") to 2,
                Pair("$PKG/ui/UiActions.kt", "errorFields(") to 1,
                Pair("$PKG/mcp/external/ExternalMcpClientManager.kt", "errorFields(") to 1,
            )
    }
}
