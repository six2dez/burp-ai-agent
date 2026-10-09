package com.six2dez.burp.aiagent.ui

import burp.api.montoya.MontoyaApi
import burp.api.montoya.persistence.Preferences
import com.fasterxml.jackson.databind.JsonNode
import com.fasterxml.jackson.databind.ObjectMapper
import com.six2dez.burp.aiagent.TestSettings
import com.six2dez.burp.aiagent.audit.AuditLogger
import com.six2dez.burp.aiagent.audit.Hashing
import com.six2dez.burp.aiagent.backends.BackendLaunchConfig
import com.six2dez.burp.aiagent.backends.BackendRegistry
import com.six2dez.burp.aiagent.config.AgentSettings
import com.six2dez.burp.aiagent.config.AgentSettingsRepository
import com.six2dez.burp.aiagent.mcp.McpSupervisor
import com.six2dez.burp.aiagent.redact.PrivacyMode
import com.six2dez.burp.aiagent.redact.Redaction
import com.six2dez.burp.aiagent.scanner.ActiveAiScanner
import com.six2dez.burp.aiagent.scanner.PassiveAiScanner
import com.six2dez.burp.aiagent.supervisor.AgentSupervisor
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertSame
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertTimeoutPreemptively
import org.junit.jupiter.api.io.TempDir
import org.mockito.Answers
import org.mockito.kotlin.any
import org.mockito.kotlin.mock
import org.mockito.kotlin.whenever
import java.awt.Component
import java.awt.Container
import java.io.File
import java.lang.reflect.InvocationTargetException
import java.nio.file.Path
import java.time.Duration
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import javax.swing.AbstractButton
import javax.swing.SwingUtilities

/**
 * Quick 261008-sqa — the Verbose audit setting end to end.
 *
 * It is persisted as `audit.verbose` with a false default for existing installs, sits in the Audit
 * logging row of Settings, follows the Unsaved changes marker, and reaches the REAL [AuditLogger] (App
 * startup and the Save body) and ChatPanel's tool-decision reporter (the applied snapshot). Fixtures are
 * copied from SettingsSingleSourceOfTruthTest, HeaderSettingsWritesTest and ChatPanelToolGateTest.
 */
class AuditVerboseSettingTest {
    @TempDir
    lateinit var root: Path

    private val panels = CopyOnWriteArrayList<SettingsPanel>()
    private val mapper = ObjectMapper()

    @BeforeEach
    fun installObservers() {
        ChatPanelTestHarness.installSettledObserver()
    }

    @AfterEach
    fun releaseFixtures() {
        AuditLogger.registerGlobalEmitter(null)
        ChatPanelTestHarness.releaseSettledObserver()
        OffEdtDispatch.registerSettledObserver(null)
        // The Save body installs custom patterns into the process-wide Redaction singleton.
        Redaction.setCustomPatterns(emptyList())
        panels.forEach { it.shutdown() }
        panels.clear()
    }

    /** LOCKED-1: a 1.0.0 install has audit.enabled but no audit.verbose, and must load verbose OFF. */
    @Test
    fun anExistingInstallWithNoVerboseKeyLoadsVerboseOff() {
        val store = PrefsStore()
        store.booleans["audit.enabled"] = true
        store.strings["privacy.mode"] = "STRICT"
        store.strings["backend.preferred"] = "ollama"
        val repo = AgentSettingsRepository(apiWith(store))

        val loaded = repo.load()
        assertTrue(loaded.auditEnabled, "Anti-vacuity: the seeded audit.enabled must load.")
        assertEquals(PrivacyMode.STRICT, loaded.privacyMode, "Anti-vacuity: the seeded privacy mode must load.")
        assertFalse(loaded.auditVerbose, "A missing audit.verbose key is an existing install: verbose stays off.")
        assertFalse(repo.defaultSettings().auditVerbose, "The default is off.")
    }

    @Test
    fun verboseOnRoundTripsThroughTheRepository() {
        val store = PrefsStore()
        val repo = AgentSettingsRepository(apiWith(store))

        repo.save(repo.defaultSettings().copy(auditVerbose = true))
        assertEquals(true, store.booleans["audit.verbose"], "Verbose on is stored under audit.verbose.")
        assertTrue(AgentSettingsRepository(apiWith(store)).load().auditVerbose, "Verbose on loads back.")

        repo.save(repo.defaultSettings().copy(auditVerbose = false))
        assertEquals(false, store.booleans["audit.verbose"], "Verbose off is stored as false.")
    }

    @Test
    fun aSaveReachesTheRealAuditLogger() {
        val home = root.resolve("save-home").toFile()
        val logger = AuditLogger(newApi(PrefsStore()), home)
        val panel = newPanel(logger)
        var onScreen: AgentSettings? = null
        onEdt { onScreen = panel.currentSettings() }

        panel.applyAndSaveSettingsBody(onScreen!!.copy(auditEnabled = true, auditVerbose = true))
        logPrompt(logger)
        panel.applyAndSaveSettingsBody(onScreen!!.copy(auditEnabled = true, auditVerbose = false))
        logPrompt(logger)

        val lines = File(home, "audit.jsonl").readLines(Charsets.UTF_8)
        assertEquals(2, lines.size, "Both saves enabled audit logging, so both records were written.")
        assertTrue(lines[0].contains(PROMPT_MARK), "After a verbose save the prompt body is recorded.")
        assertFalse(lines[1].contains(PROMPT_MARK), "After a non-verbose save the prompt body is not recorded.")
        assertTrue(lines[1].contains(Hashing.sha256Hex(PROMPT)), "The digest is recorded in both modes.")
        assertTrue(lines[1].contains("\"promptUtf8Bytes\":"), "The byte length is recorded in both modes.")
    }

    @Test
    fun theVerboseSwitchSitsInTheAuditRowAndFollowsTheMarker() {
        val repo = AgentSettingsRepository(newApi(PrefsStore()))
        val panel = newPanel(AuditLogger(newApi(PrefsStore()), root.resolve("marker-home").toFile()), repo)
        onEdt {
            assertNotNull(panel.auditEnabled.parent, "Anti-vacuity: the audit switch is placed.")
            assertSame(panel.auditEnabled.parent, panel.auditVerbose.parent, "The Verbose switch shares the Audit logging row.")
            assertFalse(panel.auditVerbose.toolTipText.isNullOrBlank(), "The Verbose switch explains itself.")
            assertMarker(panel, false, "A fresh panel has no unsaved changes.")
            panel.auditVerbose.isSelected = true
            assertTrue(panel.currentSettings().auditVerbose, "The switch is read into the on-screen settings.")
            assertMarker(panel, true, "Turning Verbose on is an unsaved change.")
        }

        saveAndSettle { panel.saveSettings() }

        onEdt { assertFalse(panel.unsavedChangesLabel.isVisible, "Save settings must clear the marker.") }
        assertTrue(repo.load().auditVerbose, "The saved snapshot carries verbose on.")

        onEdt {
            panel.auditVerbose.isSelected = false
            panel.applySettingsToUi(repo.load())
            assertTrue(panel.auditVerbose.isSelected, "applySettingsToUi selects the switch from the snapshot.")
        }
    }

    @Test
    fun startupAndSaveApplyVerboseBesideEnabled() {
        val app = codeLines(File(MAIN_SOURCE_ROOT, "com/six2dez/burp/aiagent/App.kt"))
        assertEquals(1, app.count { it.contains("auditLogger.verbose = settings.auditVerbose") }, "App applies verbose once.")

        val io = codeLines(File(MAIN_SOURCE_ROOT, "com/six2dez/burp/aiagent/ui/SettingsPanelSettingsIO.kt"))
        val applied = io.indices.filter { io[it].contains("audit.verbose = updated.auditVerbose") }
        assertEquals(1, applied.size, "The Save body applies verbose exactly once.")
        assertTrue(
            io[applied.single() - 1].contains("audit.setEnabled(updated.auditEnabled)"),
            "Verbose is applied on the line right after audit.setEnabled.",
        )
    }

    @Test
    fun aToolDecisionUnderVerboseIsWrittenWithItsArgsByTheRealLogger() {
        val loudHome = root.resolve("decision-verbose").toFile()
        runApprovedToolCall(loudHome, auditVerbose = true, marker = ARGS_ON_MARKER)
        val loud = decisionRecords(loudHome)
        val withArgs = loud.filter { argsOf(it).contains(ARGS_ON_MARKER) }
        assertEquals(1, withArgs.size, "Exactly one decision record carries the verbose args: $loud")
        val payload = withArgs.single().path("payload")
        assertEquals(
            Hashing.sha256Hex(argsOf(withArgs.single())),
            payload.path("argsSha256").asText(),
            "argsSha256 is the digest of the args the reporter received.",
        )

        val quietHome = root.resolve("decision-quiet").toFile()
        runApprovedToolCall(quietHome, auditVerbose = false, marker = ARGS_OFF_MARKER)
        val quietText = File(quietHome, "audit.jsonl").readText(Charsets.UTF_8)
        assertFalse(quietText.contains(ARGS_OFF_MARKER), "With verbose off the args body is never written.")
        val quiet = decisionRecords(quietHome)
        assertTrue(quiet.any { it.path("payload").has("argsSha256") }, "Anti-vacuity: the decision was recorded.")
        assertTrue(quiet.none { it.path("payload").has("args") }, "With verbose off no record has an args key.")
    }

    // ── Helpers ──────────────────────────────────────────────────────────────────────────

    private fun runApprovedToolCall(
        home: File,
        auditVerbose: Boolean,
        marker: String,
    ) {
        // The real sink, registered exactly as App.kt does.
        val logger = AuditLogger(newApi(PrefsStore()), home)
        logger.setEnabled(true)
        AuditLogger.registerGlobalEmitter { type, payload -> logger.logEvent(type, payload) }
        val settings = TestSettings.baselineSettings().copy(auditVerbose = auditVerbose)
        val h =
            ChatPanelTestHarness.create(
                modelResponse = toolCall("proxy_http_history", """{"count":5,"note":"$marker"}"""),
                getSettings = { settings },
            )
        ChatPanelTestHarness.sendUserMessage(h, "summarise the proxy history")
        ChatPanelTestHarness.drainEdt()
        val card = requireNotNull(ChatPanelTestHarness.findApprovalCard(h.panel.root)) { "No approval card appeared." }
        val approve =
            requireNotNull(allDescendants(card).filterIsInstance<AbstractButton>().firstOrNull { it.text == "Approve once" }) {
                "No 'Approve once' button on the card."
            }
        // The parked decision's trace id and the chain's trace id are the same value: one chain
        // threads one id through the gate and every worker it dispatches.
        val traceId = ChatPanelTestHarness.chainTraceId(h)
        SwingUtilities.invokeAndWait { approve.doClick() }
        ChatPanelTestHarness.awaitToolSettled(label = traceId, count = 1)
        AuditLogger.registerGlobalEmitter(null)
    }

    private fun argsOf(record: JsonNode): String = record.path("payload").path("args").asText()

    private fun decisionRecords(home: File): List<JsonNode> =
        File(home, "audit.jsonl")
            .readLines(Charsets.UTF_8)
            .map { mapper.readTree(it) }
            .filter { it.path("type").asText() == "mcp_tool_decision" }

    private fun logPrompt(logger: AuditLogger) {
        val bundle =
            logger.buildPromptBundle(
                sessionId = "s1",
                backendId = "ollama",
                backendConfig = BackendLaunchConfig(backendId = "ollama", displayName = "Ollama"),
                promptText = PROMPT,
                contextJson = null,
                privacyMode = PrivacyMode.BALANCED,
                determinismMode = false,
            )
        logger.logEvent("prompt", bundle)
    }

    private fun toolCall(
        tool: String,
        argsJson: String,
    ): String =
        """
        ```json
        {"tool":"$tool","args":$argsJson}
        ```
        """.trimIndent()

    private fun allDescendants(container: Container): List<Component> =
        container.components.flatMap { child ->
            listOf(child) + if (child is Container) allDescendants(child) else emptyList()
        }

    /** Runs [block] on the EDT and rethrows its own failure rather than the invocation wrapper. */
    private fun onEdt(block: () -> Unit) {
        try {
            SwingUtilities.invokeAndWait(block)
        } catch (wrapped: InvocationTargetException) {
            throw wrapped.cause ?: wrapped
        }
    }

    /** EDT only: refreshes the marker and asserts its visibility. */
    private fun assertMarker(
        panel: SettingsPanel,
        visible: Boolean,
        message: String,
    ) {
        panel.refreshUnsavedMarker()
        assertEquals(visible, panel.unsavedChangesLabel.isVisible, message)
    }

    /** Runs [dispatch] on the EDT, waits for that save to settle, then drains the EDT once. */
    private fun saveAndSettle(dispatch: () -> Unit) {
        val settled = CountDownLatch(1)
        OffEdtDispatch.registerSettledObserver { settled.countDown() }
        onEdt(dispatch)
        assertTimeoutPreemptively(Duration.ofSeconds(FAILSAFE_SECONDS)) {
            assertTrue(settled.await(FAILSAFE_SECONDS, TimeUnit.SECONDS), "The save never settled.")
        }
        onEdt { }
    }

    private class PrefsStore {
        val strings = mutableMapOf<String, String>()
        val booleans = mutableMapOf<String, Boolean>()
        val integers = mutableMapOf<String, Int>()
    }

    private fun apiWith(store: PrefsStore): MontoyaApi = newApi(store)

    private fun newApi(store: PrefsStore): MontoyaApi {
        // Built BEFORE the whenever() below, or Mockito reports UnfinishedStubbingException.
        val preferences = inMemoryPreferences(store)
        val api: MontoyaApi = mock(defaultAnswer = Answers.RETURNS_DEEP_STUBS)
        whenever(api.persistence().preferences()).thenReturn(preferences)
        return api
    }

    private fun newPanel(
        audit: AuditLogger,
        repo: AgentSettingsRepository = AgentSettingsRepository(newApi(PrefsStore())),
    ): SettingsPanel {
        val api = newApi(PrefsStore())
        val backends: BackendRegistry = mock(defaultAnswer = Answers.RETURNS_DEEP_STUBS)
        whenever(backends.listAllBackendIds()).thenReturn(listOf("codex-cli", "ollama"))
        val panel =
            SettingsPanel(
                api = api,
                settingsRepo = repo,
                backends = backends,
                supervisor = mock<AgentSupervisor>(defaultAnswer = Answers.RETURNS_DEEP_STUBS),
                audit = audit,
                mcpSupervisor = mock<McpSupervisor>(defaultAnswer = Answers.RETURNS_DEEP_STUBS),
                passiveAiScanner = mock<PassiveAiScanner>(defaultAnswer = Answers.RETURNS_DEEP_STUBS),
                activeAiScanner = mock<ActiveAiScanner>(defaultAnswer = Answers.RETURNS_DEEP_STUBS),
            )
        panels.add(panel)
        return panel
    }

    private fun inMemoryPreferences(store: PrefsStore): Preferences {
        val prefs = mock<Preferences>()
        whenever(prefs.getString(any())).thenAnswer { store.strings[it.getArgument<String>(0)] }
        whenever(prefs.setString(any(), any())).thenAnswer {
            store.strings[it.getArgument<String>(0)] = it.getArgument(1)
            null
        }
        whenever(prefs.getBoolean(any())).thenAnswer { store.booleans[it.getArgument<String>(0)] }
        whenever(prefs.setBoolean(any(), any())).thenAnswer {
            store.booleans[it.getArgument<String>(0)] = it.getArgument(1)
            null
        }
        whenever(prefs.getInteger(any())).thenAnswer { store.integers[it.getArgument<String>(0)] }
        whenever(prefs.setInteger(any(), any())).thenAnswer {
            store.integers[it.getArgument<String>(0)] = it.getArgument(1)
            null
        }
        return prefs
    }

    /** Non-comment lines, with the house filter: a line-comment marker, an asterisk or a block opener first. */
    private fun codeLines(file: File): List<String> =
        file.readLines().filterNot { line ->
            val trimmed = line.trimStart()
            trimmed.startsWith("//") || trimmed.startsWith("*") || trimmed.startsWith("/*")
        }

    private companion object {
        const val MAIN_SOURCE_ROOT = "src/main/kotlin"
        const val FAILSAFE_SECONDS = 20L
        const val PROMPT_MARK = "prompt-body-SENTINEL"
        const val PROMPT = "$PROMPT_MARK → é"
        const val ARGS_ON_MARKER = "args-on-SENTINEL"
        const val ARGS_OFF_MARKER = "args-off-SENTINEL"
    }
}
