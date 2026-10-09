package com.six2dez.burp.aiagent.ui

import burp.api.montoya.MontoyaApi
import burp.api.montoya.persistence.Preferences
import com.six2dez.burp.aiagent.audit.AuditLogger
import com.six2dez.burp.aiagent.backends.BackendRegistry
import com.six2dez.burp.aiagent.config.AgentSettingsRepository
import com.six2dez.burp.aiagent.config.McpSettings
import com.six2dez.burp.aiagent.mcp.McpSupervisor
import com.six2dez.burp.aiagent.redact.PrivacyMode
import com.six2dez.burp.aiagent.redact.Redaction
import com.six2dez.burp.aiagent.scanner.ActiveAiScanner
import com.six2dez.burp.aiagent.scanner.PassiveAiScanner
import com.six2dez.burp.aiagent.supervisor.AgentSupervisor
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertTimeoutPreemptively
import org.mockito.Answers
import org.mockito.kotlin.any
import org.mockito.kotlin.argumentCaptor
import org.mockito.kotlin.clearInvocations
import org.mockito.kotlin.mock
import org.mockito.kotlin.verify
import org.mockito.kotlin.whenever
import java.lang.reflect.InvocationTargetException
import java.time.Duration
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicReference
import javax.swing.SwingUtilities

/**
 * Quick 261008-o97 — a MainTab header write (backend picker; MCP, Passive and Active toggles and the
 * matching Settings-tab switches) saves ONLY the field the user clicked, onto the SAVED snapshot, at
 * save time and under the repository write lock. Unsaved Settings edits stay unsaved.
 *
 * MainTab cannot be built headlessly, so these tests drive the seam its writes go through: each test's
 * "MainTab composition" block is what MainTab's click handler plus its persist-queue worker do.
 * `SettingsPersistQueueTest`'s ledger pins MainTab to that seam.
 */
class HeaderSettingsWritesTest {
    private val panels = CopyOnWriteArrayList<SettingsPanel>()
    private val gates = CopyOnWriteArrayList<SaveWriteGate>()

    @AfterEach
    fun releaseFixtures() {
        // A failed assertion can leave a Save worker parked in the gate; never leak it into later tests.
        gates.forEach { it.release.countDown() }
        gates.clear()
        OffEdtDispatch.registerSettledObserver(null)
        // The Save body installs custom patterns into the process-wide Redaction singleton.
        Redaction.setCustomPatterns(emptyList())
        panels.forEach { it.shutdown() }
        panels.clear()
    }

    /**
     * Q-261008-o97-R1 — a header Passive toggle with STRICT saved and OFF on screen (unsaved) saves only
     * passiveAiEnabled: the saved privacy mode stays STRICT and the OFF edit stays marked unsaved.
     */
    @Test
    fun aHeaderPassiveToggleSavesOnlyItsFieldAndLeavesUnsavedEditsUnsaved() {
        val api = newApi()
        val repo = AgentSettingsRepository(api)
        repo.save(repo.load().copy(privacyMode = PrivacyMode.STRICT))
        val panel = newPanel(api, repo, mock(defaultAnswer = Answers.RETURNS_DEEP_STUBS))
        var target = false
        onEdt {
            panel.privacyMode.selectedItem = PrivacyMode.OFF
            target = !panel.passiveAiEnabled.isSelected
        }

        // MainTab composition
        onEdt { panel.setPassiveAiEnabled(target) }
        onBackgroundThread { persistHeaderChange(repo, HeaderSettingsChange.PassiveAiEnabled(target)) }
        // end MainTab composition

        assertEquals(
            PrivacyMode.STRICT,
            repo.load().privacyMode,
            "A header toggle must not save the unsaved OFF privacy edit; only Save settings may.",
        )
        assertEquals(target, repo.load().passiveAiEnabled, "The header toggle must save its own field.")
        val reread = AgentSettingsRepository(api).load()
        assertEquals(PrivacyMode.STRICT, reread.privacyMode, "The preferences must still say STRICT.")
        assertEquals(target, reread.passiveAiEnabled, "The preferences must hold the toggled field.")
        onEdt { assertMarker(panel, true, "OFF is still on screen and unsaved, so the marker must stay.") }
    }

    /**
     * Q-261008-o97-MCP — the header MCP toggle applies the SAVED MCP settings (port included) plus the
     * clicked enabled flag and the saved privacy mode; an unsaved port edit and an unsaved privacy edit
     * are neither saved nor applied.
     */
    @Test
    fun anMcpHeaderToggleAppliesTheSavedMcpSettingsAndIgnoresAnUnsavedMcpEdit() {
        val api = newApi()
        val repo = AgentSettingsRepository(api)
        repo.save(repo.load().copy(privacyMode = PrivacyMode.STRICT))
        val savedPort = repo.load().mcpSettings.port
        val target = !repo.load().mcpSettings.enabled
        val mcp: McpSupervisor = mock(defaultAnswer = Answers.RETURNS_DEEP_STUBS)
        val panel = newPanel(api, repo, mcp)
        onEdt {
            panel.mcpPort.value = savedPort + 1
            panel.privacyMode.selectedItem = PrivacyMode.OFF
        }
        clearInvocations(mcp)

        // MainTab composition
        onEdt { panel.setMcpEnabled(target) }
        onBackgroundThread { persistHeaderChangeAndApplyMcp(repo, mcp, HeaderSettingsChange.McpEnabled(target)) }
        // end MainTab composition

        val mcpCaptor = argumentCaptor<McpSettings>()
        val privacyCaptor = argumentCaptor<PrivacyMode>()
        verify(mcp).applySettings(mcpCaptor.capture(), privacyCaptor.capture(), any(), any())
        assertEquals(savedPort, mcpCaptor.firstValue.port, "The MCP apply must use the SAVED port, not the unsaved edit.")
        assertEquals(target, mcpCaptor.firstValue.enabled, "The MCP apply must carry the clicked enabled flag.")
        assertEquals(PrivacyMode.STRICT, privacyCaptor.firstValue, "The MCP apply must use the SAVED privacy mode.")
        val saved = repo.load()
        assertEquals(savedPort, saved.mcpSettings.port, "The unsaved port edit must not be saved.")
        assertEquals(target, saved.mcpSettings.enabled, "The MCP toggle must save its own field.")
        assertEquals(PrivacyMode.STRICT, saved.privacyMode, "The unsaved privacy edit must not be saved.")
        onEdt { assertMarker(panel, true, "The port and privacy edits are still unsaved, so the marker must stay.") }
    }

    /**
     * Q-261008-o97-ATOMIC — a header toggle that overlaps a Settings Save parked inside save() waits for
     * it (the repository write lock) and both changes are kept: STRICT from the Save, the toggle from the
     * header write.
     */
    @Test
    fun aHeaderToggleDuringAnInFlightSettingsSaveKeepsBothChanges() {
        val gate = SaveWriteGate().also { gates.add(it) }
        val api = newApi(gate)
        val repo = AgentSettingsRepository(api)
        val panel = newPanel(api, repo, mock(defaultAnswer = Answers.RETURNS_DEEP_STUBS))
        onEdt { panel.privacyMode.selectedItem = PrivacyMode.STRICT }
        gate.armed.set(true)
        val settle = dispatchSave { panel.saveSettings() }
        assertTimeoutPreemptively(Duration.ofSeconds(FAILSAFE_SECONDS)) {
            assertTrue(gate.entered.await(FAILSAFE_SECONDS, TimeUnit.SECONDS), "The Save never reached save().")
        }

        // MainTab's sync of the Settings tab, then its persist worker.
        onEdt { panel.setPassiveAiEnabled(true) }
        val change = HeaderSettingsChange.PassiveAiEnabled(true)
        val toggler = Thread({ persistHeaderChange(repo, change) }, "header-toggle-worker")
        toggler.isDaemon = true
        toggler.start()
        awaitBlockedOrFinished(toggler)
        assertTrue(
            toggler.isAlive,
            "The header write must wait for the in-flight Settings save (the repository write lock) " +
                "instead of reading the pre-save snapshot and saving it beside the toggle.",
        )
        gate.release.countDown()
        assertTimeoutPreemptively(Duration.ofSeconds(FAILSAFE_SECONDS)) { toggler.join() }
        settle()

        assertEquals(PrivacyMode.STRICT, repo.load().privacyMode, "The Save's STRICT must be kept.")
        assertTrue(repo.load().passiveAiEnabled, "The header toggle must be kept.")
        val reread = AgentSettingsRepository(api).load()
        assertEquals(PrivacyMode.STRICT, reread.privacyMode, "The preferences must say STRICT.")
        assertTrue(reread.passiveAiEnabled, "The preferences must hold the toggle.")
        // STRICT and the toggle are both on screen and both saved: no false marker after the race.
        onEdt { assertMarker(panel, false, "A header toggle that landed during a Save flight must leave no marker.") }
    }

    /**
     * Q-261008-o97-MARKER — a header toggle with nothing else unsaved leaves no Unsaved changes marker.
     *
     * The repository is deliberately NOT seeded: its stored backend "burp-ai" is not in the fixture's
     * backend combo, which is exactly the normalization that makes a saved repository object differ
     * from its on-screen rendering.
     */
    @Test
    fun aHeaderToggleWithNothingElseUnsavedLeavesNoMarker() {
        val api = newApi()
        val repo = AgentSettingsRepository(api)
        val panel = newPanel(api, repo, mock(defaultAnswer = Answers.RETURNS_DEEP_STUBS))
        onEdt {
            assertMarker(panel, false, "Anti-vacuity: a fresh panel has no unsaved changes.")
            panel.setPassiveAiEnabled(true)
        }
        onBackgroundThread { persistHeaderChange(repo, HeaderSettingsChange.PassiveAiEnabled(true)) }

        onEdt { assertMarker(panel, false, "A header toggle with nothing else unsaved must leave no marker.") }
        assertTrue(repo.load().passiveAiEnabled, "The header toggle must be saved.")
    }

    // ---------------------------------------------------------------------------------------------
    // Fixture (copied in shape from SettingsSingleSourceOfTruthTest's marker fixture)
    // ---------------------------------------------------------------------------------------------

    /**
     * Parks the FIRST preference write made on the Settings Save worker (`burp-ai-settings-save`) once
     * armed, i.e. the Save is inside `AgentSettingsRepository.save()` with nothing published yet. The arm
     * flag is consumed by compareAndSet, so no other write and no other thread ever blocks.
     */
    private class SaveWriteGate {
        val armed = AtomicBoolean(false)
        val entered = CountDownLatch(1)
        val release = CountDownLatch(1)

        fun onWrite() {
            if (Thread.currentThread().name != SAVE_THREAD_NAME) return
            if (!armed.compareAndSet(true, false)) return
            entered.countDown()
            check(release.await(FAILSAFE_SECONDS, TimeUnit.SECONDS)) { "The write gate was never released." }
        }
    }

    /** Runs [block] on a background thread, the shape of MainTab's persist worker, then drains the EDT. */
    private fun onBackgroundThread(block: () -> Unit) {
        val failure = AtomicReference<Throwable?>(null)
        val worker = Thread(block, "header-write-worker")
        worker.isDaemon = true
        worker.setUncaughtExceptionHandler { _, e -> failure.set(e) }
        assertTimeoutPreemptively(Duration.ofSeconds(FAILSAFE_SECONDS)) {
            worker.start()
            worker.join()
        }
        failure.get()?.let { throw it }
        onEdt { }
    }

    /** Waits until [thread] is BLOCKED on a monitor or has finished; a deadlock failsafe, not a timer. */
    private fun awaitBlockedOrFinished(thread: Thread) {
        assertTimeoutPreemptively(Duration.ofSeconds(FAILSAFE_SECONDS)) {
            while (thread.isAlive && thread.state != Thread.State.BLOCKED) {
                Thread.yield()
            }
        }
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

    /**
     * Runs [dispatch] on the EDT and returns a function that waits for that save to settle, then drains
     * the EDT once. The wait is a deadlock failsafe inside [assertTimeoutPreemptively], never a duration
     * assertion.
     */
    private fun dispatchSave(dispatch: () -> Unit): () -> Unit {
        val settled = CountDownLatch(1)
        OffEdtDispatch.registerSettledObserver { settled.countDown() }
        onEdt(dispatch)
        return {
            assertTimeoutPreemptively(Duration.ofSeconds(FAILSAFE_SECONDS)) {
                assertTrue(settled.await(FAILSAFE_SECONDS, TimeUnit.SECONDS), "The save never settled.")
            }
            onEdt { }
        }
    }

    private fun newApi(gate: SaveWriteGate? = null): MontoyaApi {
        // Built BEFORE the whenever() below, or Mockito reports UnfinishedStubbingException.
        val preferences = inMemoryPreferences(gate)
        val api: MontoyaApi = mock(defaultAnswer = Answers.RETURNS_DEEP_STUBS)
        whenever(api.persistence().preferences()).thenReturn(preferences)
        return api
    }

    private fun newPanel(
        api: MontoyaApi,
        repo: AgentSettingsRepository,
        mcpSupervisor: McpSupervisor,
    ): SettingsPanel {
        val backends: BackendRegistry = mock(defaultAnswer = Answers.RETURNS_DEEP_STUBS)
        whenever(backends.listAllBackendIds()).thenReturn(listOf("codex-cli", "ollama"))
        val panel =
            SettingsPanel(
                api = api,
                settingsRepo = repo,
                backends = backends,
                supervisor = mock<AgentSupervisor>(defaultAnswer = Answers.RETURNS_DEEP_STUBS),
                audit = mock<AuditLogger>(defaultAnswer = Answers.RETURNS_DEEP_STUBS),
                mcpSupervisor = mcpSupervisor,
                passiveAiScanner = mock<PassiveAiScanner>(defaultAnswer = Answers.RETURNS_DEEP_STUBS),
                activeAiScanner = mock<ActiveAiScanner>(defaultAnswer = Answers.RETURNS_DEEP_STUBS),
            )
        panels.add(panel)
        return panel
    }

    private fun inMemoryPreferences(gate: SaveWriteGate?): Preferences {
        val strings = mutableMapOf<String, String>()
        val booleans = mutableMapOf<String, Boolean>()
        val integers = mutableMapOf<String, Int>()

        val prefs = mock<Preferences>()
        whenever(prefs.getString(any())).thenAnswer { strings[it.getArgument<String>(0)] }
        whenever(prefs.setString(any(), any())).thenAnswer {
            gate?.onWrite()
            strings[it.getArgument<String>(0)] = it.getArgument(1)
            null
        }
        whenever(prefs.getBoolean(any())).thenAnswer { booleans[it.getArgument<String>(0)] }
        whenever(prefs.setBoolean(any(), any())).thenAnswer {
            gate?.onWrite()
            booleans[it.getArgument<String>(0)] = it.getArgument(1)
            null
        }
        whenever(prefs.getInteger(any())).thenAnswer { integers[it.getArgument<String>(0)] }
        whenever(prefs.setInteger(any(), any())).thenAnswer {
            gate?.onWrite()
            integers[it.getArgument<String>(0)] = it.getArgument(1)
            null
        }
        return prefs
    }

    private companion object {
        const val FAILSAFE_SECONDS = 20L
        const val SAVE_THREAD_NAME = "burp-ai-settings-save"
    }
}
