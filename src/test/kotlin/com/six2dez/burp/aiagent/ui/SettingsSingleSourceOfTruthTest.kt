package com.six2dez.burp.aiagent.ui

import burp.api.montoya.MontoyaApi
import burp.api.montoya.persistence.Preferences
import com.six2dez.burp.aiagent.audit.AuditLogger
import com.six2dez.burp.aiagent.backends.BackendRegistry
import com.six2dez.burp.aiagent.config.AgentSettings
import com.six2dez.burp.aiagent.config.AgentSettingsRepository
import com.six2dez.burp.aiagent.mcp.McpSupervisor
import com.six2dez.burp.aiagent.mirrorAppliedSettingsInto
import com.six2dez.burp.aiagent.redact.PrivacyMode
import com.six2dez.burp.aiagent.redact.Redaction
import com.six2dez.burp.aiagent.scanner.ActiveAiScanner
import com.six2dez.burp.aiagent.scanner.PassiveAiScanner
import com.six2dez.burp.aiagent.scanner.ensureBackendRunning
import com.six2dez.burp.aiagent.supervisor.AgentSupervisor
import com.six2dez.burp.aiagent.ui.components.PrivacyPill
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import org.junit.jupiter.api.assertTimeoutPreemptively
import org.mockito.Answers
import org.mockito.kotlin.any
import org.mockito.kotlin.clearInvocations
import org.mockito.kotlin.mock
import org.mockito.kotlin.mockingDetails
import org.mockito.kotlin.never
import org.mockito.kotlin.spy
import org.mockito.kotlin.verify
import org.mockito.kotlin.whenever
import java.awt.Container
import java.awt.event.ActionEvent
import java.io.File
import java.lang.reflect.InvocationTargetException
import java.time.Duration
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import javax.swing.JLabel
import javax.swing.SwingUtilities

/**
 * Quick 261008-n0c — the extension acts on ONE applied settings snapshot (review C2 and H10).
 *
 * The store is the single [AgentSettingsRepository] that `App` constructs and injects into `MainTab` and
 * `SettingsPanel`. These tests pin that there is exactly one such construction, that a Settings save
 * reaches the scanners' providers with no reload, that change listeners only ever see a fully persisted
 * snapshot, and that `AgentSupervisor` is kept as a listener-fed mirror of the store.
 *
 * The fixture is copied in shape from `SettingsSaveAsyncTest.newFixture` and `inMemoryPreferences`.
 */
class SettingsSingleSourceOfTruthTest {
    private val panels = CopyOnWriteArrayList<SettingsPanel>()
    private val scanners = CopyOnWriteArrayList<PassiveAiScanner>()

    @AfterEach
    fun releaseFixtures() {
        OffEdtDispatch.registerSettledObserver(null)
        // The Save body installs custom patterns into the process-wide Redaction singleton.
        Redaction.setCustomPatterns(emptyList())
        panels.forEach { it.shutdown() }
        panels.clear()
        scanners.forEach { it.shutdown() }
        scanners.clear()
    }

    /**
     * C2 — exactly one [AgentSettingsRepository] is constructed in main sources, and it is App's.
     * A second instance is a second cache that a save through the first never updates.
     */
    @Test
    fun exactlyOneSettingsRepositoryIsConstructedAndItIsApps() {
        val root = File(MAIN_SOURCE_ROOT)
        assertTrue(
            root.isDirectory,
            "Expected to find `$MAIN_SOURCE_ROOT` relative to `${System.getProperty("user.dir")}`, " +
                "resolved as `${root.absolutePath}`.",
        )
        val constructions =
            root
                .walkTopDown()
                .filter { it.isFile && it.extension == "kt" }
                .flatMap { file ->
                    codeLines(file)
                        .filter { it.contains("AgentSettingsRepository(") && !it.contains("class AgentSettingsRepository(") }
                        .map { file.relativeTo(root).invariantSeparatorsPath }
                }.toList()
        assertEquals(
            listOf("com/six2dez/burp/aiagent/App.kt"),
            constructions.sorted(),
            "C2: App must construct the one settings repository and inject it everywhere; every other " +
                "construction is a second cache that goes stale after a save through the first.",
        )
    }

    /**
     * C2 (brief test a) — a Settings save is visible to the passive scanner's provider with no reload,
     * and the scanner retargets the shared supervisor to the saved backend.
     */
    @Test
    fun aSettingsSaveReachesThePassiveScannerWithoutAReloadAndRetargetsItsBackend() {
        val api = newApi()
        val appRepo = AgentSettingsRepository(api)
        val supervisor: AgentSupervisor = mock(defaultAnswer = Answers.RETURNS_DEEP_STUBS)
        whenever(supervisor.status()).thenReturn(AgentSupervisor.Status("Running", "burp-ai"))
        whenever(supervisor.currentSessionId()).thenReturn("session-1")
        whenever(supervisor.startOrAttach(any())).thenReturn(false)
        whenever(supervisor.lastStartError()).thenReturn("test")
        // App.kt's provider, verbatim.
        val passive = PassiveAiScanner(api, supervisor, mock<AuditLogger>()) { appRepo.load() }
        scanners.add(passive)
        assertEquals(PrivacyMode.BALANCED, passive.getSettings().privacyMode, "Anti-vacuity: default privacy.")
        assertEquals("burp-ai", passive.getSettings().preferredBackendId, "Anti-vacuity: default backend.")

        val panel = newPanel(api, appRepo, supervisor, mock(defaultAnswer = Answers.RETURNS_DEEP_STUBS))
        var updated: AgentSettings? = null
        SwingUtilities.invokeAndWait {
            updated = panel.currentSettings().copy(privacyMode = PrivacyMode.STRICT, preferredBackendId = "ollama")
        }
        panel.applyAndSaveSettingsBody(updated!!)

        assertEquals(
            PrivacyMode.STRICT,
            passive.getSettings().privacyMode,
            "C2: the passive scanner must redact with the saved privacy mode, not the load-time one.",
        )
        assertEquals("ollama", passive.getSettings().preferredBackendId, "C2: the saved backend must reach the scanner.")
        passive.ensureBackendRunning(passive.getSettings())
        verify(supervisor).startOrAttach("ollama")
    }

    /** C2 — every successful save notifies the listeners in order, after the snapshot is published. */
    @Test
    fun everySuccessfulSaveNotifiesListenersAfterTheSnapshotIsPublished() {
        val repo = AgentSettingsRepository(newApi())
        val snapshot = repo.defaultSettings().copy(privacyMode = PrivacyMode.STRICT, preferredBackendId = "ollama")
        val calls = CopyOnWriteArrayList<String>()
        val first = CopyOnWriteArrayList<AgentSettings>()
        val second = CopyOnWriteArrayList<AgentSettings>()
        repo.addChangeListener { saved ->
            calls.add("first")
            first.add(saved)
            first.add(repo.load())
        }
        repo.addChangeListener { saved ->
            calls.add("second")
            second.add(saved)
            second.add(repo.load())
        }

        val saver = Thread { repo.save(snapshot) }
        saver.start()
        saver.join()

        assertEquals(listOf(snapshot, snapshot), first.toList(), "The first listener must see the published snapshot.")
        assertEquals(listOf(snapshot, snapshot), second.toList(), "The second listener must see the published snapshot.")
        assertEquals(listOf("first", "second"), calls.toList(), "Listeners run in registration order.")
    }

    /** C2 / WR-03 — a save whose preference writes throw notifies no listener. */
    @Test
    fun aFailedSaveNotifiesNoListener() {
        val api: MontoyaApi = mock(defaultAnswer = Answers.RETURNS_DEEP_STUBS)
        val preferences = inMemoryPreferences(failIntegerWrites = true)
        whenever(api.persistence().preferences()).thenReturn(preferences)
        val repo = AgentSettingsRepository(api)
        val seen = CopyOnWriteArrayList<AgentSettings>()
        repo.addChangeListener { seen.add(it) }

        assertThrows<IllegalStateException> { repo.save(repo.defaultSettings()) }
        assertTrue(seen.isEmpty(), "A save that did not persist must not notify listeners: $seen")
    }

    /**
     * C2 / T-n0c-04 — a save that never goes through the Settings tab (MainTab's header writes) still
     * reaches AgentSupervisor, whose launch config reads its own mirror of the snapshot.
     */
    @Test
    fun aSaveOutsideTheSettingsTabReachesTheSupervisorThroughTheRepository() {
        val repo = AgentSettingsRepository(newApi())
        val supervisor: AgentSupervisor = mock(defaultAnswer = Answers.RETURNS_DEEP_STUBS)
        mirrorAppliedSettingsInto(repo, supervisor)
        val snapshot = repo.defaultSettings().copy(passiveAiEnabled = true, preferredBackendId = "ollama")
        val provider = { repo.load() }

        val saver = Thread { repo.save(snapshot) }
        saver.start()
        saver.join()

        verify(supervisor).applySettings(snapshot)
        assertEquals(snapshot, provider(), "The scanners' provider must return the saved snapshot.")
    }

    /**
     * H10 (brief test b) — a chat send with unsaved Settings edits sends the applied snapshot's backend
     * and privacy mode, shows the applied mode in the pill, and saves or applies nothing.
     */
    @Test
    fun aChatSendWithUnsavedSettingsEditsSendsTheAppliedSnapshotAndSavesOrAppliesNothing() {
        val api = newApi()
        val repo = spy(AgentSettingsRepository(api))
        val applied = repo.defaultSettings().copy(preferredBackendId = "codex-cli")
        repo.save(applied)
        val appSupervisor: AgentSupervisor = mock(defaultAnswer = Answers.RETURNS_DEEP_STUBS)
        val mcpSupervisor: McpSupervisor = mock(defaultAnswer = Answers.RETURNS_DEEP_STUBS)
        val panel = newPanel(api, repo, appSupervisor, mcpSupervisor)
        SwingUtilities.invokeAndWait {
            panel.privacyMode.selectedItem = PrivacyMode.OFF
            panel.setPreferredBackend("ollama")
        }
        clearInvocations(repo, appSupervisor, mcpSupervisor)

        // ---- MainTab composition (MainTab.kt: `getSettings = { settingsRepo.load() }`, no apply hook) ----
        val h = ChatPanelTestHarness.create("ok", getSettings = { repo.load() })
        // ---- end of MainTab composition ----

        ChatPanelTestHarness.sendUserMessage(h, "hello")
        ChatPanelTestHarness.drainEdt()

        val sent = mockingDetails(h.supervisor).invocations.single { it.method.name == "sendChat" }.arguments
        assertEquals(PrivacyMode.BALANCED, sent[SEND_CHAT_PRIVACY_INDEX], "H10: the chat must send the applied privacy mode.")
        assertEquals("codex-cli", sent[SEND_CHAT_BACKEND_INDEX], "H10: the chat must send the applied backend.")
        var pillText: String? = null
        SwingUtilities.invokeAndWait {
            pillText = ChatPanelTestHarness.find(h.panel.root, PrivacyPill::class.java) { true }?.text
        }
        assertEquals("BALANCED", pillText, "T-n0c-03: the chat pill must show the mode actually in effect.")
        verify(repo, never()).save(any())
        verify(appSupervisor, never()).applySettings(any())
        verify(h.supervisor, never()).applySettings(any())
        verify(mcpSupervisor, never()).applySettings(any(), any(), any(), any())
        assertEquals(applied, repo.load(), "A chat send must leave the applied snapshot untouched.")
    }

    /**
     * MARKER — the Unsaved changes label follows on-screen edits (an edit shows it, reverting hides it)
     * and clears once Save settings has applied the on-screen values.
     */
    @Test
    fun theUnsavedMarkerFollowsOnScreenEditsAndClearsOnSave() {
        val f = markerFixture()
        var original: Any? = null
        onEdt {
            original = f.panel.privacyMode.selectedItem
            assertMarker(f.panel, false, "A fresh panel has no unsaved changes.")
            f.panel.privacyMode.selectedItem = PrivacyMode.OFF
            assertMarker(f.panel, true, "An on-screen edit must show the marker.")
            f.panel.privacyMode.selectedItem = original
            assertMarker(f.panel, false, "Reverting the edit must hide the marker.")
            f.panel.privacyMode.selectedItem = PrivacyMode.OFF
            assertMarker(f.panel, true, "A second edit must show the marker again.")
        }

        saveAndSettle { f.panel.saveSettings() }

        onEdt { assertFalse(f.panel.unsavedChangesLabel.isVisible, "Save settings must clear the marker.") }
        assertEquals(PrivacyMode.OFF, f.repo.load().privacyMode, "The edit must be the applied snapshot.")
    }

    /** MARKER — an edit made while a save is in flight was not saved, so it stays marked. */
    @Test
    fun anEditMadeDuringTheSaveFlightStaysMarkedUnsaved() {
        val f = markerFixture()
        val workerEntered = CountDownLatch(1)
        val release = CountDownLatch(1)
        whenever(f.supervisor.applySettings(any())).thenAnswer {
            workerEntered.countDown()
            release.await(FAILSAFE_SECONDS, TimeUnit.SECONDS)
            null
        }
        val settle =
            dispatchSave {
                f.panel.privacyMode.selectedItem = PrivacyMode.OFF
                f.panel.saveSettings()
            }
        assertTrue(workerEntered.await(FAILSAFE_SECONDS, TimeUnit.SECONDS), "The save never reached the worker.")
        onEdt { f.panel.privacyMode.selectedItem = PrivacyMode.STRICT }
        release.countDown()
        settle()

        onEdt { assertTrue(f.panel.unsavedChangesLabel.isVisible, "STRICT is on screen but OFF was saved.") }
        assertEquals(PrivacyMode.OFF, f.repo.load().privacyMode, "The flight saved its dispatch-time snapshot.")
    }

    /** MARKER — Restore defaults applies what it puts on screen, so it leaves no unsaved marker. */
    @Test
    fun restoreDefaultsLeavesNoUnsavedMarker() {
        val f = markerFixture()
        onEdt {
            f.panel.privacyMode.selectedItem = PrivacyMode.OFF
            assertMarker(f.panel, true, "Anti-vacuity: the edit must show the marker.")
        }

        saveAndSettle { f.panel.restoreDefaultsConfirmed() }

        onEdt { assertFalse(f.panel.unsavedChangesLabel.isVisible, "Restore defaults must leave no marker.") }
    }

    /**
     * MARKER — a save of exactly the on-screen values from a worker clears the marker, because the
     * listener carries every header field that save changed. The header-write case lives in
     * HeaderSettingsWritesTest.
     */
    @Test
    fun aBackgroundSaveOfTheOnScreenValuesClearsTheMarker() {
        val f = markerFixture()
        var snapshot: AgentSettings? = null
        onEdt {
            f.panel.passiveAiEnabled.isSelected = !f.panel.passiveAiEnabled.isSelected
            snapshot = f.panel.currentSettings()
            assertMarker(f.panel, true, "Anti-vacuity: the toggle must show the marker.")
        }

        // A worker-thread save of exactly the on-screen values.
        val saver = Thread { f.repo.save(snapshot!!) }
        saver.start()
        saver.join()
        onEdt { }

        onEdt { assertFalse(f.panel.unsavedChangesLabel.isVisible, "A saved header write must clear the marker.") }
    }

    /** MARKER — the label sits in the Settings button row and the existing 2 s status timer refreshes it. */
    @Test
    fun theMarkerSitsInTheSettingsButtonRowAndTheRefreshTimerDrivesIt() {
        val f = markerFixture()
        onEdt {
            val tabs = BottomTabsPanel(f.panel, null)
            val found =
                ChatPanelTestHarness.find(tabs.root as Container, JLabel::class.java) {
                    it === f.panel.unsavedChangesLabel
                }
            assertTrue(found != null, "The Unsaved changes label must sit in the Settings button row.")
            f.panel.privacyMode.selectedItem = PrivacyMode.OFF
            val timer = requireNotNull(f.panel.statusRefreshTimer) { "The status refresh timer is missing." }
            timer.actionListeners.forEach { it.actionPerformed(ActionEvent(timer, ActionEvent.ACTION_PERFORMED, null)) }
            assertTrue(f.panel.unsavedChangesLabel.isVisible, "The status refresh tick must refresh the marker.")
        }
    }

    // ---------------------------------------------------------------------------------------------
    // Fixture
    // ---------------------------------------------------------------------------------------------

    private class MarkerFixture(
        val panel: SettingsPanel,
        val repo: AgentSettingsRepository,
        val supervisor: AgentSupervisor,
    )

    private fun markerFixture(): MarkerFixture {
        val api = newApi()
        val repo = AgentSettingsRepository(api)
        val supervisor: AgentSupervisor = mock(defaultAnswer = Answers.RETURNS_DEEP_STUBS)
        val panel = newPanel(api, repo, supervisor, mock(defaultAnswer = Answers.RETURNS_DEEP_STUBS))
        return MarkerFixture(panel, repo, supervisor)
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

    /** [dispatchSave], then wait for it to settle. */
    private fun saveAndSettle(dispatch: () -> Unit) = dispatchSave(dispatch)()

    private fun newApi(): MontoyaApi {
        // Built BEFORE the whenever() below, or Mockito reports UnfinishedStubbingException.
        val preferences = inMemoryPreferences()
        val api: MontoyaApi = mock(defaultAnswer = Answers.RETURNS_DEEP_STUBS)
        whenever(api.persistence().preferences()).thenReturn(preferences)
        return api
    }

    @Suppress("UNUSED_PARAMETER")
    private fun newPanel(
        api: MontoyaApi,
        repo: AgentSettingsRepository,
        supervisor: AgentSupervisor,
        mcpSupervisor: McpSupervisor,
    ): SettingsPanel {
        val backends: BackendRegistry = mock(defaultAnswer = Answers.RETURNS_DEEP_STUBS)
        whenever(backends.listAllBackendIds()).thenReturn(listOf("codex-cli", "ollama"))
        val panel =
            SettingsPanel(
                api = api,
                settingsRepo = repo,
                backends = backends,
                supervisor = supervisor,
                audit = mock<AuditLogger>(defaultAnswer = Answers.RETURNS_DEEP_STUBS),
                mcpSupervisor = mcpSupervisor,
                passiveAiScanner = mock<PassiveAiScanner>(defaultAnswer = Answers.RETURNS_DEEP_STUBS),
                activeAiScanner = mock<ActiveAiScanner>(defaultAnswer = Answers.RETURNS_DEEP_STUBS),
            )
        panels.add(panel)
        return panel
    }

    private fun inMemoryPreferences(failIntegerWrites: Boolean = false): Preferences {
        val strings = mutableMapOf<String, String>()
        val booleans = mutableMapOf<String, Boolean>()
        val integers = mutableMapOf<String, Int>()

        val prefs = mock<Preferences>()
        whenever(prefs.getString(any())).thenAnswer { strings[it.getArgument<String>(0)] }
        whenever(prefs.setString(any(), any())).thenAnswer {
            strings[it.getArgument<String>(0)] = it.getArgument(1)
            null
        }
        whenever(prefs.getBoolean(any())).thenAnswer { booleans[it.getArgument<String>(0)] }
        whenever(prefs.setBoolean(any(), any())).thenAnswer {
            booleans[it.getArgument<String>(0)] = it.getArgument(1)
            null
        }
        whenever(prefs.getInteger(any())).thenAnswer { integers[it.getArgument<String>(0)] }
        whenever(prefs.setInteger(any(), any())).thenAnswer {
            check(!failIntegerWrites) { "simulated preference write failure" }
            integers[it.getArgument<String>(0)] = it.getArgument(1)
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
        const val SEND_CHAT_BACKEND_INDEX = 1
        const val SEND_CHAT_PRIVACY_INDEX = 5
        const val FAILSAFE_SECONDS = 20L
    }
}
