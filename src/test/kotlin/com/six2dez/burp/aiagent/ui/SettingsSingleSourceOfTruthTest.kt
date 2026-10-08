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
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import org.mockito.Answers
import org.mockito.kotlin.any
import org.mockito.kotlin.mock
import org.mockito.kotlin.verify
import org.mockito.kotlin.whenever
import java.io.File
import java.util.concurrent.CopyOnWriteArrayList
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

    // ---------------------------------------------------------------------------------------------
    // Fixture
    // ---------------------------------------------------------------------------------------------

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
            if (failIntegerWrites) throw IllegalStateException("simulated preference write failure")
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
    }
}
