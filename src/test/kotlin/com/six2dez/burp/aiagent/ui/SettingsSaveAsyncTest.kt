package com.six2dez.burp.aiagent.ui

import burp.api.montoya.MontoyaApi
import burp.api.montoya.core.BurpSuiteEdition
import burp.api.montoya.persistence.Preferences
import com.six2dez.burp.aiagent.audit.AuditLogger
import com.six2dez.burp.aiagent.backends.BackendRegistry
import com.six2dez.burp.aiagent.config.AgentSettings
import com.six2dez.burp.aiagent.config.AgentSettingsRepository
import com.six2dez.burp.aiagent.mcp.McpRequestLimiter
import com.six2dez.burp.aiagent.mcp.McpSupervisor
import com.six2dez.burp.aiagent.mcp.McpToolContext
import com.six2dez.burp.aiagent.redact.PrivacyMode
import com.six2dez.burp.aiagent.redact.Redaction
import com.six2dez.burp.aiagent.scanner.ActiveAiScanner
import com.six2dez.burp.aiagent.scanner.PassiveAiScanner
import com.six2dez.burp.aiagent.supervisor.AgentSupervisor
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNotEquals
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertTimeoutPreemptively
import org.mockito.Answers
import org.mockito.kotlin.any
import org.mockito.kotlin.mock
import org.mockito.kotlin.never
import org.mockito.kotlin.times
import org.mockito.kotlin.verify
import org.mockito.kotlin.whenever
import java.io.File
import java.time.Duration
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicReference
import javax.swing.JButton
import javax.swing.SwingUtilities

/**
 * SC4 / E7 / E8 / FLAG-23-06 — the Settings save path.
 *
 * **Naming constraint (hard).** `build.gradle.kts` excludes `*IntegrationTest`, `*ConcurrencyTest`,
 * `*BackpressureTest`, `*RestartPolicyTest` and `*SupervisionTest` under `-PexcludeHeavyTests=true`,
 * which is exactly what `.github/workflows/build.yml` passes. `SettingsSaveAsyncTest` is the approved
 * name; any of those five suffixes would make this suite silently stop running on the PR gate.
 *
 * **No test here compares an elapsed duration to a threshold.** A blocked EDT is proved by a mutual
 * latch whose failure mode is a deadlock that [assertTimeoutPreemptively] reports categorically, and
 * by the recorded outcome of that handshake rather than by a latch count alone — the vacuous-pass trap
 * plan 23-01 documented after hitting it.
 *
 * The `JOptionPane` save-failure modal is deliberately NOT asserted: `JOptionPane.getRootFrame()`
 * throws `HeadlessException`, a measured fact recorded in `CONCERNS.md`. These tests assert the banner
 * and the busy seam; the modal is routed to `23-HUMAN-UAT.md`. The modal was not deleted to make it
 * testable — D-12 keeps both surfaces on purpose.
 */
class SettingsSaveAsyncTest {
    /** Labels recorded from [OffEdtDispatch]'s settle observer — one per completed dispatch. */
    private val settled = CopyOnWriteArrayList<String>()
    private lateinit var settledSignal: CountDownLatch
    private val panels = CopyOnWriteArrayList<SettingsPanel>()

    @BeforeEach
    fun installObserver() {
        settled.clear()
        settledSignal = CountDownLatch(1)
        OffEdtDispatch.registerSettledObserver { label ->
            settled.add(label)
            settledSignal.countDown()
        }
    }

    @AfterEach
    fun releaseObserver() {
        OffEdtDispatch.registerSettledObserver(null)
        // Redaction is a process-wide singleton, so a custom pattern left installed by the E8 test
        // would follow this JVM into RedactionTest. Clearing is isolation, not tidiness.
        Redaction.setCustomPatterns(emptyList())
        panels.forEach { it.shutdown() }
        panels.clear()
    }

    /**
     * A2 — is a real [SettingsPanel] constructible under `-Djava.awt.headless=true`?
     *
     * Everything the rest of this suite asserts is built on a real panel, so this is checked first and
     * on its own. It asserts nothing about saving: construction succeeding, and `currentSettings()`
     * returning a settings object read back off the real Swing components, is the whole claim.
     */
    @Test
    fun settingsPanelIsHeadlesslyConstructible() {
        val fixture = newFixture()

        assertNotNull(
            fixture.panel.currentSettings(),
            "A2: a real SettingsPanel must be constructible headlessly and must read its own " +
                "Swing components back through currentSettings().",
        )
    }

    /**
     * S-11 (a) / SC4 / E7 — the EDT runs queued work while a save is in flight.
     *
     * `mcpSupervisor.applySettings` stands in for the real path's reach into
     * `KtorMcpServerManager.stop()`'s bounded `future.get(10, TimeUnit.SECONDS)`: it blocks until a
     * runnable queued to the EDT *after* the click has run. If the save body were still on the EDT
     * that runnable could never run, and the handshake records a categorical failure rather than a
     * slow path a timer has to guess at.
     */
    @Test
    fun theEdtIsFreeWhileASettingsSaveIsInFlight() {
        assertTimeoutPreemptively(Duration.ofSeconds(30)) {
            val fixture = newFixture()
            val workerEntered = CountDownLatch(1)
            val probeRan = CountDownLatch(1)
            val edtWasFree = AtomicBoolean(false)
            val workerThread = AtomicReference<String>()

            whenever(fixture.mcpSupervisor.applySettings(any(), any(), any(), any())).thenAnswer {
                workerThread.set(Thread.currentThread().name)
                workerEntered.countDown()
                edtWasFree.set(probeRan.await(20, TimeUnit.SECONDS))
                null
            }

            SwingUtilities.invokeAndWait { fixture.panel.saveSettings() }
            assertTrue(
                workerEntered.await(20, TimeUnit.SECONDS),
                "SC4: the save never reached mcpSupervisor.applySettings.",
            )
            SwingUtilities.invokeLater { probeRan.countDown() }
            assertTrue(settledSignal.await(25, TimeUnit.SECONDS), "SC4: the save never settled.")

            // The LOUD clause, asserted first: the handshake's own recorded outcome. A bare
            // `probeRan.count == 0` would also read zero after a synchronous save finally returned and
            // the EDT drained its queue — green with the defect fully present.
            assertTrue(
                edtWasFree.get(),
                "SC4/E7: the EDT must run queued work while the save is mid-flight. A false here means " +
                    "the save body blocked the EDT for the whole bounded ten-second MCP stop wait.",
            )
            assertEquals(
                "burp-ai-settings-save",
                workerThread.get(),
                "SC4: the save body must run on the named daemon worker, not the EDT.",
            )
        }
    }

    /**
     * S-11 (b) / E7 — the snapshot is taken on the EDT before dispatch, and the success banner is
     * written from the completion callback rather than from the line after the dispatch returns.
     *
     * The component is mutated *while the worker is blocked*. A body that read the live Swing
     * components instead of its snapshot would observe the second value; a body holding the
     * pre-dispatch snapshot observes the first. That is what makes this assertion discriminating
     * rather than a restatement of the call.
     */
    @Test
    fun theSnapshotIsTakenOnTheEdtAndTheBannerIsWrittenFromTheCallback() {
        assertTimeoutPreemptively(Duration.ofSeconds(30)) {
            val fixture = newFixture()
            val workerEntered = CountDownLatch(1)
            val release = CountDownLatch(1)
            val appliedSnapshot = AtomicReference<AgentSettings>()

            whenever(fixture.supervisor.applySettings(any())).thenAnswer { invocation ->
                appliedSnapshot.set(invocation.getArgument(0))
                workerEntered.countDown()
                release.await(20, TimeUnit.SECONDS)
                null
            }

            SwingUtilities.invokeAndWait {
                fixture.panel.privacyMode.selectedItem = PrivacyMode.OFF
                fixture.panel.saveSettings()
            }
            assertTrue(workerEntered.await(20, TimeUnit.SECONDS), "The save never reached the worker.")

            // Mid-flight: the banner still reads the start message, and the component is edited under
            // the worker's feet. D-10 leaves every field editable during a save on purpose.
            SwingUtilities.invokeAndWait {
                assertEquals(
                    "Saving settings...",
                    fixture.panel.saveFeedbackLabel.text,
                    "UI-SPEC T1: the start banner stands for the whole flight.",
                )
                fixture.panel.privacyMode.selectedItem = PrivacyMode.STRICT
            }

            release.countDown()
            assertTrue(settledSignal.await(25, TimeUnit.SECONDS), "The save never settled.")
            SwingUtilities.invokeAndWait { }

            assertEquals(
                PrivacyMode.OFF,
                appliedSnapshot.get().privacyMode,
                "D-11: the body must apply the snapshot currentSettings() read on the EDT before " +
                    "dispatch. STRICT here means it read the live Swing component from the worker.",
            )
            assertEquals(
                "Saved and applied.",
                fixture.panel.saveFeedbackLabel.text,
                "Rule C-2: the success banner is written from the completion callback.",
            )
        }
    }

    /**
     * FLAG-23-06 / T-23-09 — the busy seam lowers on BOTH failure shapes, exactly once each.
     *
     * A path that returns without lowering leaves the Settings tab permanently unsaveable with no
     * error and no way back short of reloading the extension, so the failure paths are asserted
     * specifically. A success-only test does not cover the hazard.
     */
    @Test
    fun theBusySeamLowersOnBothFailureShapes() {
        assertTimeoutPreemptively(Duration.ofSeconds(30)) {
            // Shape 1: the save body throws.
            val bodyFailure = newFixture()
            val bodyBusy = recordBusy(bodyFailure.panel)
            whenever(bodyFailure.supervisor.applySettings(any()))
                .thenAnswer { throw IllegalStateException("mcp restart refused") }

            SwingUtilities.invokeAndWait { bodyFailure.panel.saveSettings() }
            assertTrue(settledSignal.await(25, TimeUnit.SECONDS), "The failing save never settled.")
            SwingUtilities.invokeAndWait { }

            assertEquals(
                listOf(true, false),
                bodyBusy.toList(),
                "FLAG-23-06: the seam must be raised once and lowered once when the body throws.",
            )
            val failureBanner = bodyFailure.panel.saveFeedbackLabel.text
            assertTrue(
                failureBanner.startsWith("Save failed: "),
                "Rule C-2: the failure banner is written from the completion callback. Actual: $failureBanner",
            )

            // Shape 2: the completion callback itself throws. This is the second `finally` layer;
            // OffEdtDispatch's own tail wrapper cannot lower a seam it does not know about.
            settledSignal = CountDownLatch(1)
            val callbackFailure = newFixture()
            val callbackBusy = recordBusy(callbackFailure.panel)
            SwingUtilities.invokeAndWait {
                callbackFailure.panel.applyAndSaveSettingsAsync(callbackFailure.panel.currentSettings()) {
                    throw IllegalStateException("completion callback blew up")
                }
            }
            assertTrue(settledSignal.await(25, TimeUnit.SECONDS), "The save never settled.")
            SwingUtilities.invokeAndWait { }

            assertEquals(
                listOf(true, false),
                callbackBusy.toList(),
                "FLAG-23-06: the seam must still lower when the completion callback throws.",
            )
        }
    }

    /**
     * UI-SPEC Rule T-1 / T-2 / D-10 — the seam disables BOTH action buttons, and restores Save's fill.
     *
     * Driven through a real [BottomTabsPanel], which is what installs the listener, so this asserts
     * the shipped wiring rather than a listener the test supplied. Disabling only Save would leave
     * Restore defaults able to start a second save mid-flight, re-entering the double-save race
     * through the other door.
     */
    @Test
    fun bothActionButtonsGoInertWhileBusyAndComeBack() {
        val fixture = newFixture()
        val tabs = BottomTabsPanel(fixture.panel)
        val save = requireNotNull(button(tabs, "Save settings")) { "Save settings button not found." }
        val restore = requireNotNull(button(tabs, "Restore defaults")) { "Restore defaults button not found." }
        val seam = requireNotNull(fixture.panel.busyListener) { "BottomTabsPanel did not install the busy seam." }

        seam(true)
        assertFalse(save.isEnabled, "Rule T-1: Save settings must be inert while a save is in flight.")
        assertFalse(restore.isEnabled, "Rule T-1: Restore defaults must be inert too, not only Save.")
        assertEquals(
            UiTheme.Colors.outlineVariant,
            save.background,
            "Rule T-2: the opaque Save button keeps painting its fill when disabled, so it is recolored.",
        )
        assertNotEquals(
            UiTheme.Colors.primary,
            save.background,
            "Rule T-2: an inert Save button must not still read as the primary action.",
        )

        seam(false)
        assertTrue(save.isEnabled, "Rule T-1: Save settings must come back.")
        assertTrue(restore.isEnabled, "Rule T-1: Restore defaults must come back.")
        assertEquals(UiTheme.Colors.primary, save.background, "Rule T-2: T0 restores the primary fill.")
    }

    /**
     * E8 / S-11 (c) — a tool worker dispatched mid-save redacts under its own snapshot privacy mode,
     * against a fully-published custom-pattern list, and is never unredacted.
     *
     * This pins the recorded `documented-residual` answer to AI-SPEC dimension E8. It goes RED if a
     * future refactor ever makes the tool path read `getSettings()` live instead of the immutable
     * [McpToolContext] snapshot taken on the EDT before its dispatch — exactly the regression E8
     * exists to catch.
     */
    @Test
    fun aToolWorkerMidSaveRedactsUnderItsSnapshotModeAndIsNeverUnredacted() {
        assertTimeoutPreemptively(Duration.ofSeconds(30)) {
            val fixture = newFixture()
            val marker = "SAVE-MARKER-4242"
            Redaction.setCustomPatterns(emptyList())

            // The save flips privacy mode STRICT -> OFF and publishes a custom pattern matching the
            // marker. Those are the two privacy-relevant global writes E8 names, and the body keeps
            // them contiguous.
            val updated =
                fixture.panel.currentSettings().copy(
                    privacyMode = PrivacyMode.OFF,
                    customRedactionPatterns = listOf("SAVE-MARKER-[0-9]+"),
                )

            // The tool worker's context, snapshotted BEFORE the save, exactly as ChatPanel builds it
            // on the EDT before dispatching a tool call.
            val toolContext =
                McpToolContext(
                    api = fixture.api,
                    privacyMode = PrivacyMode.STRICT,
                    determinismMode = false,
                    hostSalt = "salt",
                    toolToggles = emptyMap(),
                    unsafeEnabled = false,
                    unsafeTools = emptySet(),
                    enabledUnsafeTools = emptySet(),
                    limiter = McpRequestLimiter(4),
                    edition = BurpSuiteEdition.COMMUNITY_EDITION,
                    maxBodyBytes = 262_144,
                )

            // Park the save AFTER Redaction.setCustomPatterns has published, so the interleave under
            // test is the real one: a pre-save snapshot mode paired with a post-save pattern list.
            val patternsPublished = CountDownLatch(1)
            val release = CountDownLatch(1)
            whenever(fixture.passiveAiScanner.setEnabled(any())).thenAnswer {
                patternsPublished.countDown()
                release.await(20, TimeUnit.SECONDS)
                null
            }

            SwingUtilities.invokeAndWait { fixture.panel.applyAndSaveSettingsAsync(updated) { } }
            assertTrue(patternsPublished.await(20, TimeUnit.SECONDS), "The save never published its patterns.")

            val permit = toolContext.limiter.tryAcquire()
            // The marker is deliberately BARE. An earlier form read `token=$marker`, which STRICT's
            // built-in url/form token rule redacts on its own — the assertion below went green with
            // Redaction.setCustomPatterns deleted from the body, i.e. it proved nothing about the
            // post-save half of the E8 pairing. Measured, then fixed.
            val redacted = toolContext.redactIfNeeded(marker)
            release.countDown()
            assertTrue(settledSignal.await(25, TimeUnit.SECONDS), "The save never settled.")

            assertEquals(
                PrivacyMode.STRICT,
                toolContext.privacyMode,
                "E8: the tool worker redacts under the mode captured in its immutable snapshot. OFF " +
                    "here means the worker read live settings instead of its own context.",
            )
            assertEquals(
                PrivacyMode.OFF,
                fixture.panel.settings.privacyMode,
                "The save must really have flipped the mode, or the assertion above is vacuous.",
            )
            assertFalse(
                redacted.contains(marker),
                "E8: every reachable pairing redacts under some consistent policy. There is no state " +
                    "in which a call is redacted under no rules. Actual: $redacted",
            )
            assertTrue(
                permit,
                "E10: each call site mints its own limiter, so a save in flight must not exhaust the " +
                    "tool path's permits.",
            )
            assertFalse(
                redacted.contains("Too many concurrent MCP requests."),
                "E10: the tool path must not be throttled by a concurrent settings save.",
            )
        }
    }

    /**
     * Rule C-2 / D-13 — `restoreDefaultsWithConfirmation` reports from the completion callback, and its
     * confirmation stays on the EDT before dispatch.
     *
     * **Asserted structurally, and that bound is measured rather than chosen.** This path opens with
     * `JOptionPane.showConfirmDialog`, and `JOptionPane.getRootFrame()` throws `HeadlessException`
     * (`CONCERNS.md`), so the caller cannot be driven headlessly at all — the sibling save path carries
     * the behavioural version of the same claim, since D-13 puts both callers on ONE async path. The
     * form follows `ChatPanelToolGateTest.userDialogPathIsNotDoublePrompted`, and `build.gradle.kts`
     * declares this file as a `tasks.test` input so an edit to it actually re-runs this assertion
     * instead of being served from cache — the measured 22-09 stale-cache defect.
     *
     * `"Defaults restored and applied."` is printed today from inside the callback. Printed on the line
     * after an async call returns it would be a lie, which is the concrete regression this pins.
     */
    @Test
    fun restoreDefaultsConfirmsBeforeDispatchAndReportsFromTheCallback() {
        val body = restoreDefaultsSource()
        val applyToUi = body.indexOf("applySettingsToUi(defaults, notifyHosts = false)")
        val startBanner = body.indexOf("\"Restoring defaults...\"")
        val dispatch = body.indexOf("applyAndSaveSettingsAsync(")
        val successBanner = body.indexOf("\"Defaults restored and applied.\"")
        val failureBanner = body.indexOf("\"Restore failed: ")

        val confirmBody = functionBody("fun SettingsPanel.restoreDefaultsWithConfirmation()")
        val confirm = confirmBody.indexOf("showConfirmDialog")
        val handoff = confirmBody.indexOf("restoreDefaultsConfirmed()")

        assertTrue(
            confirm in 0 until handoff,
            "Rule T-3: the confirmation must precede the dispatch. restoreDefaultsWithConfirmation must " +
                "still open with showConfirmDialog and only then hand off to restoreDefaultsConfirmed().",
        )
        assertTrue(
            applyToUi in 0 until dispatch,
            "Rule T-3, narrowed to what is true: applySettingsToUi's COMPONENT writes are what stay on " +
                "the EDT before the dispatch. Its three host notifications are NOT EDT-safe — they " +
                "reach disk I/O and a bounded ten-second MCP server stop — and are suppressed at this " +
                "call site by notifyHosts = false. A bare applySettingsToUi(defaults) here would " +
                "restore the SC4 freeze this assertion previously certified as correct.",
        )
        assertTrue(startBanner in 0 until dispatch, "Rule C-2: every T1 entry needs a T1 banner.")
        assertTrue(successBanner > dispatch, "Rule C-2: the success line must come from the completion callback.")
        assertTrue(failureBanner > dispatch, "Rule C-2: the failure line must come from the completion callback too.")
    }

    /**
     * `missing` item 1 / SC4 — the restore-defaults path fires NO host notification on the EDT.
     *
     * The installed callback is MainTab-shaped: `MainTab.onMcpEnabledChanged` reaches
     * `settingsRepo.save()` and `mcpSupervisor.applySettings(...)`, and with the MCP defaults disabled
     * that reaches `KtorMcpServerManager`'s bounded `future.get(10, TimeUnit.SECONDS)`. Here it blocks
     * until a runnable the test queues to the EDT *after* the restore has been posted. Against the code
     * as committed at `2a0c703` the callback fires ON the EDT, that runnable can never run, and the
     * invocation count reads 1 — which is the red probe this assertion is accepted on.
     */
    @Test
    fun restoreDefaultsDoesNotFireTheHostNotificationsOnTheEdt() {
        assertTimeoutPreemptively(Duration.ofSeconds(40)) {
            val fixture = newFixture()
            val seam = fixture.installBlockingMcpCallback()

            SwingUtilities.invokeLater { fixture.panel.restoreDefaultsConfirmed() }
            SwingUtilities.invokeLater { seam.releaseNow() }
            assertTrue(settledSignal.await(30, TimeUnit.SECONDS), "The restore never settled.")
            SwingUtilities.invokeAndWait { }

            assertEquals(
                0,
                seam.invocations.get(),
                "SC4: restoreDefaultsConfirmed must not fire onMcpEnabledChanged on the EDT. Each " +
                    "invocation reaches MainTab's settingsRepo.save() plus mcpSupervisor.applySettings(), " +
                    "and with MCP going enabled -> disabled that is McpSupervisor.stop()'s bounded " +
                    "ten-second wait paid by the Burp UI. Threads seen: ${seam.threads.toList()}.",
            )
        }
    }

    /**
     * The negative control for the test above: without it, deleting the three notifications outright
     * would also make that test pass — and would silently break every OTHER caller of
     * `applySettingsToUi`, which legitimately needs the host told.
     *
     * Driven off the EDT on purpose, so the blocking callback is harmless and the EDT stays free to run
     * the release runnable.
     */
    @Test
    fun applySettingsToUiStillNotifiesHostsByDefault() {
        assertTimeoutPreemptively(Duration.ofSeconds(40)) {
            val fixture = newFixture()
            val seam = fixture.installBlockingMcpCallback()
            val defaults = AgentSettingsRepository(fixture.api).defaultSettings()

            val driver = Thread({ fixture.panel.applySettingsToUi(defaults) }, "apply-to-ui-driver")
            driver.isDaemon = true
            driver.start()

            assertTrue(seam.entered.await(30, TimeUnit.SECONDS), "The default path never notified the host at all.")
            SwingUtilities.invokeLater { seam.releaseNow() }
            driver.join(TimeUnit.SECONDS.toMillis(30))

            assertEquals(
                1,
                seam.invocations.get(),
                "applySettingsToUi must still notify the host when notifyHosts keeps its default. The " +
                    "restore path suppresses the notifications at ONE call site; it does not delete them.",
            )
            assertTrue(
                seam.edtWasFree.get(),
                "The release runnable never ran, so this control proved nothing about the default path.",
            )
        }
    }

    /**
     * UI-SPEC Rule T-3 / `missing` item 1 — suppressing the notifications did not also suppress the
     * component writes.
     *
     * Behavioural, not a source-text index comparison: a value only `applySettingsToUi` writes is read
     * back through `currentSettings()` while the save worker is still parked, so the write is proved to
     * have happened on the EDT BEFORE the dispatch was released.
     */
    @Test
    fun restoreDefaultsStillWritesTheComponentsBeforeDispatch() {
        assertTimeoutPreemptively(Duration.ofSeconds(30)) {
            val fixture = newFixture()
            val workerEntered = CountDownLatch(1)
            val release = CountDownLatch(1)
            whenever(fixture.supervisor.applySettings(any())).thenAnswer {
                workerEntered.countDown()
                release.await(20, TimeUnit.SECONDS)
                null
            }

            SwingUtilities.invokeAndWait { fixture.panel.privacyMode.selectedItem = PrivacyMode.OFF }
            SwingUtilities.invokeAndWait { fixture.panel.restoreDefaultsConfirmed() }
            assertTrue(workerEntered.await(20, TimeUnit.SECONDS), "The restore never reached the worker.")

            val onScreen = AtomicReference<AgentSettings>()
            SwingUtilities.invokeAndWait { onScreen.set(fixture.panel.currentSettings()) }
            release.countDown()
            assertTrue(settledSignal.await(25, TimeUnit.SECONDS), "The restore never settled.")

            assertEquals(
                AgentSettingsRepository(fixture.api).defaultSettings().privacyMode,
                onScreen.get().privacyMode,
                "Rule T-3: applySettingsToUi's component writes must still run, on the EDT, before the " +
                    "dispatch. OFF here — the value the test set beforehand — means the component write " +
                    "was lost along with the host notifications.",
            )
        }
    }

    /**
     * CR-01 / T-23-08-01 — a save still in flight when the extension unloads never reaches the MCP
     * supervisor.
     *
     * `App.shutdown()` calls `MainTab.shutdown()` — and so `SettingsPanel.shutdown()` — FIRST, before
     * `mcpSupervisor.shutdown()`. Without a supersede, the save worker's `mcpSupervisor.applySettings`
     * can land afterwards and leave an MCP server LISTENING on `127.0.0.1` owned by an unloaded
     * extension's classloader, with no live extension behind SEC-04's access-control checks.
     *
     * **Why the settle await above the `never()` is not decoration.** After an asynchronous dispatch a
     * bare `never()` passes *vacuously and faster* than it would with the bug absent — the worker has
     * simply not reached the call yet. The await is asserted with a message so the assertion below can
     * only be read once the body has provably finished or returned. Its paired positive control,
     * [aSaveThatIsNotSupersededDoesReachTheMcpSupervisor], is what distinguishes "guarded" from
     * "never wired at all".
     *
     * `supervisor.applySettings` is the parking point because it is the statement immediately before
     * the guard, so the worker is provably INSIDE the body when `shutdown()` lands. `@AfterEach`
     * already calls `shutdown()` on every fixture panel, so the explicit call here is an additional,
     * earlier one rather than the only one.
     */
    @Test
    fun aSaveSupersededByShutdownNeverReachesTheMcpSupervisor() {
        assertTimeoutPreemptively(Duration.ofSeconds(30)) {
            val fixture = newFixture()
            val insideBody = CountDownLatch(1)
            val release = CountDownLatch(1)
            whenever(fixture.supervisor.applySettings(any())).thenAnswer {
                insideBody.countDown()
                release.await(20, TimeUnit.SECONDS)
                null
            }

            SwingUtilities.invokeAndWait { fixture.panel.saveSettings() }
            assertTrue(insideBody.await(20, TimeUnit.SECONDS), "The save never entered the body at all.")
            fixture.panel.shutdown()
            release.countDown()

            assertTrue(
                settledSignal.await(25, TimeUnit.SECONDS),
                "CR-01: the superseded save never settled, so the never() below would pass vacuously.",
            )
            verify(fixture.mcpSupervisor, never()).applySettings(any(), any(), any(), any())
        }
    }

    /**
     * The positive control for [aSaveSupersededByShutdownNeverReachesTheMcpSupervisor].
     *
     * Identical fixture, identical latch shape, no `shutdown()`. Without it, the `never()` above would
     * be equally green if `mcpSupervisor.applySettings` had simply been deleted from the save body —
     * an assertion that cannot distinguish "guarded" from "never wired at all".
     */
    @Test
    fun aSaveThatIsNotSupersededDoesReachTheMcpSupervisor() {
        assertTimeoutPreemptively(Duration.ofSeconds(30)) {
            val fixture = newFixture()
            val insideBody = CountDownLatch(1)
            val release = CountDownLatch(1)
            whenever(fixture.supervisor.applySettings(any())).thenAnswer {
                insideBody.countDown()
                release.await(20, TimeUnit.SECONDS)
                null
            }

            SwingUtilities.invokeAndWait { fixture.panel.saveSettings() }
            assertTrue(insideBody.await(20, TimeUnit.SECONDS), "The save never entered the body at all.")
            release.countDown()

            assertTrue(settledSignal.await(25, TimeUnit.SECONDS), "The unsuperseded save never settled.")
            verify(fixture.mcpSupervisor, times(1)).applySettings(any(), any(), any(), any())
        }
    }

    /**
     * CR-01 / T-23-08-02 — a save superseded at unload never re-enables either AI scanner.
     *
     * `App.shutdown()` disables and shuts down both scanners before it reaches the MCP supervisor. A
     * save worker that re-arms one afterwards keeps sending observed traffic to an AI backend after the
     * user believes the extension is unloaded — directly against the project's core value.
     *
     * **Two shapes, because one would leave the second guard unfalsifiable.** The guards are sequential
     * early returns, so a supersede that lands before the FIRST of them short-circuits the rest, and a
     * probe deleting the later guard would change nothing observable. Each shape therefore parks the
     * worker immediately *after* one guard so that the next one is the only thing that can stop it:
     *
     *  - Shape 1 parks inside `mcpSupervisor.applySettings`, i.e. past guard 1, so the PASSIVE guard is
     *    the one under test.
     *  - Shape 2 parks inside `passiveAiScanner.setEnabled`, i.e. past guard 2, so the ACTIVE guard is
     *    the one under test — and the passive scanner's own `times(1)` proves the worker really did get
     *    that far rather than stopping earlier for an unrelated reason.
     *
     * Every `never()` sits after an asserted `settledSignal.await(...)`: a bare `never()` passes
     * vacuously and FASTER with the bug present, because the worker has not reached the call yet.
     */
    @Test
    fun aSaveSupersededByShutdownNeverReEnablesTheScanners() {
        assertTimeoutPreemptively(Duration.ofSeconds(40)) {
            // Shape 1 — supersede lands past guard 1; the passive guard is what must stop it.
            val past1 = newFixture()
            val inMcp = CountDownLatch(1)
            val releaseMcp = CountDownLatch(1)
            whenever(past1.mcpSupervisor.applySettings(any(), any(), any(), any())).thenAnswer {
                inMcp.countDown()
                releaseMcp.await(20, TimeUnit.SECONDS)
                null
            }

            SwingUtilities.invokeAndWait { past1.panel.saveSettings() }
            assertTrue(inMcp.await(20, TimeUnit.SECONDS), "The save never got past guard 1 at all.")
            past1.panel.shutdown()
            releaseMcp.countDown()
            assertTrue(
                settledSignal.await(25, TimeUnit.SECONDS),
                "CR-01 shape 1: the superseded save never settled, so the never() below would pass " +
                    "vacuously.",
            )

            verify(past1.passiveAiScanner, never()).setEnabled(any())
            verify(past1.activeAiScanner, never()).setEnabled(any())

            // Shape 2 — supersede lands past guard 2; the active guard is the only thing left.
            settledSignal = CountDownLatch(1)
            val past2 = newFixture()
            val inPassive = CountDownLatch(1)
            val releasePassive = CountDownLatch(1)
            whenever(past2.passiveAiScanner.setEnabled(any())).thenAnswer {
                inPassive.countDown()
                releasePassive.await(20, TimeUnit.SECONDS)
                null
            }

            SwingUtilities.invokeAndWait { past2.panel.saveSettings() }
            assertTrue(inPassive.await(20, TimeUnit.SECONDS), "The save never got past guard 2 at all.")
            past2.panel.shutdown()
            releasePassive.countDown()
            assertTrue(
                settledSignal.await(25, TimeUnit.SECONDS),
                "CR-01 shape 2: the superseded save never settled, so the never() below would pass " +
                    "vacuously.",
            )

            verify(past2.passiveAiScanner, times(1)).setEnabled(any())
            verify(past2.activeAiScanner, never()).setEnabled(any())
        }
    }

    /**
     * The positive control for [aSaveSupersededByShutdownNeverReEnablesTheScanners].
     *
     * Same fixture, same latch shape, no `shutdown()`. Without it, both `never()` clauses above would
     * be equally green if the two `setEnabled` calls had simply been deleted from the save body.
     */
    @Test
    fun aSaveThatIsNotSupersededDoesEnableTheScanners() {
        assertTimeoutPreemptively(Duration.ofSeconds(30)) {
            val fixture = newFixture()
            val inMcp = CountDownLatch(1)
            val release = CountDownLatch(1)
            whenever(fixture.mcpSupervisor.applySettings(any(), any(), any(), any())).thenAnswer {
                inMcp.countDown()
                release.await(20, TimeUnit.SECONDS)
                null
            }

            SwingUtilities.invokeAndWait { fixture.panel.saveSettings() }
            assertTrue(inMcp.await(20, TimeUnit.SECONDS), "The save never entered the body at all.")
            release.countDown()
            assertTrue(settledSignal.await(25, TimeUnit.SECONDS), "The unsuperseded save never settled.")

            verify(fixture.passiveAiScanner, times(1)).setEnabled(any())
            verify(fixture.activeAiScanner, times(1)).setEnabled(any())
        }
    }

    /**
     * CR-01 / T-23-08-04 — a save submitted AFTER unload is refused outright, and strands nothing.
     *
     * `applyAndSaveSettingsAsync` returns at `if (disposed) return` before the busy seam is raised, so
     * `onDone` is never invoked and there is no seam left raised for nobody to lower. Raising a seam
     * that never lowers is what leaves the Settings tab permanently unsaveable (FLAG-23-06), which is
     * why the recorded busy list — not merely the absence of a dispatch — is the loud clause here.
     *
     * **Reading the settle record for an absence claim is acceptable ONLY here**, because no worker is
     * dispatched at all and that absence is itself asserted with a bounded wait. Do not copy this
     * pattern into a case where a worker does start: there the settle record would read empty simply
     * because the worker has not finished yet, and the assertion would pass vacuously.
     */
    @Test
    fun aSaveSubmittedAfterShutdownIsRefusedWithoutRaisingTheBusySeam() {
        assertTimeoutPreemptively(Duration.ofSeconds(30)) {
            val fixture = newFixture()
            val busy = recordBusy(fixture.panel)
            val onDoneFired = AtomicBoolean(false)

            fixture.panel.shutdown()
            SwingUtilities.invokeAndWait {
                fixture.panel.applyAndSaveSettingsAsync(fixture.panel.currentSettings()) {
                    onDoneFired.set(true)
                }
            }
            SwingUtilities.invokeAndWait { }

            assertEquals(
                emptyList<Boolean>(),
                busy.toList(),
                "CR-01: a save submitted after unload must not raise the busy seam. A raised seam with " +
                    "no worker to lower it leaves the Settings tab permanently unsaveable.",
            )
            assertFalse(
                settledSignal.await(2, TimeUnit.SECONDS),
                "CR-01: no worker may be dispatched at all after unload. Labels seen: ${settled.toList()}.",
            )
            assertFalse(
                settled.contains("settings-save"),
                "CR-01: a settings-save settled after unload. Labels seen: ${settled.toList()}.",
            )
            assertFalse(onDoneFired.get(), "CR-01: onDone must not fire for a refused save.")
        }
    }

    // ---------------------------------------------------------------------------------------------
    // Fixture
    // ---------------------------------------------------------------------------------------------

    private class Fixture(
        val panel: SettingsPanel,
        val api: MontoyaApi,
        val supervisor: AgentSupervisor,
        val mcpSupervisor: McpSupervisor,
        val passiveAiScanner: PassiveAiScanner,
        val activeAiScanner: ActiveAiScanner,
    ) {
        /**
         * Installs a MainTab-SHAPED `onMcpEnabledChanged` and returns its recorder.
         *
         * Before this existed, `newFixture()` left all three `onXxxChanged` callbacks null, which is
         * precisely why no test in this suite could fail for the SC4 restore-defaults gap
         * (`23-VERIFICATION.md` gaps.missing item 3). The real `MainTab` callback does a disk write and
         * a bounded ten-second MCP stop; this one records its calling thread and its invocation count
         * and BLOCKS, so firing it on the EDT is observable rather than merely slow.
         */
        fun installBlockingMcpCallback(): BlockingHostCallback {
            val recorder = BlockingHostCallback()
            panel.onMcpEnabledChanged = { enabled -> recorder.fire(enabled) }
            return recorder
        }
    }

    /** See [Fixture.installBlockingMcpCallback]. */
    private class BlockingHostCallback {
        val invocations = AtomicInteger(0)
        val threads = CopyOnWriteArrayList<String>()
        val entered = CountDownLatch(1)
        val edtWasFree = AtomicBoolean(false)
        private val gate = CountDownLatch(1)

        fun fire(
            @Suppress("UNUSED_PARAMETER") enabled: Boolean,
        ) {
            invocations.incrementAndGet()
            threads.add(Thread.currentThread().name)
            entered.countDown()
            edtWasFree.set(gate.await(20, TimeUnit.SECONDS))
        }

        /** Released from a runnable queued to the EDT, so a blocked EDT is a categorical failure. */
        fun releaseNow() {
            gate.countDown()
        }
    }

    /** Records every value the busy seam publishes, in order, replacing any listener already installed. */
    private fun recordBusy(panel: SettingsPanel): CopyOnWriteArrayList<Boolean> {
        val seen = CopyOnWriteArrayList<Boolean>()
        panel.setBusyListener { busy -> seen.add(busy) }
        return seen
    }

    private fun button(
        tabs: BottomTabsPanel,
        text: String,
    ): JButton? = ChatPanelTestHarness.find(tabs.root as java.awt.Container, JButton::class.java) { it.text == text }

    /**
     * Builds a real [SettingsPanel] from deep-stub collaborators, following the
     * `ChatPanelTestHarness.create` construction pattern, plus the in-memory [Preferences] fake from
     * `SettingsDefaultsPersistenceTest` so `AgentSettingsRepository.load()` has somewhere to read from.
     */
    private fun newFixture(): Fixture {
        // Built BEFORE the whenever() below: passing inMemoryPreferences() inline would build its own
        // mock while this stubbing is still open, which Mockito reports as UnfinishedStubbingException.
        val preferences = inMemoryPreferences()
        val api: MontoyaApi = mock(defaultAnswer = Answers.RETURNS_DEEP_STUBS)
        whenever(api.persistence().preferences()).thenReturn(preferences)
        // A REAL list, not a deep stub: SettingsPanel.kt:115 calls .toTypedArray() on the result, and
        // a mocked List returns null from Collection.toArray(T[]), which JComboBox rejects with an NPE.
        val backends: BackendRegistry = mock(defaultAnswer = Answers.RETURNS_DEEP_STUBS)
        whenever(backends.listAllBackendIds()).thenReturn(listOf("codex-cli", "ollama"))
        val supervisor: AgentSupervisor = mock(defaultAnswer = Answers.RETURNS_DEEP_STUBS)
        val mcpSupervisor: McpSupervisor = mock(defaultAnswer = Answers.RETURNS_DEEP_STUBS)
        val passiveAiScanner: PassiveAiScanner = mock(defaultAnswer = Answers.RETURNS_DEEP_STUBS)
        val activeAiScanner: ActiveAiScanner = mock(defaultAnswer = Answers.RETURNS_DEEP_STUBS)
        val panel =
            SettingsPanel(
                api = api,
                settingsRepo = AgentSettingsRepository(api),
                backends = backends,
                supervisor = supervisor,
                audit = mock<AuditLogger>(defaultAnswer = Answers.RETURNS_DEEP_STUBS),
                mcpSupervisor = mcpSupervisor,
                passiveAiScanner = passiveAiScanner,
                activeAiScanner = activeAiScanner,
            )
        panels.add(panel)
        return Fixture(panel, api, supervisor, mcpSupervisor, passiveAiScanner, activeAiScanner)
    }

    /** Copied in shape from `SettingsDefaultsPersistenceTest.inMemoryPreferences`. */
    private fun inMemoryPreferences(): Preferences {
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
            integers[it.getArgument<String>(0)] = it.getArgument(1)
            null
        }
        return prefs
    }

    /**
     * The source text of `restoreDefaultsWithConfirmation`, read from disk.
     *
     * Named, resolved and asserted rather than left to surface as a bare `FileNotFoundException`, which
     * is what a build-layout change would otherwise produce here. `build.gradle.kts` declares this path
     * as a `tasks.test` input, so an edit to it invalidates the cache and this assertion re-runs.
     */
    private fun restoreDefaultsSource(): String = functionBody("internal fun SettingsPanel.restoreDefaultsConfirmed()")

    /**
     * The brace-balanced body of [signature] in `SettingsPanelActions.kt`, read from disk, with every
     * comment line stripped.
     *
     * Comment lines are removed for the same reason the `MainTab` ledger gate removes them: the
     * production KDoc and inline comments legitimately name the very tokens these ordering assertions
     * index on, and a raw-text index would then measure the comment rather than the code. Measured, not
     * theorised — the first draft of this assertion failed because a comment above the confirmation
     * dialog mentioned `restoreDefaultsConfirmed()`. The filter matches the phase-wide canonical one: a
     * line whose first non-space characters are a line-comment marker, a continuation asterisk, or a
     * block-comment opener.
     */
    private fun functionBody(signature: String): String {
        val file = File(ACTIONS_SOURCE)
        assertTrue(
            file.isFile,
            "Expected to find `$ACTIONS_SOURCE` relative to the test working directory " +
                "`${System.getProperty("user.dir")}`, resolved as `${file.absolutePath}`. If the build " +
                "layout changed, fix the path here and in the matching `tasks.test` input declaration.",
        )
        val source =
            file
                .readLines()
                .filterNot { line ->
                    val trimmed = line.trimStart()
                    trimmed.startsWith("//") || trimmed.startsWith("*") || trimmed.startsWith("/*")
                }.joinToString("\n")
        val start = source.indexOf(signature)
        require(start >= 0) {
            "No `$signature` in $ACTIONS_SOURCE — this structural assertion is stale."
        }
        val open = source.indexOf('{', start)
        var depth = 0
        var index = open
        while (index < source.length) {
            if (source[index] == '{') depth++
            if (source[index] == '}') {
                depth--
                if (depth == 0) return source.substring(open, index + 1)
            }
            index++
        }
        error("Unbalanced braces after `$signature` in $ACTIONS_SOURCE.")
    }

    private companion object {
        const val ACTIONS_SOURCE = "src/main/kotlin/com/six2dez/burp/aiagent/ui/SettingsPanelActions.kt"
    }
}
