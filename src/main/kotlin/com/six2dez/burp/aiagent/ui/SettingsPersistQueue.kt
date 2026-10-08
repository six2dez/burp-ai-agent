package com.six2dez.burp.aiagent.ui

import com.six2dez.burp.aiagent.config.AgentSettings
import com.six2dez.burp.aiagent.config.AgentSettingsRepository
import com.six2dez.burp.aiagent.config.toPreprocessorSettings
import com.six2dez.burp.aiagent.mcp.McpSupervisor
import java.util.concurrent.atomic.AtomicLong
import java.util.concurrent.locks.ReentrantLock
import kotlin.concurrent.withLock

/**
 * The single seam every `MainTab` settings write leaves the EDT through, ordered and mutually excluded.
 *
 * **Defect 1 — the EDT half of CR-02 (REL-05 / SC4).** `MainTab`'s header toggles and the Settings-tab
 * host callbacks called `settingsRepo.save()` and `mcpSupervisor.applySettings(...)` inline on the AWT
 * Event Dispatch Thread. With MCP enabled→disabled that reaches `McpSupervisor.stop()` and then
 * `KtorMcpServerManager`'s bounded `future.get(10, TimeUnit.SECONDS)` — up to ten seconds of frozen
 * Burp UI per click. [submit] moves the persist body onto a named daemon worker and returns
 * immediately; nothing after the dispatch waits on that worker, which is the distinction
 * `OffEdtDispatch`'s KDoc draws between offloading and actually freeing the UI.
 *
 * **Defect 2 — the torn-snapshot half of CR-02, and the sharper of the two.** Two settings writes in
 * flight at once can interleave inside `AgentSettingsRepository.save()`, which writes ~107 preference
 * keys one at a time with `KEY_PRIVACY_MODE` and `KEY_CUSTOM_REDACTION_PATTERNS` a hundred keys apart.
 * An interleave can therefore persist `privacyMode` from one snapshot beside `customRedactionPatterns`
 * from another, leaving redaction weaker than either state the user actually chose. On a tool whose
 * stated core value is that the privacy controls are non-negotiable, that is not a cosmetic race.
 * [applyIfCurrent] runs each apply body to completion under one [ReentrantLock], so two writes
 * submitted through this queue cannot interleave.
 *
 * **Scope of that claim, stated honestly.** It covers writes submitted THROUGH this queue. No settings
 * write runs on the EDT any more: the chat stopped saving settings on every send in quick 261008-n0c.
 * The Settings tab's Save and Restore defaults run on their own `burp-ai-settings-save` worker,
 * outside this lock; D-10 stops two of those overlapping, but not one of those and a header write
 * submitted here, so those two can still interleave inside `save()`.
 *
 * **Ordering.** [submit] mints its generation on the CALLING thread as its first statement, so
 * submission order is click order rather than thread-start order — the same placement rule, and the
 * same reason, as `OffEdtDispatch`'s dispatched observer. A generation that reaches the lock after a
 * newer one has already begun applying is dropped rather than replayed over it.
 *
 * Concurrency is `java.util.concurrent` plus JDK Swing via `OffEdtDispatch`, per CONVENTIONS.md:95 and
 * D-05: no second marshalling helper, no pool, no additional concurrency layer outside the `mcp`
 * package.
 */
internal class SettingsPersistQueue(
    private val logError: (String) -> Unit,
) {
    /** Monotonic submission counter. Minted on the calling (EDT) thread so order is click order. */
    private val submitted = AtomicLong(0)

    /** Highest generation whose apply body has BEGUN. Advanced under [lock], before the body runs. */
    private val applied = AtomicLong(0)

    /** Serialises apply bodies so a settings write is persisted whole. See "Defect 2" above. */
    private val lock = ReentrantLock()

    @Volatile
    private var disposed = false

    /**
     * Persists [snapshot] off the EDT and reports the outcome to [onSettled] on the EDT.
     *
     * Call this from the EDT with [snapshot] already read off the Swing components — the snapshot is
     * what crosses the thread boundary, so the worker never reads a live component. [label] identifies
     * this unit of work in `OffEdtDispatch`'s observers and in the error log; the generation is
     * appended so two clicks on the same control stay distinguishable.
     *
     * Returns as soon as the worker thread is started. The worker is named `burp-ai-settings-sync`.
     */
    fun <T> submit(
        label: String,
        supersedeKey: Any,
        payload: T,
        apply: (T) -> Unit,
        onSettled: (Result<Unit>) -> Unit,
    ) {
        // FIRST STATEMENT, and load-bearing rather than stylistic: minted on the calling thread, so
        // the generation records the order the user clicked in, not the order the JVM happened to
        // start daemon threads in.
        val generation = submitted.incrementAndGet()
        OffEdtDispatch.run(
            threadName = "burp-ai-settings-sync",
            label = "$label-$generation",
            logError = logError,
            work = { applyIfCurrent(generation, supersedeKey, payload, apply) },
            onEdt = onSettled,
        )
    }

    /**
     * Stops NEW applies from starting. Deliberately does no more than that, and says so.
     *
     * It sets a `@Volatile` flag and returns; it must NEVER acquire [lock]. A worker inside a bounded
     * ten-second `mcpSupervisor.applySettings` holds that lock, and `MainTab.shutdown()` calls this
     * from the EDT — a lock-taking `dispose()` would reintroduce, at unload, the precise ten-second
     * freeze this class exists to remove.
     *
     * The bound it buys is therefore "no new apply starts", not "the in-flight apply is stopped". An
     * apply already past the [disposed] check runs to completion. Stated rather than overclaimed; the
     * full supersede of an in-flight settings worker is `T-23-06-06`, owned by plan 23-08 (CR-01).
     */
    fun dispose() {
        disposed = true
    }

    /**
     * Applies [snapshot] under [lock] if [generation] is still the newest one to have reached here.
     *
     * [applied] is advanced BEFORE [apply] runs, on purpose: a body that throws must not leave its
     * generation replayable, or a failed older write could later be applied over a newer successful
     * one — the same torn state the lock exists to prevent, arriving by a slower route.
     */
    @Suppress("UNUSED_PARAMETER")
    private fun <T> applyIfCurrent(
        generation: Long,
        supersedeKey: Any,
        payload: T,
        apply: (T) -> Unit,
    ) {
        lock.withLock {
            if (disposed) return
            if (generation <= applied.get()) return
            applied.set(generation)
            apply(payload)
        }
    }
}

/** One header settings write: the single field a click changes. */
internal sealed class HeaderSettingsChange {
    abstract fun applyTo(settings: AgentSettings): AgentSettings

    val supersedeKey: Any get() = javaClass

    data class PreferredBackend(
        val backendId: String,
    ) : HeaderSettingsChange() {
        override fun applyTo(settings: AgentSettings): AgentSettings = settings.copy(preferredBackendId = backendId)
    }

    data class McpEnabled(
        val enabled: Boolean,
    ) : HeaderSettingsChange() {
        override fun applyTo(settings: AgentSettings): AgentSettings =
            settings.copy(mcpSettings = settings.mcpSettings.copy(enabled = enabled))
    }

    data class PassiveAiEnabled(
        val enabled: Boolean,
    ) : HeaderSettingsChange() {
        override fun applyTo(settings: AgentSettings): AgentSettings = settings.copy(passiveAiEnabled = enabled)
    }

    data class ActiveAiEnabled(
        val enabled: Boolean,
    ) : HeaderSettingsChange() {
        override fun applyTo(settings: AgentSettings): AgentSettings = settings.copy(activeAiEnabled = enabled)
    }
}

/** Worker body of a header write that does not touch MCP. */
internal fun persistHeaderChange(
    settingsRepo: AgentSettingsRepository,
    change: HeaderSettingsChange,
): AgentSettings = settingsRepo.update(change::applyTo)

/** Worker body of a header MCP write. */
internal fun persistHeaderChangeAndApplyMcp(
    settingsRepo: AgentSettingsRepository,
    mcpSupervisor: McpSupervisor,
    change: HeaderSettingsChange.McpEnabled,
): AgentSettings {
    val saved = settingsRepo.update(change::applyTo)
    mcpSupervisor.applySettings(saved.mcpSettings, saved.privacyMode, saved.determinismMode, saved.toPreprocessorSettings())
    return saved
}
