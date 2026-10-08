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
 * flight at once could interleave inside `AgentSettingsRepository.save()`, which writes ~107 preference
 * keys one at a time with `KEY_PRIVACY_MODE` and `KEY_CUSTOM_REDACTION_PATTERNS` a hundred keys apart,
 * and so persist `privacyMode` from one snapshot beside `customRedactionPatterns` from another. That
 * is now guarded by `AgentSettingsRepository`'s write lock, which `save()` and `update()` both take, for
 * EVERY writer: the header writes submitted here and the Settings tab's Save and Restore defaults on
 * their own `burp-ai-settings-save` worker alike. That closes residual R2 of quick 261008-n0c (quick
 * 261008-o97). This queue's [lock] still runs each apply body to completion before the next starts,
 * so two header MCP writes never overlap their bounded MCP stop/start.
 *
 * **Ordering.** [submit] mints its generation on the CALLING thread as its first statement, so
 * submission order is click order rather than thread-start order — the same placement rule, and the
 * same reason, as `OffEdtDispatch`'s dispatched observer. The newest click wins PER SUPERSEDE KEY: a
 * generation that reaches the lock after a newer one with the same key has already begun applying is
 * dropped rather than replayed over it. Writes with different keys never drop each other, because each
 * sets one field of the saved snapshot. Residual R4, stated rather than hidden: a Settings Save
 * dispatched BEFORE a header click but persisted AFTER it writes its click-time value of that field back
 * over the click; the Save tail re-syncs the header controls to what it saved, and the Settings control
 * keeps the Unsaved changes marker on.
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

    /**
     * Per supersede key, the highest generation whose apply body has BEGUN. Read and written only under
     * [lock], and advanced before the body runs.
     */
    private val appliedByKey = HashMap<Any, Long>()

    /** Serialises apply bodies, so two header MCP writes never overlap. See "Defect 2" above. */
    private val lock = ReentrantLock()

    @Volatile
    private var disposed = false

    /**
     * Runs [apply] on [payload] off the EDT and reports the outcome to [onSettled] on the EDT.
     *
     * Call this from the EDT. [payload] is the value a click chose, never a snapshot read off the Swing
     * components: the worker reads the saved snapshot itself, at apply time (quick 261008-o97).
     * [supersedeKey] names what the write sets (one field); only a newer write with the SAME key can
     * supersede this one. [label] identifies this unit of work in `OffEdtDispatch`'s observers and in the
     * error log; the generation is appended so two clicks on the same control stay distinguishable.
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
     * Applies [payload] under [lock] if [generation] is still the newest one with [supersedeKey] to have
     * reached here.
     *
     * The key's generation is recorded BEFORE [apply] runs, on purpose: a body that throws must not leave
     * its generation replayable, or a failed older write could later be applied over a newer successful
     * one to the same field.
     */
    private fun <T> applyIfCurrent(
        generation: Long,
        supersedeKey: Any,
        payload: T,
        apply: (T) -> Unit,
    ) {
        lock.withLock {
            if (disposed) return
            if (generation <= (appliedByKey[supersedeKey] ?: 0L)) return
            appliedByKey[supersedeKey] = generation
            apply(payload)
        }
    }
}

/**
 * One settings write made outside Save settings: the single field a click changed (quick 261008-o97).
 *
 * These are the four fields `MainTab`'s backend picker and MCP, Passive and Active header toggles, and
 * the Settings tab's MCP, passive and active switches write. One subclass per field. What crosses the
 * EDT boundary is this value, never a snapshot: the worker applies it to the SAVED snapshot inside the
 * repository write lock, so unsaved Settings edits stay unsaved.
 */
internal sealed class HeaderSettingsChange {
    /** [settings] with exactly this change's one field set; every other field unchanged. */
    abstract fun applyTo(settings: AgentSettings): AgentSettings

    /** The persist-queue supersede key: the subclass, i.e. the field this change sets. */
    val supersedeKey: Any get() = javaClass

    companion object {
        /**
         * [into] with every header field that differs between [from] and [to] set to [to]'s value; every
         * other field of [into] unchanged. Used by the Unsaved changes marker: a header write changes one
         * field of the saved snapshot, and the same single-field change is applied to the on-screen
         * rendering of the applied settings.
         */
        fun carry(
            from: AgentSettings,
            to: AgentSettings,
            into: AgentSettings,
        ): AgentSettings =
            listOf(
                PreferredBackend(to.preferredBackendId),
                McpEnabled(to.mcpSettings.enabled),
                PassiveAiEnabled(to.passiveAiEnabled),
                ActiveAiEnabled(to.activeAiEnabled),
            ).filter { it.applyTo(from) != from }
                .fold(into) { acc, change -> change.applyTo(acc) }
    }

    data class PreferredBackend(
        val backendId: String,
    ) : HeaderSettingsChange() {
        override fun applyTo(settings: AgentSettings): AgentSettings = settings.copy(preferredBackendId = backendId)
    }

    data class McpEnabled(
        val enabled: Boolean,
    ) : HeaderSettingsChange() {
        override fun applyTo(settings: AgentSettings): AgentSettings = settings.copy(mcpSettings = settings.mcpSettings.copy(enabled = enabled))
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

/**
 * Worker body of a header write that does not touch MCP: saves [change] onto the saved snapshot through
 * the atomic `AgentSettingsRepository.update`. Runs on `burp-ai-settings-sync`. Returns what was saved.
 *
 * **Worker-body ledger.** `headerWriteWorkerBodiesSaveOnlyThroughTheAtomicUpdate` asserts these counts
 * as equalities on the comment-stripped code of this file:
 *
 * | Token | Count | Composition |
 * |---|---|---|
 * | `settingsRepo.update(` | 2 | one in each of the two worker bodies |
 * | `settingsRepo.save(` | 0 | a header write never saves a whole snapshot |
 * | `mcpSupervisor.applySettings(` | 1 | persistHeaderChangeAndApplyMcp only |
 */
internal fun persistHeaderChange(
    settingsRepo: AgentSettingsRepository,
    change: HeaderSettingsChange,
): AgentSettings = settingsRepo.update(change::applyTo)

/**
 * Worker body of a header MCP write: saves [change] like [persistHeaderChange], then applies MCP built
 * from what was SAVED (MCP settings, privacy mode, determinism and preprocessor settings), never from
 * unsaved MCP edits. Only this body reaches `McpSupervisor.stop()`, as `T-23-06-07` requires. The MCP
 * apply runs outside the repository lock, because its stop is a bounded ten-second wait (residual R5).
 */
internal fun persistHeaderChangeAndApplyMcp(
    settingsRepo: AgentSettingsRepository,
    mcpSupervisor: McpSupervisor,
    change: HeaderSettingsChange.McpEnabled,
): AgentSettings {
    val saved = settingsRepo.update(change::applyTo)
    mcpSupervisor.applySettings(saved.mcpSettings, saved.privacyMode, saved.determinismMode, saved.toPreprocessorSettings())
    return saved
}
