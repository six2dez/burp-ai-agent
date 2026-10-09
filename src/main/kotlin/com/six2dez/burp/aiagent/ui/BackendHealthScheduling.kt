package com.six2dez.burp.aiagent.ui

import com.six2dez.burp.aiagent.backends.nvidia.NvidiaNimBackendFactory
import com.six2dez.burp.aiagent.backends.perplexity.PerplexityBackendFactory
import com.six2dez.burp.aiagent.config.AgentSettings
import com.six2dez.burp.aiagent.util.LoopbackHost
import java.time.LocalTime
import java.time.format.DateTimeFormatter
import java.util.concurrent.Executor
import java.util.concurrent.RejectedExecutionException
import java.util.concurrent.atomic.AtomicBoolean

private val checkedAtFormatter: DateTimeFormatter = DateTimeFormatter.ofPattern("HH:mm:ss")

private const val DEFAULT_OLLAMA_URL = "http://127.0.0.1:11434"
private const val DEFAULT_LMSTUDIO_URL = "http://127.0.0.1:1234"

/** Backends whose health check never leaves this machine (process probes / Burp's own AI). */
private val alwaysLocalBackendIds =
    setOf("codex-cli", "gemini-cli", "opencode-cli", "claude-cli", "copilot-cli", "burp-ai")

/** Why the AI status pill wants a fresh backend health result. */
enum class HealthCheckTrigger { STARTUP, PERIODIC, SETTINGS_CHANGED, USER_CLICK }

/**
 * Decides which status-pill health checks may run.
 *
 * Remote providers are never polled on a timer: each check is a network call to a third party
 * (and used to be a billable completion), so they are checked only at startup, after a settings or
 * backend change, and when the user clicks the pill. Local backends (CLI tools, Burp AI, HTTP
 * servers on a loopback literal) are cheap to probe and may be polled.
 */
internal object BackendHealthPolicy {
    fun isLocal(settings: AgentSettings): Boolean {
        val id = settings.preferredBackendId
        val url =
            when (id) {
                in alwaysLocalBackendIds -> return true
                "ollama" -> settings.ollamaUrl.ifBlank { DEFAULT_OLLAMA_URL }
                "lmstudio" -> settings.lmStudioUrl.ifBlank { DEFAULT_LMSTUDIO_URL }
                "openai-compatible" -> settings.openAiCompatibleUrl
                "nvidia-nim" -> settings.nvidiaNimUrl.ifBlank { NvidiaNimBackendFactory.DEFAULT_BASE_URL }
                "perplexity" -> settings.perplexityUrl.ifBlank { PerplexityBackendFactory.DEFAULT_BASE_URL }
                // anthropic and external / unknown backends: never billed by a timer.
                else -> ""
            }
        return url.isNotBlank() && LoopbackHost.isLoopbackUrl(url)
    }

    fun shouldRun(
        trigger: HealthCheckTrigger,
        settings: AgentSettings,
    ): Boolean = trigger != HealthCheckTrigger.PERIODIC || isLocal(settings)

    fun tooltip(
        message: String,
        checkedAt: LocalTime,
    ): String = "$message Last checked ${checkedAt.format(checkedAtFormatter)}. Click to re-check."
}

/**
 * Runs at most one task at a time on [executor].
 *
 * A submit that lands while a task is in flight is refused; when it asked to [submit]'s `coalesce`,
 * [onRerun] fires exactly once after the flight ends, so a Settings save or a click that arrives
 * mid-check still produces a fresh result instead of being lost. A task that throws, or an executor
 * that rejects the task, always leaves the gate released.
 */
internal class SingleFlightGate(
    private val executor: Executor,
    private val onRerun: () -> Unit,
) {
    private val running = AtomicBoolean(false)
    private val rerunRequested = AtomicBoolean(false)

    fun submit(
        coalesce: Boolean,
        task: () -> Unit,
    ): Boolean {
        if (!running.compareAndSet(false, true)) {
            if (coalesce) rerunRequested.set(true)
            return false
        }
        return try {
            executor.execute {
                try {
                    task()
                } finally {
                    running.set(false)
                    if (rerunRequested.getAndSet(false)) onRerun()
                }
            }
            true
        } catch (_: RejectedExecutionException) {
            running.set(false)
            false
        }
    }
}
