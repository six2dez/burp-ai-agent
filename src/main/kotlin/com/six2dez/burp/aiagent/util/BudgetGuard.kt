package com.six2dez.burp.aiagent.util

/**
 * AWT-free per-session token-budget decision object.
 *
 * Mirrors the [com.six2dez.burp.aiagent.redact.SecretShapes] contract: a pure Kotlin `object` with
 * a nested enum type and a single typed pure function — no side effects, no Swing dependency.
 *
 * ### AWT-free contract
 * This file MUST NOT import `java.awt.*` or `javax.swing.*`. The decision function is exercised
 * by unit tests in a headless context and is reused from both [com.six2dez.burp.aiagent.ui.ChatPanel]
 * (EDT) and the scanner path (background thread).
 *
 * ### Off-by-default
 * Both thresholds default to 0 in [com.six2dez.burp.aiagent.config.AgentSettings]. When
 * `warnThreshold == 0` and `hardCap == 0`, [evaluate] always returns [State.OFF] — the guardrail
 * never surprise-blocks (SC4c).
 */
object BudgetGuard {
    /** Budget decision returned by [evaluate]. */
    enum class State {
        /** Both thresholds are 0 (unlimited) OR usage is below the warn threshold. No action needed. */
        OFF,

        /** Usage has crossed the warn threshold but not the hard cap. Show an informational banner. */
        WARN,

        /** Usage has crossed the hard cap. Show a risk banner and pause the passive scanner. */
        CAP,
    }

    /**
     * Pure decision function: maps (usedTokens, thresholds) → [State].
     *
     * - [hardCap] takes precedence over [warnThreshold] when both are exceeded.
     * - A threshold of 0 means "unlimited / off" — it never fires.
     * - This function has no side effects; callers handle the state transitions.
     */
    fun evaluate(
        usedTokens: Long,
        warnThreshold: Int,
        hardCap: Int,
    ): State =
        when {
            hardCap > 0 && usedTokens >= hardCap -> State.CAP
            warnThreshold > 0 && usedTokens >= warnThreshold -> State.WARN
            else -> State.OFF
        }

    /**
     * Returns the sum of estimated input + output tokens across all flows/backends in the current
     * Burp process session.
     *
     * [TokenTracker.snapshot] already combines actual-when-available + remainder-estimate
     * (`TokenTracker.kt:109-110`); no additional arithmetic is needed here.
     */
    fun currentSessionTokens(): Long =
        TokenTracker
            .snapshot()
            .sumOf { it.inputTokensEstimated + it.outputTokensEstimated }
}
