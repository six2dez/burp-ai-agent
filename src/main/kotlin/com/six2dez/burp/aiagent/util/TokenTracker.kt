package com.six2dez.burp.aiagent.util

import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicLong
import kotlin.math.ceil
import kotlin.math.max

data class TokenUsageSnapshot(
    val flow: String,
    val backendId: String,
    val calls: Long,
    val cacheHits: Long,
    val inputChars: Long,
    val outputChars: Long,
    val inputTokensEstimated: Long,
    val outputTokensEstimated: Long
)

object TokenTracker {
    private data class UsageKey(val flow: String, val backendId: String)

    private class UsageCounter {
        val calls = AtomicLong(0)
        val cacheHits = AtomicLong(0)
        val inputChars = AtomicLong(0)
        val outputChars = AtomicLong(0)
        val inputCharsWithActual = AtomicLong(0)
        val outputCharsWithActual = AtomicLong(0)
        val inputTokensActual = AtomicLong(0)
        val outputTokensActual = AtomicLong(0)
    }

    private val counters = ConcurrentHashMap<UsageKey, UsageCounter>()

    fun estimateTokens(chars: Int): Int {
        return estimateTokens(chars, null)
    }

    fun estimateTokens(chars: Int, backendId: String?): Int {
        if (chars <= 0) return 0
        val charsPerToken = charsPerTokenForBackend(backendId)
        return max(1, ceil(chars / charsPerToken).toInt())
    }

    private fun estimateTokens(chars: Long, backendId: String?): Long {
        if (chars <= 0L) return 0L
        val charsPerToken = charsPerTokenForBackend(backendId)
        return max(1L, ceil(chars / charsPerToken).toLong())
    }

    fun record(
        flow: String,
        backendId: String?,
        inputChars: Int,
        outputChars: Int,
        cacheHit: Boolean = false,
        inputTokensActual: Int? = null,
        outputTokensActual: Int? = null
    ) {
        val key = UsageKey(
            flow = flow.trim().ifBlank { "unknown" },
            backendId = backendId?.trim().orEmpty().ifBlank { "unknown" }
        )
        val counter = counters.computeIfAbsent(key) { UsageCounter() }
        val safeInputChars = inputChars.toLong().coerceAtLeast(0)
        val safeOutputChars = outputChars.toLong().coerceAtLeast(0)
        counter.calls.incrementAndGet()
        if (cacheHit) {
            counter.cacheHits.incrementAndGet()
        }
        counter.inputChars.addAndGet(safeInputChars)
        counter.outputChars.addAndGet(safeOutputChars)
        inputTokensActual?.let {
            counter.inputTokensActual.addAndGet(it.toLong().coerceAtLeast(0))
            counter.inputCharsWithActual.addAndGet(safeInputChars)
        }
        outputTokensActual?.let {
            counter.outputTokensActual.addAndGet(it.toLong().coerceAtLeast(0))
            counter.outputCharsWithActual.addAndGet(safeOutputChars)
        }
    }

    fun snapshot(): List<TokenUsageSnapshot> {
        return counters.entries.map { (key, counter) ->
            val inChars = counter.inputChars.get()
            val outChars = counter.outputChars.get()
            val inCharsWithActual = counter.inputCharsWithActual.get().coerceIn(0L, inChars)
            val outCharsWithActual = counter.outputCharsWithActual.get().coerceIn(0L, outChars)
            val inTokensActual = counter.inputTokensActual.get().coerceAtLeast(0L)
            val outTokensActual = counter.outputTokensActual.get().coerceAtLeast(0L)
            val inCharsToEstimate = (inChars - inCharsWithActual).coerceAtLeast(0L)
            val outCharsToEstimate = (outChars - outCharsWithActual).coerceAtLeast(0L)
            TokenUsageSnapshot(
                flow = key.flow,
                backendId = key.backendId,
                calls = counter.calls.get(),
                cacheHits = counter.cacheHits.get(),
                inputChars = inChars,
                outputChars = outChars,
                inputTokensEstimated = inTokensActual + estimateTokens(inCharsToEstimate, key.backendId),
                outputTokensEstimated = outTokensActual + estimateTokens(outCharsToEstimate, key.backendId)
            )
        }.sortedWith(compareBy<TokenUsageSnapshot> { it.flow }.thenBy { it.backendId })
    }

    private fun charsPerTokenForBackend(backendId: String?): Double {
        return when (backendId?.trim()?.lowercase()) {
            "openai-compatible", "nvidia-nim" -> 3.6
            "ollama", "lmstudio" -> 3.8
            "claude-cli" -> 3.5
            "gemini-cli" -> 3.7
            else -> 4.0
        }
    }
}
