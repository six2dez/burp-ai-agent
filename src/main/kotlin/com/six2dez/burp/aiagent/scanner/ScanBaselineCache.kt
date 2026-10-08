package com.six2dez.burp.aiagent.scanner

import burp.api.montoya.http.message.HttpRequestResponse
import burp.api.montoya.http.message.requests.HttpRequest
import com.six2dez.burp.aiagent.config.Defaults

/** One measured baseline: the original request with its response, and the round trip in ms. */
internal data class BaselineSample(
    val requestResponse: HttpRequestResponse,
    val elapsedMs: Long,
)

/** RED scaffold (quick 261008-vau): declarations only; every lookup measures, nothing is kept. */
@Suppress("UNUSED_PARAMETER", "unused", "FunctionOnlyReturningConstant")
internal class ScanBaselineCache(
    private val maxEntries: Int = Defaults.ACTIVE_SCAN_BASELINE_MAX_ENTRIES,
    private val ttlMs: Long = Defaults.ACTIVE_SCAN_BASELINE_TTL_MS,
    private val clock: () -> Long = System::currentTimeMillis,
) {
    fun baselineFor(
        request: HttpRequest,
        waitTimeoutMs: Long,
        measure: () -> BaselineSample?,
    ): BaselineSample? = measure()

    fun clear() = Unit

    fun size(): Int = 0

    companion object {
        @Suppress("UNUSED_PARAMETER", "FunctionOnlyReturningConstant")
        fun keyOf(request: HttpRequest): String? = null
    }
}
