package com.six2dez.burp.aiagent.scanner

import burp.api.montoya.http.message.HttpRequestResponse
import burp.api.montoya.http.message.requests.HttpRequest
import com.six2dez.burp.aiagent.audit.Hashing
import com.six2dez.burp.aiagent.config.Defaults
import java.util.concurrent.CompletableFuture
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.ExecutionException
import java.util.concurrent.TimeUnit
import java.util.concurrent.TimeoutException

/** One measured baseline: the original request with its response, and the round trip in ms. */
internal data class BaselineSample(
    val requestResponse: HttpRequestResponse,
    val elapsedMs: Long,
)

/**
 * One baseline per original request, shared by every active-scan target built from it (quick
 * 261008-vau). Before this cache the scanner re-sent the original request for every (insertion
 * point, vulnerability class) target, so one request with several parameters was replayed once per
 * point and class before any payload was tried.
 *
 * **Key.** A SHA-256 hex digest of `"<https|http>|<host>|<port>\n"` followed by the request's raw
 * bytes. Content, not object identity: Burp hands manual, insertion-point and passive-driven targets
 * different [HttpRequestResponse] objects for the same request, and Montoya documents no
 * equals/hashCode for them. The raw bytes include cookies; they are only digested in memory, the
 * digest is never logged or persisted, and every entry is dropped when the scanner stops. When the
 * bytes or the service cannot be read, [keyOf] returns null and the baseline is measured uncached
 * (the pre-cache behaviour for that one target, never a skipped target).
 *
 * **Lifetime and bounds.** A sample lives [ttlMs] from its insertion and is measured again after
 * that. At most [maxEntries] completed samples are kept: the oldest completed ones are evicted first
 * when a new measurement starts. In-flight entries are never evicted (at most one per scan worker).
 * [clear] runs when the scanner stops, which covers disabling it, every restart, shutdown and
 * extension unload. No scheduler and no executor: expiry and eviction happen on lookup.
 *
 * **Failures.** A measurement that times out, throws or returns no response is never cached: its
 * owner removes the entry BEFORE completing the shared future. Lookups already waiting on that
 * flight get no sample (their targets report a baseline failure); a later lookup measures again.
 * A waiter waits at most its `waitTimeoutMs`; on timeout or interrupt (flag restored) it gets no
 * sample and leaves the entry to its owner.
 *
 * **Time-based trade-off.** BLIND_TIME payloads compare each payload's round trip with ONE baseline
 * round trip per original request, measured when the first target of that request ran (up to the
 * TTL earlier). Before this cache each target measured its own baseline right before its payloads.
 * Both are a single sample. A latency drift `d` since the baseline shifts the measured delay by `d`:
 * with a 5 s payload the 90-120 % window still confirms for `d` between -0.5 s and +1.0 s, a larger
 * drift can miss a true positive, and a false positive still needs at least 4.5 s of unexplained
 * extra delay. A baseline over 1 s still disables time-based detection for that request.
 */
internal class ScanBaselineCache(
    private val maxEntries: Int = Defaults.ACTIVE_SCAN_BASELINE_MAX_ENTRIES,
    private val ttlMs: Long = Defaults.ACTIVE_SCAN_BASELINE_TTL_MS,
    private val clock: () -> Long = System::currentTimeMillis,
) {
    private class Entry(
        val insertedAtMs: Long,
    ) {
        val sample = CompletableFuture<BaselineSample?>()
    }

    private val entries = ConcurrentHashMap<String, Entry>()

    /**
     * The shared baseline of [request]: a live sample, the result of a measurement already in
     * flight on another worker (waiting at most [waitTimeoutMs]), or a fresh [measure] run by this
     * caller. Null when the measurement failed. A [measure] that throws propagates to its caller.
     */
    fun baselineFor(
        request: HttpRequest,
        waitTimeoutMs: Long,
        measure: () -> BaselineSample?,
    ): BaselineSample? {
        val key = keyOf(request) ?: return measure()
        dropIfExpired(key)
        val fresh = Entry(clock())
        val existing = entries.putIfAbsent(key, fresh)
        return if (existing == null) measureAsOwner(key, fresh, measure) else awaitSample(existing, waitTimeoutMs)
    }

    fun clear() {
        entries.clear()
    }

    fun size(): Int = entries.size

    private fun dropIfExpired(key: String) {
        val current = entries[key]
        if (current != null && current.sample.isDone && clock() - current.insertedAtMs >= ttlMs) {
            entries.remove(key, current)
        }
    }

    private fun measureAsOwner(
        key: String,
        entry: Entry,
        measure: () -> BaselineSample?,
    ): BaselineSample? {
        evictOldestCompleted()
        var sample: BaselineSample? = null
        try {
            sample = measure()
        } finally {
            if (sample == null) entries.remove(key, entry)
            entry.sample.complete(sample)
        }
        return sample
    }

    private fun evictOldestCompleted() {
        while (entries.size > maxEntries) {
            val oldest =
                entries.entries
                    .filter { it.value.sample.isDone }
                    .minByOrNull { it.value.insertedAtMs } ?: break
            entries.remove(oldest.key, oldest.value)
        }
    }

    private fun awaitSample(
        entry: Entry,
        waitTimeoutMs: Long,
    ): BaselineSample? =
        try {
            entry.sample.get(waitTimeoutMs, TimeUnit.MILLISECONDS)
        } catch (_: TimeoutException) {
            null
        } catch (_: ExecutionException) {
            null
        } catch (_: InterruptedException) {
            Thread.currentThread().interrupt()
            null
        }

    companion object {
        /** The content key of [request], or null when its service or raw bytes cannot be read. */
        fun keyOf(request: HttpRequest): String? =
            runCatching {
                val service = request.httpService()
                val bytes = request.toByteArray()?.bytes
                if (service == null || bytes == null) {
                    null
                } else {
                    val scheme = if (service.secure()) "https" else "http"
                    val tuple = "$scheme|${service.host()}|${service.port()}\n".toByteArray(Charsets.UTF_8)
                    Hashing.sha256Hex(tuple + bytes)
                }
            }.getOrNull()
    }
}
