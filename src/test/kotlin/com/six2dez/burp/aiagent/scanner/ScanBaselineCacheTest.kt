package com.six2dez.burp.aiagent.scanner

import burp.api.montoya.http.HttpService
import burp.api.montoya.http.message.HttpRequestResponse
import burp.api.montoya.http.message.requests.HttpRequest
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNotEquals
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertSame
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import org.junit.jupiter.api.assertTimeoutPreemptively
import org.mockito.Answers
import org.mockito.Mockito
import org.mockito.kotlin.mock
import org.mockito.stubbing.Answer
import java.time.Duration
import java.util.concurrent.CountDownLatch
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicReferenceArray
import burp.api.montoya.core.ByteArray as MontoyaByteArray

/**
 * Quick 261008-vau — the contract of [ScanBaselineCache], driven directly with a manual clock:
 * reuse by request content, TTL, size bound (oldest completed first), failures never cached,
 * one in-flight measurement shared by concurrent lookups, clear, and the content key.
 *
 * The concurrency tests synchronise on latches and thread states only; no sleep length decides
 * an outcome.
 */
class ScanBaselineCacheTest {
    private var now = 0L
    private val cache = ScanBaselineCache(maxEntries = MAX_ENTRIES, ttlMs = TTL_MS, clock = { now })
    private val measurements = AtomicInteger(0)

    @Test
    fun aSecondLookupOfTheSameRequestReusesTheSample() {
        val first = cache.baselineFor(request("/a"), WAIT_MS, ::measure)
        val second = cache.baselineFor(request("/a"), WAIT_MS, ::measure)

        assertEquals(1, measurements.get())
        assertSame(first, second)
    }

    @Test
    fun aSampleIsReusedUntilItsTtlAndMeasuredAgainAfter() {
        cache.baselineFor(request("/a"), WAIT_MS, ::measure)
        now += TTL_MS - 1
        cache.baselineFor(request("/a"), WAIT_MS, ::measure)
        assertEquals(1, measurements.get(), "a sample younger than the TTL is reused")

        now += 2
        cache.baselineFor(request("/a"), WAIT_MS, ::measure)
        assertEquals(2, measurements.get(), "a sample older than the TTL is measured again")
    }

    @Test
    fun atMostMaxEntriesAreKeptAndTheOldestGoesFirst() {
        for (path in listOf("/1", "/2", "/3", "/4")) {
            cache.baselineFor(request(path), WAIT_MS, ::measure)
            now += 1
        }
        assertTrue(cache.size() <= MAX_ENTRIES, "size ${cache.size()} exceeds $MAX_ENTRIES")
        assertEquals(4, measurements.get())

        cache.baselineFor(request("/4"), WAIT_MS, ::measure)
        assertEquals(4, measurements.get(), "the newest sample is kept")

        cache.baselineFor(request("/1"), WAIT_MS, ::measure)
        assertEquals(5, measurements.get(), "the oldest sample was evicted")
    }

    @Test
    fun aNullOrThrowingMeasurementIsNotCached() {
        assertNull(cache.baselineFor(request("/a"), WAIT_MS) { measurements.incrementAndGet().let { null } })
        cache.baselineFor(request("/a"), WAIT_MS, ::measure)
        assertEquals(2, measurements.get(), "a null measurement is not cached")

        val failure = IllegalStateException("boom")
        val thrown = assertThrows<IllegalStateException> { cache.baselineFor(request("/b"), WAIT_MS) { throw failure } }
        assertSame(failure, thrown)
        cache.baselineFor(request("/b"), WAIT_MS, ::measure)
        assertEquals(3, measurements.get(), "a throwing measurement is not cached")
    }

    @Test
    fun concurrentLookupsShareOneInFlightMeasurement() {
        val results = sharedFlight { sample() }

        assertEquals(1, measurements.get(), "one measurement for five concurrent lookups")
        assertNotNull(results[0])
        for (index in 1 until LOOKUPS) {
            assertSame(results[0], results[index], "lookup $index shares the owner's sample")
        }
    }

    @Test
    fun waitersOfAFailedFlightGetNoSampleAndALaterLookupRetries() {
        val results = sharedFlight { null }

        assertEquals(1, measurements.get(), "one measurement during the flight")
        for (index in 0 until LOOKUPS) {
            assertNull(results[index], "lookup $index gets no sample from a failed flight")
        }
        cache.baselineFor(request("/a"), WAIT_MS, ::measure)
        assertEquals(2, measurements.get(), "a later lookup measures again")
    }

    @Test
    fun clearDropsEverySample() {
        cache.baselineFor(request("/a"), WAIT_MS, ::measure)
        cache.baselineFor(request("/a"), WAIT_MS, ::measure)
        assertEquals(1, measurements.get())

        cache.clear()
        assertEquals(0, cache.size())
        cache.baselineFor(request("/a"), WAIT_MS, ::measure)
        assertEquals(2, measurements.get())
    }

    @Test
    fun theKeyCoversServiceAndBytes() {
        val key = ScanBaselineCache.keyOf(request("/a"))
        assertNotNull(key)
        assertTrue(Regex("[0-9a-f]{64}").matches(key.orEmpty()), "key is a SHA-256 hex digest: $key")
        assertEquals(key, ScanBaselineCache.keyOf(request("/a")), "equal content, distinct objects")
        assertNotEquals(key, ScanBaselineCache.keyOf(request("/b")), "other bytes")
        assertNotEquals(key, ScanBaselineCache.keyOf(request("/a", host = "other.example")), "other host")
        assertNotEquals(key, ScanBaselineCache.keyOf(request("/a", port = 8443)), "other port")
        assertNotEquals(key, ScanBaselineCache.keyOf(request("/a", secure = false)), "other scheme")
        assertNull(ScanBaselineCache.keyOf(request("/a", withBytes = false)), "no bytes, no key")
        assertNull(ScanBaselineCache.keyOf(request("/a", withService = false)), "no service, no key")
    }

    @Test
    fun anUnkeyableRequestIsMeasuredEveryTime() {
        cache.baselineFor(request("/a", withBytes = false), WAIT_MS, ::measure)
        cache.baselineFor(request("/a", withBytes = false), WAIT_MS, ::measure)

        assertEquals(2, measurements.get())
        assertEquals(0, cache.size())
    }

    // ---------------------------------------------------------------------------------------------
    // Fixture
    // ---------------------------------------------------------------------------------------------

    private fun measure(): BaselineSample {
        measurements.incrementAndGet()
        return sample()
    }

    private fun sample(): BaselineSample = BaselineSample(mock<HttpRequestResponse>(), SAMPLE_ELAPSED_MS)

    /**
     * Runs one owner lookup whose measurement blocks on a latch, starts four more lookups of the
     * same request, waits until all four are parked, then releases the owner. Returns the five
     * results in start order (owner first).
     */
    private fun sharedFlight(ownerResult: () -> BaselineSample?): AtomicReferenceArray<BaselineSample?> {
        val results = AtomicReferenceArray<BaselineSample?>(LOOKUPS)
        val entered = CountDownLatch(1)
        val release = CountDownLatch(1)
        val blockingMeasure: () -> BaselineSample? = {
            measurements.incrementAndGet()
            entered.countDown()
            release.await()
            ownerResult()
        }
        assertTimeoutPreemptively(Duration.ofSeconds(AWAIT_SECONDS)) {
            val owner = Thread { results.set(0, cache.baselineFor(request("/a"), WAIT_MS, blockingMeasure)) }
            owner.start()
            entered.await()
            val waiters =
                (1 until LOOKUPS).map { index ->
                    Thread { results.set(index, cache.baselineFor(request("/a"), WAIT_MS, blockingMeasure)) }
                }
            waiters.forEach { it.start() }
            while (!waiters.all { it.state == Thread.State.WAITING || it.state == Thread.State.TIMED_WAITING }) {
                Thread.onSpinWait()
            }
            release.countDown()
            owner.join()
            waiters.forEach { it.join() }
        }
        return results
    }

    private fun request(
        path: String,
        host: String = "target.example",
        port: Int = 443,
        secure: Boolean = true,
        withBytes: Boolean = true,
        withService: Boolean = true,
    ): HttpRequest {
        val service =
            answering(HttpService::class.java) { name ->
                when (name) {
                    "host" -> host
                    "port" -> port
                    "secure" -> secure
                    else -> DEFAULT
                }
            }
        val raw = "GET $path HTTP/1.1\r\nHost: $host\r\n\r\n".toByteArray(Charsets.UTF_8)
        val bytes = answering(MontoyaByteArray::class.java) { name -> if (name == "getBytes") raw.copyOf() else DEFAULT }
        return answering(HttpRequest::class.java) { name ->
            when (name) {
                "httpService" -> if (withService) service else null
                "toByteArray" -> if (withBytes) bytes else null
                "method" -> "GET"
                "path" -> path
                else -> DEFAULT
            }
        }
    }

    private fun <T> answering(
        type: Class<T>,
        answer: (String) -> Any?,
    ): T =
        Mockito.mock(
            type,
            Answer<Any?> { invocation ->
                val result = answer(invocation.method.name)
                if (result === DEFAULT) Answers.RETURNS_DEFAULTS.answer(invocation) else result
            },
        )

    private companion object {
        val DEFAULT = Any()
        const val MAX_ENTRIES = 3
        const val TTL_MS = 1_000L
        const val WAIT_MS = 10_000L
        const val LOOKUPS = 5
        const val AWAIT_SECONDS = 10L
        const val SAMPLE_ELAPSED_MS = 5L
    }
}
