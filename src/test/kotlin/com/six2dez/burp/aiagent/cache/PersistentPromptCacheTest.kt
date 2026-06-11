package com.six2dez.burp.aiagent.cache

import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import java.io.File
import java.nio.file.Files

/**
 * SC4 / QUAL-02 — covers three critical paths in PersistentPromptCache that previously had
 * zero test coverage: put/get round-trip, TTL eviction, and disk-size eviction.
 *
 * All tests use a temp directory injected via the constructor; the production
 * ~/.burp-ai-agent/cache/ directory is never accessed.
 */
class PersistentPromptCacheTest {
    private lateinit var tmpDir: File

    @BeforeEach
    fun setUp() {
        // Always use a temp directory — never the production ~/.burp-ai-agent/cache/
        tmpDir = Files.createTempDirectory("cache-test").toFile()
    }

    @AfterEach
    fun tearDown() {
        tmpDir.deleteRecursively()
    }

    @Test
    fun putAndGetRoundTrip() {
        val cache = PersistentPromptCache(cacheDir = tmpDir)
        val entry =
            CachedEntry(
                createdAtMs = System.currentTimeMillis(),
                issues = listOf(CachedIssue(title = "SQLI", severity = "HIGH")),
            )
        cache.put("abc123", entry)
        val retrieved = cache.get("abc123")
        assertNotNull(retrieved)
        assertEquals("SQLI", retrieved!!.issues.first().title)
    }

    @Test
    fun getReturnsNullForExpiredEntry() {
        // ttlMs = 1L so any entry older than 1 ms is immediately expired
        val cache = PersistentPromptCache(cacheDir = tmpDir, ttlMs = 1L)
        // Write an entry with a creation timestamp 1 second in the past
        val entry =
            CachedEntry(
                createdAtMs = System.currentTimeMillis() - 1000L,
                issues = emptyList(),
            )
        cache.put("hash1", entry)
        // Small sleep ensures at least 1 ms has elapsed since createdAtMs
        Thread.sleep(5)
        assertNull(cache.get("hash1"))
    }

    @Test
    fun evictsOldestWhenDiskLimitExceeded() {
        // maxDiskBytes = 200 forces eviction after a few entries
        val cache = PersistentPromptCache(cacheDir = tmpDir, maxDiskBytes = 200L)
        repeat(20) { i ->
            cache.put(
                "hash$i",
                CachedEntry(
                    createdAtMs = System.currentTimeMillis(),
                    issues = listOf(CachedIssue(title = "T$i")),
                ),
            )
        }
        assertTrue(cache.diskSizeBytes() <= 200L, "disk size must be within the limit after eviction")
    }
}
