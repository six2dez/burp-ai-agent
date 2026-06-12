package com.six2dez.burp.aiagent.cache

import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.module.kotlin.registerKotlinModule
import java.io.File
import java.util.concurrent.locks.ReentrantReadWriteLock
import kotlin.concurrent.read
import kotlin.concurrent.write

data class CachedEntry(
    val createdAtMs: Long,
    val issues: List<CachedIssue>,
)

data class CachedIssue(
    val reasoning: String? = null,
    val title: String? = null,
    val severity: String? = null,
    val detail: String? = null,
    val confidence: Int? = null,
    val requestIndex: Int? = null,
)

class PersistentPromptCache(
    private val cacheDir: File = File(System.getProperty("user.home"), ".burp-ai-agent/cache"),
    val maxDiskBytes: Long = DEFAULT_MAX_DISK_BYTES,
    val ttlMs: Long = DEFAULT_TTL_MS,
) {
    private val mapper = ObjectMapper().registerKotlinModule()
    private val lock = ReentrantReadWriteLock()

    init {
        cacheDir.mkdirs()
    }

    fun get(promptHash: String): CachedEntry? {
        val file = fileFor(promptHash)
        val hit: CachedEntry? =
            lock.read {
                try {
                    val entry = mapper.readValue(file, CachedEntry::class.java)
                    if (System.currentTimeMillis() - entry.createdAtMs <= ttlMs) entry else null
                } catch (_: Exception) {
                    // INTENTIONAL: cache read failures are best-effort; corrupt/missing files are
                    // cleaned up under the write lock below; must not crash scanner pipeline.
                    null
                }
            }
        if (hit != null) return hit

        // Expired or corrupt entry: remove the stale file under the WRITE lock. Never mutate the
        // filesystem while holding only the read lock (WR-01). Re-validate under the write lock so a
        // concurrent put() that refreshed this entry between locks is not discarded.
        if (file.exists()) {
            lock.write {
                try {
                    val current = mapper.readValue(file, CachedEntry::class.java)
                    if (System.currentTimeMillis() - current.createdAtMs > ttlMs) file.delete()
                } catch (_: Exception) {
                    // INTENTIONAL: corrupt/unreadable cache file — best-effort delete; ignore failures.
                    if (file.exists()) file.delete()
                }
            }
        }
        return null
    }

    fun put(
        promptHash: String,
        entry: CachedEntry,
    ) {
        val file = fileFor(promptHash)
        lock.write {
            try {
                mapper.writeValue(file, entry)
                evictIfNeeded()
            } catch (_: Exception) {
                // INTENTIONAL: cache write failures are best-effort; must not crash scanner pipeline
            }
        }
    }

    fun clear() {
        lock.write {
            cacheDir.listFiles { f -> f.extension == "json" }?.forEach { it.delete() }
        }
    }

    fun diskSizeBytes(): Long =
        lock.read {
            cacheDir
                .listFiles { f -> f.extension == "json" }
                ?.sumOf { it.length() } ?: 0L
        }

    fun entryCount(): Int =
        lock.read {
            cacheDir.listFiles { f -> f.extension == "json" }?.size ?: 0
        }

    private fun fileFor(promptHash: String): File {
        val safeHash = promptHash.replace(SAFE_HASH_REGEX, "").take(64)
        return File(cacheDir, "$safeHash.json")
    }

    private fun evictIfNeeded() {
        val files = cacheDir.listFiles { f -> f.extension == "json" } ?: return
        val filesWithSize = files.map { it to it.length() }
        var totalSize = filesWithSize.sumOf { it.second }
        if (totalSize <= maxDiskBytes) return

        // Evict oldest files first (LRU by lastModified)
        val sorted = filesWithSize.sortedBy { it.first.lastModified() }
        for ((file, size) in sorted) {
            if (totalSize <= (maxDiskBytes * 0.8).toLong()) break // Evict to 80% capacity
            totalSize -= size
            file.delete()
        }
    }

    companion object {
        const val DEFAULT_MAX_DISK_BYTES = 50L * 1024 * 1024 // 50 MB
        const val DEFAULT_TTL_MS = 24L * 60 * 60 * 1000 // 24 hours
        private val SAFE_HASH_REGEX = Regex("[^a-zA-Z0-9]")
    }
}
