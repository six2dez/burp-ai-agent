package com.six2dez.burp.aiagent.scanner

import com.six2dez.burp.aiagent.util.IssueUtils
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicLong

/**
 * Shared knowledge base across passive scanner, active scanner, and chat.
 * Stores tech stack hints, vulnerability signals, and host context
 * so each component can make smarter decisions.
 */
object ScanKnowledgeBase {

    // Tech stack detected per host (e.g., "nginx", "Django", "PostgreSQL")
    private val techStackByHost = ConcurrentHashMap<String, MutableSet<String>>()

    // Vulnerability signals per normalized endpoint
    private val vulnSignals = ConcurrentHashMap<String, MutableList<VulnSignal>>()

    // Error patterns observed per host (for adaptive payload generation)
    private val errorPatterns = ConcurrentHashMap<String, MutableSet<String>>()

    // Auth patterns per host
    private val authPatterns = ConcurrentHashMap<String, AuthInfo>()

    private val lastUpdatedMs = AtomicLong(0L)

    data class VulnSignal(
        val endpoint: String,
        val vulnClass: String,
        val severity: String,
        val confidence: Int,
        val source: String,         // "passive", "active", "chat", "bounty_prompt"
        val evidence: String = "",
        val timestampMs: Long = System.currentTimeMillis()
    )

    data class AuthInfo(
        val hasSessionCookies: Boolean = false,
        val hasAuthHeader: Boolean = false,
        val hasApiKey: Boolean = false,
        val authCookieNames: Set<String> = emptySet()
    )

    // --- Tech Stack ---

    fun recordTechStack(host: String, technologies: Set<String>) {
        if (technologies.isEmpty()) return
        val normalized = host.lowercase()
        techStackByHost.getOrPut(normalized) { ConcurrentHashMap.newKeySet() }
            .addAll(technologies.map { it.lowercase() })
        lastUpdatedMs.set(System.currentTimeMillis())
    }

    fun getTechStack(host: String): Set<String> {
        return techStackByHost[host.lowercase()]?.toSet() ?: emptySet()
    }

    // --- Vulnerability Signals ---

    fun recordVulnSignal(signal: VulnSignal) {
        val key = normalizeEndpointKey(signal.endpoint)
        val signals = vulnSignals.getOrPut(key) { mutableListOf() }
        synchronized(signals) {
            // Avoid duplicate signals for same vuln class on same endpoint
            val exists = signals.any {
                it.vulnClass == signal.vulnClass && it.source == signal.source
            }
            if (!exists) {
                signals.add(signal)
                if (signals.size > MAX_SIGNALS_PER_ENDPOINT) {
                    signals.removeAt(0)
                }
            }
        }
        lastUpdatedMs.set(System.currentTimeMillis())
    }

    fun getVulnSignals(endpoint: String): List<VulnSignal> {
        val key = normalizeEndpointKey(endpoint)
        return vulnSignals[key]?.let { synchronized(it) { it.toList() } } ?: emptyList()
    }

    fun getSignalsByHost(host: String): List<VulnSignal> {
        val normalized = host.lowercase()
        return vulnSignals.entries
            .filter { it.key.contains(normalized) }
            .flatMap { entry -> synchronized(entry.value) { entry.value.toList() } }
    }

    fun hasHighPrioritySignals(endpoint: String): Boolean {
        return getVulnSignals(endpoint).any {
            it.severity.uppercase() in setOf("CRITICAL", "HIGH") && it.confidence >= 80
        }
    }

    // --- Error Patterns ---

    fun recordErrorPattern(host: String, pattern: String) {
        val normalized = host.lowercase()
        errorPatterns.getOrPut(normalized) { ConcurrentHashMap.newKeySet() }
            .add(pattern.take(200))
        lastUpdatedMs.set(System.currentTimeMillis())
    }

    fun getErrorPatterns(host: String): Set<String> {
        return errorPatterns[host.lowercase()]?.toSet() ?: emptySet()
    }

    // --- Auth Info ---

    fun recordAuthInfo(host: String, info: AuthInfo) {
        authPatterns[host.lowercase()] = info
        lastUpdatedMs.set(System.currentTimeMillis())
    }

    fun getAuthInfo(host: String): AuthInfo? {
        return authPatterns[host.lowercase()]
    }

    // --- Context Summary (for chat / AI prompts) ---

    fun buildContextSummary(host: String): String? {
        val tech = getTechStack(host)
        val signals = getSignalsByHost(host)
        val errors = getErrorPatterns(host)
        val auth = getAuthInfo(host)

        if (tech.isEmpty() && signals.isEmpty() && errors.isEmpty() && auth == null) return null

        return buildString {
            if (tech.isNotEmpty()) {
                appendLine("Detected technologies: ${tech.joinToString(", ")}")
            }
            if (auth != null) {
                val authTypes = mutableListOf<String>()
                if (auth.hasSessionCookies) authTypes.add("session cookies (${auth.authCookieNames.joinToString(",")})")
                if (auth.hasAuthHeader) authTypes.add("auth header")
                if (auth.hasApiKey) authTypes.add("API key")
                if (authTypes.isNotEmpty()) {
                    appendLine("Auth mechanisms: ${authTypes.joinToString(", ")}")
                }
            }
            if (signals.isNotEmpty()) {
                appendLine("Previous findings (${signals.size}):")
                signals.sortedByDescending { it.confidence }.take(10).forEach { s ->
                    appendLine("  - [${s.severity}] ${s.vulnClass} on ${s.endpoint.takeLast(60)} (${s.source}, confidence=${s.confidence})")
                }
            }
            if (errors.isNotEmpty()) {
                appendLine("Error patterns observed: ${errors.take(5).joinToString(", ")}")
            }
        }.trim()
    }

    // --- Maintenance ---

    fun clear() {
        techStackByHost.clear()
        vulnSignals.clear()
        errorPatterns.clear()
        authPatterns.clear()
        lastUpdatedMs.set(0L)
    }

    fun stats(): Map<String, Int> = mapOf(
        "hosts" to techStackByHost.size,
        "endpoints_with_signals" to vulnSignals.size,
        "total_signals" to vulnSignals.values.sumOf { synchronized(it) { it.size } },
        "hosts_with_errors" to errorPatterns.size,
        "hosts_with_auth" to authPatterns.size
    )

    private fun normalizeEndpointKey(endpoint: String): String {
        return try {
            val uri = java.net.URI(endpoint)
            val host = uri.host?.lowercase().orEmpty()
            val path = IssueUtils.normalizePathSegments(uri.path.orEmpty())
            "$host:$path"
        } catch (_: Exception) {
            endpoint.lowercase().take(200)
        }
    }

    private const val MAX_SIGNALS_PER_ENDPOINT = 20
}
