package com.six2dez.burp.aiagent.scanner

import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.module.kotlin.registerKotlinModule
import com.six2dez.burp.aiagent.redact.PrivacyMode
import com.six2dez.burp.aiagent.supervisor.AgentSupervisor
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicReference

/**
 * Generates adaptive payloads using AI based on knowledge base context.
 * Payloads are cached per (vulnClass, techStack) key to avoid redundant AI calls.
 */
class AdaptivePayloadEngine(
    private val supervisor: AgentSupervisor
) {
    private val mapper = ObjectMapper().registerKotlinModule()

    // Cache: key = "vulnClass:sortedTechStack" -> generated payloads
    private val payloadCache = ConcurrentHashMap<String, CachedPayloads>()

    private data class CachedPayloads(
        val payloads: List<Payload>,
        val createdAtMs: Long = System.currentTimeMillis()
    )

    fun generateAdaptivePayloads(
        vulnClass: VulnClass,
        host: String,
        paramName: String,
        originalValue: String,
        maxPayloads: Int = 5,
        privacyMode: PrivacyMode = PrivacyMode.BALANCED
    ): List<Payload> {
        val techStack = ScanKnowledgeBase.getTechStack(host)
        val errorPatterns = ScanKnowledgeBase.getErrorPatterns(host)

        // Nothing adaptive to do without context
        if (techStack.isEmpty() && errorPatterns.isEmpty()) return emptyList()

        // Check cache
        val cacheKey = "${vulnClass.name}:${techStack.sorted().joinToString(",")}"
        val cached = payloadCache[cacheKey]
        if (cached != null && System.currentTimeMillis() - cached.createdAtMs < CACHE_TTL_MS) {
            return cached.payloads.take(maxPayloads)
        }

        // Redact sensitive data in prompt context when privacy mode is active
        val safeHost = if (privacyMode != PrivacyMode.OFF) "[REDACTED_HOST]" else host
        val safeParamName = if (privacyMode == PrivacyMode.STRICT) "[REDACTED_PARAM]" else paramName
        val safeOriginalValue = if (privacyMode != PrivacyMode.OFF) "[REDACTED_VALUE]" else originalValue
        val safeErrorPatterns = if (privacyMode == PrivacyMode.STRICT) emptySet() else errorPatterns

        // Build prompt for AI
        val prompt = buildPayloadPrompt(vulnClass, techStack, safeErrorPatterns, safeParamName, safeOriginalValue, maxPayloads)

        // Send to AI with short timeout
        val responseBuffer = StringBuilder()
        val latch = CountDownLatch(1)
        val errorRef = AtomicReference<String?>(null)

        try {
            supervisor.send(
                text = prompt,
                history = emptyList(),
                contextJson = null,
                privacyMode = privacyMode,
                determinismMode = true,
                onChunk = { chunk -> responseBuffer.append(chunk) },
                onComplete = { err ->
                    errorRef.set(err?.message)
                    latch.countDown()
                },
                traceId = "adaptive-payload-${vulnClass.name}",
                jsonMode = true,
                maxOutputTokens = com.six2dez.burp.aiagent.config.Defaults.PAYLOAD_MAX_OUTPUT_TOKENS
            )

            if (!latch.await(TIMEOUT_MS, TimeUnit.MILLISECONDS)) return emptyList()
            if (errorRef.get() != null) return emptyList()

            val payloads = parsePayloadResponse(responseBuffer.toString(), vulnClass)
            if (payloads.isNotEmpty()) {
                payloadCache[cacheKey] = CachedPayloads(payloads)
            }
            return payloads.take(maxPayloads)
        } catch (_: Exception) {
            return emptyList()
        }
    }

    private fun buildPayloadPrompt(
        vulnClass: VulnClass,
        techStack: Set<String>,
        errorPatterns: Set<String>,
        paramName: String,
        originalValue: String,
        maxPayloads: Int
    ): String {
        return """
Generate $maxPayloads test payloads for ${vulnClass.name} vulnerability testing.

Context:
- Target technologies: ${techStack.joinToString(", ").ifBlank { "unknown" }}
- Parameter name: $paramName
- Original value: ${originalValue.take(100)}
${if (errorPatterns.isNotEmpty()) "- Error patterns observed: ${errorPatterns.take(3).joinToString("; ")}" else ""}

Requirements:
- Payloads must be specific to the detected technology stack
- Each payload should test a different bypass technique
- Include WAF bypass variants if applicable
- DO NOT include destructive payloads (DROP, DELETE, TRUNCATE, shutdown, rm)
- Keep payloads under 200 characters

Output JSON array only:
[{"value":"payload_string","detection":"ERROR_BASED|BLIND_BOOLEAN|BLIND_TIME|REFLECTION","evidence":"what to look for in response"}]
""".trim()
    }

    private fun parsePayloadResponse(text: String, vulnClass: VulnClass): List<Payload> {
        if (text.isBlank()) return emptyList()
        return try {
            val cleaned = text.trim()
                .removePrefix("```json").removePrefix("```")
                .removeSuffix("```").trim()
            val root = mapper.readTree(cleaned)
            val array = if (root.isArray) root else root.path("payloads").takeIf { it.isArray } ?: return emptyList()

            array.mapNotNull { node ->
                val value = node.path("value").asText("").take(200)
                if (value.isBlank()) return@mapNotNull null
                // Safety: reject destructive payloads
                if (DESTRUCTIVE_PATTERN.containsMatchIn(value)) return@mapNotNull null

                val detection = when (node.path("detection").asText("").uppercase()) {
                    "BLIND_BOOLEAN" -> DetectionMethod.BLIND_BOOLEAN
                    "BLIND_TIME" -> DetectionMethod.BLIND_TIME
                    "REFLECTION" -> DetectionMethod.REFLECTION
                    "OUT_OF_BAND" -> DetectionMethod.OUT_OF_BAND
                    else -> DetectionMethod.ERROR_BASED
                }
                val evidence = node.path("evidence").asText("AI-generated payload")
                Payload(value, vulnClass, detection, PayloadRisk.MODERATE, evidence)
            }
        } catch (_: Exception) {
            emptyList()
        }
    }

    fun clearCache() {
        payloadCache.clear()
    }

    companion object {
        private const val CACHE_TTL_MS = 30L * 60 * 1000 // 30 minutes
        private const val TIMEOUT_MS = 15_000L
        private val DESTRUCTIVE_PATTERN = Regex(
            "\\b(DROP|DELETE|TRUNCATE|ALTER|GRANT|REVOKE|SHUTDOWN|EXEC\\s+xp_|rm\\s+-|FORMAT|DESTROY)\\b",
            RegexOption.IGNORE_CASE
        )
    }
}
