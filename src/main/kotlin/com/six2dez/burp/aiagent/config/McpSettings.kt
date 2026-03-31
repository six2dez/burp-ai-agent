package com.six2dez.burp.aiagent.config

import com.fasterxml.jackson.databind.json.JsonMapper
import com.fasterxml.jackson.module.kotlin.registerKotlinModule
import java.security.SecureRandom
import java.util.Base64

data class McpSettings(
    val enabled: Boolean,
    val host: String,
    val port: Int,
    val externalEnabled: Boolean,
    val stdioEnabled: Boolean,
    val token: String,
    val allowedOrigins: List<String>,
    val tlsEnabled: Boolean,
    val tlsAutoGenerate: Boolean,
    val tlsKeystorePath: String,
    val tlsKeystorePassword: String,
    val scanTaskTtlMinutes: Int,
    val collaboratorClientTtlMinutes: Int,
    val maxConcurrentRequests: Int,
    val maxBodyBytes: Int,
    val proxyHistoryMaxItemsPerRequest: Int = Defaults.MCP_PROXY_HISTORY_MAX_ITEMS_PER_REQUEST,
    val proxyHistoryNewestFirst: Boolean = Defaults.MCP_PROXY_HISTORY_NEWEST_FIRST,
    val toolToggles: Map<String, Boolean>,
    val enabledUnsafeTools: Set<String>,
    val unsafeEnabled: Boolean
) {
    companion object {
        private val mapper = JsonMapper.builder()
            .build()
            .registerKotlinModule()

        fun generateToken(): String {
            val bytes = ByteArray(32)
            SecureRandom().nextBytes(bytes)
            return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes)
        }

        fun generatePassword(): String {
            val bytes = ByteArray(24)
            SecureRandom().nextBytes(bytes)
            return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes)
        }

        fun parseToolToggles(raw: String?): Map<String, Boolean> {
            if (raw.isNullOrBlank()) return emptyMap()
            return try {
                mapper.readValue(raw, Map::class.java)
                    .mapNotNull { (k, v) ->
                        val key = k?.toString()?.trim().orEmpty()
                        val value = when (v) {
                            is Boolean -> v
                            is String -> v.equals("true", ignoreCase = true)
                            else -> null
                        }
                        if (key.isNotBlank() && value != null) key to value else null
                    }
                    .toMap()
            } catch (_: Exception) {
                emptyMap()
            }
        }

        fun serializeToolToggles(toggles: Map<String, Boolean>): String {
            return try {
                mapper.writeValueAsString(toggles)
            } catch (_: Exception) {
                "{}"
            }
        }

        fun parseAllowedOrigins(raw: String?): List<String> {
            if (raw.isNullOrBlank()) return emptyList()
            return raw
                .split('\n', ',', ';')
                .asSequence()
                .map { it.trim() }
                .filter { it.isNotBlank() }
                .distinct()
                .toList()
        }

        fun serializeAllowedOrigins(origins: List<String>): String {
            if (origins.isEmpty()) return ""
            return origins
                .asSequence()
                .map { it.trim() }
                .filter { it.isNotBlank() }
                .distinct()
                .joinToString("\n")
        }

        fun parseUnsafeToolSet(raw: String?): Set<String> {
            if (raw.isNullOrBlank()) return emptySet()
            return raw
                .split(',', '\n', ';')
                .asSequence()
                .map { it.trim() }
                .filter { it.isNotBlank() }
                .toSet()
        }

        fun serializeUnsafeToolSet(ids: Set<String>): String {
            if (ids.isEmpty()) return ""
            return ids
                .asSequence()
                .map { it.trim() }
                .filter { it.isNotBlank() }
                .sorted()
                .joinToString(",")
        }
    }
}
