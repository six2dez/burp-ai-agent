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
    val tlsEnabled: Boolean,
    val tlsAutoGenerate: Boolean,
    val tlsKeystorePath: String,
    val tlsKeystorePassword: String,
    val maxConcurrentRequests: Int,
    val maxBodyBytes: Int,
    val toolToggles: Map<String, Boolean>,
    val unsafeEnabled: Boolean,
    val hostAnonymizationSalt: String = ""
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
    }
}
