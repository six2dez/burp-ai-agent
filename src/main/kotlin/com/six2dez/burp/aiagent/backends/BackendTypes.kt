package com.six2dez.burp.aiagent.backends

import com.six2dez.burp.aiagent.backends.http.MontoyaHttpTransport

data class BackendLaunchConfig(
    val backendId: String,
    val displayName: String,
    val command: List<String> = emptyList(), // for CLI backends
    val baseUrl: String? = null,             // for HTTP backends
    val model: String? = null,
    val headers: Map<String, String> = emptyMap(),
    val requestTimeoutSeconds: Long? = null,
    val embeddedMode: Boolean = false,
    val sessionId: String? = null,
    val determinismMode: Boolean = false,
    val env: Map<String, String> = emptyMap(),
    val cliSessionId: String? = null,        // for CLI session resume (e.g. Claude --resume)
    val contextWindow: Int? = null,
    val transport: MontoyaHttpTransport? = null
)

data class ChatMessage(val role: String, val content: String)

data class TokenUsage(
    val inputTokens: Int,
    val outputTokens: Int
)

sealed class HealthCheckResult {
    data object Healthy : HealthCheckResult()
    data class Degraded(val message: String) : HealthCheckResult()
    data class Unavailable(val message: String) : HealthCheckResult()
    data object Unknown : HealthCheckResult()

    val isHealthy: Boolean
        get() = this is Healthy

    val isReachable: Boolean
        get() = this is Healthy || this is Degraded

    fun summary(): String {
        return when (this) {
            Healthy -> "Healthy"
            is Degraded -> "Degraded: $message"
            is Unavailable -> "Unavailable: $message"
            Unknown -> "Unknown"
        }
    }
}

interface AgentConnection {
    fun isAlive(): Boolean
    fun send(
        text: String,
        history: List<ChatMessage>? = null,
        onChunk: (String) -> Unit,
        onComplete: (Throwable?) -> Unit,
        systemPrompt: String? = null,
        jsonMode: Boolean = false,
        maxOutputTokens: Int? = null
    )
    fun stop()
}

interface DiagnosableConnection {
    fun exitCode(): Int?
    fun lastOutputTail(): String?
}

interface UsageAwareConnection {
    fun lastTokenUsage(): TokenUsage?
}

interface JsonModeCapable

interface AiBackend {
    val id: String
    val displayName: String
    val supportsSystemRole: Boolean get() = false
    fun launch(config: BackendLaunchConfig): AgentConnection
    fun isAvailable(settings: com.six2dez.burp.aiagent.config.AgentSettings): Boolean = true
    fun healthCheck(settings: com.six2dez.burp.aiagent.config.AgentSettings): HealthCheckResult = HealthCheckResult.Unknown
}

interface SessionAwareConnection : AgentConnection {
    fun cliSessionId(): String?
}

interface AiBackendFactory {
    fun create(): AiBackend
}
