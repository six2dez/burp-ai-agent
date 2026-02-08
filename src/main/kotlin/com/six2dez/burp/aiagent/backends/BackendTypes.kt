package com.six2dez.burp.aiagent.backends

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
    val contextWindow: Int? = null
)

data class ChatMessage(val role: String, val content: String)

interface AgentConnection {
    fun isAlive(): Boolean
    fun send(
        text: String,
        history: List<ChatMessage>? = null,
        onChunk: (String) -> Unit,
        onComplete: (Throwable?) -> Unit
    )
    fun stop()
}

interface DiagnosableConnection {
    fun exitCode(): Int?
    fun lastOutputTail(): String?
}

interface AiBackend {
    val id: String
    val displayName: String
    fun launch(config: BackendLaunchConfig): AgentConnection
    fun isAvailable(settings: com.six2dez.burp.aiagent.config.AgentSettings): Boolean = true
}

interface SessionAwareConnection : AgentConnection {
    fun cliSessionId(): String?
}

interface AiBackendFactory {
    fun create(): AiBackend
}
