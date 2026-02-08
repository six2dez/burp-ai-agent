package com.six2dez.burp.aiagent.supervisor

import com.six2dez.burp.aiagent.backends.AgentConnection
import com.six2dez.burp.aiagent.backends.SessionAwareConnection
import java.util.concurrent.ConcurrentHashMap

/**
 * Manages per-chat-session connection state so that follow-up messages
 * within the same chat can resume context (e.g. Claude CLI --resume,
 * or Ollama/LM Studio in-memory conversation history).
 */
class ChatSessionManager {

    private data class ChatConnectionState(
        val backendId: String,
        val cliSessionId: String?,
        val connection: AgentConnection?
    )

    private val sessions = ConcurrentHashMap<String, ChatConnectionState>()

    /**
     * Returns the stored cliSessionId for a chat session, or null if none.
     */
    fun cliSessionIdFor(chatId: String, requestedBackendId: String): String? {
        val state = sessions[chatId] ?: return null
        if (state.backendId != requestedBackendId) return null
        return state.cliSessionId
    }

    /**
     * Returns an existing reusable connection for HTTP backends (Ollama/LM Studio)
     * that maintain in-memory conversation history.
     */
    fun existingConnectionFor(chatId: String, backendId: String): AgentConnection? {
        val state = sessions[chatId] ?: return null
        if (state.backendId != backendId) return null
        val conn = state.connection ?: return null
        return if (conn.isAlive()) conn else null
    }

    /**
     * Update session state after a message completes.
     * For CLI backends: stores the cliSessionId for resume on next message.
     * For HTTP backends: stores the connection for reuse (conversation history).
     */
    fun updateSession(chatId: String, backendId: String, connection: AgentConnection) {
        val cliSessionId = (connection as? SessionAwareConnection)?.cliSessionId()
        sessions[chatId] = ChatConnectionState(
            backendId = backendId,
            cliSessionId = cliSessionId,
            connection = connection
        )
    }

    /**
     * Remove session state when a chat is deleted or cleared.
     */
    fun removeSession(chatId: String) {
        val removed = sessions.remove(chatId)
        removed?.connection?.stop()
    }

    /**
     * Shutdown all sessions.
     */
    fun shutdown() {
        for ((_, state) in sessions) {
            try {
                state.connection?.stop()
            } catch (e: Exception) {
                System.err.println("Failed to stop chat session connection: ${e.message}")
            }
        }
        sessions.clear()
    }
}
