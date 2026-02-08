package com.six2dez.burp.aiagent.backends.http

import com.six2dez.burp.aiagent.config.Defaults
import okhttp3.OkHttpClient
import java.io.EOFException
import java.net.Proxy
import java.util.concurrent.ConcurrentLinkedDeque

object HttpBackendSupport {
    fun buildClient(timeoutSeconds: Long): OkHttpClient {
        return OkHttpClient.Builder()
            .connectTimeout(java.time.Duration.ofSeconds(10))
            .writeTimeout(java.time.Duration.ofSeconds(30))
            .readTimeout(java.time.Duration.ofSeconds(timeoutSeconds))
            .callTimeout(java.time.Duration.ofSeconds(timeoutSeconds))
            .proxy(Proxy.NO_PROXY)
            .build()
    }

    fun isRetryableConnectionError(e: Exception): Boolean {
        if (e is EOFException) return true
        if (e is java.net.ConnectException || e is java.net.SocketTimeoutException) return true
        if (e is java.net.SocketException) return true
        val msg = e.message?.lowercase().orEmpty()
        return msg.contains("failed to connect") ||
            msg.contains("connection refused") ||
            msg.contains("timeout") ||
            msg.contains("unexpected end of stream") ||
            msg.contains("stream was reset") ||
            msg.contains("end of input")
    }

    fun retryDelayMs(attempt: Int): Long {
        return when (attempt) {
            0 -> 500
            1 -> 1000
            2 -> 1500
            3 -> 2000
            4 -> 3000
            else -> 4000
        }
    }
}

class ConversationHistory(private val maxMessages: Int = Defaults.MAX_HISTORY_MESSAGES) {
    private val history = ConcurrentLinkedDeque<Map<String, String>>()

    fun addUser(content: String) {
        history.addLast(mapOf("role" to "user", "content" to content))
        trim()
    }

    fun addAssistant(content: String) {
        history.addLast(mapOf("role" to "assistant", "content" to content))
        trim()
    }

    fun snapshot(): List<Map<String, String>> = history.toList()

    fun setHistory(newHistory: List<com.six2dez.burp.aiagent.backends.ChatMessage>) {
        history.clear()
        newHistory.forEach { msg ->
            history.addLast(mapOf("role" to msg.role, "content" to msg.content))
        }
        trim()
    }

    private fun trim() {
        while (history.size > maxMessages) {
            history.pollFirst()
        }
    }
}
