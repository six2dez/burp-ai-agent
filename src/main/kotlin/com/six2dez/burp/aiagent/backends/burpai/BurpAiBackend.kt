package com.six2dez.burp.aiagent.backends.burpai

import burp.api.montoya.MontoyaApi
import burp.api.montoya.ai.chat.Message
import burp.api.montoya.ai.chat.PromptOptions
import com.six2dez.burp.aiagent.backends.AgentConnection
import com.six2dez.burp.aiagent.backends.AiBackend
import com.six2dez.burp.aiagent.backends.BackendLaunchConfig
import com.six2dez.burp.aiagent.backends.ChatMessage
import com.six2dez.burp.aiagent.backends.HealthCheckResult
import com.six2dez.burp.aiagent.config.AgentSettings
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicBoolean

class BurpAiBackend(private val api: MontoyaApi) : AiBackend {
    override val id: String = "burp-ai"
    override val displayName: String = "Burp AI (built-in)"
    override val supportsSystemRole: Boolean = true

    override fun launch(config: BackendLaunchConfig): AgentConnection =
        BurpAiConnection(api, config)

    override fun isAvailable(settings: AgentSettings): Boolean =
        try { api.ai().isEnabled() } catch (_: Exception) { false }

    override fun healthCheck(settings: AgentSettings): HealthCheckResult =
        try {
            if (api.ai().isEnabled()) HealthCheckResult.Healthy
            else HealthCheckResult.Unavailable("Burp AI is not enabled. Enable 'Use AI' in Burp Suite settings.")
        } catch (e: Exception) {
            HealthCheckResult.Unavailable("Burp AI unavailable: ${e.message}")
        }
}

private class BurpAiConnection(
    private val api: MontoyaApi,
    private val config: BackendLaunchConfig
) : AgentConnection {

    private val alive = AtomicBoolean(true)
    private val exec: ExecutorService = Executors.newSingleThreadExecutor { r ->
        Thread(r, "burp-ai-${config.sessionId}").apply { isDaemon = true }
    }
    private val promptOptions = PromptOptions.promptOptions()
        .withTemperature(if (config.determinismMode) 0.0 else 0.3)

    override fun isAlive(): Boolean = alive.get()

    override fun send(
        text: String,
        history: List<ChatMessage>?,
        onChunk: (String) -> Unit,
        onComplete: (Throwable?) -> Unit,
        systemPrompt: String?,
        jsonMode: Boolean,
        maxOutputTokens: Int?
    ) {
        if (!alive.get()) {
            onComplete(IllegalStateException("Burp AI connection is closed"))
            return
        }
        try {
            exec.submit {
                try {
                    val messages = buildMessages(text, history, systemPrompt, jsonMode)
                    val response = api.ai().prompt().execute(promptOptions, *messages.toTypedArray())
                    val content = response.content() ?: ""
                    if (content.isNotEmpty()) {
                        onChunk(content)
                    }
                    onComplete(null)
                } catch (e: Exception) {
                    onComplete(e)
                }
            }
        } catch (e: java.util.concurrent.RejectedExecutionException) {
            onComplete(IllegalStateException("Burp AI connection is closed"))
        }
    }

    override fun stop() {
        alive.set(false)
        exec.shutdownNow()
    }

    private fun buildMessages(
        text: String,
        history: List<ChatMessage>?,
        systemPrompt: String?,
        jsonMode: Boolean
    ): List<Message> {
        val messages = mutableListOf<Message>()

        if (!systemPrompt.isNullOrBlank()) {
            messages.add(Message.systemMessage(systemPrompt))
        }

        history?.forEach { msg ->
            val m = when (msg.role.lowercase()) {
                "system" -> Message.systemMessage(msg.content)
                "assistant" -> Message.assistantMessage(msg.content)
                else -> Message.userMessage(msg.content)
            }
            messages.add(m)
        }

        val userText = if (jsonMode) {
            "$text\n\nIMPORTANT: Respond ONLY with valid JSON. No markdown, no explanation, just the JSON object."
        } else {
            text
        }
        messages.add(Message.userMessage(userText))

        return messages
    }
}
