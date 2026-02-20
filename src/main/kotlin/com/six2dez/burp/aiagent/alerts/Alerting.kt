package com.six2dez.burp.aiagent.alerts

import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import java.util.concurrent.TimeUnit

object Alerting {
    private val client = OkHttpClient.Builder()
        .connectTimeout(5, TimeUnit.SECONDS)
        .readTimeout(10, TimeUnit.SECONDS)
        .writeTimeout(10, TimeUnit.SECONDS)
        .build()

    fun sendWebhook(webhookUrl: String, text: String) {
        val json = """{"text":${escapeJson(text)}}"""
        val req = Request.Builder()
            .url(webhookUrl)
            .post(json.toRequestBody("application/json".toMediaType()))
            .build()
        try {
            client.newCall(req).execute().use { response ->
                if (!response.isSuccessful) {
                    System.err.println("[Burp AI Agent] Webhook delivery failed: HTTP ${response.code} for $webhookUrl")
                }
            }
        } catch (e: java.io.IOException) {
            System.err.println("[Burp AI Agent] Webhook delivery failed for $webhookUrl: ${e.message}")
        } catch (e: Exception) {
            System.err.println("[Burp AI Agent] Unexpected webhook error for $webhookUrl: ${e::class.simpleName}: ${e.message}")
        }
    }

    fun shutdownClient() {
        client.dispatcher.executorService.shutdown()
        client.connectionPool.evictAll()
    }

    private fun escapeJson(s: String): String {
        val sb = StringBuilder(s.length + 16)
        sb.append('"')
        for (ch in s) {
            when (ch) {
                '\\' -> sb.append("\\\\")
                '"' -> sb.append("\\\"")
                '\n' -> sb.append("\\n")
                '\r' -> sb.append("\\r")
                '\t' -> sb.append("\\t")
                '\b' -> sb.append("\\b")
                '\u000C' -> sb.append("\\f")
                else -> {
                    if (ch.code < 0x20) {
                        sb.append("\\u%04x".format(ch.code))
                    } else {
                        sb.append(ch)
                    }
                }
            }
        }
        sb.append('"')
        return sb.toString()
    }
}
