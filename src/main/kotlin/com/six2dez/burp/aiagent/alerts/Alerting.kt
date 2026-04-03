package com.six2dez.burp.aiagent.alerts

import com.six2dez.burp.aiagent.backends.http.MontoyaHttpTransport
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody

object Alerting {
    @Volatile
    var transport: MontoyaHttpTransport? = null
    private val fallbackClient = OkHttpClient()

    fun sendWebhook(webhookUrl: String, text: String) {
        try {
            val json = """{"text":${escapeJson(text)}}"""
            val t = transport
            if (t != null) {
                t.post(webhookUrl, emptyMap(), json, 10_000)
            } else {
                val req = Request.Builder()
                    .url(webhookUrl)
                    .post(json.toRequestBody("application/json".toMediaType()))
                    .build()
                fallbackClient.newCall(req).execute().use { }
            }
        } catch (_: Exception) {
            // Webhook delivery is best-effort; don't crash callers
        }
    }

    fun shutdownClient() {
        fallbackClient.dispatcher.executorService.shutdown()
        fallbackClient.connectionPool.evictAll()
    }

    private fun escapeJson(s: String): String =
        "\"" + s.replace("\\", "\\\\").replace("\"", "\\\"")
            .replace("\n", "\\n").replace("\r", "\\r").replace("\t", "\\t") + "\""
}
