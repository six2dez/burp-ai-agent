package com.six2dez.burp.aiagent.backends

object BackendDiagnostics {
    data class RetryEvent(
        val backendId: String,
        val attempt: Int,
        val delayMs: Long,
        val reason: String?
    )

    @Volatile
    var output: ((String) -> Unit)? = null

    @Volatile
    var error: ((String) -> Unit)? = null

    @Volatile
    var retry: ((RetryEvent) -> Unit)? = null

    fun log(message: String) {
        try {
            output?.invoke(message)
        } catch (_: Exception) {
            System.err.println(message)
        }
        if (output == null) {
            System.err.println(message)
        }
    }

    fun logError(message: String) {
        try {
            error?.invoke(message)
        } catch (_: Exception) {
            System.err.println(message)
        }
        if (error == null) {
            System.err.println(message)
        }
    }

    fun logRetry(backendId: String, attempt: Int, delayMs: Long, reason: String?) {
        retry?.invoke(
            RetryEvent(
                backendId = backendId,
                attempt = attempt,
                delayMs = delayMs,
                reason = reason
            )
        )
    }
}
