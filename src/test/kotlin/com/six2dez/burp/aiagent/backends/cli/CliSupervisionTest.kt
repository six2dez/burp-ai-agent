package com.six2dez.burp.aiagent.backends.cli

import com.six2dez.burp.aiagent.backends.BackendLaunchConfig
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.Timeout
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit

/**
 * SC4 / QUAL-02 — covers the CLI process watchdog timeout path (REL-04, issue #71).
 *
 * NonInteractiveCliConnection.send() runs the user command and calls onComplete with an
 * IllegalStateException whose message contains "timed out" when the process exceeds
 * cliTimeoutSeconds.
 *
 * Important: CliBackend.launch() coerces cliTimeoutSeconds to coerceIn(30, 3600) regardless
 * of the value passed in BackendLaunchConfig (see CliBackend.kt line 38). So the minimum
 * actual timeout is 30 seconds. The latch await is set to 65 seconds and @Timeout to 70
 * seconds to give the watchdog enough headroom while still bounding CI impact.
 */
class CliSupervisionTest {
    @Test
    @Timeout(70, unit = TimeUnit.SECONDS)
    fun sendTimesOutAndReportsViaOnComplete() {
        // Platform guard: use the correct argv for "sleep forever" on each OS
        val sleepCmd =
            if (System.getProperty("os.name").lowercase().contains("win")) {
                listOf("cmd", "/c", "timeout", "/t", "60")
            } else {
                listOf("sleep", "60")
            }

        // Use a generic backend id so NonInteractiveCliConnection.buildCommand() returns
        // the raw sleepCmd without Codex-specific command wrapping (which would prepend
        // "codex exec ..." and fail to find the codex binary).
        val backend = CliBackend("ollama", "Ollama")

        // cliTimeoutSeconds = 1 is coerced to the floor of 30 by CliBackend.launch()
        // (see CliBackend.kt line 38: coerceIn(30, 3600)).
        // The process will be killed after ~30 seconds and onComplete will fire.
        val config =
            BackendLaunchConfig(
                backendId = "ollama",
                displayName = "Ollama",
                command = sleepCmd,
                env = emptyMap(),
                embeddedMode = true,
                cliTimeoutSeconds = 1, // coerced to 30 by the backend
            )

        val connection = backend.launch(config)

        var completionError: Throwable? = null
        val latch = CountDownLatch(1)

        connection.send(
            text = "test",
            history = null,
            onChunk = {},
            onComplete = { err ->
                completionError = err
                latch.countDown()
            },
        )

        // Wait up to 65 seconds — the actual timeout is 30 s after coercion
        val completed = latch.await(65, TimeUnit.SECONDS)

        try {
            assertTrue(completed, "onComplete must be called within 65 seconds")
            assertNotNull(completionError, "onComplete must receive an error on timeout")
            assertTrue(
                completionError!!.message?.contains("timed out", ignoreCase = true) == true,
                "error message must mention timeout; got: ${completionError!!.message}",
            )
        } finally {
            connection.stop()
        }
    }
}
