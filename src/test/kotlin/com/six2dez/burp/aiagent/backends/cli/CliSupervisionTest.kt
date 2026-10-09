package com.six2dez.burp.aiagent.backends.cli

import com.six2dez.burp.aiagent.backends.BackendLaunchConfig
import org.junit.jupiter.api.Assertions.assertEquals
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
        val sleepCmd = sleepForeverCommand(System.getProperty("os.name"))

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
                completionError!!.message.orEmpty().startsWith(EXPECTED_TIMEOUT_PREFIX),
                "The error must be the watchdog's timeout message, not an immediate non-zero exit read as a " +
                    "failed command. Expected it to start with '$EXPECTED_TIMEOUT_PREFIX'; got: ${completionError!!.message}",
            )
        } finally {
            connection.stop()
        }
    }

    @Test
    fun theSleepCommandIsChosenByOsName() {
        val why =
            "The backend always redirects the child's stdin (from NUL or from a pipe). Windows timeout.exe " +
                "exits at once on redirected input, while ping ignores stdin; and ping must be the direct child, " +
                "because destroyForcibly kills only the direct child."
        assertEquals(listOf("ping", "-n", "61", "127.0.0.1"), sleepForeverCommand("Windows 11"), why)
        assertEquals(listOf("ping", "-n", "61", "127.0.0.1"), sleepForeverCommand("Windows Server 2022"), why)
        assertEquals(listOf("sleep", "60"), sleepForeverCommand("Mac OS X"), "macOS keeps the POSIX sleep, which ignores stdin.")
        assertEquals(listOf("sleep", "60"), sleepForeverCommand("Linux"), "Linux keeps the POSIX sleep, which ignores stdin.")
    }
}

/**
 * The start of the watchdog's timeout message for the 30 s floor.
 *
 * Built by `buildTimeoutMessage` in CliBackend.kt; `CliBackend.launch` coerces `cliTimeoutSeconds` to at
 * least 30, so a timeout from this test always reads "after 30s".
 */
private const val EXPECTED_TIMEOUT_PREFIX = "CLI command timed out after 30s"

/**
 * The argv for a process that runs well past the 30 s watchdog on the OS named by [osName].
 *
 * The backend always redirects the child's stdin, from NUL or from a pipe. Windows timeout.exe exits at
 * once on redirected input (CI saw "ERROR: Input redirection is not supported" after 0.11-0.13 s), so
 * Windows uses ping, which ignores stdin: 61 echo requests one second apart take about 60 s, and the
 * watchdog kills it first. It runs without a cmd wrapper, so destroyForcibly kills the process actually
 * sleeping instead of leaving a grandchild running. The `contains("win")` predicate matches the backend's
 * own OS check.
 */
private fun sleepForeverCommand(osName: String): List<String> =
    if (osName.lowercase().contains("win")) {
        listOf("ping", "-n", "61", "127.0.0.1")
    } else {
        listOf("sleep", "60")
    }
