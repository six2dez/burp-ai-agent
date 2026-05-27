package com.six2dez.burp.aiagent.backends.cli

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

/**
 * Bug #68 — `copilot` was invoked without the `-p <prompt>` non-interactive flag, so the CLI
 * dropped into its interactive selection menu and the supervisor's 60-second wall-clock timeout
 * was the only way the call ever returned.
 *
 * The fix builds the argv with `--no-color --quiet -p <prompt>` (idempotent if the user already
 * supplied any of those flags via `BackendLaunchConfig.command`). These tests pin that contract.
 *
 * Visibility note (per PLAN.md `output` block): `buildCopilotCommand` was extracted from the
 * private inner class `NonInteractiveCliConnection` to a top-level `internal fun` in the same
 * package so tests can call it without reflection. Visibility was not widened beyond `internal`.
 */
class CopilotCommandBuilderTest {
    @Test
    fun bareCopilotCommandGetsNoColorQuietAndPromptFlag() {
        val argv = buildCopilotCommand(listOf("copilot"), "analyze this")
        assertEquals(
            listOf("copilot", "--no-color", "--quiet", "-p", "analyze this"),
            argv,
        )
    }

    @Test
    fun noColorAndQuietAppearBeforeDashP() {
        val argv = buildCopilotCommand(listOf("copilot"), "analyze this")
        val pIndex = argv.indexOf("-p")
        val noColorIndex = argv.indexOf("--no-color")
        val quietIndex = argv.indexOf("--quiet")
        assertTrue(noColorIndex in 0 until pIndex, "--no-color must precede -p in $argv")
        assertTrue(quietIndex in 0 until pIndex, "--quiet must precede -p in $argv")
    }

    @Test
    fun promptIsTheLastArgvElement() {
        val argv = buildCopilotCommand(listOf("copilot"), "the prompt")
        assertEquals("the prompt", argv.last())
    }

    @Test
    fun userSuppliedQuietIsNotDuplicated() {
        val argv = buildCopilotCommand(listOf("copilot", "--quiet"), "x")
        assertEquals(1, argv.count { it == "--quiet" }, "no duplicate --quiet in $argv")
    }

    @Test
    fun userSuppliedNoColorIsNotDuplicated() {
        val argv = buildCopilotCommand(listOf("copilot", "--no-color"), "x")
        assertEquals(1, argv.count { it == "--no-color" }, "no duplicate --no-color in $argv")
    }

    @Test
    fun userSuppliedDashPSkipsAutoInjectedPrompt() {
        val argv = buildCopilotCommand(listOf("copilot", "-p", "my-prompt"), "ignored")
        // The user already specified `-p my-prompt` via extras; the helper must not append a
        // second `-p`, otherwise the CLI would see two prompts and bail out.
        assertEquals(1, argv.count { it == "-p" }, "no duplicate -p in $argv")
        assertFalse(argv.contains("ignored"), "auto-injected prompt must not be appended when user supplied -p")
    }

    @Test
    fun userSuppliedLongPromptFlagSkipsAutoInjectedDashP() {
        val argv = buildCopilotCommand(listOf("copilot", "--prompt", "my-prompt"), "ignored")
        assertFalse(argv.contains("-p"), "helper must not append -p when user already supplied --prompt: $argv")
        assertFalse(argv.contains("ignored"), "auto-injected prompt must not be appended when user supplied --prompt")
    }

    @Test
    fun extrasArePreservedInOrder() {
        val argv = buildCopilotCommand(listOf("copilot", "--config", "foo"), "x")
        // Extras flow through; auto-injected flags come first, then extras, then the auto -p prompt.
        val configIdx = argv.indexOf("--config")
        val fooIdx = argv.indexOf("foo")
        assertTrue(configIdx >= 0 && fooIdx == configIdx + 1, "--config foo preserved as adjacent pair in $argv")
    }
}
