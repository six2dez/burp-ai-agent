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
 * The fix builds the argv with `--no-color --silent -p <prompt>` and strips legacy `--quiet`
 * from extras, because newer Copilot CLI versions no longer support `--quiet`.
 * These tests pin that contract.
 *
 * Visibility note (per PLAN.md `output` block): `buildCopilotCommand` was extracted from the
 * private inner class `NonInteractiveCliConnection` to a top-level `internal fun` in the same
 * package so tests can call it without reflection. Visibility was not widened beyond `internal`.
 */
class CopilotCommandBuilderTest {
    @Test
    fun bareCopilotCommandGetsNoColorSilentAndPromptFlag() {
        val argv = buildCopilotCommand(listOf("copilot"), "analyze this")
        assertEquals(
            listOf("copilot", "--no-color", "--silent", "-p", "analyze this"),
            argv,
        )
    }

    @Test
    fun noColorAndSilentAppearBeforeDashP() {
        val argv = buildCopilotCommand(listOf("copilot"), "analyze this")
        val pIndex = argv.indexOf("-p")
        val noColorIndex = argv.indexOf("--no-color")
        val silentIndex = argv.indexOf("--silent")
        assertTrue(noColorIndex in 0 until pIndex, "--no-color must precede -p in $argv")
        assertTrue(silentIndex in 0 until pIndex, "--silent must precede -p in $argv")
    }

    @Test
    fun promptIsTheLastArgvElement() {
        val argv = buildCopilotCommand(listOf("copilot"), "the prompt")
        assertEquals("the prompt", argv.last())
    }

    @Test
    fun userSuppliedLegacyQuietIsRemoved() {
        val argv = buildCopilotCommand(listOf("copilot", "--quiet"), "x")
        assertFalse(argv.contains("--quiet"), "legacy --quiet must be stripped from $argv")
    }

    @Test
    fun userSuppliedNoColorIsNotDuplicated() {
        val argv = buildCopilotCommand(listOf("copilot", "--no-color"), "x")
        assertEquals(1, argv.count { it == "--no-color" }, "no duplicate --no-color in $argv")
    }

    @Test
    fun userSuppliedSilentIsNotDuplicated() {
        val argv = buildCopilotCommand(listOf("copilot", "--silent"), "x")
        assertEquals(1, argv.count { it == "--silent" }, "no duplicate --silent in $argv")
    }

    @Test
    fun userSuppliedShortSilentIsNotDuplicated() {
        val argv = buildCopilotCommand(listOf("copilot", "-s"), "x")
        assertEquals(1, argv.count { it == "-s" }, "no duplicate -s in $argv")
        assertEquals(0, argv.count { it == "--silent" }, "must not auto-add --silent when -s already exists in $argv")
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
