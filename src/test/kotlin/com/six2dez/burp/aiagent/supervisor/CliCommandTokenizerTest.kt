package com.six2dez.burp.aiagent.supervisor

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test

/**
 * Bug #67 — Windows CLI paths containing backslashes must survive [AgentSupervisor.tokenizeCommand]
 * intact. The tokenizer is parametrized by an explicit `isWindows` flag so the cases can be exercised
 * deterministically on any host OS (the production default still derives the flag from `os.name`).
 *
 * The cases below also pin the long-standing Unix escape behavior (a `\` outside quotes still escapes
 * the next character) so the Windows fix does not regress Unix-style paths.
 */
class CliCommandTokenizerTest {
    @Test
    fun windowsAbsolutePathIsPreservedAsSingleToken() {
        val cmd = "C:\\Users\\u\\bin\\claude.exe"
        val tokens = AgentSupervisor.tokenizeCommand(cmd, isWindows = true)
        assertEquals(listOf("C:\\Users\\u\\bin\\claude.exe"), tokens)
    }

    @Test
    fun windowsQuotedPathWithSpacesYieldsTwoTokens() {
        val cmd = "\"C:\\Program Files\\X\\y.exe\" --print"
        val tokens = AgentSupervisor.tokenizeCommand(cmd, isWindows = true)
        assertEquals(listOf("C:\\Program Files\\X\\y.exe", "--print"), tokens)
    }

    @Test
    fun unixAbsolutePathSplitsOnWhitespace() {
        val cmd = "/usr/local/bin/copilot --quiet"
        val tokens = AgentSupervisor.tokenizeCommand(cmd, isWindows = false)
        assertEquals(listOf("/usr/local/bin/copilot", "--quiet"), tokens)
    }

    @Test
    fun unixBackslashSpaceIsTreatedAsEscapedSpaceOutsideQuotes() {
        // Existing POSIX-ish behavior: a `\` outside quotes escapes the next character.
        val cmd = "/path/with\\ space/bin"
        val tokens = AgentSupervisor.tokenizeCommand(cmd, isWindows = false)
        assertEquals(listOf("/path/with space/bin"), tokens)
    }

    @Test
    fun unixBackslashIsLiteralInsideDoubleQuotes() {
        // Inside double-quoted strings the backslash branch is skipped (no escape interpretation),
        // so a literal `\n` remains a backslash followed by an `n`. This matches the fixed
        // tokenizer's `inQuotes` guard.
        val cmd = "\"a\\nb\""
        val tokens = AgentSupervisor.tokenizeCommand(cmd, isWindows = false)
        assertEquals(listOf("a\\nb"), tokens)
    }
}
