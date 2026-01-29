package com.six2dez.burp.aiagent.backends.cli

import com.six2dez.burp.aiagent.backends.AgentConnection
import com.six2dez.burp.aiagent.backends.AiBackend
import com.six2dez.burp.aiagent.backends.BackendLaunchConfig
import com.six2dez.burp.aiagent.backends.DiagnosableConnection
import com.six2dez.burp.aiagent.backends.SessionAwareConnection
import java.io.BufferedReader
import java.io.InputStreamReader
import java.util.Locale
import java.util.ArrayDeque
import java.util.concurrent.Executors
import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger

class CliBackend(
    override val id: String,
    override val displayName: String
) : AiBackend {

        override fun launch(config: BackendLaunchConfig): AgentConnection {
        require(config.command.isNotEmpty()) { "CLI backend requires a command" }
        val usePty = (id == "codex-cli" || id == "gemini-cli" || id == "claude-cli") && !config.embeddedMode
        return if (config.embeddedMode) {
            NonInteractiveCliConnection(id, config.command, config.env, config.cliSessionId)
        } else {
            CliConnection(config.command, config.env, usePty, config.embeddedMode)
        }
    }

    private class NonInteractiveCliConnection(
        private val backendId: String,
        private val baseCommand: List<String>,
        private val env: Map<String, String>,
        initialCliSessionId: String? = null
    ) : SessionAwareConnection {
        private val executor = Executors.newSingleThreadExecutor()
        @Volatile
        private var _cliSessionId: String? = initialCliSessionId

        override fun cliSessionId(): String? = _cliSessionId

        override fun isAlive(): Boolean = true

        override fun send(text: String, onChunk: (String) -> Unit, onComplete: (Throwable?) -> Unit) {
            executor.submit {
                val outputFile = if (backendId == "codex-cli") {
                    java.io.File.createTempFile("burp-ai-agent-codex", ".txt")
                } else {
                    null
                }
                val (cmd, stdinText) = buildCommand(text, outputFile)
                try {
                    val process = ProcessBuilder(normalizeWindowsCommand(cmd))
                        .apply { environment().putAll(env) }
                        .redirectErrorStream(true)
                        .directory(java.io.File(System.getProperty("user.home")))
                        .start()

                    if (!stdinText.isNullOrBlank()) {
                        process.outputStream.bufferedWriter().use { writer ->
                            writer.write(stdinText)
                            writer.newLine()
                        }
                    } else {
                        process.outputStream.close()
                    }

                    val rawOutput = StringBuilder()
                    val reader = BufferedReader(InputStreamReader(process.inputStream))
                    reader.forEachLine { line -> rawOutput.appendLine(line) }

                    if (!process.waitFor(120, TimeUnit.SECONDS)) {
                        process.destroyForcibly()
                        onComplete(IllegalStateException("CLI command timed out"))
                        return@submit
                    }
                    if (process.exitValue() != 0) {
                        val tail = rawOutput.toString().trim().take(2000)
                        val msg = if (tail.isBlank()) {
                            "CLI command failed (exit=${process.exitValue()})"
                        } else {
                            "CLI command failed (exit=${process.exitValue()}): $tail"
                        }
                        onComplete(IllegalStateException(msg))
                        return@submit
                    }

                    val finalMessage = when (backendId) {
                        "codex-cli" -> readCodexOutput(outputFile, rawOutput.toString(), text)
                        "gemini-cli" -> readGeminiOutput(rawOutput.toString(), text)
                        "opencode-cli" -> readOpenCodeOutput(rawOutput.toString(), text)
                        "claude-cli" -> readClaudeOutput(rawOutput.toString(), text)
                        else -> rawOutput.toString().trim()
                    }
                    if (finalMessage.isNotBlank()) {
                        onChunk(finalMessage)
                    }
                    onComplete(null)
                } catch (e: Exception) {
                    onComplete(e)
                } finally {
                    try {
                        outputFile?.delete()
                    } catch (_: Exception) {
                    }
                }
            }
        }

        override fun stop() {
            executor.shutdownNow()
        }

        private fun buildCommand(prompt: String, outputFile: java.io.File?): Pair<List<String>, String?> {
            return when (backendId) {
                "codex-cli" -> {
                    val cmd = buildCodexExecCommand(baseCommand, outputFile)
                    cmd to prompt
                }
                "gemini-cli" -> {
                    val cmd = buildGeminiCommand(baseCommand, prompt)
                    cmd to null
                }
                "opencode-cli" -> {
                    val cmd = buildOpenCodeCommand(baseCommand, prompt)
                    cmd to null
                }
                "claude-cli" -> {
                    val cmd = buildClaudeCommand(baseCommand)
                    cmd to prompt
                }
                else -> baseCommand to prompt
            }
        }

        private fun buildCodexExecCommand(cmd: List<String>, outputFile: java.io.File?): List<String> {
            val base = cmd.firstOrNull() ?: "codex"
            val extras = cmd.drop(1)
            val hasExec = extras.contains("exec")
            val filtered = extras.filterNot { it == "chat" }
            val args = mutableListOf<String>()
            args.add(base)
            if (hasExec) {
                args.addAll(filtered)
            } else {
                args.add("exec")
                args.add("--color")
                args.add("never")
                args.add("--skip-git-repo-check")
                args.addAll(filtered)
            }
            if (outputFile != null && !args.contains("--output-last-message")) {
                args.add("--output-last-message")
                args.add(outputFile.absolutePath)
            }
            if (!args.contains("-")) {
                args.add("-")
            }
            return args
        }

        private fun buildGeminiCommand(cmd: List<String>, prompt: String): List<String> {
            val base = cmd.firstOrNull() ?: "gemini"
            val extras = filterGeminiPromptFlags(cmd.drop(1))
            val args = mutableListOf<String>()
            args.add(base)
            args.addAll(extras)
            if (!args.contains("--output-format")) {
                args.add("--output-format")
                args.add("text")
            }
            args.add(prompt)
            return args
        }

        private fun filterGeminiPromptFlags(args: List<String>): List<String> {
            val filtered = mutableListOf<String>()
            var skipNext = false
            for (arg in args) {
                if (skipNext) {
                    skipNext = false
                    continue
                }
                if (arg == "-p" || arg == "--prompt" || arg == "-i" || arg == "--prompt-interactive") {
                    skipNext = true
                    continue
                }
                filtered.add(arg)
            }
            return filtered
        }

        private fun readCodexOutput(outputFile: java.io.File?, stdout: String, prompt: String): String {
            val fileText = outputFile?.takeIf { it.exists() }?.readText()?.trim().orEmpty()
            if (fileText.isNotBlank()) return fileText
            val inputLines = prompt.lines().map { it.trim() }.filter { it.isNotBlank() }.toSet()
            return stdout.lineSequence()
                .map { it.trim() }
                .filter { it.isNotBlank() && !inputLines.contains(it) }
                .joinToString("\n")
                .trim()
        }

        private fun readGeminiOutput(stdout: String, prompt: String): String {
            val inputLines = prompt.lines().map { it.trim() }.filter { it.isNotBlank() }.toSet()
            return stdout.lineSequence()
                .map { it.trim() }
                .filter { it.isNotBlank() && !inputLines.contains(it) }
                .filterNot { isGeminiNoiseLine(it) }
                .joinToString("\n")
                .trim()
        }

        private fun isGeminiNoiseLine(line: String): Boolean {
            val lower = line.lowercase()
            return lower == "loaded cached credentials." ||
                lower.startsWith("mcp server 'burp':") ||
                lower.startsWith("error during discovery for mcp server") ||
                lower.startsWith("loading extension:") ||
                lower.startsWith("listening for changes") ||
                lower.contains("supports tool updates") ||
                (lower.startsWith("ready.") && lower.contains("standing by")) ||
                lower.startsWith("send over your first target")
        }

        private fun buildOpenCodeCommand(cmd: List<String>, prompt: String): List<String> {
            val base = cmd.firstOrNull() ?: "opencode"
            val extras = cmd.drop(1)
            val args = mutableListOf<String>()
            args.add(base)
            args.add("run")
            args.addAll(extras)
            args.add(prompt)
            return args
        }

        private fun readOpenCodeOutput(stdout: String, prompt: String): String {
            val inputLines = prompt.lines().map { it.trim() }.filter { it.isNotBlank() }.toSet()
            return stdout.lineSequence()
                .map { it.trim() }
                .filter { it.isNotBlank() && !inputLines.contains(it) }
                .joinToString("\n")
                .trim()
        }

        private fun buildClaudeCommand(cmd: List<String>): List<String> {
            val base = cmd.firstOrNull() ?: "claude"
            val extras = cmd.drop(1)
            val args = mutableListOf<String>()
            args.add(base)
            args.addAll(extras)
            if (!args.contains("-p") && !args.contains("--print")) {
                args.add("-p")
            }
            val currentSessionId = _cliSessionId
            if (currentSessionId != null) {
                // Follow-up message: resume existing conversation
                args.add("--resume")
                args.add(currentSessionId)
            } else {
                // First message: generate a new session id
                val newId = java.util.UUID.randomUUID().toString()
                _cliSessionId = newId
                args.add("--session-id")
                args.add(newId)
            }
            return args
        }

        private fun readClaudeOutput(stdout: String, prompt: String): String {
            val inputLines = prompt.lines().map { it.trim() }.filter { it.isNotBlank() }.toSet()
            return stdout.lineSequence()
                .map { it.trim() }
                .filter { it.isNotBlank() && !inputLines.contains(it) }
                .joinToString("\n")
                .trim()
        }
    }

    private class CliConnection(
        cmd: List<String>,
        env: Map<String, String>,
        private val usePty: Boolean,
        private val embeddedMode: Boolean
    ) : AgentConnection, DiagnosableConnection {
        private val alive = AtomicBoolean(true)
        private val exitCode = AtomicInteger(Int.MIN_VALUE)
        private val process: Process = startProcess(cmd, env)

        private val writer = process.outputStream.bufferedWriter()
        private val exec = Executors.newSingleThreadExecutor()
        private val readerExec = Executors.newSingleThreadExecutor()
        private val outputQueue = LinkedBlockingQueue<String>()
        private val lastLines = ArrayDeque<String>(50)

        init {
            val reader = BufferedReader(InputStreamReader(process.inputStream))
            readerExec.submit {
                try {
                    while (alive.get()) {
                        val line = reader.readLine() ?: break
                        synchronized(lastLines) {
                            if (lastLines.size >= 50) lastLines.removeFirst()
                            lastLines.addLast(line)
                        }
                        outputQueue.offer(line)
                    }
                } finally {
                    alive.set(false)
                    try {
                        exitCode.set(process.waitFor())
                    } catch (_: Exception) {
                    }
                }
            }
        }

        override fun isAlive(): Boolean = alive.get() && process.isAlive

        override fun send(text: String, onChunk: (String) -> Unit, onComplete: (Throwable?) -> Unit) {
            if (!isAlive()) {
                onComplete(buildExitError())
                return
            }

            exec.submit {
                try {
                    // write input
                    writer.write(text)
                    writer.newLine()
                    writer.flush()

                    if (embeddedMode) {
                        readEmbeddedResponse(text, onChunk, onComplete)
                        return@submit
                    }

                    val start = System.currentTimeMillis()
                    var lastRead = System.currentTimeMillis()
                    while (System.currentTimeMillis() - lastRead < 1500) {
                        val line = outputQueue.poll(200, TimeUnit.MILLISECONDS)
                        if (line != null) {
                            lastRead = System.currentTimeMillis()
                            onChunk(line)
                        }
                        if (System.currentTimeMillis() - start > 60_000) break // safety
                        if (!isAlive() && outputQueue.isEmpty()) break
                    }

                    if (!isAlive()) {
                        onComplete(buildExitError())
                    } else {
                        onComplete(null)
                    }
                } catch (e: Exception) {
                    onComplete(e)
                }
            }
        }

        override fun stop() {
            alive.set(false)
            try {
                writer.close()
            } catch (_: Exception) {}
            process.destroy()
            exec.shutdownNow()
            readerExec.shutdownNow()
        }

        override fun exitCode(): Int? {
            val code = exitCode.get()
            return if (code == Int.MIN_VALUE) null else code
        }

        override fun lastOutputTail(): String? {
            val tail = synchronized(lastLines) { lastLines.joinToString("\n") }
            return tail.ifBlank { null }
        }

        private fun readEmbeddedResponse(
            text: String,
            onChunk: (String) -> Unit,
            onComplete: (Throwable?) -> Unit
        ) {
            val inputLines = text.lines().map { it.trim() }.filter { it.isNotBlank() }.toSet()
            val start = System.currentTimeMillis()
            var lastRead = System.currentTimeMillis()
            var received = false
            while (true) {
                val line = outputQueue.poll(250, TimeUnit.MILLISECONDS)
                if (line != null) {
                    lastRead = System.currentTimeMillis()
                    val trimmed = line.trim()
                    if (trimmed.isNotBlank() && !inputLines.contains(trimmed)) {
                        received = true
                        onChunk(line)
                    }
                }
                val idleMs = System.currentTimeMillis() - lastRead
                if (idleMs > 2000 && received) break
                if (System.currentTimeMillis() - start > 120_000) break
                if (!isAlive() && outputQueue.isEmpty()) break
            }

            if (!isAlive() && !received) {
                onComplete(buildExitError())
            } else {
                onComplete(null)
            }
        }

        private fun buildExitError(): Throwable {
            val code = exitCode()
            val tail = lastOutputTail().orEmpty()
            val msg = buildString {
                append("Process not alive")
                if (code != null) append(" (exit=$code)")
                if (tail.isNotBlank()) {
                    append(": ")
                    append(tail.take(2000))
                }
            }
            return IllegalStateException(msg)
        }

        private fun startProcess(cmd: List<String>, env: Map<String, String>): Process {
            val normalizedCmd = normalizeWindowsCommand(cmd)
            if (usePty && isUnixLike()) {
                val ptyCmd = buildPtyCommand(normalizedCmd)
                return ProcessBuilder(ptyCmd)
                    .apply { environment().putAll(env) }
                    .redirectErrorStream(true)
                    .start()
            }
            return ProcessBuilder(normalizedCmd)
                .apply { environment().putAll(env) }
                .redirectErrorStream(true)
                .start()
        }

        private fun buildPtyCommand(cmd: List<String>): List<String> {
            val joined = cmd.joinToString(" ") { shellEscape(it) }
            val os = System.getProperty("os.name").lowercase(Locale.ROOT)
            return if (os.contains("mac")) {
                // macOS: script -q /dev/null /bin/sh -c "command"
                listOf("script", "-q", "/dev/null", "/bin/sh", "-c", joined)
            } else {
                // Linux: script -q -c "command" /dev/null
                listOf("script", "-q", "-c", joined, "/dev/null")
            }
        }

        private fun shellEscape(arg: String): String {
            if (arg.isEmpty()) return "''"
            if (arg.none { it.isWhitespace() || it == '"' || it == '\'' }) return arg
            return "'" + arg.replace("'", "'\"'\"'") + "'"
        }

        private fun isUnixLike(): Boolean {
            val os = System.getProperty("os.name").lowercase(Locale.ROOT)
            return os.contains("mac") || os.contains("nix") || os.contains("nux")
        }

    }
}

private fun normalizeWindowsCommand(cmd: List<String>): List<String> {
    if (!isWindows() || cmd.isEmpty()) return cmd
    val first = cmd.first()
    if (first.contains("\\") || first.contains("/")) return cmd
    val lower = first.lowercase(Locale.ROOT)
    return if (lower.endsWith(".exe")) {
        listOf(first.dropLast(4)) + cmd.drop(1)
    } else {
        cmd
    }
}

private fun isWindows(): Boolean {
    val os = System.getProperty("os.name").lowercase(Locale.ROOT)
    return os.contains("win")
}
