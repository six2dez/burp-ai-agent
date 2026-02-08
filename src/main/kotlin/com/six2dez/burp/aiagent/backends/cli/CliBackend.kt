package com.six2dez.burp.aiagent.backends.cli

import com.six2dez.burp.aiagent.backends.AgentConnection
import com.six2dez.burp.aiagent.backends.AiBackend
import com.six2dez.burp.aiagent.backends.BackendLaunchConfig
import com.six2dez.burp.aiagent.backends.DiagnosableConnection
import com.six2dez.burp.aiagent.backends.SessionAwareConnection
import com.six2dez.burp.aiagent.config.Defaults
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

    override fun isAvailable(settings: com.six2dez.burp.aiagent.config.AgentSettings): Boolean {
        val command = when (id) {
            "claude-cli" -> settings.claudeCmd
            "gemini-cli" -> settings.geminiCmd
            "codex-cli" -> settings.codexCmd
            "opencode-cli" -> settings.opencodeCmd
            "ollama" -> settings.ollamaCliCmd
            else -> ""
        }
        if (command.isBlank()) return false
        val cmdList = command.trim().split("\\s+".toRegex())
        val env = mapOf("PATH" to com.six2dez.burp.aiagent.supervisor.AgentSupervisor.buildCliPathStatic())
        val resolved = resolveCommand(cmdList, env)
        if (resolved.isEmpty()) return false
        val executable = resolved[0]
        val file = java.io.File(executable)
        val available = file.exists() && file.canExecute()
        if (available) {
            com.six2dez.burp.aiagent.backends.BackendDiagnostics.log("[Burp AI Agent] Found $displayName: $executable")
        }
        return available
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

        override fun send(
            text: String,
            history: List<com.six2dez.burp.aiagent.backends.ChatMessage>?,
            onChunk: (String) -> Unit,
            onComplete: (Throwable?) -> Unit
        ) {
            executor.submit {
                // Prepend history if provided
                val historyText = if (history != null && history.isNotEmpty()) {
                    history.joinToString("\n") { "${it.role}: ${it.content}" } + "\n\n"
                } else ""
                
                val finalText = historyText + text
                val outputFile = if (backendId == "codex-cli") {
                    java.io.File.createTempFile("burp-ai-agent-codex", ".txt")
                } else {
                    null
                }


                // Update history and build transcript for stateless CLIs
                val promptToSend: String
                val promptFile: java.io.File?
                
                // If we have a cliSessionId, the backend already has the history. 
                // We only need to provide historyText if we are starting a NEW session or switched backends.
                val effectiveHistory = if (_cliSessionId == null) historyText else ""
                val combinedText = effectiveHistory + text

                if (backendId == "claude-cli" && combinedText.length > Defaults.LARGE_PROMPT_THRESHOLD) {
                    val tFile = java.io.File.createTempFile("burp_uv_prompt_", ".txt")
                    tFile.writeText(combinedText)
                    promptFile = tFile
                    promptToSend = "Please process the instructions and data provided in the following file:\n${tFile.absolutePath}"
                } else {
                    promptFile = null
                    promptToSend = combinedText
                }

                val (cmd, stdinText) = buildCommand(promptToSend, outputFile)
                val resolvedCmd = resolveCommand(cmd, env)
                try {
                    val process = ProcessBuilder(normalizeWindowsCommand(resolvedCmd))
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
                    val lastOutputAt = java.util.concurrent.atomic.AtomicLong(0L)
                    val hasOutput = java.util.concurrent.atomic.AtomicBoolean(false)
                    val readerThread = Thread({
                        val reader = BufferedReader(InputStreamReader(process.inputStream))
                        reader.forEachLine { line ->
                            rawOutput.appendLine(line)
                            hasOutput.set(true)
                            lastOutputAt.set(System.currentTimeMillis())
                        }
                    }, "burp-ai-agent-cli-reader")
                    readerThread.isDaemon = true
                    readerThread.start()

                    var terminatedAfterIdle = false
                    if (backendId == "opencode-cli") {
                        val start = System.currentTimeMillis()
                        while (true) {
                            if (process.waitFor(200, TimeUnit.MILLISECONDS)) break
                            val idleMs = System.currentTimeMillis() - lastOutputAt.get()
                            if (hasOutput.get() && idleMs > 1500) {
                                terminatedAfterIdle = true
                                process.destroyForcibly()
                                break
                            }
                            if (System.currentTimeMillis() - start > Defaults.CLI_PROCESS_TIMEOUT_SECONDS * 1000L) break
                        }
                    } else {
                        if (!process.waitFor(Defaults.CLI_PROCESS_TIMEOUT_SECONDS.toLong(), TimeUnit.SECONDS)) {
                            process.destroyForcibly()
                            try {
                                readerThread.join(2000)
                            } catch (_: InterruptedException) {
                                Thread.currentThread().interrupt()
                            }
                            val tail = rawOutput.toString().trim().take(2000)
                            val msg = if (tail.isBlank()) {
                                "CLI command timed out"
                            } else {
                                "CLI command timed out: $tail"
                            }
                            onComplete(IllegalStateException(msg))
                            return@submit
                        }
                    }
                    try {
                        readerThread.join(2000)
                    } catch (_: InterruptedException) {
                        Thread.currentThread().interrupt()
                    }
                    if (!terminatedAfterIdle && process.exitValue() != 0) {
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
                    } catch (_: Exception) {
                    }
                    try {
                        promptFile?.delete()
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
                    val cmd = buildGeminiCommand(baseCommand)
                    cmd to prompt
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

        private fun buildGeminiCommand(cmd: List<String>): List<String> {
            val base = cmd.firstOrNull() ?: "gemini"
            val extras = filterGeminiPromptFlags(cmd.drop(1))
            val args = mutableListOf<String>()
            args.add(base)
            args.addAll(extras)
            if (!args.contains("--output-format")) {
                args.add("--output-format")
                args.add("text")
            }
            if (!args.contains("-p") && !args.contains("--prompt")) {
                args.add("-p")
                args.add(".")
            }
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
                lower.startsWith("send over your first target") ||
                lower.startsWith("hook registry initialized")
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

        override fun send(
            text: String,
            history: List<com.six2dez.burp.aiagent.backends.ChatMessage>?,
            onChunk: (String) -> Unit,
            onComplete: (Throwable?) -> Unit
        ) {
            if (!isAlive()) {
                onComplete(buildExitError())
                return
            }

            exec.submit {
                try {
                    // Prepend history if provided (Best effort for interactive CLI)
                    val historyText = if (history != null && history.isNotEmpty()) {
                        history.joinToString("\n") { "${it.role}: ${it.content}" } + "\n\n"
                    } else ""
                    
                    val finalText = historyText + text

                    // write input
                    writer.write(finalText)
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
            } catch (e: Exception) {
                System.err.println("Failed to close CLI writer: ${e.message}")
            }
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
                if (System.currentTimeMillis() - start > Defaults.CLI_PROCESS_TIMEOUT_SECONDS * 1000L) break
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
            val resolvedCmd = resolveCommand(cmd, env)
            val normalizedCmd = normalizeWindowsCommand(resolvedCmd)
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
    } else if (lower == "opencode" || lower == "opencode.cmd") {
        val resolved = resolveWindowsNpmShim("opencode.cmd")
        if (resolved != null) {
            listOf(resolved) + cmd.drop(1)
        } else {
            cmd
        }
    } else {
        cmd
    }
}

private fun resolveCommand(cmd: List<String>, env: Map<String, String>): List<String> {
    if (cmd.isEmpty()) return cmd
    val first = cmd[0]
    
    // 1. If already an absolute path, verify and return
    val firstFile = java.io.File(first)
    if (firstFile.isAbsolute) {
        return if (firstFile.exists()) {
            com.six2dez.burp.aiagent.backends.BackendDiagnostics.log("[Burp AI Agent] Resolved absolute: $first")
            cmd
        } else {
            com.six2dez.burp.aiagent.backends.BackendDiagnostics.log("[Burp AI Agent] Absolute path not found: $first")
            emptyList()
        }
    }

    // 2. Manual PATH search to avoid dependency on 'which' / 'where'
    val path = env["PATH"] ?: System.getenv("PATH") ?: ""
    val sep = java.io.File.pathSeparator
    val isWin = isWindows()
    val extensions = if (isWin) listOf("", ".exe", ".bat", ".cmd") else listOf("")

    for (dir in path.split(sep)) {
        if (dir.isBlank()) continue
        for (ext in extensions) {
            val candidate = java.io.File(dir, first + ext)
            try {
                if (candidate.exists() && candidate.canExecute()) {
                    return listOf(candidate.absolutePath) + cmd.drop(1)
                }
            } catch (_: Exception) {}
        }
    }

    return emptyList()
}

private fun isWindows(): Boolean {
    val os = System.getProperty("os.name").lowercase(Locale.ROOT)
    return os.contains("win")
}

private fun resolveWindowsNpmShim(executable: String): String? {
    val candidates = mutableListOf<java.io.File>()
    val appData = System.getenv("APPDATA")?.takeIf { it.isNotBlank() }
    val localAppData = System.getenv("LOCALAPPDATA")?.takeIf { it.isNotBlank() }
    val userProfile = System.getenv("USERPROFILE")?.takeIf { it.isNotBlank() }
    if (appData != null) {
        candidates.add(java.io.File(appData, "npm\\$executable"))
    }
    if (localAppData != null) {
        candidates.add(java.io.File(localAppData, "npm\\$executable"))
    }
    if (userProfile != null) {
        candidates.add(java.io.File(userProfile, "AppData\\Roaming\\npm\\$executable"))
    }
    return candidates.firstOrNull { it.exists() }?.absolutePath
}
