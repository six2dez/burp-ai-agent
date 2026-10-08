package com.six2dez.burp.aiagent.audit

import burp.api.montoya.MontoyaApi
import com.six2dez.burp.aiagent.TestSettings
import com.six2dez.burp.aiagent.backends.AgentConnection
import com.six2dez.burp.aiagent.backends.AiBackend
import com.six2dez.burp.aiagent.backends.BackendLaunchConfig
import com.six2dez.burp.aiagent.backends.BackendRegistry
import com.six2dez.burp.aiagent.backends.ChatMessage
import com.six2dez.burp.aiagent.redact.PrivacyMode
import com.six2dez.burp.aiagent.supervisor.AgentSupervisor
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNotEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Assumptions.assumeTrue
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.io.TempDir
import org.mockito.Answers
import org.mockito.kotlin.mock
import org.mockito.kotlin.whenever
import java.io.File
import java.nio.file.FileSystems
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.attribute.PosixFilePermissions
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit

/**
 * Quick 261008-sqa: the audit trail goes through the REAL [AuditLogger] write path (and, for the
 * send tests, the REAL [AgentSupervisor]) into a temporary home. It must hold no credential in
 * either mode, record bodies as a SHA-256 plus UTF-8 byte length unless verbose is on, create
 * nothing before the first write, and write owner-only files on POSIX file systems.
 */
class AuditWritePathTest {
    @TempDir
    lateinit var root: Path

    private val api: MontoyaApi = mock<MontoyaApi>(defaultAnswer = Answers.RETURNS_DEEP_STUBS)

    private var homeCounter = 0

    private fun freshHome(): File {
        homeCounter += 1
        return root.resolve("audit-home-$homeCounter").toFile()
    }

    private fun newLogger(home: File): AuditLogger = AuditLogger(api, home)

    private fun writtenText(home: File): String {
        val sb = StringBuilder()
        val log = File(home, "audit.jsonl")
        if (log.isFile) sb.append(log.readText(Charsets.UTF_8))
        File(home, "bundles").listFiles()?.filter { it.isFile }?.sortedBy { it.name }?.forEach {
            sb.append('\n').append(it.readText(Charsets.UTF_8))
        }
        return sb.toString()
    }

    private fun posix(): Boolean = FileSystems.getDefault().supportedFileAttributeViews().contains("posix")

    private fun modeOf(file: File): String = PosixFilePermissions.toString(Files.getPosixFilePermissions(file.toPath()))

    private fun setMode(
        file: File,
        mode: String,
    ) {
        Files.setPosixFilePermissions(file.toPath(), PosixFilePermissions.fromString(mode))
    }

    private fun digestOf(s: String): String = Hashing.sha256Hex(s)

    private fun bytesOf(s: String): Int = s.toByteArray(Charsets.UTF_8).size

    private fun bundleOf(
        logger: AuditLogger,
        config: BackendLaunchConfig = BackendLaunchConfig(backendId = "ollama", displayName = "Ollama"),
    ): PromptBundle =
        logger.buildPromptBundle(
            sessionId = "s1",
            backendId = config.backendId,
            backendConfig = config,
            promptText = PROMPT,
            contextJson = CONTEXT,
            privacyMode = PrivacyMode.BALANCED,
            determinismMode = false,
        )

    private fun assertNoCredential(text: String) {
        // The MCP token first: it is the headline leak, so a failure names it.
        assertFalse(text.contains(TOKEN), "the MCP token must never be written")
        for (sentinel in CREDENTIAL_SENTINELS) {
            assertFalse(text.contains(sentinel), "credential sentinel '$sentinel' must never be written")
        }
    }

    private fun assertNoBody(text: String) {
        for (sentinel in BODY_SENTINELS) {
            assertFalse(text.contains(sentinel), "body sentinel '$sentinel' must not be written unless verbose is on")
        }
    }

    @Test
    fun fixtureBodiesHaveMoreUtf8BytesThanChars() {
        // Anti-vacuity: a length assertion that confused chars with UTF-8 bytes would still pass
        // if the bodies were pure ASCII.
        assertNotEquals(PROMPT.length, bytesOf(PROMPT))
        assertNotEquals(CONTEXT.length, bytesOf(CONTEXT))
        assertNotEquals(CHUNK.length, bytesOf(CHUNK))
    }

    @Test
    fun constructingTheLoggerAndRunningWithAuditOffCreatesNothing() {
        val home = freshHome()
        val logger = newLogger(home)
        assertFalse(home.exists(), "constructing the logger must not create ${home.name}")

        logger.setEnabled(false)
        logger.logEvent("session_start", mapOf("backendId" to "ollama"))
        logger.writePromptBundle(bundleOf(logger))
        assertFalse(home.exists(), "running with audit off must not create ${home.name}")
    }

    @Test
    fun directoriesAppearOnlyWhenSomethingIsWritten() {
        val home = freshHome()
        val logger = newLogger(home)
        logger.setEnabled(true)
        assertFalse(home.exists(), "enabling audit without a write must not create ${home.name}")

        logger.logEvent("session_start", mapOf("backendId" to "ollama"))
        assertTrue(File(home, "audit.jsonl").isFile, "the first event writes audit.jsonl")
        assertFalse(File(home, "bundles").exists(), "an event alone must not create bundles/")
        assertFalse(File(home, "contexts").exists(), "an event alone must not create contexts/")

        logger.writePromptBundle(bundleOf(logger))
        val bundles = File(home, "bundles").listFiles()?.toList().orEmpty()
        assertEquals(1, bundles.size, "writePromptBundle writes exactly one bundle")
        assertFalse(File(home, "contexts").exists(), "a prompt never creates contexts/")
    }

    @Test
    fun newAuditFilesAreOwnerOnly() {
        assumeTrue(posix())
        val home = freshHome()
        val logger = newLogger(home)
        logger.setEnabled(true)
        logger.logEvent("session_start", mapOf("backendId" to "ollama"))
        val bundle = logger.writePromptBundle(bundleOf(logger))

        assertEquals("rw-------", modeOf(File(home, "audit.jsonl")), "audit.jsonl mode")
        assertEquals("rw-------", modeOf(bundle), "bundle file mode")
        assertEquals("rwx------", modeOf(File(home, "bundles")), "bundles/ mode")
        assertEquals("rwx------", modeOf(home), "a base directory the logger creates is owner-only")
    }

    @Test
    fun olderWorldReadableFilesAreTightenedOnTheNextWriteAndKeepTheirContent() {
        assumeTrue(posix())
        val home = freshHome()
        home.mkdirs()
        setMode(home, "rwxr-xr-x")
        val log = File(home, "audit.jsonl")
        log.writeText("{\"old\":1}\n")
        setMode(log, "rw-r--r--")
        val bundles = File(home, "bundles")
        bundles.mkdirs()
        setMode(bundles, "rwxr-xr-x")

        val logger = newLogger(home)
        logger.setEnabled(true)
        logger.logEvent("session_start", mapOf("backendId" to "ollama"))
        val bundle = logger.writePromptBundle(bundleOf(logger))

        assertEquals("rw-------", modeOf(log), "an older audit.jsonl is tightened on the next write")
        val lines = log.readLines(Charsets.UTF_8)
        assertEquals("{\"old\":1}", lines.first(), "the old content is kept")
        assertTrue(lines.size == 2 && lines[1].contains("\"session_start\""), "the new record follows the old line: $lines")
        assertEquals("rwx------", modeOf(bundles), "an older bundles/ is tightened on the next write")
        assertEquals("rw-------", modeOf(bundle), "the new bundle is owner-only")
        assertEquals("rwxr-xr-x", modeOf(home), "the shared base directory is left as it is")
    }

    @Test
    fun tighteningNeverAddsAPermission() {
        assumeTrue(posix())
        val home = freshHome()
        home.mkdirs()
        val log = File(home, "audit.jsonl")
        log.writeText("")
        setMode(log, "-w-------")
        val bundles = File(home, "bundles")
        bundles.mkdirs()
        setMode(bundles, "-wx------")

        val logger = newLogger(home)
        logger.setEnabled(true)
        logger.logEvent("session_start", mapOf("backendId" to "ollama"))
        logger.writePromptBundle(bundleOf(logger))

        assertEquals("-w-------", modeOf(log), "a narrower file mode is kept exactly")
        assertEquals("-wx------", modeOf(bundles), "a narrower directory mode is kept exactly")

        setMode(log, "rw-------")
        setMode(bundles, "rwx------")
        assertTrue(log.readText(Charsets.UTF_8).contains("\"session_start\""), "the record was written")
        assertEquals(1, bundles.listFiles()?.size, "the bundle was written")
    }

    @Test
    fun hashesOnlyByDefault() {
        val home = freshHome()
        val logger = newLogger(home)
        logger.setEnabled(true)
        val bundle = bundleOf(logger)
        logger.logEvent("prompt", bundle)
        logger.writePromptBundle(bundle)

        val text = writtenText(home)
        assertNoBody(text)
        assertTrue(text.contains(digestOf(PROMPT)), "prompt digest present")
        assertTrue(text.contains("\"promptUtf8Bytes\":${bytesOf(PROMPT)}"), "prompt UTF-8 length present")
        assertTrue(text.contains(digestOf(CONTEXT)), "context digest present")
        assertTrue(text.contains("\"contextUtf8Bytes\":${bytesOf(CONTEXT)}"), "context UTF-8 length present")
        assertTrue(text.contains("\"verbose\":false"), "the bundle records that it is not verbose")
    }

    @Test
    fun verboseAddsTheBodiesAndKeepsTheDigests() {
        val home = freshHome()
        val logger = newLogger(home)
        logger.setEnabled(true)
        logger.verbose = true
        val bundle = bundleOf(logger)
        logger.logEvent("prompt", bundle)
        logger.writePromptBundle(bundle)

        val text = writtenText(home)
        assertTrue(text.contains("\"promptUtf8Bytes\":${bytesOf(PROMPT)}"), "prompt UTF-8 length present under verbose")
        assertTrue(text.contains("\"contextUtf8Bytes\":${bytesOf(CONTEXT)}"), "context UTF-8 length present under verbose")
        assertTrue(text.contains(digestOf(PROMPT)), "prompt digest present under verbose")
        assertTrue(text.contains(digestOf(CONTEXT)), "context digest present under verbose")
        assertTrue(text.contains(PROMPT_MARK), "prompt body present under verbose")
        assertTrue(text.contains(CONTEXT_MARK), "context body present under verbose")
        assertTrue(text.contains("\"verbose\":true"), "the bundle records that it is verbose")
    }

    @Test
    fun bundleConfigIsAnAllowlistInBothModes() {
        for (verbose in listOf(false, true)) {
            val home = freshHome()
            val logger = newLogger(home)
            logger.setEnabled(true)
            logger.verbose = verbose
            val config =
                BackendLaunchConfig(
                    backendId = "openai-compatible",
                    displayName = "Generic",
                    model = "m1",
                    baseUrl = SENTINEL_URL,
                    headers =
                        mapOf(
                            "Authorization" to "Bearer $API_KEY",
                            "X-Custom-Auth" to CUSTOM_AUTH,
                            "apikey" to APIKEY_HEADER,
                        ),
                    env = mapOf("MCP_TOKEN" to TOKEN, "BURP_MCP_TOKEN" to TOKEN, "PATH" to PATH_VALUE),
                    command = listOf("codex", "--api-key", CLI_ARG),
                    cliSessionId = CLI_SESSION,
                )
            val bundle = bundleOf(logger, config)
            logger.logEvent("prompt", bundle)
            logger.writePromptBundle(bundle)

            val text = writtenText(home)
            assertNoCredential(text)
            assertFalse(text.contains(PATH_VALUE), "env values are never written (verbose=$verbose)")
            for (name in listOf("Authorization", "X-Custom-Auth", "apikey", "MCP_TOKEN", "BURP_MCP_TOKEN", "PATH")) {
                assertTrue(text.contains("\"$name\""), "the name '$name' is kept (verbose=$verbose)")
            }
            assertTrue(text.contains("\"https://llm.example:8443/v1\""), "the endpoint form of baseUrl is kept (verbose=$verbose)")
        }
    }

    @Test
    fun endpointOfKeepsSchemeHostPortAndPathOnly() {
        val table =
            listOf(
                "https://u:urlpass-SENTINEL@h.example:8443/a/b?t=urlquery-SENTINEL#f" to "https://h.example:8443/a/b",
                "//u:urlpass-SENTINEL@h.example/p?t=urlquery-SENTINEL" to "//h.example/p",
                "https://u:p@ss-urlpass-SENTINEL@h.example/p" to "https://h.example/p",
                // Ambiguous: a raw `?` before the last `@` could be in a password or start a query.
                // Either reading puts the other one's secret in the output, so it fails closed.
                "https://u:pa?ss-urlpass-SENTINEL@h.example/x" to "https://",
                "https://h.example?token=urlquery-SENTINEL" to "https://h.example",
                "not a url?x=urlquery-SENTINEL" to "not a url",
                // No path: a query or fragment holding an `@` must never be read as userinfo.
                "https://gw.example?user=a@b.com&key=urlquery-SENTINEL" to "https://",
                "https://gw.example#frag@urlquery-SENTINEL" to "https://",
                // No `//`: the userinfo of a scheme-less authority is stripped too.
                "u:urlpass-SENTINEL@llm.example:11434/v1" to "llm.example:11434/v1",
                // A `//` inside a query: the fail-closed prefix is itself cut at its query.
                "/p?r=//a?b@urlquery-SENTINEL" to "/p",
            )
        // Every row is evaluated before asserting, so a failure names all mismatching rows at once.
        val outputs = table.map { (input, _) -> input to AuditLogger.endpointOf(input) }
        val mismatches =
            table.zip(outputs).filter { (row, result) -> row.second != result.second }.map { (row, result) ->
                "endpointOf(${row.first}) expected <${row.second}> but was <${result.second}>"
            }
        assertEquals(emptyList<String>(), mismatches, "endpointOf rows")
        val leaks = outputs.filter { (_, out) -> out == null || out.contains(URL_PASSWORD) || out.contains(URL_QUERY) || out.contains('#') }
        assertEquals(emptyList<Pair<String, String?>>(), leaks, "endpointOf output holding a secret, a fragment or null")
        assertEquals(null, AuditLogger.endpointOf(null))
        assertEquals(null, AuditLogger.endpointOf("   "))
    }

    @Test
    fun aChatSendThroughTheRealSupervisorWritesNoCredentialAndHashesOnly() {
        val quietHome = freshHome()
        runChatSend(quietHome, verbose = false)
        val quiet = writtenText(quietHome)
        assertNoCredential(quiet)
        assertNoBody(quiet)
        assertDigestRecords(quiet)

        val verboseHome = freshHome()
        runChatSend(verboseHome, verbose = true)
        val loud = writtenText(verboseHome)
        assertNoCredential(loud)
        for (sentinel in BODY_SENTINELS) {
            assertTrue(loud.contains(sentinel), "body sentinel '$sentinel' is written under verbose")
        }
        assertDigestRecords(loud)
    }

    @Test
    fun anAgentSendThroughStartOrAttachIsHashedTheSameWay() {
        val home = freshHome()
        withSupervisor(home, verbose = false) { supervisor ->
            assertTrue(supervisor.startOrAttach(BACKEND_ID), "the fake backend starts")
            val latch = CountDownLatch(1)
            supervisor.send(
                text = PROMPT,
                contextJson = CONTEXT,
                privacyMode = PrivacyMode.BALANCED,
                determinismMode = false,
                onChunk = {},
                onComplete = { latch.countDown() },
            )
            assertTrue(latch.await(5, TimeUnit.SECONDS), "the send completed")
        }
        val text = writtenText(home)
        assertNoCredential(text)
        assertNoBody(text)
        assertDigestRecords(text)
    }

    private fun assertDigestRecords(text: String) {
        assertTrue(text.contains("\"chunkSha256\":\"${digestOf(CHUNK)}\""), "chunk digest present")
        assertTrue(text.contains("\"chunkUtf8Bytes\":${bytesOf(CHUNK)}"), "chunk UTF-8 length present")
        assertTrue(text.contains("\"status\":\"error\""), "prompt_complete records the error status")
        assertTrue(text.contains("\"errorClass\":\"IllegalStateException\""), "prompt_complete records the error class")
        assertTrue(text.contains(digestOf(ERROR_MESSAGE)), "prompt_complete records the error digest")
        assertTrue(text.contains(digestOf(PROMPT)), "prompt digest present")
        assertTrue(text.contains(digestOf(CONTEXT)), "context digest present")
    }

    private fun runChatSend(
        home: File,
        verbose: Boolean,
    ) {
        withSupervisor(home, verbose) { supervisor ->
            val latch = CountDownLatch(1)
            supervisor.sendChat(
                chatSessionId = "chat-1",
                backendId = BACKEND_ID,
                text = PROMPT,
                contextJson = CONTEXT,
                privacyMode = PrivacyMode.BALANCED,
                determinismMode = false,
                onChunk = {},
                onComplete = { latch.countDown() },
            )
            assertTrue(latch.await(5, TimeUnit.SECONDS), "the chat send completed")
        }
    }

    private fun withSupervisor(
        home: File,
        verbose: Boolean,
        block: (AgentSupervisor) -> Unit,
    ) {
        val logger = newLogger(home)
        logger.setEnabled(true)
        logger.verbose = verbose
        val registry = mock<BackendRegistry>()
        whenever(registry.get(BACKEND_ID)).thenReturn(FakeBackend())
        val pool = Executors.newSingleThreadExecutor { r -> Thread(r, "audit-test-worker").apply { isDaemon = true } }
        val supervisor = AgentSupervisor(api = api, registry = registry, audit = logger, workerPool = pool)
        try {
            val baseline = TestSettings.baselineSettings(BACKEND_ID)
            supervisor.applySettings(
                baseline.copy(
                    openAiCompatibleUrl = SENTINEL_URL,
                    openAiCompatibleModel = "m1",
                    openAiCompatibleApiKey = API_KEY,
                    openAiCompatibleHeaders = "X-Custom-Auth: $CUSTOM_AUTH\napikey: $APIKEY_HEADER",
                    mcpSettings = baseline.mcpSettings.copy(enabled = true, token = TOKEN),
                ),
            )
            block(supervisor)
        } finally {
            supervisor.shutdown()
            pool.shutdownNow()
        }
    }

    /** A backend whose connection streams [CHUNK] twice and then fails with a provider error. */
    private class FakeBackend : AiBackend {
        override val id: String = BACKEND_ID
        override val displayName: String = "Fake"

        override fun launch(config: BackendLaunchConfig): AgentConnection =
            object : AgentConnection {
                override fun isAlive(): Boolean = true

                override fun send(
                    text: String,
                    history: List<ChatMessage>?,
                    onChunk: (String) -> Unit,
                    onComplete: (Throwable?) -> Unit,
                    systemPrompt: String?,
                    jsonMode: Boolean,
                    maxOutputTokens: Int?,
                ) {
                    onChunk(CHUNK)
                    onChunk(CHUNK)
                    onComplete(IllegalStateException(ERROR_MESSAGE))
                }

                override fun stop() = Unit
            }
    }

    private companion object {
        const val BACKEND_ID = "openai-compatible"
        const val TOKEN = "mcp-token-SENTINEL-7f3a"
        const val API_KEY = "sk-APIKEY-SENTINEL"
        const val CUSTOM_AUTH = "custom-auth-SENTINEL"
        const val APIKEY_HEADER = "apikey-hdr-SENTINEL"
        const val URL_PASSWORD = "urlpass-SENTINEL"
        const val URL_QUERY = "urlquery-SENTINEL"
        const val SENTINEL_URL = "https://user:$URL_PASSWORD@llm.example:8443/v1?key=$URL_QUERY#frag"
        const val CLI_ARG = "cli-arg-SENTINEL"
        const val CLI_SESSION = "cli-session-SENTINEL"
        const val PATH_VALUE = "/opt/path-SENTINEL"
        const val PROMPT_MARK = "prompt-body-SENTINEL"
        const val PROMPT = "$PROMPT_MARK → é"
        const val CONTEXT_MARK = "context-body-SENTINEL"
        const val CONTEXT = "{\"ctx\":\"$CONTEXT_MARK ü\"}"
        const val CHUNK_MARK = "chunk-body-SENTINEL"
        const val CHUNK = "$CHUNK_MARK •"
        const val ERROR_MARK = "errbody-SENTINEL"
        const val ERROR_MESSAGE = "HTTP 400: $ERROR_MARK"

        val CREDENTIAL_SENTINELS =
            listOf(TOKEN, API_KEY, CUSTOM_AUTH, APIKEY_HEADER, URL_PASSWORD, URL_QUERY, CLI_ARG, CLI_SESSION)
        val BODY_SENTINELS = listOf(PROMPT_MARK, CONTEXT_MARK, CHUNK_MARK, ERROR_MARK)
    }
}
