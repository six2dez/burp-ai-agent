package com.six2dez.burp.aiagent.mcp.external

/**
 * Transport protocol for an external MCP server connection.
 */
enum class ExternalMcpTransport {
    SSE,
    STDIO,
}

/**
 * Configuration for a single external MCP server entry.
 *
 * The [bearerToken] field holds the PLAINTEXT token in memory — encryption lives ONLY at the
 * AgentSettings persistence boundary (Plan 16-02). Callers of [AgentSettingsRepository.load]
 * receive [bearerToken] as plaintext and MUST NOT call [SecretCipher.decrypt] on it again.
 *
 * Named [bearerToken] (not `encryptedToken`) to make the plaintext-in-memory contract explicit.
 */
data class ExternalMcpServerConfig(
    /** Display name; also used as namespace key in `ext:<name>:<tool>` tool prefix. */
    val name: String,
    /** SSE or STDIO transport. */
    val transport: ExternalMcpTransport,
    /** SSE endpoint URL; blank for STDIO servers. */
    val url: String = "",
    /** Parsed command list for STDIO transport. */
    val command: List<String> = emptyList(),
    /** Additional arguments appended to [command] for STDIO transport. */
    val extraArgs: List<String> = emptyList(),
    /** Environment variables injected into the subprocess for STDIO transport. */
    val envVars: Map<String, String> = emptyMap(),
    /**
     * SSE bearer token; holds PLAINTEXT in memory.
     * Encryption boundary is AgentSettings (see Plan 16-02).
     * Stored as ENC1:-prefixed ciphertext at rest; decrypted to plaintext on load.
     */
    val bearerToken: String = "",
    /** User can disable a server without removing it from the list. */
    val enabled: Boolean = true,
)
