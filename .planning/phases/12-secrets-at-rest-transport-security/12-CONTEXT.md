# Phase 12: Secrets at Rest & Transport Security - Context

**Gathered:** 2026-06-10
**Status:** Ready for planning

<domain>
## Phase Boundary

Encrypt all stored credentials at rest and close two transport-security gaps. In scope: AES-256-GCM encryption of the 7 secret-bearing Burp preferences (5 backend API keys, `mcp.token`, `mcp.tls.keystore.password`) plus the forthcoming `anthropicApiKey`; a one-time idempotent schema v3→v4 migration of existing plaintext values; in-JVM TLS self-signed cert generation (removing the keytool argv password exposure, A3); and a soft, non-blocking SSRF warning when a backend base-URL resolves to a private/link-local/cloud-metadata address (A6). Out of scope: passphrase/keychain mechanisms (deferred — per-install key chosen), changing AgentSettings' in-memory representation, and any new runtime dependency (javax.crypto only).

</domain>

<decisions>
## Implementation Decisions

### Encryption & Master Key (SEC-01)
- Cipher: **AES-256-GCM** via `javax.crypto` (JDK 21 built-in) — authenticated encryption; no new dependency
- Master-key bootstrap: a **per-install random 256-bit key** stored in a separate Burp preference entry (zero user friction, works headless). No passphrase prompt in v0.9.0
- KDF: `PBKDF2WithHmacSHA256` kept available as the code path for a future optional passphrase upgrade, but not required now (Argon2 rejected — would need BouncyCastle)
- Secrets covered: all 7 existing secret keys (ollama / lmstudio / openai-compat / nvidia / perplexity API keys, `mcp.token`, `mcp.tls.keystore.password`) and the future `anthropicApiKey` field (CAP-01) must be encrypted from introduction

### Migration & Failure Behavior (SEC-01)
- Migration: **idempotent schema v3→v4** in `migrateIfNeeded()` — encrypt each plaintext secret in place, overwrite the plaintext only after a round-trip decrypt verifies; re-running the migration must not double-encrypt
- Decrypt failure: **fail-soft** — treat an undecryptable value as empty and log only the preference KEY NAME (never key material); the user re-enters the secret
- Runtime representation: AgentSettings stays **plaintext in memory** (decrypt on load, encrypt on save); only the persistence I/O boundary changes
- Headless: the per-install key path must work with `java.awt.headless=true` (no `HeadlessException`); never block startup

### Transport Hardening (SEC-02, SEC-03)
- keytool fix (A3): generate the self-signed MCP TLS cert **in-JVM** (no keytool subprocess) — removes the `-storepass`/`-keypass` argv exposure and the external keytool dependency
- SSRF trigger (A6): warn on save when a backend host resolves to a loopback-excluded **private (RFC-1918), link-local, or cloud-metadata (169.254.169.254)** address
- SSRF enforcement: **soft** — warn and proceed; never block (internal targets are legitimate for a pentest tool)
- Warning placement: **inline**, non-modal, in the backend settings field on save

### Claude's Discretion
- Exact crypto helper class shape (e.g. a `SecretCipher`/`SecretsVault` object), key-pref naming, GCM IV/nonce handling, and the in-JVM cert API (JDK `CertAndKeyGen` vs a minimal hand-rolled X509) are at implementation discretion, subject to the no-new-dependency and route-through-Burp constraints

</decisions>

<code_context>
## Existing Code Insights

### Reusable Assets
- `config/AgentSettings.kt` — owns persistence: `save()` (~line 630), `migrateIfNeeded()` (line 633), `CURRENT_SETTINGS_SCHEMA_VERSION = 3` (line 796), `KEY_SETTINGS_SCHEMA_VERSION` (line 795). This is where the encrypt/decrypt boundary and the v4 migration live
- `mcp/McpTls.kt` — `generateSelfSigned()` currently shells out to keytool with `-storepass`/`-keypass` on argv (lines 35–75); replace with in-JVM generation
- The 7 secret preference keys identified by milestone research (`.planning/research/ARCHITECTURE.md`)

### Established Patterns
- Schema migration via `migrateIfNeeded()` with a stored integer version and per-version upgrade steps (idempotent)
- Settings persisted through Burp's Preferences API; `AtomicReference` cache in the repository
- All HTTP backends already route through `MontoyaHttpTransport` (do not regress)

### Integration Points
- `AgentSettings.save()`/`load()` — wrap secret-field read/write with decrypt/encrypt
- `migrateIfNeeded()` — add the v3→v4 step
- `McpTls.resolve()`/`generateSelfSigned()` — in-JVM cert path
- Backend settings UI fields — emit the SSRF warning on save (`SettingsPanel` / backend config panel)

</code_context>

<specifics>
## Specific Ideas

- Plaintext must be overwritten only after a verified round-trip decrypt (no data loss on migration).
- Never log secret material — only preference key names on failure.
- No new runtime dependency: `javax.crypto` + JDK only.
- `anthropicApiKey` (Phase 14) must be born encrypted — this phase establishes the mechanism it relies on.

</specifics>

<deferred>
## Deferred Ideas

- Optional user master passphrase to derive the key (PBKDF2 path scaffolded but not wired) — future enhancement.
- OS keychain integration (macOS Keychain / Windows DPAPI / libsecret) — rejected for v0.9.0 to keep the single fat JAR cross-platform and dependency-free.

</deferred>
