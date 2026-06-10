# Stack Research — v0.9.0 Additions

**Domain:** Burp Suite Extension (Kotlin/JVM) — Hardening, Quality & New Capabilities milestone
**Researched:** 2026-06-10
**Confidence:** HIGH (all versions verified via Maven Central, official docs, and GitHub releases)

---

## Scope

This file covers **only the stack additions needed for v0.9.0**. The existing stack (Kotlin 2.1.21,
Gradle Kotlin DSL, JVM 21, Montoya API 2026.2, OkHttp 4.12.0, Jackson 2.21.2,
kotlinx-serialization 1.8.1, kotlinx-coroutines 1.9.0, MCP kotlin-sdk 0.5.0 / Ktor 3.1.3
Netty, SLF4J 2.0.16, JUnit Jupiter 6.0.3, Mockito-Kotlin 5.4.0, ktlint 1.5.0, JaCoCo) is
already validated and is not re-researched here.

---

## C1 — Native Anthropic Messages API Backend

### Decision: NO new dependency — reuse existing OkHttp + MontoyaHttpTransport + Jackson/kotlinx

**Verdict confirmed by official API docs.**

The Anthropic Messages API is **plain HTTPS + JSON** over standard HTTP/1.1:

- Endpoint: `POST https://api.anthropic.com/v1/messages`
- Token counting: `POST https://api.anthropic.com/v1/messages/count_tokens`
- Required headers: `Content-Type: application/json`, `anthropic-version: 2023-06-01`, `x-api-key: <key>`
- Streaming: standard **Server-Sent Events (SSE)** — same `text/event-stream` format already
  handled for the Ktor/MCP SSE path; `"stream": true` in the request body enables it.
- No WebSockets, no proprietary framing, no SDK-specific transport layer.

This means the existing `HttpBackendSupport` → `MontoyaHttpTransport` → OkHttp path handles
Anthropic exactly the same way it handles Ollama or any OpenAI-compatible backend. The Anthropic
wire format differs from OpenAI only at the JSON schema level (different request/response field
names, `content[]` blocks, `tool_use` / `tool_result` content types, `cache_control` for prompt
caching). That difference is a serialization concern, not a transport concern.

**Official Anthropic Java SDK** (`com.anthropic:anthropic-java:2.40.1`, MIT) exists but is
explicitly ruled out for this project:

- Ships its own OkHttp client (`anthropic-java-client-okhttp` module); pulling it in would add a
  second OkHttp tree to the fat JAR.
- Has a pluggable `HttpClient` interface that could, in theory, be backed by
  `MontoyaHttpTransport`, but that requires copying SDK core classes or writing shims — more work
  than just implementing the JSON shape directly.
- Brings heavyweight transitive dependencies (Jackson, Gson, OkHttp, potentially Retrofit-style
  adapters) that conflict or bloat the single fat JAR.
- The `anthropic-java-core` module alone is ~500 KB; total SDK + OkHttp2 + transitive = several
  MB of redundant code already present under different coordinates.
- **MIT-compatible license** — not the blocking factor, but size/conflict is.

**Recommendation:** Implement `AnthropicBackend : HttpBackendSupport` following exactly the same
pattern as the existing OpenAI-compatible backend. Serialize/deserialize Anthropic's JSON schema
with the Jackson/kotlinx-serialization already in the project. Parse SSE `data:` lines from the
OkHttp `ResponseBody` stream exactly as any other streaming backend.

Source: Anthropic Messages API official docs (platform.claude.com/docs/en/api/messages),
confirmed 2026-06-10. [HIGH confidence]

---

## C2 — Encrypt Secrets at Rest (API Keys + TLS Keystore Password)

### Decision: NO new dependency — implement portable AES-256-GCM via javax.crypto (JDK built-in)

**Comparison: OS Keychain libs vs portable passphrase-derived encryption**

#### Option A — OS Keychain (java-keyring)

| Attribute | Detail |
|-----------|--------|
| Artifact | `com.github.javakeyring:java-keyring:1.0.4` |
| License | BSD-3-Clause (MIT-compatible for redistribution) |
| Last release | August 30, 2023 — maintenance-mode, no 2024/2025 updates |
| Platform support | macOS Keychain, Windows Credential Manager (DPAPI), Linux libsecret/DBus |
| Native approach | JNA (not JNI) — loads OS shared libraries at runtime |
| Fat-JAR concern | **CRITICAL**: JNA loads native `.dylib`/`.dll`/`.so` at runtime from the OS.
  The Java code ships in the fat JAR, but it calls `libsecret` (Linux) or `Security.framework`
  (macOS) or `wincred.dll` (Windows) via JNA bindings. The JAR itself is cross-platform.
  However, on Linux the call path goes through `libsecret` → D-Bus → a running keyring daemon
  (GNOME Keyring or KWallet). **This is not always present in headless/server environments or
  minimal desktop setups used by pentesters**, and it would fail silently or throw an unchecked
  exception at first use. |
| Cross-platform confidence | macOS and Windows: HIGH. Linux: MEDIUM (requires a running secret
  service daemon). |
| No-native-install-step? | Technically true — JNA uses the OS library already present — but
  `libsecret` may not be installed on all Linux distros. |
| Verdict | REJECT for v0.9.0. The dependency is in maintenance mode and the Linux path is
  unreliable for pentest-grade portability. If a future version of the extension prioritizes
  keychain integration, this library is the right vehicle, but it needs a fallback path anyway. |

#### Option B — Portable passphrase-derived AES-256-GCM via javax.crypto

| Attribute | Detail |
|-----------|--------|
| Dependency | NONE — 100% JDK built-in (`javax.crypto`, `java.security`) |
| Algorithm | AES-256-GCM (AEAD), key derived via PBKDF2WithHmacSHA256 (100 000 iterations) |
| Cross-platform | YES — same code, same behavior on macOS/Linux/Windows with any JDK 21 |
| Fat-JAR impact | Zero — no new bytes in the JAR |
| License concern | None — JDK standard library |
| No native install | YES — JDK 21 includes hardware-accelerated AES (AES-NI) via the JCE SunJCE
  provider; no native install required |
| Encryption envelope | `salt(16 bytes) || iv(12 bytes) || ciphertext || GCM-tag(16 bytes)`, Base64
  stored in Burp Preferences alongside a flag marking the value as encrypted |
| Key derivation input | A stable per-install secret derived from a combination of machine
  identifier + user-provided master passphrase OR a randomly-generated per-install key stored
  separately from the secrets (stored in a separate Burp Preference key so it is not in the
  same serialized blob as the encrypted values) |

**Recommendation:** Implement a `SecretsVault` utility class (~100 lines of Kotlin) using
`javax.crypto.Cipher.getInstance("AES/GCM/NoPadding")` and
`javax.crypto.SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")`. This is zero-dependency,
fully portable, and zero JAR bloat.

The Google Tink alternative (`com.google.crypto.tink:tink:1.21.0`, Apache-2.0) is explicitly
evaluated and rejected:

- Tink 1.21.0 depends on `com.google.protobuf:protobuf-java:4.33.0` as a **compile-scope
  transitive dependency**. Burp Suite itself ships Protobuf internally; adding a second Protobuf
  tree to the fat JAR risks `ClassCastException` at runtime when Burp loads the extension.
- Tink also pulls `com.google.code.gson:gson:2.13.2` — a second JSON library alongside
  Jackson/kotlinx-serialization.
- For AES-256-GCM, Tink adds zero capability over `javax.crypto` — it is a higher-level wrapper
  around the same JCE primitives.

Source: Tink 1.21.0 POM at Maven Central (direct deps verified 2026-06-10). [HIGH confidence]

---

## C3 — Act as an MCP Client to External/Custom MCP Servers

### Decision: VERSION BUMP required — upgrade `io.modelcontextprotocol:kotlin-sdk` from 0.5.0 to 0.13.0

**Current project version 0.5.0 is significantly outdated.** Latest stable is **0.13.0** (published
~2026-06-03 on Maven Central). The SDK has shipped 8 minor versions between 0.5.0 and 0.13.0.

#### Version 0.5.0 vs 0.13.0

| Feature | 0.5.0 | 0.13.0 |
|---------|-------|--------|
| MCP server support | YES | YES |
| MCP client support | YES (basic) | YES (full, documented) |
| Client transports | Partial | `StdioClientTransport`, `StreamableHttpClientTransport`, `SseClientTransport` (backwards compat), `WebSocketClientTransport` |
| Ktor version | 3.1.3 | **3.4.3** |
| Kotlin stdlib | — | 2.3.21 (transitive) |
| DNS rebinding protection | No | YES (on by default, HTTP transports) |
| Dispatcher configurability | No | YES (`Dispatchers.Default` for handlers) |
| Back-pressure on send() | No | YES |
| SSE onClose callbacks | Broken | Fixed |

#### Artifact coordinates

Full SDK (includes client + server):
```kotlin
implementation("io.modelcontextprotocol:kotlin-sdk:0.13.0")
```

Client-only (preferred for C3 — smaller transitive footprint):
```kotlin
implementation("io.modelcontextprotocol:kotlin-sdk-client:0.13.0")
```

The server artifact (`kotlin-sdk-server`) is already in use for the embedded MCP server. Upgrading
the umbrella artifact or splitting to `kotlin-sdk-server` + `kotlin-sdk-client` both work.

#### Ktor version change (3.1.3 → 3.4.3)

The project currently uses `ktor-server-netty:3.1.3` embedded by the MCP sdk. After upgrading to
kotlin-sdk 0.13.0, Ktor will move to **3.4.3**. Since Ktor is only used for the embedded MCP
server (not for any user-facing HTTP traffic — all AI traffic routes through
`MontoyaHttpTransport`), this is a contained bump. The `ktor-server-netty` engine dependency may
need to be explicitly re-declared at `3.4.3` in `build.gradle.kts` to avoid mixed Ktor versions.

#### Ktor-BOM issue (issue #390)

Kotlin-sdk 0.7.5+ omits Ktor dependency versions from its POM, requiring consumers to provide Ktor
via a BOM or explicit version pins. Workaround: declare `io.ktor:ktor-bom:3.4.3` as a
`platform()` BOM import, or pin all Ktor dependencies explicitly. The project already pins Ktor
directly; update the pin from 3.1.3 to 3.4.3 after the sdk bump.

Source: Maven Central (0.13.0 POM, kotlin-sdk-client:0.13.0 deps verified 2026-06-10),
GitHub releases page. [HIGH confidence]

---

## C4 — Pre-Send Secret Tripwire (Entropy/Secret Detection)

### Decision: NO new dependency — implement inline using hand-curated regex + Shannon entropy via javax.crypto / pure Kotlin

**No suitable JVM library exists that is single-JAR, MIT-compatible, lightweight, and
production-maintained for this use case.**

#### What was evaluated

| Option | Status | Reason to Reject |
|--------|--------|-----------------|
| Gitleaks binary (Go) | OUT — external process, not a JAR library |
| Gitleaks TOML rule catalog (regex-only reuse) | PARTIAL — usable, but Gitleaks regexes use
  Go regex engine syntax; some patterns use `(?-i:...)` inline flag toggling and lookahead/
  lookbehind forms that are valid in Java's `java.util.regex` but the semantics may differ.
  The catalog has 100+ rules and 3209 lines — importing it wholesale is a heavy maintenance
  surface for a focused tripwire feature. |
| betterleaks | OUT — too new (2025/2026), no JVM library artifact |
| OWASP Secrets Management checker | OUT — not a JVM library |
| Shannon entropy standalone library | No production Maven artifact found; the algorithm is
  trivial (30 lines of Kotlin) |

#### Recommendation: implement `SecretTripwire` inline

The feature needed for C4 is a **pre-send gate**, not a scanner. It needs to catch obvious
secrets that survive redaction — long high-entropy strings, bearer tokens, AWS-style keys —
before the payload leaves the extension. That is a different, narrower scope than a full
gitleaks scan.

Implement with two layers:

1. **Regex patterns** — curate ~15-20 high-signal patterns derived from gitleaks TOML
   covering the top secret types: AWS access keys, generic bearer tokens, private key PEM
   headers, GitHub PATs, Google API keys, Anthropic/OpenAI API keys, JWT `ey...` prefix.
   All patterns can be expressed in standard Java regex (`java.util.regex.Pattern`) — the
   subset of gitleaks patterns that do not use Go-specific lookahead forms is compatible.

2. **Shannon entropy check** — strings matching the regex guard are additionally tested for
   entropy > 3.5 bits/char (base64 alphabet), which separates random-looking secrets from
   placeholder strings like `your-api-key-here`. Shannon entropy is 20 lines of Kotlin:
   `val freq = s.groupingBy { it }.eachCount()` → `freq.values.sumOf { c -> ... }`.

Both layers are pure Kotlin / standard library, zero new dependencies, zero fat-JAR impact.

The gitleaks TOML file is MIT-licensed and the patterns may be ported directly with attribution
as inline constants, avoiding a binary or library dependency entirely.

Source: gitleaks TOML (github.com/gitleaks/gitleaks, MIT, verified 2026-06-10). [HIGH confidence]

---

## B3 — detekt Static Analysis Gradle Plugin

### Decision: ADD `io.gitlab.arturbosch.detekt:detekt-gradle-plugin:1.23.8` with explicit Kotlin compatibility configuration

#### Current state

detekt stable: **1.23.8** (released 2025-02-21)
detekt alpha: **2.0.0-alpha.3** (Kotlin 2.3.21, Gradle 9.3.1) — not production-ready

#### Kotlin 2.1.21 compatibility

detekt 1.23.8 is **built against Kotlin 2.0.21**, not 2.1.x. Known issues:

- Issue #7883 documents a compiler warning (not a hard failure) in 1.23.7+ on Kotlin 2.1.0:
  `org.jetbrains.kotlin:kotlin-compiler-embeddable` appears in the build classpath alongside
  the Kotlin Gradle plugin, which Kotlin 2.1.0+ flags. This is a **warning, not a build
  failure** in most configurations.
- detekt 2.0.0-alpha.3 (Kotlin 2.3.21) is the only version that officially supports Kotlin 2.1+
  families, but alpha releases are unsuitable for a CI gate.

**Practical verdict for v0.9.0:** Use **1.23.8** with the following mitigations:

1. Declare `detektPlugins` scope dependencies rather than `classpath`, which prevents the
   `kotlin-compiler-embeddable` classpath pollution.
2. Set `jvmTarget = "21"` in the detekt Kotlin DSL config block.
3. Accept the Kotlin 2.1.x warning as a known non-blocking issue; track detekt 2.0.0 stable
   (targeting Kotlin 2.x) for upgrade in a subsequent milestone.
4. If the warning becomes a hard error after a Kotlin toolchain upgrade, upgrade detekt to the
   then-current 2.0.0 stable.

#### Gradle coordinates

```kotlin
// build.gradle.kts — plugins block
plugins {
    id("io.gitlab.arturbosch.detekt") version "1.23.8"
}

// dependency for rule configuration
dependencies {
    detektPlugins("io.gitlab.arturbosch.detekt:detekt-formatting:1.23.8")
}
```

Both artifacts are on the Gradle Plugin Portal and Maven Central.

| Attribute | Detail |
|-----------|--------|
| License | Apache-2.0 (confirmed, MIT-compatible) |
| Fat-JAR impact | NONE — build-time plugin only, not included in the extension JAR |
| Cross-platform | YES — pure JVM Gradle plugin |
| Blocking vs warning | Configure as a separate `detektMain` task; wire as `check` dependency
  once the team agrees on severity thresholds |

Source: detekt.dev/docs/introduction/compatibility, GitHub releases. [HIGH confidence]

---

## Summary Matrix

| Item | New Artifact? | Coordinates | Version | License | Fat-JAR Impact | Action |
|------|--------------|-------------|---------|---------|----------------|--------|
| C1 Anthropic backend | NO | — | — | — | None | Implement `AnthropicBackend` using existing OkHttp + MontoyaHttpTransport + Jackson |
| C2 Secrets at rest | NO | — | — | — | None | Implement `SecretsVault` using `javax.crypto` AES-256-GCM + PBKDF2 |
| C3 MCP client | VERSION BUMP | `io.modelcontextprotocol:kotlin-sdk:0.13.0` (or `-client:0.13.0`) | 0.13.0 | Apache-2.0 | Replaces 0.5.0; Ktor bumps 3.1.3→3.4.3 | Bump MCP SDK; pin `ktor-bom:3.4.3`; re-test embedded server |
| C4 Secret tripwire | NO | — | — | — | None | Implement `SecretTripwire` with ~15 curated regexes + Shannon entropy (pure Kotlin) |
| B3 detekt | ADD (build-time only) | `io.gitlab.arturbosch.detekt` plugin `1.23.8` | 1.23.8 | Apache-2.0 | Zero (build plugin) | Add to `plugins {}` block; configure detekt DSL; wire to `check` task |

---

## What NOT to Add

| Avoid | Why | Use Instead |
|-------|-----|-------------|
| `com.anthropic:anthropic-java:2.40.1` | Ships OkHttp + Gson + heavyweight transitive tree; can't route through MontoyaHttpTransport without shims; bloats fat JAR by several MB | Implement `AnthropicBackend` directly |
| `com.google.crypto.tink:tink:1.21.0` | Transitive `protobuf-java:4.33.0` clashes with Burp's internal Protobuf; also pulls Gson; overkill for AES-GCM | `javax.crypto` JDK built-in |
| `com.github.javakeyring:java-keyring:1.0.4` | Maintenance-mode (last release Aug 2023); Linux path requires `libsecret` daemon (unreliable in headless/pentest environments); JNA adds ~1 MB to fat JAR; needs fallback path anyway | `javax.crypto` portable AES-GCM |
| `io.modelcontextprotocol:kotlin-sdk:0.5.0` (keep at current) | Lacks documented client transports; SSE client onClose broken; outdated Ktor 3.1.3 | Upgrade to 0.13.0 |
| `detekt:2.0.0-alpha.3` | Alpha; not production-ready | `1.23.8` with Kotlin 2.1 workaround |

---

## Version Compatibility Notes

| Package | Compatible With | Notes |
|---------|-----------------|-------|
| `kotlin-sdk:0.13.0` | Ktor 3.4.3, Kotlin stdlib 2.3.21 (transitive) | Pin `ktor-bom:3.4.3` platform BOM in build.gradle.kts; Kotlin 2.3.21 stdlib is a transitive dep but Kotlin 2.1.21 compiler remains the project compiler — runtime stdlib alignment needed |
| `detekt:1.23.8` | Kotlin 2.0.21 (built against); Kotlin 2.1.x — warning only, not error | Add `kotlinCompilerClasspath` exclusion if warning escalates |
| `javax.crypto` AES-GCM | JVM 21 (SunJCE provider) | AES-NI hardware acceleration included; no configuration needed |

---

## Sources

- Anthropic Messages API docs (platform.claude.com/docs/en/api/messages) — wire format confirmed HTTPS+JSON+SSE, verified 2026-06-10 [HIGH]
- anthropics/anthropic-sdk-java README + HttpClient.kt source — pluggable transport interface confirmed; OkHttp default confirmed; MIT license; v2.40.1 latest [HIGH]
- io.modelcontextprotocol kotlin-sdk 0.13.0 POM (central.sonatype.com) — client artifact deps: ktor-client-core 3.4.3, kotlin-stdlib 2.3.21 [HIGH]
- MCP kotlin-sdk GitHub releases 0.13.0 — Ktor 3.4.3 upgrade, client transport list confirmed [HIGH]
- MCP kotlin-sdk README — client-only artifact coordinates confirmed [HIGH]
- MCP kotlin-sdk issue #390 — ktor-bom requirement for 0.7.5+ documented [MEDIUM]
- com.google.crypto.tink:tink:1.21.0 POM (central.sonatype.com) — protobuf-java:4.33.0 transitive dep confirmed [HIGH]
- google/tink-java GitHub — Apache-2.0 license; v1.21.0 latest (March 24, 2025/2026) [HIGH]
- detekt compatibility table (detekt.dev) — 1.23.8 latest stable, built against Kotlin 2.0.21; 2.0.0-alpha.3 only for 2.3.x [HIGH]
- detekt issue #7883 — Kotlin 2.1.0 kotlin-compiler-embeddable warning in 1.23.7+ [MEDIUM]
- javakeyring/java-keyring — v1.0.4 latest (Aug 2023), BSD-3 license, JNA-based, Linux libsecret dependency [MEDIUM]
- gitleaks/config/gitleaks.toml — MIT license, Go regex engine, 100+ rules, Shannon entropy thresholds [HIGH]

---

*Stack research for: Burp AI Agent v0.9.0 (Hardening, Quality & New Capabilities) — additions only*
*Researched: 2026-06-10*
