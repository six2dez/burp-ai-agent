# Phase 17: Reliability & Concurrency Hardening - Pattern Map

**Mapped:** 2026-06-11
**Files analyzed:** 9 production targets (1 CREATE, 8 MODIFY) + 7 test targets (6 CREATE, 1 EXTEND)
**Analogs found:** 16 / 16 — every file has a closest in-repo analog (no RESEARCH-only fallbacks needed)

> This is an internal-correctness phase. Every "new" pattern already exists in the codebase; the work is **wiring discipline** plus one tiny SOURCE-retained annotation and one config knob. All line numbers were read directly from source on 2026-06-11.

---

## File Classification

| New/Modified File | Role | Data Flow | Closest Analog | Match Quality |
|-------------------|------|-----------|----------------|---------------|
| `util/GuardedBy.kt` (CREATE) | annotation/util | — (compile-time doc) | `util/SsrfGuard.kt` (file style only) + RESEARCH Pattern 1 | role-match (no existing annotation class in repo) |
| `ui/ChatPanel.kt` (MODIFY, REL-01) | component (Swing) | event-driven / request-response | self — existing `invokeLater` sites `:568,:579,:594,:633,:641` | exact (intra-file) |
| `backends/cli/CliBackend.kt` (MODIFY, REL-02+04) | backend connection | file-I/O + process I/O | self — existing `finally` cleanup `:274-288`, inline delete `:138` | exact (intra-file) |
| `config/AgentSettings.kt` (MODIFY, REL-04) | config | CRUD (prefs) | `perplexityTimeoutSeconds` / `nvidiaNimTimeoutSeconds` fields | exact |
| `config/Defaults.kt` (MODIFY, REL-04) | config | constant | `CLI_PROCESS_TIMEOUT_SECONDS` (`:41`) | exact |
| `backends/http/HttpBackendSupport.kt` (EXTEND, REL-03) | service/util | request-response | self — `isRetryableConnectionError` (`:125`), `newCircuitBreaker` (`:148`) | exact (intra-file) |
| `backends/openai/OpenAiCompatibleBackend.kt` (MODIFY, REL-03) | backend connection | request-response | self — `!resp.isSuccessful` branch `:243-264` | exact |
| `backends/anthropic/AnthropicBackend.kt` (MODIFY, REL-03) | backend connection | request-response | OpenAiCompatible `:243` + self `:197-213` | exact |
| `backends/ollama/OllamaBackend.kt` (MODIFY, REL-03) | backend connection | request-response | OpenAiCompatible `:243` + self `:294-298` | exact |
| `backends/lmstudio/LmStudioBackend.kt` (MODIFY, REL-03) | backend connection | request-response | OpenAiCompatible `:243` + self `:193-197` | exact |
| `mcp/KtorMcpServerManager.kt` (MODIFY, REL-02/SC5) | mcp manager | event-driven (lifecycle) | self — `shutdown()` bounded await `:245-252` | exact (intra-file) |
| `redact/Redaction.kt` (MODIFY, REL-02/SC5) | redaction/cache | transform + cache | self — nested `ConcurrentHashMap` `:145-146`, `computeIfAbsent` `:291-292` | exact (intra-file) |
| `ui/ChatPanelConcurrencyTest.kt` (EXTEND, SC1) | test (concurrency) | — | self — `CountDownLatch` + `Executors` hammer pattern | exact |
| `backends/http/HttpBackendCircuitFailureTest.kt` (CREATE, SC3) | test (transport spy) | — | `HttpBackendTransportRoutingTest` (`spy`+`doReturn`) + `CircuitBreakerTest` (`nowProvider`) | exact |
| `backends/cli/CliTimeoutMessageTest.kt` (CREATE, SC4) | test (extracted builder) | — | `CopilotCommandBuilderTest` (extracted-`internal fun` precedent) | exact |
| `mcp/McpShutdownBoundTest.kt` (CREATE, SC5a) | test (integration) | — | `McpServerIntegrationTest` / `McpSupervisorRestartPolicyTest` | role-match |
| `redact/RedactionHostMapBoundTest.kt` (CREATE, SC5b) | test (unit) | — | `RedactionTest` (round-trip + format regex) | exact |

---

## Pattern Assignments

### `util/GuardedBy.kt` — CREATE (REL-01 prerequisite)

**Role:** SOURCE-retained documentation annotation. **No existing `annotation class` in the repo** (verified: `grep -l "annotation class"` returns nothing), so this is a genuinely new file — but trivial. JCIP/jsr305 are NOT on the classpath (RESEARCH §Project Constraints), so a local copy is mandatory, not optional.

**File-style analog:** `util/SsrfGuard.kt:1-20` — same package (`com.six2dez.burp.aiagent.util`), same file-header KDoc-explaining-the-why convention. Copy the package line + the "why a local copy exists" header comment style.

**Exact content to author (from RESEARCH Pattern 1, verified against constraints):**
```kotlin
package com.six2dez.burp.aiagent.util

// Local SOURCE-retained replacement for net.jcip.annotations.GuardedBy.
// JCIP (net.jcip) and jsr305 are deliberately NOT on the classpath (zero-new-deps,
// MIT/fat-JAR control). SOURCE retention keeps it out of the compiled output entirely.
@Target(AnnotationTarget.FIELD, AnnotationTarget.PROPERTY)
@Retention(AnnotationRetention.SOURCE)
annotation class GuardedBy(val lock: String)
```

**GOTCHA (load-bearing):**
- **MUST be `@Retention(AnnotationRetention.SOURCE)`** — not RUNTIME/CLASS. SOURCE keeps it out of the fat JAR (zero runtime/class footprint). A4/A3 in RESEARCH: if a future Phase-18 detekt rule wants to *read* it, bump to CLASS — but default to SOURCE now.
- **Target must include both `FIELD` and `PROPERTY`** — Kotlin `private val x = linkedMapOf(...)` is a property; annotating it needs `PROPERTY` (or `@field:` use-site). Include both to be safe.
- `-Xjsr305=strict` (build.gradle.kts) is **irrelevant** here — it only governs jsr305-annotated *external* types, not a local annotation.

---

### `ui/ChatPanel.kt` — MODIFY (REL-01: EDT confinement) [component, event-driven]

**Analog:** self — the existing `SwingUtilities.invokeLater` calls already inside the same `onComplete` lambda. This is the established cross-thread-UI pattern; you are extending it to cover the map reads + Swing mutations that currently run off-EDT.

**The 4 maps to annotate** (`ChatPanel.kt:104-107`):
```kotlin
private val sessionPanels = linkedMapOf<String, SessionPanel>()
private val sessionStates = linkedMapOf<String, ToolSessionState>()
private val sessionsById = linkedMapOf<String, ChatSession>()
private val sessionDrafts = linkedMapOf<String, String>()
```
Keep them `linkedMapOf` (insertion order matters — do NOT convert to ConcurrentHashMap; CONTEXT forbids it). Add `@GuardedBy("EDT")` to each.

**The off-EDT entry point** — `onComplete = { err -> ... }` at `ChatPanel.kt:570`. RESEARCH confirms this lambda runs on the **backend connection's executor thread, NOT the EDT** (`AgentSupervisor.sendChat` → `connection.send` with no EDT marshalling). The existing `invokeLater` calls inside it (lines `:568, :579, :594, :633, :641`) prove the author already knows this — they wrap every Swing touch. The bug is the two that were missed.

**Existing in-lambda `invokeLater` precedent to copy** (`ChatPanel.kt:632-645`):
```kotlin
if (err != null) {
    SwingUtilities.invokeLater { assistant.finish("\n[Error] ${err.message}") }
    onCompleted?.invoke(responseBuffer.toString(), err)   // <-- note: onCompleted invoked OFF-EDT here
} else {
    val finalResp = responseBuffer.toString()
    // ...
    SwingUtilities.invokeLater {
        assistant.append("\n")
        refreshSessionList()
        onResponseReady()
    }
    // ... then the maybeExecuteToolCall chain (:646) runs OFF-EDT — THIS is the race
```

**The race site to fix** — the `maybeExecuteToolCall(...)` call at `ChatPanel.kt:646-662` runs on the backend thread, and inside `maybeExecuteToolCall` (`:2046`) it reads the maps off-EDT and mutates Swing:
```kotlin
// ChatPanel.kt:2049-2050  — OFF-EDT map reads (the data race)
val panel = sessionPanels[sessionId] ?: return false
val backendId = sessionsById[sessionId]?.lastBackendId ?: getSettings().preferredBackendId
// ...
// ChatPanel.kt:2074 and :2096  — OFF-EDT Swing mutation
panel.addMessage("Tool result: ${call.tool}", "Error: $errorMessage")
panel.addMessage("Tool result: ${call.tool}", result)
```

**Fix shape (RESEARCH Pattern 2 + Open Question 1 — narrowest change):** marshal the map reads + `panel.addMessage` onto the EDT, but **keep `onCompleted` invocation off-EDT** (it does no UI work itself; it re-enters `sendMessage` which marshals its own UI — see `:2107`). Add an `assertEdt()` helper:
```kotlin
private fun assertEdt() {
    assert(SwingUtilities.isEventDispatchThread()) { "session maps must be touched on the EDT" }
}
```

**GOTCHAS (load-bearing):**
- **Pitfall 1 (callback thread):** `onCompleted` is invoked at SIX+ sites (`:281,:298,:310,:345,:467,:634,:655,:661,:2113`). Pick ONE thread for it and document it. Recommended: keep `onCompleted` **off-EDT** (matches the existing `:634` behavior). Move ONLY the map reads + `panel.addMessage` onto the EDT. Re-entrant `sendMessage(...)` (`:2107` → `supervisor.sendChat`) submits to a backend executor internally, so calling it from the EDT will not block the EDT.
- **Pitfall 2 + Wave-0 gate:** `assert(...)` is a **no-op without `-ea`**. **`tasks.test` in `build.gradle.kts:137-151` does NOT currently enable assertions** (no `jvmArgs("-ea")` / `enableAssertions = true`). The EDT `assert` will silently never fire in CI unless this is added. The **concurrency test is the real gate**, not the assert. → This is a required Wave-0 task.
- **Pitfall 3 (test fragility):** Do NOT instantiate `ChatPanel` from many threads (its constructor builds real Swing + `UiTheme` → `HeadlessException`/NPE). The existing `ChatPanelConcurrencyTest` tests the *primitive* (`InFlightConnectionTracker`) in isolation — follow that precedent (see test section below).
- **A2:** Re-verify no OTHER background thread (timer / persist-on-shutdown) touches the maps. RESEARCH says persist/restore (`:1287-1427`) run via UI actions and timers stop via `stopAllTimers`, but confirm at plan time.

---

### `backends/cli/CliBackend.kt` — MODIFY (REL-02 deleteOnExit + REL-04 timeout) [backend, file-I/O + process I/O]

**Analog:** self — the existing temp-file lifecycle and `waitFor` timeout in the same `send` body.

**REL-02 — the 2 `createTempFile` sites** (`CliBackend.kt:109` and `:121`):
```kotlin
// :109  (codex output file)
java.io.File.createTempFile("burp-ai-agent-codex", ".txt")
// :121  (uv prompt file — claude-cli / copilot-cli, prompt > LARGE_PROMPT_THRESHOLD)
val tFile = java.io.File.createTempFile("burp_uv_prompt_", ".txt")
```
**Existing cleanup to preserve** (`CliBackend.kt:274-288` `finally`, plus inline delete `:138`):
```kotlin
} finally {
    try { process?.destroyForcibly() } catch (_: Exception) {}
    try { promptFile?.delete() } catch (_: Exception) {}
    try { outputFile?.delete() } catch (_: Exception) {}
}
```
**Fix:** add `.apply { deleteOnExit() }` (or a line `tFile.deleteOnExit()`) at BOTH creation sites — keep the `finally` deletes (primary) AND `deleteOnExit` (crash-safety net). The existing owner-only POSIX perms at `:124-135` stay.

**REL-04 — the timeout** (`CliBackend.kt:225`, standard path):
```kotlin
if (!process.waitFor(Defaults.CLI_PROCESS_TIMEOUT_SECONDS.toLong(), TimeUnit.SECONDS)) {
    process.destroyForcibly()
    // ...
    val tail = rawOutput.toString().trim().take(2000)
    val msg = if (tail.isBlank()) "CLI command timed out"
              else "CLI command timed out: $tail"
    onComplete(IllegalStateException(msg))
    return@submit
}
```
**Fix (RESEARCH §Code Examples + Pitfall 6):**
1. Read a user-configurable `cliTimeoutSeconds` from settings instead of the hardcoded `Defaults.CLI_PROCESS_TIMEOUT_SECONDS` at the `waitFor` call.
2. Extract an `internal fun buildTimeoutMessage(tail: String, timeoutSeconds: Int): String` that names the limit AND suggests remediation (increase the timeout / pre-install the CLI). This mirrors how `buildCopilotCommand` was extracted for testability (see `CopilotCommandBuilderTest`).

**GOTCHAS (load-bearing):**
- **Pitfall 6 (shared constant):** `Defaults.CLI_PROCESS_TIMEOUT_SECONDS` (`Defaults.kt:41`) is ALSO the default for HTTP backends (`AgentSettings.kt:959,961` — `defaultPerplexityTimeoutSeconds`/`defaultNvidiaNimTimeoutSeconds` both return it) and a fallback in `AgentSupervisor`. **Do NOT mutate it in place** — ADD `cliTimeoutSeconds`. Repurposing the constant would silently change HTTP defaults.
- **There are THREE `waitFor`/timeout-read sites**, not one: `:222` (opencode wall-clock loop), `:225` (standard path), and the embedded `CliConnection` loop at `:736`. RESEARCH names all three; the planner must decide which read the new setting (at minimum `:225`).
- **Privacy:** the timeout message must name the LIMIT + remediation, never prompt content. The existing `take(2000)` bounded-tail discipline stays.
- **deleteOnExit accumulates** in a JVM-global list — fine here because temp files are per-send and also deleted in `finally` (the hook almost always no-ops). Keep BOTH (Anti-Pattern in RESEARCH).

---

### `config/AgentSettings.kt` + `config/Defaults.kt` — MODIFY (REL-04: cliTimeoutSeconds) [config, CRUD]

**Analog:** `perplexityTimeoutSeconds` / `nvidiaNimTimeoutSeconds` — the closest existing `*TimeoutSeconds` fields. Copy ALL FIVE touch points (field decl → load → baseline → persist+KEY → default fn). Both carry inline defaults, so the positional `baselineSettings` stays compiling (RESEARCH A6 / CONTEXT "positional baselineSettings safe").

**1. Field declaration** (`AgentSettings.kt:56,61` — add a defaulted `Int`):
```kotlin
val nvidiaNimTimeoutSeconds: Int = 60,
val perplexityTimeoutSeconds: Int = 60,
// ADD (defaulted so existing positional/named constructions keep compiling):
val cliTimeoutSeconds: Int = Defaults.CLI_PROCESS_TIMEOUT_SECONDS,   // 120
```

**2. Load from prefs** (`AgentSettings.kt:289-291` — the `getInteger ?: default).coerceIn` idiom):
```kotlin
perplexityTimeoutSeconds =
    (prefs.getInteger(KEY_PERPLEXITY_TIMEOUT) ?: defaultPerplexityTimeoutSeconds())
        .coerceIn(30, 3600),
// ADD (coerceIn to a sane CLI range — V5 input-validation; reject negative/zero):
cliTimeoutSeconds =
    (prefs.getInteger(KEY_CLI_TIMEOUT) ?: Defaults.CLI_PROCESS_TIMEOUT_SECONDS)
        .coerceIn(30, 3600),
```

**3. Baseline / defaults factory** (`AgentSettings.kt:454`):
```kotlin
perplexityTimeoutSeconds = defaultPerplexityTimeoutSeconds(),
// ADD:
cliTimeoutSeconds = Defaults.CLI_PROCESS_TIMEOUT_SECONDS,
```

**4. Persist** (`AgentSettings.kt:560` + KEY const at `:814`):
```kotlin
prefs.setInteger(KEY_PERPLEXITY_TIMEOUT, settings.perplexityTimeoutSeconds.coerceIn(30, 3600))
// ADD:
prefs.setInteger(KEY_CLI_TIMEOUT, settings.cliTimeoutSeconds.coerceIn(30, 3600))
// ... and in the companion (near :814):
private const val KEY_CLI_TIMEOUT = "cli.timeoutSeconds"
```

**5. (Optional) default fn** (`AgentSettings.kt:959-961` style) — or reuse `Defaults.CLI_PROCESS_TIMEOUT_SECONDS` directly.

**GOTCHAS:**
- **A6:** plaintext pref (`getInteger`/`setInteger`), NOT `SecretCipher` — it's a timeout integer, not a secret (matches the `customRedactionPatterns` config-not-secret precedent).
- **`coerceIn(30, 3600)`** matches every sibling timeout field — keep the SAME bounds for consistency (V5).
- `Defaults.kt` may need no change (reuse `CLI_PROCESS_TIMEOUT_SECONDS=120` as the default); add a distinct const only if a different CLI default is desired.

---

### `backends/http/HttpBackendSupport.kt` — EXTEND (REL-03: shared 429/5xx helper) [service/util, request-response]

**Analog:** self — `isRetryableConnectionError(e)` (`:125-136`) and `newCircuitBreaker()` (`:148-153`). The new helper is the HTTP-status sibling of the existing connection-error helper. **EXTEND this existing `object` — do NOT create a new file** (the brief asked to check; it exists at 8667 bytes).

**Existing connection-error sibling to mirror** (`HttpBackendSupport.kt:125`):
```kotlin
fun isRetryableConnectionError(e: Exception): Boolean {
    if (e is EOFException) return true
    if (e is java.net.ConnectException || e is java.net.SocketTimeoutException) return true
    // ...
}
```

**Add (RESEARCH Pattern 3 — ONE helper, all 4 backends call it):**
```kotlin
/** 429 and 5xx are transient/overload signals the breaker should count (mirrors retry intent). */
fun isRetryableHttpStatus(statusCode: Int): Boolean = statusCode == 429 || statusCode in 500..599

/** Call on every non-successful HTTP response BEFORE onComplete, so the breaker sees overload. */
fun CircuitBreaker.recordHttpFailureIfRetryable(statusCode: Int) {
    if (isRetryableHttpStatus(statusCode)) recordFailure()
}
```
`CircuitBreaker.recordFailure()` (`CircuitBreaker.kt:83`) and the threshold (`CIRCUIT_FAILURE_THRESHOLD=5`, `HttpBackendSupport.kt:13`) are unchanged.

**GOTCHAS:**
- **4xx (400/401/403) must NOT trip the breaker** — those are non-transient config errors. The helper counts ONLY 429/5xx. (Anti-Pattern in RESEARCH.)
- **This single helper closes Phase 14 WR-05** — do NOT duplicate the `if (status in ...) recordFailure()` inline per backend (the four near-identical copies are exactly what caused the WR-05 drift).

---

### The 4 HTTP backends — MODIFY (REL-03: route 429/5xx through the helper) [backend, request-response]

**All four are structurally identical** (verified): each holds `private val circuitBreaker: CircuitBreaker` (constructed via `HttpBackendSupport.newCircuitBreaker()`), calls `circuitBreaker.tryAcquire()` at entry, `circuitBreaker.recordSuccess()` on the success path, and `circuitBreaker.recordFailure()` ONLY inside the connection-error `catch` — **never on the HTTP `!resp.isSuccessful` branch**. That missing call is the bug. The variable is named `circuitBreaker` in all four, so the fix line is byte-identical across them.

**The one-line fix per backend — add `circuitBreaker.recordHttpFailureIfRetryable(resp.statusCode)` immediately before the existing `onComplete(...)` in each `!resp.isSuccessful` block. Keep `return@submit` (no new retry — Pitfall 4). Leave the existing per-status user message untouched.**

| Backend | `!resp.isSuccessful` site | breaker field | success `recordSuccess()` | failure `recordFailure()` (conn-error only, today) |
|---------|---------------------------|---------------|---------------------------|-----------------------------------------------------|
| `OpenAiCompatibleBackend.kt` | `:243-264` | `:129` | `:285` | `:293` |
| `AnthropicBackend.kt` | `:197-213` (note 400-model guard `:188` BEFORE it) | `:73` | `:243` | `:251` |
| `OllamaBackend.kt` | `:294-298` (inside `if (transport != null)`) | `:206` | `:371` | `:379` |
| `LmStudioBackend.kt` | `:193-197` | `:94` | `:247` | `:255` |

**Canonical excerpt — `OpenAiCompatibleBackend.kt:243-264`** (the richest; the other three are simpler one-line messages):
```kotlin
val resp = transport.post(endpointUrl, allHeaders, json, timeoutSeconds * 1000)
if (!resp.isSuccessful) {
    errorLog("HTTP ${resp.statusCode}: ${resp.body.take(500)}")
    val message =
        when (resp.statusCode) {
            429 -> "$backendDisplayName rate limited (HTTP 429). Check quota/capacity or retry later."
            else -> buildString { /* #66 diagnosable 4xx: endpoint + body.take(800) + hints */ }
        }
    // ADD THIS ONE LINE (before onComplete):
    circuitBreaker.recordHttpFailureIfRetryable(resp.statusCode)
    onComplete(IllegalStateException(message))
    return@submit
}
```
**Ollama / LmStudio simpler form** (`OllamaBackend.kt:294`, `LmStudioBackend.kt:193`):
```kotlin
if (!resp.isSuccessful) {
    errorLog("HTTP ${resp.statusCode}: ${resp.body.take(500)}")
    circuitBreaker.recordHttpFailureIfRetryable(resp.statusCode)   // ADD
    onComplete(IllegalStateException("<Backend> HTTP ${resp.statusCode}: ${resp.body}"))
    return@submit
}
```

**GOTCHAS:**
- **Anthropic has a model-rejection 400 guard at `:188`** that `return@submit`s BEFORE the generic `!resp.isSuccessful` block. A 400 is NOT retryable, so it correctly does not (and should not) trip the breaker. Add the helper only in the generic block at `:197`, after the 400-model guard.
- **Ollama's failure branch is inside `if (transport != null)`** (`:292`) — the `else` no-transport OkHttp path (`:301+`) is the unit-test-only path; the production fix lives in the transport branch.
- **NVIDIA + Perplexity** delegate to `OpenAiCompatibleBackend` (factories) — fixing OpenAiCompatible covers them automatically. **BurpAi is excluded** (native Burp AI, no HTTP).
- **Pitfall 4 (no double-count):** add `recordFailure` but keep `return@submit` — do NOT add HTTP-status retries (would let one overloaded server trip the breaker faster than the threshold intends).

---

### `mcp/KtorMcpServerManager.kt` — MODIFY (REL-02/SC5: bound stop()) [mcp manager, lifecycle]

**Analog:** self — `shutdown()` (`:245-252`) is ALREADY bounded (10s `awaitTermination` + `shutdownNow`). `stop()` (`:230-243`) is NOT — it does `executor.submit { ... }` with no bound, so a hung `server.stop(1000, 5000)` leaves `stop()` effectively unbounded at the executor level. Give `stop()` the same bounded-await semantics.

**The bounded analog to copy** (`KtorMcpServerManager.kt:245-252`):
```kotlin
override fun shutdown() {
    server?.stop(1000, 5000)
    server = null
    executor.shutdown()
    if (!executor.awaitTermination(10, TimeUnit.SECONDS)) {
        executor.shutdownNow()
    }
}
```

**The unbounded site to fix** (`KtorMcpServerManager.kt:230-243`):
```kotlin
override fun stop(callback: (McpServerState) -> Unit) {
    callback(McpServerState.Stopping)
    executor.submit {                       // <-- submitted work can hang; stop() returns but never bounds it
        try {
            server?.stop(1000, 5000)
            server = null
            api.logging().logToOutput("Stopped MCP server")
            callback(McpServerState.Stopped)
        } catch (e: Exception) {
            api.logging().logToError(e)
            callback(McpServerState.Failed(e))
        }
    }
}
```
**Fix:** bound the submitted task (e.g. `future = executor.submit{...}; future.get(bound, SECONDS)` with a force-stop + `Failed`/`Stopped` callback on timeout), mirroring `shutdown()`'s `awaitTermination`+`shutdownNow`.

**GOTCHAS:**
- The `McpServerManager` interface (`mcp/McpServerManager.kt:28-30`) declares both `stop(callback)` and `shutdown()` — only the `KtorMcpServerManager` IMPL changes; the interface signature stays.
- The `callback` is the lifecycle channel — on timeout, still drive `callback(Stopped)` or `callback(Failed(...))` so the UI doesn't wait forever. Don't drop the callback.
- `server.stop(1000, 5000)` already has Ktor-level grace/timeout (gracePeriodMillis/timeoutMillis); the NEW bound is at the executor/manager level so `stop()` itself can't hang.

---

### `redact/Redaction.kt` — MODIFY (REL-02/SC5: LRU-cap host maps) [redaction/cache, transform+cache]

**Analog:** self — the nested `ConcurrentHashMap` host maps and their `computeIfAbsent` create points. RESEARCH Pattern 4 = JDK `LinkedHashMap(accessOrder=true).removeEldestEntry`, wrapped in `Collections.synchronizedMap`.

**The unbounded maps** (`Redaction.kt:145-146`):
```kotlin
private val hostForwardMap = ConcurrentHashMap<String, ConcurrentHashMap<String, String>>()
private val hostReverseMap = ConcurrentHashMap<String, ConcurrentHashMap<String, String>>()
```
**The create + write site** (`Redaction.kt:289-294`, inside `anonymizeHost`):
```kotlin
val anon = "host-$short.local"
if (recordMapping) {
    hostForwardMap.computeIfAbsent(salt) { ConcurrentHashMap() }[host] = anon   // <-- INNER map is unbounded
    hostReverseMap.computeIfAbsent(salt) { ConcurrentHashMap() }[anon] = host
}
return anon
```
**The reads/clears to preserve** (`Redaction.kt:297-310`):
```kotlin
fun deAnonymizeHost(host: String, salt: String): String? = hostReverseMap[salt]?.get(host)

fun clearMappings(salt: String? = null) {
    if (salt == null) { hostForwardMap.clear(); hostReverseMap.clear(); return }
    hostForwardMap.remove(salt)
    hostReverseMap.remove(salt)
}
```
**Fix (RESEARCH Pattern 4):** keep the OUTER `ConcurrentHashMap<salt, ...>` and its `computeIfAbsent(salt){...}` / `remove(salt)` EXACTLY as-is; swap ONLY the INNER `ConcurrentHashMap()` for a bounded LRU:
```kotlin
private fun <K, V> boundedLru(maxEntries: Int): MutableMap<K, V> =
    java.util.Collections.synchronizedMap(
        object : LinkedHashMap<K, V>(16, 0.75f, /* accessOrder = */ true) {
            override fun removeEldestEntry(eldest: Map.Entry<K, V>): Boolean = size > maxEntries
        },
    )
// then: hostForwardMap.computeIfAbsent(salt) { boundedLru(HOST_MAP_CAP) }[host] = anon
```
Recommended cap: `4096` per salt (A4 / CONTEXT "a few thousand, Claude's discretion").

**GOTCHAS (load-bearing — privacy-critical):**
- **The map is NESTED** (`salt → host → anon`). Bound the **INNER** per-salt map, NOT the outer salt map. The outer `computeIfAbsent(salt){...}` / `remove(salt)` MUST stay so `clearMappings` keeps working (Pitfall 5).
- **Output format is frozen:** `host-<12hex>.local` (6 HKDF bytes → 12 hex, `:288`). LRU eviction MUST NOT touch the HKDF crypto or the format. `RedactionTest` asserts `Regex("^host-[0-9a-f]{12}\\.local$")` and round-trips `anonymizeHost`→`deAnonymizeHost` — both must stay green (V6 / Pitfall 5).
- **Forward/reverse eviction skew is benign:** if forward evicts `host→anon` but reverse still has `anon→host`, de-anon still works (reverse is the lookup path) and re-anonymizing is deterministic (HKDF is pure) — document it, cap both at the same size.
- **`@Volatile`/concurrency:** wrap the inner LRU in `Collections.synchronizedMap` (LinkedHashMap is not thread-safe). The outer map stays `ConcurrentHashMap`.

---

## Shared Patterns

### Circuit-Breaker failure recording (REL-03)
**Source:** new helper in `backends/http/HttpBackendSupport.kt` (sibling of `isRetryableConnectionError:125`); breaker at `backends/http/CircuitBreaker.kt` (`recordFailure:83`, `recordSuccess:74`, threshold 5).
**Apply to:** all 4 HTTP backends (OpenAiCompatible, Anthropic, Ollama, LmStudio) at their `!resp.isSuccessful` branch. NVIDIA/Perplexity inherit via OpenAiCompatible. BurpAi excluded.
```kotlin
fun isRetryableHttpStatus(statusCode: Int): Boolean = statusCode == 429 || statusCode in 500..599
fun CircuitBreaker.recordHttpFailureIfRetryable(statusCode: Int) {
    if (isRetryableHttpStatus(statusCode)) recordFailure()
}
```

### EDT marshalling (REL-01)
**Source:** `SwingUtilities.invokeLater { ... }` — established in `ChatPanel.kt:568,:579,:594,:633,:641`.
**Apply to:** the off-EDT map reads + `panel.addMessage` reached from `onComplete:570` → `maybeExecuteToolCall:2046` (`:2049,:2050,:2074,:2096`). Keep `onCompleted` off-EDT.

### Bounded executor shutdown (REL-02/SC5)
**Source:** `KtorMcpServerManager.shutdown():245-252` — `executor.shutdown()` + `awaitTermination(10, SECONDS)` + `shutdownNow()`.
**Apply to:** `KtorMcpServerManager.stop():230` (bound the submitted task).
```kotlin
executor.shutdown()
if (!executor.awaitTermination(10, TimeUnit.SECONDS)) { executor.shutdownNow() }
```

### Temp-file lifecycle (REL-02)
**Source:** `CliBackend.kt:274-288` `finally` cleanup + inline `:138`.
**Apply to:** both `createTempFile` sites (`:109,:121`) — add `deleteOnExit()` at creation, keep `finally` deletes.

### Settings field (defaulted) + prefs round-trip (REL-04)
**Source:** `perplexityTimeoutSeconds` / `nvidiaNimTimeoutSeconds` — field decl (`:56,:61`), load+coerce (`:289-291`), baseline (`:454`), persist+KEY (`:560,:814`), default fn (`:959-961`).
**Apply to:** `cliTimeoutSeconds` — copy all five touch points; `coerceIn(30, 3600)`; plaintext `getInteger`/`setInteger`.

### LRU-bounded cache (REL-02/SC5)
**Source:** RESEARCH Pattern 4 — `Collections.synchronizedMap(LinkedHashMap(16, 0.75f, accessOrder=true){ removeEldestEntry = size > cap })`.
**Apply to:** the INNER per-salt host map in `Redaction.kt` (`anonymizeHost:291-292`). Keep the outer `ConcurrentHashMap` + `computeIfAbsent`/`remove`.

---

## Test Pattern Assignments

### `ui/ChatPanelConcurrencyTest.kt` — EXTEND (SC1)
**Analog:** itself — it already tests the concurrency *primitive* (`InFlightConnectionTracker`) in isolation with `Executors.newFixedThreadPool(4)` + `CountDownLatch` + `Collections.synchronizedList`, NOT the heavy `ChatPanel` object. Follow that precedent (Pitfall 3): a single-thread executor stands in for the EDT while other threads attempt access; assert no `ConcurrentModificationException` and a consistent final state. Existing pattern (`:38-54`):
```kotlin
val pool = Executors.newFixedThreadPool(4)
val start = CountDownLatch(1)
val results = Collections.synchronizedList(mutableListOf<AgentConnection?>())
repeat(4) { pool.submit { start.await(); results.add(tracker.take()) } }
start.countDown(); pool.shutdown(); assertTrue(pool.awaitTermination(2, TimeUnit.SECONDS))
```
**Wave-0 build task:** add `jvmArgs("-ea")` (or `enableAssertions = true`) to `tasks.test` in `build.gradle.kts:137` so the EDT `assert` fires (currently absent — Pitfall 2).

### `backends/http/HttpBackendCircuitFailureTest.kt` — CREATE (SC3)
**Analogs:** `HttpBackendTransportRoutingTest` (transport spy) + `CircuitBreakerTest` (determinism). The spy helper to copy (`HttpBackendTransportRoutingTest.kt:288-294`):
```kotlin
private fun stubTransportPost(): MontoyaHttpTransport {
    val api = mock<MontoyaApi>(/* RETURNS_DEEP_STUBS */)
    val transport = spy(MontoyaHttpTransport(api))
    doReturn(TransportResponse(200, "{}", true)).whenever(transport).post(any(), any(), any(), any())
    return transport
}
```
**For SC3:** return `TransportResponse(429, "rate limited", false)` (or 503), drive ~6 sends (threshold is 5) via `CountDownLatch`, and assert the breaker opened **behaviorally** — the Nth send fails fast with `HttpBackendSupport.openCircuitError(...)` text `"temporarily unavailable (circuit open)"` (RESEARCH §Code Examples + Open Question 3: do NOT widen breaker visibility). `TransportResponse(statusCode, body, isSuccessful)` is at `MontoyaHttpTransport.kt:9`. Cover OpenAiCompatible (→ NVIDIA/Perplexity), Anthropic, Ollama, LmStudio.

### `backends/cli/CliTimeoutMessageTest.kt` — CREATE (SC4)
**Analog:** `CopilotCommandBuilderTest` (extracted-`internal fun` precedent). Primary test = unit-test the extracted `buildTimeoutMessage(tail, timeoutSeconds)` string directly (OS-independent): assert it `contains("timed out")`, names the configured limit, and suggests `increase`/`pre-install`. Optional integration variant uses `/bin/sh -c "sleep 5"` with `timeoutSeconds=1`, guarded by `Assumptions.assumeTrue(File("/bin/sh").exists())`.

### `mcp/McpShutdownBoundTest.kt` — CREATE (SC5a)
**Analogs:** `McpServerIntegrationTest` / `McpSupervisorRestartPolicyTest`. Start a manager, call `stop(callback)`, assert the callback reaches `Stopped`/`Failed` within `(bound + margin)` via `CountDownLatch.await(timeout)` — and that it does NOT block indefinitely. **Naming note:** `*IntegrationTest` / `*RestartPolicyTest` / `*ConcurrencyTest` are EXCLUDED under `-PexcludeHeavyTests=true` (`build.gradle.kts:143-149`); `McpShutdownBoundTest` is NOT excluded by those globs (good — runs in the standard suite). If it's heavy, name it accordingly on purpose.

### `redact/RedactionHostMapBoundTest.kt` — CREATE (SC5b)
**Analog:** `RedactionTest` — copy its round-trip + format assertions and keep them green:
```kotlin
// RedactionTest.kt:73-76, 146-156, 161-166
val a = Redaction.anonymizeHost("example.com", "salt-a")           // stable per salt
assertEquals("a.example", Redaction.deAnonymizeHost(anonA, "salt-a"))   // round-trip
result.matches(Regex("^host-[0-9a-f]{12}\\.local$"))                    // frozen format
Redaction.clearMappings("salt-a"); assertEquals(null, Redaction.deAnonymizeHost(anonA, "salt-a"))
```
**For SC5b:** anonymize > CAP distinct hosts under one salt, assert the inner map size stays ≤ CAP (LRU bound), AND that the format + a recently-used round-trip still hold. **`Redaction` is an `object`** (singleton) — tests share state; reset via `clearMappings()` in setup/teardown to avoid cross-test bleed.

---

## No Analog Found

None. Every production and test file has a concrete in-repo analog with line anchors. `util/GuardedBy.kt` is the only genuinely new file (no existing `annotation class` in the repo), but its full content is specified verbatim above and its package/header style follows `util/SsrfGuard.kt`.

---

## Cross-Cutting Gotchas (planner must enforce)

1. **`@GuardedBy` MUST be `@Retention(SOURCE)`** — zero runtime/class footprint, no new dependency. JCIP/jsr305 are deliberately off-classpath.
2. **The host map is NESTED** (`salt → host → anon`) — bound the INNER map, keep the outer `ConcurrentHashMap` + `computeIfAbsent`/`remove` so `clearMappings` and the `host-<12hex>.local` round-trip survive.
3. **New `AgentSettings` fields MUST be defaulted** (`cliTimeoutSeconds: Int = Defaults.CLI_PROCESS_TIMEOUT_SECONDS`) so the positional `baselineSettings` keeps compiling.
4. **ONE shared 429/5xx helper** in `HttpBackendSupport` — do NOT duplicate per backend (that drift caused WR-05). The breaker field is `circuitBreaker` in all four backends, so the call line is identical.
5. **Do NOT mutate `Defaults.CLI_PROCESS_TIMEOUT_SECONDS`** — it is shared with HTTP-backend defaults (`AgentSettings.kt:959,961`). ADD `cliTimeoutSeconds`.
6. **`tasks.test` does NOT enable `-ea`** (`build.gradle.kts:137-151`) — the EDT `assert` is a no-op in CI until `jvmArgs("-ea")` is added. The concurrency test, not the assert, is the SC1 gate.
7. **Keep `return@submit` on 429/5xx** — add `recordFailure` only; no new HTTP-status retry (Pitfall 4).
8. **Bound `stop()` at the executor/manager level**, mirroring `shutdown():245-252`; the `callback` must still fire (`Stopped`/`Failed`) on timeout so the UI doesn't hang.
9. **Validate with `./gradlew test`, NOT `ktlintCheck`** (known `generateBuildFlags` defect). Regression watch: `RedactionTest`, `CircuitBreakerTest`, `HttpBackendTransportRoutingTest`, `AnthropicModelErrorTest`, MCP server/restart tests.

---

## Metadata

**Analog search scope:** `src/main/kotlin/com/six2dez/burp/aiagent/{ui,backends/{cli,http,openai,anthropic,ollama,lmstudio},mcp,redact,config,util}` + `src/test/kotlin/.../{ui,backends/{cli,http},mcp,redact}` + `build.gradle.kts`.
**Files scanned (read directly):** ChatPanel.kt, CliBackend.kt, AgentSettings.kt, Defaults.kt (grep), HttpBackendSupport.kt, CircuitBreaker.kt, MontoyaHttpTransport.kt, OpenAiCompatibleBackend.kt, AnthropicBackend.kt, OllamaBackend.kt, LmStudioBackend.kt, McpServerManager.kt, KtorMcpServerManager.kt, Redaction.kt, SsrfGuard.kt, ChatPanelConcurrencyTest.kt, CircuitBreakerTest.kt, HttpBackendTransportRoutingTest.kt, RedactionTest.kt (grep), build.gradle.kts.
**Pattern extraction date:** 2026-06-11
**Source consistency:** all line anchors verified against RESEARCH.md's defect map; no discrepancies found (RESEARCH was authored from the same source reads).
