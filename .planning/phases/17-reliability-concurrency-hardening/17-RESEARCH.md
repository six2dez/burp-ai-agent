# Phase 17: Reliability & Concurrency Hardening - Research

**Researched:** 2026-06-11
**Domain:** JVM concurrency (Swing EDT confinement), resource lifecycle (temp files / executor shutdown), HTTP fault tolerance (circuit breaker + timeouts), process timeout handling
**Confidence:** HIGH — this is an internal-correctness phase; every finding is grounded in the project's own source, which was read directly. No external library choices are required; no new dependencies.

## Summary

All four REL items are **internal robustness fixes on existing code paths** — no new features, no new libraries, no new dependencies. The research confirmed the exact defect sites named in CONTEXT.md and, importantly, found that **all four HTTP backends share the identical REL-03 defect** (not just Anthropic/OpenAiCompatible), which makes a shared helper the correct fix.

The single most important architectural finding: `ChatPanel`'s backend `onComplete` callback (`ChatPanel.kt:570`) runs **on the backend connection's own executor thread, NOT the EDT**. Inside that callback, `maybeExecuteToolCall(...)` (`ChatPanel.kt:2046`) reads `sessionPanels[sessionId]` and `sessionsById[sessionId]` (lines 2049–2050) and calls `panel.addMessage(...)` — all off-EDT, concurrently with EDT mutations (`createSession`/`deleteSession`/`restore`). This is the concrete REL-01 data race. The fix per CONTEXT is EDT confinement (assert + `invokeLater`), NOT thread-safe collections, preserving insertion order.

**Primary recommendation:** Define a local `@GuardedBy` annotation (zero new deps — JCIP/jsr305 are NOT on the classpath), confine the 4 maps to the EDT by routing the off-EDT `maybeExecuteToolCall` map reads + Swing mutations through `SwingUtilities.invokeLater`, add a shared `CircuitBreaker` failure-recording helper that all 4 HTTP backends call on 429/5xx, bound the MCP executor shutdown (already partially bounded — tighten it), LRU-cap the inner host maps, and make the CLI process timeout configurable with an actionable timeout message for issue #71. Extend the four existing test harnesses (`ChatPanelConcurrencyTest`, `CircuitBreakerTest`, `HttpBackendTransportRoutingTest`, `McpRequestLimiterConcurrencyTest`) rather than inventing new patterns.

<user_constraints>
## User Constraints (from CONTEXT.md)

### Locked Decisions

**REL-01 — EDT confinement**
- Annotate the 4 `ChatPanel` session maps (currently `linkedMapOf`) with `@GuardedBy("EDT")` and keep them EDT-confined (NOT converted to thread-safe collections). Add EDT assertions on access; any off-EDT mutation routes via `SwingUtilities.invokeLater`. A concurrency test verifies no data race (SC1's required test). Preserve insertion order (they are `linkedMapOf` for ordering).

**REL-02 — Resource hardening**
- CLI temp files (`CliBackend.kt` `createTempFile` sites): delete in a `finally` block (not only `catch`) AND call `deleteOnExit()` at creation so a crash still cleans up. Audit ALL temp-file sites (codex/uv prompt files, output files).
- MCP server shutdown (`McpServerManager.stop()`/`shutdown()`): bound with a timeout (e.g. `awaitTermination(timeout)`) so `stop()` never hangs; force-stop after the bound.
- Host-anonymization maps (`Redaction.hostForwardMap`/`hostReverseMap`): **size-cap with LRU-style eviction** (bounded memory over a long session) AND keep the existing `clearMappings` on salt rotation. The exact cap is at Claude's discretion (e.g. a few thousand entries).

**REL-03 — Uniform HTTP timeouts + CircuitBreaker**
- All HTTP backends (Ollama, OpenAI-compatible, Perplexity, NVIDIA, Anthropic, BurpAI) share **consistent connect/read timeout** defaults via `MontoyaHttpTransport` and route through the `CircuitBreaker`; none construct their own client/bypass the transport.
- **Route retryable HTTP failures (429 / 5xx) through `CircuitBreaker.recordFailure`** so the breaker + retry logic actually see them — this **closes Phase 14's deferred WR-05** (Anthropic 429/5xx was not routed through `recordFailure`; the OpenAiCompatible analog wasn't either, so fix it consistently across backends here). A success path calls `recordSuccess`.

**REL-04 — Issue #71 (CLI command timeout)**
- Researcher fetches issue #71. Reproduce + fix the **root cause** if tractable; otherwise surface an **actionable error message** (SC4 permits either). Add a **regression test** in both cases.

### Claude's Discretion
- Exact timeout values (connect/read), the host-map cap size + eviction policy details, the MCP shutdown bound, the EDT-assertion mechanism, and whether REL-04 lands as a root-cause fix vs actionable error (depends on what #71 turns out to be) — at Claude's discretion, guided by the existing `CircuitBreaker`/`MontoyaHttpTransport`/`CliBackend` code.

### Deferred Ideas (OUT OF SCOPE)
- The QUAL-04 silently-swallowed `catch (Exception)` audit + shared logging helper — Phase 18 (ties to REL-04 diagnosability but is a separate requirement). Do NOT do a broad swallowed-exception audit in this phase; only REL-04's specific timeout-diagnosability message is in scope.
</user_constraints>

<phase_requirements>
## Phase Requirements

| ID | Description | Research Support |
|----|-------------|------------------|
| REL-01 (SC1) | ChatPanel session maps accessed without data races; EDT-confined; concurrency test proves it | Confirmed the race: `onComplete` callback (`ChatPanel.kt:570`) runs off-EDT, and `maybeExecuteToolCall` (`:2046`) reads `sessionPanels`/`sessionsById` (`:2049–2050`) + mutates Swing off-EDT. Local `@GuardedBy` annotation needed (no JCIP on classpath). Existing `ChatPanelConcurrencyTest` is the test seam. |
| REL-02 (SC2/SC5) | CLI temp files `finally`+`deleteOnExit`; bounded MCP shutdown; bounded host maps | Temp-file sites: `CliBackend.kt:109` (codex output), `:121` (uv prompt). Current cleanup: `finally` block at `:274–288` (covers prompt+output), inline `delete()` at `:138`. Missing: `deleteOnExit()` at both creation sites. MCP shutdown already bounded at `KtorMcpServerManager.kt:245–252` (10s) — `stop()` at `:230` is NOT bounded. Host maps are nested `ConcurrentHashMap` at `Redaction.kt:145–146`, unbounded. |
| REL-03 (SC3) | All HTTP backends share timeouts + route through CircuitBreaker; none bypass transport; 429/5xx → recordFailure | **All four** HTTP-failure paths skip `recordFailure`: OpenAiCompatible (`:243–264`), Anthropic (`:197–213`), Ollama (`:294–298`), LMStudio (`:193–197`). NVIDIA+Perplexity delegate to OpenAiCompatible. BurpAi uses native Burp AI (no HTTP — correctly excluded). Timeout already centralized in `MontoyaHttpTransport`. |
| REL-04 (#71) | CLI timeout (issue #71) diagnosed + fixed/actionable + regression test | Root cause: `Defaults.CLI_PROCESS_TIMEOUT_SECONDS = 120` is hardcoded and NOT user-overridable for CLI (HTTP backends have per-backend timeout prefs; CLI does not). `npx @google/gemini-cli` first-run download exceeds 120s → bare "CLI command timed out" (`CliBackend.kt:233–239`) with no remediation hint. `gemini-cli` IS registered, so this is the standard-timeout path, not an unrecognized-CLI path. |
</phase_requirements>

## Project Constraints (from CLAUDE.md)

These are binding directives extracted from `CLAUDE.md` and `AGENTS.md`; the planner must verify compliance.

| Directive | Source | Impact on this phase |
|-----------|--------|----------------------|
| **Zero new runtime dependencies** unless already present | CLAUDE.md (MIT-compat, fat-JAR control) | `@GuardedBy` MUST be a local annotation — JCIP (`net.jcip`) and jsr305 are NOT on the classpath (verified via `gradlew dependencies`). Only `org.jetbrains:annotations:23.0.0` is available transitively, and it has no `@GuardedBy`. |
| **Build/test with `./gradlew test`, NOT `ktlintCheck`** | MEMORY.md (`generateBuildFlags` wiring defect) | All validation commands in this research use `./gradlew test`. `./gradlew ktlintCheck` fails standalone (pre-existing defect, fixed separately in QUAL-05/Phase 18). |
| **Kotlin (JVM 21), Gradle Kotlin DSL, Montoya API** | CLAUDE.md / ADR-1/2/3 | No language/stack changes. Swing UI on EDT (ADR-2 locks Swing). |
| **English only in code & comments** | AGENTS.md (non-negotiable) | All new code/comments in English. |
| **Privacy is non-negotiable** | CLAUDE.md core value | Host-map LRU eviction must not change the anonymization output format (`host-<12hex>.local`) or break `deAnonymizeHost`. Error messages must not leak prompt content (existing pattern: bounded tails, shape-only previews). |
| **No outbound telemetry** | CLAUDE.md / Out of Scope | REL-04 diagnosability is local error-message text only; no crash reporting. |

## Architectural Responsibility Map

| Capability | Primary Tier | Secondary Tier | Rationale |
|------------|-------------|----------------|-----------|
| Session-map mutation/read (REL-01) | UI / EDT (`ChatPanel`) | Backend executor threads (callbacks) | Maps are UI state; the defect is that backend callback threads touch them. Fix confines all access to the EDT. |
| CLI temp-file lifecycle (REL-02) | Backend / CLI (`CliBackend`) | OS filesystem | Files are created/consumed entirely within the CLI connection's worker thread; cleanup is a `finally` + JVM-shutdown concern. |
| MCP server shutdown bound (REL-02/SC5) | MCP server (`KtorMcpServerManager`) | Ktor/Netty executor | The Netty engine + single-thread executor own shutdown; the bound belongs at the manager's `stop()`/`shutdown()`. |
| Host-anonymization map bounding (REL-02/SC5) | Redaction (`Redaction`) | — | Pure in-memory cache owned by `Redaction`; bound + evict at the map layer. |
| HTTP timeout + failure recording (REL-03) | Backend HTTP connections | Transport (`MontoyaHttpTransport`) + `CircuitBreaker` | Timeout is centralized in the transport; failure-recording is per-connection (each owns its breaker). The shared helper lives at the `HttpBackendSupport` layer. |
| CLI process timeout (REL-04) | Backend / CLI (`CliBackend`) | Config (`AgentSettings`/`Defaults`) | The timeout value + actionable message are CLI-connection concerns; making it user-configurable touches settings. |

## Standard Stack

**No new libraries.** This phase uses only what is already in the build. The "stack" here is the set of existing internal abstractions to reuse.

### Core (existing internal components — reuse, do not replace)
| Component | Location | Purpose | Why standard |
|-----------|----------|---------|--------------|
| `CircuitBreaker` | `backends/http/CircuitBreaker.kt` | CLOSED/OPEN/HALF_OPEN breaker with injectable `nowProvider` | Already the single breaker abstraction; `nowProvider` makes it deterministically testable (see `CircuitBreakerTest`). |
| `MontoyaHttpTransport` | `backends/http/MontoyaHttpTransport.kt` | The ONLY production HTTP path (Burp-proxy-visible); `post(timeoutMs=120_000)`, `get(timeoutMs=3_000)`, `.withResponseTimeout(timeoutMs)` | Centralizes timeouts (issue #69 trap: backends must not build their own client). |
| `HttpBackendSupport` | `backends/http/HttpBackendSupport.kt` | Factory for breakers (`newCircuitBreaker()`), retry helpers (`isRetryableConnectionError`, `retryDelayMs`), `openCircuitError` | The natural home for the new shared 429/5xx → recordFailure helper. |
| `SwingUtilities.invokeLater` | JDK | EDT marshalling | The established cross-thread UI pattern in `ChatPanel` (already used at `:568`, `:579`, `:594`, `:633`, `:641`). |
| Local `@GuardedBy` annotation | NEW (to create) | Documents the EDT-confinement contract on the 4 maps | JCIP not on classpath; a 3-line Kotlin `annotation class` carries the same documentation intent with zero deps. |

### Supporting (test infrastructure — already present)
| Library | Version | Purpose | When to use |
|---------|---------|---------|-------------|
| JUnit Jupiter | 6.0.3 | Test framework | All tests. |
| mockito-kotlin | 5.4.0 | Mocking + `spy()` | Mock/spy `MontoyaHttpTransport` to return `TransportResponse(429, ...)` for REL-03 tests. |
| mockwebserver (OkHttp) | 4.12.0 | Local HTTP server | Available if a real transport round-trip is preferred over a spy (spy is simpler here). |
| `java.util.concurrent` (`CountDownLatch`, `Executors`, `AtomicLong`) | JDK | Concurrency test scaffolding | REL-01 map-hammering test; REL-04 process-timeout test. |

### Alternatives Considered
| Instead of | Could Use | Tradeoff |
|------------|-----------|----------|
| EDT confinement (REL-01) | `Collections.synchronizedMap` / `ConcurrentHashMap` | CONTEXT explicitly rejects this. Thread-safe collections would still leave the off-EDT `panel.addMessage(...)` Swing mutation unsafe, and would not fix the read-modify-write races (e.g. `getOrPut`). EDT confinement fixes both the maps AND the Swing calls. |
| Local `@GuardedBy` (REL-01) | Add `net.jcip:jcip-annotations` or `com.google.code.findbugs:jsr305` | Violates zero-new-deps. jsr305 is also effectively unmaintained and adds a split-package risk under JPMS. A local annotation is strictly better here. |
| Shared `recordFailure` helper (REL-03) | Duplicate the `if (statusCode in retryableSet) recordFailure()` inline in each backend | Four near-identical copies already caused the WR-05 drift. A single helper in `HttpBackendSupport` (e.g. `isRetryableHttpStatus(code)` + a `recordHttpOutcome(...)`) prevents future divergence. |
| Configurable CLI timeout (REL-04) | Just raise the hardcoded default to e.g. 300s | A bigger constant still fails for very slow first-run `npx` downloads and gives no user control. CONTEXT favors actionable error; a configurable setting + actionable message is the durable fix. |

**Installation:** None. No `npm`/`pip`/`cargo`/Gradle dependency additions.

## Package Legitimacy Audit

**Not applicable — this phase installs zero external packages.** No registry lookups, no slopcheck needed. The only "new" artifact is a local Kotlin annotation class authored in-repo. Verified via `./gradlew dependencies --configuration compileClasspath`: no dependency changes are required, and JCIP/jsr305 are deliberately NOT added.

## Architecture Patterns

### System Architecture Diagram (the four data-flow paths this phase touches)

```
REL-01  EDT confinement
────────────────────────────────────────────────────────────────────
  [EDT] createSession / deleteSession / restore / switchTo
        │  write/read sessionPanels, sessionStates, sessionsById, sessionDrafts
        ▼
  ┌─────────────────────────┐
  │ 4 linkedMap session maps │  ◄── DATA RACE
  └─────────────────────────┘
        ▲
        │ read sessionPanels[id], sessionsById[id]  + panel.addMessage()
  [backend-connection thread]  maybeExecuteToolCall()   (ChatPanel.kt:2046)
        ▲
        │ onComplete(err)  (runs on connection executor, NOT EDT)
  connection.send(...)  ──►  AgentSupervisor.sendChat (:509)  ──►  ChatPanel onComplete (:570)

  FIX: every map touch + Swing call inside onComplete/maybeExecuteToolCall → SwingUtilities.invokeLater


REL-03  HTTP failure → breaker
────────────────────────────────────────────────────────────────────
  send() ─► circuitBreaker.tryAcquire()
            │ allowed
            ▼
        transport.post(url, headers, json, timeoutMs)
            │
            ├─ throws (ConnectException/SocketTimeout) ─► isRetryableConnectionError ─► recordFailure() ✓ (exists)
            │
            └─ returns TransportResponse(statusCode=429|5xx)
                       │
                       └─► onComplete(error) + return   ◄── recordFailure() NEVER CALLED ✗ (the bug, all 4 backends)

  FIX: before onComplete on a retryable HTTP status, call circuitBreaker.recordFailure() via shared helper


REL-02  resource lifecycle
────────────────────────────────────────────────────────────────────
  CliBackend temp files:  createTempFile (:109 codex output, :121 uv prompt)
        │  (no deleteOnExit today)
        ▼
   write → use → finally { promptFile?.delete(); outputFile?.delete() } (:274–288)
        FIX: add deleteOnExit() at BOTH creation sites (crash-safe)

  MCP shutdown:  stop() (:230, single-thread executor.submit, server.stop(1000,5000)) — NOT bounded at executor level
                 shutdown() (:245, executor.shutdown + awaitTermination(10s) + shutdownNow) — bounded ✓
        FIX: give stop() the same bounded-await semantics

  Host maps:  hostForwardMap[salt][host]=anon ; hostReverseMap[salt][anon]=host  (nested ConcurrentHashMap, unbounded)
        FIX: bound the INNER map per salt with LRU eviction (keep clearMappings on rotation)


REL-04  CLI process timeout (#71)
────────────────────────────────────────────────────────────────────
  send() ─► process.waitFor(CLI_PROCESS_TIMEOUT_SECONDS=120, SECONDS)   (:225, hardcoded const, no user override)
            │ timed out
            ▼
        "CLI command timed out[: <tail>]"   (:233–239)  ◄── no remediation hint, not configurable
        FIX: (a) add user-configurable cliTimeoutSeconds; (b) actionable message naming the timeout value +
             suggesting pre-install / longer timeout (esp. for npx first-run downloads)
```

### Recommended File Touch Map (no new modules; all edits in existing files + 1 tiny annotation + tests)
```
src/main/kotlin/com/six2dez/burp/aiagent/
├── util/GuardedBy.kt                    # NEW — @Target(FIELD) annotation class GuardedBy(val lock: String)
├── ui/ChatPanel.kt                      # REL-01 — annotate 4 maps; route off-EDT access via invokeLater; EDT assert helper
├── backends/cli/CliBackend.kt           # REL-02 (deleteOnExit) + REL-04 (configurable timeout + actionable msg)
├── backends/http/HttpBackendSupport.kt  # REL-03 — add isRetryableHttpStatus()/recordHttpOutcome() shared helper
├── backends/http/{OpenAiCompatible,Ollama,LmStudio}Backend.kt + anthropic/AnthropicBackend.kt  # REL-03 — call helper on !isSuccessful
├── mcp/KtorMcpServerManager.kt          # REL-02/SC5 — bound stop() like shutdown()
├── redact/Redaction.kt                  # REL-02/SC5 — LRU-cap inner host maps
└── config/{Defaults,AgentSettings}.kt   # REL-04 — cliTimeoutSeconds setting (Defaults default + prefs key)
```

### Pattern 1: Local `@GuardedBy` annotation (zero-dep documentation contract)
**What:** A minimal Kotlin annotation that documents which lock/thread guards a field. Replaces JCIP's `@GuardedBy` without a dependency.
**When to use:** On the 4 `ChatPanel` session-map fields.
**Example:**
```kotlin
// src/main/kotlin/com/six2dez/burp/aiagent/util/GuardedBy.kt
// Source: documents the same contract as net.jcip.annotations.GuardedBy (not on classpath; zero-dep local copy).
@Target(AnnotationTarget.FIELD, AnnotationTarget.PROPERTY)
@Retention(AnnotationRetention.SOURCE)   // SOURCE: documentation only, no runtime/class footprint
annotation class GuardedBy(val lock: String)
```
```kotlin
// usage in ChatPanel.kt
@GuardedBy("EDT") private val sessionPanels = linkedMapOf<String, SessionPanel>()
@GuardedBy("EDT") private val sessionStates = linkedMapOf<String, ToolSessionState>()
@GuardedBy("EDT") private val sessionsById  = linkedMapOf<String, ChatSession>()
@GuardedBy("EDT") private val sessionDrafts = linkedMapOf<String, String>()
```
Note: `@Retention(SOURCE)` keeps it out of the fat JAR entirely. Confirm `-Xjsr305=strict` (build.gradle.kts:105) does not interact — it only affects jsr305-annotated *external* types, not a local annotation, so it is irrelevant here.

### Pattern 2: EDT assertion + confinement
**What:** Assert EDT on map access in debug/test builds; route off-EDT callers through `invokeLater`.
**When to use:** The off-EDT site is `maybeExecuteToolCall` (called from `onComplete` at `:646`).
**Example:**
```kotlin
// helper (private in ChatPanel)
private fun assertEdt() {
    // Use assert (JVM -ea in tests) rather than a hard throw, to avoid changing prod behavior.
    assert(SwingUtilities.isEventDispatchThread()) { "session maps must be touched on the EDT" }
}

// The off-EDT chain at onComplete (:646) currently calls maybeExecuteToolCall(...) directly on the
// backend thread. Route the map-touching + Swing-mutating body onto the EDT:
SwingUtilities.invokeLater {
    val chained = maybeExecuteToolCall(sessionId, userText, finalResp, toolContext, toolIterationsLeft, traceId, onCompleted)
    if (!chained) onCompleted?.invoke(finalResp, null)
}
```
Subtlety the planner must handle: `maybeExecuteToolCall` calls back into `sendMessage(...)` (`:2107`), which calls `supervisor.sendChat(...)` — that re-entrant send must still kick off correctly from the EDT (it submits to a backend executor internally, so it will not block the EDT). Verify the `onCompleted` invocation semantics are preserved (it is currently invoked off-EDT; moving it onto the EDT is consistent with the other `onCompleted` call at `:634` which is already inside the off-EDT path — choose ONE thread for `onCompleted` and document it).

### Pattern 3: Shared HTTP-outcome → breaker helper (REL-03)
**What:** One function that decides whether an HTTP status is breaker-worthy and records it, so all 4 backends behave identically.
**Example:**
```kotlin
// HttpBackendSupport.kt
/** 429 and 5xx are transient/overload signals the breaker should count (mirrors retry intent). */
fun isRetryableHttpStatus(statusCode: Int): Boolean = statusCode == 429 || statusCode in 500..599

/** Call on every non-successful HTTP response BEFORE onComplete, so the breaker sees overload. */
fun CircuitBreaker.recordHttpFailureIfRetryable(statusCode: Int) {
    if (isRetryableHttpStatus(statusCode)) recordFailure()
}
```
```kotlin
// each backend, at the `if (!resp.isSuccessful)` site (OpenAiCompatible:243, Anthropic:197, Ollama:294, LmStudio:193):
if (!resp.isSuccessful) {
    errorLog("HTTP ${resp.statusCode}: ${resp.body.take(500)}")
    circuitBreaker.recordHttpFailureIfRetryable(resp.statusCode)   // <-- the one new line
    onComplete(IllegalStateException(message))
    return@submit
}
```
Design note: leave the existing per-status user-message construction (429 hint, 4xx hints) exactly as-is — only ADD the breaker call. A 4xx like 400/401/403 is a config error, NOT transient, so it correctly does NOT trip the breaker (the helper only counts 429/5xx). This matches the existing connection-error retry intent (`isRetryableConnectionError`).

### Pattern 4: LRU-bounded inner host map (REL-02/SC5)
**What:** Replace the inner `ConcurrentHashMap<host,anon>` per salt with a synchronized access-ordered `LinkedHashMap` that evicts the eldest beyond a cap.
**Example:**
```kotlin
// Redaction.kt — a small bounded map keyed by salt; the OUTER map stays ConcurrentHashMap<salt, BoundedMap>.
private fun <K, V> boundedLru(maxEntries: Int): MutableMap<K, V> =
    java.util.Collections.synchronizedMap(
        object : LinkedHashMap<K, V>(16, 0.75f, /* accessOrder = */ true) {
            override fun removeEldestEntry(eldest: Map.Entry<K, V>): Boolean = size > maxEntries
        },
    )
```
Subtlety: `hostForwardMap[salt][host]=anon` and `hostReverseMap[salt][anon]=host` are two maps that must stay consistent. If forward evicts `host→anon` but reverse still holds `anon→host`, `deAnonymizeHost` could resolve a host whose forward mapping was evicted — benign (reverse is the lookup path) but document it. Simpler: cap both maps at the same size with the same policy; eviction skew across the two is acceptable because re-anonymizing the same host is deterministic (HKDF is pure) and re-populates the forward map. Keep `computeIfAbsent(salt) { boundedLru(CAP) }` on the OUTER map so per-salt maps are created lazily. Recommended cap: a few thousand (e.g. 4096) per CONTEXT discretion — large enough that a normal session never evicts, small enough to bound memory.

### Anti-Patterns to Avoid
- **Converting the 4 maps to `ConcurrentHashMap`:** CONTEXT forbids it; it would not fix the off-EDT `panel.addMessage` Swing mutation and would hide (not fix) read-modify-write races.
- **Adding jsr305/JCIP for one annotation:** violates zero-new-deps; use a local annotation.
- **Throwing from the EDT assertion in production:** use `assert(...)` (enabled under `-ea` in tests) so prod behavior is unchanged; a hard `IllegalStateException` could crash the UI on an edge case the tests didn't cover.
- **Recording 4xx (400/401/403) as breaker failures:** those are non-transient config errors; tripping the breaker on them would wrongly fail-fast a fixable auth/model mistake. Only 429/5xx.
- **`deleteOnExit()` in a long-lived loop without `finally`:** `deleteOnExit` accumulates in a JVM-global list; here it is fine because temp files are per-send and also deleted in `finally`, so the registered hook almost always no-ops. Keep BOTH (finally is the primary; deleteOnExit is the crash-safety net), exactly as CONTEXT specifies.

## Don't Hand-Roll

| Problem | Don't Build | Use Instead | Why |
|---------|-------------|-------------|-----|
| Circuit-breaker state machine | A new breaker | Existing `CircuitBreaker` (`nowProvider`-injectable) | Already tested (`CircuitBreakerTest`), thread-safe, with the exact CLOSED/OPEN/HALF_OPEN semantics needed. |
| HTTP timeout plumbing | Per-backend OkHttp clients | `MontoyaHttpTransport.post(..., timeoutMs)` | Issue #69 trap — a private client bypasses Burp's proxy/cert store. Transport is the single timeout point. |
| `@GuardedBy` annotation semantics | A reflective lock-checker | A SOURCE-retained doc annotation + `assert(isEventDispatchThread())` | Runtime lock verification is overkill; the contract is documentation + a test-time EDT assertion. |
| LRU eviction | A custom ring buffer / manual size tracking | `LinkedHashMap(accessOrder=true).removeEldestEntry` | JDK-built-in, correct, one override method. |
| Bounded executor shutdown | Busy-wait / `Thread.sleep` loops | `ExecutorService.awaitTermination(timeout)` then `shutdownNow()` | The pattern is already in `shutdown()` (`:245–252`); reuse it for `stop()`. |
| Process timeout | A watchdog thread | `Process.waitFor(timeout, unit)` (already used at `:225`) | The existing call is correct; only the VALUE (hardcoded 120) and the ERROR MESSAGE need changing. |

**Key insight:** Every primitive this phase needs already exists in the codebase and is tested. The work is **wiring discipline** (call the breaker on HTTP failures, confine map access to the EDT, bound two already-existing shutdown/cache paths) plus one config knob — not building new machinery.

## Runtime State Inventory

This is a code-correctness phase, not a rename/migration. Still, two "runtime state" questions are relevant:

| Category | Items Found | Action Required |
|----------|-------------|------------------|
| Stored data | **None.** No datastore keys/IDs change. The host-anonymization maps are in-memory only (rebuilt each session; HKDF is deterministic so eviction is safe). | None — verified by reading `Redaction.kt` (maps are `private val`, never persisted). |
| Live service config | **None.** MCP shutdown-bound change is behavioral, not a config/registration change. No external service stores Phase-17 state. | None. |
| OS-registered state | **CLI temp files** in the system temp dir (`createTempFile` → `$TMPDIR`). Today they are deleted in `finally`; on a hard crash they leak. `deleteOnExit()` registers a JVM shutdown hook to clean them. | Add `deleteOnExit()` at `CliBackend.kt:109` and `:121`. Pre-existing leaked temp files from prior crashes are out of scope (named `burp-ai-agent-codex*` / `burp_uv_prompt_*`). |
| Secrets/env vars | **None.** No secret keys or env var names change. The new `cliTimeoutSeconds` is a plain integer pref (not a secret) — persist via `prefs.getInteger`, NOT `SecretCipher` (matches the `customRedactionPatterns` plaintext-config precedent in STATE.md). | Add a new prefs key (e.g. `cli.timeoutSeconds`); plaintext is correct. |
| Build artifacts | **None.** No `pyproject`/package rename; the local `@GuardedBy` annotation is SOURCE-retained, so it does not even enter the compiled output. | None. |

**Canonical question — after every file is updated, what runtime state still holds an old value?** Only stale CLI temp files from *past* crashes (cosmetic, in `$TMPDIR`); the new `deleteOnExit()` prevents *future* leaks. No persisted config, secret, or datastore key is affected.

## Common Pitfalls

### Pitfall 1: Moving `onComplete` body onto the EDT changes callback thread for `onCompleted`
**What goes wrong:** REL-01 routes `maybeExecuteToolCall` (and its map reads) onto the EDT via `invokeLater`. But `maybeExecuteToolCall` and the `else` branch both invoke the caller's `onCompleted` callback. Today `onCompleted` is invoked off-EDT; after the fix it may run on the EDT. Callers that block or do heavy work in `onCompleted` would now stall the UI.
**Why it happens:** `onCompleted` is a chained continuation used by tool-followup recursion (`:2113`) and by external callers of `sendMessage`.
**How to avoid:** Audit all `onCompleted` call sites (`:281`, `:298`, `:310`, `:345`, `:467`, `:634`, `:655`, `:661`, `:2113`). Decide ONE thread for `onCompleted` and document it. Safest: keep `onCompleted` invocation off-EDT (it does no UI work itself — the recursion re-enters `sendMessage` which marshals its own UI), and ONLY move the map reads + `panel.addMessage` onto the EDT. This narrows the change surface.
**Warning signs:** UI freeze during multi-step tool chains; `assert` firing in `maybeExecuteToolCall`.

### Pitfall 2: `assert` is a no-op in production (so the EDT contract isn't enforced at runtime)
**What goes wrong:** `assert(...)` only runs with `-ea`. Gradle test runs typically enable it (verify in `build.gradle.kts` test task), but the shipped JAR runs in Burp's JVM without `-ea`, so a future off-EDT regression would not throw.
**Why it happens:** Kotlin `assert` compiles to a guarded check controlled by JVM assertion status.
**How to avoid:** The CONCURRENCY TEST (not the assert) is the real guarantee. Make the test hammer the maps from multiple threads while EDT mutates, and assert no `ConcurrentModificationException` / consistent final state. The assert is a developer aid; the test is the gate. Confirm the test task enables assertions (`jvmArgs("-ea")`) so the assert fires in CI.
**Warning signs:** Test passes even when a map is touched off-EDT → assertions not enabled in the test task.

### Pitfall 3: REL-01 concurrency test that hammers `ChatPanel` directly will explode in AWT
**What goes wrong:** `ChatPanel`'s constructor builds real Swing components and references `UiTheme`; instantiating it from many threads in a headless CI is fragile.
**Why it happens:** `ChatPanel` is a heavy UI object; the maps are `private`.
**How to avoid:** Two viable test strategies — (a) extract the map-bearing logic into a small testable holder (overkill for this phase), or (b) follow the existing `ChatPanelConcurrencyTest` precedent which tests the *concurrency primitive* (`InFlightConnectionTracker`) in isolation, and add a focused test that exercises the specific race via a minimal harness. Given CONTEXT keeps the maps as plain `linkedMapOf` confined to the EDT, the most faithful test: run map mutations on a single dedicated "EDT" thread (a single-thread executor standing in for the EDT) while other threads attempt reads, and assert the reads are always routed through that same thread (no direct concurrent access). Run AWT tests headless (`-Djava.awt.headless=true` is already implied by CI; `Toolkit` is not needed if you avoid realizing components).
**Warning signs:** `HeadlessException`, `NullPointerException` from `UiTheme` during test construction.

### Pitfall 4: 429/5xx breaker-tripping makes the retry loop double-count
**What goes wrong:** The HTTP-failure path (`!resp.isSuccessful`) currently `return@submit`s immediately — it does NOT loop/retry. If you both (a) add `recordFailure` AND (b) start retrying on 429/5xx, a single overloaded server could trip the breaker much faster than intended (1 failure per request still, but now also the retry attempts count).
**Why it happens:** The existing retry loop only retries on *connection exceptions*, not HTTP status. The minimal REL-03 fix records the failure but keeps the current "no retry on HTTP status, fail fast to caller" behavior.
**How to avoid:** Do the MINIMAL change: add `recordFailure()` before `onComplete` on 429/5xx, but keep `return@submit` (do NOT add HTTP-status retries). This satisfies "the breaker sees overload" without changing retry semantics. If retry-on-429 is desired, that is a larger behavioral change — flag it for the planner, but CONTEXT only requires routing through `recordFailure`.
**Warning signs:** Breaker opens after 1–2 requests in a 429 test where the threshold is 5.

### Pitfall 5: LRU eviction breaks `clearMappings(salt)` semantics or the round-trip
**What goes wrong:** If the bounded map is built with the wrong key or the outer `computeIfAbsent` is removed, salt rotation (`clearMappings`) or de-anonymization could break.
**Why it happens:** Two nested maps + two directions (forward/reverse) must stay coherent.
**How to avoid:** Keep the OUTER `ConcurrentHashMap<salt, BoundedMap>` and its `computeIfAbsent(salt){...}` / `remove(salt)` exactly as-is; only swap the INNER `ConcurrentHashMap()` for the bounded LRU. Keep `clearMappings` untouched. Existing `RedactionTest` round-trip + privacy-mode tests must stay green (they assert `anonymizeHost` → `deAnonymizeHost` round-trips and the `host-<12hex>.local` format).
**Warning signs:** `RedactionTest` round-trip failures; mismatched forward/reverse counts.

### Pitfall 6: `Defaults.CLI_PROCESS_TIMEOUT_SECONDS` is shared with HTTP-backend defaults
**What goes wrong:** That constant is also the default for `ollama`/`lmstudio`/`openai`/`perplexity`/`nvidia` timeouts (`AgentSettings.kt:943–961`) and a fallback in `AgentSupervisor.kt:718`. Renaming or repurposing it would silently change HTTP defaults.
**Why it happens:** Historical reuse of one "120s" constant for both CLI and HTTP defaults.
**How to avoid:** For REL-04, ADD a new dedicated `cliTimeoutSeconds` (settings + a new `Defaults` const if you want a distinct default), and have the CLI `waitFor` read the user-configured value. Do NOT mutate `CLI_PROCESS_TIMEOUT_SECONDS` in place (it would change HTTP defaults). The two CLI `waitFor` sites are `:225` (standard) and the opencode wall-clock at `:222`; the embedded `CliConnection` loop also reads it at `:736`.
**Warning signs:** HTTP backend timeout tests change behavior after a "CLI-only" edit.

## Code Examples

### REL-03 test — 429/5xx trips the breaker (spy the transport)
```kotlin
// Pattern from HttpBackendTransportRoutingTest.stubTransportPost() + CircuitBreakerTest determinism.
// Source: src/test/kotlin/.../http/HttpBackendTransportRoutingTest.kt (spy) + CircuitBreakerTest.kt
@Test
fun `429 response records a circuit-breaker failure`() {
    val api = mock<MontoyaApi>(defaultAnswer = Mockito.RETURNS_DEEP_STUBS)
    val transport = spy(MontoyaHttpTransport(api))
    doReturn(TransportResponse(statusCode = 429, body = "rate limited", isSuccessful = false))
        .whenever(transport).post(any(), any(), any(), any())

    val backend = OpenAiCompatibleBackend(id = "openai-compatible", displayName = "OpenAI-compatible")
    val conn = backend.launch(
        BackendLaunchConfig(
            backendId = "openai-compatible", displayName = "OpenAI-compatible",
            baseUrl = "https://example.test/v1", model = "gpt-4o",
            headers = emptyMap(), requestTimeoutSeconds = 30L, transport = transport,
        ),
    )
    // Drive enough sends to cross the breaker threshold (5) and assert the breaker opened:
    // either expose breaker state for the test, or assert the Nth send fails fast with the
    // "circuit open" message from HttpBackendSupport.openCircuitError(...).
    val errors = (1..6).map { sendAndAwait(conn) }   // helper using CountDownLatch like the existing test
    assertTrue(errors.any { it?.message?.contains("circuit open") == true },
        "expected the breaker to open after repeated 429s")
}
```
Planner note: the breaker is `private` to the connection. To assert state cleanly, either (a) test via observable behavior (the Nth send returns `openCircuitError` "temporarily unavailable (circuit open)"), or (b) add a tiny test seam. Prefer (a) — it tests the user-visible contract.

### REL-04 test — CLI timeout produces an actionable message (real short hanging process)
```kotlin
// A genuinely-slow process via the shell; set the configurable timeout very low for the test.
// Use /bin/sh 'sleep 5' on *nix; guard with Assumptions for Windows/CI without a shell.
@Test
fun `CLI timeout yields actionable message naming the timeout`() {
    org.junit.jupiter.api.Assumptions.assumeTrue(File("/bin/sh").exists())
    // Construct a CliConnection-equivalent with cliTimeoutSeconds = 1 and command ["/bin/sh","-c","sleep 5"].
    // Assert onComplete fires with a message that (a) says it timed out, (b) names the configured
    // limit, (c) suggests increasing the timeout / pre-installing the CLI.
    val err = runCliAndAwait(command = listOf("/bin/sh", "-c", "sleep 5"), timeoutSeconds = 1)
    assertNotNull(err)
    assertTrue(err!!.message!!.contains("timed out"))
    assertTrue(err.message!!.contains("1"))                       // the configured limit surfaced
    assertTrue(err.message!!.contains("increase", ignoreCase = true) ||
               err.message!!.contains("pre-install", ignoreCase = true))
}
```
Alternative (no shell dependency): extract the timeout-message builder into an `internal fun buildTimeoutMessage(tail: String, timeoutSeconds: Int): String` (mirrors how `buildCopilotCommand` was extracted for testability) and unit-test the string directly — faster and OS-independent. Recommended primary test = the extracted-builder unit test; the real-process test is an optional integration check.

### REL-02 test — temp file deleted even when write throws
```kotlin
// Force the post-create write to fail and assert the temp file does not survive.
// The simplest seam: verify deleteOnExit is registered AND finally deletes. A behavioral test:
// inject a prompt large enough to take the temp-file branch (combinedText.length > LARGE_PROMPT_THRESHOLD),
// stub the process start to throw, and assert no leftover burp_uv_prompt_* file remains in $TMPDIR.
@Test
fun `uv prompt temp file is cleaned up on failure`() {
    val before = tempFilesMatching("burp_uv_prompt_")
    // ... run a claude-cli/copilot-cli send with a >32k prompt and a command that fails fast ...
    val after = tempFilesMatching("burp_uv_prompt_")
    assertEquals(before, after, "temp prompt file leaked after failure")
}
```

### REL-02/SC5 test — bounded MCP stop() never hangs
```kotlin
// Pattern from McpSupervisorRestartPolicyTest / McpServerIntegrationTest (already in the suite).
@Test
fun `stop completes within the bound even if the server is slow`() {
    // Start a manager, then call stop(callback) and assert the callback reaches Stopped/Failed
    // within (bound + margin) using a CountDownLatch; assert it does NOT block indefinitely.
}
```

## State of the Art

This is internal hardening; no external "state of the art" shift applies. The only currency note:

| Old Approach | Current Approach | When Changed | Impact |
|--------------|------------------|--------------|--------|
| JCIP `@GuardedBy` (`net.jcip:jcip-annotations`, 2013) | Local SOURCE-retained annotation; or Kotlin-native confinement | — | JCIP is unmaintained and not on this classpath. A local annotation avoids a dead dependency. Error Prone's `@GuardedBy` exists but also requires a dep — not warranted for 4 fields. |

**Deprecated/outdated:** Nothing in scope is deprecated. `Process.waitFor(timeout, unit)`, `LinkedHashMap.removeEldestEntry`, `ExecutorService.awaitTermination`, and `SwingUtilities.invokeLater` are all current, stable JDK APIs on JVM 21.

## Assumptions Log

| # | Claim | Section | Risk if Wrong |
|---|-------|---------|---------------|
| A1 | Recording 429/5xx on the breaker should KEEP the current fail-fast (no HTTP-status retry) behavior; only add `recordFailure` | Pitfall 4 / Pattern 3 | If the maintainer wants retry-on-429, that's a larger behavioral change. CONTEXT only requires routing through `recordFailure`, so the minimal change is the safe reading — but confirm at plan-phase. |
| A2 | The off-EDT race surface is limited to `maybeExecuteToolCall` (the only map access inside `onComplete`) plus its `panel.addMessage`; all other map sites are already EDT-reached (action listeners, init, persist) | REL-01 analysis | If another off-EDT entry exists (e.g. a timer or persist-on-shutdown thread), it would be an additional confinement site. The grep at `ChatPanel.kt` shows the persist/restore (`:1287–1427`) run via UI actions, and timers stop via `stopAllTimers` — but the planner should re-verify no background thread calls into the maps. |
| A3 | A SOURCE-retained `@GuardedBy` is acceptable to the maintainer (vs. RUNTIME for tooling) | Pattern 1 | If a future static-analysis tool (Phase 18 detekt) wants to read the annotation, it may need CLASS/RUNTIME retention. Trivial to change; SOURCE is the zero-footprint default. |
| A4 | Host-map LRU cap of ~4096 per salt is acceptable (CONTEXT says "a few thousand, Claude's discretion") | Pattern 4 | If real sessions touch >4096 distinct hosts, eviction churn could re-anonymize repeatedly (cheap, deterministic — benign). Confirm the cap at plan-phase. |
| A5 | Issue #71 root cause is the 120s hardcoded CLI timeout being exceeded by `npx @google/gemini-cli` first-run download (not a different gemini-cli bug) | REL-04 analysis | The issue body had empty actual/expected fields, so this is inferred from the reproduction command + the code. SC4 permits an actionable error even if the exact root cause differs, so the fix (configurable timeout + actionable message) is robust to this assumption being partially wrong. |
| A6 | The new `cliTimeoutSeconds` is plain-text config (prefs `getInteger`), not a secret | Runtime State Inventory | Matches the `customRedactionPatterns` precedent (config ≠ secret). No risk; it's a timeout integer. |

## Open Questions

1. **Should `onCompleted` run on the EDT or off it after the REL-01 fix?**
   - What we know: today it runs off-EDT; the fix moves the map reads onto the EDT.
   - What's unclear: whether moving `onCompleted` too would stall the UI for chained tool calls.
   - Recommendation: keep `onCompleted` off-EDT; marshal ONLY the map reads + `panel.addMessage` onto the EDT (narrowest change). Decide explicitly in the plan and add a comment.

2. **429 retry vs. fail-fast.**
   - What we know: CONTEXT requires `recordFailure` on 429/5xx; the current code fails fast (no HTTP retry).
   - What's unclear: whether the maintainer also wants retry-with-backoff on 429.
   - Recommendation: minimal change (record + keep fail-fast). Flag retry-on-429 as a possible follow-up; do not expand scope.

3. **Breaker observability for tests.**
   - What we know: the breaker is `private` to each connection.
   - What's unclear: whether to add a test seam or assert purely behaviorally.
   - Recommendation: assert behaviorally (the "circuit open" message after N failures). Avoid widening visibility.

## Environment Availability

| Dependency | Required By | Available | Version | Fallback |
|------------|------------|-----------|---------|----------|
| JDK 21 (JVM) | Whole build | ✓ | per Gradle toolchain | — |
| `./gradlew test` | All SC validation | ✓ | Gradle wrapper present | — |
| JUnit Jupiter | Tests | ✓ | 6.0.3 | — |
| mockito-kotlin | REL-03 transport spy | ✓ | 5.4.0 | mockwebserver (also present) |
| mockwebserver | optional REL-03 round-trip | ✓ | 4.12.0 | spy (preferred) |
| `/bin/sh` (for the optional REL-04 real-process test) | REL-04 integration test only | ✓ on macOS/Linux | — | Extracted message-builder unit test (OS-independent, recommended primary) |
| `./gradlew ktlintCheck` | NOT used | ✗ (known defect) | — | `./gradlew test` (per MEMORY.md) |

**Missing dependencies with no fallback:** None.
**Missing dependencies with fallback:** `ktlintCheck` is broken standalone (pre-existing `generateBuildFlags` defect, addressed in Phase 18/QUAL-05) — use `./gradlew test`. The REL-04 real-process test depends on a shell; the extracted-builder unit test is the OS-independent fallback and is the recommended primary.

## Validation Architecture

> nyquist_validation is enabled (config.json `workflow.nyquist_validation: true`).

### Test Framework
| Property | Value |
|----------|-------|
| Framework | JUnit Jupiter 6.0.3 (+ mockito-kotlin 5.4.0, mockwebserver 4.12.0) |
| Config file | `build.gradle.kts` (`tasks.test { useJUnitPlatform() }`); verify `-ea` is enabled for assertions to fire |
| Quick run command | `./gradlew test --tests "com.six2dez.burp.aiagent.<TargetTest>"` |
| Full suite command | `./gradlew test` |

### Phase Requirements → Test Map
| SC | Behavior | Test Type | Automated Command | File Exists? |
|----|----------|-----------|-------------------|--------------|
| SC1 | No data race on the 4 session maps under concurrent EDT-mutation + off-EDT reads | concurrency unit | `./gradlew test --tests "com.six2dez.burp.aiagent.ui.ChatPanelConcurrencyTest"` | ✅ extend existing |
| SC2 | CLI temp files (`uv` prompt, codex output) deleted in `finally` AND on crash (`deleteOnExit`) | unit (forced-failure) | `./gradlew test --tests "com.six2dez.burp.aiagent.backends.cli.CliBackendTempFileTest"` | ❌ Wave 0 |
| SC3 | Each HTTP backend routes 429/5xx through `recordFailure` (breaker opens after threshold); uniform timeout via transport | unit (transport spy) | `./gradlew test --tests "com.six2dez.burp.aiagent.backends.http.HttpBackendCircuitFailureTest"` | ❌ Wave 0 |
| SC4 | #71 — slow/hanging CLI yields an actionable timeout message naming the configured limit | unit (extracted builder) + optional integration | `./gradlew test --tests "com.six2dez.burp.aiagent.backends.cli.CliTimeoutMessageTest"` | ❌ Wave 0 |
| SC5a | `McpServerManager.stop()` completes within the bound, never hangs | integration | `./gradlew test --tests "com.six2dez.burp.aiagent.mcp.McpShutdownBoundTest"` | ❌ Wave 0 |
| SC5b | Host-anonymization maps stay bounded under many distinct hosts; round-trip + format preserved | unit | `./gradlew test --tests "com.six2dez.burp.aiagent.redact.RedactionHostMapBoundTest"` | ❌ Wave 0 (RedactionTest exists for round-trip regression) |

### Sampling Rate
- **Per task commit:** the specific new test for that task (`--tests` filter above).
- **Per wave merge:** `./gradlew test` (full suite — ~83 existing test files must stay green; this phase touches shared code paths).
- **Phase gate:** Full `./gradlew test` green before `/gsd-verify-work`. Regression watch: `RedactionTest`, `CircuitBreakerTest`, `HttpBackendTransportRoutingTest`, `AnthropicModelErrorTest`, `McpServerIntegrationTest`, `McpSupervisorRestartPolicyTest` must remain green (these cover the exact files being modified).

### Wave 0 Gaps
- [ ] `src/main/kotlin/com/six2dez/burp/aiagent/util/GuardedBy.kt` — the local annotation (production, prerequisite for REL-01)
- [ ] `backends/cli/CliBackendTempFileTest.kt` — covers SC2 (temp-file finally + deleteOnExit on failure)
- [ ] `backends/http/HttpBackendCircuitFailureTest.kt` — covers SC3 (429/5xx → recordFailure for OpenAiCompatible[+NVIDIA/Perplexity], Anthropic, Ollama, LmStudio)
- [ ] `backends/cli/CliTimeoutMessageTest.kt` — covers SC4 (#71 actionable message; test the extracted `buildTimeoutMessage`)
- [ ] `mcp/McpShutdownBoundTest.kt` — covers SC5a (bounded stop())
- [ ] `redact/RedactionHostMapBoundTest.kt` — covers SC5b (LRU bound + round-trip preserved)
- [ ] Extend `ui/ChatPanelConcurrencyTest.kt` — covers SC1 (map confinement under concurrency)
- [ ] Verify `tasks.test` enables assertions (`jvmArgs("-ea")`) so the EDT `assert` fires in CI

*Manual UAT:* Issue #71 — a maintainer running `npx @google/gemini-cli` on a fresh machine should see the actionable message (and be able to raise the new timeout). This is a human smoke check; the automated regression is the extracted-message unit test.

## Security Domain

> `security_enforcement` is not set to `false` anywhere in config.json — treat as enabled. This is an internal reliability phase with no new attack surface, but two existing guarantees must be preserved.

### Applicable ASVS Categories

| ASVS Category | Applies | Standard Control |
|---------------|---------|-----------------|
| V2 Authentication | no | No auth code touched (MCP bearer-token path in `KtorMcpServerManager` is read but only the shutdown-bound changes, not auth). |
| V3 Session Management | no | `ChatPanel` "sessions" are UI chat tabs, not security sessions. |
| V4 Access Control | no | No scope/permission changes. |
| V5 Input Validation | partial | CLI timeout setting is an integer pref — coerce to a sane range (`coerceIn`) like existing timeouts (`AgentSettings` uses `coerceIn`); reject negative/zero. |
| V6 Cryptography | no (preserve) | Host anonymization uses HKDF (`Redaction`); the LRU change MUST NOT alter the crypto or the `host-<12hex>.local` output. No crypto is added/modified. |
| V7 Error Handling & Logging | yes | REL-04 actionable error + existing "shape-only" log discipline. New error/log text must NOT leak prompt content (existing precedent: bounded tails `take(2000)`, shape-only previews). |

### Known Threat Patterns for this stack

| Pattern | STRIDE | Standard Mitigation |
|---------|--------|---------------------|
| Sensitive prompt/response leaking into error text or logs (REL-04 message, REL-03 error message) | Information Disclosure | Keep the established bounded-tail / shape-only pattern; the new timeout message names the LIMIT and remediation, never the prompt. Reuse the existing `take(N)` truncation. |
| Temp-file residue containing prompt data after a crash (REL-02) | Information Disclosure | `deleteOnExit()` + existing owner-only POSIX perms (`CliBackend.kt:126–132`) + `finally` delete. The fix STRENGTHENS this guarantee. |
| Unbounded host-map growth as a memory-exhaustion vector over a long session (REL-02/SC5) | Denial of Service | LRU cap bounds memory; this is itself a hardening control. |
| MCP `stop()` hanging (REL-02/SC5) leaving a port bound / resources held | Denial of Service | Bounded `awaitTermination` + `shutdownNow` force-stop. |
| Breaker never tripping on 429/5xx → unbounded retry/load amplification against a struggling upstream (REL-03) | Denial of Service (amplification) | Routing 429/5xx through `recordFailure` lets the breaker fail-fast under overload — the core REL-03 control. |

## Sources

### Primary (HIGH confidence) — all read directly this session
- `src/main/kotlin/.../ui/ChatPanel.kt` — 4 maps (`:104–107`), off-EDT `onComplete` (`:570`), `maybeExecuteToolCall` map reads (`:2046–2118`), all 40+ map access sites enumerated via grep, existing `invokeLater` usage.
- `src/main/kotlin/.../backends/cli/CliBackend.kt` — temp-file creates (`:109`, `:121`), cleanup `finally` (`:274–288`), inline delete (`:138`), timeout `waitFor` (`:222`, `:225`, `:736`), timeout message (`:233–239`).
- `src/main/kotlin/.../backends/http/{MontoyaHttpTransport,CircuitBreaker,HttpBackendSupport}.kt` — transport timeout centralization, breaker API (`recordSuccess:74`, `recordFailure:83`, `nowProvider`), `newCircuitBreaker`/`openCircuitError`/`isRetryableConnectionError`.
- `src/main/kotlin/.../backends/{openai/OpenAiCompatibleBackend,anthropic/AnthropicBackend,ollama/OllamaBackend,lmstudio/LmStudioBackend,burpai/BurpAiBackend}.kt` — confirmed all 4 HTTP backends skip `recordFailure` on `!resp.isSuccessful` (OpenAi `:243`, Anthropic `:197`, Ollama `:294`, LmStudio `:193`); NVIDIA/Perplexity factories delegate to OpenAiCompatible; BurpAi uses native Burp AI (no HTTP).
- `src/main/kotlin/.../mcp/KtorMcpServerManager.kt` — `stop()` unbounded (`:230`), `shutdown()` bounded 10s (`:245–252`), `server.stop(1000,5000)`.
- `src/main/kotlin/.../redact/Redaction.kt` — nested `ConcurrentHashMap` host maps (`:145–146`), `anonymizeHost` HKDF + `computeIfAbsent` (`:274–295`), `deAnonymizeHost` (`:297`), `clearMappings` (`:302`).
- `src/main/kotlin/.../config/{Defaults,AgentSettings}.kt` — `CLI_PROCESS_TIMEOUT_SECONDS=120` (Defaults:41), per-backend HTTP timeout prefs (AgentSettings:38–61), shared-const reuse for HTTP defaults (`:943–961`).
- `src/main/kotlin/.../supervisor/AgentSupervisor.kt` — `sendChat` (`:415`) calls `connection.send` (`:509`) with no EDT marshalling → callbacks run on the backend executor thread.
- `src/test/kotlin/.../ui/ChatPanelConcurrencyTest.kt`, `.../http/{CircuitBreakerTest,HttpBackendTransportRoutingTest}.kt`, `.../mcp/McpRequestLimiterConcurrencyTest.kt`, `.../backends/cli/CopilotCommandBuilderTest.kt` — established test patterns (CountDownLatch, transport spy returning `TransportResponse`, `nowProvider`-injected breaker, extracted-`internal fun` testing).
- `build.gradle.kts` — test deps (JUnit 6.0.3, mockito-kotlin 5.4.0, mockwebserver 4.12.0), `-Xjsr305=strict` (`:105`).
- `./gradlew dependencies --configuration compileClasspath` — confirmed JCIP/jsr305 NOT on classpath; only `org.jetbrains:annotations:23.0.0`.

### Secondary (MEDIUM confidence)
- Issue #71 (provided in the task brief; GitHub issue body had empty actual/expected fields — root cause INFERRED from the reproduction command `npx @google/gemini-cli ...` + the hardcoded 120s timeout code path).

### Tertiary (LOW confidence)
- None. No WebSearch was needed — this is a closed-world internal-code phase.

## Metadata

**Confidence breakdown:**
- Standard stack (reuse existing components): HIGH — all components read directly; no external choices.
- Architecture (the four fix patterns): HIGH — each defect site located and quoted from source.
- REL-01 race identification: HIGH — the off-EDT callback → map-read chain is explicit in the code.
- REL-03 (all 4 backends share the gap): HIGH — read each backend's `!resp.isSuccessful` branch.
- REL-04 root cause: MEDIUM — issue body was empty; cause inferred from repro command + code (mitigated by SC4 allowing an actionable error regardless of exact cause).
- Pitfalls: HIGH — derived from reading the actual call graphs (onComplete/onCompleted threading, shared timeout constant, nested host maps).

**Research date:** 2026-06-11
**Valid until:** 2026-07-11 (stable — internal code; only invalidated if the named files are heavily refactored before planning, e.g. by an out-of-order Phase 19 mega-file split, which is currently deferred behind Phase 16).
