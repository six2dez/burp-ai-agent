---
phase: 17-reliability-concurrency-hardening
reviewed: 2026-06-11T00:00:00Z
depth: standard
files_reviewed: 16
files_reviewed_list:
  - src/main/kotlin/com/six2dez/burp/aiagent/backends/http/HttpBackendSupport.kt
  - src/main/kotlin/com/six2dez/burp/aiagent/backends/openai/OpenAiCompatibleBackend.kt
  - src/main/kotlin/com/six2dez/burp/aiagent/backends/anthropic/AnthropicBackend.kt
  - src/main/kotlin/com/six2dez/burp/aiagent/backends/ollama/OllamaBackend.kt
  - src/main/kotlin/com/six2dez/burp/aiagent/backends/lmstudio/LmStudioBackend.kt
  - src/main/kotlin/com/six2dez/burp/aiagent/ui/ChatPanel.kt
  - src/main/kotlin/com/six2dez/burp/aiagent/util/GuardedBy.kt
  - src/main/kotlin/com/six2dez/burp/aiagent/backends/cli/CliBackend.kt
  - src/main/kotlin/com/six2dez/burp/aiagent/config/AgentSettings.kt
  - src/main/kotlin/com/six2dez/burp/aiagent/backends/BackendTypes.kt
  - src/main/kotlin/com/six2dez/burp/aiagent/supervisor/AgentSupervisor.kt
  - src/main/kotlin/com/six2dez/burp/aiagent/mcp/KtorMcpServerManager.kt
  - src/main/kotlin/com/six2dez/burp/aiagent/redact/Redaction.kt
  - src/test/kotlin/com/six2dez/burp/aiagent/mcp/McpShutdownBoundTest.kt
  - src/test/kotlin/com/six2dez/burp/aiagent/redact/RedactionHostMapBoundTest.kt
  - src/test/kotlin/com/six2dez/burp/aiagent/ui/ChatPanelConcurrencyTest.kt
findings:
  critical: 0
  warning: 6
  info: 5
  total: 11
status: issues_found
---

# Phase 17: Code Review Report

**Reviewed:** 2026-06-11T00:00:00Z
**Depth:** standard
**Files Reviewed:** 16
**Status:** issues_found

## Summary

Reviewed the Phase 17 reliability/concurrency hardening across REL-01 (EDT confinement),
REL-02 (bounded MCP stop + LRU host maps), REL-03 (HTTP circuit-breaker failure recording),
and REL-04 (configurable CLI timeout).

The four headline reliability goals are largely met and the new tests genuinely exercise the
contracts they claim:

- **REL-03 verified correct.** `isRetryableHttpStatus` classifies `429 || 500..599`; `recordHttpFailureIfRetryable`
  is wired into the `!resp.isSuccessful` branch of all four HTTP backends (OpenAI `:263`, Anthropic
  `:212`, Ollama `:297`, LM Studio `:196`) and `recordSuccess()` is on the success path in each. No
  double-record on the success path (a 4xx that returns early never reaches `recordSuccess`).
- **REL-02 SC5a verified correct.** `stop()` uses `future.get(10s)` only and never terminates the
  shared executor; the terminal `shutdown()` is the only place that calls `awaitTermination`+`shutdownNow`.
  `McpShutdownBoundTest.stopDoesNotTerminateExecutorAllowingRestart` proves stop→start→stop with no
  `RejectedExecutionException`.
- **REL-02 SC5b verified correct.** Inner host maps are bounded synchronized access-ordered
  `LinkedHashMap` with `removeEldestEntry`; HKDF is pure so re-anonymizing an evicted host is
  deterministic; `clearMappings`/de-anonymize round-trip preserved.
- **REL-04 verified mostly correct.** `cliTimeoutSeconds` is a defaulted settings field, `coerceIn(30,3600)`,
  `Defaults.CLI_PROCESS_TIMEOUT_SECONDS` is NOT mutated, and `buildTimeoutMessage` bounds the tail and
  leaks no prompt content.

No BLOCKER-class defects (no injection, no secret leak, no data-loss). However, the **REL-01 EDT-confinement
claim is materially incomplete**: the maps were annotated `@GuardedBy("EDT")` and one off-EDT call site
was fixed, but several other off-EDT access paths to the same maps remain (WR-01). There are also a
REL-04 validation-floor mismatch with the documented default (WR-02), a double-counted circuit-breaker
failure on HTTP-error retries (WR-03), and a couple of robustness gaps. Details below.

Build/test posture per project rules: `./gradlew test` is the gate; `ktlintCheck` is known-broken
(generateBuildFlags) and not flagged.

## Warnings

### WR-01: REL-01 — `@GuardedBy("EDT")` maps are still mutated off-EDT via `shutdown()` → `cancelInFlightRequest()`

**File:** `src/main/kotlin/com/six2dez/burp/aiagent/ui/ChatPanel.kt:857-868`, `:1293-1296`
**Issue:** The phase annotated `sessionPanels` / `sessionStates` / `sessionsById` / `sessionDrafts`
with `@GuardedBy("EDT")` and fixed the `onComplete`→`maybeExecuteToolCall` path with `invokeLater`.
But `cancelInFlightRequest()` reads `sessionsList.selectedValue` and `sessionPanels[sessionId]` and
calls `panel.addMessage(...)` (Swing mutation) **on the calling thread**, and it is invoked from
`shutdown()` (`:1294`). `shutdown()` is wired to Burp's unloading handler
(`BurpAiAgentExtension.kt:12` → `App.shutdown()`), which runs on a Montoya/Burp thread, **not the EDT**.
So extension-unload touches the `@GuardedBy("EDT")` maps and mutates Swing off-EDT — exactly the race
class REL-01 set out to close. `maybeExecuteToolCall` got an `assertEdt()` guard; `cancelInFlightRequest`
did not, so the contract is asserted in one place and silently violated in another.
(Note: `clearInMemorySessionState()` at `:1302` is reached from `onProjectChanged`, which fires from a
`javax.swing.Timer` and IS on the EDT, so that path is fine — the gap is specifically the unload path.)
**Fix:** Make the shutdown path marshal onto the EDT (or make `cancelInFlightRequest` safe to call from
any thread). Minimal change:
```kotlin
fun shutdown() {
    if (SwingUtilities.isEventDispatchThread()) {
        cancelInFlightRequest()
        sessionPanels.values.forEach { it.stopAllTimers() }
    } else {
        SwingUtilities.invokeAndWait {
            cancelInFlightRequest()
            sessionPanels.values.forEach { it.stopAllTimers() }
        }
    }
}
```
Add `assertEdt()` to `cancelInFlightRequest()` too, so the confinement contract is enforced uniformly
rather than only on the tool-call path.

### WR-02: REL-04 — validation floor (30s) silently overrides the documented `coerceIn` and is reachable from `launch()`

**File:** `src/main/kotlin/com/six2dez/burp/aiagent/config/AgentSettings.kt:296-298`, `:570`; `src/main/kotlin/com/six2dez/burp/aiagent/backends/cli/CliBackend.kt:33`
**Issue:** The field doc (`AgentSettings.kt:62-64`) and `BackendTypes.kt:20-21` describe
`cliTimeoutSeconds` as "use the user-configured timeout … null means use Defaults
(=120)". Validation on both load (`:297`) and save (`:570`) is `coerceIn(30, 3600)`. That floor of
**30s is undocumented** at the field and is a behavior change: a user who sets, say, 10s gets silently
clamped to 30s with no feedback. More importantly, `CliBackend.launch` (`:33`) reads
`config.cliTimeoutSeconds ?: Defaults.CLI_PROCESS_TIMEOUT_SECONDS` and passes it straight into the
`NonInteractiveCliConnection` watchdog **without re-coercing**. The repository clamps on the
persistence boundary, but `BackendLaunchConfig.cliTimeoutSeconds` is a plain nullable `Int` with no
invariant — any caller constructing a config directly (tests, future call sites) can inject `0` or a
negative value, producing `process.waitFor(0, SECONDS)` (immediate timeout) or
`cliTimeoutSeconds * 1000L` overflow/zero on the opencode wall-clock break (`CliBackend.kt:233`).
**Fix:** (a) Document the 30s floor in the field KDoc and ideally surface a UI note. (b) Defensively
coerce at the consumption boundary so the connection never trusts an unvalidated value:
```kotlin
val timeoutSeconds = (config.cliTimeoutSeconds ?: Defaults.CLI_PROCESS_TIMEOUT_SECONDS).coerceIn(30, 3600)
```

### WR-03: REL-03 — HTTP-error retries double-count circuit-breaker failures across the retry loop

**File:** `src/main/kotlin/com/six2dez/burp/aiagent/backends/ollama/OllamaBackend.kt:295-299`; `src/main/kotlin/com/six2dez/burp/aiagent/backends/lmstudio/LmStudioBackend.kt:194-198`; (same shape, lower risk, in OpenAI `:263-265` / Anthropic `:212-214`)
**Issue:** On a non-successful HTTP response the code calls `recordHttpFailureIfRetryable(statusCode)`
and then `onComplete(...)` + `return@submit`. For OpenAI/Anthropic this terminates the attempt loop,
so a 5xx records exactly one failure — fine. But the breaker's purpose is to trip after
`CIRCUIT_FAILURE_THRESHOLD = 5` failures, and the **connection-exception** path *also* records a
failure (`recordFailure()` at OpenAI `:295`, etc.) and then retries up to 6 times. A backend that
throws a retryable `SocketTimeoutException` on every attempt records **6 failures from a single
`send()`**, immediately tripping the breaker (threshold 5) even though the user made one request. That
is arguably intended ("6 strikes = open"), but it is inconsistent with the HTTP-status path which
records **1** failure for a single failed `send()` and never retries the 5xx. The net effect: transient
TCP flakiness trips the breaker ~6x faster than transient 5xx overload, which is backwards (5xx is the
stronger "upstream is overloaded" signal). Worth an explicit decision + comment, since the asymmetry is
silent and surprising.
**Fix:** Either record at most one breaker failure per `send()` regardless of retry count, or document
the intended asymmetry. A simple bound:
```kotlin
// record at most once per send() so a 6-retry storm == one breaker failure
if (retryable && !recordedFailure) { circuitBreaker.recordFailure(); recordedFailure = true }
```

### WR-04: Ollama/LM Studio HTTP-error path echoes the **full** response body into the exception message

**File:** `src/main/kotlin/com/six2dez/burp/aiagent/backends/ollama/OllamaBackend.kt:298`; `src/main/kotlin/com/six2dez/burp/aiagent/backends/lmstudio/LmStudioBackend.kt:197`
**Issue:** The error log is correctly bounded (`resp.body.take(500)`), but the exception surfaced to
the UI uses the **unbounded** body:
`onComplete(IllegalStateException("Ollama HTTP ${resp.statusCode}: ${resp.body}"))`. OpenAI and
Anthropic learned this lesson — their error messages use `resp.body.take(800)` (`OpenAi…:255`,
`Anthropic…:206`). Ollama/LM Studio did not. A large or hostile error body (these are local servers,
but a misconfigured reverse-proxy or a model that echoes the prompt in its error envelope) flows
verbatim into an `[Error] …` chat bubble and into `session.messages` (persisted). This is a robustness
/ consistency gap and a mild information-surface issue (the error body can contain echoed prompt
fragments), inconsistent with the privacy-bounding discipline applied elsewhere in this very phase.
**Fix:** Bound the body in the message the same way the other two backends do:
```kotlin
onComplete(IllegalStateException("Ollama HTTP ${resp.statusCode}: ${resp.body.take(800)}"))
```

### WR-05: `ConversationHistory` mixes `ConcurrentLinkedDeque` with a separate lock — `snapshot()`/`trim()` can observe an inconsistent `runningTotalChars`

**File:** `src/main/kotlin/com/six2dez/burp/aiagent/backends/http/HttpBackendSupport.kt:179-249`
**Issue:** `history` is a `ConcurrentLinkedDeque` but every mutation is *also* wrapped in
`synchronized(lock)`, and `runningTotalChars` (a plain `var`) is only safe under that lock. The deque's
own thread-safety is therefore redundant and, worse, misleading: it implies concurrent access is fine,
but `runningTotalChars` is not atomic with the deque ops. Within a single connection the executor is
single-threaded so this never actually races in production — but the data structure choice advertises a
concurrency guarantee the class does not honor, and any future caller that touches the deque outside
`lock` (it's `private`, so low risk today) would corrupt the char accounting. This is a maintainability
landmine, not a live bug.
**Fix:** Use a plain `ArrayDeque` under the existing `lock` (the deque's concurrency is unused), or drop
the lock and make the counter derivation lock-free. Pick one model; don't layer two.

### WR-06: `evictStaleClients()` runs on every `sharedClient()` call and can shut down a client mid-use under concurrency

**File:** `src/main/kotlin/com/six2dez/burp/aiagent/backends/http/HttpBackendSupport.kt:53-97`
**Issue:** `sharedClient()` calls `evictStaleClients()` opportunistically on every invocation. Eviction
iterates `sharedClients.entries` and, for any entry idle > 10min, calls
`entry.client.dispatcher.executorService.shutdown()` + `connectionPool.evictAll()`. The `lastUsedAt`
field is `@Volatile var` but the check-then-shutdown is not atomic: thread A can read entry X as stale
(last used 10min+1ms ago) while thread B simultaneously calls `computeIfAbsent` for the same key,
gets the cached entry, refreshes `lastUsedAt`, and begins a request — then A shuts down the dispatcher
out from under B. The window is narrow and only affects clients that were idle for 10 minutes (so
practically rare), but the result is a hard-to-reproduce `RejectedExecutionException` on an in-flight
request. The Ollama/LM Studio non-transport (test) paths use this shared client.
**Fix:** Remove the entry from the map atomically *before* shutting it down, and skip shutdown if it was
just refreshed — or simply don't shut down the dispatcher on opportunistic eviction (let GC + idle
connection eviction reclaim it). At minimum, guard with `sharedClients.remove(key, entry)` (the
two-arg form) and only shut down on a successful removal.

## Info

### IN-01: `GuardedBy` is documentation-only and unverifiable for non-EDT locks

**File:** `src/main/kotlin/com/six2dez/burp/aiagent/util/GuardedBy.kt:10-12`
**Issue:** `@Retention(SOURCE)` is the right call for zero-footprint, and the annotation is correct for
its stated purpose. But because it is source-only and `lock = "EDT"` is a magic string with no compiler
or runtime check, it provides no enforcement — the only thing standing between the annotation and a
violation is the hand-placed `assertEdt()` calls, which (per WR-01) are not on every access path. Worth
a one-line note in the KDoc that the annotation is advisory and that `assertEdt()` must accompany every
mutation site to make it real.
**Fix:** Add to the KDoc: "Advisory only — pair every access with `assertEdt()` (EDT) or the
corresponding `synchronized` block; this annotation performs no runtime check."

### IN-02: REL-04 timeout message bound (`take(2000)`) is duplicated as a magic number at the two call sites

**File:** `src/main/kotlin/com/six2dez/burp/aiagent/backends/cli/CliBackend.kt:244`, `:255`, `:762`
**Issue:** The "bound the tail to 2000 chars" discipline that `buildTimeoutMessage`'s KDoc relies on is
enforced by callers via a bare `take(2000)` repeated in three places. If one call site forgets it, the
privacy/length guarantee in the helper's doc silently breaks (the helper itself does not bound `tail`).
**Fix:** Hoist `private const val CLI_TAIL_MAX = 2000` and use it at all three sites, or bound inside
`buildTimeoutMessage` so the guarantee lives with the function that documents it.

### IN-03: `isValidHost` accepts any port when none is present in the `Host` header

**File:** `src/main/kotlin/com/six2dez/burp/aiagent/mcp/KtorMcpServerManager.kt:326-340`
**Issue:** When the `Host` header has no port (`parts.size == 1`), `port` is `null` and the
`port != expectedPort` check is skipped, so `Host: localhost` (no port) passes regardless of the bound
port. Loopback hostname is still required so this is not an SSRF/rebinding hole, but it is laxer than
the comment implies. Pre-existing (not introduced this phase); noting for completeness since the file
was in scope.
**Fix:** If strictness is desired, require the port to be present and match when `externalEnabled` is
false; otherwise document that a missing port is intentionally allowed.

### IN-04: `RedactionHostMapBoundTest` asserts the LRU cap only indirectly; the `cap` literal is duplicated from prod

**File:** `src/test/kotlin/com/six2dez/burp/aiagent/redact/RedactionHostMapBoundTest.kt:31`, `:67`
**Issue:** The test hardcodes `val cap = 4096` with a comment "must match HOST_MAP_CAP in Redaction.kt"
but `HOST_MAP_CAP` is `private`, so a future change to the prod constant won't fail this test — it will
just silently test the wrong boundary. The test also only verifies round-trip survival of *recent*
entries (correct, but it never asserts that eviction actually occurred), so a regression that made the
map unbounded would still pass. This is acceptable given the private constant, but the coupling is
fragile.
**Fix:** Expose the cap via an `internal` test seam (like `testHkdfExtract`) so the test reads the real
value, or add an `internal fun hostMapSize(salt): Int` seam to assert `size <= cap` directly.

### IN-05: `ChatPanelConcurrencyTest.sessionMaps_noDataRaceUnderEdtConfinement` tests a stand-in map, not `ChatPanel`

**File:** `src/test/kotlin/com/six2dez/burp/aiagent/ui/ChatPanelConcurrencyTest.kt:73-157`
**Issue:** The SC1 test models the confinement invariant with a fresh `linkedMapOf` and a fake-EDT
executor rather than driving `ChatPanel` itself (justified — `ChatPanel` needs Swing/`UiTheme` and
throws `HeadlessException`). It proves the *pattern* is race-free, but it cannot catch the actual gap in
WR-01 (an off-EDT call site that bypasses the pattern), because the test never exercises the real call
graph. The green check here is necessary but not sufficient evidence that REL-01 is closed — which is
why WR-01 slipped through. Calling this out so the test result isn't over-trusted.
**Fix:** No change required to the test itself; treat WR-01 as the real gate. Optionally add a headless
guard test that calls `chatPanel.shutdown()` from a non-EDT thread and asserts no exception / no
off-EDT Swing mutation (e.g., via a custom `RepaintManager` thread-check).

---

_Reviewed: 2026-06-11T00:00:00Z_
_Reviewer: Claude (gsd-code-reviewer)_
_Depth: standard_
