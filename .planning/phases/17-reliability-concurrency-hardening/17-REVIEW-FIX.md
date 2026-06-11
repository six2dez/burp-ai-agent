---
phase: 17-reliability-concurrency-hardening
fixed_at: 2026-06-11T00:00:00Z
review_path: .planning/phases/17-reliability-concurrency-hardening/17-REVIEW.md
iteration: 1
findings_in_scope: 6
fixed: 3
skipped: 3
status: partial
---

# Phase 17: Code Review Fix Report

**Fixed at:** 2026-06-11T00:00:00Z
**Source review:** .planning/phases/17-reliability-concurrency-hardening/17-REVIEW.md
**Iteration:** 1

**Summary:**
- Findings in scope (Warnings, critical_warning scope): 6
- Fixed: 3
- Skipped: 3

Validated with `./gradlew test` (project gate; `ktlintCheck` is known-broken via the
`generateBuildFlags` wiring and not used). Full suite **BUILD SUCCESSFUL** after all fixes —
no SC regression (REL-01 EDT confinement, REL-03 4-backend recordFailure, restart-safe `stop()`,
LRU host maps, #71 timeout all still green), and the new WR-01 regression guard passes.

## Fixed Issues

### WR-01: `@GuardedBy("EDT")` maps mutated off-EDT via `shutdown()` → `cancelInFlightRequest()`

**Files modified:** `src/main/kotlin/com/six2dez/burp/aiagent/ui/ChatPanel.kt`, `src/test/kotlin/com/six2dez/burp/aiagent/ui/ChatPanelConcurrencyTest.kt`
**Commit:** 53171e2
**Applied fix:** Added `assertEdt()` to `cancelInFlightRequest()` so the EDT-confinement contract
is enforced uniformly (not only on the tool-call path). Rewrote `shutdown()` to marshal its
session-map + Swing work (`cancelInFlightRequest()` + `stopAllTimers()`) onto the EDT via an
`isEventDispatchThread()`-guarded `SwingUtilities.invokeAndWait`, since `shutdown()` is reached
from Burp's unload handler on a Montoya thread (not the EDT). The off-EDT branch swallows
`InterruptedException` (re-setting the interrupt flag) and `InvocationTargetException` so unload
never throws. `clearInMemorySessionState()` was left unchanged: it is reached only from
`onProjectChanged`, which fires from a `javax.swing.Timer` (already on the EDT), and now correctly
passes the new `assertEdt()` guard. Added `shutdownMarshalingRunsConfinedWorkOnEdtWhenCalledOffEdt`
test asserting the off-EDT marshaling shape runs the confined work on the EDT (not the calling
thread) and is synchronous. This closes the REL-01 completeness gap so every session-map mutation
is EDT-confined. **Note:** the marshaling is structurally verified (compile + test); the
correctness of EDT confinement under real Burp-unload timing should be confirmed in manual QA.

### WR-02: `cliTimeoutSeconds` floor not enforced at the consumption boundary

**Files modified:** `src/main/kotlin/com/six2dez/burp/aiagent/backends/cli/CliBackend.kt`, `src/main/kotlin/com/six2dez/burp/aiagent/config/AgentSettings.kt`
**Commit:** 018aed7
**Applied fix:** `CliBackend.launch` now re-coerces the resolved timeout
`(config.cliTimeoutSeconds ?: Defaults.CLI_PROCESS_TIMEOUT_SECONDS).coerceIn(30, 3600)` before
handing it to the `NonInteractiveCliConnection` watchdog, mirroring the `AgentSettings` persistence
clamp. This makes the watchdog robust against directly-constructed configs (tests / future call
sites) that could inject `0` or a negative value — eliminating `waitFor(0)` immediate-timeout and
the wall-clock overflow. Also documented the `[30, 3600]` clamp and the silent 30s floor in the
`cliTimeoutSeconds` field KDoc (part (a) of the review's suggested fix). The UI-note portion of
the suggestion was not added (out of low-risk scope; the KDoc + persistence clamp already capture
the invariant).

### WR-04: Ollama/LM Studio error path echoed the full response body into the exception message

**Files modified:** `src/main/kotlin/com/six2dez/burp/aiagent/backends/ollama/OllamaBackend.kt`, `src/main/kotlin/com/six2dez/burp/aiagent/backends/lmstudio/LmStudioBackend.kt`
**Commit:** 7b2ee4e
**Applied fix:** Bounded the surfaced error body with `.take(800)` in the `onComplete(...)` exception
message of both backends, matching the OpenAI/Anthropic analog (`OpenAiCompatibleBackend` :255,
`AnthropicBackend` :206). A large or secret-laden error envelope from a local server / misconfigured
proxy no longer flows verbatim into the `[Error] …` chat bubble and into persisted
`session.messages`. The `errorLog(...take(500))` was already bounded and left as-is.

## Skipped Issues

### WR-03: HTTP-error retries double-count circuit-breaker failures across the retry loop

**File:** `src/main/kotlin/com/six2dez/burp/aiagent/backends/ollama/OllamaBackend.kt:295-299`, `src/main/kotlin/com/six2dez/burp/aiagent/backends/lmstudio/LmStudioBackend.kt:194-198`, OpenAI `:263-265`, Anthropic `:212-214`
**Reason:** skipped: tuning observation, not a clear bug — fix is not low-risk. The review itself
frames the connection-exception retry recording ~6 failures vs 1 for a 5xx as "arguably intended
('6 strikes = open')". Adding a `recordedFailure` latch to bound breaker failures to one per
`send()` would change the documented REL-03 circuit-breaker semantics (`CIRCUIT_FAILURE_THRESHOLD = 5`
across all four backends) and could mask genuinely flaky transport. Per fix guidance, this is a
TUNING decision deferred to an explicit owner choice rather than auto-applied. Documenting the
asymmetry in-code would be the safer follow-up; left untouched to avoid regressing REL-03 behavior.

### WR-05: `ConversationHistory` mixes `ConcurrentLinkedDeque` with a separate lock

**File:** `src/main/kotlin/com/six2dez/burp/aiagent/backends/http/HttpBackendSupport.kt:179-249`
**Reason:** skipped: maintainability landmine, not a live bug (review's own classification). The
executor is single-threaded per connection so `runningTotalChars` never actually races in
production, and `history` is `private` (no external caller can touch the deque outside `lock`).
Swapping `ConcurrentLinkedDeque` → `ArrayDeque` touches a shared support class used by all four HTTP
backends and risks subtle behavior changes for a non-functional cleanup. Out of the low-risk
auto-fix envelope; deferred.

### WR-06: `evictStaleClients()` can shut down a client mid-use under concurrency

**File:** `src/main/kotlin/com/six2dez/burp/aiagent/backends/http/HttpBackendSupport.kt:53-97`
**Reason:** skipped: narrow, hard-to-reproduce race (only clients idle >10min) in the shared
client-eviction path used by all HTTP backends. The suggested fix (atomic two-arg
`sharedClients.remove(key, entry)` before shutdown, or dropping opportunistic dispatcher shutdown)
is a behavioral change to the shared transport-pooling code with real regression surface and would
warrant its own focused test. Beyond the low-risk auto-fix scope for this iteration; deferred to a
dedicated change. No correctness regression introduced by leaving it as-is.

**Info findings (IN-01..IN-05):** out of `critical_warning` scope — not attempted this iteration.
IN-05's suggestion (a headless off-EDT `shutdown()` guard test) is partially addressed by the WR-01
regression test added above.

---

_Fixed: 2026-06-11T00:00:00Z_
_Fixer: Claude (gsd-code-fixer)_
_Iteration: 1_
