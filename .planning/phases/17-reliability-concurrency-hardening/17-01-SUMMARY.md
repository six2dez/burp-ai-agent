---
phase: 17-reliability-concurrency-hardening
plan: "01"
subsystem: backends/http
tags: [rel-03, circuit-breaker, reliability, tdd, wr-05-closed]
dependency_graph:
  requires: []
  provides: [recordHttpFailureIfRetryable, isRetryableHttpStatus]
  affects:
    - backends/openai/OpenAiCompatibleBackend.kt
    - backends/anthropic/AnthropicBackend.kt
    - backends/ollama/OllamaBackend.kt
    - backends/lmstudio/LmStudioBackend.kt
tech_stack:
  added: []
  patterns: [transport-spy test (MockitoKotlin), TDD RED/GREEN, top-level extension function]
key_files:
  created:
    - src/main/kotlin/com/six2dez/burp/aiagent/backends/http/HttpBackendSupport.kt (extended with isRetryableHttpStatus + recordHttpFailureIfRetryable)
    - src/test/kotlin/com/six2dez/burp/aiagent/backends/http/HttpBackendCircuitFailureTest.kt
  modified:
    - src/main/kotlin/com/six2dez/burp/aiagent/backends/openai/OpenAiCompatibleBackend.kt
    - src/main/kotlin/com/six2dez/burp/aiagent/backends/anthropic/AnthropicBackend.kt
    - src/main/kotlin/com/six2dez/burp/aiagent/backends/ollama/OllamaBackend.kt
    - src/main/kotlin/com/six2dez/burp/aiagent/backends/lmstudio/LmStudioBackend.kt
decisions:
  - "recordHttpFailureIfRetryable defined as top-level extension on CircuitBreaker (not a member extension of the HttpBackendSupport object) so all backends can import and call it directly without needing an explicit object receiver scope"
  - "isRetryableHttpStatus remains an object member (static helper) for direct unit-testable access"
  - "429 and 5xx only; 400/401/403/404 deliberately excluded — non-transient config errors must not trip the breaker (Pitfall 4)"
  - "No new retry on HTTP status — return@submit kept; only recordFailure added (Pitfall 4 compliance)"
  - "AnthropicBackend 400-model guard at :188 returns before the generic !resp.isSuccessful block — 400 correctly excluded"
  - "OllamaBackend helper placed in the transport != null production branch; no-transport OkHttp path is test-only and untouched"
metrics:
  duration: "~10 minutes"
  completed_date: "2026-06-11"
  tasks: 2
  files: 7
requirements: [REL-03]
---

# Phase 17 Plan 01: HTTP Backend Circuit-Breaker Failure Recording Summary

REL-03: shared `isRetryableHttpStatus`/`recordHttpFailureIfRetryable` helper wired into all 4 HTTP backends so 429/5xx responses trip the circuit breaker, closing Phase 14 WR-05 drift.

## What Was Built

A single shared extension function `CircuitBreaker.recordHttpFailureIfRetryable(statusCode: Int)` defined as a top-level extension in `HttpBackendSupport.kt`. This calls `recordFailure()` only when `isRetryableHttpStatus` returns true (429 or 5xx); 4xx config errors are excluded.

One line (`circuitBreaker.recordHttpFailureIfRetryable(resp.statusCode)`) was added before the existing `onComplete(IllegalStateException(...))` call in the `!resp.isSuccessful` branch of all four HTTP backends:

- `OpenAiCompatibleBackend` at the richest failure block (covers NVIDIA/Perplexity automatically)
- `AnthropicBackend` in the generic `!resp.isSuccessful` block only — the 400-model rejection guard at `:188` returns before it and correctly stays out
- `OllamaBackend` inside the `transport != null` production branch
- `LmStudioBackend` at its failure block

`HttpBackendCircuitFailureTest` was created with:
- Direct unit tests for `isRetryableHttpStatus` (429/500/503/599 → true; 200/400/401/403/404 → false)
- Behavioral breaker-open tests for all 4 backends: 6 consecutive 429 sends cause at least one failure with "circuit open" in the message
- A negative test confirming 400 does NOT open the breaker

## Commits

| Commit | Type | Description |
|--------|------|-------------|
| 0ce9033 | test | RED scaffold + isRetryableHttpStatus/recordHttpFailureIfRetryable helper |
| 60b9f9e | feat | Wire recordHttpFailureIfRetryable into all 4 HTTP backends — closes REL-03/WR-05 |

## Success Criteria — Status

- [x] isRetryableHttpStatus(429/500/503/599) == true; isRetryableHttpStatus(200/400/401/403/404) == false
- [x] All 4 backends call recordHttpFailureIfRetryable at !resp.isSuccessful (verified: 4 production call sites)
- [x] HttpBackendCircuitFailureTest passes for OpenAiCompatible, Anthropic, Ollama, LmStudio
- [x] 400 does NOT trip the breaker (negative test passes)
- [x] Anthropic 400-model guard path unchanged (AnthropicModelErrorTest stays green)
- [x] No new HTTP-status retry added (return@submit kept, Pitfall 4)
- [x] Full `./gradlew test` green (no regressions)
- [x] NVIDIA/Perplexity inherit fix via OpenAiCompatibleBackend; BurpAi excluded
- [x] Phase 14 WR-05 closed: zero duplicated retryable-status predicate per backend

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] recordHttpFailureIfRetryable moved from member extension to top-level extension**
- **Found during:** Task 2 wiring
- **Issue:** Kotlin member extensions defined inside an `object` require the object as a dispatch receiver to be in scope — calling `circuitBreaker.recordHttpFailureIfRetryable(...)` directly from a backend class would not compile without `with(HttpBackendSupport) { ... }` wrapping every call site.
- **Fix:** Removed the member extension from inside `HttpBackendSupport` object and defined it as a top-level `fun CircuitBreaker.recordHttpFailureIfRetryable(...)` in the same file. `isRetryableHttpStatus` stays as an object member (backends already import HttpBackendSupport and call it as a static helper; the extension delegates to it). All 4 backends add a single `import com.six2dez.burp.aiagent.backends.http.recordHttpFailureIfRetryable`.
- **Files modified:** HttpBackendSupport.kt, OpenAiCompatibleBackend.kt, AnthropicBackend.kt, OllamaBackend.kt, LmStudioBackend.kt
- **Commits:** 0ce9033, 60b9f9e

## TDD Gate Compliance

- RED gate commit: 0ce9033 (`test(17-01): RED scaffold...`) — isRetryableHttpStatus assertions GREEN; behavioral breaker-open assertions FAILED as expected
- GREEN gate commit: 60b9f9e (`feat(17-01): wire recordHttpFailureIfRetryable...`) — all assertions pass

## Threat Flags

None — no new network endpoints, auth paths, or schema changes introduced. The change adds a `recordFailure()` call on the existing breach path; the threat model entries T-17-01-01 and T-17-01-02 are both mitigated as designed.

## Known Stubs

None.

## Self-Check

Files confirmed present:
- `src/main/kotlin/com/six2dez/burp/aiagent/backends/http/HttpBackendSupport.kt` — extended
- `src/test/kotlin/com/six2dez/burp/aiagent/backends/http/HttpBackendCircuitFailureTest.kt` — created
- 4 backend files modified — confirmed via grep (4 production call sites)

Commits confirmed: 0ce9033, 60b9f9e both in git log.
`./gradlew test` — BUILD SUCCESSFUL.
