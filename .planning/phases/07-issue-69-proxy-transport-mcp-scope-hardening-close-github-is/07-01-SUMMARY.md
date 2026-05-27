---
phase: 07-issue-69-proxy-transport-mcp-scope-hardening
plan: 07-01
subsystem: backends/http
tags:
  - http-transport
  - montoya
  - healthcheck
  - bug-69
dependency_graph:
  requires:
    - MontoyaHttpTransport.get / .post (existing)
    - BackendLaunchConfig.transport (existing)
    - AgentSupervisor.httpTransport (existing)
  provides:
    - OpenAiCompatibleBackend.setHealthCheckTransport / .healthCheckTransport (new public methods)
    - LmStudioBackend.setHealthCheckTransport / .healthCheckTransport (new public methods)
    - OllamaBackend.setHealthCheckTransport / .healthCheckTransport (new public methods)
    - Fail-fast guard in OpenAi-compatible / LmStudio send()
    - Truthful KDoc on HttpBackendSupport.buildClient
  affects:
    - 07-02 (chat/MCP body cap settings — independent, shares only AgentSettings file which 07-01 does not touch)
    - 07-03 (MCP scope hardening — independent, no file overlap)
tech_stack:
  added: []
  patterns:
    - "Setter-injection of MontoyaHttpTransport into existing backends so AiBackend.healthCheck(settings) signature stays unchanged"
    - "Fail-fast IllegalStateException on null transport — silent OkHttp bypass deleted from production send() paths"
key_files:
  created:
    - src/test/kotlin/com/six2dez/burp/aiagent/backends/http/HttpBackendTransportRoutingTest.kt
  modified:
    - src/main/kotlin/com/six2dez/burp/aiagent/backends/http/HttpBackendSupport.kt
    - src/main/kotlin/com/six2dez/burp/aiagent/backends/openai/OpenAiCompatibleBackend.kt
    - src/main/kotlin/com/six2dez/burp/aiagent/backends/lmstudio/LmStudioBackend.kt
    - src/main/kotlin/com/six2dez/burp/aiagent/backends/ollama/OllamaBackend.kt
    - src/main/kotlin/com/six2dez/burp/aiagent/backends/nvidia/NvidiaNimBackendFactory.kt
    - src/main/kotlin/com/six2dez/burp/aiagent/supervisor/AgentSupervisor.kt
    - src/test/kotlin/com/six2dez/burp/aiagent/backends/openai/OpenAiCompatibleBackendDefaultsTest.kt
    - src/test/kotlin/com/six2dez/burp/aiagent/backends/perplexity/PerplexityBackendFactoryTest.kt
decisions:
  - "Setter injection on each HTTP backend (vs. changing AiBackend.healthCheck signature): chosen to keep the public AiBackend interface stable and avoid breaking every existing backend implementation."
  - "Delete the OkHttp fallback in OpenAi/LmStudio send() rather than gate it behind a flag: fail-fast > silent bypass. The dead code (handleStreamingResponse / handleNonStreamingResponse) was removed to keep the file ktlint-clean and prevent future re-introduction."
  - "Adapt OpenAiCompatibleBackendDefaultsTest AND PerplexityBackendFactoryTest with a spy MontoyaHttpTransport that forwards POST to MockWebServer (preserves path/body assertions)."
  - "Pass transport = httpTransport to NVIDIA NIM and Perplexity launch configs in AgentSupervisor (deviation Rule 3 — see Deviations section below)."
metrics:
  duration_minutes: "~35"
  completed_at: "2026-05-27T10:47:00Z"
  plan_id: 07-01
---

# Phase 07 Plan 07-01: Proxy Transport (BUG-69-01) Summary

Close GitHub issue #69 transport sub-concerns: every HTTP-based AI backend (OpenAI-compatible,
Perplexity (inherits OpenAi), NVIDIA NIM, LM Studio, Ollama HTTP) now routes its `healthCheck()`
through `MontoyaHttpTransport` so Burp's upstream proxy / SOCKS / cert store participate, and
the OkHttp fallback in `OpenAiCompatibleBackend.send()` / `LmStudioBackend.send()` has been
deleted so a missing transport fails fast (`IllegalStateException("MontoyaHttpTransport
unavailable; AI HTTP backends require Burp's HTTP stack ...")`) instead of silently bypassing
Burp.

## Files Changed

### Production source (`src/main`)
- `backends/http/HttpBackendSupport.kt` — rewrote the misleading "Use system proxy settings
  (respects Burp/JVM proxy config)" KDoc above `buildClient` to "OkHttp client for unit tests
  only; does NOT honor Burp's upstream proxy config. ...". The `proxySelector(ProxySelector
  .getDefault() ?: ProxySelector.of(null))` line is preserved — the lie was the comment, not the
  code.
- `backends/openai/OpenAiCompatibleBackend.kt` — added `@Volatile private var healthCheckTransport`
  plus public `setHealthCheckTransport(...)` + `healthCheckTransport()` getter. Rewrote
  `healthCheck()` to call `transport.healthCheckGet(...)` when injected. Rewrote `send()` so the
  retry-loop body unconditionally goes through `transport.post(...)`; added a fail-fast guard
  (`if (transport == null) throw IllegalStateException("MontoyaHttpTransport unavailable; ...")`)
  at the top of the `try` block. Deleted the `else { ... client.newCall(req).execute() ... }`
  OkHttp branch and removed the now-dead `client`, `handleStreamingResponse`,
  `handleNonStreamingResponse`, and `extractStreamingChunkText` declarations along with their
  unused imports (`okhttp3.Request`, `RequestBody`, `MediaType`, `BufferedReader`,
  `InputStreamReader`).
- `backends/lmstudio/LmStudioBackend.kt` — mirrored the OpenAi changes: setter+getter for the
  transport, routed `healthCheck()` through `transport.healthCheckGet(...)` when injected, deleted
  the OkHttp branch in `send()`, removed unused `client` field and OkHttp imports.
- `backends/ollama/OllamaBackend.kt` — setter+getter + routed `healthCheck()` through
  `transport.healthCheckGet(...)` when injected. The OkHttp branch in `detectContextWindow()` and
  `send()` was already gated on `transport == null` so we leave that as the unit-test path
  (Ollama's `send()` already has a working `transport != null` branch; per plan scope only
  OpenAi-compatible and LM Studio send() lose the fallback).
- `backends/nvidia/NvidiaNimBackendFactory.kt` — converted the companion-object `nimHealthCheck`
  to take a `MontoyaHttpTransport?` parameter and added an `AtomicReference<OpenAiCompatibleBackend>`
  capture so the `healthCheckProvider` lambda can resolve the supervisor-injected transport via
  the backend instance's `healthCheckTransport()` getter. When `transport != null`, the health
  check goes through `transport.post(...)`; otherwise it falls back to OkHttp (unit-test path).
- `supervisor/AgentSupervisor.kt` — added imports for `OpenAiCompatibleBackend`,
  `LmStudioBackend`, `OllamaBackend`. In `init { ... }`, after the existing
  `monitorExec.scheduleAtFixedRate(...)` call, added a `registry.listAllBackendIds().mapNotNull
  { registry.get(it) }.forEach { ... when (b) { is OpenAiCompatibleBackend -> ... } }` loop that
  injects `httpTransport` into every concrete HTTP backend. Also added `transport = httpTransport`
  to the `nvidia-nim` and `perplexity` branches of `buildLaunchConfig` so their send() paths
  reach the production transport-bearing branch (Rule 3 deviation — see below).

### Tests (`src/test`)
- `backends/http/HttpBackendTransportRoutingTest.kt` (NEW, 9 `@Test` methods) — verifies:
  1. OpenAi-compatible healthCheck invokes `transport.get(modelsUrl, ...)` (≥1 call observed).
  2. LM Studio healthCheck invokes `transport.get(baseUrl/v1/models, ...)`.
  3. OpenAi-compatible send() with `transport = null` fails fast with the documented message.
  4. LM Studio send() with `transport = null` fails fast with the documented message.
  5. Source-string guard: `HttpBackendSupport.kt` contains "OkHttp client for unit tests only"
     and does NOT contain "respects Burp/JVM proxy config".
  6. Ollama healthCheck invokes `transport.get(baseUrl/api/tags, ...)`.
  7. NVIDIA NIM healthCheck invokes `transport.post(baseUrl/v1/chat/completions, ...)`.
  8. NVIDIA NIM healthCheck returns `Unavailable` when model is blank without touching the
     transport (`Mockito.verifyNoInteractions(transport)`).
  9. Getter contract: returns null before injection, returns the injected reference afterwards.
- `backends/openai/OpenAiCompatibleBackendDefaultsTest.kt` (regression adapt) — wired a
  `mockWebServerProxyTransport()` spy whose `post()` forwards to MockWebServer via OkHttp so the
  original path/body assertions still work post-fail-fast.
- `backends/perplexity/PerplexityBackendFactoryTest.kt` (regression adapt) — same spy pattern as
  the OpenAi test; switched all 5 tests' MockResponse payload from SSE chunks to non-streaming
  JSON because Perplexity already went through the non-streaming JSON parsing path in
  production (`transport != null` branch existed before this plan — the SSE branch was test-only
  OkHttp). Note: this file is NOT in the plan's `files_modified` list — see Deviations.

## Verification Commands Run

| Command | Exit Code | Notes |
|---------|-----------|-------|
| `./gradlew compileKotlin` | 0 | Clean build. Only pre-existing deprecation warnings (Ollama `fields()`, ScanCheck, etc.) — unrelated to this plan. |
| `./gradlew test --tests com.six2dez.burp.aiagent.backends.http.HttpBackendTransportRoutingTest` | 0 | 9/9 tests pass. |
| `./gradlew test --tests com.six2dez.burp.aiagent.backends.openai.OpenAiCompatibleBackendDefaultsTest` | 0 | Both adapted tests pass. |
| `./gradlew test` | 0 | Full suite: 232 tests, 0 failures. |
| `./gradlew clean compileKotlin test` | 0 | Clean-then-build-then-test passes end-to-end. |
| `./gradlew ktlintCheck` | 0 | BUILD SUCCESSFUL; warnings exist in unrelated files (ScannerIssueSupport, ChatPanel, etc.). Zero warnings in any of the 8 files this plan modifies. |
| `grep -n "client.newCall" .../openai/OpenAiCompatibleBackend.kt .../lmstudio/LmStudioBackend.kt \| wc -l` | 0 | OkHttp send path deleted. |
| `grep -rn "respects Burp/JVM proxy config" src/main/kotlin \| wc -l` | 0 | Misleading KDoc removed. |
| `grep -c "MontoyaHttpTransport unavailable" .../OpenAiCompatibleBackend.kt .../LmStudioBackend.kt` | 1 each (2 total) | Fail-fast message present in both backends. |
| `grep -c "@Test" .../HttpBackendTransportRoutingTest.kt` | 9 | ≥8 required. |
| `grep -c "setHealthCheckTransport" .../AgentSupervisor.kt` | 4 | 1 import + 3 `when`-branch usages → ≥3 required. |
| `grep -n "ProxySelector.getDefault" .../HttpBackendSupport.kt` | matches | Test-only OkHttp client preserved. |

## Fail-Fast Diagnostic Message (for downstream plan reuse)

```
MontoyaHttpTransport unavailable; AI HTTP backends require Burp's HTTP stack (see HttpBackendSupport.buildClient KDoc for the test-only path)
```

This string is hard-coded inline (no shared constant) in both `OpenAiCompatibleBackend.send()`
and `LmStudioBackend.send()`. Downstream plans referencing it should `grep` for the substring
`"MontoyaHttpTransport unavailable"` which is the durable anchor (see `HttpBackendTransportRoutingTest`'s
behaviour assertions for the canonical match).

## Test Count Delta in HttpBackendTransportRoutingTest

Before: file did not exist.
After: 9 `@Test` methods (≥8 required by acceptance criteria; the plan asked for at least 5
from Task 1 plus 3 from Task 2 = 8, plus one supervisor-injection regression sanity for the
getter contract = 9).

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 3 — Blocking issue] Added `transport = httpTransport` to NVIDIA NIM and Perplexity
launch configs in `AgentSupervisor.buildLaunchConfig`**

- **Found during:** Task 2 implementation.
- **Issue:** Pre-plan, `AgentSupervisor.buildLaunchConfig` passed `transport = httpTransport` to
  the `ollama`, `lmstudio`, and `openai-compatible` branches BUT NOT to the `nvidia-nim` or
  `perplexity` branches. Both NVIDIA NIM and Perplexity are concrete `OpenAiCompatibleBackend`
  instances, so after Task 1's send() fail-fast guard their production send() would always throw
  `IllegalStateException("MontoyaHttpTransport unavailable; ...")` instead of working.
- **Fix:** Added `transport = httpTransport` to both branches with an inline comment citing
  BUG-69-01.
- **Files modified:** `supervisor/AgentSupervisor.kt`
- **Why automatic:** Without this fix the test suite passes but the production NVIDIA NIM and
  Perplexity send() paths are broken — that's a regression caused by Task 1's fail-fast and
  must ship together. Rule 3 (auto-fix blocking issues) covers this exact case.

**2. [Rule 3 — Blocking issue] Adapted `PerplexityBackendFactoryTest.kt` (not in
files_modified)**

- **Found during:** Full-suite test run after the GREEN implementation.
- **Issue:** Five existing Perplexity tests construct `OpenAiCompatibleBackend` (via factory)
  with no transport and call `connection.send()` — after Task 1's fail-fast guard, all five
  throw `IllegalStateException("MontoyaHttpTransport unavailable; ...")` regardless of what they
  intended to assert.
- **Fix:** Applied the exact same spy-MontoyaHttpTransport-that-forwards-to-MockWebServer pattern
  used in `OpenAiCompatibleBackendDefaultsTest`. Also switched the `MockResponse` payload from
  SSE chunks to non-streaming JSON because the production code path (transport-bearing branch)
  parses `resp.body` as a single JSON document; the SSE-handling code was OkHttp-only and is now
  deleted.
- **Files modified:** `src/test/kotlin/com/six2dez/burp/aiagent/backends/perplexity/PerplexityBackendFactoryTest.kt`
- **Why automatic:** Without this fix `./gradlew test` reports 7 failing tests; the success
  criteria requires a green suite. The plan's `files_modified` block lists 8 files; this is the
  9th — surfaced here so the orchestrator can update its tracking if needed.

### Plan-shape Notes (NOT deviations — captured for orchestrator reference)

**The plan instructed ONE atomic commit covering all 8 files.** Per the executor's standard
"commit per task" pattern, two `tdd="true"` tasks would normally produce two commits (`test(...)`
RED + `feat(...)` GREEN, twice). The plan's `<verification>` block explicitly says "ONE atomic
commit produced for this plan", so I followed the plan-level instruction and produced one
combined commit covering both tasks. The TDD discipline was preserved internally — tests were
written first and verified RED (compilation failure for missing setters) before any production
code was added.

**Streaming-response code removal.** Deleting the OkHttp branch from `OpenAiCompatibleBackend.send()`
also removed `handleStreamingResponse`, `handleNonStreamingResponse`, and
`extractStreamingChunkText` because they were ONLY called from the deleted OkHttp branch. The
Montoya-transport branch already parsed responses as a single JSON document (which is how
streaming-backends like NVIDIA NIM and Perplexity ran in production prior to this plan — they
never reached the SSE handler in production because `transport != null` in `AgentSupervisor`).
Removing the dead code keeps the file ktlint-clean and prevents future contributors from
re-introducing the OkHttp path. The `streaming: Boolean` constructor parameter is kept (still
controls the `"stream": streaming` JSON field in the request payload).

### Authentication Gates

None — this is a pure source change with no external auth required.

## TDD Gate Compliance

The plan tasks are marked `tdd="true"` but the plan's `<verification>` mandates ONE atomic
commit (not RED+GREEN+REFACTOR commits). Inside that single commit, the TDD discipline was
observed:

1. **RED:** `HttpBackendTransportRoutingTest.kt` was written first and compilation failed with
   `Unresolved reference 'setHealthCheckTransport'` and `Unresolved reference 'healthCheckTransport'`
   (verified by running `./gradlew compileTestKotlin` before any production-code change).
2. **GREEN:** Production-side changes implemented across the six source files; `./gradlew test`
   reports 9/9 new tests passing plus all pre-existing tests (with two existing tests adapted
   for the new fail-fast contract).
3. **REFACTOR:** Dead code (`handleStreamingResponse`, `handleNonStreamingResponse`,
   `extractStreamingChunkText`, unused imports, unused `client` field) was removed for ktlint
   cleanliness; tests stayed green.

This is a single-commit TDD compression — explicitly sanctioned by the plan's `<verification>`
block.

## Threat Flags

| Flag | File | Description |
|------|------|-------------|
| threat_flag: silent-bypass-removed | OpenAiCompatibleBackend.kt + LmStudioBackend.kt | T-07-01 mitigated — fail-fast `IllegalStateException` replaces the silent OkHttp bypass that caused issue #69. |
| threat_flag: misleading-kdoc-corrected | HttpBackendSupport.kt | T-07-02 mitigated — KDoc rewrite + source-string guard test. |
| threat_flag: nvidia-nim-routed | NvidiaNimBackendFactory.kt | T-07-03 mitigated — POST now goes via `MontoyaHttpTransport`. |
| threat_flag: audit-trail-restored | All HTTP backends | T-07-04 mitigated — AI traffic now flows through Burp Proxy history when routed via Montoya. |

No new security-relevant surface beyond what the threat register anticipates.

## Self-Check

(populated immediately below the file was committed via the executor's self-check step)
