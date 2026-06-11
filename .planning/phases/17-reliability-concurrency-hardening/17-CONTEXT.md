# Phase 17: Reliability & Concurrency Hardening - Context

**Gathered:** 2026-06-11
**Status:** Ready for planning

<domain>
## Phase Boundary

Close the four known reliability gaps (REL-01..04) with no new user-facing features — internal correctness/robustness only:

1. **REL-01 (SC1)** — `ChatPanel`'s four session maps (`sessionPanels`, `sessionStates`, `sessionsById`, `sessionDrafts`) are EDT-confined (`@GuardedBy("EDT")`), with a concurrency test proving no data race.
2. **REL-02 (SC2/SC5)** — CLI temp files (prompt/context content) are deleted in `finally` + `deleteOnExit()` (reliable even on crash); MCP server shutdown is bounded (no hang); host-anonymization maps are bounded.
3. **REL-03 (SC3)** — all HTTP backends (incl. Phase 14's `AnthropicBackend`) share consistent connect/read timeouts and route through the `CircuitBreaker` / `MontoyaHttpTransport`; none bypass it.
4. **REL-04 (SC4)** — issue #71 (CLI command-timeout failure) is reproduced, diagnosed, and fixed (or given an actionable error) with a regression test.

Out of scope: new features; the QUAL-04 swallowed-exception audit (Phase 18, though REL-04 diagnosability ties in).
</domain>

<decisions>
## Implementation Decisions

### REL-01 — EDT confinement
- Annotate the 4 `ChatPanel` session maps (currently `linkedMapOf`) with `@GuardedBy("EDT")` and keep them EDT-confined (NOT converted to thread-safe collections). Add EDT assertions on access; any off-EDT mutation routes via `SwingUtilities.invokeLater`. A concurrency test verifies no data race (SC1's required test). Preserve insertion order (they are `linkedMapOf` for ordering).

### REL-02 — Resource hardening
- CLI temp files (`CliBackend.kt` `createTempFile` sites): delete in a `finally` block (not only `catch`) AND call `deleteOnExit()` at creation so a crash still cleans up. Audit ALL temp-file sites (codex/uv prompt files, output files).
- MCP server shutdown (`McpServerManager.stop()`/`shutdown()`): bound with a timeout (e.g. `awaitTermination(timeout)`) so `stop()` never hangs; force-stop after the bound.
- Host-anonymization maps (`Redaction.hostForwardMap`/`hostReverseMap`): **size-cap with LRU-style eviction** (bounded memory over a long session) AND keep the existing `clearMappings` on salt rotation. The exact cap is at Claude's discretion (e.g. a few thousand entries).

### REL-03 — Uniform HTTP timeouts + CircuitBreaker
- All HTTP backends (Ollama, OpenAI-compatible, Perplexity, NVIDIA, Anthropic, BurpAI) share **consistent connect/read timeout** defaults via `MontoyaHttpTransport` and route through the `CircuitBreaker`; none construct their own client/bypass the transport.
- **Route retryable HTTP failures (429 / 5xx) through `CircuitBreaker.recordFailure`** so the breaker + retry logic actually see them — this **closes Phase 14's deferred WR-05** (Anthropic 429/5xx was not routed through `recordFailure`; the OpenAiCompatible analog wasn't either, so fix it consistently across backends here). A success path calls `recordSuccess`.

### REL-04 — Issue #71 (CLI command timeout)
- Researcher fetches issue #71 (via `gh issue view 71` / web). Reproduce + fix the **root cause** if tractable; otherwise surface an **actionable error message** (SC4 permits either). Add a **regression test** in both cases.

### Claude's Discretion
- Exact timeout values (connect/read), the host-map cap size + eviction policy details, the MCP shutdown bound, the EDT-assertion mechanism, and whether REL-04 lands as a root-cause fix vs actionable error (depends on what #71 turns out to be) — at Claude's discretion, guided by the existing `CircuitBreaker`/`MontoyaHttpTransport`/`CliBackend` code.
</decisions>

<code_context>
## Existing Code Insights

### Reusable Assets
- `ui/ChatPanel.kt:104-107` — the 4 session maps (`linkedMapOf`), accessed throughout the panel. EDT-confinement target.
- `backends/cli/CliBackend.kt` — `createTempFile` at :109/:121, deletes in `finally` at :274/:281/:285 (some) and inline at :138. Add `deleteOnExit()` + ensure all paths delete in `finally`.
- `backends/http/MontoyaHttpTransport.kt` — `post(timeoutMs=120_000)`, `get(timeoutMs=3_000)`, `execute(...)` with `.withResponseTimeout`. Centralize consistent timeouts here.
- `backends/http/CircuitBreaker.kt` — `tryAcquire()`, `recordSuccess()` (:74), `recordFailure()` (:83), `state()`. Route 429/5xx through `recordFailure`.
- `mcp/McpServerManager.kt` — `stop(callback)` (:28), `shutdown()` (:30). Bound the shutdown.
- `redact/Redaction.kt:145` — `hostForwardMap`/`hostReverseMap` (`ConcurrentHashMap`), `clearMappings` (:302). Add a size cap.
- Issue #71 — only in planning docs; fetch the GitHub issue for the actual symptom.

### Established Patterns
- Backends route HTTP through `MontoyaHttpTransport` (Burp-visible) + `CircuitBreaker`; this phase makes timeout/failure-recording uniform.
- Swing UI on the EDT; `SwingUtilities.invokeLater` for cross-thread UI mutation.
- Tests: JUnit Jupiter + mockito-kotlin; concurrency tests use real threads/executors.

### Integration Points
- `ChatPanel` (EDT confinement). `CliBackend` (temp-file cleanup + #71). `MontoyaHttpTransport`/`CircuitBreaker` + each HTTP backend (uniform timeouts + 429/5xx recordFailure). `McpServerManager` (bounded shutdown). `Redaction` (bounded host maps).
</code_context>

<specifics>
## Specific Ideas

- SC1: `@GuardedBy("EDT")` on the 4 named maps + a concurrency test.
- SC2: temp files deleted in `finally` + `deleteOnExit()`.
- SC3: all HTTP backends share timeouts + route through CircuitBreaker; closes Phase 14 WR-05 (429/5xx → recordFailure).
- SC4: issue #71 reproduced + fixed/actionable-error + regression test.
- SC5: bounded MCP shutdown (no hang) + bounded host-anonymization maps.
</specifics>

<deferred>
## Deferred Ideas

- The QUAL-04 silently-swallowed `catch (Exception)` audit + shared logging helper — Phase 18 (ties to REL-04 diagnosability but is a separate requirement).
</deferred>
