---
phase: 17-reliability-concurrency-hardening
verified: 2026-06-11T12:00:00Z
status: passed
score: 5/5
overrides_applied: 0
human_uat_deferred: true
human_uat_note: "All 5 success criteria verified against the actual source + a green test suite (orchestrator-performed verification; the gsd-verifier agent confirmed key checks but its return truncated before writing this file). The single human-UAT item — issue #71 live `npx @google/gemini-cli` smoke (fresh machine → actionable timeout message; raising cliTimeoutSeconds lets it complete) — was deferred-and-accepted by the maintainer ('defer all remaining' policy for this autonomous run) and is tracked in 17-HUMAN-UAT.md. The automated regression for #71 is CliTimeoutMessageTest."
---

# Phase 17: Reliability & Concurrency Hardening — Verification Report

**Status:** passed (5/5 automated must-haves) · #71 live smoke = deferred human-UAT
**Requirements:** REL-01, REL-02, REL-03, REL-04 — all covered.

## Success Criteria (verified against real source)

| SC | Requirement | Evidence | Verdict |
|----|-------------|----------|---------|
| SC1 | REL-01 EDT confinement | `util/GuardedBy.kt` is `@Retention(AnnotationRetention.SOURCE)`; the 4 ChatPanel session maps carry `@GuardedBy("EDT")`; the off-EDT writers (onComplete→maybeExecuteToolCall via `invokeLater`, and `cancelInFlightRequest`/`shutdown` via `assertEdt()` + `invokeAndWait` guarded by `isEventDispatchThread()`) are EDT-confined; `build.gradle.kts` adds `jvmArgs("-ea")`; `ChatPanelConcurrencyTest` green. | VERIFIED |
| SC2 | REL-02 temp files | `CliBackend` calls `deleteOnExit()` at both `createTempFile` sites + deletes in `finally`; `CliBackendTempFileTest` green. | VERIFIED |
| SC3 | REL-03 HTTP timeouts/CircuitBreaker | shared `HttpBackendSupport.recordHttpFailureIfRetryable` (429/5xx) is called by all 4 backends (OpenAiCompatible, Anthropic, Ollama, LmStudio); `recordSuccess` on success; `HttpBackendCircuitFailureTest` green. Closes Phase 14 WR-05. | VERIFIED |
| SC4 | REL-04 issue #71 | `cliTimeoutSeconds` is a defaulted `AgentSettings` field (coerced floor at consumption); `buildTimeoutMessage` is actionable (names the limit + remediation); `Defaults.CLI_PROCESS_TIMEOUT_SECONDS = 120` untouched; `CliTimeoutMessageTest` green. Live npx smoke = human-UAT. | VERIFIED (auto) / human-UAT (live) |
| SC5a | REL-02 bounded MCP shutdown | `KtorMcpServerManager.stop()` is RESTART-SAFE — `future.get(10s)` only, executor NOT terminated; terminal `shutdown()` keeps `awaitTermination`+`shutdownNow`; `McpShutdownBoundTest` proves stop→start→stop with no `RejectedExecutionException`. | VERIFIED |
| SC5b | REL-02 bounded host maps | inner per-salt maps are bounded synchronized `LinkedHashMap(accessOrder)` with `removeEldestEntry` (cap 4096); outer `ConcurrentHashMap` + `clearMappings` + `host-<12hex>.local` round-trip preserved; `RedactionHostMapBoundTest` + `RedactionTest` green. | VERIFIED |

## Code Review
17-REVIEW.md: clean. Actionable warnings WR-01 (the real REL-01 off-EDT gap — cancelInFlightRequest/shutdown), WR-02, WR-04 fixed + verified; WR-03/05/06 documented & accepted (tuning / behavioral changes outside the low-risk auto-fix envelope; no SC impact).

## human_verification
- **Issue #71 live smoke (REL-04/SC4):** on a fresh machine, run `npx @google/gemini-cli --output-format text --model gemini-2.5-flash --yolo` via the CLI backend → confirm the actionable timeout message naming the configurable limit, and that raising `cliTimeoutSeconds` in Settings lets it complete. (Deferred; tracked in 17-HUMAN-UAT.md.)

## Full suite
`./gradlew test` — BUILD SUCCESSFUL (green).
