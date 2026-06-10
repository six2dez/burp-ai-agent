---
phase: 14-anthropic-backend-token-budget-listener-port
plan: 01
subsystem: backends/anthropic, config, ui
tags: [anthropic, backend, http-transport, secret-encryption, ui-card]
dependency_graph:
  requires: [Phase 12 SEC-01 SecretCipher, MontoyaHttpTransport, HttpBackendSupport]
  provides: [AnthropicBackend, AnthropicBackendFactory, anthropicApiKey encrypted, anthropicModel field, tokenBudget fields]
  affects: [BackendRegistry, AgentSupervisor, AgentSettings, BackendConfigPanel, SettingsPanel]
tech_stack:
  added: []
  patterns: [MontoyaHttpTransport-routed HTTP backend, SecretCipher AES-256-GCM encrypted key, TDD RED/GREEN cycle]
key_files:
  created:
    - src/main/kotlin/com/six2dez/burp/aiagent/backends/anthropic/AnthropicBackend.kt
    - src/main/kotlin/com/six2dez/burp/aiagent/backends/anthropic/AnthropicBackendFactory.kt
    - src/test/kotlin/com/six2dez/burp/aiagent/backends/anthropic/AnthropicBackendTransportRoutingTest.kt
    - src/test/kotlin/com/six2dez/burp/aiagent/backends/anthropic/AnthropicModelErrorTest.kt
  modified:
    - src/main/kotlin/com/six2dez/burp/aiagent/backends/BackendRegistry.kt
    - src/main/kotlin/com/six2dez/burp/aiagent/supervisor/AgentSupervisor.kt
    - src/main/resources/META-INF/services/com.six2dez.burp.aiagent.backends.AiBackendFactory
    - src/main/kotlin/com/six2dez/burp/aiagent/config/AgentSettings.kt
    - src/main/kotlin/com/six2dez/burp/aiagent/ui/panels/BackendConfigPanel.kt
    - src/main/kotlin/com/six2dez/burp/aiagent/ui/SettingsPanel.kt
    - src/test/kotlin/com/six2dez/burp/aiagent/backends/BackendRegistryTest.kt
    - src/test/kotlin/com/six2dez/burp/aiagent/config/AgentSettingsSecretEncryptionTest.kt
decisions:
  - Native Anthropic Messages API backend ships stream=false (single buffered onChunk) matching all existing HTTP backends; SC1 proof is proxy-visible request, not per-token UI animation (Pitfall 1 / RESEARCH Q1 RESOLVED)
  - Anthropic card has NO Base URL row — endpoint is a fixed backend constant, no false configurability, no SSRF surface (FLAG-14-02)
  - tokenBudgetWarnThreshold/tokenBudgetHardCap declared in 14-01 as defaulted AgentSettings fields so 14-02 never collides on AgentSettings.kt
  - KEY_ANTHROPIC_API_KEY added to migrateToSchemaV4 secretKeys list for belt-and-suspenders idempotent encryption
metrics:
  duration: ~30 minutes
  completed: 2026-06-10T17:26:49Z
  tasks_completed: 3
  files_changed: 12
---

# Phase 14 Plan 01: Anthropic Backend + AgentSettings Foundation Summary

Native Anthropic Messages API backend (AiBackend over MontoyaHttpTransport, x-api-key auth, top-level system field, usage extraction) with encrypted API key (SecretCipher), supervisor dispatch branch, registry + ServiceLoader registration, Anthropic settings card, and all four AgentSettings fields for the phase.

## What Was Built

### AnthropicBackend.kt (CREATE)
A near-copy of OpenAiCompatibleConnection with Anthropic-specific divergences:
- **DIVERGENCE 1:** system prompt as top-level `"system"` field, NOT injected via `setSystemPrompt` (which would produce a `{"role":"system"}` message that Anthropic rejects)
- **DIVERGENCE 2:** `x-api-key` + `anthropic-version: 2023-06-01` headers built by supervisor (NOT `withBearerToken` — Pitfall 2)
- **DIVERGENCE 3:** fixed constant `ANTHROPIC_MESSAGES_URL = "https://api.anthropic.com/v1/messages"` (no baseUrl selector)
- **DIVERGENCE 4 (SC3):** 400 + body.contains("model") → exact string "Anthropic rejected the model ID — check Settings > Anthropic > Model" before the generic non-2xx handler
- **DIVERGENCE 5:** response parsed from `content[].text` (not `choices[0].message.content`)
- **DIVERGENCE 6:** usage from `usage.input_tokens` / `usage.output_tokens` (not `prompt_tokens`/`completion_tokens`)
- SC2 invariants: `transport == null` fail-fast guard verbatim from analog; no okhttp3/OkHttpClient import; single `transport.post()` call is the only HTTP path

### AgentSettings.kt (MODIFY)
Four new defaulted fields: `anthropicModel` (default `"claude-sonnet-4-6"`), `anthropicApiKey` (default `""`), `tokenBudgetWarnThreshold` (default `0`), `tokenBudgetHardCap` (default `0`). All four declared here so 14-02/14-03 never collide. `anthropicApiKey` encrypted via `SecretCipher` at save/load; thresholds stored as plain integers (`setInteger`, never cipher — Pitfall 5). `KEY_ANTHROPIC_API_KEY` added to `migrateToSchemaV4` secret-migration list. Key constants `KEY_ANTHROPIC_MODEL`, `KEY_ANTHROPIC_API_KEY`, `KEY_TOKEN_BUDGET_WARN`, `KEY_TOKEN_BUDGET_CAP` added to companion.

### AgentSupervisor.kt (MODIFY)
`"anthropic"` branch in `when(backendId)` dispatch: resolves `anthropicModel`/`anthropicApiKey` from settings; builds `mapOf("x-api-key" to apiKey, "anthropic-version" to "2023-06-01")`; sets `transport = httpTransport`. Does NOT use `withBearerToken` (Pitfall 2). Without this branch the backend receives no auth headers.

### BackendConfigPanel.kt (MODIFY)
`BackendConfigState` gains `anthropicModel`/`anthropicApiKey`. `buildAnthropicPanel()`: Model row + API key (Bearer) row + Test connection button + trailing spacer. No Base URL row (FLAG-14-02 — fixed endpoint prevents false configurability + SSRF risk). `cards.add(buildAnthropicPanel(), "anthropic")` registered after perplexity. `currentBackendSettings()` and `applyState()` wired for both fields.

### BackendRegistry.kt + META-INF/services (MODIFY)
`AnthropicBackendFactory()` added to the fallback built-ins list (for when ServiceLoader returns empty). `com.six2dez.burp.aiagent.backends.anthropic.AnthropicBackendFactory` appended to the ServiceLoader manifest.

### Tests (CREATE/EXTEND)
- `AnthropicBackendTransportRoutingTest`: SC2a transport-routing verify, SC2b null-transport fail-fast, SC2c source-string guard
- `AnthropicModelErrorTest`: SC3 exact string assertion
- `BackendRegistryTest`: `anthropicBackend_registeredWithCorrectId()` added
- `AgentSettingsSecretEncryptionTest`: `roundTrip_allSevenSecretKeys_encryptedAtRest` renamed to `roundTrip_allEightSecretKeys_encryptedAtRest` with `anthropicApiKey = "k-anthropic"` added

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] Comment in AnthropicBackend.kt triggered SC2c source-string guard**
- **Found during:** Task 2 GREEN verification
- **Issue:** KDoc comment "No okhttp3 / OkHttpClient on this path" contained the exact strings the SC2c test asserts must be absent
- **Fix:** Rephrased comment to "SC2c: no direct HTTP client construction on this path" — preserves the meaning without containing the forbidden strings
- **Files modified:** `AnthropicBackend.kt`
- **Commit:** bc874ea (fixed inline before commit)

**2. [Rule 1 - Bug] Lambda type inference on test send() calls**
- **Found during:** Task 1 RED verification
- **Issue:** `{ chunks.add(it) }` and `{ }` lambdas produced "Cannot infer type" errors alongside the expected `AnthropicBackend` unresolved reference; the errors were secondary but prevented clean RED verification
- **Fix:** Made lambda parameters explicit: `{ chunk -> chunks.add(chunk) }` and `{ _: String -> }`
- **Files modified:** `AnthropicBackendTransportRoutingTest.kt`, `AnthropicModelErrorTest.kt`
- **Commit:** c2b1d4c (corrected before final RED commit)

## TDD Gate Compliance

| Gate | Commit | Status |
|------|--------|--------|
| RED — test files exist, compilation fails on unresolved AnthropicBackend | c2b1d4c | PASS |
| GREEN — AnthropicBackend implemented, all SC2/SC3 tests pass | bc874ea | PASS |
| Task 3 — AgentSettings + UI card + registration + 8-key encryption round-trip | 28829b6 | PASS |

## Verification Results

- `./gradlew test --tests "com.six2dez.burp.aiagent.backends.anthropic.*"` — SC2a/b/c + SC3: GREEN
- `./gradlew test --tests "com.six2dez.burp.aiagent.backends.BackendRegistryTest"` — registration: GREEN
- `./gradlew test --tests "com.six2dez.burp.aiagent.config.AgentSettingsSecretEncryptionTest"` — 8-key round-trip: GREEN
- `grep -E "okhttp3|OkHttpClient" AnthropicBackend.kt` — no output (SC2c clean)
- `./gradlew test` (full suite) — 367 tests, all GREEN (up from 358 pre-phase)
- SC1 (live streaming visible through proxy with real API key) — HUMAN-UAT only; not automated

## Known Stubs

None — all production fields, save/load, and UI wiring are fully implemented. The token-budget fields (`tokenBudgetWarnThreshold`, `tokenBudgetHardCap`) are declared and persisted but their enforcement logic ships in 14-02 (by design).

## Threat Flags

No new threat surface beyond what is documented in the plan's `<threat_model>`. All T-14-01 through T-14-SC mitigations applied:
- T-14-01: transport-routed HTTP, null fail-fast, SC2c source guard — verified by tests
- T-14-02: `anthropicApiKey` encrypted at rest (ENC1: envelope verified by round-trip test)
- T-14-03: body-shape-only logging copied verbatim from OpenAI analog
- T-14-04: fixed endpoint constant, no Base URL row on card (FLAG-14-02 applied)
- T-14-05: `x-api-key` + `anthropic-version` header, NOT Bearer
- T-14-06: Jackson `path()` null-safe parsing, only `content[].text` and usage ints consumed

## Self-Check: PASSED

Files verified:
- `src/main/kotlin/com/six2dez/burp/aiagent/backends/anthropic/AnthropicBackend.kt` — FOUND
- `src/main/kotlin/com/six2dez/burp/aiagent/backends/anthropic/AnthropicBackendFactory.kt` — FOUND
- `src/test/kotlin/com/six2dez/burp/aiagent/backends/anthropic/AnthropicBackendTransportRoutingTest.kt` — FOUND
- `src/test/kotlin/com/six2dez/burp/aiagent/backends/anthropic/AnthropicModelErrorTest.kt` — FOUND

Commits verified:
- c2b1d4c (RED tests) — FOUND
- bc874ea (GREEN implementation) — FOUND
- 28829b6 (AgentSettings + UI + tests) — FOUND
