---
phase: "07"
phase_name: "Proxy Transport + MCP Scope Hardening"
verified_at: "2026-05-27"
status: passed
score: 7/7 ROADMAP Success Criteria verified
re_verification:
  previous_status: none
  initial_verification: true
---

# Phase 07: Proxy Transport + MCP Scope Hardening — Verification Report

**Phase Goal (ROADMAP):** Close GitHub issue #69. All AI-backend HTTP traffic (health-check + chat) is routed through `MontoyaHttpTransport` so Burp's upstream proxy / SOCKS / cert store is honored; the chat-context builder respects a small-model defaults profile that fits 1278-token-class models; and the MCP server enforces an in-scope-only restriction across every tool that returns Burp HTTP data.

**Verified:** 2026-05-27
**Status:** passed
**Verifier:** Claude (gsd-verifier) — goal-backward against ROADMAP success criteria 1–7

## Per-Criterion Verdicts

### SC1 — healthCheck routes via MontoyaHttpTransport for every HTTP backend

**Verdict:** PASS

| Backend | healthCheck transport routing | Evidence |
| ------- | ----------------------------- | -------- |
| OpenAI-compatible | `transport.healthCheckGet(modelsUrl, headers, ...)` when injected | `src/main/kotlin/com/six2dez/burp/aiagent/backends/openai/OpenAiCompatibleBackend.kt:108-117` |
| Perplexity | inherits OpenAI-compatible (no override → routes via transport) | `src/main/kotlin/com/six2dez/burp/aiagent/backends/perplexity/PerplexityBackendFactory.kt`; supervisor passes `transport = httpTransport` for `perplexity` at `AgentSupervisor.kt:852` |
| NVIDIA NIM | `transport.post(...)` via `nimHealthCheck(settings, backendRef.get()?.healthCheckTransport())` | `src/main/kotlin/com/six2dez/burp/aiagent/backends/nvidia/NvidiaNimBackendFactory.kt:48, 94-108` |
| LM Studio | `transport.healthCheckGet(url, headers, ...)` when injected | `src/main/kotlin/com/six2dez/burp/aiagent/backends/lmstudio/LmStudioBackend.kt:76-84` |
| Ollama HTTP | `transport.healthCheckGet(url, headers, ...)` when injected | `src/main/kotlin/com/six2dez/burp/aiagent/backends/ollama/OllamaBackend.kt:95-103` |

Supervisor injection wires every concrete instance during init:

- `AgentSupervisor.kt:73` — `internal val httpTransport = MontoyaHttpTransport(api)`
- `AgentSupervisor.kt:90-100` — `registry.listAllBackendIds().mapNotNull { registry.get(it) }.forEach { when (b) { is OpenAiCompatibleBackend → b.setHealthCheckTransport(httpTransport); is LmStudioBackend → ...; is OllamaBackend → ... } }`. The NVIDIA NIM and Perplexity factories produce `OpenAiCompatibleBackend` instances, so the `is OpenAiCompatibleBackend` branch covers them too.

The OkHttp `HttpBackendSupport.healthCheckGet` is retained for unit tests only (transport==null path); production code paths always reach the supervisor-injected transport.

### SC2 — send() fails fast when transport == null; no OkHttp fallback

**Verdict:** PASS

- `OpenAiCompatibleBackend.send()` throws `IllegalStateException("MontoyaHttpTransport unavailable; AI HTTP backends require Burp's HTTP stack ...")` at `OpenAiCompatibleBackend.kt:195-200` before reaching any HTTP call.
- `LmStudioBackend.send()` mirrors the same guard at `LmStudioBackend.kt:156-161`.
- `grep -n "client.newCall" src/main/kotlin/com/six2dez/burp/aiagent/backends/openai/OpenAiCompatibleBackend.kt src/main/kotlin/com/six2dez/burp/aiagent/backends/lmstudio/LmStudioBackend.kt` → **0 matches** (the OkHttp branch is fully removed from production send paths).
- `grep -c "MontoyaHttpTransport unavailable"` in those two files → **1 each** (fail-fast message present in both).

Production wiring guarantees the guard is unreachable in real Burp sessions: `AgentSupervisor.buildLaunchConfig` passes `transport = httpTransport` for `ollama` (`AgentSupervisor.kt:734`), `lmstudio` (`:762`), `openai-compatible` (`:790`), `nvidia-nim` (`:821`), and `perplexity` (`:852`).

### SC3 — Unit tests assert OkHttp fallback unreachable + KDoc comment corrected

**Verdict:** PASS

- `src/test/kotlin/com/six2dez/burp/aiagent/backends/http/HttpBackendTransportRoutingTest.kt` (9 `@Test` methods):
  - `healthCheck routes OpenAiCompatible through transport` (line 42) — asserts `transport.get(modelsUrl, ...)` is invoked.
  - `healthCheck routes LmStudio through transport` (line 63).
  - `healthCheck routes Ollama through transport` (line 184).
  - `healthCheck routes NvidiaNim through transport via POST` (line 204).
  - `healthCheck NvidiaNim returns Unavailable when model blank without touching transport` (line 228).
  - `send fails fast when transport is null on OpenAi-compatible` (line 83) — asserts `IllegalStateException("MontoyaHttpTransport unavailable")` instead of any OkHttp call.
  - `send fails fast when transport is null on LmStudio` (line 121).
  - `buildClient KDoc declares test-only and does not claim proxy honoring` (line 158) — source-string guard: asserts the KDoc contains `"OkHttp client for unit tests only"` AND does NOT contain `"respects Burp/JVM proxy config"`.
  - `getter returns null before injection and the same instance after setHealthCheckTransport` (line 248).
- Source-string guard verified live: `grep -rn "respects Burp/JVM proxy config" src/main/kotlin/` → **0 matches**. The new KDoc at `HttpBackendSupport.kt:32-42` reads `"OkHttp client for unit tests only; does NOT honor Burp's upstream proxy config..."`.

### SC4 — MCP body-size spinner accepts 32 KB – 100 MB, denominated in KB

**Verdict:** PASS

- Spinner declaration `SettingsPanel.kt:229-240`:
  ```
  private val mcpMaxBodyKb = JSpinner(SpinnerNumberModel(
      (settings.mcpSettings.maxBodyBytes / 1024).coerceAtLeast(32),
      32, 102_400, 32,
  ))
  ```
  Range 32 to 102_400 = 32 KB to 100 MB. Step 32.
- Label `Max body size (KB)` at `McpConfigPanel.kt:81`.
- Tooltip `"Max tool output size in KB. Range 32 KB – 102400 KB (100 MB)."` at `SettingsPanel.kt:542`.
- Storage-layer clamp `AgentSettings.kt:1137`: `coerceIn(32 * 1024, 100 * 1024 * 1024)` — legacy stored values below 32 KB are clamped up; values above 100 MB clamped down.
- `currentSettings()` writes `maxBodyBytes = ((mcpMaxBodyKb.value as? Int) ?: 2048).coerceAtLeast(32) * 1024` (`SettingsPanel.kt:1006`).
- `applySettingsToUi()` reads `mcpMaxBodyKb.value = (updated.mcpSettings.maxBodyBytes / 1024).coerceAtLeast(32)` (`SettingsPanel.kt:1241`).
- `grep -n "Max body size (MB)" src/main/kotlin/` → **0 matches** (legacy label fully removed).

### SC5 — Small-model mode toggle caps ContextCollector to 1500/750

**Verdict:** PASS

- Setting: `AgentSettings.smallModelMode: Boolean = false` at `AgentSettings.kt:134`; pref key `KEY_CHAT_SMALL_MODEL_MODE = "chat.small.model.mode"` at `:775`; load/save plumbing at `:379, :629`; default `false` at `:478`.
- UI toggle: `chatSmallModelMode = ToggleSwitch(settings.smallModelMode)` at `SettingsPanel.kt:149`; placed in Backend section `addRowFull(profileGrid, "Small model mode", chatSmallModelMode)` at `:630`; persisted via `smallModelMode = chatSmallModelMode.isSelected` at `:1158`; refreshed at `:1209`.
- Cap source: `src/main/kotlin/com/six2dez/burp/aiagent/ui/UiActionsContextOptions.kt:14-29`:
  ```
  internal fun buildContextOptionsFromSettings(settings: AgentSettings): ContextOptions =
      ContextOptions(
          ...
          maxRequestBodyChars = if (settings.smallModelMode) SMALL_MODEL_REQUEST_BODY_MAX_CHARS else settings.contextRequestBodyMaxChars,
          maxResponseBodyChars = if (settings.smallModelMode) SMALL_MODEL_RESPONSE_BODY_MAX_CHARS else settings.contextResponseBodyMaxChars,
          ...
      )
  private const val SMALL_MODEL_REQUEST_BODY_MAX_CHARS = 1_500
  private const val SMALL_MODEL_RESPONSE_BODY_MAX_CHARS = 750
  ```
- Wiring chain: `UiActions.contextOptionsFromSettings` delegates to `buildContextOptionsFromSettings` → ContextOptions(1500, 750) → `ContextCollector.fromRequestResponses` consumes `options.maxRequestBodyChars/maxResponseBodyChars` at `ContextCollector.kt:42, 48` to truncate request/response bodies.

### SC6 — `mcpScopeOnly` setting + per-tool enforcement

**Verdict:** PASS

- Setting: `McpSettings.scopeOnly: Boolean = false` at `McpSettings.kt:32`; pref key `KEY_MCP_SCOPE_ONLY = "mcp.scope.only"` at `AgentSettings.kt:745`; load/save plumbing at `:1152, :1185`. No field on `AgentSettings` itself (correctly co-located on the `mcpSettings` sub-object).
- UI checkbox: `mcpScopeOnly = JCheckBox("Restrict MCP tools to in-scope hosts", settings.mcpSettings.scopeOnly)` at `SettingsPanel.kt:264-268`; row added in `McpConfigPanel.kt:66` as `addRowFull(grid, "Restrict to in-scope hosts", mcpScopeOnlyCheckbox)`; persisted via `scopeOnly = mcpScopeOnly.isSelected` at `SettingsPanel.kt:1018`; refreshed at `:1248`.
- Plumbing: `McpToolContext.scopeOnly: Boolean = false` field at `McpToolContext.kt:35`; populated by `McpRuntimeContextFactory.kt:46` with `scopeOnly = settings.scopeOnly`.
- Helper file: `src/main/kotlin/com/six2dez/burp/aiagent/mcp/tools/McpScopeFilter.kt` exists with `filterInScope` (two overloads), `rejectIfOutOfScope`, and `deriveScopeUrl` (added per Plan 07-03 deviation to avoid Burp static-factory dependency in tests).
- Per-tool enforcement in `src/main/kotlin/com/six2dez/burp/aiagent/mcp/tools/McpTools.kt`:
  - **6 read-style tools** filtered via `filterInScope`: `proxy_http_history` (line 1866), `proxy_http_history_regex` (line 1886), `proxy_ws_history` (line 1961), `proxy_ws_history_regex` (line 1980), `site_map` (line 1998), `site_map_regex` (line 2021).
  - **2 read-style tools** with OR'd per-call+global semantics: `proxy_history_annotate` (line 1902 — `input.scopeOnly || context.scopeOnly`), `response_body_search` (line 1929).
  - **6 write-style tools** with `rejectIfOutOfScope` short-circuit before the Burp sink: `http1_request` (line 1353), `http2_request` (line 1389), `repeater_tab` (line 1418), `repeater_tab_with_payload` (line 1435), `intruder` (line 1450), `intruder_prepare` (line 1467). Each rejection happens BEFORE any `api.http()/api.repeater()/api.intruder()` call.
- `grep -c "rejectIfOutOfScope" McpTools.kt` → exactly **6** (matching the success-criteria fixed count for write tools).
- WebSocket scope filter uses `ProxyWebSocketMessage.upgradeRequest().url()` — confirmed exposed by Montoya 2026.2 per Plan 07-03 SUMMARY.

### SC7 — Unit tests cover (a) transport.get for healthCheck, (b) small-model 1500/750, (c) per-tool short-circuit

**Verdict:** PASS

- **(a)** transport.get/post invocation for healthCheck: covered by `HttpBackendTransportRoutingTest` (9 @Test methods). See SC3 evidence.
- **(b)** small-model mode emits 1500/750: `src/test/kotlin/com/six2dez/burp/aiagent/context/SmallModelContextOptionsTest.kt` (3 @Test methods using fully-qualified `@org.junit.jupiter.api.Test`):
  - `contextOptionsRespectSmallModelMode_trueBranchCapsAt1500_750` (line 20-38) — asserts `1_500 / 750` for `smallModelMode=true`.
  - `contextOptionsRespectSmallModelMode_falseBranchPassesThroughVerbatim` (line 40-54).
  - `contextOptionsDefaultsAreUnchangedForFalse` (line 56-65) — asserts default `4_000 / 8_000`.
- **(c)** every scope-aware MCP tool short-circuits when out-of-scope: `src/test/kotlin/com/six2dez/burp/aiagent/mcp/tools/McpToolScopeEnforcementTest.kt` (24 @Test methods). Read tools: `proxyHttpHistory_scopeOn_*`, `proxyHistoryAnnotate_*`, `responseBodySearch_*`, `proxyWsHistory*`, `siteMap*` — each pair (scopeOn / scopeOff). Write tools: `http1Request_scopeOn_rejectsOutOfScopeAndNeverHitsApi` (line 260), `http2Request_scopeOn_*` (line 301), `repeaterTab_scopeOn_*` (line 319), `repeaterTabWithPayload_scopeOn_*` (line 334), `intruder_scopeOn_*` (line 349), `intruderPrepare_scopeOn_*` (line 364). Each write-tool test uses `verify(api.http(), never()).sendRequest(...)` / `verify(api.repeater(), never()).sendToRepeater(...)` / `verify(api.intruder(), never()).sendToIntruder(...)` to prove the short-circuit happens BEFORE any sink invocation.
- Additional coverage: `McpScopeFilterTest` (8 @Test methods) — unit tests for `filterInScope` / `rejectIfOutOfScope` semantics; `AgentSettingsMigrationTest` — adds `smallModelMode_roundTripsThroughSaveLoad`, `mcpBodyBytesBelow32KbIsClampedOnLoad`, `mcpBodyBytesAbove100MbIsClampedOnLoad`, `mcpScopeOnly_roundTripsThroughSaveLoad` (4 new @Test methods).

## Build + Test Verification

| Command | Exit | Notes |
| ------- | ---- | ----- |
| `./gradlew test` | 0 | 262 tests, 0 failures, 100% pass (build/reports/tests/test/index.html) |
| `./gradlew ktlintCheck` | 0 | BUILD SUCCESSFUL. Pre-existing warnings remain in unrelated files (CustomPromptLibraryEditor.kt, MainTab.kt, MarkdownRenderer.kt, ActiveScanQueuePanel.kt) — none introduced by Phase 7. |

## Phase-7-Specific Test Selection

| Command | Exit | Notes |
| ------- | ---- | ----- |
| `./gradlew test --tests HttpBackendTransportRoutingTest --tests SmallModelContextOptionsTest --tests McpScopeFilterTest --tests McpToolScopeEnforcementTest --tests AgentSettingsMigrationTest` | 0 | All Phase 7 tests green |

## Grep Matrix (live, on current HEAD)

| Check | Threshold | Actual | Result |
| ----- | --------- | ------ | ------ |
| `grep -n "client.newCall" .../OpenAiCompatibleBackend.kt .../LmStudioBackend.kt` | 0 | 0 | PASS |
| `grep -rn "respects Burp/JVM proxy config" src/main/kotlin/` | 0 | 0 | PASS |
| `grep -c "MontoyaHttpTransport unavailable" .../OpenAiCompatibleBackend.kt` | ≥1 | 1 | PASS |
| `grep -c "MontoyaHttpTransport unavailable" .../LmStudioBackend.kt` | ≥1 | 1 | PASS |
| `grep -c "setHealthCheckTransport" .../AgentSupervisor.kt` | ≥3 | 3 (one per HTTP backend type) | PASS |
| `grep -c "rejectIfOutOfScope" .../McpTools.kt` | exactly 6 | 6 | PASS |
| `grep -c "filterInScope" .../McpTools.kt` | ≥6 | 6 | PASS |
| `grep -c "scopeOnly \|\| context.scopeOnly" .../McpTools.kt` | ≥2 | 2 | PASS |
| `grep -c "@Test" HttpBackendTransportRoutingTest.kt` | ≥8 | 9 | PASS |
| `grep -c "@org.junit.jupiter.api.Test" SmallModelContextOptionsTest.kt` | ≥2 | 3 | PASS |
| `grep -c "@Test" McpScopeFilterTest.kt` | ≥4 | 8 | PASS |
| `grep -c "@Test" McpToolScopeEnforcementTest.kt` | ≥14 | 24 | PASS |
| `grep -n "Max body size (MB)" src/main/kotlin/` | 0 | 0 | PASS |
| `grep -n "Max body size (KB)" .../McpConfigPanel.kt` | ≥1 | 1 | PASS |
| Spinner range in SettingsPanel.kt | 32, 102_400 | 32, 102_400 | PASS |
| Storage clamp `coerceIn(32 * 1024, 100 * 1024 * 1024)` | present | present (`AgentSettings.kt:1137`) | PASS |
| `KEY_MCP_SCOPE_ONLY = "mcp.scope.only"` | present | `AgentSettings.kt:745` | PASS |
| `McpSettings.scopeOnly: Boolean = false` | present | `McpSettings.kt:32` | PASS |
| `McpToolContext.scopeOnly` | present | `McpToolContext.kt:35` | PASS |
| `McpRuntimeContextFactory.create` passes `scopeOnly = settings.scopeOnly` | present | `McpRuntimeContextFactory.kt:46` | PASS |

## Goal Achievement Summary

All seven ROADMAP Success Criteria are verified in the merged codebase:

| # | Truth | Status |
| - | ----- | ------ |
| 1 | healthCheck for every HTTP backend routes via MontoyaHttpTransport (OkHttp removed from production) | PASS |
| 2 | OpenAi/LmStudio send() has no OkHttp fallback; transport==null fails fast | PASS |
| 3 | Unit tests prove fallback unreachable + KDoc corrected | PASS |
| 4 | MCP "Max body size" spinner accepts 32 KB to 100 MB (KB-denominated) | PASS |
| 5 | smallModelMode toggle caps ContextCollector to 1500/750 chars | PASS |
| 6 | mcpScopeOnly setting + per-tool enforcement (6 read filtered, 6 write reject, 2 OR'd) | PASS |
| 7 | Unit tests cover (a) transport.get healthCheck, (b) small-model 1500/750, (c) per-tool short-circuit | PASS |

**Score:** 7 / 7 ROADMAP Success Criteria verified.

The phase goal — closing GitHub issue #69's four sub-concerns (transport, body-cap, small-model, MCP scope) — is achieved end-to-end:
- Production AI HTTP traffic now flows through Burp's `api.http().sendRequest(...)`, honoring upstream proxy / SOCKS / cert store and appearing in Burp Proxy history.
- The MCP body-size cap is configurable down to 32 KB so 1278-token-class models can consume tool output without OOMing the model's context.
- A one-click "Small model mode" toggle shrinks chat-context bodies to 1500 / 750 chars.
- MCP tools (8 read-style, 6 write-style) consult `api.scope().isInScope(...)` when the global toggle is on, with backwards-compatible default OFF.

No gaps. No human verification items required for this phase — all seven criteria are programmatically verifiable in the codebase, and the test suite (`262 tests, 0 failures`) plus ktlint check (`BUILD SUCCESSFUL`) confirm wired behaviour.

_Verified: 2026-05-27_
_Verifier: Claude (gsd-verifier)_
