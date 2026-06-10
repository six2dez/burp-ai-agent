---
phase: 14-anthropic-backend-token-budget-listener-port
verified: 2026-06-10T18:35:00Z
status: passed
score: 9/9 automated must-haves verified
overrides_applied: 0
human_uat_deferred: true
human_uat_note: "All 9 automated must-haves verified (399 tests). The 4 live-API/Swing smoke tests below were deferred-and-accepted by the maintainer (2026-06-10, 'defer all remaining' policy for this autonomous run) and are tracked as pending in 14-HUMAN-UAT.md; they surface in /gsd-progress and /gsd-audit-uat until tested with a live Anthropic key in a running Burp."
human_verification:
  - test: "Select Anthropic in Settings > Backend, enter a real API key, send a message, and confirm the response appears in Burp Proxy > HTTP history as a single POST to https://api.anthropic.com/v1/messages"
    expected: "Response text rendered in the chat UI; the request appears in Burp's HTTP history tab with the correct endpoint URL and x-api-key/anthropic-version headers"
    why_human: "SC1 live streaming requires a real Anthropic API key and a running Burp instance — cannot be exercised in a headless test context"
  - test: "With a real API key configured, set Model to 'bogus-model-id-xyz' and send any message; confirm the error displayed matches exactly: 'Anthropic rejected the model ID — check Settings > Anthropic > Model'"
    expected: "The exact SC3 string appears in the chat error display (live confirmation that the real Anthropic 400 body contains the word 'model' and triggers the guard)"
    why_human: "The exact-string mapping is unit-tested (AnthropicModelErrorTest passes), but confirming the real Anthropic 400 response body contains 'model' requires a live API key"
  - test: "From an MCP client, call proxy_http_history with listener_port set to a port that has no history (e.g., 9876) and confirm an empty result is returned without an error message"
    expected: "Empty list or empty response body, no 'Error:' prefix"
    why_human: "SC5 live MCP client confirmation against a real Burp listener — the filter logic is fully tested by ProxyHistoryListenerPortFilterTest but live integration with a running Burp MCP server is not automatable in unit tests"
  - test: "Set warn threshold to 100 tokens and hard cap to 500 tokens in Settings; perform AI interactions until session tokens exceed 100; confirm an amber WARN banner appears in the chat panel; continue until tokens exceed 500 and confirm the banner turns red (RISK level) and passive scanning stops responding to new proxy traffic"
    expected: "WARN banner visible at warn threshold (amber); RISK banner at cap (red); passive scanner does not enqueue new items after cap is reached; chat remains usable throughout"
    why_human: "SC4 banner visual rendering (WARN/RISK colors, SubtleNotice.Level.WARN vs RISK) and the passive scanner's observable behavior in a live Burp session require a running Burp instance with the extension loaded"
---

# Phase 14: Anthropic Backend + Token Budget + Listener Port — Verification Report

**Phase Goal:** Users can select a native Anthropic Messages API backend (encrypted key, editable model, streaming via MontoyaHttpTransport, token counting, specific model-error message); per-session token-budget guardrails (warn + hard cap, scanner pauses at cap, chat warn banner); MCP proxy_http_history filterable by Burp listener port.
**Verified:** 2026-06-10T18:35:00Z
**Status:** human_needed
**Re-verification:** No — initial verification

## Goal Achievement

### Observable Truths

| # | Truth | Status | Evidence |
|---|-------|--------|----------|
| 1 | AnthropicBackend.kt contains no okhttp3/OkHttpClient reference on the production path (SC2c) | VERIFIED | `grep -E "okhttp3\|OkHttpClient" AnthropicBackend.kt` returns no output; AnthropicBackendTransportRoutingTest SC2c source-string guard passes (3/3 tests green) |
| 2 | send() with a null transport fails fast with "MontoyaHttpTransport unavailable" — no OkHttp fallback (SC2b) | VERIFIED | Lines 131-135 in AnthropicBackend.kt: `if (transport == null) throw IllegalStateException("MontoyaHttpTransport unavailable; …")`; AnthropicBackendTransportRoutingTest SC2b asserts exact message prefix, passes |
| 3 | A 400 whose body contains "model" surfaces the exact string: "Anthropic rejected the model ID — check Settings > Anthropic > Model" (SC3) | VERIFIED | Line 191 in AnthropicBackend.kt contains the exact CONTEXT.md string; AnthropicModelErrorTest.`send returns exact SC3 string when 400 body contains model` uses `assertEquals(sc3ErrorMessage, err.message)` and passes (1/1 tests green) |
| 4 | anthropicApiKey is encrypted at rest via SecretCipher under KEY_ANTHROPIC_API_KEY and is in the schema-V4 secret-migration list (SEC) | VERIFIED | AgentSettings.kt L296: `cipher.decrypt(…, KEY_ANTHROPIC_API_KEY)`; L563: `cipher.encrypt(settings.anthropicApiKey, KEY_ANTHROPIC_API_KEY)`; L735: KEY_ANTHROPIC_API_KEY in migrateToSchemaV4 secretKeys list; AgentSettingsSecretEncryptionTest extended to 8 keys, asserts ENC1: envelope + round-trip, passes |
| 5 | AnthropicBackendFactory is registered via both META-INF/services and the BackendRegistry fallback list (id "anthropic") | VERIFIED | META-INF/services contains `com.six2dez.burp.aiagent.backends.anthropic.AnthropicBackendFactory` as last line; BackendRegistry.kt L15 imports AnthropicBackendFactory, L63 adds `AnthropicBackendFactory()` to fallback list; BackendRegistryTest `anthropicBackend_registeredWithCorrectId` passes |
| 6 | AgentSupervisor "anthropic" branch builds x-api-key/anthropic-version headers + injects httpTransport (SC2 wiring) | VERIFIED | AgentSupervisor.kt L855-877: `"anthropic" ->` branch constructs `mapOf("x-api-key" to apiKey, "anthropic-version" to "2023-06-01")` and sets `transport = httpTransport` |
| 7 | BudgetGuard {OFF, WARN, CAP} is AWT-free; off-by-default (warn=0/cap=0 → OFF); both thresholds default 0; pauseability in scanner (SC4a/SC4b/SC4c) | VERIFIED | BudgetGuard.kt has no java.awt/javax.swing imports; `evaluate(…, 0, 0)` always returns OFF (BudgetGuardTest 10/10 green); PassiveAiScannerBudgetPauseTest 12/12 green covering: enqueue no-op when paused, KB not cleared, isEnabled() unchanged, manualScan returns 0 when paused |
| 8 | The passive scanner pauses at hard cap via budgetPaused AtomicBoolean on BOTH auto-scan (enqueueForScanCheck) and manualScan paths — does NOT call setEnabled or clear ScanKnowledgeBase (SC4b) | VERIFIED | PassiveAiScanner.kt L356: `if (budgetPaused.get()) return` in enqueueForScanCheck; L557: `if (budgetPaused.get()) { …return 0 }` in manualScan; setEnabled is untouched in both paths; PassiveAiScannerBudgetPauseTest `manualScan_whenBudgetPaused_isNoOpAndReturnsZero` passes |
| 9 | proxy_http_history listener_port filter applied to BOTH dispatch paths (paginated ~L649 and manual decode ~L1860); no-match returns empty list not error; unset returns all (SC5) | VERIFIED | McpTools.kt L658: `.let { s -> if (listenerPort != null) s.filter { it.listenerPort() == listenerPort } else s }` (paginated path); L1871: identical filter on manual path; `grep -c "it.listenerPort() ==" McpTools.kt` = 2; ProxyHistoryListenerPortFilterTest 7/7 green (both paths A+B, no-match, unset-all cases) |

**Score:** 9/9 automated truths verified

### Human-only truths (SC1 live streaming)

SC1 (live Anthropic API streaming visible in Burp Proxy history) is designated HUMAN-UAT only per 14-VALIDATION.md and the verification focus note. It is not counted in the automated score.

### Deferred Items

The following items are explicitly deferred per REQUIREMENTS.md CAP-01 annotation and 14-CONTEXT.md:

| Item | Addressed In | Evidence |
|------|-------------|---------|
| Native tool-use and prompt-caching | Future phase (unscheduled) | REQUIREMENTS.md CAP-01 annotation: "native tool-use and prompt-caching deferred to a future phase — not in SC1–SC5, recorded in 14-CONTEXT.md Deferred Ideas" |
| 429/5xx error handling via recordFailure | Phase 17 (REL-03) | 14-REVIEW-FIX.md: "429/5xx-not-via-recordFailure deferred to Phase 17 REL-03" |

### Required Artifacts

| Artifact | Expected | Status | Details |
|----------|----------|--------|---------|
| `src/main/kotlin/com/six2dez/burp/aiagent/backends/anthropic/AnthropicBackend.kt` | Anthropic Messages API backend; transport-routed, SC3 model-error string, SC2b fail-fast | VERIFIED | 304 lines; no okhttp3 import; `transport.post(ANTHROPIC_MESSAGES_URL, …)` is the only HTTP call; exact SC3 string at L191; null-transport guard at L131 |
| `src/main/kotlin/com/six2dez/burp/aiagent/backends/anthropic/AnthropicBackendFactory.kt` | AiBackendFactory create() returns AnthropicBackend() | VERIFIED | 7 lines; `override fun create(): AiBackend = AnthropicBackend()` |
| `src/main/kotlin/com/six2dez/burp/aiagent/config/AgentSettings.kt` | anthropicModel/anthropicApiKey/tokenBudgetWarnThreshold/tokenBudgetHardCap fields; KEY_ANTHROPIC_API_KEY; encrypted load/save; migration entry | VERIFIED | All four fields present with defaults at L64-70; KEY_ANTHROPIC_API_KEY at L817; cipher.decrypt at L296, cipher.encrypt at L563; migration list at L735 |
| `src/main/resources/META-INF/services/com.six2dez.burp.aiagent.backends.AiBackendFactory` | ServiceLoader registration for AnthropicBackendFactory | VERIFIED | Last line: `com.six2dez.burp.aiagent.backends.anthropic.AnthropicBackendFactory` |
| `src/main/kotlin/com/six2dez/burp/aiagent/util/BudgetGuard.kt` | AWT-free object: enum State{OFF,WARN,CAP}; evaluate(used,warn,cap); currentSessionTokens() | VERIFIED | 57 lines; no AWT/Swing imports; `enum class State` defined; `fun evaluate(…)` at L40; `fun currentSessionTokens()` at L54 |
| `src/main/kotlin/com/six2dez/burp/aiagent/scanner/PassiveAiScanner.kt` | budgetPaused AtomicBoolean; setBudgetPaused/isBudgetPaused; gate in enqueueForScanCheck AND manualScan | VERIFIED | budgetPaused at L66; gate at L356 (enqueueForScanCheck) and L557 (manualScan); setBudgetPaused/isBudgetPaused at L68-69 |
| `src/main/kotlin/com/six2dez/burp/aiagent/ui/ChatPanel.kt` | budgetNotice SubtleNotice at BorderLayout.NORTH; budget check after TokenTracker.record; passiveScanner constructor param | VERIFIED | budgetNotice at L116; added to chatContainer at L248; budget check block at L585-605; `passiveScanner: PassiveAiScanner? = null` constructor param at L84 |
| `src/main/kotlin/com/six2dez/burp/aiagent/ui/panels/PassiveScanConfigPanel.kt` | Token budget section rendering warn/cap fields | VERIFIED | Constructor params tokenBudgetWarnField/tokenBudgetHardCapField at L53-54; section built at L293-321 with "Token budget" title |
| `src/main/kotlin/com/six2dez/burp/aiagent/mcp/tools/McpTools.kt` | listenerPort:Int? on GetProxyHttpHistory + GetProxyHttpHistoryRestricted; .filter in both seq pipelines | VERIFIED | L2725: `val listenerPort: Int? = null` on GetProxyHttpHistory; L2732: same on GetProxyHttpHistoryRestricted; L658: paginated filter; L1871: manual decode filter |

### Key Link Verification

| From | To | Via | Status | Details |
|------|----|-----|--------|---------|
| `supervisor/AgentSupervisor.kt` | `backends/anthropic/AnthropicBackend.kt` | `"anthropic" ->` branch builds x-api-key/anthropic-version headers + transport=httpTransport | WIRED | L855-877: branch confirmed, `mapOf("x-api-key" to apiKey, "anthropic-version" to "2023-06-01")`, `transport = httpTransport` |
| `backends/anthropic/AnthropicBackend.kt` | `https://api.anthropic.com/v1/messages` | `transport.post(ANTHROPIC_MESSAGES_URL, …)` — the only HTTP call | WIRED | L185: `transport.post(ANTHROPIC_MESSAGES_URL, allHeaders, json, …)` confirmed as sole HTTP call |
| `config/AgentSettings.kt` | `SecretCipher` | `cipher.encrypt/decrypt` under `KEY_ANTHROPIC_API_KEY` | WIRED | L296: decrypt on load; L563: encrypt on save; both use KEY_ANTHROPIC_API_KEY constant |
| `ui/panels/BackendConfigPanel.kt` | `ui/SettingsPanel.kt` | anthropicModel/anthropicApiKey threaded through BackendConfigState into AgentSettings | WIRED | BackendConfigPanel L287-288: reads from fields; SettingsPanel L1135-1136: maps into AgentSettings construction |
| `ui/ChatPanel.kt` | `util/BudgetGuard.kt` | `BudgetGuard.evaluate(…)` drives banner level (via passiveScanner.reconcileBudget or direct) | WIRED | ChatPanel L591-593: `passiveScanner?.reconcileBudget(s) ?: BudgetGuard.evaluate(used, warn, cap)` |
| `ui/ChatPanel.kt` | `scanner/PassiveAiScanner.kt` | `reconcileBudget(s)` calls `setBudgetPaused(true)` at CAP | WIRED | PassiveAiScanner.kt L92: `setBudgetPaused(state == BudgetGuard.State.CAP)` inside reconcileBudget; ChatPanel calls reconcileBudget at L592 |
| `scanner/PassiveAiScanner.kt enqueueForScanCheck` | budgetPaused gate | `if (budgetPaused.get()) return` | WIRED | L356: line immediately after enabled check, exactly as specified |
| `scanner/PassiveAiScanner.kt manualScan` | budgetPaused gate | `if (budgetPaused.get()) { …return 0 }` | WIRED | L557: gate before any executor submission in manualScan |
| `ui/MainTab.kt` | `ui/ChatPanel.kt` | `passiveAiScanner` threaded into ChatPanel constructor as `passiveScanner = passiveAiScanner` | WIRED | MainTab.kt L109-110: `passiveScanner = passiveAiScanner` in ChatPanel construction |
| `ui/SettingsPanel.kt currentSettings()` | `AgentSettings.tokenBudgetWarnThreshold/tokenBudgetHardCap` | warn/cap JTextField parsed via `toIntOrNull() ?: 0` | WIRED | SettingsPanel L1137-1138: `tokenBudgetWarnThreshold = tokenBudgetWarnField.text.trim().toIntOrNull()?.coerceAtLeast(0) ?: 0` and same for hardCap |
| `mcp/tools/McpTools.kt GetProxyHttpHistory (paginated path)` | `ProxyHttpRequestResponse.listenerPort()` | `.filter { it.listenerPort() == listenerPort }` | WIRED | L658: `.let { s -> if (listenerPort != null) s.filter { it.listenerPort() == listenerPort } else s }` |
| `mcp/tools/McpTools.kt manual decode path` | `ProxyHttpRequestResponse.listenerPort()` | `input.listenerPort != null` filter | WIRED | L1871: `.let { s -> if (input.listenerPort != null) s.filter { it.listenerPort() == input.listenerPort } else s }` |

### Data-Flow Trace (Level 4)

| Artifact | Data Variable | Source | Produces Real Data | Status |
|----------|---------------|--------|-------------------|--------|
| ChatPanel.kt | budgetNotice (banner state) | `BudgetGuard.currentSessionTokens()` → `TokenTracker.snapshot()` → real accumulated token counts | Yes — TokenTracker accumulates actual input/output tokens across backends | FLOWING |
| AnthropicBackend.kt | response content | `transport.post(…)` → Anthropic API response body → `content[].text` parse | Yes — real HTTP response from transport | FLOWING |
| McpTools.kt | proxy_http_history items | `api.proxy().history()` → Montoya API real proxy history | Yes — live Burp proxy data | FLOWING |

### Behavioral Spot-Checks

| Behavior | Command | Result | Status |
|----------|---------|--------|--------|
| No okhttp3 in AnthropicBackend | `grep -E "okhttp3\|OkHttpClient" AnthropicBackend.kt` | No output (exit 1) | PASS |
| SC3 exact error string present | `grep -n "Anthropic rejected the model ID" AnthropicBackend.kt` | L191 matches | PASS |
| listener_port filter count = 2 (both paths) | `grep -c "it.listenerPort() == " McpTools.kt` | 2 | PASS |
| Full test suite | `./gradlew test` (399 tests, 0 failures) | BUILD SUCCESSFUL | PASS |
| Phase-14 test files pass | AnthropicBackendTransportRoutingTest (3), AnthropicModelErrorTest (1), BudgetGuardTest (10), PassiveAiScannerBudgetPauseTest (12), ProxyHistoryListenerPortFilterTest (7) | All 33 tests pass, 0 failures | PASS |

### Requirements Coverage

| Requirement | Source Plan | Description | Status | Evidence |
|-------------|------------|-------------|--------|----------|
| CAP-01 | 14-01-PLAN.md | Native Anthropic Messages API backend with streaming, token counting, encrypted key, model selection | SATISFIED | AnthropicBackend.kt + AnthropicBackendFactory.kt implemented; transport-routed; SC2/SC3 tests pass; encrypted key in migration list |
| CAP-03 | 14-03-PLAN.md | Filter MCP proxy-history by Burp listener port | SATISFIED | McpTools.kt has listenerPort filter on both dispatch paths; ProxyHistoryListenerPortFilterTest 7/7 green |
| CAP-04 | 14-02-PLAN.md | Per-session token-budget guardrails (warn/cap, scanner pause, chat banner) | SATISFIED | BudgetGuard.kt; scanner budgetPaused gate in enqueueForScanCheck + manualScan; ChatPanel banner; BudgetGuardTest + PassiveAiScannerBudgetPauseTest all green |

### Anti-Patterns Found

No blockers or debt markers found. Scan of all phase-14 modified production files (AnthropicBackend.kt, AnthropicBackendFactory.kt, BudgetGuard.kt, PassiveAiScanner.kt, McpTools.kt, AgentSettings.kt, BackendConfigPanel.kt, SettingsPanel.kt, PassiveScanConfigPanel.kt, ChatPanel.kt, MainTab.kt, BackendRegistry.kt, AgentSupervisor.kt) returned zero hits for: TBD, FIXME, XXX, TODO, HACK, PLACEHOLDER, "not yet implemented", "coming soon".

| File | Line | Pattern | Severity | Impact |
|------|------|---------|---------|--------|
| (none) | — | — | — | — |

### Human Verification Required

#### 1. Live Anthropic Streaming (SC1)

**Test:** Select "Anthropic" in Settings > Backend, enter a real Anthropic API key in the masked field (confirm it is masked), enter model "claude-sonnet-4-6", then send a message from the Chat panel.
**Expected:** A text response appears in the chat UI; the request is visible in Burp Proxy > HTTP history as a POST to `https://api.anthropic.com/v1/messages` with headers `x-api-key` and `anthropic-version: 2023-06-01`.
**Why human:** Requires a live Anthropic API key and a running Burp Suite instance. The transport routing, header construction, and response rendering involve the Burp extension runtime which cannot be exercised headlessly.

#### 2. Live Model-Error Confirmation (SC3 live)

**Test:** With a real API key, set Model to "bogus-model-id-xyz" and send a message.
**Expected:** The chat error displays exactly: `Anthropic rejected the model ID — check Settings > Anthropic > Model`
**Why human:** Confirms the real Anthropic API returns a 400 body containing "model", which is the trigger condition in the code. The exact-string mapping is fully unit-tested; this confirms the trigger fires against the real endpoint.

#### 3. Live MCP listener_port filter (SC5 live)

**Test:** From an MCP client (e.g., via the MCP server at 127.0.0.1), call `proxy_http_history` with `{"count": 10, "listener_port": 9876}` (a port with no history).
**Expected:** Empty response body (no items), no "Error:" prefix.
**Why human:** Live MCP client integration against a running Burp MCP server cannot be exercised in unit tests.

#### 4. Budget Banner Visual + Scanner Pause (SC4 live)

**Test:** Set warn threshold to 100 tokens and hard cap to 500 tokens in Settings > Passive AI Scanner > Token budget. Perform AI interactions until session token count (visible in usage footer) exceeds 100, then continues to 500.
**Expected:** At 100+ tokens: amber WARN banner appears in chat panel. At 500+ tokens: banner turns red (RISK level), text reads "Token budget reached (…/…). Passive scanning paused; chat is still available." Passive scanner stops processing new proxy traffic; chat UI remains fully functional.
**Why human:** SubtleNotice.Level visual rendering (amber vs red colors), and the observable behavior of the passive scanner (not enqueuing proxy traffic after the cap) require a live Burp session.

### Gaps Summary

No automated gaps found. All 9 automated must-haves are VERIFIED. The 4 human-verification items all require a live Burp instance with a real Anthropic API key and are the only items blocking a `passed` status.

The scope exclusions noted in the verification focus are confirmed as non-gaps: native tool-use and prompt-caching are explicitly deferred per REQUIREMENTS.md CAP-01 annotation; 429/5xx handling via recordFailure is deferred to Phase 17 REL-03 (per 14-REVIEW-FIX.md); per-token streaming is a known architectural limitation of MontoyaHttpTransport documented as the correct and locked behavior.

---

_Verified: 2026-06-10T18:35:00Z_
_Verifier: Claude (gsd-verifier)_
