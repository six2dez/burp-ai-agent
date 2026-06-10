---
phase: 14-anthropic-backend-token-budget-listener-port
reviewed: 2026-06-10T17:52:44Z
depth: standard
files_reviewed: 20
files_reviewed_list:
  - src/main/kotlin/com/six2dez/burp/aiagent/backends/anthropic/AnthropicBackend.kt
  - src/main/kotlin/com/six2dez/burp/aiagent/backends/anthropic/AnthropicBackendFactory.kt
  - src/main/kotlin/com/six2dez/burp/aiagent/backends/BackendRegistry.kt
  - src/main/kotlin/com/six2dez/burp/aiagent/supervisor/AgentSupervisor.kt
  - src/main/kotlin/com/six2dez/burp/aiagent/config/AgentSettings.kt
  - src/main/kotlin/com/six2dez/burp/aiagent/util/BudgetGuard.kt
  - src/main/kotlin/com/six2dez/burp/aiagent/scanner/PassiveAiScanner.kt
  - src/main/kotlin/com/six2dez/burp/aiagent/ui/ChatPanel.kt
  - src/main/kotlin/com/six2dez/burp/aiagent/ui/MainTab.kt
  - src/main/kotlin/com/six2dez/burp/aiagent/ui/panels/BackendConfigPanel.kt
  - src/main/kotlin/com/six2dez/burp/aiagent/ui/panels/PassiveScanConfigPanel.kt
  - src/main/kotlin/com/six2dez/burp/aiagent/ui/SettingsPanel.kt
  - src/main/kotlin/com/six2dez/burp/aiagent/mcp/tools/McpTools.kt
  - src/test/kotlin/com/six2dez/burp/aiagent/backends/anthropic/AnthropicBackendTransportRoutingTest.kt
  - src/test/kotlin/com/six2dez/burp/aiagent/backends/anthropic/AnthropicModelErrorTest.kt
  - src/test/kotlin/com/six2dez/burp/aiagent/util/BudgetGuardTest.kt
  - src/test/kotlin/com/six2dez/burp/aiagent/scanner/PassiveAiScannerBudgetPauseTest.kt
  - src/test/kotlin/com/six2dez/burp/aiagent/mcp/tools/ProxyHistoryListenerPortFilterTest.kt
  - src/test/kotlin/com/six2dez/burp/aiagent/config/AgentSettingsSecretEncryptionTest.kt
  - src/test/kotlin/com/six2dez/burp/aiagent/backends/BackendRegistryTest.kt
findings:
  critical: 0
  warning: 5
  info: 4
  total: 9
status: issues_found
---

# Phase 14: Code Review Report

**Reviewed:** 2026-06-10T17:52:44Z
**Depth:** standard
**Files Reviewed:** 20
**Status:** issues_found

## Summary

Reviewed the Anthropic Messages API backend (CAP-01), the token-budget guardrail (CAP-04),
and the proxy-history listener-port filter (CAP-03), plus the supervisor wiring, settings
encryption/migration, UI panels, and the accompanying tests.

The security-sensitive surfaces are in good shape:
- **SC2 (transport routing):** `AnthropicBackend` fails fast on `transport == null`, routes all
  HTTP through the injected `MontoyaHttpTransport`, and constructs no OkHttp client. Verified by
  source-string + behavioral tests.
- **SC3 (model-rejection):** the exact CONTEXT.md string is emitted before the generic handler.
- **Headers:** the supervisor builds `x-api-key` + `anthropic-version` (not Bearer); the key is
  sourced from encrypted settings and never logged (only shape/byte-count is logged, Bug #66).
- **Secrets:** `anthropicApiKey` is encrypted via `SecretCipher(KEY_ANTHROPIC_API_KEY)`, added to
  the v4 migration list, defaulted, and covered by the 8-key round-trip + fail-soft tests.
- **Token-budget params** are persisted as plain integers (never `SecretCipher`), matching Pitfall 5.
- **Pitfall 3 (pause gate):** `budgetPaused` is a separate `AtomicBoolean`; the no-op enqueue path
  does not clear the knowledge base or flip `isEnabled()` — verified by tests.
- **MCP param naming:** `listenerPort` (camelCase) is **consistent** with every other MCP tool
  parameter (`includeUnpreprocessedResponse`, `targetHostname`, `targetPort`, `baseUrl`,
  `typicalSeverity`, …). No inconsistency — the review-focus note can be closed as a non-issue.

The findings below are correctness/robustness gaps in the CAP-04 budget feature (enforcement only
fires on the chat path, and the pause latch is never released) and a few smaller robustness items.
No blockers.

## Warnings

### WR-01: Token-budget hard cap is never enforced on the scanner-only path

**File:** `src/main/kotlin/com/six2dez/burp/aiagent/scanner/PassiveAiScanner.kt:967-972`
(see also `src/main/kotlin/com/six2dez/burp/aiagent/ui/ChatPanel.kt:567-594`)

**Issue:** The only place that evaluates `BudgetGuard.evaluate(...)` and calls
`passiveScanner.setBudgetPaused(true)` is the chat `onComplete` callback in `ChatPanel`
(ChatPanel.kt:576-587). The passive scanner records its own token consumption via
`TokenTracker.record(flow = "passive_scanner", …)` at `PassiveAiScanner.kt:967` and `:819`, but it
**never evaluates the budget**. `BudgetGuard.currentSessionTokens()` sums all flows including the
scanner's, yet nothing on the scanner path reads it. Consequence: a user who runs the passive
scanner without ever sending a chat turn will blow past the configured hard cap indefinitely — the
"pause passive scanning at the cap" guarantee silently does not hold for the scanner-driven case,
which is exactly the workload most likely to burn tokens unattended.

**Fix:** Evaluate the budget inside the scanner after recording tokens and self-pause, e.g. in
`doAnalysis` right after the `TokenTracker.record(...)` at line 967:
```kotlin
TokenTracker.record(flow = "passive_scanner", backendId = settings.preferredBackendId,
    inputChars = singlePrompt.length, outputChars = responseBuffer.length)
val cap = settings.tokenBudgetHardCap
if (cap > 0 && BudgetGuard.evaluate(BudgetGuard.currentSessionTokens(), settings.tokenBudgetWarnThreshold, cap) == BudgetGuard.State.CAP) {
    setBudgetPaused(true)
    api.logging().logToOutput("[PassiveAiScanner] Token hard cap reached — pausing passive scanning")
}
```
(The batch-flush path that also calls `TokenTracker.record` should gate the same way.)

### WR-02: Budget pause is a one-way latch — never released within a process

**File:** `src/main/kotlin/com/six2dez/burp/aiagent/ui/ChatPanel.kt:581-592`
(contract claim: `src/main/kotlin/com/six2dez/burp/aiagent/scanner/PassiveAiScanner.kt:64-67`,
`src/main/kotlin/com/six2dez/burp/aiagent/util/BudgetGuard.kt:14-17`)

**Issue:** `setBudgetPaused(true)` is the only mutation of the gate anywhere in `main/` — there is
**no caller of `setBudgetPaused(false)`** (confirmed by grep across the source tree). The WARN and
OFF branches of the `when (BudgetGuard.evaluate(...))` block in ChatPanel do nothing to the
scanner. `applyPassiveAiSettings()` (SettingsPanel.kt:1615) does not reset it either. So once the
hard cap is hit, passive scanning stays paused for the entire Burp run even if the user raises the
cap, sets it to 0 (unlimited/off), or the session token count is otherwise no longer over the cap.
This contradicts the KDoc on `PassiveAiScanner.budgetPaused` ("reversible") and the BudgetGuard
"never surprise-blocks" framing — the only way to resume is to restart Burp. Because the budget is
per-process and monotonic, even legitimately disabling the guardrail mid-session cannot recover.

**Fix:** Make the gate track the current `BudgetGuard.State` rather than latching. In the ChatPanel
`when`, drive both directions:
```kotlin
when (BudgetGuard.evaluate(used, warn, cap)) {
    BudgetGuard.State.CAP -> { /* banner */ passiveScanner?.setBudgetPaused(true) }
    BudgetGuard.State.WARN -> { /* banner */ passiveScanner?.setBudgetPaused(false) }
    BudgetGuard.State.OFF -> { budgetNotice.hideNotice(); passiveScanner?.setBudgetPaused(false) }
}
```
and additionally clear it when the cap is lowered/cleared in `applyPassiveAiSettings()` (e.g.
`if (currentSettings().tokenBudgetHardCap == 0) passiveAiScanner.setBudgetPaused(false)`).

### WR-03: Budget banner only refreshes on a chat turn, so the cap can be exceeded without notice

**File:** `src/main/kotlin/com/six2dez/burp/aiagent/ui/ChatPanel.kt:576-594`

**Issue:** The budget evaluation is wired exclusively into the chat `sendChat` completion callback.
Scanner activity (which also feeds `TokenTracker`) advances `currentSessionTokens()` but never
triggers a re-evaluation, so the RISK/WARN banner shown to the user is stale until the next chat
message is sent. Combined with WR-01, a scanner-heavy session can be far over the hard cap while
the UI still shows OFF/WARN. Even ignoring the enforcement gap, the user-facing budget indicator is
not a reliable reflection of session spend.

**Fix:** Drive the banner from a lightweight timer (there is already a 30s `sessionPersistTimer` in
`MainTab` and a 2s `statusRefreshTimer` in `SettingsPanel`) or from a `TokenTracker` change hook,
so the budget state is recomputed independent of chat turns. Re-use the same
`BudgetGuard.evaluate(currentSessionTokens(), warn, cap)` mapping on the EDT.

### WR-04: Anthropic launch silently accepts a blank/empty API key and only fails at HTTP time

**File:** `src/main/kotlin/com/six2dez/burp/aiagent/supervisor/AgentSupervisor.kt:855-877`
(see also `src/main/kotlin/com/six2dez/burp/aiagent/backends/anthropic/AnthropicBackend.kt:38-53`)

**Issue:** When `anthropicApiKey` is blank, the supervisor still builds
`headers = mapOf("x-api-key" to "", "anthropic-version" to "2023-06-01")` and launches the
connection. `AnthropicBackend` inherits the default `isAvailable() = true` (BackendTypes.kt:95) and
returns `HealthCheckResult.Unknown`, so the registry reports the backend "Healthy" (BackendRegistry
maps Unknown + available → Healthy). The first real request then fails with a raw Anthropic 401,
surfaced via the generic `else` branch as "Anthropic HTTP 401 … verify the model name is valid and
the API key is correct." There is no early, actionable validation for the missing key — unlike the
OpenAI-compatible/NVIDIA/Perplexity backends, which `validateBackendCommand` (MainTab.kt:685-724)
guards for empty URL/model. `anthropic` has no entry in that `when`, so it falls through to
`"Unsupported backend: anthropic"` if it is ever the preferred backend in the chat path validation.

**Fix:** (1) Add an `anthropic` branch to `MainTab.validateBackendCommand` that returns
`"Anthropic API key is empty."` when `settings.anthropicApiKey.isBlank()` (and optionally a blank-
model check). (2) Optionally short-circuit in the supervisor `"anthropic"` branch / backend
`launch` to fail fast with a clear message when the key is blank, rather than sending an empty
`x-api-key`.

### WR-05: 429 retry path records a circuit-breaker success and returns 429 as a non-retryable error

**File:** `src/main/kotlin/com/six2dez/burp/aiagent/backends/anthropic/AnthropicBackend.kt:191-207`

**Issue:** A non-2xx response (including 429 and 5xx) returns through the `if (!resp.isSuccessful)`
block, which calls `onComplete(...)` and `return@submit` **without** calling
`circuitBreaker.recordFailure()` and without honoring any retry. Only thrown
connection-level exceptions go through the retry/`recordFailure` path (lines 241-260). So a transient
HTTP 429/503 from Anthropic is treated as a terminal, non-retryable failure, and the circuit
breaker never accounts for server-side rejections. The 429 message even says "retry later," but the
backend does no retry itself. This is a robustness gap rather than a correctness bug, but it means
the circuit breaker and the 6-attempt retry loop provide no protection against the most common
real-world Anthropic failure mode (rate limiting). Note `recordSuccess()` is only reached on the
2xx path, so this does not falsely mark failures as successes — but failures are entirely invisible
to the breaker.

**Fix:** Treat retryable status codes (429, 502, 503, 504) like retryable exceptions: call
`circuitBreaker.recordFailure()` and continue the retry loop (respecting `attempt`/`maxAttempts`
and, for 429, a `Retry-After`-derived backoff if present) instead of `return@submit`. Keep 4xx
(other than 429) terminal.

## Info

### IN-01: `proxy_http_history_regex` does not support the listener_port filter

**File:** `src/main/kotlin/com/six2dez/burp/aiagent/mcp/tools/McpTools.kt:2736-2747`
(registration paths: `:666-681`, `:1881-1899`)

**Issue:** The CAP-03 `listenerPort` field was added to `GetProxyHttpHistory` /
`GetProxyHttpHistoryRestricted` and applied on both dispatch paths of `proxy_http_history`, but the
sibling `GetProxyHttpHistoryRegex` / `GetProxyHttpHistoryRegexRestricted` classes have no
`listenerPort` field and the regex tool applies no port filter. This appears intentional given the
phase scope names only `proxy_http_history`, so it is informational, not a defect — but the
asymmetry will surprise an agent that can filter by port on one history tool and not the other.

**Fix (optional):** Add the same `listenerPort: Int? = null` field to both regex data classes and
the same `.let { s -> if (listenerPort != null) s.filter { it.listenerPort() == listenerPort } else s }`
step in the two regex dispatch lambdas, for parity.

### IN-02: Anthropic timeout is read from prefs only, ignoring `AgentSettings`

**File:** `src/main/kotlin/com/six2dez/burp/aiagent/supervisor/AgentSupervisor.kt:861-862`

**Issue:** Every other HTTP backend resolves its timeout as `settings?.xxxTimeoutSeconds ?:
prefs.getInteger(...) ?: default`. The anthropic branch uses only
`prefs.getInteger("anthropic.timeoutSeconds") ?: Defaults.CLI_PROCESS_TIMEOUT_SECONDS` — there is no
`anthropicTimeoutSeconds` field on `AgentSettings` and the key `anthropic.timeoutSeconds` is never
written by `AgentSettingsRepository.save` (no such `prefs.setInteger`). The result is that the
Anthropic request timeout is effectively always the 120s default and is not user-configurable,
inconsistent with the other backends. Functionally harmless (120s is reasonable) but a latent
inconsistency.

**Fix:** Either add an `anthropicTimeoutSeconds` settings field (persisted like the others) or drop
the dead `prefs.getInteger("anthropic.timeoutSeconds")` read and document the fixed default.

### IN-03: `listenerPort` is not range-validated; negative/zero values silently match nothing

**File:** `src/main/kotlin/com/six2dez/burp/aiagent/mcp/tools/McpTools.kt:658`, `:1871`

**Issue:** `listenerPort` is taken verbatim from untrusted JSON and compared with
`it.listenerPort() == listenerPort`. A negative or zero value (or one >65535) parses fine and simply
yields an empty result rather than an error. This matches the "no-match → empty, not error" spec, so
it is not a bug — but an explicitly invalid port produces the same empty output as a valid-but-unused
port, which can confuse callers debugging why nothing matched.

**Fix (optional):** When `listenerPort` is non-null and outside `1..65535`, return a short
`"Error: listenerPort must be 1-65535"` so an obviously bad value is distinguishable from a real
no-match. Low priority.

### IN-04: `AnthropicConnection` model blank-handling expression is redundant

**File:** `src/main/kotlin/com/six2dez/burp/aiagent/backends/anthropic/AnthropicBackend.kt:39`

**Issue:** `val model = config.model?.ifBlank { "" } ?: ""` is a no-op transform: `ifBlank { "" }`
on a blank string already returns `""`, so the whole expression is equivalent to
`config.model ?: ""`. A blank/empty `model` is then sent to Anthropic, which will reject it with a
400 — but that path is the SC3 model-rejection string, so behavior is acceptable. This is a minor
readability/clarity nit.

**Fix:** Simplify to `val model = config.model.orEmpty()` (and rely on SC3 for the empty-model case),
or add an explicit blank-model guard if early validation is desired.

---

_Reviewed: 2026-06-10T17:52:44Z_
_Reviewer: Claude (gsd-code-reviewer)_
_Depth: standard_
