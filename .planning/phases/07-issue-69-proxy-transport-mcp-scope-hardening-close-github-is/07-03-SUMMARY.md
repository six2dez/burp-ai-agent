---
phase: 07
plan: 3
subsystem: mcp + settings + ui
tags:
  - mcp
  - scope
  - security-hardening
  - scope-bug-69
requires:
  - 07-02
provides:
  - mcpSettings.scopeOnly
  - McpScopeFilter (filterInScope + rejectIfOutOfScope + deriveScopeUrl)
  - McpToolContext.scopeOnly
  - mcpScopeOnly UI checkbox
affects:
  - McpSettings.kt
  - AgentSettings.kt
  - McpToolContext.kt
  - McpRuntimeContextFactory.kt
  - McpScopeFilter.kt (new)
  - McpTools.kt
  - SettingsPanel.kt
  - McpConfigPanel.kt
  - AgentSettingsMigrationTest.kt
  - McpScopeFilterTest.kt (new)
  - McpToolScopeEnforcementTest.kt (new)
tech_stack:
  added: []
  patterns:
    - pure helper object for scope enforcement (no logging, no audit side effects)
    - URL derivation from parameter tuple to dodge Burp static factory deps in tests
    - per-call boolean OR'd with global toggle for backwards-compat override semantics
    - rejection BEFORE static factory invocation so a single closed-tap point gates every write tool
key_files:
  created:
    - src/main/kotlin/com/six2dez/burp/aiagent/mcp/tools/McpScopeFilter.kt
    - src/test/kotlin/com/six2dez/burp/aiagent/mcp/tools/McpScopeFilterTest.kt
    - src/test/kotlin/com/six2dez/burp/aiagent/mcp/tools/McpToolScopeEnforcementTest.kt
  modified:
    - src/main/kotlin/com/six2dez/burp/aiagent/config/McpSettings.kt
    - src/main/kotlin/com/six2dez/burp/aiagent/config/AgentSettings.kt
    - src/main/kotlin/com/six2dez/burp/aiagent/mcp/McpToolContext.kt
    - src/main/kotlin/com/six2dez/burp/aiagent/mcp/McpRuntimeContextFactory.kt
    - src/main/kotlin/com/six2dez/burp/aiagent/mcp/tools/McpTools.kt
    - src/main/kotlin/com/six2dez/burp/aiagent/ui/SettingsPanel.kt
    - src/main/kotlin/com/six2dez/burp/aiagent/ui/panels/McpConfigPanel.kt
    - src/test/kotlin/com/six2dez/burp/aiagent/config/AgentSettingsMigrationTest.kt
decisions:
  - "Reject BEFORE constructing the Montoya HttpRequest in every write tool (rather than calling request.url() on a freshly-built HttpRequest). Achieves three goals at once: (1) tightens the trust-boundary at the EARLIEST possible point so out-of-scope URLs never touch Burp factories; (2) avoids a runtime cost when the call is rejected; (3) lets the test suite verify enforcement without a Burp runtime to load static factories. Introduced `McpScopeFilter.deriveScopeUrl(hostname, port, usesHttps, rawRequest)` as the shared URL builder."
  - "Per-call `scopeOnly` parameter on proxy_history_annotate and response_body_search is preserved for backwards compatibility and OR'd with `ctx.scopeOnly` — global ON beats per-call OFF, and the historical per-call ON still works. Documented as the BUG-69-03 explicit instruction in 07-CONTEXT.md."
  - "WebSocket scope filter uses `ProxyWebSocketMessage.upgradeRequest().url()` which exists on Montoya 2026.2 (verified via `javap` on the montoya-api jar). The fallback exemption documented in 07-03-PLAN's threat register (T-07-12) does NOT need to be claimed — WS tools ARE filtered."
  - "Helper functions are pure (no logging, no audit emission). Tool-level telemetry is already emitted by `runTool` which wraps every handler, so adding scope-related events at the helper would double-count."
metrics:
  duration_minutes: ~35
  completed_at: 2026-05-27T11:15:00Z
  files_created: 3
  files_modified: 8
  commits: 2
  tests_added: 25
---

# Phase 07 Plan 03: Proxy Transport + MCP Scope Hardening — MCP Scope Enforcement Summary

Closes BUG-69-03 (GitHub issue #69 sub-concern 4): the MCP server no longer leaks Burp HTTP data for hosts the user has not declared in-scope, and no longer sends traffic to out-of-scope hosts when an AI requests it. A single global `mcpSettings.scopeOnly` toggle (default OFF for backwards compatibility) gates every existing scope-aware MCP tool.

## What Changed

### Data model (McpSettings.kt + AgentSettings.kt)

- **New field** `McpSettings.scopeOnly: Boolean = false` as the last data-class parameter. Default false so existing serialised v3 preferences load unchanged — no schema bump.
- **New constant** `private const val KEY_MCP_SCOPE_ONLY = "mcp.scope.only"` in the AgentSettings companion KEY block, co-located with `KEY_MCP_UNSAFE`.
- `loadMcpSettings()` reads `prefs.getBoolean(KEY_MCP_SCOPE_ONLY) ?: false`.
- `saveMcpSettings()` persists `prefs.setBoolean(KEY_MCP_SCOPE_ONLY, settings.scopeOnly)`.
- **No field added to `AgentSettings`** — the new knob lives on the existing `mcpSettings: McpSettings` sub-object, consistent with how `maxBodyBytes`, `unsafeEnabled`, etc. are stored.

### Tool plumbing (McpToolContext.kt + McpRuntimeContextFactory.kt)

- `McpToolContext.scopeOnly: Boolean = false` field appended (default false → bytewise-compatible with every existing call site that does not pass the new arg).
- `McpRuntimeContextFactory.create(...)` now passes `scopeOnly = settings.scopeOnly` when constructing the per-request `McpToolContext`. This is the sole production construction site of `McpToolContext` (verified via grep — `McpStdioBridge.kt` and `KtorMcpServerManager.kt` both delegate through this factory).

### Scope helper (mcp/tools/McpScopeFilter.kt — NEW)

A pure singleton with three functions, no logging, no audit side effects:

| Function | Used by | Behaviour |
|----------|---------|-----------|
| `filterInScope(Sequence<T>, (T) -> String?, McpToolContext)` | every read-style tool | When `ctx.scopeOnly = true`, retains items whose URL extractor produces an in-scope URL; null URLs are dropped (fail-closed). When `scopeOnly = false`, returns input verbatim and **never** invokes `api.scope()`. |
| `filterInScope(List<T>, ...)` | read-style tools that get a `List` from Montoya | Convenience overload that calls `items.asSequence()`. |
| `rejectIfOutOfScope(url: String, McpToolContext)` | every write-style tool | When `ctx.scopeOnly = true`, returns the documented rejection string `"Refused: $url is out of scope (mcpScopeOnly=true). Use scope_include to add it."` for out-of-scope URLs, else null. When `scopeOnly = false`, returns null unconditionally and **never** invokes `api.scope()`. |
| `deriveScopeUrl(hostname, port, usesHttps, rawRequest)` | every write-style tool | Builds the URL the scope check needs WITHOUT calling any Burp static factory. Parses the request-target from the first request-line of `rawRequest`; falls back to `/`. Handles absolute-form URIs (`http://...`, `https://...`, `*`) by passing them through. Renders the port suffix only when non-default for the scheme. |

### Per-tool enforcement (McpTools.kt)

**READ tools (filter the result sequence when `ctx.scopeOnly` is on):**

| Tool | URL extractor | Notes |
|------|---------------|-------|
| `proxy_http_history` | `it.request()?.url()` | layered after `orderedProxyHistory` |
| `proxy_http_history_regex` | `it.request()?.url()` | layered after `orderedProxyHistory` |
| `proxy_ws_history` | `it.upgradeRequest()?.url()` | Montoya `ProxyWebSocketMessage.upgradeRequest()` verified on 2026.2 |
| `proxy_ws_history_regex` | `it.upgradeRequest()?.url()` | same |
| `site_map` | `it.request()?.url()` | layered after determinism sort |
| `site_map_regex` | `it.request()?.url()` | layered after the user-supplied `SiteMapFilter` |
| `proxy_history_annotate` | inline `(input.scopeOnly \|\| context.scopeOnly)` | per-call `scopeOnly` retained as override; OR'd with global so global ON beats per-call OFF |
| `response_body_search` | inline `(input.scopeOnly \|\| context.scopeOnly)` | same OR'd semantics |

**WRITE tools (reject BEFORE constructing the HttpRequest / template):**

| Tool | URL source | Sink that is NEVER reached when out-of-scope |
|------|------------|-----------------------------------------------|
| `http1_request` | `deriveScopeUrl(host, port, https, fixedContent)` | `api.http().sendRequest(...)` |
| `http2_request` | `deriveScopeUrl(host, port, https, "GET $h2Path HTTP/2")` — pulls path from `:path` pseudo-header | `api.http().sendRequest(..., HTTP_2)` |
| `repeater_tab` | `deriveScopeUrl(host, port, https, input.content)` | `api.repeater().sendToRepeater(...)` |
| `repeater_tab_with_payload` | `deriveScopeUrl(host, port, https, rendered)` — AFTER replacements so the final URL is checked | `api.repeater().sendToRepeater(...)` |
| `intruder` | `deriveScopeUrl(host, port, https, input.content)` | `api.intruder().sendToIntruder(HttpRequest, ...)` |
| `intruder_prepare` | `deriveScopeUrl(host, port, https, fixed)` — derived from the existing `targetHostname/targetPort/usesHttps` fields per `HttpServiceParams` (McpTools.kt:2178–2189) | `api.intruder().sendToIntruder(HttpService, HttpRequestTemplate, ...)` |

Exactly **6** `rejectIfOutOfScope` call sites — one per write tool, matching the success-criteria fixed-count requirement.

### Exact rejection string

External MCP clients can match on the canonical substring `is out of scope (mcpScopeOnly=true)`:

```
Refused: https://example.test/path is out of scope (mcpScopeOnly=true). Use scope_include to add it.
```

The format is `Refused: $url is out of scope (mcpScopeOnly=true). Use scope_include to add it.` — `url` is the derived scope URL passed into `rejectIfOutOfScope`.

### UI (SettingsPanel.kt + McpConfigPanel.kt)

- **New JCheckBox** `mcpScopeOnly` declared alongside `mcpUnsafe`, with the label *"Restrict MCP tools to in-scope hosts"* and the tooltip *"When enabled, MCP tools that return Burp HTTP data only include in-scope items, and send_request-style tools refuse out-of-scope URLs. Issue #69."*. Styled with `UiTheme.Typography.body` to mirror `mcpUnsafe`.
- `currentSettings()` writes `scopeOnly = mcpScopeOnly.isSelected` into the new McpSettings constructor argument.
- `refresh()` (via `applySettingsToUi()`) sets `mcpScopeOnly.isSelected = updated.mcpSettings.scopeOnly` so the toggle round-trips from persistence to UI.
- `McpConfigPanel` gains a new constructor parameter `mcpScopeOnlyCheckbox: JComponent` (renamed to avoid clashing with SettingsPanel's `mcpScopeOnly` field name). Rendered as a full-width row labelled *"Restrict to in-scope hosts"* immediately after the External access / Stdio bridge row — adjacent to the other security-impact toggles.
- `SettingsPanel.mcpSection()` wires the new checkbox through `McpConfigPanel(..., mcpScopeOnlyCheckbox = mcpScopeOnly, ...)`.

### Tests

#### `AgentSettingsMigrationTest.mcpScopeOnly_roundTripsThroughSaveLoad` (1 new @Test, three nested runs)

| Run | Behaviour covered |
|-----|-------------------|
| save with scopeOnly=true → fresh load | round-trips as true |
| save with scopeOnly=false → fresh load | round-trips as false |
| absent preference → fresh load | defaults to false |

#### `McpScopeFilterTest` (NEW, 8 @Test methods)

| Test | Behaviour covered |
|------|-------------------|
| `filterInScope_keepsOnlyInScopeUrlsWhenScopeOnlyTrue` | mixed allow/deny list filters down to the allowed URLs |
| `filterInScope_isBytewiseNoOpWhenScopeOnlyFalse` | scopeOnly=false → input returned verbatim, `api.scope()` never consulted |
| `filterInScope_dropsNullUrlItemsUnderScopeOnlyAndKeepsThemWhenOff` | null URLs drop under ON (fail-closed) and stay under OFF |
| `filterInScope_sequenceOverloadIsLazyAndPreservesOrdering` | order preserved, allow-list correctly applied to a sequence |
| `rejectIfOutOfScope_returnsNullForInScopeUrlUnderScopeOnly` | in-scope URL → null |
| `rejectIfOutOfScope_returnsDocumentedStringForOutOfScopeUnderScopeOnly` | out-of-scope under ON → string contains canonical marker, URL, and `scope_include` remediation |
| `rejectIfOutOfScope_returnsNullRegardlessOfScopeWhenScopeOnlyFalse` | scopeOnly=false → null even for "blocked" URLs, `api.scope()` never consulted |
| `helpers_doNotEmitLogsOrSideEffects` | no `api.logging()` interaction from either helper (purity guard) |

#### `McpToolScopeEnforcementTest` (NEW, 24 @Test methods)

Per-tool integration coverage; `exec(...)` goes through `McpToolExecutor.executeTool` so the real handler dispatch, toolToggles gate, and per-tool URL extraction logic are exercised. Stub setup uses `RETURNS_DEEP_STUBS` and a configurable scope predicate (only the canonical `example.com` host is in scope).

| Tool | scope-ON test | scope-OFF test | extras |
|------|---------------|----------------|--------|
| `proxy_http_history` | filters out blocked.test, keeps example.com | both hosts present | |
| `proxy_http_history_regex` | filters | both present | |
| `proxy_history_annotate` | (per-call OFF + ctx ON) → still filters; (per-call ON + ctx OFF) → still filters | bothOff → returns both | OR'd-with-global semantics |
| `response_body_search` | per-call OFF + ctx ON → filters | bothOff → both | OR'd-with-global semantics |
| `proxy_ws_history` | upgrade URL is filtered | both | URL via `upgradeRequest().url()` |
| `proxy_ws_history_regex` | filters | both | same |
| `site_map` | filters | both | |
| `site_map_regex` | filters | both | |
| `http1_request` | returns rejection string, `api.http().sendRequest` never invoked | absence-of-rejection-string, `api.scope()` never consulted | write-tool short-circuit |
| `http2_request` | returns rejection string, sendRequest never invoked | (covered indirectly) | scope check moved BEFORE `HttpHeader.httpHeader(...)` so factory failures don't mask the check |
| `repeater_tab` | rejection + `sendToRepeater` never called | (omitted, redundant with http1) | |
| `repeater_tab_with_payload` | rejection AFTER replacements | (omitted) | proves the post-replacement URL is the one checked |
| `intruder` | rejection + `sendToIntruder(HttpRequest, ...)` never called | (omitted) | |
| `intruder_prepare` | rejection + `sendToIntruder(HttpService, HttpRequestTemplate, ...)` never called | (omitted) | proves the early-exit before template construction |

`McpToolScopeEnforcementTest.kt` is 25 tests total (24 @Test methods; one is a 3-branch parametrised-style test, but JUnit 5 sees 24 individual cases).

## Verification

```
./gradlew clean compileKotlin test     → BUILD SUCCESSFUL (full test suite green)
./gradlew ktlintCheck                  → BUILD SUCCESSFUL (only pre-existing violations remain;
                                          my files have no new ktlint hits)
```

### Plan acceptance grep matrix

| Check | Threshold | Actual | Result |
|-------|-----------|--------|--------|
| `grep -c "val scopeOnly" src/.../McpSettings.kt` | ≥1 | 1 | PASS |
| `grep -c "KEY_MCP_SCOPE_ONLY\|mcp.scope.only" src/.../AgentSettings.kt` | ≥3 | 3 | PASS |
| `grep -c "scopeOnly" src/.../McpToolContext.kt` | ≥1 | 1 | PASS |
| `grep -c "scopeOnly = settings.scopeOnly" src/.../McpRuntimeContextFactory.kt` | ≥1 | 1 | PASS |
| `grep -c "McpScopeFilter\\." src/.../McpTools.kt` | ≥12 | 18 | PASS |
| `grep -c "rejectIfOutOfScope" src/.../McpTools.kt` | EXACTLY 6 | 6 | PASS |
| `grep -c "scopeOnly \|\| context.scopeOnly" src/.../McpTools.kt` | ≥2 | 2 | PASS |
| `grep -c "@Test" McpToolScopeEnforcementTest.kt` | ≥14 | 24 | PASS |
| `grep -c "@Test" McpScopeFilterTest.kt` | ≥4 | 8 | PASS |
| Schema version unchanged | 3 | 3 | PASS |
| No build.gradle.kts / version changes | none | none | PASS |
| Files changed match `files_modified` | 11 | 11 | PASS |

## Deviations from Plan

### `[Rule 3 - Test-environment incompatibility] Reject BEFORE constructing Burp factory objects, not after`

- **Found during:** Task 2 verification (initial test failures).
- **Issue:** The plan's `<action>` instructed write tools to call `rejectIfOutOfScope(request.url(), context)` AFTER constructing the Montoya `HttpRequest` (via `HttpRequest.httpRequest(...)`). In a pure-JVM unit test the Montoya static factory (`burp.api.montoya.internal.ObjectFactoryLocator.FACTORY`) is null, so the construction throws an NPE before the scope check runs. The rejection-string assertion fails because the handler returns the factory-NPE error string instead. The plan's verification `<automated>` says `./gradlew compileKotlin ktlintCheck test --tests McpToolScopeEnforcementTest` — without a fix, that command exits 1.
- **Fix:** Added a pure helper `McpScopeFilter.deriveScopeUrl(hostname, port, usesHttps, rawRequest)` that builds the equivalent URL from the parameter tuple + raw request-line WITHOUT calling any Burp factory. Refactored all 6 write tools to derive the URL FIRST, call `rejectIfOutOfScope` on the derived URL, and only build the `HttpRequest` if the call is permitted. This also tightens the trust boundary (out-of-scope calls now skip BOTH the `HttpHeader` and `HttpRequest` factory invocations) and gives a small runtime win when the call is rejected. Also moves the `http2_request` scope check up so it precedes the `HttpHeader.httpHeader(...)` factory loop (same test-environment reason).
- **Files modified:** `src/main/kotlin/com/six2dez/burp/aiagent/mcp/tools/McpScopeFilter.kt` (added `deriveScopeUrl`), `src/main/kotlin/com/six2dez/burp/aiagent/mcp/tools/McpTools.kt` (relocated scope checks).
- **Commit:** 53113db.

### `[Rule 3 - Test-environment incompatibility] Mock ByteArray instead of constructing it in WS tests`

- **Found during:** Task 2 verification.
- **Issue:** The WebSocket scope tests stub `ProxyWebSocketMessage.payload()` to return a `burp.api.montoya.core.ByteArray`. The plan called for `ByteArray.byteArray(payload)` to build the stub — that's the same factory pattern, fails the same NPE.
- **Fix:** Replaced the real `ByteArray` construction with `mock<burp.api.montoya.core.ByteArray>()` and stubbed `toString()` (the only method the serializer calls). Eight WS tests now run.
- **Files modified:** `src/test/kotlin/com/six2dez/burp/aiagent/mcp/tools/McpToolScopeEnforcementTest.kt` (`stubWsItem` helper).
- **Commit:** 53113db.

### `[Rule 3 - Plan stale line refs] Tool handler line numbers in the plan are stale post-refactor`

- **Found during:** Task 2 reading.
- **Issue:** The plan's `<interfaces>` references absolute line numbers (e.g. "http1_request (line 80)", "proxy_http_history (line 644)") in `McpTools.kt`. Those numbers point to the LEGACY `registerToolsLegacy` function (line 67) which is `@Suppress("unused")` and never registered — the live dispatch is in `McpToolExecutor.executeToolResult` at line 1309. I located the live handlers by grep on tool-name strings (`"http1_request" ->`, `"proxy_http_history" ->`) and updated those. The behavior of the patch is identical to what the plan intended; only the location is different.
- **Fix:** Applied all scope-enforcement edits at the live dispatch sites (1336 / 1346 / 1382 / 1388 / 1395 / 1401 for write tools; 1791 / 1808 / 1826 / 1854 / 1876 / 1892 / 1909 / 1925 for read tools — approximate post-patch).
- **No code-level deviation from plan intent; just a road-map correction.**

### `[Rule 3 - Plan-vs-orchestrator commit count] Two commits, not one`

- **Found during:** Final verification.
- **Issue:** The plan's `<verification>` line says "ONE atomic commit for this plan." but the plan declares two `<task>` elements AND the orchestrator says "Commit each task atomically." Same contradiction as 07-02 (documented there too).
- **Fix:** Committed per-task as the orchestrator instructed. Two commits: `59f9bf7` (Task 1 — data plumbing, helper, UI, migration test) and `53113db` (Task 2 — per-tool enforcement, integration tests). `git diff --name-only HEAD~2 HEAD` shows exactly the 11 files in `files_modified`, preserving the plan's "exactly these 11 files change" intent.

## WebSocket Scope Gaps

**None.** The plan's `<interfaces>` allows for a documented exemption if `ProxyWebSocketMessage.upgradeRequest()` is not exposed on the in-scope Montoya version. I confirmed via `javap -p burp.api.montoya.proxy.ProxyWebSocketMessage` against `montoya-api-2026.2.jar` that:

```
public abstract burp.api.montoya.http.message.requests.HttpRequest upgradeRequest();
```

is present. So `proxy_ws_history` and `proxy_ws_history_regex` ARE scope-filtered via `it.upgradeRequest()?.url()`. T-07-12 in the threat register is now `mitigate`, not `accept`.

## Known Stubs

None. The full chain (preference → McpSettings → loadMcpSettings → McpRuntimeContextFactory → McpToolContext.scopeOnly → tool handler → McpScopeFilter → `api.scope()`) is wired end-to-end and round-trips through the round-trip test.

## Threat Flags

None. Every code path touches an existing trust boundary already enumerated in the plan's `<threat_model>` (T-07-08 / T-07-09 / T-07-10 / T-07-11). The mitigations the plan called for are applied and tested:

- **T-07-08 (Info Disclosure — read tools):** `filterInScope` consults `api.scope().isInScope` when on; null URLs dropped conservatively. Tests `proxy_http_history_scopeOn_filtersOutOfScopeItems` etc.
- **T-07-09 (Tampering — write tools):** Short-circuit BEFORE crossing `api.http()/api.repeater()/api.intruder()`. Tests `*_scopeOn_rejectsOutOfScopeAndNeverHitsApi` use `verify(..., never())`.
- **T-07-10 (Spoofing — AI uses repeater_tab to bypass http1_request):** `repeater_tab` symmetric with `http1_request` now — both gated by `rejectIfOutOfScope`. Test `repeaterTab_scopeOn_rejectsOutOfScopeAndNeverHitsApi`.
- **T-07-11 (Repudiation — scopeOnly state changes silently):** Boolean stored alongside every other AgentSettings/McpSettings field via the existing Preferences pipeline. No additional audit emission added (consistent with `acceptance` disposition; tool-level telemetry runs in `runTool`).
- **T-07-12 (Info Disclosure — WS frame scope check):** Confirmed `upgradeRequest()` is exposed on Montoya 2026.2 → mitigated, not accepted.

## Commits

| Hash | Type | Title | Files |
|------|------|-------|-------|
| 59f9bf7 | feat(07-03) | add mcpScopeOnly setting + McpScopeFilter helper | McpSettings.kt, AgentSettings.kt, McpToolContext.kt, McpRuntimeContextFactory.kt, McpScopeFilter.kt (NEW), SettingsPanel.kt, McpConfigPanel.kt, AgentSettingsMigrationTest.kt, McpScopeFilterTest.kt (NEW) |
| 53113db | feat(07-03) | enforce McpScopeFilter on every scope-aware MCP tool | McpScopeFilter.kt (added deriveScopeUrl), McpTools.kt, McpToolScopeEnforcementTest.kt (NEW) |

## Self-Check: PASSED

- File `src/main/kotlin/com/six2dez/burp/aiagent/mcp/tools/McpScopeFilter.kt` → exists.
- File `src/test/kotlin/com/six2dez/burp/aiagent/mcp/tools/McpScopeFilterTest.kt` → exists.
- File `src/test/kotlin/com/six2dez/burp/aiagent/mcp/tools/McpToolScopeEnforcementTest.kt` → exists.
- Commit `59f9bf7` → in `git log --oneline --all`.
- Commit `53113db` → in `git log --oneline --all`.
- `./gradlew clean compileKotlin test` → BUILD SUCCESSFUL.
- `./gradlew ktlintCheck` on my files → no new violations introduced.
- Schema version stamp `CURRENT_SETTINGS_SCHEMA_VERSION = 3` → unchanged.
- `git diff --name-only HEAD~2 HEAD` → exactly 11 files, matching `files_modified`.
- No `build.gradle.kts` or version changes.
- `rejectIfOutOfScope` occurrences = exactly 6 (one per write tool).
- `McpScopeFilter.` total = 18 (well above the ≥12 threshold).
- WebSocket tools ARE filtered via `upgradeRequest().url()` — no documented gap.
