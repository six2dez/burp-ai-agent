---
phase: 14
plan: "03"
subsystem: mcp
tags: [cap-03, sc5, listener-port, proxy-history, mcp-tools, filter]
dependency_graph:
  requires: ["14-01"]
  provides: ["listener-port-filter:proxy_http_history"]
  affects: ["mcp/tools/McpTools.kt"]
tech_stack:
  added: []
  patterns:
    - ".let { s -> if (field != null) s.filter { it.method() == field } else s } on Sequence (Montoya API filter pattern)"
key_files:
  created:
    - src/test/kotlin/com/six2dez/burp/aiagent/mcp/tools/ProxyHistoryListenerPortFilterTest.kt
  modified:
    - src/main/kotlin/com/six2dez/burp/aiagent/mcp/tools/McpTools.kt
decisions:
  - "listenerPort JSON key is camelCase (listenerPort) matching kotlinx-serialization field name — not snake_case listener_port"
  - "GetProxyHttpHistoryRestricted gains the same listenerPort field so schema exposes the param under both allowUnpreprocessed settings"
  - "Filter is applied BEFORE McpScopeFilter.filterInScope in the manual path (additive scoping — narrows, never widens)"
metrics:
  duration: "~20 minutes"
  completed: "2026-06-10"
  tasks_completed: 2
  files_modified: 2
---

# Phase 14 Plan 03: Listener-Port Filter for proxy_http_history Summary

**One-liner:** Optional `listenerPort: Int?` field on `GetProxyHttpHistory` + `GetProxyHttpHistoryRestricted` with `.filter { it.listenerPort() == listenerPort }` applied in both `proxy_http_history` dispatch paths via the Montoya 2026.2 `ProxyHttpRequestResponse.listenerPort()` accessor.

## What Was Built

CAP-03 / SC5 (closes #70): an external AI agent can now scope `proxy_http_history` queries to a single Burp listener port by passing `listenerPort: <port>` in the tool call. Unset / null returns all ports (current behaviour preserved). A port with no matching items returns an empty list, not an error.

### Changes

**`src/main/kotlin/com/six2dez/burp/aiagent/mcp/tools/McpTools.kt`**

- `GetProxyHttpHistory` (L2719): added `val listenerPort: Int? = null` — the kotlinx-serialization field name is `listenerPort` (camelCase); this is the JSON key MCP clients must send.
- `GetProxyHttpHistoryRestricted` (L2726): same field — exposes `listenerPort` in the tool schema under both the `allowUnpreprocessed=true` branch (`GetProxyHttpHistory::class.asInputSchema()`) and the restricted branch (`GetProxyHttpHistoryRestricted::class.asInputSchema()`).
- Paginated path (~L649): `.let { s -> if (listenerPort != null) s.filter { it.listenerPort() == listenerPort } else s }` chained onto `orderedProxyHistory(items, context)`.
- Manual decode path (~L1860): `.let { s -> if (input.listenerPort != null) s.filter { it.listenerPort() == input.listenerPort } else s }` chained after `orderedProxyHistory`, before `McpScopeFilter.filterInScope` (additive — narrows results only).

**`src/test/kotlin/com/six2dez/burp/aiagent/mcp/tools/ProxyHistoryListenerPortFilterTest.kt`** (new)

- 7 tests covering SC5: filter-to-port, no-match-empty-not-error, unset-all-ports for both dispatch paths.
- Path A (paginated lambda): exercises filter predicate directly via `GetProxyHttpHistory.listenerPort`.
- Path B (manual decode): calls `McpToolExecutor.executeTool("proxy_http_history", ...)` end-to-end.
- `GetProxyHttpHistoryRestricted` schema coverage: `restrictedDataClass_hasListenerPortField`.

## Acceptance Criteria Verification

- `grep -c "it.listenerPort() == " src/main/kotlin/com/six2dez/burp/aiagent/mcp/tools/McpTools.kt` → **2** (Pitfall 4 guard, both paths filtered).
- `grep -n "val listenerPort: Int? = null" McpTools.kt` → lines 2725 and 2732 (both data classes).
- `./gradlew test --tests "...ProxyHistoryListenerPortFilterTest"` → 7/7 green.
- `./gradlew test` full suite → **389 tests, 0 failures** (up from 382 pre-phase-14-03).
- `proxy_http_history_regex` is unchanged (out of scope).

## TDD Gate Compliance

| Gate | Commit | Status |
|------|--------|--------|
| RED | `28bb9c6` — test(14-03): add failing SC5 listener-port filter test | PASS — compilation error: Unresolved reference 'listenerPort' |
| GREEN | `047578e` — feat(14-03): add listenerPort filter to proxy_http_history both dispatch paths | PASS — 7/7 tests green |
| REFACTOR | n/a — no cleanup needed | — |

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] listenerPort JSON key is camelCase, not snake_case**
- **Found during:** Task 2 GREEN verification
- **Issue:** Test sent `listener_port` (snake_case) but `decodeJson` (`Json { ignoreUnknownKeys = true }`) silently ignored it — field remained null, filter was skipped, all items returned.
- **Root cause:** kotlinx-serialization uses the Kotlin property name (`listenerPort`) as the JSON key by default. No `NamingStrategy` or `@SerialName("listener_port")` is configured. The existing fields like `includeUnpreprocessedResponse` are also camelCase in JSON.
- **Fix:** Updated test Path B assertions to use `listenerPort` (camelCase) matching the serialization contract. The production code is correct — no change needed there.
- **Files modified:** `ProxyHistoryListenerPortFilterTest.kt` (test-only fix)
- **Commits:** `047578e`

## Known Stubs

None — filter is fully wired; `listenerPort()` returns real data from the Montoya `ProxyHttpRequestResponse` accessor in production.

## Threat Flags

No new network endpoints, auth paths, file access patterns, or schema changes at trust boundaries beyond those covered in the plan's threat model (T-14-12, T-14-13, T-14-14). The `listenerPort` filter narrows results only — it does not widen what the tool can return.

## Self-Check: PASSED

- `src/test/kotlin/com/six2dez/burp/aiagent/mcp/tools/ProxyHistoryListenerPortFilterTest.kt` — FOUND
- `src/main/kotlin/com/six2dez/burp/aiagent/mcp/tools/McpTools.kt` modified — FOUND (lines 2725, 2732, paginated path, manual path)
- Commit `28bb9c6` — FOUND (RED)
- Commit `047578e` — FOUND (GREEN)
- Full suite 389 tests green — VERIFIED
