# Phase 8: BApp Store resubmission — MCP pivot to extension-native tools + compliance fixes - Context

**Gathered:** 2026-05-28
**Status:** Ready for planning
**Source:** Approved plan (harness plan mode) — ~/.claude/plans/drifting-hatching-sphinx.md. Strategy decisions already made with the user this session; treat them as LOCKED.

<domain>
## Phase Boundary

Resolve all four PortSwigger BApp Store review feedback points on issue [#231](https://github.com/PortSwigger/extension-portal/issues/231) so the extension can `/reopen` and pass review in one cycle, **without discarding the existing MCP work**.

The four points from the latest reviewer comment:
1. **Name** — reviewer asked to confirm the name is "Custom AI Agent". It already is everywhere (`App.kt:57` setName, `App.kt:129` suite tab, `build.gradle.kts` archiveBaseName `Custom-AI-Agent`). Confirmation only — no code change.
2. **MCP** — MCP tools that expose the generic Montoya API must come from the official Burp MCP Server, not this extension. The reviewer explicitly allows *"MCP tooling that hooks into the capabilities of your extension."* Today the MCP server exposes 58 tools, 57 of them generic Montoya wrappers that duplicate the official server.
3. **`ai.isEnabled()`** — every call to an AI provider must check `ai.isEnabled()` first. Today only the `burp-ai` backend is gated; CLI/HTTP backends bypass it.
4. **Passive scanning** — must be implemented as a `PassiveScanCheck` (`ScanCheck.passiveAudit()`), not via a `ProxyResponseHandler`.

**In scope:** MCP tool classification + store-build gating + new extension-native AI MCP tools; global `ai.isEnabled()` gating; passive-scan migration to `ScanCheck.passiveAudit()`; verification that the store build exposes only native tools; the `/reopen` reply text.

**Out of scope:** Removing/deleting the 57 generic tools (they stay in the GitHub "full" build); reworking CLI-backend process spawning; redaction-engine changes; UI redesign beyond MCP panel copy/list filtering.
</domain>

<decisions>
## Implementation Decisions (LOCKED unless noted)

### MCP strategy — "pivot + keep full off-store build" (LOCKED, user choice)
- Keep 100% of MCP infrastructure (Ktor SSE server, stdio bridge, bearer-token auth, TLS, CORS, per-tool toggles, `McpScopeFilter`, settings, UI panel, audit logging, redaction). Nothing in the infra is deleted.
- Add a `nativeTool: Boolean = false` field to `McpToolDescriptor` (`mcp/McpToolCatalog.kt`). Mark extension-native tools `true`; leave the 57 generic Montoya wrappers `false`.
- Add `McpToolCatalog.available()` = `if (BuildFlags.STORE_BUILD) tools.filter { it.nativeTool } else tools`. Keep `all()` for full enumeration/tests.
- Route tool **registration** (`mcp/tools/McpToolHandlers.kt` `McpToolRegistrations` / `Server.registerTools()`) and the **UI list** (`ui/panels/McpConfigPanel.kt`) through `available()` so the store build neither registers nor displays generic tools.

### Build gating (LOCKED)
- `build.gradle.kts`: read `providers.gradleProperty("storeBuild").orNull == "true"` (default `false` → preserves current full-build behavior).
- Generate `BuildFlags.kt` (`object BuildFlags { const val STORE_BUILD = <true|false> }`) into a generated source dir via a small Gradle task wired before `compileKotlin`. Compile-time constant so the store JAR cannot re-expose generic tools at runtime. No new plugin (keep MIT-compat / dependency-light).
- Two artifacts: store `./gradlew shadowJar -PstoreBuild=true` → `Custom-AI-Agent-<version>.jar` (native only); full `./gradlew shadowJar` → e.g. `Custom-AI-Agent-full-<version>.jar` (all tools) for GitHub releases.
- Runtime-gating (unregistered ⇒ uncallable) is the chosen mechanism. Fallback if a reviewer objects to generic code merely being present: separate Gradle source set excluding generic tool sources from the store artifact. Start with constant-gate; escalate only if asked.

### Extension-native MCP tools (the allowed "hooks into your extension" set)
Keep `status` and `issue_create` (mark native). Add new native tools that reuse existing engines and flow through the existing MCP redaction + audit + scope pipeline:
- `ai_analyze` → `AgentSupervisor.send(...)` (`supervisor/AgentSupervisor.kt:291`), jsonMode + maxOutputTokens
- `ai_passive_scan` → `PassiveAiScanner.manualScan(requests)` (`scanner/PassiveAiScanner.kt:543`) + `getLastFindings(n)`
- `ai_findings_recent` → `PassiveAiScanner.getLastFindings(n)` (`:500`)
- `redact_preview` → `Redaction.apply(text, RedactionPolicy.fromMode(mode), salt)` (pattern at `PassiveAiScanner.kt:837`) — unique privacy capability
- `ai_audit_query` → `AiRequestLogger` (respect audit defaults: hashes only unless verbose)
- `ai_backends_list` → `BackendRegistry.listBackendIds(settings)` + `supervisor.status()`
- `ai_active_scan` (OPTIONAL, Pro) → `ActiveAiScanner`
All AI-calling tools must pass the `ai.isEnabled()` gate.

### `ai.isEnabled()` gating (LOCKED intent, mechanism TBD by research)
- PortSwigger best-practices doc (confirmed) requires checking `ai.isEnabled()` before issuing ANY AI request, including third-party providers.
- Gate all backends (not just `burp-ai`). Likely a broadened gate in `AgentSupervisor.startOrAttach()` (`:148`) and `send()` (`:309`), plus broaden `isBlockedByBurpAiGate()` (`:138`); existing `isAiEnabled()` is at `:119`, `requiresBurpAiAndDisabled()` at `:131`.
- Also verify: Burp AI is the **default** provider (`settings.preferredBackendId` default), and third-party HTTP uses Montoya networking + `RequestOptions.withUpstreamTLSVerification()` (already done in `AiScanCheck.kt:197,:205`).
- **OPEN RISK (research must address):** `api.ai().isEnabled()` may be `false`/unavailable on Burp Community, which would block third-party (CLI/Ollama/OpenAI) backends there — conflicting with the project's Community-support constraint and the deliberate design comment at `AgentSupervisor.kt:107-131`. A Community verification task is REQUIRED before committing the global gate. If Community lacks the toggle, escalate to PortSwigger in the issue rather than silently breaking Community.

### Passive scan → `ScanCheck.passiveAudit()` (LOCKED intent)
- Remove the `ProxyResponseHandler` (`scanner/PassiveAiScanner.kt` handler `298-357`, registered `:362`).
- Implement `AiScanCheck.passiveAudit(baseRequestResponse)` (currently a no-op at `scanner/AiScanCheck.kt:85`): run fast synchronous local heuristic checks (`runLocalChecks`) and return them as `AuditResult` immediately; enqueue items for async AI deep-analysis (reuse `PassiveAiScanner` executor/batching/cache/redaction), registering AI findings as `AuditIssue` when ready.
- `PassiveAiScanner` becomes the async engine invoked by the ScanCheck. Keep the user-initiated `manualScan` context-menu path. Reuse existing `consolidateIssues()` (`AiScanCheck.kt:94`).
- **Implication (accepted):** automatic passive AI scanning becomes Pro-only (scanner is Pro-only; `AiScanCheck` already degrades on Community at `App.kt:153-160`). Community keeps manual/context-menu AI analysis. Document this.

### Name (LOCKED)
- No code change. Confirm "Custom AI Agent" in the `/reopen` reply.
</decisions>

<canonical_refs>
## Canonical References

**Downstream agents MUST read these before planning or implementing.**

### Approved plan & strategy
- `~/.claude/plans/drifting-hatching-sphinx.md` — full approved plan (authoritative; do not re-derive strategy)

### MCP (Part 1)
- `src/main/kotlin/com/six2dez/burp/aiagent/mcp/McpToolCatalog.kt` — 58 descriptors; add `nativeTool` + `available()`
- `src/main/kotlin/com/six2dez/burp/aiagent/mcp/tools/McpToolHandlers.kt` — `McpToolRegistrations` registration
- `src/main/kotlin/com/six2dez/burp/aiagent/mcp/tools/McpTools.kt` — `executeToolResult()` handler switch (new tool handlers go here)
- `src/main/kotlin/com/six2dez/burp/aiagent/mcp/tools/McpScopeFilter.kt` — reused by new tools
- `src/main/kotlin/com/six2dez/burp/aiagent/ui/panels/McpConfigPanel.kt` — MCP UI list (route through `available()`)
- `build.gradle.kts` — shadowJar config; add `-PstoreBuild` gate + generated `BuildFlags.kt`

### AI gating (Part 2)
- `src/main/kotlin/com/six2dez/burp/aiagent/supervisor/AgentSupervisor.kt` — gate points `:119,:131,:138,:148,:309`
- `src/main/kotlin/com/six2dez/burp/aiagent/BurpAiAgentExtension.kt` — `enhancedCapabilities()=AI_FEATURES`
- `src/main/kotlin/com/six2dez/burp/aiagent/backends/BackendRegistry.kt` + `backends/burpai/BurpAiBackend.kt` — backend abstraction & existing burp-ai gate
- PortSwigger best practices: https://portswigger.net/burp/documentation/desktop/extend-burp/extensions/creating/creating-ai-extensions/best-practices

### Passive scan (Part 3)
- `src/main/kotlin/com/six2dez/burp/aiagent/scanner/AiScanCheck.kt` — implement `passiveAudit()`, reuse `consolidateIssues()`
- `src/main/kotlin/com/six2dez/burp/aiagent/scanner/PassiveAiScanner.kt` — drop ProxyResponseHandler; async engine
- `src/main/kotlin/com/six2dez/burp/aiagent/App.kt` — `:154` registers `AiScanCheck`; wiring

### Project constraints
- `CLAUDE.md` (Constraints), `AGENTS.md` (English-only), `SPEC.md`, `DECISIONS.md`
</canonical_refs>

<specifics>
## Specific Ideas

- The official Burp MCP Server (PortSwigger/mcp-server) already exposes the generic Montoya surface; the reviewer invited PRs there for genuinely-novel generic capabilities. As an execution refinement, diff the 57 generic tools against the official server's `Tools.kt` to identify any worth upstreaming (optional, not blocking).
- `issue_create` and `status` are borderline; classify as native (issue_create is the sink for AI findings; status reports the extension's own state). If the reviewer objects, they can move.
- The `/reopen` reply draft lives in the approved plan (Part 4) — reuse it.
</specifics>

<deferred>
## Deferred Ideas

- Upstreaming generic tools to PortSwigger/mcp-server (optional follow-up; not required for acceptance).
- Source-set-level exclusion of generic tool code from the store artifact (only if the reviewer objects to runtime-gating).
- Any reconsideration of CLI-backend process spawning vs store policy (not raised in the latest comment).
</deferred>

---

*Phase: 08-bapp-store-resubmission-mcp-pivot-to-extension-native-tools*
*Context gathered: 2026-05-28 from approved harness plan (decisions pre-locked with user)*
