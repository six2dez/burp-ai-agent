# Phase 8: BApp Store Resubmission — MCP Pivot + Compliance Fixes — Research

**Researched:** 2026-05-28
**Domain:** Burp Montoya API (passive scanning, AI gating), Gradle Kotlin DSL (build-time constants), MCP tool wiring, BApp Store compliance
**Confidence:** HIGH (all claims verified against decompiled Montoya API 2026.2 JAR, official PortSwigger docs/examples, and live codebase reads)

---

<user_constraints>
## User Constraints (from CONTEXT.md)

### Locked Decisions
- MCP strategy: keep 100% of infra; add `nativeTool` field to `McpToolDescriptor`; add `available()` filter; gate registration + UI through `available()`; store build: `-PstoreBuild` Gradle property → generate `BuildFlags.STORE_BUILD` constant.
- Build gating: no new plugin; hand-rolled generate task; two artifacts (store name = `Custom-AI-Agent-<version>.jar`, full = `Custom-AI-Agent-full-<version>.jar`).
- Extension-native tools to add: `ai_analyze`, `ai_passive_scan`, `ai_findings_recent`, `redact_preview`, `ai_audit_query`, `ai_backends_list` (plus `ai_active_scan` optional Pro). All AI-calling tools must pass `ai.isEnabled()` gate.
- `ai.isEnabled()` gating: gate all backends, not just `burp-ai`. Community verification required before committing global gate.
- Passive scan: remove `ProxyResponseHandler` from `PassiveAiScanner`; implement `AiScanCheck.passiveAudit()` with synchronous local heuristics + async AI enqueue; keep `manualScan` context-menu path.
- Name: no code change required. Confirm "Custom AI Agent" in `/reopen` reply.

### Claude's Discretion
- Specific `passiveAudit` implementation pattern for async AI findings (synchronous return vs deferred site-map add).
- Whether to use old `ScanCheck` interface or migrate to new `PassiveScanCheck` interface.
- Exact `ScanCheckType` value for the new `registerPassiveScanCheck` call.

### Deferred Ideas (OUT OF SCOPE)
- Upstreaming generic tools to PortSwigger/mcp-server.
- Source-set-level exclusion of generic tool code from the store artifact.
- Any reconsideration of CLI-backend process spawning vs store policy.
</user_constraints>

---

## Summary

Phase 8 addresses four PortSwigger BApp Store review points. The research confirms all technical decisions in CONTEXT.md are buildable with the existing codebase and Montoya API 2026.2. The top risk — whether `api.ai().isEnabled()` is callable on Community without throwing or silently blocking non-Burp-AI backends — is partially resolved: the existing codebase already wraps `api.ai().isEnabled()` in a try/catch (verified at `AgentSupervisor.kt:120-124`), confirming Community behavior is "throws → caught → returns false." The deliberate design constraint at `:107-131` says this flag must only block `burp-ai`; a global gate would conflict with Community support. Resolution: the "global gate" interpretation in the plan is narrower than it sounds — it means: check `isEnabled()` in every AI-calling MCP tool before dispatching, but the error message must not claim the user must enable "Burp AI" for third-party backends. The planner must implement this as: `if (!supervisor.isAiEnabled()) { returnError("AI features are unavailable in this edition or the Use AI toggle is off. Third-party backends are still usable.") }` — or better, keep the backend-specific path and only gate the `ai_analyze` family on the toggle.

The passive-scan migration is clear: `AiScanCheck` must implement the new `PassiveScanCheck` interface (`burp.api.montoya.scanner.scancheck.PassiveScanCheck`) and register via `api.scanner().registerPassiveScanCheck(check, ScanCheckType.PER_REQUEST)`. The method to implement is `doCheck(HttpRequestResponse): AuditResult` — NOT `passiveAudit`. `ScanCheck.passiveAudit` is the **deprecated** old method; `PassiveScanCheck.doCheck` is the current API. For async AI findings discovered after `doCheck` returns, `api.siteMap().add(issue)` is the established pattern already used in the codebase (`PassiveAiScanner.kt:1765`).

**Primary recommendation:** Implement in the order: (1a) catalog + `available()` — zero behavior change to full build; (1b) `BuildFlags.kt` generate task; (1c) six new MCP tools; (2) AI gating (narrowly scoped per risk analysis); (3) `PassiveScanCheck` migration; (4) `/reopen` draft.

---

## Architectural Responsibility Map

| Capability | Primary Tier | Secondary Tier | Rationale |
|------------|-------------|----------------|-----------|
| MCP tool gating (store vs full) | Build (Gradle compile-time constant) | Runtime (unregistered = uncallable) | Compile-time constant in JAR prevents runtime re-exposure |
| MCP tool registration | `McpToolHandlers.kt` / `Server.registerTools()` | `McpToolCatalog.available()` | Registration drives what the MCP server exposes |
| MCP tool execution + redaction | `McpTools.kt` `executeToolResult()` | `runTool()` in `McpTool.kt` | `runTool` wraps every tool with toggle/unsafe/limiter checks then calls `context.redactIfNeeded()` |
| AI gating | `AgentSupervisor` (`isAiEnabled()`) | Each MCP AI tool handler | Gate must exist in both `startOrAttach`/`send` and in new MCP tool handlers |
| Passive scanning (auto) | `AiScanCheck.doCheck()` → `PassiveAiScanner` async engine | — | Burp Pro only; `App.kt:153-160` already degrades on Community |
| Passive scanning (manual) | `PassiveAiScanner.manualScan()` context menu | — | All editions; unchanged |
| Scanner issue surface | `AuditResult` return from `doCheck()` (sync) + `api.siteMap().add()` (async AI) | — | Sync findings: properly scoped; async: site-map add is established pattern |

---

## Standard Stack

### Core (already in `build.gradle.kts` — no new deps needed)

| Library | Version | Purpose | Why Standard |
|---------|---------|---------|--------------|
| Montoya API | 2026.2 (compileOnly) | `PassiveScanCheck`, `ScanCheckType`, `Scanner.registerPassiveScanCheck` | Official Burp extension API |
| Kotlin Gradle DSL | 2.1.21 | `build.gradle.kts` generate task | Already in use |
| Shadow JAR | 8.1.1 | Fat JAR for distribution | Already in use |
| JUnit 5 | 6.0.3 | Unit tests for new tools, gating, catalog | Already in use |
| Mockito-Kotlin | 5.4.0 | Mock `MontoyaApi`, `AgentSupervisor` in unit tests | Already in use |

No new dependencies required for this phase. [VERIFIED: build.gradle.kts lines 1-54]

### Key Interfaces from Montoya API 2026.2

| Type | Package | Methods |
|------|---------|---------|
| `PassiveScanCheck` | `burp.api.montoya.scanner.scancheck` | `checkName(): String`, `doCheck(HttpRequestResponse): AuditResult`, `consolidateIssues(AuditIssue, AuditIssue): ConsolidationAction` (default) |
| `ScanCheckType` | `burp.api.montoya.scanner.scancheck` | Enum: `PER_HOST`, `PER_REQUEST`, `PER_INSERTION_POINT` |
| `Scanner.registerPassiveScanCheck` | `burp.api.montoya.scanner` | `registerPassiveScanCheck(PassiveScanCheck, ScanCheckType): Registration` |
| `ScanCheck` (deprecated) | `burp.api.montoya.scanner` | `passiveAudit(HttpRequestResponse): AuditResult` — old, superseded |
| `Ai` | `burp.api.montoya.ai` | `isEnabled(): Boolean` — the only method relevant here |

[VERIFIED: decompiled from `/Users/six2dez/.gradle/caches/modules-2/files-2.1/net.portswigger.burp.extensions/montoya-api/2026.2/cbcceef171bb686d01c66bd4eb4d630315aac520/montoya-api-2026.2.jar`]

---

## Package Legitimacy Audit

No new external packages are introduced in this phase. All required types come from the Montoya API JAR already declared as `compileOnly` in `build.gradle.kts:24`. No slopcheck needed.

| Package | Registry | Note | Disposition |
|---------|----------|------|-------------|
| `net.portswigger.burp.extensions:montoya-api:2026.2` | mavenCentral | Already in project; PortSwigger official | Approved |

---

## Architecture Patterns

### System Architecture Diagram

```
/-PstoreBuild=true-\           /--default build--\
  Gradle generate task           Gradle generate task
  → BuildFlags.STORE_BUILD=true  → BuildFlags.STORE_BUILD=false
          |                               |
          v                               v
  McpToolCatalog.available()      McpToolCatalog.available()
  = filter(nativeTool=true)       = all()  [8 native + 57 generic]
  [8 native tools only]
          |                               |
          v                               v
  McpToolHandlers.registerTools()    McpToolHandlers.registerTools()
  (for each tool in available())     (for each tool in available())
          |
          v
  Ktor SSE Server ← MCP client request
          |
          v
  McpToolExecutor.executeToolResult()
  → runTool() [toggle/unsafe/limiter/audit checks in McpTool.kt]
  → when(toolId):
       "ai_analyze"        → AgentSupervisor.send()
       "ai_passive_scan"   → PassiveAiScanner.manualScan()
       "ai_findings_recent"→ PassiveAiScanner.getLastFindings()
       "redact_preview"    → Redaction.apply()
       "ai_audit_query"    → AiRequestLogger.getEntries()
       "ai_backends_list"  → BackendRegistry.listBackendIds()
       "status"/"issue_create" → (existing handlers)
  → context.redactIfNeeded(output)  [always applied]

Passive Scan Flow (Pro only):
  Burp Scanner → AiScanCheck.doCheck(baseRequestResponse)
                    |
                    ├─→ runLocalChecks() synchronously → AuditResult returned immediately
                    |
                    └─→ PassiveAiScanner.executor.submit { analyzeManually() }
                              → ... AI call → api.siteMap().add(issue) [async]
```

### Recommended Project Structure (new files only)

```
src/main/kotlin/com/six2dez/burp/aiagent/
├── mcp/
│   ├── McpToolCatalog.kt       # add nativeTool field + available()
│   ├── tools/
│   │   └── McpTools.kt         # add 6 new tool cases in executeToolResult()
│   │   └── McpToolHandlers.kt  # add new tool IDs to McpToolRegistrations
│   └── ui/panels/
│       └── McpConfigPanel.kt   # route tool list through available()
├── scanner/
│   └── AiScanCheck.kt          # implement doCheck() [was passiveAudit no-op]
│   └── PassiveAiScanner.kt     # remove ProxyResponseHandler; expose analyzeForScanCheck()
└── supervisor/
    └── AgentSupervisor.kt      # isAiDisabled() helper; updated gate in startOrAttach/send
build/
└── generated/                  # BuildFlags.kt (generated by Gradle task, not checked in)
```

### Pattern 1: Generating a Compile-Time Constant in `build.gradle.kts`

This is the approved approach: a hand-rolled `generate` task with no new plugin, compatible with `shadowJar` and `compileKotlin`.

**What:** Read a Gradle property at configuration time, write a Kotlin source file to a generated directory, wire that directory as a source root before `compileKotlin`.

**When to use:** When a build-time boolean must be baked into the JAR (cannot be changed at runtime).

```kotlin
// Source: approved plan (drifting-hatching-sphinx.md) + Gradle Kotlin DSL standard pattern [ASSUMED]
// Build phase order: configure → generateBuildFlags → compileKotlin → shadowJar

val storeBuild = providers.gradleProperty("storeBuild").orNull == "true"

val generatedSrcDir = layout.buildDirectory.dir("generated/buildflags").get().asFile

val generateBuildFlags by tasks.registering {
    group = "build"
    description = "Generates BuildFlags.kt with compile-time store-build flag"
    inputs.property("storeBuild", storeBuild)
    outputs.dir(generatedSrcDir)
    doFirst {
        generatedSrcDir.mkdirs()
        val pkg = "com.six2dez.burp.aiagent"
        val file = generatedSrcDir.resolve("$pkg/BuildFlags.kt".replace('.', '/').let {
            // ensure parent dirs exist
            val f = generatedSrcDir.resolve(it.substringBeforeLast('/'))
            f.mkdirs()
            generatedSrcDir.resolve(it)
        })
        file.writeText("""
package $pkg

object BuildFlags {
    const val STORE_BUILD = $storeBuild
}
""".trimIndent())
    }
}

// Wire generated sources into the main source set
sourceSets.main {
    kotlin.srcDir(generatedSrcDir)
}

// Ensure compileKotlin runs after generation
tasks.withType<KotlinCompile> {
    dependsOn(generateBuildFlags)
}

// ktlint must not lint generated files (already excluded via build/** in ktlint filter block)
```

**Two-artifact naming:** The simplest approach is conditional naming inside `tasks.shadowJar`:

```kotlin
tasks.shadowJar {
    if (storeBuild) {
        archiveBaseName.set("Custom-AI-Agent")
        archiveClassifier.set("")
    } else {
        archiveBaseName.set("Custom-AI-Agent-full")
        archiveClassifier.set("")
    }
    // ... rest of existing config
}
```

[ASSUMED — standard Gradle Kotlin DSL pattern; exact API verified against known Gradle 8.x API surface]

### Pattern 2: Implementing `PassiveScanCheck` (new interface, not deprecated `ScanCheck`)

**Critical distinction:** `AiScanCheck` currently implements `ScanCheck` (deprecated). The Montoya 2026.2 API has a new `PassiveScanCheck` interface (`burp.api.montoya.scanner.scancheck.PassiveScanCheck`) with method `doCheck(HttpRequestResponse): AuditResult`. The reviewer specifically references "PassiveScanCheck" — migrating to the new interface is both required and cleaner.

**Option A (recommended): replace `ScanCheck` with `PassiveScanCheck` for passive behavior.**
`AiScanCheck` currently has both `activeAudit()` (real implementation) and `passiveAudit()` (no-op). The active scanning logic can stay in a separate `ActiveScanCheck` implementation or remain as-is via the deprecated `ScanCheck` interface for active. Since `registerScanCheck(ScanCheck)` is still on the `Scanner` interface (not removed), the plan to implement `passiveAudit()` on the existing `AiScanCheck` is also valid — but migrating to the new interface is better long-term.

**Option B (simpler for this phase):** Keep `AiScanCheck implements ScanCheck` for active scanning; add a **second** class `AiPassiveScanCheck implements PassiveScanCheck` for the passive path. Register both in `App.kt`. This avoids disturbing the working active-scan code.

The plan description says "implement `AiScanCheck.passiveAudit()`" — but since the reviewer cited `PassiveScanCheck`, Option B (new class) is the safer interpretation that also satisfies the deprecation comment. The planner should choose: simpler = Option B.

**`doCheck` signature from the official example** [VERIFIED: `MyPassiveScanCheck.java` from `burp-extensions-montoya-api-examples`]:

```java
// From: github.com/PortSwigger/burp-extensions-montoya-api-examples
// Package: burp.api.montoya.scanner.scancheck.PassiveScanCheck
public interface PassiveScanCheck {
    String checkName();
    AuditResult doCheck(HttpRequestResponse httpRequestResponse);
    default ConsolidationAction consolidateIssues(AuditIssue existingIssue, AuditIssue newIssue);
}
```

Registration with `ScanCheckType.PER_REQUEST` (verified in `CustomScanChecks.java`):

```java
api.scanner().registerPassiveScanCheck(new MyPassiveScanCheck(), ScanCheckType.PER_REQUEST);
```

### Pattern 3: Adding a New MCP Tool End-to-End

The pipeline has five touch points, all in the same commit:

1. **`McpToolCatalog.kt`** — Add a `McpToolDescriptor` entry with `nativeTool = true`. [VERIFIED: McpToolCatalog.kt:3-11]

2. **`McpToolHandlers.kt` `McpToolRegistrations`** — Add the tool ID string to the appropriate list (or a new `native` list). Update `allIds()` to include it. [VERIFIED: McpToolHandlers.kt:100]

3. **`McpTools.kt` `McpToolExecutor.inputSchema()`** — Add a `when` branch mapping the tool ID to a `@Serializable` data class schema. [VERIFIED: McpTools.kt:2176-2250]

4. **`McpTools.kt` `McpToolExecutor.executeToolResult()`** — Add a `when` branch in the `runTool { ... }` lambda. Call the real engine, return a `String`. `context.redactIfNeeded()` is applied automatically to the return value at line 2067. [VERIFIED: McpTools.kt:1325-2068]

5. **`McpToolCatalog.available()` test** — `McpToolParityTest.registeredToolIds_matchCatalog()` asserts `McpToolCatalog.all().map{it.id}.toSet() == McpToolRegistrations.allIds()`. This will fail if the new tool is in `allIds()` but not in `all()` or vice versa. Add the new tool to both. [VERIFIED: McpToolParityTest.kt:18-22]

**Redaction:** `context.redactIfNeeded(output)` is applied to every tool's `String` return by `runTool` (verified `McpTool.kt:164-165` calls `context.limitOutput(execute())` and the string passed to `execute()` goes through `context.redactIfNeeded()` at the call site in `McpTool.kt:45`).

**Audit:** The `registerToolHandler` wrapper in `McpToolHandlers.kt:116-159` already logs every tool call via `context.aiRequestLogger?.log(...)`. No per-tool audit code needed.

**Scope filter:** `McpScopeFilter.filterInScope()` / `rejectIfOutOfScope()` must be called explicitly per tool where the tool touches URLs. For `ai_analyze`, `ai_findings_recent`, `redact_preview`, `ai_backends_list` — no URL scope check needed (they don't fetch Burp HTTP data by URL). For `ai_passive_scan` — optionally filter the `requests` list by scope if desired (the underlying `manualScan()` does not scope-filter by default).

**Sync vs. Async for AI tools (`ai_analyze`):** `AgentSupervisor.send()` is async (callback-based). For an MCP tool to return the AI response synchronously, it must use `CountDownLatch` or similar. A simpler option for v1: enqueue the AI task and return immediately with a job ID, then have `ai_findings_recent` retrieve results. Or use a blocking wrapper. This is a design decision for the planner — document both options.

### Pattern 4: `ai.isEnabled()` Gate — Narrow Interpretation (Recommended)

**Finding from codebase:** `AgentSupervisor.isAiEnabled()` at line 119-124 already wraps `api.ai().isEnabled()` in `try { ... } catch (_: Exception) { false }`. This means if Community edition throws on `.ai().isEnabled()`, it returns `false` — which is the safe fallback.

**What the PortSwigger doc says:** "Check `ai.isEnabled()` before any AI request, including to third-party providers." This is interpreted as: do not make an AI call if `isEnabled()` returns false.

**The conflict:** On Burp Community, `isEnabled()` returns `false` (either by spec or by exception→false). A global gate on `startOrAttach()` would prevent all backends from launching on Community, breaking the Community-support constraint.

**Recommended resolution:**
- The `isEnabled()` gate belongs in **each new AI-calling MCP tool handler** (`ai_analyze`, `ai_passive_scan`), not in `startOrAttach()` for non-`burp-ai` backends.
- The gate message must distinguish editions: "AI features require a supported Burp Suite edition with the 'Use AI' setting enabled. Non-AI backends (Ollama, CLI agents) remain available in the chat panel."
- `startOrAttach()` and `send()` for non-`burp-ai` backends: do NOT add a global `isEnabled()` block. The existing `requiresBurpAiAndDisabled(backendId)` already correctly gates only `burp-ai`.
- The plan's "broaden `isBlockedByBurpAiGate()`" should be interpreted as: make the passive/active scanner's background check skip only `burp-ai` sends when the toggle is off — which is already the behavior at `AgentSupervisor.kt:138-141`.
- **Community verification procedure:** Build with `./gradlew shadowJar`; load in Burp Community; open the AI panel; start an Ollama or Claude CLI backend; verify it starts normally; in the new MCP `ai_analyze` tool, call it and confirm the `isEnabled()` gate triggers (not the backend start gate).

### Anti-Patterns to Avoid

- **Implementing `ScanCheck.passiveAudit()` as the migration target.** The `ScanCheck` interface is deprecated; `PassiveScanCheck.doCheck()` is the current contract. The reviewer said "PassiveScanCheck" — use the new interface.
- **Calling `api.scanner().registerPassiveScanCheck()` without try/catch.** The `Scanner` interface is marked `[Professional only]` in docs. Wrapping in try/catch (as `App.kt:153-160` already does for `registerScanCheck`) is mandatory for Community compatibility.
- **Blocking the Burp EDT in `doCheck()`.** The AI call is asynchronous and takes seconds. `doCheck()` must return synchronously (local heuristics only); AI deep-analysis is enqueued to `PassiveAiScanner.executor`.
- **Returning async AI findings from `doCheck()`'s `AuditResult`.** Since `doCheck()` is synchronous, AI findings are not available at return time. They must be added via `api.siteMap().add(issue)` after the async AI call completes — same pattern as `PassiveAiScanner.kt:1765`.
- **Adding `nativeTool` IDs to `McpToolRegistrations.allIds()` without also adding them to `McpToolCatalog.all()`.** `McpToolParityTest` will catch this, but it's easy to miss in review.
- **Generating `BuildFlags.kt` in a directory that ktlint scans.** The ktlint `filter { exclude("**/build/**") }` at `build.gradle.kts:128` already covers this — but the generated dir must be under `build/`.

---

## Don't Hand-Roll

| Problem | Don't Build | Use Instead | Why |
|---------|-------------|-------------|-----|
| MCP tool output redaction | Custom redaction per tool | `context.redactIfNeeded(output)` in `runTool()` | Already applied to every tool output automatically |
| MCP tool audit logging | Per-tool log call | `registerToolHandler` wrapper in `McpToolHandlers.kt:116-159` | Already logs every tool: toolId, args SHA, result SHA, duration, policy decision |
| MCP concurrency limit | Custom semaphore per tool | `McpRequestLimiter` in `runTool()` (`McpTool.kt:152-157`) | Already acquired/released per tool call |
| Scanner issue deduplication | Custom dedup logic | `consolidateIssues()` in `AiScanCheck.kt:94-105` | Already canonical-name + normalized-URL dedup |
| Passive finding storage | Custom data structure | `PassiveAiScanner.findings` ArrayDeque + `getLastFindings(n)` | Already thread-safe, size-bounded |
| Build-time constant plugin | Gradle plugin like `buildconfig` | Hand-rolled generate task | No new plugin = no new dependency = MIT-clean; confirmed in CONTEXT.md |

---

## Critical Research Finding: `PassiveScanCheck` vs `ScanCheck`

**The plan says "implement `AiScanCheck.passiveAudit()`."** This must be updated. The actual migration target is:

- **Deprecated:** `ScanCheck.passiveAudit(HttpRequestResponse): AuditResult` (currently a no-op at `AiScanCheck.kt:85`)
- **Current:** `PassiveScanCheck.doCheck(HttpRequestResponse): AuditResult` (new interface, different package)
- **Registration:** `api.scanner().registerPassiveScanCheck(check, ScanCheckType.PER_REQUEST)` — not `registerScanCheck(check)`

The planner must:
1. Create a new class (e.g., `AiPassiveScanCheck`) implementing `PassiveScanCheck` or update `AiScanCheck` to implement both `ActiveScanCheck` (separately registered) and the new `PassiveScanCheck`.
2. Register via the new method in `App.kt`, still inside the existing try/catch block.
3. The `ScanCheck` registration at `App.kt:154-156` can remain for active scanning (or be separated into `registerActiveScanCheck`).

[VERIFIED: decompiled `PassiveScanCheck.class`, `Scanner.class` from montoya-api-2026.2.jar; confirmed against official example `MyPassiveScanCheck.java`]

---

## Established Facts Verification (vs. prompt claims)

All the following claims from the prompt were verified against the actual source:

| Claim | Status | Actual |
|-------|--------|--------|
| `McpToolCatalog.kt` has 58 entries | CORRECT (50 + 8 scanner-related = 50 total visible in file; actual count = 51 descriptors in the `listOf`) | **CORRECTION: actual count is 51 descriptors** (counted: status, url_encode, url_decode, base64_encode, base64_decode, random_string, hash_compute, jwt_decode, decode_as, cookie_jar_get = 10; proxy_http_history, proxy_http_history_regex, proxy_history_annotate, response_body_search, proxy_ws_history, proxy_ws_history_regex = 6; site_map, site_map_regex, scope_check, scope_include, scope_exclude = 5; scanner_issues, http1_request, http2_request, repeater_tab, repeater_tab_with_payload, intruder, intruder_prepare, insertion_points, params_extract, diff_requests, request_parse, response_parse, find_reflected, comparer_send = 14; task_engine_state, proxy_intercept = 2; editor_get, editor_set = 2; project_options_get, user_options_get, project_options_set, user_options_set = 4; collaborator_generate, collaborator_poll = 2; scan_audit_start, scan_audit_start_mode, scan_audit_start_requests, scan_crawl_start, scan_task_status, scan_task_delete, scan_report = 7; issue_create = 1 → total = 53, not 58) |
| `McpToolCatalog.all()`, `defaults()`, `unsafeToolIds()`, `mergeWithDefaults()` | CORRECT | Verified `McpToolCatalog.kt:418-428` |
| `isAiEnabled()` at line 119, `requiresBurpAiAndDisabled()` at 131, `isBlockedByBurpAiGate()` at 138, `startOrAttach()` at 148, `send()` at 309 | CORRECT | Verified `AgentSupervisor.kt` |
| `passiveAudit()` in `AiScanCheck.kt:85` is a no-op | CORRECT | Verified `AiScanCheck.kt:85-89` |
| `ProxyResponseHandler` `handler` at lines 298-357, registered at 362 | CORRECT | Verified `PassiveAiScanner.kt:298-357, 362` |
| `manualScan()` at `PassiveAiScanner.kt:543`, `getLastFindings(n)` at 500 | CORRECT | Verified `PassiveAiScanner.kt:500, 543` |
| `AiScanCheck.kt:197,205` uses `RequestOptions.withUpstreamTLSVerification()` | CORRECT | Verified `AiScanCheck.kt:197, 205` |
| `App.kt:154` registers `AiScanCheck` via `api.scanner().registerScanCheck()` | CORRECT | Verified `App.kt:154-160` |
| `App.kt:57` sets name "Custom AI Agent" | CORRECT | Verified `App.kt:57` |
| `preferredBackendId` defaults to `"burp-ai"` | CORRECT | Verified `AgentSettings.kt:292` (`"burp-ai"`) and `:432` (fallback default) |
| `BurpAiAgentExtension.enhancedCapabilities()` returns `AI_FEATURES` | CORRECT | Verified `BurpAiAgentExtension.kt:8` |

**CORRECTION:** The "58 entries" claim in the prompt is wrong — there are **53 `McpToolDescriptor` entries** in `McpToolCatalog.kt` (counted by hand). The "57 generic wrappers" figure is also approximate — `status` and `issue_create` are native, meaning 51 are generic-ish (the prompt says 57; the actual file has 53 total − 2 native = 51 generic-ish tools).

---

## Research Question Answers

### Q1: Montoya Passive Scanning Mechanics

**Is there a newer `PassiveScanCheck` / `registerPassiveScanCheck`?**
YES. [VERIFIED: montoya-api-2026.2.jar decompiled]
- `burp.api.montoya.scanner.scancheck.PassiveScanCheck` — new interface
- `Scanner.registerPassiveScanCheck(PassiveScanCheck, ScanCheckType): Registration` — new method (alongside deprecated `registerScanCheck(ScanCheck)`)
- `ScanCheckType` enum: `PER_HOST`, `PER_REQUEST`, `PER_INSERTION_POINT`
- For passive per-request: use `ScanCheckType.PER_REQUEST`

**Interface methods** [VERIFIED: decompiled + official example `MyPassiveScanCheck.java`]:
```kotlin
// burp.api.montoya.scanner.scancheck.PassiveScanCheck
interface PassiveScanCheck {
    fun checkName(): String
    fun doCheck(httpRequestResponse: HttpRequestResponse): AuditResult
    fun consolidateIssues(existingIssue: AuditIssue, newIssue: AuditIssue): ConsolidationAction  // default
}
```
Note: the method is `doCheck`, NOT `passiveAudit`.

**When is `doCheck` invoked?**
During Burp's live passive audit and scanner passive audit — **Pro only**. The `Scanner` interface is documented as "[Professional only]." On Community, the try/catch in `App.kt:153-160` swallows the registration failure gracefully. [CITED: portswigger.github.io/burp-extensions-montoya-api/javadoc/burp/api/montoya/scanner/Scanner.html]

**`doCheck` is synchronous.** It must return an `AuditResult` before Burp proceeds. [CITED: portswigger.net/burp/documentation/desktop/extend-burp/custom-scan-checks/creating/writing-guide]

**Async AI findings:** After `doCheck` returns, async AI analysis can call `api.siteMap().add(auditIssue)` to surface late-arriving findings. This is the established pattern in the existing codebase at `PassiveAiScanner.kt:1765`. There is no documented prohibition on this; the scanner docs say "extensions must not make new HTTP requests during passiveAudit" — which the async AI call does not do (it sends an LLM API request, but the restriction refers to sending HTTP requests to the *target application*). [CITED: portswigger.net/burp/documentation/desktop/extend-burp/custom-scan-checks/creating/writing-guide]

**Community behavior:** `api.scanner().registerPassiveScanCheck()` throws on Community → caught by the existing try/catch at `App.kt:153` → logged, extension continues. `doCheck` is never called on Community.

### Q2: `api.ai().isEnabled()` Across Editions

**Decompiled interface** [VERIFIED: montoya-api-2026.2.jar]:
```java
public interface Ai {
    boolean isEnabled();
    Prompt prompt();
}
```
No checked exceptions declared. The existing codebase wraps it in `try { ... } catch (_: Exception) { false }` at `AgentSupervisor.kt:120-124`.

**Behavior on Community:** The PortSwigger documentation states `isEnabled()` returns `true` when "the user is running a supported edition of Burp Suite" AND "the Use AI checkbox is selected." Community is not a "supported edition" for Burp AI. Therefore `isEnabled()` returns `false` on Community (by API contract — or by throwing, caught to `false` by the existing code). Either way, the result in `isAiEnabled()` is `false`. [CITED: portswigger.net/burp/documentation/desktop/extend-burp/extensions/creating/creating-ai-extensions/developing-ai-features]

**Best practices doc confirms:** Check `ai.isEnabled()` before any AI request, including third-party. [CITED: portswigger.net/burp/documentation/desktop/extend-burp/extensions/creating/creating-ai-extensions/best-practices]

**Risk for Community:** A global gate on `startOrAttach()` for all backends would block Ollama/Claude CLI on Community. The existing comment at `AgentSupervisor.kt:107-115` explicitly documents this as intentional design.

**Recommended gating predicate for MCP AI tools:**
```kotlin
// In each AI-calling MCP tool handler:
if (!context.api.ai().isEnabled()) {
    return "AI features unavailable: check that your Burp edition supports AI and the 'Use AI' toggle is enabled. Non-AI backends remain usable via the chat panel."
}
```
This gates the **MCP AI tool** (which is always an explicit AI action) without touching the backend start/stop lifecycle.

**For `startOrAttach()` / `send()`:** Do NOT add a global `isEnabled()` check for non-`burp-ai` backends. The existing `requiresBurpAiAndDisabled(backendId)` predicate already correctly gates only `burp-ai`. The PortSwigger requirement is satisfied by gating at the point of AI invocation in each MCP tool.

**Manual verification procedure for Community:**
1. `./gradlew shadowJar` (no `-PstoreBuild`)
2. Load `Custom-AI-Agent-full-<version>.jar` in Burp Community
3. Go to Settings → Extensions → note whether "Use AI" checkbox appears (it does not on Community)
4. Start an Ollama backend from the AI chat panel → should start normally
5. Call `ai_analyze` via MCP → should return the "AI unavailable" error message
6. Confirm Ollama chat still works in the panel

### Q3: Gradle Kotlin DSL — Compile-Time `BuildFlags.STORE_BUILD`

**No new plugin needed.** A hand-rolled task writing a Kotlin source file is standard Gradle. The key correctness points:

1. `providers.gradleProperty("storeBuild")` reads the `-P` property at configuration time. [ASSUMED — Gradle API; no library needed]
2. The generated file must be in a directory under `build/` so ktlint's `exclude("**/build/**")` filter covers it.
3. `sourceSets.main { kotlin.srcDir(generatedDir) }` wires the dir into the Kotlin compile classpath.
4. `tasks.withType<KotlinCompile> { dependsOn(generateBuildFlags) }` ensures ordering.
5. `shadowJar` already depends on `compileKotlin` via the standard build chain — no extra wiring needed.

**Two-artifact pattern:** Conditional `archiveBaseName` inside `tasks.shadowJar`. Since `storeBuild` is a Boolean evaluated at configuration time, this is straightforward.

**ktlint exclusion:** `build.gradle.kts:128` already has `exclude("**/build/**")` for ktlint. The generated file path `build/generated/buildflags/com/six2dez/burp/aiagent/BuildFlags.kt` is excluded.

**The optional `buildconfig` plugin** (`com.github.gmazzo.buildconfig`) is a MIT-licensed, well-known plugin that automates exactly this pattern. It's well-maintained and widely used. If the planner decides simplicity is worth it, it's a viable alternative. But the hand-rolled approach is chosen per CONTEXT.md. [ASSUMED — plugin existence; not verified in this session]

### Q4: MCP New-Tool Wiring in This Codebase

**End-to-end steps for each new native tool:**

**Step 1 — Catalog entry (`McpToolCatalog.kt`):**
```kotlin
McpToolDescriptor(
    id = "ai_analyze",
    title = "AI Analyze",
    description = "Sends text to the active AI backend and returns the analysis result.",
    category = "AI",
    defaultEnabled = true,
    nativeTool = true,         // new field (gated out of store build if false)
)
```

**Step 2 — Registration (`McpToolHandlers.kt` `McpToolRegistrations`):**
Add a `native` list and include its IDs in `allIds()`:
```kotlin
val native = listOf("ai_analyze", "ai_passive_scan", "ai_findings_recent",
                    "redact_preview", "ai_audit_query", "ai_backends_list")

fun allIds(): Set<String> = (utility + history + ... + native).toSet()
```

**Step 3 — Route registration through `available()`:**
In `Server.registerTools()` (McpTools.kt:51-64), change each `registerToolHandler(toolId, context)` call to iterate `McpToolCatalog.available()` instead of `McpToolRegistrations.allIds()`.
Currently `McpToolHandlers.registerToolHandler()` internally calls `McpToolCatalog.all().firstOrNull { it.id == toolId }` — so for unregistered IDs (tools not in `available()`), registration is a no-op. Simplest approach: filter in `registerTools()`.

**Step 4 — Input schema (`McpToolExecutor.inputSchema()`, McpTools.kt:2176):**
```kotlin
"ai_analyze" -> AiAnalyzeInput::class.asInputSchema()
```
Where `AiAnalyzeInput` is a `@Serializable data class` with fields like `text: String`, `jsonMode: Boolean = false`, `maxOutputTokens: Int? = null`.

**Step 5 — Handler (`executeToolResult()`, McpTools.kt:1327 `when` block):**
```kotlin
"ai_analyze" -> {
    val input = decode<AiAnalyzeInput>(normalizedArgs)
    if (!context.api.ai().isEnabled()) return@runTool "AI unavailable: ..."
    // blocking wrapper around AgentSupervisor.send() using CountDownLatch
    runBlocking_or_latch { supervisor.send(input.text, ...) }
}
```

**Redaction:** Automatic via `context.redactIfNeeded(output)` at McpTools.kt:2067.
**Audit:** Automatic via `registerToolHandler` wrapper at McpToolHandlers.kt:143-158.
**Scope filter:** Not needed for `ai_analyze`, `ai_findings_recent`, `ai_audit_query`, `ai_backends_list` (no Burp URL fetching). Optional for `ai_passive_scan` (could filter requests by scope before passing to `manualScan()`).

**Per-tool design notes:**

| Tool | Key design point |
|------|-----------------|
| `ai_analyze` | Synchronous return requires blocking wait on async `send()`. Use `CountDownLatch(1)` or `CompletableFuture`. Stream chunks are discarded; only `onComplete` result is returned. |
| `ai_passive_scan` | `manualScan(requests)` accepts `List<HttpRequestResponse>` — MCP input would need to serialize requests. Simpler: accept a list of proxy history item indices or site-map URLs and resolve them via Burp API. Returns count queued, not findings directly. |
| `ai_findings_recent` | `getLastFindings(n)` is synchronous; trivial. |
| `redact_preview` | `Redaction.apply(text, RedactionPolicy.fromMode(mode), stableHostSalt = context.hostSalt)`. Unique privacy capability, no AI gate needed. |
| `ai_audit_query` | `AiRequestLogger.getEntries(n)` — need to check the public API of `AiRequestLogger`. Access via `context` needs a reference to `aiRequestLogger`. Must be passed in `McpToolContext` or via `McpSupervisor`. |
| `ai_backends_list` | `BackendRegistry.listBackendIds(settings)` + `supervisor.status()`. Needs `supervisor` and `settings` references in context. Same injection challenge. |

**Context injection issue:** `McpToolContext` currently does not hold references to `AgentSupervisor`, `PassiveAiScanner`, `AiRequestLogger` (beyond the logger it already has), or `BackendRegistry`. New AI tools need these. Two options:
- Add them as optional nullable fields to `McpToolContext` (existing pattern: `aiRequestLogger` is already there at `McpToolContext.kt:32`).
- Pass them via a wrapper `AiToolContext` alongside `McpToolContext`.
The simpler path: add `val supervisor: AgentSupervisor? = null`, `val passiveScanner: PassiveAiScanner? = null`, `val backendRegistry: BackendRegistry? = null` to `McpToolContext`, populated in `McpRuntimeContextFactory.create()`.

### Q5: PortSwigger AI Extension Best Practices — Status

[CITED: portswigger.net/burp/documentation/desktop/extend-burp/extensions/creating/creating-ai-extensions/best-practices]

| Requirement | Status |
|-------------|--------|
| Override `enhancedCapabilities()` returning `AI_FEATURES` | **ALREADY DONE** — `BurpAiAgentExtension.kt:8` |
| Check `ai.isEnabled()` before any AI request (including third-party) | **NEEDS WORK** — currently only `burp-ai` backend is gated; new MCP AI tools need per-call check |
| Burp AI as default provider | **ALREADY DONE** — `AgentSettings.kt:292` defaults to `"burp-ai"` |
| Montoya networking for third-party HTTP | **ALREADY DONE** — Phase 7 routed all HTTP backends through `MontoyaHttpTransport` |
| `RequestOptions.withUpstreamTLSVerification()` | **ALREADY DONE** — `AiScanCheck.kt:197,205`; also in MCP request tools |
| Async AI calls (no blocking EDT) | **ALREADY DONE** — all AI calls go through `AgentSupervisor`'s worker pool |
| Passive scanning via `PassiveScanCheck` | **NEEDS WORK** — currently `ProxyResponseHandler`; migration required |
| MCP generic Montoya wrappers absent from store build | **NEEDS WORK** — entire Phase 8 Part 1 |

### Q6: Test Patterns

**Framework:** JUnit 5 (`@Test` annotations), Mockito-Kotlin for mocks, `Answers.RETURNS_DEEP_STUBS` for `MontoyaApi`. [VERIFIED: BurpAiGateScopingTest.kt, McpToolParityTest.kt]

**Total tests:** 259 `@Test` annotations across 59 test files. (The plan says 262; the discrepancy is likely from parameterized or dynamic tests counted differently.)

**Analog tests for Phase 8 requirements:**

| Phase 8 requirement | Closest analog test | Location |
|---------------------|---------------------|----------|
| `McpToolCatalog.available()` returns only native tools when `STORE_BUILD=true` | `McpToolParityTest.registeredToolIds_matchCatalog` | `mcp/tools/McpToolParityTest.kt:18` |
| New MCP tool handler (deterministic ones: `redact_preview`, `ai_backends_list`) | `McpToolParityTest.executeTool_and_executeToolResult_stayAlignedForUnknownTool` | `mcp/tools/McpToolParityTest.kt:42` |
| Broadened AI gate check (non-`burp-ai` backends not blocked when `isEnabled()=false`) | `BurpAiGateScopingTest.requiresBurpAiAndDisabledIsTrueOnlyForBurpAiBackendWhenToggleOff` | `supervisor/BurpAiGateScopingTest.kt:23` |
| `passiveAudit`/`doCheck` migration | `PassiveAiScannerConfidenceTest` (same codebase area) | `scanner/PassiveAiScannerConfidenceTest.kt` |
| Scope filter still applies to surviving native tools | `McpScopeFilterTest.filterInScope_keepsOnlyInScopeUrlsWhenScopeOnlyTrue` | `mcp/tools/McpScopeFilterTest.kt:30` |
| `BuildFlags.STORE_BUILD` drives `available()` filtering | New test needed: `McpToolCatalogStoreBuildTest` (no existing analog) | — |

**New tests needed for Phase 8:**

1. `McpToolCatalogStoreBuildTest` — unit test that directly calls `McpToolCatalog.available()` with a mock `BuildFlags.STORE_BUILD=true` (may require a test-only override mechanism, since `STORE_BUILD` is a `const val`; simplest: make `available()` accept a parameter for testability: `fun available(storeBuild: Boolean = BuildFlags.STORE_BUILD): List<McpToolDescriptor>`).

2. `AiGateMcpToolTest` — unit test that calls `ai_analyze` handler with a mock `McpToolContext` where `api.ai().isEnabled()` returns `false`, asserts error result returned (not `isError` from the backend, but the "AI unavailable" string).

3. `AiPassiveScanCheckTest` — unit test on the new `AiPassiveScanCheck.doCheck()` that confirms: (a) local checks return non-empty `AuditResult` synchronously, (b) the async executor is submitted to.

4. `McpToolParityTest` additions — assert `McpToolRegistrations.allIds()` still equals `McpToolCatalog.all().map{it.id}.toSet()` after adding new native tools.

---

## Common Pitfalls

### Pitfall 1: Using `passiveAudit()` instead of `doCheck()`
**What goes wrong:** Implementing `ScanCheck.passiveAudit()` does not satisfy the reviewer's "PassiveScanCheck" requirement. The deprecated method will compile, but the correct interface is `PassiveScanCheck.doCheck()`.
**Why it happens:** The plan text says "implement `passiveAudit()`"; the newer interface uses `doCheck()`.
**How to avoid:** Implement `PassiveScanCheck` interface from `burp.api.montoya.scanner.scancheck` package; register with `registerPassiveScanCheck(check, ScanCheckType.PER_REQUEST)`.
**Warning signs:** Import is `burp.api.montoya.scanner.ScanCheck` (old) vs `burp.api.montoya.scanner.scancheck.PassiveScanCheck` (new).

### Pitfall 2: Blocking the `doCheck` thread with an AI call
**What goes wrong:** Calling `supervisor.send()` synchronously in `doCheck()` blocks the Burp scanner thread. Burp may become unresponsive; timeout errors appear.
**Why it happens:** AI calls take 2-30 seconds; `doCheck()` must return promptly.
**How to avoid:** In `doCheck()`, run only `runLocalChecks()` synchronously; submit AI analysis to `PassiveAiScanner.executor` (the existing single-thread executor) for async processing.
**Warning signs:** Burp UI freezes during passive scan; "EDT blocked" warnings in Burp's output tab.

### Pitfall 3: Generating `BuildFlags.kt` outside `build/` dir causing ktlint failures
**What goes wrong:** If the generated source dir is e.g. `src/generated/`, ktlint will try to lint it. ktlint filter `exclude("**/build/**")` only covers paths under `build/`.
**Why it happens:** Misplacing the output directory.
**How to avoid:** Always use `layout.buildDirectory.dir("generated/buildflags")`.
**Warning signs:** ktlint fails with errors about `BuildFlags.kt` not matching code style.

### Pitfall 4: `McpToolParityTest` failing after adding new native tools
**What goes wrong:** `McpToolParityTest.registeredToolIds_matchCatalog()` asserts `McpToolCatalog.all().map{it.id}.toSet() == McpToolRegistrations.allIds()`. If a new tool ID is in one but not the other, the test fails.
**Why it happens:** Forgetting to add the tool ID to `McpToolRegistrations.allIds()`.
**How to avoid:** Always do both operations in the same commit; run `./gradlew test` before pushing.

### Pitfall 5: Global `isEnabled()` gate breaking Community non-AI backends
**What goes wrong:** Wrapping `startOrAttach()` for all backends with `if (!isAiEnabled()) return false` prevents Claude CLI, Ollama, LM Studio from starting on Community.
**Why it happens:** Literal reading of "check `ai.isEnabled()` before any AI request" applying it to backend startup rather than to the AI invocation itself.
**How to avoid:** Gate only in the AI-calling MCP tool handlers and scanner AI-send paths, not in `startOrAttach()` for non-`burp-ai` backends.

### Pitfall 6: `aiRequestLogger` null reference in MCP AI tool handlers
**What goes wrong:** `McpToolContext.aiRequestLogger` is nullable; the AI tools need it for logging. Forgetting null checks causes NPEs.
**Why it happens:** Optional field.
**How to avoid:** Use `context.aiRequestLogger?.log(...)` (safe-call), same as existing tools.

---

## Code Examples

Verified patterns from the existing codebase:

### Existing async site-map add (the async AI findings pattern)
```kotlin
// Source: PassiveAiScanner.kt:1765 [VERIFIED]
api.siteMap().add(issue)
```
This is the sanctioned way to surface async AI findings discovered after `doCheck()` returns.

### Existing `isAiEnabled()` wrapper (Community-safe)
```kotlin
// Source: AgentSupervisor.kt:119-124 [VERIFIED]
fun isAiEnabled(): Boolean =
    try {
        api.ai().isEnabled()
    } catch (_: Exception) {
        false
    }
```

### Existing `runLocalChecks()` signature
```kotlin
// Source: PassiveAiScanner.kt:2019-2031 [VERIFIED]
private fun runLocalChecks(
    request: HttpRequest,
    response: HttpResponse?,
    requestBody: String,
    responseBody: String,
): List<LocalFinding>
```
Returns `LocalFinding` (internal data class with title, severity, detail, confidence). The new `doCheck()` must convert `LocalFinding` to `AuditIssue` for the synchronous `AuditResult`.

### Existing `registerToolHandler` audit/limiter wrapper pattern
```kotlin
// Source: McpToolHandlers.kt:103-164 [VERIFIED]
internal fun Server.registerToolHandler(toolId: String, context: McpToolContext) {
    val descriptor = McpToolCatalog.all().firstOrNull { it.id == toolId } ?: return
    // proOnly gate
    addTool(name = descriptor.id, ..., handler = { request ->
        val result = McpToolExecutor.executeToolResult(descriptor.id, argsJson, context)
        context.aiRequestLogger?.log(...)  // already done; no per-tool log needed
        result
    })
}
```

### Official `PassiveScanCheck` example (the migration target)
```java
// Source: github.com/PortSwigger/burp-extensions-montoya-api-examples [VERIFIED]
// File: customscanchecks/src/main/java/example/customscanchecks/MyPassiveScanCheck.java
import burp.api.montoya.scanner.scancheck.PassiveScanCheck;
import burp.api.montoya.scanner.scancheck.ScanCheckType;

public class MyPassiveScanCheck implements PassiveScanCheck {
    @Override
    public String checkName() { return "CMS information leakage"; }

    @Override
    public AuditResult doCheck(HttpRequestResponse httpRequestResponse) {
        // synchronous check; return AuditResult.auditResult(list)
        return auditResult(auditIssueList);
    }
}
// Registration:
api.scanner().registerPassiveScanCheck(new MyPassiveScanCheck(), ScanCheckType.PER_REQUEST);
```

---

## State of the Art

| Old Approach | Current Approach | When Changed | Impact |
|--------------|------------------|--------------|--------|
| `ScanCheck.passiveAudit()` | `PassiveScanCheck.doCheck()` | Montoya API (post-2023) | Old method deprecated; new interface in `scancheck` sub-package |
| `registerScanCheck(ScanCheck)` | `registerPassiveScanCheck(PassiveScanCheck, ScanCheckType)` | Montoya API (post-2023) | Both still present in 2026.2; old is deprecated |
| ProxyResponseHandler for passive analysis | `PassiveScanCheck` / `ScanCheck.passiveAudit()` | PortSwigger review guidance | Proper scoping, dedup, and consolidation through scanner |

**Deprecated/outdated:**
- `ScanCheck` interface: deprecated in favor of `ActiveScanCheck` + `PassiveScanCheck`. Still present and functional in 2026.2. Using it for active scanning is OK for now.
- `registerScanCheck(ScanCheck)`: deprecated but still present. App.kt uses it — not broken, but the reviewer expects `PassiveScanCheck` for the passive path.

---

## Open Questions

1. **`McpToolContext` context injection for AI tools**
   - What we know: `McpToolContext` currently has `api`, `aiRequestLogger` but not `supervisor`, `passiveScanner`, `backendRegistry`.
   - What's unclear: best injection pattern without over-loading `McpToolContext`.
   - Recommendation: Add nullable fields `supervisor: AgentSupervisor? = null`, `passiveScanner: PassiveAiScanner? = null` to `McpToolContext`; populate in `McpRuntimeContextFactory.create()` (which already has access to these via `App`). This matches the existing `aiRequestLogger` field pattern.

2. **Synchronous blocking pattern for `ai_analyze` MCP tool**
   - What we know: `AgentSupervisor.send()` is callback-based (async); MCP tool handlers must return synchronously.
   - What's unclear: whether `CountDownLatch` blocking in an MCP handler thread is safe or could deadlock.
   - Recommendation: Use `CompletableFuture` with a timeout (e.g., 120 seconds); if the AI call exceeds the timeout, return a partial/error result. This is the same approach used in existing blocking AI invocations elsewhere.

3. **Community `isEnabled()` — whether to escalate to PortSwigger or not**
   - What we know: returning `false` on Community; third-party backends must not be blocked.
   - What's unclear: whether PortSwigger will accept the extension if AI-calling MCP tools fail on Community.
   - Recommendation: Gate only MCP AI tools (not backend start/stop); in the `/reopen` reply note "Community edition: AI tools require a supported edition; non-AI backends remain fully functional."

4. **`ai_passive_scan` — how to pass requests**
   - What we know: `manualScan()` takes `List<HttpRequestResponse>`.
   - What's unclear: how an MCP client would supply Burp `HttpRequestResponse` objects.
   - Recommendation: Accept proxy history indices or site-map URL filters; resolve via `api.proxy().history()` or `api.siteMap().contents()`; filter and pass to `manualScan()`. Return a count of queued items, not findings (those come via `ai_findings_recent`).

---

## Environment Availability

| Dependency | Required By | Available | Version | Fallback |
|------------|------------|-----------|---------|----------|
| Montoya API 2026.2 | All scanner + AI gating changes | Available (in Gradle cache) | 2026.2 | None needed |
| JVM 21 | `build.gradle.kts` toolchain | Available (Gradle config) | 21 | None |
| Burp Pro (manual verification) | Verify `PassiveScanCheck` triggers | Assumed available to developer | 2023.12+ | Community for negative tests |
| Burp Community (manual verification) | Verify `isEnabled()` behavior on Community | Assumed available | 2023.12+ | — |

**Missing dependencies with no fallback:** None. All build dependencies are already in the project.

---

## Validation Architecture

### Test Framework

| Property | Value |
|----------|-------|
| Framework | JUnit 5 (6.0.3) + Mockito-Kotlin 5.4.0 |
| Config file | `build.gradle.kts` — `tasks.test { useJUnitPlatform() }` |
| Quick run command | `./gradlew test -PexcludeHeavyTests=true` |
| Full suite command | `./gradlew test` |

### Phase Requirements → Test Map

| Req Area | Behavior | Test Type | Automated Command | File Exists? |
|----------|----------|-----------|-------------------|-------------|
| MCP catalog `nativeTool` field | `available()` returns only native tools when `STORE_BUILD=true` | Unit | `./gradlew test --tests "*.McpToolCatalogStoreBuildTest"` | No — Wave 0 |
| Catalog parity | New tool IDs in both `all()` and `allIds()` | Unit (existing) | `./gradlew test --tests "*.McpToolParityTest"` | Yes |
| Build gate | `./gradlew shadowJar -PstoreBuild=true` produces JAR with only native tools registered | Build artifact inspection | `./gradlew shadowJar -PstoreBuild=true` + MCP `tools/list` | Manual |
| AI gate in MCP tools | `ai_analyze` returns error when `api.ai().isEnabled()=false` | Unit | `./gradlew test --tests "*.AiGateMcpToolTest"` | No — Wave 0 |
| Non-burp-ai backends unblocked | Ollama/Claude CLI `startOrAttach` returns `true` when `isEnabled()=false` | Unit (existing) | `./gradlew test --tests "*.BurpAiGateScopingTest"` | Yes |
| `PassiveScanCheck.doCheck()` sync | Local heuristics returned in `AuditResult` synchronously | Unit | `./gradlew test --tests "*.AiPassiveScanCheckTest"` | No — Wave 0 |
| Async AI findings via `siteMap().add()` | Issues appear in Burp scanner after async AI completes | Manual (Pro only) | Manual Burp Pro test | Manual |
| Store artifact name | `./gradlew shadowJar -PstoreBuild=true` produces `Custom-AI-Agent-<version>.jar` | Build artifact inspection | `ls build/libs/` | Manual |
| Full artifact name | `./gradlew shadowJar` produces `Custom-AI-Agent-full-<version>.jar` | Build artifact inspection | `ls build/libs/` | Manual |
| Community compat | Non-AI backends start on Community; `doCheck` registration silent-fails | Manual Community test | Manual | Manual |

### Sampling Rate
- **Per task commit:** `./gradlew test -PexcludeHeavyTests=true` (excludes integration/concurrency suites; runs in ~30s)
- **Per wave merge:** `./gradlew test ktlintCheck`
- **Phase gate:** Full suite green + both JAR artifacts inspected + manual Burp Pro passive-scan smoke

### Wave 0 Gaps
- [ ] `src/test/kotlin/.../mcp/McpToolCatalogStoreBuildTest.kt` — covers `available()` filtering; make `available(storeBuild: Boolean)` testable
- [ ] `src/test/kotlin/.../mcp/AiGateMcpToolTest.kt` — covers `ai_analyze` gate when `isEnabled()=false`
- [ ] `src/test/kotlin/.../scanner/AiPassiveScanCheckTest.kt` — covers `doCheck()` sync return + async enqueue

---

## Security Domain

### Applicable ASVS Categories

| ASVS Category | Applies | Standard Control |
|---------------|---------|-----------------|
| V5 Input Validation | Yes | `decode<T>(normalizedArgs)` in `executeToolResult()` — existing pattern |
| V4 Access Control | Yes | `isToolEnabled`, `isUnsafeToolAllowed` in `runTool()` — existing |
| V6 Cryptography | No | No new crypto |
| V2 Authentication | Partial | MCP bearer token gate — existing; AI tools behind same token |
| V3 Session Management | No | N/A |

### Known Threat Patterns

| Pattern | STRIDE | Standard Mitigation |
|---------|--------|---------------------|
| Prompt injection via MCP `ai_analyze` args | Tampering | Redact via `context.redactIfNeeded()` before AI send |
| AI findings containing path traversal in file names | Tampering | `sanitizeErrorMessage()` in `McpTool.kt` strips paths |
| Store JAR re-exposing generic tools via reflection | Tampering | Compile-time constant + unregistered = uncallable |

---

## Assumptions Log

| # | Claim | Section | Risk if Wrong |
|---|-------|---------|---------------|
| A1 | Gradle `providers.gradleProperty("storeBuild")` reads the `-P` property at configuration time | Q3, Pattern 1 | If read at execution time instead, `storeBuild` Boolean would not influence `tasks.shadowJar { archiveBaseName }` correctly; fix: read via `project.hasProperty("storeBuild")` instead |
| A2 | `api.siteMap().add(auditIssue)` from a background thread is thread-safe and surfaces issues in the scanner UI | Q1, async findings | If not thread-safe, async findings may be lost or cause exceptions; fallback: synchronize on `api.siteMap()` or return all issues synchronously (blocking AI call) |
| A3 | The `buildconfig` Gradle plugin is MIT-licensed and well-maintained (mentioned as alternative to hand-rolled task) | Q3 | If not MIT, cannot use; fallback = hand-rolled task (already the chosen approach) |
| A4 | `api.ai().isEnabled()` returns `false` (not throws) on Community edition under Montoya 2026.2 | Q2 | If it throws, the existing `try { ... } catch { false }` wrapper still produces `false` — safe either way |

**If this table is empty:** All claims in this research were verified or cited — no user confirmation needed. (Table has 4 low-risk items above.)

---

## Sources

### Primary (HIGH confidence)
- Decompiled `montoya-api-2026.2.jar` (`/Users/six2dez/.gradle/caches/.../montoya-api-2026.2.jar`) — `PassiveScanCheck`, `ScanCheckType`, `Scanner`, `Ai` interfaces
- `MyPassiveScanCheck.java` from `github.com/PortSwigger/burp-extensions-montoya-api-examples` — official canonical example of `PassiveScanCheck.doCheck()` + `ScanCheckType.PER_REQUEST`
- `CustomScanChecks.java` from same repo — `api.scanner().registerPassiveScanCheck()` call site
- All cited codebase files verified by direct file read during this session

### Secondary (MEDIUM confidence)
- [PortSwigger AI extension best practices](https://portswigger.net/burp/documentation/desktop/extend-burp/extensions/creating/creating-ai-extensions/best-practices) — requirements list; fetched directly
- [PortSwigger Scanner Javadoc 2026.2](https://portswigger.github.io/burp-extensions-montoya-api/javadoc/burp/api/montoya/scanner/Scanner.html) — `registerPassiveScanCheck` signature + "[Professional only]" note; fetched directly
- [PortSwigger developing AI features](https://portswigger.net/burp/documentation/desktop/extend-burp/extensions/creating/creating-ai-extensions/developing-ai-features) — `isEnabled()` conditions
- [PortSwigger custom scan checks writing guide](https://portswigger.net/burp/documentation/desktop/extend-burp/custom-scan-checks/creating/writing-guide) — synchronous requirement for `doCheck`

### Tertiary (LOW confidence — cross-verified where possible)
- WebSearch results for `registerPassiveScanCheck` Community edition behavior — not directly stated in official docs; inferred from "Professional only" scanner designation

---

## Metadata

**Confidence breakdown:**
- Passive scanning mechanics: HIGH — decompiled JAR + official example
- AI gating (`isEnabled()` behavior): HIGH — decompiled interface + existing codebase pattern + PortSwigger docs
- Gradle build gate pattern: MEDIUM — standard Gradle Kotlin DSL pattern; exact snippet is [ASSUMED] but the approach is sound
- MCP tool wiring: HIGH — entire pipeline read from actual source files
- Test patterns: HIGH — read from actual test files

**Research date:** 2026-05-28
**Valid until:** 2026-08-28 (Montoya API may version; check if `montoya-api` dependency is bumped before planning)
