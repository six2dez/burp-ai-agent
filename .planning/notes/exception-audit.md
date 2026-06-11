# Exception Audit — SC5 / QUAL-04

**Date:** 2026-06-11
**Scope:** 183 catch sites across 52 files (all in `src/main/kotlin`)
**Method:** `grep -rn "catch.*Exception\|catch.*Throwable\|catch.*Error\b" src/main/kotlin --include="*.kt"` + manual classification
**Focus modules (Task 2 target):** `cache/`, `scanner/ActiveAiScanner.kt`, `supervisor/`, `backends/cli/`
**Plan:** 18-04 (Phase 18 Quality Tooling & Build Hardening)

---

## Annotation Convention (from 18-PATTERNS.md)

### Form 1 — Intentional swallow (no log needed)
```kotlin
} catch (_: Exception) {
    // INTENTIONAL: <reason why swallowing is correct>
}
```

### Form 2 — Operational failure that should surface to user

**Modules WITH MontoyaApi reference (scanner, supervisor):**
```kotlin
} catch (e: Exception) {
    api.logging().logToError("[ModuleName] <context>: ${e.message}")
}
```

**Modules WITHOUT MontoyaApi (cache, cli, config, util):**
```kotlin
} catch (e: Exception) {
    BackendDiagnostics.logError("[ModuleName] <context>: ${e.message}")
}
```

### Privacy rule (NON-NEGOTIABLE)
Log messages MUST NOT interpolate: request body content, API keys, bearer tokens, passwords, `e.stackTraceToString()` in production paths.
Only `${e.message}` and structural context (module name, operation name) are safe to interpolate.

---

## Focused Modules Audit Table

### Module: cache/ (PersistentPromptCache.kt) — 2 sites

| File | Line | Catch Type | Current Behavior | Classification | Disposition |
|------|------|------------|-----------------|----------------|-------------|
| cache/PersistentPromptCache.kt | 47 | `_: Exception` | Silent swallow on read; deletes corrupt file | INTENTIONAL | Add `// INTENTIONAL: cache read failures are best-effort; corrupt files are deleted; must not crash scanner pipeline` |
| cache/PersistentPromptCache.kt | 63 | `_: Exception` | Silent swallow — "Silently fail on disk write errors" | INTENTIONAL | Upgrade comment to `// INTENTIONAL: cache write failures are best-effort; must not crash scanner pipeline` |

**Notes:**
- Both catch sites in the cache module are correctly silent. Cache is a best-effort optimization — read/write failures must not propagate to the scanner pipeline.
- Pitfall 5 (RESEARCH.md): the `put()` catch IS intentional; do NOT add a log call here.

---

### Module: scanner/ActiveAiScanner.kt — 16 sites

| File | Line | Catch Type | Current Behavior | Classification | Disposition | Status |
|------|------|------------|-----------------|----------------|-------------|--------|
| scanner/ActiveAiScanner.kt | 331 | `_: InterruptedException` | Sets thread interrupt flag | INTENTIONAL | Add `// INTENTIONAL: thread interrupt during executor shutdown; interrupt flag restored` | DONE |
| scanner/ActiveAiScanner.kt | 353 | `e: Exception` | `api.logging().logToError("[ActiveAiScanner] Error: ${e.message}")` | ALREADY-LOGGED | Verify [ModuleName] prefix — PRESENT | DONE |
| scanner/ActiveAiScanner.kt | 507 | `e: Exception` | `api.logging().logToError("[ActiveAiScanner] Boolean dual test error: ${e.message}")` | ALREADY-LOGGED | Verify [ModuleName] prefix — PRESENT | DONE |
| scanner/ActiveAiScanner.kt | 577 | `e: Exception` | `api.logging().logToError("[ActiveAiScanner] Payload error: ${e.message}")` | ALREADY-LOGGED | Verify [ModuleName] prefix — PRESENT | DONE |
| scanner/ActiveAiScanner.kt | 649 | `e: Exception` | `api.logging().logToError("[ActiveAiScanner] IDOR test error: ${e.message}")` | ALREADY-LOGGED | Verify [ModuleName] prefix — PRESENT | DONE |
| scanner/ActiveAiScanner.kt | 952 | `e: Exception` | `api.logging().logToError("[ActiveAiScanner] Collaborator unavailable: ${e.message}")` | ALREADY-LOGGED | Verify [ModuleName] prefix — PRESENT | DONE |
| scanner/ActiveAiScanner.kt | 960 | `e: Exception` | `api.logging().logToError("[ActiveAiScanner] Collaborator payload error: ${e.message}")` | ALREADY-LOGGED | Verify [ModuleName] prefix — PRESENT | DONE |
| scanner/ActiveAiScanner.kt | 1017 | `e: TimeoutException` | `api.logging().logToError("[ActiveAiScanner] Request timeout after...")` | ALREADY-LOGGED | Verify [ModuleName] prefix — PRESENT | DONE |
| scanner/ActiveAiScanner.kt | 1021 | `e: Exception` | `api.logging().logToError("[ActiveAiScanner] Request error: ${e.message}")` | ALREADY-LOGGED | Verify [ModuleName] prefix — PRESENT | DONE |
| scanner/ActiveAiScanner.kt | 1168 | `e: Exception` | `api.logging().logToError("[ActiveAiScanner] Failed to create issue: ${e.message}")` | ALREADY-LOGGED | Verify [ModuleName] prefix — PRESENT | DONE |
| scanner/ActiveAiScanner.kt | 1412 | `e: Exception` | `api.logging().logToError("[ActiveAiScanner] 403 bypass header error: ${e.message}")` | ALREADY-LOGGED | Verify [ModuleName] prefix — PRESENT | DONE |
| scanner/ActiveAiScanner.kt | 1460 | `e: Exception` | `api.logging().logToError("[ActiveAiScanner] 403 bypass path error: ${e.message}")` | ALREADY-LOGGED | Verify [ModuleName] prefix — PRESENT | DONE |
| scanner/ActiveAiScanner.kt | 1512 | `e: Exception` | `api.logging().logToError("[ActiveAiScanner] 403 bypass method error: ${e.message}")` | ALREADY-LOGGED | Verify [ModuleName] prefix — PRESENT | DONE |
| scanner/ActiveAiScanner.kt | 1578 | `_: InterruptedException` | Sets thread interrupt flag on shutdown | INTENTIONAL | Add `// INTENTIONAL: thread interrupt on executor shutdown; interrupt flag restored` | DONE |

**Notes:**
- ActiveAiScanner is already the best-logged module in the focused set — 12 of 14 catch sites already have `api.logging().logToError()` with `[ActiveAiScanner]` prefix.
- Two InterruptedException sites are correctly intentional (executor shutdown pattern — `Thread.currentThread().interrupt()` restores the flag).

---

### Module: supervisor/ (AgentSupervisor.kt + ChatSessionManager.kt) — 12 sites

| File | Line | Catch Type | Current Behavior | Classification | Disposition | Status |
|------|------|------------|-----------------|----------------|-------------|--------|
| supervisor/AgentSupervisor.kt | 122 | `_: Exception` | Returns false (isAiEnabled() fallback) | INTENTIONAL | Add `// INTENTIONAL: Burp AI API unavailable in Community edition; fallback returns false` | DONE |
| supervisor/AgentSupervisor.kt | 225 | `e: Exception` | `api.logging().logToError("Failed to launch backend $backendId: ${e.message}")` | ALREADY-LOGGED | [ModuleName] prefix MISSING — add `[AgentSupervisor]` prefix | DONE |
| supervisor/AgentSupervisor.kt | 462 | `e: Exception` | `api.logging().logToError("Failed to launch backend $backendId: ${e.message}")` | ALREADY-LOGGED | [ModuleName] prefix MISSING — add `[AgentSupervisor]` prefix (sendChat path) | DONE |
| supervisor/AgentSupervisor.kt | 1022 | `e: Exception` | `safeLogOutput("[$name] output stream closed: ${e.message}")` | ALREADY-LOGGED | Context tag uses service name already — ACCEPTABLE | DONE |
| supervisor/AgentSupervisor.kt | 1028 | `e: Exception` | `safeLogError("Failed to start service $name: ${e.message}")` | ALREADY-LOGGED | Context tag ACCEPTABLE; add `[AgentSupervisor]` prefix | DONE |
| supervisor/AgentSupervisor.kt | 1037 | `_: Throwable` | `System.err.println(message)` fallback in safeLogOutput | INTENTIONAL | Add `// INTENTIONAL: safeLogOutput fallback must not throw; stderr is the last resort` | DONE |
| supervisor/AgentSupervisor.kt | 1045 | `_: Throwable` | `System.err.println(message)` fallback in safeLogError | INTENTIONAL | Add `// INTENTIONAL: safeLogError fallback must not throw; stderr is the last resort` | DONE |
| supervisor/AgentSupervisor.kt | 1058 | `_: InterruptedException` | Calls shutdownNow() + re-interrupts | INTENTIONAL | Add `// INTENTIONAL: interrupt during monitor shutdown; shutdownNow() called; interrupt flag restored` | DONE |
| supervisor/AgentSupervisor.kt | 1064 | `e: Exception` | `safeLogError("Failed to terminate service '$name': ${e.message}")` | ALREADY-LOGGED | Context tag ACCEPTABLE — DONE | DONE |
| supervisor/AgentSupervisor.kt | 1236 | `_: Exception` | Returns null from capturePathFromShells / tryCapture | INTENTIONAL | Add `// INTENTIONAL: shell PATH capture is best-effort; returns null on failure (fallback to System.getenv)` | DONE |
| supervisor/ChatSessionManager.kt | 81 | `e: Exception` | `System.err.println("Failed to stop chat session connection: ${e.message}")` | NEEDS-LOG | Upgrade: `BackendDiagnostics.logError("[ChatSessionManager] Failed to stop session connection: ${e.message}")` | DONE |

---

### Module: backends/cli/ (CliBackend.kt) — 17 sites

| File | Line | Catch Type | Current Behavior | Classification | Disposition | Status |
|------|------|------------|-----------------|----------------|-------------|--------|
| backends/cli/CliBackend.kt | 149 | `_: UnsupportedOperationException` | Silent — skips POSIX perms on non-POSIX (Windows) | INTENTIONAL | Add `// INTENTIONAL: non-POSIX filesystem (Windows) does not support POSIX file permissions; skip` | DONE |
| backends/cli/CliBackend.kt | 153 | `e: Exception` | Deletes temp file + `onComplete(e)` | INTENTIONAL | Add `// INTENTIONAL: temp file write failed; cleanup and propagate error via onComplete` | DONE |
| backends/cli/CliBackend.kt | 246 | `_: InterruptedException` | Restores interrupt flag in inner join | INTENTIONAL | Add `// INTENTIONAL: interrupted while waiting for reader thread; restores interrupt flag` | DONE |
| backends/cli/CliBackend.kt | 256 | `_: InterruptedException` | Restores interrupt flag in outer join | INTENTIONAL | Add `// INTENTIONAL: interrupted while waiting for reader thread after timeout; restores interrupt flag` | DONE |
| backends/cli/CliBackend.kt | 283 | `e: Exception` | `onComplete(e)` — propagates error to caller | INTENTIONAL | Add `// INTENTIONAL: CLI process launch/execution error; propagated via onComplete` | DONE |
| backends/cli/CliBackend.kt | 289 | `_: Exception` | Finally block — destroyForcibly() cleanup | INTENTIONAL | Add `// INTENTIONAL: finally block cleanup; destroyForcibly() must not prevent file cleanup` | DONE |
| backends/cli/CliBackend.kt | 293 | `_: Exception` | Finally block — promptFile cleanup | INTENTIONAL | Add `// INTENTIONAL: finally block cleanup; file deletion must not prevent process cleanup` | DONE |
| backends/cli/CliBackend.kt | 297 | `_: Exception` | Finally block — outputFile cleanup | INTENTIONAL | Add `// INTENTIONAL: finally block cleanup; file deletion must not prevent process cleanup` | DONE |
| backends/cli/CliBackend.kt | 301 | `e: RejectedExecutionException` | `onComplete(IllegalStateException(...))` | INTENTIONAL | Add `// INTENTIONAL: executor shut down; propagate shutdown state via onComplete` | DONE |
| backends/cli/CliBackend.kt | 310 | `_: InterruptedException` | `Thread.currentThread().interrupt()` | INTENTIONAL | Add `// INTENTIONAL: interrupted during executor shutdown; restores interrupt flag` | DONE |
| backends/cli/CliBackend.kt | 617 | `_: Exception` | `exitCode.set(process.waitFor())` in reader thread finally | INTENTIONAL | Add `// INTENTIONAL: waitFor() in finally block must not throw to avoid masking reader exception` | DONE |
| backends/cli/CliBackend.kt | 621 | `e: Exception` | `stop(); throw e` — re-throws after cleanup | INTENTIONAL | Add `// INTENTIONAL: process start failed; stop() for cleanup then re-throw` | DONE |
| backends/cli/CliBackend.kt | 674 | `e: Exception` | `onComplete(e)` — propagates error via callback | INTENTIONAL | Add `// INTENTIONAL: send() execution error; propagated via onComplete` | DONE |
| backends/cli/CliBackend.kt | 684 | `e: Exception` | `System.err.println("Failed to close CLI writer: ${e.message}")` | NEEDS-LOG | Upgrade: `BackendDiagnostics.logError("[CliBackend] Failed to close CLI writer: ${e.message}")` | DONE |
| backends/cli/CliBackend.kt | 692 | `_: InterruptedException` | `process.destroyForcibly(); Thread.currentThread().interrupt()` | INTENTIONAL | Add `// INTENTIONAL: interrupted while waiting for process; destroyForcibly() + restore interrupt flag` | DONE |
| backends/cli/CliBackend.kt | 700 | `_: InterruptedException` | `Thread.currentThread().interrupt()` in exec awaitTermination | INTENTIONAL | Add `// INTENTIONAL: interrupted during exec executor shutdown; restores interrupt flag` | DONE |
| backends/cli/CliBackend.kt | 705 | `_: InterruptedException` | `Thread.currentThread().interrupt()` in readerExec awaitTermination | INTENTIONAL | Add `// INTENTIONAL: interrupted during reader executor shutdown; restores interrupt flag` | DONE |
| backends/cli/CliBackend.kt | 976 | `_: Exception` | Silently returns empty list from PATH dir resolution | INTENTIONAL | Add `// INTENTIONAL: unreadable PATH directory; skip silently to avoid aborting full PATH search` | DONE |

---

## Summary of Focused Module Coverage

| Module | Sites | INTENTIONAL | NEEDS-LOG | ALREADY-LOGGED |
|--------|-------|-------------|-----------|----------------|
| cache/ | 2 | 2 | 0 | 0 |
| scanner/ActiveAiScanner.kt | 14 | 2 | 0 | 12 |
| supervisor/ (AgentSupervisor + ChatSessionManager) | 12 | 5 | 1 | 6 |
| backends/cli/CliBackend.kt | 17 | 15 | 2 | 0 |
| **Total focused** | **45** | **24** | **3** | **18** |

NEEDS-LOG sites to be annotated with log calls:
1. `ChatSessionManager.kt:81` — upgrade `System.err.println` to `BackendDiagnostics.logError("[ChatSessionManager] ...")`
2. `CliBackend.kt:684` — upgrade `System.err.println` to `BackendDiagnostics.logError("[CliBackend] ...")`
3. `AgentSupervisor.kt:225` — add `[AgentSupervisor]` prefix to existing `logToError`
4. `AgentSupervisor.kt:462` — add `[AgentSupervisor]` prefix to existing `logToError` (sendChat path)
5. `AgentSupervisor.kt:1028` — add `[AgentSupervisor]` prefix to existing `safeLogError`

ALREADY-LOGGED sites needing prefix verification: All 18 sites in ActiveAiScanner.kt confirmed with `[ActiveAiScanner]` prefix.

---

## Remaining Sites (Outside Focused Scope) — TODO-AUDIT

The following modules contain the remaining 138 catch sites. These will receive
`// TODO-AUDIT: review exception handling` markers in a future plan.

| Module | Files | Catch Site Count |
|--------|-------|-----------------|
| agents/ | AgentProfileLoader.kt | 7 |
| alerts/ | Alerting.kt | 1 |
| App.kt | App.kt | 5 |
| audit/ | AiRequestLogger.kt, AuditLogger.kt | 3 |
| backends/anthropic/ | AnthropicBackend.kt | 3 |
| backends/ | BackendDiagnostics.kt (2 — INTENTIONAL), BackendRegistry.kt (5) | 7 |
| backends/burpai/ | BurpAiBackend.kt | 4 |
| backends/http/ | HttpBackendSupport.kt, MontoyaHttpTransport.kt | 3 |
| backends/lmstudio/ | LmStudioBackend.kt | 3 |
| backends/nvidia/ | NvidiaNimBackendFactory.kt | 2 |
| backends/ollama/ | OllamaBackend.kt | 4 |
| backends/openai/ | OpenAiCompatibleBackend.kt | 3 |
| backends/perplexity/ | PerplexityBackendFactory.kt | 1 |
| config/ | AgentSettings.kt (4), CustomPromptDefinition.kt, McpSettings.kt (2), SecretCipher.kt (2) | 9 |
| context/ | ContextCollector.kt | 1 |
| mcp/ | KtorMcpServerManager.kt (11), McpRequestLimiter.kt, McpSupervisor.kt (3) | 15 |
| mcp/tools/ | CollaboratorRegistry.kt, McpTool.kt (2), McpTools.kt (9), ScannerTaskRegistry.kt | 13 |
| prompts/bountyprompt/ | BountyPromptTagResolver.kt | 1 |
| redact/ | Redaction.kt, SafeRegex.kt (3) | 4 |
| scanner/ (non-ActiveAiScanner) | AdaptivePayloadEngine.kt (2), AiScanCheck.kt, InjectionPointExtractor.kt (6), JsEndpointExtractor.kt, PassiveAiScanner.kt (12), ScanKnowledgeBase.kt | 23 |
| ui/ | AiLoggerPanel.kt, ChatPanel.kt (12), components/ (3), MainTab.kt (2), panels/ (1), SettingsPanel.kt (2), UiActions.kt (2) | 23 |
| util/ | IssueUtils.kt, SsrfGuard.kt (2) | 3 |
| **Total remaining** | | **138** |

**Action for remaining sites:** Each bare silent catch block in the above modules will receive
`// TODO-AUDIT: review exception handling` comment to make the technical debt visible without
risking behavioral regressions.

---

## BackendDiagnostics.kt — Special Case (Already INTENTIONAL)

The two catch sites in `BackendDiagnostics.kt` (lines 23, 34) are the canonical INTENTIONAL pattern:
```kotlin
} catch (_: Exception) {
    System.err.println(message)  // INTENTIONAL: logging facility fallback must not throw; stderr is the last resort
}
```
These are the reference implementation for Form 1. They are ALREADY correctly annotated conceptually and will be formally marked in Task 2.
