---
phase: 8
slug: bapp-store-resubmission-mcp-pivot-to-extension-native-tools
status: draft
nyquist_compliant: false
wave_0_complete: false
created: 2026-05-28
---

# Phase 8 — Validation Strategy

> Per-phase validation contract for feedback sampling during execution.
> Source: 08-RESEARCH.md "Validation Architecture" (JUnit 5 + Mockito-Kotlin; 262 existing tests).

---

## Test Infrastructure

| Property | Value |
|----------|-------|
| **Framework** | JUnit 5 (6.0.3) + Mockito-Kotlin 5.4.0 |
| **Config file** | `build.gradle.kts` — `tasks.test { useJUnitPlatform() }` |
| **Quick run command** | `./gradlew test -PexcludeHeavyTests=true` |
| **Full suite command** | `./gradlew test` |
| **Estimated runtime** | ~30s quick / full suite longer (262 tests) |

---

## Sampling Rate

- **After every task commit:** Run `./gradlew test -PexcludeHeavyTests=true`
- **After every plan wave:** Run `./gradlew test ktlintCheck`
- **Before `/gsd:verify-work`:** Full suite green + both JAR artifacts inspected + manual Burp Pro passive-scan smoke
- **Max feedback latency:** ~30 seconds (quick suite)

---

## Per-Task Verification Map

> Plan/Task IDs are assigned by the planner; rows below bind each requirement area to its proof. Executor updates Status.

| Req Area | Wave | Requirement | Threat Ref | Secure Behavior | Test Type | Automated Command | File Exists | Status |
|----------|------|-------------|------------|-----------------|-----------|-------------------|-------------|--------|
| MCP catalog `nativeTool` + `available()` filtering | 1 | MCP-no-dup | T-08-03 | Store build cannot expose generic tools (unregistered ⇒ uncallable) | unit | `./gradlew test --tests "*.McpToolCatalogStoreBuildTest"` | ❌ W0 | ⬜ pending |
| Catalog/registration parity | 1 | MCP-no-dup | — | New tool IDs present in both `all()` and `allIds()` | unit (existing) | `./gradlew test --tests "*.McpToolParityTest"` | ✅ | ⬜ pending |
| New native MCP tools wired (analyze/redact/scan/findings/audit/backends) | 2 | MCP hooks-into-extension | T-08-01 | Args redacted via `context.redactIfNeeded()` before AI send | unit | `./gradlew test --tests "*.Mcp*ToolTest"` | ❌ W0 | ⬜ pending |
| AI gate on new MCP AI tools | 2 | ai.isEnabled gating | T-08-01 | `ai_analyze` returns error when `api.ai().isEnabled()=false` | unit | `./gradlew test --tests "*.AiGateMcpToolTest"` | ❌ W0 | ⬜ pending |
| Non-burp-ai backends remain usable when AI disabled (Community) | 2 | keep Community support | — | Ollama/Claude CLI `startOrAttach` returns true when `isEnabled()=false` | unit (existing) | `./gradlew test --tests "*.BurpAiGateScopingTest"` | ✅ | ⬜ pending |
| Passive scan migrated to `PassiveScanCheck.doCheck()` | 3 | PassiveScanCheck | T-08-02 | Local heuristics returned in `AuditResult` synchronously | unit | `./gradlew test --tests "*.AiPassiveScanCheckTest"` | ❌ W0 | ⬜ pending |
| Async AI findings surfaced via `siteMap().add()` | 3 | PassiveScanCheck | T-08-02 | Issues appear in scanner after async AI completes | manual (Pro) | Manual Burp Pro test | Manual | ⬜ pending |
| Store artifact name & contents | 4 | no-dup / store build | T-08-03 | `shadowJar -PstoreBuild=true` → `Custom-AI-Agent-<v>.jar`, MCP `tools/list` shows only native | build inspect | `./gradlew shadowJar -PstoreBuild=true` + `ls build/libs/` | Manual | ⬜ pending |
| Full artifact name & contents | 4 | keep full build | — | `shadowJar` → `Custom-AI-Agent-full-<v>.jar`, all tools present | build inspect | `./gradlew shadowJar` + `ls build/libs/` | Manual | ⬜ pending |
| Community compatibility | 4 | keep Community support | — | Non-AI backends start; `registerPassiveScanCheck` silent-fails on Community | manual (Community) | Manual Burp Community test | Manual | ⬜ pending |

*Status: ⬜ pending · ✅ green · ❌ red · ⚠️ flaky*

---

## Wave 0 Requirements

- [ ] `src/test/kotlin/.../mcp/McpToolCatalogStoreBuildTest.kt` — `available()` returns only native tools when store-build flag is true (make `available(storeBuild: Boolean)` testable rather than reading the const directly)
- [ ] `src/test/kotlin/.../mcp/AiGateMcpToolTest.kt` — `ai_analyze` (and peers) return a clear error when `api.ai().isEnabled()=false`
- [ ] `src/test/kotlin/.../scanner/AiPassiveScanCheckTest.kt` — `doCheck()` returns local findings synchronously and enqueues async AI analysis

*Existing `McpToolParityTest` and `BurpAiGateScopingTest` cover parity and backend-scoping regressions.*

---

## Manual-Only Verifications

| Behavior | Requirement | Why Manual | Test Instructions |
|----------|-------------|------------|-------------------|
| Store JAR exposes only native MCP tools | MCP no-dup | Requires running MCP server + client `tools/list` | Build `-PstoreBuild=true`, load in Burp, start MCP, list tools — assert only native set |
| Async AI passive findings appear in scanner | PassiveScanCheck | Needs Burp Pro scanner + live AI backend | Run passive scan in Burp Pro; confirm AI issues register via site map |
| `ai.isEnabled()` behavior on Community (TOP RISK) | keep Community support | Burp Community runtime required; decides gate design | Load full JAR in Burp Community: does "Use AI" checkbox appear? Can `isEnabled()` be true? Do Ollama/Claude CLI backends still start? Record result before finalizing the gate. |
| Toggle "Use AI" off blocks AI tools | ai.isEnabled gating | Requires Burp Pro AI runtime | In Burp Pro, disable Use AI; confirm `ai_analyze` + agent send are blocked with clear message |

---

## Validation Sign-Off

- [ ] All tasks have `<automated>` verify or Wave 0 dependencies
- [ ] Sampling continuity: no 3 consecutive tasks without automated verify
- [ ] Wave 0 covers all MISSING references (3 new test files above)
- [ ] No watch-mode flags
- [ ] Feedback latency < 30s (quick suite)
- [ ] `nyquist_compliant: true` set in frontmatter

**Approval:** pending
