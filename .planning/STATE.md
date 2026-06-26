---
gsd_state_version: 1.0
milestone: v0.9.0
milestone_name: Hardening, Quality & New Capabilities
status: milestone_complete
stopped_at: Milestone complete (Phase 19 was final phase)
last_updated: 2026-06-26T08:36:28.840Z
last_activity: 2026-06-16
progress:
  total_phases: 8
  completed_phases: 7
  total_plans: 31
  completed_plans: 53
  percent: 88
---

# Project State

## Project Reference

See: .planning/PROJECT.md (updated 2026-06-10)

**Core value:** Bring modern AI to a real security workflow without leaking sensitive traffic to third-party providers — privacy controls and an audit trail are non-negotiable, AI capability is additive.
**Current focus:** Milestone complete

## Current Position

Phase: 19
Plan: Not started
Status: Milestone complete
Last activity: 2026-06-26

## Performance Metrics

**Velocity:**

- Total plans completed: 26
- Average duration: —
- Total execution time: 0 hours

**By Phase:**

| Phase | Plans | Total | Avg/Plan |
|-------|-------|-------|----------|
| — | — | — | — |
| 01 | 1 | - | - |
| 11 | 4 | - | - |
| 13 | 3 | - | - |
| 14 | 3 | - | - |
| 15 | 3 | - | - |
| 17 | 3 | - | - |
| 18 | 4 | - | - |
| 19 | 5 | - | - |

**Recent Trend:**

- Last 5 plans: —
- Trend: —

*Updated after each plan completion*
| Phase 08-bapp-store-resubmission-mcp-pivot-to-extension-native-tools- P02 | 27 | 3 tasks | 13 files |
| Phase 08 P03 | 20 | 2 tasks | 4 files |
| Phase 09 P01 | 3 | 2 tasks | 3 files |
| Phase 10-mcp-tools-tab-redesign P01 | 8 | 2 tasks | 2 files |
| Phase 11-settings-tabs-theme-rollout P01 | 2 | 2 tasks | 2 files |
| Phase 11 P02 | 8 | 2 tasks | 3 files |
| Phase 11 P03 | 14 | 2 tasks | 5 files |
| Phase 11-settings-tabs-theme-rollout P04 | 35 | 2 tasks | 1 files |
| Phase 13-privacy-redaction-hardening P01 | 30 | 3 tasks | 4 files |
| Phase 13 P02 | 30 | 3 tasks | 7 files |
| Phase 13 P03 | 5 | 3 tasks | 3 files |
| Phase 15 P01 | 4 | 3 tasks | 4 files |
| Phase 15-pre-send-secret-tripwire P03 | 6min | 3 tasks | 4 files |
| Phase 17-reliability-concurrency-hardening P01 | 10m | 2 tasks | 7 files |
| Phase 17 P02 | 3m | 2 tasks | 4 files |
| Phase 18 P01 | 15m | 2 tasks | 4 files |
| Phase 18 P02 | multi-session | 2 tasks | 40 files |
| Phase 18 P04 | 10m | 2 tasks | 5 files |
| Phase 16-external-mcp-client P01 | 5min | 2 tasks | 3 files |
| Phase 16-external-mcp-client P02 | 615 | 2 tasks | 7 files |
| Phase 16 P04 | 9min | 2 tasks | 3 files |
| Phase 19 P01 | 20m | 2 tasks | 4 files |
| Phase 19-mega-file-split-docs P02 | 120 | 7 tasks | 10 files |
| Phase 19-mega-file-split-docs P03 | multi-session-180min | 2 tasks | 7 files |

## Accumulated Context

### Decisions

Decisions are logged in PROJECT.md Key Decisions table.
Recent decisions affecting current work:

- Init: Active milestone scoped to v0.7.0 stabilization (Unreleased features + open bugs + docs + release).
- Init: Codebase mapping skipped — `SPEC.md`, `DECISIONS.md`, `AGENTS.md`, `CHANGELOG.md` already capture architecture.
- Init: Domain research skipped — maintainer is the domain expert.
- Roadmap: Three feature audits (Perplexity, insertion-point, prompt library) split into independent parallel-safe phases; release cut isolated as Phase 6 choke point.
- 08-01: Hand-rolled GenerateBuildFlagsTask (abstract class with @Input/@OutputDirectory) required for Gradle configuration-cache compatibility instead of doFirst lambda.
- 08-01: BuildFlags.kt generated into build/generated/buildflags/ (ktlint excluded via **/build/**); nativeTool: Boolean = false default preserves all 53 existing descriptors.
- 08-01: available(storeBuild: Boolean = BuildFlags.STORE_BUILD) default-arg overload enables unit testing without config-cache mocking.
- [Phase ?]: B1 fix: registerToolHandler() uses available() so STORE_BUILD=true silently skips generic tool IDs
- [Phase ?]: B2 fix: ai_passive_scan checks supervisor.isAiEnabled() BEFORE passiveScanner null check
- [Phase ?]: setAiToolDependencies() added to McpServerManager interface so typed reference can call it
- v0.8.0 Roadmap: UI-07 (no regressions) is cross-cutting — echoed as a success criterion in both Phase 10 and Phase 11 rather than assigned its own phase, since regression-safety is a property of phases that modify existing UI, not a deliverable on its own.
- v0.8.0 Roadmap: Phase 9 (design system) is additive only (new module, no panel migration); Phases 10 and 11 consume it. Phase 10 (MCP tab) prioritized over Phase 11 (settings rollout) because the MCP tab is the highest user pain point and benefits from Phase 8's nativeTool classification already in place.
- [Phase ?]: UiTheme.kt retained as legacy shim (KDoc-only change): Phase 11 will align naming (outline→border, statusRunning→statusSuccess) once all call sites migrated
- [Phase ?]: SC5 (formGrid non-null) deferred to DesignComponentsTest in Plan 02: formGrid() lives in Components.kt not DesignTokens.kt
- v0.9.0 Roadmap: Phase 12 (SEC) must be first — all new secret fields rely on it; no new secret lands in plaintext. Phase 19 (QUAL-01 mega-file split) must be last — PassiveAiScanner hook points from Phase 15 must be committed before the split.
- v0.9.0 Roadmap: CAP-03 (listener port filter) and CAP-04 (token budget) co-land with CAP-01 (Anthropic) in Phase 14 — small, non-conflicting additions; natural fit alongside Anthropic's four-field token usage surfacing.
- v0.9.0 Roadmap: CAP-02 (external MCP) requires kotlin-sdk 0.5.0→0.13.0 Burp-JVM test-run gate; placed after CAP-01 so the SDK bump does not block earlier phases.
- v0.9.0 Roadmap: PRIV-04 (redaction coverage UI) co-lands with PRIV-01+PRIV-02 in Phase 13 — the UI indicator shows when a known secret shape passes through, using the same curated pattern set as the Phase 15 tripwire.
- [Phase ?]: Body/form regex uses (^|[?&]) anchor to close leading-field gap (T-13-05)
- [Phase ?]: customRedactionPatterns persisted plaintext newline-joined — NOT SecretCipher (config not secrets)
- [Phase ?]: compiledCustomPatterns @Volatile list — EDT write visible to redaction thread without full synchronization
- [Phase ?]: setCustomPatterns called in applyAndSaveSettings — edits take effect without restart
- [13-03]: SecretShapes includes high-entropy hex shape placed last; T-13-11 false-positive risk accepted (non-blocking banner)
- [13-03]: SecretShapes is single AWT-free source of truth for PRIV-04 and Phase 15 tripwire reuse contract
- [13-03]: ContextPreviewDialog banner uses Level.WARN (advisory); categories-only — raw values never interpolated (T-13-10)
- [14-03]: listenerPort JSON key is camelCase (listenerPort) matching kotlinx-serialization field name — MCP clients send listenerPort not listener_port; GetProxyHttpHistoryRestricted also gains listenerPort for schema exposure under restricted branch
- [Phase ?]: recordHttpFailureIfRetryable defined as top-level CircuitBreaker extension so backends can import it directly
- [Phase ?]: A2 confirmed: generateBuildFlags.flatMap { it.outputDir } registers structural dependency in Gradle 8.12.1; builtBy() fallback not needed
- [Phase ?]: A1 confirmed: kotlin-compiler-embeddable warning absent in Kotlin 2.1.21 + detekt 1.23.8; no resolutionStrategy.force() needed
- [Phase ?]: detekt-formatting NOT added to detekt plugins to avoid double-gating style rules with ktlint
- [Phase ?]: SC5 scope: 45 catch sites in focused modules fully annotated; 138 remaining get TODO-AUDIT markers for future plan
- [Phase ?]: Module prefix convention: [ModuleName] added to AgentSupervisor logToError calls
- [Phase ?]: Path A confirmed: kotlin-sdk stays at 0.5.0; only 3 explicit dep pins needed (no SDK or Kotlin plugin bump)
- [Phase ?]: Wave 0 scaffold pattern: @Disabled stubs with commented production code document plan N+1 implementation contract
- [Phase ?]: SC1 < 500 line target physically unachievable for SettingsPanel.kt: field declarations alone are ~512 lines; 855 lines is the minimum achievable floor after all method body extractions

### Roadmap Evolution

- 2026-05-27: Phase 7 added — Proxy Transport + MCP Scope Hardening (closes GitHub issue #69; parallel-safe with Phases 1, 4, 5; must merge before Phase 6).
- 2026-05-28: Phase 8 added — BApp Store resubmission (MCP pivot to extension-native tools + `-PstoreBuild` gate, gate all AI calls on `ai.isEnabled()`, migrate passive scanning to `ScanCheck.passiveAudit()`, confirm name). Addresses PortSwigger review feedback on issue #231; follows Phase 07. Approved plan seed: ~/.claude/plans/drifting-hatching-sphinx.md.
- 2026-05-29: Phases 9-11 added — v0.8.0 UI/UX Overhaul milestone. Phase 9: Design System Foundation (UI-01). Phase 10: MCP Tools Tab Redesign (UI-03, UI-04, UI-05, UI-07). Phase 11: Settings Tabs + Theme Rollout (UI-02, UI-06, UI-08, UI-07). All 8 UI-* requirements mapped; 100% coverage.
- 2026-06-10: Phases 12-19 added — v0.9.0 Hardening, Quality & New Capabilities milestone. 22 requirements mapped across 8 phases. Hard ordering constraints from research enforced: SEC first, QUAL-01 split last.

### Pending Todos

[From .planning/todos/pending/ — ideas captured during sessions]

[No pending todos — all pre-planning items resolved as of Phase 19.]

### Blockers/Concerns

[Issues that affect future work]

- **✅ RESOLVED 2026-06-12 — Phase 16 blocker dissolved (Path A, NO Kotlin bump).** A compile spike proved `kotlin-sdk:0.5.0` already ships the full MCP client (`Client`/`SseClientTransport`/`StdioClientTransport`) and compiles under Kotlin 2.1.21 with only `ktor-client-core/cio:3.1.3` added. No Kotlin/Ktor bump required; human-only Burp ClassLoader gate does not apply. Phase 16 executed successfully.
- **Phase 16 human-UAT pending** — Code-complete (5/6 plans committed, automated-verified); SC1 real-server connect and SC5 live-Burp load are human-UAT items tracked in `16-HUMAN-UAT.md`.

### Quick Tasks Completed

| # | Description | Date | Commit | Directory |
|---|-------------|------|--------|-----------|
| 260527-f7q | Fix bugs 66, 67, 68: CLI tokenizer, Copilot CLI hang, OpenAI-compatible diagnostics | 2026-05-27 | 8a6af50 | [260527-f7q-fix-bugs-66-67-68-cli-tokenizer-copilot-](./quick/260527-f7q-fix-bugs-66-67-68-cli-tokenizer-copilot-/) |
| 260602-v08 | Bump version to 0.8.0 + promote CHANGELOG [Unreleased] → [0.8.0] | 2026-06-02 | 55f0b28 | — |
| 260602-cl8 | Complete CHANGELOG [0.8.0]: Phase 07 (#69) scope hardening/transport + backend fixes #66/67/68 | 2026-06-02 | 8caf0cb | — |

## Deferred Items

Items acknowledged and carried forward from previous milestone close:

| Category | Item | Status | Deferred At |
|----------|------|--------|-------------|
| v2 | MCP-V2-01 — user-registered MCP server (#41) | Promoted to CAP-02 in v0.9.0 | 2026-05-13 |
| v2 | REL-V2-01 — opt-in local-only diagnostics endpoint | Deferred to post-v0.9.0 | 2026-05-13 |

## Session Continuity

Last session: 2026-06-16T11:52:52.058Z
Stopped at: Completed 19-03-PLAN.md
Resume file: None
