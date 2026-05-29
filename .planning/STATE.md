---
gsd_state_version: 1.0
milestone: v0.8.0
milestone_name: UI/UX Overhaul
status: executing
stopped_at: Phase 9 UI-SPEC approved
last_updated: "2026-05-29T11:31:09.881Z"
last_activity: 2026-05-29 -- Phase 09 planning complete
progress:
  total_phases: 11
  completed_phases: 4
  total_plans: 16
  completed_plans: 13
  percent: 36
---

# Project State

## Project Reference

See: .planning/PROJECT.md (updated 2026-05-29)

**Core value:** Bring modern AI to a real security workflow without leaking sensitive traffic to third-party providers — privacy controls and an audit trail are non-negotiable, AI capability is additive.
**Current focus:** Phase 09 — Design System Foundation (v0.8.0 UI/UX Overhaul; roadmap defined, ready for planning)

## Current Position

Phase: 9 — Design System Foundation
Plan: —
Status: Ready to execute
Last activity: 2026-05-29 -- Phase 09 planning complete

## Performance Metrics

**Velocity:**

- Total plans completed: 1
- Average duration: —
- Total execution time: 0 hours

**By Phase:**

| Phase | Plans | Total | Avg/Plan |
|-------|-------|-------|----------|
| — | — | — | — |
| 01 | 1 | - | - |

**Recent Trend:**

- Last 5 plans: —
- Trend: —

*Updated after each plan completion*
| Phase 08-bapp-store-resubmission-mcp-pivot-to-extension-native-tools- P02 | 27 | 3 tasks | 13 files |
| Phase 08 P03 | 20 | 2 tasks | 4 files |

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

### Roadmap Evolution

- 2026-05-27: Phase 7 added — Proxy Transport + MCP Scope Hardening (closes GitHub issue #69; parallel-safe with Phases 1, 4, 5; must merge before Phase 6).
- 2026-05-28: Phase 8 added — BApp Store resubmission (MCP pivot to extension-native tools + `-PstoreBuild` gate, gate all AI calls on `ai.isEnabled()`, migrate passive scanning to `ScanCheck.passiveAudit()`, confirm name). Addresses PortSwigger review feedback on issue #231; follows Phase 07. Approved plan seed: ~/.claude/plans/drifting-hatching-sphinx.md.
- 2026-05-29: Phases 9-11 added — v0.8.0 UI/UX Overhaul milestone. Phase 9: Design System Foundation (UI-01). Phase 10: MCP Tools Tab Redesign (UI-03, UI-04, UI-05, UI-07). Phase 11: Settings Tabs + Theme Rollout (UI-02, UI-06, UI-08, UI-07). All 8 UI-* requirements mapped; 100% coverage.

### Pending Todos

[From .planning/todos/pending/ — ideas captured during sessions]

None yet.

### Blockers/Concerns

[Issues that affect future work]

- GitHub issue #62 (release pipeline publishes stale code) gates the v0.7.0 release; Phase 4 must close before Phase 6 can ship.
- Phase 8 Wave 4 (08-04-PLAN.md) remains in-progress — manual smoke + /reopen reply needed before Phase 8 completes.

### Quick Tasks Completed

| # | Description | Date | Commit | Directory |
|---|-------------|------|--------|-----------|
| 260527-f7q | Fix bugs 66, 67, 68: CLI tokenizer, Copilot CLI hang, OpenAI-compatible diagnostics | 2026-05-27 | 8a6af50 | [260527-f7q-fix-bugs-66-67-68-cli-tokenizer-copilot-](./quick/260527-f7q-fix-bugs-66-67-68-cli-tokenizer-copilot-/) |

## Deferred Items

Items acknowledged and carried forward from previous milestone close:

| Category | Item | Status | Deferred At |
|----------|------|--------|-------------|
| v2 | MCP-V2-01 — user-registered MCP server (#41) | Deferred to post-v0.7.0 | 2026-05-13 |
| v2 | REL-V2-01 — opt-in local-only diagnostics endpoint | Deferred to post-v0.7.0 | 2026-05-13 |

## Session Continuity

Last session: 2026-05-29T10:40:12.371Z
Stopped at: Phase 9 UI-SPEC approved
Resume file: .planning/phases/09-design-system-foundation/09-UI-SPEC.md
