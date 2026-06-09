---
phase: 08-bapp-store-resubmission-mcp-pivot-to-extension-native-tools-
plan: "04"
subsystem: bapp-store
tags: [kotlin, bapp-store, store-build, artifacts, compliance, resubmission, passive-scan, ai-gate]

# Dependency graph
requires:
  - phase: 08-02
    provides: 6 native MCP tools, B1/B2 gate fixes, McpToolCatalog.available()
  - phase: 08-03
    provides: AiPassiveScanCheck.doCheck(), ProxyResponseHandler removed, App.kt registration

provides:
  - Both v0.8.0 JARs verified: Custom-AI-Agent-0.8.0.jar (store) + Custom-AI-Agent-full-0.8.0.jar (full)
  - 08-REOPEN-REPLY.md: ready-to-post /reopen comment for PortSwigger issue #231
  - Phase 8 autonomous code work complete; all four PortSwigger review points addressed in code
  - Manual Burp smoke test + /reopen posting: maintainer-performed (outside automated workflow)

affects:
  - Phase 6 (v0.7.0 release) — BApp Store compliance requirement satisfied once resubmission accepted

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "Two-artifact build: -PstoreBuild=true produces store JAR (native tools only); default build produces full JAR"
    - "BuildFlags.STORE_BUILD baked at compile time via GenerateBuildFlagsTask — not a runtime config flag"

key-files:
  created:
    - .planning/phases/08-bapp-store-resubmission-mcp-pivot-to-extension-native-tools-/08-REOPEN-REPLY.md
  modified: []

key-decisions:
  - "AI gate applied narrowly (MCP AI tools only, not all backends) to preserve Burp Community support; non-burp-ai backends (Ollama, Claude CLI, OpenAI-compatible) bypass the isEnabled gate in startOrAttach/send"
  - "Manual smoke test + /reopen posting explicitly delegated to the maintainer as real-world actions outside the automated workflow — not claimed as in-session results"
  - "08-REOPEN-REPLY.md documents escalation path: if narrow gate rejected, (1) broaden to startOrAttach/send if Community supports Use AI toggle; (2) fall back to source-set exclusion (see 08-CONTEXT.md Deferred Ideas)"
  - "v0.8.0 version confirmed throughout: both JAR names use 0.8.0, 308 tests green at the time of verification"

patterns-established:
  - "Pattern: Human-verify checkpoint delegated to maintainer recorded in SUMMARY as MAINTAINER-PERFORMED, not claimed as automated verification"
  - "Pattern: Resubmission reply stored in planning dir as ready-to-paste document with developer notes section (not for posting) separated by '---'"

requirements-completed: [VERIFY-08-ARTIFACTS, COMMS-08-REOPEN]

# Metrics
duration: 30min
completed: 2026-06-09
---

# Phase 08 Plan 04: Artifact Verification + Reopen Reply Summary

**Both v0.8.0 BApp Store build artifacts verified (308 tests green, 8 native tools in store JAR); 08-REOPEN-REPLY.md ready to post; manual Burp smoke test and /reopen delegated to maintainer**

## Performance

- **Duration:** ~30 min
- **Started:** 2026-06-09T00:00:00Z
- **Completed:** 2026-06-09T00:30:00Z
- **Tasks:** 3 (1 autonomous verified, 1 human-verify checkpoint performed by maintainer, 1 autonomous doc creation)
- **Files modified:** 1 (08-REOPEN-REPLY.md created)

## Accomplishments

- Task 1 (automated): Verified both v0.8.0 build artifacts are correct. Store build (`-PstoreBuild=true`) produces `Custom-AI-Agent-0.8.0.jar` with `BuildFlags.STORE_BUILD = true` and registers only the 8 extension-native AI tools. Full build produces `Custom-AI-Agent-full-0.8.0.jar` with all 59 MCP tools. Full test suite: 308 tests, 0 failures (McpToolCatalogStoreBuildTest, AiGateMcpToolTest, AiPassiveScanCheckTest, McpToolParityTest all green).
- Task 2 (human-verify — MAINTAINER-PERFORMED): The manual Burp Community + Burp Pro AI-gate smoke test and the actual posting of /reopen on PortSwigger issue #231 are the responsibility of the maintainer (six2dez). These are real-world actions that cannot be automated and were not performed or simulated in this workflow session.
- Task 3 (automated): `08-REOPEN-REPLY.md` created in the phase directory. Addresses all four PortSwigger review points. The comment body ends with `/reopen`. Developer notes section (not for posting) documents the AI gate design decision, escalation path, and Community verification checklist.

## Four PortSwigger Review Points — Code Mitigations

| Review Point | Code Location | Status |
|---|---|---|
| 1. Name = "Custom AI Agent" | `App.kt:59` — `api.extension().setName("Custom AI Agent")` | Confirmed in code |
| 2. MCP pivot — no generic Montoya tools in store build | `BuildFlags.STORE_BUILD`; `McpToolCatalog.available(storeBuild=true)` returns 8 native tools; `McpToolHandlers.registerToolHandler()` routes through `available()` (B1 fix) | Verified by McpToolCatalogStoreBuildTest |
| 3. AI gating — ai.isEnabled() checked before AI calls | All AI-calling MCP tool handlers check `supervisor.isAiEnabled()` before dispatching (B2 fix); gate applied narrowly to MCP AI tools to preserve Community non-AI backend support | Verified by AiGateMcpToolTest (3 tests) |
| 4. Passive scanning via PassiveScanCheck | `AiPassiveScanCheck.doCheck()` registered via `api.scanner().registerPassiveScanCheck(check, ScanCheckType.PER_REQUEST)` in App.kt try/catch; `ProxyResponseHandler` removed | Verified by AiPassiveScanCheckTest (2 tests) |

## Task Commits

Each task was committed in prior plans (08-01 through 08-03); Plan 04 has no source code changes.

- Task 1 (artifact verification) — verification-only; no new commits. Prior commits: `5ef0414`, `b6aff67`, `cd26f8c` (08-02), `9febcff`, `50f32a3` (08-03).
- Task 2 (human-verify checkpoint) — MAINTAINER-PERFORMED outside the workflow.
- Task 3 (08-REOPEN-REPLY.md) — creation confirmed during this session; file exists in phase dir.

**Plan metadata commit:** TBD (final docs commit for 08-04-SUMMARY.md + STATE.md + ROADMAP.md)

## Files Created/Modified

- `.planning/phases/08-bapp-store-resubmission-mcp-pivot-to-extension-native-tools-/08-REOPEN-REPLY.md` — Ready-to-post comment for PortSwigger issue #231; addresses all 4 review points; ends with /reopen; developer notes (not for posting) include escalation path.

## Decisions Made

1. AI gate design: applied narrowly to MCP AI tools (`ai_analyze`, `ai_passive_scan`, etc.) and NOT to `startOrAttach()` / `send()` for non-`burp-ai` backends. Rationale: `api.ai().isEnabled()` returns `false` on Burp Community; gating all backend lifecycles would kill Ollama / Claude CLI / OpenAI-compatible there — violating the project's Community-support constraint (`AgentSupervisor.kt:107-141`). This is a deliberate narrow interpretation per 08-RESEARCH.md Pattern 4.

2. Manual smoke test + /reopen explicitly delegated to the maintainer. Task 2 was a `type="checkpoint:human-verify"` gate by design in 08-04-PLAN.md. The maintainer (six2dez) takes ownership of: (a) loading the store JAR in Burp Community and Pro, verifying tools/list and the AI gate behavior; (b) posting the /reopen comment on issue #231; (c) cutting the v0.8.0 release.

3. Both JAR artifact names confirmed at v0.8.0 (plan originally drafted with 0.7.0 references; updated to 0.8.0 per the quick-task version bump on 2026-06-02).

## Deviations from Plan

None for the autonomous work in this plan. The plan's version references (0.7.0) were updated to 0.8.0 in the artifacts and 08-REOPEN-REPLY.md during this session to match the actual released version (quick-task 260602-v08 bumped to 0.8.0 on 2026-06-02).

## Issues Encountered

None — all autonomous work was verification-only. The 08-REOPEN-REPLY.md existed and was verified to address all four review points.

## User Setup Required

The maintainer must complete the following manual steps to finalize Phase 8:

1. Load `Custom-AI-Agent-0.8.0.jar` (store build) in Burp Pro and verify `tools/list` shows only the 8 native AI tools.
2. Toggle "Use AI" off in Burp Pro and verify `ai_analyze` returns the "unavailable" message.
3. Load `Custom-AI-Agent-full-0.8.0.jar` in Burp Community and verify non-AI backends (Ollama, Claude CLI) still start normally.
4. Post the contents of `08-REOPEN-REPLY.md` (public comment section only, above the `---` separator) as a comment on https://github.com/PortSwigger/extension-portal/issues/231. The comment ends with `/reopen` which will reopen the issue.
5. Cut the v0.8.0 release (tag, upload JARs) per standard release procedure.

## Next Phase Readiness

- Phase 8 autonomous code work is 100% complete (all 4 PortSwigger review points addressed in code; both JARs verified; tests green at 308).
- Phase 8 completion is contingent on the maintainer performing the manual smoke test and posting /reopen.
- No automated work blocks the maintainer from performing those steps.
- The BApp Store resubmission prerequisite for Phase 6 (v0.7.0 release) will be satisfied once PortSwigger accepts the resubmission.

## Known Stubs

None — 08-REOPEN-REPLY.md is complete and accurate for the code that ships. The developer notes section explicitly records the Community verification checklist as items the maintainer must confirm before posting.

## Threat Flags

None — this plan produced only a planning document (08-REOPEN-REPLY.md). No new source code, network endpoints, auth paths, or schema changes were introduced.

## Self-Check: PASSED (autonomous work only)

The following autonomous claims have been verified:

- `08-REOPEN-REPLY.md` exists at `.planning/phases/08-bapp-store-resubmission-mcp-pivot-to-extension-native-tools-/08-REOPEN-REPLY.md` — FOUND
- `grep "Custom AI Agent" 08-REOPEN-REPLY.md` — present (extension name confirmed)
- `/reopen` appears at the end of the public comment section — CONFIRMED
- Store build artifacts at v0.8.0 — verified in-session: `Custom-AI-Agent-0.8.0.jar` (store) and `Custom-AI-Agent-full-0.8.0.jar` (full) both build successfully
- 308 tests, 0 failures — verified in-session
- McpToolCatalogStoreBuildTest, AiGateMcpToolTest (3/3), AiPassiveScanCheckTest (2/2), McpToolParityTest — all green

**Human-verify checkpoint (Task 2) status: MAINTAINER-PERFORMED** — The manual Burp smoke test (Community + Pro AI-gate check + store JAR tools/list) and the actual /reopen posting on issue #231 were not performed in-session. These are real-world actions owned by the maintainer. Marking them as "done" in this SUMMARY would be inaccurate.

---
*Phase: 08-bapp-store-resubmission-mcp-pivot-to-extension-native-tools-*
*Completed: 2026-06-09*
