---
gsd_summary_version: 1.0
quick_id: 260714-ekv
title: BApp Store code-review batch B — heavy findings 1, 2, 7
status: complete
date: 2026-07-14
branch: fix/bapp-store-code-review
---

# Quick Task 260714-ekv — Summary

Completed the 3 heavier BApp Store code-review findings, finishing all 8 flagged items across batches A + B on `fix/bapp-store-code-review`.

## Commits

| Finding | Commit | Change |
|---------|--------|--------|
| 2 — BountyPrompt I/O on EDT | `80c45bd` | Cache `LoadedBountyPrompts`; refresh on a daemon thread at startup + on settings save; menu reads cache (no EDT disk I/O). |
| 1 — site-map scan on EDT | `b113a61` | `targets` is now a memoized `Lazy<List<HttpRequestResponse>>`; `api.siteMap().requestResponses(filter)` runs only when an action fires, not at menu build. |
| 7 — blocking Collaborator poll | `d1ccc56` | Single shared Collaborator client + pending-payload map + one 60 s `ScheduledExecutorService` poller; issue created async via shared `confirmFinding`. |

## Verification

`JAVA_HOME=$(/usr/libexec/java_home -v 21) ./gradlew compileKotlin test ktlintCheck` — **passing** (compile ✓, tests ✓, ktlint ✓) with all 8 findings applied.

## Notes

- Finding 1 was implemented via a subagent against an exact spec; it also caught two internal `targets` uses beyond the enumerated list (an audit-log `targets.size` and a second `filterValidTargets` call) — both required for compile.
- Behaviour changes are intended and reviewer-sanctioned: the site-map menu label now reads "site map subtree" (exact count is unknown until an action expands the subtree), and BountyPrompt submenu items drop the per-item `(count)`.
- No unit tests cover the Swing menu or live Collaborator flow; correctness rests on the compile/test/ktlint gate + design review. Both are worth a human smoke-test in Burp before/at resubmission.

## Next

Post the `/reopen` comment on extension-portal#231 mapping all 8 findings, then resubmit.
