---
gsd_summary_version: 1.0
quick_id: 260714-dp1
title: BApp Store code-review quick-wins (findings 3, 4, 6, 8 + verify 5)
status: complete
date: 2026-07-14
branch: fix/bapp-store-code-review
---

# Quick Task 260714-dp1 — Summary

Addressed the 4 low-risk findings + 1 verification from PortSwigger's automated code-review of the BApp Store submission ([extension-portal#231](https://github.com/PortSwigger/extension-portal/issues/231#issuecomment-4878007095)). The 3 heavier findings (site-map defer, bounty-prompt cache, collaborator async polling) are deferred to a follow-up batch.

## Commits (one per finding, on `fix/bapp-store-code-review`)

| Finding | Commit | Change |
|---------|--------|--------|
| 4 — deprecated `ScanCheck` | `72dcd34` | `AiScanCheck` now implements `ActiveScanCheck` (`checkName` + `doCheck(_, _, Http)`); registered via `registerActiveScanCheck(PER_INSERTION_POINT)`; empty `passiveAudit` removed. |
| 6 — health monitor cancels on throw | `b98c86b` | `scheduleAtFixedRate({ checkHealth() })` body wrapped in `try/catch (Throwable)` that logs. |
| 8 — unbounded regex over response body | `85a5ffc` | `response_body_search` caps the body to 64 KB (`boundForRegexScan`) before matching, in both `McpToolLegacy` and `McpToolExecutorImpl`. |
| 3 — `Thread.sleep` ties up scanner thread | `a65ea32` | Throttle now sleeps only `max(0, delay − elapsed)` since the last request instead of the full delay on top of the round-trip. |
| 5 — `requestExecutor` unload (verify) | `e9333b4` | Verified `requestExecutor` IS shut down on unload (`registerUnloadingHandler → App.shutdown() → activeAiScanner.shutdown()`); hardened `App.shutdown()` by splitting the disable/shutdown steps. |

## Verification

`JAVA_HOME=$(/usr/libexec/java_home -v 21) ./gradlew compileKotlin test ktlintCheck` — **passing** (compile ✓, tests ✓, ktlint ✓).

## Notes

- **Finding 5 was a false positive** by the automated reviewer: it inspected `stopProcessing()` (which correctly leaves `requestExecutor` alive across enable/disable cycles) but missed the dedicated `shutdown()` method wired to the unload path. No functional bug; hardening added for robustness.
- **Findings 7 & 8 sit in code gated out of the BApp Store build** (non-`nativeTool` MCP tools). Fixed anyway because PortSwigger reviews the full repo.
- No tests referenced `AiScanCheck.activeAudit`, so the `doCheck` rename needed no test updates.

## Follow-up (separate batch)

Finding 1 (defer `api.siteMap().requestResponses()` out of the EDT menu-build path), Finding 2 (cache bounty-prompt definitions at startup), Finding 7 (consolidate the SSRF-OOB collaborator polling into a single scheduled poller). Then post the `/reopen` reply mapping all 8 points.
