---
gsd_plan_version: 1.0
quick_id: 260714-ekv
title: BApp Store code-review batch B — heavy findings 1, 2, 7
status: complete
date: 2026-07-14
branch: fix/bapp-store-code-review
mode: quick
---

# Quick Task 260714-ekv — BApp Store code-review batch B (heavy findings)

## Context

Second batch of the BApp Store automated code-review remediation ([extension-portal#231](https://github.com/PortSwigger/extension-portal/issues/231#issuecomment-4878007095)). Batch A (260714-dp1) handled the 4 low-risk findings + verification; this batch handles the 3 heavier refactors on the same branch `fix/bapp-store-code-review`.

## Tasks (one atomic commit each)

### Task 1 — Finding 1: defer site-map subtree expansion off the EDT
- **File:** `ui/UiActions.kt` (`requestResponseMenuItems` + `buildTargetedTestsMenu` / `buildBountyPromptMenu` / `buildHttpCustomPromptsMenu`)
- **Action:** `api.siteMap().requestResponses(filter)` iterated the whole site map during menu build on the EDT. Make `targets` a memoized `Lazy<List<HttpRequestResponse>>`; the scan runs only when an action fires. Cheap emptiness guard + label at build time.
- **Done:** No site-map scan on the menu-build path.

### Task 2 — Finding 2: cache BountyPrompt definitions
- **Files:** `ui/UiActions.kt`, `App.kt`, `ui/SettingsPanelSettingsIO.kt`
- **Action:** Cache parsed definitions (`LoadedBountyPrompts`), refreshed on a background daemon thread — primed at startup and on settings save. Menu reads the cache with no disk I/O.
- **Done:** `buildBountyPromptMenu` does no directory listing / JSON parse on the EDT.

### Task 3 — Finding 7: async SSRF-OOB confirmation
- **File:** `scanner/ActiveAiScanner.kt`
- **Action:** Replace per-target Collaborator client + 30 s blocking poll with a single shared client, a `ConcurrentHashMap` of pending payloads, and one `ScheduledExecutorService` polling every 60 s that matches interactions and creates the issue asynchronously (`confirmFinding`, shared with the sync path). Poller lifecycle tied to start/stopProcessing; stale entries expire.
- **Done:** No scanner thread blocks polling the Collaborator.

## Gate

`JAVA_HOME=$(/usr/libexec/java_home -v 21) ./gradlew compileKotlin test ktlintCheck` passes.
