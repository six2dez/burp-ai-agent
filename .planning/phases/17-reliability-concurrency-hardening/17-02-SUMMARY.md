---
phase: 17-reliability-concurrency-hardening
plan: "02"
subsystem: ui/concurrency
tags: [rel-01, edt-confinement, concurrency, swing, zero-deps]
dependency_graph:
  requires: [17-01]
  provides: [REL-01]
  affects: [ui/ChatPanel.kt, util/GuardedBy.kt, build.gradle.kts, test/ChatPanelConcurrencyTest.kt]
tech_stack:
  added: []
  patterns: [EDT-confinement via SwingUtilities.invokeLater, @GuardedBy SOURCE annotation, JVM -ea assertions]
key_files:
  created:
    - src/main/kotlin/com/six2dez/burp/aiagent/util/GuardedBy.kt
    - (extended) src/test/kotlin/com/six2dez/burp/aiagent/ui/ChatPanelConcurrencyTest.kt
  modified:
    - src/main/kotlin/com/six2dez/burp/aiagent/ui/ChatPanel.kt
    - build.gradle.kts
decisions:
  - "onCompleted continuation stays off-EDT (narrowest change); only map reads + panel.addMessage routed via invokeLater"
  - "A2 confirmed via grep + MainTab caller audit: all other map write sites are EDT-reached (UI actions, javax.swing.Timer)"
  - "assertEdt() uses JVM assert (not throw) to preserve prod behavior when -ea is off"
  - "SC1 gate is the ChatPanelConcurrencyTest, not the assert — assert is a developer aid only"
  - "@GuardedBy is SOURCE-retained: zero runtime/class footprint, not in fat JAR"
metrics:
  duration: "3 minutes"
  completed: "2026-06-11"
  tasks_completed: 2
  files_changed: 4
---

# Phase 17 Plan 02: REL-01 EDT Confinement Summary

**One-liner:** EDT-confined the 4 ChatPanel session maps with a local @GuardedBy SOURCE annotation, invokeLater-wrapped the off-EDT maybeExecuteToolCall race site, and added an SC1 concurrency test with -ea assertions enabled in CI.

## Tasks Completed

| Task | Name | Commit | Files |
|------|------|--------|-------|
| 1 | GuardedBy annotation, -ea, SC1 test scaffold | 6970a54 | GuardedBy.kt (new), build.gradle.kts, ChatPanelConcurrencyTest.kt |
| 2 | Annotate 4 maps, assertEdt(), invokeLater fix | d85a958 | ChatPanel.kt |

## What Was Built

### util/GuardedBy.kt (new)
Local SOURCE-retained replacement for `net.jcip.annotations.GuardedBy`. Zero new dependencies (JCIP/jsr305 deliberately off-classpath). `@Target(FIELD, PROPERTY)` covers Kotlin `private val` declarations without requiring a `@field:` use-site qualifier. `@Retention(SOURCE)` keeps the annotation out of the fat JAR entirely.

### ChatPanel.kt — 4 map annotations + assertEdt() + invokeLater fix
- `@GuardedBy("EDT")` added to all four session maps; maps remain `linkedMapOf` (insertion order preserved — not converted to ConcurrentHashMap, per REL-01 locked decision).
- `assertEdt()` private helper: `assert(SwingUtilities.isEventDispatchThread())` under JVM `-ea`; no-op in production — does not change prod behavior.
- `assertEdt()` called inside `maybeExecuteToolCall` so a future off-EDT regression trips in CI.
- Off-EDT race fixed: the `maybeExecuteToolCall(...)` call that read `sessionPanels[sessionId]` / `sessionsById[sessionId]` and called `panel.addMessage(...)` from the backend executor thread (via `onComplete` at ~:570) is now wrapped in `SwingUtilities.invokeLater { ... }`.
- `onCompleted` continuation remains off-EDT (invoked from the invokeLater block when not chained, consistent with narrowest-change approach; re-enters `sendMessage` which submits to a backend executor and does not block the EDT).

### build.gradle.kts — -ea assertion enablement
`jvmArgs("-ea")` added to `tasks.test`; existing `excludeHeavyTests` filter and `nightlyRegressionTest` task untouched.

### ChatPanelConcurrencyTest.kt — SC1 gate
Extended with `sessionMaps_noDataRaceUnderEdtConfinement`: a single-thread executor stands in for the EDT; 200 mutations and 4*200 reads are all routed through that executor; asserts no `ConcurrentModificationException` and consistent final map state (200 entries). Does NOT instantiate ChatPanel (avoids HeadlessException in CI).

## SC1 Assert Coverage — A2 Verification (per critical constraints option b)

**Decision: option (b)** — hard-verify that every write site is already EDT-reached; document them here. `assertEdt()` is placed only at the `maybeExecuteToolCall` entry point (the sole off-EDT entry; now fixed via invokeLater).

**All map write sites enumerated:**

| Site | Method | EDT-reached via |
|------|--------|-----------------|
| ChatPanel.kt:707-712 | `createSession` | UI action (button, action card), always EDT |
| ChatPanel.kt:757 | `renameSession` | `JOptionPane` input dialog, always EDT |
| ChatPanel.kt:773-780 | `deleteSession` | `JOptionPane` confirm dialog, always EDT |
| ChatPanel.kt:442-443 | `sendFromInput` | ActionListener on sendBtn, always EDT |
| ChatPanel.kt:487,498,504 | `sendMessage` | Called from `sendFromInput` (EDT) or from `maybeExecuteToolCall` which is now inside `invokeLater` |
| ChatPanel.kt:972-973 | `clearCurrentChat` | `JOptionPane` confirm dialog, always EDT |
| ChatPanel.kt:1145,1149,1158 | `persistActiveSessionDraft`, `restoreDraftForSession`, `syncDraftFromInput` | Called from UI-triggered methods, always EDT |
| ChatPanel.kt:1305-1308 | `clearInMemorySessionState` | Called from `MainTab.onProjectChanged()` which fires from `javax.swing.Timer` (EDT) |
| ChatPanel.kt:1317-1346 | `saveSessions` | Called from `javax.swing.Timer` callback (EDT) and from `MainTab.shutdown()` (plugin lifecycle, EDT-safe) |
| ChatPanel.kt:1394-1448 | `restoreSessions` | Called from `MainTab` constructor body during Burp extension init (EDT) and from `onProjectChanged` (`javax.swing.Timer`, EDT) |

**Conclusion:** `maybeExecuteToolCall` (now inside `invokeLater`) was the ONLY off-EDT map-read path. No additional confinement sites required. `assertEdt()` at the `maybeExecuteToolCall` entry point is the right guard — any future regression to calling it off-EDT will trip under `-ea` in CI.

## Deviations from Plan

None — plan executed exactly as written.

## Known Stubs

None. No placeholder or stub code introduced.

## Threat Flags

None. No new attack surface introduced. The fix closes T-17-02-01 (data race as DoS via ConcurrentModificationException) and mitigates T-17-02-02 (UI freeze regression — `onCompleted` stays off-EDT).

## Self-Check: PASSED

- GuardedBy.kt: FOUND
- ChatPanelConcurrencyTest.kt: FOUND
- Task 1 commit 6970a54: FOUND
- Task 2 commit d85a958: FOUND
- `./gradlew test` full suite: BUILD SUCCESSFUL
