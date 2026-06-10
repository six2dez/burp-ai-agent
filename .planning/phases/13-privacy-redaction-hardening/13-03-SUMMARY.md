---
phase: 13-privacy-redaction-hardening
plan: "03"
subsystem: redact/ui
tags: [priv-04, secret-shapes, context-preview, banner, kotlin, tdd]
dependency_graph:
  requires:
    - 13-01: redact package conventions + PrivacyMode
  provides:
    - SecretShapes AWT-free curated secret-shape set (PRIV-04 + Phase 15 tripwire contract)
    - Non-blocking WARN banner in ContextPreviewDialog showing surviving-secret categories
  affects:
    - src/main/kotlin/com/six2dez/burp/aiagent/redact/SecretShapes.kt (new)
    - src/main/kotlin/com/six2dez/burp/aiagent/ui/components/ContextPreviewDialog.kt (modified)
    - src/test/kotlin/com/six2dez/burp/aiagent/redact/SecretShapesTest.kt (new)
tech_stack:
  added: []
  patterns:
    - AWT-free object with curated Regex vals (mirrors Redaction.kt idiom)
    - SubtleNotice Level.WARN advisory banner in header BoxLayout stack
    - TDD RED/GREEN cycle across tasks 1 and 2
key_files:
  created:
    - src/main/kotlin/com/six2dez/burp/aiagent/redact/SecretShapes.kt
    - src/test/kotlin/com/six2dez/burp/aiagent/redact/SecretShapesTest.kt
  modified:
    - src/main/kotlin/com/six2dez/burp/aiagent/ui/components/ContextPreviewDialog.kt
decisions:
  - SecretShapes includes the broad high-entropy hex key shape (32+ hex chars) placed LAST, accepting T-13-11 (false-positive desensitisation) as the non-blocking banner makes false positives low-harm
  - Category names are case-insensitive-substring-matched in tests for robustness to minor wording drift
  - Duplicate JWT literal in SecretShapes (vs Redaction.jwtRegex) is intentional — avoids coupling detection and redaction layers
  - FLAG-13-02 honoured: only SubtleNotice banner added to ContextPreviewDialog; surrounding un-migrated literals untouched
metrics:
  duration: "~5 minutes"
  completed: "2026-06-10T15:01:00Z"
  tasks_completed: 3
  files_changed: 3
---

# Phase 13 Plan 03: PRIV-04 Survived-Secret Banner Summary

**One-liner:** AWT-free `SecretShapes` object with 8 curated shapes + non-blocking `SubtleNotice.Level.WARN` banner in `ContextPreviewDialog` naming surviving secret categories post-redaction.

## What Was Built

### SecretShapes.kt (new, redact package)

A pure-Kotlin, AWT-free `object` in `com.six2dez.burp.aiagent.redact`:

- `data class Shape(val category: String, val regex: Regex)` — minimal pair for detection
- `val shapes: List<Shape>` — 8 ordered entries with verified prefixes:
  - OpenAI key (`sk-` legacy + `sk-proj-/svcacct-/admin-` modern forms)
  - AWS access key (`AKIA[0-9A-Z]{16}`)
  - GitHub token (`gh[pousr]_<36+>`)
  - GitHub fine-grained PAT (`github_pat_<22+>`)
  - Google API key (`AIza<35>`)
  - Slack token (`xox[baprs]-<10+>`)
  - JWT (`eyJ…`)
  - High-entropy hex key (`[0-9a-fA-F]{32,}`) — placed last per T-13-11 open question
- `fun findSurviving(text: String): Set<String>` — returns category names only; never the matched values
- Zero `java.awt` / `javax.swing` imports — Phase 15 tripwire AWT-free contract satisfied

### SecretShapesTest.kt (new, TDD RED→GREEN)

- `findSurvivingReturnsCategories`: positive sample per shape (OpenAI legacy, OpenAI proj, AWS, GitHub ghp_, GitHub fine-grained PAT, Google, Slack, JWT)
- `benignTextHasNoSurvivors`: plain English sentence returns empty set
- `shortHexDoesNotTriggerHighEntropyShape`: smoke test documents the hex-shape inclusion choice
- `nonSecretQueryStringNotFlagged`: URL with non-sensitive keys returns empty set
- All assertions use `contains(category, ignoreCase = true)` — robust to minor name changes

### ContextPreviewDialog.kt (modified, Task 3)

- Added `import com.six2dez.burp.aiagent.redact.SecretShapes`
- In `confirm(...)` after the "Context (as will be sent, after redaction):" label:
  - `val survivors = SecretShapes.findSurviving(contextJson)` — scans POST-redaction context only
  - Non-empty: `setMessage(Level.WARN, html)` with single/multiple copy from UI-SPEC §Copywriting
  - Empty: `hideNotice()` — clean context shows no banner
  - Message uses `survivors.joinToString(", ")` — category names only, never raw values (T-13-10)
- `confirm(...)` signature and `Send`/`Cancel` semantics unchanged — banner is advisory (no hard stop)
- No `Color()`/`Font()`/`Dimension()` literals added — FLAG-13-02 un-migrated dialog preserved

## Deviations from Plan

None - plan executed exactly as written.

The high-entropy hex shape inclusion decision was explicitly at Claude's discretion (Open Question 3,
13-RESEARCH.md lines 654-656): it is included, placed last, with a comment documenting the
false-positive risk and the T-13-11 acceptance rationale. This matches the plan's permissive guidance.

## Threat Surface Scan

No new network endpoints, auth paths, file access patterns, or schema changes introduced. The banner
exposes category names already derivable from the existing `Redaction.kt` patterns and the
`SecretShapes` shapes object. T-13-10 mitigation (categories-only, no raw values) was verified by
grep confirming no raw match interpolation in the message builder.

## Known Stubs

None. `SecretShapes.findSurviving` is fully wired into `ContextPreviewDialog.confirm()` and the
curated shapes are populated with all 8 verified entries. No placeholder data or TODO wiring.

## Self-Check: PASSED

- `src/main/kotlin/com/six2dez/burp/aiagent/redact/SecretShapes.kt` — exists (95 lines)
- `src/test/kotlin/com/six2dez/burp/aiagent/redact/SecretShapesTest.kt` — exists (115 lines)
- `src/main/kotlin/com/six2dez/burp/aiagent/ui/components/ContextPreviewDialog.kt` — modified (112 lines)
- Commit 83db98e: `test(13-03): add failing SecretShapesTest (RED)` — RED gate present
- Commit ca895bc: `feat(13-03): add SecretShapes AWT-free curated secret-shape set` — GREEN gate present
- Commit b961628: `feat(13-03): add non-blocking survived-secret WARN banner` — Task 3 committed
- `./gradlew test --tests "*SecretShapesTest"`: BUILD SUCCESSFUL
- `./gradlew test` (full suite): BUILD SUCCESSFUL
- AWT-free: `grep "import java.awt\|import javax.swing" SecretShapes.kt` returns empty
- No Level.RISK in ContextPreviewDialog: confirmed by grep
- No raw matched values in banner: confirmed by grep (message uses survivors variable only)
