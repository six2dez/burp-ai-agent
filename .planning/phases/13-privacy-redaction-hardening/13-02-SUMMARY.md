---
phase: 13
plan: 02
subsystem: redact
tags: [privacy, redaction, body-redaction, custom-patterns, persistence, ui, priv-02]
dependency_graph:
  requires: ["13-01"]
  provides: ["PRIV-02"]
  affects: ["Redaction.apply", "AgentSettings", "PrivacyConfigPanel", "SettingsPanel"]
tech_stack:
  added: []
  patterns:
    - "volatile list for thread-safe pattern push from EDT to redaction thread"
    - "DeadlineCharSequence (SafeRegex) for ReDoS-safe custom pattern application"
    - "newline-joined plaintext pref for list-of-strings config (not secrets)"
    - "addRowFull(grid, label, area, helpText) for full-width JTextArea row in form grid"
key_files:
  created: []
  modified:
    - src/main/kotlin/com/six2dez/burp/aiagent/redact/Redaction.kt
    - src/main/kotlin/com/six2dez/burp/aiagent/config/Defaults.kt
    - src/main/kotlin/com/six2dez/burp/aiagent/config/AgentSettings.kt
    - src/main/kotlin/com/six2dez/burp/aiagent/ui/panels/PrivacyConfigPanel.kt
    - src/main/kotlin/com/six2dez/burp/aiagent/ui/SettingsPanel.kt
    - src/test/kotlin/com/six2dez/burp/aiagent/redact/RedactionTest.kt
    - src/test/kotlin/com/six2dez/burp/aiagent/config/AgentSettingsMigrationTest.kt
decisions:
  - "Body/form regex uses (^|[?&]) anchor to close leading-field gap (old [?&]-only missed first param)"
  - "JSON key regex is curated/key-scoped — not a full JSON parser; partial-escaped-quote limitation documented"
  - "compiledCustomPatterns is @Volatile list — EDT write (save) visible to redaction thread without full synchronization"
  - "customRedactionPatterns persisted plaintext newline-joined — NOT SecretCipher (patterns are config not secrets)"
  - "Custom patterns validated via SafeRegex.isPatternSafe at save time; invalid/slow lines dropped, valid lines persisted"
  - "setCustomPatterns called in applyAndSaveSettings so edits take effect without restart"
metrics:
  duration: "~30 minutes"
  completed: "2026-06-10T14:51:58Z"
  tasks_completed: 3
  files_modified: 7
---

# Phase 13 Plan 02: Body/Form/JSON Redaction + Custom Patterns Summary

Body redaction reaching leading form-urlencoded fields and JSON keys, plus a user-configurable custom-pattern engine validated against catastrophic backtracking, persisted as plaintext config.

## Tasks Completed

| Task | Name | Commit | Files |
|------|------|--------|-------|
| 1 | RED tests (body/custom/persistence) | 9e7f83d | RedactionTest.kt, AgentSettingsMigrationTest.kt |
| 2 | Body/form/JSON + custom engine (GREEN) | f7ab377 | Redaction.kt, Defaults.kt |
| 3 | Persist + Privacy panel + setCustomPatterns (GREEN) | 9425bf0 | AgentSettings.kt, PrivacyConfigPanel.kt, SettingsPanel.kt |

## What Was Built

### Body-redaction engine (Redaction.kt + Defaults.kt)

- `SENSITIVE_KEYS` const shared by `urlTokenParamRegex`, `formBodyParamRegex`, `jsonSecretKeyRegex`
- `formBodyParamRegex = Regex("(?im)(^|[?&])(KEYS)=[^&\\s\"'<>]+")` — the `(^|[?&])` anchor closes the documented leading-field gap (T-13-05); `apikey=sk-abc123&user=bob` → `apikey=[REDACTED]&user=bob`
- `jsonSecretKeyRegex = Regex("(?i)(\"(?:KEYS)\"\\s*:\\s*)\"[^\"]*\"")` — key-scoped; `"name":"alice"` untouched
- `compiledCustomPatterns: @Volatile List<Pattern>` + `setCustomPatterns()` mutator
- Body stage guarded by `Defaults.MAX_REDACTION_BODY_CHARS = 1_000_000` (bodies over cap short-circuited)
- Each custom pattern runs via `SafeRegex.replaceAllSafe(out, p, "[REDACTED]")` — 50 ms deadline (T-13-06)
- All new logic inside `if (policy.redactTokens)` — OFF mode passes through unchanged

### Persistence (AgentSettings.kt)

- `customRedactionPatterns: List<String> = emptyList()` data class field
- `KEY_CUSTOM_REDACTION_PATTERNS = "privacy.custom.redaction.patterns.v1"` — plaintext, NOT `SecretCipher`
- `load()`: `prefs.getString(key).orEmpty().split('\n').map { it.trim() }.filter { it.isNotBlank() }`
- `save()`: `prefs.setString(key, settings.customRedactionPatterns.joinToString("\n"))`
- Absent key → `emptyList()` (mirrors v3 absent-key-default precedent, no migration step needed)

### Privacy panel UI (PrivacyConfigPanel.kt + SettingsPanel.kt)

- `PrivacyConfigPanel` gains optional `customPatternsArea: JComponent` + `patternsFeedback: JComponent` params
- `addRowFull(grid, "Custom redaction patterns", customPatternsArea, helpText = "…")` inserted after Anonymization row, before Save feedback
- `SettingsPanel` constructs `JTextArea` (via `applyAreaStyle`, `rows=4`) and feedback `JLabel` (caption font, hidden initially)
- `validateAndCollectCustomPatterns()`: splits text area by newline, calls `SafeRegex.isPatternSafe` on each line, updates label with `DesignTokens.Colors.statusError` / `.statusSuccess` (re-read each call per UI-SPEC rule 4)
- `applySettingsToUi()`: reloads text area from `updated.customRedactionPatterns`, hides feedback
- `applyAndSaveSettings()`: calls `Redaction.setCustomPatterns(updated.customRedactionPatterns)` — live pipeline updated without restart

## Tests

All 354 tests pass (0 failures, 0 errors). New tests added:

**RedactionTest.kt (5 new):**
- `bodyFormLeadingFieldRedacted` — leading form-body field redacted in STRICT+BALANCED; `user=bob` untouched
- `bodyJsonSecretKeysRedacted` — `"api_key"` and `"token"` values redacted; `"name":"alice"` untouched
- `offModePreservesBodies` — OFF mode returns form and JSON bodies unchanged
- `customPatternRedactsInStrictAndBalanced` — `\bSECRET-\d{4}\b` applied in STRICT+BALANCED, inactive in OFF
- `oversizeBodySkippedSafely` — body > 1 MB short-circuits; call returns promptly without throwing

**AgentSettingsMigrationTest.kt (2 new):**
- `customRedactionPatterns_roundTripsThroughSaveLoad` — save `["foo","bar"]`, reload → same list; stored value is `"foo\nbar"` (not `ENC1:`)
- `customRedactionPatterns_absentKeyDefaultsToEmptyList` — fresh install with no key → `emptyList()`

## Deviations from Plan

None — plan executed exactly as written.

## Known Stubs

None. All body-redaction paths are wired; custom patterns persist and apply at runtime.

## Threat Flags

No new network endpoints, auth paths, or schema changes at trust boundaries were introduced.
All threat-model items from the plan's STRIDE register were addressed:
- T-13-05: formBodyParamRegex (^|[?&]) closes the leading-field gap; verified by bodyFormLeadingFieldRedacted
- T-13-06: each custom pattern runs via SafeRegex.replaceAllSafe (50 ms deadline); save rejects via isPatternSafe; body stage has 1 MB cap
- T-13-07: patterns persisted plaintext — no SecretCipher, never logged
- T-13-08: key-scoped regexes; non-sensitive params asserted untouched in tests

## Self-Check: PASSED

Files verified present:
- src/main/kotlin/com/six2dez/burp/aiagent/redact/Redaction.kt ✓
- src/main/kotlin/com/six2dez/burp/aiagent/config/Defaults.kt ✓ (MAX_REDACTION_BODY_CHARS)
- src/main/kotlin/com/six2dez/burp/aiagent/config/AgentSettings.kt ✓ (customRedactionPatterns + KEY)
- src/main/kotlin/com/six2dez/burp/aiagent/ui/panels/PrivacyConfigPanel.kt ✓ (customPatternsArea row)
- src/main/kotlin/com/six2dez/burp/aiagent/ui/SettingsPanel.kt ✓ (setCustomPatterns in save path)

Commits verified:
- 9e7f83d (RED tests) ✓
- f7ab377 (body engine GREEN) ✓
- 9425bf0 (persistence + UI GREEN) ✓

Full `./gradlew test` green: 354 tests, 0 failures, 0 errors.
