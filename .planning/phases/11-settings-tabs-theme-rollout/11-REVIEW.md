---
phase: 11-settings-tabs-theme-rollout
reviewed: 2026-06-02T10:45:09Z
depth: deep
files_reviewed: 10
files_reviewed_list:
  - src/main/kotlin/com/six2dez/burp/aiagent/ui/SettingsPanel.kt
  - src/main/kotlin/com/six2dez/burp/aiagent/ui/panels/ActiveScanConfigPanel.kt
  - src/main/kotlin/com/six2dez/burp/aiagent/ui/panels/ActiveScanQueuePanel.kt
  - src/main/kotlin/com/six2dez/burp/aiagent/ui/panels/BackendConfigPanel.kt
  - src/main/kotlin/com/six2dez/burp/aiagent/ui/panels/CustomPromptsConfigPanel.kt
  - src/main/kotlin/com/six2dez/burp/aiagent/ui/panels/HelpConfigPanel.kt
  - src/main/kotlin/com/six2dez/burp/aiagent/ui/panels/McpConfigPanel.kt
  - src/main/kotlin/com/six2dez/burp/aiagent/ui/panels/PassiveScanConfigPanel.kt
  - src/main/kotlin/com/six2dez/burp/aiagent/ui/panels/PrivacyConfigPanel.kt
  - src/main/kotlin/com/six2dez/burp/aiagent/ui/panels/PromptConfigPanel.kt
findings:
  critical: 0
  warning: 2
  info: 3
  total: 5
status: issues_found
---

# Phase 11: Code Review Report

**Reviewed:** 2026-06-02T10:45:09Z
**Depth:** deep
**Files Reviewed:** 10
**Status:** issues_found

## Summary

Phase 11 migrates all Burp settings panels from the legacy `UiTheme` styling helper and per-class GridBag/inline layout code onto the Phase 9 design system (`DesignTokens` + the shared `Components.kt` helpers `formGrid`, `addRowFull`, `addRowPair`, `addSpacerRow`, `sectionPanel`, `buildTabPanel`, `applyFieldStyle`, `applyAreaStyle`). The structural change of the phase is the removal of builder-lambda constructor parameters from seven `*ConfigPanel` classes (`HelpConfigPanel`, `PrivacyConfigPanel`, `PassiveScanConfigPanel`, `ActiveScanConfigPanel`, `PromptConfigPanel`, `CustomPromptsConfigPanel`, `McpConfigPanel`) and replacement of the local copies of the layout helpers in `SettingsPanel.kt` with top-level imports from the design module.

I focused the adversarial pass on the four highest-risk areas called out for this phase and found them sound:

- **Settings persistence integrity (UI-07):** The persistence-critical methods (`currentSettings()`, `applySettingsToUi()`, `applyAndSaveSettings()`, and `BackendConfigPanel.currentBackendSettings()`/`applyState()`) are unchanged by this diff apart from `UiTheme` → `DesignTokens` symbol renames. Every settings field is still read with the same `as? Int ?: default` / `.text.trim()` / `.isSelected` pattern and written back via the same `.value` / `.text` / `.isSelected` assignment. No settings key strings live in these UI files (they are in `AgentSettings`/`AgentSettingsRepository`, untouched). Label-text relayouts (e.g. "Timeout (sec)" → "Timeout (s)", "Concurrent scans" → "Max concurrent") are display-only and do not affect save/load.
- **Null-safety:** No new nullable dereferences introduced. The `getClientProperty("row") as? Int ?: 0` pattern in `BackendConfigPanel.buildBurpAiPanel()` is null-safe and consistent with `formGrid()`, which seeds `row = 0`.
- **JPasswordField masking:** Preserved. `applyFieldStyle(field: JTextField)` (design module) only sets font/border/colors and never touches `echoChar`; `JPasswordField` is a `JTextField` subclass, so passing `ollamaApiKey`/`lmStudioApiKey`/etc. through `applyFieldStyle` is type-safe and keeps masking. Password reads still use `String(field.password).trim()`.
- **The two recent fixes:** Both are correct. `updateFieldStyle()` now sets `inputBackground` unconditionally and conveys the disabled state via foreground only; `updateMcpTlsState()` still mirrors that by setting `mcpKeystorePassword.foreground` to `onSurfaceVariant` when disabled, so the disabled cue is preserved. The `burpIntegrationTab` restructure correctly avoids the nested-scroll-pane wheel-event regression by using a non-scrolling `BorderLayout` container around the panel's own inner `JScrollPane`.

**Cross-file verification:** All seven refactored constructors match their call sites in `SettingsPanel.kt` (every call uses named arguments with the exact parameter names; no missing or extra params). Each injected Swing component is added to exactly one parent grid across the reorganized `build()` methods (no double-add that would orphan a component). `compileKotlin` passes cleanly (exit 0), confirming the constructor-signature change propagated consistently. No leftover `UiTheme` symbol references remain in code (only two stale doc comments). No debug artifacts, no empty catch blocks, no injection/secret/crypto concerns (these are local Swing UI files with no network or data trust boundary).

Findings are limited to maintainability items; none block shipping.

## Warnings

### WR-01: `updateFieldStyle` is applied to only one of the two TLS keystore fields, leaving styling responsibility split

**File:** `src/main/kotlin/com/six2dez/burp/aiagent/ui/SettingsPanel.kt:2456-2467`
**Issue:** After the refactor, `updateMcpTlsState()` calls `updateFieldStyle(mcpKeystorePath)` (which now resets `background` to `inputBackground` and toggles `foreground` by enabled state) but hand-rolls the equivalent for `mcpKeystorePassword` inline (`mcpKeystorePassword.foreground = if (...) inputForeground else onSurfaceVariant`) without resetting its `background`. Because `mcpKeystorePassword` is a `JPasswordField` (a `JTextField`), it is eligible for the same `updateFieldStyle` helper. The two fields are now styled by two different code paths for the same enable/disable transition, which is easy to drift out of sync on the next change (e.g. if the disabled background rule is reintroduced for one but not the other). This is a maintainability/robustness concern, not a current visible bug.
**Fix:** Route the password field through the same helper. Since `updateFieldStyle` takes `JTextField`, this is type-compatible:
```kotlin
mcpKeystorePath.isEnabled = tlsEnabled
mcpKeystorePassword.isEnabled = tlsEnabled
updateFieldStyle(mcpKeystorePath)
updateFieldStyle(mcpKeystorePassword)
```
and delete the bespoke `mcpKeystorePassword.foreground = ...` line.

### WR-02: `addRowFull(panel, "", buttonRow)` relies on an empty-string label cell to align button rows, producing a fragile blank-label layout idiom

**File:** `src/main/kotlin/com/six2dez/burp/aiagent/ui/panels/BackendConfigPanel.kt:296-304, 345-352, 367-374, 382, 396, 409, 422`
**Issue:** The migration replaced the old dedicated `addButtonRow(panel, row, component)` helper (which explicitly added a blank label cell) with `addRowFull(panel, "", buttonRowPanel)`. This works, but it leans on `addRowFull` adding an empty `JLabel("")` in column 0 to push the button cluster into the field column. The button-row `JPanel` is a `BoxLayout` panel (not a "small component"), so `isSmallComponent()` returns false and it gets `fill = HORIZONTAL` across columns 1–3 — fine today, but the alignment now depends on an implicit interaction between the empty label and the small-component predicate rather than an explicit "no-label row" affordance. If `addRowFull`'s small-component / fill logic changes, every backend button row shifts silently. Maintainability concern only; renders correctly as written.
**Fix:** Consider adding an explicit `addButtonRow`/`addFieldOnlyRow` helper to `Components.kt` (column-1 span, no label) and using it for these rows, so the intent ("a row with no label") is encoded rather than emulated with `""`.

## Info

### IN-01: Unused `BadgeStyle` import in `SettingsPanel.kt` (pre-existing)

**File:** `src/main/kotlin/com/six2dez/burp/aiagent/ui/SettingsPanel.kt:26`
**Issue:** `import com.six2dez.burp.aiagent.ui.design.BadgeStyle` has no usage in the file body (only `toolBadge(...)` is used, which takes a `BadgeStyle` but is presumably called with the enum elsewhere or imported separately). This import was already present and unused at the base commit `6b522ca`; the phase 11 diff did not introduce it. Flagged for completeness since the file is in scope, but it is not a phase-11 regression.
**Fix:** Remove the unused import line. Low priority — verify no usage was intended before deleting.

### IN-02: Stale `UiTheme` references in code comments after the migration

**File:** `src/main/kotlin/com/six2dez/burp/aiagent/ui/SettingsPanel.kt:607-608`
**Issue:** Two comments still say "mcpNotice styles itself via UiTheme" and "privacyNotice styles itself via UiTheme" even though the rest of the codebase moved off `UiTheme` to `DesignTokens` in this phase. If `UiTheme` is later removed/renamed, these comments become misleading.
**Fix:** Update the comments to reference the current styling source (`DesignTokens` / `SubtleNotice`'s own theming) or drop the implementation detail.

### IN-03: Display-label wording diverged from the underlying setting semantics in a few rows

**File:** `src/main/kotlin/com/six2dez/burp/aiagent/ui/panels/ActiveScanConfigPanel.kt:153-159`, `src/main/kotlin/com/six2dez/burp/aiagent/ui/panels/PassiveScanConfigPanel.kt:191`
**Issue:** Several user-facing labels were reworded during the relayout (e.g. "Max risk level" → "Risk level", "SSRF OAST" → "Use Collaborator", "Rate limit (sec)" → "Rate limit (s)"). These are cosmetic and do not affect persistence, but "Risk level" is now slightly less precise than "Max risk level" for a setting that is a ceiling (`activeAiMaxRiskLevel` / `PayloadRisk`). No functional impact.
**Fix:** Optional — restore "Max risk level" (or similar) if the "maximum/ceiling" semantics should remain explicit to the user.

---

_Reviewed: 2026-06-02T10:45:09Z_
_Reviewer: Claude (gsd-code-reviewer)_
_Depth: deep_
