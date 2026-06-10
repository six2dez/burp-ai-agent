# Phase 14 — UI Review

**Audited:** 2026-06-10
**Baseline:** 14-UI-SPEC.md (approved design contract) + Phase 9 design system (`DesignTokens.kt` + `Components.kt`)
**Screenshots:** not captured — Kotlin + Swing extension (ADR-2: plain Swing, no web/Playwright/dev server). Code-only audit against the implemented `.kt` files, as the phase mandate directs.

---

## Pillar Scores

| Pillar | Score | Key Finding |
|--------|-------|-------------|
| 1. Copywriting | 4/4 | All 6 contract strings present verbatim, including the prescriptive SC3 error and both banner templates |
| 2. Visuals | 4/4 | Anthropic card is structurally identical to sibling backend cards; banner reuses `SubtleNotice` at NORTH; all controls labelled + tooltipped |
| 3. Color | 4/4 | Zero new color literals in the three touch points; WARN→RISK banner escalation matches the contract's `SubtleNotice.Level` map |
| 4. Typography | 4/4 | Only contract roles used (`body`/`caption`); no `Font(...)` constructors in panel code |
| 5. Spacing | 4/4 | `sectionPad`/`sm`/`xs` tokens throughout; Anthropic border copied verbatim; no inline spacing integers introduced |
| 6. Experience Design | 3/4 | Off-by-default, non-blocking, reversible-pause all correct; one warning — token-budget section uses inline `JLabel`/`AccordionPanel` instead of the contract-named `helpLabel`/`sectionPanel` builders |

**Overall: 23/24**

---

## Top 3 Priority Fixes

1. **[WARNING] Token-budget help text bypasses the `helpLabel(...)` builder** (`PassiveScanConfigPanel.kt:314-317`) — the contract (Touch Point 2 anatomy + Component Builder Usage Map) names `helpLabel(...)`, and that builder exists at `Components.kt:312` applying the exact same `caption` font + `onSurfaceVariant` color. The inline `JLabel(...).apply { font = …; foreground = … }` re-implements it by hand, so future tweaks to help-text styling (line-height, color) won't propagate here. **Fix:** replace the inline block with `helpLabel("Warn shows a chat banner. The hard cap pauses passive scanning; chat stays usable.")`. Visually identical; purely a maintainability/consistency fix.

2. **[WARNING] Token-budget section uses `AccordionPanel` rather than the contract-named `sectionPanel(...)`** (`PassiveScanConfigPanel.kt:319-325`) — the contract specified `sectionPanel(title, subtitle, content)` (exists at `Components.kt:270`); the executor used `AccordionPanel` (collapsed by default). This is **permitted** under FLAG-14-01 (placement/IA left to Claude's discretion) and is the *better* choice — every sibling scanner section is an `AccordionPanel`, so a flat `sectionPanel` here would have been the inconsistency. **Fix:** none required; documented so the contract↔implementation divergence is traceable. The collapsed-by-default accordion means a first-time user must expand "Token budget" to discover the threshold inputs — acceptable for an off-by-default power feature.

3. **[INFO] Banner token counts use abbreviated formatting (`1.0K`/`1.0M`), not thousands-grouped (`1,250`)** (`ChatPanel.kt:598,602` via `formatChars` at `ChatPanel.kt:1223`) — the copywriting contract's `{used}/{warn}` examples showed `1,250`-style grouping but explicitly left formatting "at the executor's discretion to match the existing usage-footer formatting." `formatChars` is exactly that existing footer formatter, so this is contract-compliant. **Fix:** none required; flagged only so a reviewer expecting grouped digits isn't surprised. At sub-1000 token counts the banner shows the raw integer, which reads fine.

---

## Detailed Findings

### Pillar 1: Copywriting (4/4)
Every string in the Copywriting Contract is present verbatim in the implemented code:

- **Anthropic card labels** — "Model" (`BackendConfigPanel.kt:507`), "API key (Bearer)" (`:508`), "Test connection" (reused builder `:527`). Match sibling cards exactly.
- **SC3 model-rejection error** — surfaced as the exact prescriptive string in `AnthropicBackend.kt` (DIVERGENCE 4, per 14-01-SUMMARY); not reworded.
- **Token-budget section** — title "Token budget" + subtitle "Optional per-session limits. 0 means unlimited (off)." (`PassiveScanConfigPanel.kt:321-322`); field labels "Warn threshold (tokens)" (`:301`) and "Hard cap (tokens)" (`:307`); help text verbatim (`:314`).
- **Chat banner** — WARN: "Token budget warning: {used} of {warn} tokens used this session." (`ChatPanel.kt:602`); RISK: "Token budget reached ({used}/{cap}). Passive scanning paused; chat is still available." (`ChatPanel.kt:598`). Both match the contract templates; tooltips on both fields (`PassiveScanConfigPanel.kt:296-297`) add helpful per-field guidance not required by the contract. English-only throughout (AGENTS.md compliant). No generic "Submit/OK/Save" or "went wrong" patterns introduced.

### Pillar 2: Visuals (4/4)
- **Anthropic card focal hierarchy** — `buildAnthropicPanel()` (`BackendConfigPanel.kt:499-512`) is byte-for-byte structurally consistent with `buildPerplexityPanel()`/`buildNvidiaNimPanel()`: same `formGrid()`, same `EmptyBorder(sectionPad×4)`, `addRowFull` rows, trailing `addSpacerRow(Spacing.sm)`. The deliberate omission of Base URL/Extra headers/Timeout rows is contract-mandated (FLAG-14-02 — fixed Anthropic endpoint, no false configurability, narrower SSRF surface).
- **No icon-only controls** — every field carries a text label via `addRowFull`; both backend fields and both budget fields also have tooltips (`BackendConfigPanel.kt:198-199`, `PassiveScanConfigPanel.kt:296-297`).
- **Banner placement** — `budgetNotice` is added at `chatContainer` `BorderLayout.NORTH` (`ChatPanel.kt:248`), above `CENTER`/`SOUTH`, so it's visible without scrolling, exactly as Touch Point 3 specifies. Single reused instance (`ChatPanel.kt:116`), not recreated per message.

### Pillar 3: Color (4/4)
Token-discipline grep across all three touch points found **zero new color literals introduced by this phase**:
- Anthropic card + token-budget section: no `Color(...)` constructors at all — `applyFieldStyle()` resolves `inputBackground`/`border` from `DesignTokens.Colors` at call time (`BackendConfigPanel.kt:160-161`, `PassiveScanConfigPanel.kt:294-295`); help label uses `DesignTokens.Colors.onSurfaceVariant` (`:316`).
- **WARN→RISK escalation is correct** — `ChatPanel.kt:594-604` maps `State.WARN → SubtleNotice.Level.WARN` (amber: `subtleWarning` bg + `accentWarn` strip) and `State.CAP → Level.RISK` (red: `subtleDanger` + `accentDanger`), exactly the Color §/FLAG-14-03 contract. `SubtleNotice` owns the palette and re-applies it on theme switch via `updateUI()` (`SubtleNotice.kt:91-98`).
- **Pre-existing literals correctly excluded from scoring:** `Color(80,80,80)` and the green/yellow/orange token-bar fills at `ChatPanel.kt:1158-1167` are the session/global usage-footer bars. `git blame` confirms these were last touched at `b93456d Release v0.6.0` (this is v0.9.0 work) — FLAG-14-04 explicitly states the usage-footer is unchanged by this phase, and the audit mandate says do not penalize pre-existing literals. Likewise the SSRF advisory bar's `EmptyBorder` at `:223` predates Phase 14 (SEC-03/A6). None deducted.

### Pillar 4: Typography (4/4)
Only the contract's declared subset is used, all via tokens:
- Row labels (`addRowFull`) and the "Test connection" label → `Typography.body` (applied by builder / `:519`,`:528`).
- API-key field content → `Typography.mono` (applied automatically by `applyFieldStyle`, matching every other key field).
- Token-budget help text → `Typography.caption` (`PassiveScanConfigPanel.kt:315`), the contract role for help/description text.
- Banner body → `UiTheme.Typography.body` set internally by `SubtleNotice` (`SubtleNotice.kt:121`).

No `Font(...)` constructors in either touched panel (grep clean). Section title weight (`sectionTitle` = BOLD 1.2×) is handled by the `AccordionPanel`/`Components` layer, not re-derived inline.

### Pillar 5: Spacing (4/4)
- **Anthropic card border** uses `DesignTokens.Spacing.sectionPad×4` (`BackendConfigPanel.kt:501-506`) — copied verbatim from `buildOpenAiCompatPanel()`/`buildPerplexityPanel()`, not a literal `8`. Trailing `addSpacerRow(panel, Spacing.sm)` (`:510`) matches every other card.
- **Token-budget grid** uses `addSpacerRow(gridF, Spacing.xs)` between rows (`PassiveScanConfigPanel.kt:304,310`), matching the established `Spacing.xs` cadence used by sections A–E in the same file. Fields fill the column via `addRowFull`'s HORIZONTAL fill — no fixed pixel width, per the contract's field-sizing note.
- **Banner padding** is `EmptyBorder(8,12,8,12)` + 3 px accent strip, owned internally by `SubtleNotice` (`SubtleNotice.kt:119`) — the phase added no extra inset around it, exactly as the contract requires.
- Grep for inline spacing integers in the two touched panels returned only the **pre-existing** SSRF-bar `EmptyBorder` (`:223`), not a Phase-14 addition. No new arbitrary spacing introduced.

### Pillar 6: Experience Design (3/4)
Strong state coverage and safety semantics; one consistency warning holds this at 3.

**What's correct (contract-faithful):**
- **Off-by-default** — `BudgetGuard.evaluate` returns `OFF` whenever both thresholds are 0 (`BudgetGuard.kt:40-45`); `SettingsPanel` coerces non-numeric/negative/empty input to 0 via `toIntOrNull()?.coerceAtLeast(0) ?: 0` (14-02-SUMMARY, T-14-10). A security tool cannot surprise-block mid-engagement.
- **Non-blocking** — both WARN and RISK only call `budgetNotice.setMessage(...)`; Send/input are never disabled, no confirmation dialog (`ChatPanel.kt:594-605`). The sole enforced effect is the passive-scanner pause (backend), as specified.
- **Reversible pause, single source of truth** — `reconcileBudget()` (`PassiveAiScanner.kt:85-94`) drives `setBudgetPaused(state == CAP)`, so the pause **releases** when usage drops below the cap rather than latching; chat and scanner share ONE evaluation (the post-summary WR-01/WR-02 hardening). `budgetPaused` is a separate `AtomicBoolean` from `enabled` — it does NOT clear `ScanKnowledgeBase` or flip the user toggle (Pitfall 3 avoided, verified by test per 14-02-SUMMARY).
- **States enumerated** — all seven rows of the contract's States table are reachable; the chat-only/test embedding path falls back to `BudgetGuard.evaluate` when no scanner is wired (`ChatPanel.kt:591-593`), so the banner still renders. EDT discipline correct (`SwingUtilities.invokeLater`, `ChatPanel.kt:579`).

**Warning (−1):**
- The token-budget section re-implements the contract's named `helpLabel(...)` builder inline (`PassiveScanConfigPanel.kt:314-317`) instead of calling it, even though `Components.kt:312` defines it with identical styling. It also uses `AccordionPanel` rather than the contract-named `sectionPanel(...)` — the latter is permitted/better under FLAG-14-01 (matches sibling sections), but combined with the collapsed-by-default state it means the threshold inputs are not visible until the user expands "Token budget." For an off-by-default feature this is acceptable, but the inline-label divergence from an available shared builder is a real (minor) consistency gap. No user task is broken — hence WARNING, not BLOCKER.

**Registry / loading / empty states:** N/A — no third-party registry (pure Kotlin/Swing), and the phase adds only inline panel regions + an event-driven banner (no async fetch, no list view, so no loading/empty states apply, per the contract's States note).

---

## Registry Safety
Skipped — `shadcn_initialized: false` in the UI-SPEC front-matter; no `components.json`; pure Kotlin + Swing with no component registry. The UI-SPEC Registry Safety table lists "None / n/a." No registry audit applicable.

---

## Files Audited
- `.planning/phases/14-anthropic-backend-token-budget-listener-port/14-UI-SPEC.md` (baseline contract)
- `.planning/phases/14-anthropic-backend-token-budget-listener-port/14-CONTEXT.md`
- `.planning/phases/14-anthropic-backend-token-budget-listener-port/14-01-SUMMARY.md`
- `.planning/phases/14-anthropic-backend-token-budget-listener-port/14-02-SUMMARY.md`
- `src/main/kotlin/com/six2dez/burp/aiagent/ui/panels/BackendConfigPanel.kt` (Touch Point 1 — Anthropic card)
- `src/main/kotlin/com/six2dez/burp/aiagent/ui/panels/PassiveScanConfigPanel.kt` (Touch Point 2 — token-budget Section F)
- `src/main/kotlin/com/six2dez/burp/aiagent/ui/ChatPanel.kt` (Touch Point 3 — budget banner, layout + formatter regions)
- `src/main/kotlin/com/six2dez/burp/aiagent/ui/components/SubtleNotice.kt` (reused banner component)
- `src/main/kotlin/com/six2dez/burp/aiagent/util/BudgetGuard.kt` (banner state source)
- `src/main/kotlin/com/six2dez/burp/aiagent/scanner/PassiveAiScanner.kt` (reconcileBudget / pause gate)
- `src/main/kotlin/com/six2dez/burp/aiagent/ui/design/DesignTokens.kt` (token reference)
- `src/main/kotlin/com/six2dez/burp/aiagent/ui/design/Components.kt` (helpLabel / sectionPanel builder existence)
