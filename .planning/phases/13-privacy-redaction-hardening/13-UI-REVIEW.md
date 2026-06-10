# Phase 13 — UI Review

**Audited:** 2026-06-10
**Baseline:** `13-UI-SPEC.md` (approved design contract) + Phase 9 design system (`ui/design/DesignTokens.kt` + `Components.kt`)
**Screenshots:** not captured — Kotlin + Swing extension, no web frontend exists (ADR-2). Code-only audit. (A service answered on `:8080`, but it is unrelated to this repo — no `package.json`, no `.tsx/.jsx`, no Vite config present; nothing to screenshot.)
**Scope:** the two additive Swing touch points only. Pre-existing un-migrated `ContextPreviewDialog` literals are out of scope per FLAG-13-02 and are not penalized.

---

## Pillar Scores

| Pillar | Score | Key Finding |
|--------|-------|-------------|
| 1. Copywriting | 3/4 | All contract strings present; rejected-validation copy was silently extended ("matches empty string") beyond the contracted string. |
| 2. Visuals | 4/4 | WARN banner sits above the body scroll, visible without scrolling; category-only messaging; correct visual severity (amber, not red). |
| 3. Color | 4/4 | Zero new color literals in phase code. All semantic tokens (`statusError`/`statusSuccess`, `SubtleNotice` WARN palette) resolved dynamically. |
| 4. Typography | 4/4 | Only `caption` (feedback), `mono` (text area via `applyAreaStyle`), and `SubtleNotice` `body` used. No `Font(...)` constructor in phase code. |
| 5. Spacing | 3/4 | Panel uses `Spacing.sm`/`Spacing.xs` correctly, BUT the banner gap added a NEW `Box.createVerticalStrut(6)` literal instead of `DesignTokens.Spacing.sm` (contract said `Spacing.sm`). |
| 6. Experience Design | 4/4 | Non-blocking advisory honored (Send/Cancel unchanged); hidden-when-clean; save-time ReDoS validation with inline error feedback; theme-switch-safe foreground re-read. |

**Overall: 22/24**

---

## Top 3 Priority Fixes

1. **New raw spacing literal `Box.createVerticalStrut(6)` introduced above the banner** (WARNING, Spacing) — `ContextPreviewDialog.kt:72`, added by this phase (commit `b961628`). The UI-SPEC Spacing/Color sections specified the gap between the header rows and the survived-secret banner as `Spacing.sm` (8 px), and Light/Dark rule 3 forbids inline spacing integers in code added by this phase. The plan permitted *reusing* the dialog's existing struts but explicitly said "do NOT introduce NEW literals" — a fresh `createVerticalStrut(6)` is a new literal. *Impact:* a 6 px gap that drifts from the 8 px contract value and re-embeds a magic number into an un-migrated dialog, eroding the token discipline the phase otherwise upholds. *Fix:* replace `Box.createVerticalStrut(6)` on line 72 with `Box.createVerticalStrut(DesignTokens.Spacing.sm)` (import `DesignTokens`), adding the banner gap via the contracted token. If the surrounding struts must remain `6` to stay visually consistent in the un-migrated dialog, document that explicitly as an intentional FLAG-13-02 carve-out for the banner's leading strut.

2. **Rejected-validation copy diverges from the contracted string** (WARNING, Copywriting) — `SettingsPanel.kt:1237` and `:1239`. The contract (Copywriting table) specifies `"Pattern rejected: invalid regex or too slow (ReDoS guard). Fix it and save again."` and the multiple-form equivalent. The implementation reads `"Pattern rejected: invalid regex, matches empty string, or too slow (ReDoS guard). Fix it and save again."` *Impact:* the executor added an accurate clause (the validator does reject empty-match patterns), but it is an undocumented deviation from the approved copy contract — the kind of drift the contract exists to prevent. *Fix:* either (a) update the UI-SPEC Copywriting table to ratify the "matches empty string" clause as the canonical copy, or (b) revert the two strings to the contracted wording. Ratifying (a) is preferred since the clause is truthful and improves the problem-then-next-step guidance.

3. **Validation feedback persists across reopen with no auto-clear timer** (WARNING, Experience Design) — `SettingsPanel.kt:1241-1248`. On success the label is set visible with "Custom patterns saved." and stays visible until the next `applySettingsToUi` reload hides it (`:1316`). Unlike the sibling `updateSaveFeedback` path (`:975`, `:1000`), which uses a `resetMs` auto-reset, the patterns-feedback label has no timed clear. The contract says success "briefly shows the success copy ... or stays hidden — both acceptable," so this is contract-compliant, but it is a parity gap with the established `saveFeedback` convention the contract told it to mirror. *Impact:* a stale green "saved" confirmation can linger on the panel after the action is long past, which reads as less polished than the adjacent save-feedback label. *Fix:* route the patterns feedback through the same `updateSaveFeedback`-style timed reset (e.g. 3000 ms) for parity, or accept as-is and note the intentional difference.

---

## Detailed Findings

### Pillar 1: Copywriting (3/4)

Contract strings audited against `SettingsPanel.kt` and `ContextPreviewDialog.kt`:

- **Row label** — `PrivacyConfigPanel.kt:56` `"Custom redaction patterns"` — exact match to contract. PASS.
- **Help text** — `PrivacyConfigPanel.kt:57` `"One regex per line. Applied in STRICT and BALANCED. Validated on Save."` — exact match (70 chars, ≤100). PASS.
- **Validation success** — `SettingsPanel.kt:1245` `"Custom patterns saved."` — exact match. PASS.
- **Survived-secret banner (single)** — `ContextPreviewDialog.kt:64` `"A value matching a known secret shape ($shapes) survived redaction. Review before sending."` — exact match to contract. PASS.
- **Survived-secret banner (multiple)** — `ContextPreviewDialog.kt:66` `"$n values matching known secret shapes ($shapes) survived redaction. Review before sending."` — exact match. PASS.
- **Send / Cancel** — `ContextPreviewDialog.kt:90` `arrayOf("Send", "Cancel")` — unchanged as contracted. PASS.
- **DEVIATION — validation-rejected copy** — `SettingsPanel.kt:1237`/`1239`: the implemented strings insert `", matches empty string,"` / `", match empty string,"` not present in the contracted strings. Sentence case and problem-then-next-step structure are preserved, English-only (AGENTS.md) satisfied. Accurate but un-ratified — see Priority Fix 2.

Generic-label scan (`Submit`/`OK`/`Click Here`) over the touched files: none in phase-added strings. The only `OK`-adjacent control is the pre-existing `JOptionPane` Send/Cancel pairing, which is correct.

Score 3/4: one specific, un-ratified copy deviation from the approved contract on the error path; everything else is an exact match.

### Pillar 2: Visuals (4/4)

- **Focal point / placement** — `ContextPreviewDialog.kt:72-73`: the banner is added to the `header` `BoxLayout(Y_AXIS)` stack *after* the "Context (as will be sent, after redaction):" label and *before* `bodyScroll` is placed in `BorderLayout.CENTER` (`:88`). This satisfies the contract requirement that it be "visible without scrolling, since its purpose is to warn before the user clicks Send." PASS.
- **Severity legibility** — `SubtleNotice.applyStyle()` (`SubtleNotice.kt:100-120`) renders WARN as `subtleWarning` background + `accentWarn` 3 px left accent strip. Amber advisory, correctly distinct from RISK (red). Matches the contract's WARN-not-RISK rationale and FLAG-13-03. PASS.
- **No raw-secret exposure** — the banner interpolates `survivors.joinToString(", ")` (category names only); the diff confirms no matched substring is echoed (T-13-10). Good visual-security hygiene. PASS.
- **Validation-feedback hierarchy** — `SettingsPanel.kt:206-210`: the feedback label uses `caption` (smaller than the body-weight row label), giving correct secondary hierarchy under the field; color-coded by outcome. PASS.

No icon-only controls introduced; no hierarchy regressions. Score 4/4.

### Pillar 3: Color (4/4)

Literal audit of phase-touched code:

```
grep -nE "Color\(|Font\(|Dimension\(" PrivacyConfigPanel.kt ContextPreviewDialog.kt
```

- `PrivacyConfigPanel.kt`: **zero** matches — no color/font/dimension literals.
- `ContextPreviewDialog.kt`: the only `Dimension(...)` hits (lines 25, 47, 84) are the **pre-existing** un-migrated scaffold (`780×560`, `740×90`, `740×340`), explicitly excluded by FLAG-13-02. The phase diff (commit `b961628`) added **no** `Color(`/`Font(`/`Dimension(` literal. PASS.
- **Semantic tokens** — validation label uses `DesignTokens.Colors.statusError` (`:1242`) / `statusSuccess` (`:1246`), both re-read on each set per Light/Dark rule 4. Banner inherits `UiTheme.Colors.subtleWarning` + `accentWarn` via `SubtleNotice`. All verified to exist (`DesignTokens.kt:179/183`, `UiTheme.kt:69/71`) and resolve via computed `get` properties (theme-dynamic). PASS.
- **60/30/10** — unchanged: `surface` dominant, `inputBackground`+`border` on the one new field, accent limited to the L&F focus ring + the single WARN strip. No accent overuse. PASS.

Score 4/4: the phase introduced no new color decisions outside the two contracted semantic tokens, and added zero hardcoded colors.

### Pillar 4: Typography (4/4)

- **Text area** — `SettingsPanel.kt:202-205` constructs the `JTextArea` and calls `applyAreaStyle(it)`, which sets `Typography.mono` (`Components.kt:468`). Regex-as-code rendered in mono — matches contract. PASS.
- **Feedback label** — `SettingsPanel.kt:208` sets `font = DesignTokens.Typography.caption`. Matches contract (caption for inline validation feedback). PASS.
- **Help line** — rendered via `addRowFull(..., helpText=...)` → `helpLabel()` → `Typography.caption` (`Components.kt:312-315`). PASS.
- **Row label** — `addRowFull` applies `Typography.body` (`Components.kt:128`). PASS.
- **Banner body** — `SubtleNotice.applyStyle()` sets `body.font = UiTheme.Typography.body` (`SubtleNotice.kt:121`). PASS.

Distinct roles in phase code: `body`, `caption`, `mono` (+ inherited `sectionTitle` on the unchanged section header) — within the contracted subset; no `Font(...)` constructor added by the phase. Score 4/4.

### Pillar 5: Spacing (3/4)

- **PrivacyConfigPanel** — `:62` `addSpacerRow(grid, DesignTokens.Spacing.xs)` and `:75` `EmptyBorder(DesignTokens.Spacing.sm, 0, 0, 0)`. Both use tokens, matching the contract's Spacing table (xs spacer, sm top inset). The trailing `0, 0, 0` args are structural (no top/side offset), not magic spacing values. PASS.
- **Text-area sizing** — `JTextArea(..., 4, 20)` → `rows=4` matches the contracted convention; width fills the field column via `addRowFull` HORIZONTAL (a `JTextArea` is not a "small component" per `isSmallComponent`). No fixed pixel width. PASS.
- **Banner internal padding** — handled inside `SubtleNotice` (`EmptyBorder(8,12,8,12)` + 3 px strip, `SubtleNotice.kt:119`); the phase correctly did NOT wrap extra insets around it. PASS.
- **DEVIATION — new `createVerticalStrut(6)` literal** — `ContextPreviewDialog.kt:72`. git blame confirms this line was *added* by phase commit `b961628`, not pre-existing. The contract's Spacing and Color sections both specify the header-to-banner gap as `Spacing.sm` (8 px), and Light/Dark rule 3 prohibits inline spacing integers in phase-added code. The plan's own action text is internally contradictory ("optionally ... matching the existing 6 px struts" vs "do NOT introduce NEW literals"); the executor resolved it toward visual consistency with the un-migrated dialog rather than the token contract. See Priority Fix 1.

Score 3/4: a single, real, phase-introduced spacing literal that deviates from the contract's stated `Spacing.sm` value; all other spacing is token-correct.

### Pillar 6: Experience Design (4/4)

State coverage against the contract's States table:

- **Custom patterns — empty / not validated** — `SettingsPanel.kt:1218-1221`: empty area → label hidden, returns `emptyList()`. PASS.
- **Custom patterns — saved valid** — `:1244-1248`: valid lines persisted; success copy shown in `statusSuccess`. PASS (see Priority Fix 3 re: no auto-clear timer — contract-permitted, parity gap only).
- **Custom patterns — one or more rejected** — `:1223-1243`: offending lines dropped (FLAG-13-04 preferred behavior), valid lines kept, error copy in `statusError`. Save-time validation runs `SafeRegex.isPatternSafe` (compile + ~50 ms ReDoS probe) per line. PASS.
- **Survived secret — none** — `ContextPreviewDialog.kt:70` `hideNotice()` — banner hidden, dialog unchanged. PASS.
- **Survived secret — one or more** — `:68` `setMessage(Level.WARN, ...)` — banner shown, Send still enabled (`:90-101` unchanged). PASS.
- **Non-blocking guarantee** — `confirm(...)` signature and `Send`/`Cancel` return semantics unchanged; the banner never disables Send and adds no confirmation step (Phase 15 territory). PASS.
- **Theme-switch resilience** — feedback label foreground re-read from tokens on every set (`:1242`/`:1246`); `SubtleNotice` re-applies its palette via `updateUI()` (`SubtleNotice.kt:91-98`). PASS.
- **Live application without restart** — `Redaction.setCustomPatterns(updated.customRedactionPatterns)` wired into `applyAndSaveSettings` (`:1471`). PASS.

No loading/empty-data states apply (both touch points are inline additions). No destructive actions introduced; correctly no confirmation dialog. Score 4/4.

---

## Registry Safety

shadcn **not initialized** (`components.json` absent) and the project is pure Kotlin/Swing with no third-party component registry (UI-SPEC Registry Safety: "not applicable"). Registry audit skipped per the auditor contract — no Registry Safety findings.

---

## Files Audited

- `src/main/kotlin/com/six2dez/burp/aiagent/ui/panels/PrivacyConfigPanel.kt` (custom-pattern row wiring)
- `src/main/kotlin/com/six2dez/burp/aiagent/ui/components/ContextPreviewDialog.kt` (survived-secret WARN banner)
- `src/main/kotlin/com/six2dez/burp/aiagent/ui/components/SubtleNotice.kt` (reused advisory component — pre-existing, palette verification)
- `src/main/kotlin/com/six2dez/burp/aiagent/ui/SettingsPanel.kt` (text-area + feedback-label construction, save-time validation, `Redaction.setCustomPatterns` wiring)
- `src/main/kotlin/com/six2dez/burp/aiagent/ui/design/Components.kt` (builder token compliance — `addRowFull`, `applyAreaStyle`, `helpLabel`)
- `src/main/kotlin/com/six2dez/burp/aiagent/ui/design/DesignTokens.kt` (token existence: `Typography`, `Colors.statusError/statusSuccess`)
- `src/main/kotlin/com/six2dez/burp/aiagent/ui/UiTheme.kt` (`SubtleNotice` WARN palette: `subtleWarning`, `accentWarn`)
- Baselines: `13-UI-SPEC.md`, `13-CONTEXT.md`, `13-02-PLAN.md`, `13-03-PLAN.md`, `13-01/02/03-SUMMARY.md`
