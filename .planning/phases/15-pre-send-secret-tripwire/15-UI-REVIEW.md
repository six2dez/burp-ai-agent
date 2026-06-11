# Phase 15 — UI Review

**Audited:** 2026-06-11
**Baseline:** 15-UI-SPEC.md (approved) — minimal delta extending 13-UI-SPEC.md / Phase 9 design system
**Screenshots:** Not captured — Kotlin + Swing extension (ADR-2: plain Swing, no web/browser); no dev server or render target exists. Audit is code-only against the implemented Swing source. (Port 8080 returned 200 but no `package.json`/`components.json` exists — that listener is unrelated to this extension's UI.)

**Scope discipline:** The entire UI delta is ONE touch point — `ui/components/ContextPreviewDialog.kt`. Detector (`SecretTripwire`), scanner/MCP hooks, and audit emit are AWT-free backend and out of UI scope per the spec. Audit kept proportional to the delta.

---

## Pillar Scores

| Pillar | Score | Key Finding |
|--------|-------|-------------|
| 1. Copywriting | 3/4 | Both shipped strings are verbatim-correct; the spec's plural "{N} values…" banner variant was collapsed to the singular phrasing (permitted by FLAG-15-01, minor informativeness loss) |
| 2. Visuals | 4/4 | RISK red banner is a real, higher-severity focal point above the body; affirmative relabel makes "proceed past a secret" explicit — no icon-only/unlabeled controls |
| 3. Color | 4/4 | Zero new `Color()`/`Font()`/hex literals; RISK maps to inherited `subtleDanger`/`accentDanger`, the level Phase 13 pre-reserved (FLAG-13-03) and already active in 5+ components |
| 4. Typography | 4/4 | No font derivation added in the dialog; banner body inherits `Typography.body` from `SubtleNotice` |
| 5. Spacing | 4/4 | The one new strut uses the token `DesignTokens.Spacing.sm` (not a literal); pre-existing raw literals are out-of-scope FLAG-13-02/FLAG-15-04 and correctly left un-migrated |
| 6. Experience Design | 4/4 | Warn-with-confirmation gate, never a hard-block; Cancel is default focus via `options[1]` initialValue; banner names category only, never the raw token |

**Overall: 23/24**

---

## Top 3 Priority Fixes

All findings are WARNING-class or below — there are no BLOCKERs. This is a clean, spec-faithful minimal delta.

1. **[WARNING] Plural-match banner copy collapsed to singular phrasing** — `ContextPreviewDialog.kt:72` always renders "A value matching a known secret shape ({shapes})…" even when multiple distinct categories survived. The spec offers a dedicated "{N} values that may be secrets survived redaction ({shapes})." variant for the mixed/multiple case (15-UI-SPEC § Delta 1 banner copy table, row 3). Impact: when several shapes are flagged the banner under-communicates count and reads slightly off grammatically ("A value matching a known secret shape (AWS access key, JWT)"). **Fix (optional):** branch on `scan.shapeCategories.size > 1` to emit the "{N} values…" variant. Explicitly permitted to skip per FLAG-15-01 (two-state collapse) — accept-as-is is a valid product call.

2. **[WARNING] Advisory (WARN/amber) state intentionally dropped — confirm this is desired long-term** — `ContextPreviewDialog.kt:63-77` is two-state (clean → RISK); the Phase 13 amber "survived shape but not gating" advisory no longer renders in this dialog. This is sanctioned by FLAG-15-01 and SUMMARY decision `[15-02]`, so it is **not** a defect. Impact: every surviving-shape signal now reads as RISK-red with a confirmation gate; if a future phase reintroduces a non-gating advisory tier, the three-state table must be restored. **Fix:** none required now — flagged only so the collapse is a tracked, deliberate decision rather than silent drift.

3. **[INFO] Pre-existing dialog literals remain un-migrated (carried FLAG-13-02 / FLAG-15-04)** — `BorderLayout(8, 8)` (L25), `Dimension(780, 560)` (L26), `Dimension(740, …)` (L48/L90), `Box.createVerticalStrut(6)` (L36/L51) are raw literals, not `DesignTokens`. Per the spec these are explicitly **out of scope** for Phase 15 and must NOT be penalized. Impact: none for this phase. **Fix:** none now — future UI-debt candidate to migrate the host dialog to `DesignTokens.Spacing`/sizing tokens.

---

## Detailed Findings

### Pillar 1: Copywriting (3/4)

Verified the two shipped strings against the spec's Copywriting Contract — both are verbatim:

- `ContextPreviewDialog.kt:69` — "A high-entropy value that may be a secret survived redaction. Review before sending." → exact match to 15-UI-SPEC § Delta 1, entropy-only row.
- `ContextPreviewDialog.kt:72` — "A value matching a known secret shape ($shapes) survived redaction. Review before sending." → exact match to the named-shape row.
- Affirmative label "Send anyway" is sourced from `gate.affirmativeLabel` (`SecretTripwire.gateDecision`, `SecretTripwire.kt:77`), which returns "Send anyway" on match and "Send" on the clean path — exactly the conditional CTA the spec requires. `Cancel` and title "Review context before sending to AI" are unchanged, as mandated.
- Sentence case, English-only (AGENTS.md): compliant.

**Gap (−1):** The spec's third banner variant — "{N} values that may be secrets survived redaction ({shapes})." for the mixed/multiple case — is not implemented; multi-category matches fall through to the singular line 72 phrasing. FLAG-15-01 permits this two-state collapse, so it is a quality/informativeness gap, not a contract violation. Score held at 3 rather than 4 to record that one of three specified copy variants is absent.

### Pillar 2: Visuals (4/4)

- Clear focal point: on a tripwire hit the RISK (red `subtleDanger` bg + `accentDanger` left strip) banner sits between the "Context (as will be sent…)" label and `bodyScroll` (`ContextPreviewDialog.kt:78-79`), drawing the eye before the user reaches the affirmative button.
- Severity hierarchy: RISK red is correctly higher-severity than the Phase 13 amber advisory it supersedes, matching the spec's rationale (the signal now *gates* the send).
- No icon-only/unlabeled controls — both actions are text buttons ("Send anyway" / "Cancel").
- Clean-path visual is byte-for-byte unchanged (`hideNotice()` at L76), satisfying "dialog visually identical to today" when nothing is flagged.

### Pillar 3: Color (4/4)

- `grep` for `Color(` / `Font(` / `0x…` / `Color.[A-Z]` in `ContextPreviewDialog.kt`: **zero hits**. Light/Dark rule 1 (no new literals) fully satisfied.
- RISK palette is inherited, not redefined: `SubtleNotice.kt:105` (`Level.RISK -> UiTheme.Colors.subtleDanger`) and `:111` (`-> UiTheme.Colors.accentDanger`). The dialog only selects the level; it adds no color.
- RISK was already an active level pre-Phase-15 — present in `SettingsPanel`, `ChatPanel`, `SafetyIndicator`, `MainTab`, `SubtleNotice` — so this introduces no new visual, exactly as Phase 13 reserved via FLAG-13-03.
- Theme-correctness is free: `SubtleNotice.updateUI()` re-applies the palette on a Burp theme switch (`SubtleNotice.kt:91-98`).

### Pillar 4: Typography (4/4)

- No `Typography`/`.font` reference is added in `ContextPreviewDialog.kt` (grep clean). The banner body font is owned by `SubtleNotice.applyStyle()` → `body.font = UiTheme.Typography.body` (`SubtleNotice.kt:121`). No new size/weight/derivation introduced. Fully inherited per spec § Typography.

### Pillar 5: Spacing (4/4)

- The single new vertical strut above the banner uses the token: `header.add(Box.createVerticalStrut(DesignTokens.Spacing.sm))` (`ContextPreviewDialog.kt:78`) — token-driven, not a literal. This matches the spec's "the existing `Spacing.sm` (8px) strut above the banner is unchanged."
- Pre-existing raw literals (`BorderLayout(8,8)`, `Dimension(780,560)`, `Dimension(740,…)`, `createVerticalStrut(6)`) are the documented un-migrated host-dialog literals (FLAG-13-02 / FLAG-15-04). Spec explicitly forbids migrating them this phase; correctly left untouched. Not penalized.

### Pillar 6: Experience Design (4/4)

- **Warn-with-confirmation, never a hard-block:** the gate is a single `JOptionPane.showOptionDialog` (`ContextPreviewDialog.kt:101`) with both `Send anyway` and `Cancel` always present (`options = arrayOf(gate.affirmativeLabel, "Cancel")`, L99). A legitimate base64 fuzz payload is dismissible-to-proceed (SC2) — no silent block path exists.
- **Affirmative is never the default focus:** `initialValue = options[1]` (Cancel) at L109, regardless of tripwire state (G5 / Pitfall 5). Verified.
- **No raw-secret re-exposure:** the banner interpolates only `scan.shapeCategories` (`ContextPreviewDialog.kt:65`), which `SecretTripwire` guarantees carries category names only — "The raw matched token is NEVER a field and NEVER interpolated into any result or log" (`SecretTripwire.kt:17-19`). Banner names the CATEGORY, never the value (PRIV-03 discipline).
- **Boolean contract preserved:** `confirm()` still returns `Boolean` (`return choice == 0`, L115); single caller `ChatPanel.kt:299` unchanged. The `secret_tripwire_allow` audit emit is correctly placed at the ChatPanel call site after `createSession` (carries a real session id, avoids double-logging) — out of UI scope but verified consistent with SUMMARY decision `[15-02]`.
- No loading/empty state needed — inline change to a dialog shown only at send time (spec § States confirms n/a).

---

## Registry Safety

Not applicable. No `components.json` and no `package.json` — pure Kotlin/Swing (ADR-2), no shadcn or third-party component registry. 15-UI-SPEC § Registry Safety confirms "None — n/a". Registry audit skipped per the gate condition.

---

## Files Audited

- `src/main/kotlin/com/six2dez/burp/aiagent/ui/components/ContextPreviewDialog.kt` (the sole UI touch point — full read + line-level audit)
- `src/main/kotlin/com/six2dez/burp/aiagent/ui/components/SubtleNotice.kt` (RISK level palette + font inheritance — confirmed no new literal)
- `src/main/kotlin/com/six2dez/burp/aiagent/redact/SecretTripwire.kt` (gate contract `affirmativeLabel`/`gateDecision`/`shapeCategories` no-leak — backend, referenced for category-only verification)
- Cross-ref grep: RISK usage across `src/main/kotlin` (SettingsPanel, ChatPanel, SafetyIndicator, MainTab) to confirm no new visual introduced

**Baselines:** `15-UI-SPEC.md`, `15-CONTEXT.md`, `15-02-SUMMARY.md`
