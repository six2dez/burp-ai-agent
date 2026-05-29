# Requirements: Burp AI Agent — v0.8.0 (active) + v0.7.0 (carryover)

**Defined:** 2026-05-13
**Core Value:** Bring modern AI to a real security workflow **without** leaking sensitive traffic to third-party providers.

## v0.8.0 Requirements — UI/UX Overhaul (ACTIVE milestone)

Scope = redesign the extension's Swing UI on a small shared design system, applied across the Settings area and all its tabs, with special focus on the MCP tools tab. New roadmap phases continue numbering from the previous milestone (Phase 9+).

### UI / UX

- [ ] **UI-01**: A shared design-system module (spacing / typography / color tokens + reusable Swing components — section headers, labeled fields, help text, buttons) is the single styling source for settings panels
- [ ] **UI-02**: Every Settings tab is rebuilt on the design system — consistent layout, spacing, grouping, labels, and one-line descriptions
- [ ] **UI-03**: The MCP tools tab groups tools into extension-native (AI) vs generic (Montoya) sections with clear visual hierarchy, replacing the current flat/disordered list
- [ ] **UI-04**: Each MCP tool row shows whether it ships in the store build (native) or only the full build (generic)
- [ ] **UI-05**: The MCP tools list has a live search/filter (name + description) and per-group bulk enable/disable
- [ ] **UI-06**: Settings navigation is scannable — each tab/section has a title + short description; long tabs use collapsible sections
- [ ] **UI-07**: The redesign preserves all existing functionality and settings persistence — no behaviour or config regressions (values still load/save; tests green)
- [ ] **UI-08**: The UI honours Burp's light/dark theme via tokens — no hardcoded colors that break in dark mode

---

> The **v0.7.0** (v1) and **v2** sections below are **carryover** from the previous milestone — kept open, not archived. New roadmap phases (9+) map only to the v0.8.0 UI-* requirements above.

## v1 Requirements

Scope = the next release cut, `v0.7.0`. Stabilizes the three `Unreleased` CHANGELOG features (Perplexity backend, AI-scan-on-insertion-point, custom-prompt-library UX), clears the two open bugs that gate a clean release, refreshes user-facing documentation, and ships.

### Perplexity Backend

- [ ] **PPLX-01**: User can pick **Perplexity** in Settings → Backend with URL / Model / API key / Headers / Timeout fields pre-populated to sane defaults
- [ ] **PPLX-02**: User running a prompt via Perplexity gets a successful chat completion against `https://api.perplexity.ai/chat/completions` (no `/v1` prefix) using a Sonar-family model
- [ ] **PPLX-03**: Perplexity backend silently skips the unsupported `response_format: json_object` field, even when callers (e.g. passive scanner) request JSON mode — JSON intent is preserved in the system prompt
- [ ] **PPLX-04**: Existing backends (NVIDIA NIM, Generic OpenAI-compatible) still behave identically — `OpenAiCompatibleBackend` constructor defaults are backwards-compatible
- [ ] **PPLX-05**: Saved settings from v0.6.x load unchanged — new `perplexity*` fields default safely; no `migrateIfNeeded` bump required

### AI Scan on Insertion Point

- [ ] **INSP-01**: Right-clicking a request with a text selection in the editor shows **AI Scan on Selected Insertion Point** in the context menu
- [ ] **INSP-02**: The menu item is hidden when there is no selection or the selection overlaps no candidate parameter / header / JSON field
- [ ] **INSP-03**: User selects one or more vuln classes via the existing vuln-class picker; the active scan queues one `ActiveScanTarget` per class at priority 60 (ahead of background passive queue)
- [ ] **INSP-04**: Selection resolution covers URL params, body params, cookies, header lines, and JSON/XML body field substrings (via Montoya `ParsedHttpParameter.valueOffsets()` then fallbacks)

### Custom Prompt Library UX

- [ ] **PROM-01**: User filters the Prompt Templates editor with a live, case-insensitive search across title and prompt text
- [ ] **PROM-02**: User toggles **★ Favorite** on entries; favorites pin to the top of the editor and the right-click submenus
- [ ] **PROM-03**: User exports the library to a pretty-printed `.json` file with favorites first
- [ ] **PROM-04**: User imports a `.json` library file; matching ids replace existing entries, new ids append, duplicate ids in the input are de-duplicated defensively
- [ ] **PROM-05**: Move Up / Move Down respects the favorites grouping — reorders cannot scramble the favorites/non-favorites boundary
- [ ] **PROM-06**: Right-click submenu order matches editor order (favorites first), without re-sorting at menu-build time

### Bugs Gating Release

- [ ] **BUG-01** (closes #62): Release pipeline publishes the **current tagged code**, not a stale revision — release JAR, SBOM, and SHA-256 match the source at the release commit
- [ ] **BUG-02** (closes #66): Generic OpenAI-compatible backend handles the user-reported usage error cleanly — root cause identified, surfaced with an actionable error message, fix verified against the reporter's scenario

### Release Engineering

- [ ] **REL-01**: `CHANGELOG.md`'s `[Unreleased]` section is promoted to `[0.7.0] - <release date>` with upgrade notes preserved and any new fixes folded in
- [ ] **REL-02**: Version is bumped consistently (`build.gradle.kts`, any version constants, JAR name `Custom-AI-Agent-0.7.0.jar`)
- [ ] **REL-03**: `./gradlew clean shadowJar` produces a loadable JAR on macOS, Linux, and Windows (matches existing CI matrix)
- [ ] **REL-04**: Git tag pushed; GitHub release pipeline uploads JAR + SHA-256 + CycloneDX SBOM with release notes extracted from the matching `CHANGELOG.md` section
- [ ] **REL-05**: `ktlintCheck`, `jacocoTestReport`, and the full test suite pass on the release commit across the existing OS matrix

### Documentation

- [ ] **DOC-01**: `README.md` lists Perplexity in the backend table with setup notes (default URL, sample model)
- [ ] **DOC-02**: User-facing documentation (`burp-ai-agent.six2dez.com`) covers Perplexity backend, insertion-point scanning, and the custom prompt library UX additions
- [ ] **DOC-03**: `SPEC.md` `## 4 Core features` reflects the Unreleased additions (Perplexity in 4.4, insertion-point scanning in 4.2 or §5.2, prompt library UX in 4.2)

## v2 Requirements

Deferred to a post-`v0.7.0` cycle.

### Custom MCP server (issue #41)

- **MCP-V2-01**: Users can register an additional, user-defined MCP server alongside the built-in one (read-only initially, unsafe-mode gated where applicable)

### Telemetry-free reliability signals

- **REL-V2-01**: Optional local-only structured diagnostics endpoint that users can opt into for self-debugging without sending anything offline

## Out of Scope

Explicitly excluded for `v0.7.0`. Tracked here to prevent scope creep.

| Feature | Reason |
|---------|--------|
| Hot-swapping backends at runtime | SPEC non-goal — stop + restart is acceptable; complexity does not pay back |
| Replacing Burp's native scanner | SPEC non-goal — AI scanners are complementary, secondary to Burp evidence |
| New AI backends beyond the existing 11 | v0.7.0 is a stabilization release, not a backend-expansion release |
| Rewriting UI in JavaFX / Compose | ADR-2 locked Swing in for native Burp embedding |
| Outbound telemetry / crash reporting | Violates the core privacy contract; users explicitly enable audit logging instead |
| Mobile / standalone build | Plugin only runs inside Burp; out of remit |

## Traceability

| Requirement | Phase | Status |
|-------------|-------|--------|
| PPLX-01 | Phase 1 — Perplexity Backend Audit | Pending |
| PPLX-02 | Phase 1 — Perplexity Backend Audit | Pending |
| PPLX-03 | Phase 1 — Perplexity Backend Audit | Pending |
| PPLX-04 | Phase 1 — Perplexity Backend Audit | Pending |
| PPLX-05 | Phase 1 — Perplexity Backend Audit | Pending |
| INSP-01 | Phase 2 — Insertion-Point Scan Audit | Pending |
| INSP-02 | Phase 2 — Insertion-Point Scan Audit | Pending |
| INSP-03 | Phase 2 — Insertion-Point Scan Audit | Pending |
| INSP-04 | Phase 2 — Insertion-Point Scan Audit | Pending |
| PROM-01 | Phase 3 — Prompt Library UX Audit | Pending |
| PROM-02 | Phase 3 — Prompt Library UX Audit | Pending |
| PROM-03 | Phase 3 — Prompt Library UX Audit | Pending |
| PROM-04 | Phase 3 — Prompt Library UX Audit | Pending |
| PROM-05 | Phase 3 — Prompt Library UX Audit | Pending |
| PROM-06 | Phase 3 — Prompt Library UX Audit | Pending |
| BUG-01 | Phase 4 — Release-Gating Bug Fixes | Pending |
| BUG-02 | Phase 4 — Release-Gating Bug Fixes | Pending |
| DOC-01 | Phase 5 — Documentation Refresh | Pending |
| DOC-02 | Phase 5 — Documentation Refresh | Pending |
| DOC-03 | Phase 5 — Documentation Refresh | Pending |
| REL-01 | Phase 6 — v0.7.0 Release Cut | Pending |
| REL-02 | Phase 6 — v0.7.0 Release Cut | Pending |
| REL-03 | Phase 6 — v0.7.0 Release Cut | Pending |
| REL-04 | Phase 6 — v0.7.0 Release Cut | Pending |
| REL-05 | Phase 6 — v0.7.0 Release Cut | Pending |
| UI-01 | Phase 9 — Design System Foundation | Pending |
| UI-03 | Phase 10 — MCP Tools Tab Redesign | Pending |
| UI-04 | Phase 10 — MCP Tools Tab Redesign | Pending |
| UI-05 | Phase 10 — MCP Tools Tab Redesign | Pending |
| UI-07 | Phase 10 — MCP Tools Tab Redesign (cross-cutting SC) | Pending |
| UI-02 | Phase 11 — Settings Tabs + Theme Rollout | Pending |
| UI-06 | Phase 11 — Settings Tabs + Theme Rollout | Pending |
| UI-08 | Phase 11 — Settings Tabs + Theme Rollout | Pending |

**Coverage:**
- v0.7.0 (v1) requirements: 25 total
- Mapped to phases: 25 (Phase 1: 5, Phase 2: 4, Phase 3: 6, Phase 4: 2, Phase 5: 3, Phase 6: 5)
- v0.8.0 requirements: 8 total (UI-01..UI-08)
- Mapped to phases: 8 (Phase 9: 1, Phase 10: 4 incl. UI-07 cross-cutting, Phase 11: 3+UI-07 cross-cutting)
- Unmapped: 0

---
*Requirements defined: 2026-05-13*
*Last updated: 2026-05-29 — v0.8.0 UI-01..UI-08 mapped to Phases 9-11 (gsd-roadmapper)*
