# Roadmap: Burp AI Agent — v0.7.0 (carryover) + v0.8.0 (active)

## Overview

Stabilization milestone for the three `Unreleased` features (Perplexity backend, AI scan on selected insertion point, custom prompt library UX), the two open bugs gating release (#62 release pipeline, #66 openai-compatible usage error), the user-facing documentation refresh, and the v0.7.0 release cut itself. The three feature-audit phases (1, 2, 3) are independent and parallel-safe. The release phase (6) is a choke point that depends on every earlier phase being green.

**v0.8.0 phases (9-11)** begin after the carryover milestone. They redesign the extension's Swing UI on a shared design-system foundation, applied across the MCP tools tab and all Settings tabs, with light/dark theme consistency via tokens.

## Phases

**Phase Numbering:**

- Integer phases (1, 2, 3): Planned milestone work
- Decimal phases (2.1, 2.2): Urgent insertions (marked with INSERTED)

Decimal phases appear between their surrounding integers in numeric order.

- [ ] **Phase 1: Perplexity Backend Audit** - Verify shipped Perplexity backend meets SPEC, lock behaviour with tests
- [x] **Phase 2: Insertion-Point Scan Audit** - Verify right-click insertion-point scanning + selection resolution, lock with tests (completed 2026-05-13)
- [x] **Phase 3: Prompt Library UX Audit** - Verify search / favorites / import-export / ordering, lock with tests (completed 2026-05-13)
- [ ] **Phase 4: Release-Gating Bug Fixes** - Close #62 (release pipeline publishes stale code) and #66 (openai-compatible usage error)
- [ ] **Phase 5: Documentation Refresh** - README, `burp-ai-agent.six2dez.com`, and `SPEC.md` reflect the three Unreleased features
- [ ] **Phase 6: v0.7.0 Release Cut** - Promote CHANGELOG, bump version, build, tag, publish JAR + SBOM + SHA-256, CI green on matrix
- [x] **Phase 7: Proxy Transport + MCP Scope Hardening** - Close #69: route all AI-backend HTTP via Montoya, small-model context defaults, MCP in-scope-only enforcement (completed 2026-05-27)
- [ ] **Phase 8: BApp Store resubmission — MCP pivot + compliance** - Close #231 review: store-build MCP exposes only extension-native AI tools (generic Montoya tools gated to a GitHub full build), gate all AI calls on `ai.isEnabled()`, migrate passive scan to `PassiveScanCheck.doCheck()`, confirm name
- [x] **Phase 9: Design System Foundation** - Shared spacing/typography/color tokens + reusable Swing components as the single styling source for all settings panels (completed 2026-05-29)
- [ ] **Phase 10: MCP Tools Tab Redesign** - Group tools into native (AI) vs generic (Montoya) sections, show store/full-build indicators, add live search/filter + per-group bulk toggle
- [ ] **Phase 11: Settings Tabs + Theme Rollout** - Rebuild every Settings tab on the design system with scannable navigation, collapsible sections, and light/dark theme token support

## Phase Details

### Phase 1: Perplexity Backend Audit

**Goal**: Perplexity backend shipped in `Unreleased` is verified against SPEC and locked with tests so regressions cannot ship in v0.7.0.
**Depends on**: Nothing (parallel-safe with Phase 2 and Phase 3)
**Requirements**: PPLX-01, PPLX-02, PPLX-03, PPLX-04, PPLX-05
**Success Criteria** (what must be TRUE):

  1. User can select **Perplexity** in Settings -> Backend and the URL / Model / API key / Headers / Timeout fields are pre-populated to documented defaults (`https://api.perplexity.ai/chat/completions`, Sonar-family model).
  2. A unit test asserts that `OpenAiCompatibleBackend` configured for Perplexity targets `chat/completions` with no `/v1` prefix and omits `response_format: json_object` even when callers set `jsonMode = true`; the JSON intent is still expressed in the system prompt.
  3. A unit test asserts the existing NVIDIA NIM and Generic OpenAI-compatible backends retain their pre-Perplexity behaviour (constructor defaults are backwards-compatible: `chatCompletionsBasePath = "/v1/chat/completions"`, `supportsJsonObjectResponseFormat = true`).
  4. A unit test asserts `AgentSettings` saved by v0.6.1 deserialises in v0.7.0 with the five new `perplexity*` fields defaulting safely and **no** `migrateIfNeeded` schema bump.
  5. Running a real prompt through the Perplexity backend with a valid API key returns a streamed chat completion end-to-end (manual or integration-test confirmation).

**Plans**: 1 plan
Plans:

- [x] 01-01-PLAN.md — Add MockWebServer dep + write 2 new wire-level test classes (Perplexity + OpenAI defaults) + extend AgentSettingsMigrationTest with PPLX-05 + record D-06 manual smoke and D-08 wording-gap handoffs in 01-VERIFICATION.md

### Phase 2: Insertion-Point Scan Audit

**Goal**: The right-click "AI Scan on Selected Insertion Point" action correctly resolves the selection across all Burp parameter shapes, queues active scan targets at the right priority, and hides itself when there is no valid candidate.
**Depends on**: Nothing (parallel-safe with Phase 1 and Phase 3)
**Requirements**: INSP-01, INSP-02, INSP-03, INSP-04
**Success Criteria** (what must be TRUE):

  1. Right-clicking a request in Proxy / Repeater with a text selection that overlaps a URL/body/cookie parameter, a header line, or a JSON/XML body field shows **AI Scan on Selected Insertion Point** in the context menu.
  2. The menu item is hidden when the selection is empty or overlaps no candidate parameter / header / JSON field (verified by both a unit test on the resolver and a manual smoke check).
  3. Selecting one or more vuln classes via the existing picker queues exactly one `ActiveScanTarget` per class at priority 60 — ahead of the background passive queue — verified by a unit test against the active-scanner queue.
  4. Selection resolution covers (a) URL parameters via `ParsedHttpParameter.valueOffsets()`, (b) body parameters, (c) cookies, (d) header lines, and (e) JSON/XML body field substring matches, each covered by a unit test.

**Plans**: 3 plans
Plans:

- [x] 02-01-PLAN.md — Add 5 resolver sub-case @Test methods to InjectionPointExtractorTest.kt (BODY_PARAM, COOKIE, XML_ELEMENT, PATH_SEGMENT, non-empty headerAllowlist) — locks INSP-04 + INSP-02 boundary
- [x] 02-02-PLAN.md — Add 4 queue-contract @Test methods to ActiveScannerQueueModelTest.kt (one-per-class + dedup-bypass, out-of-scope short-circuit, PASSIVE_ONLY filter, queue-full short count) — locks INSP-03 + threats T-2-01/T-2-02
- [x] 02-03-PLAN.md — Create 02-HUMAN-UAT.md scaffolding with 6 maintainer-fillable scenarios — locks INSP-01 + INSP-02 UI-builder branches per D-08/D-09

**UI hint**: yes

### Phase 3: Prompt Library UX Audit

**Goal**: The Settings -> Prompt Templates editor and right-click submenus correctly implement search, favorites, JSON import/export, and ordering invariants so users cannot get into a corrupted or surprising state.
**Depends on**: Nothing (parallel-safe with Phase 1 and Phase 2)
**Requirements**: PROM-01, PROM-02, PROM-03, PROM-04, PROM-05, PROM-06
**Success Criteria** (what must be TRUE):

  1. The editor's live search filter matches case-insensitively across title and prompt text and updates the visible row set on every keystroke (covered by a unit test on the filter logic).
  2. Toggling `★ Favorite` pins an entry to the top of the editor table and to the right-click submenus, and the `isFavorite` field round-trips through save -> reload and export -> import (unit-tested).
  3. Export writes a pretty-printed `.json` file with favorites first; import merges by id (matching ids replace, new ids append) and de-duplicates duplicate ids in the input file defensively. A unit test feeds a hand-crafted JSON with duplicate ids and verifies the post-import library is well-formed.
  4. Move Up / Move Down cannot scramble the favorites / non-favorites boundary — a reorder attempt that would cross the boundary is rejected or clamped, locked by a unit test.
  5. Right-click submenus iterate entries in editor order (favorites first) with no re-sort at menu-build time — verified by a unit test on `filterForMenu`.

**Plans**: 3 plans
Plans:

- [x] 03-01-PLAN.md — Add filterForMenuPreservesExternalFavoritesFirstOrder @Test to CustomPromptFilterTest.kt — locks PROM-06 favorites-first ordering invariant (Wave 1)
- [x] 03-02-PLAN.md — Extract parseLibraryJson + mergeById + applyMove into CustomPromptDefinition.Companion, wire handleImport/handleExport/handleMove as thin shells, add 10 @Test methods in new CustomPromptLibraryJsonTest.kt — locks PROM-03/04/05 + fixes distinctBy → associateBy behaviour (Wave 1)
- [x] 03-03-PLAN.md — Create 03-HUMAN-UAT.md with 4 maintainer-fillable scenarios — locks PROM-01/02/03/04/05 Swing-layer verification (Wave 2)

**UI hint**: yes

### Phase 4: Release-Gating Bug Fixes

**Goal**: The two GitHub issues that block a clean release are resolved with regression coverage: #62 (release pipeline publishes stale code) and #66 (openai-compatible backend usage error).
**Depends on**: Nothing (can run in parallel with Phases 1-3, but its outcome must be merged before Phase 6)
**Requirements**: BUG-01, BUG-02
**Success Criteria** (what must be TRUE):

  1. A dry-run of the release workflow on a tagged commit produces a JAR whose SHA-256 matches the source tree at the tagged commit (verified by re-running `./gradlew shadowJar` locally on that commit and comparing checksums) — closes #62.
  2. The Generic OpenAI-compatible backend, when triggered by the user-reported scenario in #66, either succeeds or surfaces an actionable error message that identifies the upstream cause (HTTP status, body snippet, suggested remediation) — verified by a unit test that exercises the failure path.
  3. The root cause of #66 is documented in the PR description (and folded into `CHANGELOG.md [Unreleased]`'s `Fixed` section) so reviewers and downstream users understand the fix.

**Plans**: TBD

### Phase 5: Documentation Refresh

**Goal**: User-facing documentation (README, `burp-ai-agent.six2dez.com`, `SPEC.md`) reflects the Perplexity backend, insertion-point scanning, and prompt library UX additions so v0.7.0 ships with no doc drift.
**Depends on**: Phases 1, 2, 3 (behaviour must be locked before documenting it)
**Requirements**: DOC-01, DOC-02, DOC-03
**Success Criteria** (what must be TRUE):

  1. `README.md`'s backend table lists Perplexity alongside the existing 10 backends with the default URL (`https://api.perplexity.ai/chat/completions`), a sample Sonar model id, and a note that no `/v1` prefix is used.
  2. The public docs site (`burp-ai-agent.six2dez.com`) has a dedicated Perplexity page, an "AI Scan on Selected Insertion Point" walkthrough, and a section under the Prompt Library page covering search / favorites / import-export — all linked from the appropriate index pages.
  3. `SPEC.md` section 4 (Core features) is updated: 4.4 lists Perplexity as a supported HTTP backend; 5.2 (or 4.2) documents the insertion-point scanning entry point; 4.2 documents the prompt library UX additions. No other SPEC sections drift.

**Plans**: TBD

### Phase 7: Proxy Transport + MCP Scope Hardening

**Goal**: GitHub issue #69 closed. All AI-backend HTTP traffic (health-check + chat) is routed through `MontoyaHttpTransport` so Burp's upstream proxy / SOCKS / cert store is honored; the chat-context builder respects a small-model defaults profile that fits 1278-token-class models; and the MCP server enforces an in-scope-only restriction across every tool that returns Burp HTTP data.
**Depends on**: Nothing (parallel-safe with Phase 1, 4, 5)
**Requirements**: BUG-69-01 (transport unification), BUG-69-02 (small-model defaults), BUG-69-03 (MCP scope enforcement)
**Success Criteria** (what must be TRUE):

  1. `healthCheck()` for every HTTP-based backend (OpenAI-compatible, Perplexity, NVIDIA, LM Studio, Ollama HTTP) goes through `MontoyaHttpTransport` when a `BurpExtensionApi` instance is available; the OkHttp fallback path is removed from production code paths so Burp's upstream proxy and SOCKS config are always honored.
  2. The chat code path in `OpenAiCompatibleBackend.send()` and `LmStudioBackend.send()` no longer contains an OkHttp fallback branch; if `transport == null` at runtime in a real Burp session, the call fails fast with a clear error rather than silently bypassing Burp's network stack.
  3. A unit test asserts the OkHttp fallback (still kept for non-Burp test environments) is never reached when a non-null `MontoyaHttpTransport` is passed; another asserts the fallback's documentation comment is corrected to reflect that it does NOT honor Burp's upstream proxy.
  4. The MCP "Max body size" UI spinner accepts values from 32 KB to 100 MB (today: 1 MB minimum), denominated in KB so users with small-context models can configure tight caps without UI gymnastics.
  5. A "Small-model mode" toggle (or per-backend max-context awareness) caps `ContextCollector` request/response chars to 1500/750 (today: 4000/8000) when enabled or when the active backend declares a context window ≤ 4k tokens.
  6. A new `mcpScopeOnly: Boolean` setting plus checkbox in the MCP section of `SettingsPanel` controls the scope filter. When enabled, every MCP tool that returns Burp HTTP data (`site_map`, `proxy_history`, `target_tree`, repeater/intercept history, etc.) filters results to `api.scope().isInScope(url)`, and the `send_request` tool rejects calls targeting out-of-scope URLs.
  7. Unit tests cover (a) `MontoyaHttpTransport.get()` is invoked for the health-check path, (b) small-model mode emits a 1500/750 ContextCapture, (c) every scope-aware MCP tool short-circuits when `mcpScopeOnly=true` and the target is out of scope.

**Plans**: 3 plans
Plans:

- [x] 07-01-PLAN.md — Transport unification: route healthCheck for OpenAi/LmStudio/Ollama/NvidiaNim through MontoyaHttpTransport, remove OkHttp send() fallback, fix misleading buildClient KDoc (Wave 1, BUG-69-01)
- [x] 07-02-PLAN.md — Small-model defaults: add `chat.smallModelMode` toggle that caps ContextCollector to 1500/750 chars + convert MCP body-cap UI from MB to KB (range 32-102400) + lower storage floor to 32 KB (Wave 1, BUG-69-02)
- [x] 07-03-PLAN.md — MCP scope enforcement: add `mcpScopeOnly` setting + checkbox + McpScopeFilter helper; filter every read-style MCP tool to in-scope hosts; reject out-of-scope URLs in write-style tools (Wave 2, BUG-69-03)

### Phase 8: BApp Store resubmission — MCP pivot to extension-native tools + compliance fixes

**Goal:** Get the extension accepted on the PortSwigger BApp Store (issue #231) by resolving all four review feedback points without discarding the MCP work: (1) pivot the store build's MCP server to expose only extension-native AI tools while gating the 51 generic Montoya wrappers out of the store JAR (kept in a GitHub "full" build); (2) gate AI-calling MCP tools on `api.ai().isEnabled()`; (3) migrate passive scanning from `ProxyResponseHandler` to `PassiveScanCheck.doCheck()` (modern Montoya 2026.2 interface); (4) confirm the name "Custom AI Agent".
**Requirements**: BApp Store AI extension best practices (enhancedCapabilities + ai.isEnabled gating, Montoya networking + TLS verification, Burp AI as default provider); no generic-Montoya MCP duplication of the official server; preserve privacy redaction + audit trail; keep Burp Community support (verify the AI gate does not break non-Burp-AI backends there).
**Depends on:** Phase 7
**Plans:** 3/4 plans executed

Plans:
**Wave 1**

- [x] 08-01-PLAN.md — Wave 1: -PstoreBuild Gradle gate + BuildFlags.kt generate task + two-artifact naming + nativeTool field + McpToolCatalog.available() + Wave-0 test stubs (Wave 1, completed 2026-05-29)

**Wave 2** *(blocked on Wave 1 completion)*

- [x] 08-02-PLAN.md — Wave 2: 6 new native MCP tools (ai_analyze, ai_passive_scan, ai_findings_recent, redact_preview, ai_audit_query, ai_backends_list) + context injection + available() routing in registration + SettingsPanel UI (Wave 2, depends on 08-01)
- [x] 08-03-PLAN.md — Wave 3: AiPassiveScanCheck implementing PassiveScanCheck.doCheck() + remove ProxyResponseHandler from PassiveAiScanner + App.kt registration (Wave 3, depends on 08-01)

**Wave 4** *(blocked on Wave 2 completion)*

- [ ] 08-04-PLAN.md — Wave 4: artifact inspection + Community/Pro AI-gate manual verification (checkpoint) + /reopen reply draft (Wave 4, depends on 08-02 + 08-03)

### Phase 6: v0.7.0 Release Cut

**Goal**: v0.7.0 is tagged, built, and published with a complete release artefact set (JAR + SHA-256 + SBOM + release notes) on a green CI matrix across macOS, Linux, and Windows.
**Depends on**: Phases 1, 2, 3, 4, 5 (every feature audit + both bug fixes + docs must be merged first)
**Requirements**: REL-01, REL-02, REL-03, REL-04, REL-05
**Success Criteria** (what must be TRUE):

  1. `CHANGELOG.md`'s `[Unreleased]` block is renamed to `[0.7.0] - <release date>`, the upgrade notes are preserved, and any new fixes folded in by Phase 4 appear under `Fixed`.
  2. Version is bumped consistently across `build.gradle.kts` and any version constants; `./gradlew clean shadowJar` produces `Custom-AI-Agent-0.7.0.jar` that loads in Burp Community and Burp Pro on macOS, Linux, and Windows (CI matrix green).
  3. `ktlintCheck`, `jacocoTestReport`, and the full test suite pass on the release commit across the existing OS matrix.
  4. Git tag `v0.7.0` is pushed; the GitHub release pipeline uploads `Custom-AI-Agent-0.7.0.jar`, a matching SHA-256 checksum, and a CycloneDX SBOM (`bom.json`) with release notes auto-extracted from the `[0.7.0]` `CHANGELOG.md` section.
  5. The published JAR's SHA-256 matches the SHA-256 of `./gradlew shadowJar` run locally on the tagged commit (regression coverage for BUG-01 in production).

**Plans**: TBD

---

## v0.8.0 Phase Details

### Phase 9: Design System Foundation

**Goal**: A shared Swing design-system module (spacing, typography, color tokens + reusable components) exists in `ui/` and is the single styling source that all settings panels can adopt — no panel depends on ad-hoc literals after this phase.
**Depends on**: Nothing (new module; no existing panel is migrated yet)
**Requirements**: UI-01
**Success Criteria** (what must be TRUE):

  1. A `DesignTokens` object (or equivalent) in `ui/design/` exposes spacing constants, font descriptors, and color roles (primary, surface, muted, border) that resolve correctly against `UIManager` in both Burp light and dark themes — no hardcoded hex values in the token layer.
  2. At least four reusable Swing component builders exist — section header label, labeled field row (label + control + optional help text), inline help/description label, and primary/secondary action button — each applying tokens so visual consistency is guaranteed by construction.
  3. A unit or visual-verification test (or a developer-run harness) confirms token values load without throwing in a headless JVM context, exercising both "light" and "dark" UIManager overrides.
  4. No existing panel behaviour or settings-persistence changes: the new module is additive only; all tests remain green after the addition (`./gradlew test` passes).

**Plans**: 2 plans
Plans:

**Wave 1**

- [x] 09-01-PLAN.md — Create DesignTokens.kt (Spacing / Typography / Colors objects) + DesignTokensTest.kt (7 headless tests: spacing multiples-of-4, light/dark UIManager flip, color roles non-null, typography derivation)

**Wave 2** *(blocked on Wave 1 completion)*

- [x] 09-02-PLAN.md — Create Components.kt (11 builder functions + BadgeStyle + applyFieldStyle/applyAreaStyle) + DesignComponentsTest.kt (15 builder construction tests) + full suite regression check

**UI hint**: yes

### Phase 10: MCP Tools Tab Redesign

**Goal**: The MCP tools tab (`McpConfigPanel`) is reorganized into two clearly labelled sections — extension-native AI tools and generic Montoya tools — with store-build / full-build badges per row, a live search/filter field, and per-group bulk enable/disable toggles, built on the Phase 9 design system.
**Depends on**: Phase 9 (design-system tokens + components); Phase 8 (nativeTool field + McpToolCatalog.available() already in place)
**Requirements**: UI-03, UI-04, UI-05, UI-07
**Success Criteria** (what must be TRUE):

  1. Opening the MCP tab shows two visually distinct sections — "AI Tools (extension-native)" and "Montoya Tools (generic)" — each rendered with the Phase 9 section-header component; tools appear in the correct section based on `McpToolDescriptor.nativeTool`.
  2. Each tool row displays a "store" or "full" badge (or equivalent visual indicator) derived from the tool's build availability, so users can immediately see which tools ship in the BApp Store build without consulting external docs.
  3. Typing in the search/filter field narrows both sections in real time (case-insensitive match on tool name and description); clearing the field restores all tools.
  4. A "Enable all / Disable all" control per group performs a bulk toggle that applies to all tools currently visible in that group (respects active search filter); the resulting per-tool enabled states persist through settings save/reload.
  5. All existing per-tool enable/disable toggles, the master unsafe-mode switch, and MCP server start/stop remain fully functional — no behavior or persistence regression; the full test suite passes.

**Plans**: TBD
**UI hint**: yes

### Phase 11: Settings Tabs + Theme Rollout

**Goal**: Every Settings tab is rebuilt on the Phase 9 design system, giving the entire Settings area a consistent layout (labeled fields, section headers, one-line descriptions, collapsible sections for long tabs) and full light/dark theme fidelity via tokens — no hardcoded colors remain anywhere in settings panels.
**Depends on**: Phase 9 (design-system tokens + components); Phase 10 recommended (MCP tab done first as the highest-priority panel)
**Requirements**: UI-02, UI-06, UI-08, UI-07
**Success Criteria** (what must be TRUE):

  1. Every Settings tab (`SettingsPanel`, `MainTab`, and all panels under `ui/panels/`) uses Phase 9 labeled-field rows and section headers exclusively — no ad-hoc `JLabel` + `JTextField` pairs remain that bypass the design system.
  2. Each tab and each collapsible section within a tab has a visible title and a one-line description (≤ 80 chars) so a user scanning the settings can understand the purpose of each group without opening it.
  3. Long tabs (MCP, Scanner, Backend) use collapsible sections; collapsed state is preserved between extension restarts via `AgentSettings` (or equivalent persistence key).
  4. With Burp's theme set to dark, all settings panels render using dark-appropriate token values — no visible white/light backgrounds or black text against dark surfaces; verified by a developer smoke-check in Burp Pro dark mode.
  5. All existing settings values (backend selection, privacy mode, audit toggle, MCP config, scanner thresholds, prompt library) load and save correctly after the redesign — a regression test pass (`./gradlew test`) and a manual settings-persistence smoke-check confirm no regressions.

**Plans**: TBD
**UI hint**: yes

## Progress

**Execution Order (v0.7.0 carryover):**
Phases 1, 2, 3, and 4 are parallel-safe and can be planned/executed concurrently. Phase 5 (docs) depends on Phases 1-3 being merged. Phase 6 (release cut) depends on every other phase being complete.

**Execution Order (v0.8.0):**
Phase 9 must complete first (design-system foundation). Phase 10 (MCP tab) and Phase 11 (settings rollout) both depend on Phase 9; Phase 10 is recommended before Phase 11 since it is the highest-priority panel.

| Phase | Plans Complete | Status | Completed |
|-------|----------------|--------|-----------|
| 1. Perplexity Backend Audit | 0/1 | Not started | - |
| 2. Insertion-Point Scan Audit | 3/3 | Complete   | 2026-05-13 |
| 3. Prompt Library UX Audit | 3/3 | Complete   | 2026-05-13 |
| 4. Release-Gating Bug Fixes | 0/TBD | Not started | - |
| 5. Documentation Refresh | 0/TBD | Not started | - |
| 6. v0.7.0 Release Cut | 0/TBD | Not started | - |
| 7. Proxy Transport + MCP Scope Hardening | 3/3 | Complete   | 2026-05-27 |
| 8. BApp Store resubmission — MCP pivot + compliance | 3/4 | In Progress|  |
| 9. Design System Foundation | 2/2 | Complete   | 2026-05-29 |
| 10. MCP Tools Tab Redesign | 0/TBD | Not started | - |
| 11. Settings Tabs + Theme Rollout | 0/TBD | Not started | - |
