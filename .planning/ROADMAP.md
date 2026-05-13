# Roadmap: Burp AI Agent — v0.7.0

## Overview

Stabilization milestone for the three `Unreleased` features (Perplexity backend, AI scan on selected insertion point, custom prompt library UX), the two open bugs gating release (#62 release pipeline, #66 openai-compatible usage error), the user-facing documentation refresh, and the v0.7.0 release cut itself. The three feature-audit phases (1, 2, 3) are independent and parallel-safe. The release phase (6) is a choke point that depends on every earlier phase being green.

## Phases

**Phase Numbering:**
- Integer phases (1, 2, 3): Planned milestone work
- Decimal phases (2.1, 2.2): Urgent insertions (marked with INSERTED)

Decimal phases appear between their surrounding integers in numeric order.

- [ ] **Phase 1: Perplexity Backend Audit** - Verify shipped Perplexity backend meets SPEC, lock behaviour with tests
- [x] **Phase 2: Insertion-Point Scan Audit** - Verify right-click insertion-point scanning + selection resolution, lock with tests (completed 2026-05-13)
- [ ] **Phase 3: Prompt Library UX Audit** - Verify search / favorites / import-export / ordering, lock with tests
- [ ] **Phase 4: Release-Gating Bug Fixes** - Close #62 (release pipeline publishes stale code) and #66 (openai-compatible usage error)
- [ ] **Phase 5: Documentation Refresh** - README, `burp-ai-agent.six2dez.com`, and `SPEC.md` reflect the three Unreleased features
- [ ] **Phase 6: v0.7.0 Release Cut** - Promote CHANGELOG, bump version, build, tag, publish JAR + SBOM + SHA-256, CI green on matrix

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
**Plans**: TBD
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

## Progress

**Execution Order:**
Phases 1, 2, 3, and 4 are parallel-safe and can be planned/executed concurrently. Phase 5 (docs) depends on Phases 1-3 being merged. Phase 6 (release cut) depends on every other phase being complete.

| Phase | Plans Complete | Status | Completed |
|-------|----------------|--------|-----------|
| 1. Perplexity Backend Audit | 0/1 | Not started | - |
| 2. Insertion-Point Scan Audit | 3/3 | Complete   | 2026-05-13 |
| 3. Prompt Library UX Audit | 0/TBD | Not started | - |
| 4. Release-Gating Bug Fixes | 0/TBD | Not started | - |
| 5. Documentation Refresh | 0/TBD | Not started | - |
| 6. v0.7.0 Release Cut | 0/TBD | Not started | - |
