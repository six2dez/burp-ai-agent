# Phase 19: Mega-File Split + Docs - Context

**Gathered:** 2026-06-16
**Status:** Ready for planning
**Mode:** Smart discuss (autonomous) — 3 grey areas, all accepted as recommended

<domain>
## Phase Boundary

The last code change of the v0.9.0 milestone. Three deliverables, no new features:

1. **QUAL-01 — Mega-file split (no behaviour change).** Split the three mega-files into
   focused, same-package files. The three *named* files must each end under ~500 lines
   (SC1's literal gate); extracted helper files are grouped by cohesion. The full
   `./gradlew test` suite must be green before and after each individual extraction, and
   `ServiceLoader`/`META-INF/services` backend registration must stay intact (SC2).
   - `src/main/kotlin/com/six2dez/burp/aiagent/mcp/tools/McpTools.kt` — **2925 lines**
   - `src/main/kotlin/com/six2dez/burp/aiagent/ui/SettingsPanel.kt` — **2782 lines**
   - `src/main/kotlin/com/six2dez/burp/aiagent/scanner/PassiveAiScanner.kt` — **2566 lines**

2. **DOC-01 — `.planning/` reconciliation.** PROJECT/STATE/ROADMAP/REQUIREMENTS reflect
   shipped v0.7.0 and v0.8.0; closed issues #62/#66/#67/#68/#69 acknowledged; confirmed
   stale/superseded carryover pruned (SC3).

3. **DOC-02 — User-facing docs.** README.md, SPEC.md, DECISIONS.md updated for v0.9.0
   features (Anthropic backend, AES-256-GCM secret encryption, redaction changes — real
   HKDF + body/custom patterns, external MCP client, token-budget guardrails) (SC4), plus
   the public docs site `burp-ai-agent.six2dez.com` gains pages for the two highest-novelty
   features: Anthropic backend and external MCP servers (SC5).

**Out of this phase:** any behaviour change, new feature, opportunistic bug fix, CHANGELOG
promotion, or `build.gradle.kts` version bump (see Deferred).

</domain>

<decisions>
## Implementation Decisions

### Mega-File Split Strategy (QUAL-01 / SC1, SC2)
- **Split boundary by responsibility / feature cohesion** — extract logically-related
  groups (e.g. tool-handler families in McpTools, per-tab panel builders in SettingsPanel,
  scan queue/dedup/formatting in PassiveAiScanner). Not by type, not mechanical line-chunking.
- **Same-package top-level functions/objects in new files** — keep extracted code in the
  same Kotlin package as the origin file so there are **zero call-site changes and no import
  churn**; lowest behaviour-change risk. No new sub-packages, no wrapping into new classes
  unless the original code was already a class member that moves wholesale.
- **Size target = the three named files each land under ~500 lines** (the literal SC1 gate).
  Extracted helper files are grouped by cohesion and kept reasonable, but SC1 does not gate
  the helper-file sizes — do not split cohesive code awkwardly just to chase a number.
- **One atomic commit per extraction**, with `./gradlew test` run green **between each**
  extraction (satisfies SC1's "before and after each individual extraction"). Not one big
  commit per mega-file.

### User-Facing Docs (DOC-02 / SC4, SC5)
- **SC5 site source = in-repo `docs/` served by GitHub Pages.** Single repo
  (`github.com/six2dez/burp-ai-agent`); no Pages workflow and the existing `docs/` already
  holds 3 topic guides (mcp-hardening, ui-safety-guide, backend-troubleshooting). New
  markdown goes there. NOT a separate external repo.
- **SC5 deliverable = two new concise pages**: `docs/anthropic-backend.md` and
  `docs/external-mcp-servers.md` (setup + key options + privacy/security notes). The
  **live-URL render is a HUMAN-UAT item** — the maintainer confirms the pages render at the
  custom domain after the Pages rebuild (Pages config/CNAME is managed outside the repo).
- **In-repo docs (SC4):** the untracked `SPEC.md`, `DECISIONS.md`, and `AGENTS.md` are
  **committed** as part of this phase while being updated. `DECISIONS.md` gets ADR-style
  entries matching its existing format for the v0.9.0 decisions (AES-256-GCM secrets-at-rest,
  real-HKDF host anonymization, Anthropic backend via `MontoyaHttpTransport` not a vendored
  SDK, external-MCP untrusted-output trust boundary, per-session token-budget guardrails).
  `README.md` gains a concise "What's new in v0.9.0" section + a native **Anthropic** row in
  the backend roster + external-MCP-server mention + privacy/security notes. (README today
  documents only the *Claude CLI* backend and Claude Desktop MCP — neither covers CAP-01/02.)
- **CHANGELOG.md promotion and the `build.gradle.kts` 0.8.0→0.9.0 version bump are DEFERRED**
  to a separate release-cut task. CHANGELOG is not in DOC-02's list, and v0.8.0 did this as
  standalone quick tasks (260602-v08, 260602-cl8) after the phases closed.

### .planning Reconciliation & Scope Guard (DOC-01 / SC3)
- **Prune confirmed-superseded/stale entries** (e.g. the now-moot kotlin-sdk 0.13.0-bump
  blocker — Path A dissolved it; resolved-issue carryover #62/#66/#67/#68/#69) **and** verify
  v0.7.0/v0.8.0 shipped state is recorded accurately. Not verify-only.
- **Strict mechanical-only refactor** — no features, no opportunistic bug fixes during the
  split. Anything noteworthy found is captured as a follow-up todo, not fixed inline.
- **No-behaviour-change proof = the existing full `./gradlew test` suite green before+after
  each extraction, plus SC2's `BackendRegistryTest.loadAll()` factory-count assertion.** Do
  not author new characterization tests for moved code (the existing suite is the safety net).
- **Phase 16 note:** Phase 16 (External MCP Client) is **code-complete and committed** (5/6
  plans; its McpTools ext-MCP additions are in `main`). Its human-UAT (SC1 real-server
  connect, SC5 live-Burp load) is tracked separately in `16-HUMAN-UAT.md` and does **not**
  block Phase 19 — Phase 19 splits the *committed* McpTools.kt including those additions.

</decisions>

<code_context>
## Existing Code Insights

### Reusable Assets
- Codebase maps already exist under `.planning/codebase/` (ARCHITECTURE, CONCERNS,
  CONVENTIONS, INTEGRATIONS, STACK, STRUCTURE, TESTING) — plan-phase research should read
  CONVENTIONS.md + STRUCTURE.md to match the project's file-organization idiom for the split.
- `docs/` already contains topic-guide markdown (mcp-hardening.md, ui-safety-guide.md,
  backend-troubleshooting.md) — new SC5 pages follow the same concise, task-oriented style.
- `DECISIONS.md` (82 lines, untracked) already uses an ADR-style format — append, don't restyle.
- `CHANGELOG.md` (630 lines) has an empty `## [Unreleased]` section and a `## [0.8.0]` entry
  documenting v0.8.0 — out of scope here but the reference point for the future release task.

### Established Patterns
- Kotlin (JVM 21), Gradle Kotlin DSL, Montoya API; Swing UI (ADR-2 locks Swing in).
- Backends are discovered via `ServiceLoader` (`META-INF/services`) — the split must not
  disturb factory registration; `BackendRegistryTest.loadAll()` asserts the factory count (SC2).
- AWT-free core logic vs Swing UI separation already practiced (e.g. SecretShapes, BudgetGuard,
  Entropy) — a good model for extracting non-UI logic out of SettingsPanel/scanner files.
- `version = "0.8.0"` in build.gradle.kts line 15 (reference for the deferred bump).

### Integration Points
- McpTools.kt lives in `…/mcp/tools/`; extracted files stay in that package.
- SettingsPanel.kt lives in `…/ui/`; extracted per-tab builders stay in `…/ui/`.
- PassiveAiScanner.kt lives in `…/scanner/`; extracted scan/queue/format helpers stay in `…/scanner/`.
- The fat JAR (`./gradlew shadowJar`, artifact `Custom-AI-Agent-<version>.jar`) and the
  `-PstoreBuild=true` two-artifact build must still build after the split.

</code_context>

<specifics>
## Specific Ideas

- SC1's "<400–500 lines" applies to the **three named files** specifically — the verifier
  checks those three, not every extracted helper. Slim the named files; group helpers sanely.
- README backend roster currently has a "Claude CLI" row but **no native Anthropic (Messages
  API) row** — add one distinct from the CLI entry.
- The two SC5 doc pages target the two highest-novelty v0.9.0 features by name: **Anthropic
  backend** and **external MCP servers**.
- Pre-existing standalone-`ktlintCheck` defect was the subject of Phase 18 (QUAL-05) — assume
  it is fixed; if `./gradlew check`/`ktlintCheck` still misbehaves standalone, fall back to
  `./gradlew test` for the per-extraction green-checks and note it (do not re-fix here).

</specifics>

<deferred>
## Deferred Ideas

- **CHANGELOG.md `[Unreleased]→[0.9.0]` promotion + `build.gradle.kts` version bump 0.8.0→0.9.0**
  → a separate release-cut quick task after the milestone closes (matches v0.8.0 practice).
- **Any opportunistic bug fix or behaviour tweak** spotted during the split → capture as a
  follow-up todo; this phase is strictly mechanical.
- **New characterization tests** for the moved code → not now; the existing full test suite +
  BackendRegistryTest is the agreed safety net.
- **SC5 live-site DNS/Pages deployment** (the actual `burp-ai-agent.six2dez.com` render) →
  HUMAN-UAT; the repo deliverable is the markdown pages only.

</deferred>
