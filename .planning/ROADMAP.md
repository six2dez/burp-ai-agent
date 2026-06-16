# Roadmap: Burp AI Agent

## Shipped (Historical)

### v0.7.0 — Release Cut + Stabilization (shipped 2026-05-15)

Phases 1–8 closed. Features: Perplexity backend, AI scan on selected insertion point, custom prompt library UX, bug fixes #62/#66/#67/#68, proxy transport + MCP scope hardening (#69), BApp Store resubmission (#231).

| Phase | Name | Status |
|-------|------|--------|
| 1 | Perplexity Backend Audit | Not started |
| 2 | Insertion-Point Scan Audit | Complete (2026-05-13) |
| 3 | Prompt Library UX Audit | Complete (2026-05-13) |
| 4 | Release-Gating Bug Fixes | — |
| 5 | Documentation Refresh | — |
| 6 | v0.7.0 Release Cut | — |
| 7 | Proxy Transport + MCP Scope Hardening | Complete (2026-05-27) |
| 8 | BApp Store resubmission — MCP pivot + compliance | Complete (2026-06-09) |

### v0.8.0 — UI/UX Overhaul (shipped 2026-06-02)

Phases 9–11 closed. Features: design system foundation (UI-01), MCP tools tab redesign (UI-03/04/05/07), all settings tabs rebuilt on design system with light/dark theme (UI-02/06/07/08).

| Phase | Name | Status |
|-------|------|--------|
| 9 | Design System Foundation | Complete (2026-05-29) |
| 10 | MCP Tools Tab Redesign | Complete (2026-05-29) |
| 11 | Settings Tabs + Theme Rollout | Complete (2026-06-02) |

---

## Active Milestone: v0.9.0 — Hardening, Quality & New Capabilities

**Status:** Planning — started 2026-06-10

**Goal:** Harden privacy/security, pay down quality and maintainability debt, and add new capabilities on the stable v0.8.0 base — without compromising the non-negotiable core value (privacy controls + audit trail).

**Ordering rationale (from research):**

- SEC (Phase 12) must land first — all new secret fields (Anthropic key, external MCP tokens) must be encrypted from day one; migration ladder must exist before any new secret field is added.
- Privacy hardening (Phase 13) is independent of SEC and can run after it without conflicts.
- CAP-01/03/04 (Phase 14) depends on Phase 12; Anthropic API key must be encrypted from the first commit that introduces it.
- PRIV-03 tripwire (Phase 15) depends on Phase 12 (meaningful once keys leave plaintext) and must land before QUAL-01 (the split moves the PassiveAiScanner hook points).
- CAP-02 external MCP (Phase 16) is highest novelty/build-risk; placed after CAP-01; kotlin-sdk 0.5.0→0.13.0 bump gated on a Burp-JVM test-run.
- REL reliability (Phase 17) is independent and can follow feature phases.
- Quality tooling (Phase 18) adds detekt/ktlint gates and test coverage — independent, safe after features.
- QUAL-01 mega-file split (Phase 19) is the last code phase — pure no-behaviour-change refactor; DOC-01/02 co-land here once features are stable.

## Phases

- [x] **Phase 12: Secrets at Rest & Transport Security** — Encrypt all stored API keys (AES-256-GCM), fix keytool argv password exposure, add soft SSRF backend URL warning ✓ 2026-06-10
- [x] **Phase 13: Privacy & Redaction Hardening** — Fix host-anonymization algorithm (real HKDF), broaden redaction to request/response bodies with user-configurable patterns, add redaction-coverage UI (completed 2026-06-10)
- [x] **Phase 14: Anthropic Backend + Token Budget + Listener Port** — Native Anthropic Messages API backend with streaming/tool-use/prompt-caching; per-session token-budget guardrails; MCP proxy-history listener port filter (completed 2026-06-10)
- [x] **Phase 15: Pre-Send Secret Tripwire** — Post-redaction tripwire scanning final payload for high-entropy secrets before any send; warn-with-confirmation UI; audit-logged allowlist (completed 2026-06-11)
- [ ] **Phase 16: External MCP Client** — Connect to external/custom MCP servers (SSE + stdio transports); auth tokens encrypted; SSRF guard; untrusted-output trust boundary
- [x] **Phase 17: Reliability & Concurrency Hardening** — EDT confinement on ChatPanel session maps; CLI temp file cleanup via finally; bounded MCP shutdown; uniform HTTP timeouts/CircuitBreaker; fix CLI timeout bug #71 (completed 2026-06-11)
- [x] **Phase 18: Quality Tooling & Build Hardening** — Raise scanner/CLI/cache test coverage; add detekt + blocking ktlint with committed baseline; audit 136 exception-logging sites; fix generateBuildFlags sourceSets wiring (completed 2026-06-11)
- [ ] **Phase 19: Mega-File Split + Docs** — Split 3 mega-files (no behaviour change); finalize .planning reconciliation; update user-facing docs for v0.9.0 changes

## Phase Details

### Phase 12: Secrets at Rest & Transport Security

**Goal**: All stored credentials are encrypted at rest from this phase forward — no professional tool stores secrets in plaintext; existing secrets are migrated non-destructively; two secondary transport-security gaps (keytool argv password, SSRF-blind backend URLs) are closed simultaneously.
**Depends on**: Nothing (must be first — every subsequent phase that introduces a new secret relies on this)
**Requirements**: SEC-01, SEC-02, SEC-03
**Success Criteria** (what must be TRUE):

  1. A user who upgrades from v0.8.0 has all their existing API keys and MCP tokens transparently migrated to AES-256-GCM encrypted form; Settings loads correctly with plaintext values at runtime; plaintext form is overwritten only after round-trip decrypt succeeds.
  2. Secrets never appear in Burp's output/error logs — the crypto path logs only the Preferences key name on failure, never the key material.
  3. A user enabling MCP TLS no longer has the keystore password exposed in a `ps aux` listing during keytool execution; the password is written to a temp file with owner-read-only permissions or generated in-JVM.
  4. A user who types a non-loopback private/link-local URL in any backend settings field sees a soft SSRF warning on save (non-blocking — the user can proceed deliberately).
  5. Unit tests cover: AES-GCM round-trip, schema-V4 migration idempotency (re-running migration does not double-encrypt), and headless Linux fallback path (no `HeadlessException` with `java.awt.headless=true`).

**Plans**: 4 plans

Plans:

- [ ] 12-01-PLAN.md — SecretCipher.kt: AES-256-GCM utility + per-install master key (SEC-01 foundation)
- [ ] 12-02-PLAN.md — Schema v4 migration + encrypt/decrypt wiring in AgentSettingsRepository (SEC-01)
- [ ] 12-03-PLAN.md — In-JVM TLS cert generation in McpTls.kt, removes keytool subprocess (SEC-02)
- [ ] 12-04-PLAN.md — SsrfGuard + inline warning in BackendConfigPanel (SEC-03)

### Phase 13: Privacy & Redaction Hardening

**Goal**: The redaction pipeline's privacy claims match its implementation — host anonymization uses real HKDF; redaction covers request/response bodies (not just headers); users can add custom patterns and test them; a UI indicator surfaces when a known secret shape survived redaction.
**Depends on**: Phase 12 (Phase 12 closes before Phase 13 begins, ensuring no conflicts on Redaction.kt; the two phases touch different files and are logically independent but sequencing avoids any merge friction)
**Requirements**: PRIV-01, PRIV-02, PRIV-04
**Success Criteria** (what must be TRUE):

  1. `Redaction.anonymizeHost` uses `Mac.getInstance("HmacSHA256")` (HKDF extract/expand) not `MessageDigest.getInstance("SHA-256")` — the SPEC's stated privacy guarantee now matches the implementation; existing STRICT-mode tests stay green.
  2. A secret in the leading field of a `application/x-www-form-urlencoded` request body (e.g. `apikey=sk-abc123&...`) is redacted in STRICT and BALANCED modes, confirmed by a unit test.
  3. A user can enter a custom regex pattern in Settings; the pattern is applied during redaction and the UI validates it against an adversarial ReDoS test string (50 ms timeout) before accepting it.
  4. The redaction preview dialog flags when a known secret shape (matching the same curated pattern set as the tripwire) passed through redaction, so the user can see what the pipeline missed before sending.
  5. Unit tests cover STRICT/BALANCED/OFF mode matrix for the new body-redaction paths and the custom-pattern ReDoS guard.

**Plans**: 3 plans

Plans:
**Wave 1**

- [x] 13-01-PLAN.md — HKDF host anonymization (PRIV-01) + SafeRegex ReDoS-guard foundation (redact core) [wave 1]

**Wave 2** *(blocked on Wave 1 completion)*

- [x] 13-02-PLAN.md — Body/form/JSON redaction + custom-pattern engine, persistence, and Privacy panel wiring (PRIV-02) [wave 2]
- [x] 13-03-PLAN.md — Shared SecretShapes curated set + survived-secret WARN banner in the preview dialog (PRIV-04) [wave 2]

**UI hint**: yes

### Phase 14: Anthropic Backend + Token Budget + Listener Port

**Goal**: Users can select a native Anthropic Messages API backend (the highest-demand gap in the current backend roster); per-session token-budget guardrails surface consumption and enforce hard caps; and MCP proxy-history results can be filtered by listener port — all three ship together since CAP-03 and CAP-04 are small additions that share no conflicts with CAP-01.
**Depends on**: Phase 12 (anthropicApiKey must be encrypted from the first commit that introduces it)
**Requirements**: CAP-01, CAP-03, CAP-04
**Success Criteria** (what must be TRUE):

  1. A user can select "Anthropic" in Settings > Backend, enter an API key (encrypted on save), choose a model (editable, defaulting to a current alias), and send a chat message that streams tokens back through the Burp proxy — verified by a HUMAN-UAT smoke test with a live Anthropic API key.
  2. Anthropic traffic appears in Burp's Proxy > HTTP history (confirming `MontoyaHttpTransport` is used, not a direct OkHttp client); `grep OkHttp AnthropicBackend.kt` returns empty on the production code path.
  3. A 400 response from Anthropic that contains "model" in the error body surfaces a specific user-visible message ("Anthropic rejected the model ID — check Settings > Anthropic > Model") rather than a generic error.
  4. A user can set a session token-budget warn threshold and hard cap; the passive scanner pauses when the hard cap fires; the chat UI shows a warning banner when the warn threshold is crossed.
  5. A user using the MCP `proxy_http_history` tool can filter results by Burp listener port (e.g. `8080`), and only requests received on that port are returned.

**Plans**: 3 plans
- [x] 14-01-PLAN.md — Anthropic Messages API backend + supervisor branch + registration + all AgentSettings fields (encrypted key) + Anthropic settings card (CAP-01)
- [x] 14-02-PLAN.md — Token-budget guardrails: AWT-free BudgetGuard + scanner budgetPaused gate + chat banner + Settings token-budget section (CAP-04)
- [x] 14-03-PLAN.md — proxy_http_history listener_port filter on both dispatch paths (CAP-03, closes #70)
**UI hint**: yes

### Phase 15: Pre-Send Secret Tripwire

**Goal**: A post-redaction tripwire scans the final outbound payload for high-entropy strings that survived the redaction pipeline and warns the user before the payload leaves Burp — the warning is non-blocking (warn-with-confirmation, not hard-stop) so legitimate pentest payloads are never silently blocked.
**Depends on**: Phase 12 (meaningful once existing keys are no longer plaintext in preferences; adds hooks to PassiveAiScanner before Phase 19 moves those methods)
**Requirements**: PRIV-03
**Success Criteria** (what must be TRUE):

  1. A request body containing a live AWS-format key (`AKIA...`) that survives BALANCED-mode redaction triggers a confirmation dialog ("This payload appears to contain a high-entropy value — send anyway?") before reaching the AI backend — verified by a unit test with a synthetic high-entropy string.
  2. A legitimate high-entropy pentest payload (e.g. a base64-encoded fuzz string) also shows the confirmation dialog and the user can dismiss it to proceed; the send is never hard-blocked.
  3. Allowlist actions (user chose "send anyway") are written to the audit log with the session ID and a truncated entropy score — the allowlist decision is auditable.
  4. The tripwire fires on all three outbound paths: ChatPanel interactive send, PassiveAiScanner batch/single sends, and MCP tool output via `McpToolContext.redactIfNeeded()`.
  5. The confirmation dialog is visible in the context preview dialog where the tripwire match is highlighted.

**Plans**: 3 plans

Plans:
**Wave 1**

- [x] 15-01-PLAN.md — Detector core: AWT-free Entropy.kt (Shannon) + SecretTripwire.kt reusing SecretShapes.findSurviving + EntropyTest/SecretTripwireTest (SC1/SC2/SC3-no-leak) [wave 1]

**Wave 2** *(blocked on Wave 1; file-disjoint, run in parallel)*

- [x] 15-02-PLAN.md — Interactive path: ContextPreviewDialog RISK gate + "Send anyway"/Cancel + ChatPanel allowlist audit (SC5/SC3) [wave 2]
- [x] 15-03-PLAN.md — Non-interactive paths: PassiveAiScanner three send sites + McpToolContext.redactIfNeeded, detect+audit+proceed (SC4/SC2) [wave 2]

**UI hint**: yes

### Phase 16: External MCP Client

**Goal**: Users can register external/custom MCP servers and the agent can call their tools — the highest-novelty phase of the milestone; external server auth tokens are encrypted (Phase 12 dependency); untrusted tool output is wrapped before entering the AI context to prevent prompt injection; SSRF warning covers external MCP URLs.
**Depends on**: Phase 12 (external MCP bearer tokens must be encrypted from day one). NOTE: Path A confirmed — kotlin-sdk 0.5.0 already ships the full MCP client; no Kotlin/Ktor bump required; Burp-JVM ClassLoader gate is a standard smoke test only
**Requirements**: CAP-02
**Success Criteria** (what must be TRUE):

  1. A user can add an external MCP server (SSE or stdio transport) in the MCP settings CRUD UI; the server connects and its tools appear alongside Burp's built-in tools in the agent's tool preamble — verified by a HUMAN-UAT with a real external MCP server.
  2. External MCP tool results are wrapped in an explicit trust-boundary marker before they enter the AI prompt context; the audit log records every external tool invocation and its result summary.
  3. Configuring an external MCP server URL that resolves to an RFC-1918 or link-local address triggers the same soft SSRF warning introduced in Phase 12.
  4. External server auth tokens are stored encrypted (Phase 12 SecretStore); they are never logged or exposed in the Settings UI in plaintext (show/hide toggle, same as other API key fields).
  5. The extension loads, the embedded MCP server starts, and the UI is responsive after the kotlin-sdk 0.13.0 bump — no `ClassLoader` conflicts or `NoClassDefFoundError` on Burp's JVM (verified in CI).

**Plans**: 6 plans

Plans:
**Wave 1** *(parallel — disjoint file sets)*

- [x] 16-01-PLAN.md — Add 3 Ktor client deps to build.gradle.kts + Wave 0 test scaffolds (ExternalMcpClientManagerTest, ExternalMcpSettingsMigrationTest) [wave 1]

**Wave 2** *(parallel — disjoint file sets)*

- [x] 16-02-PLAN.md — ExternalMcpServerConfig data model + McpSettings.externalMcpServers field + AgentSettings schema v5 migration (encrypted blob) [wave 2]
- [x] 16-03-PLAN.md — ExternalMcpClientManager: SSE+stdio transport lifecycle, trust-boundary wrap, AuditLogger [wave 2]

**Wave 3** *(parallel — disjoint file sets)*

- [x] 16-04-PLAN.md — McpToolContext.externalClientManager field + McpTools describeTools fan-out + ext: routing + outbound arg redaction (D-03) [wave 3]
- [x] 16-05-PLAN.md — ExternalServersPanel CRUD UI (16-UI-SPEC.md) + SettingsPanel MCP section wiring [wave 3]

**Wave 4** *(blocking UAT checkpoint)*

- [ ] 16-06-PLAN.md — Pre-flight check gate + Human UAT: SC1 real-server connect + SC5 Burp fat-JAR smoke test [wave 4]

**UI hint**: yes

### Phase 17: Reliability & Concurrency Hardening

**Goal**: The four known reliability gaps are closed: ChatPanel session state is safely EDT-confined; CLI temp files containing prompt content are reliably deleted even on crashes; all HTTP backends enforce consistent timeouts through the CircuitBreaker; and the CLI-command-timeout failure (issue #71) is diagnosed and fixed with a regression test.
**Depends on**: Phase 14 (AnthropicBackend must be included in the CircuitBreaker/timeout audit); Phase 16 recommended (McpClientManager lifecycle included in shutdown-bound audit)
**Requirements**: REL-01, REL-02, REL-03, REL-04
**Success Criteria** (what must be TRUE):

  1. `ChatPanel`'s four session maps (`sessionPanels`, `sessionStates`, `sessionsById`, `sessionDrafts`) carry `@GuardedBy("EDT")` annotations and an `assert(SwingUtilities.isEventDispatchThread())` guard at every write site; a `ChatPanelConcurrencyTest` verifies no off-EDT writes are reachable.
  2. CLI temp files containing prompt/context content are deleted in `finally` blocks (not only in `catch`); `deleteOnExit()` is also called as a belt-and-suspenders fallback; confirmed by a test that simulates an exception mid-execution.
  3. All HTTP backends (including the new AnthropicBackend from Phase 14) share consistent connect/read timeouts and route through `CircuitBreaker`; no backend can bypass `MontoyaHttpTransport` on the production code path.
  4. Issue #71 (CLI command timeout failure) is reproduced, diagnosed, and fixed or given an actionable error message; a regression test prevents recurrence.
  5. MCP server shutdown completes within a bounded timeout (no hang on `McpSupervisor.stop()`); host-anonymization maps are bounded or cleared to prevent memory growth over long pentests.

**Plans**: 3 plans (all wave 1 — files_modified disjoint, fully parallel)

Plans:
**Wave 1** *(no inter-plan dependencies; disjoint file sets — run in parallel)*

- [x] 17-01-PLAN.md — REL-03: shared 429/5xx → CircuitBreaker.recordFailure helper in HttpBackendSupport + wire all 4 HTTP backends (OpenAiCompatible/Anthropic/Ollama/LmStudio) + HttpBackendCircuitFailureTest (closes Phase 14 WR-05)
- [x] 17-02-PLAN.md — REL-01: local SOURCE-retained @GuardedBy annotation + ChatPanel EDT confinement (invokeLater on off-EDT tool-result map reads + addMessage) + jvmArgs("-ea") + ChatPanelConcurrencyTest
- [x] 17-03-PLAN.md — REL-02 + REL-04: CLI deleteOnExit + configurable cliTimeoutSeconds + actionable buildTimeoutMessage (#71); bounded McpServerManager.stop(); LRU-capped host-anonymization maps + 4 tests

### Phase 18: Quality Tooling & Build Hardening

**Goal**: The build and test infrastructure is hardened so regressions surface quickly: detekt static analysis and blocking ktlint are added with committed baselines; test coverage for the scanner queue, CLI supervision, and cache module is raised from near-zero; 136 silently-swallowed exception sites are audited; and the `generateBuildFlags` Gradle wiring is fixed so `./gradlew ktlintCheck` runs standalone.
**Depends on**: Phase 17 recommended (reliability fixes increase coverage scope); independent of Phase 19
**Requirements**: QUAL-02, QUAL-03, QUAL-04, QUAL-05
**Success Criteria** (what must be TRUE):

  1. `./gradlew ktlintCheck` passes standalone (without init-script workarounds), confirming the `generateBuildFlags` task is wired via `sourceSets` so consumers inherit the dependency automatically.
  2. `detekt` runs as a blocking CI check with a committed `detekt-baseline.xml`; new code must be clean; existing violations are captured in the baseline and do not break CI.
  3. `ktlintFormat` has been run on the entire codebase in a dedicated commit that precedes the `ktlintCheck` blocking-gate commit — confirmed by git log ordering.
  4. Test coverage for `scanner` queue/dedup, `cli` backend supervision, and the `cache` module is measurably raised from the current 0–3% baseline (target: at least one meaningful test class per module that exercises the critical path).
  5. Silently-swallowed `catch (Exception)` sites have been audited; each site either logs a contextual message via a shared helper or carries a `// INTENTIONAL: <reason>` comment; the audit is documented in a short tracking note.

**Plans**: 4 plans

Plans:
**Wave 1** *(SC1 + SC2 — both modify build.gradle.kts, serialized within one plan)*

- [x] 18-01-PLAN.md — Fix generateBuildFlags srcDir wiring (SC1/QUAL-05) + add detekt 1.23.8 with committed baseline (SC2/QUAL-02-detekt) [wave 1]

**Wave 2** *(SC3 — depends on SC1 for standalone ktlintCheck; two-commit sequence within plan)*

- [x] 18-02-PLAN.md — ktlintFormat mass-format commit then ktlint strict-by-default gate-flip commit (SC3/QUAL-02-ktlint) [wave 2]

**Wave 3** *(SC4 + SC5 — both depend on Wave 2 ktlintFormat; file-disjoint, run in parallel)*

- [x] 18-03-PLAN.md — Raise test coverage: PersistentPromptCacheTest, ActiveScannerDedupTest, CliSupervisionTest (SC4/QUAL-03) [wave 3]
- [x] 18-04-PLAN.md — Exception audit: annotate/log ~30-50 catch sites in cache/scanner/supervisor/cli; tracking note (SC5/QUAL-04) [wave 3]

### Phase 19: Mega-File Split + Docs

**Goal**: The three mega-files are split into focused files with no behaviour change (the last code change of the milestone, so no subsequent feature lands on top of the refactor); planning artifacts reflect the shipped v0.7.0/v0.8.0 state; user-facing docs are updated for all v0.9.0 additions.
**Depends on**: All code phases (12–18) complete — pure refactor must be last so no in-flight feature conflicts; PRIV-03 hooks (Phase 15) are inside PassiveAiScanner and must be committed before the split
**Requirements**: QUAL-01, DOC-01, DOC-02
**Success Criteria** (what must be TRUE):

  1. `McpTools.kt`, `SettingsPanel.kt`, and `PassiveAiScanner.kt` are each under 400–500 lines after the split; the full test suite (`./gradlew test`) passes before and after each individual extraction with zero behaviour changes.
  2. `ServiceLoader` registration (`META-INF/services`) is intact after the split — `BackendRegistryTest.loadAll()` asserts the expected number of built-in factories; no `ClassNotFoundException` at runtime.
  3. `.planning/` (PROJECT.md, STATE.md, ROADMAP.md, REQUIREMENTS.md) reflects shipped v0.7.0 and v0.8.0; closed issues #62/#66/#67/#68/#69 are acknowledged in the relevant planning artifacts with no stale carryover entries.
  4. `README.md`, `SPEC.md`, and `DECISIONS.md` are updated to document the Anthropic backend, secret encryption (AES-256-GCM), redaction changes (real HKDF, body patterns, custom patterns), external MCP client, and token-budget guardrails.
  5. The public docs site (`burp-ai-agent.six2dez.com`) has pages or sections for the Anthropic backend and external MCP servers, so v0.9.0 ships with no doc drift on the two highest-novelty features.

**Plans**: 5 plans

Plans:
**Wave 1** *(all parallel — disjoint file sets)*

- [x] 19-01-PLAN.md — McpTools.kt split: McpToolModels + McpToolHelpers + McpToolExecutorImpl (QUAL-01) [wave 1]
- [ ] 19-02-PLAN.md — PassiveAiScanner.kt split: Models + Heuristics + Parsing + Prompts (QUAL-01) [wave 1]
- [ ] 19-03-PLAN.md — SettingsPanel.kt split: ScannerTabs + McpTabs as internal extensions (QUAL-01) [wave 1]
- [ ] 19-04-PLAN.md — .planning/ reconciliation: prune stale blockers/todos, update traceability (DOC-01) [wave 1]
- [ ] 19-05-PLAN.md — User-facing docs: README + DECISIONS + SPEC + 2 docs/ pages (DOC-02) [wave 1]

---

## Progress

**Execution Order (v0.9.0):**

Phase 12 (SEC) must be first. Phase 13 (Privacy) and Phase 12 are sequential (avoid merge friction on crypto/redaction files). Phase 14 (Anthropic/CAP) depends on Phase 12. Phase 15 (tripwire) depends on Phase 12 and must precede Phase 19. Phase 16 (external MCP) depends on Phase 12; requires kotlin-sdk Burp-JVM test-run gate. Phase 17 (reliability) follows Phases 14 and 16 for full scope. Phase 18 (quality tooling) is independent, runs after Phase 17. Phase 19 (split + docs) is the last code phase.

| Phase | Plans Complete | Status | Completed |
|-------|----------------|--------|-----------|
| 12. Secrets at Rest & Transport Security | 4/4 | ✅ Complete | 2026-06-10 |
| 13. Privacy & Redaction Hardening | 3/3 | Complete    | 2026-06-10 |
| 14. Anthropic Backend + Token Budget + Listener Port | 3/3 | Complete    | 2026-06-10 |
| 15. Pre-Send Secret Tripwire | 3/3 | Complete    | 2026-06-11 |
| 16. External MCP Client | 5/6 | In Progress|  |
| 17. Reliability & Concurrency Hardening | 3/3 | Complete    | 2026-06-11 |
| 18. Quality Tooling & Build Hardening | 4/4 | Complete    | 2026-06-12 |
| 19. Mega-File Split + Docs | 1/5 | In Progress|  |
