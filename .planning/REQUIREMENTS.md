# Requirements: Burp AI Agent — v0.9.0 (Hardening, Quality & New Capabilities)

**Defined:** 2026-06-10
**Core Value:** Bring modern AI to a real security workflow **without** leaking sensitive traffic to third-party providers — privacy controls and an audit trail are non-negotiable.

Scope = the 18 items of the approved project-review roadmap, grouped into 6 themes. Derived from `~/.claude/plans/haz-una-revision-completa-sleepy-puddle.md` and the milestone research in `.planning/research/`. New roadmap phases continue numbering from the previous milestone (Phase 12+).

Research-mandated ordering: **SEC (encrypt secrets) lands before CAP-01 (Anthropic key must be encrypted from day one)**; **QUAL-01 (mega-file split) lands last** as a pure no-behaviour-change refactor so it does not conflict with the C4/feature hooks.

## v0.9.0 Requirements

### Privacy & Redaction (PRIV) — core value

- [x] **PRIV-01** (A1): Host anonymization uses a cryptographic method consistent with its documentation — either real HKDF (HMAC-SHA256 extract/expand) **or** docs corrected to "salted SHA-256"; the forward/reverse host mapping still resolves and existing privacy-mode tests stay green. *[HKDF-vs-docs decision resolved at this item's plan-phase]*
- [x] **PRIV-02** (A2): Redaction catches secrets in request/response **bodies**, not just header lines — the leading field of an `x-www-form-urlencoded` body and a **user-configurable custom pattern list** are redacted; covered by STRICT/BALANCED unit tests and a ReDoS/perf guard on large bodies
- [x] **PRIV-03** (C4): A pre-send **secret tripwire** scans the **final redacted payload** and warns the user (warn-with-confirmation, not silent) before a high-entropy secret leaves Burp; allowlist actions are audit-logged and visibly flagged in the preview dialog
- [x] **PRIV-04** (C6): The redaction preview/coverage UI flags when a known secret shape passes through and lets the user test custom patterns against a sample request *[Phase 13 scope decision, 2026-06-10: "test custom patterns" delivered as save-time syntax + ReDoS-timeout validation (ROADMAP SC3), NOT an interactive sample-request tester — narrowing accepted by maintainer; the survived-secret preview-dialog banner is the "coverage UI flag"]*

### Secrets at Rest & Transport Security (SEC)

- [x] **SEC-01** (C2): The 7+ stored secrets (all backend API keys, `mcp.token`, `mcp.tls.keystore.password`) are **encrypted at rest** (AES-256-GCM via `javax.crypto`); a one-time idempotent migration encrypts existing plaintext values; decryption is transparent at runtime and secrets never appear in logs. *[key-bootstrap mechanism — per-install random key, resolved Phase 12]*
- [x] **SEC-02** (A3): The TLS keystore password is never exposed on a process command line (no `keytool -storepass` argv) — generated in-JVM or via `-storepass:file`/`:env`
- [x] **SEC-03** (A6): The user is warned when a configured backend base-URL resolves to a non-loopback internal/link-local address (soft SSRF guard) without blocking deliberate advanced use

### Reliability & Concurrency (REL)

- [x] **REL-01** (A4): ChatPanel session state is accessed safely with respect to the Swing EDT — no data races on the session maps (EDT-confined or thread-safe collections), verified by a concurrency test
- [x] **REL-02** (A5): Sensitive CLI temp files (prompt/context) are reliably deleted via `finally`+`deleteOnExit`; MCP server shutdown is bounded (no hang); host-anonymization maps are cleared/bounded
- [x] **REL-03** (B6): All HTTP backends apply consistent timeouts/retries and route through the `CircuitBreaker` — none can bypass `MontoyaHttpTransport`
- [x] **REL-04** (#71): The reported CLI-command-timeout failure (issue #71) is diagnosed and fixed or handled with an actionable error message, with a regression test

### Quality & Maintainability (QUAL)

- [x] **QUAL-01** (B1): The three mega-files (`McpTools.kt` 2770, `SettingsPanel.kt` 2596, `PassiveAiScanner.kt` 2480) are split into focused files with **no behaviour change** — full test suite green before/after; ServiceLoader/registration intact
- [x] **QUAL-02** (B2): Test coverage is raised for the scanner queue/dedup, CLI backend supervision, and the `cache` module (currently 0–3%)
- [x] **QUAL-03** (B3): `detekt` is added to the build and `ktlint` is enforced as a **blocking** check, each with a committed baseline so existing code does not break CI
- [x] **QUAL-04** (B4): Silently-swallowed `catch (Exception)` sites are audited and replaced with logged, contextual handling via a shared logging helper (ties to REL-04 diagnosability)
- [x] **QUAL-05** (B5): The `generateBuildFlags` step is modeled as a proper source-generating task wired via `sourceSets`, so consumers inherit the dependency automatically and `./gradlew ktlintCheck` runs standalone (removes the fragile `dependsOn` workaround)

### New Capabilities (CAP)

- [x] **CAP-01** (C1): User can select a native **Anthropic Messages API** backend with streaming, tool-use, prompt caching, and token counting — reusing OkHttp + `MontoyaHttpTransport` (no SDK that bypasses Burp), API key encrypted via SEC-01 *[Phase 14 scope decision, 2026-06-10: ships streaming (single-chunk, proxy-visible — MontoyaHttpTransport buffers, matching all existing backends) + token counting + encrypted key + model selection (SC1–SC3); **native tool-use and prompt-caching deferred to a future phase** — not in SC1–SC5, recorded in 14-CONTEXT.md Deferred Ideas]*
- [x] **CAP-02** (C3, closes #41): User can register external/custom **MCP server(s)** and the agent can call their tools — scope/unsafe-gated, external server auth tokens stored encrypted (SEC-01), with SSRF/untrusted-output safeguards
- [x] **CAP-03** (C5, closes #70): User can filter MCP proxy-history tool output by Burp **listener port**
- [x] **CAP-04** (C7): User gets per-session **token-budget guardrails** — warn at a threshold and cap at a limit (pausing the passive scanner when the hard cap fires), built on the existing `TokenTracker`

### Planning & Docs Reconciliation (DOC)

- [x] **DOC-01** (A7): `.planning/` (PROJECT, STATE, ROADMAP, REQUIREMENTS) reflects shipped v0.7.0/v0.8.0 and closed issues #62/#66/#67/#68/#69; stale carryover removed *(partially completed at milestone start; finalized when phases close)*
- [x] **DOC-02**: User-facing docs (`README.md`, `SPEC.md`, `DECISIONS.md`, `burp-ai-agent.six2dez.com`) are updated for the v0.9.0 changes (Anthropic backend, secret encryption, redaction changes, external MCP, token budgets)

## Deferred (v2 / future)

- **REL-V2-01**: Opt-in local-only structured diagnostics endpoint for self-debugging without sending anything offline — *still deferred*
- *(MCP-V2-01, user-registered MCP server #41, is promoted into this milestone as **CAP-02**.)*

## Out of Scope

Explicitly excluded for v0.9.0. Tracked to prevent scope creep.

| Feature | Reason |
|---------|--------|
| Hot-swapping backends at runtime | SPEC non-goal — stop + restart is acceptable |
| Replacing Burp's native scanner | SPEC non-goal — AI scanners are complementary, secondary to Burp evidence |
| AI backends beyond Anthropic (CAP-01) this milestone | Scope control — one new backend; others remain via OpenAI-compatible/CLI |
| Rewriting UI in JavaFX / Compose | ADR-2 locked Swing in for native Burp embedding |
| Outbound telemetry / crash reporting | Violates the core privacy contract |
| Vendoring an Anthropic SDK that embeds its own HTTP client | Would bypass `MontoyaHttpTransport` (the #69 trap) and bloat the fat JAR |
| Bouncy Castle / Tink / java-keyring as new runtime deps | Research: javax.crypto suffices for SEC-01; avoid fat-JAR/protobuf conflicts |

## Traceability

| Requirement | Phase | Status |
|-------------|-------|--------|
| SEC-01 | Phase 12: Secrets at Rest & Transport Security | Complete |
| SEC-02 | Phase 12: Secrets at Rest & Transport Security | Complete |
| SEC-03 | Phase 12: Secrets at Rest & Transport Security | Complete |
| PRIV-01 | Phase 13: Privacy & Redaction Hardening | Complete |
| PRIV-02 | Phase 13: Privacy & Redaction Hardening | Complete |
| PRIV-04 | Phase 13: Privacy & Redaction Hardening | Complete |
| CAP-01 | Phase 14: Anthropic Backend + Token Budget + Listener Port | Complete |
| CAP-03 | Phase 14: Anthropic Backend + Token Budget + Listener Port | Complete |
| CAP-04 | Phase 14: Anthropic Backend + Token Budget + Listener Port | Complete |
| PRIV-03 | Phase 15: Pre-Send Secret Tripwire | Complete |
| CAP-02 | Phase 16: External MCP Client | Complete |
| REL-01 | Phase 17: Reliability & Concurrency Hardening | Complete |
| REL-02 | Phase 17: Reliability & Concurrency Hardening | Complete |
| REL-03 | Phase 17: Reliability & Concurrency Hardening | Complete |
| REL-04 | Phase 17: Reliability & Concurrency Hardening | Complete |
| QUAL-02 | Phase 18: Quality Tooling & Build Hardening | Complete |
| QUAL-03 | Phase 18: Quality Tooling & Build Hardening | Complete |
| QUAL-04 | Phase 18: Quality Tooling & Build Hardening | Complete |
| QUAL-05 | Phase 18: Quality Tooling & Build Hardening | Complete |
| QUAL-01 | Phase 19: Mega-File Split + Docs | Complete |
| DOC-01 | Phase 19: Mega-File Split + Docs | Complete |
| DOC-02 | Phase 19: Mega-File Split + Docs | Complete |

**Coverage:**
- v0.9.0 requirements: 22 total (PRIV 4, SEC 3, REL 4, QUAL 5, CAP 4, DOC 2)
- Mapped to phases: 22/22 (100%)

---

## Shipped (historical record)

- **v0.8.0 — UI/UX Overhaul** (2026-06-02): UI-01..UI-08 (design system, MCP tools tab redesign, settings rebuilt on tokens, light/dark theme). Phases 9–11.
- **v0.7.0 — Release Cut + stabilization** (2026-05-15): PPLX-01..05 (Perplexity backend), INSP-01..04 (insertion-point scan), PROM-01..06 (prompt library UX), BUG-01 (#62 release pipeline), BUG-02 (#66 OpenAI-compatible), REL/DOC release engineering, plus Phase 7 (#69 proxy transport + MCP scope) and Phase 8 (#231 BApp Store resubmission). Phases 1–8.

---
*Requirements defined: 2026-06-10 — milestone v0.9.0*
