---
phase: 19
slug: mega-file-split-docs
status: draft
nyquist_compliant: false
wave_0_complete: false
created: 2026-06-16
---

# Phase 19 — Validation Strategy

> Per-phase validation contract for feedback sampling during execution.
> This is a **no-behaviour-change refactor + docs** phase. The validation contract is the
> *existing* test suite staying green across every extraction — not new behavioural tests.

---

## Test Infrastructure

| Property | Value |
|----------|-------|
| **Framework** | JUnit (Kotlin) via the Gradle `test` task |
| **Config file** | `build.gradle.kts` |
| **Quick run command** | `JAVA_HOME=$(/usr/libexec/java_home -v 21) ./gradlew test` |
| **Full suite command** | `JAVA_HOME=$(/usr/libexec/java_home -v 21) ./gradlew check` |
| **Estimated runtime** | ~2–5 min (`test`); longer for `check` (detekt + ktlint + shadowJar) |

> **Build note (from research):** the JDK-21 `JAVA_HOME` prefix is mandatory — the default
> JDK (25) is incompatible with Gradle 8.12.1. `./gradlew check`/`ktlintCheck` is expected to
> run standalone after Phase 18 (QUAL-05); if it regresses, fall back to `./gradlew test` for
> the per-extraction green-check and note it (do not re-fix here).

---

## Sampling Rate

- **After every extraction commit:** Run `./gradlew test` (JDK 21) — must be green before the
  next extraction begins (SC1: "test suite passes before and after each individual extraction").
- **After each mega-file is fully split:** Run `./gradlew check` (JDK 21) — detekt + ktlint +
  full test + shadowJar, to catch any `internal` visibility-widening lint objections early.
- **Before phase verification:** `./gradlew check` green **and** `./gradlew shadowJar` builds
  the fat JAR (`Custom-AI-Agent-*.jar`) so ServiceLoader/registration is proven intact at
  package time.
- **Max feedback latency:** ~300 seconds.

---

## Per-Task Verification Map

> Rows are populated as the planner creates extraction tasks. The invariant across **every**
> code task is identical: the extraction is purely mechanical and `./gradlew test` stays green.

| Task ID | Plan | Wave | Requirement | Threat Ref | Secure Behavior | Test Type | Automated Command | File Exists | Status |
|---------|------|------|-------------|------------|-----------------|-----------|-------------------|-------------|--------|
| 19-XX-XX | XX | — | QUAL-01 | — | N/A (no behaviour change) | regression | `./gradlew test` (JDK 21) | ✅ existing suite | ⬜ pending |
| 19-XX-XX | XX | — | QUAL-01 / SC2 | — | ServiceLoader factories load; no ClassNotFoundException | regression | `./gradlew test --tests '*BackendRegistryTest*'` (JDK 21) | ✅ existing | ⬜ pending |

*Status: ⬜ pending · ✅ green · ❌ red · ⚠️ flaky*

---

## Wave 0 Requirements

- Existing infrastructure covers all phase requirements. No new test framework or fixtures
  needed — the named files' behaviour is already exercised by the current suite, and SC2 is
  covered by the existing `BackendRegistryTest`.
- DOC-01/DOC-02 are documentation deliverables verified by file-content assertions (see
  Manual-Only Verifications), not by the test runner.

---

## Manual-Only Verifications

| Behavior | Requirement | Why Manual | Test Instructions |
|----------|-------------|------------|-------------------|
| The three named files each land < ~500 lines | QUAL-01 / SC1 | Line-count check, not a unit test | `wc -l` on McpTools.kt, SettingsPanel.kt, PassiveAiScanner.kt |
| `.planning/` reflects shipped v0.7.0/v0.8.0; stale carryover pruned | DOC-01 / SC3 | Editorial review of planning docs | Inspect PROJECT/STATE/ROADMAP/REQUIREMENTS for stale entries |
| README/SPEC/DECISIONS document the 5 v0.9.0 feature areas | DOC-02 / SC4 | Editorial review | grep each doc for Anthropic / AES-256-GCM / HKDF / external MCP / token budget |
| Live docs site renders the 2 new pages at the custom domain | DOC-02 / SC5 | External GitHub-Pages deployment outside the repo | HUMAN-UAT: maintainer confirms `burp-ai-agent.six2dez.com` shows the Anthropic + external-MCP pages after Pages rebuild |

---

## Validation Sign-Off

- [ ] Every code extraction task verifies via `./gradlew test` green (regression sampling)
- [ ] Sampling continuity: no 3 consecutive tasks without an automated green-check
- [ ] SC2 covered by existing `BackendRegistryTest`
- [ ] No watch-mode flags
- [ ] Feedback latency < 300s
- [ ] `nyquist_compliant: true` set in frontmatter (flipped after plans populate the task map)

**Approval:** pending
