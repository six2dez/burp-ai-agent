# Phase 1: Perplexity Backend Audit - Discussion Log

> **Audit trail only.** Do not use as input to planning, research, or execution agents.
> Decisions are captured in CONTEXT.md — this log preserves the alternatives considered.

**Date:** 2026-05-13
**Phase:** 1-perplexity-backend-audit
**Areas discussed:** Defaults policy (model + URL), Test scope and depth, Live success criterion (#5) verification, Settings migration test, Documentation reconciliation

**Mode:** non-interactive (user invoked `/gsd-discuss-phase 1` with the "no clarifying questions" override in effect). Claude analysed the shipped code (`PerplexityBackendFactory.kt`, `OpenAiCompatibleBackend.kt`, `AgentSettings.kt`, `BackendConfigPanel.kt`, `META-INF/services/...AiBackendFactory`), the requirements (PPLX-01..05 in `.planning/REQUIREMENTS.md`), the ROADMAP success criteria, the codebase intel under `.planning/codebase/`, and the `[Unreleased]` CHANGELOG block, then picked the reasonable engineering call for each gray area.

---

## Default model field — pre-populate vs. free-form

| Option | Description | Selected |
|--------|-------------|----------|
| Pre-populate `perplexityModel = "sonar"` | Match ROADMAP success criterion #1 wording literally; commit a default model and lock it with a test. | |
| Keep `perplexityModel = ""` (free-form) | Honour the CHANGELOG's explicit design choice ("free-form field so any future Perplexity model name works without an extension update"). UI tooltip already lists sonar-family suggestions. | ✓ |
| UI placeholder only | Show `sonar` as a placeholder string in the JTextField without writing it to settings. | |

**Choice:** keep free-form (D-01).
**Notes:** ROADMAP wording is sloppy — the audit verifies the shipped behaviour, and Phase 5 (Docs Refresh) clarifies the wording. Hard-coding `"sonar"` would freeze a choice that Perplexity changes faster than our release cadence.

---

## Default URL form — bare host vs. fully-resolved path

| Option | Description | Selected |
|--------|-------------|----------|
| `perplexityUrl = "https://api.perplexity.ai/chat/completions"` | Make the stored default match the literal string in ROADMAP success criterion #1. | |
| `perplexityUrl = "https://api.perplexity.ai"` (bare host) | Keep shipped behaviour; `buildChatCompletionsUrl` resolves to `/chat/completions` at request time. Matches convention used by other HTTP backends in this codebase. | ✓ |
| Show resolved URL in tooltip / placeholder only | Cosmetic UI change. | |

**Choice:** keep bare host (D-02).
**Notes:** The ROADMAP's `(https://api.perplexity.ai/chat/completions, ...)` describes the resolved runtime URL, not the field value. Changing the stored default would force a migration step for users who haven't touched the field; the current shape is correct and idempotent.

---

## Test depth — reflection vs. wire capture

| Option | Description | Selected |
|--------|-------------|----------|
| Reflection on private fields | Use Java reflection to read `chatCompletionsBasePath` / `supportsJsonObjectResponseFormat` from the constructed `OpenAiCompatibleBackend`. Fast but brittle. | |
| `MockWebServer` wire capture | Spin OkHttp's `MockWebServer`, point the backend at it, capture `RecordedRequest`, assert path + body. Durable across internal refactors. | ✓ |
| Real-API integration test | Hit the live Perplexity endpoint with a real API key in CI. | |

**Choice:** MockWebServer wire capture, fast suite only (D-04, D-05).
**Notes:** This codebase already uses MockWebServer-style harnesses (`McpServerIntegrationTest`); the test helpers are in `src/test/kotlin/com/six2dez/burp/aiagent/backends/http/`. Behavioural assertions also lock the URL builder, JSON-mode skip, and bearer header in one shot.

---

## Success criterion #5 — live API confirmation

| Option | Description | Selected |
|--------|-------------|----------|
| Env-gated nightly integration test | Skip in CI without `PERPLEXITY_API_KEY` env var; run nightly with a real key. | |
| Manual smoke recorded in verification notes | One-time confirmation by the maintainer, captured as a short paragraph (key source, date, model, request count, response hash). | ✓ |
| Both | Manual smoke + env-gated nightly test. | |

**Choice:** manual smoke only (D-06).
**Notes:** Perplexity API requires a paid key. Project convention is no external secrets in CI. A manual one-time smoke recorded in `01-VERIFICATION.md` gives equivalent regression guard alongside the permanent unit tests.

---

## Settings migration test — coverage shape

| Option | Description | Selected |
|--------|-------------|----------|
| New top-level test file | `PerplexityMigrationTest.kt` for PPLX-05 in its own file. | |
| Extend `AgentSettingsMigrationTest` | Add a `@Test` method to the existing file using its `InMemoryPrefs` helper. Matches the convention of co-locating schema-migration assertions. | ✓ |
| Inline assertion in `PerplexityBackendFactoryTest` | Tangle migration concerns with backend wire-shape concerns. | |

**Choice:** extend `AgentSettingsMigrationTest` (D-07).
**Notes:** Keeps schema-migration locks discoverable in one file; the test asserts schema version stays at 3 and the five perplexity fields default safely when v0.6.x preferences (no `perplexity.*` keys) are loaded.

---

## Documentation reconciliation — fix here vs. Phase 5

| Option | Description | Selected |
|--------|-------------|----------|
| Fix ROADMAP / SPEC wording in Phase 1 | Edit ROADMAP success criterion #1 phrasing and SPEC §4.4 in this audit phase. | |
| Capture as `KNOWN-WORDING-GAP` and hand to Phase 5 | Audit records both gaps; Phase 5 (Documentation Refresh) owns the rewording. | ✓ |

**Choice:** defer to Phase 5 (D-08).
**Notes:** Phase 5 is the documentation phase by design; doing the rewording here would scope-creep the audit. The audit's verification notes list the two gaps so Phase 5 can pick them up.

---

## Claude's Discretion

- Exact MockWebServer harness vs. custom `Interceptor` — planner picks based on what already exists in `src/test/kotlin/com/six2dez/burp/aiagent/backends/http/` (researcher inventories first).
- Whether to widen visibility on `OpenAiCompatibleConnection.chatCompletionsBasePath` to `internal` — only if behavioural assertions cannot reach the lock without it.
- Exact test method naming convention (CamelCase vs backtick-quoted) — both accepted in this codebase.

## Deferred Ideas

- Perplexity model dropdown / `/models` endpoint fetch.
- Citation / source field handling for Sonar responses.
- `Retry-After`-aware rate limit handling on the shared HTTP layer.
- Env-gated nightly real-API integration test (revisit when project CI-secrets policy is updated).
- Refactoring the two duplicate `buildChatCompletionsUrl` implementations into a shared helper.
