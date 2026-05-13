# Phase 1: Perplexity Backend Audit — Verification Record

**Created:** 2026-05-13
**Phase:** 01-perplexity-backend-audit
**Plan:** 01-01

---

## D-06 — Manual end-to-end Perplexity smoke (PPLX-02 + ROADMAP §Phase 1 SC#5)

> [ ] Maintainer to fill — record on first maintainer pass with a real Perplexity API key.

- `api_key_source:` pending — maintainer-personal-pplx-key (NOT in CI, NOT committed)
- `date:` pending — recorded on first maintainer pass
- `model:` pending — Sonar-family model (e.g. sonar, sonar-pro)
- `request_count:` pending — integer (e.g. 1)
- `observed_streamed_completion:` pending — short description (e.g. streamed delta chunks rendered in chat panel, final assistant message rendered without truncation)
- `response_body_sha256:` pending — 64-char hex SHA-256 of the captured response body (maintainer computes from audit log when verbose mode is enabled per ADR-7)

**Note (D-06):** Perplexity requires a paid API key; CI does not own one and project convention forbids real secrets in CI. ROADMAP success criterion #5 ("Running a real prompt … returns a streamed chat completion end-to-end") is satisfied by this one-time manual smoke — not by a permanent integration test. No pplx-* key or response body is committed here.

---

## D-08 — Known wording gaps handed off to Phase 5 (Documentation Refresh)

These are documentation gaps only — they do NOT block Phase 1 sign-off. Both will be resolved in Phase 5.

- `KNOWN-WORDING-GAP: ROADMAP §Phase 1 SC#1 — tooltip suggests Sonar-family names; field is not pre-filled (Phase 5 to clarify the wording)`
- `KNOWN-WORDING-GAP: SPEC §4.4 — Perplexity not yet listed in the pluggable HTTP backend table (Phase 5 to add Perplexity)`

**Context:**
1. ROADMAP success criterion #1 uses the phrase "Sonar-family model pre-population" — the audit confirms the field is free-form blank by default (D-01) and the tooltip in `BackendConfigPanel` lists Sonar-family names as examples. Phase 5 (Docs Refresh) will clarify the wording so it aligns with what shipped.
2. SPEC.md §4.4 currently lists five HTTP backends (Ollama, LM Studio, NVIDIA NIM, Generic OpenAI-compatible, Burp native AI) but omits Perplexity. Phase 5 will add Perplexity to §4.4.

---

## Automated verification summary

All three Gradle invocations were run during T4 (Task 4: Full-phase verification) on 2026-05-13.

| Command | Timestamp (UTC) | Exit code |
|---------|-----------------|-----------|
| `./gradlew test -PexcludeHeavyTests=true` | 2026-05-13T09:06:xx | exit 0 |
| `./gradlew ktlintCheck` | 2026-05-13T09:06:xx | exit 0 |
| `./gradlew compileKotlin compileTestKotlin` | 2026-05-13T09:06:xx | exit 0 |

**Test classes verified passing:**
- `PerplexityBackendFactoryTest` — 5 tests (PPLX-02 URL edge cases + PPLX-03 no response_format)
- `OpenAiCompatibleBackendDefaultsTest` — 2 tests (PPLX-04 backwards-compat defaults)
- `AgentSettingsMigrationTest` — all existing tests + 1 new (PPLX-05 v0.6.x prefs safe defaults)

**Production code unchanged:** `git diff --stat src/main/kotlin/` returns no entries — zero production code modified (audit phase, tests only).
