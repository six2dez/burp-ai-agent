---
phase: 14
slug: anthropic-backend-token-budget-listener-port
status: draft
nyquist_compliant: false
wave_0_complete: false
created: 2026-06-10
---

# Phase 14 — Validation Strategy

> Per-phase validation contract. Source: 14-RESEARCH.md "## Validation Architecture" (HIGH confidence).

---

## Test Infrastructure

| Property | Value |
|----------|-------|
| **Framework** | JUnit 5 (Jupiter) + Mockito-Kotlin (`org.mockito.kotlin`) |
| **Config file** | Gradle `test` task — no separate junit config |
| **Quick run command** | `./gradlew test --tests "*Anthropic*"` (or the specific new test class) |
| **Full suite command** | `./gradlew test` |
| **Estimated runtime** | quick: seconds; full suite: ~1–2 min |

> **Build note:** validate with `./gradlew test`. Do NOT gate on `./gradlew ktlintCheck` (pre-existing generateBuildFlags defect, per CLAUDE.md/MEMORY).

---

## Sampling Rate

- **After every task commit:** `./gradlew test --tests "*Anthropic*"` (or the new test class)
- **After every plan wave:** `./gradlew test` (full suite — 358+ tests must stay green)
- **Before `/gsd-verify-work`:** full suite green; SC1 manual smoke with a live Anthropic key
- **Max feedback latency:** < 120 seconds

---

## Per-Requirement Verification Map

| SC | Behavior | Test Type | Automated Command | File |
|----|----------|-----------|-------------------|------|
| SC1 | Streaming chat works end-to-end with a live key (proxy-visible) | **manual-UAT** | — (human; needs live `x-api-key`) | HUMAN-UAT |
| SC2a | `AnthropicBackend.send()` issues HTTP only via injected transport to `api.anthropic.com/v1/messages` | unit | `./gradlew test --tests "*AnthropicBackendTransportRoutingTest*"` (spy transport) | ❌ W0 |
| SC2b | `send()` with `transport == null` fails fast (no OkHttp fallback) | unit | same file (asserts "transport unavailable" error) | ❌ W0 |
| SC2c | `grep OkHttp AnthropicBackend.kt` empty | source-string guard | test asserts source has no `okhttp3`/`OkHttpClient` | ❌ W0 |
| SC3 | 400 body containing "model" → exact SC3 string | unit | `*AnthropicModelErrorTest*` (stub 400 "...model..."; assert onComplete error == SC3 string) | ❌ W0 |
| SC4a | Crossing warn → WARN banner; crossing cap → RISK + scanner paused | unit | `*BudgetGuardTest*` (drive used past warn then cap; assert level + pause decision) | ❌ W0 |
| SC4b | `enqueueForScanCheck` is a no-op when `budgetPaused` (NOT setEnabled — that clears KB) | unit | `*PassiveAiScannerBudgetPauseTest*` | ❌ W0 |
| SC4c | warn=0 & cap=0 → never pauses, never banners (off by default) | unit | `*BudgetGuardTest*` zero-thresholds case | ❌ W0 |
| SC5 | `proxy_http_history` filtered by `listener_port` → only that port; no match → empty (not error); unset → all. Filter added to BOTH dispatch paths in McpTools.kt | unit | `*ProxyHistoryListenerPortFilterTest*` | ❌ W0 |
| reg | `AnthropicBackendFactory` registered + `KEY_ANTHROPIC_API_KEY` round-trips encrypted | unit | extend `BackendRegistryTest` + `AgentSettings` round-trip | ⚠️ extend |

*Status: ⬜ pending · ✅ green · ❌ red · ⚠️ flaky*

---

## Wave 0 Requirements

- [ ] `backends/anthropic/AnthropicBackendTransportRoutingTest.kt` — SC2a/b/c (model on `HttpBackendTransportRoutingTest`, reuse its spy-transport helper)
- [ ] `backends/anthropic/AnthropicModelErrorTest.kt` — SC3 (stub 400 "model" body)
- [ ] `util/BudgetGuardTest.kt` (or equivalent) — SC4a/SC4c thresholds → {OFF, WARN, CAP} enum (pure AWT-free helper)
- [ ] `scanner/PassiveAiScannerBudgetPauseTest.kt` — SC4b enqueue no-op when paused
- [ ] `mcp/tools/ProxyHistoryListenerPortFilterTest.kt` — SC5 (both dispatch paths)
- [ ] Extend `backends/BackendRegistryTest.kt` (Anthropic registered) + `AgentSettings` round-trip for the new encrypted key
- [ ] Framework install: none — JUnit 5 + Mockito-Kotlin already present

> Keep the budget comparison in a pure `BudgetGuard` object (used/warn/cap → {OFF, WARN, CAP}) so SC4 logic is testable without Swing; ChatPanel just renders the enum. Mirrors Phase 13's AWT-free `SecretShapes`.

---

## Manual-Only Verifications

| Behavior | Requirement | Why Manual | Test Instructions |
|----------|-------------|------------|-------------------|
| Anthropic chat streams end-to-end through the proxy | CAP-01/SC1 | Needs a live Anthropic API key + running Burp; proxy-visibility is observed, not unit-asserted | In Burp: Settings>Backend>Anthropic, enter a real key + `claude-sonnet-4-6`, send a chat; confirm a reply arrives AND the request appears in Proxy>HTTP history (to `api.anthropic.com`) |
| Invalid-model 400 surfaces the SC3 message | CAP-01/SC3 | Confirm the live 400 body actually contains "model" (research assumption A1) | Set model to a bogus ID, send; confirm the specific "Anthropic rejected the model ID…" message appears |
| Token-budget banner renders (WARN/RISK) | CAP-04/SC4 | Swing rendering | Set a low warn+cap, send chats until thresholds cross; confirm WARN banner then RISK banner + passive scanner paused |

---

## Validation Sign-Off

- [ ] All tasks have `<automated>` verify or Wave 0 dependencies (except SC1 human-UAT)
- [ ] Sampling continuity: no 3 consecutive tasks without automated verify
- [ ] Wave 0 covers all MISSING references
- [ ] No watch-mode flags
- [ ] Feedback latency < 120s
- [ ] `nyquist_compliant: true` set in frontmatter

**Approval:** pending
