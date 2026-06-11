---
phase: 17
slug: reliability-concurrency-hardening
status: approved
nyquist_compliant: true
wave_0_complete: false
created: 2026-06-11
---

# Phase 17 — Validation Strategy

> Per-phase validation contract. Source: 17-RESEARCH.md "## Validation Architecture" (HIGH confidence).

---

## Test Infrastructure

| Property | Value |
|----------|-------|
| **Framework** | JUnit Jupiter 6.0.3 + mockito-kotlin 5.4.0 + mockwebserver 4.12.0 |
| **Config file** | `build.gradle.kts` (`useJUnitPlatform()`); ensure `-ea` is enabled so EDT `assert`s fire |
| **Quick run command** | `./gradlew test --tests "com.six2dez.burp.aiagent.<TargetTest>"` |
| **Full suite command** | `./gradlew test` |
| **Estimated runtime** | quick: seconds; full suite: ~1–2 min |

> **Build note:** validate with `./gradlew test`, NOT `./gradlew ktlintCheck` (generateBuildFlags defect).

---

## Sampling Rate

- **After every task commit:** the specific new test (`--tests` filter below)
- **After every plan wave:** `./gradlew test` (full suite — must stay green; this phase touches shared paths)
- **Before `/gsd-verify-work`:** full suite green. Regression watch: `RedactionTest`, `CircuitBreakerTest`, `HttpBackendTransportRoutingTest`, `AnthropicModelErrorTest`, MCP server/restart tests
- **Max feedback latency:** < 120 seconds

---

## Per-Requirement Verification Map

| SC | Behavior | Test Type | Automated Command | File |
|----|----------|-----------|-------------------|------|
| SC1 | No data race on the 4 ChatPanel session maps under concurrent EDT-mutation + off-EDT reads | concurrency | `./gradlew test --tests "*ChatPanelConcurrencyTest"` | extend/new |
| SC2 | CLI temp files (`uv` prompt, codex output) deleted in `finally` AND on crash (`deleteOnExit`) | unit (forced-failure) | `./gradlew test --tests "*CliBackendTempFileTest"` | ❌ W0 |
| SC3 | Each HTTP backend routes 429/5xx through `recordFailure` (breaker opens after threshold); uniform timeout via transport | unit (transport spy) | `./gradlew test --tests "*HttpBackendCircuitFailureTest"` | ❌ W0 |
| SC4 | #71 — slow/hanging CLI yields an actionable timeout message naming the configurable limit | unit (extracted builder) | `./gradlew test --tests "*CliTimeoutMessageTest"` | ❌ W0 |
| SC5a | `McpServerManager.stop()` completes within the bound, never hangs (shutdown() already bounded) | integration | `./gradlew test --tests "*McpShutdownBoundTest"` | ❌ W0 |
| SC5b | Host-anonymization maps stay bounded under many distinct hosts; round-trip + format preserved | unit | `./gradlew test --tests "*RedactionHostMapBoundTest"` | ❌ W0 |

*Status: ⬜ pending · ✅ green · ❌ red · ⚠️ flaky*

---

## Wave 0 Requirements

- [ ] `util/GuardedBy.kt` — local SOURCE-retained `@GuardedBy` annotation (no JCIP/jsr305 on classpath; prerequisite for REL-01)
- [ ] `backends/cli/CliBackendTempFileTest.kt` — SC2 (temp-file finally + deleteOnExit on failure)
- [ ] `backends/http/HttpBackendCircuitFailureTest.kt` — SC3 (429/5xx → recordFailure for OpenAiCompatible[+NVIDIA/Perplexity], Anthropic, Ollama, LmStudio)
- [ ] `backends/cli/CliTimeoutMessageTest.kt` — SC4 (#71 actionable message; test the extracted `buildTimeoutMessage`)
- [ ] `mcp/McpShutdownBoundTest.kt` — SC5a (bounded `stop()`)
- [ ] `redact/RedactionHostMapBoundTest.kt` — SC5b (LRU bound + round-trip preserved)
- [ ] Extend/new `ui/ChatPanelConcurrencyTest.kt` — SC1 (map confinement under concurrency)
- [ ] Verify `tasks.test` enables assertions (`jvmArgs("-ea")`) so the EDT `assert` fires
- [ ] Framework install: none — JUnit Jupiter + mockito-kotlin + mockwebserver already present

---

## Manual-Only Verifications

| Behavior | Requirement | Why Manual | Test Instructions |
|----------|-------------|------------|-------------------|
| Issue #71 actionable timeout end-to-end | REL-04/SC4 | Needs a fresh machine running `npx @google/gemini-cli` (first-run download > timeout) | In Burp with the CLI backend, run the #71 repro command on a machine without the CLI cached → confirm the actionable timeout message naming the configurable limit, and that raising the new `cliTimeoutSeconds` setting lets it complete |

> The automated regression for #71 is the extracted-message unit test (`CliTimeoutMessageTest`); the live npx run is the human smoke check.

---

## Validation Sign-Off

- [ ] All tasks have `<automated>` verify or Wave 0 dependencies (except the #71 live npx smoke = human-UAT)
- [ ] Sampling continuity: no 3 consecutive tasks without automated verify
- [ ] Wave 0 covers all MISSING references
- [ ] No watch-mode flags
- [ ] Feedback latency < 120s
- [ ] `nyquist_compliant: true` set in frontmatter

**Approval:** approved 2026-06-11
