---
phase: 16
slug: external-mcp-client
status: approved
nyquist_compliant: true
wave_0_complete: false
created: 2026-06-15
---

# Phase 16 — Validation Strategy

> Per-phase validation contract for feedback sampling during execution.

---

## Test Infrastructure

| Property | Value |
|----------|-------|
| **Framework** | JUnit Jupiter (JUnit Platform) + Mockito-Kotlin 5.4.0 |
| **Config file** | `build.gradle.kts` — `useJUnitPlatform()` (`-ea` assertions on) |
| **Quick run command** | `./gradlew test -PexcludeHeavyTests=true --no-daemon` |
| **Full suite command** | `./gradlew test --no-daemon` |
| **Estimated runtime** | ~60–120 seconds (full) |

---

## Sampling Rate

- **After every task commit:** `./gradlew test -PexcludeHeavyTests=true --no-daemon`
- **After every plan wave:** `./gradlew test --no-daemon`
- **Before `/gsd-verify-work`:** `./gradlew check --no-daemon` (detekt + strict ktlint + tests) must be green
- **Max feedback latency:** ~120 seconds

---

## Per-Task Verification Map

> Task IDs are assigned by the planner ({plan}-T{task}); rows map each CAP-02 success criterion to its verification.

| Task ID | Plan | Wave | Requirement | Threat Ref | Secure Behavior | Test Type | Automated Command | File Exists | Status |
|---------|------|------|-------------|------------|-----------------|-----------|-------------------|-------------|--------|
| 16-xx-xx | client | — | CAP-02/SC1 | T-16-tool-collision | External tools appear as `ext:<server>:<tool>` in preamble after connect | integration | `./gradlew test --tests "*.ExternalMcpClientManagerTest" --no-daemon` | ❌ W0 | ⬜ pending |
| 16-xx-xx | client | — | CAP-02/SC2 | T-16-prompt-injection | External tool results wrapped in trust-boundary marker; invocation audit-logged | unit | `./gradlew test --tests "*.ExternalMcpClientManagerTest.trustBoundary*" --no-daemon` | ❌ W0 | ⬜ pending |
| 16-xx-xx | config | — | CAP-02/SC3 | T-16-ssrf | RFC-1918 / link-local SSE URL triggers soft SSRF warning | unit | `./gradlew test --tests "*.SsrfGuardTest" --no-daemon` | ✅ existing | ⬜ pending |
| 16-xx-xx | config | — | CAP-02/SC4 | T-16-token-leak | Bearer tokens encrypted at rest (SecretCipher); schema-v5 migration round-trips | unit | `./gradlew test --tests "*.SecretCipherTest" --tests "*.ExternalMcpSettingsMigrationTest" --no-daemon` | ⚠ partial — new migration test | ⬜ pending |
| 16-xx-xx | build | — | CAP-02/SC5 | T-16-classloader | Extension loads after ktor-client-cio:3.1.3 added; no ClassLoader/NoClassDefFound on Burp JVM | smoke | `./gradlew shadowJar --no-daemon` + manual Burp load (HUMAN-UAT) | ❌ manual | ⬜ pending |

*Status: ⬜ pending · ✅ green · ❌ red · ⚠️ flaky*

---

## Wave 0 Requirements

- [ ] `src/test/kotlin/.../mcp/external/ExternalMcpClientManagerTest.kt` — lifecycle (connect/list/call), trust-boundary wrap (SC2), tool-name `ext:` disambiguation (SC1), reconnect/timeout behavior, stdio process cleanup
- [ ] `src/test/kotlin/.../config/ExternalMcpSettingsMigrationTest.kt` — schema-v5 migration round-trip (encrypt/decrypt external-server token; idempotency) (SC4)

*Existing `SsrfGuardTest` (SC3) and `SecretCipherTest` (SC4 foundation) require no new framework setup.*

---

## Manual-Only Verifications

| Behavior | Requirement | Why Manual | Test Instructions |
|----------|-------------|------------|-------------------|
| Connect to a REAL external MCP server (SSE + stdio); tools appear and are callable | CAP-02/SC1 | Needs a live external MCP server | Add a real SSE and a real stdio MCP server in the MCP settings; confirm tools appear as `ext:<server>:<tool>` and a tool call returns a result |
| Extension loads in live Burp after the 3 client deps; embedded server still starts; UI responsive | CAP-02/SC5 | Burp bundles its own Kotlin runtime — must confirm no ClassLoader conflict on the real JVM | `./gradlew shadowJar`, load `Custom-AI-Agent-*.jar` in Burp, confirm load + MCP tab responsive + no `NoClassDefFoundError` in Output/Errors |

*Note: Path A (no Kotlin bump) makes SC5 a standard smoke test, not the blocking gate the 0.13.0 bump would have required.*

---

## Validation Sign-Off

- [ ] All tasks have `<automated>` verify or Wave 0 dependencies (SC5 is documented manual-only)
- [ ] Sampling continuity: no 3 consecutive tasks without automated verify
- [ ] Wave 0 covers all MISSING references (2 new test files)
- [ ] No watch-mode flags (`--no-daemon`; no `--continuous`)
- [ ] Feedback latency < 120s
- [x] `nyquist_compliant: true` (all SCs have automated verify except SC5, which is documented manual-only)

**Approval:** approved 2026-06-15
