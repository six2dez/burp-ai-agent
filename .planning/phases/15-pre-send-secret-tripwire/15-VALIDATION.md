---
phase: 15
slug: pre-send-secret-tripwire
status: approved
nyquist_compliant: true
wave_0_complete: false
created: 2026-06-11
---

# Phase 15 — Validation Strategy

> Per-phase validation contract. Source: 15-RESEARCH.md "## Validation Architecture" (HIGH confidence).

---

## Test Infrastructure

| Property | Value |
|----------|-------|
| **Framework** | JUnit Jupiter 6.0.3 + kotlin-test + mockito-kotlin (all present) |
| **Config file** | `build.gradle.kts` (`useJUnitPlatform()`) |
| **Quick run command** | `./gradlew test --tests "*SecretTripwireTest" --tests "*EntropyTest"` |
| **Full suite command** | `./gradlew test` |
| **Estimated runtime** | quick: seconds; full suite: ~1–2 min |

> **Build note:** validate with `./gradlew test`, NOT `./gradlew ktlintCheck` (pre-existing generateBuildFlags defect).

---

## Sampling Rate

- **After every task commit:** `./gradlew test --tests "*SecretTripwireTest" --tests "*EntropyTest"`
- **After every plan wave:** `./gradlew test` (full suite — 399+ tests must stay green)
- **Before `/gsd-verify-work`:** full suite green; plus one manual Burp smoke for SC5 dialog render
- **Max feedback latency:** < 120 seconds

---

## Per-Requirement Verification Map

| SC | Behavior | Test Type | Automated Command | File |
|----|----------|-----------|-------------------|------|
| SC1 | AWS-format key (`AKIA…`) surviving BALANCED redaction → `SecretTripwire.scan(...).matched == true` (synthetic high-entropy also) | unit | `./gradlew test --tests "*SecretTripwireTest"` | ❌ W0 |
| SC2 | Legit base64 fuzz (≥20 chars, entropy ≥ threshold) ALSO `matched == true` (gate appears) AND no hook blocks — every path proceeds | unit | `./gradlew test --tests "*SecretTripwireTest"` | ❌ W0 |
| SC3 | Allowlist/detection writes an audit event with `sessionId` + TRUNCATED entropy score + shape categories; NEVER the raw value | unit | `./gradlew test` (assert `Entropy.truncatedScore(...)`; payload has sessionId/entropyScore/shapeCategories, NOT the input token) | ❌ W0 |
| SC4 | Fires (detect + audit) on ALL THREE paths: chat, scanner (single/batch/sendSingleAnalysis), MCP (redactIfNeeded) | unit (per hook) | `./gradlew test` — one test per hook, stub `supervisor.currentSessionId()`, capture `emitGlobal`, assert send still proceeds | ❌ W0 |
| SC5 | Preview dialog: banner WARN→RISK + "Send anyway"/Cancel gate when matched; Cancel default focus (logic testable; Swing render = human-UAT) | unit (logic) + human-UAT | `./gradlew test` (branch picks RISK + "Send anyway" + default Cancel when matched) | ❌ W0 (logic); manual (render) |

*Status: ⬜ pending · ✅ green · ❌ red · ⚠️ flaky*

---

## Wave 0 Requirements

- [ ] `src/test/kotlin/com/six2dez/burp/aiagent/redact/SecretTripwireTest.kt` — SC1, SC2, SC3 (no-leak), SC4 (detector half)
- [ ] `src/test/kotlin/com/six2dez/burp/aiagent/redact/EntropyTest.kt` — bits/char correctness (uniform 16-char hex ≈ 4.0; constant ≈ 0.0), MIN_TOKEN_LEN gate, charset classification, `truncatedScore` format
- [ ] Per-hook tests (SC4) for the three paths (new `SecretTripwireHooksTest.kt` or extend scanner/MCP test files) — mockito-kotlin stub `currentSessionId()`, assert audit emitted + send proceeds
- [ ] Framework install: none — JUnit Jupiter + kotlin-test + mockito-kotlin already present

> Keep `SecretTripwire`/`Entropy` AWT-free in the `redact` package (headless-testable; mirrors SecretShapes/SafeRegex).

---

## Manual-Only Verifications

| Behavior | Requirement | Why Manual | Test Instructions |
|----------|-------------|------------|-------------------|
| ContextPreviewDialog tripwire render (RISK red banner, "Send anyway" button, Cancel default focus, never hard-block) | PRIV-03/SC5/SC1/SC2 | Swing rendering | In Burp, send a chat whose post-redaction payload contains a surviving `AKIA…`/high-entropy token → confirm the RISK banner + "Send anyway"/Cancel gate appears; Cancel dismisses, "Send anyway" proceeds and is audit-logged |

---

## Validation Sign-Off

- [ ] All tasks have `<automated>` verify or Wave 0 dependencies (except SC5 render = human-UAT)
- [ ] Sampling continuity: no 3 consecutive tasks without automated verify
- [ ] Wave 0 covers all MISSING references
- [ ] No watch-mode flags
- [ ] Feedback latency < 120s
- [ ] `nyquist_compliant: true` set in frontmatter

**Approval:** approved 2026-06-11
