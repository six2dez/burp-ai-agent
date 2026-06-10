---
phase: 13
slug: privacy-redaction-hardening
status: draft
nyquist_compliant: false
wave_0_complete: false
created: 2026-06-10
---

# Phase 13 — Validation Strategy

> Per-phase validation contract for feedback sampling during execution.
> Source: 13-RESEARCH.md "## Validation Architecture" (HIGH confidence).

---

## Test Infrastructure

| Property | Value |
|----------|-------|
| **Framework** | JUnit Jupiter 6.0.3 (`org.junit.jupiter:junit-jupiter`) |
| **Config file** | `build.gradle.kts` (tests in `src/test/kotlin`) |
| **Quick run command** | `./gradlew test --tests "com.six2dez.burp.aiagent.redact.*"` |
| **Full suite command** | `./gradlew test` |
| **Estimated runtime** | ~quick: seconds; full suite: ~1–2 min |

> **Build note (MEMORY):** `./gradlew ktlintCheck` fails standalone due to a pre-existing
> `generateBuildFlags` wiring defect (unrelated to this phase). Validate with `./gradlew test`;
> do NOT gate Phase 13 on `ktlintCheck`.

---

## Sampling Rate

- **After every task commit:** Run `./gradlew test --tests "com.six2dez.burp.aiagent.redact.*"`
- **After every plan wave:** Run `./gradlew test`
- **Before `/gsd-verify-work`:** Full suite must be green (~308 tests baseline at v0.8.0)
- **Max feedback latency:** < 120 seconds

---

## Per-Requirement Verification Map

> Task IDs assigned by the planner; rows below map each requirement/behavior to its automated proof.

| Requirement | Behavior | Test Type | Automated Command | File Exists |
|-------------|----------|-----------|-------------------|-------------|
| PRIV-01 | HKDF determinism: same (salt,host) → same anon; different salt → different | unit | `./gradlew test --tests "*RedactionTest.hostAnonymizationIsStablePerSalt"` | ✅ existing |
| PRIV-01 | Output format stays `host-<12hex>.local` (`host-[0-9a-f]{12}\.local`) | unit | `./gradlew test --tests "*RedactionTest"` | ❌ W0 (add assertion) |
| PRIV-01 | HKDF matches RFC 5869 Test Case 1 (PRK/OKM) — correct construction | unit | `./gradlew test --tests "*RedactionTest.hkdfMatchesRfc5869Vector"` | ❌ W0 |
| PRIV-01 | forward/reverse map still resolves after HKDF swap | unit | `./gradlew test --tests "*RedactionTest.clearMappings*"` | ✅ existing |
| PRIV-01 | STRICT still strips cookies/tokens/hosts (no regression) | unit | `./gradlew test --tests "*RedactionTest.strictMode*"` | ✅ existing |
| PRIV-02 | Leading form-body field `apikey=sk-abc123&…` redacted (STRICT+BALANCED) | unit | `./gradlew test --tests "*RedactionTest.bodyFormLeadingFieldRedacted"` | ❌ W0 |
| PRIV-02 | JSON `"api_key":"…"`/`"token":"…"` redacted; `"name":"alice"` untouched | unit | `./gradlew test --tests "*RedactionTest.bodyJsonSecretKeysRedacted"` | ❌ W0 |
| PRIV-02 | OFF mode leaves bodies untouched | unit | `./gradlew test --tests "*RedactionTest.offModePreservesBodies"` | ❌ W0 |
| PRIV-02 | Custom pattern applied STRICT+BALANCED, inactive OFF | unit | `./gradlew test --tests "*RedactionTest.customPatternRedacts*"` | ❌ W0 |
| PRIV-02 | Body over size cap short-circuited (not hung, not redacted) | unit | `./gradlew test --tests "*RedactionTest.oversizeBodySkippedSafely"` | ❌ W0 |
| PRIV-02 / SC3 | `SafeRegex.isPatternSafe("(a+)+$")`==false within budget; `"\\d+"`==true | unit | `./gradlew test --tests "*SafeRegexTest"` | ❌ W0 (new file) |
| PRIV-02 / SC3 | `replaceAllSafe` returns input unchanged (no hang) on catastrophic pattern | unit | `./gradlew test --tests "*SafeRegexTest.catastrophicPatternTimesOutAndReturnsInput"` | ❌ W0 |
| PRIV-02 | Custom-pattern persistence round-trips through settings (mock Preferences) | unit | `./gradlew test --tests "*AgentSettings*"` | ❌ W0 (extend) |
| PRIV-04 | `SecretShapes.findSurviving` detects each shape (positive) + rejects benign (negative) | unit | `./gradlew test --tests "*SecretShapesTest"` | ❌ W0 (new file) |
| PRIV-04 | Banner logic: survivors → WARN; clean → hidden (pure logic, no Swing) | unit | `./gradlew test --tests "*SecretShapesTest.findSurvivingReturnsCategories"` | ❌ W0 |

*Status: ⬜ pending · ✅ green · ❌ red · ⚠️ flaky*

---

## Wave 0 Requirements

- [ ] `src/test/kotlin/com/six2dez/burp/aiagent/redact/SafeRegexTest.kt` — PRIV-02 SC3 (ReDoS guard)
- [ ] `src/test/kotlin/com/six2dez/burp/aiagent/redact/SecretShapesTest.kt` — PRIV-04 detection (positive + negative)
- [ ] Extend `src/test/kotlin/com/six2dez/burp/aiagent/redact/RedactionTest.kt` — body/form/JSON STRICT/BALANCED/OFF + HKDF format + RFC vector + custom-pattern cases
- [ ] Extend existing `AgentSettings` test — custom-pattern persistence round-trip (mock `Preferences` via mockito-kotlin)
- [ ] Framework install: none — JUnit Jupiter 6.0.3 already configured

---

## Manual-Only Verifications

| Behavior | Requirement | Why Manual | Test Instructions |
|----------|-------------|------------|-------------------|
| Custom-pattern text area renders + inline validation feedback shows on Save | PRIV-02 | Swing rendering not unit-tested (project convention) | In Burp, open Privacy settings, paste `(a+)+$`, Save → see rejection notice; paste `\d{6}`, Save → accepted |
| Survived-secret WARN banner appears in pre-send preview | PRIV-04 | Swing rendering not unit-tested | Trigger a Send with a payload containing a surviving `sk-proj-…` shape → preview dialog shows non-blocking WARN banner naming the shape category |

> The *logic* behind both (`SafeRegex.isPatternSafe`, `SecretShapes.findSurviving`) IS unit-tested above —
> that is the Nyquist-meaningful coverage. Keep `SecretShapes`/`SafeRegex` free of AWT imports so they
> stay headless-testable and reusable by the Phase 15 tripwire.

---

## Validation Sign-Off

- [ ] All tasks have `<automated>` verify or Wave 0 dependencies
- [ ] Sampling continuity: no 3 consecutive tasks without automated verify
- [ ] Wave 0 covers all MISSING references (SafeRegexTest, SecretShapesTest, RedactionTest extensions)
- [ ] No watch-mode flags
- [ ] Feedback latency < 120s
- [ ] `nyquist_compliant: true` set in frontmatter

**Approval:** pending
