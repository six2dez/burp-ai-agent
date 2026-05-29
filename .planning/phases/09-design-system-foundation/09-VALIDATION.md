---
phase: 9
slug: design-system-foundation
status: draft
nyquist_compliant: false
wave_0_complete: false
created: 2026-05-29
---

# Phase 9 — Validation Strategy

> Test contract for the design-system foundation module. Source: 09-UI-SPEC.md + Phase 9 success criteria (ROADMAP). Framework: JUnit 5 + Mockito-Kotlin (existing).

---

## Test Infrastructure

| Property | Value |
|----------|-------|
| **Framework** | JUnit 5 (6.0.3) + Mockito-Kotlin 5.4.0 |
| **Config file** | `build.gradle.kts` — `tasks.test { useJUnitPlatform() }` |
| **Quick run command** | `./gradlew test -PexcludeHeavyTests=true` |
| **Full suite command** | `./gradlew test` |
| **Estimated runtime** | ~30s quick |

Swing tokens/components are testable headless: drive light/dark by mutating `UIManager` defaults in-test (`UIManager.put(key, color)`), build components on the EDT-free path, assert on resolved values/structure. No screenshot/visual tests.

---

## Per-Requirement Verification Map

| Req | Behavior | Test Type | Automated Command | File |
|-----|----------|-----------|-------------------|------|
| UI-01 (tokens) | Spacing tokens are the documented multiples of 4 (4/8/12/16/24 + pads=8) | unit | `./gradlew test --tests "*.DesignTokensTest"` | ❌ W0 |
| UI-01 (color roles) | Each color role resolves from a `UIManager` key (no hardcoded `Color(...)` literals in the token layer); re-resolves when UIManager light→dark changes | unit | `./gradlew test --tests "*.DesignTokensTest"` | ❌ W0 |
| UI-01 (typography) | Type roles derive from the Swing base font via `deriveFont` (3 distinct sizes, 2 weights) | unit | `./gradlew test --tests "*.DesignTokensTest"` | ❌ W0 |
| UI-08 (theme) | Tokens load without throwing under both a light and a dark `UIManager` setup (headless) | unit | `./gradlew test --tests "*.DesignTokensTest"` | ❌ W0 |
| UI-01 (components) | Each builder (`sectionPanel`, `formGrid`/`addRowFull`/`addRowPair`, `helpLabel`, `primaryButton`, `secondaryButton`, `buildTabPanel`, `toolBadge`) returns a configured non-null component applying tokens | unit | `./gradlew test --tests "*.DesignComponentsTest"` | ❌ W0 |
| UI-07 (no regression) | Existing UiTheme.kt consumers + full suite stay green after extraction | unit (existing) | `./gradlew test` | ✅ |

---

## Wave 0 Requirements

- [ ] `src/test/kotlin/com/six2dez/burp/aiagent/ui/design/DesignTokensTest.kt` — spacing/typography/color-role resolution + light/dark headless
- [ ] `src/test/kotlin/com/six2dez/burp/aiagent/ui/design/DesignComponentsTest.kt` — each builder constructs + applies tokens

*Existing UI tests (if any) + the full suite cover UI-07 regression.*

---

## Manual-Only Verifications

| Behavior | Why Manual | Test Instructions |
|----------|------------|-------------------|
| Visual parity / no obvious regressions in existing panels | Swing rendering is visual | Load full JAR in Burp; open Settings tabs; confirm layout looks consistent in light AND dark theme (real check lands in phases 10-11 which adopt the system) |

---

## Validation Sign-Off

- [ ] DesignTokensTest + DesignComponentsTest exist and pass
- [ ] No hardcoded color literals in the token layer (assert via test or review)
- [ ] Full suite green (UI-07)
- [ ] `nyquist_compliant: true` set in frontmatter

**Approval:** pending
