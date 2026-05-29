---
phase: 10
slug: mcp-tools-tab-redesign
status: draft
nyquist_compliant: false
wave_0_complete: false
created: 2026-05-29
---

# Phase 10 — Validation Strategy

> Test contract for the MCP tools tab redesign. Source: 10-UI-SPEC.md + Phase 10 success criteria. Framework: JUnit 5 + Mockito-Kotlin. The tab lives in `SettingsPanel.kt`; the grouping/filter/badge logic should be extracted into pure, testable helpers (mirroring how Phase 3 extracted prompt-library logic) so the Swing layer stays a thin shell.

---

## Test Infrastructure

| Property | Value |
|----------|-------|
| **Framework** | JUnit 5 (6.0.3) + Mockito-Kotlin 5.4.0 |
| **Quick run** | `./gradlew test -PexcludeHeavyTests=true` |
| **Full suite** | `./gradlew test` |

Swing rendering itself is verified manually; the *logic* (grouping, badge mapping, filter predicate, bulk-toggle target set) is unit-tested as pure functions.

---

## Per-Requirement Verification Map

| Req | Behavior | Test Type | Automated Command | File |
|-----|----------|-----------|-------------------|------|
| UI-03 (grouping) | Tools split into native (AI) vs generic (Montoya) by `McpToolDescriptor.nativeTool`; ordering deterministic | unit | `./gradlew test --tests "*.McpToolTabModelTest"` | ❌ W0 |
| UI-04 (badge) | Badge text/style derives from `nativeTool` (native → "Store + Full"/NATIVE; generic → "Full only"/FULL) | unit | `./gradlew test --tests "*.McpToolTabModelTest"` | ❌ W0 |
| UI-05 (search) | Filter predicate matches title OR description, case-insensitive; empty query → all | unit | `./gradlew test --tests "*.McpToolTabModelTest"` | ❌ W0 |
| UI-05 (bulk toggle) | "Enable/Disable all" targets exactly the currently-visible tools of that group (respects active filter); produces the expected toolToggles delta | unit | `./gradlew test --tests "*.McpToolTabModelTest"` | ❌ W0 |
| UI-07 (persistence) | `toolToggles` / `enabledUnsafeTools` / `unsafeEnabled` round-trip through save→reload unchanged; collect/apply helpers preserved | unit (existing + extend) | `./gradlew test --tests "*.McpSettings*" "*.AgentSettings*"` | ✅/extend |
| UI-07 (no regression) | Full suite green; existing MCP server controls + unsafe semantics intact | unit (existing) | `./gradlew test` | ✅ |

---

## Wave 0 Requirements

- [ ] `src/test/kotlin/com/six2dez/burp/aiagent/ui/.../McpToolTabModelTest.kt` — covers the extracted grouping + badge-mapping + filter + bulk-toggle-target helpers (pure logic, no Swing instantiation needed)

*Existing MCP settings persistence tests cover UI-07 round-trip; extend if the redesign adds any new persisted field (it should not).*

---

## Manual-Only Verifications

| Behavior | Why Manual | Test Instructions |
|----------|------------|-------------------|
| Tab visual layout (two grouped sections, headers, per-row badge, search bar, per-group bulk buttons) | Swing rendering | Load full JAR in Burp → Settings → MCP tools: confirm AI vs Montoya sections, badges, live search narrows both sections, "Enable/Disable all" per group works, in light AND dark theme |
| Store-build view | Needs the store JAR | Load `Custom-AI-Agent-0.7.0.jar`: confirm only native tools appear (and read sensibly without the generic section) |

---

## Validation Sign-Off

- [ ] McpToolTabModelTest exists and passes (grouping/badge/filter/bulk-toggle logic)
- [ ] Existing toolToggles/unsafe persistence tests green (UI-07)
- [ ] Full suite green
- [ ] `nyquist_compliant: true` set in frontmatter

**Approval:** pending
