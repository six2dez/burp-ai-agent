# Phase 18: Quality Tooling & Build Hardening - Context

**Gathered:** 2026-06-11
**Status:** Ready for planning
**Mode:** Auto-generated (infrastructure phase — discuss skipped per smart-discuss infrastructure detection)

<domain>
## Phase Boundary

Harden the build and test infrastructure so regressions surface quickly. Scope:

- **QUAL-05 / SC1** — Fix `generateBuildFlags` Gradle wiring so `./gradlew ktlintCheck` runs standalone (no init-script workaround); the generated-source dependency must be inherited automatically by ktlint consumers.
- **QUAL-02 / SC2** — Add `detekt` static analysis as a blocking CI check with a committed `detekt-baseline.xml` (existing violations baselined, new code must be clean).
- **QUAL-02 / SC3** — Run `ktlintFormat` across the whole codebase in a dedicated commit that PRECEDES the `ktlintCheck` blocking-gate commit (git log ordering is a success criterion); then flip ktlint to strict (`ignoreFailures=false`).
- **QUAL-03 / SC4** — Raise test coverage for `scanner` queue/dedup, `cli` backend supervision, and the `cache` module from the 0–3% baseline (≥1 meaningful test class per module exercising the critical path).
- **QUAL-04 / SC5** — Audit silently-swallowed `catch (Exception)` sites (~181 in current tree): each site either logs a contextual message via a shared helper OR carries a `// INTENTIONAL: <reason>` comment; document the audit in a short tracking note.

This is a developer-facing build/quality phase. No user-facing behavior, no UI surface.

</domain>

<decisions>
## Implementation Decisions

### Claude's Discretion
All implementation choices are at Claude's discretion — this is a pure infrastructure phase (build tooling, static-analysis config, test coverage, exception-handling audit). The ROADMAP success criteria are the spec. Guidance for the planner:

- **detekt config**: prefer detekt's default ruleset plus a committed `detekt-baseline.xml` capturing current violations; wire as a blocking `check` dependency. Pick a detekt version compatible with the project's Kotlin 2.1.21 plugin (do NOT bump Kotlin — see the Phase 16 deferral blocker).
- **ktlint strict flip**: the project already gates strictness on the `ktlintStrict` property (lenient by default). SC2/SC3 imply making the gate blocking by default once the baseline is clean — sequence the format commit before the gate-flip commit.
- **generateBuildFlags fix**: the current wiring uses `tasks.matching { it.name.startsWith("runKtlint") }.dependsOn(generateBuildFlags)` plus `sourceSets.main { kotlin.srcDir(generatedSrcDir) }`. Prefer wiring the generated source so the task dependency is inferred structurally (e.g. via the source-generating task as the srcDir provider) rather than name-matching, so `ktlintCheck` resolves the dependency standalone.
- **coverage targets**: "measurably raised from 0–3%" — one meaningful test class per module (scanner queue/dedup, cli supervision, cache) exercising the critical path is sufficient; no hard coverage-percentage gate required.
- **exception audit**: prefer a shared logging helper (e.g. an extension on the existing logging facility) for the log-or-annotate decision; sites that are genuinely intentional get `// INTENTIONAL: <reason>`. Capture the audit in a short tracking note under `.planning/` or `docs/`.
- **CI**: "blocking CI check" means the gradle task graph fails on violation; whether a GitHub Actions workflow file exists/needs updating should be checked during planning.

</decisions>

<code_context>
## Existing Code Insights

### Reusable Assets
- `build.gradle.kts` already has: ktlint plugin `org.jlleitschuh.gradle.ktlint:12.1.1` (ktlint engine 1.5.0, lenient via `ktlintStrict` property), `jacoco` plugin with `jacocoTestReport` wired as `finalizedBy` on `Test`, shadow plugin, cyclonedx SBOM.
- `GenerateBuildFlagsTask` (abstract, `@Input`/`@OutputDirectory`, config-cache compatible) generates `BuildFlags.kt` into `build/generated/buildflags/`; `sourceSets.main.kotlin.srcDir(generatedSrcDir)` adds it; ktlint excludes `**/build/**` and `**/generated/**`.
- Existing test patterns: scanner module has 10 test classes (e.g. `ScannerQueueBackpressureTest`, `ActiveScannerQueueModelTest`); cli has `CliBackendTempFileTest`, `CliTimeoutMessageTest`, `CopilotCommandBuilderTest`. JUnit Platform, `-ea` assertions enabled in `tasks.test`.

### Established Patterns
- Source root: `src/main/kotlin/com/six2dez/burp/aiagent/`; modules: `scanner/`, `cache/`, `backends/cli/`.
- `cache/` module currently appears to have NO dedicated test class (0% baseline — primary SC4 target).
- ~181 `catch (...Exception...)` sites in `src/main/kotlin` (ROADMAP estimate was 136; codebase has grown) — SC5 audit scope.
- Heavy-test exclusion (`excludeHeavyTests`) and `nightlyRegressionTest` task already segment slow suites.

### Integration Points
- New `detekt` plugin block + `detekt { baseline = file("detekt-baseline.xml") }` + a blocking dependency from `check`.
- The `generateBuildFlags` ↔ ktlint task-dependency wiring (build.gradle.kts ~lines 90–113) is the SC1 fix site.
- CI workflow under `.github/workflows/` (verify presence during planning) for the blocking-gate requirement.

</code_context>

<specifics>
## Specific Ideas

- The `generateBuildFlags` standalone-ktlint defect is a known, reproduced issue (documented in maintainer memory: `./gradlew ktlintCheck` currently fails standalone; `./gradlew test` or an init-script workaround is the current mitigation). SC1 closes it.
- SC3 explicitly requires the `ktlintFormat` mass-format commit to come BEFORE the blocking-gate commit in git history — plan two separate commits in that order.
- Do NOT bump the Kotlin plugin (2.1.21) — Phase 16 deferral blocker documents that a Kotlin/Ktor bump breaks `compileKotlin`. Choose a detekt version built against Kotlin 2.1.x.

</specifics>

<deferred>
## Deferred Ideas

None — phase scope is well-bounded by the five success criteria.

</deferred>
