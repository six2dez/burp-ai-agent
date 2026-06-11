---
phase: 18-quality-tooling-build-hardening
plan: "01"
subsystem: build
tags: [sc1, sc2, detekt, ktlint, gradle, generateBuildFlags, static-analysis, ci]
dependency_graph:
  requires: []
  provides: [SC1-ktlintCheck-standalone, SC2-detekt-blocking-gate]
  affects: [build.gradle.kts, detekt.yml, detekt-baseline.xml, .github/workflows/build.yml]
tech_stack:
  added: ["io.gitlab.arturbosch.detekt:detekt-gradle-plugin:1.23.8 (Apache-2.0)"]
  patterns: [structural-srcDir-wiring, detekt-baseline, gradle-task-provider-flatMap]
key_files:
  created: [detekt.yml, detekt-baseline.xml]
  modified: [build.gradle.kts, .github/workflows/build.yml]
decisions:
  - "A2 confirmed via primary fix: generateBuildFlags.flatMap { it.outputDir } correctly infers dependency in Gradle 8.12.1; builtBy() fallback not needed"
  - "A1 confirmed: kotlin-compiler-embeddable warning absent entirely in this project's env (Kotlin 2.1.21 + detekt 1.23.8); build succeeds with no warning suppression needed"
  - "LongParameterList: switched from deprecated threshold to functionThreshold/constructorThreshold (1.23.8 API)"
  - "generatedSrcDir local variable removed (only used in now-deleted srcDir call)"
  - "detekt-formatting NOT added (would double-gate ktlint style rules)"
metrics:
  duration: "~15 minutes"
  completed: "2026-06-11T12:14:25Z"
  tasks: 2
  files: 4
---

# Phase 18 Plan 01: generateBuildFlags Wiring Fix + detekt 1.23.8 Static Analysis Gate Summary

Fixed the generateBuildFlags Gradle task wiring so ktlintCheck runs standalone without init-script, and integrated detekt 1.23.8 as a blocking static-analysis gate with a committed 1536-line baseline.

## Tasks Completed

| Task | Name | Commit | Files |
|------|------|--------|-------|
| 1 | Fix generateBuildFlags srcDir wiring + add detekt plugin + config | eb19094 | build.gradle.kts, detekt.yml |
| 2 | Generate detekt baseline | 3c4517c | detekt-baseline.xml |
| 2 | Wire detekt blocking gate in CI + fix LongParameterList deprecation | dec62db | build.gradle.kts, detekt.yml, .github/workflows/build.yml |

## Verification Results

### A1: kotlin-compiler-embeddable advisory check

**Path taken:** Primary (no intervention needed)

`./gradlew detekt --info --no-daemon 2>&1 | grep -i "embeddable|warning|error"` produced no `kotlin-compiler-embeddable` warning at all in this project's environment (macOS, Kotlin 2.1.21 + detekt 1.23.8). The concern documented in RESEARCH.md as Assumption A1 did not materialize. The `detekt` task succeeds without any warning suppression or `resolutionStrategy.force()` override.

Exit code after baseline: 0. BUILD SUCCESSFUL.

### A2: ktlintCheck standalone from clean build dir

**Path taken:** Primary (flatMap form works; builtBy() fallback not needed)

```
rm -rf build/ && ./gradlew ktlintCheck --no-daemon
BUILD SUCCESSFUL in 5s
8 actionable tasks: 8 executed
```

`generateBuildFlags.flatMap { it.outputDir }` correctly registers the structural dependency in Gradle 8.12.1. The `tasks.matching { startsWith("runKtlint") }.configureEach { dependsOn }` name-match hack has been removed.

### SC1: ktlintCheck standalone (plan success criterion)

`rm -rf build/ && ./gradlew ktlintCheck --no-daemon` exits 0. Violations are present but advisory (ktlint `ignoreFailures = true` — strict gate flip is Plan 02).

### SC2: detekt with baseline (plan success criterion)

`./gradlew detekt --no-daemon` exits 0 with `detekt-baseline.xml` present. Baseline is 198 KB / 1536 lines capturing all pre-existing violations.

### Full check task

`./gradlew check --no-daemon -PexcludeHeavyTests=true` exits 0. All tasks pass: detekt, ktlintCheck, test, jacocoTestReport.

## Build.gradle.kts Changes

### SC1: Structural srcDir wiring

**Removed:**
```kotlin
val generatedSrcDir = layout.buildDirectory.dir("generated/buildflags")

sourceSets.main {
    kotlin.srcDir(generatedSrcDir)  // plain Provider — no task-origin metadata
}

// fragile name-match hack
tasks.matching { it.name.startsWith("runKtlint") }.configureEach {
    dependsOn(generateBuildFlags)
}
```

**Added:**
```kotlin
sourceSets.main {
    kotlin.srcDir(generateBuildFlags.flatMap { it.outputDir })
}
// outputDir now set inline: outputDir.set(layout.buildDirectory.dir("generated/buildflags"))
```

### SC2: detekt plugin and config

Added to `plugins {}` block:
```kotlin
id("io.gitlab.arturbosch.detekt") version "1.23.8"
```

Added `detekt {}` block after `ktlint {}`:
```kotlin
detekt {
    buildUponDefaultConfig = true
    allRules = false
    baseline = file("detekt-baseline.xml")
    parallel = true
    config.setFrom(files("detekt.yml"))
}
```

## detekt.yml

Project-specific overrides using correct 1.23.8 API (no deprecated `threshold` property):

```yaml
complexity:
  LongMethod:
    threshold: 80
  LongParameterList:
    functionThreshold: 10
    constructorThreshold: 10
naming:
  FunctionNaming:
    excludes: [ '**/test/**' ]
```

## CI Changes (build.yml)

Added blocking detekt step in `lint` job (after ktlintCheck):
```yaml
- name: detekt (blocking)
  run: ./gradlew detekt --no-daemon
```

The ktlintCheck step retains `continue-on-error: true` — that removal is Plan 02 (SC3 gate-flip).

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] Fixed LongParameterList deprecated threshold property**
- **Found during:** Task 2 (detektBaseline run showed: "Property 'complexity>LongParameterList>threshold' is deprecated. Use `functionThreshold` and `constructorThreshold` instead.")
- **Issue:** detekt.yml used deprecated `threshold` key for `LongParameterList`; would cause advisory noise on every detekt run
- **Fix:** Replaced with `functionThreshold: 10` and `constructorThreshold: 10` per the 1.23.8 API
- **Files modified:** detekt.yml
- **Commit:** dec62db

## Known Stubs

None — this plan modifies only build configuration and CI YAML; no stub-pattern data flows are introduced.

## Threat Flags

| Flag | File | Description |
|------|------|-------------|
| threat_flag: supply-chain | build.gradle.kts | New Gradle plugin `io.gitlab.arturbosch.detekt:detekt-gradle-plugin:1.23.8` resolved from Maven Central at build time. Mitigated: version pinned, Apache-2.0 license, well-known 8+ year OSS project — see RESEARCH.md Package Legitimacy Audit. |

## Self-Check: PASSED

- [x] `build.gradle.kts` exists and contains `generateBuildFlags.flatMap { it.outputDir }`
- [x] `detekt.yml` exists in project root
- [x] `detekt-baseline.xml` exists (198 KB, 1536 lines)
- [x] `.github/workflows/build.yml` contains `./gradlew detekt --no-daemon` step
- [x] Commits eb19094, 3c4517c, dec62db visible in `git log`
- [x] `./gradlew ktlintCheck --no-daemon` exits 0 from clean build dir (SC1)
- [x] `./gradlew detekt --no-daemon` exits 0 with baseline (SC2)
- [x] `./gradlew check --no-daemon` exits 0 (full gate)
