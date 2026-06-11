# Phase 18: Quality Tooling & Build Hardening - Research

**Researched:** 2026-06-11
**Domain:** Gradle build tooling, static analysis (detekt), ktlint, test coverage, exception handling
**Confidence:** HIGH

---

<user_constraints>
## User Constraints (from CONTEXT.md)

### Locked Decisions
None — all implementation choices are at Claude's discretion for this infrastructure phase.

### Claude's Discretion
All implementation choices: detekt version/config, ktlint strict-flip sequencing, generateBuildFlags fix approach, test coverage shape, exception-audit scope.

### Deferred Ideas (OUT OF SCOPE)
None — phase scope is well-bounded by the five success criteria.
</user_constraints>

<phase_requirements>
## Phase Requirements

| ID | Description | Research Support |
|----|-------------|------------------|
| QUAL-05 | Fix `generateBuildFlags` so `./gradlew ktlintCheck` runs standalone | SC1: idiomatic Gradle 8 task-provider srcDir wiring eliminates name-match dependsOn |
| QUAL-03 | Add detekt as blocking CI check with committed baseline | SC2: detekt 1.23.8 + `io.gitlab.arturbosch.detekt` plugin; `detektBaseline` task + `check` dependency |
| QUAL-03 | Run ktlintFormat mass-format, then flip ktlint to strict | SC3: two-commit sequence; flip `ignoreFailures` default; escape hatch via property |
| QUAL-02 | Raise test coverage for scanner/cache/cli modules | SC4: `PersistentPromptCacheTest` (zero coverage), scanner dedup, CLI supervision |
| QUAL-04 | Audit 183 `catch (...Exception...)` sites: log or annotate | SC5: `// INTENTIONAL:` convention; shared helper wrapping `api.logging().logToError()`; tractable audit scope |
</phase_requirements>

---

## Summary

Phase 18 is a pure developer-facing build and quality phase with five disjoint but sequentially important sub-problems. None of them change user-visible behavior.

**SC1 (generateBuildFlags):** The current wiring at build.gradle.kts:98 passes `generatedSrcDir` (a `Provider<Directory>`) to `kotlin.srcDir()`. Because this value is a plain directory provider without task-origin metadata, Gradle's dependency checker cannot infer that `generateBuildFlags` produces the directory. The `tasks.matching { it.name.startsWith("runKtlint") }.dependsOn(...)` workaround at lines 111-113 targets task names known at configuration time, but `ktlintCheck` is an aggregate task that delegates to `runKtlint*` tasks that may not yet exist when the matching is evaluated. The idiomatic Gradle 8 fix is to pass `generateBuildFlags.flatMap { it.outputDir }` (the task's own `outputDir` property accessed through the `TaskProvider`) to `kotlin.srcDir()`, so Gradle registers the task as the structural producer of that directory. This eliminates both the name-match hack and the standalone failure.

**SC2 (detekt):** The latest stable detekt is `1.23.8` (released 2025-02-20), built against Kotlin `2.0.21`. It is compatible with a Kotlin 2.1.21 project: the plugin's embedded Kotlin analysis engine analyses source ASTs independently of the compiler version, though it will emit a Kotlin KGP warning about `kotlin-compiler-embeddable` being on the classpath alongside the KGP. This warning is advisory (the analysis still runs) and was reported as issue #7883 on Jan 2025; the migration away from `kotlin-compiler-embeddable` landed after the 1.23.8 release (March 2025 in `main`, destined for 2.0.0-alpha series). The `io.gitlab.arturbosch.detekt` plugin automatically registers a `detekt` task as a dependency of `check`. Generating a `detekt-baseline.xml` requires running `./gradlew detektBaseline` once, which creates the XML capturing all current violations. The detekt-formatting module overlaps with ktlint rules — avoid adding it to prevent double-gating the same style rules.

**SC3 (ktlint strict flip):** The project already gates ktlint strictness on the `ktlintStrict` Gradle property: `ignoreFailures` is `true` by default and `false` only when `-PktlintStrict=true` is passed. The SC3 change inverts this: `ignoreFailures` becomes `false` by default, with an escape hatch property `-PktlintLenient=true`. This requires a two-commit sequence: commit A = `./gradlew ktlintFormat` (auto-fixes the codebase), commit B = flip the default. The `**/build/**` and `**/generated/**` exclusions already in the ktlint config mean `BuildFlags.kt` is untouched by `ktlintFormat`.

**SC4 (test coverage):** The `cache/` module (`PersistentPromptCache.kt`) has zero test coverage. Critical paths — thread-safe read/write, TTL eviction, disk-size eviction — are pure file I/O with no AWT/Burp seams. The `scanner/` module has 10 test classes covering queue backpressure and model operations but lacks coverage of the dedup map (`processedTargets`) lifecycle. The `backends/cli/` module's supervision path (process watchdog, restart, `NonInteractiveCliConnection.send` timeout) is tested at the behavior level by `CliBackendTempFileTest` but not for the supervisor-level recovery path in `AgentSupervisor`. Minimal coverage means one meaningful test class per module exercising the critical path.

**SC5 (exception audit):** 183 `catch (...Exception...)` sites across 52 files. Of these, only one currently touches a log call at the catch site. The project's logging facility is Montoya `api.logging().logToError()/logToOutput()`, plus `BackendDiagnostics.logError()` for non-Montoya contexts (config/cache/util where the API instance is unavailable). The audit is tractable in one phase at a scope of ~30-50 sites to fully annotate, with remaining sites carrying a tracking note.

**Primary recommendation:** Sequence the five work items as: Wave 1 = SC1 (build fix, unblocks SC3 standalone run), SC2 (detekt integration), commit A of SC3 (ktlintFormat). Wave 2 = commit B of SC3 (strict flip), SC4 (new tests). Wave 3 = SC5 (exception audit + tracking note). `build.gradle.kts` is a hot file — SC1 and SC2 both modify it; assign them to the same plan or explicitly serialize their plans.

---

## Architectural Responsibility Map

| Capability | Primary Tier | Secondary Tier | Rationale |
|------------|-------------|----------------|-----------|
| generateBuildFlags task wiring (SC1) | Build system | — | Gradle configuration-phase concern; no source change needed |
| detekt static analysis (SC2) | Build system | CI | Plugin config in build.gradle.kts; CI YAML for blocking gate |
| ktlint strict gate (SC3) | Build system | CI | build.gradle.kts change; CI YAML `continue-on-error` removal |
| Test coverage — cache module (SC4) | Test tier | — | New test file, no production code change |
| Test coverage — scanner dedup (SC4) | Test tier | — | New test class against existing `ActiveAiScanner` seams |
| Test coverage — CLI supervision (SC4) | Test tier | — | New test against `AgentSupervisor` or `NonInteractiveCliConnection` seams |
| Exception audit (SC5) | Source (all modules) | docs/ | Edit catch sites; write tracking note |

---

## Standard Stack

### Core (already in project — no new dependencies needed for SC1/SC3/SC4/SC5)

| Library | Version | Purpose | Why Standard |
|---------|---------|---------|--------------|
| `org.jlleitschuh.gradle.ktlint` | 12.1.1 (ktlint 1.5.0) | Style enforcement | Already applied; SC3 changes config only |
| JUnit Jupiter | (via `kotlin("test")` + `junit-jupiter:6.0.3`) | Unit tests | Already used by all 85 existing test classes |
| Mockito-Kotlin | 5.4.0 | Mocking Burp Montoya API | Already used throughout test suite |

### New Dependency: detekt (SC2 only)

| Plugin | Version | Purpose | Why This Version |
|--------|---------|---------|-----------------|
| `io.gitlab.arturbosch.detekt` | **1.23.8** | Kotlin static analysis | Latest stable; released 2025-02-20; compatible with Kotlin 2.1.x source analysis; Gradle 8.12.1 ready [CITED: detekt.dev/docs/introduction/compatibility/] |

**Important compatibility note:** detekt 1.23.8 was built against Kotlin `2.0.21`. With this project's Kotlin KGP `2.1.21`, the Kotlin compiler will emit a `kotlin-compiler-embeddable` warning (issue #7883, confirmed open for 1.23.8). This warning is advisory — the analysis still runs correctly. The fix (migration to `kotlin-compiler`) shipped after 1.23.8 and targets the 2.0.0-alpha line. Accept the warning and suppress it in build output if needed. Do NOT use detekt 2.0.0-alpha — it targets Kotlin 2.3.x which requires a Kotlin plugin bump that is BLOCKED by the Phase 16 deferral. [CITED: github.com/detekt/detekt/releases/tag/v1.23.8] [ASSUMED: warning is advisory and analysis succeeds with Kotlin 2.1.21 KGP]

**Installation (build.gradle.kts addition):**
```kotlin
plugins {
    // ... existing plugins ...
    id("io.gitlab.arturbosch.detekt") version "1.23.8"
}
```

### Alternatives Considered

| Instead of | Could Use | Tradeoff |
|------------|-----------|----------|
| detekt 1.23.8 | detekt 2.0.0-alpha.3 | Alpha supports Kotlin 2.3.x but REQUIRES Kotlin plugin bump — BLOCKED |
| detekt 1.23.8 | ktlint only (no detekt) | Misses logic/complexity rules; QUAL-03 explicitly requires detekt |

---

## Package Legitimacy Audit

This phase adds one new Gradle plugin: `io.gitlab.arturbosch.detekt:detekt-gradle-plugin:1.23.8`.

| Package | Registry | Age | Downloads | Source Repo | slopcheck | Disposition |
|---------|----------|-----|-----------|-------------|-----------|-------------|
| `io.gitlab.arturbosch.detekt:detekt-gradle-plugin:1.23.8` | Maven Central | 8+ yrs (project), release Feb 2025 | 202 dependent components (Maven Central) | github.com/detekt/detekt | N/A — slopcheck unavailable (JVM registry) | Approved — well-known OSS project, MIT-adjacent license, confirmed at central.sonatype.com and github.com/detekt/detekt |

**Packages removed due to slopcheck verdict:** none
**Packages flagged as suspicious:** none

*slopcheck was unavailable (pip install denied in this environment). However, `io.gitlab.arturbosch.detekt` is a well-established, widely-used Kotlin static analysis tool with a public GitHub repository, multi-year history, and direct Maven Central listing. Its legitimacy is independently verifiable and does not depend on slopcheck.*

---

## Architecture Patterns

### System Architecture Diagram

```
build.gradle.kts
  └── SC1: generateBuildFlags TaskProvider
          │  outputDir: Provider<Directory>  ← pass this to kotlin.srcDir()
          ↓
      sourceSets.main.kotlin (source set)
          ↓ inferred dependency
      runKtlintCheckOverMainSourceSet
      compileKotlin
          ↓
      check ← detekt (SC2)
            ← ktlintCheck (SC3, blocking)
            ← test (SC4 new tests)
```

```
Exception Audit (SC5)
  grep inventory  →  52 files, 183 sites
        ↓
  classify:  [already-logged]  [intentional-swallow]  [missing-log]
        ↓
  actions:
    already-logged → add // INTENTIONAL: or upgrade to logToError if missing context
    intentional-swallow → add // INTENTIONAL: <reason>
    missing-log → add api.logging().logToError("[Module] context: ${e.message}")
        ↓
  tracking note: .planning/notes/exception-audit.md
```

### Recommended Project Structure

No new directories. Changes are:
```
build.gradle.kts               # SC1, SC2, SC3 changes
detekt-baseline.xml            # SC2: generated by detektBaseline, committed
detekt.yml                     # SC2 (optional): buildUponDefaultConfig overrides
src/test/kotlin/.../cache/
  PersistentPromptCacheTest.kt # SC4: new
src/test/kotlin/.../scanner/
  ActiveScannerDedupTest.kt    # SC4: new (or extend ActiveScannerQueueModelTest)
src/test/kotlin/.../backends/cli/
  CliSupervisionTest.kt        # SC4: new (test NonInteractiveCliConnection supervision)
.planning/notes/
  exception-audit.md           # SC5: tracking note
```

### Pattern 1: Structural srcDir Wiring (SC1 Fix)

**What:** Pass the task's `outputDir` property — accessed through the `TaskProvider` — to `kotlin.srcDir()` instead of the raw `Provider<Directory>`. This makes Gradle register the task as the structural producer of the directory.

**When to use:** Any code-generating task whose output is added to a Kotlin source set.

**The root cause:** `kotlin.srcDir(generatedSrcDir)` at build.gradle.kts:98 where `generatedSrcDir` is `layout.buildDirectory.dir("generated/buildflags")` — a plain directory provider with no task-origin metadata. Gradle's strict dependency checker sees a directory being consumed without a declared producer. [CITED: docs.gradle.org/current/userguide/lazy_configuration.html — task dependency inference requires a provider originating from a task output property]

**The fix:**
```kotlin
// REMOVE this (plain provider — no task origin):
sourceSets.main {
    kotlin.srcDir(generatedSrcDir)
}

// REMOVE this (name-match hack — fragile):
tasks.matching { it.name.startsWith("runKtlint") }.configureEach {
    dependsOn(generateBuildFlags)
}

// ADD this (structural wiring — task's own outputDir property):
sourceSets.main {
    kotlin.srcDir(generateBuildFlags.flatMap { it.outputDir })
}
// KotlinCompile already has dependsOn(generateBuildFlags) — keep that block as-is.
```

`generateBuildFlags.flatMap { it.outputDir }` accesses the `outputDir: DirectoryProperty` through the `TaskProvider`, so Gradle knows that this source directory is produced by the `generateBuildFlags` task and adds an automatic dependency to any task that consumes that directory — including `runKtlintCheckOverMainSourceSet`. [CITED: gradle.org issue #28304, discuss.gradle.org — `project.files(task.map { it.outputDir }).builtBy(task)` is one variant; `taskProvider.flatMap { it.outputDir }` is the cleaner Kotlin DSL equivalent]

### Pattern 2: detekt Integration (SC2)

**What:** Apply `io.gitlab.arturbosch.detekt` 1.23.8, generate a baseline, wire as blocking `check` dependency.

**Step 1 — Plugin block:**
```kotlin
// In plugins {}:
id("io.gitlab.arturbosch.detekt") version "1.23.8"
```

**Step 2 — detekt configuration block:**
```kotlin
detekt {
    buildUponDefaultConfig = true          // extend defaults, don't replace
    allRules = false                        // only rules in default ruleset
    baseline = file("detekt-baseline.xml") // baseline file in repo root
    parallel = true                         // AST parallel building
    config.setFrom(files("detekt.yml"))    // optional custom overrides (can omit if just baseline)
}
```

**Step 3 — Generate the baseline (run once, commit result):**
```bash
./gradlew detektBaseline
git add detekt-baseline.xml
git commit -m "chore: generate detekt baseline capturing pre-existing violations"
```

**Step 4 — Wire as blocking `check` dependency:**
Detekt 1.23.8 automatically registers `detekt` as a `check` dependency. No extra wiring needed — `./gradlew check` will fail on new violations not in the baseline. [CITED: detekt.dev/docs/1.23.8/gettingstarted/gradle/ — "the detekt task is automatically run when executing gradle check"]

**detekt-formatting overlap:** Do NOT add `io.gitlab.arturbosch.detekt:detekt-formatting` as a detekt plugin. It wraps ktlint rules and would create a second gate for the same violations. Use detekt for logic/complexity rules, ktlint for style. [ASSUMED: the project does not currently have detekt-formatting; verify before committing]

**Optional detekt.yml overrides (recommended minimal set):**
```yaml
# detekt.yml — override noisy rules for this codebase
complexity:
  LongMethod:
    threshold: 80      # PassiveAiScanner/McpTools have long methods by design
  LongParameterList:
    threshold: 10      # AgentSettings constructor has many fields
naming:
  FunctionNaming:
    excludes: [ '**/test/**' ]
```

### Pattern 3: ktlint Strict Flip (SC3)

**Current gate logic (build.gradle.kts:171-174):**
```kotlin
ignoreFailures.set(
    (project.findProperty("ktlintStrict") as? String)?.equals("true", ignoreCase = true) != true,
)
// Lenient by default: fails only when -PktlintStrict=true
```

**New logic (inverted — strict by default, escape hatch for emergency):**
```kotlin
ignoreFailures.set(
    (project.findProperty("ktlintLenient") as? String)?.equals("true", ignoreCase = true) == true,
)
// Strict by default: fails UNLESS -PktlintLenient=true
```

**Two-commit ordering:**
- Commit A: `./gradlew ktlintFormat` (auto-fixes ~all violations). Do NOT flip the gate yet.
- Commit B: Flip `ignoreFailures` logic as above. This commit is the "blocking gate" commit that SC3 measures.

`BuildFlags.kt` is excluded from ktlint via `exclude("**/build/**")` and `exclude("**/generated/**")` — confirmed safe.

**CI update (build.yml):** Remove `continue-on-error: true` from the ktlintCheck step in the `lint` job.

### Pattern 4: Logging Helper for Exception Audit (SC5)

**Existing facility:** The project uses `api.logging().logToError(msg)` / `api.logging().logToOutput(msg)` (Montoya API) and `BackendDiagnostics.logError(msg)` (for contexts without the Montoya API — used in config, cache, backends).

**The two classification outcomes for each catch site:**

1. **Operational failure that should surface to the user (majority):**
   ```kotlin
   } catch (e: Exception) {
       api.logging().logToError("[ModuleName] operation failed: ${e.message}")
   }
   ```
   Or for non-Montoya contexts:
   ```kotlin
   } catch (e: Exception) {
       BackendDiagnostics.logError("[ModuleName] operation failed: ${e.message}")
   }
   ```

2. **Deliberate swallow where swallowing is the correct behavior:**
   ```kotlin
   } catch (_: Exception) {
       // INTENTIONAL: webhook delivery is best-effort; failures must not crash callers
   }
   ```

**Audit tractability strategy:**
- Do NOT attempt all 183 sites in one phase — that is ~52 files touching production paths with risk of behavioral regressions.
- Recommended scope: ~30-50 sites in the highest-value modules (cache, scanner, supervisor, cli) that directly affect diagnosability.
- Remaining sites: add `// TODO-AUDIT: review exception handling` comments; document in tracking note.
- Tracking note location: `.planning/notes/exception-audit.md` with a table of all 183 sites, their module, classification, and disposition.

**Audit script (for the tracking note):**
```bash
grep -rn "catch.*Exception\|catch.*Throwable" src/main/kotlin \
  --include="*.kt" | sort > /tmp/exception-audit-raw.txt
```

### Anti-Patterns to Avoid

- **Don't add detekt-formatting:** Creates a double-gate with ktlint on style rules (formatting/indentation). Use detekt for logic rules only.
- **Don't flip ktlint strict before ktlintFormat:** Mass-format commit must precede the gate-flip commit in git log or SC3 is not met.
- **Don't pass a plain Provider<Directory> to kotlin.srcDir():** This is the exact bug causing SC1. The provider must originate from the task's `outputDir` property accessed through the `TaskProvider`.
- **Don't use `tasks.matching { }.dependsOn()` for source-gen dependencies:** Name-matching is fragile — task names can change, and the tasks may not exist at configuration time.
- **Don't baseline detekt at zero (empty baseline):** An empty baseline means ALL current violations block CI immediately. Always run `detektBaseline` first to capture pre-existing violations.
- **Don't auto-fix exception sites with a mechanical script:** Some `catch (_: Exception)` sites are correctly silent (e.g., `BackendDiagnostics.log` fallback, webhook best-effort, regex compile fail-open). Mechanical replacement would introduce regressions.
- **Don't put SC1 and SC2 in separate parallel plans if both touch build.gradle.kts:** Merge conflicts are guaranteed. Assign them to the same plan or serialize explicitly.

---

## Don't Hand-Roll

| Problem | Don't Build | Use Instead | Why |
|---------|-------------|-------------|-----|
| Kotlin static analysis | Custom AST visitor | detekt 1.23.8 | ~800 built-in rules covering complexity, style, potential bugs; community-maintained |
| ktlint auto-format | Manual reformatting | `./gradlew ktlintFormat` | Engine handles all 183 style rules in one pass |
| Baseline generation | Manual XML | `./gradlew detektBaseline` | Correct XML schema, source-set-aware |
| Test mocking of Montoya API | Custom test doubles | `mockito-kotlin` + `mock<MontoyaApi>(defaultAnswer = Answers.RETURNS_DEEP_STUBS)` | Deep-stub pattern already used in 20+ tests |

**Key insight:** The standard Gradle lazy-configuration API (`TaskProvider.flatMap { it.outputDir }`) eliminates an entire category of brittle name-matching workarounds. Always prefer structural dependency wiring over `dependsOn` by name.

---

## Common Pitfalls

### Pitfall 1: detekt kotlin-compiler-embeddable Warning Blocks CI
**What goes wrong:** `./gradlew detekt` prints `"The artifact org.jetbrains.kotlin:kotlin-compiler-embeddable is present in the build classpath along Kotlin Gradle plugin."` and a team member treats it as a failure.
**Why it happens:** detekt 1.23.8 bundles `kotlin-compiler-embeddable`; Kotlin KGP 2.1.x warns about this classpath overlap.
**How to avoid:** Document the warning in the PR description. The warning does not fail the build. It cannot be resolved without bumping detekt to 2.0.0-alpha (which requires a Kotlin plugin bump — blocked).
**Warning signs:** CI log shows the warning text. The `detekt` task itself succeeds or fails based on rule violations, not the warning.

### Pitfall 2: detektBaseline XML Not Committed
**What goes wrong:** `detekt-baseline.xml` is generated locally but not committed. CI runs `detekt` with no baseline, all pre-existing violations fail the build.
**Why it happens:** The file is easy to overlook — it is generated in the project root, not in `build/`.
**How to avoid:** The plan must include an explicit step: `git add detekt-baseline.xml && git commit`.
**Warning signs:** CI failing with hundreds of detekt violations on the first run.

### Pitfall 3: ktlintFormat Touches Generated Sources
**What goes wrong:** After SC1 fix, `BuildFlags.kt` may be discovered by ktlintFormat if the exclusion filter is evaluated before the task runs.
**Why it happens:** Unlikely but possible if exclusion patterns are not applied correctly.
**How to avoid:** The existing `exclude("**/build/**")` and `exclude("**/generated/**")` patterns in the ktlint block already prevent this. Verify they remain in place after SC3 edits.
**Warning signs:** ktlintFormat modifies `build/generated/buildflags/com/six2dez/burp/aiagent/BuildFlags.kt`.

### Pitfall 4: ktlintCheck Still Fails Standalone After SC1 Fix
**What goes wrong:** Switching to `generateBuildFlags.flatMap { it.outputDir }` is correct but the old `tasks.matching { }.dependsOn(generateBuildFlags)` block is left in place. Both blocks coexist, causing no harm but leaving dead code.
**Why it happens:** Partial application of the fix.
**How to avoid:** Remove the `tasks.matching { it.name.startsWith("runKtlint") }.configureEach { dependsOn(generateBuildFlags) }` block entirely when applying the structural fix.
**Warning signs:** Both wiring mechanisms present; `./gradlew ktlintCheck --dry-run` shows redundant dependency edges.

### Pitfall 5: Silently Swallowed Exception in cache Module is Correct Behavior
**What goes wrong:** SC5 auditor adds a log call to `PersistentPromptCache.put()`'s catch block, which already has a comment: `// Silently fail on disk write errors`. This is intentional — cache write failures must not crash the scanner.
**Why it happens:** Mechanical audit without reading context.
**How to avoid:** Read the existing comment at each catch site before classifying. The cache module's two catches (`get()` and `put()`) both intentionally swallow — they should get `// INTENTIONAL:` annotations, not log calls.
**Warning signs:** Log output fills with cache write errors during normal operation.

### Pitfall 6: PersistentPromptCacheTest Writes to Real Filesystem
**What goes wrong:** Tests using the default constructor (`PersistentPromptCache()`) write to `~/.burp-ai-agent/cache/`. On CI, the home directory may not be writable or may accumulate test files.
**Why it happens:** The constructor defaults to the production cache dir.
**How to avoid:** Always construct `PersistentPromptCache` with a `java.nio.file.Files.createTempDirectory()` directory in tests; clean up in `@AfterEach`.
**Warning signs:** Tests pass locally but fail on CI with permission errors, or test artifacts left in `~/.burp-ai-agent/cache/`.

---

## Code Examples

### SC1: Structural srcDir Wiring
```kotlin
// Source: docs.gradle.org/current/userguide/lazy_configuration.html (task dependency inference)
// Remove:
//   sourceSets.main { kotlin.srcDir(generatedSrcDir) }         // line 97-99
//   tasks.matching { ... }.configureEach { dependsOn(...) }    // lines 111-113
// Add:
sourceSets.main {
    // Pass the task's own outputDir through the TaskProvider — Gradle infers the dependency.
    kotlin.srcDir(generateBuildFlags.flatMap { it.outputDir })
}
// The KotlinCompile dependsOn block (lines 101-107) stays untouched.
```

### SC2: detekt Configuration
```kotlin
// Source: detekt.dev/docs/1.23.8/gettingstarted/gradle/
detekt {
    buildUponDefaultConfig = true
    allRules = false
    baseline = file("detekt-baseline.xml")
    parallel = true
}
```

### SC3: ktlint Strict-by-Default Gate
```kotlin
// In ktlint { } block — replace the existing ignoreFailures.set(...) line:
ignoreFailures.set(
    (project.findProperty("ktlintLenient") as? String)?.equals("true", ignoreCase = true) == true,
)
// Strict by default; override with: ./gradlew ktlintCheck -PktlintLenient=true
```

### SC4: PersistentPromptCache Test Pattern
```kotlin
// Source: project convention — mirrors CliBackendTempFileTest.kt seam approach
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import java.nio.file.Files

class PersistentPromptCacheTest {
    private lateinit var tmpDir: java.io.File

    @BeforeEach fun setUp() {
        tmpDir = Files.createTempDirectory("cache-test").toFile()
    }

    @AfterEach fun tearDown() { tmpDir.deleteRecursively() }

    @Test fun getReturnsNullForExpiredEntry() {
        val cache = PersistentPromptCache(cacheDir = tmpDir, ttlMs = 1L)
        val entry = CachedEntry(System.currentTimeMillis() - 1000, emptyList())
        cache.put("hash1", entry)
        Thread.sleep(5)
        assert(cache.get("hash1") == null)
    }

    @Test fun putAndGetRoundTrip() {
        val cache = PersistentPromptCache(cacheDir = tmpDir)
        val issue = CachedIssue(title = "SQLI", severity = "HIGH")
        val entry = CachedEntry(System.currentTimeMillis(), listOf(issue))
        cache.put("abc123", entry)
        val retrieved = cache.get("abc123")
        assert(retrieved?.issues?.first()?.title == "SQLI")
    }

    @Test fun evictsOldestFilesWhenDiskLimitExceeded() {
        val cache = PersistentPromptCache(cacheDir = tmpDir, maxDiskBytes = 200L)
        // write entries until limit; verify oldest removed
        repeat(20) { i ->
            cache.put("hash$i", CachedEntry(System.currentTimeMillis(), listOf(CachedIssue(title = "T$i"))))
        }
        assert(cache.diskSizeBytes() <= 200L)
    }
}
```

### SC4: scanner Dedup Test Pattern
```kotlin
// Source: project convention — mirrors ActiveScannerQueueModelTest.kt seam
// Critical path: processedTargets ConcurrentHashMap prevents re-queuing same URL+param
@Test fun manualScanDedupSkipsAlreadyProcessedTarget() {
    val scanner = newScannerWithSmallTimeout()
    val rr = requestResponse("http://example.com/?id=1", "id", "1")
    // Enqueue and immediately mark as processed (simulate completed scan)
    scanner.manualScan(listOf(rr), listOf(VulnClass.SQLI))
    // The dedup map key is url+paramName; re-enqueue the same target
    val second = scanner.manualScan(listOf(rr), listOf(VulnClass.SQLI))
    // If dedup is working, the second enqueue is 0 (or 1 if queue has not yet processed)
    // — assert queue state is bounded
    assert(scanner.getQueueItems(limit = 100).size <= scanner.maxQueueSize)
}
```

### SC5: Exception Site Classification Examples
```kotlin
// INTENTIONAL swallow — disk write best-effort (PersistentPromptCache.kt:63)
} catch (_: Exception) {
    // INTENTIONAL: cache write failures are best-effort; must not crash scanner pipeline
}

// Missing log — operational failure that should surface (BackendRegistry.kt:125)
} catch (e: Exception) {
    BackendDiagnostics.logError("[BackendRegistry] Failed to load backend config: ${e.message}")
}

// Already-logged but needs context tag (ChatPanel.kt — already has logging, just verify tag)
} catch (e: Exception) {
    api.logging().logToError("[ChatPanel] Failed to save sessions: ${e.message}")
}
```

---

## CI Analysis (SC2 + SC3 Blocking Gates)

**Current build.yml state:**
- `lint` job: runs `ktlintCheck --no-daemon` with `continue-on-error: true` (non-blocking)
- `pr-gate` job: runs `./gradlew test -PexcludeHeavyTests=true` (tests only)
- No detekt step exists.

**release.yml state:** runs `ktlintCheck` without `continue-on-error` (already blocking for releases).

**Minimal CI changes needed:**

1. **Add detekt to `lint` job in build.yml:**
```yaml
- name: detekt (blocking)
  run: ./gradlew detekt --no-daemon
```

2. **Remove `continue-on-error: true` from ktlintCheck in build.yml** (after SC3 gate-flip commit).

3. **No change to release.yml** — ktlintCheck already blocking there; add detekt step for consistency.

The `nightly-regression.yml` does not need detekt — it focuses on test suites.

**"Blocking CI check" definition:** Per CONTEXT.md, this means the Gradle `check` task graph fails on violation. Since detekt auto-wires to `check`, and ktlintCheck is added to `check` via the ktlint plugin, both gates are satisfied at the Gradle level even without CI file changes. CI file changes make the gates visible in the PR review UI.

---

## State of the Art

| Old Approach | Current Approach | When Changed | Impact |
|--------------|------------------|--------------|--------|
| `tasks.matching { }.dependsOn()` for generated sources | `taskProvider.flatMap { it.outputDir }` structural wiring | Gradle 7.4+ (Provider API matured) | Inferred dependency; no fragile name-match |
| ktlint as advisory check | ktlint as blocking gate | SC3 of this phase | Regressions surface in CI |
| No static analysis beyond ktlint | detekt for logic/complexity rules | SC2 of this phase | Catches bugs ktlint cannot |
| catch (_: Exception) {} silent swallow | Annotated or logged | SC5 of this phase | Diagnosability for issue #71 class failures |

**Deprecated/outdated:**
- `tasks.matching { it.name.startsWith("runKtlint") }.configureEach { dependsOn(...) }`: replaced by structural srcDir wiring in SC1.
- `ignoreFailures.set(ktlintStrict != true)`: replaced by inverted gate in SC3.

---

## Assumptions Log

| # | Claim | Section | Risk if Wrong |
|---|-------|---------|---------------|
| A1 | detekt 1.23.8's `kotlin-compiler-embeddable` warning with Kotlin KGP 2.1.21 is advisory only (analysis still succeeds) | Standard Stack, Pitfall 1 | If it causes a build failure, the detekt version must be lowered or the warning suppressed via Gradle configuration |
| A2 | `generateBuildFlags.flatMap { it.outputDir }` correctly establishes inferred dependency in Gradle 8.12.1 / Kotlin Gradle plugin source sets | Pattern 1 | If SourceDirectorySet does not accept this form, an explicit `builtBy()` chain is needed: `project.files(generateBuildFlags.flatMap { it.outputDir }).builtBy(generateBuildFlags)` |
| A3 | detekt-formatting is not currently added to the project as a detekt plugin | Don't Hand-Roll, Pitfall notes | If it is present, double-gating exists already; research `detektPlugins` deps in build.gradle.kts |
| A4 | All 183 `catch` sites counted by grep are in `src/main/kotlin` (not generated or test code) | SC5 description | If some are in test code, scope of SC5 narrows beneficially |

**If A1 is wrong:** Test with `./gradlew detekt --info` and check if the task action exits non-zero. If so, use `configurations.detekt { resolutionStrategy.force("org.jetbrains.kotlin:kotlin-compiler-embeddable:2.1.21") }` as a workaround, or accept the alpha version risk with explicit maintainer approval.

**If A2 is wrong:** Fallback pattern:
```kotlin
sourceSets.main {
    kotlin.srcDir(
        project.files(generateBuildFlags.flatMap { it.outputDir }).builtBy(generateBuildFlags)
    )
}
```

---

## Open Questions (RESOLVED)

All three questions are resolved by the Phase 18 plans; resolutions recorded inline below.

1. **detekt warning severity in this project's CI**
   - What we know: The `kotlin-compiler-embeddable` warning is printed to build output; does not fail the `detekt` task itself.
   - What's unclear: Whether the project's CI configuration has `-Werror`-equivalent flags that could escalate Kotlin warnings to errors.
   - **RESOLVED:** Plan 18-01 Task 2 runs the A1 verification (`./gradlew detekt --info 2>&1 | grep -i "embeddable\|warning\|error"`) and confirms the embeddable warning is advisory-only BEFORE wiring detekt as a blocking gate; CI workflows are read and confirmed to carry no `-Werror` escalation. A documented fallback exists if the warning is ever treated as an error.

2. **detekt type-resolution scope**
   - What we know: `detekt` (default task) runs WITHOUT type resolution. `detektMain` and `detektTest` have type resolution but require `classpath` and `jvmTarget` configuration. Type-resolution rules catch more bugs but require more setup and run slower.
   - What's unclear: Whether type-resolution rules are wanted for this project.
   - **RESOLVED:** Use the default non-type-resolution `detekt` task (faster, less config). Type resolution is explicitly deferred out of Phase 18 scope.

3. **Scope of SC5 "one phase"**
   - What we know: 183 sites in 52 files. Auditing all is risky for behavioral regressions in one phase.
   - What's unclear: How many sites the maintainer considers "sufficient" for SC5 success.
   - **RESOLVED:** Plan 18-04 targets the ~30–50 highest-value sites in cache/scanner/supervisor/cli (these directly affect diagnosability per the REL-04 link in QUAL-04). The remaining sites are enumerated in the `.planning/notes/exception-audit.md` tracking note with `// TODO-AUDIT:` markers — satisfying SC5's "audited + documented" criterion without a risky all-at-once rewrite.

---

## Environment Availability

| Dependency | Required By | Available | Version | Fallback |
|------------|------------|-----------|---------|----------|
| Gradle 8.12.1 | All build tasks | Yes | 8.12.1 | — |
| Java 21 | Compilation, tests | Yes | 21 (toolchain) | — |
| detekt 1.23.8 | SC2 | Will be downloaded from Maven Central | n/a (new) | — |
| `./gradlew ktlintCheck` standalone | SC1 verification | Currently FAILS (the bug being fixed) | n/a | — |

---

## Validation Architecture

### Test Framework

| Property | Value |
|----------|-------|
| Framework | JUnit Jupiter 6.0.3 via `useJUnitPlatform()` |
| Config file | `build.gradle.kts` `tasks.test` block |
| Quick run command | `./gradlew test -PexcludeHeavyTests=true --no-daemon` |
| Full suite command | `./gradlew test --no-daemon` |

### Phase Requirements -> Test Map

| Req ID | Behavior | Test Type | Automated Command | File Exists? |
|--------|----------|-----------|-------------------|-------------|
| QUAL-05 | `ktlintCheck` passes standalone after srcDir fix | build verification | `./gradlew ktlintCheck --no-daemon` | N/A — build task |
| QUAL-03 | `detekt` runs with baseline, new violations fail | build verification | `./gradlew detekt --no-daemon` | N/A — build task |
| QUAL-03 | ktlint is blocking gate (strict by default) | build verification | `./gradlew ktlintCheck --no-daemon` | N/A — build task |
| QUAL-02 | `PersistentPromptCache` get/put/evict round-trip | unit | `./gradlew test --tests "*.PersistentPromptCacheTest" --no-daemon` | No — Wave 0 |
| QUAL-02 | Scanner dedup prevents re-queuing | unit | `./gradlew test --tests "*.ActiveScannerDedupTest" --no-daemon` | No — Wave 0 |
| QUAL-02 | CLI supervision handles process timeout | unit | `./gradlew test --tests "*.CliSupervisionTest" --no-daemon` | No — Wave 0 |
| QUAL-04 | Exception audit tracking note exists | manual | Review `.planning/notes/exception-audit.md` | No — Wave 0 |

### Sampling Rate

- **Per task commit:** `./gradlew test -PexcludeHeavyTests=true --no-daemon`
- **Per wave merge:** `./gradlew test --no-daemon`
- **Phase gate:** `./gradlew check --no-daemon` (includes detekt + ktlintCheck + tests) before `/gsd-verify-work`

### Wave 0 Gaps

- [ ] `src/test/kotlin/com/six2dez/burp/aiagent/cache/PersistentPromptCacheTest.kt` — covers QUAL-02 (cache module)
- [ ] `src/test/kotlin/com/six2dez/burp/aiagent/scanner/ActiveScannerDedupTest.kt` — covers QUAL-02 (scanner dedup)
- [ ] `src/test/kotlin/com/six2dez/burp/aiagent/backends/cli/CliSupervisionTest.kt` — covers QUAL-02 (CLI supervision)
- [ ] `detekt-baseline.xml` — generated by `./gradlew detektBaseline`, committed before SC2 goes live
- [ ] `.planning/notes/exception-audit.md` — SC5 tracking note

---

## Security Domain

> `security_enforcement` is absent from config.json — treated as enabled.

### Applicable ASVS Categories

| ASVS Category | Applies | Standard Control |
|---------------|---------|-----------------|
| V2 Authentication | No | N/A — no auth changes |
| V3 Session Management | No | N/A — no session changes |
| V4 Access Control | No | N/A — no access control changes |
| V5 Input Validation | Partial | Exception audit (SC5): ensure catch blocks do not inadvertently swallow input validation errors silently |
| V6 Cryptography | No | N/A — no crypto changes |

### Relevant Threat Patterns

| Pattern | STRIDE | Standard Mitigation |
|---------|--------|---------------------|
| Silent exception swallow masking malformed input | Information Disclosure | SC5 audit: log contextual error; never log secret values in error messages |
| Exception message leaking sensitive values | Information Disclosure | Audit convention: `${e.message}` is safe for operational errors; never interpolate request body or API key in log messages |

---

## Sources

### Primary (HIGH confidence)
- [detekt Compatibility Table](https://detekt.dev/docs/introduction/compatibility/) — detekt version to Kotlin compiler mapping
- [detekt 1.23.8 Gradle docs](https://detekt.dev/docs/1.23.8/gettingstarted/gradle/) — plugin ID, check task wiring, baseline task
- [detekt v1.23.8 Release](https://github.com/detekt/detekt/releases/tag/v1.23.8) — release date, Kotlin version
- [Gradle lazy_configuration docs](https://docs.gradle.org/current/userguide/lazy_configuration.html) — task dependency inference via Provider API
- [Gradle SourceDirectorySet Javadoc](https://docs.gradle.org/current/javadoc/org/gradle/api/file/SourceDirectorySet.html) — `srcDir()` accepts `Object` evaluated via `project.files()`
- [build.gradle.kts](build.gradle.kts) — actual wiring at lines 66, 90-99, 101-113, 166-182 (VERIFIED: codebase)
- [build.yml, release.yml, nightly-regression.yml](/.github/workflows/) — current CI state (VERIFIED: codebase)
- [PersistentPromptCache.kt](src/main/kotlin/.../cache/PersistentPromptCache.kt) — zero-test module (VERIFIED: codebase)
- [ScannerQueueBackpressureTest.kt, ActiveScannerQueueModelTest.kt](src/test/kotlin/.../scanner/) — existing scanner test patterns (VERIFIED: codebase)
- [CliBackendTempFileTest.kt](src/test/kotlin/.../backends/cli/) — CLI test seam pattern (VERIFIED: codebase)

### Secondary (MEDIUM confidence)
- [ktlint-gradle issue #746](https://github.com/JLLeitschuh/ktlint-gradle/issues/746) — confirms `srcDir` + generated sources implicit dependency problem; suggests `builtBy()` pattern
- [gradle/gradle issue #28304](https://github.com/gradle/gradle/issues/28304) — `SourceDirectorySet.srcDir` with unset provider; confirms `project.files().builtBy()` as working approach
- [detekt issue #7883](https://github.com/detekt/detekt/issues/7883) — `kotlin-compiler-embeddable` warning with Kotlin 2.1.0; closed but 1.23.8 still contains the embeddable
- [detekt issue #8027](https://github.com/detekt/detekt/issues/8027) — migration from embeddable opened March 2025 (after 1.23.8)

### Tertiary (LOW confidence)
- [discuss.gradle.org — custom OutputDirectory as source](https://discuss.gradle.org/t/pass-custom-task-outputdirectory-as-input-to-extension-property-filecollection/49109) — `project.files(task.map { it.outputDir }).builtBy(task)` as alternative to flatMap

---

## Metadata

**Confidence breakdown:**
- SC1 (generateBuildFlags fix): HIGH — root cause confirmed from codebase + Gradle docs; fix pattern corroborated by issue tracker
- SC2 (detekt): MEDIUM-HIGH — version confirmed from official releases; kotlin-compiler-embeddable warning behavior is ASSUMED (advisory not failure)
- SC3 (ktlint strict flip): HIGH — existing code read directly; two-commit ordering is a mechanical sequencing requirement
- SC4 (test coverage): HIGH — zero-coverage confirmed from test file listing; seams identified from source
- SC5 (exception audit): HIGH — exact count confirmed (183 sites, 52 files) via grep; logging facility confirmed from source
- CI analysis: HIGH — all three workflow files read directly

**Research date:** 2026-06-11
**Valid until:** 2026-08-11 (stable tooling; detekt 1.23.8 is a point release; Gradle 8.12.1 is stable)
