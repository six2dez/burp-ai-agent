import org.gradle.api.tasks.PathSensitivity
import org.gradle.api.tasks.testing.Test
import org.jetbrains.kotlin.gradle.tasks.KotlinCompile
import javax.xml.parsers.DocumentBuilderFactory

plugins {
    kotlin("jvm") version "2.1.21"
    kotlin("plugin.serialization") version "2.1.21"
    id("com.github.johnrengelman.shadow") version "8.1.1"
    id("org.jlleitschuh.gradle.ktlint") version "12.1.1"
    id("org.cyclonedx.bom") version "1.10.0"
    id("io.gitlab.arturbosch.detekt") version "1.23.8"
    jacoco
}

group = "com.six2dez.burp"
version = "1.0.0"

repositories {
    mavenCentral()
    maven("https://www.jetbrains.com/intellij-repository/releases")
    maven("https://packages.jetbrains.team/maven/p/ij/intellij-dependencies")
}

dependencies {
    // Burp Montoya API (compileOnly, Burp provides it at runtime)
    compileOnly("net.portswigger.burp.extensions:montoya-api:2026.2")

    // JSON
    implementation("com.fasterxml.jackson.core:jackson-databind:2.22.1")
    implementation("com.fasterxml.jackson.module:jackson-module-kotlin:2.22.1")

    // HTTP client (Ollama + webhooks)
    implementation("com.squareup.okhttp3:okhttp:5.4.0")

    // MCP Server (Ktor + MCP SDK)
    implementation("io.modelcontextprotocol:kotlin-sdk:0.5.0")
    implementation("io.ktor:ktor-server-core:3.5.2")
    implementation("io.ktor:ktor-server-netty:3.5.2")
    implementation("io.ktor:ktor-server-cors:3.5.2")
    implementation("io.ktor:ktor-server-sse:3.5.2")
    implementation("io.ktor:ktor-server-content-negotiation:3.5.2")
    implementation("io.ktor:ktor-serialization-kotlinx-json:3.5.2")
    // Phase 16: Ktor CLIENT modules (pin to 3.1.3 to match server-side Ktor family)
    implementation("io.ktor:ktor-client-core:3.5.2")
    implementation("io.ktor:ktor-client-cio:3.5.2")
    // kotlin-logging: transitive via kotlin-sdk:0.5.0 StdioClientTransport; declared explicitly to pin version
    implementation("io.github.oshai:kotlin-logging-jvm:7.0.7")
    implementation("org.jetbrains.kotlinx:kotlinx-serialization-json:1.8.1")
    implementation("org.jetbrains.kotlinx:kotlinx-io-core:0.5.4")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-core:1.9.0")

    // Logging façade (we keep it minimal; Burp logs are also used)
    implementation("org.slf4j:slf4j-api:2.0.16")
    implementation("org.slf4j:slf4j-simple:2.0.16")

    testImplementation(kotlin("test"))
    testImplementation("org.junit.jupiter:junit-jupiter:6.0.3")
    testImplementation("net.portswigger.burp.extensions:montoya-api:2026.2")
    testImplementation("org.mockito.kotlin:mockito-kotlin:5.4.0")
    testImplementation("com.squareup.okhttp3:mockwebserver:5.4.0")
}

java {
    toolchain {
        languageVersion.set(JavaLanguageVersion.of(21))
    }
}

// -PstoreBuild=true produces the BApp Store artifact (native tools only).
// Default (false) produces the full GitHub release artifact.
val storeBuild = providers.gradleProperty("storeBuild").orNull == "true"

abstract class GenerateBuildFlagsTask : DefaultTask() {
    @get:Input
    abstract val storeBuildFlag: Property<Boolean>

    @get:Input
    abstract val version: Property<String>

    @get:OutputDirectory
    abstract val outputDir: DirectoryProperty

    @TaskAction
    fun generate() {
        val pkgDir =
            outputDir
                .get()
                .asFile
                .resolve("com/six2dez/burp/aiagent")
                .also { it.mkdirs() }
        pkgDir.resolve("BuildFlags.kt").writeText(
            """
package com.six2dez.burp.aiagent

object BuildFlags {
    const val STORE_BUILD = ${storeBuildFlag.get()}
    const val VERSION = "${version.get()}"
}
            """.trimIndent() + "\n",
        )
    }
}

val generateBuildFlags by tasks.registering(GenerateBuildFlagsTask::class) {
    group = "build"
    description = "Generates BuildFlags.kt with a compile-time store-build flag and the project version"
    storeBuildFlag.set(storeBuild)
    // SEC-05 / P11: capture the project version at CONFIGURATION time. gradle.properties sets
    // org.gradle.configuration-cache=true, so reading any Project API (including project.version)
    // from inside @TaskAction generate() would fail the build. The Property carries the captured
    // value into execution instead.
    version.set(project.version.toString())
    outputDir.set(layout.buildDirectory.dir("generated/buildflags"))
}

sourceSets.main {
    // Pass the task's own outputDir through the TaskProvider — Gradle infers the dependency
    // for any task consuming this source directory (including runKtlintCheckOverMainSourceSet).
    kotlin.srcDir(generateBuildFlags.flatMap { it.outputDir })
}

tasks.withType<KotlinCompile> {
    dependsOn(generateBuildFlags)
    compilerOptions {
        jvmTarget.set(org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_21)
        freeCompilerArgs.addAll(listOf("-Xjsr305=strict"))
    }
}

tasks.jar {
    enabled = false
}

tasks.shadowJar {
    if (storeBuild) {
        archiveBaseName.set("Custom-AI-Agent")
    } else {
        archiveBaseName.set("Custom-AI-Agent-full")
    }
    archiveClassifier.set("")
    mergeServiceFiles()
    isZip64 = true

    // Shadow JAR should include all runtime dependencies
    configurations = listOf(project.configurations.runtimeClasspath.get())
}

tasks.build {
    dependsOn(tasks.shadowJar)
}

tasks.test {
    useJUnitPlatform()
    jvmArgs("-ea", "-Djava.awt.headless=true") // Enable JVM assertions so EDT assert() fires in CI (REL-01 SC1 gate)
    // The headless flag above serves the Phase 22 SC4 harness (ChatPanelTestHarness), which
    // constructs a REAL ChatPanel and drives its REAL Send button. ubuntu-latest is headless anyway;
    // forcing the flag makes a developer Mac behave identically instead of silently taking the
    // windowed path and hiding a CI-only failure.
    // The generated BuildFlags.STORE_BUILD offers no other seam a test can compare against, so
    // McpBuildFlagsVersionTest used to assert a literal false — which made `-PstoreBuild=true`, the
    // BApp Store artifact build path, fail its own test suite. Passing the already-resolved
    // `storeBuild` Boolean (configuration-cache-safe, exactly as tasks.shadowJar consumes it) lets
    // the test assert that the generated constant tracks the Gradle property under either build.
    systemProperty("storeBuild.expected", storeBuild.toString())
    // SEC-06 / SC1: DecisionsAdrTest reads these two files from disk at runtime rather than from the
    // compiled classpath, so Gradle cannot infer them. Without declaring them, a change to EITHER is
    // invisible to the up-to-date check and the build cache — and a commit that edits only DECISIONS.md,
    // or only the SecTier KDoc, produces byte-identical compiled output and therefore an identical
    // cache key. The test task would be restored from cache and the guard would never run, in exactly
    // the case it exists to catch. Measured: mutating the AUTO sentence left `./gradlew test` GREEN
    // until `cleanTest` forced a re-run.
    inputs
        .file("DECISIONS.md")
        .withPropertyName("adrRecord")
        .withPathSensitivity(PathSensitivity.RELATIVE)
    inputs
        .file("src/main/kotlin/com/six2dez/burp/aiagent/mcp/McpToolCatalog.kt")
        .withPropertyName("secTierKdocSource")
        .withPathSensitivity(PathSensitivity.RELATIVE)
    // QUAL-07 / SC3: DetektBaselineBoundTest counts `<ID>` entries in detekt-baseline.xml from disk to
    // enforce ADR-17 clause 1 (the baseline shrinks and is never appended to). Same stale-cache defect
    // as the two declarations above, and in its most dangerous form: a commit that ONLY appends a
    // baseline entry produces byte-identical compiled output, so without this declaration the cache key
    // is unchanged and the guard is served from cache in exactly the commit that violates the rule.
    inputs
        .file("detekt-baseline.xml")
        .withPropertyName("detektBaseline")
        .withPathSensitivity(PathSensitivity.RELATIVE)
    // DOC-03 / SC5 / SC6: SecurityDocsTest reads these six markdown files from disk — the same
    // stale-cache defect as the DECISIONS.md declaration above, in its purest form. A
    // documentation-only edit produces BYTE-IDENTICAL compiled output, so without these declarations
    // the cache key is unchanged and the guard is served from cache in exactly the commit that breaks
    // it. Measured for this build: with `securityPolicy` declared, mutating one asserted word in
    // SECURITY.md re-executed `:test` (11 tests, 1 failed) instead of reporting UP-TO-DATE.
    inputs
        .file("SECURITY.md")
        .withPropertyName("securityPolicy")
        .withPathSensitivity(PathSensitivity.RELATIVE)
    inputs
        .file("README.md")
        .withPropertyName("readmeClaims")
        .withPathSensitivity(PathSensitivity.RELATIVE)
    inputs
        .file("SPEC.md")
        .withPropertyName("specClaims")
        .withPathSensitivity(PathSensitivity.RELATIVE)
    inputs
        .file("docs/ui-safety-guide.md")
        .withPropertyName("uiSafetyRunbook")
        .withPathSensitivity(PathSensitivity.RELATIVE)
    inputs
        .file("docs/anthropic-backend.md")
        .withPropertyName("anthropicBackendDoc")
        .withPathSensitivity(PathSensitivity.RELATIVE)
    inputs
        .file("docs/external-mcp-servers.md")
        .withPropertyName("externalMcpDoc")
        .withPathSensitivity(PathSensitivity.RELATIVE)
    // SEC-06 / SC5 / CR-02: ToolApprovalGateVisibilityTest reads this file from disk to pin
    // `approvedOrigin` as private and `ModelApproved` as file-private, for the same reason and with the
    // same caveat as the two declarations above. A visibility widening does change the compiled output,
    // but a comment-only edit to the file does not — and this guard's source-text half asserts on text
    // that includes the surrounding declarations. Undeclared, that edit produces an identical cache key
    // and the test task is served from cache with the guard never running (the 22-09 defect).
    inputs
        .file("src/main/kotlin/com/six2dez/burp/aiagent/mcp/ToolApprovalGate.kt")
        .withPropertyName("originVisibilitySource")
        .withPathSensitivity(PathSensitivity.RELATIVE)
    // SEC-06 / SC4 / WR-09: ChatPanelToolGateTest reads this file from disk in `functionBody` to make
    // the two structural assertions it cannot drive headlessly — the modal-dialog path in
    // `userDialogPathIsNotDoublePrompted`, and `resolvePending`'s no-followup rule in
    // `shutdownResolvesAllPendingDecisionsWithoutSendingATurn`. Same defect as the three declarations
    // above, and the one 22-09 measured on its own ADR guard: an edit that changes the source text but
    // not the compiled bytecode — a comment replaced in place, a string reflowed — produces an
    // identical cache key, so the test task is served from cache and the structural guard never runs in
    // exactly the case it exists to catch.
    inputs
        .file("src/main/kotlin/com/six2dez/burp/aiagent/ui/ChatPanel.kt")
        .withPropertyName("chatPanelStructuralSource")
        .withPathSensitivity(PathSensitivity.RELATIVE)
    // REL-05 / SC4 / Rule C-2: SettingsSaveAsyncTest reads this file from disk in
    // `restoreDefaultsSource` to assert the one ordering it cannot drive headlessly — the
    // restore-defaults path opens with `JOptionPane.showConfirmDialog`, and `getRootFrame()` throws
    // `HeadlessException`. Same defect as the four declarations above: moving
    // `"Defaults restored and applied."` back out of the completion callback changes the source text
    // but can leave the compiled output of the surrounding class close enough that the cache key
    // survives, so the guard would be served from cache and never run in exactly the case it exists
    // to catch.
    inputs
        .file("src/main/kotlin/com/six2dez/burp/aiagent/ui/SettingsPanelActions.kt")
        .withPropertyName("settingsActionsStructuralSource")
        .withPathSensitivity(PathSensitivity.RELATIVE)
    // REL-05 / SC4 / CR-02: SettingsPersistQueueTest reads this file from disk in
    // `everyMainTabSettingsWriteGoesThroughThePersistQueue` to assert the four mention counts pinned in
    // the KDoc ledger above `MainTab.persistSettings` — that every enumerated settings write goes
    // through the persist queue rather than calling settingsRepo.save() inline on the EDT. Same defect
    // as the five declarations above: reverting one call site back to an inline save changes the source
    // text but leaves the surrounding compiled output close enough that the cache key can survive, so
    // the guard would be served from cache and never run in exactly the case it exists to catch (the
    // 22-09 stale-cache defect).
    inputs
        .file("src/main/kotlin/com/six2dez/burp/aiagent/ui/MainTab.kt")
        .withPropertyName("mainTabPersistSource")
        .withPathSensitivity(PathSensitivity.RELATIVE)
    // REL-05 / SC4 / Rule T-3: SettingsSaveAsyncTest's corrected structural assertion now reads THIS
    // file too — the narrowed claim is that applySettingsToUi's component writes stay on the EDT while
    // its three host notifications are suppressed at the restore call site, and the `notifyHosts` guard
    // that makes that true lives here. Same 22-09 stale-cache defect as the six declarations above:
    // deleting the guard changes the source text but can leave the cache key intact.
    inputs
        .file("src/main/kotlin/com/six2dez/burp/aiagent/ui/SettingsPanelSettingsIO.kt")
        .withPropertyName("settingsIoStructuralSource")
        .withPathSensitivity(PathSensitivity.RELATIVE)
    // REL-06 / SC1 / REL-07: SchedulerGuardCoverageTest walks the WHOLE main source tree from disk and
    // asserts that only three files call a recurring schedule directly. A per-file declaration like the
    // seven above would be blind to a scheduler introduced in an eighth, undeclared file — which is the
    // exact defect the allowlist exists to catch, so the declaration has to be as wide as the assertion.
    // This is the first `inputs.dir` in this build and it deliberately supersedes per-file entries for
    // every Phase 24 structural assertion: REL-06-D here, REL-07-D and REL-07-F on CliBackend.kt, and
    // REL-07-G on App.kt / ActiveAiScanner.kt / AgentSupervisor.kt. Accepted cost: `tasks.test` re-runs
    // on any main-source edit. The defect it prevents is the measured 22-09 one recorded at :170-176 —
    // mutating source text without changing bytecode yields an identical cache key, so the guard is
    // served from cache in exactly the commit that breaks it.
    inputs
        .dir("src/main/kotlin")
        .withPropertyName("mainSourceTreeStructuralInputs")
        .withPathSensitivity(PathSensitivity.RELATIVE)
    val excludeHeavyTests =
        (project.findProperty("excludeHeavyTests") as? String)
            ?.trim()
            ?.equals("true", ignoreCase = true) == true
    if (excludeHeavyTests) {
        filter {
            excludeTestsMatching("*IntegrationTest")
            excludeTestsMatching("*ConcurrencyTest")
            excludeTestsMatching("*BackpressureTest")
            excludeTestsMatching("*RestartPolicyTest")
            excludeTestsMatching("*SupervisionTest") // WR-03: 30s coerced-timeout floor — excluded from fast PR gate
        }
    }
}

// REL-05 / SC1 / S-10: `tasks.test` above enables `-ea`, so a green McpToolExecutorEdtGuardTest there
// proves the guard throws in a JVM where the debug-time assertion facility is ON — which is not the JVM
// SC1 is about. Shipped Burp runs WITHOUT `-ea`, and SC1's whole objection to the existing ChatPanel
// assertion is that it is a no-op there. This task re-runs that one class with assertions DISABLED, so
// "the guard fires where it matters" is demonstrated rather than asserted.
//
// WR-11 corrected the second half of this comment. It stays out of the `check` lifecycle task on
// purpose — `check` is the fast path and this is a deliberate, separately named gate — AND it is
// invoked explicitly by `.github/workflows/build.yml`'s pr-gate step on all three OSes and by
// `.github/workflows/nightly-regression.yml`. The justification it used to carry, that it "duplicates
// coverage the fast PR gate already has", was wrong in exactly the way that mattered: the fast PR gate
// runs with `-ea`, where an `assert`-based guard is equally green, so reverting `check(...)` to
// `assert(...)` in McpToolExecutorImpl would have left every automated gate passing.
// Run it locally with: ./gradlew edtGuardWithoutAssertionsTest
tasks.register<Test>("edtGuardWithoutAssertionsTest") {
    description = "Runs the executor's EDT door guard with JVM assertions disabled (REL-05 / SC1)."
    group = "verification"
    useJUnitPlatform()
    val testSourceSet = sourceSets.test.get()
    testClassesDirs = testSourceSet.output.classesDirs
    classpath = testSourceSet.runtimeClasspath
    // `-da`, and no `-ea` anywhere: this is the flag the whole task exists for.
    jvmArgs("-da", "-Djava.awt.headless=true")
    systemProperty("storeBuild.expected", storeBuild.toString())
    filter {
        includeTestsMatching("*McpToolExecutorEdtGuardTest")
    }
}

tasks.register<Test>("nightlyRegressionTest") {
    description = "Runs integration, concurrency, and resilience suites intended for nightly validation."
    group = "verification"
    useJUnitPlatform()
    filter {
        includeTestsMatching("*IntegrationTest")
        includeTestsMatching("*ConcurrencyTest")
        includeTestsMatching("*BackpressureTest")
        includeTestsMatching("*RestartPolicyTest")
        includeTestsMatching("*SupervisionTest") // WR-03: still runs in nightly regression
    }
}

ktlint {
    version.set("1.5.0")
    android.set(false)
    // Strict by default: fails unless -PktlintLenient=true is passed as an escape hatch.
    // Mass-format commit (style(sc3)) preceded this gate-flip — codebase is clean.
    ignoreFailures.set(
        (project.findProperty("ktlintLenient") as? String)?.equals("true", ignoreCase = true) == true,
    )
    reporters {
        reporter(org.jlleitschuh.gradle.ktlint.reporter.ReporterType.PLAIN)
        reporter(org.jlleitschuh.gradle.ktlint.reporter.ReporterType.CHECKSTYLE)
    }
    filter {
        exclude("**/build/**")
        exclude("**/generated/**")
    }
}

detekt {
    buildUponDefaultConfig = true // extend defaults, not replace
    allRules = false // only default ruleset rules
    baseline = file("detekt-baseline.xml") // committed baseline; generate with: ./gradlew detektBaseline
    parallel = true
    config.setFrom(files("detekt.yml")) // project-specific overrides
}

tasks.withType<Test> {
    finalizedBy(tasks.named("jacocoTestReport"))
}

tasks.named<JacocoReport>("jacocoTestReport") {
    dependsOn(tasks.named("test"))
    reports {
        xml.required.set(true)
        html.required.set(true)
    }
}

// QUAL-06 / SC2: the fourteen coverage floors sealed in
// `.planning/phases/26-coverage-static-analysis-debt-docs/26-COVERAGE.md` were RECORDED there and
// enforced by nothing — a regression below any of them was invisible to `./gradlew check`. The floors
// below are the sealed "Floor" column verbatim, NOT the "Measured" column: pinning measured values
// would turn every future refactor red for no reason, and pinning below the floor would silently move
// the seal. Twelve of the fourteen map onto JaCoCo's element model (BUNDLE / PACKAGE / SOURCEFILE);
// floor 3, the `mcp` tree aggregate across four packages, is not a JaCoCo element and is enforced
// separately by `jacocoMcpTreeCoverageVerification` below.
val jacocoLineFloors =
    mapOf(
        // floor 1 - package backends/cli, line >= 36.0%
        "com.six2dez.burp.aiagent.backends.cli" to "0.360",
        // floor 4 - package mcp/tools, line >= 49.0%
        "com.six2dez.burp.aiagent.mcp.tools" to "0.490",
        // floor 5 - package mcp/schema, line >= 70.0%
        "com.six2dez.burp.aiagent.mcp.schema" to "0.700",
        // floor 9 - package config, line >= 96.2%
        "com.six2dez.burp.aiagent.config" to "0.962",
        // floor 11 - package redact, line >= 97.5%
        "com.six2dez.burp.aiagent.redact" to "0.975",
    )

val jacocoBranchFloors =
    mapOf(
        // floor 10 - package config, branch >= 91.0%
        "com.six2dez.burp.aiagent.config" to "0.910",
        // floor 12 - package redact, branch >= 93.0%
        "com.six2dez.burp.aiagent.redact" to "0.930",
    )

val jacocoSourceFileLineFloors =
    mapOf(
        // floor 2 - CliBackend.kt, line >= 26.0%
        "com/six2dez/burp/aiagent/backends/cli/CliBackend.kt" to "0.260",
        // floor 6 - McpToolHelpers.kt, line >= 58.0%
        "com/six2dez/burp/aiagent/mcp/tools/McpToolHelpers.kt" to "0.580",
        // floor 7 - McpToolModels.kt, line >= 50.0%
        "com/six2dez/burp/aiagent/mcp/tools/McpToolModels.kt" to "0.500",
        // floor 8 - Serialization.kt, line >= 70.0%
        "com/six2dez/burp/aiagent/mcp/schema/Serialization.kt" to "0.700",
    )

// The PACKAGE floors above are written in DOTTED form and the SOURCEFILE floors below in SLASHED
// form. That is not an inconsistency: JaCoCo names PACKAGE elements with dots and SOURCEFILE elements
// with the slashed package path plus the file name, and an include pattern that does not match ANY
// element makes its rule pass VACUOUSLY with no output at all. Measured while wiring this: with the
// packages written in slashed form, all seven package rules were silently skipped and the build was
// green with the floors set to 99.9%. Verify any change here by raising a floor above the measured
// value and confirming the rule actually reports a violation.

// floor 3 - the `mcp` tree (mcp, mcp/tools, mcp/schema, mcp/external), line >= 65.0%.
val jacocoMcpTreePackages =
    listOf(
        "com/six2dez/burp/aiagent/mcp",
        "com/six2dez/burp/aiagent/mcp/tools",
        "com/six2dez/burp/aiagent/mcp/schema",
        "com/six2dez/burp/aiagent/mcp/external",
    )
val jacocoMcpTreeLineFloor = 0.650

tasks.named<JacocoCoverageVerification>("jacocoTestCoverageVerification") {
    // `tasks.withType<Test>` already finalises the test task with jacocoTestReport, but relying on that
    // ordering would leave this task reading whatever exec data happened to be on disk. Depend on the
    // report explicitly so the verification cannot run against a stale or absent one.
    dependsOn(tasks.named<JacocoReport>("jacocoTestReport"))
    violationRules {
        rule {
            // floor 13 - project-wide line >= 57.0%
            element = "BUNDLE"
            limit {
                counter = "LINE"
                value = "COVEREDRATIO"
                minimum = "0.570".toBigDecimal()
            }
            // floor 14 - project-wide branch >= 34.8%
            limit {
                counter = "BRANCH"
                value = "COVEREDRATIO"
                minimum = "0.348".toBigDecimal()
            }
        }
        jacocoLineFloors.forEach { (pkg, floor) ->
            rule {
                element = "PACKAGE"
                includes = listOf(pkg)
                limit {
                    counter = "LINE"
                    value = "COVEREDRATIO"
                    minimum = floor.toBigDecimal()
                }
            }
        }
        jacocoBranchFloors.forEach { (pkg, floor) ->
            rule {
                element = "PACKAGE"
                includes = listOf(pkg)
                limit {
                    counter = "BRANCH"
                    value = "COVEREDRATIO"
                    minimum = floor.toBigDecimal()
                }
            }
        }
        jacocoSourceFileLineFloors.forEach { (sourceFile, floor) ->
            rule {
                element = "SOURCEFILE"
                includes = listOf(sourceFile)
                limit {
                    counter = "LINE"
                    value = "COVEREDRATIO"
                    minimum = floor.toBigDecimal()
                }
            }
        }
    }
}

// Floor 3 has no JaCoCo element to attach to: `mcp` tree is an aggregate over four sibling packages,
// and JaCoCo offers BUNDLE, PACKAGE, SOURCEFILE, CLASS and METHOD but nothing between BUNDLE and
// PACKAGE. Decomposing it into four per-package floors would NOT be the same assertion - two of the
// four packages sit below 65% individually while the aggregate is above it - so the aggregate is
// computed here from the same XML report the other twelve floors are verified against.
val jacocoMcpTreeCoverageVerification =
    tasks.register("jacocoMcpTreeCoverageVerification") {
        group = "verification"
        description = "Verifies the sealed mcp-tree line coverage floor (phase 26 SC2 floor 3)."
        val reportFile = layout.buildDirectory.file("reports/jacoco/test/jacocoTestReport.xml")
        val packages = jacocoMcpTreePackages
        val floor = jacocoMcpTreeLineFloor
        dependsOn(tasks.named<JacocoReport>("jacocoTestReport"))
        inputs.file(reportFile).withPathSensitivity(PathSensitivity.RELATIVE)
        outputs.upToDateWhen { false }
        doLast {
            val xml = reportFile.get().asFile
            check(xml.isFile) { "Jacoco XML report not found at ${xml.absolutePath}." }
            val factory = DocumentBuilderFactory.newInstance()
            factory.isNamespaceAware = false
            factory.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false)
            val document = factory.newDocumentBuilder().parse(xml)
            var covered = 0L
            var missed = 0L
            val packageNodes = document.getElementsByTagName("package")
            for (index in 0 until packageNodes.length) {
                val node = packageNodes.item(index) as org.w3c.dom.Element
                if (node.getAttribute("name") !in packages) continue
                var child = node.firstChild
                while (child != null) {
                    val element = child as? org.w3c.dom.Element
                    if (element != null &&
                        element.tagName == "counter" &&
                        element.getAttribute("type") == "LINE"
                    ) {
                        covered += element.getAttribute("covered").toLong()
                        missed += element.getAttribute("missed").toLong()
                    }
                    child = child.nextSibling
                }
            }
            val total = covered + missed
            check(total > 0L) {
                "No LINE counters found for the mcp tree packages $packages in ${xml.absolutePath}. " +
                    "A floor that measures nothing passes vacuously - fix the package names here."
            }
            val ratio = covered.toDouble() / total.toDouble()
            check(ratio >= floor) {
                "mcp tree line coverage is %.2f%% (%d/%d), below the sealed floor of %.1f%% "
                    .format(ratio * 100, covered, total, floor * 100) +
                    "(phase 26 SC2 floor 3, 26-COVERAGE.md). Add tests - do NOT lower the floor."
            }
            logger.lifecycle(
                "mcp tree line coverage: %.2f%% (%d/%d), floor %.1f%% - MET"
                    .format(ratio * 100, covered, total, floor * 100),
            )
        }
    }

tasks.named("check") {
    dependsOn(tasks.named("jacocoTestCoverageVerification"))
    dependsOn(jacocoMcpTreeCoverageVerification)
}

tasks.named<org.cyclonedx.gradle.CycloneDxTask>("cyclonedxBom") {
    includeConfigs.set(listOf("runtimeClasspath"))
    outputFormat.set("json")
    outputName.set("bom")
    destination.set(
        layout.buildDirectory
            .dir("reports/sbom")
            .get()
            .asFile,
    )
}
