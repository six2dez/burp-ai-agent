import com.github.jengelman.gradle.plugins.shadow.tasks.ShadowJar
import org.gradle.api.tasks.PathSensitivity
import org.gradle.api.tasks.testing.Test
import org.gradle.api.tasks.testing.logging.TestExceptionFormat
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
version = "1.0.1"

repositories {
    mavenCentral()
    maven("https://www.jetbrains.com/intellij-repository/releases")
    maven("https://packages.jetbrains.team/maven/p/ij/intellij-dependencies")
}

dependencies {
    // Burp Montoya API (compileOnly, Burp provides it at runtime)
    compileOnly("net.portswigger.burp.extensions:montoya-api:2026.2")

    // JSON
    // Jackson's Gradle module metadata imports its BOM, so these two versions also align jackson-core and jackson-annotations
    implementation("com.fasterxml.jackson.core:jackson-databind:2.22.3")
    implementation("com.fasterxml.jackson.module:jackson-module-kotlin:2.22.3")

    // HTTP client (Ollama + webhooks)
    implementation("com.squareup.okhttp3:okhttp:5.4.0")

    // MCP Server (Ktor + MCP SDK)
    // Phase 29 / NET-02 (RESEARCH Pitfall 2, OQ6): the SDK pulls both CIO engines transitively. The store
    // MCP server runs on Netty and opens no client connection of its own, so neither CIO engine is on the
    // store classpath; the full build gets the client engine back below, for the external MCP client.
    implementation("io.modelcontextprotocol:kotlin-sdk:0.5.0") {
        exclude(group = "io.ktor", module = "ktor-client-cio")
        exclude(group = "io.ktor", module = "ktor-server-cio")
    }
    implementation("io.ktor:ktor-server-core:3.1.3")
    implementation("io.ktor:ktor-server-netty:3.1.3")
    // Ktor 3.1.3 pulls Netty 4.1.119, which has known advisories; the BOM pins the patched 4.1.x line without a Ktor upgrade
    implementation(platform("io.netty:netty-bom:4.1.138.Final"))
    implementation("io.ktor:ktor-server-cors:3.1.3")
    implementation("io.ktor:ktor-server-sse:3.1.3")
    implementation("io.ktor:ktor-server-content-negotiation:3.1.3")
    implementation("io.ktor:ktor-serialization-kotlinx-json:3.1.3")
    // Phase 16 Ktor CLIENT modules: declared in the `full` dependencies block below (NET-02).
    // kotlin-logging: transitive via kotlin-sdk:0.5.0 StdioClientTransport; declared explicitly to pin version
    implementation("io.github.oshai:kotlin-logging-jvm:7.0.7")
    implementation("org.jetbrains.kotlinx:kotlinx-serialization-json:1.8.1")
    implementation("org.jetbrains.kotlinx:kotlinx-io-core:0.5.4")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-core:1.9.0")

    // Logging façade (we keep it minimal; Burp logs are also used)
    implementation("org.slf4j:slf4j-api:2.0.20")
    implementation("org.slf4j:slf4j-simple:2.0.20")

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

abstract class GenerateBuildFlagsTask : DefaultTask() {
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
    const val VERSION = "${version.get()}"
}
            """.trimIndent() + "\n",
        )
    }
}

// Phase 30 / CI-01: the two build outputs storeJarContentTest reads from disk, handed to its JVM as system
// properties. Gradle cannot infer a file a test opens by path, so they are declared here as annotated
// properties: `jvmArgumentProviders` is a @Nested input of the Test task, which makes both the store JAR and
// the src/full class directories task inputs. A changed JAR therefore re-runs the inspection instead of
// being served from cache (the 22-09 stale-cache defect class). A lambda provider would be a Java lambda,
// which Gradle cannot fingerprint as a nested input, so this is a class (RESEARCH assumption A1).
abstract class StoreJarInspectionArgs : CommandLineArgumentProvider {
    @get:InputFile
    @get:PathSensitive(PathSensitivity.NONE)
    abstract val storeJar: RegularFileProperty

    @get:InputFiles
    @get:PathSensitive(PathSensitivity.RELATIVE)
    abstract val fullClassDirs: ConfigurableFileCollection

    override fun asArguments(): Iterable<String> =
        listOf(
            "-Dburp.aiagent.storeJar=${storeJar.get().asFile.absolutePath}",
            "-Dburp.aiagent.fullClassDirs=" + fullClassDirs.files.joinToString(File.pathSeparator) { it.absolutePath },
        )
}

val generateBuildFlags by tasks.registering(GenerateBuildFlagsTask::class) {
    group = "build"
    // Phase 29 / BUILD-04: VERSION is the only generated constant. The flavor is decided by which
    // source sets a JAR packages (bappJar: main; fullJar: main + full), never by a compile-time flag.
    description = "Generates BuildFlags.kt with the project version"
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
    // Main ONLY: the `full` source set sees BuildFlags through main's output, so adding the
    // generated directory there too would compile a second BuildFlags class into the full JAR.
    kotlin.srcDir(generateBuildFlags.flatMap { it.outputDir })
}

// Phase 29 / BUILD-01 (D-01, D-16): two flavors from two source sets. `src/main` is the core that
// both JARs carry and the ONLY input of the BApp Store JAR; `src/full` holds what ships in the GitHub
// build alone. `src/test` keeps its default classpath (main only), which is the compile-time proof that
// core code and store tests never reference a full-only class. `src/fullTest` sees all three outputs so
// full tests reuse TestSettings and the test rigs. Store and full classpaths are never merged in one
// Test task: store tests must never run with `full` on the classpath.
val fullSourceSet =
    sourceSets.create("full") {
        compileClasspath += sourceSets.main.get().output
        runtimeClasspath += sourceSets.main.get().output
    }
val fullTestSourceSet =
    sourceSets.create("fullTest") {
        compileClasspath += sourceSets.main.get().output + fullSourceSet.output + sourceSets.test.get().output
        runtimeClasspath += sourceSets.main.get().output + fullSourceSet.output + sourceSets.test.get().output
    }
configurations["fullImplementation"].extendsFrom(configurations.implementation.get())
// Montoya stays compileOnly in the full flavor too: Burp provides it at runtime.
configurations["fullCompileOnly"].extendsFrom(configurations.compileOnly.get())
configurations["fullRuntimeOnly"].extendsFrom(configurations.runtimeOnly.get())
configurations["fullTestImplementation"].extendsFrom(
    configurations["fullImplementation"],
    configurations.testImplementation.get(),
)
configurations["fullTestRuntimeOnly"].extendsFrom(
    configurations["fullRuntimeOnly"],
    configurations.testRuntimeOnly.get(),
)

val fullImplementation by configurations.getting

dependencies {
    // Phase 16: Ktor CLIENT modules (pin to 3.1.3 to match server-side Ktor family).
    // Phase 29 / NET-02: full build only - the external MCP client (ExternalMcpClientManager). The store
    // runtime classpath, and so the BApp Store JAR, carries no Ktor client engine.
    fullImplementation("io.ktor:ktor-client-core:3.1.3")
    fullImplementation("io.ktor:ktor-client-cio:3.1.3")
}

kotlin {
    // Association lets src/full see main's `internal` API (much of mcp/tools is internal) and lets
    // src/fullTest reuse the internal test helpers in src/test.
    val compilations = target.compilations
    compilations.getByName("full").associateWith(compilations.getByName("main"))
    compilations.getByName("fullTest").associateWith(compilations.getByName("main"))
    compilations.getByName("fullTest").associateWith(compilations.getByName("full"))
    compilations.getByName("fullTest").associateWith(compilations.getByName("test"))
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

// Phase 29 / BUILD-02 (D-04): one explicit Shadow task per flavor. A registered ShadowJar task does
// NOT inherit the excludes the Shadow plugin applies to `shadowJar` alone, and a signed dependency's
// .SF/.DSA/.RSA left in a fat JAR makes Burp reject it ("Invalid signature file digest"), so both tasks
// repeat them.
val shadowDefaultExcludes =
    arrayOf("META-INF/INDEX.LIST", "META-INF/*.SF", "META-INF/*.DSA", "META-INF/*.RSA", "module-info.class")

val bappJar by tasks.registering(ShadowJar::class) {
    group = "build"
    description = "Builds the BApp Store JAR from src/main only."
    // The EntryPoint contract in BappManifest.bmf. This is the ONLY place the store file name appears in
    // the build script (pinned by BappManifestTest): no other task may write a file under this name.
    archiveFileName.set("custom-ai-agent-bapp.jar")
    from(sourceSets.main.get().output)
    configurations = listOf(project.configurations.runtimeClasspath.get())
    mergeServiceFiles()
    exclude(*shadowDefaultExcludes)
    // Phase 29 / 29-12: incremental Kotlin compilation leaves the empty directory of a package that moved
    // to src/full (backends/cli/) in build/classes. Without this the store JAR carries that empty
    // directory entry, and a content inspection of the store JAR cannot tell it from a leaked package.
    includeEmptyDirs = false
    // Phase 29 / NET-02 (OQ6): the store build ships no MCP client. The SDK artifact carries its client
    // package (Client, SseClientTransport, StdioClientTransport, ...) next to the server classes the store
    // MCP server uses; the client half is stripped here, and nothing in src/main references it.
    exclude("io/modelcontextprotocol/kotlin/sdk/client/**")
    isZip64 = true
}

val fullJar by tasks.registering(ShadowJar::class) {
    group = "build"
    description = "Builds the GitHub full JAR from src/main + src/full."
    archiveBaseName.set("Custom-AI-Agent-full")
    archiveClassifier.set("")
    from(sourceSets.main.get().output, fullSourceSet.output)
    configurations = listOf(project.configurations["fullRuntimeClasspath"])
    // Merges the core and full META-INF/services files for the same SPI into one.
    mergeServiceFiles()
    exclude(*shadowDefaultExcludes)
    isZip64 = true
}

// Phase 29 / BUILD-02: a bare `./gradlew shadowJar` used to build the full flavor silently, so a
// default BuildCommand would have published the non-compliant JAR. It now refuses to run and names
// the two flavor tasks instead. The action references no `project` state (configuration cache), and
// the task is never cached or up-to-date, so no earlier output can be restored in place of the error.
tasks.shadowJar {
    outputs.cacheIf { false }
    outputs.upToDateWhen { false }
    doFirst {
        throw GradleException(
            "shadowJar is retired. Use ./gradlew bappJar (BApp Store build) or ./gradlew fullJar (GitHub full build).",
        )
    }
}

tasks.build {
    dependsOn(bappJar, fullJar)
}

// Files the tests read from disk at runtime, declared as inputs of BOTH test suites (`test` and
// `fullTest`). Gradle cannot infer a file a test opens by path, so without these declarations an edit
// that changes only source text or a document leaves the cache key unchanged and the guard reading it
// is served from cache, in exactly the commit it exists to catch.
fun Test.declareStructuralInputs() {
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
    // on any main-source edit. The defect it prevents is the measured 22-09 one recorded with the DECISIONS.md declaration above —
    // mutating source text without changing bytecode yields an identical cache key, so the guard is
    // served from cache in exactly the commit that breaks it.
    inputs
        .dir("src/main/kotlin")
        .withPropertyName("mainSourceTreeStructuralInputs")
        .withPathSensitivity(PathSensitivity.RELATIVE)
    // Phase 29: the structural guards that walk the source tree must keep guarding code that moved into
    // src/full, and BappManifestTest reads BappManifest.bmf from disk. Same 22-09 stale-cache defect as
    // every declaration above: a text-only edit to either produces identical compiled output.
    inputs
        .dir("src/full/kotlin")
        .withPropertyName("fullSourceTreeStructuralInputs")
        .withPathSensitivity(PathSensitivity.RELATIVE)
    // Phase 29 / 29-02: RedactingPolicySurvivalSweepTest runs in `test` and sweeps BOTH test roots
    // (SourceRoots.TESTS). `test` does not compile src/fullTest, so without this declaration a survival
    // pin added there leaves the `test` cache key unchanged and the sweep is served from cache.
    inputs
        .dir("src/fullTest/kotlin")
        .withPropertyName("fullTestSourceTreeStructuralInputs")
        .withPathSensitivity(PathSensitivity.RELATIVE)
    inputs
        .file("BappManifest.bmf")
        .withPropertyName("bappManifest")
        .withPathSensitivity(PathSensitivity.RELATIVE)
    // Phase 29 / BUILD-04: FlavorBranchGuardTest reads this build script and every workflow from disk.
    // Same 22-09 stale-cache defect: a comment-only edit to either changes no compiled output, so an
    // undeclared file would let the guard be served from cache in the commit that re-adds a switch.
    inputs
        .file("build.gradle.kts")
        .withPropertyName("buildScriptStructuralInput")
        .withPathSensitivity(PathSensitivity.RELATIVE)
    inputs
        .dir(".github/workflows")
        .withPropertyName("workflowsStructuralInputs")
        .withPathSensitivity(PathSensitivity.RELATIVE)
}

// -PexcludeHeavyTests=true (the fast PR gate) drops the heavy suites from BOTH test tasks; they still
// run in nightlyRegressionTest / nightlyRegressionFullTest.
val excludeHeavyTests =
    (project.findProperty("excludeHeavyTests") as? String)
        ?.trim()
        ?.equals("true", ignoreCase = true) == true

fun Test.excludeHeavyTestsIfRequested() {
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

tasks.test {
    useJUnitPlatform()
    jvmArgs("-ea", "-Djava.awt.headless=true") // Enable JVM assertions so EDT assert() fires in CI (REL-01 SC1 gate)
    // The headless flag above serves the Phase 22 SC4 harness (ChatPanelTestHarness), which
    // constructs a REAL ChatPanel and drives its REAL Send button. ubuntu-latest is headless anyway;
    // forcing the flag makes a developer Mac behave identically instead of silently taking the
    // windowed path and hiding a CI-only failure.
    declareStructuralInputs()
    excludeHeavyTestsIfRequested()
    // Phase 30 / CI-01: StoreJarContentTest needs the store JAR property and runs only in storeJarContentTest.
    filter { excludeTestsMatching("*StoreJarContentTest") }
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
    filter {
        includeTestsMatching("*McpToolExecutorEdtGuardTest")
    }
}

// Phase 29 / D-16: the full flavor's own suite. It runs on the fullTest classpath (main + full + test
// outputs) and never shares a Test task with `test`, whose classpath must stay store-only.
val fullTest =
    tasks.register<Test>("fullTest") {
        description = "Runs the full-flavor test suite (src/fullTest) against main + full."
        group = "verification"
        useJUnitPlatform()
        testClassesDirs = fullTestSourceSet.output.classesDirs
        classpath = fullTestSourceSet.runtimeClasspath
        jvmArgs("-ea", "-Djava.awt.headless=true")
        declareStructuralInputs()
        excludeHeavyTestsIfRequested()
    }

// Phase 30 / CI-01 (ADR-18: "checked by content, not by intent"): opens the JAR bappJar writes and fails,
// naming each entry and its rule, on any full-only class, CLI backend, Ktor client / CIO or MCP SDK client
// class, plug-in services file or CLI factory line. It automates the manual 29-17 check.
//
// It is its own task rather than a class in `test` on purpose: inside plain `test`, every unit run would
// have to build the store JAR first, and the coverage job's dry-run guard would find a packaging check in
// the graph it reads. `check` depends on it, and build.yml (pr-gate, store-build) and release.yml invoke it
// by name, so a PR and a release are gated by the same task. It runs on the store test classpath only:
// the src/full output is read as FILES (the derived forbidden set), never put on the classpath. It is
// derived from the class directories alone, never from the full resources, which hold an AiBackendFactory
// services file the store JAR legitimately carries too. Not finalized by jacocoTestReport and given no
// structural inputs or heavy-test filter: it measures a JAR, not coverage.
//
// The store JAR is referenced only through bappJar's archiveFile provider: BappManifestTest pins the store
// file name to a single occurrence in this script, the archive-name setter inside bappJar.
// Run it locally with: ./gradlew bappJar storeJarContentTest
val storeJarContentTest =
    tasks.register<Test>("storeJarContentTest") {
        description = "Inspects the BApp Store JAR for full-only and CLI content (CI-01)."
        group = "verification"
        useJUnitPlatform()
        val testSourceSet = sourceSets.test.get()
        testClassesDirs = testSourceSet.output.classesDirs
        classpath = testSourceSet.runtimeClasspath
        jvmArgs("-ea", "-Djava.awt.headless=true")
        dependsOn(bappJar)
        jvmArgumentProviders.add(
            objects.newInstance<StoreJarInspectionArgs>().apply {
                storeJar.set(bappJar.flatMap { it.archiveFile })
                fullClassDirs.from(fullSourceSet.output.classesDirs)
            },
        )
        filter { includeTestsMatching("*StoreJarContentTest") }
        // The default SHORT format prints the exception type and location but not its message, so a CI log
        // would show a failure without the offending entry (RESEARCH Pitfall 3).
        testLogging {
            events("failed")
            exceptionFormat = TestExceptionFormat.FULL
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

// Phase 29 (Pitfall 14): the heavy suites that live in src/fullTest get their own nightly pass on the
// fullTest classpath. The two classpaths are never merged into one task.
tasks.register<Test>("nightlyRegressionFullTest") {
    description = "Runs the full-flavor integration, concurrency, and resilience suites intended for nightly validation."
    group = "verification"
    useJUnitPlatform()
    testClassesDirs = fullTestSourceSet.output.classesDirs
    classpath = fullTestSourceSet.runtimeClasspath
    jvmArgs("-ea", "-Djava.awt.headless=true")
    filter {
        includeTestsMatching("*IntegrationTest")
        includeTestsMatching("*ConcurrencyTest")
        includeTestsMatching("*BackpressureTest")
        includeTestsMatching("*RestartPolicyTest")
        includeTestsMatching("*SupervisionTest")
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
    // Phase 29 (Pitfall 8): detekt's default source is src/main + src/test only, so code in the full
    // flavor would go unchecked. Both flavors' sources and tests are analyzed against one baseline.
    source.setFrom(files("src/main/kotlin", "src/test/kotlin", "src/full/kotlin", "src/fullTest/kotlin"))
}

// Only `test` is finalized by the coverage report. The report reads the execution data of `test` and
// depends on `test`, so finalizing every Test task made edtGuardWithoutAssertionsTest and
// nightlyRegressionTest schedule a second full `test` run under whatever Gradle properties that
// invocation had. In CI the assertions-disabled step re-ran the whole suite, heavy tests included,
// after the fast suite had already passed with -PexcludeHeavyTests=true.
tasks.test {
    finalizedBy(tasks.named("jacocoTestReport"))
}

// Phase 29 (Pitfall 5, D-16): the floors measure BOTH flavors. Code that moves from src/main into
// src/full keeps being counted only if the report and the verification read main + full classes and the
// execution data of both `test` and `fullTest`. JaCoCo's defaults are main classes and `test` data alone,
// under which a moved package would vanish from the report and its PACKAGE / SOURCEFILE rule would pass
// vacuously. The defaults are cleared and set explicitly so no input is counted twice.
fun JacocoReportBase.measureBothFlavors() {
    executionData.setFrom()
    executionData(tasks.test.get(), fullTest.get())
    classDirectories.setFrom()
    sourceDirectories.setFrom()
    sourceSets(sourceSets.main.get(), fullSourceSet)
}

tasks.named<JacocoReport>("jacocoTestReport") {
    // Kept on purpose: Gradle's JaCoCo plugin does not make the report depend on `test`, so without
    // this line the two floor tasks run on their own (as CI does) would verify stale or absent data.
    // It depends on `fullTest` too, which is why `./gradlew test` runs both suites: the report that
    // finalizes `test` needs the full suite's execution data.
    dependsOn(tasks.named("test"), fullTest)
    measureBothFlavors()
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
    // `tasks.test` (the only task the report finalizes) already runs jacocoTestReport after it, but
    // relying on that ordering would leave this task reading whatever exec data happened to be on disk.
    // Depend on the report explicitly so the verification cannot run against a stale or absent one.
    dependsOn(tasks.named<JacocoReport>("jacocoTestReport"))
    measureBothFlavors()
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
    dependsOn(fullTest)
    dependsOn(storeJarContentTest)
    dependsOn(tasks.named("jacocoTestCoverageVerification"))
    dependsOn(jacocoMcpTreeCoverageVerification)
}

tasks.named<org.cyclonedx.gradle.CycloneDxTask>("cyclonedxBom") {
    // The release publishes both JARs with one SBOM (Phase 30 / CI-02, SBOM decision):
    // fullRuntimeClasspath extends the store runtime classpath (fullImplementation and fullRuntimeOnly
    // extend implementation and runtimeOnly), so this bom.json lists every dependency of both assets.
    includeConfigs.set(listOf("fullRuntimeClasspath"))
    outputFormat.set("json")
    outputName.set("bom")
    destination.set(
        layout.buildDirectory
            .dir("reports/sbom")
            .get()
            .asFile,
    )
}
