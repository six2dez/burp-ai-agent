import org.gradle.api.tasks.testing.Test
import org.jetbrains.kotlin.gradle.tasks.KotlinCompile

plugins {
    kotlin("jvm") version "2.4.10"
    kotlin("plugin.serialization") version "2.1.21"
    id("com.github.johnrengelman.shadow") version "8.1.1"
    id("org.jlleitschuh.gradle.ktlint") version "12.1.1"
    id("org.cyclonedx.bom") version "1.10.0"
    id("io.gitlab.arturbosch.detekt") version "1.23.8"
    jacoco
}

group = "com.six2dez.burp"
version = "0.9.1"

repositories {
    mavenCentral()
    maven("https://www.jetbrains.com/intellij-repository/releases")
    maven("https://packages.jetbrains.team/maven/p/ij/intellij-dependencies")
}

dependencies {
    // Burp Montoya API (compileOnly, Burp provides it at runtime)
    compileOnly("net.portswigger.burp.extensions:montoya-api:2026.2")

    // JSON
    implementation("com.fasterxml.jackson.core:jackson-databind:2.22.0")
    implementation("com.fasterxml.jackson.module:jackson-module-kotlin:2.22.0")

    // HTTP client (Ollama + webhooks)
    implementation("com.squareup.okhttp3:okhttp:4.12.0")

    // MCP Server (Ktor + MCP SDK)
    implementation("io.modelcontextprotocol:kotlin-sdk:0.5.0")
    implementation("io.ktor:ktor-server-core:3.1.3")
    implementation("io.ktor:ktor-server-netty:3.1.3")
    implementation("io.ktor:ktor-server-cors:3.1.3")
    implementation("io.ktor:ktor-server-sse:3.1.3")
    implementation("io.ktor:ktor-server-content-negotiation:3.1.3")
    implementation("io.ktor:ktor-serialization-kotlinx-json:3.1.3")
    // Phase 16: Ktor CLIENT modules (pin to 3.1.3 to match server-side Ktor family)
    implementation("io.ktor:ktor-client-core:3.1.3")
    implementation("io.ktor:ktor-client-cio:3.1.3")
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
    testImplementation("com.squareup.okhttp3:mockwebserver:4.12.0")
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
}
            """.trimIndent() + "\n",
        )
    }
}

val generateBuildFlags by tasks.registering(GenerateBuildFlagsTask::class) {
    group = "build"
    description = "Generates BuildFlags.kt with a compile-time store-build flag"
    storeBuildFlag.set(storeBuild)
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
    jvmArgs("-ea") // Enable JVM assertions so EDT assert() fires in CI (REL-01 SC1 gate)
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
