import org.gradle.api.tasks.testing.Test
import org.jetbrains.kotlin.gradle.tasks.KotlinCompile

plugins {
    kotlin("jvm") version "2.1.21"
    kotlin("plugin.serialization") version "2.1.21"
    id("com.github.johnrengelman.shadow") version "8.1.1"
    id("org.jlleitschuh.gradle.ktlint") version "12.1.1"
    id("org.cyclonedx.bom") version "1.10.0"
    jacoco
}

group = "com.six2dez.burp"
version = "0.6.0"

repositories {
    mavenCentral()
    maven("https://www.jetbrains.com/intellij-repository/releases")
    maven("https://packages.jetbrains.team/maven/p/ij/intellij-dependencies")
}

dependencies {
    // Burp Montoya API (compileOnly, Burp provides it at runtime)
    compileOnly("net.portswigger.burp.extensions:montoya-api:2026.2")

    // JSON
    implementation("com.fasterxml.jackson.core:jackson-databind:2.17.2")
    implementation("com.fasterxml.jackson.module:jackson-module-kotlin:2.17.2")

    // HTTP client (Ollama + webhooks)
    implementation("com.squareup.okhttp3:okhttp:4.12.0")

    // MCP Server (Ktor + MCP SDK)
    implementation("io.modelcontextprotocol:kotlin-sdk:0.5.0")
    implementation("io.ktor:ktor-server-core:3.4.3")
    implementation("io.ktor:ktor-server-netty:3.4.3")
    implementation("io.ktor:ktor-server-cors:3.4.3")
    implementation("io.ktor:ktor-server-sse:3.4.3")
    implementation("io.ktor:ktor-server-content-negotiation:3.4.3")
    implementation("io.ktor:ktor-serialization-kotlinx-json:3.4.3")
    implementation("org.jetbrains.kotlinx:kotlinx-serialization-json:1.8.1")
    implementation("org.jetbrains.kotlinx:kotlinx-io-core:0.5.4")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-core:1.9.0")

    // Logging façade (we keep it minimal; Burp logs are also used)
    implementation("org.slf4j:slf4j-api:2.0.16")
    implementation("org.slf4j:slf4j-simple:2.0.16")

    testImplementation(kotlin("test"))
    testImplementation("org.junit.jupiter:junit-jupiter:5.11.3")
    testImplementation("net.portswigger.burp.extensions:montoya-api:2026.2")
    testImplementation("org.mockito.kotlin:mockito-kotlin:5.4.0")
}

java {
    toolchain {
        languageVersion.set(JavaLanguageVersion.of(21))
    }
}

tasks.withType<KotlinCompile> {
    compilerOptions {
        jvmTarget.set(org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_21)
        freeCompilerArgs.addAll(listOf("-Xjsr305=strict"))
    }
}

tasks.jar {
    enabled = false
}

tasks.shadowJar {
    archiveBaseName.set("Custom-AI-Agent")
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
    }
}

ktlint {
    version.set("1.5.0")
    android.set(false)
    // Start lenient: `ktlintFormat` auto-fixes most violations, but the initial run will still
    // surface things that need manual review. Flip to `false` once the baseline is clean.
    ignoreFailures.set(
        (project.findProperty("ktlintStrict") as? String)?.equals("true", ignoreCase = true) != true,
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
