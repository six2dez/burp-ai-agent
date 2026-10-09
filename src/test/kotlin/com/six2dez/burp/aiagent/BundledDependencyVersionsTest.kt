package com.six2dez.burp.aiagent

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Assertions.fail
import org.junit.jupiter.api.Test
import java.util.Properties

/**
 * Quick 261009-ejm: the extension JAR bundles Netty (the MCP server engine, pulled in by Ktor),
 * Jackson (JSON parsing of AI replies and settings) and slf4j. The shadow JAR packages
 * `runtimeClasspath`, and the test classpath resolves Netty, Jackson and slf4j to the same versions,
 * so this test reads the versions at runtime from the classpath rather than from the build script.
 *
 * The values are FLOORS, not pins: a later patch bump stays green, while a downgrade, a dropped
 * `netty-bom` platform line or a mixed set of Netty versions turns it red.
 *
 * Naming note: like `McpBuildFlagsVersionTest`, the class name deliberately does NOT end in
 * `IntegrationTest` (or any other suffix listed in the `excludeHeavyTests` filter block inside
 * `tasks.test` in `build.gradle.kts`), because `-PexcludeHeavyTests=true` would silently skip it.
 */
class BundledDependencyVersionsTest {
    @Test
    fun nettyArtifactsShareOnePatchedVersion() {
        val versions =
            io.netty.util.Version
                .identify()
                .mapValues { it.value.artifactVersion() }
        assertTrue(
            versions.keys.containsAll(ENGINE_ARTIFACTS),
            "Netty artifacts on the classpath must include $ENGINE_ARTIFACTS, found ${versions.keys.sorted()}",
        )
        assertEquals(
            1,
            versions.values.distinct().size,
            "all Netty artifacts must share one version (mixed Netty versions fail at runtime): $versions",
        )
        assertEquals(emptyList<String>(), floorMisses(versions, NETTY_FLOOR))
    }

    @Test
    fun jacksonModulesAreAtLeastThePatchedRelease() {
        val versions =
            mapOf(
                "jackson-core" to com.fasterxml.jackson.core.json.PackageVersion.VERSION,
                "jackson-databind" to com.fasterxml.jackson.databind.cfg.PackageVersion.VERSION,
                "jackson-module-kotlin" to com.fasterxml.jackson.module.kotlin.PackageVersion.VERSION,
            ).mapValues { (_, v) -> "${v.majorVersion}.${v.minorVersion}.${v.patchLevel}" }
        assertEquals(emptyList<String>(), floorMisses(versions, JACKSON_FLOOR))
    }

    @Test
    fun slf4jApiAndProviderAreAtLeastTheCurrentPatch() {
        val misses = mutableListOf<String>()
        for (artifact in listOf("slf4j-api", "slf4j-simple")) {
            val copies = pomVersions("org.slf4j", artifact)
            assertTrue(
                copies.isNotEmpty(),
                "no META-INF/maven/org.slf4j/$artifact/pom.properties found on the test classpath",
            )
            // Every copy is checked: a stale duplicate on the classpath must not hide behind a patched one.
            copies.forEach { version -> misses += floorMisses(mapOf(artifact to version), SLF4J_FLOOR) }
        }
        assertEquals(emptyList<String>(), misses.sorted())
    }

    private fun numericTriple(version: String): List<Int> {
        val runs =
            Regex("""\d+""")
                .findAll(version)
                .map { it.value.toInt() }
                .take(3)
                .toList()
        if (runs.size < 3) {
            fail<Unit>("version '$version' does not contain three numeric components")
        }
        return runs
    }

    private fun floorMisses(
        versions: Map<String, String>,
        floor: String,
    ): List<String> {
        val floorTriple = numericTriple(floor)
        return versions
            .filter { (_, version) ->
                // Lexicographic comparison of the numeric triples; equal to the floor is not a miss.
                numericTriple(version)
                    .zip(floorTriple)
                    .firstOrNull { (have, want) -> have != want }
                    ?.let { (have, want) -> have < want } ?: false
            }.map { (name, version) -> "$name $version (floor $floor)" }
            .sorted()
    }

    private fun pomVersions(
        group: String,
        artifact: String,
    ): List<String> =
        javaClass.classLoader
            .getResources("META-INF/maven/$group/$artifact/pom.properties")
            .toList()
            .map { url ->
                url.openStream().use { stream ->
                    Properties().apply { load(stream) }.getProperty("version").orEmpty()
                }
            }

    companion object {
        const val NETTY_FLOOR = "4.1.138"
        const val JACKSON_FLOOR = "2.22.3"
        const val SLF4J_FLOOR = "2.0.18"

        /** Non-vacuity: the artifacts Ktor's Netty engine needs must be present at all. */
        val ENGINE_ARTIFACTS =
            setOf(
                "netty-common",
                "netty-buffer",
                "netty-transport",
                "netty-handler",
                "netty-codec",
                "netty-codec-http",
                "netty-codec-http2",
                "netty-resolver",
            )
    }
}
