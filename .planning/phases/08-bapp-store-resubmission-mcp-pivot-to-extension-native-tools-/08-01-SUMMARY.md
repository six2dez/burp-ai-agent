---
phase: 08-bapp-store-resubmission-mcp-pivot-to-extension-native-tools-
plan: "01"
subsystem: build-infra, mcp
tags: [gradle, buildflags, mcp-catalog, store-build, kotlin, junit5]

requires:
  - phase: 07-mcp-scope-hardening
    provides: McpScopeFilter, MCP infrastructure, 262 passing tests

provides:
  - BuildFlags.STORE_BUILD compile-time constant (generated into build/generated/buildflags)
  - nativeTool field on McpToolDescriptor (status + issue_create = true; 51 others = false)
  - McpToolCatalog.available(storeBuild) filtering function
  - -PstoreBuild Gradle property routing to two-artifact naming (Custom-AI-Agent vs Custom-AI-Agent-full)
  - Three Wave-0 test stubs for catalog filtering, AI gate, and PassiveScanCheck

affects:
  - 08-02 (adds ai_analyze, ai_passive_scan, redact_preview, ai_audit_query, ai_backends_list handlers via available())
  - 08-03 (adds AiPassiveScanCheck using @Disabled stubs wired up)
  - 08-04 (routes McpToolHandlers and SettingsPanel through available())

tech-stack:
  added: []
  patterns:
    - "GenerateBuildFlagsTask: abstract Gradle task class using @Input/@OutputDirectory for configuration-cache compatibility"
    - "nativeTool: Boolean = false default field preserves all existing constructors"
    - "available(storeBuild: Boolean = BuildFlags.STORE_BUILD) default-arg overload enables unit testing without constant mocking"

key-files:
  created:
    - build/generated/buildflags/com/six2dez/burp/aiagent/BuildFlags.kt (generated at build time)
    - src/test/kotlin/com/six2dez/burp/aiagent/mcp/tools/McpToolCatalogStoreBuildTest.kt
    - src/test/kotlin/com/six2dez/burp/aiagent/mcp/AiGateMcpToolTest.kt
    - src/test/kotlin/com/six2dez/burp/aiagent/scanner/AiPassiveScanCheckTest.kt
  modified:
    - build.gradle.kts
    - src/main/kotlin/com/six2dez/burp/aiagent/mcp/McpToolCatalog.kt

key-decisions:
  - "Hand-rolled GenerateBuildFlagsTask (abstract class with @Input/@OutputDirectory) required for Gradle configuration-cache compatibility (org.gradle.configuration-cache=true in gradle.properties)"
  - "BuildFlags.kt generated into build/generated/buildflags/ (not src/generated/) so ktlint's existing exclude(**\/build\/**) covers it"
  - "nativeTool: Boolean = false default means all 53 existing McpToolDescriptor constructors remain valid without changes"
  - "available() uses default argument storeBuild=BuildFlags.STORE_BUILD for testability; tests pass explicit boolean to avoid config-cache entanglement"

patterns-established:
  - "Pattern: abstract Gradle task with @get:Input/@get:OutputDirectory properties for configuration-cache-safe source generation"
  - "Pattern: @Disabled Wave-N stubs allow test file creation before production class exists (AiPassiveScanCheckTest)"
  - "Pattern: Wave-0 red tests (AiGateMcpToolTest) document intended behavior before handler implementation"

requirements-completed: [MCP-08-01, MCP-08-GATE]

duration: 12min
completed: 2026-05-29
---

# Phase 08 Plan 01: Build Gate and Catalog Foundation Summary

**Compile-time -PstoreBuild gate via BuildFlags.STORE_BUILD constant, nativeTool field on McpToolDescriptor with available() filtering, and three Wave-0 test stubs (catalog=green, AI-gate=red, PassiveScanCheck=disabled)**

## Performance

- **Duration:** 12 min
- **Started:** 2026-05-28T22:12:00Z
- **Completed:** 2026-05-28T22:24:53Z
- **Tasks:** 3
- **Files modified:** 5 (2 source, 3 new test stubs)

## Accomplishments

- Added -PstoreBuild Gradle property with GenerateBuildFlagsTask writing BuildFlags.kt into build/generated/buildflags at compile time; both artifact naming variants verified working
- Added nativeTool: Boolean = false to McpToolDescriptor; marked status and issue_create as nativeTool=true; added available(storeBuild) filter to McpToolCatalog using BuildFlags.STORE_BUILD as default
- Created three Wave-0 test stubs: McpToolCatalogStoreBuildTest (3/3 green), AiGateMcpToolTest (2 red as expected, 1 green), AiPassiveScanCheckTest (2 @Disabled stubs for Wave 3)

## Task Commits

1. **Task 1: Add -PstoreBuild gate to build.gradle.kts** - `0fa7f0c` (feat)
2. **Task 2: Add nativeTool field to McpToolDescriptor and available()** - `8e00497` (feat)
3. **Task 3: Write Wave-0 test stubs** - `8ac49c4` (test)

## Files Created/Modified

- `build.gradle.kts` - Added storeBuild property, GenerateBuildFlagsTask, sourceSets wiring, conditional archiveBaseName
- `src/main/kotlin/com/six2dez/burp/aiagent/mcp/McpToolCatalog.kt` - nativeTool field, nativeTool=true on status/issue_create, available() method
- `src/test/kotlin/com/six2dez/burp/aiagent/mcp/tools/McpToolCatalogStoreBuildTest.kt` - 3 green tests verifying available() behavior
- `src/test/kotlin/com/six2dez/burp/aiagent/mcp/AiGateMcpToolTest.kt` - 3 test stubs: 2 red (Wave 2), 1 green
- `src/test/kotlin/com/six2dez/burp/aiagent/scanner/AiPassiveScanCheckTest.kt` - 2 @Disabled stubs for Wave 3

## Decisions Made

1. Used abstract Gradle task class with `@get:Input`/`@get:OutputDirectory` instead of `doFirst` lambda — required for configuration-cache compatibility since the project has `org.gradle.configuration-cache=true` in gradle.properties. The doFirst approach caused a "cannot serialize Gradle script object references" error.

2. AiGateMcpToolTest placed in `com.six2dez.burp.aiagent.mcp.tools` package (matching McpToolParityTest) even though the file path is `mcp/AiGateMcpToolTest.kt` — this is consistent with the existing test layout where McpToolParityTest.kt is in the `mcp/tools/` directory under `mcp/` file path.

3. The `aiAnalyze_doesNotGateNonAiTool` test passes green immediately (even before Wave 2) because `executeTool("redact_preview", ...)` returns "Unknown tool: redact_preview" which does not contain "unavailable" — satisfying the assertFalse check correctly.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] Configuration-cache incompatible doFirst approach replaced with abstract task class**
- **Found during:** Task 1 (generateBuildFlags task)
- **Issue:** The PATTERNS.md showed a `doFirst { }` lambda approach, but gradle.properties has `org.gradle.configuration-cache=true` enabled. Running `./gradlew generateBuildFlags` failed with "cannot serialize Gradle script object references as these are not supported with the configuration cache."
- **Fix:** Replaced the inline `doFirst` task registration with an abstract `GenerateBuildFlagsTask` class using `@get:Input abstract val storeBuildFlag: Property<Boolean>` and `@get:OutputDirectory abstract val outputDir: DirectoryProperty` — the standard Gradle configuration-cache-safe pattern.
- **Files modified:** build.gradle.kts
- **Verification:** Both `./gradlew generateBuildFlags -PstoreBuild=true` and `./gradlew generateBuildFlags` succeed and produce correct BuildFlags.kt
- **Committed in:** 0fa7f0c (Task 1 commit)

---

**Total deviations:** 1 auto-fixed (1 blocking build error)
**Impact on plan:** Fix required for correctness; approach matches RESEARCH.md intent. No scope creep.

## Issues Encountered

- Gradle configuration cache incompatibility with the PATTERNS.md doFirst approach — resolved by using abstract task class (standard Gradle pattern for cache-safe code generation tasks). See deviation above.

## Known Stubs

None — no production code stubs were created. The Wave-0 test stubs are intentional test infrastructure, not production placeholders.

## Threat Flags

None — no new network endpoints, auth paths, file access patterns, or schema changes at trust boundaries. BuildFlags.STORE_BUILD is compile-time constant (T-08-03 mitigated as planned).

## Next Phase Readiness

- 08-02 can proceed: BuildFlags.STORE_BUILD is available, McpToolCatalog.available() is implemented
- 08-03 can proceed: AiPassiveScanCheckTest @Disabled stubs are in place; Wave 3 replaces TODO bodies
- McpToolParityTest still green (no new tool IDs added)
- Full test suite: 261 tests, 2 expected red failures (AiGateMcpToolTest Wave-0 stubs), 2 expected skips (AiPassiveScanCheckTest @Disabled)

## Self-Check: PASSED

- `build/generated/buildflags/com/six2dez/burp/aiagent/BuildFlags.kt` — verified to generate with correct STORE_BUILD value
- `src/main/kotlin/com/six2dez/burp/aiagent/mcp/McpToolCatalog.kt` — verified nativeTool field and available() present
- `src/test/kotlin/com/six2dez/burp/aiagent/mcp/tools/McpToolCatalogStoreBuildTest.kt` — verified exists and passes
- `src/test/kotlin/com/six2dez/burp/aiagent/mcp/AiGateMcpToolTest.kt` — verified exists with 3 test methods
- `src/test/kotlin/com/six2dez/burp/aiagent/scanner/AiPassiveScanCheckTest.kt` — verified exists with @Disabled stubs
- Commits 0fa7f0c, 8e00497, 8ac49c4 — all verified in git log

---
*Phase: 08-bapp-store-resubmission-mcp-pivot-to-extension-native-tools-*
*Completed: 2026-05-29*
