---
phase: 16-external-mcp-client
plan: "01"
subsystem: testing
tags: [ktor-client, kotlin-logging, mcp-client, test-scaffolds, gradle]

requires:
  - phase: 12-secrets-hardening
    provides: SecretCipher used in ExternalMcpSettingsMigrationTest stubs (ENC1: prefix assertions)
  - phase: 13-privacy-redaction-hardening
    provides: SsrfGuard referenced in ExternalMcpClientManagerTest comments

provides:
  - "build.gradle.kts: io.ktor:ktor-client-core:3.1.3 + ktor-client-cio:3.1.3 + kotlin-logging-jvm:7.0.7 pinned"
  - "Wave 0 test scaffold: ExternalMcpClientManagerTest.kt (4 @Disabled stubs, plan 16-03 contract)"
  - "Wave 0 test scaffold: ExternalMcpSettingsMigrationTest.kt (4 @Disabled stubs + InMemoryPrefs, plan 16-02 contract)"

affects:
  - 16-02 (ExternalMcpSettingsMigration — fills in stubs from ExternalMcpSettingsMigrationTest)
  - 16-03 (ExternalMcpClientManager — fills in stubs from ExternalMcpClientManagerTest)
  - 16-04 (McpTools routing — depends on ExternalMcpClientManager from 16-03)
  - 16-05 (ExternalServersPanel UI — depends on config from 16-02)

tech-stack:
  added:
    - "io.ktor:ktor-client-core:3.1.3 — Ktor HTTP client API surface"
    - "io.ktor:ktor-client-cio:3.1.3 — CIO engine for SseClientTransport (overrides 3.0.2 transitive)"
    - "io.github.oshai:kotlin-logging-jvm:7.0.7 — explicit pin of StdioClientTransport's transitive dep"
  patterns:
    - "Explicit dep pin pattern: declare higher version to override kotlin-sdk:0.5.0's transitive 3.0.2"
    - "Wave 0 scaffold pattern: @Disabled stubs with commented-out production code as plan N+1 contract"

key-files:
  created:
    - src/test/kotlin/com/six2dez/burp/aiagent/mcp/external/ExternalMcpClientManagerTest.kt
    - src/test/kotlin/com/six2dez/burp/aiagent/config/ExternalMcpSettingsMigrationTest.kt
  modified:
    - build.gradle.kts

key-decisions:
  - "Path A confirmed: kotlin-sdk stays at 0.5.0; only 3 explicit dep pins needed (no SDK or Kotlin plugin bump)"
  - "Test scaffold stubs use @Disabled (not commented-out class) so compileTestKotlin validates imports"
  - "Detekt UnusedPrivateMember suppressed via @Suppress on apiWith() helper — it is called by disabled stubs"

patterns-established:
  - "Wave 0 scaffold: @Disabled test stubs document implementation contract for successor plans"
  - "InMemoryPrefs + apiWith() helpers mirrored from AgentSettingsMigrationTest.kt — reuse exactly"

requirements-completed:
  - CAP-02

duration: 5min
completed: 2026-06-15
---

# Phase 16 Plan 01: Dependency Pins + Wave 0 Test Scaffolds Summary

**Pinned ktor-client-core/cio:3.1.3 and kotlin-logging-jvm:7.0.7; created two Wave 0 @Disabled test scaffolds establishing the 16-02 and 16-03 implementation contracts**

## Performance

- **Duration:** ~5 min
- **Started:** 2026-06-15T13:08:29Z
- **Completed:** 2026-06-15T13:13:38Z
- **Tasks:** 2
- **Files modified:** 3

## Accomplishments

- Added three explicit dependency declarations to `build.gradle.kts` (ktor-client-core, ktor-client-cio, kotlin-logging-jvm), confirming `compileKotlin BUILD SUCCESSFUL` and `3.0.2 -> 3.1.3` version override in runtimeClasspath
- Created `ExternalMcpClientManagerTest.kt` (131 lines, 4 `@Disabled` stubs) covering trust-boundary wrap, `ext:` routing, stdio process cleanup, and integration connect+listTools
- Created `ExternalMcpSettingsMigrationTest.kt` (186 lines, 4 `@Disabled` stubs + `InMemoryPrefs` + `apiWith()` helpers) covering round-trip, ENC1: encryption, schema-v5 bump, and idempotency

## Task Commits

Each task was committed atomically:

1. **Task 1: Add three Ktor client + kotlin-logging dep declarations** - `eb97cec` (chore)
2. **Task 2: Create Wave 0 test scaffolds** - `b96359c` (test)

**Plan metadata:** see final docs commit hash below

## Files Created/Modified

- `build.gradle.kts` — Added 5 lines: comment + 3 implementation() deps + comment; kotlin-sdk stays at 0.5.0
- `src/test/kotlin/com/six2dez/burp/aiagent/mcp/external/ExternalMcpClientManagerTest.kt` — Wave 0 stub: 4 @Disabled tests for plan 16-03 lifecycle/routing/shutdown contract
- `src/test/kotlin/com/six2dez/burp/aiagent/config/ExternalMcpSettingsMigrationTest.kt` — Wave 0 stub: 4 @Disabled tests + InMemoryPrefs for plan 16-02 schema-v5 migration contract

## Decisions Made

- Path A confirmed: kotlin-sdk stays at 0.5.0; the three new lines are version-alignment pins only (no SDK or Kotlin plugin bump)
- Test scaffold stubs use `@Disabled` (not commented-out class bodies) so `compileTestKotlin` validates import correctness and gives plan 16-02/16-03 a clean compilation gate
- Detekt `UnusedPrivateMember` suppressed via `@Suppress` on `apiWith()` — it is needed by the disabled stubs and will be called directly once plan 16-02 enables them

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] Detekt UnusedPrivateProperty/UnusedPrivateMember violations in stub bodies**
- **Found during:** Task 2 (test scaffold creation) — detekt post-creation run
- **Issue:** Commented-out stub code declared local `val serverName`/`val rawResult` before the comments, triggering 4 `UnusedPrivateProperty`/`UnusedPrivateMember` findings. `apiWith()` helper also flagged as unused.
- **Fix:** Moved local val declarations inside comments; added `@Suppress("UnusedPrivateMember")` to `apiWith()` which is intentionally dormant until plan 16-02 enables the tests
- **Files modified:** Both new test files
- **Verification:** `./gradlew detekt --no-daemon` exits 0 after fix
- **Committed in:** b96359c (Task 2 commit)

---

**Total deviations:** 1 auto-fixed (Rule 1 — build correctness)
**Impact on plan:** Detekt gate required moving variable declarations into comments and adding a suppress annotation. No scope creep.

## Issues Encountered

None beyond the detekt fix noted above.

## User Setup Required

None — no external service configuration required.

## Next Phase Readiness

- Plan 16-02 (`ExternalMcpServerConfig` + schema-v5 migration): stubs in `ExternalMcpSettingsMigrationTest.kt` define the exact test contract; uncomment the test bodies and ensure they pass
- Plan 16-03 (`ExternalMcpClientManager`): stubs in `ExternalMcpClientManagerTest.kt` define the lifecycle, routing, and shutdown contract
- Build is fully green: `compileKotlin`, `test -PexcludeHeavyTests=true`, `ktlintCheck`, `detekt` all pass

## Self-Check

- [x] `build.gradle.kts` contains `ktor-client-core:3.1.3`, `ktor-client-cio:3.1.3`, `kotlin-logging-jvm:7.0.7`
- [x] `io.modelcontextprotocol:kotlin-sdk:0.5.0` unchanged (grep confirmed)
- [x] Kotlin plugin version `2.1.21` unchanged
- [x] Both test scaffold files exist at specified paths
- [x] Line counts: ClientManagerTest=131 (≥40), MigrationTest=186 (≥30)
- [x] Commits exist: eb97cec (Task 1), b96359c (Task 2)
- [x] `ktlintCheck` BUILD SUCCESSFUL
- [x] `detekt` BUILD SUCCESSFUL
- [x] `test -PexcludeHeavyTests=true` BUILD SUCCESSFUL

## Self-Check: PASSED

---
*Phase: 16-external-mcp-client*
*Completed: 2026-06-15*
