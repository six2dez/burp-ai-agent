---
phase: 12-secrets-at-rest-transport-security
plan: 03
subsystem: infra
tags: [tls, keytool, pkcs12, mcp, process-env, kotlin]

requires:
  - phase: none
    provides: independent transport-hardening fix
provides:
  - McpTls.generateSelfSigned passes the keystore password via KS_PASS env var (no argv exposure)
  - PKCS12 self-signed cert generation unchanged in contract (CN=burp-mcp, RSA-2048, SHA256withRSA, 365d)
affects: [MCP external TLS, McpTls.resolve callers]

tech-stack:
  added: [none]
  patterns: [child-process secret passing via ProcessBuilder.environment(), not argv]

key-files:
  created:
    - src/test/kotlin/com/six2dez/burp/aiagent/mcp/McpTlsInJvmTest.kt
  modified:
    - src/main/kotlin/com/six2dez/burp/aiagent/mcp/McpTls.kt

key-decisions:
  - "Kept the keytool ProcessBuilder approach (no sun.security.*, no --add-exports — both fail at runtime inside Burp's JVM); only swapped -storepass/-keypass for the :env form."
  - "Password supplied via .also { it.environment()[\"KS_PASS\"] = passStr } before .start()."

patterns-established:
  - "Pattern: pass child-process secrets through the environment map, never as a command-line argument (avoids ps-aux exposure)."

requirements-completed: [SEC-02]

duration: 10min
completed: 2026-06-10
---

# Phase 12: Transport Security — Plan 03 Summary

**keytool keystore password now flows through the KS_PASS child-process env var via -storepass:env / -keypass:env — eliminating the plaintext password from the keytool argv (ps-aux exposure).**

## Performance

- **Duration:** ~10 min
- **Tasks:** 1 (TDD)
- **Files modified:** 1 modified + 1 test created

## Accomplishments
- Replaced `"-storepass", passStr` / `"-keypass", passStr` argv pairs with `-storepass:env KS_PASS` / `-keypass:env KS_PASS`.
- Set `KS_PASS` on `ProcessBuilder.environment()` via `.also { it.environment()["KS_PASS"] = passStr }` before `.start()`.
- Left `findKeytool()`, `resolve()`, and `McpTlsMaterial` untouched — external contract unchanged.
- No `sun.security.*` usage and no `--add-exports` (both would throw at runtime inside Burp's JVM).
- 7 tests: keystore file written, PKCS12 round-trip load, cert subject/algorithm/validity, source argv assertions (no literal password; uses :env + KS_PASS), and resolve() auto-generation.

## Task Commits
1. **Task 1: keytool env-var password (TDD)** — see `fix(12): keytool env-var password` commit.

## Files Created/Modified
- `src/main/kotlin/com/six2dez/burp/aiagent/mcp/McpTls.kt` — argv `:env` form + KS_PASS env assignment.
- `src/test/kotlin/com/six2dez/burp/aiagent/mcp/McpTlsInJvmTest.kt` — 7 cert/argv tests (uses TestSettings.baselineSettings().mcpSettings.copy(...)).

## Decisions Made
- Test constructs McpSettings via `TestSettings.baselineSettings().mcpSettings.copy(...)` rather than the full positional constructor, since McpSettings has many required fields. Functionally identical, less brittle.

## Deviations from Plan
None of substance. The plan suggested either a split-chain or `.also` style; the `.also { it.environment()["KS_PASS"] = passStr }` form was used (explicitly allowed by the plan).

## Issues Encountered
None. Existing McpSupervisorConnectionTest / McpServerIntegrationTest pass — no regression.

## Next Phase Readiness
- Transport hardening for SEC-02 complete. SsrfGuard (12-04) is the last SEC requirement.

---
*Phase: 12-secrets-at-rest-transport-security*
*Completed: 2026-06-10*
