---
phase: quick-260527-f7q
plan: 01
subsystem: backends
tags: [kotlin, gradle, junit5, cli, copilot, openai-compatible, header-parser, windows-paths, stdin-eof, error-diagnostics]

requires:
  - phase: v0.7.0
    provides: shipped AiBackend interface, CliBackend, OpenAiCompatibleBackend, HeaderParser
provides:
  - OS-aware tokenizer (AgentSupervisor.tokenizeCommand) that preserves Windows backslash paths
  - Shared tokenizer between supervisor launch path and CliBackend.isAvailable() so argv[0] agrees
  - Non-interactive Copilot invocation via positional `-p <prompt>` with idempotent flag injection
  - Explicit stdin redirect (NUL on Windows, /dev/null on Unix) for ALL CLI backends — closes the 60s interactive-menu hang
  - Privacy-safe pre-flight body-shape log for OpenAI-compatible POSTs (model, message count, byte length only)
  - Diagnosable 4xx error messages with endpoint URL, 800-char body excerpt, and remediation hints (both Montoya + OkHttp transports)
  - Regression-pin tests for HeaderParser.withBearerToken (empty/whitespace/case-insensitive guards)
affects: [v0.7.0 release notes, CLI backend onboarding, OpenAI-compatible provider docs]

tech-stack:
  added: []
  patterns:
    - "Top-level `internal fun` extraction for helpers that need to be unit-tested without widening visibility"
    - "Companion-object factoring of pure helpers so they can be shared across packages while staying `internal`"
    - "Privacy-by-design pre-flight logs: emit body SHAPE (counts, sizes), never message content"

key-files:
  created:
    - src/test/kotlin/com/six2dez/burp/aiagent/supervisor/CliCommandTokenizerTest.kt
    - src/test/kotlin/com/six2dez/burp/aiagent/backends/cli/CopilotCommandBuilderTest.kt
    - src/test/kotlin/com/six2dez/burp/aiagent/util/HeaderParserTest.kt
  modified:
    - src/main/kotlin/com/six2dez/burp/aiagent/supervisor/AgentSupervisor.kt
    - src/main/kotlin/com/six2dez/burp/aiagent/backends/cli/CliBackend.kt
    - src/main/kotlin/com/six2dez/burp/aiagent/backends/openai/OpenAiCompatibleBackend.kt

key-decisions:
  - "Tokenizer refactor option (a): moved `tokenizeCommand` to AgentSupervisor.Companion as `internal fun` instead of a separate object. Existing instance call sites compile unchanged; CliBackend now calls `AgentSupervisor.tokenizeCommand(...)`."
  - "Extracted `buildCopilotCommand` from `NonInteractiveCliConnection` (private inner class) to a top-level `internal fun` in the same package. This keeps test access without reflection while keeping the symbol out of the backend's public API."
  - "HeaderParser.withBearerToken already had both guards (empty-token short-circuit + case-insensitive Authorization preservation); production code untouched. Only regression-pin tests were added (per plan step 3: 'only ADD the empty-token guard. If it does not, add both guards')."
  - "Hardened stdin EOF for ALL CLI backends (not only Copilot) via explicit ProcessBuilder.redirectInput(NUL|/dev/null). This is broader than the literal Copilot fix but matches the plan's `<behavior>` directive and addresses STRIDE T-quick-02 for every future CLI."

patterns-established:
  - "Sharing pure helpers across packages via `internal` companion/top-level functions instead of `public` widening"
  - "Pre-flight HTTP logs emit shape metadata only; full body never leaves the redaction boundary in debug logs"
  - "Idempotent argv flag injection: check `extras.contains(flag)` before adding, so user-supplied overrides flow through unchanged"

requirements-completed: [BUG-66, BUG-67, BUG-68]

duration: 10min 30s
completed: 2026-05-27
---

# Phase quick-260527-f7q Plan 01: Fix Bugs #66 #67 #68 (CLI tokenizer, Copilot, OpenAI-compat) Summary

**OS-aware Windows-path tokenizer, non-interactive Copilot CLI invocation, and privacy-safe diagnosable OpenAI-compatible 4xx errors — three production bugs closed as three atomic commits.**

## Performance

- **Duration:** 10 min 30 s
- **Started:** 2026-05-27T09:04:01Z
- **Completed:** 2026-05-27T09:14:31Z
- **Tasks:** 3 / 3
- **Files modified:** 3
- **Files created:** 3 (all test files)
- **Tests added:** 18 (5 + 8 + 5)
- **Full suite after final commit:** 56 suites / 214 tests / 0 failures / 0 errors / 0 skipped

## Accomplishments

- **Bug #67 closed** — `tokenizeCommand` is now OS-aware. On Windows, a single backslash is no longer treated as a shell escape, so paths like `C:\Users\u\bin\claude.exe` survive intact. On Unix, the historical POSIX-ish backslash-escape behavior is preserved but only outside quoted strings. `CliBackend.isAvailable()` and the supervisor's launch path now share the same tokenizer so `isAvailable()` and `send()` resolve argv[0] identically.
- **Bug #68 closed** — Copilot CLI now runs non-interactively: argv is `copilot --no-color --quiet -p <prompt>` with idempotent flag injection (no duplicates when the user already supplied any of those). The prompt is positional, not stdin, and `NonInteractiveCliConnection.send()` explicitly redirects stdin to `NUL` (Windows) or `/dev/null` (Unix) for ALL CLI backends when no stdin payload is supplied. The 60s interactive-menu hang is gone.
- **Bug #66 closed** — OpenAI-compatible 4xx errors are now diagnosable. Pre-flight `debugLog` prints `POST <url> (model=… messages=N json_bytes=B [json_mode=true] [max_tokens=K])` — body SHAPE only, never message content. Non-429 error messages include the endpoint URL, up to 800 chars of response body, and a remediation hint (`/v1` suffix, model catalog, API-key validity). Both Montoya and OkHttp transport branches emit identical messages. `HeaderParser.withBearerToken` already had both guards (empty-token + case-insensitive Authorization preservation); regression-pin tests added.

## Task Commits

Each task was committed atomically on branch `worktree-agent-a32e8c0ae133ae1d5`:

1. **Task 1: Bug #67 — preserve backslashes in Windows CLI paths** — `fc490bb` (fix)
2. **Task 2: Bug #68 — non-interactive Copilot invocation + stdin EOF** — `8e3451f` (fix)
3. **Task 3: Bug #66 — OpenAI-compatible 4xx diagnostics + skip empty Bearer** — `ac1b4c8` (fix)

`./gradlew compileKotlin test` was green after each commit (no intermediate red), and `./gradlew test` reports 0 failures / 0 errors across 214 tests after the final commit.

## Files Created/Modified

- `src/main/kotlin/com/six2dez/burp/aiagent/supervisor/AgentSupervisor.kt` — Removed instance `private fun tokenizeCommand`, added companion `internal fun tokenizeCommand(command, isWindows = …)` with parametrized OS flag. Backslash branch now skipped on Windows and inside Unix quoted strings.
- `src/main/kotlin/com/six2dez/burp/aiagent/backends/cli/CliBackend.kt` — Replaced `command.trim().split("\\s+".toRegex())` in `isAvailable()` with `AgentSupervisor.tokenizeCommand(command.trim())`. Updated `buildCommand("copilot-cli", …)` to use new `buildCopilotCommand(cmd, prompt)` and return `cmd to null`. Extracted `buildCopilotCommand` to a top-level `internal fun`. Hardened `NonInteractiveCliConnection.send()` with explicit `ProcessBuilder.redirectInput(Redirect.from(NUL|/dev/null))` when `stdinText` is null/blank.
- `src/main/kotlin/com/six2dez/burp/aiagent/backends/openai/OpenAiCompatibleBackend.kt` — Replaced pre-flight `debugLog("request -> $endpointUrl")` with `safeBodyPreview` (model/messages/json_bytes/json_mode/max_tokens). Replaced the `else` arm of both transport branches' error `when` to emit URL + 800-char body excerpt + remediation hints.
- `src/test/kotlin/com/six2dez/burp/aiagent/supervisor/CliCommandTokenizerTest.kt` (new) — 5 tests pinning Windows absolute paths, Windows quoted paths with spaces, Unix paths, Unix `\ ` escape, and Unix literal-backslash-inside-quotes.
- `src/test/kotlin/com/six2dez/burp/aiagent/backends/cli/CopilotCommandBuilderTest.kt` (new) — 8 tests covering bare invocation, flag ordering (`--no-color`/`--quiet` before `-p`), prompt is last argv, idempotent `--quiet`/`--no-color`/`-p`/`--prompt`, and extras preservation.
- `src/test/kotlin/com/six2dez/burp/aiagent/util/HeaderParserTest.kt` (new) — 5 regression-pin tests for empty/whitespace tokens, non-empty bearer insertion, and case-insensitive Authorization preservation.

## Decisions Made

See `key-decisions` in the frontmatter for the four substantive decisions; in brief:

1. Refactor option (a) — `tokenizeCommand` to `AgentSupervisor.Companion` as `internal fun` (not a separate `object CliCommandTokenizer`). Keeps the diff small (one symbol move + one companion entry) and existing instance call sites compile unchanged.
2. `buildCopilotCommand` extracted to a top-level `internal fun` in the cli package (the only minimal visibility change required for testing).
3. HeaderParser production code intentionally NOT modified — the existing implementation already had both guards. Test file added as regression pin.
4. Stdin EOF hardening applied to ALL CLI backends, not just Copilot, matching the plan's `<behavior>` directive that this fix "guarantees EOF semantics for ALL CLI backends".

## Deviations from Plan

### 1. [Rule 3 — Blocking / Recovery] Initial commit landed on `main` instead of the per-agent worktree branch (cwd drift)

- **Found during:** Task 1 commit step
- **Issue:** The first `cd /Users/six2dez/Tools/burp-ai-agent && …` call in this session changed cwd from the worktree (`/Users/six2dez/Tools/burp-ai-agent/.claude/worktrees/agent-a32e8c0ae133ae1d5`) to the main repo working directory. The pre-commit HEAD assertion was bypassed because the cwd-drift sentinel had not yet been written (this was the very first commit), and `[ -f .git ]` was false for the main repo (its `.git` is a directory), so the worktree-only HEAD assertion was silently skipped. Commit `fc490bb` thus landed on `main` instead of `worktree-agent-a32e8c0ae133ae1d5`. This is exactly the failure mode warned about in the executor's "cwd-drift assertion (worktree mode only)" block (#3097).
- **Fix:** From inside the worktree, fast-forwarded the per-agent branch to `fc490bb` (`git reset --hard fc490bb` on `worktree-agent-a32e8c0ae133ae1d5`). The commit hash and content are preserved; the worktree branch now contains the Task 1 commit as its first new commit on top of `4994bc1`. `main` was left at `fc490bb` (not rewound) because rewinding a protected ref is forbidden by the executor protocol. Tasks 2 and 3 then committed cleanly on top.
- **Files modified:** None (this was a git-state recovery, not a code change).
- **Verification:** `git rev-parse --abbrev-ref HEAD` reports `worktree-agent-a32e8c0ae133ae1d5`; `git log --oneline -4` shows `ac1b4c8 8e3451f fc490bb 4994bc1` on the worktree branch in correct order.
- **Committed in:** N/A (state-only recovery, no diff).
- **Orchestrator impact:** When the orchestrator merges `worktree-agent-a32e8c0ae133ae1d5` back into `main`, the merge will fast-forward `main` from `fc490bb` → `8e3451f` → `ac1b4c8`. `main` already contains `fc490bb`, so the resulting tree is identical to a clean per-agent execution. **Action requested:** the orchestrator should verify the fast-forward merge produces the expected three-commit increment and not assume `main` was untouched before merging.
- **Mitigation for future runs:** From Task 2 onward, every Bash invocation explicitly used `cd "$WT"` or `pwd`-checks against the worktree path before any git/file operation, and the cwd-drift sentinel was confirmed populated. All subsequent commits landed on the correct branch.

### 2. [Plan-anticipated] HeaderParser production code unchanged

- **Found during:** Task 3 (Bug #66 implementation)
- **Issue:** Plan step 3 said "If the existing function already preserves a user-supplied `Authorization` header, keep that behavior — only ADD the empty-token guard. If it does not, add both guards." On inspection, `HeaderParser.withBearerToken` already had BOTH guards (empty-token short-circuit at line 25 and case-insensitive Authorization preservation at lines 26-27). No production change was required.
- **Fix:** Added the three required regression-pin tests in `HeaderParserTest.kt` (plus two bonus tests for whitespace-only tokens and case-insensitive preservation). The contract is now pinned so the guards cannot silently regress.
- **Files modified:** Only `src/test/kotlin/com/six2dez/burp/aiagent/util/HeaderParserTest.kt` (created); `src/main/kotlin/com/six2dez/burp/aiagent/util/HeaderParser.kt` is unchanged.
- **Verification:** All 5 HeaderParser tests pass against the unchanged implementation.
- **Committed in:** `ac1b4c8` (Task 3 commit).
- **TDD note:** The RED phase for HeaderParser tests passed immediately (not a "fail-fast" violation — the plan explicitly anticipated this with "if it does not, add both guards"). The real Task-3 work was the OpenAi-compat diagnostics, which DID fail before the edit (no body-preview, no remediation hints).

### 3. [Rule 2 — Missing critical for #68] Hardened stdin EOF for ALL CLI backends, not only Copilot

- **Found during:** Task 2 (Bug #68 implementation)
- **Issue:** The literal fix for #68 only requires Copilot to not hang. But the same stdin-block vector exists for every other CLI backend that probes stdin before printing (a future-proofing concern called out in the plan's STRIDE register T-quick-02).
- **Fix:** Applied `redirectInput(Redirect.from(NUL|/dev/null))` unconditionally in `NonInteractiveCliConnection.send()` so that every backend (codex-cli, gemini-cli, claude-cli, opencode-cli, copilot-cli, ollama) gets an immediate EOF when no stdin payload is supplied. This matches the plan's `<behavior>` directive verbatim: "guarantees EOF semantics for ALL CLI backends (not only Copilot)".
- **Files modified:** `src/main/kotlin/com/six2dez/burp/aiagent/backends/cli/CliBackend.kt` (one location).
- **Verification:** Full test suite (214 tests) still green; no test regression in `BackendHealthCheckTest`, `AgentSupervisorRestartPolicyTest`, or any other CLI-adjacent suite.
- **Committed in:** `8e3451f` (Task 2 commit).

---

**Total deviations:** 3 documented (1 git-state recovery, 1 plan-anticipated no-op, 1 plan-scoped behavior application).
**Impact on plan:** No scope creep. The git-state recovery preserved all work; the HeaderParser no-op is plan-anticipated; the stdin-EOF hardening is a verbatim plan directive.

## Issues Encountered

- **cwd drift on first commit (described in Deviations §1 above)** — root cause: `cd <abs-path>` to the main-repo toplevel in the very first Bash call moved out of the worktree before the spawn-time sentinel was written. Recovery was clean (commit hash preserved on the per-agent branch via fast-forward), but the orchestrator merge step must be aware that `main` already carries `fc490bb` so the merge-back is a 2-commit fast-forward, not a 3-commit fast-forward.

## Threat Surface Scan

No new attack surface introduced beyond what the plan's `<threat_model>` already enumerated. All threats `T-quick-01` through `T-quick-05` are mitigated as planned (`T-quick-04` is the accepted disposition for surfacing up to 800 chars of provider response body, bounded). No new network endpoints, auth paths, file access patterns, or schema changes.

## Known Stubs

None. Every change is wired end-to-end: tokenizer is called by both `isAvailable()` and the supervisor's launch path; `buildCopilotCommand` is dispatched from `buildCommand("copilot-cli", …)`; the new error-message format is reached by both transport branches.

## Self-Check: PASSED

- **Test files exist:** `CliCommandTokenizerTest.kt`, `CopilotCommandBuilderTest.kt`, `HeaderParserTest.kt` — all present at the paths declared in the plan.
- **Commits exist:** `fc490bb`, `8e3451f`, `ac1b4c8` — all reachable from `worktree-agent-a32e8c0ae133ae1d5`.
- **Closes footers:** Each commit has exactly one `Closes #NN` line.
- **Forbidden files untouched:** `build.gradle.kts`, `gradle/`, `ROADMAP.md`, `STATE.md`, `PLAN.md`, and the rest of `.planning/` are unchanged.
- **Version unchanged:** `version = "0.7.0"` in `build.gradle.kts`.
- **Full suite green:** 214 tests / 0 failures / 0 errors / 0 skipped after the final commit.

## Next Phase Readiness

- All three bugs are closed locally on `worktree-agent-a32e8c0ae133ae1d5`. The orchestrator can merge the branch back into `main`; the merge is a fast-forward (note Deviations §1 — `main` already has `fc490bb`, so the merge applies `8e3451f` and `ac1b4c8` on top).
- No remote push performed (per plan constraint).
- No version bump (per plan constraint).
- Three GitHub issues will close automatically once the commits land on `main`.

---
*Phase: quick-260527-f7q*
*Completed: 2026-05-27*
