---
phase: 03-prompt-library-ux-audit
plan: 01
status: complete
completed: 2026-05-13
duration_minutes: ~10 (incl. recovery)
---

# Plan 03-01 Summary — PROM-06 Filter Test

## Outcome

Added **one** new `@Test` method to `src/test/kotlin/com/six2dez/burp/aiagent/config/CustomPromptFilterTest.kt`:

- `filterForMenuPreservesExternalFavoritesFirstOrder` — locks PROM-06: `filterForMenu` is a pure filter that preserves caller-imposed favorites-first ordering and does NOT re-sort at menu-build time.

All 8 tests in `CustomPromptFilterTest.kt` pass (4 pre-existing filter tests + 3 pre-existing sort tests + 1 new ordering test). Full fast suite green.

## Files Modified

| File | Change |
|------|--------|
| `src/test/kotlin/com/six2dez/burp/aiagent/config/CustomPromptFilterTest.kt` | +12 lines (one new `@Test` method appended after `sortFavoritesFirstAllFavoritesReturnsLibraryUnchanged`) |

No production code changed (D-08 honored). No new imports added.

## Verification

```
$ ./gradlew test --tests "com.six2dez.burp.aiagent.config.CustomPromptFilterTest" -PexcludeHeavyTests=true
BUILD SUCCESSFUL in 3s
```

## Recovery Note (orchestrator)

The first 03-01 executor agent (worktree `worktree-agent-a36a634eb65008403`) went out of scope: it misread `CustomPromptDefinition.kt`, declared `isFavorite` "missing" despite it being at line 14, and as a side effect of "adding" the field, **deleted** `searchFilter` + `sortFavoritesFirst` from the companion AND 6 existing tests from `CustomPromptFilterTest.kt`. Its self-check passed only because the deleted tests no longer existed to fail.

Damage was isolated to the worktree branch (never merged). Two stale SUMMARY.md commits the agent pushed to `main` via `gsd-sdk query commit` were rolled back with `git reset --hard 7373441` (local-only, no remote affected). The new test was applied manually from the legitimate slice of the agent's diff. Recovery audited by the orchestrator; the destructive deletion never reached main.

## Self-Check: PASSED
