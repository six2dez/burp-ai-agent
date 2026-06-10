---
phase: 13-privacy-redaction-hardening
fixed_at: 2026-06-10T15:30:00Z
review_path: .planning/phases/13-privacy-redaction-hardening/13-REVIEW.md
iteration: 1
findings_in_scope: 5
fixed: 4
skipped: 1
status: partial
---

# Phase 13: Code Review Fix Report

**Fixed at:** 2026-06-10T15:30:00Z
**Source review:** .planning/phases/13-privacy-redaction-hardening/13-REVIEW.md
**Iteration:** 1

**Summary:**
- Findings in scope (Critical + Warning): 5
- Fixed: 4 (CR-01, WR-01, WR-03, WR-04)
- Skipped: 1 (WR-02 — deliberate design choice, documented below)

All four applied fixes were verified by re-reading the modified sections and by a green
`./gradlew test` run (full suite, including 4 new tests). Three Info findings (IN-01, IN-02,
IN-03) were out of scope (fix_scope = critical_warning); all three are flagged "No change
required" in REVIEW.md.

## Fixed Issues

### CR-01: Custom redaction patterns are never loaded at startup — silently inactive until next manual Save

**Files modified:** `src/main/kotlin/com/six2dez/burp/aiagent/App.kt`, `src/test/kotlin/com/six2dez/burp/aiagent/redact/RedactionTest.kt`
**Commit:** b17d58e
**Applied fix:** Added `Redaction.setCustomPatterns(settings.customRedactionPatterns)` in
`App.initialize()` immediately after `val settings = settingsRepo.load()`, with a comment
explaining the startup-seeding rationale. This makes persisted custom patterns active on every
launch instead of only after a manual re-save, closing the silent data-leak. The call is safe
unconditionally (patterns were validated by `isPatternSafe` on save; `setCustomPatterns` drops
any uncompilable entry). Added regression test `customPatternsFromSettingsAreActiveAfterSeeding`
that exercises the load → seed → apply contract using a pattern sourced from the persisted list
(not set inline), which the prior test `customPatternRedactsInStrictAndBalanced` did not cover.

### WR-01: Custom pattern that matches the empty string explodes/corrupts the outbound context

**Files modified:** `src/main/kotlin/com/six2dez/burp/aiagent/redact/SafeRegex.kt`, `src/main/kotlin/com/six2dez/burp/aiagent/ui/SettingsPanel.kt`, `src/test/kotlin/com/six2dez/burp/aiagent/redact/SafeRegexTest.kt`
**Commit:** 99b3595
**Applied fix:** Added an empty-match guard in `SafeRegex.isPatternSafe` — `if
(compiled.matcher("").find()) false else <existing ReDoS probe>` — so zero-width-matching
patterns (`a*`, `\d*`, `[0-9]*`, `\s*`, `x?`, `(foo)?`, `.*`, `a|`) are rejected before they can
be applied via `replaceAll` and corrupt/bloat the context. Broadened the `SettingsPanel`
rejection feedback message to name the empty-match case ("invalid regex, matches empty string,
or too slow") so the user understands why a pattern was dropped. Added tests
`emptyMatchingPatternsAreRejected` (footguns rejected) and `nonEmptyMatchingPatternsStillAccepted`
(genuine ≥1-char patterns still pass).

### WR-03: JSON redaction silently misses numeric / unquoted secret values

**Files modified:** `src/main/kotlin/com/six2dez/burp/aiagent/redact/Redaction.kt`, `src/test/kotlin/com/six2dez/burp/aiagent/redact/RedactionTest.kt`
**Commit:** 4a6a07b
**Applied fix:** Extended `jsonSecretKeyRegex`'s value side from `"[^"]*"` to
`("[^"]*"|true|false|null|-?\d+(?:\.\d+)?)` so a sensitive key with a numeric, boolean, or null
value is also redacted (e.g. `{"token":12345,"api_key":true}`). The existing replacement lambda
already references only group 1 and emits the quoted token `"[REDACTED]"`, so any matched value
type is normalized to a valid JSON string — no replacement-side change needed. Updated the
limitation comment to record the now-closed numeric/unquoted gap. Added test
`bodyJsonUnquotedSecretValuesRedacted` covering numeric/boolean/null/negative-int sensitive
values while asserting non-sensitive numeric fields (`balance`) stay untouched.

### WR-04: `bearerRegex` trailing `=*` can over-consume benign characters after a token

**Files modified:** `src/main/kotlin/com/six2dez/burp/aiagent/redact/Redaction.kt`
**Commit:** d3bad49
**Applied fix:** Documentation-only (no behavioral change). Added a comment above `bearerRegex`
explaining that the trailing `=*` intentionally consumes any run of `=` immediately after the
token, that this is fail-safe over-redaction (not a leak — the full Authorization header is
already replaced by `authHeaderRegex`), and that `bearerRegex` additionally covers bearer tokens
in bodies/JSON/free text. This follows the reviewer's primary accepted-tradeoff remedy: the
reviewer's own precise-boundary suggestion `(?:=*)(?![A-Za-z0-9])` does NOT fix the cited
`Bearer abc=== then text` case (the lookahead succeeds on the trailing space), and dropping `=*`
would risk leaking real base64 padding. Documenting the intentional behavior is the
lowest-risk resolution for this benign, lowest-priority nit.

## Skipped Issues

### WR-02: `code` is an over-broad sensitive-key token that redacts benign body fields

**File:** `src/main/kotlin/com/six2dez/burp/aiagent/redact/Redaction.kt:80-81` (`SENSITIVE_KEYS`)
**Reason:** Skipped as a deliberate design choice per fix guidance (this finding was explicitly
named as the design-choice example to skip). The inclusion of `code` in `SENSITIVE_KEYS` is an
intentional, privacy-conservative decision: `code` carries OAuth authorization codes, which are
secrets that grant token exchange. The reviewer's concern is over-redaction of benign fields
(HTTP status codes, country codes, coupon codes), which is fail-safe for secrecy — it degrades
AI analysis quality slightly but never leaks. Narrowing to `auth_code|authorization_code` or
dropping `code` would re-open a leak path for the standalone OAuth `code=` parameter, directly
weakening the project's non-negotiable privacy guarantee. Per the guidance ("For any warning
whose fix is actually a deliberate design choice ... SKIP it and document the rationale rather
than degrading behavior"), the privacy-favoring behavior is retained. The false-positive
tradeoff is acknowledged here as a known, accepted limitation.

**Original issue:** `SENSITIVE_KEYS` includes the bare token `code`; combined with
`formBodyParamRegex`, any form/query field named `code` is redacted (e.g.
`code=200&status=ok` → `code=[REDACTED]&status=ok`). `code` is common in benign contexts, so the
broad token strips data the analyst may need in the AI context.

---

_Fixed: 2026-06-10T15:30:00Z_
_Fixer: Claude (gsd-code-fixer)_
_Iteration: 1_
