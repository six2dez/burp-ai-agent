---
phase: 13-privacy-redaction-hardening
reviewed: 2026-06-10T00:00:00Z
depth: standard
files_reviewed: 12
files_reviewed_list:
  - src/main/kotlin/com/six2dez/burp/aiagent/redact/Redaction.kt
  - src/main/kotlin/com/six2dez/burp/aiagent/redact/SafeRegex.kt
  - src/main/kotlin/com/six2dez/burp/aiagent/redact/SecretShapes.kt
  - src/main/kotlin/com/six2dez/burp/aiagent/config/AgentSettings.kt
  - src/main/kotlin/com/six2dez/burp/aiagent/config/Defaults.kt
  - src/main/kotlin/com/six2dez/burp/aiagent/ui/components/ContextPreviewDialog.kt
  - src/main/kotlin/com/six2dez/burp/aiagent/ui/panels/PrivacyConfigPanel.kt
  - src/main/kotlin/com/six2dez/burp/aiagent/ui/SettingsPanel.kt
  - src/test/kotlin/com/six2dez/burp/aiagent/redact/RedactionTest.kt
  - src/test/kotlin/com/six2dez/burp/aiagent/redact/SafeRegexTest.kt
  - src/test/kotlin/com/six2dez/burp/aiagent/redact/SecretShapesTest.kt
  - src/test/kotlin/com/six2dez/burp/aiagent/config/AgentSettingsMigrationTest.kt
findings:
  critical: 1
  warning: 4
  info: 3
  total: 8
status: issues_found
---

# Phase 13: Code Review Report

**Reviewed:** 2026-06-10
**Depth:** standard
**Files Reviewed:** 12
**Status:** issues_found

## Summary

Reviewed the Phase 13 privacy/redaction hardening change set: the HKDF host-anonymization
rewrite, the body-level (form/JSON/custom) redaction pass, the ReDoS-safe `SafeRegex`
deadline guard, the curated `SecretShapes` survivor detector, the `ContextPreviewDialog`
WARN banner, and the `customRedactionPatterns` settings plumbing.

The crypto is correct: HKDF extract/expand matches RFC 5869 Test Case 1 (verified by the
in-tree vector test, which passes), the empty-salt zero-byte substitution is sound, the 6-byte
OKM → 12-hex output format is preserved, and host anonymization is deterministic per salt. The
curated `SecretShapes` regexes are anchored with `\b` and use single quantifiers — I stress-tested
all eight against 100K-char adversarial inputs and every one completes in under 2 ms, so there is
no ReDoS in the detection set even though `findSurviving` does not route through `SafeRegex`. The
built-in form/JSON regexes use a bounded `[^&\s"'<>]+` / `[^"]*` value class with no nested
quantifiers and do not over-match suffix keys (`publickey`, `donkey`) because the alternation is
gated by `(^|[?&])`. The `ContextPreviewDialog` banner names categories only and never echoes the
matched value. Plaintext storage of custom patterns (not via `SecretCipher`) is correct — they are
config, not secrets — and the absent-key default is a safe empty list. No secret or matched content
is logged anywhere (migration catch blocks log key names only).

However, there is one BLOCKER: configured custom redaction patterns are **not loaded into the
redaction engine at extension startup** — they only become active after the user manually re-saves
Settings. On every Burp launch the custom-pattern list silently resets to empty, so the exact
secrets a user configured the tool to strip will be sent to the AI backend until they happen to
click Save again. This defeats the feature's privacy guarantee with no user-visible signal.

The remaining findings are over-redaction / output-corruption issues (empty-matching custom
patterns, the broad `code` key) and documented under-redaction limitations that are worth
re-confirming.

## Critical Issues

### CR-01: Custom redaction patterns are never loaded at startup — silently inactive until next manual Save

**File:** `src/main/kotlin/com/six2dez/burp/aiagent/App.kt:82` (init) and
`src/main/kotlin/com/six2dez/burp/aiagent/ui/SettingsPanel.kt:1471` (only caller of `setCustomPatterns`)

**Issue:**
`Redaction.compiledCustomPatterns` starts as `emptyList()` and is populated *only* by
`Redaction.setCustomPatterns(...)`, which is called from exactly one place:
`SettingsPanel.applyAndSaveSettings()` (line 1471), i.e. only when the user clicks **Save** in the
current session. The extension entry point `App.initialize()` loads `settings` at line 82 and wires
up every other subsystem (audit, supervisor, MCP, passive/active scanners) from it, but it never
calls `Redaction.setCustomPatterns(settings.customRedactionPatterns)`.

Consequence: a user who configured custom patterns (e.g. an internal token shape
`INTERNAL-[A-Z0-9]{20}`) in a previous session restarts Burp → the patterns are persisted and shown
in the Settings text area, but the live redaction pipeline holds an **empty** custom-pattern list.
Every context sent to the AI backend (chat actions, MCP tools, bounty resolver, passive scanner)
will contain the very secrets the user told the tool to strip. The failure is silent — no banner,
no log line — so the user has no way to know redaction is not applying their rules. This directly
violates the project's non-negotiable "privacy controls are non-negotiable, no leaking sensitive
traffic" constraint (CLAUDE.md) and is a data-leak regression.

The existing `RedactionTest.customPatternRedactsInStrictAndBalanced` masks this because it calls
`Redaction.setCustomPatterns(...)` directly; no test exercises the load → apply path that production
uses on startup.

**Fix:**
Push the persisted patterns into the engine during initialization, right after settings are loaded.
In `App.initialize()` (after line 82):

```kotlin
val settings = settingsRepo.load()
// PRIV-02: seed the redaction engine with persisted custom patterns so they are active
// immediately on launch — NOT only after the user re-saves Settings.
Redaction.setCustomPatterns(settings.customRedactionPatterns)
```

Because `setCustomPatterns` silently drops uncompilable entries (and persisted entries were already
validated by `isPatternSafe` on save), this is safe to call unconditionally at startup. Add a
regression test that saves patterns through the repository, constructs a fresh engine state, and
asserts `Redaction.apply(...)` redacts using a loaded (not directly-set) pattern.

## Warnings

### WR-01: Custom pattern that matches the empty string explodes/corrupts the outbound context

**File:** `src/main/kotlin/com/six2dez/burp/aiagent/redact/SafeRegex.kt:87-100` (`isPatternSafe`),
applied at `src/main/kotlin/com/six2dez/burp/aiagent/redact/Redaction.kt:241-243`

**Issue:**
`isPatternSafe` validates only (a) that the regex compiles and (b) that it does not time out on the
adversarial probe. It does **not** reject patterns that match the empty string. A user pattern such
as `a*`, `\d*`, `[0-9]*`, `\s*`, `x?`, or `(foo)?` passes validation (compiles + completes instantly)
and is then applied via `SafeRegex.replaceAllSafe(out, p, "[REDACTED]")`. `Matcher.replaceAll`
advances past zero-width matches one character at a time, so the replacement is inserted between
**every character** of the context. I verified this empirically: a 44-char JSON context becomes
~490 chars of `[REDACTED]{[REDACTED]"[REDACTED]u...`, roughly a 10x blow-up of mangled content sent
to the model. With `.*` the entire context collapses to `[REDACTED][REDACTED]`.

This is fail-*safe* for secrecy (it over-redacts rather than leaking), so it is not a BLOCKER, but
it silently corrupts the AI payload and bloats it, and the user gets a green "Custom patterns saved."
confirmation with no warning. It is a foreseeable footgun for a regex text box aimed at security
users who are not necessarily regex experts.

**Fix:**
Reject empty-matching patterns in `isPatternSafe` (or in `validateAndCollectCustomPatterns`):

```kotlin
val compiled = Pattern.compile(regex)
// Reject patterns that can match the empty string — replaceAll would insert the
// replacement between every character, corrupting and bloating the context.
if (compiled.matcher("").find() && compiled.matcher("").start() == 0 &&
    compiled.matcher("").end() == 0
) {
    return false
}
```

A simpler equivalent: `if (Pattern.compile(regex).matcher("").matches() ||
compiled.matcher("anything").let { it.find() && it.group().isEmpty() }) return false`. Surface a
distinct feedback message ("pattern can match empty string — rejected") so the user understands why.

### WR-02: `code` is an over-broad sensitive-key token that redacts benign body fields

**File:** `src/main/kotlin/com/six2dez/burp/aiagent/redact/Redaction.kt:80-81` (`SENSITIVE_KEYS`)

**Issue:**
`SENSITIVE_KEYS` includes the bare token `code`. Combined with `formBodyParamRegex`
(`(^|[?&])($SENSITIVE_KEYS)=...`), any form/query field literally named `code` is redacted. I
confirmed `code=200&status=ok` → `code=[REDACTED]&status=ok`. `code` is extremely common in benign,
non-secret contexts (HTTP status codes, country codes, coupon/discount codes, error codes, currency
codes, 2FA *display* fields, sort codes). The intent is presumably OAuth `code=` authorization codes,
but the token is too generic and will frequently strip data the analyst needs to see in the AI
context, degrading analysis quality. (The leading-substring case is fine — `country_code=` is *not*
matched because the alternation is gated by `(^|[?&])` — so the issue is specifically the standalone
`code` field.)

**Fix:**
Either drop `code` from the shared `SENSITIVE_KEYS` vocabulary, or narrow it to the OAuth-specific
forms that actually carry secrets, e.g. `auth_code|authorization_code` (and keep it out of the
high-traffic generic namespace). If `code` must stay, document the false-positive tradeoff in the
comment block at lines 78-79 alongside the existing PRIV-02 rationale.

### WR-03: JSON redaction silently misses numeric / unquoted secret values

**File:** `src/main/kotlin/com/six2dez/burp/aiagent/redact/Redaction.kt:103-106` (`jsonSecretKeyRegex`)

**Issue:**
`jsonSecretKeyRegex` only matches a string value: `"(key)"\s*:\s*"[^"]*"`. A JSON body with a
numeric or boolean value under a sensitive key is not redacted — I confirmed
`{"token":12345,"api_key":true}` passes through unchanged. Numeric secrets are real (numeric API
keys/account IDs, integer session identifiers, OTP codes serialized as numbers, `"pin":123456`).
The file documents the embedded-escaped-quote limitation (lines 100-102) but not this
numeric/unquoted-value gap, so it is an undocumented under-redaction path that could leak a
sensitive integer value to the backend.

**Fix:**
Extend the value side of the pattern to also cover unquoted JSON scalars, e.g.:

```kotlin
private val jsonSecretKeyRegex =
    Regex("(?i)(\"(?:$SENSITIVE_KEYS)\"\\s*:\\s*)(\"[^\"]*\"|true|false|null|-?\\d+(?:\\.\\d+)?)")
// replacement: "${m.groupValues[1]}\"[REDACTED]\""
```

At minimum, document the numeric-value gap in the limitation comment so it is a known, accepted
tradeoff rather than a silent surprise.

### WR-04: `bearerRegex` trailing `=*` can over-consume benign characters after a token

**File:** `src/main/kotlin/com/six2dez/burp/aiagent/redact/Redaction.kt:70` (`bearerRegex`)

**Issue:**
`bearerRegex = Regex("(?i)bearer\\s+[A-Za-z0-9\\-\\._~\\+\\/]+=*")` ends with `=*`, intended to
capture base64 padding. Because the token char-class already excludes `=`, the `=*` greedily eats
any run of `=` *immediately* following the token even when those `=` are not part of the credential.
I confirmed `Authorization: Bearer abc=== then text` → `Authorization: Bearer [REDACTED] then text`,
which swallows the `===` that followed the token. This is benign for the standard auth-header case
(the whole header is replaced first by `authHeaderRegex`), but `bearerRegex` also fires on bearer
tokens appearing in bodies/JSON/free text, where trailing `=` could be meaningful delimiters. This
is a minor correctness/over-redaction nit rather than a leak.

**Fix:**
If the intent is strictly base64url padding, the `=*` is acceptable but should be documented as
"consumes trailing `=` padding (and any adjacent `=`)". If precise boundaries matter, anchor the end
with a word/non-base64 boundary, e.g. drop the `=*` (base64url tokens rarely include `=` padding) or
replace with `(?:=*)(?![A-Za-z0-9])`. Low priority.

## Info

### IN-01: Two divergent JWT regexes maintained by hand (drift risk)

**File:** `src/main/kotlin/com/six2dez/burp/aiagent/redact/Redaction.kt:76` (`jwtRegex`) and
`src/main/kotlin/com/six2dez/burp/aiagent/redact/SecretShapes.kt:75` (JWT shape)

**Issue:**
The redaction `jwtRegex` and the detection JWT shape are intentionally duplicated literals (the
SecretShapes comment at lines 72-74 acknowledges this and prefers duplication over coupling). They
are currently identical, but hand-maintained twins drift over time, which could let a JWT form be
*detected* as a survivor while not being *redacted*, or vice versa. This is an accepted design
decision per the comment; flagging only so future edits keep them in sync.

**Fix:** No change required. If a third consumer appears (e.g. the Phase 15 tripwire), promote the
shared literal to a single `internal const val` and reference it from both sites.

### IN-02: `findSurviving` runs eight regexes on the EDT with no size cap

**File:** `src/main/kotlin/com/six2dez/burp/aiagent/ui/components/ContextPreviewDialog.kt:59`

**Issue:**
`SecretShapes.findSurviving(contextJson)` runs on the Swing EDT inside `confirm(...)`. The shapes are
all linear-time (verified: <2 ms on 100K chars) and context is bounded (`MAX_CONTEXT_TOTAL_CHARS =
40_000`), so there is no practical hang today. Noting it because, unlike the redaction custom
patterns, `findSurviving` does not go through `SafeRegex`; if a future shape with a nested quantifier
is added to the curated list it would run unbounded on the UI thread.

**Fix:** No change required now. When the Phase 15 tripwire reuses this set, consider routing the
survivor scan through a bounded matcher or asserting linear-time shapes in a test.

### IN-03: `setCustomPatterns` and save-validation drop invalid patterns via two independent code paths

**File:** `src/main/kotlin/com/six2dez/burp/aiagent/redact/Redaction.kt:121-130` and
`src/main/kotlin/com/six2dez/burp/aiagent/ui/SettingsPanel.kt:1211-1251`

**Issue:**
`setCustomPatterns` silently drops patterns that throw `PatternSyntaxException`, while
`validateAndCollectCustomPatterns` drops patterns failing `isPatternSafe` (compile + ReDoS probe).
The two filters are independent: a pattern that compiles but is unsafe is dropped at the UI layer but
would compile fine in `setCustomPatterns`; the comment at lines 118-119 assumes the input list is
"already known-safe," which holds only because the single production caller passes validated input.
The CR-01 startup fix must preserve this invariant (persisted patterns were validated on save, so
re-feeding them at startup is safe). Minor coupling note.

**Fix:** No behavioral change required. Consider a single `Redaction.setCustomPatternsValidated`
entry point that both validates and compiles, so the "already-safe" precondition cannot be violated
by a future second caller.

---

_Reviewed: 2026-06-10_
_Reviewer: Claude (gsd-code-reviewer)_
_Depth: standard_
