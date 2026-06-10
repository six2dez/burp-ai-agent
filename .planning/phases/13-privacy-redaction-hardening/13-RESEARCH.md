# Phase 13: Privacy & Redaction Hardening - Research

**Researched:** 2026-06-10
**Domain:** Privacy redaction pipeline — cryptographic host anonymization (HKDF), body/JSON secret redaction, ReDoS-safe regex, curated secret-shape detection, Swing UI touch points
**Confidence:** HIGH

## Summary

Phase 13 is almost entirely internal-Kotlin work on an existing, well-structured redaction
subsystem. Three of the four deliverables (PRIV-01 HKDF, PRIV-02 body redaction, the shared
`SecretShapes` set) live in `redact/Redaction.kt` and a new `redact/SecretShapes.kt`; the two UI
touch points (custom-pattern text area, survived-secret banner) reuse Phase 9 builders verbatim and
add no new components. **No new dependencies are required** — `javax.crypto.Mac` (HKDF) and
`java.util.regex` (with an interruptible `CharSequence` for the ReDoS guard) are JDK 21 built-ins,
which satisfies the CLAUDE.md MIT-compat constraint trivially.

The single highest-value finding: **the HKDF migration is test-safe.** Every existing test asserts
only the `host-` prefix substring (`output.contains("Host: host-")`) or per-salt determinism /
inequality — **none asserts a literal hex hash value** (verified by grep across all 71 test files).
So switching `MessageDigest.getInstance("SHA-256")` → `Mac.getInstance("HmacSHA256")` HKDF while
keeping the `host-<12hex>.local` format and per-salt determinism breaks zero tests. The CONTEXT.md
claim that "existing STRICT tests are updated to the new expected hash values" is therefore
*conservative* — in practice no expected values are hardcoded, so there is nothing to update; the
plan should simply re-run the suite to confirm green. I built and ran a pure-`javax.crypto` HKDF
against RFC 5869 Test Case 1 and it reproduces the published PRK and OKM byte-for-byte, so the
construction below is verified, not assumed.

`Redaction.apply` already runs over the **full** HTTP message string (headers + body) at all six
call sites (ContextCollector, McpToolContext, McpTools ×2, BountyPromptTagResolver, PassiveAiScanner),
so body redaction is purely a matter of *pattern reach* — no new call site, and the new patterns
automatically apply everywhere. `anonymizeHost` is called from ~10 sites but the HKDF change is
internal-only, so all callers are unaffected as long as the output format is preserved.

**Primary recommendation:** Add a verified pure-JDK HKDF (RFC 5869 extract-then-expand, HmacSHA256,
`info = "burp-ai-agent:host"`, `salt = stableHostSalt` bytes, IKM = host bytes, L = 6 → 12 hex);
add body/JSON patterns plus a `SafeRegex` interruptible-matcher primitive (50 ms timeout) into the
`policy.redactTokens` branch; extract a shared `object SecretShapes` consumed by both the new
preview banner and (later) the Phase 15 tripwire. Gate everything new on `policy.redactTokens` so
OFF mode stays a pure pass-through.

<user_constraints>
## User Constraints (from CONTEXT.md)

### Locked Decisions

**Host Anonymization (HKDF) — PRIV-01**
- Keep the output format `host-<12hex>.local` — swap only the internal algorithm so the format, call sites, and forward/reverse map semantics stay stable.
- Use real HKDF: HMAC-SHA256 extract-then-expand with a fixed app-specific info label (e.g. `burp-ai-agent:host`); reuse the existing `stableHostSalt` as the HKDF salt/IKM input.
- No persistence migration — `hostForwardMap`/`hostReverseMap` are in-memory `ConcurrentHashMap`s; existing salt rotation (`rotateSaltBtn` → `clearMappings`) already handles invalidation. Existing STRICT tests are updated to the new expected hash values.

**Body Redaction Scope — PRIV-02**
- Redact sensitive-named fields **anywhere** in an `x-www-form-urlencoded` body, including the leading field (which has no `?`/`&` prefix and is the documented gap). Reuse/extend the existing sensitive-key vocabulary from `urlTokenParamRegex`.
- Also redact known-sensitive **JSON body keys** (e.g. `"api_key":"…"`, `"token":"…"`) — AI context payloads are frequently JSON.
- Apply body redaction to **both request and response** bodies.
- Large-body guard: a size cap (skip/short-circuit bodies beyond ~1 MB) **plus** a per-pattern ~50 ms timeout to bound ReDoS and worst-case regex cost. The same 50 ms timeout primitive is reused by the custom-pattern validator.

**Custom Pattern UX & Storage — PRIV-02 / PRIV-04**
- Input UX: one-regex-per-line text area in the Privacy settings panel.
- Validation on **save**: check regex syntax AND run a ~50 ms ReDoS timeout against an adversarial test string; reject patterns that fail to compile or time out, with inline error feedback. Valid patterns persist via the existing config/secret-aware preference store.
- Replacement token: `[REDACTED]`, consistent with built-in redactions.
- Active in **STRICT + BALANCED** (folded into the `redactTokens` policy branch); inactive in OFF.

**Survived-Secret Indicator — PRIV-04**
- Location: inside the existing `ContextPreviewDialog` (the pre-send preview the user already sees).
- Presentation: a **non-blocking** warning banner showing a count and which shape(s) matched — informational, never a hard stop.
- Pattern set: introduce a **shared curated `SecretShapes`** object now (`sk-…`, `AKIA…`, `ghp_…`, JWT, generic high-entropy key forms). Phase 15's tripwire reuses the same set — single source of truth.
- Scan target: the **post-redaction** context only.

### Claude's Discretion
- Exact curated shapes in `SecretShapes`, the regex vocabulary for sensitive form/JSON keys, the precise HKDF expand length (≥ the 6 bytes currently truncated), and the timeout-enforcement mechanism (interruptible matcher vs bounded executor) are at Claude's discretion, guided by codebase conventions and the success criteria.

### Deferred Ideas (OUT OF SCOPE)
- The pre-send secret tripwire that scans the final outbound payload and warns before send (PRIV-03) — Phase 15. Phase 13 only provides the shared `SecretShapes` set it will consume.
- Bounded/cleared host-anonymization maps as a reliability concern (REL-02) — Phase 17.
</user_constraints>

<phase_requirements>
## Phase Requirements

| ID | Description | Research Support |
|----|-------------|------------------|
| PRIV-01 | Host anonymization uses a cryptographic method consistent with documentation (real HKDF HMAC-SHA256 extract/expand); forward/reverse mapping still resolves; existing privacy-mode tests stay green | Verified pure-JDK HKDF reference impl (passes RFC 5869 Test Case 1); confirmed zero tests assert literal hashes so the format-preserving swap keeps them green; `anonymizeHost` internal-only change unaffects ~10 call sites |
| PRIV-02 | Redaction catches secrets in request/response bodies — leading field of `x-www-form-urlencoded` body + user-configurable custom pattern list; STRICT/BALANCED unit tests + ReDoS/perf guard on large bodies | `Redaction.apply` already runs over full message string at all 6 call sites; body-start-anchored form regex + JSON-key regex + `SafeRegex` interruptible-matcher (50 ms) + 1 MB size cap; persistence via existing `AgentSettings`/`Preferences` list-serialization pattern |
| PRIV-04 | Redaction preview UI flags when a known secret shape passes through | Shared `object SecretShapes`; `SubtleNotice` WARN banner in `ContextPreviewDialog` (single caller: ChatPanel.kt:290) scanning post-redaction `contextJson`; UI-SPEC already approved |
</phase_requirements>

## Project Constraints (from CLAUDE.md)

| Directive | How Phase 13 complies |
|-----------|----------------------|
| Kotlin (JVM 21), Gradle Kotlin DSL, Montoya API — fixed | All new code is Kotlin/JDK; no stack change |
| **No new dependencies unless MIT-compat + justified; prefer JDK built-ins** | HKDF via `javax.crypto.Mac`; ReDoS guard via `java.util.regex` + interruptible `CharSequence`. **Zero new deps.** |
| Privacy controls non-negotiable; hand-curated regex + HKDF host anonymization is the documented design | This phase *implements* the documented HKDF and extends the hand-curated regex set — directly serves the core value |
| STRICT / BALANCED / OFF must stay user-visible & pre-flight | New behavior gates on `policy.redactTokens` (active STRICT+BALANCED, inactive OFF); modes unchanged |
| English-only code & comments (AGENTS.md) | All identifiers, comments, copy strings English |
| MIT license — keep deps compatible | No deps added |
| Audit defaults: disabled, hashes only | Untouched by this phase |

## Architectural Responsibility Map

| Capability | Primary Tier | Secondary Tier | Rationale |
|------------|-------------|----------------|-----------|
| HKDF host anonymization | Redaction core (`redact/Redaction.kt`) | — | Pure crypto transform on a string; no UI, no I/O, no persistence. Internal algorithm swap behind a stable `anonymizeHost` signature. |
| Body / form / JSON secret redaction | Redaction core (`redact/Redaction.kt`) | — | Extends the existing `apply()` `redactTokens` branch; runs over the full message string already passed in. No new call site. |
| ReDoS-safe regex timeout | Redaction core (new `redact/SafeRegex.kt` util) | Config validation (`PrivacyConfigPanel` save path) | Single primitive reused by body redaction AND custom-pattern save validation. Belongs with redaction, not UI. |
| Curated secret shapes | Redaction core (new `redact/SecretShapes.kt`) | UI preview (PRIV-04) + Phase 15 tripwire | Single source of truth (`object`); consumed by UI and a future scanner. Pure data + matching logic. |
| Custom-pattern persistence | Config (`config/AgentSettings.kt` + `Preferences`) | — | Follows the existing list-serialization pattern (`customPromptLibrary`). Patterns are NOT secrets — plaintext pref is correct; no `SecretCipher`. |
| Custom-pattern input + validation feedback | UI panel (`ui/panels/PrivacyConfigPanel.kt`) | Redaction core (calls `SafeRegex` validator) | Swing form row; delegates the actual ReDoS check to the redaction-core primitive. |
| Survived-secret banner | UI dialog (`ui/components/ContextPreviewDialog.kt`) | Redaction core (calls `SecretShapes.findSurviving`) | Display-only; scans post-redaction context via the shared object. |

## Standard Stack

### Core
| Library | Version | Purpose | Why Standard |
|---------|---------|---------|--------------|
| `javax.crypto.Mac` (`HmacSHA256`) | JDK 21 built-in | HKDF extract + expand HMAC primitive | Already used in `SecretCipher.kt` (PBKDF2WithHmacSHA256); standard JCA algorithm; no external HKDF lib needed |
| `javax.crypto.spec.SecretKeySpec` | JDK 21 built-in | Wrap salt/PRK bytes as an HMAC key | Standard JCA key spec; already imported in `SecretCipher.kt` |
| `java.util.regex` (`Pattern` / `Matcher`) | JDK 21 built-in | Body/JSON/custom-pattern matching + the interruptible-matcher ReDoS guard | Project convention is hand-curated `kotlin.text.Regex`/`java.util.regex`; the interruptible-`CharSequence` trick needs raw `Matcher`, not `kotlin.text.Regex` |

### Supporting
| Library | Version | Purpose | When to Use |
|---------|---------|---------|-------------|
| `java.util.concurrent` (`Executors`, `Future`, `TimeoutException`) | JDK 21 built-in | ONLY if the bounded-executor timeout variant is chosen over the interruptible-`CharSequence` variant | Alternative ReDoS mechanism — see Pattern 2; the interruptible-`CharSequence` variant is preferred (no thread pool, no `ThreadLocal` leak risk in Burp's long-lived JVM) |
| JUnit Jupiter | 6.0.3 (in build) | Unit tests for all four deliverables | Existing test framework — `org.junit.jupiter.api.*` |
| `org.mockito.kotlin:mockito-kotlin` | 5.4.0 (in build) | Mock `Preferences` for persistence round-trip tests if needed | Already used for `AgentSettings` tests |

### Alternatives Considered
| Instead of | Could Use | Tradeoff |
|------------|-----------|----------|
| Pure-JDK HKDF | Bouncy Castle `HKDFBytesGenerator` | REQUIREMENTS.md explicitly excludes Bouncy Castle as a new runtime dep ("javax.crypto suffices… avoid fat-JAR conflicts"). ~30 lines of verified JDK code beats a multi-MB dep. |
| Interruptible `CharSequence` (preferred) | Bounded `ExecutorService` + `Future.get(timeout)` | Executor variant interrupts a *separate* thread running the match; simpler to reason about but adds a thread pool to a long-lived plugin JVM and risks lingering threads. Interruptible-`CharSequence` keeps it on the calling thread with a tripwire — no pool. Both are acceptable per CONTEXT discretion. |
| Regex-based JSON-key redaction | Jackson tree-walk (`JsonNode`) re-serialize | A tree-walk is more robust against weird escaping but (a) bodies may be truncated/invalid JSON (see `ContextCollector.truncateHttpMessageBody`), (b) re-serializing would reorder/reformat the user's body and break the "don't corrupt non-secret content" goal. Curated regex over the raw string matches the established pattern and tolerates partial bodies. |

**Installation:**
```bash
# No installation. All primitives are JDK 21 built-ins already on the classpath.
# javax.crypto.Mac — same package family as the existing SecretCipher.kt
# java.util.regex — same family as the existing Redaction.kt regexes
```

**Version verification:** N/A — no external packages added. Build already targets JVM 21
(`build.gradle.kts:58 languageVersion = 21`, `:104 jvmTarget = JVM_21`) and `javax.crypto.Mac`
HmacSHA256 is a guaranteed JCA standard algorithm on every conformant JDK 21.
`[VERIFIED: ran javax.crypto HKDF against RFC 5869 Test Case 1 on local JDK — PRK + OKM match]`

## Package Legitimacy Audit

> **Not applicable — Phase 13 installs no external packages.** All cryptographic and regex
> primitives are JDK 21 built-ins (`javax.crypto.*`, `java.util.regex.*`, `java.util.concurrent.*`),
> already on the compile/runtime classpath and not subject to registry slopcheck. The CLAUDE.md
> "prefer JDK built-ins" constraint and the REQUIREMENTS.md exclusion of Bouncy Castle/Tink/keyring
> deps make any new package a contract violation. slopcheck/registry verification skipped by design.

**Packages removed due to slopcheck [SLOP] verdict:** none (no packages)
**Packages flagged as suspicious [SUS]:** none (no packages)

## Architecture Patterns

### System Architecture Diagram

```
                         ┌─────────────────────────────────────────────┐
  HTTP message string    │            Redaction.apply(raw, policy,      │
  (headers + body,       │                   stableHostSalt)            │
  full, from 6 callers) ─┼──▶ if stripCookies ─▶ cookie/set-cookie strip│
                         │    if redactTokens ─▶ header-auth regex       │
                         │                       bearer / basic regex    │
                         │                       jwt regex               │
                         │                       urlTokenParamRegex      │
                         │      ╔══════════ NEW (PRIV-02) ══════════╗     │
                         │      ║ body size-cap guard (≤ ~1 MB)     ║     │
                         │      ║ form-body sensitive-field regex   ║     │
                         │      ║   (body-start-anchored, no [?&])  ║     │
                         │      ║ JSON sensitive-key regex          ║     │
                         │      ║ custom user patterns (each via    ║──┐  │
                         │      ║   SafeRegex 50ms timeout)         ║  │  │
                         │      ╚════════════════════════════════════╝  │  │
                         │    if anonymizeHosts ─▶ hostHeaderRegex ──┐   │  │
                         └───────────────────────────────────────────┼───┼──┘
                                                                      │   │
                  ╔═══════════ NEW (PRIV-01) ═══════════╗             │   │
                  ║ anonymizeHost(host, salt):          ║◀────────────┘   │
                  ║   PRK = HMAC(salt_bytes, host_bytes)║  (extract)       │
                  ║   OKM = HMAC(PRK, ""|info|0x01)[:6] ║  (expand, L=6)   │
                  ║   "host-" + 12hex + ".local"        ║                  │
                  ║   record fwd/reverse map (in-mem)   ║                  │
                  ╚═════════════════════════════════════╝                  │
                                                                           │
   ┌──────────────────────────────────────────┐    ┌──────────────────────▼─────────┐
   │ PrivacyConfigPanel (Settings)            │    │ object SecretShapes (NEW)      │
   │  custom-pattern JTextArea                │    │  ordered list of (category,    │
   │  on Save: for each line →                │───▶│   high-confidence Regex)       │
   │    compile + SafeRegex(50ms,adversarial) │    │  findSurviving(text): Set<cat> │
   │    reject bad/slow; persist valid via    │    └──────────────▲─────────────────┘
   │    AgentSettings.customRedactionPatterns │                   │
   └──────────────────────────────────────────┘                   │ (post-redaction scan)
                                                                   │
   ┌──────────────────────────────────────────┐                   │
   │ ContextPreviewDialog.confirm (1 caller:   │                   │
   │   ChatPanel:290) — pre-send preview       │───────────────────┘
   │  scan POST-redaction contextJson →        │
   │  if survivors: SubtleNotice WARN banner   │   (Phase 15 tripwire will reuse SecretShapes here)
   │  (non-blocking; Send stays enabled)       │
   └──────────────────────────────────────────┘
```

The reader can trace the primary use case: a full HTTP string enters `Redaction.apply`, flows
through cookie → token → **new body/JSON/custom** → host stages (host stage calls the **new HKDF**
`anonymizeHost`), and the redacted output is later scanned by `SecretShapes` in the preview dialog
to warn about anything that survived.

### Recommended Project Structure
```
src/main/kotlin/com/six2dez/burp/aiagent/redact/
├── Redaction.kt          # MODIFY: HKDF anonymizeHost; add body/JSON/custom redaction to redactTokens branch
├── SafeRegex.kt          # NEW: interruptible-matcher 50ms timeout primitive (reused by Redaction + PrivacyConfigPanel)
└── SecretShapes.kt       # NEW: object — curated high-confidence shapes + findSurviving(text)

src/main/kotlin/com/six2dez/burp/aiagent/config/
└── AgentSettings.kt      # MODIFY: add customRedactionPatterns: List<String>; KEY + load/save/serialize (plaintext, NOT SecretCipher)

src/main/kotlin/com/six2dez/burp/aiagent/ui/panels/
└── PrivacyConfigPanel.kt # MODIFY: inject patternsArea + validationFeedback; add full-width row + Save validation

src/main/kotlin/com/six2dez/burp/aiagent/ui/components/
└── ContextPreviewDialog.kt # MODIFY: scan contextJson via SecretShapes; show SubtleNotice WARN banner

src/main/kotlin/com/six2dez/burp/aiagent/ui/
├── SettingsPanel.kt      # MODIFY: construct patternsArea/feedback fields; wire into privacySection(); persist on save
└── ChatPanel.kt          # (no change needed — banner is internal to ContextPreviewDialog)

src/test/kotlin/com/six2dez/burp/aiagent/redact/
├── RedactionTest.kt      # MODIFY: add body/form/JSON STRICT-BALANCED-OFF cases + custom-pattern cases
├── SafeRegexTest.kt      # NEW: timeout fires on catastrophic backtracking; fast pattern returns
└── SecretShapesTest.kt   # NEW: each shape matches a positive sample, rejects a negative
```

### Pattern 1: HKDF (RFC 5869) in pure JDK — PRIV-01
**What:** Replace SHA-256 digest with HMAC-SHA256 extract-then-expand, format-preserving.
**When to use:** The new body of `Redaction.anonymizeHost`.
**Verified reference** (this exact extract+expand reproduced RFC 5869 Test Case 1 PRK/OKM on local JDK 21):
```kotlin
// Source: RFC 5869 (https://www.rfc-editor.org/rfc/rfc5869) — VERIFIED against Test Case 1 locally.
// All javax.crypto — no new dependency. Lives in redact/Redaction.kt.
private const val HKDF_INFO = "burp-ai-agent:host"   // app-specific context label
private const val HKDF_OKM_LEN = 6                   // 6 bytes → 12 hex → preserves host-<12hex>.local

private fun hmacSha256(key: ByteArray, data: ByteArray): ByteArray {
    val mac = Mac.getInstance("HmacSHA256")
    // RFC 5869 allows an all-zero / empty salt; SecretKeySpec rejects a 0-length key,
    // so when salt bytes are empty fall back to a single zero byte (extract step only).
    val keySpec = SecretKeySpec(if (key.isEmpty()) ByteArray(1) else key, "HmacSHA256")
    mac.init(keySpec)
    return mac.doFinal(data)
}

/** RFC 5869 HKDF-Extract: PRK = HMAC-Hash(salt, IKM). */
private fun hkdfExtract(salt: ByteArray, ikm: ByteArray): ByteArray = hmacSha256(salt, ikm)

/** RFC 5869 HKDF-Expand: OKM = first L octets of T(1)|T(2)|… ; T(i)=HMAC(PRK, T(i-1)|info|i). */
private fun hkdfExpand(prk: ByteArray, info: ByteArray, length: Int): ByteArray {
    val out = ByteArrayOutputStream()
    var t = ByteArray(0)
    var counter = 1
    while (out.size() < length) {
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(prk, "HmacSHA256"))
        mac.update(t); mac.update(info); mac.update(counter.toByte())
        t = mac.doFinal()
        out.write(t)
        counter++
    }
    return out.toByteArray().copyOf(length)
}

fun anonymizeHost(host: String, salt: String, recordMapping: Boolean = true): String {
    // salt → HKDF salt bytes; host → IKM. (Equivalent strength to the old salt+":"+host hash,
    // now via a real KDF that matches the SPEC's "HKDF host anonymization" claim.)
    val prk = hkdfExtract(salt.toByteArray(StandardCharsets.UTF_8), host.toByteArray(StandardCharsets.UTF_8))
    val okm = hkdfExpand(prk, HKDF_INFO.toByteArray(StandardCharsets.UTF_8), HKDF_OKM_LEN)
    val short = okm.joinToString("") { "%02x".format(it) }   // 6 bytes → 12 hex chars
    val anon = "host-$short.local"
    if (recordMapping) {
        hostForwardMap.computeIfAbsent(salt) { ConcurrentHashMap() }[host] = anon
        hostReverseMap.computeIfAbsent(salt) { ConcurrentHashMap() }[anon] = host
    }
    return anon
}
```
- **Determinism:** HMAC is deterministic, so `(salt, host)` → same OKM → same anon. Satisfies the
  `hostAnonymizationIsStablePerSalt` test (`a == b`, `a != c`) with no change.
- **`info` label:** `"burp-ai-agent:host"` binds the derivation to this app + this use (host
  anonymization), per RFC 5869's `info` purpose. Any stable non-empty string works; document it.
- **`L = 6`:** keeps `host-<12hex>.local` exactly. CONTEXT permits ≥ 6; 6 is the format-preserving
  minimum. (Collision space 2^48 is unchanged from the old `digest.take(6)`.)
- **Salt/IKM mapping:** salt → extract salt, host → IKM is the textbook arrangement (salt is the
  non-secret per-install value; host is the input keying material).

### Pattern 2: ReDoS-safe regex timeout (interruptible CharSequence) — PRIV-02 / SC3
**What:** Run a `Matcher` against an input wrapped so `charAt` throws once a deadline passes,
bounding any single pattern to ~50 ms even under catastrophic backtracking.
**When to use:** Every custom user pattern (during both apply() and save-validation); optionally
wrap built-in body patterns too for defense-in-depth.
**Example:**
```kotlin
// Source: well-documented JDK idiom (ocpsoft.org, exratione.com) — the JDK has NO built-in
// interruptible Matcher (JDK-8234713 "Won't fix"). Lives in redact/SafeRegex.kt.
// [CITED: https://www.ocpsoft.org/regex/how-to-interrupt-a-long-running-infinite-java-regular-expression/]
private class DeadlineCharSequence(
    private val inner: CharSequence,
    private val deadlineNanos: Long,
) : CharSequence {
    override val length get() = inner.length
    override fun get(index: Int): Char {
        // The matcher calls charAt() in its inner backtracking loop, so the deadline is
        // observed promptly even on a pathological pattern.
        if (System.nanoTime() > deadlineNanos) throw RegexTimeoutException()
        return inner[index]
    }
    override fun subSequence(startIndex: Int, endIndex: Int) =
        DeadlineCharSequence(inner.subSequence(startIndex, endIndex), deadlineNanos)
    override fun toString() = inner.toString()
}

class RegexTimeoutException : RuntimeException()

object SafeRegex {
    const val DEFAULT_TIMEOUT_MS = 50L

    /** Returns the replaced string, or the ORIGINAL input unchanged if the pattern times out
     *  (fail-open on redaction cost — never throw into the redaction pipeline; never hang). */
    fun replaceAllSafe(input: String, pattern: Pattern, replacement: String,
                       timeoutMs: Long = DEFAULT_TIMEOUT_MS): String = try {
        val deadline = System.nanoTime() + timeoutMs * 1_000_000
        val m = pattern.matcher(DeadlineCharSequence(input, deadline))
        m.replaceAll(replacement)
    } catch (_: RegexTimeoutException) {
        input  // give up on this pattern; do not corrupt or hang
    }

    /** Used by PrivacyConfigPanel save-validation: true = compiles AND finishes within budget
     *  on the adversarial probe. */
    fun isPatternSafe(regex: String, timeoutMs: Long = DEFAULT_TIMEOUT_MS): Boolean = try {
        val p = Pattern.compile(regex)                 // syntax check
        val deadline = System.nanoTime() + timeoutMs * 1_000_000
        p.matcher(DeadlineCharSequence(ADVERSARIAL_PROBE, deadline)).find()
        true
    } catch (_: PatternSyntaxException) { false }
      catch (_: RegexTimeoutException) { false }

    // Classic catastrophic-backtracking trigger; a non-anchored-end pattern over a long run of
    // 'a' with a trailing non-match maximizes backtracking. Tune length so a safe pattern is
    // comfortably under 50ms while a pathological one blows past it.
    private const val ADVERSARIAL_PROBE =
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa!"
}
```
- **Adversarial test string** (for SafeRegexTest and the save-probe): a pattern like `(a+)+$`
  (or `(a|a)+$`, `(a*)*$`) against `"aaaa…a!"` exhibits exponential backtracking — the canonical
  ReDoS demonstrator. The test asserts `isPatternSafe("(a+)+\$")` returns `false` within ~50 ms
  and a benign pattern like `"\\d+"` returns `true`.
- **Why interruptible-CharSequence over executor:** no thread pool in Burp's long-lived JVM, no
  risk of orphaned threads (an `ExecutorService.submit` that you abandon on timeout keeps running
  the runaway regex on a pool thread). The deadline check is on the calling thread. CONTEXT leaves
  the mechanism to discretion; this is the lower-risk choice.

### Pattern 3: Body-anchored form-field + JSON-key redaction — PRIV-02
**What:** Two new curated regexes, added to the `redactTokens` branch, that reach into bodies.
**When to use:** Inside `Redaction.apply`, gated on `policy.redactTokens`, after the existing
`urlTokenParamRegex` line.
**Example:**
```kotlin
// Source: derived from the existing urlTokenParamRegex vocabulary (Redaction.kt:74-77). [ASSUMED vocabulary]
// Reuse the SAME sensitive-key alternation so query-string and body coverage stay consistent.
private const val SENSITIVE_KEYS =
    "access_token|api_key|apikey|auth|token|key|secret|password|pwd|session|sid|code"

// (1) x-www-form-urlencoded field ANYWHERE in a body, INCLUDING the leading field with no [?&].
//     Anchor on a delimiter that is start-of-line/string OR & — closing the documented gap.
//     (?im): multiline + case-insensitive; \r?\n and ^ cover the body-start case.
private val formBodyParamRegex = Regex(
    "(?im)(^|[?&])(" + SENSITIVE_KEYS + ")=[^&\\s\"'<>]+",
)
// Replace keeping the key + delimiter: "$1$2=[REDACTED]"

// (2) JSON string values for sensitive keys: "api_key":"...."  /  "token" : "...."
private val jsonSecretKeyRegex = Regex(
    "(?i)(\"(?:" + SENSITIVE_KEYS + ")\"\\s*:\\s*)\"[^\"]*\"",
)
// Replace: "$1\"[REDACTED]\""
```
Applied as:
```kotlin
if (policy.redactTokens) {
    // ...existing header/bearer/jwt/urlToken replacements...
    if (raw.length <= MAX_REDACTION_BODY_CHARS) {           // size cap (~1 MB) — skip giant bodies
        out = out.replace(formBodyParamRegex) { m -> "${m.groupValues[1]}${m.groupValues[2]}=[REDACTED]" }
        out = out.replace(jsonSecretKeyRegex) { m -> "${m.groupValues[1]}\"[REDACTED]\"" }
        for (p in compiledCustomPatterns) {                  // user patterns, each timeout-bounded
            out = SafeRegex.replaceAllSafe(out, p, "[REDACTED]")
        }
    }
}
```
- **Don't corrupt non-secret content:** both regexes are key-scoped — they only touch a value that
  follows a sensitive *key name*. `name=alice` / `"name":"alice"` are untouched (existing test
  `balancedModeRedactsUrlTokensInQueryStrings` already guards the query-string equivalent; add the
  body equivalent).
- **Leading-field gap, concretely (SC2):** body `apikey=sk-abc123&user=bob` (no leading `?`/`&`):
  `(^|[?&])` matches at start → `apikey=[REDACTED]&user=bob`. This is the exact documented gap the
  old `[?&]`-only `urlTokenParamRegex` missed.
- **Size cap:** `MAX_REDACTION_BODY_CHARS ≈ 1_000_000`. Note `ContextCollector` already truncates
  bodies (4k req / 8k resp default), so in the main path bodies are already small; the cap is a
  belt-and-suspenders bound for the other callers (MCP tools, bounty resolver) that may pass larger
  strings. When skipped, leave the body unredacted but DO NOT hang — pair with the per-pattern
  timeout so even an under-cap body cannot stall.

### Pattern 4: Shared `SecretShapes` curated set — PRIV-04 (+ Phase 15 reuse)
**What:** An `object` holding ordered (human-category, high-confidence-Regex) pairs and a
`findSurviving(text)` that returns the set of categories present.
**When to use:** PRIV-04 banner now; Phase 15 tripwire later — single source of truth.
**Example:**
```kotlin
// Source: prefixes VERIFIED against multiple secret-scanning tools (gitleaks/trufflehog-class
// patterns) + AWS/GitHub/Google formats. [VERIFIED: secret-scanning pattern corpora]
// Lives in redact/SecretShapes.kt. Phase 15 (PRIV-03) consumes the SAME object.
object SecretShapes {
    data class Shape(val category: String, val regex: Regex)

    val shapes: List<Shape> = listOf(
        // OpenAI: legacy sk-<48> AND modern sk-proj-/svcacct-/admin- forms embedding base64 'T3BlbkFJ'
        Shape("OpenAI key", Regex("\\bsk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_-]{20,}\\b")),
        Shape("AWS access key", Regex("\\bAKIA[0-9A-Z]{16}\\b")),
        Shape("GitHub token", Regex("\\bgh[pousr]_[A-Za-z0-9]{36,}\\b")),       // ghp_/gho_/ghu_/ghs_/ghr_
        Shape("GitHub fine-grained PAT", Regex("\\bgithub_pat_[A-Za-z0-9_]{22,}\\b")),
        Shape("Google API key", Regex("\\bAIza[0-9A-Za-z_-]{35}\\b")),
        Shape("Slack token", Regex("\\bxox[baprs]-[0-9A-Za-z-]{10,}\\b")),
        Shape("JWT", Regex("\\beyJ[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+\\b")),
        Shape("high-entropy hex key", Regex("\\b[0-9a-fA-F]{32,}\\b")),         // 32+ hex chars
    )

    /** Returns the set of category names whose shape appears in [text] (post-redaction context). */
    fun findSurviving(text: String): Set<String> =
        shapes.filter { it.regex.containsMatchIn(text) }.map { it.category }.toSet()
}
```
- **VERIFIED prefixes:** `AKIA[0-9A-Z]{16}`, `AIza[0-9A-Za-z_-]{35}`, `gh[pousr]_…{36,}`,
  `xox[baprs]-…`, JWT `eyJ….….…` — all confirmed against current secret-scanning pattern corpora.
- **`[VERIFIED]` caveat on OpenAI:** modern keys are `sk-proj-…` / embed base64 `T3BlbkFJ`; the
  regex above covers both legacy and modern. The exact suffix length floor (`{20,}`) is `[ASSUMED]`
  and tunable — keep it generous to catch survivors without over-matching.
- **`high-entropy hex key` risk:** `[0-9a-fA-F]{32,}` will match MD5/SHA hashes and other benign
  hex. Because the banner is *informational and non-blocking*, a false positive only adds a warning —
  acceptable per the "reveal what survived" purpose. The plan may make this shape opt-in or move it
  last; flag for the planner.
- **Reuse contract for Phase 15:** keep `SecretShapes` free of UI/Swing imports so the
  Phase 15 tripwire (a scanner-side, non-UI consumer) can depend on it without dragging in AWT.
- **Relationship to the existing `jwtRegex` in `Redaction.kt`:** that one *redacts* JWTs during
  `apply`; `SecretShapes.JWT` *detects* a JWT that survived. Different purpose, similar pattern —
  fine to duplicate the literal, or have `Redaction` reference `SecretShapes` for the JWT shape
  (planner's call; not required).

### Pattern 5: Custom-pattern persistence — PRIV-02
**What:** Add `customRedactionPatterns: List<String>` to `AgentSettings`, persisted as a delimited
string via `Preferences` — **plaintext, NOT `SecretCipher`** (patterns are config, not secrets).
**When to use:** `config/AgentSettings.kt` load/save + a new `KEY_*` constant.
**Example:**
```kotlin
// Source: mirrors the existing customPromptLibrary serialization (AgentSettings.kt:1128-1149)
// and the simpler serializeIdSet/parseIdSet pattern (AgentSettings.kt:1082-1122).
// data class field:
val customRedactionPatterns: List<String> = emptyList(),

// companion key:
private const val KEY_CUSTOM_REDACTION_PATTERNS = "privacy.custom.redaction.patterns.v1"

// load(): newline is a poor delimiter for a single pref string; use the JSON-list approach
// (customPromptMapper) OR a newline-joined string since regexes may contain commas but rarely
// newlines. Newline-join is simplest and matches the one-regex-per-line UX:
customRedactionPatterns =
    prefs.getString(KEY_CUSTOM_REDACTION_PATTERNS).orEmpty()
        .split('\n').map { it.trim() }.filter { it.isNotBlank() },

// save():
prefs.setString(KEY_CUSTOM_REDACTION_PATTERNS, settings.customRedactionPatterns.joinToString("\n"))
```
- **Schema migration:** absent key → `emptyList()`, exactly like the v3 `customPromptLibrary`
  precedent (AgentSettings.kt:660-665) — a *bump-the-version-stamp-only* migration, no data move.
  Current `CURRENT_SETTINGS_SCHEMA_VERSION = 4`; this could be v5 or just rely on the absent-key
  default (the v3 comment shows the project is comfortable with absent-key defaults and no explicit
  migration step). **Recommendation:** rely on the absent-key default; no new migration function
  needed — only a `data class` field + key + load/save lines.
- **NOT a secret:** do not route through `cipher.encrypt`/`decrypt`. Custom redaction patterns are
  user configuration, not credentials. (The additional_context note "study the persistence path"
  refers to understanding `SecretCipher`, not using it here.)

### Pattern 6: UI wiring (both touch points) — PRIV-02 / PRIV-04
The UI-SPEC (`13-UI-SPEC.md`, status: approved) is the authoritative contract. Key mechanics
confirmed against the code:
- **PrivacyConfigPanel** takes injected `JComponent`s in its constructor and `SettingsPanel`
  builds them (see `SettingsPanel.privacySection()` at line 1443). Add two new injected params
  (`customPatternsArea: JComponent`, `patternsFeedback: JComponent`) and a new full-width row
  via `addRowFull(grid, "Custom redaction patterns", area, helpText = "…")` inserted **after** the
  `rotateSaltBtn` row + its `addSpacerRow(grid, 4)`, **before** the Save feedback row.
- `applyAreaStyle(area)` (Components.kt:467) sets mono font + input bg/fg + 1px border + lineWrap.
  Set `area.rows = 4` (matches `promptArea`). A `JTextArea` is NOT a "small component", so
  `addRowFull` gives it `HORIZONTAL` fill (Components.kt:140-145) — fills the field column, no fixed width.
- Validation-feedback label: reuse the `saveFeedback`-style `JLabel` (re-assign foreground from
  `DesignTokens.Colors.statusError` / `statusSuccess` each time text is set, per UI-SPEC §Light/dark).
- **ContextPreviewDialog** has exactly ONE caller (`ChatPanel.kt:290`). Add a `SubtleNotice` to the
  `header` `BoxLayout(Y_AXIS)` stack between the "Context (…after redaction):" label and `bodyScroll`.
  Compute `SecretShapes.findSurviving(contextJson)`; if non-empty call
  `setMessage(SubtleNotice.Level.WARN, html)`, else `hideNotice()`. `SubtleNotice` starts hidden,
  manages its own theme via `updateUI()`, and is already token-compliant — so it satisfies the
  "don't migrate the surrounding un-migrated dialog" constraint (FLAG-13-02).
- **WARN, not RISK:** UI-SPEC §Color mandates WARN (amber) — the banner is advisory; RISK (red) is
  reserved for the privacy-OFF advisory and the Phase 15 warn-with-confirmation.

### Anti-Patterns to Avoid
- **Parsing JSON bodies with Jackson to redact keys.** Bodies are frequently truncated/invalid
  (see `ContextCollector.truncateHttpMessageBody`); re-serializing reorders and reformats the
  user's content. Use key-scoped regex over the raw string — the established pattern.
- **Using an `ExecutorService` you abandon on timeout.** The runaway regex keeps burning a pool
  thread. Use the interruptible `CharSequence` (deadline on the calling thread) instead.
- **Encrypting custom patterns via `SecretCipher`.** They are config, not secrets — plaintext pref,
  same as `bountyPromptEnabledPromptIds` / `customPromptLibrary`.
- **Hardcoding expected HKDF hashes in tests.** Existing tests deliberately assert the `host-`
  prefix + determinism only; keep that style so the crypto can evolve without brittle test churn.
- **Adding new `Color()` / `Font()` / spacing-int literals in panel/dialog code.** Violates the
  Phase 9 locked rule (UI-SPEC §Light/Dark Compliance). Use `DesignTokens` builders / `SubtleNotice`.
- **Migrating `ContextPreviewDialog` to the design system.** Out of scope (FLAG-13-02) — add only
  the token-compliant `SubtleNotice` banner.
- **Anchoring the form-body regex on `$` end** (e.g. `(a+)+$`-style) for value capture — the value
  charclass `[^&\\s\"'<>]+` is already bounded; avoid trailing-anchor patterns that backtrack.

## Don't Hand-Roll

| Problem | Don't Build | Use Instead | Why |
|---------|-------------|-------------|-----|
| HKDF | A custom KDF or a naive `SHA256(salt+host)` loop | `javax.crypto.Mac` HmacSHA256 extract+expand (Pattern 1) | RFC 5869 is a precise spec; the verified ~30-line JDK impl matches the published test vectors. A homegrown KDF would not match the SPEC's "HKDF" claim. |
| HMAC | Manual ipad/opad XOR | `Mac.getInstance("HmacSHA256")` | JCA gives constant-time, correct HMAC for free; already used in `SecretCipher`. |
| Regex timeout | Watchdog thread that calls `Thread.stop()` | Interruptible `CharSequence` deadline (Pattern 2) | `Thread.stop` is deprecated/unsafe; the JDK has no interruptible Matcher (JDK-8234713 Won't-Fix); the `charAt` deadline is the documented, safe idiom. |
| Secret-shape regexes | Inventing prefixes from memory | Curated set verified against secret-scanning corpora (Pattern 4) | Real-world key formats drift (e.g. OpenAI `sk-proj-`/`T3BlbkFJ`); use confirmed patterns. |
| List-of-strings persistence | A bespoke pref encoding | Existing `split/joinToString` or `customPromptMapper` JSON pattern (Pattern 5) | `AgentSettings` already has two precedents (`serializeIdSet`, `serializeCustomPromptLibrary`). |
| Advisory banner | A new Swing panel with hand-set colors | Existing `SubtleNotice` + `Level.WARN` | Already theme-aware (`updateUI`), token-compliant, and used by PrivacyConfigPanel/MCP advisories. |

**Key insight:** Phase 13 is a "match the implementation to the documented design" phase. Every
primitive it needs already exists in the JDK or the codebase — the work is *assembling verified
parts* (HKDF, interruptible matcher, curated shapes, existing UI builders), not inventing crypto,
concurrency, or UI machinery.

## Runtime State Inventory

> Phase 13 is **not** a rename/refactor/migration phase — it changes an algorithm and adds patterns,
> but the host-anonymization output FORMAT and all preference KEYS are preserved. This section is
> included because PRIV-01 alters how an existing stored/derived value is computed.

| Category | Items Found | Action Required |
|----------|-------------|------------------|
| Stored data | **In-memory only.** `hostForwardMap` / `hostReverseMap` are `ConcurrentHashMap`s (Redaction.kt:81-82), rebuilt per JVM session. No persisted anon-host mappings exist. | None — maps repopulate on next `apply`; HKDF produces new values for the same (salt, host) but that is invisible (format unchanged) and self-consistent within a session. |
| Live service config | None — redaction runs entirely in-process; no external service stores anon hosts. | None. |
| OS-registered state | None. | None. |
| Secrets / env vars | `privacy.host_salt` pref (`KEY_HOST_SALT`) is the salt input. **Unchanged** — HKDF reuses the same salt value; no key rename. Custom patterns add `privacy.custom.redaction.patterns.v1` (new, plaintext, not a secret). | None for the salt. New key relies on absent-key default. |
| Build artifacts / installed packages | None — no `pyproject`/`egg-info`/binary; this is a Gradle/Kotlin JAR rebuilt by `./gradlew shadowJar`. | None beyond a normal rebuild. |

**Canonical question — "after the change, what still has the OLD value cached?"**: Only the
in-memory host maps, and only for the lifetime of a running Burp session that *predates* the upgrade
(impossible in practice — the new JAR starts a fresh JVM with empty maps). The existing
`rotateSaltBtn → clearMappings` flow (SettingsPanel.kt:756) and `App.kt:214` shutdown clear already
cover invalidation. **No migration task required for PRIV-01.**

## Common Pitfalls

### Pitfall 1: `SecretKeySpec` rejects an empty/zero-length key
**What goes wrong:** RFC 5869 permits an all-zero or absent salt, but `new SecretKeySpec(new byte[0], "HmacSHA256")` throws `IllegalArgumentException: Empty key`.
**Why it happens:** JCA requires ≥ 1 key byte.
**How to avoid:** In `hmacSha256`, substitute a single zero byte when the salt is empty (shown in Pattern 1). In practice `stableHostSalt` is always a generated non-empty token, so this only guards a degenerate input — but the test `anonymizeHost("example.com", "salt-a")` passes a non-empty salt, so the happy path is unaffected.
**Warning signs:** Test throws `IllegalArgumentException` instead of returning a `host-…` string.

### Pitfall 2: Catastrophic backtracking still hangs because the deadline is only checked in `charAt`
**What goes wrong:** Some matcher operations advance without re-reading characters, so a deadline checked only in `charAt` can be observed late.
**Why it happens:** `Matcher` reads input via `charAt` during backtracking, but a fully anchored mismatch may loop in bounded ways.
**How to avoid:** Keep the timeout small (50 ms) and ALSO cap input length (the ~1 MB body cap). For the save-probe use a *short* adversarial string (≤ 64 chars) so even exponential blowup is detected in well under 50 ms. The combination (small input + deadline charAt + try/catch fail-open) is robust in practice.
**Warning signs:** `SafeRegexTest` for `(a+)+$` exceeds the timeout budget — lengthen the probe slightly or confirm the deadline units (nanos vs millis).

### Pitfall 3: Body regex corrupts a value that merely *contains* a sensitive substring
**What goes wrong:** A loose pattern like `token=[^&]+` could match inside `csrf_token_label=ok`.
**Why it happens:** Partial-word key matching.
**How to avoid:** Anchor the key on `(^|[?&])` for form bodies and on `"` quotes for JSON keys (Pattern 3), so the key must be a *whole* parameter/JSON key, not a substring. Add a negative test (`name=alice` / `username=bob` untouched).
**Warning signs:** A test like `non-sensitive params must not be touched` (already present for query strings) fails on the body variant.

### Pitfall 4: JSON-key regex breaks on escaped quotes inside values
**What goes wrong:** `"token":"ab\"cd"` — the value charclass `[^"]*` stops at the escaped quote.
**Why it happens:** Regex can't track JSON escaping.
**How to avoid:** Accept the limitation — the goal is "catch known-sensitive JSON keys", not a JSON parser. A value with an embedded escaped quote is rare for an API token (tokens are `[A-Za-z0-9._-]`). Over-redacting (stopping early and replacing) still removes the secret head; under-redacting a weird value is an acceptable miss for a hardening pass. Document it as a known limitation; do not escalate to a Jackson tree-walk (anti-pattern above).
**Warning signs:** None functional — just don't claim "all JSON secrets". Note in code comment.

### Pitfall 5: Persisting patterns through `SecretCipher` by mistake
**What goes wrong:** Routing `customRedactionPatterns` through `cipher.encrypt` would store regexes as `ENC1:` blobs and add them to the SEC-01 migration list — needless coupling.
**Why it happens:** The additional_context says "study `SecretCipher`", which can be misread as "use it".
**How to avoid:** Patterns are config, not secrets. Persist plaintext via `prefs.setString` like `bountyPromptEnabledPromptIds`. (Recorded in Pattern 5.)
**Warning signs:** Patterns appear `ENC1:`-prefixed in prefs; a round-trip test reads back garbled regexes.

### Pitfall 6: Changing `anonymizeHost` arity/signature breaks ~10 callers
**What goes wrong:** Adding a parameter to `anonymizeHost` would touch McpTools, BountyPromptTagResolver, PassiveAiScanner, ContextCollector.
**Why it happens:** Over-engineering the HKDF entry point (e.g. passing `info` as a param).
**How to avoid:** Keep the exact existing signature `anonymizeHost(host, salt, recordMapping = true)`; make `info`/`L` private constants inside `Redaction`. Internal-only change → zero caller edits. (Verified call sites: ContextCollector ×1, McpToolContext indirectly, McpTools ×3, BountyPromptTagResolver ×1, PassiveAiScanner ×1.)
**Warning signs:** Compile errors in files outside `redact/`.

## Code Examples

All load-bearing examples are inline in Patterns 1–6 above (HKDF, SafeRegex, body/JSON regex,
SecretShapes, persistence, UI wiring), each tagged with its source and provenance. The HKDF example
is `[VERIFIED]` against RFC 5869 Test Case 1 by local execution.

## State of the Art

| Old Approach | Current Approach | When Changed | Impact |
|--------------|------------------|--------------|--------|
| `MessageDigest SHA-256(salt + ":" + host)` truncated to 6 bytes | RFC 5869 HKDF (HMAC-SHA256 extract+expand), same 6-byte/12-hex output | This phase | SPEC's documented "HKDF host anonymization" now matches code; format & determinism preserved |
| `urlTokenParamRegex` keyed on `[?&]param=` (query strings only) | `(^|[?&])param=` (reaches the leading form-body field) + JSON-key regex | This phase | Closes the documented body-redaction gap (SC2) |
| OpenAI keys as `sk-[A-Za-z0-9]{20,}` | Modern keys are `sk-proj-`/`sk-svcacct-`/`sk-admin-` embedding base64 `T3BlbkFJ` | OpenAI key-format change (2023+) | `SecretShapes` regex must cover both legacy and modern forms |
| Two stacked red labels for advisories | `SubtleNotice` (INFO/WARN/RISK), theme-aware | Phase 9 (shipped) | PRIV-04 banner reuses `SubtleNotice.Level.WARN` — no new component |

**Deprecated/outdated:**
- `Thread.stop()` watchdog for regex timeouts — unsafe, deprecated. Use interruptible `CharSequence`.
- Relying on `MessageDigest` to back a claim of "HKDF" — the mismatch this phase fixes.
- `java.util.regex.InterruptibleMatcher` — proposed (JDK-8234713) but **not** shipped; do not assume it exists in JDK 21.

## Assumptions Log

| # | Claim | Section | Risk if Wrong |
|---|-------|---------|---------------|
| A1 | `info = "burp-ai-agent:host"` is an acceptable HKDF context label | Pattern 1 | None functional — any stable non-empty label works; only affects output values (which aren't asserted). Pick and document. |
| A2 | Sensitive-key vocabulary = the existing `urlTokenParamRegex` set is sufficient for bodies | Pattern 3 | Misses an unusual key name → a body secret survives (banner would flag it). Tunable; extendable by the user's custom patterns. |
| A3 | OpenAI suffix floor `{20,}` and the `high-entropy hex {32,}` shape are well-calibrated | Pattern 4 | Too loose → benign false-positive warnings (non-blocking, acceptable); too tight → a survivor unflagged. Tune during impl. |
| A4 | Newline-joined string is an adequate persistence encoding for one-regex-per-line patterns | Pattern 5 | A regex containing a literal newline would split wrong — extremely rare; JSON-list (customPromptMapper) is the fallback if needed. |
| A5 | ~1 MB (`MAX_REDACTION_BODY_CHARS`) is a sensible body size cap | Pattern 3 | Too low → large legit bodies skip redaction (mitigated: main-path bodies already truncated to 4k/8k by ContextCollector); too high → cost. Adjustable constant. |
| A6 | The interruptible-`CharSequence` mechanism (not bounded executor) is the right discretion call | Pattern 2 | If a reviewer prefers the executor, both satisfy SC3; low risk. CONTEXT explicitly leaves this to discretion. |
| A7 | Custom patterns are active in STRICT+BALANCED via `policy.redactTokens` and the compiled list lives on `Redaction` (set from settings) | Pattern 3 / 5 | If the compiled list isn't refreshed on settings save, edits won't take effect until restart. Plan must wire a `Redaction.setCustomPatterns(...)` (or pass via `apply`) on settings change. **Flag for planner.** |

## Open Questions

1. **How do compiled custom patterns reach `Redaction.apply`?**
   - What we know: `apply(raw, policy, stableHostSalt, recordMapping)` has a fixed signature; `AgentSettings` holds the raw pattern strings; settings changes flow through `SettingsPanel.onSettingsChanged`.
   - What's unclear: whether to (a) add a `Redaction.setCustomPatterns(List<Pattern>)` mutator invoked on settings save (mirrors how scanners get `applyOptimizationSettings`), or (b) add an optional `customPatterns` parameter to `apply` threaded from each caller (touches all 6 call sites).
   - Recommendation: **(a)** — a `Redaction.setCustomPatterns` updated from `SettingsPanel.applyAndSave` (alongside the existing scanner-settings application near line 1402). Keeps `apply`'s signature stable (Pitfall 6) and centralizes compilation (compile once on save, not per-message). The planner should make this an explicit task.

2. **Should the built-in body/form/JSON patterns also run under the `SafeRegex` timeout, or only user patterns?**
   - What we know: built-in patterns are curated and bounded (low ReDoS risk); user patterns are arbitrary (high risk, SC3 mandates the guard for them).
   - What's unclear: defense-in-depth vs simplicity.
   - Recommendation: wrap **user** patterns mandatorily (SC3); wrapping built-ins is optional and cheap given the input is already size-capped. Either is acceptable.

3. **Does `high-entropy hex key` belong in the default `SecretShapes`?**
   - What we know: it will match MD5/SHA hashes (benign) → false-positive WARN banners.
   - Recommendation: include it but order it LAST, or gate it behind a flag. Because the banner is non-blocking, a false positive is low-harm — but it could desensitize users. Planner's call; note it in the plan.

## Environment Availability

> Skipped — Phase 13 has no external runtime/tool/service dependencies. All work uses JDK 21
> built-ins (`javax.crypto`, `java.util.regex`, `java.util.concurrent`) already on the build
> classpath, the existing Gradle/Kotlin toolchain (`./gradlew test`, `shadowJar`), and the existing
> JUnit Jupiter 6.0.3 / mockito-kotlin 5.4.0 test stack. Nothing to probe or install.

## Validation Architecture

> nyquist_validation is enabled (`.planning/config.json` workflow.nyquist_validation = true).

### Test Framework
| Property | Value |
|----------|-------|
| Framework | JUnit Jupiter 6.0.3 (`org.junit.jupiter:junit-jupiter:6.0.3`) |
| Config file | `build.gradle.kts` (no separate junit config); tests in `src/test/kotlin` |
| Quick run command | `./gradlew test --tests "com.six2dez.burp.aiagent.redact.*"` |
| Full suite command | `./gradlew test` |

> **Build note (from MEMORY):** `./gradlew ktlintCheck` fails standalone due to a pre-existing
> `generateBuildFlags` wiring defect (unrelated to this phase). Use `./gradlew test` for validation;
> do not gate Phase 13 on `ktlintCheck`.

### Phase Requirements → Test Map
| Req ID | Behavior | Test Type | Automated Command | File Exists? |
|--------|----------|-----------|-------------------|-------------|
| PRIV-01 | HKDF determinism: same (salt,host) → same anon; different salt → different anon | unit | `./gradlew test --tests "*RedactionTest.hostAnonymizationIsStablePerSalt"` | ✅ (existing — stays green) |
| PRIV-01 | Output format remains `host-<12hex>.local` (regex `host-[0-9a-f]{12}\.local`) | unit | `./gradlew test --tests "*RedactionTest"` | ❌ Wave 0 (add format assertion) |
| PRIV-01 | HKDF matches RFC 5869 Test Case 1 (PRK/OKM) — proves correct construction | unit | `./gradlew test --tests "*RedactionTest.hkdfMatchesRfc5869Vector"` | ❌ Wave 0 |
| PRIV-01 | forward/reverse map still resolves (`deAnonymizeHost`) after HKDF swap | unit | `./gradlew test --tests "*RedactionTest.clearMappings_removesOnlyRequestedSaltOrAll"` | ✅ (existing — stays green) |
| PRIV-01 | STRICT still strips cookies/tokens/hosts | unit | `./gradlew test --tests "*RedactionTest.strictModeStripsCookiesTokensAndHosts"` | ✅ (existing — stays green) |
| PRIV-02 | Leading form-body field `apikey=sk-abc123&…` redacted (STRICT + BALANCED) | unit | `./gradlew test --tests "*RedactionTest.bodyFormLeadingFieldRedacted"` | ❌ Wave 0 |
| PRIV-02 | JSON `"api_key":"…"` / `"token":"…"` redacted; `"name":"alice"` untouched | unit | `./gradlew test --tests "*RedactionTest.bodyJsonSecretKeysRedacted"` | ❌ Wave 0 |
| PRIV-02 | OFF mode leaves bodies untouched | unit | `./gradlew test --tests "*RedactionTest.offModePreservesBodies"` | ❌ Wave 0 |
| PRIV-02 | Custom pattern applied in STRICT+BALANCED, inactive OFF | unit | `./gradlew test --tests "*RedactionTest.customPatternRedactsInStrictAndBalanced"` | ❌ Wave 0 |
| PRIV-02 | Body over size cap is short-circuited (not hung, not redacted) | unit | `./gradlew test --tests "*RedactionTest.oversizeBodySkippedSafely"` | ❌ Wave 0 |
| PRIV-02 / SC3 | `SafeRegex.isPatternSafe("(a+)+$")` == false within budget; `"\\d+"` == true | unit | `./gradlew test --tests "*SafeRegexTest"` | ❌ Wave 0 (new file) |
| PRIV-02 / SC3 | `replaceAllSafe` returns input unchanged (no hang) on catastrophic pattern | unit | `./gradlew test --tests "*SafeRegexTest.catastrophicPatternTimesOutAndReturnsInput"` | ❌ Wave 0 |
| PRIV-02 | Custom-pattern persistence round-trips through `AgentSettings` (mock Preferences) | unit | `./gradlew test --tests "*AgentSettings*"` | ❌ Wave 0 (extend existing settings test) |
| PRIV-04 | `SecretShapes.findSurviving` detects each shape (positive) and rejects a benign string (negative) | unit | `./gradlew test --tests "*SecretShapesTest"` | ❌ Wave 0 (new file) |
| PRIV-04 | Banner logic: survivors → WARN message; clean → hidden (pure-logic helper, no Swing) | unit | `./gradlew test --tests "*SecretShapesTest.findSurvivingReturnsCategories"` | ❌ Wave 0 |

> **UI note:** The two Swing touch points (text area row, `SubtleNotice` banner) are
> manual-verify (Burp smoke test) per project convention — Swing rendering isn't unit-tested here.
> The *logic* behind them (`SafeRegex.isPatternSafe` for save-validation, `SecretShapes.findSurviving`
> for the banner) IS unit-tested above, which is the Nyquist-meaningful coverage. Keep `SecretShapes`
> and `SafeRegex` free of AWT imports so they're testable headless and reusable by Phase 15.

### Sampling Rate
- **Per task commit:** `./gradlew test --tests "com.six2dez.burp.aiagent.redact.*"`
- **Per wave merge:** `./gradlew test`
- **Phase gate:** Full `./gradlew test` green (baseline ~71 test files / 308 tests reported green at v0.8.0) before `/gsd-verify-work`.

### Wave 0 Gaps
- [ ] `src/test/kotlin/com/six2dez/burp/aiagent/redact/SafeRegexTest.kt` — covers PRIV-02 SC3 (ReDoS guard)
- [ ] `src/test/kotlin/com/six2dez/burp/aiagent/redact/SecretShapesTest.kt` — covers PRIV-04 detection
- [ ] Extend `src/test/kotlin/com/six2dez/burp/aiagent/redact/RedactionTest.kt` — body/form/JSON STRICT/BALANCED/OFF + HKDF format + RFC vector + custom-pattern cases
- [ ] Extend existing `AgentSettings` test — custom-pattern persistence round-trip (mock `Preferences` via mockito-kotlin)
- [ ] Framework install: none — JUnit Jupiter 6.0.3 already configured

## Security Domain

> security_enforcement not explicitly false in config → treated as enabled. This phase IS a
> security feature (privacy redaction), so the security lens is central, not incidental.

### Applicable ASVS Categories

| ASVS Category | Applies | Standard Control |
|---------------|---------|-----------------|
| V2 Authentication | no | No auth surface touched (custom patterns are not credentials) |
| V3 Session Management | no | — |
| V4 Access Control | no | — |
| V5 Input Validation | **yes** | Custom-regex input validated on Save (syntax compile + ReDoS timeout) before persist — `SafeRegex.isPatternSafe`. Reject-and-feedback, never persist an uncompilable/slow pattern. |
| V6 Cryptography | **yes** | HKDF via `javax.crypto.Mac` HmacSHA256 (RFC 5869) — JCA, never hand-rolled. No new key material; reuses existing `privacy.host_salt`. |
| V7 Error Handling & Logging | **yes** | `SafeRegex` fails open (returns input) on timeout — never throws into the redaction pipeline, never logs the matched/secret content. Mirrors `SecretCipher`'s "log key name, never value" discipline. |
| V14 Configuration | **yes** | New pref `privacy.custom.redaction.patterns.v1` stored plaintext (config, not secret); absent-key default = empty list; no plaintext secret introduced. |

### Known Threat Patterns for Kotlin/JDK redaction pipeline

| Pattern | STRIDE | Standard Mitigation |
|---------|--------|---------------------|
| ReDoS via malicious/accidental custom regex (catastrophic backtracking) | Denial of Service | Interruptible-`CharSequence` 50 ms deadline (`SafeRegex`) + body size cap + reject-on-save validation (Pattern 2) |
| Secret leakage through an unredacted body field (the documented gap) | Information Disclosure | Body-start-anchored form regex + JSON-key regex + curated `SecretShapes` survivor warning (Patterns 3–4) |
| Weak/misrepresented anonymization (SHA-256 labeled "HKDF") | Information Disclosure / Repudiation | Real RFC 5869 HKDF so the privacy claim matches the code (Pattern 1) |
| Re-exposing a suspected secret in the UI banner | Information Disclosure | Banner names the shape *category* only (e.g. "OpenAI key"), never echoes the matched value (UI-SPEC §Message content) |
| Logging matched secret content during redaction | Information Disclosure | `SafeRegex` and redaction never log the input/matched text; follow `SecretCipher` logging contract |

## Sources

### Primary (HIGH confidence)
- RFC 5869 (HKDF) — https://www.rfc-editor.org/rfc/rfc5869 — extract/expand definition, salt/IKM/info/L roles, max L = 255·HashLen, salt default = HashLen zeros. **Plus local execution: pure-`javax.crypto` HKDF reproduced Test Case 1 PRK `07770936…c2b3e5` and OKM `3cb25f25…185865` byte-for-byte.**
- Codebase (read directly): `redact/Redaction.kt`, `redact/RedactionTest.kt` (+ `ContextPreviewConsistencyTest.kt`, `BountyPromptTagResolverTest.kt` — confirmed no hardcoded host hashes), `context/ContextCollector.kt`, `ui/panels/PrivacyConfigPanel.kt`, `ui/components/ContextPreviewDialog.kt`, `ui/components/SubtleNotice.kt`, `ui/design/Components.kt`, `config/AgentSettings.kt`, `config/SecretCipher.kt`, `config/Defaults.kt`, `ui/SettingsPanel.kt`, `build.gradle.kts`.
- JDK 21 JCA standard algorithms — `Mac` HmacSHA256, `SecretKeySpec` (same family already used by `SecretCipher.kt`).

### Secondary (MEDIUM confidence)
- OCPsoft — https://www.ocpsoft.org/regex/how-to-interrupt-a-long-running-infinite-java-regular-expression/ — interruptible `CharSequence` (`charAt` checks `Thread.interrupted()`/deadline) idiom.
- Ex Ratione — https://www.exratione.com/2017/06/preventing-unbounded-regular-expression-operations-in-java/ — same pattern, FutureTask/timeout variant.
- OpenJDK JDK-8234713 — https://bugs.openjdk.org/browse/JDK-8234713 — proposed `InterruptibleMatcher`, confirmed NOT shipped (so do not assume it exists).
- Secret-scanning pattern corpora (gitleaks/trufflehog-class): https://github.com/h33tlit/secret-regex-list , https://github.com/odomojuli/regextokens — AWS `AKIA[0-9A-Z]{16}`, Google `AIza[0-9A-Za-z_-]{35}`, GitHub `gh[pousr]_…{36,}`, Slack `xox[baprs]-…`, JWT `eyJ….….…`, OpenAI modern `sk-proj-…`/`T3BlbkFJ`.

### Tertiary (LOW confidence)
- GitHub secret-scanning patterns doc (https://docs.github.com/.../supported-secret-scanning-patterns) — confirms *which* secret types exist but withholds exact prefixes; prefixes corroborated via the secondary corpora above (cross-verified, hence patterns rated VERIFIED in Pattern 4).

## Metadata

**Confidence breakdown:**
- HKDF (PRIV-01): **HIGH** — RFC + local test-vector execution + verified test-safety (no hardcoded hashes).
- Body/JSON redaction (PRIV-02): **HIGH** — extends an existing, tested regex pattern; call-site reach verified by grep; concrete SC2 example traced.
- ReDoS guard (PRIV-02/SC3): **HIGH** — documented JDK idiom; JDK has no built-in (verified via JDK-8234713); fail-open design.
- SecretShapes (PRIV-04): **MEDIUM-HIGH** — prefixes cross-verified across multiple corpora; exact length floors and the hex-entropy shape are tunable `[ASSUMED]`.
- UI wiring: **HIGH** — UI-SPEC approved; builder signatures and the single `ContextPreviewDialog` caller verified in code.
- Persistence: **HIGH** — two existing precedents in `AgentSettings`.

**Research date:** 2026-06-10
**Valid until:** 2026-07-10 (stable — JDK crypto/regex APIs and the codebase structure are slow-moving; only the OpenAI/secret-prefix shapes drift, and those are non-blocking detection heuristics).
