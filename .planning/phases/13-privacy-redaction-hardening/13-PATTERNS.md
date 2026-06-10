# Phase 13: Privacy & Redaction Hardening - Pattern Map

**Mapped:** 2026-06-10
**Files analyzed:** 9 (3 created, 6 modified — 2 of which are test files)
**Analogs found:** 9 / 9 (every new/modified file has a strong in-repo analog)

> All paths absolute under `/Users/six2dez/Tools/burp-ai-agent/`. Line numbers reference the files
> as read on 2026-06-10. RESEARCH.md Patterns 1–6 carry the verified reference implementations; this
> map ties each one to the closest existing code to **copy structure/conventions from**, with exact
> excerpts. Where RESEARCH already verified an algorithm (HKDF vs RFC 5869, interruptible matcher),
> the analog supplies the project's *style* (crypto idioms, object layout, test shape), not the algorithm.

---

## File Classification

| New/Modified File | Role | Data Flow | Closest Analog | Match Quality |
|-------------------|------|-----------|----------------|---------------|
| `src/main/kotlin/com/six2dez/burp/aiagent/redact/Redaction.kt` (MODIFY) | service / transform | transform (string→string) | itself (existing `apply`/`anonymizeHost`) + `config/SecretCipher.kt` (javax.crypto idiom) | exact (self) + role-match (crypto) |
| `src/main/kotlin/com/six2dez/burp/aiagent/redact/SafeRegex.kt` (CREATE) | utility | transform (guarded match) | `redact/Redaction.kt` `object` style + `config/SecretCipher.kt` companion-const + fail-soft style | role-match |
| `src/main/kotlin/com/six2dez/burp/aiagent/redact/SecretShapes.kt` (CREATE) | utility / data | transform (text→Set) | `redact/Redaction.kt` (`object` + curated `Regex` vals) | exact (same package, same idiom) |
| `src/main/kotlin/com/six2dez/burp/aiagent/config/AgentSettings.kt` (MODIFY) | config / store | CRUD (load/save prefs) | `customPromptLibrary` + `bountyPromptEnabledPromptIds` serialization (same file) | exact (self-precedent) |
| `src/main/kotlin/com/six2dez/burp/aiagent/config/Defaults.kt` (MODIFY, optional) | config | n/a (constants) | existing tuning-const `object` (same file) | exact (self-precedent) |
| `src/main/kotlin/com/six2dez/burp/aiagent/ui/panels/PrivacyConfigPanel.kt` (MODIFY) | component (panel) | request-response (form input) | itself (existing injected-component form) + `Components.kt` builders | exact (self) |
| `src/main/kotlin/com/six2dez/burp/aiagent/ui/components/ContextPreviewDialog.kt` (MODIFY) | component (dialog) | request-response (preview gate) | itself (existing `confirm`) + `ui/components/SubtleNotice.kt` | exact (self) + role-match (banner) |
| `src/test/kotlin/com/six2dez/burp/aiagent/redact/RedactionTest.kt` (MODIFY) | test | request-response (assert) | itself (existing STRICT/BALANCED/OFF cases) | exact (self) |
| `src/test/kotlin/com/six2dez/burp/aiagent/redact/{SafeRegexTest,SecretShapesTest}.kt` (CREATE) | test | request-response (assert) | `redact/RedactionTest.kt` (JUnit Jupiter shape) | exact (same framework + style) |

**Wiring note (no new file, but a required edit):** `src/main/kotlin/com/six2dez/burp/aiagent/ui/SettingsPanel.kt`
must construct the new `patternsArea` + `patternsFeedback` fields, pass them into `PrivacyConfigPanel(...)`
(line 1442–1453), gather them in the snapshot block (line ~1182, next to `customPromptLibrary`), and
re-load them in the apply block (line ~1249). Analog: the `customPromptLibraryEditor` round-trip in the
same file. Covered under "Shared Patterns → SettingsPanel field round-trip".

---

## Pattern Assignments

### `redact/Redaction.kt` (service, transform) — MODIFY

**Analog:** itself (existing structure is the contract to preserve) + `config/SecretCipher.kt` for the
`javax.crypto.Mac` / `SecretKeySpec` idiom (HKDF reuses the same JCA family already in the repo).

> Three edits land here, all behind the existing signatures: (1) swap `anonymizeHost` body
> `MessageDigest` → HKDF; (2) add body/form/JSON regexes + custom-pattern loop inside the existing
> `if (policy.redactTokens)` branch; (3) add the size-cap constant. **Do NOT change `apply` or
> `anonymizeHost` signatures** — RESEARCH Pitfall 6: ~5 callers depend on them (`ContextCollector`,
> `McpToolContext`, `McpTools`, `BountyPromptTagResolver`, `PassiveAiScanner` — verified via grep).

**Existing import block to extend** (lines 1–5) — add `javax.crypto.Mac`, `javax.crypto.spec.SecretKeySpec`,
`java.io.ByteArrayOutputStream`; `MessageDigest` becomes removable once HKDF replaces it:
```kotlin
package com.six2dez.burp.aiagent.redact

import java.nio.charset.StandardCharsets
import java.security.MessageDigest          // ← remove after HKDF swap
import java.util.concurrent.ConcurrentHashMap
```

**The exact method being replaced — `anonymizeHost`** (lines 121–137). Preserve the signature, the
`host-<short>.local` format, and the in-memory map recording; swap only lines 126–130:
```kotlin
fun anonymizeHost(
    host: String,
    salt: String,
    recordMapping: Boolean = true,
): String {
    val digest =
        MessageDigest
            .getInstance("SHA-256")                                    // ← REPLACE with HKDF extract+expand
            .digest((salt + ":" + host).toByteArray(StandardCharsets.UTF_8))
    val short = digest.take(6).joinToString("") { "%02x".format(it) }  // ← keep "6 bytes → 12 hex"
    val anon = "host-$short.local"
    if (recordMapping) {                                               // ← keep verbatim
        hostForwardMap.computeIfAbsent(salt) { ConcurrentHashMap() }[host] = anon
        hostReverseMap.computeIfAbsent(salt) { ConcurrentHashMap() }[anon] = host
    }
    return anon
}
```
Replacement body + private HKDF helpers: **RESEARCH Pattern 1** (`13-RESEARCH.md` lines 242–289,
`[VERIFIED]` against RFC 5869 Test Case 1). Use `L = 6` to keep the format; `info = "burp-ai-agent:host"`.

**JCA idiom to mirror — `SecretCipher.kt`** (the only other crypto file; same `Mac`/`SecretKeySpec`
family). Note `getInstance` + `init(SecretKeySpec(...))` + `doFinal`, and the `PBKDF2WithHmacSHA256`
precedent showing the repo already uses HMAC-SHA256 (`SecretCipher.kt` lines 142–145):
```kotlin
val factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
val spec = PBEKeySpec(passphrase, salt, PBKDF2_ITERATIONS, KEY_LENGTH_BYTES * 8)
val derived = factory.generateSecret(spec).encoded
return SecretKeySpec(derived, "AES")
```
> Empty-salt guard (RESEARCH Pitfall 1): `SecretKeySpec(ByteArray(0), ...)` throws `IllegalArgumentException`.
> `stableHostSalt` is always non-empty in practice, but `hmacSha256` should substitute a single zero
> byte for an empty key (shown in RESEARCH Pattern 1, line 252).

**Body-redaction insertion point — the `redactTokens` branch** (lines 97–107). New regexes + the
custom-pattern loop go *after* the existing `urlTokenParamRegex` line (106), inside this block:
```kotlin
if (policy.redactTokens) {
    out =
        out.replace(authHeaderRegex) { m ->
            val header = m.value.substringBefore(":")
            "$header: [REDACTED]"
        }
    out = out.replace(bearerRegex, "Bearer [REDACTED]")
    out = out.replace(basicAuthRegex, "Basic [REDACTED]")
    out = out.replace(jwtRegex, "[JWT_REDACTED]")
    out = out.replace(urlTokenParamRegex, "$1[REDACTED]")
    // ── NEW (PRIV-02): if (out.length <= MAX_REDACTION_BODY_CHARS) { formBody, json, custom } ──
}
```

**Vocabulary to reuse — `urlTokenParamRegex`** (lines 74–77). The new form/JSON regexes reuse this
exact sensitive-key alternation so query-string and body coverage stay consistent:
```kotlin
private val urlTokenParamRegex =
    Regex(
        "(?i)([?&](access_token|api_key|apikey|auth|token|key|secret|password|pwd|session|sid|code)=)[^&\\s\"'<>]+",
    )
```
> New `formBodyParamRegex` / `jsonSecretKeyRegex` literals: **RESEARCH Pattern 3** (`13-RESEARCH.md`
> lines 372–404). Apply via `out = SafeRegex.replaceAllSafe(out, p, "[REDACTED]")` for each custom pattern.

**Existing curated-`Regex`-val style to match** for the new private regex vals (lines 56–79): line-anchored
`(?im)^...$`, `private val ...Regex = Regex("...")`, defined as object-level vals. Keep that style.

---

### `redact/SafeRegex.kt` (utility, guarded transform) — CREATE

**Analog:** `redact/Redaction.kt` for the top-level `object` + object-level `Regex`/const layout, and
`config/SecretCipher.kt` for the **fail-soft `try/catch` discipline** and `companion object` constant style.

**Object + const layout to mirror** — `Redaction` is an `object` with constants/regex as members; `SafeRegex`
follows the same shape (it lives in the same `redact` package). Full reference implementation
(`DeadlineCharSequence`, `RegexTimeoutException`, `replaceAllSafe`, `isPatternSafe`, `ADVERSARIAL_PROBE`)
is **RESEARCH Pattern 2** (`13-RESEARCH.md` lines 305–357) — `[CITED]` ocpsoft idiom, copy verbatim.

**Fail-soft idiom to mirror — `SecretCipher.decrypt`** (lines 105–109). The "never throw into the
pipeline, return a safe fallback" discipline is exactly what `replaceAllSafe` does (returns the
*original* input on timeout):
```kotlin
} catch (e: Exception) {
    // Fail-soft per D-01: undecryptable ciphertext is treated as empty. Never log the value.
    LOGGER.warning("SecretCipher.decrypt failed for key: $prefKeyName — treating as empty")
    ""
}
```
→ In `SafeRegex.replaceAllSafe`, the analogous fail-soft is `catch (_: RegexTimeoutException) { input }`
(RESEARCH Pattern 2 line 337–339): give up on the pattern, never corrupt or hang.

**Companion-const style to mirror — `SecretCipher`** (lines 148–169): named constants grouped at the
bottom. `SafeRegex` exposes `const val DEFAULT_TIMEOUT_MS = 50L` and `private const val ADVERSARIAL_PROBE`
in the same spirit:
```kotlin
companion object {
    const val MASTER_KEY_PREF_KEY = "secret.master.key.v1"
    private const val TRANSFORMATION = "AES/GCM/NoPadding"
    private const val GCM_TAG_BITS = 128
    // ...
}
```

> **Anti-pattern reminder (RESEARCH lines 522–524, 542):** do NOT use an `ExecutorService` you abandon
> on timeout (orphan thread burns the runaway regex). Interruptible `CharSequence` on the calling
> thread only.

---

### `redact/SecretShapes.kt` (utility/data, text→Set) — CREATE

**Analog:** `redact/Redaction.kt` — same package, same `object` + curated-`Regex`-val idiom. This is the
*closest possible* analog (the existing `jwtRegex` at `Redaction.kt:71` is literally one of the shapes).

**Idiom to mirror — `Redaction`'s curated regex vals** (lines 71–77):
```kotlin
// very generic JWT-like pattern (not perfect by design)
private val jwtRegex = Regex("\\beyJ[A-Za-z0-9_\\-]+\\.[A-Za-z0-9_\\-]+\\.[A-Za-z0-9_\\-]+\\b")
```
`SecretShapes` holds an ordered `List<Shape(category, Regex)>` + `findSurviving(text): Set<String>`.
Full reference set (OpenAI/AWS/GitHub/Google/Slack/JWT/high-entropy-hex) is **RESEARCH Pattern 4**
(`13-RESEARCH.md` lines 427–445), `[VERIFIED]` against secret-scanning corpora.

> **Reuse contract (RESEARCH line 456):** keep `SecretShapes` free of any Swing/AWT import so the
> Phase 15 tripwire (non-UI consumer) can depend on it. It is pure data + `containsMatchIn` matching —
> exactly like `Redaction`'s regex section. The `JWT` shape may reference or duplicate `Redaction.jwtRegex`
> (planner's call; duplication is acceptable per RESEARCH line 458–461).
>
> **`high-entropy hex key` caveat (RESEARCH lines 453–455):** `[0-9a-fA-F]{32,}` matches MD5/SHA hashes;
> because the banner is non-blocking, a false positive only adds a warning. Planner may move it last or
> make it opt-in.

---

### `config/AgentSettings.kt` (config/store, CRUD) — MODIFY

**Analog:** itself — `customPromptLibrary` (a `List<…>` pref) and `bountyPromptEnabledPromptIds` (a
split/join string pref) are exact self-precedents. Custom patterns are **config, not secrets** → plaintext
pref, **NOT** `SecretCipher` (RESEARCH Pattern 5 + Pitfall 5).

**(1) Data-class field** — mirror the `customPromptLibrary` field with its comment style (line 129–130):
```kotlin
// Custom prompt library (saved user prompts exposed in right-click menus)
val customPromptLibrary: List<CustomPromptDefinition> = emptyList(),
```
→ Add `val customRedactionPatterns: List<String> = emptyList(),` (RESEARCH Pattern 5 line 472).

**(2) KEY constant** — mirror the versioned-key convention (line 863):
```kotlin
private const val KEY_CUSTOM_PROMPT_LIBRARY = "custom.prompt.library.v1"
private const val CURRENT_SETTINGS_SCHEMA_VERSION = 4
```
→ Add `private const val KEY_CUSTOM_REDACTION_PATTERNS = "privacy.custom.redaction.patterns.v1"`
(RESEARCH Pattern 5 line 475).

**(3) load()** — mirror the `parseIdSet` split-pattern (lines 1082–1094) and the call site (lines 375–379):
```kotlin
private fun parseIdSet(raw: String?, fallback: Set<String>): Set<String> {
    val parsed =
        raw.orEmpty().split(',').map { it.trim() }.filter { it.isNotBlank() }.toSet()
    return if (parsed.isEmpty()) fallback else parsed
}
// call site:
bountyPromptEnabledPromptIds =
    parseIdSet(prefs.getString(KEY_BOUNTY_PROMPT_ENABLED_IDS), BountyPromptCatalog.defaultEnabledPromptIds()),
```
→ Use `split('\n')` (one-regex-per-line, RESEARCH Pattern 5 lines 480–483) rather than `,` because
regexes commonly contain commas:
```kotlin
customRedactionPatterns =
    prefs.getString(KEY_CUSTOM_REDACTION_PATTERNS).orEmpty()
        .split('\n').map { it.trim() }.filter { it.isNotBlank() },
```

**(4) save()** — mirror the `serializeIdSet` join (lines 1110–1115) and the write site (lines 631–637):
```kotlin
private fun serializeIdSet(ids: Set<String>): String =
    ids.map { it.trim() }.filter { it.isNotBlank() }.toSortedSet().joinToString(",")
// write site:
prefs.setString(KEY_BOUNTY_PROMPT_ENABLED_IDS, serializeIdSet(settings.bountyPromptEnabledPromptIds))
prefs.setString(KEY_CUSTOM_PROMPT_LIBRARY, serializeCustomPromptLibrary(settings.customPromptLibrary))
```
→ `prefs.setString(KEY_CUSTOM_REDACTION_PATTERNS, settings.customRedactionPatterns.joinToString("\n"))`
(RESEARCH Pattern 5 line 485). Place next to line 637, before the schema-version write (line 640).

**(5) Migration — NONE NEEDED.** Mirror the v3 absent-key-default precedent (lines 660–665):
```kotlin
if (effectiveVersion < 3) {
    // v3: introduces KEY_CUSTOM_PROMPT_LIBRARY. Absent key loads as empty list —
    // no data migration needed, just a version stamp so future migrations see a clean baseline.
    effectiveVersion = 3
}
```
→ RESEARCH Pattern 5 (lines 487–492) recommends relying on the absent-key default (`emptyList()`); no new
migration function or schema bump required.

**(6) defaults()** — mirror the explicit-empty default (line 485): `customPromptLibrary = emptyList(),`
→ `customRedactionPatterns = emptyList(),`.

> **Test analog for round-trip:** `config/AgentSettingsMigrationTest.kt` (mocks `Preferences` via
> mockito-kotlin per RESEARCH line 125) covers the load/save persistence shape if a round-trip test is wanted.

---

### `config/Defaults.kt` (config, constants) — MODIFY (optional)

**Analog:** itself — a flat `object` of named tuning constants (lines 37–59). If the planner centralizes
`MAX_REDACTION_BODY_CHARS` (~1 MB) and/or the 50 ms timeout default here instead of inside `Redaction`/`SafeRegex`:
```kotlin
const val MAX_HISTORY_TOTAL_CHARS = 40_000
const val LARGE_PROMPT_THRESHOLD = 32_000
const val PASSIVE_SCAN_TIMEOUT_MS = 90_000L
```
→ Same `const val NAME = <int/long>` style; `…_CHARS` for char caps, `…_MS` for millis.
RESEARCH (Pattern 3 line 414) names it `MAX_REDACTION_BODY_CHARS ≈ 1_000_000`. Either location is fine;
`Defaults.kt` matches the repo's "tuning constants live here" convention.

---

### `ui/panels/PrivacyConfigPanel.kt` (component/panel, request-response) — MODIFY

**Analog:** itself — every control is an injected `JComponent` built by `SettingsPanel` and laid out with
`Components.kt` builders. The new custom-pattern row follows the identical pattern.

**Constructor injection style to extend** (lines 14–26) — add `customPatternsArea: JComponent` and
`patternsFeedback: JComponent` params, matching `rotateSaltBtn` / `saveFeedback`:
```kotlin
class PrivacyConfigPanel(
    private val privacyMode: JComponent,
    private val auditEnabled: JComponent,
    private val autoRestart: JComponent,
    private val determinism: JComponent,
    private val rotateSaltBtn: JComponent,
    private val privacyNotice: JComponent,
    private val saveFeedback: JComponent,
    private val aiLoggerEnabled: JComponent? = null,
    private val aiLoggerMaxEntries: JComponent? = null,
) : ConfigPanel {
```

**Row-insertion point in `build()`** (lines 27–48) — insert the new full-width row + spacer **after**
the `rotateSaltBtn` ("Anonymization") row+spacer (lines 45–46), **before** the "Save feedback" row (line 47):
```kotlin
addRowFull(grid, "Anonymization", rotateSaltBtn)
addSpacerRow(grid, 4)
// ── NEW: addRowFull(grid, "Custom redaction patterns", customPatternsArea, helpText = "…")
//        + feedback row + addSpacerRow(grid, DesignTokens.Spacing.xs) ──
addRowFull(grid, "Save feedback", saveFeedback)
```

**Builder semantics (from `Components.kt`, already imported by this panel):**
- `addRowFull(grid, label, field, helpText)` — lines 112–161: a non-small field gets `fill = HORIZONTAL`
  (lines 140–145), and a non-null `helpText` auto-adds a `helpLabel` row (lines 150–160). A `JTextArea`
  is NOT small → fills the column. **Do not also add a separate `helpLabel`** (UI-SPEC §Anatomy).
- `applyAreaStyle(area)` — lines 467–474: sets `mono` font, `inputBackground`/`inputForeground`, 1px
  `border`, `lineWrap`/`wrapStyleWord`. Apply to the `JTextArea`; set `area.rows = 4` (UI-SPEC convention).
- `helpLabel(text)` — lines 312–315: `caption` font, `onSurfaceVariant` fg (auto-applied via `helpText`).

**Validation-feedback label analog — `SettingsPanel.saveFeedbackLabel`** (the UI-SPEC mandates reusing
this exact pattern: one `JLabel` whose text + foreground swap per outcome). Styling at `SettingsPanel.kt`
lines 609–613; the set-with-color helper `updateSaveFeedback` at lines 2438–2448:
```kotlin
saveFeedbackLabel.font = DesignTokens.Typography.body
saveFeedbackLabel.foreground = DesignTokens.Colors.onPrimary
// ...
saveFeedbackLabel.text = message
saveFeedbackLabel.background = backgroundColor          // statusSuccess / statusError passed in
```
→ Validation feedback re-reads `DesignTokens.Colors.statusError` / `.statusSuccess` (tokens at
`DesignTokens.kt:179,183`) each time text is set (UI-SPEC Light/dark rule 4). Copy strings: UI-SPEC §Copywriting.

> The actual ReDoS validation on Save delegates to `SafeRegex.isPatternSafe(line)` (RESEARCH Pattern 2
> line 343). The panel only displays the result. SC3: reject patterns that fail to compile OR time out.

---

### `ui/components/ContextPreviewDialog.kt` (component/dialog, request-response) — MODIFY

**Analog:** itself (existing `confirm` builds the pre-send preview) + `ui/components/SubtleNotice.kt`
(the banner to reuse, do NOT build a new one). Single caller: `ChatPanel.kt:290` (RESEARCH line 84).

**Insertion point — the `header` BoxLayout(Y_AXIS) stack** (lines 26–51). Add the banner *after* the
"Context (as will be sent, after redaction):" label (line 50), *before* `bodyScroll` is added to CENTER:
```kotlin
val header = JPanel()
header.layout = BoxLayout(header, BoxLayout.Y_AXIS)
// ...
header.add(Box.createVerticalStrut(6))
header.add(JLabel("Context (as will be sent, after redaction):"))
// ── NEW: val survivedNotice = SubtleNotice(); compute SecretShapes.findSurviving(contextJson);
//         if non-empty → survivedNotice.setMessage(SubtleNotice.Level.WARN, html) else hideNotice();
//         header.add(survivedNotice) ──
```

**Banner component — `SubtleNotice`** (`SubtleNotice.kt`). Starts hidden, manages its own theme via
`updateUI()`, token-compliant → satisfies the "don't migrate the un-migrated dialog" constraint
(FLAG-13-02). API to call (lines 69–89):
```kotlin
fun setMessage(level: Level, html: String) { /* wraps in <html>, picks accent, isVisible=true */ }
fun hideNotice() { isVisible = false }
enum class Level { INFO, WARN, RISK }   // ← use WARN (amber) per UI-SPEC §Color
```
WARN palette (`SubtleNotice.applyStyle`, lines 100–112): `Level.WARN -> UiTheme.Colors.subtleWarning`
bg + `accentWarn` strip. **Use WARN, not RISK** (UI-SPEC §Color rationale: advisory, non-blocking).

> Scan target = **post-redaction `contextJson`** only (UI-SPEC §Touch Point 2). Message names the shape
> *category* only, never the raw value (UI-SPEC §Message content). Copy: UI-SPEC §Copywriting.
> **FLAG-13-02:** add ONLY the `SubtleNotice` banner; do NOT migrate the dialog's existing raw
> `JLabel`/`JTextArea`/`BorderLayout(8,8)`/`Dimension(780,560)` literals to the design system.

---

### `test/.../redact/RedactionTest.kt` (test) — MODIFY  +  `SafeRegexTest.kt`, `SecretShapesTest.kt` (CREATE)

**Analog:** `RedactionTest.kt` — the established JUnit Jupiter shape (`@Test`, `assertTrue`/`assertEquals`,
trimIndent HTTP fixtures, `RedactionPolicy.fromMode(...)` then `Redaction.apply(...)`).

**Test structure to copy** (`RedactionTest.kt` lines 1–35):
```kotlin
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class RedactionTest {
    @Test
    fun strictModeStripsCookiesTokensAndHosts() {
        val input = """
            GET / HTTP/1.1
            Host: example.com
            Cookie: a=b
            Authorization: Bearer abc.def.ghi
            """.trimIndent()
        val policy = RedactionPolicy.fromMode(PrivacyMode.STRICT)
        val output = Redaction.apply(input, policy, stableHostSalt = "salt")
        assertTrue(output.contains("Host: host-"))    // ← asserts PREFIX only, not a literal hash
    }
```

**HKDF tests stay green as-is** — the existing assertions check the `host-` *prefix substring* and
per-salt determinism, never a literal hex value (RESEARCH lines 17–26 verified this across all test
files). Keep these two unchanged; they continue to pass after the HKDF swap:
```kotlin
@Test fun hostAnonymizationIsStablePerSalt() {
    val a = Redaction.anonymizeHost("example.com", "salt-a")
    val b = Redaction.anonymizeHost("example.com", "salt-a")
    val c = Redaction.anonymizeHost("example.com", "salt-b")
    assertEquals(a, b)        // determinism — HMAC is deterministic, still holds
    assertTrue(a != c)        // per-salt difference — still holds
}
```
> **Anti-pattern (RESEARCH line 527):** do NOT hardcode expected HKDF hashes — keep the prefix+determinism
> assertion style so the crypto can evolve without brittle churn.

**Negative-test precedent to copy for body redaction** (`RedactionTest.kt` lines 75–79) — the query-string
test already guards "don't touch non-sensitive params"; the body variant mirrors it (RESEARCH Pitfall 3):
```kotlin
assertTrue(output.contains("api_key=[REDACTED]"), "api_key query param must be redacted")
assertTrue(output.contains("name=alice"), "non-sensitive params must not be touched")
assertTrue(!output.contains("secret123") && !output.contains("xyz987"))
```
→ New cases (RESEARCH Pattern 3 line 409 SC2): body `apikey=sk-abc123&user=bob` (no leading `?`/`&`)
→ `apikey=[REDACTED]&user=bob` in STRICT+BALANCED; JSON `"token":"abc"` → `"token":"[REDACTED]"`;
`name=alice` / `"name":"alice"` untouched; OFF mode preserves all (mirror `offModePreservesAllTokens`,
lines 82–97).

**`SafeRegexTest.kt` (CREATE)** — same JUnit Jupiter shape. Assert `isPatternSafe("(a+)+\$")` returns
`false` within ~50 ms (catastrophic backtracking) and `isPatternSafe("\\d+")` returns `true`
(RESEARCH Pattern 2 lines 358–361, Pitfall 2).

**`SecretShapesTest.kt` (CREATE)** — same shape. Each shape matches a positive sample and rejects a
negative (RESEARCH structure line 235): e.g. `findSurviving("sk-...")` contains "OpenAI key";
`findSurviving("hello world")` is empty.

---

## Shared Patterns

### Cross-cutting: javax.crypto JCA idiom
**Source:** `config/SecretCipher.kt` (lines 59–61, 102–103, 142–145)
**Apply to:** `redact/Redaction.kt` HKDF helpers
The repo's one crypto file establishes `getInstance(ALGO)` → `init(SecretKeySpec(bytes, ALGO))` →
`doFinal(data)` and already uses HMAC-SHA256 (PBKDF2WithHmacSHA256). HKDF's `hmacSha256` helper mirrors
it with `Mac.getInstance("HmacSHA256")`. Verified algorithm: RESEARCH Pattern 1.

### Cross-cutting: fail-soft, never-throw-into-the-pipeline
**Source:** `config/SecretCipher.kt` decrypt (lines 105–109)
**Apply to:** `redact/SafeRegex.replaceAllSafe` (return original input on timeout) and the body-redaction
size-cap (skip giant bodies, never hang)
The established discipline is: catch, log safely (never the sensitive value), return a safe fallback.
`SafeRegex` returns the *unmodified* input on `RegexTimeoutException`; the redaction pipeline never throws.

### Cross-cutting: list-of-strings pref persistence (plaintext, not encrypted)
**Source:** `config/AgentSettings.kt` — `bountyPromptEnabledPromptIds` (`parseIdSet`/`serializeIdSet`,
lines 1082–1115) and `customPromptLibrary` (lines 130, 382–385, 637)
**Apply to:** `AgentSettings.customRedactionPatterns`
Field default `emptyList()` + versioned `KEY_*` + parse-on-load/serialize-on-save + absent-key default
(no migration). **Plaintext — patterns are config, not secrets** (RESEARCH Pitfall 5; do NOT route through
`SecretCipher.encrypt`).

### Cross-cutting: SettingsPanel field round-trip (construct → inject → snapshot → load)
**Source:** `ui/SettingsPanel.kt` — `customPromptLibraryEditor` (construct line 71; snapshot line 1182;
re-load line 1249) and `rotateSaltBtn`/`saveFeedbackLabel` injection into `PrivacyConfigPanel` (lines 1442–1453)
**Apply to:** the new `patternsArea` + `patternsFeedback` fields
Four edits in `SettingsPanel.kt`, each with a same-file precedent:
1. **Construct** the `JTextArea` + feedback `JLabel` as private fields (like `customPromptLibraryEditor` line 71 / `saveFeedbackLabel` line 199).
2. **Inject** into `PrivacyConfigPanel(...)` in `privacySection()` (lines 1442–1453) — add the two new args.
3. **Snapshot** into the settings copy near `customPromptLibrary = customPromptLibraryEditor.snapshot(),` (line 1182) — gather + validate lines here.
4. **Re-load** in the apply block near `customPromptLibraryEditor.load(updated.customPromptLibrary)` (line 1249).
> The `rotateSaltBtn` action listener (lines 756–767) is the model for "control wired to a settings
> mutation" — but no analogous listener is needed for the text area; gathering happens at snapshot time.

### Cross-cutting: theme-aware, no-literals UI (Phase 9 locked rule)
**Source:** `ui/design/Components.kt` builders + `ui/components/SubtleNotice.kt` `updateUI()` (lines 91–98)
**Apply to:** both UI touch points
No `Color(0x…)`/`Font(…)`/spacing-int literals. Colors from `DesignTokens.Colors.*`; spacing from
`DesignTokens.Spacing.*`; the banner from `SubtleNotice` (self-managing theme). The validation label
re-reads `statusError`/`statusSuccess` on each text change so a runtime theme switch is reflected
(UI-SPEC rule 4). FLAG-13-02: do not migrate `ContextPreviewDialog`'s existing literals.

---

## No Analog Found

None. Every new/modified file has a strong in-repo analog. The two genuinely new algorithms (HKDF
extract/expand, interruptible-`CharSequence` matcher) are not invented here — they are `[VERIFIED]`/`[CITED]`
reference implementations in **RESEARCH.md Patterns 1 & 2**, and the *style* (object layout, JCA idiom,
fail-soft, const grouping) is supplied by the `Redaction.kt` / `SecretCipher.kt` analogs above. The planner
should pull algorithm bodies from RESEARCH and conventions from these analogs.

---

## Metadata

**Analog search scope:**
- `src/main/kotlin/com/six2dez/burp/aiagent/redact/` (Redaction.kt)
- `src/main/kotlin/com/six2dez/burp/aiagent/config/` (SecretCipher.kt, AgentSettings.kt, Defaults.kt)
- `src/main/kotlin/com/six2dez/burp/aiagent/ui/` (SettingsPanel.kt)
- `src/main/kotlin/com/six2dez/burp/aiagent/ui/panels/` (PrivacyConfigPanel.kt)
- `src/main/kotlin/com/six2dez/burp/aiagent/ui/components/` (ContextPreviewDialog.kt, SubtleNotice.kt)
- `src/main/kotlin/com/six2dez/burp/aiagent/ui/design/` (Components.kt, DesignTokens.kt)
- `src/main/kotlin/com/six2dez/burp/aiagent/context/` (ContextCollector.kt — call-site verification)
- `src/test/kotlin/com/six2dez/burp/aiagent/redact/` (RedactionTest.kt)

**Files scanned (read or grepped):** 12 source + 1 test + cross-grep of 5 `Redaction.apply` callers
**Call-site verification:** `Redaction.apply` invoked from ContextCollector (lines 35, 52–53), McpToolContext,
McpTools, BountyPromptTagResolver, PassiveAiScanner — body redaction reaches all of them with no new call site.
**Pattern extraction date:** 2026-06-10
