# Phase 15: Pre-Send Secret Tripwire - Pattern Map

**Mapped:** 2026-06-11
**Files analyzed:** 8 (2 CREATE, 4 MODIFY, 2 CREATE-test)
**Analogs found:** 8 / 8 (all in-repo; zero new dependencies)

> This phase is ~90% integration. Every building block already exists. The only genuinely new
> code is the ~30-line `Entropy` helper and the thin `SecretTripwire` orchestrator. All line
> anchors below were re-verified against source this session (post-RESEARCH); RESEARCH's line
> numbers are accurate.

## File Classification

| New/Modified File | Role | Data Flow | Closest Analog | Match Quality |
|-------------------|------|-----------|----------------|---------------|
| `redact/Entropy.kt` | utility (pure) | transform | `redact/SafeRegex.kt` | role-match (AWT-free pure `object`) |
| `redact/SecretTripwire.kt` | service (pure detector) | transform | `redact/SecretShapes.kt` | exact (object + pure `findSurviving`-style fun) |
| `ui/components/ContextPreviewDialog.kt` (MODIFY) | component (Swing dialog) | request-response (gate) | itself — Phase 13 self-scan + SubtleNotice at L59-103 | exact (extend in place) |
| `ui/ChatPanel.kt` (MODIFY) | component (interactive send) | request-response | itself — `startSessionFromContext` L292-332 | exact (existing call site) |
| `scanner/PassiveAiScanner.kt` (MODIFY) | service (batch/single send) | event-driven / batch | itself — three `supervisor.send` sites | exact (in-place hooks) |
| `mcp/McpToolContext.kt` (MODIFY) | service (MCP output) | request-response | itself — `redactIfNeeded` L53-57 | exact (in-place hook) |
| `redact/SecretTripwireTest.kt` (CREATE) | test | — | `redact/SecretShapesTest.kt` | exact (JUnit Jupiter + Assertions) |
| `redact/EntropyTest.kt` (CREATE) | test | — | `redact/SafeRegexTest.kt` | exact (headless, AWT-free) |

---

## Pattern Assignments

### `redact/Entropy.kt` (CREATE — utility, pure transform)

**Analog:** `redact/SafeRegex.kt` (AWT-free pure `object` precedent), `redact/SecretShapes.kt` (package + KDoc style).

**AWT-free contract — copy the SecretShapes header discipline** (`SecretShapes.kt:17-19`):
```kotlin
// ### AWT-free contract
// This file MUST NOT import `java.awt.*` or `javax.swing.*`. The Phase 15 tripwire runs in a
// non-UI context and must be able to depend on [SecretShapes] without dragging in AWT.
```
And `SafeRegex.kt:21-22`:
```kotlin
//   - AWT-free: no java.awt / javax.swing imports so Phase 15's scanner-side tripwire can reuse
//     this file headless.
```
→ `Entropy.kt` imports ONLY `kotlin.math.ln`. No AWT/Swing. This is what lets the scanner + MCP
paths and the headless unit tests reuse it.

**`object` + thresholds-as-`const` style** (mirror `SafeRegex.kt:47-52`):
```kotlin
object SafeRegex {
    const val DEFAULT_TIMEOUT_MS = 50L
```
→ `Entropy` is an `object` with `MIN_TOKEN_LEN = 20`, `BASE64_THRESHOLD = 4.5`,
`HEX_THRESHOLD = 3.0` as private `const`s (tunable in one place; matches the SecretShapes
"no user-facing tuning" precedent — see RESEARCH Open Q2: ship as `const` for v1).

**Implementation (from RESEARCH Pattern 2 — verified `kotlin.math.ln` is stdlib):**
- `shannon(s): Double` — `H = -Σ p(c)·log2(p(c))`, `log2(p) = ln(p)/ln(2.0)`, `0.0` for empty.
- `maxQualifyingTokenEntropy(text): Double` — split on `Regex("[^A-Za-z0-9+/=_-]+")` (linear, ReDoS-safe — no `SafeRegex` wrapper needed; see Gotcha G6), keep tokens `len >= 20`, classify charset via `all { it in HEX_CHARS/BASE64_CHARS }`, return max entropy among tokens clearing their charset threshold, else `0.0`.
- `truncatedScore(bitsPerChar): String = "%.1f".format(bitsPerChar)` — SC3 audit score, never the token.

**Gotcha — entropy floor on the hex path:** `SecretShapes` already has a broad
`high-entropy hex key` shape (`[0-9a-fA-F]{32,}`, `SecretShapes.kt:81`). The hex entropy path
(≥3.0) overlaps it harmlessly (both → `matched`). The entropy path's REAL contribution is
**unprefixed base64** tokens that `SecretShapes` does not cover (RESEARCH Open Q3). Document this
in KDoc.

---

### `redact/SecretTripwire.kt` (CREATE — service, pure detector orchestrator)

**Analog:** `redact/SecretShapes.kt` — `object` + pure function returning category names only.

**`findSurviving` is the function to reuse verbatim** (`SecretShapes.kt:93-94`):
```kotlin
fun findSurviving(text: String): Set<String> =
    shapes.filter { it.regex.containsMatchIn(text) }.map { it.category }.toSet()
```
`SecretTripwire.scan(payload)` calls `SecretShapes.findSurviving(payload)` for the shape half and
`Entropy.maxQualifyingTokenEntropy(payload)` for the entropy half. NEVER re-implement shape
detection — single source of truth keeps interactive/non-interactive parity (SC4).

**KDoc precedent — the SecretShapes doc already pre-commits to this reuse** (`SecretShapes.kt:14-15`):
```kotlin
// * **Phase 15 tripwire (future):** the pre-send scanner reuses this same object as the single
// *   source of truth so the two detection paths stay in sync.
```

**Result type (no-leak discipline — RESEARCH Pattern 1):**
```kotlin
data class ScanResult(
    val matched: Boolean,
    val shapeCategories: Set<String>,   // names only, never raw values (mirrors findSurviving)
    val maxEntropyBitsPerChar: Double,  // 0.0 if no qualifying high-entropy token
)
// matched = categories.isNotEmpty() || maxEntropy > 0.0
```

**AWT-free contract:** same as `Entropy.kt` — MUST NOT import `java.awt.*`/`javax.swing.*`
(consumed by scanner + MCP headless). Depends only on `SecretShapes` + `Entropy` (both pure).

---

### `ui/components/ContextPreviewDialog.kt` (MODIFY — component, request-response gate)

**Analog:** ITSELF — the Phase 13 self-scan + SubtleNotice block already in this file.

**Insertion point 1 — replace the self-scan at L59-72** (current code, `ContextPreviewDialog.kt:59-72`):
```kotlin
val survivedNotice = SubtleNotice()
val survivors = SecretShapes.findSurviving(contextJson)
if (survivors.isNotEmpty()) {
    val shapes = survivors.joinToString(", ")
    val html =
        if (survivors.size == 1) {
            "A value matching a known secret shape ($shapes) survived redaction. Review before sending."
        } else {
            "${survivors.size} values matching known secret shapes ($shapes) survived redaction. Review before sending."
        }
    survivedNotice.setMessage(SubtleNotice.Level.WARN, html)
} else {
    survivedNotice.hideNotice()
}
```
→ Replace `SecretShapes.findSurviving(contextJson)` with `SecretTripwire.scan(contextJson)`
(FLAG-15-03 in-dialog self-scan; preserves the `confirm()` Boolean contract — no signature
change). On `scan.matched`, call `survivedNotice.setMessage(SubtleNotice.Level.RISK, html)`
(WARN → RISK, UI-SPEC Delta 1). Banner copy per UI-SPEC Delta 1 table (high-entropy vs named
shape). Import: add `com.six2dez.burp.aiagent.redact.SecretTripwire` (keep/drop the existing
`import ...SecretShapes` at L4 depending on whether the WARN advisory branch is retained — FLAG-15-01
permits collapsing to clean→RISK).

**SubtleNotice.Level.RISK is already wired** (`SubtleNotice.kt:25,105,111`):
```kotlin
enum class Level { INFO, WARN, RISK }
// applyStyle(): Level.RISK -> UiTheme.Colors.subtleDanger (bg) ... accentDanger (strip)
```
→ No new token/color. `setMessage(Level.RISK, html)` is the only call needed (Don't-Hand-Roll).

**Insertion point 2 — relabel the affirmative at L91-103** (current code, `ContextPreviewDialog.kt:91-103`):
```kotlin
val options = arrayOf("Send", "Cancel")
val choice =
    JOptionPane.showOptionDialog(
        parent,
        panel,
        "Review context before sending to AI",
        JOptionPane.YES_NO_OPTION,
        JOptionPane.PLAIN_MESSAGE,
        null,
        options,
        options[1],          // <- DEFAULT FOCUS = Cancel. DO NOT change to options[0].
    )
return choice == 0
```
→ `val affirmative = if (scan.matched) "Send anyway" else "Send"` (UI-SPEC Delta 2; relabel ONLY
on match). Keep `options[1]` (Cancel) as `initialValue` — **never** make the affirmative the
default focus (Gotcha G5 / Pitfall 5). Return stays `choice == 0`.

**Audit on allow — see Gotcha G3 (chat sessionId timing).** Per RESEARCH Open Q1 recommendation
(Option b), KEEP `confirm()` pure-Boolean and emit `secret_tripwire_allow` in `ChatPanel`
AFTER `createSession(...)` — see the ChatPanel entry. (Alternatively emit here with
`sessionId="none"`; both satisfy SC3. Prefer Option b for a real session id.)

---

### `ui/ChatPanel.kt` (MODIFY — component, interactive send path)

**Analog:** ITSELF — `startSessionFromContext` (the single `confirm()` caller).

**Existing call site + the timing gotcha** (`ChatPanel.kt:298-313`):
```kotlin
val prompt = spec.promptText.trim().ifBlank { "Analyze the provided context." }
if (!ContextPreviewDialog.confirm(
        parent = root,
        privacyMode = getSettings().privacyMode,
        actionName = spec.actionName,
        prompt = prompt,
        contextJson = capture.contextJson,        // <- FINAL post-redaction payload (ContextCollector L52-53)
    )
) {
    onCompleted?.invoke("", InterruptedException("Context preview cancelled by user"))
    return                                        // <- false routes here. Boolean contract is load-bearing.
}
// ... uri/title ...
val session = createSession(title)                // <- L313: session created AFTER confirm() returns
```
→ This is the load-bearing constraint: at `confirm()` time **no session exists yet**. For the
`secret_tripwire_allow` audit (SC3) with a real session id, emit AFTER `createSession(title)` at
L313 when `confirm()` returned `true` AND the payload matches. Re-scan
`SecretTripwire.scan(capture.contextJson)` (cheap, same payload) or thread a flag through; then:
```kotlin
val scan = SecretTripwire.scan(capture.contextJson)
if (scan.matched) {
    AuditLogger.emitGlobal(
        "secret_tripwire_allow",
        mapOf(
            "path" to "chat",
            "sessionId" to session.id,                                   // real id, post-createSession
            "shapeCategories" to scan.shapeCategories.toList().sorted(),
            "entropyScore" to Entropy.truncatedScore(scan.maxEntropyBitsPerChar),
        ),
    )
}
```
Imports: add `com.six2dez.burp.aiagent.audit.AuditLogger`,
`com.six2dez.burp.aiagent.redact.{SecretTripwire, Entropy}`. NEVER put the matched token in the map
(Gotcha G4).

> **Planner note:** Option (c) — let `confirm()` log `sessionId="none"` and skip the ChatPanel
> emit — is also acceptable per SC3 (the gate is what matters; a pre-session allowlist has no id).
> Pick ONE home for the chat allow-event to avoid double-logging.

---

### `scanner/PassiveAiScanner.kt` (MODIFY — service, batch/event-driven send, log+proceed)

**Analog:** ITSELF — three `supervisor.send(text = <final>, …)` sites. The payload at each site is
the FINAL post-redaction string (`safeMetadataText` redacted at L846-855, fed to
`buildAnalysisPrompt`). The supervisor does NOT redact again.

**Redaction boundary (the payload is already final here)** (`PassiveAiScanner.kt:846-858`):
```kotlin
val safeMetadataText =
    if (settings.privacyMode == com.six2dez.burp.aiagent.redact.PrivacyMode.OFF) {
        metadataText
    } else {
        Redaction.apply(metadataText, redactionPolicy, stableHostSalt = settings.hostAnonymizationSalt)
    }
// ...
val singlePrompt = buildAnalysisPrompt(safeMetadataText, settings.passiveAiMinSeverity.name)
```
→ Scan `singlePrompt`/`prompt` (the redacted product), NOT raw `metadataText` (Gotcha G1 / Pitfall 1).

**Site 1 — single send, L911** (`PassiveAiScanner.kt:911-925`): hook immediately BEFORE:
```kotlin
supervisor.send(
    text = singlePrompt,                          // <- FINAL payload to scan
    history = emptyList(),
    ...
)
```

**Site 2 — batch send, L1561** (`PassiveAiScanner.kt:1561`): `text = prompt` (from
`buildBatchAnalysisPrompt(batch)` at L1543; `batch` items hold the already-redacted
`safeMetadataText`). Hook before this `supervisor.send`.

**Site 3 — sendSingleAnalysis, L1647** (`PassiveAiScanner.kt:1647`): `text = prompt` (param;
callers pass `buildAnalysisPrompt(item.metadata, …)` where `item.metadata == safeMetadataText`).
Hook before this `supervisor.send`.

**Hook body (identical shape at all three; detect + emit + PROCEED — never block, SC2):**
```kotlin
val tw = SecretTripwire.scan(singlePrompt)        // or `prompt` at sites 2/3
if (tw.matched) {
    AuditLogger.emitGlobal(
        "secret_tripwire_detect",
        mapOf(
            "path" to "passive_scanner",
            "sessionId" to (supervisor.currentSessionId() ?: "none"),
            "shapeCategories" to tw.shapeCategories.toList().sorted(),
            "entropyScore" to Entropy.truncatedScore(tw.maxEntropyBitsPerChar),
        ),
    )
    // NO blocking — fall through to supervisor.send (SC2).
}
```

**`currentSessionId()` is already used in this file** (`PassiveAiScanner.kt:451`):
```kotlin
val currentSessionId = supervisor.currentSessionId()
```
→ Reuse the same accessor (`AgentSupervisor.kt:143`, returns `String?`). Imports: add
`com.six2dez.burp.aiagent.audit.AuditLogger`, `com.six2dez.burp.aiagent.redact.{SecretTripwire, Entropy}`.

> **Sequencing gotcha (G7):** Phase 19 (QUAL-01 mega-file split) MOVES these three methods. The
> hooks MUST land in `PassiveAiScanner.kt` NOW (Phase 15) — Phase 19 carries them along. Do not
> defer (Pitfall 6).

---

### `mcp/McpToolContext.kt` (MODIFY — service, MCP output, log+proceed)

**Analog:** ITSELF — `redactIfNeeded()`. The returned string is the final redacted MCP output.

**Insertion point — `redactIfNeeded()` L53-57** (current code, `McpToolContext.kt:53-57`):
```kotlin
fun redactIfNeeded(raw: String): String {
    if (privacyMode == PrivacyMode.OFF) return raw
    val policy = RedactionPolicy.fromMode(privacyMode)
    return Redaction.apply(raw, policy, stableHostSalt = hostSalt)
}
```
→ Compute `finalText` (the existing two return branches), scan it, emit on match, return it
(PROCEED — never block, SC2):
```kotlin
fun redactIfNeeded(raw: String): String {
    val finalText =
        if (privacyMode == PrivacyMode.OFF) raw
        else Redaction.apply(raw, RedactionPolicy.fromMode(privacyMode), stableHostSalt = hostSalt)
    val tw = SecretTripwire.scan(finalText)
    if (tw.matched) {
        AuditLogger.emitGlobal(
            "secret_tripwire_detect",
            mapOf(
                "path" to "mcp",
                "sessionId" to (supervisor?.currentSessionId() ?: "none"),   // supervisor is nullable here
                "shapeCategories" to tw.shapeCategories.toList().sorted(),
                "entropyScore" to Entropy.truncatedScore(tw.maxEntropyBitsPerChar),
            ),
        )
    }
    return finalText
}
```

**`supervisor` is already a nullable field on this data class** (`McpToolContext.kt:36`):
```kotlin
val supervisor: AgentSupervisor? = null,
```
→ Use `supervisor?.currentSessionId() ?: "none"` (null-safe). DO NOT thread an `AuditLogger`
constructor param — use the static `emitGlobal` (Don't-Hand-Roll; RESEARCH A3). Imports: add
`com.six2dez.burp.aiagent.audit.AuditLogger`, `com.six2dez.burp.aiagent.redact.{SecretTripwire, Entropy}`.

---

### `redact/SecretTripwireTest.kt` (CREATE — test)

**Analog:** `redact/SecretShapesTest.kt` (JUnit Jupiter + `Assertions.*`, category-substring asserts).

**Header + import style to copy** (`SecretShapesTest.kt:1-5`):
```kotlin
package com.six2dez.burp.aiagent.redact

import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
```

**Positive-sample assert style to copy** (`SecretShapesTest.kt:37-42`):
```kotlin
val awsResult = SecretShapes.findSurviving("AKIAIOSFODNN7EXAMPLE")
assertTrue(
    awsResult.any { it.contains("AWS", ignoreCase = true) },
    "AWS access key shape must be detected; got: $awsResult",
)
```
→ Cover SC1 (`scan("…AKIAIOSFODNN7EXAMPLE…").matched == true`; a synthetic high-entropy base64
token also `matched`), SC2 (a legit base64 fuzz payload `matched == true` AND nothing throws/blocks),
SC3 no-leak (assert `ScanResult`/audit map do NOT contain the input token substring). Reuse the
`AKIAIOSFODNN7EXAMPLE` and base64 corpus samples already in SecretShapesTest L24-77.

---

### `redact/EntropyTest.kt` (CREATE — test)

**Analog:** `redact/SafeRegexTest.kt` (headless, AWT-free, `assertEquals` for numeric/format).

**Header to copy** (`SafeRegexTest.kt:1-11`):
```kotlin
package com.six2dez.burp.aiagent.redact

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
// ... headless, no AWT ...
class SafeRegexTest {
```
→ Assert: `shannon` of a constant string ≈ 0.0; uniform 16-char hex ≈ 4.0 (use a delta);
`MIN_TOKEN_LEN` gate (a 19-char high-entropy token does NOT qualify, 20+ does); charset
classification (hex vs base64 thresholds); `truncatedScore(4.73) == "4.7"` (SC3 format).

---

## Shared Patterns

### Audit emission (cross-cutting — all three paths)
**Source:** `audit/AuditLogger.kt:26-32` (static emitter) + `mcp/tools/McpTool.kt:222-227` (call precedent).
**Apply to:** ChatPanel (allow), PassiveAiScanner (detect ×3), McpToolContext (detect).
```kotlin
// AuditLogger.kt:26 — the static channel (no constructor threading needed)
fun emitGlobal(type: String, payload: Any) { globalEmitter?.invoke(type, payload) }

// McpTool.kt:226 — the exact call shape to mirror (payload is a Map<String, Any?>)
AuditLogger.emitGlobal(type, payload)
```
**Wiring (already done, do NOT touch):** `App.kt:68` registers the emitter routing to
`logEvent`; `App.kt:222` unregisters with `null` on unload:
```kotlin
// App.kt:68
AuditLogger.registerGlobalEmitter { type, payload -> auditLogger.logEvent(type, payload) }
```
`logEvent` (`AuditLogger.kt:54-72`) appends `ts`/`type`/`payload`/`payloadSha256` and respects
`isEnabled()` (audit-disabled → silently dropped). No new AuditLogger method required.

**Audit event shape (SC3 — both event types):**
```
type    : "secret_tripwire_allow" (chat allowlist) | "secret_tripwire_detect" (non-interactive)
payload : { "path": "chat"|"passive_scanner"|"mcp",
            "sessionId": <currentSessionId() ?: "none">,
            "shapeCategories": ["AWS access key", …],   // names ONLY — never the matched value
            "entropyScore": "4.7" }                      // Entropy.truncatedScore — one decimal
```

### No-leak discipline (CLAUDE.md / AGENTS.md non-negotiable)
**Source:** `redact/SecretShapes.kt:88-91` (findSurviving returns category names only).
**Apply to:** `ScanResult`, every audit map, every banner string.
The matched token NEVER appears in `ScanResult`, the audit payload, logs, or the RISK banner.
`shapeCategories` (names) + `maxEntropyBitsPerChar`/`truncatedScore` (number) are the only
secret-derived fields. (Gotcha G4 / Pitfall 4; UI-SPEC Delta 1 "names shape category only".)

### Session-ID resolution (non-interactive paths)
**Source:** `supervisor/AgentSupervisor.kt:143`.
**Apply to:** PassiveAiScanner (`supervisor.currentSessionId()`), McpToolContext (`supervisor?.currentSessionId()`).
```kotlin
fun currentSessionId(): String? = (stateRef.get() as? AgentState.Running)?.sessionId
```
Already used by the scanner at L451/474/483/493. `?: "none"` fallback when no session is running.

### AWT-free pure-detector contract (redact package)
**Source:** `redact/SecretShapes.kt:17-19`, `redact/SafeRegex.kt:21-22`.
**Apply to:** `Entropy.kt`, `SecretTripwire.kt`.
No `java.awt.*`/`javax.swing.*` imports → reusable headless by scanner + MCP + unit tests.

### mockito-kotlin stubbing (per-hook SC4 tests, if path-level mocking is used)
**Source:** `context/ContextPreviewConsistencyTest.kt:15-16,52,55-60` (representative in-repo idiom).
```kotlin
import org.mockito.kotlin.mock
import org.mockito.kotlin.whenever
val supervisor = mock<AgentSupervisor>()
whenever(supervisor.currentSessionId()).thenReturn("sess-1")
```
`mockito-kotlin` 5.4.0 is already a test dep (build.gradle.kts:52). Use only where a path hook
needs a stubbed supervisor (the detector half is testable without mocks).

---

## No Analog Found

None. Every file has a concrete in-repo analog (the two CREATE detectors mirror
`SecretShapes`/`SafeRegex`; the four MODIFY files are edited in place at verified line anchors; the
two CREATE tests mirror existing redact tests). Zero new dependencies.

---

## Gotchas (surface to planner)

| # | Gotcha | Where | Mitigation |
|---|--------|-------|------------|
| G1 | Scan the wrong (raw, pre-redaction) bytes | PassiveAiScanner | Hook AFTER `buildAnalysisPrompt(safeMetadataText,…)`; scan `singlePrompt`/`prompt` (L911/1561/1647), NOT `metadataText` (Pitfall 1) |
| G2 | Scan a pre-redaction `contextJson` in the dialog | ContextPreviewDialog | The `contextJson` arg is ALREADY final (ContextCollector L52-53; dialog self-scans it at L60). Reuse that exact arg (Pitfall 2) |
| G3 | Chat `sessionId` timing: session created AFTER `confirm()` | ChatPanel L299 vs L313 | Emit `secret_tripwire_allow` AFTER `createSession()` (Option b) for a real id, OR accept `"none"` (Option c). NEVER break `confirm()`'s Boolean contract (RESEARCH Open Q1) |
| G4 | Leaking the secret into audit/banner | all paths | `ScanResult` + audit map carry names + score ONLY, never the token (CLAUDE.md/AGENTS.md; Pitfall 4) |
| G5 | "Send anyway" as default focus | ContextPreviewDialog L102 | Keep `options[1]` (Cancel) as `initialValue`; relabel only `options[0]` text (Pitfall 5) |
| G6 | ReDoS in the entropy tokenizer | Entropy.kt | The `[^A-Za-z0-9+/=_-]+` split is linear/safe — no `SafeRegex` wrapper needed. Only route through `SafeRegex` if a backtracking pattern is later introduced |
| G7 | Hooks landing in code Phase 19 moves | PassiveAiScanner | The three scanner hooks MUST commit in Phase 15; Phase 19 (QUAL-01 split) carries them along. Do not defer (Pitfall 6) |
| G8 | Re-running redaction inside the tripwire | all paths | The payload is FINAL at every hook (verified: supervisor.send/sendChat do NOT redact). Scan as-is; never re-redact (Anti-pattern) |
| G9 | Build with `./gradlew test`, NOT `ktlintCheck` | tests | `ktlintCheck` fails standalone (generateBuildFlags defect, MEMORY.md). New tests run under `./gradlew test` |

---

## Metadata

**Analog search scope:** `redact/`, `ui/components/`, `ui/`, `scanner/`, `mcp/`, `mcp/tools/`,
`supervisor/`, `audit/`, `src/test/.../redact/`.
**Files scanned (read this session):** SecretShapes.kt, SafeRegex.kt, ContextPreviewDialog.kt,
AuditLogger.kt, PassiveAiScanner.kt (3 ranges), McpToolContext.kt, SubtleNotice.kt,
ChatPanel.kt (startSessionFromContext), McpTool.kt (emitGlobal), AgentSupervisor.kt
(currentSessionId), App.kt (emitter, via grep), SecretShapesTest.kt, SafeRegexTest.kt,
ContextPreviewConsistencyTest.kt (mockito idiom, via grep).
**All RESEARCH line anchors re-verified accurate.**
**Pattern extraction date:** 2026-06-11
