# Phase 15: Pre-Send Secret Tripwire (PRIV-03) - Research

**Researched:** 2026-06-11
**Domain:** Outbound secret detection (post-redaction tripwire) — Shannon entropy + curated-shape scanning, AWT-free pure Kotlin, three hook points
**Confidence:** HIGH (all hook points read in source; entropy heuristic corroborated by two independent secret-scanning tools; zero new dependencies)

## Summary

Phase 15 adds a **post-redaction tripwire** that scans the FINAL outbound payload (after the redaction pipeline) for secrets that survived, on all three outbound paths, and warns-with-confirmation on the interactive path while audit-logging-and-proceeding on the two non-interactive paths. It is the last line of defense behind Phase 13's redaction and PRIV-04 banner. The mechanism is two-pronged: (a) reuse `SecretShapes.findSurviving(text)` (Phase 13's curated AWT-free shape set, whose KDoc already names "Phase 15 tripwire reuses this object") for known prefixes, and (b) a trivial pure-Kotlin Shannon-entropy heuristic for unknown high-entropy tokens. Both are wrapped in a single AWT-free `SecretTripwire.scan(finalPayload)` object in the `redact` package, mirroring the `SecretShapes`/`SafeRegex` precedent, so all three paths and unit tests reuse one detector.

The codebase was traced end-to-end and the redaction architecture is now unambiguous: **`AgentSupervisor.send()`/`sendChat()` do NOT redact** — redaction happens upstream of every send. For the chat path, `ContextCollector.fromRequestResponses()` redacts (lines 52-53) before building `capture.contextJson`, which the dialog already self-scans at `ContextPreviewDialog.kt:60`. For the scanner path, `safeMetadataText` is redacted (`PassiveAiScanner.kt:846-855`) before `buildAnalysisPrompt(...)`, so the prompt string at each `supervisor.send(text=...)` call site (lines 911, 1561, 1647) IS the final post-redaction payload. For MCP, `McpToolContext.redactIfNeeded()` (lines 53-57) returns the final redacted string. This means the tripwire hooks land at clean, well-defined points with no architectural rework.

**Primary recommendation:** Build `redact/SecretTripwire.kt` (AWT-free `object` with `scan(text): ScanResult`) reusing `SecretShapes.findSurviving`; add a `redact/Entropy.kt` helper (or fold into `SecretTripwire`) implementing truffleHog-style Shannon entropy over whitespace/punctuation-split tokens (min length 20, base64 charset ≥ 4.5 bits/char OR hex charset ≥ 3.0 bits/char). Hook the dialog gate inside `ContextPreviewDialog.confirm()` (escalate the existing `SubtleNotice` to `Level.RISK` + relabel "Send" → "Send anyway" when a match is present); hook log+proceed at the three non-interactive send sites using the **existing `AuditLogger.emitGlobal(type, payload)`** static emitter (no constructor threading needed). Use `supervisor.currentSessionId()` for the session ID on non-interactive paths. Default ON, warn-only, never blocking.

<user_constraints>
## User Constraints (from CONTEXT.md)

### Locked Decisions

**Detection method**
- Fire on BOTH: (a) `SecretShapes.findSurviving(...)` known-shape matches (Phase 13 set), AND (b) a Shannon-entropy heuristic for unknown high-entropy tokens (tokens ≥ ~20 chars with entropy ≥ ~4.0 bits/char — tunable; the exact threshold/length at Claude's discretion). The entropy score is computed regardless because SC3 logs a (truncated) entropy score.
- Keep the tripwire detector AWT-free and in/near the `redact` package so all three paths and tests can reuse it (mirrors `SecretShapes`/`SafeRegex`).

**Non-interactive paths (PassiveAiScanner, MCP)**
- There is no user to confirm. On a tripwire hit, **audit-log the detection and PROCEED** with the (already-redacted) send — never block (honors SC2 "never hard-blocked"). Only the interactive ChatPanel path shows an actual confirmation dialog. SC4's "fires on all three paths" = detect + audit-log on all three; the modal confirmation is ChatPanel-only.

**Default & scope**
- **ON by default** — warn-only and non-blocking, so low-risk. Scans the FINAL redacted payload regardless of privacy mode (it is the last line of defense, after redaction). A settings toggle can disable it. (STRICT/BALANCED/OFF all still produce a final payload to scan; the tripwire runs on whatever is about to be sent.)

**Interactive confirmation UX (SC5)**
- **Extend the existing `ContextPreviewDialog`** (do NOT add a new modal). Phase 13's survived-secret WARN banner becomes the tripwire highlight; `confirm(...)` gains a "Send anyway / Cancel" gate that appears only when a tripwire match is present. The dialog message: a warn-with-confirmation prompt such as "This payload appears to contain a high-entropy value — send anyway?". Choosing "Send anyway" = the allowlist action that gets audit-logged.

**Audit logging (SC3)**
- On "send anyway" (allowlist), write an audit event via the existing `AuditLogger` containing the session ID and a **truncated** entropy score (and the matched shape category / a redacted indicator — NEVER the raw matched secret value). Reuse `AuditLogger.logEvent(...)`. The allowlist action is also visibly flagged in the preview dialog per PRIV-03.

### Claude's Discretion
- Exact entropy threshold + min token length, the tripwire object's name/location, how the non-interactive paths surface the audit event, and the precise dialog wording/highlight rendering — at Claude's discretion, guided by the `SecretShapes`/`SafeRegex` AWT-free precedent and the existing `ContextPreviewDialog`/`AuditLogger` APIs.

### Deferred Ideas (OUT OF SCOPE)
- None — discussion stayed within phase scope. (The QUAL-01 mega-file split that later moves the PassiveAiScanner methods is Phase 19; the tripwire hooks must be committed here first.)
</user_constraints>

<phase_requirements>
## Phase Requirements

| ID | Description | Research Support |
|----|-------------|------------------|
| PRIV-03 | A pre-send secret tripwire scans the final redacted payload and warns the user (warn-with-confirmation, not silent) before a high-entropy secret leaves Burp; allowlist actions are audit-logged and visibly flagged in the preview dialog | `SecretTripwire.scan()` detector (shapes + entropy, §Standard Stack/§Code Examples); three hook points identified to the line (§Architecture Patterns → Hook Points); dialog gate via existing `ContextPreviewDialog`/`SubtleNotice.Level.RISK` (§Code Examples); audit via `AuditLogger.emitGlobal`/`logEvent` with session ID + truncated entropy score, never the raw value (§Code Examples, §Project Constraints) |
</phase_requirements>

## Project Constraints (from CLAUDE.md)

| Directive | Source | Impact on this phase |
|-----------|--------|----------------------|
| **Zero new dependencies** (MIT, keep deps compatible) | CLAUDE.md § Constraints; CONTEXT.md | Shannon entropy is trivial pure Kotlin (`ln`/`log2` from stdlib). No library. Do NOT add a secret-scanning dependency. |
| **English only in code & comments** | CLAUDE.md / AGENTS.md (non-negotiable) | All new KDoc, banner copy, audit keys in English. UI-SPEC copy strings are already English. |
| **Audit defaults: hashes/scores only, never raw secret** | CLAUDE.md § Constraints; CONTEXT.md SC3 | Audit event carries truncated entropy score + shape category name ONLY. NEVER interpolate the matched token. Mirrors existing `AuditLogger` discipline (Phase 13 banner names categories only). |
| **AWT-free detector** | CLAUDE.md (Kotlin/Swing); CONTEXT.md | `redact/SecretTripwire.kt` MUST NOT import `java.awt.*` / `javax.swing.*` (same contract as `SecretShapes.kt` lines 17-19, `SafeRegex.kt` line 21). Enables headless unit tests + scanner/MCP reuse. |
| **Build/test with `./gradlew test`, NOT `ktlintCheck`** | MEMORY.md (generateBuildFlags wiring defect) | `./gradlew ktlintCheck` fails standalone (pre-existing). Use `./gradlew test`. New tests run there. |
| **Privacy controls non-negotiable; warn-with-confirmation, never hard-stop** | CLAUDE.md core value; CONTEXT.md | Cancel is default focus; Send anyway is one click; no hard-block on any path. |

## Architectural Responsibility Map

| Capability | Primary Tier | Secondary Tier | Rationale |
|------------|-------------|----------------|-----------|
| Known-shape detection (AWS/GitHub/JWT/…) | `redact` package (`SecretShapes.findSurviving`) | — | Already exists (Phase 13), AWT-free, single source of truth; KDoc pre-commits to Phase 15 reuse |
| Shannon-entropy heuristic | `redact` package (new `SecretTripwire`/`Entropy`) | — | Pure compute, no UI/IO; must be reusable by scanner + MCP (no AWT) and unit-testable headless |
| Tripwire orchestration (`scan()`) | `redact` package (new `SecretTripwire`) | — | Pure function consumed by all three paths; mirrors `SecretShapes`/`SafeRegex` placement |
| Interactive confirmation gate (modal) | UI tier (`ContextPreviewDialog`) | — | Swing-only; the ONLY path with a human to confirm; reuses existing dialog (no new modal, UI-SPEC) |
| Banner highlight (WARN→RISK escalation) | UI tier (`SubtleNotice` inside dialog) | — | Existing component; `Level.RISK` pre-reserved by Phase 13 (FLAG-13-03) |
| Non-interactive detect + audit | Backend (`PassiveAiScanner`, `McpToolContext`) | `audit` (`AuditLogger.emitGlobal`) | No human present → log+proceed; never block; cross-cutting audit via existing global emitter |
| Audit event write (allowlist / detection) | `audit` package (`AuditLogger.logEvent`/`emitGlobal`) | — | Established discipline: hashes/scores only, never raw value |
| Session-ID resolution (non-interactive) | `supervisor` (`AgentSupervisor.currentSessionId()`) | — | Single existing accessor the scanner already uses (PassiveAiScanner.kt:451,474,483,493) |

## Standard Stack

### Core
| Library | Version | Purpose | Why Standard |
|---------|---------|---------|--------------|
| Kotlin stdlib (`kotlin.math.ln` / `kotlin.math.log2`) | bundled (JVM 21) | Shannon entropy compute | Entropy is `-Σ p·log2(p)`; one stdlib call per term. Zero new deps (CLAUDE.md). `[VERIFIED: build.gradle.kts — Kotlin/JVM 21, no math dep needed]` |
| `redact/SecretShapes.kt` (in-repo, Phase 13) | current | Known-shape detector | AWT-free curated set; `findSurviving(text): Set<String>` returns category names only. KDoc lines 14-15 pre-commit to Phase 15 reuse. `[VERIFIED: src/main/kotlin/.../redact/SecretShapes.kt]` |
| `redact/SafeRegex.kt` (in-repo, Phase 13) | current | AWT-free helper precedent + ReDoS-safe matching | The new detector follows this style; if entropy tokenization uses regex, route through `SafeRegex` patterns. `[VERIFIED: src/main/kotlin/.../redact/SafeRegex.kt]` |
| `ui/components/SubtleNotice.kt` (in-repo) | current | Tripwire highlight banner | `enum Level { INFO, WARN, RISK }`; `setMessage(level, html)` / `hideNotice()`. `Level.RISK` → `subtleDanger`/`accentDanger` already wired (lines 104-111). `[VERIFIED: src/main/kotlin/.../ui/components/SubtleNotice.kt]` |
| `audit/AuditLogger.kt` (in-repo) | current | Allowlist + detection audit | `logEvent(type: String, payload: Any)` (line 54) AND static `emitGlobal(type, payload)` (line 26) gated by registered emitter + `isEnabled()`. `[VERIFIED: src/main/kotlin/.../audit/AuditLogger.kt]` |

### Supporting
| Library | Version | Purpose | When to Use |
|---------|---------|---------|-------------|
| `supervisor/AgentSupervisor.currentSessionId()` | current | Session ID for non-interactive audit | Returns `String?` (line 143). Scanner already calls it (4 sites). MCP context holds `supervisor: AgentSupervisor?`. `[VERIFIED: AgentSupervisor.kt:143; PassiveAiScanner.kt:451]` |
| JUnit Jupiter 6.0.3 + `kotlin("test")` | 6.0.3 | Unit tests | `useJUnitPlatform()`; mirror `SecretShapesTest.kt`/`SafeRegexTest.kt` style. `[VERIFIED: build.gradle.kts:49-51,138]` |
| `mockito-kotlin` 5.4.0 | 5.4.0 | Mock supervisor/audit in path tests | Already a test dep; use only where the three-path hooks need a stubbed supervisor. `[VERIFIED: build.gradle.kts:52]` |

### Alternatives Considered
| Instead of | Could Use | Tradeoff |
|------------|-----------|----------|
| Hand-rolled Shannon entropy | A secret-scanning library (truffleHog/detect-secrets/gitleaks) | All are Python/Go CLIs, not JVM libraries; would violate zero-new-deps and the AWT-free in-process contract. The algorithm is ~15 lines of Kotlin. **Hand-roll the math, borrow the thresholds.** |
| New `SecretTripwire` object | Extend `SecretShapes` directly | Keep `SecretShapes` a pure shape registry (single responsibility); the tripwire orchestrates shapes + entropy + result type. A separate `object` keeps both testable in isolation and matches the `SafeRegex` precedent. |
| Threading `AuditLogger` into `McpToolContext` | `AuditLogger.emitGlobal(...)` static emitter | `emitGlobal` already exists for exactly this (used by `McpTool.kt:226`); avoids touching `McpToolContext`/`McpRuntimeContextFactory` constructors. Prefer the emitter. (See Open Question 1 for the dialog-path nuance.) |

**Installation:**
```bash
# No installation. Zero new dependencies — entropy is kotlin.math, detector is in-repo.
./gradlew test   # NOT ktlintCheck (generateBuildFlags defect, MEMORY.md)
```

**Version verification:** No external package to verify — all building blocks are in-repo (`SecretShapes`, `SafeRegex`, `SubtleNotice`, `AuditLogger`, `AgentSupervisor`) or Kotlin stdlib (`kotlin.math`). `[VERIFIED: no npm/PyPI/crates dependency added]`

## Package Legitimacy Audit

> Not applicable — this phase installs **zero** external packages. The entropy heuristic is pure `kotlin.math` (stdlib); every other building block is already in the repository (Phase 13 `SecretShapes`/`SafeRegex`, existing `SubtleNotice`/`AuditLogger`/`AgentSupervisor`). No registry (Maven/npm/PyPI) dependency is added, so slopcheck / registry verification has nothing to evaluate.

| Package | Registry | Disposition |
|---------|----------|-------------|
| (none) | — | No external packages added |

**Packages removed due to slopcheck [SLOP] verdict:** none (no packages)
**Packages flagged as suspicious [SUS]:** none (no packages)

## Architecture Patterns

### System Architecture Diagram

```
                          ┌──────────────────────────────────────────────────┐
                          │  redact/SecretTripwire  (NEW, AWT-free, pure)      │
                          │                                                    │
                          │  scan(finalPayload: String): ScanResult            │
                          │    ├─ shapes  = SecretShapes.findSurviving(text)   │  (reuse Phase 13)
                          │    ├─ entropy = Entropy.maxTokenEntropy(text)      │  (NEW heuristic)
                          │    │     tokenize → filter len≥20 →                │
                          │    │     base64≥4.5 OR hex≥3.0 bits/char           │
                          │    └─ ScanResult(matched, categories, maxEntropy)  │
                          └───────────────▲───────────────▲──────────▲─────────┘
                                          │               │          │
        ┌─────────────────────────────────┘               │          └──────────────────────────┐
        │ (1) INTERACTIVE                                  │ (2) SCANNER                          │ (3) MCP
        │                                                  │                                      │
  ChatPanel.startSessionFromContext()            PassiveAiScanner                       McpToolContext
        │                                          ┌── single send (L911)               .redactIfNeeded(raw) L53-57
        │  capture.contextJson  (ALREADY redacted  ├── batch send  (L1561)                    │
        │   by ContextCollector L52-53)            └── sendSingleAnalysis (L1647)        raw → Redaction.apply → final
        ▼                                          (singlePrompt/prompt = FINAL,               │
  ContextPreviewDialog.confirm(...)                redacted at L846-855)                       ▼
        │  scan(contextJson)                              │                              scan(finalRedacted)
        ├─ match? → SubtleNotice RISK + "Send anyway"     ├─ match? → emitGlobal(detection) │  match? → emitGlobal(detection)
        │           (Cancel = default focus)              │           PROCEED (never block) │  PROCEED (never block)
        ├─ "Send anyway" → true  → emitGlobal(allowlist)  ▼                                 ▼
        └─ "Cancel"      → false → existing cancel path  supervisor.send(text=final, …)   return final  → MCP wire
                  │
                  ▼
   sendMessage → supervisor.sendChat(text=finalPrompt, …)   (no redaction inside supervisor)
                  │
                  ▼
            AI backend wire
```

Data-flow notes (trace the AWS-key case, SC1):
- A `AKIA…` value in a request body → `ContextCollector.fromRequestResponses` runs `Redaction.apply` (L52). If BALANCED leaves it (it survives) → it is in `capture.contextJson`.
- `ChatPanel.startSessionFromContext` (L299) passes `capture.contextJson` to `confirm()`. The dialog runs `SecretTripwire.scan(contextJson)` → `SecretShapes` returns "AWS access key" → RISK banner + "Send anyway" gate.
- The redaction pipeline is NOT re-run inside `confirm()` / `sendChat` / `supervisor.send` — the payload the dialog scans is byte-identical to what leaves Burp (verified: `AgentSupervisor.send` L359 and `sendChat` L509 pass `text` straight to `connection.send`).

### Recommended Project Structure
```
src/main/kotlin/com/six2dez/burp/aiagent/redact/
├── SecretShapes.kt          # EXISTING (Phase 13) — reused unchanged
├── SafeRegex.kt             # EXISTING (Phase 13) — style precedent
├── Entropy.kt               # NEW — Shannon entropy + tokenizer (AWT-free); OR fold into SecretTripwire
└── SecretTripwire.kt        # NEW — object scan(text): ScanResult { matched, categories, maxEntropyBitsPerChar }

src/main/kotlin/com/six2dez/burp/aiagent/ui/components/
└── ContextPreviewDialog.kt  # EDIT — confirm() consumes SecretTripwire.scan; WARN→RISK; "Send anyway" gate; emitGlobal on allow

src/main/kotlin/com/six2dez/burp/aiagent/scanner/
└── PassiveAiScanner.kt      # EDIT — hooks at L911, L1561, L1647 (detect + emitGlobal + proceed)

src/main/kotlin/com/six2dez/burp/aiagent/mcp/
└── McpToolContext.kt        # EDIT — redactIfNeeded() (L53-57): scan final + emitGlobal + return (proceed)

src/test/kotlin/com/six2dez/burp/aiagent/redact/
├── SecretTripwireTest.kt    # NEW — SC1 (AWS+entropy fires), SC2 (base64 fuzz fires, dismissible-logic), entropy thresholds
└── EntropyTest.kt           # NEW (if split) — bits/char correctness, min-length gate, truncation
```

### Pattern 1: Single pure detector reused by all paths (mirror SecretShapes/SafeRegex)
**What:** One AWT-free `object SecretTripwire` with a pure `scan(text): ScanResult`. The dialog, scanner, and MCP all call the same function. No path re-implements detection.
**When to use:** Always — this is the load-bearing decision. Guarantees the interactive and non-interactive paths agree (SC4) and keeps tests headless.
**Example:**
```kotlin
// Source: in-repo precedent SecretShapes.kt (object + pure fun), SafeRegex.kt (AWT-free contract)
package com.six2dez.burp.aiagent.redact

/**
 * Pre-send secret tripwire (PRIV-03). AWT-free — MUST NOT import java.awt / javax.swing so the
 * scanner and MCP paths can reuse it headless (same contract as SecretShapes / SafeRegex).
 * Reuses [SecretShapes.findSurviving] for known prefixes; adds a Shannon-entropy heuristic for
 * unknown high-entropy tokens. Never echoes a matched value — only category names + a numeric score.
 */
object SecretTripwire {

    data class ScanResult(
        val matched: Boolean,
        val shapeCategories: Set<String>,   // from SecretShapes — names only, never raw values
        val maxEntropyBitsPerChar: Double,  // 0.0 if no qualifying high-entropy token
    )

    /** Scan the FINAL post-redaction [payload]. matched = a known shape survived OR a high-entropy token. */
    fun scan(payload: String): ScanResult {
        val categories = SecretShapes.findSurviving(payload)
        val maxEntropy = Entropy.maxQualifyingTokenEntropy(payload)
        return ScanResult(
            matched = categories.isNotEmpty() || maxEntropy > 0.0,
            shapeCategories = categories,
            maxEntropyBitsPerChar = maxEntropy,
        )
    }
}
```

### Pattern 2: truffleHog-style Shannon entropy over charset-classified tokens
**What:** Tokenize on whitespace/punctuation, keep tokens ≥ 20 chars, classify each token's charset (base64 vs hex), compute Shannon entropy in bits/char, flag if it clears the charset threshold.
**When to use:** Inside the entropy helper. This is the industry-standard heuristic (truffleHog, detect-secrets) — borrow the constants, not the library.
**Example:**
```kotlin
// Source: truffleHog default thresholds (base64≥4.5, hex≥3.0, len>20) — see §Sources, §Open Questions.
// Algorithm: Shannon entropy H = -Σ p(c)·log2(p(c)) over the characters of the token.
package com.six2dez.burp.aiagent.redact

import kotlin.math.ln

object Entropy {
    private const val MIN_TOKEN_LEN = 20
    private const val BASE64_THRESHOLD = 4.5   // bits/char
    private const val HEX_THRESHOLD = 3.0      // bits/char
    private val BASE64_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=".toSet()
    private val HEX_CHARS = "0123456789abcdefABCDEF".toSet()
    // Split on anything that is NOT a typical secret/token char.
    private val TOKEN_SPLIT = Regex("[^A-Za-z0-9+/=_-]+")

    /** Shannon entropy of [s] in bits per character (0.0 for empty). */
    fun shannon(s: String): Double {
        if (s.isEmpty()) return 0.0
        val counts = HashMap<Char, Int>()
        for (c in s) counts[c] = (counts[c] ?: 0) + 1
        val n = s.length.toDouble()
        var h = 0.0
        for (count in counts.values) {
            val p = count / n
            h -= p * (ln(p) / ln(2.0))   // log2(p)
        }
        return h
    }

    /**
     * Returns the max entropy (bits/char) among tokens that QUALIFY as suspect: length ≥ 20 AND
     * (mostly-base64 with entropy ≥ 4.5) OR (mostly-hex with entropy ≥ 3.0). 0.0 if none qualify.
     */
    fun maxQualifyingTokenEntropy(text: String): Double {
        var max = 0.0
        for (token in text.split(TOKEN_SPLIT)) {
            if (token.length < MIN_TOKEN_LEN) continue
            val h = shannon(token)
            val isHex = token.all { it in HEX_CHARS }
            val isB64 = token.all { it in BASE64_CHARS }
            val qualifies = (isHex && h >= HEX_THRESHOLD) || (isB64 && h >= BASE64_THRESHOLD)
            if (qualifies && h > max) max = h
        }
        return max
    }

    /** Truncated score for the audit log (SC3) — one decimal place, never the token. */
    fun truncatedScore(bitsPerChar: Double): String = "%.1f".format(bitsPerChar)
}
```

### Pattern 3: Conditional warn-with-confirmation gate inside the existing dialog (UI-SPEC Delta 2)
**What:** `confirm()` keeps its `Boolean` return. When `scan().matched`, escalate the existing `SubtleNotice` to `Level.RISK`, relabel the affirmative option to "Send anyway", keep `Cancel` as default focus, and on "Send anyway" emit the allowlist audit event before returning `true`.
**When to use:** The ChatPanel interactive path only (the single `confirm()` caller, `ChatPanel.kt:299`).
**Example:** see §Code Examples → "ContextPreviewDialog gate".

### Anti-Patterns to Avoid
- **Re-running redaction inside the tripwire or the dialog.** The payload is already final at every hook point (verified). Re-redacting would diverge from what the supervisor actually sends and waste the 50ms ReDoS budget twice. Scan the payload as-is.
- **Echoing the matched token anywhere** (UI banner, audit payload, logs). UI-SPEC and CLAUDE.md: names/categories + numeric score only. `SecretShapes.findSurviving` already returns only category names — keep that discipline in the entropy path (never put the token in `ScanResult` or the audit map).
- **Hard-blocking any path.** Cancel must always be available and the default focus; non-interactive paths must PROCEED after logging. There is no code path that drops a send because of a tripwire match (SC2).
- **Breaking `confirm()`'s `Boolean` contract.** Its single caller (`ChatPanel.kt:299`) routes `false` → "cancelled by user". Keep the signature returning `Boolean`; do the scan inside the dialog (mirroring the existing `SecretShapes.findSurviving(contextJson)` self-scan at line 60).
- **Adding an `AuditLogger` constructor param to `McpToolContext`** when `AuditLogger.emitGlobal(...)` already exists for cross-cutting audit (used by `McpTool.kt:226`). Prefer the emitter.
- **Placing the entropy regex without a ReDoS guard if it could backtrack.** The simple `[^A-Za-z0-9+/=_-]+` split is linear and safe; if a more complex pattern is introduced, route it through `SafeRegex`.

## Don't Hand-Roll

| Problem | Don't Build | Use Instead | Why |
|---------|-------------|-------------|-----|
| Known secret-prefix detection | A new AWS/GitHub/JWT regex set | `SecretShapes.findSurviving(text)` | Already curated + verified against gitleaks/trufflehog corpora (Phase 13); KDoc commits it to Phase 15 reuse; one source of truth keeps interactive/non-interactive parity (SC4) |
| The RISK highlight banner | A new red banner component | `SubtleNotice.setMessage(Level.RISK, html)` | `Level.RISK` palette (`subtleDanger`/`accentDanger`) already wired (lines 104-111); theme-correct on Burp theme switch for free; Phase 13 pre-reserved RISK (FLAG-13-03) |
| Cross-cutting audit write from non-audit-holding code | Threading `AuditLogger` through MCP/scanner constructors | `AuditLogger.emitGlobal(type, payload)` | Static emitter registered in `App.kt:68`, respects `isEnabled()`, already used by `McpTool.kt:226`. No constructor surgery. |
| Session ID lookup on non-interactive paths | A new session accessor | `supervisor.currentSessionId()` | Existing `String?` accessor (AgentSupervisor.kt:143); scanner already calls it (4 sites) |
| ReDoS-safe regex matching (if needed) | A new timeout wrapper | `SafeRegex.replaceAllSafe` / `isPatternSafe` | 50ms deadline via DeadlineCharSequence already solves JDK-8234713; AWT-free; Phase 13 |
| The confirmation modal | A brand-new `JDialog`/`JOptionPane` | Extend `ContextPreviewDialog.confirm()` | UI-SPEC: single touch point, no new modal; the gate reuses the dialog's own `showOptionDialog` step |

**Key insight:** Phase 15 is overwhelmingly an **integration** phase — ~90% of the building blocks already exist (`SecretShapes`, `SubtleNotice` with RISK, `AuditLogger.emitGlobal`, `ContextPreviewDialog` self-scan, `currentSessionId`). The only genuinely new code is the ~30-line `Entropy` helper and the thin `SecretTripwire` orchestrator. The risk is not "can we build it" but "do the hooks land at the truly-final payload and never block" — both are now verified.

## Runtime State Inventory

> Phase 15 adds new behavior; it does NOT rename or migrate anything. Included for completeness; every category is "nothing found".

| Category | Items Found | Action Required |
|----------|-------------|------------------|
| Stored data | None — no datastore keys/collections/IDs change. The audit log gains a NEW event *type* string (e.g. `secret_tripwire_allow`/`secret_tripwire_detect`) appended to the existing `~/.burp-ai-agent/audit.jsonl`; no schema migration (JSONL is append-only, untyped). Verified by reading `AuditLogger.logEvent` (writes a flat map). | None (new event type is additive) |
| Live service config | None — no external service config references the tripwire. Verified: tripwire is in-process only. | None |
| OS-registered state | None — no OS-level registration. | None |
| Secrets/env vars | None — the tripwire reads payloads in memory; it stores NO secret. By design it writes only category names + a truncated numeric score to the audit log (never the secret). Verified against CLAUDE.md audit-defaults + UI-SPEC. | None |
| Build artifacts | None — pure new Kotlin sources compiled into the existing fat JAR (`Custom-AI-Agent-<version>.jar`). No `egg-info`/binary equivalent. | None |

**The canonical question — after every file is updated, what runtime systems still hold old state?** Nothing. This phase introduces a detector + hooks; it neither renames an existing symbol that other runtime systems cache, nor migrates persisted data. The only persisted side effect is *new* audit-event rows, which require no migration.

## Common Pitfalls

### Pitfall 1: Hooking the scanner BEFORE redaction (scanning the wrong bytes)
**What goes wrong:** Placing the scanner tripwire on `metadataText` (raw) instead of `safeMetadataText`/`singlePrompt` (redacted) → the tripwire fires on values the redaction pipeline WOULD have removed, producing noise and a false sense the redaction failed.
**Why it happens:** `PassiveAiScanner` builds both a raw `metadataText` (L809-844) and a redacted `safeMetadataText` (L846-855); it's easy to grab the wrong one.
**How to avoid:** Hook AFTER `buildAnalysisPrompt(safeMetadataText, …)` — scan the exact `singlePrompt`/`prompt`/batch-`prompt` string that is the `text=` argument to `supervisor.send` (L911-912, L1561-1562, L1647-1648). That string is the final payload (supervisor does not redact).
**Warning signs:** Tripwire fires under STRICT/BALANCED on values that a redaction unit test proves are stripped.

### Pitfall 2: Re-redacting / scanning a pre-redaction `contextJson` in the dialog
**What goes wrong:** Scanning some upstream raw context instead of `capture.contextJson`.
**Why it happens:** Multiple `contextJson` variables exist in `ChatPanel.sendMessage` (the `effectiveContextJson` first-turn gate at L492).
**How to avoid:** The dialog already receives the FINAL payload as `contextJson` (redacted in `ContextCollector` L52-53) and already self-scans it at L60. Reuse that exact argument: replace `SecretShapes.findSurviving(contextJson)` with `SecretTripwire.scan(contextJson)`.
**Warning signs:** Banner shows shapes that the post-redaction body (visible in the dialog's own `JTextArea`) does not contain.

### Pitfall 3: Entropy false positives desensitizing users
**What goes wrong:** Long benign base64 (legit fuzz payloads, embedded images, JSON blobs) trips the entropy gate constantly → users reflexively click "Send anyway".
**Why it happens:** Entropy heuristics are inherently noisy; SC2 explicitly tests a *legitimate base64 fuzz payload* that SHOULD fire (and be dismissible). The desensitization risk is real but accepted (same disposition as Phase 13's high-entropy-hex shape, T-13-11).
**How to avoid:** Use the conservative truffleHog thresholds (base64 ≥ 4.5, hex ≥ 3.0, len ≥ 20) rather than the looser detect-secrets-low (3.5/2.5). Keep it warn-only + dismissible (never block). Make the threshold a `const` so it can be tuned. Document the accepted-noise tradeoff in KDoc (mirror SecretShapes ordering note).
**Warning signs:** Every send shows the gate; users stop reading it.

### Pitfall 4: Leaking the secret into the audit log or banner
**What goes wrong:** Interpolating the matched token into the audit payload or RISK banner copy.
**Why it happens:** Natural temptation to "show what was found".
**How to avoid:** `ScanResult` carries ONLY `shapeCategories` (names) + `maxEntropyBitsPerChar` (number). The audit map carries `sessionId`, `truncatedEntropyScore` (`"%.1f"`), and `shapeCategories` — never a token. The banner names categories only (UI-SPEC: "names shape category only, never the raw matched value"). This is a hard CLAUDE.md/AGENTS.md constraint.
**Warning signs:** A secret-looking substring appears in `audit.jsonl` or the dialog banner.

### Pitfall 5: Making "Send anyway" the default focus
**What goes wrong:** Setting the affirmative as the default `showOptionDialog` option → an Enter keypress silently sends past a secret.
**Why it happens:** Easy to pass the wrong `initialValue`.
**How to avoid:** Keep `options[1]` (Cancel) as the `initialValue` (current code already does this at L102). The relabel changes only `options[0]`'s text to "Send anyway"; the default stays Cancel. UI-SPEC: "the affirmative is never the default focus".
**Warning signs:** Pressing Enter on the dialog sends without an explicit click.

### Pitfall 6: Hooks landing in code Phase 19 will move
**What goes wrong:** Deferring the scanner hooks until after the QUAL-01 mega-file split (Phase 19) — but Phase 19 moves these very methods.
**Why it happens:** Tempting to wait for a cleaner file.
**How to avoid:** ROADMAP + STATE explicitly require the PassiveAiScanner hooks land in Phase 15 (committed here first); Phase 19 carries them along during the split. Put the hooks in `PassiveAiScanner.kt` now.
**Warning signs:** N/A — this is a sequencing constraint, enforced by the roadmap.

## Code Examples

### Entropy helper (Shannon, bits/char, truncated score)
See §Architecture Patterns → Pattern 2 (`redact/Entropy.kt`). Verified algorithm: `H = -Σ p(c)·log2(p(c))`; `log2(p) = ln(p)/ln(2)` via `kotlin.math.ln`. `[VERIFIED: kotlin.math.ln in stdlib; entropy formula CITED: Shannon 1948 / truffleHog implementation]`

### The tripwire detector
See §Architecture Patterns → Pattern 1 (`redact/SecretTripwire.kt`). `[VERIFIED: SecretShapes.findSurviving signature, src/main/kotlin/.../redact/SecretShapes.kt:93]`

### ContextPreviewDialog gate (extend confirm(), keep Boolean, RISK + "Send anyway")
```kotlin
// Source: existing ContextPreviewDialog.kt (lines 59-103) — minimal delta per UI-SPEC Delta 1 & 2.
// Replace the Phase-13 survived-shape block with a tripwire scan; relabel affirmative ONLY on match.
val scan = SecretTripwire.scan(contextJson)              // FINAL post-redaction payload (already redacted upstream)
if (scan.matched) {
    val shapes = scan.shapeCategories.joinToString(", ").ifBlank { "high-entropy value" }
    val html = if (scan.shapeCategories.isEmpty()) {
        "A high-entropy value that may be a secret survived redaction. Review before sending."
    } else {
        "A value matching a known secret shape ($shapes) survived redaction. Review before sending."
    }
    survivedNotice.setMessage(SubtleNotice.Level.RISK, html)   // WARN → RISK (UI-SPEC Delta 1; FLAG-13-03)
} else {
    // Optional: keep Phase 13 WARN advisory if a non-gating shape survives (FLAG-15-01 permits collapsing).
    survivedNotice.hideNotice()
}
// ... build panel as today ...
val affirmative = if (scan.matched) "Send anyway" else "Send"        // UI-SPEC Delta 2; relabel only on match
val options = arrayOf(affirmative, "Cancel")
val choice = JOptionPane.showOptionDialog(
    parent, panel, "Review context before sending to AI",
    JOptionPane.YES_NO_OPTION, JOptionPane.PLAIN_MESSAGE, null,
    options, options[1],                                            // options[1] = Cancel = DEFAULT FOCUS (never affirmative)
)
val confirmed = (choice == 0)
if (confirmed && scan.matched) {
    // SC3: allowlist audit — session ID + truncated entropy score + categories; NEVER the raw value.
    AuditLogger.emitGlobal(
        "secret_tripwire_allow",
        mapOf(
            "path" to "chat",
            "shapeCategories" to scan.shapeCategories.toList().sorted(),
            "entropyScore" to Entropy.truncatedScore(scan.maxEntropyBitsPerChar),
            // sessionId: see Open Question 1 — pass into confirm() OR resolve via supervisor at the call site.
        ),
    )
}
return confirmed
```
`[VERIFIED: ContextPreviewDialog.kt:59-103 current shape; SubtleNotice.Level.RISK exists (SubtleNotice.kt:25,105,111); AuditLogger.emitGlobal exists (AuditLogger.kt:26)]`

### Non-interactive hook — PassiveAiScanner (detect + log + PROCEED)
```kotlin
// Source: PassiveAiScanner.kt — insert immediately BEFORE each supervisor.send(text = <final>, …).
// Sites: single L911 (text = singlePrompt), batch L1561 (text = prompt), sendSingleAnalysis L1647 (text = prompt).
val tw = SecretTripwire.scan(singlePrompt)        // singlePrompt is FINAL (built from safeMetadataText, L846-855)
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
    // NO blocking — fall through and send (SC2). Non-interactive = log + proceed (CONTEXT.md).
}
supervisor.send(text = singlePrompt, /* … unchanged … */)
```
`[VERIFIED: send sites PassiveAiScanner.kt:911,1561,1647; currentSessionId AgentSupervisor.kt:143; scanner already uses currentSessionId at L451]`

### Non-interactive hook — McpToolContext.redactIfNeeded (detect + log + PROCEED)
```kotlin
// Source: McpToolContext.kt:53-57 — scan the FINAL redacted string, log on match, return it (never block).
fun redactIfNeeded(raw: String): String {
    val finalText = if (privacyMode == PrivacyMode.OFF) raw
        else Redaction.apply(raw, RedactionPolicy.fromMode(privacyMode), stableHostSalt = hostSalt)
    val tw = SecretTripwire.scan(finalText)
    if (tw.matched) {
        AuditLogger.emitGlobal(
            "secret_tripwire_detect",
            mapOf(
                "path" to "mcp",
                "sessionId" to (supervisor?.currentSessionId() ?: "none"),   // McpToolContext holds supervisor: AgentSupervisor?
                "shapeCategories" to tw.shapeCategories.toList().sorted(),
                "entropyScore" to Entropy.truncatedScore(tw.maxEntropyBitsPerChar),
            ),
        )
    }
    return finalText   // PROCEED — MCP output still returned (SC2)
}
```
`[VERIFIED: McpToolContext.kt:53-57 redactIfNeeded; supervisor field McpToolContext.kt:36; emitGlobal precedent McpTool.kt:226]`

### Audit event shape (SC3) — exact `emitGlobal`/`logEvent` call
```
type    : "secret_tripwire_allow"  (interactive allowlist)  |  "secret_tripwire_detect" (non-interactive)
payload : {
            "path"            : "chat" | "passive_scanner" | "mcp",
            "sessionId"       : <supervisor.currentSessionId() ?: "none">,   // chat: the session being started (Open Q1)
            "shapeCategories" : ["AWS access key", …]   // names only — never the matched value,
            "entropyScore"    : "4.7"                    // Entropy.truncatedScore — one decimal, never the token
          }
```
`emitGlobal` routes to `AuditLogger.logEvent(type, payload)` via the emitter registered in `App.kt:68`; `logEvent` already appends `ts`, `type`, `payload`, `payloadSha256` and respects `isEnabled()` (AuditLogger.kt:54-72). No new AuditLogger method required. `[VERIFIED: AuditLogger.kt:22-32,54-72; App.kt:68]`

## State of the Art

| Old Approach | Current Approach | When Changed | Impact |
|--------------|------------------|--------------|--------|
| Pre-send detection = Phase 13 PRIV-04 advisory banner (WARN, informational, no gate, chat-only) | Phase 15 escalates to a warn-with-confirmation **gate** (RISK) + entropy heuristic + **cross-path** coverage + **audit** | This phase | Same intent (surface what redaction missed) now enforced as a confirmation step on the chat path and audit-logged on all three |
| Entropy thresholds: detect-secrets defaults (hex 3.0 / base64 4.5) or truffleHog (hex 3.0 / base64 4.5, len 20) | (unchanged — these remain the accepted defaults) | — | Borrow the constants; both tools converged on hex 3.0 / base64 4.5 |

**Deprecated/outdated:**
- Nothing deprecated. Phase 13's `SecretShapes` and `SubtleNotice` RISK level were explicitly built to be consumed here.

## Assumptions Log

| # | Claim | Section | Risk if Wrong |
|---|-------|---------|---------------|
| A1 | truffleHog/detect-secrets default thresholds are base64 ≥ 4.5 and hex ≥ 3.0 bits/char with min token length 20 | Standard Stack / Pattern 2 | LOW — corroborated by two independent WebSearch results; both tools agree. If a project preference differs, change three `const` values. The 4.0 figure in CONTEXT.md is a reasonable middle ground; 4.5/3.0 (charset-specific) is more precise and matches the canonical tools. Final threshold is explicitly Claude's discretion (CONTEXT.md). |
| A2 | The chat-path audit event needs the session ID of the *session being started* in `startSessionFromContext`, which is created AFTER `confirm()` returns (L313) | Code Examples / Open Q1 | LOW — see Open Question 1 for two clean resolutions. Worst case the allowlist event logs `"none"` for sessionId, which is acceptable (the *detection* is the load-bearing audit; SC3 says "session ID" but does not fail if a pre-session allowlist has none). |
| A3 | `AuditLogger.emitGlobal` is the preferred audit channel for all three paths (vs. threading an `AuditLogger` instance) | Don't Hand-Roll / Code Examples | LOW — `emitGlobal` is already the cross-cutting pattern (`McpTool.kt:226`), registered in `App.kt:68`, and respects `isEnabled()`. If the planner prefers an injected instance for the dialog/scanner (both *could* hold one), that is equivalent; the event shape is unchanged. |
| A4 | Folding entropy into a single token-charset classification (`all { it in HEX/BASE64 }`) is sufficient; no need to compute entropy over a sliding window like truffleHog's diff blobs | Pattern 2 | LOW — the payload is small JSON/text, not a git diff; whole-token classification is simpler and adequate. If precision suffers, switch to per-substring scanning. |

**Note:** The threshold/length numbers (A1) and the tripwire object name/location are explicitly delegated to Claude's discretion by CONTEXT.md — they are design choices, not unverified facts, but are logged here so the planner sees them as tunable.

## Open Questions

1. **How does the chat-path allowlist audit get the session ID, given the session is created after `confirm()` returns?**
   - What we know: `startSessionFromContext` calls `confirm()` at L299, then `createSession(title)` at L313. So at confirm-time the session does not yet exist. `confirm()` currently takes no session/supervisor reference.
   - What's unclear: whether to (a) thread an optional `sessionId`/`supervisor` into `confirm()` and emit the allowlist event there, or (b) return a richer result and emit at the call site after the session is created, or (c) accept `sessionId = "none"` for the pre-session allowlist (the *detection* fires regardless; the gate is what matters).
   - Recommendation: **Option (b)** — keep `confirm()` pure-Boolean (preserves its single-caller contract, FLAG-15-03), and emit `secret_tripwire_allow` in `ChatPanel.startSessionFromContext` *after* `createSession(...)` when `confirm()` returned true AND a re-scan (or a passed-through flag) shows a match, using the freshly-created `session.id`. This keeps the dialog UI-only and the audit at a point that has a real session ID. Alternatively (c) is acceptable per SC3's intent (the allowlist decision is logged; a brand-new session legitimately has no prior ID). Planner decides; both satisfy SC3.

2. **Should the entropy threshold be a settings field or a code `const`?**
   - What we know: CONTEXT.md says "A settings toggle can disable it" (enable/disable) and the threshold is "tunable… at Claude's discretion".
   - What's unclear: whether tuning the *numeric threshold* needs to be user-facing.
   - Recommendation: ship the threshold as a `const` (4.5/3.0/20) for v1 — simplest, matches the SecretShapes "no user-facing tuning" precedent. Expose only the on/off toggle if any (CONTEXT.md mentions a disable toggle as optional). Numeric tuning can be a future enhancement.

3. **Does the existing `high-entropy hex key` SecretShapes shape (`[0-9a-fA-F]{32,}`) make the entropy hex-path redundant?**
   - What we know: `SecretShapes` already has a broad hex-32+ shape (line 81). The entropy hex threshold (3.0) would also catch high-entropy hex.
   - What's unclear: overlap is fine (both feed `matched`), but the entropy path adds value mainly for **base64** tokens with no known prefix (which SecretShapes does NOT cover).
   - Recommendation: keep both — the entropy path's real contribution is base64/non-hex high-entropy tokens. The hex overlap is harmless (de-duplicated into a single `matched` boolean). Document that the entropy heuristic primarily extends coverage to *unprefixed base64* secrets.

## Environment Availability

> Phase 15 is a pure in-process code change (new Kotlin sources + edits) with no new external tool/service/runtime dependency. The only "tool" is the existing Gradle build.

| Dependency | Required By | Available | Version | Fallback |
|------------|------------|-----------|---------|----------|
| Gradle (`./gradlew test`) | Build + unit tests | ✓ | wrapper (in repo) | — |
| JDK 21 | Compile target (JVM 21) | ✓ (project requires) | 21 | — |
| `kotlin.math` (stdlib) | Shannon entropy | ✓ | bundled w/ Kotlin | — (no fallback needed) |

**Missing dependencies with no fallback:** None.
**Missing dependencies with fallback:** None.

> NOTE (MEMORY.md): use `./gradlew test`, NOT `./gradlew ktlintCheck` — the latter fails standalone due to the pre-existing `generateBuildFlags` wiring defect.

## Validation Architecture

### Test Framework
| Property | Value |
|----------|-------|
| Framework | JUnit Jupiter 6.0.3 + `kotlin("test")` (`org.junit.jupiter.api.Test`, `Assertions.*`) |
| Config file | `build.gradle.kts` (`tasks.test { useJUnitPlatform() }`, lines 138/156) |
| Quick run command | `./gradlew test --tests "com.six2dez.burp.aiagent.redact.SecretTripwireTest" --tests "com.six2dez.burp.aiagent.redact.EntropyTest"` |
| Full suite command | `./gradlew test` |

### Phase Requirements → Test Map (SC = success criteria from CONTEXT.md/ROADMAP)
| SC | Behavior | Test Type | Automated Command | File Exists? |
|----|----------|-----------|-------------------|-------------|
| SC1 | A live AWS-format key (`AKIA…`) surviving BALANCED redaction makes `SecretTripwire.scan(...).matched == true` (synthetic high-entropy string also). The *dialog firing* is the logic; the actual modal render is human-UAT. | unit | `./gradlew test --tests "*SecretTripwireTest"` (`scan("…AKIAIOSFODNN7EXAMPLE…").matched` is true; `scan(highEntropyB64).matched` is true) | ❌ Wave 0 |
| SC2 | A legitimate base64 fuzz payload (≥20 chars, entropy ≥ 4.5) ALSO sets `matched == true` (so the gate appears) AND nothing in the detector/hook blocks — every hook returns/proceeds. Dismissibility (Cancel) is exercised at the unit level by asserting `confirm` returns `Boolean` and the non-interactive hooks always call through to `send`. | unit | `./gradlew test --tests "*SecretTripwireTest"` (assert `scan(legitBase64).matched`; assert non-interactive hook logic never throws/blocks) | ❌ Wave 0 |
| SC3 | "Send anyway" / detection writes an audit event with `sessionId` + a TRUNCATED entropy score + shape categories, NEVER the raw value. | unit | `./gradlew test` (assert `Entropy.truncatedScore(4.73) == "4.7"`; assert the audit payload map contains `sessionId`/`entropyScore`/`shapeCategories` and does NOT contain the input token substring) | ❌ Wave 0 |
| SC4 | Fires (detect + audit) on ALL THREE paths. | unit (per hook) | `./gradlew test` — one test per hook with a mocked `supervisor`/captured `emitGlobal`: chat (dialog logic), scanner (`sendSingleAnalysis`/single/batch), MCP (`redactIfNeeded`). Use `mockito-kotlin` to stub `supervisor.currentSessionId()` and capture the emitted event. | ❌ Wave 0 |
| SC5 | Preview dialog highlights the match (banner WARN→RISK) + "Send anyway" gate. Banner-level *selection logic* and option-label/default-focus *logic* are unit-testable; the actual Swing rendering (red strip, modal layout) is **human-UAT**. | unit (logic) + human-UAT (render) | `./gradlew test` (assert the branch picks `Level.RISK` + affirmative label `"Send anyway"` + default option == Cancel when `matched`); manual Burp smoke test for the visual | ❌ Wave 0 (logic); manual (render) |

### Sampling Rate
- **Per task commit:** `./gradlew test --tests "*SecretTripwireTest" --tests "*EntropyTest"` (fast, < a few seconds)
- **Per wave merge:** `./gradlew test` (full suite — 308+ tests currently green per STATE/blockers)
- **Phase gate:** Full `./gradlew test` green before `/gsd-verify-work`; plus one manual Burp smoke test for SC5 dialog render (warn-with-confirmation, RISK banner, Cancel default).

### Wave 0 Gaps
- [ ] `src/test/kotlin/com/six2dez/burp/aiagent/redact/SecretTripwireTest.kt` — covers SC1, SC2, SC3 (no-leak), SC4 (detector half)
- [ ] `src/test/kotlin/com/six2dez/burp/aiagent/redact/EntropyTest.kt` — bits/char correctness (e.g. uniform 16-char hex ≈ 4.0; a constant string ≈ 0.0), MIN_TOKEN_LEN gate, charset classification, `truncatedScore` format
- [ ] Per-hook tests (SC4) for the three paths — may live in existing scanner/MCP test files or a new `SecretTripwireHooksTest.kt`; use `mockito-kotlin` to stub `AgentSupervisor.currentSessionId()` and assert the audit event is emitted with the right keys and proceeds (send still called)
- [ ] Framework install: none — JUnit Jupiter + kotlin-test + mockito-kotlin already present (build.gradle.kts:49-52)

*Human-UAT (not automatable here): the actual `ContextPreviewDialog` Swing render — RISK red banner, "Send anyway" button, Cancel default focus — verified in a live Burp smoke test (per the existing manual-smoke practice noted in STATE blockers).*

## Security Domain

> `security_enforcement` not set to `false` in config → included. This phase IS a security control (PRIV-03), so the security framing is central.

### Applicable ASVS Categories

| ASVS Category | Applies | Standard Control |
|---------------|---------|-----------------|
| V5 Input Validation | partial | The tripwire validates the *outbound* payload (egress), not user input. The entropy regex split is linear/ReDoS-free; if a richer pattern is added, route via `SafeRegex` (50ms deadline). |
| V6 Cryptography | no (do-not-hand-roll relevance) | No crypto in this phase. Shannon entropy is information theory, not cryptography. The HKDF host-anonymization / SecretCipher are out of scope (Phase 12/13). Do NOT introduce any crypto. |
| V7 Errors & Logging | yes | The audit event MUST log category + truncated score + sessionId, and MUST NOT log the secret value (CLAUDE.md audit-defaults; UI-SPEC). `AuditLogger.logEvent` already hashes the payload (`payloadSha256`) and respects `isEnabled()`. |
| V8 Data Protection (egress / data-leak prevention) | **yes (core)** | This control's entire purpose: prevent a high-entropy secret from leaving Burp to a third-party AI without the user's informed, audited consent. Warn-with-confirmation + audit = the DLP control. |
| V14 Configuration | yes | Default ON (CONTEXT.md). If a disable toggle is added it must be user-visible and not silently weaken the control. |

### Known Threat Patterns for {Kotlin/Swing Burp extension, outbound secret-leak prevention}

| Pattern | STRIDE | Standard Mitigation |
|---------|--------|---------------------|
| Secret survives redaction and is exfiltrated to a third-party AI backend | Information Disclosure | Post-redaction tripwire (this phase): detect + warn-with-confirmation (chat) / detect + audit (scanner, MCP) |
| Tripwire echoes the secret into the audit log or UI banner (self-inflicted leak) | Information Disclosure | Category names + truncated numeric score only; never the matched token (CLAUDE.md; UI-SPEC; verified in `ScanResult` design) |
| User reflexively bypasses the gate (alert fatigue) | Repudiation / Information Disclosure | Conservative thresholds (4.5/3.0/20) to limit false positives; Cancel as default focus; audit every "Send anyway" so bypasses are attributable |
| Hard-block breaks a legitimate pentest payload (availability of the tool) | Denial of Service (of the workflow) | NEVER block — warn-only on all paths; non-interactive paths always proceed (SC2) |
| ReDoS in the entropy tokenizer on a large adversarial body | Denial of Service | Linear `[^A-Za-z0-9+/=_-]+` split; if extended, use `SafeRegex` 50ms deadline (Phase 13) |
| Tripwire silently disabled, weakening DLP without trace | Tampering / Repudiation | Default ON; disable toggle (if any) user-visible; `AuditLogger.isEnabled()` already gates audit emission |

## Sources

### Primary (HIGH confidence)
- In-repo source (read this session): `redact/SecretShapes.kt` (findSurviving, AWT-free contract, Phase 15 reuse KDoc), `redact/SafeRegex.kt` (AWT-free + ReDoS precedent), `ui/components/ContextPreviewDialog.kt` (confirm() Boolean contract, self-scan L60, default-Cancel L102), `ui/components/SubtleNotice.kt` (Level.RISK wiring L25,104-111), `audit/AuditLogger.kt` (logEvent L54, emitGlobal L26, isEnabled), `scanner/PassiveAiScanner.kt` (redaction L846-855, send sites L911/1561/1647, currentSessionId usage), `mcp/McpToolContext.kt` (redactIfNeeded L53-57, supervisor field), `mcp/McpRuntimeContextFactory.kt` (no AuditLogger field), `supervisor/AgentSupervisor.kt` (send/sendChat do NOT redact L359/L509, currentSessionId L143), `context/ContextCollector.kt` (redaction at capture build L52-53), `ui/ChatPanel.kt` (startSessionFromContext L274-332, sendMessage L446-549), `mcp/tools/McpTool.kt` (emitGlobal precedent L226), `App.kt` (registerGlobalEmitter L68), `build.gradle.kts` (test deps L49-52, useJUnitPlatform L138/156), `src/test/.../redact/SecretShapesTest.kt` (test style).
- `.planning/phases/15-pre-send-secret-tripwire/15-CONTEXT.md` (locked decisions, discretion).
- `.planning/phases/15-pre-send-secret-tripwire/15-UI-SPEC.md` (approved UI contract: Delta 1 RISK escalation, Delta 2 gate, FLAG-15-01..04).
- `.planning/REQUIREMENTS.md` (PRIV-03 wording, line 16).

### Secondary (MEDIUM confidence)
- Shannon-entropy secret-detection thresholds (truffleHog: base64 ≥ 4.5, hex ≥ 3.0, token len > 20; detect-secrets defaults base64 4.5 / hex 3.0) — corroborated across two independent WebSearch result sets (rafter.so, Yelp/detect-secrets repo, trufflesecurity issue #168, multiple truffleHog forks). Not fetched from canonical source this session (raw fetch 404'd); thresholds are consistent and widely cited.
  - https://rafter.so/blog/secrets/secret-scanning-tools-comparison
  - https://github.com/Yelp/detect-secrets/blob/master/detect_secrets/plugins/high_entropy_strings.py
  - https://github.com/trufflesecurity/truffleHog/issues/168

### Tertiary (LOW confidence)
- None relied upon. (The entropy constants are corroborated MEDIUM; the algorithm itself is standard information theory.)

## Metadata

**Confidence breakdown:**
- Standard stack: HIGH — every building block read in-repo this session; zero new deps; entropy is stdlib math.
- Architecture / hook points: HIGH — all three send sites and the redaction boundary traced to exact lines; confirmed `supervisor.send`/`sendChat` do not redact (so call-site payloads are final).
- Entropy thresholds: MEDIUM — domain-standard (truffleHog/detect-secrets), corroborated by two searches, not canonical-fetched; explicitly tunable per CONTEXT.md discretion.
- Pitfalls: HIGH — derived from reading the actual code paths (wrong-variable, default-focus, re-redaction, leak).
- Audit mechanism: HIGH — `emitGlobal` pattern verified in `App.kt` + `McpTool.kt`.

**Research date:** 2026-06-11
**Valid until:** 2026-07-11 (stable — in-repo code + a settled heuristic; re-verify only if Phase 13 `SecretShapes`/`SubtleNotice` or the send paths change before planning)
