# Phase 15: Pre-Send Secret Tripwire - Context

**Gathered:** 2026-06-11
**Status:** Ready for planning

<domain>
## Phase Boundary

A **post-redaction** tripwire (PRIV-03) that scans the FINAL outbound payload — after the redaction pipeline has run — for secrets/high-entropy strings that survived, and warns the user before the payload leaves Burp. The warning is **warn-with-confirmation, never a hard-stop**, so legitimate pentest payloads are never silently blocked.

Fires on all three outbound paths (SC4): ChatPanel interactive send, PassiveAiScanner batch/single sends, and MCP tool output via `McpToolContext.redactIfNeeded()`. Reuses Phase 13's shared `SecretShapes` curated set as the known-shape detector. Allowlist decisions ("send anyway") are audit-logged (SC3) and the match is visibly highlighted in the existing context preview dialog (SC5).

Out of scope: changing the redaction pipeline itself (Phase 13); blocking sends.
</domain>

<decisions>
## Implementation Decisions

### Detection method
- Fire on BOTH: (a) `SecretShapes.findSurviving(...)` known-shape matches (Phase 13 set), AND (b) a Shannon-entropy heuristic for unknown high-entropy tokens (tokens ≥ ~20 chars with entropy ≥ ~4.0 bits/char — tunable; the exact threshold/length at Claude's discretion). The entropy score is computed regardless because SC3 logs a (truncated) entropy score.
- Keep the tripwire detector AWT-free and in/near the `redact` package so all three paths and tests can reuse it (mirrors `SecretShapes`/`SafeRegex`).

### Non-interactive paths (PassiveAiScanner, MCP)
- There is no user to confirm. On a tripwire hit, **audit-log the detection and PROCEED** with the (already-redacted) send — never block (honors SC2 "never hard-blocked"). Only the interactive ChatPanel path shows an actual confirmation dialog. SC4's "fires on all three paths" = detect + audit-log on all three; the modal confirmation is ChatPanel-only.

### Default & scope
- **ON by default** — warn-only and non-blocking, so low-risk. Scans the FINAL redacted payload regardless of privacy mode (it is the last line of defense, after redaction). A settings toggle can disable it. (STRICT/BALANCED/OFF all still produce a final payload to scan; the tripwire runs on whatever is about to be sent.)

### Interactive confirmation UX (SC5)
- **Extend the existing `ContextPreviewDialog`** (do NOT add a new modal). Phase 13's survived-secret WARN banner becomes the tripwire highlight; `confirm(...)` gains a "Send anyway / Cancel" gate that appears only when a tripwire match is present. The dialog message: a warn-with-confirmation prompt such as "This payload appears to contain a high-entropy value — send anyway?". Choosing "Send anyway" = the allowlist action that gets audit-logged.

### Audit logging (SC3)
- On "send anyway" (allowlist), write an audit event via the existing `AuditLogger` containing the session ID and a **truncated** entropy score (and the matched shape category / a redacted indicator — NEVER the raw matched secret value). Reuse `AuditLogger.logEvent(...)`. The allowlist action is also visibly flagged in the preview dialog per PRIV-03.

### Claude's Discretion
- Exact entropy threshold + min token length, the tripwire object's name/location, how the non-interactive paths surface the audit event, and the precise dialog wording/highlight rendering — at Claude's discretion, guided by the `SecretShapes`/`SafeRegex` AWT-free precedent and the existing `ContextPreviewDialog`/`AuditLogger` APIs.
</decisions>

<code_context>
## Existing Code Insights

### Reusable Assets
- `redact/SecretShapes.kt` (Phase 13) — `object SecretShapes` with `shapes: List<Shape(category, regex)>` and `findSurviving(text): Set<String>`. The tripwire's known-shape detector; its KDoc already anticipates "Phase 15 tripwire reuses this same object."
- `redact/SafeRegex.kt` (Phase 13) — AWT-free precedent for a headless, testable redact-package helper; the entropy/tripwire helper follows the same style.
- `ui/components/ContextPreviewDialog.kt` — `confirm(...)` pre-send preview; already has the Phase 13 survived-secret SubtleNotice banner. Phase 15 turns it into the warn-with-confirmation gate (SC5).
- `audit/AuditLogger.kt` — `logEvent(...)` for the allowlist audit (SC3); follows the "log shape/score, never the secret value" discipline.
- Three send paths: `ui/ChatPanel.kt` (interactive — shows the dialog), `scanner/PassiveAiScanner.kt` (batch/single — log+proceed; NOTE: Phase 19 later moves these methods, so the hooks must land here first), `mcp/McpToolContext.kt` `redactIfNeeded()` (MCP tool output — log+proceed).

### Established Patterns
- AWT-free pure detectors in the `redact` package (SecretShapes, SafeRegex), unit-tested headless.
- Pre-send preview + confirmation via `ContextPreviewDialog.confirm`.
- Audit events via `AuditLogger.logEvent`, hashes/scores only unless verbose (CLAUDE.md audit defaults).
- Redaction runs before send on all three paths; the tripwire runs AFTER redaction on the same payload.

### Integration Points
- New tripwire detector (redact package) consumed by ChatPanel (dialog gate), PassiveAiScanner (log+proceed), McpToolContext.redactIfNeeded (log+proceed).
- `ContextPreviewDialog.confirm` — confirmation gate + highlight.
- `AuditLogger.logEvent` — allowlist audit with session ID + truncated entropy score.
</code_context>

<specifics>
## Specific Ideas

- SC1 concrete: a body with a live AWS-format key (`AKIA…`) surviving BALANCED redaction triggers the confirmation dialog before the AI backend — unit-tested with a synthetic high-entropy string.
- SC2 concrete: a legitimate base64 fuzz payload also shows the dialog; the user can dismiss to proceed; never hard-blocked.
- SC3 concrete: "send anyway" writes an audit event with the session ID + truncated entropy score.
- SC4: fires on all three outbound paths.
- SC5: confirmation visible in the context preview dialog with the match highlighted.
- The tripwire scans the FINAL (post-redaction) payload — it surfaces what the redaction pipeline missed, the same intent as Phase 13's PRIV-04 banner, now escalated to a confirmation gate + cross-path coverage + audit.
</specifics>

<deferred>
## Deferred Ideas

- None — discussion stayed within phase scope. (The QUAL-01 mega-file split that later moves the PassiveAiScanner methods is Phase 19; the tripwire hooks must be committed here first.)
</deferred>
