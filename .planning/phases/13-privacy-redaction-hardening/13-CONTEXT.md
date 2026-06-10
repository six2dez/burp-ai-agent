# Phase 13: Privacy & Redaction Hardening - Context

**Gathered:** 2026-06-10
**Status:** Ready for planning

<domain>
## Phase Boundary

Make the redaction pipeline's privacy claims match its implementation. Four deliverables, all touching the redaction/privacy surface (`Redaction.kt`, `PrivacyConfigPanel.kt`, `ContextPreviewDialog.kt`, `ContextCollector.kt`):

1. **PRIV-01** — `Redaction.anonymizeHost` switches from `MessageDigest.getInstance("SHA-256")` to real HKDF (`Mac.getInstance("HmacSHA256")`, extract-then-expand). The SPEC's privacy guarantee then matches the code; existing STRICT-mode tests stay green (updated to new expected values).
2. **PRIV-02** — Redaction catches secrets in request/response **bodies**, not just header lines: the leading field of an `x-www-form-urlencoded` body, known-sensitive JSON keys, and a user-configurable custom pattern list, with a ReDoS/perf guard on large bodies.
3. **PRIV-04** — The redaction preview dialog flags when a known secret shape (shared curated set, later reused by the Phase 15 tripwire) survived redaction, so the user sees what the pipeline missed before sending.
4. Unit tests cover the STRICT/BALANCED/OFF matrix for the new body-redaction paths and the custom-pattern ReDoS guard.

Out of scope: the pre-send tripwire itself (Phase 15, PRIV-03) — Phase 13 only introduces the shared curated pattern set the tripwire will consume.
</domain>

<decisions>
## Implementation Decisions

### Host Anonymization (HKDF) — PRIV-01
- Keep the output format `host-<12hex>.local` — swap only the internal algorithm so the format, call sites, and forward/reverse map semantics stay stable.
- Use real HKDF: HMAC-SHA256 extract-then-expand with a fixed app-specific info label (e.g. `burp-ai-agent:host`); reuse the existing `stableHostSalt` as the HKDF salt/IKM input.
- No persistence migration — `hostForwardMap`/`hostReverseMap` are in-memory `ConcurrentHashMap`s; existing salt rotation (`rotateSaltBtn` → `clearMappings`) already handles invalidation. Existing STRICT tests are updated to the new expected hash values.

### Body Redaction Scope — PRIV-02
- Redact sensitive-named fields **anywhere** in an `x-www-form-urlencoded` body, including the leading field (which has no `?`/`&` prefix and is the documented gap). Reuse/extend the existing sensitive-key vocabulary from `urlTokenParamRegex`.
- Also redact known-sensitive **JSON body keys** (e.g. `"api_key":"…"`, `"token":"…"`) — AI context payloads are frequently JSON.
- Apply body redaction to **both request and response** bodies (the goal says request *and* response; `ContextCollector` already calls `Redaction.apply` on the response string).
- Large-body guard: a size cap (skip/short-circuit bodies beyond ~1 MB) **plus** a per-pattern ~50 ms timeout to bound ReDoS and worst-case regex cost. The same 50 ms timeout primitive is reused by the custom-pattern validator.

### Custom Pattern UX & Storage — PRIV-02 / PRIV-04
- Input UX: one-regex-per-line text area in the Privacy settings panel (matches the existing `PrivacyConfigPanel` form-grid style; simplest to persist).
- Validation on **save**: check regex syntax AND run a ~50 ms ReDoS timeout against an adversarial test string; reject patterns that fail to compile or time out, with inline error feedback. Valid patterns persist via the existing config/secret-aware preference store.
- Replacement token: `[REDACTED]`, consistent with built-in redactions.
- Active in **STRICT + BALANCED** (folded into the `redactTokens` policy branch); inactive in OFF.

### Survived-Secret Indicator — PRIV-04
- Location: inside the existing `ContextPreviewDialog` (the pre-send preview the user already sees).
- Presentation: a **non-blocking** warning banner showing a count and which shape(s) matched — informational, never a hard stop.
- Pattern set: introduce a **shared curated `SecretShapes`** object now (high-confidence secret shapes: `sk-…`, `AKIA…`, `ghp_…`, JWT, generic high-entropy key forms). Phase 15's tripwire reuses the same set — single source of truth.
- Scan target: the **post-redaction** context only — the indicator's purpose is to reveal what survived the pipeline, not what was caught.

### Claude's Discretion
- Exact curated shapes in `SecretShapes`, the regex vocabulary for sensitive form/JSON keys, the precise HKDF expand length (≥ the 6 bytes currently truncated), and the timeout-enforcement mechanism (e.g. interruptible matcher vs bounded executor) are at Claude's discretion, guided by codebase conventions and the success criteria.
</decisions>

<code_context>
## Existing Code Insights

### Reusable Assets
- `src/main/kotlin/.../redact/Redaction.kt` — `object Redaction` with `apply(raw, policy, stableHostSalt, recordMapping)`, `anonymizeHost`, `deAnonymizeHost`, `clearMappings`. `RedactionPolicy.fromMode(PrivacyMode)` maps STRICT/BALANCED/OFF to `stripCookies`/`redactTokens`/`anonymizeHosts` flags. Custom-pattern + body redaction extend the `redactTokens` branch.
- `src/main/kotlin/.../context/ContextCollector.kt:52-53` — already calls `Redaction.apply(req, …)` and `Redaction.apply(resp, …)` over the **full** HTTP message strings (headers + bodies), so body coverage is a matter of pattern reach, not a new call site.
- `src/main/kotlin/.../ui/panels/PrivacyConfigPanel.kt` — `ConfigPanel` with a `formGrid()` of injected components (privacyMode, auditEnabled, rotateSaltBtn, privacyNotice, saveFeedback…). Custom-pattern text area + validation feedback slot in here.
- `src/main/kotlin/.../ui/components/ContextPreviewDialog.kt` — `confirm(...)` builds the pre-send preview ("Context (as will be sent, after redaction)"). PRIV-04 banner attaches here.
- `src/test/kotlin/.../redact/RedactionTest.kt` — existing STRICT/BALANCED/OFF coverage; extend for HKDF expected values, body paths, ReDoS guard.

### Established Patterns
- Redaction is hand-curated regexes applied over the raw message string; header regexes are line-anchored `(?im)^header:…$`, URL token regex keys off `[?&]param=`. New body/JSON patterns follow the same curated-regex style (CLAUDE.md: "hand-curated regex").
- Privacy modes are a 3-value enum (`PrivacyMode`) with a policy mapping; new behavior gates on `policy.redactTokens`.
- Secrets at rest are encrypted via `config/SecretCipher.kt` (Phase 12) — custom patterns are not secrets but persist through the same preference layer.

### Integration Points
- `Redaction.apply` (called from `ContextCollector`) — body + custom-pattern redaction lands here.
- `PrivacyConfigPanel` — custom-pattern input + validation UI.
- `ContextPreviewDialog.confirm` — survived-secret banner.
- New `SecretShapes` curated set — consumed by PRIV-04 here and the Phase 15 tripwire later.
</code_context>

<specifics>
## Specific Ideas

- SC1 is prescriptive: `anonymizeHost` MUST use `Mac.getInstance("HmacSHA256")`, not `MessageDigest.getInstance("SHA-256")`.
- SC2 concrete test: `apikey=sk-abc123&...` as the leading field of an `x-www-form-urlencoded` body must be redacted in STRICT and BALANCED.
- SC3 concrete test: a user-entered custom regex is validated against an adversarial ReDoS string with a 50 ms timeout before being accepted.
- SC4: the preview dialog flags survived known-secret shapes using the same curated set as the tripwire.
- REQUIREMENTS PRIV-01 leaves "HKDF vs corrected docs" to plan-phase, but the roadmap success criterion has resolved it to **real HKDF** — follow the success criterion.
</specifics>

<deferred>
## Deferred Ideas

- The pre-send secret tripwire that scans the final outbound payload and warns before send (PRIV-03) — Phase 15. Phase 13 only provides the shared `SecretShapes` set it will consume.
- Bounded/cleared host-anonymization maps as a reliability concern (REL-02) — Phase 17.
- **Interactive "test custom pattern against a sample request" tester** (literal PRIV-04 requirement text) — explicitly OUT of scope for Phase 13 per maintainer decision (2026-06-10). PRIV-04's "test custom patterns" is delivered as save-time syntax + ReDoS-timeout validation (ROADMAP SC3) plus the survived-secret preview banner; a live sample-request tester was not requested. Revisit in a future phase if user demand surfaces.
</deferred>
