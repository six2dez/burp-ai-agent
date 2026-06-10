---
phase: 12-secrets-at-rest-transport-security
plan: 04
subsystem: ui
tags: [ssrf, url-classifier, inetaddress, swing, backend-config, kotlin]

requires:
  - phase: none
    provides: independent SSRF advisory feature
provides:
  - SsrfGuard.isPrivateOrLinkLocal pure URL classifier (RFC-1918, link-local, cloud-metadata)
  - Inline non-blocking SSRF warning in BackendConfigPanel shown on Save
affects: [BackendConfigPanel, SettingsPanel save flow]

tech-stack:
  added: [none]
  patterns: [pure network-free address-range classification; advisory non-blocking UI warning]

key-files:
  created:
    - src/main/kotlin/com/six2dez/burp/aiagent/util/SsrfGuard.kt
    - src/test/kotlin/com/six2dez/burp/aiagent/util/SsrfGuardTest.kt
  modified:
    - src/main/kotlin/com/six2dez/burp/aiagent/ui/panels/BackendConfigPanel.kt

key-decisions:
  - "Classifier only inspects literal IPs (IPv4 dotted-quad / IPv6 colon-hex); hostnames return false — no DNS per D-01."
  - "Manual authority fallback so unbracketed IPv6 literals (http://fe80::1) are classified even though URI.getHost returns null for them."
  - "Single shared warning label in the panel SOUTH bar (outside CardLayout); hidden by default, non-blocking."

patterns-established:
  - "Pattern: address-range SSRF classification via InetAddress.isSiteLocalAddress/isLinkLocalAddress with loopback explicitly excluded."

requirements-completed: [SEC-03]

duration: 14min
completed: 2026-06-10
---

# Phase 12: SSRF Advisory — Plan 04 Summary

**Pure network-free SsrfGuard flags private/link-local/cloud-metadata backend URLs, surfaced as an inline non-blocking warning in BackendConfigPanel on Save; loopback is excluded.**

## Performance

- **Duration:** ~14 min
- **Tasks:** 2 (Task 1 TDD, Task 2 UI)
- **Files modified:** 1 modified + 2 created

## Accomplishments
- `SsrfGuard.isPrivateOrLinkLocal(url)`: classifies literal IPs only — RFC-1918 (site-local), link-local (169.254.x.x, fe80::/10), and 169.254.169.254 cloud-metadata → true; loopback, public, blank, malformed, and hostnames → false. No DNS, no network, never throws.
- Robust host extraction: uses `URI.host`, with a manual authority parse fallback so unbracketed IPv6 literals are still classified.
- Wired a shared `ssrfWarningLabel` (DesignTokens.Colors.statusWarning) into the BackendConfigPanel SOUTH bar; hidden by default.
- `checkAndShowSsrfWarning(urls)` toggles the label; called at the start of `currentBackendSettings()` (fires on Save via SettingsPanel). Non-blocking — settings save regardless.
- 9 unit tests cover all classification cases including the IPv6 link-local and cloud-metadata cases.

## Task Commits
1. **Task 1: SsrfGuard pure classifier (TDD)** + **Task 2: BackendConfigPanel inline warning** — see `feat(12): SSRF backend URL warning` commit.

## Files Created/Modified
- `src/main/kotlin/com/six2dez/burp/aiagent/util/SsrfGuard.kt` — pure classifier.
- `src/main/kotlin/com/six2dez/burp/aiagent/ui/panels/BackendConfigPanel.kt` — ssrfWarningLabel + checkAndShowSsrfWarning hooked into currentBackendSettings().
- `src/test/kotlin/com/six2dez/burp/aiagent/util/SsrfGuardTest.kt` — 9 classification tests.

## Decisions Made
- Placed the single shared warning label in the panel's SOUTH bar (outside the CardLayout) per the plan's explicitly-endorsed simpler approach, rather than duplicating a row in each per-backend card. It is visible on whichever card is showing once the flag fires.

## Deviations from Plan
None of substance. `checkAndShowSsrfWarning(...)` is invoked at the start of `currentBackendSettings()` (block body) rather than literally after constructing the return value — same effect on every Save, and avoids an intermediate local.

## Issues Encountered
None. Full `./gradlew test -x ktlintCheck` suite passes.

## User Setup Required
None.

## Human UAT (visual smoke test — cannot be automated headless)
- In Burp, open backend settings, type `http://192.168.1.10` in the Ollama base URL and click Save → the inline warning label appears; the setting still saves.
- Type `http://127.0.0.1:11434` → no warning (loopback excluded).

## Next Phase Readiness
- All three SEC requirements (SEC-01/02/03) for Phase 12 are now implemented.

---
*Phase: 12-secrets-at-rest-transport-security*
*Completed: 2026-06-10*
