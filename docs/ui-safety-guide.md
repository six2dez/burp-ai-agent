# UI Safety Guide

This runbook covers safe operation of scanner and backend controls from the UI.

## Active Scanner Safety

1. Verify scope is configured before enabling active scanning.
2. Start with `SAFE` risk level.
3. IDOR/BOLA tests replay a request whose method is not GET, HEAD or OPTIONS, and the 403 bypass
   tries POST and PUT, only at `DANGEROUS`. Below it the IDOR target is skipped and the Output tab
   says why.
4. Confirm queue size and backpressure indicators before bulk actions.
5. Use targeted tests before broad scans.

## Passive Scanner Cost/Safety

1. Keep **Scope Only** enabled.
2. Tune body/header/parameter caps for cloud backends.
3. Use dedup and prompt cache controls to reduce repeated analysis.
4. Review findings before promotion into reports.

## Backend Health

1. Use **Test connection** after changing backend settings.
2. Treat `AI: Degraded` as actionable diagnostics state.
3. Inspect extension output/errors for CLI exit codes and HTTP failures.

## MCP Safety

1. Keep unsafe tools disabled unless required.
2. Disable MCP when not actively using external clients.
3. Restrict tool exposure per workflow.

## Tool-Call Confirmation

When the AI wants to run a Burp tool, a **tool-approval card** appears inline in the chat transcript — not as a pop-up dialog, so it never steals focus and it stays in the transcript as a record of what you decided. The card names the tool, shows the arguments the model supplied, and offers up to four actions.

1. **Approve once** — run this call now. The AI must ask again the next time it wants the same tool.
2. **Approve for session** — run this call and every later call to *this* tool for the rest of this chat session, without asking again.
3. **Deny** — do not run this call. The AI is told the call was not authorised, is instructed not to retry, and continues with what it already has. It does not receive an error, so a denial does not look like a malfunction it should work around.
4. **Deny for session** — deny this call and every later call to this tool for the rest of this chat session.
5. Read the arguments before approving. The card truncates long arguments for display only — **the full arguments are sent to the tool if you approve**.
6. Only some tools offer the two session actions. A tool classified as confirm-every-time (this includes any tool name the catalog does not recognise, and every external `ext:`-namespaced tool) asks on every single call, and offers **Approve once** / **Deny** only. That is deliberate: an unrecognised name must never inherit a silent tier.
7. **Approve for session** is scoped to one chat session. **Clear Chat** discards it, as does starting a new session — an approval you granted while reviewing one target must not run silently against the next.
8. Approvals never persist. They are held in memory only, so restarting Burp, reloading the extension or switching Burp project all clear them and the AI must ask again.
9. Read-only tools with bounded output run with no card at all. Tools that return bulk attacker-controlled traffic (`proxy_http_history`, `site_map`, `scanner_issues`) are *not* in that group even though they are read-only — what they return goes into model context, so they ask.
10. Every decision, including automatic runs and denials, is written to the audit log and to Burp's **Output** tab. Audit logging is off by default, so the Output line is the record most users will see; enable audit logging in **Settings** if you need the durable JSONL trail.
11. This is independent of **Unsafe Mode**. Unsafe Mode decides whether a tool may ever run at all; the confirmation tier decides whether the AI may run it *without asking you*. Leaving Unsafe Mode off does not remove the need to read these cards, and approving a card does not enable an unsafe tool.

Design rationale and threat model: [`DECISIONS.md`](../DECISIONS.md) ADR-15.
