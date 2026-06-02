# Phase 08 — `/reopen` reply for PortSwigger issue #231

## ✅ Public comment to paste on the issue (then it auto-reopens)

> Thanks for the detailed feedback — all four points are addressed in the latest build:
>
> - **Name:** confirmed, the extension is **"Custom AI Agent"** (distinct from Burp AI).
>
> - **MCP — no duplication of the official server:** the BApp Store build no longer exposes any generic Montoya-API tools over MCP. Those tools are gated out of the store artifact entirely via a compile-time flag (`-PstoreBuild`), so they are never registered and cannot be called. The MCP server now exposes **only tools that hook into this extension's own capabilities**: AI analysis, privacy-redaction preview, AI passive scan + recent AI findings, audit-trail query, AI-backend listing, plus AI-issue creation and extension status. For generic Burp-over-MCP operations, users use your official **MCP Server**. Happy to raise a PR against `PortSwigger/mcp-server` for any genuinely-novel generic capability you'd find useful.
>
> - **AI enabled check:** every AI-provider call made by the MCP AI tools now verifies `ai.isEnabled()` before issuing a request, and Burp AI remains the default provider.
>
> - **Passive scanning:** migrated from a `ProxyResponseHandler` to the Montoya **`PassiveScanCheck`** mechanism (`doCheck(...)`, registered via `api.scanner().registerPassiveScanCheck(check, ScanCheckType.PER_REQUEST)`), so findings flow through the scanner with proper scoping and issue reporting. The old proxy-response handler has been removed.
>
> /reopen

---

## 🔒 Developer notes — NOT for posting (internal)

**Before posting, run the manual smoke test (Plan 08-04 Task 2):**
- **Burp Pro** — load `Custom-AI-Agent-0.8.0.jar` (store build): open the MCP panel / `tools/list` → confirm **only the native AI tools** appear (no proxy history, repeater, scanner, scope, etc.). Toggle **Use AI off** → confirm `ai_analyze` is blocked with the "unavailable" message. Run a passive scan → confirm AI findings register via the scanner.
- **Burp Community** — load `Custom-AI-Agent-full-0.8.0.jar`: does the **"Use AI"** checkbox appear, and do third-party backends (Claude CLI / Ollama / OpenAI-compatible) still start when AI is off? Record the answer — it decides the AI-gate breadth.

**AI-gate decision (narrow, by design):** the gate is applied to the AI-calling **MCP tools** (and the existing `burp-ai` backend lifecycle), but **not** to `startOrAttach()` / `send()` for third-party backends, because `api.ai().isEnabled()` is `false` on Burp Community and gating all backend lifecycles would kill Claude CLI / Ollama / OpenAI there — violating the project's Community-support constraint (`AgentSupervisor.kt:107-141`).

**Escalation path if the reviewer rejects the narrow gate:**
1. After the Community check above, if Community exposes the "Use AI" toggle → broaden the gate to `startOrAttach()` / `send()` for non-`burp-ai` backends (full compliance).
2. If broadening breaks Community non-AI backends → fall back to the source-set exclusion option recorded in `08-CONTEXT.md` Deferred Ideas (compile the generic tool code out of the store artifact entirely).

**Artifacts produced:**
- Store: `Custom-AI-Agent-0.8.0.jar` (`BuildFlags.STORE_BUILD = true` → native tools only)
- Full: `Custom-AI-Agent-full-0.8.0.jar` (`BuildFlags.STORE_BUILD = false` → all tools, for GitHub releases)

**Status:** all autonomous code work for Phase 08 is complete and verified (308 tests green; both JARs build with the correct `STORE_BUILD` constant). Only the manual Burp smoke test + posting this comment remain.
