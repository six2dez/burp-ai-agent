---
phase: 19-mega-file-split-docs
plan: 05
subsystem: documentation
tags: [docs, v0.9.0, readme, decisions, spec, adr, anthropic-backend, external-mcp]
dependency_graph:
  requires: []
  provides:
    - docs/anthropic-backend.md
    - docs/external-mcp-servers.md
    - DECISIONS.md (ADR-8 through ADR-12)
    - README.md (What's new v0.9.0, Anthropic row, external MCP mention)
    - SPEC.md (v0.9.0 update)
    - AGENTS.md (full backend list)
  affects:
    - README.md
    - SPEC.md
    - DECISIONS.md
    - AGENTS.md
tech_stack:
  added: []
  patterns:
    - Existing docs/ guide style (H1, lead, H2 sections, numbered steps, tables)
    - ADR format (Context / Decision / Consequences per existing DECISIONS.md)
key_files:
  created:
    - docs/anthropic-backend.md
    - docs/external-mcp-servers.md
  modified:
    - README.md
    - DECISIONS.md
    - SPEC.md
    - AGENTS.md
decisions:
  - "docs/anthropic-backend.md follows existing docs/ style: 25 lines, H1+Setup+Config+Privacy Notes"
  - "docs/external-mcp-servers.md follows existing docs/ style: 26 lines, H1+Setup+Transport Types+Security Notes"
  - "DECISIONS.md ADR-8 through ADR-12 added (AES-256-GCM, HKDF, Anthropic transport, external MCP trust boundary, BudgetGuard)"
  - "SPEC.md version updated v0.5.0 → v0.9.0; §7 token budget inserted; sections renumbered 8-11"
  - "AGENTS.md backends list updated to include all 12 v0.9.0 backends (was missing 6)"
metrics:
  duration: "~3 minutes"
  completed: "2026-06-16"
  tasks_completed: 2
  files_created: 2
  files_modified: 4
---

# Phase 19 Plan 05: DOC-02 User-Facing Docs (v0.9.0) Summary

User-facing documentation updated for the v0.9.0 feature set: two new docs/ setup guides, README What's new section, 5 new ADR entries in DECISIONS.md, and SPEC.md/AGENTS.md updated and committed from untracked state.

## Tasks Completed

| # | Task | Commit | Files |
|---|------|--------|-------|
| 1 | Write docs/anthropic-backend.md + docs/external-mcp-servers.md | `31f7cb6` | docs/anthropic-backend.md, docs/external-mcp-servers.md |
| 2 | Update README/DECISIONS/SPEC + track untracked files | `139acba` | README.md, DECISIONS.md, SPEC.md, AGENTS.md |

## What Was Built

**Task 1 — New docs/ guide pages (SC5):**

- `docs/anthropic-backend.md` (25 lines): Setup guide for the native Anthropic Messages API backend. Covers 4-step setup, configuration table (Model/API Key/Timeout), and 4 Privacy Notes covering MontoyaHttpTransport proxy visibility, AES-256-GCM key storage, redaction pipeline, and token-budget guardrails.
- `docs/external-mcp-servers.md` (26 lines): Setup guide for external MCP server integration. Covers 4-step setup, SSE vs stdio transport table, and 4 Security Notes covering encrypted auth tokens, SSRF warning, trust-boundary marker, and audit logging.

Both pages mirror the existing docs/ style (mcp-hardening.md / backend-troubleshooting.md): H1 title, 1-2 sentence lead, H2 sections with numbered steps, tables for structured data, no prose padding, target 40-80 lines.

**Task 2 — In-repo doc updates (SC4):**

- `README.md`: Added "What's new in v0.9.0" section (7 bullets with links), native Anthropic backend row in the backend roster (distinct from Claude CLI row), external MCP servers note with link in the MCP section, "Privacy and Security Notes" section under Operator Playbooks covering AES-256-GCM and HKDF, plus links to both new docs/ pages in the Operator Playbooks list.
- `DECISIONS.md`: Appended ADR-8 (AES-256-GCM secrets, `javax.crypto`, `ENC1:` prefix), ADR-9 (real HKDF, `HmacSHA256`, RFC 5869), ADR-10 (Anthropic via `MontoyaHttpTransport`, no vendored SDK), ADR-11 (external MCP trust-boundary marker, kotlin-sdk 0.5.0 Path A), ADR-12 (BudgetGuard, reversible CAP/WARN/OFF states).
- `SPEC.md`: Updated version v0.5.0 → v0.9.0; added Anthropic and additional backends to §4.4; updated §4.7 redaction table with HKDF/body/custom columns and HKDF explanation; inserted §7 token-budget guardrails; added external MCP client note to §6; added AES-256-GCM note to §9 (security model); renumbered sections 7-10 → 8-11.
- `AGENTS.md`: Added 6 missing backends to the backends list (Copilot CLI, NVIDIA NIM, Perplexity, generic OpenAI-compatible, Anthropic, Burp native AI) to match v0.9.0 shipped state.

All three previously untracked files (SPEC.md, DECISIONS.md, AGENTS.md) are now tracked by git.

## Deviations from Plan

None — plan executed exactly as written.

## Known Stubs

None. All documentation content reflects shipped v0.9.0 code as described in RESEARCH.md Section 6 (Docs Facts Inventory).

## Threat Flags

None. Documentation-only changes; no new network endpoints, auth paths, or executable surface introduced. Descriptions accurately reflect AES-256-GCM, real HKDF, and trust-boundary mechanisms as-shipped.

## Self-Check: PASSED

- `docs/anthropic-backend.md`: exists, H1 correct, Setup section present, AES-256-GCM mentioned 3 times
- `docs/external-mcp-servers.md`: exists, H1 correct, Setup section present, trust-boundary and encrypted mentioned 3 times each
- `README.md`: "What's new in v0.9.0" section present; Anthropic row distinct from Claude CLI row; external-mcp-servers link present (3 occurrences); AES-256-GCM and HKDF mentioned in Privacy and Security Notes
- `DECISIONS.md`: 12 ADR entries (7 original + 5 new); all 5 new ADRs contain required terms (AES-256-GCM, HKDF/HmacSHA256, MontoyaHttpTransport, trust-boundary marker, BudgetGuard)
- `SPEC.md`, `DECISIONS.md`, `AGENTS.md`: tracked by git (confirmed `git status` shows 0 untracked for these files)
- Commits `31f7cb6` and `139acba` confirmed in `git log --oneline -4`
