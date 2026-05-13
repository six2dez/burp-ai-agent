<!-- GSD:project-start source:PROJECT.md -->
## Project

**Burp AI Agent**

A production-grade Burp Suite extension (Kotlin + Montoya API) that embeds an AI reasoning agent with pluggable backends (local + cloud), enforces privacy redaction on outbound traffic, records an auditable history, and exposes Burp operations to external AI agents over the Model Context Protocol (MCP). Targets security professionals running Burp Community or Professional on macOS / Linux / Windows.

**Core Value:** Bring modern AI to a real security workflow **without** leaking sensitive traffic to third-party providers — privacy controls and an audit trail are non-negotiable, AI capability is additive.

### Constraints

- **Tech stack**: Kotlin (JVM 21), Gradle Kotlin DSL, Burp Montoya API — fixed by ADR-1/2/3.
- **Target**: Burp Suite Community + Professional 2023.12+, cross-platform (macOS / Linux / Windows).
- **Network**: MCP server binds to `127.0.0.1` by default; external access requires explicit opt-in + bearer token + optional TLS.
- **Distribution**: single fat JAR via `./gradlew shadowJar`; artifact name `Custom-AI-Agent-<version>.jar` (renamed from `Burp-AI-Agent-*` in `v0.6.0`).
- **Privacy**: STRICT / BALANCED / OFF must all stay user-visible and pre-flight; redaction is hand-curated regex + HKDF host anonymization in STRICT.
- **License**: MIT — keep dependencies compatible.
- **Audit defaults**: disabled by default, opt-in verbose mode; hashes only unless verbose is on.
- **Languages in code & comments**: English only (AGENTS.md non-negotiable).
<!-- GSD:project-end -->

<!-- GSD:stack-start source:STACK.md -->
## Technology Stack

Technology stack not yet documented. Will populate after codebase mapping or first phase.
<!-- GSD:stack-end -->

<!-- GSD:conventions-start source:CONVENTIONS.md -->
## Conventions

Conventions not yet established. Will populate as patterns emerge during development.
<!-- GSD:conventions-end -->

<!-- GSD:architecture-start source:ARCHITECTURE.md -->
## Architecture

Architecture not yet mapped. Follow existing patterns found in the codebase.
<!-- GSD:architecture-end -->

<!-- GSD:skills-start source:skills/ -->
## Project Skills

No project skills found. Add skills to any of: `.claude/skills/`, `.agents/skills/`, `.cursor/skills/`, `.github/skills/`, or `.codex/skills/` with a `SKILL.md` index file.
<!-- GSD:skills-end -->

<!-- GSD:workflow-start source:GSD defaults -->
## GSD Workflow Enforcement

Before using Edit, Write, or other file-changing tools, start work through a GSD command so planning artifacts and execution context stay in sync.

Use these entry points:
- `/gsd-quick` for small fixes, doc updates, and ad-hoc tasks
- `/gsd-debug` for investigation and bug fixing
- `/gsd-execute-phase` for planned phase work

Do not make direct repo edits outside a GSD workflow unless the user explicitly asks to bypass it.
<!-- GSD:workflow-end -->



<!-- GSD:profile-start -->
## Developer Profile

> Profile not yet configured. Run `/gsd-profile-user` to generate your developer profile.
> This section is managed by `generate-claude-profile` -- do not edit manually.
<!-- GSD:profile-end -->
