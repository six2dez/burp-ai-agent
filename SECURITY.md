# Security Policy

## Supported Versions

Only the latest minor release receives security updates.

| Version | Supported |
| ------- | --------- |
| 0.5.x   | Yes       |
| < 0.5   | No        |

## Reporting a Vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

Report privately via [GitHub Security Advisories](https://github.com/six2dez/burp-ai-agent/security/advisories/new).

### What to include

- Affected version(s).
- Reproduction steps or proof-of-concept.
- Potential impact (e.g. credential exposure, remote code execution, data exfiltration to third-party LLMs).
- Any suggested mitigations.

### Response timeline

- Acknowledgment within 5 business days.
- Initial triage within 10 business days.
- Fix or disclosure decision within 30 days for high/critical, 90 days for medium/low.

### Scope

In scope:

- The `burp-ai-agent` extension code.
- MCP server and tool dispatcher.
- Redaction pipeline.
- Backend adapters (HTTP and CLI).
- Audit logging and persistent prompt cache.

Out of scope:

- Vulnerabilities in Burp Suite itself (report to [PortSwigger](https://portswigger.net/security)).
- Vulnerabilities in third-party AI providers (Anthropic, OpenAI, Google, NVIDIA, GitHub, etc.).
- Vulnerabilities in local model runners (Ollama, LM Studio).
- Issues requiring physical access to the user's machine.

## Security Model

The extension runs inside Burp Suite on the user's machine. The threat model assumes:

- Burp Suite preferences are accessible only to the local user.
- API keys and credentials are stored via Burp's standard preferences storage.
- The MCP server binds to `127.0.0.1` by default; external access requires explicit opt-in with a bearer token and optional TLS.
- Privacy modes (STRICT / BALANCED / OFF) control what request and response data is sent to AI backends.

See [`docs/mcp-hardening.md`](docs/mcp-hardening.md) for operational hardening guidance and [`docs/ui-safety-guide.md`](docs/ui-safety-guide.md) for safe-use recommendations.
