# Security Policy

## Supported Versions

Only the latest minor release receives security updates. `1.0.1` is the current release of the
supported `1.0.x` line. `1.0.0` carries the advisories under [Fixed in 1.0.1](#fixed-in-101) below,
so the remedy for a `1.0.0` install is to upgrade to `1.0.1`. The `0.9.x` line is no longer
supported: it carries every advisory below unfixed, so upgrade rather than wait for a backport.

| Version | Supported                                                          |
| ------- | ------------------------------------------------------------------ |
| 1.0.1   | Yes                                                                |
| 1.0.0   | No: carries the 1.0.1 advisories below unfixed; upgrade to 1.0.1   |
| 0.9.x   | No: carries SEC-04, PRIV-05 and the 1.0.1 advisories; upgrade      |
| < 0.9   | No                                                                 |

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

## Security Advisories

### Fixed in 1.0.1

The issues below were found in a full review of `1.0.0` on 2026-10-08 and are fixed in `1.0.1`.
Each one was confirmed against the shipped code, and each fix ships with a test that fails on the
old code. **No CVE and no GHSA identifier has been issued for any of them.** The CHANGELOG entry for
`1.0.1` has the technical detail; this section says who is affected and what to do.

#### ADV-101-1: audit files held the MCP token, header credentials and full prompts in clear

**Affected:** 1.0.0 and earlier, only with Audit logging turned on · **Fixed in:** 1.0.1 ·
**Severity:** high

`~/.burp-ai-agent/audit.jsonl` and `~/.burp-ai-agent/bundles/` recorded the MCP server token,
custom header values such as `X-Custom-Auth` or `apikey`, and the full prompt, captured context,
response chunks and provider error text, contrary to the documented hashes-only default. On macOS
and Linux the files were created with the default umask (typically readable by other local
accounts). In `1.0.1` records keep only header and variable names, bodies are hashed unless the new
Verbose audit switch is on, and files are owner-only.

**User action:** if you ever turned Audit logging on with `1.0.0` or earlier, regenerate the MCP
token, rotate any API key sent through a custom header, and delete the old `audit.jsonl` and
`bundles/` files (`1.0.1` does not delete or rewrite them). On a shared machine, treat their
contents as readable by other local users.

#### ADV-101-2: right-click "send to AI" context bypassed the privacy mode

**Affected:** 1.0.0 · **Fixed in:** 1.0.1 · **Severity:** high

In BALANCED and STRICT, right-click context sent the raw request URL (query-string tokens such as
`access_token=`, and the real hostname in STRICT), scanner issue name, detail and remediation
(including session IDs and bearer tokens quoted there) and BountyPrompt parameter values without
redaction. In STRICT the item's own hostname also stayed in `Referer`, `Origin`, `Location` and
absolute URLs.

**User action:** if you used right-click "send to AI" with a hosted backend (any provider other than
a local Ollama or LM Studio), treat tokens and hostnames in the requests and issues you sent as
**disclosed to that provider** and rotate the tokens. As with PRIV-05, data from your clients' or
employer's applications is included; tell them.

#### ADV-101-3: the AI scanners kept the privacy mode and backend from extension load

**Affected:** 1.0.0 · **Fixed in:** 1.0.1 · **Severity:** medium

The passive and active AI scanners and the Burp Scanner checks used the settings from when the
extension loaded. A stricter privacy mode, or a switch to a local backend, chosen in Settings did not
reach them until Burp restarted, and the passive scanner could switch the shared backend back to the
startup one.

**User action:** if you tightened the privacy mode or moved to a local backend during a session
without restarting Burp, assume passive and active AI scans for the rest of that session ran with
the earlier mode and backend, and apply the PRIV-05 / ADV-101-2 reasoning to what they sent.

#### ADV-101-4: target text could change the structure of AI backend requests

**Affected:** 1.0.0 · **Fixed in:** 1.0.1 · **Severity:** medium

Request bodies to HTTP backends lost the high byte of every character, so characters such as `Ģ`
became `"` and `Ž` became `}`. Content from a scanned page or a proxy-history tool result could
therefore close a JSON string and add members to the request, for example an extra system-role
message or a different `model`. Redaction was not bypassed, because it runs before serialization.
The same defect corrupted every non-ASCII prompt (#84, #85, #86, #88).

**User action:** none beyond upgrading.

#### ADV-101-5: chat links opened any address without asking

**Affected:** 1.0.0 · **Fixed in:** 1.0.1 · **Severity:** medium

A markdown link in an AI reply or in tool output, text a scanned target can influence, was clickable
whatever its scheme and opened at once without showing the address. On Windows a `file:` link to a
remote host makes the system connect over SMB, which can leak the user's NTLM credentials. In `1.0.1`
only http and https links open, after a confirmation that shows the full address.

**User action:** on Windows, if you clicked a chat link that did not open a web page, treat the NTLM
credentials of that Windows account as exposed to the host named in the link.

#### Also fixed in 1.0.1

- **Active scanner safety.** The IDOR/BOLA test replayed state-changing requests (DELETE, PUT,
  PATCH, POST) against neighbouring object IDs at every risk level, and the 403 bypass switched
  requests to POST or PUT. Both now happen only at DANGEROUS. If you ran the active AI scanner on
  `1.0.0` below DANGEROUS, check the targets for unintended changes.
- **Bundled libraries.** The JAR bundled Netty 4.1.119.Final and Jackson 2.22.1, which have
  published advisories. `1.0.1` bundles Netty 4.1.138.Final and Jackson 2.22.3.

### Fixed in 1.0.0

Two defects below were confirmed by **running** the shipped code during a review of `0.9.2` on
2026-08-05, not by reading it. Both affect every published `0.9.x` release.

**No CVE and no GHSA identifier has been issued for either finding.** Do not look for one — none
exists at the time of writing. Both are fixed in `1.0.0`, which is published: upgrading is the
remedy, and the user actions below still apply to anyone who ran an affected release. If you find a
further issue, report it privately using the instructions in
[Reporting a Vulnerability](#reporting-a-vulnerability) above rather than opening a public issue.

#### SEC-04 — MCP access-control checks did not run on resolved routes

**Affected:** 0.9.0, 0.9.1, 0.9.2 · **Fixed in:** 1.0.0 · **Severity:** critical

The access-control interceptor was registered *after* the `routing` block in Ktor's `Call` phase, and
Ktor runs same-phase interceptors in registration order, so any request whose route resolved was
served by its handler before the checks ran.

What that exposed:

- With external MCP access enabled, an unauthenticated `POST /message` and an unauthenticated SSE
  connect both reached the MCP handler instead of being rejected with `401`. The listener accepted
  unauthenticated tool calls.
- In local mode, the `Origin`, `Host` and `User-Agent` checks and the `X-Frame-Options`,
  `X-Content-Type-Options`, `Referrer-Policy` and `Content-Security-Policy` response headers did not
  apply to matched routes, leaving the browser-origin defences inert.

Reproduction actually observed: in external mode, with no `Authorization` header, `POST /message`
returned `400 "sessionId query parameter is not provided"` — the MCP handler's own error, proving the
handler ran — rather than `401`. Only unmatched paths returned `401`.

Precondition, stated honestly: the MCP server binds to `127.0.0.1` by default, so the
unauthenticated-listener exposure required the explicit external-access opt-in. The local-mode gap
required no opt-in; it applied to every install running the MCP server.

**User action:** if you enabled external MCP access on 0.9.0, 0.9.1 or 0.9.2, treat that listener as
having accepted **unauthenticated** tool calls for the entire period it was reachable beyond
loopback, and rotate the MCP bearer token. Review Burp's own logs and your audit log for tool calls
you did not initiate.

#### PRIV-05 — session cookies reached AI backends unredacted in STRICT and BALANCED

**Affected:** 0.9.0, 0.9.1, 0.9.2 · **Fixed in:** 1.0.0 · **Severity:** high

The passive scanner emitted a dedicated cookies section into the prompt as bare `name=value` pairs,
dropping the `Cookie:` header prefix that the redaction rule keyed on. Sensitive-key matching was an
exact match against a fixed list, so real-world cookie names were not recognised.

What that exposed: cookie values named `JSESSIONID`, `PHPSESSID`, `connect.sid`, `auth_token`,
`csrftoken` and `remember_me` were included verbatim in the prompt sent to the configured AI backend
in **both STRICT and BALANCED** privacy modes. Only a cookie literally named `session` was caught.

**User action:** if you ran passive AI scanning on 0.9.0, 0.9.1 or 0.9.2 with a non-local backend
(any hosted provider — Anthropic, OpenAI, Google, NVIDIA, Perplexity, GitHub, or any
OpenAI-compatible endpoint you configured), treat every session cookie that passed through that
scanning as **disclosed to that provider** and rotate it. Cookies belonging to your clients' or
employer's applications are included; rotation is their decision to make, so tell them. If your
backend was a local runner (Ollama, LM Studio) the data did not leave your machine.

## Security Model

The extension runs inside Burp Suite on the user's machine. The threat model assumes:

- Burp Suite preferences are accessible only to the local user.
- API keys and credentials are stored via Burp's standard preferences storage, encrypted with
  AES-256-GCM under a per-install random master key (`SecretCipher`). **That master key is itself
  stored in Burp Preferences, Base64-encoded, beside the ciphertext it protects**
  (`secret.master.key.v1`). The encryption therefore protects against casual inspection of a
  preferences file or an exported project — it does **not** protect against an attacker or a process
  that can read those preferences, because such a reader has the key too. Treat preference-file
  access as equivalent to credential access.
- The MCP server binds to `127.0.0.1` by default; external access requires explicit opt-in with a bearer token and optional TLS.
- Privacy modes (STRICT / BALANCED / OFF) control what request and response data is sent to AI backends.

See [`docs/mcp-hardening.md`](docs/mcp-hardening.md) for operational hardening guidance and [`docs/ui-safety-guide.md`](docs/ui-safety-guide.md) for safe-use recommendations.
