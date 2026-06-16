# External MCP Servers

Burp AI Agent can connect to external or custom MCP servers over SSE (HTTP-based) or stdio (local process) transports, so AI agents can call tools from those servers alongside Burp's built-in MCP tools in the same session.

## Setup

1. Open **Settings > MCP > External Servers**.
2. Click **Add** and enter a server name and transport type:
   - **SSE**: enter the full SSE URL (e.g. `http://localhost:3000/sse`).
   - **stdio**: enter the executable command (e.g. `/usr/local/bin/my-mcp-server`).
3. For SSE servers that require authentication, enter the bearer token. The token is stored encrypted at rest (AES-256-GCM).
4. Click **Connect**. Once connected, the server's tools appear in the agent's tool list alongside the built-in Burp tools.

## Transport Types

| Transport | Use When | Example |
|-----------|----------|---------|
| SSE | HTTP-based remote or local server | `http://localhost:3000/sse` |
| stdio | Local process (launched by the extension) | `/usr/local/bin/my-mcp-server` |

## Security Notes

1. Auth tokens for external servers are stored encrypted at rest (AES-256-GCM), the same as Anthropic and other API keys.
2. Configuring a non-loopback SSE URL (any host other than `127.0.0.1` or `localhost`) triggers an SSRF warning — confirm intent before proceeding.
3. All output from external servers is wrapped in a trust-boundary marker before it enters the AI prompt, preventing prompt-injection attacks from untrusted or compromised server responses.
4. Every external tool invocation is recorded in the audit log (when audit logging is enabled), including the server name, tool name, and result hash.
