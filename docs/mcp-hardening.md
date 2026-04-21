# MCP Hardening Runbook

Use this checklist before exposing MCP beyond loopback.

## Baseline

1. Keep bind host at `127.0.0.1` unless external access is required.
2. Keep **Unsafe Tools** disabled by default.
3. Enable only the minimum MCP tools needed for current workflow.

## External Access

1. Enable TLS.
2. Use strong bearer token and rotate it.
3. Restrict allowed origins/hosts to trusted clients.
4. Validate `Authorization: Bearer <token>` is sent on every request.

## Operational Controls

1. Set conservative MCP request concurrency.
2. Set `Max Body Bytes` to avoid oversized payload exfiltration.
3. Keep privacy mode at `STRICT` or `BALANCED` for cloud clients.
4. Keep audit logging enabled for traceability.

## Credential Storage

1. The TLS keystore password is persisted in Burp's preferences (`mcp.tls.keystore.password`) as plaintext. Burp preferences are stored in the user's project file and are only as protected as that file.
2. If the project file or preferences export could leak (shared backups, multi-user hosts), treat the MCP bearer token and TLS keystore as compromised and rotate both.
3. For high-assurance setups, generate the keystore offline with your own `keytool` invocation and point the extension at it via settings, so the password never touches Burp preferences.
4. The MCP bearer token is generated with `SecureRandom` (32 bytes base64). Rotate it if any external client is decommissioned.

## Verification

1. Test local health endpoint: `GET /__mcp/health`.
2. Test denied request (missing/invalid token) returns auth error.
3. Confirm unsafe tools are blocked when master switch is off.

## Incident Response

1. Disable MCP toggle immediately.
2. Rotate token.
3. Review audit logs and extension output.
4. Re-enable with reduced scope.
