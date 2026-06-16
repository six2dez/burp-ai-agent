# Anthropic Backend

The Anthropic backend connects directly to the Anthropic Messages API (`/v1/messages`) using Burp's own HTTP transport (`MontoyaHttpTransport`), not a vendored Anthropic SDK — all Anthropic API traffic appears in Burp's Proxy > HTTP history.

## Setup

1. Open **Settings > Backend** and select **Anthropic** from the backend dropdown.
2. Enter your Anthropic API key. The key is stored encrypted at rest (AES-256-GCM) and never written to logs.
3. Set the model name in the **Model** field. The field is a free-form string; the default is `claude-3-5-sonnet-20241022`. Update it to any current Anthropic model without needing an extension update.
4. Click **Save** and then **Test connection** to verify the key and model are accepted.

## Configuration

| Setting | Default | Notes |
|---------|---------|-------|
| Model | `claude-3-5-sonnet-20241022` | Free-form string; any current Anthropic model name works |
| API Key | _(empty)_ | Stored AES-256-GCM encrypted on save |
| Timeout | 30 s | Increase for large prompts or slow connections |

## Privacy Notes

1. All requests to `api.anthropic.com` route through Burp's proxy and appear in **Proxy > HTTP history**. You can inspect, replay, or modify them like any other HTTP traffic.
2. The API key is encrypted at rest using AES-256-GCM with a per-install master key. The plaintext key is never written to logs or exported settings files.
3. The active privacy mode (STRICT / BALANCED / OFF) applies before every prompt is sent. In STRICT mode, hosts are anonymized via HKDF; in BALANCED and STRICT modes, cookies, tokens, and auth headers are redacted.
4. Per-session token-budget guardrails (`BudgetGuard`) cap how much context the passive scanner sends. Configure the warn threshold and hard cap in **Settings > Passive Scanner > Token Budget**.
