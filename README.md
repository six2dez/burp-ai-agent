# Burp AI Agent

**The bridge between Burp Suite and modern AI.**

<!-- screenshot: main extension tab with chat and settings visible -->
![Burp AI Agent Screenshot](screenshots/main-tab.png)

Burp AI Agent is an extension for Burp Suite that integrates AI into your security workflow. Use local models or cloud providers, connect external AI agents via MCP, and let passive/active scanners find vulnerabilities while you focus on manual testing.

## Highlights

- **9 AI Backends** — Ollama, LM Studio, NVIDIA NIM, Generic OpenAI-compatible, Gemini CLI, Claude CLI, Codex CLI, OpenCode CLI, Copilot CLI.
- **53+ MCP Tools** — Let Claude Desktop (or any MCP client) drive Burp autonomously.
- **62 Vulnerability Classes** — Passive and Active AI scanners across injection, auth, crypto, and more.
- **Burp Scan Skill** — Use your preferred AI coding assistant (Claude Code, Gemini CLI, Codex, etc.) as a scanner via MCP.
- **3 Privacy Modes** — STRICT / BALANCED / OFF. Redact sensitive data before it leaves Burp.
- **Custom Prompt Library** — Save free-form prompts per context (HTTP request or scanner issue); launch them from the right-click menu or type ad-hoc ones via `Custom…`.
- **Audit Logging** — JSONL with SHA-256 integrity hashing for compliance; every launch stamped with `promptSource` / `contextKind` for reproducibility.

## Quick Start

### 1. Install

Download the latest JAR from [Releases](https://github.com/six2dez/burp-ai-agent/releases), or build from source (Java 21):

```bash
git clone https://github.com/six2dez/burp-ai-agent.git
cd burp-ai-agent
JAVA_HOME=/path/to/jdk-21 ./gradlew clean shadowJar
# Output: build/libs/Custom-AI-Agent-<version>.jar
```

### 2. Load into Burp

1. Open Burp Suite (Community or Professional).
2. Go to **Extensions > Installed > Add**.
3. Select **Java** as extension type and choose the `.jar` file.

<!-- screenshot: Burp Extensions > Add dialog with the JAR loaded -->
![Load Extension](screenshots/burp-extensions-add.png)

### 3. Agent Profiles

The extension auto-installs the bundled profiles into `~/.burp-ai-agent/AGENTS/` on first run.
Drop additional `*.md` files in that directory to add custom profiles.

### 4. Configure a Backend

Open the **AI Agent** tab and go to **Settings**. Pick a backend:

| Backend | Type | Setup |
| :--- | :--- | :--- |
| **Ollama** | Local HTTP | Install [Ollama](https://ollama.com), run `ollama serve`, pull a model (`ollama pull llama3.1`). |
| **LM Studio** | Local HTTP | Install [LM Studio](https://lmstudio.ai), load a model, start the server. |
| **NVIDIA NIM** | HTTP | Use the default `https://integrate.api.nvidia.com` endpoint, set your NVIDIA API key, and choose a model such as `moonshotai/kimi-k2.5`. |
| **Generic OpenAI-compatible** | HTTP | Provide a base URL and model for any OpenAI-compatible provider. |
| **Gemini CLI** | Cloud CLI | Install `gemini`, run `gemini auth login`. |
| **Claude CLI** | Cloud CLI | Install `claude`, set `ANTHROPIC_API_KEY` or run `claude login`. |
| **Codex CLI** | Cloud CLI | Install `codex`, set `OPENAI_API_KEY`. |
| **OpenCode CLI** | Cloud CLI | Install `opencode`, configure provider credentials. |
| **Copilot CLI** | Cloud CLI | Install `copilot` and sign in with your GitHub account. |

For **NVIDIA NIM**, the backend expects the same chat-completions style flow as the NVIDIA hosted endpoint. A working configuration is:

```text
Backend: NVIDIA NIM
Base URL: https://integrate.api.nvidia.com
Model: moonshotai/kimi-k2.5
API Key: <your nvapi token>
```

Leave extra headers empty unless your gateway requires them. The extension sends requests to `/v1/chat/completions` and uses the configured bearer token automatically.

### 5. Run Your First Analysis

1. Browse a target through Burp Proxy.
2. Right-click any request in **Proxy > HTTP History**.
3. Select **Extensions > Burp AI Agent > Analyze this request**.
4. A chat session opens with the AI analysis.

<!-- screenshot: right-click context menu showing Burp AI Agent actions -->
![Context Menu](screenshots/context-menu-request.png)

### 6. Connect Claude Desktop via MCP (Optional)

Enable the MCP server in **Settings > MCP Server** and add this to your Claude Desktop config:

**macOS**: `~/Library/Application Support/Claude/claude_desktop_config.json`
**Windows**: `%APPDATA%\Claude\claude_desktop_config.json`

```json
{
  "mcpServers": {
    "burp-ai-agent": {
      "command": "npx",
      "args": [
        "-y",
        "supergateway",
        "--sse",
        "http://127.0.0.1:9876/sse"
      ]
    }
  }
}
```

> Requires Node.js 18+. If you enable **External Access**, the MCP client must send `Authorization: Bearer <token>` on every request.

## Burp Scan Skill (Terminal AI Scanning)

The `burp-scan` skill lets you use any AI coding assistant (Claude Code, Gemini CLI, Codex, etc.) as a Burp scanner from your terminal. Instead of the plugin's built-in AI, **your terminal AI becomes the reasoning engine** while Burp provides the tools via MCP.

### What It Contains

- 53+ MCP tool reference organized by scanning action
- Passive analysis protocol (traffic analysis without sending requests)
- Active testing payload library (200+ payloads for 62 vuln classes with detection patterns)
- End-to-end scanning workflow (scope -> passive -> active -> OOB -> report)
- Issue creation protocol with severity/confidence mapping

### Install for Claude Code

Copy the skill to your Claude Code skills directory:

```bash
# Global (available in all projects)
cp -r skills/burp-scan ~/.claude/skills/burp-scan

# Or project-specific
cp -r skills/burp-scan .claude/skills/burp-scan
```

Then use `/burp-scan` in Claude Code or let it trigger automatically when you mention Burp scanning.

### Install for Other AI Assistants

The skill is a standalone Markdown file at [`skills/burp-scan/SKILL.md`](skills/burp-scan/SKILL.md). You can use it with any AI assistant that supports system prompts or context files:

- **Gemini CLI / Codex / OpenCode**: Add as a context file or paste into your system prompt
- **Custom MCP clients**: Include the skill content as system context alongside your MCP connection
- **Any LLM**: The file is self-contained — feed it as context along with your MCP tool definitions

### Usage Example

```
You: Connect to Burp MCP at localhost:9876 and scan the proxy history for IDOR vulnerabilities

AI: [Uses proxy_http_history to pull traffic]
    [Identifies endpoints with numeric IDs]
    [Sends http1_request with ID+1, ID-1 payloads]
    [Compares responses for different user data]
    [Creates issue_create for confirmed IDOR]
```

> The skill and the plugin's built-in scanner are complementary: the plugin runs automated background scanning, while the skill enables interactive, analyst-guided scanning from your terminal.

## Documentation

Full documentation is available at **[burp-ai-agent.six2dez.com](https://burp-ai-agent.six2dez.com)**.

- [Installation](https://burp-ai-agent.six2dez.com/getting-started/installation)
- [Quick Start](https://burp-ai-agent.six2dez.com/getting-started/quick-start)
- [UI Tour](https://burp-ai-agent.six2dez.com/user-guide/ui-tour)
- [Agent Profiles](https://burp-ai-agent.six2dez.com/user-guide/agent-profiles)
- [Passive Scanner](https://burp-ai-agent.six2dez.com/scanners/passive)
- [Active Scanner](https://burp-ai-agent.six2dez.com/scanners/active)
- [MCP Overview](https://burp-ai-agent.six2dez.com/mcp/overview)
- [Privacy Modes](https://burp-ai-agent.six2dez.com/privacy/privacy-modes)
- [Settings Reference](https://burp-ai-agent.six2dez.com/reference/settings-reference)
- [Troubleshooting](https://burp-ai-agent.six2dez.com/reference/troubleshooting)
- [Burp Scan Skill](https://burp-ai-agent.six2dez.com/user-guide/burp-scan-skill)

## Operator Playbooks

- [MCP Hardening](docs/mcp-hardening.md)
- [UI Safety Guide](docs/ui-safety-guide.md)
- [Backend Troubleshooting](docs/backend-troubleshooting.md)

Settings are schema-versioned internally (`settings.schema.version`) and migrated additively on load for safe upgrades.

## Requirements

- **Burp Suite** Community or Professional (2023.12+)
- **Java 21** (bundled with modern Burp for runtime; required separately for building from source)
- At least one AI backend configured (see table above)

## License

This project is licensed under the [MIT License](LICENSE).

## Disclaimer

Usage of Burp AI Agent for attacking targets without prior consent is illegal. It is the user's responsibility to obey all applicable laws. The developers assume no liability for misuse or damage caused by this tool. Use responsibly.

## Contributing

Issues and pull requests are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md) for development setup and guidelines, or the [Developer docs](https://burp-ai-agent.six2dez.com/developer/architecture) for architecture details.
