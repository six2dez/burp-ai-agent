# Burp AI Agent

**The bridge between Burp Suite and modern AI.**

<!-- screenshot: main extension tab with chat and settings visible -->
![Burp AI Agent Screenshot](screenshots/main-tab.png)

Burp AI Agent is an extension for Burp Suite that integrates AI into your security workflow. Use local models or cloud providers, connect external AI agents via MCP, and let passive/active scanners find vulnerabilities while you focus on manual testing.

## Highlights

- **7 AI Backends** — Ollama, LM Studio, Generic OpenAI-compatible, Gemini CLI, Claude CLI, Codex CLI, OpenCode CLI.
- **53+ MCP Tools** — Let Claude Desktop (or any MCP client) drive Burp autonomously.
- **62 Vulnerability Classes** — Passive and Active AI scanners across injection, auth, crypto, and more.
- **3 Privacy Modes** — STRICT / BALANCED / OFF. Redact sensitive data before it leaves Burp.
- **Audit Logging** — JSONL with SHA-256 integrity hashing for compliance.

## Quick Start

### 1. Install

Download the latest JAR from [Releases](https://github.com/six2dez/burp-ai-agent/releases), or build from source (Java 21):

```bash
git clone https://github.com/six2dez/burp-ai-agent.git
cd burp-ai-agent
JAVA_HOME=/path/to/jdk-21 ./gradlew clean shadowJar
# Output: build/libs/Burp-AI-Agent-<version>.jar
```

### 2. Load into Burp

1. Open Burp Suite (Community or Professional).
2. Go to **Extensions > Installed > Add**.
3. Select **Java** as extension type and choose the `.jar` file.

<!-- screenshot: Burp Extensions > Add dialog with the JAR loaded -->
![Load Extension](screenshots/burp-extensions-add.png)

### 3. Install Agent Profiles

Copy the sample profiles so the AI gets role-specific instructions:

```bash
cp -r AGENTS/ ~/.burp-ai-agent/AGENTS/
```

### 4. Configure a Backend

Open the **AI Agent** tab and go to **Settings**. Pick a backend:

| Backend | Type | Setup |
| :--- | :--- | :--- |
| **Ollama** | Local HTTP | Install [Ollama](https://ollama.com), run `ollama serve`, pull a model (`ollama pull llama3.1`). |
| **LM Studio** | Local HTTP | Install [LM Studio](https://lmstudio.ai), load a model, start the server. |
| **Gemini CLI** | Cloud CLI | Install `gemini`, run `gemini auth login`. |
| **Claude CLI** | Cloud CLI | Install `claude`, set `ANTHROPIC_API_KEY` or run `claude login`. |
| **Codex CLI** | Cloud CLI | Install `codex`, set `OPENAI_API_KEY`. |
| **OpenCode CLI** | Cloud CLI | Install `opencode`, configure provider credentials. |

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
        "@modelcontextprotocol/server-sse",
        "http://127.0.0.1:9876/sse"
      ]
    }
  }
}
```

> Requires Node.js 18+. If you enable **External Access**, the MCP client must send `Authorization: Bearer <token>` on every request.

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
