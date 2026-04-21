# Contributing to Burp AI Agent

Thanks for your interest in contributing! Here's how to get started.

## Development Setup

1. **Clone the repo**:
   ```bash
   git clone https://github.com/six2dez/burp-ai-agent.git
   cd burp-ai-agent
   ```

2. **Requirements**: Java 21 (Temurin or Oracle JDK). Ensure `JAVA_HOME` is set.

3. **Build**:
   ```bash
   ./gradlew clean shadowJar
   ```
   Output JAR: `build/libs/Custom-AI-Agent-<version>.jar`

4. **Run tests**:
   ```bash
   ./gradlew test
   ```

5. **Lint and coverage** (optional but recommended before opening a PR):
   ```bash
   ./gradlew ktlintFormat        # auto-fix style
   ./gradlew ktlintCheck         # verify style (non-blocking in CI until baseline is clean)
   ./gradlew jacocoTestReport    # HTML at build/reports/jacoco/test/html/index.html
   ```

6. **Load in Burp**: Open Burp Suite, go to **Extensions > Installed > Add**, select the JAR.

## Project Structure

```
src/main/kotlin/com/six2dez/burp/aiagent/
├── ui/              Swing UI components
├── config/          Settings and configuration
├── context/         Request/issue context collection
├── backends/        AI backend adapters (CLI + HTTP)
├── redact/          Privacy redaction pipeline
├── audit/           JSONL audit logging
├── scanner/         Passive and Active AI scanners
├── supervisor/      Backend lifecycle management
├── mcp/             MCP server and tools
├── agents/          Agent profile loader
└── App.kt           Extension entry point
```

## Submitting Changes

1. **Fork** the repository.
2. Create a **feature branch** from `main`: `git checkout -b feature/my-feature`.
3. Make your changes. Follow the existing code style (Kotlin, no wildcard imports).
4. Add tests if applicable.
5. Run `./gradlew test` and ensure all tests pass.
6. **Commit** with a clear message describing what and why.
7. Open a **Pull Request** against `main`.

## Code Style

- Kotlin with strict JSR-305 null-safety annotations.
- Keep a clear separation between UI, logic, and backend layers.
- Small, testable components. Favor pure functions for data transformations.
- No hardcoded secrets or credentials.

## Reporting Bugs

Open an [issue](https://github.com/six2dez/burp-ai-agent/issues) with:
- Burp Suite version (Community or Pro).
- OS and Java version.
- Steps to reproduce.
- Extension output/error logs (Extensions > Installed > Output/Errors tabs).

## Adding a Backend

See the [Adding a Backend](https://burp-ai-agent.six2dez.com/developer/adding-backend) developer guide for implementing new AI backend adapters.

## Adding MCP Tools

See the [Adding MCP Tools](https://burp-ai-agent.six2dez.com/developer/adding-mcp-tools) developer guide.

## Documentation

Docs live in `https://burp-ai-agent.six2dez.com/`.

## License

By contributing, you agree that your contributions will be licensed under the [MIT License](LICENSE).
