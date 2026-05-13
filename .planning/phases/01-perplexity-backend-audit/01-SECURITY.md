---
phase: "01-perplexity-backend-audit"
plan: "01"
asvs_level: 1
threats_total: 4
threats_open: 0
threats_closed: 4
audited_at: "2026-05-13"
auditor: "gsd-security-auditor (claude-sonnet-4-6)"
block_on: "critical"
verdict: "SECURED"
---

# Security Audit — Phase 01: Perplexity Backend Audit

**Phase:** 01 — Perplexity Backend Audit (behaviour-locking tests only; zero production code modified)
**ASVS Level:** 1
**Threats Closed:** 4/4
**Audited:** 2026-05-13

---

## Threat Verification

| Threat ID | Category | Disposition | Status | Evidence |
|-----------|----------|-------------|--------|----------|
| T-01 | secrets-management | mitigate | CLOSED | See T-01 detail below |
| T-02 | information-disclosure | mitigate | CLOSED | See T-02 detail below |
| T-03 | tampering / test reliability | mitigate | CLOSED | See T-03 detail below |
| T-04 | denial-of-service (test infra) | mitigate | CLOSED | See T-04 detail below |

---

## Threat Details

### T-01 — Test secrets in CI (secrets-management) — CLOSED

**Declared mitigation:** D-06 forbids real API keys; tests use `"pplx-test"` literal placeholder; VERIFICATION.md grep gate forbids `pplx-[A-Za-z0-9]{40,}`.

**Verification method:** Grep for real key pattern across all cited files + CI workflows.

**Evidence:**

1. `PerplexityBackendFactoryTest.kt` lines 45, 78, 110, 142, 177 — all five `@Test` methods use the literal placeholder `"Bearer pplx-test"`. The string `pplx-test` is 9 characters after the prefix; the real-key pattern requires 40+ alphanumeric characters. Confirmed: no real key.

2. `build.gradle.kts` — grep for `pplx-[A-Za-z0-9]{40}` returns zero matches. The file declares only `testImplementation("com.squareup.okhttp3:mockwebserver:4.12.0")` at line 53.

3. `.github/workflows/build.yml`, `release.yml`, `nightly-regression.yml` — grep for `PERPLEXITY_API_KEY`, `PERPLEXITY`, and `pplx` returns zero matches across all three workflow files. No CI secret reference exists.

4. `.planning/phases/01-perplexity-backend-audit/01-VERIFICATION.md` — contains `pplx-*` only in the prose description `maintainer-personal-pplx-key` (plain English, not a credential pattern); `grep -E 'pplx-[A-Za-z0-9]{40}'` returns zero matches.

5. `OpenAiCompatibleBackendDefaultsTest.kt` — `headers = emptyMap()` throughout; no Authorization header set. No key placeholder of any kind.

**Disposition confirmed CLOSED.**

---

### T-02 — Token leakage in test or runtime logs (information-disclosure) — CLOSED

**Declared mitigation:** `BackendDiagnostics.log(...)` only logs URLs, not Authorization header values; tests do not assert against log output.

**Verification method:** Read `BackendDiagnostics.kt` fully; read `OpenAiCompatibleBackend.kt` debugLog call site; grep test files for any log assertion patterns.

**Evidence:**

1. `src/main/kotlin/com/six2dez/burp/aiagent/backends/BackendDiagnostics.kt` (actual path; differs from `backends/http/BackendDiagnostics.kt` cited in the threat register — the file exists at `backends/BackendDiagnostics.kt`) — `log(message: String)` is a pass-through to `output?.invoke(message)`. The object holds zero reference to headers or API keys. The log function accepts only an opaque `String`; the caller controls what is passed.

2. `OpenAiCompatibleBackend.kt` line 200 — the only `debugLog` call in the request-send path is `debugLog("request -> $endpointUrl")`. `endpointUrl` is the resolved URL string (e.g. `http://localhost:PORT/chat/completions`). The Authorization header and all other request headers are applied to the `Request.Builder` at lines 244-246 and are never interpolated into any log string.

3. `PerplexityBackendFactoryTest.kt` — no call to `BackendDiagnostics`, no assertion on any log output, no mock/capture of `BackendDiagnostics.output`. Confirmed by full file read (205 lines).

4. `OpenAiCompatibleBackendDefaultsTest.kt` — same: no log assertion, no `BackendDiagnostics` reference. Confirmed by full file read (111 lines).

**Note on file path discrepancy:** The threat register cited `src/main/kotlin/com/six2dez/burp/aiagent/backends/http/BackendDiagnostics.kt` but the file lives at `src/main/kotlin/com/six2dez/burp/aiagent/backends/BackendDiagnostics.kt`. This is a documentation-only discrepancy; the correct file was located and verified. The mitigation evidence is conclusive regardless of the path error in the register.

**Disposition confirmed CLOSED.**

---

### T-03 — Cross-test pollution via HttpBackendSupport.sharedClient static cache (tampering / test reliability) — CLOSED

**Declared mitigation:** Each MockWebServer instance gets a unique port → unique cache key. Tests MUST NOT call `shutdownSharedClients()` in `@AfterEach`.

**Verification method:** Read `HttpBackendSupport.kt` cache key logic; grep both new test files for `shutdownSharedClients`.

**Evidence:**

1. `src/main/kotlin/com/six2dez/burp/aiagent/backends/http/HttpBackendSupport.kt` lines 20-23 — `ClientKey` is a data class of `(baseUrl: String, timeoutSeconds: Long)` where `baseUrl` is lowercased and trimmed. Each `MockWebServer` binds to a randomly-assigned free port (e.g. `:54321`, `:54322`), making every `server.url("/").toString()` unique across concurrent test runs. The cache therefore produces distinct entries per server instance. No collision risk.

2. `PerplexityBackendFactoryTest.kt` — `grep -n "shutdownSharedClients"` returns zero matches. Confirmed across all 205 lines.

3. `OpenAiCompatibleBackendDefaultsTest.kt` — `grep -n "shutdownSharedClients"` returns zero matches. Confirmed across all 111 lines.

4. `AgentSettingsMigrationTest.kt` — no MockWebServer usage; no `shutdownSharedClients` call. Not applicable.

**Disposition confirmed CLOSED.**

---

### T-04 — MockWebServer left running across tests (denial-of-service / test infra) — CLOSED

**Declared mitigation:** `@AfterEach { server.shutdown() }` on every test class that uses MockWebServer.

**Verification method:** Read `@AfterEach` teardown in both new test files.

**Evidence:**

1. `PerplexityBackendFactoryTest.kt` lines 27-30 — `@AfterEach fun teardown() { server.shutdown() }`. Present and correctly annotated with `org.junit.jupiter.api.AfterEach`.

2. `OpenAiCompatibleBackendDefaultsTest.kt` lines 27-29 — `@AfterEach fun teardown() { server.shutdown() }`. Present and correctly annotated.

3. `AgentSettingsMigrationTest.kt` — does not use MockWebServer; no `@AfterEach` required for this threat.

**Both MockWebServer-using classes call `server.shutdown()` in `@AfterEach`. File descriptor leak and port exhaustion risks are mitigated.**

**Disposition confirmed CLOSED.**

---

## Unregistered Flags

The SUMMARY.md `## Threat Model Dispositions` section maps all four threats (T-01..T-04) to their declared dispositions. No new attack surface flags appeared during implementation with no threat mapping.

**Unregistered flags: none.**

---

## Accepted Risks

None. All four threats carry `mitigate` disposition. No risks were accepted or transferred in this phase.

---

## Audit Notes

### Scope confirmation
Phase 1 is a behaviour-locking audit — test code only. Zero production code under `src/main/kotlin/` was modified. The runtime surfaces for T-02 (`BackendDiagnostics`) and T-03 (`HttpBackendSupport.sharedClient`) are pre-existing, unchanged by this phase; the audit verifies the new tests do not violate the relevant invariants, which they do not.

### File path discrepancy (informational)
The threat register cited `BackendDiagnostics.kt` at `backends/http/BackendDiagnostics.kt`; the actual location is `backends/BackendDiagnostics.kt`. This does not affect the mitigation — the log function was located and verified. The register should be updated in a future phase to reflect the correct path.

### ktlintIgnoreFailures flag (informational)
`build.gradle.kts` line 120 sets `ignoreFailures` to `true` unless `ktlintStrict=true` is passed. This means `./gradlew ktlintCheck` exits 0 even if lint violations exist (unless the strict flag is set). The Phase 1 executor reported `ktlintCheck` as passing but this represents a weak lint gate. This is a pre-existing project configuration, not introduced by Phase 1, and is outside the threat register scope. Noted for awareness.

### D-06 manual smoke pending (informational)
The one-time maintainer smoke run required by ROADMAP SC#5 has not yet been performed (all six D-06 fields in `01-VERIFICATION.md` are marked "pending"). This is expected project state — it is not a security finding. The D-06 gate is a functional confidence check, not a security control; its absence does not open any of T-01..T-04.

---

## Audit Trail

| Item | Detail |
|------|--------|
| Auditor | gsd-security-auditor (claude-sonnet-4-6) |
| Audit date | 2026-05-13 |
| Phase | 01-perplexity-backend-audit |
| Plan | 01-01 |
| ASVS level | 1 |
| Files read | `01-01-PLAN.md`, `01-01-SUMMARY.md`, `01-CONTEXT.md`, `01-VERIFICATION.md`, `build.gradle.kts`, `PerplexityBackendFactoryTest.kt`, `OpenAiCompatibleBackendDefaultsTest.kt`, `AgentSettingsMigrationTest.kt`, `BackendDiagnostics.kt`, `HttpBackendSupport.kt`, `OpenAiCompatibleBackend.kt` (partial), `.github/workflows/build.yml`, `release.yml`, `nightly-regression.yml` |
| Verdict | SECURED — 4/4 threats closed, 0 open, 0 blockers |
