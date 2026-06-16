# Phase 19: Mega-File Split + Docs - Research

**Researched:** 2026-06-16
**Domain:** Kotlin refactor (no-behaviour-change file split) + documentation reconciliation
**Confidence:** HIGH

---

<user_constraints>
## User Constraints (from CONTEXT.md)

### Locked Decisions

**Mega-File Split Strategy (QUAL-01 / SC1, SC2)**
- Split boundary by responsibility / feature cohesion — extract logically-related groups.
- Same-package top-level functions/objects in new files — zero call-site changes, no import churn.
- Size target = the three named files each land under ~500 lines. Helper files sized by cohesion.
- One atomic commit per extraction, with `./gradlew test` run green between each extraction.

**User-Facing Docs (DOC-02 / SC4, SC5)**
- SC5 site source = in-repo `docs/` served by GitHub Pages. New markdown goes there.
- SC5 deliverable = two new concise pages: `docs/anthropic-backend.md` and `docs/external-mcp-servers.md`.
- Live-URL render is a HUMAN-UAT item.
- Untracked `SPEC.md`, `DECISIONS.md`, and `AGENTS.md` are committed as part of this phase while being updated.
- `DECISIONS.md` gets ADR-style entries for v0.9.0 decisions.
- `README.md` gains a "What's new in v0.9.0" section + native Anthropic backend row + external-MCP mention + privacy/security notes.
- CHANGELOG.md promotion and `build.gradle.kts` version bump are DEFERRED.

**.planning Reconciliation (DOC-01 / SC3)**
- Prune confirmed-superseded/stale entries (the now-moot kotlin-sdk 0.13.0-bump blocker, resolved-issue carryover #62/#66/#67/#68/#69).
- Verify v0.7.0/v0.8.0 shipped state is recorded accurately. Not verify-only.
- No-behaviour-change proof = existing full `./gradlew test` suite green before+after each extraction.
- Phase 16 is code-complete and committed — Phase 19 splits the committed McpTools.kt including those additions.

### Claude's Discretion

All three grey areas were accepted as recommended (autonomous mode). No open discretion items.

### Deferred Ideas (OUT OF SCOPE)

- CHANGELOG.md `[Unreleased]→[0.9.0]` promotion + `build.gradle.kts` 0.8.0→0.9.0 version bump.
- Any opportunistic bug fix or behaviour tweak spotted during the split.
- New characterization tests for moved code.
- SC5 live-site DNS/Pages deployment.
</user_constraints>

<phase_requirements>
## Phase Requirements

| ID | Description | Research Support |
|----|-------------|------------------|
| QUAL-01 | Mega-file split — McpTools.kt, SettingsPanel.kt, PassiveAiScanner.kt each under ~500 lines, full test suite green before/after each extraction, ServiceLoader intact | Split-boundary maps (Section 3), ServiceLoader risk analysis (Section 4), verification approach (Section 5) |
| DOC-01 | .planning/ reconciliation — PROJECT/STATE/ROADMAP/REQUIREMENTS reflect shipped v0.7.0/v0.8.0; closed issues #62–#69 acknowledged; stale carryover pruned | .planning reconciliation targets (Section 7) |
| DOC-02 | User-facing docs updated for v0.9.0 (Anthropic backend, AES-256-GCM, redaction changes, external MCP, token budgets); two new docs/ pages | Docs facts inventory (Section 6), existing docs style (Section 8) |
</phase_requirements>

---

## Summary

Phase 19 is a pure no-behaviour-change refactor plus documentation reconciliation — the last code phase of the v0.9.0 milestone. Three deliverables: split three mega-files into cohesion-bounded same-package files; reconcile `.planning/` to reflect shipped state; and update user-facing docs for the v0.9.0 feature set.

The codebase is in excellent shape for splitting. All three mega-files follow a clear internal structure: `McpTools.kt` has a dispatcher (`McpToolExecutor`), a legacy stub, tool-model data classes, and a set of private helper functions; `SettingsPanel.kt` has a single `SettingsPanel` class with UI component fields, `init` wiring, public API methods, section builder methods, and status/action methods; `PassiveAiScanner.kt` has a single `PassiveAiScanner` class with public API, request routing, AI interaction, local heuristics, response parsing, and dedup/cache helpers — plus two file-level data classes and a `companion object` with constants.

The key technical constraint is that all extracted code stays in the **same Kotlin package** as the origin file, so no import statements change anywhere in the codebase. Top-level functions and `object` declarations in Kotlin are visible across files in the same package without imports. For class members (which must stay attached to their class), only `private` scope is a risk — any member marked `private` that is called from another class cannot be extracted to a new file. The audit below confirms this is manageable for all three files.

**Primary recommendation:** Execute extractions in this order — McpTools.kt first (self-contained data class tail + executor object), then PassiveAiScanner.kt (helper/parsing cluster), then SettingsPanel.kt (section builders). Run `./gradlew test` (not `./gradlew check`) as the per-extraction gate, using the known-working JAVA_HOME wrapper.

---

## Architectural Responsibility Map

| Capability | Primary Tier | Secondary Tier | Rationale |
|------------|-------------|----------------|-----------|
| MCP tool dispatch (McpToolExecutor) | Backend/MCP Server | — | Owns runtime routing, no UI coupling |
| MCP tool model data classes | MCP/API | — | Pure serializable parameter types |
| MCP shared helper functions | MCP/API | — | Pure transforms (sanitizeHeaders, maybeAnonymizeUrl, diffLines, etc.) |
| SettingsPanel tab section builders | UI (Swing) | Settings Config | Build Swing component trees, must stay in ui/ package |
| SettingsPanel status/action helpers | UI (Swing) | Scanner | Drive scanner state from UI events |
| PassiveAiScanner dedup/cache helpers | Scanner | — | Pure cache manipulation, AWT-free |
| PassiveAiScanner AI response parsing | Scanner | — | Pure text transforms, AWT-free |
| PassiveAiScanner local heuristics | Scanner | — | Pure pattern-matching, AWT-free |
| .planning reconciliation | Documentation | — | Metadata only, no code change |
| docs/ site pages | Documentation/UI | — | Markdown consumed by GitHub Pages |

---

## Section 3: Split-Boundary Maps

### 3.1 McpTools.kt (2925 lines → target: named file under 500)

**Current structure:**
- Lines 1–52: Package declaration, imports, `toolJson` val
- Lines 53–70: `Server.registerTools()` — the dispatcher that calls 10 `register*Tools()` extension functions
- Lines 72–882: `Server.registerToolsLegacy()` — private legacy stub (marked `@Suppress("unused")`, kept for reference)
- Lines 884–1262: Private top-level helper functions (12 functions: `executeIssueCreate`, `findProxyHistoryMatch`, `withAiIssuePrefix`, `hasEquivalentIssue`, `normalizeHttpRequest`, `truncateIfNeeded`, `ensureAllowedProxyHistoryCount`, `orderedProxyHistory`, `decodeJwt`, `normalizeHashAlgorithm`, `diffLines`, `countOccurrences`, `parseHighlightColor`, `sanitizeHeaders`, `maybeAnonymizeUrl`, `resolveReportPath`, `applyReplacements`, `resolveAuditConfig`, `getActiveEditor`)
- Lines 1263–1270: `data class ToolSpec`
- Lines 1272–2533: `object McpToolExecutor` — the runtime dispatcher (the large switch/when block)
- Lines 2534–2926: 40+ `@Serializable data class` tool model types

**Proposed extractions:**

| New File | Contents | Approx Lines | Rationale |
|----------|----------|-------------|-----------|
| `McpToolModels.kt` | All `@Serializable data class` types (lines 2534–2926): `SendHttp1Request`, `SendHttp2Request`, `CreateRepeaterTab`, `RepeaterTabWithPayload`, `SendToIntruder`, `IntruderPrepare`, `InsertionPoints`, `ExtractParams`, `DiffRequests`, `RequestParse`, `ResponseParse`, `ParsedParam`, `ParsedRequest`, `ParsedResponse`, `FindReflected`, `ComparerSend`, `ProxyHistoryAnnotate`, `ResponseBodySearch`, `CookieJarGet`, `CookieEntry`, `ScopeCheck`, `ScopeUpdate`, `CollaboratorGenerate`, `CollaboratorPoll`, and all other data classes plus the `Paginated` interface, `ToolSpec` | ~420 | These are pure data types with no logic; natural cohesion unit |
| `McpToolHelpers.kt` | All private top-level helpers (lines 884–1262): `executeIssueCreate`, `findProxyHistoryMatch`, `withAiIssuePrefix`, `hasEquivalentIssue`, `normalizeHttpRequest`, `truncateIfNeeded`, `ensureAllowedProxyHistoryCount`, `orderedProxyHistory`, `decodeJwt`, `normalizeHashAlgorithm`, `diffLines`, `countOccurrences`, `parseHighlightColor`, `sanitizeHeaders`, `maybeAnonymizeUrl`, `resolveReportPath`, `applyReplacements`, `resolveAuditConfig`, `getActiveEditor` | ~380 | Pure transform functions, no shared state |
| `McpToolExecutorImpl.kt` | `object McpToolExecutor` (lines 1272–2533) | ~1260 | The runtime when-block dispatcher is a coherent unit; may need further splitting if desired but is not required by SC1 |

**Resulting McpTools.kt:** package + imports + `toolJson` val + `Server.registerTools()` + `Server.registerToolsLegacy()` = approximately 90 lines. Well under 500.

**Cross-reference risks:**
- `toolJson` (private top-level val, line 53) is referenced by `McpToolExecutor` (in the large when-block). Solution: make it `internal` and keep it in `McpTools.kt`, or move it to `McpToolHelpers.kt` since helpers also reference it. Both approaches work because same-package access is transparent.
- `registerToolsLegacy` is `private` and self-contained — stays in `McpTools.kt` or moves to a `McpToolLegacy.kt`; it is never called from outside.
- `getActiveEditor` is declared `fun` (package-private) — safe to move to helpers.
- `normalizeHttpRequest` is declared `internal` — safe to move; tests may reference it directly.
- No companion object to worry about; `McpTools.kt` has no class.
- `McpToolExecutor` is an `object` — moving it to a new file changes nothing because objects in the same package are accessible without imports.

### 3.2 SettingsPanel.kt (2782 lines → target: named file under 500)

**Current structure:**
- Lines 1–75: Package, imports
- Lines 77–538: `class SettingsPanel` — constructor, `private val` field declarations (all the UI component fields: spinners, combos, text fields, toggles, panels)
- Lines 539–976: `init { }` block — wiring all listeners, tooltips, initial styling
- Lines 978–1496: Public API methods (`refreshProfileOptions`, `setDialogParent`, `generalTabComponent`, `passiveScannerTabComponent`, etc., `currentSettings()`, `validateAndCollectCustomPatterns`, `applySettingsToUi`, `parseTimeoutSeconds`, `parseIdSetInput`, `shutdown`, `parseAllowedOriginsInput`, `parseContentTypePrefixesInput`, `applyAndSaveSettings`)
- Lines 1526–1635: Private section builders (portion): `applyMcpToolToggles`, `dialogParentComponent`, `helpSection`, `privacySection`, `passiveAiScannerSection`, `refreshPassiveAiStatus`, `applyPassiveAiSettings`
- Lines 1637–1930: Status display and dialog helpers: `showPassiveAiFindingsDialog`, `showActiveAiFindingsDialog`, `testBackendConnection`, `showActiveScanQueueDialog`, `showScannerTriageDialog`, `severityRank`, `activeAiScannerSection`, `updateActiveRiskDescription`, `refreshActiveAiStatus`, `applyActiveAiSettings`
- Lines 2002–2500+: Tab section builders continued: `promptSection`, `customPromptsSection`, `mcpSection`, `tokenPanel`, `mcpQuickActions`, `buildSseUrl`, `buildCurlCommand`, `copyToClipboard`, `buildMcpToolsPanel`
- Lines 2457–2782: Utility/warning methods: `updateUnsafeToolStates`, `updatePrivacyWarnings`, `updateRiskWarnings`, `refreshPrivacyNotice`, `refreshMcpNotice`, `updateSaveFeedback`, `updateMcpTlsState`, `updateMcpCorsWarning`, `collectMcpToolToggles`, `collectEnabledUnsafeTools`, `applyUnsafeToolApprovals`, `updateProfileWarnings`, `availableMcpToolsWithReasons`, `availableMcpTools`, `updateFieldStyle`, `styleCombo`, `openExternalCli`, `shellQuote`

**The challenge:** `SettingsPanel` is a single class. You cannot extract class members to a separate file in Kotlin while keeping them as class members — they must either remain in the class or become top-level functions/extension functions that accept the state they need as parameters. The LOCKED decision says "extract to same-package top-level functions/objects in NEW files." This is achievable for methods that only need their parameters; it is not achievable for methods that read `private val` fields of `SettingsPanel` (the UI component references like `passiveAiEnabled`, `mcpEnabled`, etc.).

**Viable extraction approach:** The section-builder methods (`passiveAiScannerSection()`, `activeAiScannerSection()`, `mcpSection()`, `promptSection()`, `customPromptsSection()`, `helpSection()`, `privacySection()`) already delegate most construction to dedicated `*ConfigPanel` classes in `ui/panels/`. These builder methods in `SettingsPanel` primarily pass the pre-constructed UI fields (spinners, toggles) into the panel builder. They are private methods that read `this.someField`.

Because they read private fields, strict top-level extraction would require passing all field references as parameters — making the function signatures very wide. A cleaner alternative that satisfies the locked decision: convert the section builders into `internal` extension functions on `SettingsPanel` in a new file. Kotlin extension functions on a class can only access `public` and `internal` members of the class, not `private` ones. This means all the UI component fields referenced by the section builders would need to become `internal` (not `private`).

**Recommended approach for SettingsPanel:**
1. Change the `private val` declarations for UI component fields to `internal val` (visibility widening within the same module — no behaviour change, no call-site change outside the module).
2. Extract the section-builder private methods as `internal fun SettingsPanel.*()` extension functions into two new files, grouped by tab:

| New File | Contents | Approx Lines |
|----------|----------|-------------|
| `SettingsPanelScannerTabs.kt` | `passiveAiScannerSection()`, `refreshPassiveAiStatus()`, `applyPassiveAiSettings()`, `showPassiveAiFindingsDialog()`, `activeAiScannerSection()`, `refreshActiveAiStatus()`, `applyActiveAiSettings()`, `updateActiveRiskDescription()`, `showActiveAiFindingsDialog()`, `showActiveScanQueueDialog()`, `showScannerTriageDialog()`, `severityRank()` | ~450 |
| `SettingsPanelMcpTabs.kt` | `mcpSection()`, `tokenPanel()`, `mcpQuickActions()`, `buildSseUrl()`, `buildCurlCommand()`, `copyToClipboard()`, `buildMcpToolsPanel()`, `updateUnsafeToolStates()`, `collectMcpToolToggles()`, `collectEnabledUnsafeTools()`, `applyUnsafeToolApprovals()`, `availableMcpToolsWithReasons()`, `availableMcpTools()`, `updateMcpTlsState()`, `updateMcpCorsWarning()`, `refreshMcpNotice()` | ~500 |
| Keep in `SettingsPanel.kt` | Constructor + field declarations + `init` + public API + `currentSettings()` + `applySettingsToUi()` + `applyAndSaveSettings()` + `helpSection()` + `privacySection()` + `promptSection()` + `customPromptsSection()` + `updatePrivacyWarnings()`, `updateRiskWarnings()`, `refreshPrivacyNotice()`, `updateSaveFeedback()`, styling helpers | ~480 |

**Cross-reference risk — private field visibility:** The main risk is `private val` fields accessed in extracted extension functions. Changing them to `internal val` is the only clean path that maintains same-package-file extraction without copy-pasting all field references as parameters. This is a visibility change within the module only — Burp's classloader sees the compiled class, not the visibility modifier, so there is no behaviour or binary change. The existing tests do not construct `SettingsPanel` directly (they test via `AgentSupervisor` and individual panel classes), so this change does not break tests.

**Alternative if `internal` is objectionable:** Keep `private val` fields in the class, and instead extract only the methods that are purely building Swing component trees from their parameters (the delegate calls to `*ConfigPanel`). These methods already receive everything they need via the panel constructors; `passiveAiScannerSection()` for example simply passes pre-constructed `JSpinner`, `JCheckBox`, etc. references. Measure what remains in `SettingsPanel.kt` after those extractions — the init block alone is ~440 lines. If that doesn't get below 500, the `internal` field approach is required.

### 3.3 PassiveAiScanner.kt (2566 lines → target: named file under 500)

**Current structure:**
- Lines 1–35: Package, imports
- Lines 37–54: `data class PassiveAiFinding` and `data class PassiveAiScannerStatus` (file-level)
- Lines 56–2566: `class PassiveAiScanner` — one large class with a `private companion object` at line 2481

**Internal structure of PassiveAiScanner:**
- Public API (lines 56–545): constructor, `budgetPaused`, `setBudgetPaused`, `isBudgetPaused`, `reconcileBudget`, `reconcileBudgetAndLog`, counters, executor, `setEnabled`, `applyOptimizationSettings`, `ensureBackendRunning`, `waitForBackendSession`, `getStatus`, `getLastFindings`, `shutdown`, `resetStats`, `getManualScanProgress`, `manualScan`, `enqueueForScanCheck`, `localChecks`, `isEnabled`, `applyOptimizationSettings`
- Analysis entry point (lines ~600–1050): `analyzeManually`, main analysis flow calling AI, `handleAiResponse`, `handleParsedAiIssues`, `handleFinding`, `recordFinding`, `issueNameForPassive`, `hasExistingIssue`, `queueToActiveScanner`
- JS endpoint discovery (lines ~1050–1105): `extractAndLogJsEndpoints`, `discoveredJsEndpoints`
- Body/prompt helpers (lines ~1100–1500): `truncateWithEllipsis`, `endpointDedupWindowMs`, `responseFingerprintDedupWindowMs`, `promptCacheTtlMs`, `trimLruCache`, `shouldSkipAiAfterLocalFindings`, `shouldSkipUninterestingTraffic`, `hasInterestingResponseHeaders`, `shouldSkipRecentlyAnalyzedEndpoint`, `buildEndpointCacheKey`, `normalizePathSegments`, `buildCompactRequestBody`, `buildCompactResponseBody`, `isJsonBody`, `compactJsonBody`, `compactHtmlBody`, `promptResultCacheValue`, `putPromptResultCacheValue`, `sha256Hex`, `buildAnalysisPrompt`, `buildBatchAnalysisPrompt`, `flushBatch`
- Local heuristics (lines ~2057–2215): `internal data class LocalFinding`, `runLocalChecks`, `checkForSqlErrors`, `checkForXssReflection`, `checkForSensitiveDataExposure`, `checkForCsrfMissing`, `checkForDangerousUploadExtension`
- AI response parsing (lines ~2215–2400): `parseIssuesJson`, `parseIssuesFromAiResponse`, `cleanJsonResponse`, `parseIssuesNode`, `parseNodeIfValid`, `stripCodeFences`, `extractBalancedJsonCandidates`
- Batch analysis (lines ~2400–2480): `parseArgsMapOrEmpty` (actually on McpToolExecutor), batch queue handling
- `companion object` with constants (lines 2481–2535)
- Misc helpers (lines 2537–2566): `buildMetadataSectionPlain`, `mapSeverity`, `severityLevel`, `mapTitleToVulnClass`, `isGeminiCapacityError`, `maybeLogBackoff`

**Proposed extractions:**

Since all of these are class members (not top-level), the same `internal` visibility approach applies. However, unlike SettingsPanel, many PassiveAiScanner helper methods only access `companion object` constants (not instance fields), making them good candidates for extraction as standalone top-level functions (passing the few instance references they need explicitly).

| New File | Contents | Approx Lines |
|----------|----------|-------------|
| `PassiveAiScannerModels.kt` | File-level data classes only: `PassiveAiFinding`, `PassiveAiScannerStatus`, `internal data class LocalFinding`, `internal data class AiIssueItem`, `private data class CachedAiIssues`, `data class PendingAnalysis` (if top-level or extractable) | ~60 |
| `PassiveAiScannerHeuristics.kt` | `runLocalChecks`, `checkForSqlErrors`, `checkForXssReflection`, `checkForSensitiveDataExposure`, `checkForCsrfMissing`, `checkForDangerousUploadExtension` — these are `private` methods that only need request/response parameters, no instance fields | ~200 |
| `PassiveAiScannerParsing.kt` | `parseIssuesFromAiResponse`, `cleanJsonResponse`, `parseIssuesJson`, `parseIssuesNode`, `parseNodeIfValid`, `stripCodeFences`, `extractBalancedJsonCandidates`, `sha256Hex` (delegates to Hashing) — these are parse-only, take String parameters, return values | ~200 |
| `PassiveAiScannerPrompts.kt` | `buildAnalysisPrompt`, `buildBatchAnalysisPrompt`, `buildMetadataSectionPlain`, `buildCompactRequestBody`, `buildCompactResponseBody`, `isJsonBody`, `compactJsonBody`, `compactHtmlBody`, `truncateWithEllipsis` — text/prompt builders, no instance state beyond constants | ~350 |
| Keep in `PassiveAiScanner.kt` | Constructor, all instance fields, `companion object`, public API methods, `enqueueForScanCheck`, `localChecks` (entry points), analysis flow methods (`analyzeManually`, `handleAiResponse`, `handleParsedAiIssues`, `handleFinding`, `recordFinding`), dedup methods (`shouldSkip*`, `buildEndpointCacheKey`), cache access (`promptResultCacheValue`, `putPromptResultCacheValue`), batch and JS endpoint handling, `ensureBackendRunning`, `waitForBackendSession` | ~480 |

**Cross-reference risk — `companion object` constants:** The `private companion object` at line 2481 holds ~35 constants (BACKOFF thresholds, cache sizes, regex patterns). These are `private` to the class. Extracted top-level functions that previously referenced these constants would need them passed as parameters or the companion object changed to `internal companion object`. The recommended approach: move the `companion object` constants that are needed only in extracted functions to top-level `private const val` declarations in the new file, and keep the class-specific constants in the class companion object.

**Critical preserved items:** `internal data class LocalFinding` is referenced by `AiPassiveScanCheck.kt` (calls `passiveAiScanner.localChecks()` which returns `List<LocalFinding>`). The `LocalFinding` type must remain `internal` and in the `scanner` package. Moving it to `PassiveAiScannerModels.kt` in the same package is safe.

---

## Section 4: ServiceLoader / Registration Risk

**ServiceLoader registration file:**
`src/main/resources/META-INF/services/com.six2dez.burp.aiagent.backends.AiBackendFactory`

Contains 11 entries (verified by reading the file):
1. `com.six2dez.burp.aiagent.backends.cli.CodexCliBackendFactory`
2. `com.six2dez.burp.aiagent.backends.cli.GeminiCliBackendFactory`
3. `com.six2dez.burp.aiagent.backends.cli.OpenCodeCliBackendFactory`
4. `com.six2dez.burp.aiagent.backends.cli.ClaudeCliBackendFactory`
5. `com.six2dez.burp.aiagent.backends.lmstudio.LmStudioBackendFactory`
6. `com.six2dez.burp.aiagent.backends.nvidia.NvidiaNimBackendFactory`
7. `com.six2dez.burp.aiagent.backends.perplexity.PerplexityBackendFactory`
8. `com.six2dez.burp.aiagent.backends.ollama.OllamaBackendFactory`
9. `com.six2dez.burp.aiagent.backends.openai.OpenAiCompatibleBackendFactory`
10. `com.six2dez.burp.aiagent.backends.cli.CopilotCliBackendFactory`
11. `com.six2dez.burp.aiagent.backends.anthropic.AnthropicBackendFactory`

**Split impact:** None. The split affects only three files in the `mcp/tools/`, `ui/`, and `scanner/` packages. No factory class is moved; no class in `backends/` is modified. The ServiceLoader file references fully-qualified class names that remain unchanged.

**BackendRegistryTest:** `BackendRegistryTest.kt` contains:
- `listBackendIds_usesAvailabilityCachePerSettings()` — tests ordering/caching behaviour
- `anthropicBackend_registeredWithCorrectId()` — asserts `allIds.contains("anthropic")` (does NOT assert a factory count)
- `reloadAndShutdown_clearAvailabilityCache()` — tests cache invalidation

**The test does NOT assert a specific factory count integer.** The CONTEXT.md refers to "SC2's BackendRegistryTest.loadAll() factory-count assertion" — this assertion is not a count check; it is the `anthropicBackend_registeredWithCorrectId()` test that asserts `"anthropic"` is present in `registry.listAllBackendIds()`. Planners should not frame the gate as "assert count=11" but as "BackendRegistryTest passes green."

**`mergeServiceFiles()` in shadow JAR:** `build.gradle.kts` configures the shadow task with service file merging. The split does not add any new service files, so no change to build configuration is needed.

---

## Section 5: No-Behaviour-Change Verification Approach

**Per-extraction gate:**
```bash
JAVA_HOME=$(/usr/libexec/java_home -v 21) ./gradlew test
```
Use this form (not bare `./gradlew`) because the project's CONVENTIONS.md documents that Gradle 8.12.1 fails under JDK >= 24 (Homebrew default). Claude Code's Bash sessions have `JAVA_HOME` pre-set via `.claude/settings.local.json`, but explicit is safer.

**Why `test` not `check`:**
Phase 18 (QUAL-05) fixed the `generateBuildFlags` wiring so `./gradlew ktlintCheck` runs standalone. However, CONTEXT.md says "if `./gradlew check`/`ktlintCheck` still misbehaves standalone, fall back to `./gradlew test`." The per-extraction gate should be `./gradlew test` (always works, runs all JUnit tests). Use `./gradlew check` as the final phase gate (includes ktlint) rather than per-extraction.

**Phase gate (after all extractions):**
```bash
JAVA_HOME=$(/usr/libexec/java_home -v 21) ./gradlew check
```

**What `./gradlew test` exercises:**
- `BackendRegistryTest` (SC2 gate — anthropic factory present)
- `RedactionTest`, `AgentSettingsMigrationTest`, `PassiveAiScannerTest`, all unit tests
- The tests call into the same compiled bytecode — a visibility-change from `private` to `internal` on field declarations does not affect test behaviour since tests operate at the public API boundary

**Fat JAR gate (after all splits, before phase close):**
```bash
JAVA_HOME=$(/usr/libexec/java_home -v 21) ./gradlew shadowJar
```
Build must succeed and produce `build/libs/Custom-AI-Agent-0.8.0.jar`. This confirms no missing symbol after the split.

**Manual smoke (HUMAN-UAT, not automated):** Load the resulting JAR in Burp and confirm the MCP server starts and at least one tool responds. This is the same class of check as Phase 16's SC5 UAT and is appropriately a human item.

---

## Section 6: Docs Facts Inventory (for DOC-02 doc-writing tasks)

The doc tasks need accurate v0.9.0 specifics. Sources by feature:

### Anthropic Backend (CAP-01)
- **Implementation:** `backends/anthropic/AnthropicBackend.kt` + `AnthropicBackendFactory.kt`
- **Transport:** Uses `MontoyaHttpTransport` (not a vendored Anthropic SDK) — from DECISIONS.md context and REQUIREMENTS.md "Out of Scope" table: "Vendoring an Anthropic SDK that embeds its own HTTP client — Would bypass MontoyaHttpTransport"
- **HTTP client:** OkHttp via existing `HttpBackendSupport` pattern
- **API:** Anthropic Messages API (`/v1/messages`)
- **Features shipped in Phase 14:** streaming (single-chunk, proxy-visible), token counting, encrypted API key (via SEC-01), model selection (SC1–SC3). Native tool-use and prompt-caching deferred.
- **Settings fields:** `anthropicModel`, `anthropicApiKey` (visible in SettingsPanel.kt constructor at lines 146–148)
- **Backend ID:** `"anthropic"` (confirmed by BackendRegistryTest)
- **Source for doc:** Phase 14 CONTEXT.md/SUMMARY + REQUIREMENTS.md CAP-01 entry + CHANGELOG.md `[Unreleased]` (when promoted)

### AES-256-GCM Secret Encryption (SEC-01)
- **Implementation:** `javax.crypto` only — no Bouncy Castle, no Tink (REQUIREMENTS.md Out of Scope table)
- **Cipher:** AES-256-GCM via `javax.crypto.Cipher`
- **Key bootstrap:** Per-install random key (resolved at Phase 12 plan-phase — stated in REQUIREMENTS.md "key-bootstrap mechanism resolved at this item's plan-phase")
- **Scope:** 7+ stored secrets: all backend API keys, `mcp.token`, `mcp.tls.keystore.password`
- **Migration:** one-time idempotent migration on load
- **Source for doc:** Phase 12 SUMMARY + REQUIREMENTS.md SEC-01 + DECISIONS.md (new ADR for v0.9.0)

### Real HKDF Host Anonymization (PRIV-01)
- **Decision resolved:** Uses real HKDF (HMAC-SHA256 extract/expand) — REQUIREMENTS.md PRIV-01
- **State.md decision:** `[13-03]: SecretShapes is single AWT-free source of truth for PRIV-04 and Phase 15 tripwire reuse contract`
- **Effect:** STRICT mode host anonymization now matches its documentation
- **Source for doc:** Phase 13 SUMMARY + REQUIREMENTS.md PRIV-01

### Body/Custom Redaction Patterns (PRIV-02)
- **What shipped:** Redaction catches secrets in request/response bodies (leading field of x-www-form-urlencoded) + user-configurable custom pattern list
- **State.md decision:** `customRedactionPatterns persisted plaintext newline-joined — NOT SecretCipher (config not secrets)`; `compiledCustomPatterns @Volatile list`
- **Validation:** `SafeRegex.isPatternSafe` (regex compile + 50ms ReDoS probe) on save
- **UI:** `customPatternsArea` in SettingsPanel (PRIV-02 section visible at line 222+)
- **Source:** Phase 13 SUMMARY + REQUIREMENTS.md PRIV-02

### External MCP Client (CAP-02)
- **Implementation:** kotlin-sdk 0.5.0 (NOT 0.13.0 — Path A confirmed, STATE.md blockers section)
- **Transport:** `SseClientTransport` / `StdioClientTransport` from existing sdk
- **Trust boundary:** "untrusted-output trust boundary marker" — from CONTEXT.md (Phase 16 decision)
- **State.md decision:** `Path A confirmed: kotlin-sdk stays at 0.5.0; only 3 explicit dep pins needed`
- **Security note:** External server auth tokens stored encrypted (SEC-01); SSRF/untrusted-output safeguards
- **UI:** `ExternalServersPanel` in `ui/panels/` (visible in SettingsPanel.kt at line 237)
- **Phase 16 is code-complete** — STATE.md confirms 5/6 plans completed, human-UAT pending
- **Source:** Phase 16 CONTEXT.md/SUMMARY + REQUIREMENTS.md CAP-02

### Token Budget Guardrails (CAP-04)
- **Implementation:** `BudgetGuard` in `util/` (referenced in PassiveAiScanner.kt lines 89–110)
- **States:** `BudgetGuard.State.CAP` → pause passive scanning; `WARN` → advisory; `OFF` → no action
- **Gate:** reversible — cap can be cleared/raised to resume
- **UI fields:** `tokenBudgetWarnField`, `tokenBudgetHardCapField` in SettingsPanel (lines 528–537)
- **Source:** Phase 14 SUMMARY (CAP-04 co-landed with CAP-01) + REQUIREMENTS.md CAP-04

### Pre-Send Secret Tripwire (PRIV-03)
- **Trigger:** scans final redacted payload for high-entropy secrets
- **Behaviour:** warn-with-confirmation (not silent block); allowlist actions audit-logged
- **State.md decision:** `[13-03]: ContextPreviewDialog banner uses Level.WARN (advisory); categories-only — raw values never interpolated`
- **Source:** Phase 15 SUMMARY + REQUIREMENTS.md PRIV-03

---

## Section 7: .planning Reconciliation Targets

### Confirmed stale — PRUNE

**STATE.md blockers:**
- The multi-paragraph "(SUPERSEDED)" kotlin-sdk 0.13.0 blocker (lines 142–143 of STATE.md). The resolution ("Path A confirmed") is documented there. The entire block from "*(SUPERSEDED) Phase 16 (CAP-02) was deferred*" through the end of that bullet can be removed, leaving only the "✅ RESOLVED 2026-06-12" summary.
- "GitHub issue #62 (release pipeline publishes stale code) gates the v0.7.0 release; Phase 4 must close before Phase 6 can ship." — Both Phase 4 and Phase 6 are long completed; this is stale carryover.
- "Phase 8 code + resubmission artifacts complete and verified… maintainer is performing the manual Burp smoke test…" — Phase 8 closed at v0.8.0; this is stale.

**STATE.md `stopped_at` and `Current Position`:**
- Update to reflect Phase 19 as the current phase. Current stopped_at says "Phase 16 (External MCP Client) CODE-COMPLETE" — Phase 16 is done; Phase 19 is executing.

**STATE.md `Pending Todos`:**
- "Phase 16 (CAP-02) pre-planning: run kotlin-sdk 0.13.0 Burp-JVM compatibility test" — Moot; Path A resolved this.
- "Phase 14 (CAP-01) planning: decide key-bootstrap UX" — Moot; Phase 12 + 14 are complete.

**REQUIREMENTS.md Traceability table:**
- All items marked "Pending" (SEC-01, SEC-02, SEC-03, QUAL-01, DOC-01, DOC-02) need their status evaluated. At Phase 19's close: SEC-01/02/03 remain "Pending" (Phase 12 is in the roadmap but the traceability shows it pending — check if Phase 12 shipped). Based on STATE.md velocity table, Phase 12 is not listed with completed plans, suggesting it may still be pending. This is an area for the DOC-01 plan task to verify.

**Closed issues to acknowledge:**
- #62 — fixed in v0.7.0 (Phase 6 / release pipeline)
- #66 — fixed in quick task 260527-f7q (OpenAI-compatible diagnostics)
- #67 — fixed in quick task 260527-f7q (Copilot CLI hang)
- #68 — fixed in quick task 260527-f7q (CLI tokenizer)
- #69 — addressed in Phase 7 (proxy transport + MCP scope hardening)
- #231 — BApp Store resubmission (Phase 8); `08-REOPEN-REPLY.md` was ready at STATE.md write time

**ROADMAP:** Mark Phases 12–18 as complete once verified. Current STATE.md only shows phases up to 18 in velocity table.

---

## Section 8: Docs Style Reference

The three existing `docs/` pages follow this pattern (confirmed by reading `mcp-hardening.md`):
- H1 title, then short lead paragraph describing purpose
- H2 sections with numbered step lists (action-oriented, not descriptive)
- Tables for structured reference data
- Code blocks for commands and configuration values
- Concise: `mcp-hardening.md` is ~60 lines total

**New pages must match:** `docs/anthropic-backend.md` and `docs/external-mcp-servers.md` should follow the same task-oriented, concise structure. No prose padding. Sections: setup, key options, privacy/security notes.

---

## Standard Stack (for doc writing tasks)

No new packages. All doc work is markdown + existing project structure.

## Package Legitimacy Audit

No external packages are installed in this phase. The split is purely in-tree; the doc pages are markdown only.

**Packages removed due to slopcheck [SLOP] verdict:** none
**Packages flagged as suspicious [SUS]:** none

---

## Architecture Patterns

### Recommended Project Structure After Split

```
src/main/kotlin/com/six2dez/burp/aiagent/
├── mcp/tools/
│   ├── McpTools.kt              # registerTools() + registerToolsLegacy() only (~90 lines)
│   ├── McpToolModels.kt         # @Serializable data class types (~420 lines)
│   ├── McpToolHelpers.kt        # private top-level transforms (~380 lines)
│   └── McpToolExecutorImpl.kt   # object McpToolExecutor (~1260 lines)
├── ui/
│   ├── SettingsPanel.kt         # class declaration + fields + init + public API (~480 lines)
│   ├── SettingsPanelScannerTabs.kt  # scanner section builders as internal extensions (~450 lines)
│   └── SettingsPanelMcpTabs.kt     # MCP/Burp section builders as internal extensions (~500 lines)
└── scanner/
    ├── PassiveAiScanner.kt      # class + public API + analysis flow + dedup (~480 lines)
    ├── PassiveAiScannerModels.kt    # data classes (~60 lines)
    ├── PassiveAiScannerHeuristics.kt # local check functions (~200 lines)
    ├── PassiveAiScannerParsing.kt   # AI response parsing functions (~200 lines)
    └── PassiveAiScannerPrompts.kt   # prompt/body builders (~350 lines)
```

### Anti-Patterns to Avoid

- **Sub-package creation:** CONTEXT.md locks "no new sub-packages." All extracted files stay in the same package directory.
- **Wrapping into new classes:** Do not wrap extracted functions into new classes — use top-level functions or extension functions only (unless code was already a class member that moves wholesale as an object).
- **Changing behaviour during split:** If any method is found to have a bug, capture it as a TODO comment — do not fix inline.
- **Splitting `companion object` across files:** Keep the class's `companion object` in the class's primary file. Move constants that are needed in extracted top-level files to file-level `private const val`.

---

## Common Pitfalls

### Pitfall 1: `private` visibility blocks extraction
**What goes wrong:** Attempting to call a `private` method or field from an extension function defined in a different file — Kotlin does not allow this even in the same package.
**Why it happens:** Kotlin `private` is file-private, not class-private. A `private fun` in `PassiveAiScanner.kt` is inaccessible to `PassiveAiScannerParsing.kt` even if both are in the same package.
**How to avoid:** Change to `internal` before extracting. Verify with `./gradlew compileKotlin` after each visibility change — the compiler reports access errors immediately.
**Warning signs:** IDE shows "Cannot access 'X': it is private in file" red underline.

### Pitfall 2: `companion object` constants become inaccessible
**What goes wrong:** Extracted top-level functions reference `CONSTANT_NAME` which was a `private companion object` member — compile error.
**Why it happens:** `private companion object` constants are only accessible within the class body.
**How to avoid:** For constants needed in extracted files, either (a) pass them as parameters, (b) move them to `internal companion object`, or (c) redeclare them as `private const val` in the new file.
**Warning signs:** `Unresolved reference: CONSTANT_NAME` compile error.

### Pitfall 3: `internal data class` visibility
**What goes wrong:** `internal data class LocalFinding` (inside `PassiveAiScanner.kt`) is referenced by `AiPassiveScanCheck.kt`. Moving it to `PassiveAiScannerModels.kt` — if accidentally changed to `private` — breaks `AiPassiveScanCheck`.
**How to avoid:** Keep `internal` visibility on `LocalFinding` and `AiIssueItem`. Confirm with compilation.

### Pitfall 4: Wrong Gradle invocation drops JDK
**What goes wrong:** Running bare `./gradlew test` under macOS with Homebrew's JDK 25 causes Gradle 8.12.1 to fail with a JDK version error.
**How to avoid:** Always use `JAVA_HOME=$(/usr/libexec/java_home -v 21) ./gradlew test` unless the shell's `.tool-versions` hook is confirmed active.

### Pitfall 5: Extracting `mcpTool {}` lambda bodies needs care
**What goes wrong:** The `registerToolsLegacy` function contains inline tool handler lambdas that capture `api` and `context` from the extension function receiver. Moving them to a different file requires that they are called as top-level functions that accept `api` and `context` as parameters.
**How to avoid:** `registerToolsLegacy` is already marked `@Suppress("unused")` — leave it in place in `McpTools.kt`. The _active_ `registerTools()` delegates to 10 `register*Tools()` extension functions that are already in separate files (HistoryTools.kt, SiteMapTools.kt, etc., as documented in STRUCTURE.md). McpTools.kt itself does NOT need those delegated into it — the 2925 lines of McpTools.kt contain code that is not in those separate files.

---

## Validation Architecture

Skip this section: `workflow.nyquist_validation` is not explicitly set to false, so it is enabled.

### Test Framework

| Property | Value |
|----------|-------|
| Framework | JUnit 5 (Jupiter) via Gradle test task |
| Config file | `build.gradle.kts` (test block) |
| Quick run command | `JAVA_HOME=$(/usr/libexec/java_home -v 21) ./gradlew test` |
| Full suite command | `JAVA_HOME=$(/usr/libexec/java_home -v 21) ./gradlew check` |

### Phase Requirements → Test Map

| Req ID | Behavior | Test Type | Automated Command | Notes |
|--------|----------|-----------|-------------------|-------|
| QUAL-01 SC1 | Named files under 500 lines after split | build verification | `wc -l` on three files post-split | Automated check in verification task |
| QUAL-01 SC2 | ServiceLoader registration intact; BackendRegistryTest passes | unit | `./gradlew test --tests "*.BackendRegistryTest"` | anthropicBackend_registeredWithCorrectId() asserts "anthropic" in registry |
| QUAL-01 general | No behaviour change — full suite green before + after each extraction | unit | `./gradlew test` | Run before AND after each extraction commit |
| DOC-01 | .planning/ reconciliation completeness | manual review | N/A | Human reviewer checks pruned items and updated facts |
| DOC-02 | docs/ pages exist and have correct content | manual | `ls docs/anthropic-backend.md docs/external-mcp-servers.md` | Content accuracy is HUMAN-UAT (live site render) |

### Sampling Rate

- **Per extraction commit:** `JAVA_HOME=$(/usr/libexec/java_home -v 21) ./gradlew test`
- **Per wave merge:** `JAVA_HOME=$(/usr/libexec/java_home -v 21) ./gradlew check`
- **Phase gate:** Full suite green + `shadowJar` builds successfully before `/gsd-verify-work`

### Wave 0 Gaps

None — existing test infrastructure covers all phase requirements. The split does not require new test files; existing tests serve as the no-behaviour-change safety net.

---

## Environment Availability

| Dependency | Required By | Available | Version | Fallback |
|------------|------------|-----------|---------|----------|
| JDK 21 | `./gradlew test` | ✓ | Temurin 21 (via JAVA_HOME or .tool-versions) | None — required |
| Gradle 8.12.1 | Build | ✓ | 8.12.1 (wrapper pinned) | None |
| kotlin-sdk 0.5.0 | Already in build (Phase 16) | ✓ | Already resolved by Path A | N/A |

---

## Security Domain

This phase introduces no new network-facing code, no new authentication paths, and no new data handling. The split is purely mechanical.

| ASVS Category | Applies | Note |
|---------------|---------|------|
| V5 Input Validation | No (no new inputs) | Split is mechanical |
| V2–V4, V6 | No | No auth, crypto, or access control code is added |

The doc pages (DOC-02) must correctly describe v0.9.0 security features as-shipped — particularly:
- AES-256-GCM is the cipher (not AES-128, not GCM without auth tag)
- HKDF is real HKDF (HmacSHA256 extract+expand), not salted SHA-256
- External MCP trust-boundary marker prevents untrusted-output injection

---

## Assumptions Log

| # | Claim | Section | Risk if Wrong |
|---|-------|---------|---------------|
| A1 | Phase 12 (SEC-01/02/03) shipped state is "Pending" in REQUIREMENTS.md traceability | Section 7 | If Phase 12 actually completed, DOC-01 plan must also update its traceability rows to "Complete" |
| A2 | McpToolExecutor can live in a single extracted file at ~1260 lines (SC1 does not gate helper file sizes) | Section 3.1 | Per CONTEXT.md: "SC1 does not gate the helper-file sizes" — this is locked, not assumed |
| A3 | `applyAreaStyle`, `applyFieldStyle` imported from `ui.design` are available in extracted extension function files without new imports (same package) | Section 3.2 | If these are in a different package (they are in `ui/design/`), they DO require explicit imports in extracted files. Risk: low — extension files in `ui/` package already import `ui.design.*` at the top of SettingsPanel.kt |

**If this table is empty of HIGH-risk assumptions:** All critical claims were verified by reading source files directly.

---

## Open Questions (RESOLVED)

1. **Phase 12 completion status**
   - What we know: STATE.md velocity table does not list Phase 12 with completed plans; REQUIREMENTS.md Traceability shows SEC-01/02/03 as "Pending" with Phase 12 as the assigned phase.
   - What's unclear: Did Phase 12 execute but its completion not update STATE.md, or is it truly pending?
   - Recommendation: DOC-01 plan task should read `.planning/phases/12-*/` to check for a SUMMARY or completed PLAN files before updating the traceability table.
   - RESOLVED: Plan 19-04 Task 1 reads `.planning/phases/12-*/` for SUMMARY/completed PLAN files and confirms Phase 12 completion status before Task 2 edits the REQUIREMENTS.md traceability table.

2. **SettingsPanel `private` → `internal` field widening — ktlint/detekt objections**
   - What we know: ktlint does not flag visibility changes. detekt has a baseline committed (Phase 18).
   - What's unclear: Does the detekt baseline include any rules that would flag `internal` vs `private` field declarations?
   - Recommendation: Run `./gradlew check` after the first SettingsPanel visibility change to surface any detekt rule violation; add to baseline if needed (it would be a pre-existing pattern by the time the baseline was set).
   - RESOLVED: Plan 19-03 Task 1 runs `JAVA_HOME=$(/usr/libexec/java_home -v 21) ./gradlew check` after the visibility widening and adds to the detekt baseline if any rule fires.

---

## Sources

### Primary (HIGH confidence)
- Source files read directly: `McpTools.kt`, `SettingsPanel.kt`, `PassiveAiScanner.kt` (line counts and structure verified)
- `META-INF/services/com.six2dez.burp.aiagent.backends.AiBackendFactory` (ServiceLoader entries verified)
- `BackendRegistryTest.kt` (test assertions verified)
- `.planning/phases/19-mega-file-split-docs/19-CONTEXT.md` (locked decisions)
- `.planning/REQUIREMENTS.md` (requirement definitions and traceability)
- `.planning/STATE.md` (project history and blockers)
- `.planning/codebase/STRUCTURE.md` and `CONVENTIONS.md` (project patterns)
- `DECISIONS.md` (ADR format reference)
- `docs/mcp-hardening.md` (style reference for new pages)

### Secondary (MEDIUM confidence)
- `CHANGELOG.md` (v0.8.0 / v0.7.0 entries for shipped-state reference)
- `SPEC.md` (living specification for DECISIONS.md update reference)

### Tertiary (LOW confidence — none)

---

## Metadata

**Confidence breakdown:**
- Split-boundary maps: HIGH — derived from direct reading of all three source files
- ServiceLoader risk: HIGH — service file read directly, test assertions read directly
- Verification approach: HIGH — grounded in CONVENTIONS.md and CONTEXT.md locked decisions
- Docs facts inventory: HIGH — derived from REQUIREMENTS.md, STATE.md decisions, and CHANGELOG.md
- .planning reconciliation targets: HIGH — derived from STATE.md text directly

**Research date:** 2026-06-16
**Valid until:** 2026-07-16 (stable codebase; 30-day horizon is conservative)
