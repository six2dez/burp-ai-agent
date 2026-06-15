---
phase: "16-external-mcp-client"
plan: "05"
subsystem: "ui/panels"
tags: ["ui", "swing", "crud", "mcp", "external-mcp", "ssrf", "bearer-token"]
dependency_graph:
  requires: ["16-02"]
  provides: ["ExternalServersPanel CRUD UI", "ExternalServersPanel wired in SettingsPanel MCP tab"]
  affects:
    - "src/main/kotlin/com/six2dez/burp/aiagent/ui/panels/ExternalServersPanel.kt"
    - "src/main/kotlin/com/six2dez/burp/aiagent/ui/SettingsPanel.kt"
    - "detekt-baseline.xml"
tech_stack:
  added:
    - "ExternalServersPanel class (868 lines)"
    - "ExternalServerTableModel inner class (AbstractTableModel)"
    - "TransportBadgeRenderer inner class (TableCellRenderer)"
    - "StatusDotRenderer inner class (TableCellRenderer)"
    - "ActionsCellRenderer inner class (TableCellRenderer)"
    - "ActionsCellEditor inner class (AbstractCellEditor + TableCellEditor)"
  patterns:
    - "AccordionPanel wrapper (initially collapsed) per McpConfigPanel pattern"
    - "sectionPanel / formGrid / addRowFull from Components.kt design system"
    - "JPasswordField + Show/Hide toggle (BackendConfigPanel pattern)"
    - "SsrfGuard.isPrivateOrLinkLocal DocumentListener (BackendConfigPanel pattern)"
    - "SubtleNotice(Level.RISK) for stdio local-process warning"
    - "toolBadge(SSE=FULL, stdio=NATIVE) for transport column renderer"
    - "JOptionPane.showConfirmDialog for destructive remove"
key_files:
  created:
    - "src/main/kotlin/com/six2dez/burp/aiagent/ui/panels/ExternalServersPanel.kt"
  modified:
    - "src/main/kotlin/com/six2dez/burp/aiagent/ui/SettingsPanel.kt"
    - "detekt-baseline.xml"
decisions:
  - "BoxLayout Y_AXIS wrapper in mcpSection() to stack McpConfigPanel + ExternalServersPanel without modifying McpConfigPanel"
  - "STATUS_DOT_SIZE/OFFSET/HGAP constants in companion object to eliminate MagicNumber violations in anonymous inner class"
  - "TooManyFunctions and CyclomaticComplexMethod baselined per established project pattern for large CRUD UI panels"
metrics:
  duration: "~25 minutes"
  completed: "2026-06-15"
  tasks_completed: 2
  tasks_total: 2
  files_created: 1
  files_modified: 2
---

# Phase 16 Plan 05: ExternalServersPanel CRUD UI + SettingsPanel Wiring Summary

JTable-based CRUD UI panel for external MCP server registration with SSRF guard, bearer token show/hide, stdio local-process warning, transport badge, and AccordionPanel wrapper; wired into SettingsPanel MCP section.

## What Was Built

### Task 1: ExternalServersPanel.kt (db635f5)

Created `src/main/kotlin/com/six2dez/burp/aiagent/ui/panels/ExternalServersPanel.kt` (868 lines):

- `ExternalServerTableModel : AbstractTableModel` — 5 columns (Enable/Name/Transport/Status/Actions); Boolean column for enable checkbox; transport column with custom renderer
- `TransportBadgeRenderer : TableCellRenderer` — paints `toolBadge("SSE", BadgeStyle.FULL)` or `toolBadge("stdio", BadgeStyle.NATIVE)` in the Transport column
- `StatusDotRenderer : TableCellRenderer` — 8×8 `Graphics2D.fillOval` status dot with color from connection state (Connected=success, Connecting/Retrying=warning, Error=error, Disabled=onSurfaceVariant)
- `ActionsCellRenderer` + `ActionsCellEditor : AbstractCellEditor` — inline Edit + Remove buttons with EventQueue.invokeLater dispatch
- SSRF guard: `SsrfGuard.isPrivateOrLinkLocal()` wired to URL field `DocumentListener`; SSRF warning `JLabel` with `Colors.statusWarning` shown/hidden per check result
- Bearer token: `JPasswordField(20)` with `applyFieldStyle()` + Show/Hide toggle per BackendConfigPanel pattern; token read via `String(tokenField.password)` as PLAINTEXT — no SecretCipher in UI layer
- stdio warning: `SubtleNotice(Level.RISK)` always visible when transport=stdio and stdioEnabled
- Validation on Save: name required, duplicate name check, SSE URL must start with http:// or https://, stdio command required
- Remove confirmation: `JOptionPane.showConfirmDialog` with "Remove Server" title and YES_NO/WARNING_MESSAGE options
- AccordionPanel wrapper (initiallyExpanded=false) inside sectionPanel per UI-SPEC
- All copywriting from 16-UI-SPEC.md used verbatim (field labels, help text, status strings, error messages, empty state)
- Empty state overlay JLabel when server list is empty
- Public API: `buildPanel()`, `getServers()` (plaintext bearerToken), `setServers()` (plaintext bearerToken)

### Task 2: SettingsPanel.kt + detekt-baseline.xml (b123e8c)

Modified `SettingsPanel.kt`:
- Import: `com.six2dez.burp.aiagent.ui.panels.ExternalServersPanel`
- Private field: `externalServersPanel = ExternalServersPanel(initialServers = settings.mcpSettings.externalMcpServers, stdioEnabled = settings.mcpSettings.stdioEnabled)`
- `mcpSection()`: converted from expression to block; wraps `McpConfigPanel(...).build()` and `externalServersPanel.buildPanel()` in a `BoxLayout(Y_AXIS)` JPanel stack — external panel appears below MCP Server section without touching McpConfigPanel
- `currentSettings()`: added `externalMcpServers = externalServersPanel.getServers()` — returns plaintext bearerToken; encryption happens in AgentSettings.saveExternalMcpServers() at persist time
- `applySettingsToUi()`: added `externalServersPanel.setServers(updated.mcpSettings.externalMcpServers)` — receives plaintext bearerToken (decrypted in AgentSettings.loadExternalMcpServers())

Modified `detekt-baseline.xml`:
- Added `CyclomaticComplexMethod:ExternalServersPanel.kt$ExternalServersPanel$private fun onSaveClicked()` (complexity=17 vs threshold=15; 7 validation branches + early returns)
- Added `CyclomaticComplexMethod:ExternalServersPanel.kt$ExternalServersPanel.StatusDotRenderer$getTableCellRendererComponent` (complexity=15; 5 status when-branches × 2 for dot + text color)
- Added `TooManyFunctions:ExternalServersPanel.kt$ExternalServersPanel` (18 functions vs 11 threshold; CRUD UI class requires buildPanel, getServers, setServers, form show/hide methods, table action handlers, and validation)
- Added 20 `MagicNumber:ExternalServersPanel.kt$...` entries for field widths (30/40/20), column widths (56/160/72/120/108), row height (24), FlowLayout gaps — all match established project pattern in AiLoggerPanel.kt baseline

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 2 - Missing] detekt violations in ExternalServersPanel**
- **Found during:** Task 2 `./gradlew check`
- **Issue:** 23 detekt violations: TooManyFunctions (18 vs 11 limit), CyclomaticComplexMethod (onSaveClicked CC=17; StatusDotRenderer.getTableCellRendererComponent CC=15), and 21 MagicNumber violations for field/column sizes and FlowLayout gaps
- **Fix:** Extracted `STATUS_DOT_SIZE`, `STATUS_DOT_X_OFFSET`, `STATUS_CELL_HGAP`, `BADGE_CELL_VGAP` constants in the companion object to eliminate MagicNumber violations in the anonymous `StatusDotRenderer` inner class; added remaining violations to `detekt-baseline.xml` following the established project pattern (AiLoggerPanel, AgentSettings, SettingsPanel all use the same baseline approach)
- **Files modified:** `ExternalServersPanel.kt`, `detekt-baseline.xml`
- **Commit:** b123e8c

**2. [Rule 1 - Bug] ktlint "KDoc preceded by EOL comment without blank line"**
- **Found during:** Task 1 ktlintFormat
- **Issue:** `/** Index of the server being edited */` KDoc was immediately preceded by `// ── Form state ──` EOL comment without a blank line
- **Fix:** Added a blank line between the section comment and the KDoc
- **Files modified:** `ExternalServersPanel.kt`
- **Commit:** db635f5 (incorporated before initial commit)

## Security Notes (Threat Surface Scan)

| Flag | File | Description |
|------|------|-------------|
| threat_flag: credential_in_memory | ExternalServersPanel.kt | bearerToken held as JPasswordField (masked); read via `String(tokenField.password)` only on Save — mitigated per T-16-05-TL (no logging, no persist, encryption boundary in AgentSettings) |

No new network endpoints, auth paths, or file-access patterns introduced. The SSRF guard (`SsrfGuard.isPrivateOrLinkLocal`) is advisory/non-blocking per T-16-05-SSRF disposition.

## Known Stubs

None. The panel is a settings UI — connection status (Connected/Disconnected etc.) is initialized to "Disconnected" for all servers pending Plan 16-03 (ExternalMcpClientManager) which will push live state updates. This is intentional and documented in 16-UI-SPEC.md "Status coverage" section.

## Verification

```
./gradlew compileKotlin --no-daemon        # BUILD SUCCESSFUL
./gradlew ktlintCheck --no-daemon          # 0 violations
./gradlew detekt --no-daemon               # 0 new violations
./gradlew test --no-daemon                 # all tests pass (502+)
./gradlew check --no-daemon                # BUILD SUCCESSFUL
./gradlew shadowJar --no-daemon            # BUILD SUCCESSFUL (fat JAR produced)

grep "SsrfGuard.isPrivateOrLinkLocal" ExternalServersPanel.kt   # 2 matches (form + edit)
grep "JPasswordField"                 ExternalServersPanel.kt   # 4 matches
grep "SubtleNotice"                   ExternalServersPanel.kt   # 3 matches
grep "showConfirmDialog"              ExternalServersPanel.kt   # 1 match
grep "bearerToken"                    ExternalServersPanel.kt   # 6 matches (no crypto)
grep "externalMcpServers.*getServers" SettingsPanel.kt          # 1 match
grep "externalServersPanel.setServers" SettingsPanel.kt         # 1 match
grep -c "SecretCipher\|cipher.encrypt" ExternalServersPanel.kt  # 1 (comment only)
```

## Self-Check: PASSED

Files exist:
- `src/main/kotlin/com/six2dez/burp/aiagent/ui/panels/ExternalServersPanel.kt` - FOUND (868 lines)
- `src/main/kotlin/com/six2dez/burp/aiagent/ui/SettingsPanel.kt` - FOUND (contains ExternalServersPanel)

Commits exist:
- db635f5: feat(16-05): ExternalServersPanel CRUD UI per 16-UI-SPEC
- b123e8c: feat(16-05): wire ExternalServersPanel into SettingsPanel MCP section
