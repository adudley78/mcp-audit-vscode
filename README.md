# mcp-audit — VS Code / Cursor Extension

Inline security diagnostics for [MCP](https://modelcontextprotocol.io/) server configuration files, powered by the [mcp-audit](https://github.com/mcp-audit/mcp-audit) CLI.

---

## What it does

- **Red/yellow squiggles** on server keys in `claude_desktop_config.json`, `mcp.json`, and other supported MCP config files — the same findings `mcp-audit scan` reports, shown inline as you edit.
- **Hover cards** with the finding title, severity, description, evidence, and remediation.
- **Status bar** showing the current file's letter grade and finding count (e.g. `mcp-audit: B (3 findings)`). Clicking opens the Problems panel.
- **Command palette** actions:
  - `mcp-audit: Scan current file` — manual re-scan
  - `mcp-audit: Scan workspace` — scan all open MCP config files
  - `mcp-audit: Fix current file` — run `mcp-audit fix` and show the diff in the Output channel

The extension is a thin wrapper — all detection logic runs in the `mcp-audit` binary. No detection is reimplemented in TypeScript.

---

## Requirements

Install the `mcp-audit` binary first:

```bash
pip install mcp-audit
# or download a binary from https://github.com/mcp-audit/mcp-audit/releases
```

The extension auto-detects the binary from `PATH` and common install locations. Set `mcp-audit.binaryPath` explicitly if auto-detection fails.

---

## Supported files

| File name | Description |
|---|---|
| `claude_desktop_config.json` | Claude Desktop |
| `mcp.json` | Cursor, generic MCP |
| `.cursor/mcp.json` | Cursor (project-level) |
| `.claude/settings.json` | Claude Code |
| `claude_code_config.json` | Claude Code (alternate) |
| `mcp_config.json` | Generic MCP |

---

## Settings

| Setting | Default | Description |
|---|---|---|
| `mcp-audit.binaryPath` | `""` | Explicit path to the `mcp-audit` binary. Leave empty for auto-detection. |
| `mcp-audit.severityThreshold` | `"info"` | Minimum severity to show (`info`, `low`, `medium`, `high`, `critical`). |
| `mcp-audit.runOnSave` | `true` | Re-scan automatically on save. |
| `mcp-audit.runOnOpen` | `true` | Scan automatically when a config file is opened. |

---

## Severity mapping

| mcp-audit severity | VS Code diagnostic |
|---|---|
| CRITICAL | Error (red squiggle) |
| HIGH | Error (red squiggle) |
| MEDIUM | Warning (yellow squiggle) |
| LOW | Information (blue line) |
| INFO | Hint (grey dots) |

---

## Known limitations

- **Line-level precision:** Squiggles point to the *server key block* in the config, not the specific offending line within that block. The `mcp-audit` CLI does not yet expose per-finding line numbers — a follow-up story (Finding.line_number) will improve this.
- **Large files:** Files over 5 MB are skipped (an INFO diagnostic is shown).
- **Scan timeout:** If `mcp-audit` takes more than 10 seconds, the scan is cancelled and a warning is shown in the Output channel.

---

## Cursor compatibility

Cursor is a VS Code fork. This extension works in Cursor without modification — install the VSIX from the VS Code Marketplace or via `Extensions: Install from VSIX…` in Cursor.

---

## Troubleshooting

**"mcp-audit binary not found"** — Install `mcp-audit` (`pip install mcp-audit`) or set `mcp-audit.binaryPath` to the absolute path of your binary.

**No squiggles on open files** — Check `mcp-audit.runOnOpen` is `true`, and run `mcp-audit: Scan current file` from the command palette. Check the **mcp-audit** Output channel (`View → Output → mcp-audit`) for error details.

**Squiggles are at line 1 instead of the right line** — This is a known limitation; see above.

---

## License

Apache 2.0 — same as the main [mcp-audit](https://github.com/mcp-audit/mcp-audit) project.
