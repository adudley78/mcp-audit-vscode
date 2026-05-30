# Changelog

## 0.1.2 — 2026-05-30

- Fix: bundle jsonc-parser's ESM build via esbuild `mainFields` so the extension no longer throws `Cannot find module ./impl/format` on activation.

## 0.1.1 — 2026-05-30

- Fix: extension now activates on JSON/JSONC open (`activationEvents` were empty in the original 0.1.0 scaffold and the same-version repackage never deployed the fix). Version bumped so the new build actually installs.

## 0.1.0 — 2026-05-18

Initial release.

- Inline diagnostics for MCP server configuration files in VS Code and Cursor
- Severity-mapped squiggles: CRITICAL/HIGH → Error, MEDIUM → Warning, LOW → Information, INFO → Hint
- Hover cards with finding title, description, evidence, remediation, OWASP tags, and CVE cross-references
- Status bar grade badge (`mcp-audit: A (0 findings)`)
- Auto-detection of the `mcp-audit` binary from PATH and common install locations
- `mcp-audit: Scan current file`, `mcp-audit: Scan workspace`, and `mcp-audit: Fix current file` command palette actions
- `mcp-audit.binaryPath`, `severityThreshold`, `runOnSave`, `runOnOpen` settings
- Graceful degradation when the binary is not found (one-time notification, no error storm)
- File size guard (5 MB), scan timeout (10 s), malformed-JSON diagnostic
- jsonc-parser based server-key line resolution (squiggles on the right server block, falls back to line 1)
