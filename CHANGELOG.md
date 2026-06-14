# Changelog

## 0.2.0 — 2026-06-14

### Added

- **Inline registry verdicts** via `mcp-audit vet` (requires mcp-audit ≥ 1.1.0).
  - After-text decorations appear on each server key, showing one of:
    - `✓ verified · 0 known CVEs (Maintainer)`
    - `⚠ N known CVEs — CVE-YYYY-NNNNN`
    - `⚠ possible typosquat — did you mean real-package?`
    - `? not in registry — no verdict available`
  - Hover cards include a capabilities one-liner and a link to the server's mcp-audit.dev page.
  - `cve` verdict → Warning diagnostic with CVE ID(s) in the Problems panel.
  - `typosquat` verdict → Warning diagnostic "Possible typosquat — did you mean X?".
  - `unknown` verdict → hint decoration only; no squiggle (unknown is not an error).
  - `verified` verdict → decoration only; no diagnostic.
- **Feature detection**: `mcp-audit vet --help` is probed once per binary path per session. If the subcommand is absent (binary < 1.1.0) or errors, the feature is silently disabled and existing scan diagnostics are unaffected.
- **Batch support**: when the binary's help text indicates multiple names are accepted, a single `mcp-audit vet name1 name2 ... --format json` invocation is used; otherwise one call per server.
- **Session cache**: vet results are cached per server name for the lifetime of the VS Code session. Repeated saves do not re-invoke the binary for already-resolved packages.
- **Debounce**: verdict runs are debounced 300 ms per document to avoid rapid-fire subprocess calls on quick edits.
- **New setting** `mcp-audit.verdict.online` (default `false`): pass `--online` to `mcp-audit vet` for live registry lookups instead of the bundled registry snapshot.

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
