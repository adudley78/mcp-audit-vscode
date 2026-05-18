# ADR-0002 — Extension lives in a separate repository

**Date:** 2026-05-18  
**Status:** Accepted  
**Decision made in:** STORY-0032  
**Recorded here in:** STORY-0042 (before publishing makes it irreversible)

---

## Context

When building the `mcp-audit-vscode` VS Code extension (STORY-0032), two
structural options were evaluated:

**Option A — Subdirectory of the main repo:**  
`mcp-audit/extensions/vscode/` inside the Python `mcp-audit` repository.
TypeScript tooling (npm, esbuild, `vsce`) co-exists with Python tooling
(`uv`, `pytest`, `ruff`). A single CI pipeline runs both.

**Option B — Separate repository:**  
`mcp-audit-vscode` as a standalone GitHub repository. Independent CI,
versioning, changelog, and Marketplace publishing pipeline. The extension
communicates with `mcp-audit` only through its binary's JSON stdout — no
import dependency at build time.

---

## Decision

**Option B was chosen and has been implemented.** This ADR records it before
the first `vsce publish` makes it permanent (marketplace listings are tied to
a publisher + extension name and cannot be migrated between repos without
republishing under a new ID).

---

## Reasons

### 1. Toolchain separation

The VS Code Marketplace toolchain (`@vscode/vsce`, `@vscode/test-electron`,
esbuild) is Node-centric. Adding it to a Python monorepo requires npm scripts
alongside `uv run` commands, increasing cognitive load for contributors who
know one ecosystem but not the other. Separate repos let each use the standard
toolchain idioms without compromise.

### 2. Independent versioning

The extension starts at `0.1.0`. It may ship hotfixes (e.g. a hover card
rendering bug) between `mcp-audit` minor releases. Coupling extension patch
versions to Python minor versions would create unnecessary friction. The
extension's public contract is the `mcp-audit scan --format json` output
schema — not the Python package version.

### 3. No build-time cross-language dependency

The extension does not import any Python code. It spawns the `mcp-audit`
binary at runtime and reads JSON from stdout. A separate repo makes this
runtime-only boundary explicit. Nothing in `mcp-audit-vscode/` requires Python
to build, test, or package.

### 4. Marketplace artifact cleanliness

`vsce package` produces a `.vsix` that must not include Python source,
Semgrep rules, test fixtures, or any other mcp-audit repo content. A
dedicated `.vscodeignore` in a standalone repo is straightforward. Expressing
"exclude everything in the monorepo except the TypeScript bundle" is
fragile and error-prone.

### 5. Publisher isolation

The VS Code Marketplace `publisher` field is tied to an Azure DevOps
organisation. Keeping the extension in a dedicated repo makes it easy to
transfer publisher ownership or add maintainers without granting access to
the main mcp-audit codebase.

---

## Constraint: wrapper, not reimplementation

This decision comes with one non-negotiable constraint:

> **The extension must not reimplement any detection logic in TypeScript.**

All security detection runs in the `mcp-audit` binary. The extension's only
job is:

1. Detect MCP config file names.
2. Spawn `mcp-audit scan --path <file> --format json`.
3. Parse the JSON output.
4. Render `vscode.Diagnostic` objects.

New detection rules and analyzers belong in the main `mcp-audit` repo.
If a detection change requires an extension change (e.g. a new Finding field),
that is a coordinated, intentional update — not organic drift.

---

## Public API contract

The JSON output of `mcp-audit scan --format json` is the **public API** between
the extension and the CLI. Specifically:

- `ScanResult.findings[]` — array of `Finding` objects
- `ScanResult.score.grade` — letter grade for the status bar
- `Finding.server` — server name used for line resolution
- `Finding.id`, `.severity`, `.title`, `.description`, `.evidence`, `.remediation`
- `Finding.owasp_mcp_top_10`, `.cve`, `.cwe`

The `types.ts` file in this repository is the authoritative TypeScript mirror
of the Python `models.py` definitions. Any breaking change to these fields
(rename, removal, type change) requires a **coordinated update** to `types.ts`
and a version bump in this extension.

**Never rely on undocumented fields or internal Python module interfaces.**

---

## Consequences

- `mcp-audit` (main repo): no npm/Node changes. Only documentation updates
  (`docs/ide-extension.md`, `README.md` badge, `CHANGELOG.md`).
- `mcp-audit-vscode`: its own CI (TypeScript lint + tests + `vsce package`
  on three OSes), its own `CHANGELOG.md`, its own Marketplace listing.
- The Cursor Marketplace submission (STORY-0042) uses the same `.vsix`
  artifact — no code changes needed, only a manual form submission.
- Open VSX Registry (for Gitpod/Theia users) is a future option — same
  artifact, separate submission.
