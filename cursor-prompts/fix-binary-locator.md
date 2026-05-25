# Fix: binaryLocator misses macOS Python framework and Homebrew paths

## Problem

`src/binaryLocator.ts` has a `candidatePaths()` function that checks a short
list of fallback locations when `which mcp-audit` fails. It misses two very
common macOS install locations:

1. `/opt/homebrew/bin/mcp-audit` — Homebrew-managed installs (Apple Silicon Macs)
2. `/Library/Frameworks/Python.framework/Versions/<N>/bin/mcp-audit` — standard
   macOS Python installs via python.org installer or system Python

VS Code launches extension processes with a stripped PATH that excludes both
of these locations, so `whichSync()` fails and none of the current candidates
match. The result: the extension silently does nothing, no squiggles, no status
bar item, and only a one-time toast that many users dismiss without reading.

Confirmed on: macOS 14, Python 3.12 installed via python.org, mcp-audit
installed via `pip install mcp-audit-scanner`. Binary is at:
`/Library/Frameworks/Python.framework/Versions/3.12/bin/mcp-audit`

## Fix

In `src/binaryLocator.ts`, extend the `candidatePaths()` function for macOS
to also check:

- `/opt/homebrew/bin/mcp-audit` (Homebrew, Apple Silicon)
- `/usr/local/opt/python/bin/mcp-audit` (Homebrew Intel)
- `/Library/Frameworks/Python.framework/Versions/3.13/bin/mcp-audit`
- `/Library/Frameworks/Python.framework/Versions/3.12/bin/mcp-audit`
- `/Library/Frameworks/Python.framework/Versions/3.11/bin/mcp-audit`
- `/Library/Frameworks/Python.framework/Versions/3.10/bin/mcp-audit`

Add them inside the existing `if (!IS_WINDOWS)` branch, after the existing
candidates. Keep the existing entries — just append the new ones.

Also add `/opt/homebrew/bin/mcp-audit.exe` is NOT needed (Windows only branch
handles that already).

## Acceptance criteria

- `candidatePaths()` returns the new paths on macOS (non-Windows)
- Existing paths are unchanged — this is additive only
- `npm run build` exits 0 (no type errors)
- Existing tests in `test/` still pass (`npm test`)
- No new dependencies introduced

## Files to change

- `src/binaryLocator.ts` — the only file that needs to change

## Do not change

- The resolution order (explicit setting → which → candidates)
- The `isExecutable()` helper
- The `whichSync()` helper
- Anything in `src/extension.ts`, `src/constants.ts`, or test files
